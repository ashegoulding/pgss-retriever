import getopt
import json
import locale
import os
import re
import shutil
import subprocess
import sys
import urllib.parse
from contextlib import contextmanager
from datetime import datetime
from enum import Enum
from html.parser import HTMLParser

import requests
import yaml

from pgss_retriever import exceptions


class Version:
	dot_ver = "0.0.0"
	rev = 0
	name = None
	var = None

	def __str__ () -> str:
		return '''Version: {ver}
Revision: {rev}{name}{var}'''.format(
	ver = Version.dot_ver,
	rev = Version.rev,
	name = "Name: " + Version.name if Version.name else "",
	var = "Variant: " + Version.var if Version.var else ""
)

HELP_STR = '''Get and email pay slips from PGSS.
Usage: {exec} -f <config>
Options:
  -f <config>:  use the yaml config file
  -h, --help:   print this message and exit normally
  -V,--version: print version info and exit normally'''

class InitModes(Enum):
	'''Initial invocation behaviour'''
	SEND_LAST = 0 # Email one latest pay slip
	CACHE_ONLY = 1 # Just remember the id of the latest pay slip
	SEND_ALL = 2 # Email all the pay slips

ConfigSkel = {
	# "auth": {},
	"url": {
		"auth": '''https://ess.myobpayglobal.com/CompassGroup/BaseForm.aspx''',
		"deauth": '''https://ess.myobpayglobal.com/CompassGroup/BaseForm.aspx?_req=Login.Logout''',
		"home": '''https://ess.myobpayglobal.com/CompassGroup/BaseForm.aspx?_view=HomePage.HomePage''',
		"payslips": '''https://ess.myobpayglobal.com/CompassGroup/BaseForm.aspx?_req=Documents.ShowPaySlips&Param1=5&key=7''',
		"doc_script": '''https://ess.myobpayglobal.com/CompassGroup/Document/DocumentShow.aspx?'''
	},
	"dir": {
		"cache": "cache",
		"tmp": "tmp"
	},
	"limits": {
		"eml-size": 5242880, # 5 MiB
		"nb-attachments": 20
	},
	"init-mode": 0,
	"mail": {
		"backend": "mailx",
		"exec": "/usr/bin/mailx"
		# "recipients": []
	}
}

RetTaskParamSkel = {
	"init-mode": InitModes.SEND_LAST
}

class AuthScriptParser (HTMLParser):
	class MAGIC (Enum):
		FORM_NAME = "Form1"

	def __init__ (self):
		super().__init__()
		self.form_data = None

	def handle_starttag (self, tag, attrs):
		attrs = dict(attrs)

		if self.form_data is None:
			# State: looking for form tag
			if (tag.lower() == "form"
				and attrs.get("name") == self.MAGIC.FORM_NAME.value):
				self.form_data = {}
		else:
			# State: looking for input tags
			match tag.lower():
				case "form": raise exceptions.PageFormatError(
					"Nested form encountered")
				case "input":
					name = attrs.get("name")
					val = attrs.get("value", "")
					if name:
						self.form_data[name] = val

class AuthErrorParser (HTMLParser):
	def __init__ (self):
		super().__init__()
		self.msg = None
		self.__flag = False

	def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
		attrs = dict(attrs)
		cl = attrs.get("class")

		if cl and cl.find("error-container") >= 0:
			self.__flag = True

	def handle_data(self, data: str):
		if self.__flag:
			data = data.strip()
			if data:
				self.msg = data
				self.__flag = False

class PayslipsDirParser (HTMLParser):
	def __init__ (self, prefix: str):
		super().__init__()
		self.prefix = prefix
		self.ctx_id = None
		self.ctx_url = None
		self.dir = {}

	def handle_starttag (self, tag, attrs):
		attrs = dict(attrs)

		if tag.lower() == "a":
			link = attrs.get("href", "")
			if not link.startswith(self.prefix): return

			qs = urllib.parse.parse_qs(link[len(self.prefix):])
			self.ctx_id = qs.get("DocumentID", [""])[0]
			self.ctx_url = link

	def handle_data(self, data: str):
		if self.ctx_id:
			self.dir[self.ctx_id] = {
				"url": self.ctx_url,
				"filename": data.strip()
			}
			self.ctx_id = None

def decode_html (r: requests.Response) -> str:
	ctype = r.headers["content-type"]
	if not re.search(
		'''(text/html|application/xhtml\+xml);''',
		ctype,
		re.I):
		raise exceptions.ContentTypeError(
			"Expected 'content-type: {ctype}'".format(ctype))

	return str(r.content, r.encoding)

class PGSSRetriever:
	def __init__ (self, conf: dict):
		self.conf = ConfigSkel | conf
		self.session = None

	def do_auth (self):
		try:
			self.session = requests.Session()

			# Load the login page to get idempos
			with self.session.get(self.conf["url"]["auth"]) as r:
				r.raise_for_status()
				parser = AuthScriptParser()
				parser.feed(decode_html(r))
				form = parser.form_data

			# Put auth data and do POST
			form["Login$Login_Component0$Username"] = self.conf["auth"]["username"]
			form["Login$Login_Component0$Password"] = self.conf["auth"]["password"]
			# form["__ASYNCPOST"] = "true"
			# form["formChanged"] = "1"
			# form["__LASTFOCUS"] = ""
			# form["ScriptManager1"] = "Login$contentUpdatePanel|Login$Login_Component1Sign_In_internal"
			# form["__EVENTTARGET"] = ""
			# form["__EVENTARGUMENT"] = ""
			with self.session.post(
				url = self.conf["url"]["auth"],
				data = form) as r:
				r.raise_for_status()
				if r.url != self.conf["url"]["home"]:
					parser = AuthErrorParser()

					parser.feed(decode_html(r))
					raise exceptions.AuthFailedError(parser.msg)
		except:
			self.session = None
			raise

	def do_deauth (self):
		if not self.session: return

		r = self.session.get(url = self.conf["url"]["deauth"])
		r.raise_for_status()
		self.session.close()
		self.session = None

	def __get_cache_path (self) -> str:
		return "{base}{sep}{id}.json".format(
			base = self.conf["dir"]["cache"],
			sep = os.sep,
			id = self.conf["auth"]["username"]
		)

	def __get_tmpfile_path (self, doc_id, filename) -> str:
		return "{base}{sep}{doc_id}_{filename}".format(
			base = self.conf["dir"]["tmp"],
			sep = os.sep,
			doc_id = doc_id,
			filename = filename
		)

	def __construct_skel_cache (self):
		return {
			"dir": {}
		}

	def __do_retrieve (self, doc_id: str, entry: dict):
		r = self.session.get(entry["url"])
		tmp_path = self.__get_tmpfile_path(doc_id, entry["filename"])
		with open(tmp_path, "wb") as f:
			f.write(r.content)
		entry["size"] = len(r.content)

	def __get_isotimestr (self) -> str:
		return datetime.utcnow().isoformat()

	def __do_email (self, m: dict):
		argv = [ self.conf["mail"]["exec"], "-s", "PGSS Payslip" ]
		for k in m.keys():
			v = m[k]
			tmp_fn = self.__get_tmpfile_path(k, v["filename"])
			argv.append("-a")
			argv.append(tmp_fn)
		argv += self.conf["mail"]["recipients"]

		sys_enc = None
		loc = locale.getdefaultlocale()
		if len(loc) >= 2: sys_enc = loc[1]

		with subprocess.Popen(
			argv,
			stdin = subprocess.PIPE) as p:
			# Careful with the locale. The IO could be in encoding other
			# than utf-8. In this case, getdefaultlocale() shouldn't return
			# "utf-8"
			p.stdin.write(
'''Attached: pay slip(s) for employee #{username} retrieved from PGSS'''.format(
	username = self.conf["auth"]["username"]
).encode(sys_enc))
			p.stdin.close()

			ec = p.wait()
			if ec != 0:
				raise ChildProcessError(
					"Child process returned exit code: {ec}".format(ec = ec))

		ts = self.__get_isotimestr()
		for i in m.values():
			print(i)
			i["sent"] = ts

	def __do_prep_dirs (self):
		os.makedirs(name = self.conf["dir"]["cache"], mode = 0o755, exist_ok = True)
		os.makedirs(name = self.conf["dir"]["tmp"], mode = 0o755, exist_ok = True)

	def __clear_tmp (self):
		shutil.rmtree(self.conf["dir"]["tmp"], True)

	def do_work (self, params: dict):
		'''Do the work:
		- Read the cache
		- Retrieve the pay slips
		- Email them to configured recipients'''

		# Assert login state
		if not self.session: raise exceptions.UnauthenticatedError()

		self.__do_prep_dirs()

		# Load cache
		cache = self.__construct_skel_cache()
		new_cache = False
		try:
			with open(self.__get_cache_path()) as cache_f:
				cache |= json.load(cache_f)
		except FileNotFoundError:
			new_cache = True
		except:
			raise

		# Retrieve payslip page
		r = self.session.get(url = self.conf["url"]["payslips"])
		r.raise_for_status()
		parser = PayslipsDirParser(self.conf["url"]["doc_script"])
		parser.feed(decode_html(r))
		theirs = parser.dir

		# Cross-ref cache to construct delta, depending on the cases
		d = set(theirs.keys()).difference(cache["dir"].keys())
		proc = {}

		if new_cache:
			match self.conf["init-mode"]:
				case InitModes.SEND_LAST.value:
					l = list(d)
					l.sort()

					d = set([l.pop()])

					for i in l:
						proc[i] = theirs[i]
						proc[i]["sent"] = None

					del l
				case InitModes.CACHE_ONLY.value:
					for i in d:
						proc[i] = theirs[i]
						proc[i]["sent"] = None
					d = set()
				case InitModes.SEND_ALL.value: pass
				case _: raise KeyError()
		try:
			# Retrieve delta
			for i in d:
				entry = theirs[i]
				self.__do_retrieve(i, entry)
			# Email delta
			att_q = {}
			size_sum = 0
			d_l = list(d)
			d_l.sort()
			while d_l:
				while (d_l and
					self.conf["limits"]["eml-size"] >= size_sum and
					self.conf["limits"]["nb-attachments"] >= len(att_q)):
					i = d_l.pop()
					att_q[i] = theirs[i]
					size_sum += theirs[i]["size"]
				self.__do_email(att_q)
				proc |= att_q
				att_q.clear()
		except:
			raise
		finally:
			self.__clear_tmp()

			cache["dir"] |= proc
			cache["last-run"] = self.__get_isotimestr()
			with open(self.__get_cache_path(), "w") as f:
				json.dump(cache, f, indent = 1)

class ProgParams:
	def __init__ (self):
		self.conf = None
		self.help = False
		self.version = False

def ParseArgs (args: list[str]) -> ProgParams:
	ret = ProgParams()

	opts = getopt.getopt(
		args,
		"f:hV",
		[
			"help",
			"version"
		])
	for t in opts[0]:
		match t[0]:
			case "-h" | "--help": ret.help = True
			case "-V" | "--version": ret.version = True
			case "-f":
				if ret.conf:
					raise exceptions.OptionError(
						"Duplicate option '{opt}'".format(opt = t[0]))
				else:
					ret.conf = t[1]

	return ret

@contextmanager
def open_retriever (conf: dict) -> PGSSRetriever:
	ret = PGSSRetriever(conf)

	try:
		ret.do_auth()
		yield ret
	finally:
		ret.do_deauth()

def __main__ ():
	ec = None

	try:
		params = ParseArgs(sys.argv[1:])
	except (getopt.GetoptError, exceptions.OptionError) as e:
		sys.stderr.write('''{msg}
Run '{exec} --help' for usage.
'''.format(
	msg = e.msg,
	exec = sys.argv[0]
))
		sys.exit(2)

	if params.help:
		print(HELP_STR.format(exec = sys.argv[0]))
		ec = 0
	if params.version:
		print(Version.__str__())
		ec = 0

	if ec is not None:
		sys.exit(ec)

	with open(params.conf) as f:
		conf = yaml.load(f, yaml.Loader)["pgss-ret"]

	try:
		with open_retriever(conf) as pgss_r:
			pgss_r.do_work(params)
			ec = 0
	except exceptions.AuthFailedError as e:
		sys.stderr.write('''Login failed: {msg}
'''.format(msg = e))
		ec = 1

	sys.exit(ec)
