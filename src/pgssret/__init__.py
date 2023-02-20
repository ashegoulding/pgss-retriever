import getpass
import json
import os
import re
import shutil
from ssl import SSLContext
import ssl
import urllib.parse
from datetime import datetime
from enum import Enum
from html.parser import HTMLParser

import requests
import smtplib
from email.message import EmailMessage

from pgssret import exceptions


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

class InitModes(Enum):
	'''Initial invocation behaviour'''
	SEND_LAST = 0 # Email one latest pay slip
	CACHE_ONLY = 1 # Just remember the id of the latest pay slip (no email)
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
	"init-mode": 0
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
		tag = tag.lower()

		if self.form_data is None:
			# State: looking for form tag
			if (tag == "form"
				and attrs.get("name") == self.MAGIC.FORM_NAME.value):
				self.form_data = {}
		else:
			# State: looking for input tags
			if tag == "form": raise exceptions.PageFormatError(
				"Nested form encountered")
			elif tag == "input":
				name = attrs.get("name")
				val = attrs.get("value", "")
				if name:
					self.form_data[name] = val

class AuthErrorParser (HTMLParser):
	def __init__ (self):
		super().__init__()
		self.msg = None
		self.__flag = False

	def handle_starttag(self, tag: str, attrs: list[tuple]):
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
	post_backend_map = {}

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

	def __do_post_smtplib (self,
		subject: str,
		body: str,
		m: map,
		recipients: list,
		params: map):
		def tail (c: smtplib.SMTP, sslctx: SSLContext = None):
			if sslctx:
				try: c.starttls(context = sslctx)
				except:
					if params.get("allow-plaintext", False): pass
					else: raise

			cred = params.get("cred")
			if cred:
				c.user = cred.get("username")
				c.password = cred.get("password")

			c.send_message(mail)

		mail = EmailMessage()

		mail["From"] = params.get("from", getpass.getuser())
		mail["To"] = ", ".join(recipients)

		for k in m.keys():
			v = m[k]
			tmp_fn = self.__get_tmpfile_path(k, v["filename"])
			with open(tmp_fn, "rb") as fp:
				# TODO: timestamp and filetype
				mail.add_attachment(
					fp.read(),
					maintype = "application",
					subtype = "octet-stream")

		proto_str = params["proto"]
		host = params.get("host", "localhost")
		tlsca = params.get("ca")
		tlskey = params.get("tlskey")
		tlscert = params.get("tlscert")

		def init_ssl () -> SSLContext:
			if tlsca or tlskey or tlscert:
				rv = SSLContext()
				rv.load_verify_locations(tlsca)
				rv.load_cert_chain(tlscert, tlskey, params.get("tlskeypw"))
			else:
				rv = ssl.create_default_context()

		if proto_str == "lmtp":
			with smtplib.LMTP(host, params.get("port", smtplib.LMTP_PORT)) as c:
				c.connect()
				tail(c)
		elif proto_str == "smtp":
			with smtplib.SMTP(host, params.get("port", 0)) as c:
				tail(c, init_ssl())
		elif proto_str == "smtps":
			with smtplib.SMTP_SSL(
				host,
				params.get("port", 0),
				context = init_ssl()) as c:
				tail(c)
		else: raise KeyError()

		ts = self.__get_isotimestr()
		for i in m.values():
			print(i)
			i["sent"] = ts

	post_backend_map["smtplib"] = __do_post_smtplib

	def __do_post (self, m: dict):
		backend_method = PGSSRetriever.post_backend_map[
			self.conf["post"]["backend"]]
		return backend_method(
			self,
			self.conf["post"]["subject"],
			self.conf["post"]["body"],
			m,
			self.conf["post"]["recipients"],
			self.conf["post"]["params"]
		)

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
			if self.conf["init-mode"] == InitModes.SEND_LAST.value:
				l = list(d)
				l.sort()

				d = set([l.pop()])

				for i in l:
					proc[i] = theirs[i]
					proc[i]["sent"] = None

				del l
			elif self.conf["init-mode"] == InitModes.CACHE_ONLY.value:
				for i in d:
					proc[i] = theirs[i]
					proc[i]["sent"] = None
				d = set()
			elif self.conf["init-mode"] == InitModes.SEND_ALL.value: pass
			else: raise KeyError()
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
				self.__do_post(att_q)
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
