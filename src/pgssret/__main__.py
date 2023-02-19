from contextlib import contextmanager
import getopt
import sys
import yaml
from pgssret import PGSSRetriever, Version, exceptions

EXEC = "python -m pgssret"
HELP_STR = '''Get and email pay slips from PGSS.
Usage: {exec} -f <config>
Options:
  -f <config>:  use the yaml config file
  -h, --help:   print this message and exit normally
  -V,--version: print version info and exit normally'''

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
		if t[0] == "-h" or t[0] == "--help": ret.help = True
		elif t[0] == "-V" or t[0] == "--version": ret.version = True
		elif t[0] == "-f":
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

try:
	params = ParseArgs(sys.argv[1:])
except (getopt.GetoptError, exceptions.OptionError) as e:
	sys.stderr.write('''{msg}
Run '{exec} --help' for usage.
'''.format(
msg = str(e),
exec = EXEC
))
	sys.exit(2)


######################################################################
# Execution starts here
######################################################################
ec = None

if params.help:
	print(HELP_STR.format(exec = EXEC))
	ec = 0
if params.version:
	print(Version.__str__())
	ec = 0

if not params.conf:
	sys.stderr.write("No config specified.\n")
	sys.exit(2)

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
'''.format(msg = str(e)))
	ec = 1

sys.exit(ec)
