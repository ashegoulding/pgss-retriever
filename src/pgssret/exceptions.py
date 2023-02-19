class PGSSRetBaseExcept (BaseException): ...

class OptionError (PGSSRetBaseExcept):
	'''Invalid executable option'''
	...

class ContentTypeError (PGSSRetBaseExcept):
	'''Unexpected content-type header value'''
	...

class UnauthenticatedError (PGSSRetBaseExcept):
	'''Not authenticated prior to retrieval'''
	...

class AuthFailedError (PGSSRetBaseExcept):
	'''Unsuccessful login attempt'''
	...

class PageFormatError (PGSSRetBaseExcept):
	'''Page returned has unexpected structure'''
	...
