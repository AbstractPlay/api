import cherrypy
import requests
import os
import re
import uuid
import cgi
import datetime
from urllib.parse import quote
from passlib.apps import custom_app_context as pwd_context
import lib.common
import lib.db

templatesdir = os.getenv('ABSTRACTPLAY_TEMPLATESDIR', '/home/protected/server/templates')
from jinja2 import Environment, FileSystemLoader
env = Environment(loader=FileSystemLoader(templatesdir))

class Me(object):
	exposed = True

	@property
	def db(self):
	    return cherrypy.request.db

	@cherrypy.tools.accept(media="text/html")
	@cherrypy.tools.authtool()
	def GET(self, authdata):
		q = self.db.query(lib.db.User).filter(lib.db.User.userid == authdata['userid'])
		if q.count() != 1:
			raise cherrypy.HTTPError("400 Bad Request", "Could not find your user record! This should never happen! Please go to /auth and log in again. If this continues to happen, please contact the system administrator.")
		user = q.first()
		return cgi.escape(repr(user), quote=True)

class Users(object):
	exposed = True

	@property
	def db(self):
	    return cherrypy.request.db

	def __init__(self):
		self.me = Me()

	@cherrypy.tools.json_out()
	@cherrypy.popargs('userid')
	def GET(self, userid=None, offset=0, count=None):
		if (userid is None):
			d = dict()
			d['data'] = []
			d['offset'] = offset
			q = self.db.query(lib.db.User).order_by(lib.db.User.userid)
			d['total'] = q.count()
			q = q.offset(offset)
			if (count is not None):
				q = q.limit(count)
				d['count'] = count
			rows = q.all()
			for row in rows:
				d['data'].append(row.to_public_resource())
			cherrypy.response.headers['Link'] = '&lt;https://www.abstractplay.com/schemas/resources_user/1-0-0.json#&gt;; rel="describedBy"'
			return d
		elif (userid == 'new'):
			raise cherrypy.InternalRedirect('/user/new')
		else:
			q = self.db.query(lib.db.User).filter(lib.db.User.userid==userid)
			if (q.count() == 1):
				cherrypy.response.headers['Link'] = '&lt;https://www.abstractplay.com/schemas/resources_user/1-0-0.json#&gt;; rel="describedBy"'
				rec = q.first()
				return rec.to_public_resource()
			else:
				raise cherrypy.HTTPError(404, "The given userid ({0}) could not be found.".format(userid))

	@cherrypy.tools.accept(media="text/html")
	def POST(self, **kwargs):
		if 'serviceid' not in kwargs:
			raise cherrypy.HTTPError("400 Bad Request", "Missing 'serviceid' parameter.")

		username = kwargs['username']
		email = kwargs['email']
		email = email.lower()
		tos = kwargs['tos']

		result = re.match(r'^[A-Za-z0-9_]{3,50}$', username)
		if ( (username is None) or (len(username) < 3) or (len(username) > 50) or (result is None) ):
			raise cherrypy.HTTPError("400 Bad Request", "The screen name must be between 5 and 50 alphanumeric characters (including underscores).")

		if (tos != "on"):
			raise cherrypy.HTTPError("400 Bad Request", "You must confirm you have read the terms of service.");

		if ( (email is None) or ('@' not in email) ):
			raise cherrypy.HTTPError("400 Bad Request", "You must provide an email address.");

		#make sure username is unique
		q = self.db.query(lib.db.User).filter(lib.db.User.username_normalized==username.lower())
		if (q.count() > 0):
			raise cherrypy.HTTPError("400 Bad Request", "The requested username ({0}) is already in use.".format(username))

		#make sure email address is unique
		q = self.db.query(lib.db.User).filter(lib.db.User.email==email)
		if (q.count() > 0):
			raise cherrypy.HTTPError("400 Bad Request", "The given email address ({0}) is already in use. Players are only permitted to have one account.".format(email))

		if kwargs['serviceid'] == 'password':
			password1 = kwargs['password1']
			password2 = kwargs['password2']

			if ( (password1 is None) or (len(password1) < 8) or (len(password1) > 255) or (password1 != password2) ):
				raise cherrypy.HTTPError("400 Bad Request", "Passwords must be between 8 and 255 characters long.");

		date = datetime.datetime.now()
		user = lib.db.User(username=username, username_normalized=username.lower(), email=email, email_verified=False, date_created=date, deleted=False)
		user.namehistory = [lib.db.NameHistory(name=username, date_effective=date)]

		if kwargs['serviceid'] != 'password':
			user.oauth = [lib.db.OAuth(service=kwargs['serviceid'], foreignid=kwargs['foreignid'])]
		else:
			password = pwd_context.encrypt(password1)
			user.password = lib.db.Password(password=password)

		try:
			self.db.add(user)
			self.db.commit()
		except Exception as ex:
			raise cherrypy.HTTPError("500 Internal Server Error", "An error occurred when trying to create your account. The server said: {0}".format(ex.strerror))

		#get the userid
		rec = self.db.query(lib.db.User).filter(lib.db.User.username==username).first()

		#send verification email
		code = lib.common.genHexStr(16)
		expires = datetime.datetime.now() + datetime.timedelta(hours=1)
		verify = lib.db.EmailVerify(email=rec.email, code=code, expires=expires)
		self.db.add(verify)
		self.db.commit()
		lib.common.sendVerificationEmail(rec.email, code, expires)

		#return 201
		cherrypy.session['userid'] = rec.userid
		cherrypy.response.status = "201 Created"
		cherrypy.response.headers['Location'] = "/users/{0}".format(rec.userid)
		return '<a href="/users/{0}/">/users/{1}</a>'.format(rec.userid, rec.userid)

	def OPTIONS(self):
		return None

