import os
import cherrypy
import uuid
import requests
from urllib.parse import quote
from sqlalchemy import or_
from passlib.apps import custom_app_context as pwd_context
import json
import datetime

import lib.common
import lib.db

templatesdir = os.getenv('ABSTRACTPLAY_TEMPLATESDIR', '/home/protected/server/templates')
from jinja2 import Environment, FileSystemLoader
env = Environment(loader=FileSystemLoader(templatesdir))

class Email(object):
	exposed = True

	@property
	def db(self):
	    return cherrypy.request.db

	def GET(self, **kwargs):
		if ('code' in kwargs):
			q = self.db.query(lib.db.EmailVerify).filter(lib.db.EmailVerify.code == kwargs['code']).filter(lib.db.EmailVerify.expires > datetime.datetime.now())
			if (q.count() != 1):
				raise cherrypy.HTTPError(400, "Invalid or expired authorization code. Please request a new code.")
			coderec = q.first()

			#find user
			q = self.db.query(lib.db.User).filter(lib.db.User.email == coderec.email)
			if (q.count() != 1):
				raise cherrypy.HTTPError(400, "That code does not map to an existing user. Did you delete your account or change your email address?")
			user = q.first()

			#mark the user as verified
			user.email_verified = True

			#delete the code
			self.db.delete(coderec)

			#commit changes
			self.db.commit()

			#return confirmation
			tmpl = env.get_template('email/verified.html')
			return tmpl.render()
		else:
			tmpl = env.get_template('email/submitcode.html')
			return tmpl.render()

	def POST(self, code):
		raise cherrypy.HTTPRedirect('/auth/email?code={0}'.format(code))

class Authorize(object):
	exposed = True

	@property
	def db(self):
	    return cherrypy.request.db

	def GET(self):
		oauth = cherrypy.session.get('oauth')
		if (oauth is None):
			raise cherrypy.HTTPError("400 Bad Request", "You should only be here as part of an OAuth login flow. Something has gone wrong. If this persists, please contact the system administrator.")

		#gather scopes
		allscopes = self.db.query(lib.db.Scope).all()
		reqdscopes = []
		for rec in allscopes:
			if (rec.name in oauth['scopes']):
				reqdscopes.append(rec)

		q = self.db.query(lib.db.Client).filter(lib.db.Client.app_id == oauth['client_id'])
		if (q.count() != 1):
			raise cherrypy.HTTPError(400, "Unrecognized client_id.")
		rec = q.first()

		tmpl = env.get_template('authorize.html')
		return tmpl.render(client_name=rec.clientname, scopes=reqdscopes)

	def POST(self, authdscopes, choice):
		oauth = cherrypy.session.get('oauth')
		if (oauth is None):
			raise cherrypy.HTTPError("400 Bad Request", "You should only be here as part of an OAuth login flow. Something has gone wrong. If this persists, please contact the system administrator.")

		if (choice == 'deny'):
			url = oauth['redirect_uri']
			url += '?error=access_denied'
			if (oauth['state'] is not None):
				url += '&state=' + quote(oauth['state'])
			raise cherrypy.HTTPRedirect(url)
		else:
			if isinstance(authdscopes, str):
				authdscopes = [authdscopes]
			if (oauth['response_type'] == 'token'):
				token = ''
				expires = datetime.datetime.now() + datetime.timedelta(hours=1)
				q = self.db.query(lib.db.OAuthAccess).filter(lib.db.OAuthAccess.clientid == oauth['real_client_id']).filter(lib.db.OAuthAccess.userid == cherrypy.session.get('userid'))
				if (q.count() == 1):
					rec = q.first()
					rec.expires = expires
					rec.scopes = ' '.join(authdscopes)
					token = rec.token
				else:
					token = lib.common.genHexStr(128)
					rec = lib.db.OAuthAccess(clientid=oauth['real_client_id'], userid=cherrypy.session.get('userid'), token=token, expires=expires, scopes=' '.join(authdscopes))
					self.db.add(rec)
				self.db.commit()
				url = oauth['redirect_uri']
				url += '#access_token=' + quote(token)
				url += '&token_type=bearer'
				url += '&expires_in=3600'
				url += '&scope=' + quote(' '.join(authdscopes))
				if (oauth['state'] is not None):
					url += '&state=' + quote(oauth['state'])
				cherrypy.session['oauth'] = None
				raise cherrypy.HTTPRedirect(url)
			else:
				q = self.db.query(lib.db.OAuthCode).filter(lib.db.OAuthCode.clientid == oauth['real_client_id']).filter(lib.db.OAuthCode.userid == cherrypy.session.get('userid'))
				if (q.count() == 1):
					rec = q.first()
					self.db.delete(rec)
					self.db.commit
				token = lib.common.genHexStr(64)
				expires = datetime.datetime.now() + datetime.timedelta(minutes=10)
				rec = lib.db.OAuthCode(clientid=oauth['real_client_id'], userid=cherrypy.session.get('userid'), code=token, expires=expires, redirect_uri=oauth['redirect_uri'], scopes=' '.join(authdscopes))
				self.db.add(rec)
				self.db.commit()
				url = oauth['redirect_uri']
				url += '?code=' + quote(token)
				if (oauth['state'] is not None):
					url += '&state=' + quote(oauth['state'])
				cherrypy.session['oauth'] = None
				raise cherrypy.HTTPRedirect(url)

class Code2Token(object):
	exposed = True

	@property
	def db(self):
	    return cherrypy.request.db

	@cherrypy.tools.json_out()
	def POST(self, grant_type, code, redirect_uri, client_id, client_secret):
		if (grant_type != 'authorization_code'):
			raise cherrypy.HTTPError(400, "Invalid grant_type. The only supported value is 'authorization_code'.")

		q = self.db.query(lib.db.Client).filter(lib.db.Client.app_id == client_id).filter(lib.db.Client.app_secret == client_secret)
		if (q.count() != 1):
			raise cherrypy.HTTPError(400, "Unrecognized client_id.")
		client = q.first()

		q = self.db.query(lib.db.OAuthCode).filter(lib.db.OAuthCode.code == code).filter(lib.db.OAuthCode.expires > datetime.datetime.now())
		if (q.count() != 1):
			raise cherrypy.HTTPError(400, "The provided authorization code is either invalid or expired.")
		code = q.first()

		#redirect_uris must match
		if (redirect_uri != code.redirect_uri):
			raise cherrypy.HTTPError(400, "The redirect_uri provided does not match the one authorized.")

		#clientids must match
		if (client.clientid != code.clientid):
			raise cherrypy.HTTPError(400, "The authorization code presented does not belong to you.")

		rec = {}
		#generate access token
		token = lib.common.genHexStr(128)
		expires = datetime.datetime.now() + datetime.timedelta(days=30)
		expires_in = 60 * 60 * 24 * 30
		recAT = lib.db.OAuthAccess(clientid=client.clientid, userid=code.userid, token=token, expires=expires, scopes=code.scopes)
		self.db.add(recAT)
		self.db.commit()
		rec['access_token'] = token
		rec['token_type'] = 'bearer'
		rec['expires_in'] = expires_in

		q = self.db.query(lib.db.OAuthAccess).filter(lib.db.OAuthAccess.token == token)
		access = q.first()

		#generate refresh token if applicable
		if ('REFRESH' in code.scopes):
			token = lib.common.genHexStr(192)
			expires = datetime.datetime.now() + datetime.timedelta(days=60)
			expires_in = 60 * 60 * 24 * 60
			recRT = lib.db.OAuthRefresh(clientid=client.clientid, userid=code.userid, accessid=access.id, token=token, expires=expires, scopes=code.scopes)
			self.db.add(recRT)
			self.db.commit()
			rec['refresh_token'] = token
			rec['refresh_expires_in'] = expires_in

		#delete the code
		self.db.delete(code)
		self.db.commit()

		#return
		return rec

class OAuth(object):
	exposed = True

	def __init__(self):
		self.authorize = Authorize()
		self.token = Code2Token()
		# self.debug = DebugToken()

	@property
	def db(self):
	    return cherrypy.request.db

	def GET(self, client_id, response_type, redirect_uri, scope, state=None):
		#validate client_id
		q = self.db.query(lib.db.Client).filter(lib.db.Client.app_id == client_id)
		if (q.count() != 1):
			raise cherrypy.HTTPError("400 Bad Request", "The system does not recognize your client_id. Please go to the developer screen (/users/me/dev/fronts) and confirm your client_id.")
		client = q.first()

		#validate redirect_uri
		valid = False
		for r in client.redirects:
			if (r.URI == redirect_uri):
				valid = True
				break
		if (not valid):
			raise cherrypy.HTTPError("400 Bad Redirect", "The system does not recognize the redirect_uri. Please go to the developer screen (/users/me/dev/fronts) and make sure your redirect_uri is registered.")

		#validate scopes
		vscopes = self.db.query(lib.db.Scope).all()
		validscopes = []
		for vscope in vscopes:
			validscopes.append(vscope.name)
		givenscopes = scope.split()
		for gscope in givenscopes:
			if (gscope not in validscopes):
				raise cherrypy.HTTPError("400 Bad Request", "Invalid scope was provided ({0}). Please check the documentation and try again.".format(scope))

		if (response_type not in ['code', 'token']):
			raise cherrypy.HTTPError("400 Bad Request", "Invalid response_type. Must be either 'code' or 'token'.")

		#We're good! Store everything
		oauth = {}
		oauth['real_client_id'] = client.clientid
		oauth['client_id'] = client_id
		oauth['response_type'] = response_type
		oauth['redirect_uri'] = redirect_uri
		oauth['scopes'] = scope
		oauth['state'] = state
		cherrypy.session['oauth'] = oauth #dumps(oauth)

		#redirect
		raise cherrypy.HTTPRedirect('/auth')

class Logout(object):
	exposed = True

	def GET(self):
		cherrypy.lib.sessions.expire()
		raise cherrypy.HTTPRedirect("/auth")

class GoogleCallback(object):
	exposed = True

	@property
	def db(self):
	    return cherrypy.request.db

	def GET(self, **kwargs):
		if 'error' in kwargs:
			raise cherrypy.HTTPError("400 Bad Request", "An error occurred while attempting to log in to Google.")
		if 'code' not in kwargs:
			raise cherrypy.HTTPError("502 Bad Gateway", "Google did not provide an expected response.")
		code = kwargs['code']

		try:
			accesstoken = lib.common.code2tokenGoogle(code, 'https://api.abstractplay.com/auth/google/callback')
		except:
			raise

		#get profile info
		r = requests.get('https://www.googleapis.com/plus/v1/people/me', params={'access_token': accesstoken})
		j = r.json()
		userid = j['id']

		#find the matching user
		q = self.db.query(lib.db.OAuth).filter(lib.db.OAuth.service=='google').filter(lib.db.OAuth.foreignid==userid)
		if q.count() != 1:
			raise cherrypy.HTTPError("400 Bad Request", "A matching user could not be found. Go to /forms/newuser to create a new account.")
		user = q.first()

		#log them in 
		cherrypy.session['userid'] = user.userid

		#redirect them wherever
		oauth = cherrypy.session.get('oauth')
		if (oauth is not None):
			raise cherrypy.HTTPRedirect('/auth/oauth/authorize')
		else:
			raise cherrypy.HTTPRedirect('/users/me')

class Google(object):
	exposed = True

	def __init__(self):
		self.callback = GoogleCallback()

	def GET(self):
		state = uuid.uuid4().hex
		cherrypy.session['state'] = state
		gid = lib.common.getSecret('google-id')
		redirect = 'https://api.abstractplay.com/auth/google/callback'
		raise cherrypy.HTTPRedirect('https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id={0}&redirect_uri={1}&scope=profile%20email&state={2}'.format(quote(gid), quote(redirect), quote(state)))

class FacebookCallback(object):
	exposed = True

	@property
	def db(self):
	    return cherrypy.request.db

	def GET(self, *args, **kwargs):
		fbid = lib.common.getSecret('facebook-id')
		fbsecret = lib.common.getSecret('facebook-secret')

		if 'error_description' in kwargs:
			raise cherrypy.HTTPError("400 Bad Request", "An error occurred while attempting to log in to Facebook. The Facebook servers said '{0}'".format(kwargs['error_description']))
		if 'code' not in kwargs:
			raise cherrypy.HTTPError("502 Bad Gateway", "Facebook did not provide an expected response.")
		if cherrypy.session.get('state') != kwargs['state']:
			raise cherrypy.HTTPError("400 Bad Request", "CSRF measures triggered. Please contact the administrator if this continues to happen.")

		try:
			accesstoken = lib.common.code2tokenFacebook(kwargs['code'], 'https://api.abstractplay.com/auth/facebook/callback')
		except:
			raise

		try:
			fbuserid = lib.common.verifyTokenFacebook(accesstoken)
		except:
			raise

		#find the matching user
		q = self.db.query(lib.db.OAuth).filter(lib.db.OAuth.service=='facebook').filter(lib.db.OAuth.foreignid==fbuserid)
		if q.count() != 1:
			raise cherrypy.HTTPError("400 Bad Request", "A matching user could not be found. Go to /forms/newuser to create a new account.")
		user = q.first()

		#log them in
		cherrypy.session['userid'] = user.userid

		#redirect them wherever
		oauth = cherrypy.session.get('oauth')
		if (oauth is not None):
			raise cherrypy.HTTPRedirect('/auth/oauth/authorize')
		else:
			raise cherrypy.HTTPRedirect('/users/me')

class Facebook(object):
	exposed = True

	def __init__(self):
		self.callback = FacebookCallback()

	def GET(self):
		state = uuid.uuid4().hex
		cherrypy.session['state'] = state
		fbid = lib.common.getSecret('facebook-id')
		redirect = 'https://api.abstractplay.com/auth/facebook/callback'
		raise cherrypy.HTTPRedirect('https://www.facebook.com/dialog/oauth?client_id={0}&redirect_uri={1}&state={2}&response_type=code&scope=email'.format(quote(fbid), quote(redirect), quote(state)))

class Auth(object):
	exposed = True

	@property
	def db(self):
	    return cherrypy.request.db

	def __init__(self):
		self.facebook = Facebook()
		self.google = Google()
		self.logout = Logout()
		self.oauth = OAuth()
		self.email = Email()

	@cherrypy.tools.accept(media="application/json")
	@cherrypy.tools.json_out()
	def GET(self):
		return {'whoami': 'unknown'}

	@cherrypy.tools.accept(media="text/html")
	def GET(self):
		tmpl = env.get_template('login.html')
		return tmpl.render()

	def POST(self, username, password):
		q = self.db.query(lib.db.User).filter(or_(lib.db.User.username.ilike(username), lib.db.User.email.ilike(username)))
		if (q.count() != 1):
			raise cherrypy.HTTPError("400 Bad Request", "Could not find a matching user.")
		rec = q.first()
		if (not pwd_context.verify(password, rec.password.password)):
			raise cherrypy.HTTPError("400 Bad Request", "Invalid password.")

		#log them in
		cherrypy.session['userid'] = rec.userid

		#redirect them wherever
		oauth = cherrypy.session.get('oauth')
		if (oauth is not None):
			raise cherrypy.HTTPRedirect('/auth/oauth/authorize')
		else:
			raise cherrypy.HTTPRedirect('/users/me')

	def OPTIONS(self):
		return None

