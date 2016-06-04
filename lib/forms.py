import cherrypy
import requests
import uuid
from urllib.parse import quote
import json
import os

import lib.common

templatesdir = os.getenv('ABSTRACTPLAY_TEMPLATESDIR', '/home/protected/server/templates')
from jinja2 import Environment, FileSystemLoader
env = Environment(loader=FileSystemLoader(templatesdir))

class GoogleCallback(object):
	exposed = True

	def GET(self, **kwargs):
		if 'error' in kwargs:
			raise cherrypy.HTTPError("400 Bad Request", "An error occurred while attempting to log in to Google.")
		if 'code' not in kwargs:
			raise cherrypy.HTTPError("502 Bad Gatewat", "Google did not provide an expected response.")
		code = kwargs['code']

		try:
			accesstoken = lib.common.code2tokenGoogle(code, 'https://api.abstractplay.com/forms/newuser/google/callback')
		except:
			raise

		#get profile info
		r = requests.get('https://www.googleapis.com/plus/v1/people/me', params={'access_token': accesstoken})
		j = r.json()
		userid = j['id']
		email = None
		if len(j['emails']) > 0:
			email = j['emails'][0]['value']

		#return google-specific form
		tmpl = env.get_template('newuser_foreign.html')
		return tmpl.render(servicename='Google', serviceid='google', foreignid=j['id'], email=email)

class Google(object):
	exposed = True

	def __init__(self):
		self.callback = GoogleCallback()

	def GET(self):
		state = uuid.uuid4().hex
		cherrypy.session['state'] = state
		gid = lib.common.getSecret('google-id')
		redirect = 'https://api.abstractplay.com/forms/newuser/google/callback'
		raise cherrypy.HTTPRedirect('https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id={0}&redirect_uri={1}&scope=profile%20email&state={2}'.format(quote(gid), quote(redirect), quote(state)))

class FacebookCallback(object):
	exposed = True

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
			accesstoken = lib.common.code2tokenFacebook(kwargs['code'], 'https://api.abstractplay.com/forms/newuser/facebook/callback')
		except:
			raise

		try:
			fbuserid = lib.common.verifyTokenFacebook(accesstoken)
		except:
			raise

		#get user profile
		r = requests.get('https://graph.facebook.com/me?fields=email', params={'access_token': accesstoken})
		j = r.json()
		email = j['email']

		#return Facebook-specific form
		tmpl = env.get_template('newuser_foreign.html')
		return tmpl.render(servicename='Facebook', serviceid='facebook', foreignid=fbuserid, email=email)

class Facebook(object):
	exposed = True

	def __init__(self):
		self.callback = FacebookCallback()

	def GET(self):
		state = uuid.uuid4().hex
		cherrypy.session['state'] = state
		fbid = lib.common.getSecret('facebook-id')
		redirect = 'https://api.abstractplay.com/forms/newuser/facebook/callback'
		raise cherrypy.HTTPRedirect('https://www.facebook.com/dialog/oauth?client_id={0}&redirect_uri={1}&state={2}&response_type=code&scope=email'.format(quote(fbid), quote(redirect), quote(state)))

class NewUser(object):
	exposed = True

	def __init__(self):
		self.facebook = Facebook()
		self.google = Google()

	@cherrypy.tools.accept(media="text/html")
	def GET(self):
		tmpl = env.get_template('newuser.html')
		return tmpl.render()

class Forms(object):
	exposed = True

	def __init__(self):
		self.newuser = NewUser()

	@cherrypy.tools.accept(media="application/json")
	@cherrypy.tools.json_out()
	def GET(self):
		return cherrypy.request.headers
