import os
import cherrypy

pidfile = os.getenv('ABSTRACTPLAY_PIDFILE', "logs/server.pid")
from cherrypy.process.plugins import PIDFile
PIDFile(cherrypy.engine, pidfile).subscribe()

from cp_sqlalchemy import SQLAlchemyTool, SQLAlchemyPlugin
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import or_

templatesdir = os.getenv('ABSTRACTPLAY_TEMPLATESDIR', '/home/protected/server/templates')
from jinja2 import Environment, FileSystemLoader
env = Environment(loader=FileSystemLoader(templatesdir))

import lib.db
import lib.common
#import lib.staticdirindex
#import lib.htmldir

from pymongo import MongoClient

import json
from base64 import b64decode
from passlib.apps import custom_app_context as pwd_context

import re
re_bearer = re.compile(r'^Bearer (\S+)$')
re_basic = re.compile(r'^Basic (\S+)$')

def secureheaders():
    headers = cherrypy.response.headers
    headers['Access-Control-Allow-Origin'] = 'https://www.abstractplay.com'
    headers['X-Frame-Options'] = 'DENY'
    headers['X-XSS-Protection'] = '1; mode=block'
    # headers['Content-Security-Policy'] = "default-src 'none'; script-src 'self' 'unsafe-inline' connect.facebook.net apis.google.com; connect-src 'self'; img-src 'self' data: www.facebook.com apis.google.com; style-src 'self' 'unsafe-inline'; child-src 'self' accounts.google.com staticxx.facebook.com www.facebook.com;"
    headers['Content-Security-Policy'] = "default-src 'none'; script-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; child-src 'self';"

cherrypy.tools.secureheaders = cherrypy.Tool('before_finalize', secureheaders, priority=60)

def extract_headers():
	if (cherrypy.session.get('userid') is not None):
		d = {}
		d['userid'] = cherrypy.session.get('userid')
		d['scopes'] = 'FULL'
		d['type'] = 'session'
		#headers['X-Auth-Results'] = json.dumps(d)
		cherrypy.request.params['authdata'] = d
		return
	else:
		db = cherrypy.request.db
		headers = cherrypy.request.headers
		if ('Authorization' in headers):
			m = re_bearer.match(headers['Authorization'])
			if m:
				token = m.group(1)
				q = db.query(lib.db.OAuthAccess).filter(lib.db.OAuthAccess.token == token)
				if (q.count() == 1):
					rec = q.first()
					d = {}
					d['userid'] = rec.userid
					d['scopes'] = rec.scopes
					d['type'] = 'bearer'
					d['clientid'] = rec.clientid
					#headers['X-Auth-Results'] = json.dumps(d)
					cherrypy.request.params['authdata'] = d
					return
			else:
				m = re_basic.match(headers['Authorization'])
				if m:
					try:
						pair = b64decode(m.group(1)).decode('utf-8')
					except:
						raise cherrypy.HTTPError(400, "Malformed Authorization header.")
					username, password = pair.split(':', 1)
					q = db.query(lib.db.User).filter(or_(lib.db.User.username.ilike(username), lib.db.User.email.ilike(username)))
					if (q.count() == 1):
						rec = q.first()
						if (pwd_context.verify(password, rec.password.password)):
							d = {}
							d['userid'] = rec.userid
							d['scopes'] = 'FULL'
							d['type'] = 'authorization'
							#headers['X-Auth-Results'] = json.dumps(d)
							cherrypy.request.params['authdata'] = d
							return
	raise cherrypy.HTTPError(401)

cherrypy.tools.authtool = cherrypy.Tool('before_handler', extract_headers, priority=95)

#def auth_required():
#	auth = cherrypy.headers['X-Auth-Results']
#	if (auth is None):
#		raise cherrypy.HTTPError(401)
#	cherrypy.request.params['authdata'] = json.loads(auth)
#
#cherrypy.tools.authreqd = cherrypy.Tool('before_handler', auth_required, priority=55)

description = '''![Logo](https://www.abstractplay.com/images/logo.png)
# Abstract Play API Server

Abstract Play makes available abstract strategy board games on the web. It was designed to allow those of us with limited free time to enjoy the interaction with live opponents on one's own schedule. Players can submit their move and continue on with their day. Should the opponent happen to be online at the same time, there is nothing stopping them from exchanging a number of moves in quick succession, but the design does not require it.

Abstract Play is a whole-cloth reimplementation of my previous project, [Super Duper Games](http://superdupergames.org). 

Please see the [terms of service](/static/tos.html) for more information on how to use this service, our privacy policy, and other points of intellectual property.
'''

from lib.auth import Auth
from lib.users import Users
from lib.forms import Forms
from lib.debug import Debug
from lib.games import Games
from lib.query import GraphQL

class Root(object):
	exposed = True

	@cherrypy.tools.json_out()
	def GET(self):
		cherrypy.response.headers['Link'] = '&lt;https://www.abstractplay.com/schemas/resources_root/1-0-0.json#&gt;; rel="describedBy"'
		return {'desc': description}

	# @cherrypy.tools.accept(media="text/html")
	# def GET(self):
#		client = MongoClient()
#		db = client.test_database
#		post = {"author": "Mike", "text": "My first blog post!", "tags": ["mongodb", "python", "pymongo"]}
#		posts = db.posts
#		post_id = posts.insert_one(post).inserted_id
#		return str(post_id)
		# tmpl = env.get_template('base.html')
		# return tmpl.render()

	def OPTIONS(self):
		return None

root = Root()
root.auth = Auth()
root.users = Users()
root.forms = Forms()
root.debug = Debug()
root.games = Games()
root.query = GraphQL()

if __name__ == '__main__':
	cherrypy.tools.db = SQLAlchemyTool()
	cherrypy.config.update("server.conf")
	cherrypy.tree.mount(root, '/', "server.conf")
	saplugin = SQLAlchemyPlugin(cherrypy.engine, declarative_base(), 'mysql+pymysql://{0}@abstractplay.db:3306/sdg'.format(lib.common.getSecret('db-userpass')))
	saplugin.subscribe()
	cherrypy.engine.start()
	cherrypy.engine.block()
