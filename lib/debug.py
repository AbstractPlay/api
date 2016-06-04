import cherrypy
import os.path
import PIL
import json
import jsonschema
import lib.common
import io

templatesdir = os.getenv('ABSTRACTPLAY_TEMPLATESDIR', '/home/protected/server/templates')
from jinja2 import Environment, FileSystemLoader
env = Environment(loader=FileSystemLoader(templatesdir))

schemadir = os.getenv('ABSTRACTPLAY_SCHEMADIR', '/home/public/schemas')

class Render(object):
	exposed = True

	def POST(self, injson, variant='default', size='50'):
		try:
			dct = json.loads(injson)
		except:
			raise cherrypy.HTTPError(400, "Could not parse the provided JSON.")
		img = lib.common.render(dct)
		cherrypy.response.headers['Content-Type'] = "image/png"
		buffer = io.BytesIO()
		img.save(buffer, 'PNG')
		return buffer.getvalue()

class Tokens(object):
	exposed = True

	@property
	def db(self):
	    return cherrypy.request.db

	@cherrypy.tools.json_out()
	def GET(self, token, client_id, client_secret):
		#verify client
		q = self.db.query(lib.db.Client).filter(lib.db.Client.app_id == client_id).filter(lib.db.Client.app_secret == client_secret)
		if (q.count() != 1):
			raise cherrypy.HTTPError(400, "Unrecognized client.")

		#gather token data
		q = self.db.query(lib.db.OAuthAccess).filter(lib.db.OAuthAccess.token == token)
		if (q.count() != 1):
			raise cherrypy.HTTPError(400, "Unrecognized access token.")
		tokenrec = q.first()

		#return
		rec = {}
		rec['app_id'] = tokenrec.client.app_id
		rec['app_name'] = tokenrec.client.clientname
		rec['expires_at'] = tokenrec.expires.isoformat()
		rec['scopes'] = tokenrec.scopes
		rec['user_id'] = tokenrec.userid
		return rec

class Schemas(object):
	exposed = True

	def POST(self, schema, version, injson):
		#does the file exist
		path = '/'.join([schemadir, schema, version+".json"])
		if (not os.path.isfile(path)):
			raise cherrypy.HTTPError(404, "The given schema+version does not exist (looked for {0}).".format(path))

		#load the schema
		with open(path) as infile:
			schema = json.load(infile)

		#load the injson
		try:
			injson = json.loads(injson)
		except:
			raise cherrypy.HTTPError(400, "Could not test the given JSON against the sechema because the JSON you provided is not even valid JSON.")

		#validate
		try:
			jsonschema.validate(injson, schema)
		except jsonschema.exceptions.SchemaError as ex:
			raise cherrypy.HTTPError(500, "Schema failed to validate! This should never happen. The following reason was given: {0}.".format(ex.message))
		except jsonschema.exceptions.ValidationError as ex:
			raise cherrypy.HTTPError(400, "JSON failed to validate. The following reason was given: {0}.".format(ex.message))
		except Exception as ex:
			raise cherrypy.HTTPError(500,  "An uncaught error occurred: {0}".format(ex.message))

		#return empty 200
		return None

class Debug(object):
	exposed = True

	def __init__(self):
		self.schemas = Schemas()
		self.tokens = Tokens()
		self.render = Render()

	def OPTIONS(self):
		return None

