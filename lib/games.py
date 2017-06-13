import os
import cherrypy
import lib.common
import lib.db

templatesdir = os.getenv('ABSTRACTPLAY_TEMPLATESDIR', '/home/protected/server/templates')
from jinja2 import Environment, FileSystemLoader
env = Environment(loader=FileSystemLoader(templatesdir))

class Games(object):
	exposed = True

	@property
	def db(self):
	    return cherrypy.request.db

	def __init__(self):
		pass

	@cherrypy.tools.json_out()
	def GET(self):
		#active
		num_active = 0
		#pending
		num_pending = 0
		#archived
		num_archived=0
		#available
		q = self.db.query(lib.db.GameInfo)
		num_available = q.count()

		cherrypy.response.headers['Link'] = '&lt;https://www.abstractplay.com/schemas/resources_games/1-0-0.json#&gt;; rel="describedBy"'
		return {'num_available': num_available, 'num_pending': num_pending, 'num_active': num_active, 'num_archived': num_archived}

	def OPTIONS(self):
		return None

