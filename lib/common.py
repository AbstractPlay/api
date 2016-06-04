import cherrypy
import requests
import os
import binascii
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from subprocess import Popen, PIPE
import os.path
import json
import re
from PIL import Image
import PIL.ImageOps

templatesdir = os.getenv('ABSTRACTPLAY_TEMPLATESDIR', '/home/protected/server/templates')
from jinja2 import Environment, FileSystemLoader
env = Environment(loader=FileSystemLoader(templatesdir))

secretsdir = os.getenv('ABSTRACTPLAY_SECRETSDIR', '/home/protected/apsecrets')

def genHexStr(length):
	if (length % 2 != 0):
		return None
	return binascii.b2a_hex(os.urandom(int(length/2))).decode('utf-8')

def getSecret(filename):
	try:
		f = open('{0}/{1}'.format(secretsdir, filename), 'r')
		l = f.readline()
		f.close()
		l = l.rstrip()
		return l
	except ex as Exception:
		#raise ex
		return None

def sendMail(msg):
    sendmail_location = "/usr/bin/sendmail" # sendmail location
    p = Popen([sendmail_location, "-t"], stdin=PIPE)
    p.communicate(bytes(msg, 'UTF-8'))

def sendVerificationEmail(email, code, expires):
	me = 'DoNotReply@abstractplay.com'
	subject = "AbstractPlay: Verify your email address"

	msg = MIMEMultipart('alternative')
	msg['Subject'] = subject
	msg['From'] = me
	msg['To'] = email

	tmpl_text = env.get_template('email/verify.txt')
	tmpl_html = env.get_template('email/verify.html')

	part1 = MIMEText(tmpl_text.render(code=code, expires=expires.isoformat()), 'text')
	part2 = MIMEText(tmpl_html.render(code=code, expires=expires.isoformat()), 'html')

	msg.attach(part1)
	msg.attach(part2)

	sendMail(msg.as_string())

def code2tokenGoogle(code, redirect):
	gid = getSecret('google-id')
	gsecret = getSecret('google-secret')
	payload = {
		'code': code,
		'client_id': gid,
		'client_secret': gsecret,
		'redirect_uri': redirect,
		'grant_type': 'authorization_code'
	}
	r = requests.post('https://www.googleapis.com/oauth2/v4/token', params=payload)
	if r.status_code != 200:
		raise cherrypy.HTTPError("502 Bad Gateway", "Google did not honour the credentials. Response code: {0}. Response body: {1}".format(r.status_code, r.text))
	j = r.json()
	if 'access_token' not in j:
		raise cherrypy.HTTPError("502 Bad Gateway", "Facebook did not honour the credentials.")
	return j['access_token']

def code2tokenFacebook(code, redirect):
	payload = {'client_id': getSecret('facebook-id'),
	           'redirect_uri': redirect,
	           'client_secret': getSecret('facebook-secret'),
	           'code': code}
	r = requests.get('https://graph.facebook.com/v2.3/oauth/access_token', params=payload)
	if r.status_code != 200:
		raise cherrypy.HTTPError("502 Bad Gateway", "Facebook did not honour the credentials. Response code: {0}. Response body: {1}".format(r.status_code, r.text))
	j = r.json()
	if 'access_token' not in j:
		raise cherrypy.HTTPError("502 Bad Gateway", "Facebook did not honour the credentials.")
	return j['access_token']

def verifyTokenFacebook(token):
	fbid = getSecret('facebook-id')
	fbsecret = getSecret('facebook-secret')
	payload = {'input_token': token,
	           'access_token': '{0}|{1}'.format(fbid, fbsecret)}
	r = requests.get('https://graph.facebook.com/debug_token', params=payload)
	if r.status_code != 200:
		raise cherrypy.HTTPError("502 Bad Gateway", "Facebook did not honour the credentials.")
	j = r.json()
	if j['data']['app_id'] != fbid:
		raise cherrypy.HTTPError("502 Bad Gateway", "The access token provided by Facebook was not valid.")
	if 'user_id' not in j['data']:
		raise cherrypy.HTTPError("502 Bad Gateway", "The access token provided by Facebook was not valid.")
	return j['data']['user_id']

class SpriteSheet(object):

	def __init__(self, name, variant='default', size=50):
		rootpath = '/home/public/images/sprites'
		sheetpath = "{0}/{1}/{2}_{3}px.png".format(rootpath, name, variant, size)
		datapath = "{0}/{1}/{2}_{3}px.txt".format(rootpath, name, variant, size)
		if ( (not os.path.isfile(sheetpath)) or (not os.path.isfile(datapath)) ):
			raise ValueError("The sprite sheet you requested could not be found.")
		self.data = Image.open(sheetpath)
		self.assets = {}
		re_data = re.compile(r'^(\S+) = (\d+) (\d+) (\d+) (\d+)$')
		with open(datapath) as f:
			for line in f:
				m = re_data.match(line)
				if m is None:
					raise ValueError("Invalid data file! This should never happen! (Line: {0})".format(line))
				name = m.group(1)
				x = int(m.group(2))
				y = int(m.group(3))
				width = int(m.group(4))
				height = int(m.group(5))
				self.assets[name] = (x, y, x+width, y+height)

	def get_asset(self, name):
		if name not in self.assets:
			raise ValueError("The given asset name does not exist.")
		return self.data.crop(self.assets[name])

def render(d):
	ss = SpriteSheet(d['spriteset'])
	if (isinstance(d['position'], str)):
		if (len(d['position']) % d['boardwidth'] != 0):
			raise ValueError("The 'position' needs to be evenly divisible by the 'boardwidth'.")
		board = [d['position'][i:i+d['boardwidth']] for i in range(0, len(d['position']), d['boardwidth'])]
		for i in range(len(board)):
			board[i] = list(board[i])

		#init the board
		border = 1
		margin = 5
		tare = border + margin
		size = 50
		cols = d['boardwidth']
		rows = len(d['position']) // d['boardwidth']
		im = Image.new('RGBA', (size*cols, size*rows), (0,0,0,0))

		#get the board assets
		dark = ss.get_asset('board-dark')
		light = ss.get_asset('board-light')
		if d['board'] == 'plain':
			dark = ss.get_asset('board-light')

		#lay out the board
		for row in range(rows):
			y = ((rows-1-row) * size)
			for col in range(cols):
				x = (size * col)
				if (row%2 == 0):
					if (col%2 == 0):
						im.paste(dark, box=(x,y), mask=dark)
					else:
						im.paste(light, box=(x,y), mask=light)
				else:
					if (col%2 == 0):
						im.paste(light, box=(x,y), mask=light)
					else:
						im.paste(dark, box=(x,y), mask=dark)
				#now place the piece
				piece = board[row][col]
				if piece != '-':
					name = piece
					if piece in d['legend']:
						name = d['legend'][piece]
					asset = ss.get_asset(name)
					im.paste(asset, box=(x,y), mask=asset)
		im = PIL.ImageOps.expand(im, border=border, fill=(0,0,0,255))
		im = PIL.ImageOps.expand(im, border=margin, fill=(0,0,0,0))
		return im

