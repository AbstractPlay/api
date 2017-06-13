#!/usr/local/bin/python3

import sys
sys.path.append('/home/protected/server')
import lib.db
import lib.common

import requests

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

engine = create_engine('mysql+pymysql://{0}@abstractplay.db:3306/sdg'.format(lib.common.getSecret('db-userpass')))
Session = sessionmaker(bind=engine)
s = Session()
for game in s.query(lib.db.GameInfo):
	#ping for latest state and detect changes
	url = game.url
	if (url is None):
		url = 'http://sdg-games.local:8080/' + game.id
	r_ping = requests.post(url, data={"mode": "ping"})
	isup = False
	js = None
	if r_ping.status_code == requests.codes.ok:
		isup = True
		js = r_ping.json()
	#log results
	entry = lib.db.GameStatus(gameid=game.id, msg=str(r_ping.status_code) + "\n" + r_ping.text, is_up=isup)
	s.add(entry)
	s.commit()
	#Validate JSON and check for state change
	if js is not None:
		#r_json = requests.post('https://sdg-api.local/debug')
		#compare current state with received state
		if game.state != js['state']:
			#fetch the new metadata
			r_meta = requests.post(url, data={"mode": "metadata"})
			if r_meta.status_code == requests.codes.ok:
				meta = r_meta.json()
				#update the database
				game.state = meta['state']
				game.version = meta['version']
				game.playercounts = ','.join([str(x) for x in meta['playercounts']])
				game.description = meta['description']
				game.changelog = meta['changelog']
				#TODO: MERGE VARIANTS
				s.commit()



