from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.types import String, Integer, Boolean, DateTime
import datetime
import json

Base = declarative_base()

class User(Base):
	__tablename__ = 'user'

	userid = Column(Integer, primary_key=True)
	username = Column(String)
	username_normalized = Column(String)
	date_created = Column(DateTime)
	email = Column(String)
	email_verified = Column(Boolean)
	deleted = Column(Boolean)
	date_deleted = Column(DateTime)
	country = Column(String)

	password = relationship("Password", uselist=False, back_populates="user")
	namehistory = relationship('NameHistory', back_populates="user")
	oauth = relationship("OAuth", back_populates="user")
	clients = relationship("Client", back_populates="user")
	authcodes = relationship("OAuthCode", back_populates="user")
	accesstokens = relationship("OAuthAccess", back_populates="user")
	refreshtokens = relationship("OAuthRefresh", back_populates="user")
	tags = relationship("GameTags", back_populates="user")

	def __repr__(self):
		return "<User(id={0}, name={1}, created={2}, email={3}, namehistory={4}, oauth={5}, clients={6}, authcodes={7}, accesstokens={8}, refreshtokens={9})>".format(self.userid, self.username, self.date_created, self.email, self.namehistory, self.oauth, self.clients, self.authcodes, self.accesstokens, self.refreshtokens)
		#return self.to_JSON()

	def to_public_resource(self):
		history = []
		for hist in self.namehistory:
			node = {}
			node['name'] = hist.name
			node['effective_date'] = hist.date_effective.isoformat()
			history.append(node)
		return {
			'id': self.userid,
			'name': self.username,
			'member_since': self.date_created.isoformat(),
			'country': self.country,
			'name_history': history
		}

	def to_dict(self):
		return {
			'type': "User",
			'id': self.userid,
			'name': self.username,
			'created': self.date_created.isoformat(),
			'email': self.email,
			'email_verified': self.email_verified,
			'deleted': self.deleted,
		}

	def to_JSON(self):
		return json.dumps({
			'type': "User",
			'id': self.userid,
			'name': self.username,
			'created': self.date_created.isoformat(),
			'email': self.email,
			'email_verified': self.email_verified,
			'deleted': self.deleted,
		})

class NameHistory(Base):
	__tablename__ = 'user_namehistory'

	id = Column(Integer, primary_key=True)
	userid = Column(Integer, ForeignKey('user.userid'))
	name = Column(String)
	date_effective = Column(DateTime)

	user = relationship("User", back_populates='namehistory')

	def __repr__(self):
		return "<NameHistory(name={0}, effective={1})>".format(self.name, self.date_effective)

class Password(Base):
	__tablename__ = 'user_passwords'

	id = Column(Integer, primary_key=True)
	userid = Column(Integer, ForeignKey('user.userid'))
	password = Column(String)

	user = relationship("User", back_populates='password')

class Country(Base):
	__tablename__ = 'meta_countries'

	code = Column(String, primary_key=True)
	name = Column(String)

class OAuth(Base):
	__tablename__ = 'user_oauth'

	id = Column(Integer, primary_key=True)
	userid = Column(Integer, ForeignKey('user.userid'))
	service = Column(String)
	foreignid = Column(String)

	user = relationship("User", back_populates="oauth")

	def __repr__(self):
		return "<OAuth(service={0}, foreignid={1})>".format(self.service, self.foreignid)

class Client(Base):
	__tablename__ = 'clients'

	clientid = Column(Integer, primary_key=True)
	userid = Column(Integer, ForeignKey('user.userid'))
	clientname = Column(String)
	app_id = Column(String)
	app_secret = Column(String)
	description = Column(String)

	user = relationship("User", back_populates="clients")
	redirects = relationship("Redirect", back_populates="client")
	authcodes = relationship("OAuthCode", back_populates="client")
	accesstokens = relationship("OAuthAccess", back_populates="client")
	refreshtokens = relationship("OAuthRefresh", back_populates="client")

	def __repr__(self):
		return "<Client(id={0}, clientname={1}, app_id={2}, app_secret={3}, description={4}, redirects={5})>".format(self.clientid, self.clientname, self.app_id, self.app_secret, self.description, self.redirects)

class Redirect(Base):
	__tablename__ = 'clients_redirects'

	id = Column(Integer, primary_key=True)
	clientid = Column(Integer, ForeignKey('clients.clientid'))
	URI = Column(String)

	client = relationship("Client", back_populates="redirects")

	def __repr__(self):
		return "<Redirects(id={0}, URI={1})>".format(self.id, self.URI)

class OAuthCode(Base):
	__tablename__ = 'oauth_codes'

	id = Column(Integer,  primary_key=True)
	clientid = Column(Integer, ForeignKey('clients.clientid'))
	userid = Column(Integer, ForeignKey('user.userid'))
	code = Column(String)
	expires = Column(DateTime)
	scopes = Column(String)
	redirect_uri = Column(String)

	client = relationship("Client", back_populates="authcodes")
	user = relationship("User", back_populates="authcodes")

	def __repr__(self):
		return "<OAuthCode(id={0}, clientid={1}, userid={2}, code={3}, expires={4}, scopes={5})>".format(self.id, self.clientid, self.userid, self.code, self.expires, self.scopes)

class OAuthAccess(Base):
	__tablename__ = 'oauth_access'

	id = Column(Integer,  primary_key=True)
	clientid = Column(Integer, ForeignKey('clients.clientid'))
	userid = Column(Integer, ForeignKey('user.userid'))
	token = Column(String)
	expires = Column(DateTime)
	scopes = Column(String)

	client = relationship("Client", back_populates="accesstokens")
	user = relationship("User", back_populates="accesstokens")
	refresh = relationship("OAuthRefresh", uselist=False, back_populates="access")

	def __repr__(self):
		return "<OAuthAccess(id={0}, clientid={1}, userid={2}, token={3}, expires={4}, scopes={5})>".format(self.id, self.clientid, self.userid, self.token, self.expires, self.scopes)

class OAuthRefresh(Base):
	__tablename__ = 'oauth_refresh'

	id = Column(Integer,  primary_key=True)
	clientid = Column(Integer, ForeignKey('clients.clientid'))
	userid = Column(Integer, ForeignKey('user.userid'))
	accessid = Column(Integer, ForeignKey('oauth_access.id'))
	token = Column(String)
	expires = Column(DateTime)
	scopes = Column(String)

	client = relationship("Client", back_populates="refreshtokens")
	user = relationship("User", back_populates="refreshtokens")
	access = relationship("OAuthAccess", back_populates="refresh")

	def __repr__(self):
		return "<OAuthRefresh(id={0}, clientid={1}, userid={2}, token={3}, expires={4}, scopes={5})>".format(self.id, self.clientid, self.userid, self.token, self.expires, self.scopes)

class Scope(Base):
	__tablename__ = 'scopes'

	name = Column(String, primary_key=True)
	description = Column(String)

class EmailVerify(Base):
	__tablename__ = 'email_verify'

	id = Column(Integer, primary_key=True)
	email = Column(String)
	code = Column(String)
	expires = Column(DateTime)

class GameInfo(Base):
	__tablename__ = 'games_info'

	id = Column(String, primary_key=True)
	name = Column(String)
	live_date = Column(DateTime)
	description = Column(String)
	url = Column(String)
	is_live = Column(Boolean)
	playercounts = Column(String)
	version = Column(Integer)
	state = Column(String)
	changelog = Column(String)
	publisherid = Column(Integer, ForeignKey("games_info_publishers.id"))
	rating = Column(Integer)

	publisher = relationship("Publisher", uselist=False, back_populates="games")
	status_history = relationship("GameStatus", back_populates="game")
	variants = relationship("GameVariant", back_populates="game")
	tags = relationship("GameTags", back_populates="game")

	def __repr__(self):
		return "<GameInfo(id={}, name={}, rating={}, live_date={}, description={}, url={}, is_live={}, playercounts={}, version={}, state={}, changelog={}, publisher={}, variants={})>".format(self.id, self.name, self.rating, self.live_date, self.description, self.url, self.is_live, self.playercounts, self.version, self.state, self.changelog, self.publisher, self.variants)

class Publisher(Base):
	__tablename__ = 'games_info_publishers'

	id = Column(Integer, primary_key=True)
	name = Column(String)
	url = Column(String)
	email_admin = Column(String)
	email_technical = Column(String)

	games = relationship("GameInfo", back_populates="publisher")

	def __repr__(self):
		return "<Publisher(id={}, name={}, url={}, email_admin={}, email_technical={})>".format(self.id, self.name, self.url, self.email_admin, self.email_technical)

class GameStatus(Base):
	__tablename__ = 'games_info_status'

	id = Column(Integer, primary_key=True)
	gameid = Column(String, ForeignKey("games_info.id"))
	timestamp = Column(DateTime)
	is_up = Column(Boolean)
	msg = Column(String)

	game = relationship("GameInfo", back_populates="status_history")

class GameVariant(Base):
	__tablename__ = 'games_info_variants'

	id = Column(Integer, primary_key=True)
	gameid = Column(String, ForeignKey("games_info.id"))
	name = Column(String)
	note = Column(String)
	group = Column(String)

	game = relationship("GameInfo", back_populates="variants")

class GameTags(Base):
	__tablename__ = 'games_info_tags'

	id = Column(Integer, primary_key=True)
	gameid = Column(String, ForeignKey("games_info.id"))
	userid = Column(Integer, ForeignKey("user.userid"))
	tag = Column(String)

	game = relationship("GameInfo", back_populates="tags")
	user = relationship("User", back_populates="tags")