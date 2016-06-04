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

	password = relationship("Password", uselist=False, back_populates="user")
	namehistory = relationship('NameHistory', back_populates="user")
	oauth = relationship("OAuth", back_populates="user")
	clients = relationship("Client", back_populates="user")
	authcodes = relationship("OAuthCode", back_populates="user")
	accesstokens = relationship("OAuthAccess", back_populates="user")
	refreshtokens = relationship("OAuthRefresh", back_populates="user")

	def __repr__(self):
		return "<User(id={0}, name={1}, created={2}, email={3}, namehistory={4}, oauth={5}, clients={6}, authcodes={7}, accesstokens={8}, refreshtokens={9})>".format(self.userid, self.username, self.date_created, self.email, self.namehistory, self.oauth, self.clients, self.authcodes, self.accesstokens, self.refreshtokens)
		#return self.to_JSON()

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


