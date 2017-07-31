import cherrypy
import lib.db
import json

import graphene
from graphene_sqlalchemy import SQLAlchemyObjectType
from graphql.error.format_error import format_error

## MODELS HERE

class User(SQLAlchemyObjectType):
	class Meta:
		model = lib.db.User

class NameHistory(SQLAlchemyObjectType):
	class Meta:
		model = lib.db.NameHistory

class GameInfo(SQLAlchemyObjectType):
	class Meta:
		model = lib.db.GameInfo

class Publisher(SQLAlchemyObjectType):
	class Meta:
		model = lib.db.Publisher

class GameStatus(SQLAlchemyObjectType):
	class Meta:
		model = lib.db.GameStatus

class GameVariant(SQLAlchemyObjectType):
	class Meta:
		model = lib.db.GameVariant

class GameTags(SQLAlchemyObjectType):
	class Meta:
		model = lib.db.GameTags

class Query(graphene.ObjectType):
	user = graphene.Field(User, userid=graphene.Int())
	users = graphene.List(User)
	gameinfo = graphene.Field(GameInfo, id=graphene.String())
	gamesinfo = graphene.List(GameInfo)
	publisher = graphene.Field(Publisher, id=graphene.Int())
	publishers = graphene.List(Publisher)

	def resolve_user(self, args, context, info):
		query = User.get_query(context) # SQLAlchemy query
		if args and 'userid' in args:
			query = query.filter(lib.db.User.userid == args['userid'])
		return query.first()

	def resolve_users(self, args, context, info):
		query = User.get_query(context) # SQLAlchemy query
		return query.all()

	def resolve_gameinfo(self, args, context, info):
		query = GameInfo.get_query(context) # SQLAlchemy query
		if args and 'id' in args:
			query = query.filter(lib.db.GameInfo.id == args['id'])
		return query.first()

	def resolve_gamesinfo(self, args, context, info):
		query = GameInfo.get_query(context) # SQLAlchemy query
		return query.all()

	def resolve_publisher(self, args, context, info):
		query = Publisher.get_query(context) # SQLAlchemy query
		if args and 'id' in args:
			query = query.filter(lib.db.Publisher.id == args['id'])
		return query.first()

	def resolve_publishers(self, args, context, info):
		query = Publisher.get_query(context) # SQLAlchemy query
		return query.all()

schema = graphene.Schema(query=Query)

## REQUEST HANDLING HERE
class GraphQL(object):
	exposed = True

	@property
	def db(self):
	    return cherrypy.request.db

	@cherrypy.tools.accept(media="application/json")
	@cherrypy.tools.json_out()
	def GET(self, query, **kwargs):
		variables = None
		if 'variables' in kwargs:
			variables = kwargs['variables']
		ops = None
		if 'operationName' in kwargs:
			ops = kwargs['operationName']

		result = schema.execute(query, context_value={'session': self.db}, variable_values=variables)

		errs = []
		if result.errors is not None:
			for error in result.errors:
				errs.append(format_error(error))

		if result.invalid:
			ret = {'errors': errs}
		elif len(errs) > 0:
			ret = {'data': result.data, 'errors': errs}
		else:
			ret = {'data': result.data}
		return ret



