
from marshmallow import Schema, fields, ValidationError, pre_load
from .models import User,Cate

class UserSchema(Schema):
    id = fields.Str(dump_only=True)
    name = fields.Str() 
    pw = fields.Str()
    nick = fields.Str()
    avatar = fields.Str()
    status = fields.Int()
    sheme =  fields.Str()    
    roles = fields.Str()

class CateSchema(Schema):
    id = fields.Str(dump_only=True)
    name = fields.Str() 
    url = fields.Str()
    ico = fields.Str()
    order = fields.Int()
    parent = fields.Str()
    status = fields.Int()


