#!/user/bin/env python
# -*- coding:utf8 -*-

from flask_wtf import FlaskForm
from wtforms import IntegerField,StringField,TextAreaField,PasswordField,BooleanField,SelectField,ValidationError,HiddenField
from wtforms.validators import Required,Length,Email,Regexp,EqualTo,URL,Optional
from flask_login import current_user

class UserLoginForm(FlaskForm):
    name = StringField("user name",validators=[Required()])
    pwd = StringField("user password",validators=[Required()])

class UserAddForm(FlaskForm):
    name = StringField("user name",validators=[Required()])
    nick = StringField("user nick")
    pwd = PasswordField('user Password', validators=[
        Required(), EqualTo('pwd2', message='passwords must match.')])
    pwd2 = PasswordField('Confirm password', validators=[Required()])
    roles = HiddenField("user roles") 

class UserEditForm(FlaskForm):
    nick = StringField("user nick")
    status = IntegerField("user status") 
    roles = HiddenField("user roles")

class UserChangeAvatar(FlaskForm):
    avatar = StringField("user avater",[Required()])

class UserChangePassword(FlaskForm):
    pwd_old = PasswordField('user old password',validators=[Required()])
    pwd = PasswordField('user new Password', validators=[
        Required(), EqualTo('pw2', message='passwords must match.')])
    pwd2 = PasswordField('Confirm new password', validators=[Required()])

class CateEditForm(FlaskForm):
    name = StringField("menu name",validators=[Required()])
    url = StringField("menu url",validators=[Required()])
    ico = StringField("menu icon")
    order = IntegerField("menu order")
    parent = HiddenField("menu parent")
    type = HiddenField("menu type",validators=[Required()])
    status = IntegerField("menu status",validators=[Required()]) 


