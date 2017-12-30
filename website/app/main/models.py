#!/usr/bin/env python
# -*- coding:utf8 -*-

from .. import db
from flask_login import UserMixin

class Permission:
    post = 0x01
    comment = 0x02
    edit_post = 0x04
    edit_comment = 0x08
    admin = 0x80

class User(db.Model,UserMixin):
    __tablename__ = "sys_users"
    id = db.Column(db.String(64),primary_key = True)
    name = db.Column(db.String(64))
    pw = db.Column(db.String(64))
    nick = db.Column(db.String(64))
    avatar = db.Column(db.String(64))
    status = db.Column(db.Integer)
    sheme = db.Column(db.String(64))
    roles = db.Column(db.String(64))

    def get_id(self):
        return self.id

    def __unicode__(self):
        return "<User %r>" % self.name

    def __prep__(self):
        return "<User %r>" % self.id

    def verify_password(self,password):
        return self.pw == password

    def can(self,permission):
        return permission in self.permission() 

    def permission(self):
        r = self.roles.split(',') 
        return r

class Cate(db.Model):
    __tablename__ = "sys_cates"
    id = db.Column(db.String(64),primary_key = True)
    name = db.Column(db.String(64))
    url = db.Column(db.String(128))
    ico = db.Column(db.String(64))
    order = db.Column(db.Integer)
    parent = db.Column(db.String(64),db.ForeignKey('sys_cates.id'),nullable = True)
    status = db.Column(db.Integer)
    subs = db.relationship('Cate',backref=db.backref('child',remote_side = id))

    def __unicode__(self):
        return "<User %r>" % self.name

class Post(db.Model):
    __tablename__ = "sys_posts"
    id = db.Column(db.String(64),primary_key = True)
    title = db.Column(db.String(255),default = "new post") 
    cate = db.Column(db.String(64),db.ForeignKey('sys_cates.id'))
    subcate = db.Column(db.String(64),db.ForeignKey('sys_cates.id'))
    pub_time = db.Column(db.DateTime) 
    update_time = db.Column(db.DateTime) 
    content_html = db.Column(db.Text)
    author = db.Column(db.String(255),db.ForeignKey('sys_users.id')) 
    tags = db.Column(db.String(255)) 
    status = db.Column(db.Integer)
    hits = db.Column(db.Integer,default = 0)
    comments = db.Column(db.Integer,default = 0)
    last_comment_author = db.Column(db.String(64),db.ForeignKey('sys_users.id'),nullable = True)
    last_comment_time = db.Column(db.DateTime,nullable = True)
    up = db.Column(db.Integer,default = 0)
    down = db.Column(db.Integer,default = 0)

    def __unicode__(self):
        return self.title

class Comment(db.Model):
    __tablename__ = "sys_comments"
    id = db.Column(db.String(64),primary_key = True)
    author = db.Column(db.String(64),db.ForeignKey('sys_users.id')) 
    postid = db.Column(db.String(64),db.ForeignKey('sys_posts.id')) 
    html_content = db.Column(db.Text)
    pub_time = db.Column(db.DateTime)
    update_time = db.Column(db.DateTime) 
    status = db.Column(db.Integer)







