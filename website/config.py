#!/usr/bin/env pyton
# -*- coding:utf-8 -*-

import os, sys


System_Settings = {
    'pagination':{
        'per_page': int(os.environ.get('per_page', 15)),
    },
    'copyright': {
        'display_copyright': os.environ.get('allow_donate', 'true').lower() == 'true',
        'copyright_msg': os.environ.get('copyright_msg', 'The article is not allowed to repost unless author authorized').decode('utf8')
    },
}

class Config(object):
    DEBUG = True
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))

    SECRET_KEY = os.environ.get('SECRET_KEY') or 'fjdljLJDL08_80jflKzcznv*c'

    TEMPLATE_PATH = os.path.join(BASE_DIR, 'templates').replace('\\', '/')
    STATIC_PATH = os.path.join(BASE_DIR, 'static').replace('\\', '/')

    REDIS_URL = "redis://:@redis:6379/0"
    SQLALCHEMY_DATABASE_URI = 'sqlite:///'+ os.path.join(BASE_DIR,'data/data-dev.db') 
    print SQLALCHEMY_DATABASE_URI
    #SQLALCHEMY_DATABASE_URI = 'mysql://root:loc_data#123456@mysql:3306/loc_data'
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    #SQLALCHEMY_ECHO = True 
    SQLALCHEMY_ECHO = False 


    @staticmethod
    def init_app(app):
        pass

class DevConfig(Config):
    DEBUG = True
    REDIS_URL = "redis://:@192.168.2.221:8379/0"

class PrdConfig(Config):
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = 'mysql://root:ga#123456@mysql:3306/general_admin'
    SQLALCHEMY_ECHO = False 

config = {
    'dev': DevConfig,
    'prd': PrdConfig,
    'default': DevConfig,
}
