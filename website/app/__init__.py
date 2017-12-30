#!/usr/bin/env python
# -*- coding:utf8 -*-

import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy 
from config import config
from flask_login import LoginManager,current_user



db = SQLAlchemy()
login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'main.login'


def create_app(config_name):
    print "template path:%s" % config[config_name].TEMPLATE_PATH
    print "static path:%s" % config[config_name].STATIC_PATH

    app = Flask(__name__,
        template_folder=config[config_name].TEMPLATE_PATH,
        static_folder = config[config_name].STATIC_PATH )

    app.config.from_object(config[config_name])

    config[config_name].init_app(app)

    db.init_app(app)
    login_manager.init_app(app)

    from .main import main as  main_blueprint
    app.register_blueprint(main_blueprint)

    return app

app = create_app(os.getenv('config') or 'default') 
