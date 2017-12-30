#!/usr/bin/env python
# -*- coding:utf8 -*-
from flask import Blueprint

main = Blueprint('main',__name__)

from . import views, errors
from .models import Permission
from flask_login import current_user


#@main.app_context_processor
#def inject_permissions():
#    print dir(current_user) 
#    return dict(Permission=Permission)
