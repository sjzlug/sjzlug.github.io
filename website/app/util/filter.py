#!/usr/bin/env python
# -*- coding:utf8 -*-

from .. import app

@app.template_filter()
def caps(text):
    return text.uppercase() 


@app.template_filter("make_menu")
def caps(text):
    return text.uppercase()
