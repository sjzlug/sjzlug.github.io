#!/bin/bash

export config="dev"
echo $config

python manage.py runserver

