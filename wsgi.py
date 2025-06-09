# web server gateway interface

# before start, run these commands:
# cd app
# flask --app wsgi db init
# flask --app wsgi db migrate
# flask --app wsgi db upgrade
# flask --app init_postgres db downgrade

from app.init_postgres_main import app

# This allows Flask-Migrate to find your app
application = app
