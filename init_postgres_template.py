import secrets
import flask_login
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from forms import *
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_principal import Principal, Permission, RoleNeed, Identity, identity_changed, AnonymousIdentity

#pip install Flask SQLAlchemy psycopg2-binary

# before start, run these commands:
# flask --app init_postgres db init
# flask --app init_postgres db migrate
# flask --app init_postgres db upgrade
#flask --app init_postgres db downgrade

app = Flask(__name__)

# Set up database connection details
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:postgres@localhost:5432/test'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app_secret_key = secrets.token_urlsafe(32)
app.config['SECRET_KEY'] = app_secret_key


# Initialize SQLAlchemy
db = SQLAlchemy(app)
migrate = Migrate(app,db, render_as_batch=True)

class LogsModel(db.Model):
    log_id = db.Column(db.String(100), primary_key=True)
    user_id = db.Column(db.String(120))
    classification = db.Column(db.String(120), nullable=False)
    priority = db.Column(db.String(200), nullable=False)
    time = db.Column(db.String(120), nullable=False)
    target = db.Column(db.String(120), nullable=False)
    details = db.Column(db.String(200), nullable=False)


with app.app_context():
    db.create_all() # In case user table doesn't exists already. Else remove it.


@app.route('/')
def index():
    return render_template("index.html")

@app.route('/', subdomain='admin')
def admin_index():
    return render_template("admin_index.html")


if __name__ == '__main__':
    website_url = 'localhost:5000'
    app.config['SERVER_NAME'] = website_url
    app.run(debug=True)
