import datetime
import html
import json
import os
import random
import urllib
from datetime import timedelta
from io import BytesIO

import bcrypt
import secrets

import flask
import flask_login
import pandas
from flask import Flask, render_template, request, redirect, url_for, session, flash, current_app, g, abort, \
    send_from_directory
from flask_migrate import Migrate
from flask_recaptcha import ReCaptcha
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from sqlalchemy import func, UniqueConstraint, or_
from sqlalchemy.exc import NoResultFound, IntegrityError
from sqlalchemy.orm import relationship, backref
from sqlalchemy.dialects.postgresql import ARRAY
from werkzeug.datastructures import FileStorage

from forms import *
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from Detection_System.sentinel import detect_path_traversal, detect_xss
from flask_principal import Principal, Permission, RoleNeed, Identity, identity_changed, AnonymousIdentity, \
    identity_loaded
from functools import wraps
import stripe
from werkzeug.datastructures import CombinedMultiDict
# from Crypto.Protocol.KDF import bcrypt, bcrypt_check
# from Crypto.Hash import SHA256
# from base64 import b64encode

# send email
from email.message import EmailMessage
import ssl
import smtplib

import urllib.parse

# setup 2fa
import pyotp

import Detection_System.sentinel as Sentinel
# pip install Flask SQLAlchemy psycopg2-binary
# pip install pandas openpyxl


import pandas as pd

from dotenv import load_dotenv

# before start, run these commands:
# flask --app init_postgres db init
# flask --app init_postgres db migrate
# flask --app init_postgres db upgrade
# flask --app init_postgres db downgrade

app = Flask(__name__)

# load environ vars
load_dotenv(dotenv_path='config/.env')

# Set up database connection details
SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI')

app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app_secret_key = secrets.token_urlsafe(32)
app.config['SECRET_KEY'] = app_secret_key

# configure recaptcha
RECAPTCHA_PUBLIC_KEY = os.getenv('RECAPTCHA_PUBLIC_KEY')
RECAPTCHA_PRIVATE_KEY = os.getenv('RECAPTCHA_PRIVATE_KEY')
app.config['RECAPTCHA_PUBLIC_KEY'] = RECAPTCHA_PUBLIC_KEY
app.config['RECAPTCHA_PRIVATE_KEY'] = RECAPTCHA_PRIVATE_KEY

# configure secure file upload
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 4  # 4mb max upload
app.config['UPLOAD_EXTENSIONS'] = ['.jpg', '.png', '.jpeg']

# configure limiter
limiter = Limiter(get_remote_address, app=app)

# setup pyotp
totp = pyotp.TOTP(pyotp.random_base32())

# configure flask login cookie protection
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(hours=2)

# only uncomment after https is setup, rmb to change link for the checkout to https
# app.config['SESSION_COOKIE_SECURE'] = True

# only uncomment after https is setup, rmb to change link for the checkout to https
# app.config['REMEMBER_COOKIE_SECURE'] = True

# cookie cannot be accessed by javascript on client side
app.config['SESSION_COOKIE_HTTPONLY'] = True

# cookie cannot be accessed by javascript on client side
app.config['REMEMBER_COOKIE_HTTPONLY'] = True

app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

# Initialize SQLAlchemy
db = SQLAlchemy(app)
migrate = Migrate(app, db, render_as_batch=True)

# setup login manager
login_manager = LoginManager()
login_manager.init_app(app)

# configure account lockout policy
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = 3  # 3 min

STRIPE_API_KEY = os.getenv('STRIPE_API_KEY')
stripe.api_key = STRIPE_API_KEY




# enable csrf protection
csrf = CSRFProtect(app)
csrf.init_app(app)

# enable flask talisman for http security headers
notserp_talisman = Talisman(app)

#
notserp_talisman.content_security_policy = Sentinel.HTTPSecurityHeaders.generate_csp()
# notserp_talisman.x_content_type_options = True

notserp_talisman.strict_transport_security_max_age = 15724800
notserp_talisman.strict_transport_security_include_subdomains = True
notserp_talisman.strict_transport_security_preload = True
# notserp_talisman.referrer_policy = "same-origin" #only include referrer info from same-origin request
notserp_talisman.frame_options = "DENY"  # do not load the page within an iframe

# Disable SSL verification for Stripe library
# stripe.verify_ssl_certs = False


# Create a simple model
class UserModel(db.Model, UserMixin):
    user_id = db.Column(db.String(100), primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(120), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    # this is for one way
    role_name = db.Column(db.String(100), db.ForeignKey('roles.rolename'))
    profile_pic = db.Column(db.String(200), nullable=False)

    # use .account to access the Account Model row
    account = db.relationship('AccountModel', backref='user_model', uselist=False)
    # this is for bidirectional relationship
    carts = db.relationship('CartModel', backref='user_model')
    forget_password_token = db.Column(db.String(200), server_default='None')
    otp_token = db.Column(db.String(200), server_default='None')
    lock_status = db.Column(db.String(80), server_default='Unlocked')
    failed_login_attempts = db.Column(db.Integer, server_default='0')
    locked_time = db.Column(db.DateTime, server_default=None)

    enable_2fa_email = db.Column(db.String(80), server_default='Not Enabled')

    # used for rmb me token
    alternative_token = db.Column(db.String(200), nullable=False, server_default='None')

    def __init__(self, user_id, username, email, phone, password, role, profile_pic):
        self.user_id = user_id
        self.username = username
        self.email = email
        self.phone = phone
        self.password = password
        self.profile_pic = profile_pic
        self.role_name = role

        if role == "USER":
            self.account = AccountModel(user=self)
        else:
            self.account = None

    def get_id(self):
        return self.user_id

    def get_username(self):
        return self.username

    def get_email(self):
        return self.email

    def get_phone(self):
        return self.phone

    def get_password(self):
        return self.password

    def get_role(self):
        return self.role_name

    def get_profile_pic(self):
        return self.profile_pic

    def get_account_id(self):
        return self.account

    def get_forget_password_token(self):
        return self.forget_password_token

    def get_otp_token(self):
        return self.otp_token

    def get_enable_2fa_email(self):
        return self.enable_2fa_email

    def get_alternative_token(self):
        return self.alternative_token

    def set_username(self, name):
        self.username = name

    def set_role(self, role):
        self.role_name = role

    def set_email(self, email):
        self.email = email

    def set_phone(self, phone):
        self.phone = phone

    def set_password(self, password):
        self.password = password

    def set_profile_pic(self, profile_pic):
        self.profile_pic = profile_pic

    def set_account_id(self, value):
        self.account = value

    def set_forget_password_token(self, value):
        self.forget_password_token = value

    def set_otp_token(self, value):
        self.otp_token = value

    def set_failed_login_attempts(self, attempts):
        self.failed_login_attempts = attempts

    def get_failed_login_attempts(self):
        return self.failed_login_attempts

    def failed_login_increment(self):
        login_attempts = self.get_failed_login_attempts() + 1
        self.set_failed_login_attempts(login_attempts)
        if self.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
            self.lock_status = "Locked"
            self.locked_time = datetime.datetime.now()

    def check_locked_time_done(self):
        if self.locked_time is None:
            return True
        elif self.locked_time is not None and self.locked_time + timedelta(
                minutes=LOCKOUT_DURATION) <= datetime.datetime.now():
            self.reset_account_after_lockdown()
            return True
        else:
            return False

    def reset_account_after_lockdown(self):
        self.lock_status = "Unlocked"
        self.locked_time = None

    def reset_failed_login_count(self):
        self.failed_login_attempts = 0
        self.lock_status = "Unlocked"

    def isLocked(self):
        if self.lock_status == "Locked":
            return True
        else:
            return False

    def add_new_column(self):
        self.locked_time = None
        self.lock_status = "Unlocked"
        self.failed_login_attempts = 0

    def set_enable_2fa_email(self, enabled):
        self.enable_2fa_email = enabled

    def set_alternative_token(self, token):
        self.alternative_token = token

class BlogModel(db.Model):
    id = db.Column(db.String(100), primary_key=True)
    user_id = db.Column(db.String(100), db.ForeignKey('user_model.user_id'), nullable=False)
    last_updated_by_user_id = db.Column(db.String(100), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.String(400), nullable=False)
    picture_name = db.Column(db.String(200), nullable=False)

    bloguser = relationship('UserModel', backref='blog_user')

    def __init__(self, user_who_submitted, title, description, picture_name):
        self.id = Sentinel.generate_blog_id()
        self.user_id = user_who_submitted.get_id()
        self.last_updated_by_user_id = user_who_submitted.get_id()
        self.title = title
        self.description = description
        self.picture_name = picture_name

    def get_id(self):
        return self.id

    def set_id(self, value):
        self.id = value

    def get_last_updated_user_id(self):
        return self.last_updated_by_user_id

    def set_last_updated_user_id(self, value):
        self.last_updated_by_user_id = value

    def get_user_id(self):
        return self.user_id

    def set_user_id(self, value):
        self.user_id = value

    def get_title(self):
        return self.title

    def set_title(self, value):
        self.title = value

    def get_description(self):
        return self.description

    def set_description(self, value):
        self.description = value

    def get_picture_name(self):
        return self.picture_name

    def set_picture_name(self, value):
        self.picture_name = value

# helper functions
# only admin can create blog post
def create_blog_post_helper(user_who_submitted, title, description, picture_name):
    new_blog_post = BlogModel(user_who_submitted, title, description, picture_name)
    db.session.add(new_blog_post)
    db.session.commit()
    return "Success"

def get_all_blog_post_helper():
    return db.session.execute(db.Select(BlogModel)).scalars()

# only admin can update the blog post
def update_blog_post_helper(blog_id, user_who_updated, title, description, picture_name):
    blog_to_update = db.session.execute(db.Select(BlogModel).filter_by(id=blog_id)).scalar_one()
    blog_to_update.set_last_updated_user_id(user_who_updated.get_id())
    blog_to_update.set_title(title)
    blog_to_update.set_description(description)
    blog_to_update.set_picture_name(picture_name)
    db.session.commit()
    return "Success"

# delete blog (only by admin or user who created it
def delete_blog_helper(blog_id):
    blog_to_delete = db.session.execute(db.Select(BlogModel).filter_by(id=blog_id)).scalar_one()
    db.session.delete(blog_to_delete)
    db.session.commit()
    return "Success"

class FeedbackModel(db.Model):
    feedback_id = db.Column(db.String(100), primary_key=True)
    user_id = db.Column(db.String(100), db.ForeignKey('user_model.user_id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.String(400), nullable=False)
    time_created = db.Column(db.DateTime, nullable=False)
    time_last_updated = db.Column(db.DateTime, nullable=False)

    feedbackuser = relationship('UserModel', backref='feedback_user')

    def __init__(self, user_who_created, title, description):
        self.feedback_id = Sentinel.generate_feedback_id()
        self.user_id = user_who_created.get_id()
        self.title = title
        self.description = description
        self.time_created = datetime.datetime.now()
        self.time_last_updated = datetime.datetime.now()

    def get_feedback_id(self):
        return self.feedback_id

    def set_feedback_id(self, value):
        self.feedback_id = value

    def get_user_id(self):
        return self.user_id

    def set_user_id(self, value):
        self.user_id = value

    def get_title(self):
        return self.title

    def set_title(self, value):
        self.title = value

    def get_description(self):
        return self.description

    def set_description(self, value):
        self.description = value

    def get_time_created(self):
        return self.time_created

    def set_time_created(self, value):
        self.time_created = value

    def get_time_last_updated(self):
        return self.time_last_updated

    def set_time_last_updated(self, value):
        self.time_last_updated = value


# helper functions
# feedback only for admin to see

# only to be used for USER roe
def create_feedback_helper(user_who_created, title, description):
    new_feedback = FeedbackModel(user_who_created, title, description)
    db.session.add(new_feedback)
    db.session.commit()
    return "Success"

def get_feedback_made_by_user(user_who_created):
    all_feedback_made_by_user = db.session.execute(db.Select(FeedbackModel).filter_by(user_id=user_who_created.get_id())).scalars()
    return all_feedback_made_by_user

def get_all_feedback_for_admin():
    all_feedback = db.session.execute(
        db.Select(FeedbackModel)).scalars()
    return all_feedback

# only for admin side
def update_specific_feedback(feedback_id, title, description):
    feedback_to_update = db.session.execute(db.Select(FeedbackModel).filter_by(feedback_id=feedback_id)).scalar_one()
    feedback_to_update.set_title(title)
    feedback_to_update.set_description(description)
    feedback_to_update.set_time_last_updated(datetime.datetime.now())
    db.session.commit()
    return "Success"

def delete_feedback_helper(feedback_id):
    feedback_to_delete = db.session.execute(db.Select(FeedbackModel).filter_by(feedback_id=feedback_id)).scalar_one()
    db.session.delete(feedback_to_delete)
    db.session.commit()
    return "Success"






class RoleModel(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.String(100), primary_key=True)
    rolename = db.Column(db.String(100), unique=True, nullable=False)
    superadmin_permission = db.Column(db.String(80), default='Unauthorized')
    financeadmin_permission = db.Column(db.String(80), default='Unauthorized')
    productadmin_permission = db.Column(db.String(80), default='Unauthorized')
    blogadmin_permission = db.Column(db.String(80), default='Unauthorized')
    pradmin_permission = db.Column(db.String(80), default='Unauthorized')
    user_permission = db.Column(db.String(80), default='Unauthorized')
    admin_permission = db.Column(db.String(80), default='Unauthorized')

    def __init__(self, rolename):
        self.id = Sentinel.generate_role_id()
        self.rolename = rolename

    def get_id(self):
        return self.id

    def get_rolename(self):
        return self.rolename

    def get_superadmin_permission(self):
        return self.superadmin_permission

    def set_superadmin_permission(self, value):
        self.superadmin_permission = value

    def get_financeadmin_permission(self):
        return self.financeadmin_permission

    def set_financeadmin_permission(self, value):
        self.financeadmin_permission = value

    def get_productadmin_permission(self):
        return self.productadmin_permission

    def set_productadmin_permission(self, value):
        self.productadmin_permission = value

    def get_blogadmin_permission(self):
        return self.blogadmin_permission

    def set_blogadmin_permission(self, value):
        self.blogadmin_permission = value

    def get_user_permission(self):
        return self.user_permission

    def set_user_permission(self, value):
        self.user_permission = value

    def get_admin_permission(self):
        return self.admin_permission

    def set_admin_permission(self, value):
        self.admin_permission = value

    def get_pradmin_permission(self):
        return self.pradmin_permission

    def set_pradmin_permission(self, value):
        self.pradmin_permission = value

    def set_id(self, value):
        self.id = value

    def set_rolename(self, value):
        self.rolename = value


class LogsModel(db.Model):
    log_id = db.Column(db.String(100), primary_key=True)
    user_id = db.Column(db.String(120))
    classification = db.Column(db.String(120), nullable=False)
    priority = db.Column(db.String(200), nullable=False)
    time = db.Column(db.DateTime, nullable=False)
    target = db.Column(db.String(500), nullable=False)
    details = db.Column(db.String(200), nullable=False)
    source_ip = db.Column(db.String(160), nullable=False)

    def get_log_id(self):
        return self.log_id

    def get_user_id(self):
        return self.user_id

    def get_classification(self):
        return self.classification

    def get_priority(self):
        return self.priority

    def get_time(self):
        return self.time

    def get_target(self):
        return self.target

    def get_details(self):
        return self.details

    def get_source_ip(self):
        return self.source_ip


class EVIRECModel(db.Model):
    evirec_id = db.Column(db.String(100), primary_key=True)
    log_id = db.Column(db.String(120), db.ForeignKey('logs_model.log_id'))
    path_name = db.Column(db.String(120), nullable=False)
    user_who_added = db.Column(db.String(100), db.ForeignKey('user_model.user_id'), nullable=False)
    time = db.Column(db.DateTime, nullable=False)
    time_updated = db.Column(db.DateTime, nullable=False)
    description = db.Column(db.String(200), nullable=False, default='None')

    # now to access associated log, just use evirec.log.get_user_id() or whatever function
    log = relationship('LogsModel', backref='evirec')
    user = relationship('UserModel', backref='evirec_user')

    def __init__(self, logid, pathname, description):
        self.evirec_id = Sentinel.generate_evirec_id()
        self.log_id = logid
        self.path_name = pathname
        self.user_who_added = flask_login.current_user.get_id()
        self.time = datetime.datetime.now()
        self.time_updated = datetime.datetime.now()
        self.description = description

    def get_evirec_id(self):
        return self.evirec_id

    def set_evirec_id(self, evirec_id):
        self.evirec_id = evirec_id

    def get_log_id(self):
        return self.log_id

    def set_log_id(self, log_id):
        self.log_id = log_id

    def get_path_name(self):
        return self.path_name

    def set_path_name(self, path_name):
        self.path_name = path_name

    def get_user_who_added(self):
        return self.user_who_added

    def set_user_who_added(self, value):
        self.user_who_added = value

    def get_time(self):
        return self.time

    def get_description(self):
        return self.description

    def set_description(self, value):
        self.description = value

    def get_time_updated(self):
        return self.time_updated

    def set_time_updated(self, value):
        self.time_updated = value


class AccountModel(db.Model):
    account_id = db.Column(db.String(100), primary_key=True)
    user_id = db.Column(db.String(100), db.ForeignKey('user_model.user_id'), nullable=False)
    points_balance = db.Column(db.Integer, nullable=False)
    vouchers = db.Column(db.JSON, nullable=False)

    def __init__(self, user):
        self.account_id = "ACCT_" + str(secrets.token_urlsafe(32))
        self.user_id = user.user_id
        self.points_balance = 0
        self.vouchers = {}

    def get_id(self):
        return self.account_id

    def set_id(self, value):
        self.account_id = value

    def get_user_id(self):
        return self.user_id

    def set_user_id(self, value):
        self.user_id = value

    def get_points_balance(self):
        return self.points_balance

    def set_points_balance(self, value):
        self.points_balance = value

    def get_vouchers(self):
        return self.vouchers

    def set_vouchers(self, value):
        self.vouchers = value

class TransactionModel(db.Model):
    transaction_id = db.Column(db.String(100), primary_key=True)
    account_id = db.Column(db.String(100), db.ForeignKey('account_model.account_id'), nullable=False)
    time = db.Column(db.DateTime, nullable=False)
    product_name = db.Column(db.String(100), nullable=False)
    product_id = db.Column(db.String(100), nullable=False)
    product_quantity = db.Column(db.Integer, nullable=False)
    unit_price = db.Column(db.Float, nullable=False)

    def __init__(self, account_id, time, product_name, product_id, product_quantity, unit_price):
        self.transaction_id = Sentinel.generate_transaction_id()
        self.account_id = account_id
        self.time = time
        self.product_name = product_name
        self.product_id = product_id
        self.product_quantity = product_quantity
        self.unit_price = unit_price


class InventoryModel(db.Model):
    product_id = db.Column(db.String(100), primary_key=True)
    product_name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    unit_price = db.Column(db.Float, nullable=False)
    product_stripe_id = db.Column(db.String(100), nullable=False, )
    price_stripe_id = db.Column(db.String(100), nullable=False)
    product_pic = db.Column(db.String(200), nullable=False)

    __table_args__ = (
        db.UniqueConstraint('product_stripe_id', name='uq_inventory_product_stripe_id'),
    )

    # this is to enable inventory.carts to access attribute of cart

    carts = relationship('CartModel', backref='product_from_inventory', lazy=True)

    def __init__(self, product_id, product_name, description, quantity, unit_price, product_stripe_id, price_stripe_id,
                 product_pic):
        self.product_id = product_id
        self.product_name = product_name
        self.description = description
        self.quantity = quantity
        self.unit_price = unit_price
        self.product_stripe_id = product_stripe_id
        self.price_stripe_id = price_stripe_id
        self.product_pic = product_pic

    def get_product_id(self):
        return self.product_id

    def set_product_id(self, value):
        self.product_id = value

    def get_product_name(self):
        return self.product_name

    def set_product_name(self, value):
        self.product_name = value

    def get_description(self):
        return self.description

    def set_description(self, value):
        self.description = value

    def get_quantity(self):
        return self.quantity

    def set_quantity(self, value):
        self.quantity = value

    def get_unit_price(self):
        return self.unit_price

    def set_unit_price(self, value):
        self.unit_price = value

    def get_product_stripe_id(self):
        return self.product_stripe_id

    def set_product_stripe_id(self, value):
        self.product_stripe_id = value

    def get_price_stripe_id(self):
        return self.price_stripe_id

    def set_price_stripe_id(self, value):
        self.price_stripe_id = value

    def get_product_pic(self):
        return self.product_pic

    def set_product_pic(self, value):
        self.product_pic = value

# on initiating creation of voucher, it will produce a random code
class VoucherInventoryModel(db.Model):
    voucher_id = db.Column(db.String(100), primary_key=True)
    voucher_name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    percent = db.Column(db.Integer, nullable=False)
    date_of_creation = db.Column(db.DateTime, nullable=False)
    latest_updated_date = db.Column(db.DateTime, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    unit_points_needed = db.Column(db.Float, nullable=False)


    # this is to enable inventory.carts to access attribute of cart


    voucher_carts = relationship('VoucherCartModel', backref='voucher_from_inventory', lazy=True)

    def __init__(self, name, description, percent, quantity, unit_points_needed):
        self.voucher_id = Sentinel.generate_voucher_id()
        self.voucher_name = name
        self.description = description
        self.percent = percent
        self.date_of_creation = datetime.datetime.now()
        self.latest_updated_date = datetime.datetime.now()
        self.quantity = quantity
        self.unit_points_needed = unit_points_needed

    def get_voucher_id(self):
        return self.voucher_id

    def set_voucher_id(self, voucher_id):
        self.voucher_id = voucher_id

    def get_voucher_name(self):
        return self.voucher_name

    def set_voucher_name(self, voucher_name):
        self.voucher_name = voucher_name

    def get_percent(self):
        return self.percent

    def set_percent(self, percent):
        self.percent = percent

    def get_date_of_creation(self):
        return self.date_of_creation

    def get_latest_updated_date(self):
        return self.latest_updated_date

    def set_latest_updated_date(self, date):
        self.latest_updated_date = date

    def get_description(self):
        return self.description

    def set_description(self, description):
        self.description = description

    def get_quantity(self):
        return self.quantity

    def set_quantity(self, quantity):
        self.quantity = quantity

    def get_unit_points_needed(self):
        return self.unit_points_needed

    def set_unit_points_needed(self, unit_points_needed):
        self.unit_points_needed = unit_points_needed


# assume that voucher will auto assign code to the user based on quantity
class VoucherCartModel(db.Model):
    voucher_cart_id = db.Column(db.String(100), primary_key=True)
    user_id = db.Column(db.String(100), db.ForeignKey('user_model.user_id'), nullable=False)
    coupon_stripe_id = db.Column(db.String(100), nullable=False)
    voucher_inventory_voucher_id = db.Column(db.String(100), db.ForeignKey('voucher_inventory_model.voucher_id'), nullable=False)



    # e.g. VoucherCartModel = VoucherCartModel.voucher_inventory
    voucher_inventory = relationship("VoucherInventoryModel", backref=backref("voucher_from_voucher_cart", uselist=False), lazy=True,
                             foreign_keys=[voucher_inventory_voucher_id])

    def __init__(self, user, voucher_id, stripe_coupon_id):
        self.voucher_cart_id = Sentinel.generate_voucher_cart_id()
        self.user_id = user.user_id
        self.voucher_inventory_voucher_id = voucher_id
        self.coupon_stripe_id = stripe_coupon_id


    def get_voucher_cart_id(self):
        return self.voucher_cart_id

    def set_voucher_cart_id(self, voucher_cart_id):
        self.voucher_cart_id = voucher_cart_id

    def get_user_id(self):
        return self.user_id

    def set_user_id(self, user_id):
        self.user_id = user_id

    def get_voucher_inventory_voucher_id(self):
        return self.voucher_inventory_voucher_id

    def set_voucher_inventory_voucher_id(self, voucher_inventory_voucher_id):
        self.voucher_inventory_voucher_id = voucher_inventory_voucher_id

    def get_coupon_stripe_id(self):
        return self.coupon_stripe_id

    def set_coupon_stripe_id(self, stripe_id):
        self.coupon_stripe_id = stripe_id

    def get_voucher_name(self):
        return self.voucher_inventory.get_voucher_name()

    def get_voucher_description(self):
        return self.voucher_inventory.get_description()

# helper functions for voucher
def create_voucher_blueprint_admin(name, desc, percent, quantity, points_needed):
    # creating the voucher blueprint so that can generate
    new_voucher = VoucherInventoryModel(
        name=name,
        description=desc,
        percent=percent,
        quantity=quantity,
        unit_points_needed=points_needed,
    )
    db.session.add(new_voucher)
    db.session.commit()
    return "Success"

def get_all_admin_voucher_blueprints():
    all_vouchers = db.session.execute(db.Select(VoucherInventoryModel)).scalars()
    return all_vouchers

def update_voucher_blueprint_admin(voucher_blueprint_id, name, desc, percent, quantity, points_needed):
    voucher_to_update = db.session.execute(db.Select(VoucherInventoryModel).filter_by(voucher_id=voucher_blueprint_id)).scalar_one()
    voucher_to_update.set_voucher_name(name)
    voucher_to_update.set_description(desc)
    voucher_to_update.set_percent(percent)
    voucher_to_update.set_quantity(quantity)
    voucher_to_update.set_unit_points_needed(points_needed)
    voucher_to_update.set_latest_updated_date(datetime.datetime.now())
    db.session.commit()
    return "Success"

def delete_voucher_blueprint_admin(voucher_blueprint_id):
    voucher_to_delete = db.session.execute(db.Select(VoucherInventoryModel).filter_by(voucher_id=voucher_blueprint_id)).scalar_one()
    db.session.delete(voucher_to_delete)
    db.session.commit()
    return "Success"

def check_sufficient_points(curr_user, amount_needed):
    current_usr_balance = curr_user.account.get_points_balance()
    amount_needed = amount_needed
    if current_usr_balance >= amount_needed:
        curr_user.account.set_points_balance(current_usr_balance-amount_needed)
        db.session.commit()
        return True
    else:
        return False

def redeem_code_for_points(curr_user, amount):
    current_usr_balance = curr_user.account.get_points_balance()
    curr_user.account.set_points_balance(current_usr_balance + amount)
    db.session.commit()
    return "Success"

def generate_voucher_user(voucher_blueprint_id, user_obj):

    voucher_to_create = db.session.execute(db.Select(VoucherInventoryModel).filter_by(voucher_id=voucher_blueprint_id)).scalar_one()

    if check_sufficient_points(user_obj, voucher_to_create.get_unit_points_needed()):
        print("Here")
        voucher_to_decrease_quantity = db.session.execute(db.Select(VoucherInventoryModel).filter_by(voucher_id=voucher_to_create.get_voucher_id())).scalar_one()
        voucher_to_decrease_quantity_current_quant = voucher_to_decrease_quantity.get_quantity()
        voucher_to_decrease_quantity.set_quantity(voucher_to_decrease_quantity_current_quant-1)
        stripe_coupon = stripe.Coupon.create(
            percent_off=voucher_to_create.get_percent(),
            currency="sgd",
            name=voucher_to_create.get_voucher_name(),
        )
        new_voucher = VoucherCartModel(user=user_obj,
                                       voucher_id=voucher_blueprint_id,
                                       stripe_coupon_id=stripe_coupon["id"])
        db.session.add(new_voucher)
        db.session.commit()
        return "Success"

    else:
        return "Unsuccessful"

def get_all_user_voucher_can_redeem():
    all_user_vouchers = db.session.execute(db.Select(VoucherInventoryModel).filter(VoucherInventoryModel.quantity>0)).scalars()
    #all_vouchers_related = db.session.execute(db.Select(VoucherCartModel).filter_by(VoucherCartModel.quantity > 0)).scalars()
    return all_user_vouchers

def check_if_user_has_enough_points_for_voucher(user_obj, voucher_obj):
    current_usr_balance = user_obj.account.get_points_balance()
    amount_needed = voucher_obj.get_unit_points_needed()
    if current_usr_balance >= amount_needed:
        return True
    else:
        return False

def get_all_user_voucher(user_obj):
    all_user_vouchers = db.session.execute(db.Select(VoucherCartModel).filter_by(user_id=user_obj.get_id())).scalars()
    return all_user_vouchers



def redeem_voucher(stripe_code):

    voucher_to_use = db.session.execute(db.Select(VoucherCartModel).filter_by(coupon_stripe_id=stripe_code)).scalar_one()

    # delete stripe obj
    stripe.Coupon.delete(voucher_to_use.get_coupon_stripe_id())

    # delete voucher from cart
    db.session.delete(voucher_to_use)
    db.session.commit()
    return "Success"


# stores all products in all carts
# must filter and get by user_id
class CartModel(db.Model):
    cart_id = db.Column(db.String(100), primary_key=True)
    user_id = db.Column(db.String(100), db.ForeignKey('user_model.user_id'), nullable=False)
    inventory_product_id = db.Column(db.String(100), db.ForeignKey('inventory_model.product_id'), nullable=False)
    product_stripe_id = db.Column(db.String(100), nullable=False)
    price_stripe_id = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)

    # use this attribute to access the equivalent inside the inventory db
    # from the Inventory model, now you can access cart attributes using the attribute cart

    # e.g. inventory = cart.inventory
    inventory = relationship("InventoryModel", backref=backref("product_from_cart", uselist=False), lazy=True,
                             foreign_keys=[inventory_product_id])

    def __init__(self, user, product_id, product_stripe_id, price_stripe_id, quantity):
        self.cart_id = "CART_" + str(secrets.token_urlsafe(32))
        self.user_id = user.user_id
        self.inventory_product_id = product_id
        self.product_stripe_id = product_stripe_id
        self.price_stripe_id = price_stripe_id
        self.quantity = quantity

    def get_cart_id(self):
        return self.cart_id

    def get_inventory_product_id(self):
        return self.inventory_product_id

    def get_product_stripe_id(self):
        return self.product_stripe_id

    def set_product_stripe_id(self, product_stripe_id):
        self.product_stripe_id = product_stripe_id

    def get_price_stripe_id(self):
        return self.price_stripe_id

    def set_inventory_product_id(self, value):
        self.inventory_product_id = value

    def set_price_stripe_id(self, price_stripe_id):
        self.price_stripe_id = price_stripe_id

    def get_quantity(self):
        return self.quantity

    def set_quantity(self, quantity):
        self.quantity = quantity


class AuthenticationModel(db.Model):
    auth_id = db.Column(db.String(100), primary_key=True)
    user_id = db.Column(db.String(100), nullable=False)
    one_time_pass = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.now())
    expiration_date = db.Column(db.DateTime, nullable=False)

    def __init__(self, user_id, one_time_pass, created_at, expiration_date):
        self.auth_id = Sentinel.generate_auth_id()
        self.user_id = user_id
        self.one_time_pass = one_time_pass
        self.created_at = created_at
        self.expiration_date = expiration_date

    def get_auth_id(self):
        return self.auth_id

    def set_auth_id(self, value):
        self.auth_id = value

    def get_user_id(self):
        return self.user_id

    def set_user_id(self, value):
        self.user_id = value

    def get_one_time_pass(self):
        return self.one_time_pass

    def set_one_time_pass(self, value):
        self.one_time_pass = value

    def get_created_at(self):
        return self.created_at

    def set_created_at(self, value):
        self.created_at = value

    def get_expiration_date(self):
        return self.expiration_date

    def set_expiration_date(self, value):
        self.expiration_date = value




with app.app_context():
    db.create_all()  # In case user table doesn't exists already. Else remove it.


# setup the user loader
@login_manager.user_loader
def load_user(user_id):
    return UserModel.query.filter_by(user_id=user_id).first()


# custom rbac system
def roles_required(*required_roles):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)  # unauthorized

            # check if current user role has the relevant permission
            current_user_role = current_user.get_role()

            # get role permissions from rolemodel
            role_permission = db.session.execute(
                db.select(RoleModel).filter_by(rolename=current_user_role)).scalar_one()

            # check if superadmin because instant access
            if role_permission.get_superadmin_permission() == "Authorized":
                return func(*args, **kwargs)

            # if required role is ADMIN and role_permission has admin_permission
            if "ADMIN" in required_roles and role_permission.get_admin_permission() == "Authorized":
                return func(*args, **kwargs)
            elif "SUPER_ADMIN" in required_roles and role_permission.get_superadmin_permission() == "Authorized":
                return func(*args, **kwargs)
            elif "FINANCE_ADMIN" in required_roles and role_permission.get_financeadmin_permission() == "Authorized":
                return func(*args, **kwargs)
            elif "PRODUCT_ADMIN" in required_roles and role_permission.get_productadmin_permission() == "Authorized":
                return func(*args, **kwargs)
            elif "BLOG_ADMIN" in required_roles and role_permission.get_blogadmin_permission() == "Authorized":
                return func(*args, **kwargs)
            elif "PR_ADMIN" in required_roles and role_permission.get_pradmin_permission() == "Authorized":
                return func(*args, **kwargs)
            elif "USER" in required_roles and role_permission.get_user_permission() == "Authorized":
                return func(*args, **kwargs)
            abort(403)  # Forbidden

        return wrapper

    return decorator


# jinja function to check required roles
def check_permission(user, required_role):
    user_role = user.get_role()

    # get the role permissions
    role_permission = db.session.execute(
        db.select(RoleModel).filter_by(rolename=user_role)).scalar_one()
    if role_permission.get_superadmin_permission() == "Authorized":
        return True
    elif required_role == "ADMIN" and role_permission.get_admin_permission() == "Authorized":
        return True
    elif required_role == "SUPER_ADMIN" and role_permission.get_superadmin_permission() == "Authorized":
        return True
    elif required_role == "FINANCE_ADMIN" and role_permission.get_financeadmin_permission() == "Authorized":
        return True
    elif required_role == "PRODUCT_ADMIN" and role_permission.get_productadmin_permission() == "Authorized":
        return True
    elif required_role == "BLOG_ADMIN" and role_permission.get_blogadmin_permission() == "Authorized":
        return True
    elif required_role == "PR_ADMIN" and role_permission.get_pradmin_permission() == "Authorized":
        return True
    elif required_role == "USER" and role_permission.get_user_permission() == "Authorized":
        return True
    else:
        return False

app.jinja_env.globals.update(check_permission=check_permission)
app.jinja_env.globals.update(check_if_user_has_enough_points_for_voucher=check_if_user_has_enough_points_for_voucher)
app.jinja_env.globals.update(len=len)

# product creation
def create_stripe_product_obj(name, description, price):
    new_product = stripe.Product.create(
        name=name,
        description=description,
    )

    # need to create the price obj to attach to product
    price = stripe.Price.create(
        product=new_product.id,
        unit_amount=int(price * 100),  # in cents
        currency="sgd"
    )

    return price


def create_product(product_id, product_name, description, quantity, unit_price,
                   product_pic):
    price_obj = create_stripe_product_obj(name=product_name, description=description, price=unit_price)

    new_product = InventoryModel(
        product_id=product_id,
        product_name=product_name,
        description=description,
        quantity=quantity,
        unit_price=unit_price,
        product_stripe_id=price_obj["product"],
        price_stripe_id=price_obj["id"],
        product_pic=product_pic
    )
    db.session.add(new_product)
    db.session.commit()



# since all buttons and routes for product page will pass a product_id variable for this function

# 2 functions below will get from the inventory of products and voucher
def retrieve_product(product_id):
    product = InventoryModel.query.filter_by(product_id=product_id).first()
    return product



# helper functions

# doing the login style format to popup form to update product
def update_product_helper(product_id, product_name, description, quantity, unit_price,
                          product_pic):
    product = InventoryModel.query.filter_by(product_id=product_id).first()

    # call the setters
    product.set_product_name(product_name)
    product.set_description(description)
    product.set_quantity(quantity)
    product.set_unit_price(unit_price)
    product.set_product_pic(product_pic)

    # need to update stripe price and product obj just in case
    stripe_product_id = product.get_product_stripe_id()
    stripe.Product.modify(stripe_product_id,
                          name=product_name,
                          description=description)

    stripe_price_id = product.get_price_stripe_id()
    # stripe.Price.modify(stripe_price_id,
    #                     transform_data={"unit_amount": int(unit_price * 100)})  # assume unit_price is in dollar
    # need to create the price obj to attach to product

    # need to recreate stripe price

    # first delete existing one
    stripe.Price.modify(stripe_price_id,
                        active=False)

    # create new one
    price = stripe.Price.create(
        product=stripe_product_id,
        unit_amount=int(unit_price * 100),  # in cents
        currency="sgd"
    )

    product.set_price_stripe_id(price["id"])

    db.session.commit()

    return "Successful"

# update the voucher specs in the inventory
# def update_voucher_helper(voucher_id, voucher_name, voucher_desc, quantity, points_needed):
#     voucher = VoucherInventoryModel.query.filter_by(voucher_id=voucher_id).first()
#
#     # call setters
#     voucher.set_voucher_name(voucher_name)
#     voucher.set_description(voucher_desc)
#     voucher.set_quantity(quantity)
#     voucher.set_unit_points_needed(points_needed)
#
#     db.session.commit()
#
#     return "Successful"


def delete_product_helper(prod_id):
    product = InventoryModel.query.filter_by(product_id=prod_id).first()

    # must delete the stripe price obj first
    # stripe.Price.delete(product.get_price_stripe_id())
    stripe.Price.modify(product.get_price_stripe_id(),
                        active=False)

    # then delete stripe product obj
    stripe.Product.modify(product.get_product_stripe_id(), active=False)

    # delete from Inventory
    db.session.delete(product)
    db.session.commit()

# delete from inventory
# def delete_voucher_helper(voucher_id):
#     voucher = VoucherInventoryModel.query.filter_by(voucher_id=voucher_id).first()
#     db.session.delete(voucher)
#     db.session.commit()


# additional helper function for voucher stuff

# so when user clicks button, it will auto check for the user based on points required and quantity, then add
# so technically just need modal for checkout to specify the quantity that you want

# def get_only_available_vouchers():
#     # returns only vouchers that are in stock
#     all_vouchers_related = db.session.execute(db.Select(VoucherCartModel).filter_by(VoucherCartModel.quantity > 0)).scalars()
#
#     return all_vouchers_related

# gets all vouchers that user has
# def get_current_user_vouchers(current_usr):
#     curr_usr_id = current_usr.get_id()
#
#     # search for all vouchers in VoucherCartModel for the vouchers
#     all_vouchers_related = db.session.execute(db.Select(VoucherCartModel).filter_by(user_id=curr_usr_id)).scalars()
#
#     return all_vouchers_related


# html form should limit the quantity based on how much voucher is left as negative is impossible
# def add_voucher_to_cart(current_usr, voucher_id, quantity):
#     curr_usr_id = current_usr.get_id()
#
#     # gets the voucher to be added from inventory
#     voucher_to_add = db.session.execute(db.Select(VoucherInventoryModel).filter_by(voucher_id=voucher_id)).scalar_one_or_none()
#
#     # decrease quantity
#     current_voucher_quantity = voucher_to_add.get_quantity()
#     new_quantity = current_voucher_quantity - quantity
#     voucher_to_add.set_quantity(new_quantity)
#
#     #assume that we already have a list of valid codes
#     # each voucher should have unique code
#     for i in range(quantity):
#         voucher_code = Sentinel.generate_secure_voucher_code()
#
#         # add to the VoucherCartModel
#         new_voucher_in_cart = VoucherCartModel(user=current_usr,
#                                                voucher_id=voucher_id,
#                                                quantity=1,
#                                                code=voucher_code)
#
#         db.session.add(new_voucher_in_cart)
#         db.session.commit()
#
# def remove_voucher_from_cart(voucher_cart_id):
#     voucher_to_remove_from_cart = db.session.execute(
#         db.Select(VoucherCartModel).filter_by(voucher_cart_id=voucher_cart_id)).scalar_one_or_none()
#
#     db.session.delete(voucher_to_remove_from_cart)
#     db.session.commit()
#
#
#
#
#
# def voucher_checkout(curr_usr, voucher_id, quantity):
#     voucher_to_add = db.session.execute(
#         db.Select(VoucherInventoryModel).filter_by(voucher_id=voucher_id)).scalar_one_or_none()
#
#     # check points required
#     total_points_needed = voucher_to_add.get_unit_points_needed() * quantity
#
#     if check_sufficient_points(curr_usr, total_points_needed):
#         add_voucher_to_cart(curr_usr,voucher_id,quantity)
#     else:
#         return "Insufficient points"




def add_to_log(classification, target_route, priority, details):
    log_id = "LOGS_" + secrets.token_urlsafe()
    time = datetime.datetime.now().isoformat()
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    usr_id = current_user.get_id() if current_user.get_id() is not None else "None"
    unauthorized_entry = LogsModel(log_id=log_id, user_id=usr_id, classification=classification,
                                   priority=priority, time=time, target=html.escape(target_route), details=details,
                                   source_ip=client_ip)
    db.session.add(unauthorized_entry)
    db.session.commit()


def populate_five_days_logs():
    current_time = datetime.datetime.now()
    one_day = datetime.timedelta(days=1)
    random_days = datetime.timedelta(days=random.randint(1, 5))
    for i in range(5):
        current_time = current_time + random_days

        for j in range(random.randint(10, 30)):
            unauthorized_entry = LogsModel(
                log_id="LOGS_" + secrets.token_urlsafe(),
                user_id=current_user.get_id() if current_user.get_id() is not None else "None",
                classification=random.choice(["JOB", "PATH TRAVERSAL", "CROSS-SITE SCRIPTING"]),
                priority=random.choice([0, 1, 2, 3]),
                time=current_time.isoformat(),
                target=html.escape("http://testing"),
                details="TEST DATA",
                source_ip="113.123.1.7"
            )
            db.session.add(unauthorized_entry)
            db.session.commit()


# cart helper function

def add_to_cart_helper(product_stripe_id, quantity, user_id):
    # need to search for product by id
    product_to_add = db.session.execute(
        db.Select(InventoryModel).filter_by(product_stripe_id=product_stripe_id)).scalar_one()

    # then need to modify by decreasing quantity in inventory
    current_quantity = product_to_add.get_quantity()

    # decrease quantity by how much is added to cart
    new_quantity = current_quantity - quantity

    # set new quantity in db
    product_to_add.set_quantity(new_quantity)

    # get current user

    user_buying = db.session.execute(db.Select(UserModel).filter_by(user_id=user_id)).scalar_one()

    # then we need to add to cart model
    new_cart_item = CartModel(user=user_buying,
                              product_id=product_to_add.get_product_id(),
                              product_stripe_id=product_to_add.get_product_stripe_id(),
                              price_stripe_id=product_to_add.get_price_stripe_id(),
                              quantity=quantity)

    # def init(self, user, product_id, product_stripe_id, price_stripe_id, quantity):

    db.session.add(new_cart_item)

    db.session.commit()

    # self, user, product_stripe_id, price_stripe_id, quantity


def remove_from_cart_helper(cart_id, quantity):
    # need to search for product by id in cart
    product_to_remove = db.session.execute(
        db.Select(CartModel).filter_by(cart_id=cart_id)).scalar_one()

    # need to search for product by id in inventory
    product_stripe_id = product_to_remove.get_product_stripe_id()

    product_to_add = db.session.execute(
        db.Select(InventoryModel).filter_by(product_stripe_id=product_stripe_id)).scalar_one()

    # then need to modify by increasing quantity in inventory
    current_quantity = product_to_add.get_quantity()

    # increase quantity by how much is removed to cart
    new_quantity = current_quantity + quantity

    # set new quantity in db
    product_to_add.set_quantity(new_quantity)

    db.session.delete(product_to_remove)

    db.session.commit()


def edit_quantity_helper(cart_id, quantity):
    # first get the cart item to update
    cart_item_to_update = db.session.execute(db.Select(CartModel).filter_by(cart_id=cart_id)).scalar_one()

    # then i need to add the quantity of the product in the cart back to the inventory
    quantity_to_add = cart_item_to_update.get_quantity()

    product_to_add = db.session.execute(
        db.Select(InventoryModel).filter_by(product_stripe_id=cart_item_to_update.get_product_stripe_id())).scalar_one()

    # current quantity of inventory
    current_quantity = product_to_add.get_quantity()

    # add cart quantity back to inventory
    product_to_add.set_quantity(current_quantity + quantity_to_add)

    # then with the new quantity, remove from inventory and assign to cart item
    new_quantity = product_to_add.get_quantity()
    product_to_add.set_quantity(new_quantity - quantity)

    cart_item_to_update.set_quantity(quantity)

    db.session.commit()


def checkout_helper(user_id):
    # this function needs to return a list of dictionaries
    # in each dictionary, it has to have the key of price and quantity, price being the stripe price id for the product

    # line items list
    line_items_list = []

    # first gather all products in the CartModel for the current user
    product_to_checkout = db.session.execute(
        db.Select(CartModel).filter_by(user_id=user_id)).scalars()

    # then for each product
    for checkout_product in product_to_checkout:
        line_item = {"price": checkout_product.get_price_stripe_id(), "quantity": checkout_product.get_quantity()}
        line_items_list.append(line_item)

    # return this to be used in the stripe checkout
    return line_items_list


def checkout_confirmation_helper(user_id):
    # if the checkout is successful, this function helps to clear the cart of items that have been checked out
    # first gather all products in the CartModel for the current user
    product_checkout = db.session.execute(
        db.Select(CartModel).filter_by(user_id=user_id)).scalars()

    for product_checked in product_checkout:
        # get product name
        productname = product_checked.inventory.get_product_name()
        productquantity = product_checked.get_quantity()
        unit_price = product_checked.inventory.get_unit_price()

        new_transaction = TransactionModel(account_id=flask_login.current_user.account.get_id(),
                                           product_name=productname,
                                           product_quantity=productquantity,
                                           time=datetime.datetime.now(),
                                           unit_price=unit_price,
                                           product_id=product_checked.inventory.get_product_id())

        db.session.add(new_transaction)

        db.session.delete(product_checked)

    db.session.commit()


@app.before_request
def before_request():
    # print("URL below")
    # print(request.url)

    if detect_path_traversal(request.url):
        add_to_log(classification="PATH TRAVERSAL",
                   target_route=html.escape(request.url),
                   priority=2,
                   details="Unauthorized resource access")


# Create a route to list all users in the database
# @app.route('/users')
# def list_users():
#     users = UserModel.query.all()
#     output = ''
#     for user in users:
#         output += '{} - {}\n'.format(user.username, user.email)
#     return output
#
#
# @app.route('/migrate_users')
# def migrate_users():
#     usersmodel = UserModel.query.all()
#     for user in usersmodel:
#         user.add_new_column()
#     db.session.commit()
#     return usersmodel


@app.route('/')
def index():
    # need to generate the default roles that should always exist
    try:
        role = db.session.execute(db.select(RoleModel).filter_by(rolename="USER")).scalar_one()
    except NoResultFound:
        role = None
    if not role:
        user_role = RoleModel(rolename="USER")
        user_role.set_user_permission("Authorized")
        db.session.add(user_role)
        db.session.commit()

    if not RoleModel.query.filter_by(rolename="SUPER_ADMIN").first():
        user_role = RoleModel(rolename="SUPER_ADMIN")
        user_role.set_superadmin_permission("Authorized")
        user_role.set_admin_permission("Authorized")
        db.session.add(user_role)
        db.session.commit()

    if not RoleModel.query.filter_by(rolename="FINANCE_ADMIN").first():
        user_role = RoleModel(rolename="FINANCE_ADMIN")
        user_role.set_financeadmin_permission("Authorized")
        user_role.set_admin_permission("Authorized")
        db.session.add(user_role)
        db.session.commit()

    if not RoleModel.query.filter_by(rolename="BLOG_ADMIN").first():
        user_role = RoleModel(rolename="BLOG_ADMIN")
        user_role.set_blogadmin_permission("Authorized")
        user_role.set_admin_permission("Authorized")
        db.session.add(user_role)
        db.session.commit()

    if not RoleModel.query.filter_by(rolename="PR_ADMIN").first():
        user_role = RoleModel(rolename="PR_ADMIN")
        user_role.set_pradmin_permission("Authorized")
        user_role.set_admin_permission("Authorized")
        db.session.add(user_role)
        db.session.commit()

    if not RoleModel.query.filter_by(rolename="PRODUCT_ADMIN").first():
        user_role = RoleModel(rolename="PRODUCT_ADMIN")
        user_role.set_productadmin_permission("Authorized")
        user_role.set_admin_permission("Authorized")
        db.session.add(user_role)
        db.session.commit()
    return render_template("index.html")


@app.route('/', subdomain='admin')
def admin_index():
    return render_template("admin_index.html")


@app.route('/populate_logs')
def populate_logs():
    populate_five_days_logs()
    return redirect(url_for('index'))

@app.route('/registerTemporarySuperAdmin')
def registerTemporarySuperAdmin():
    check_user_exist = UserModel.query.filter_by(email="SuperAdminDemo@email.com").first()
    if not check_user_exist:
        password = "SuperAdminDemo"
        password = password.encode('utf-8')
        mySalt = bcrypt.gensalt()
        pwd_hash = bcrypt.hashpw(password, mySalt)
        pwd_hash = pwd_hash.decode('utf-8')

        usr_id = "ID_" + secrets.token_urlsafe(32)
        username = "SuperAdminDemo"
        email = "SuperAdminDemo@email.com"
        phone = "+65 12345678"
        new_user = UserModel(user_id=usr_id,
                            username=username,
                            email=email,
                            phone=phone,
                            password=pwd_hash,
                            role="SUPER_ADMIN",
                            profile_pic="default.jpg")
        db.session.add(new_user)
        db.session.commit()
    return redirect(url_for('index'))

@app.route('/registerTemporaryUser')
def registerTemporaryUser():
    check_user_exist = UserModel.query.filter_by(email="UserDemo@email.com").first()
    if not check_user_exist:
        password = "UserDemo"
        password = password.encode('utf-8')
        mySalt = bcrypt.gensalt()
        pwd_hash = bcrypt.hashpw(password, mySalt)
        pwd_hash = pwd_hash.decode('utf-8')

        usr_id = "ID_" + secrets.token_urlsafe(32)
        username = "UserDemo"
        email = "UserDemo@email.com"
        phone = "+65 12345678"
        new_user = UserModel(user_id=usr_id,
                            username=username,
                            email=email,
                            phone=phone,
                            password=pwd_hash,
                            role="USER",
                            profile_pic="default.jpg")
        db.session.add(new_user)
        db.session.commit()
    return redirect(url_for('index'))


@app.route("/registerUser", methods=["GET", "POST"])
def registerUser():
    createuserform = CreateUserForm(request.form)
    if request.method == "POST" and createuserform.validate():

        # encryption of password

        # escape html to prevent xss
        password = html.escape(createuserform.password.data)
        password = password.encode('utf-8')
        # b64pwd = b64encode(SHA256.new(password).digest())
        # bcrypt_hash = bcrypt(b64pwd,12)
        mySalt = bcrypt.gensalt()
        pwd_hash = bcrypt.hashpw(password, mySalt)
        pwd_hash = pwd_hash.decode('utf-8')

        username = html.escape(createuserform.username.data)
        email = html.escape(createuserform.email.data)
        phone = html.escape(createuserform.phone.data)

        file = request.files["profile_pic"]


        main_file = file
        file_to_test = file.stream
        file_name = file.filename
        if file.filename:

            # MARKER FOR FILE UPLOAD PROTECTION
            # use sentinel to check for filename, content and extension, file signature as well
            if Sentinel.FileChecker.is_file_safe(file_to_test, file_name):

                # reset buffer position before save
                main_file.seek(0)

                # prevents double extension vulnerability and command injection via file name
                extension = file.filename.split(".")[1]
                new_file_name = username + "." + extension
                file.save('static/profile_pics/' + new_file_name)
                # with open('static/profile_pics/' + new_file_name, 'wb') as f:
                #     f.write(file_buffer.read())
            else:
                add_to_log("SUSPICIOUS FILE UPLOAD", request.url, 2, f"Suspicious File rejected: {file.filename}")
                new_file_name = "default.jpg"
        else:
            new_file_name = "default.jpg"


        check_user_exist = UserModel.query.filter_by(email=email).first()
        check_username_exist = UserModel.query.filter_by(username=username).first()
        if check_user_exist is None and check_username_exist is None:
            usr_id = "ID_" + secrets.token_urlsafe(32)
            new_user = UserModel(user_id=usr_id,
                                 username=username,
                                 email=email,
                                 phone=phone,
                                 password=pwd_hash,
                                 role="USER",
                                 profile_pic=new_file_name)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=False)
            add_to_log(classification="JOB",
                       target_route=html.escape(request.url),
                       priority=0,
                       details=f"User with id {current_user.get_id()} registered")

            return redirect(url_for('authenticated_user', user=new_user.get_username()))

    return render_template("registerUser.html", form=createuserform, logged_in=current_user.is_authenticated)


@app.route("/admin/registerAdmin", methods=["GET", "POST"])
def registerAdmin():
    # createadminform = CreateAdminForm(request.form)

    # get all admin permission roles
    role_with_admin = db.session.execute(db.select(RoleModel).filter_by(admin_permission="Authorized")).scalars()
    choices = [(role.get_rolename(), role.get_rolename()) for role in role_with_admin]
    print(choices)
    createadminform = CreateAdminForm(request.form)
    createadminform.role.choices = choices
    if request.method == "POST" and createadminform.validate():

        # encryption of password

        # escape html to prevent xss
        password = html.escape(createadminform.password.data)
        password = password.encode('utf-8')
        # b64pwd = b64encode(SHA256.new(password).digest())
        # bcrypt_hash = bcrypt(b64pwd,12)
        mySalt = bcrypt.gensalt()
        pwd_hash = bcrypt.hashpw(password, mySalt)
        pwd_hash = pwd_hash.decode('utf-8')

        username = html.escape(createadminform.username.data)
        email = html.escape(createadminform.email.data)
        phone = html.escape(createadminform.phone.data)
        role = html.escape(createadminform.role.data)

        file = request.files["profile_pic"]
        main_file = file
        file_to_test = file.stream
        file_name = file.filename
        if file.filename:
            # use sentinel to check for filename, content and extension, file signature as well
            if Sentinel.FileChecker.is_file_safe(file_to_test, file_name):

                # reset buffer position before save
                main_file.seek(0)

                extension = file.filename.split(".")[1]
                new_file_name = username + "." + extension
                file.save('static/profile_pics/' + new_file_name)
            else:
                add_to_log("SUSPICIOUS FILE UPLOAD", request.url, 2, f"Suspicious File rejected: {file.filename}")
                new_file_name = "default.jpg"
        else:
            new_file_name = "default.jpg"

        check_user_exist = UserModel.query.filter_by(email=email).first()
        check_username_exist = UserModel.query.filter_by(username=username).first()
        if check_user_exist is None and check_username_exist is None:
            usr_id = "ID_" + secrets.token_urlsafe(32)

            new_user = UserModel(user_id=usr_id,
                                 username=username,
                                 email=email,
                                 phone=phone,
                                 password=pwd_hash,
                                 role=role,
                                 profile_pic=new_file_name)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=False)
            add_to_log(classification="JOB",
                       target_route=html.escape(request.url),
                       priority=0,
                       details=f"Admin with id {current_user.get_id()} registered")

            return redirect(url_for('authenticated_user', user=new_user.get_username()))

    return render_template("registerAdmin.html", form=createadminform, logged_in=current_user.is_authenticated)


@app.route("/login", methods=['GET', 'POST'])
@limiter.limit("100/hour", methods=["POST"])  # apply rate limiting to login route
def login():
    # init login form
    createloginform = CreateLoginForm(request.form)
    if current_user.is_authenticated:
        return redirect(url_for("authenticated_user", user=current_user.get_username()))

    if request.method == "POST" and createloginform.validate():
        email = html.escape(createloginform.email.data)
        password = createloginform.password.data.encode('utf-8')
        print(password)
        if detect_xss(email) or detect_xss(password):
            add_to_log(classification="CROSS-SITE SCRIPTING",
                       target_route=html.escape(request.url),
                       priority=1,
                       details=f"Email:{email}, Password: {password}")
        # b64pwd = b64encode(SHA256.new(password).digest())

        check_user_exist = UserModel.query.filter_by(email=email).first()
        # print(type(check_user_exist.get_password()))
        if not check_user_exist:
            flash("That email does not exist, please try again or register for an account")
            add_to_log(classification="JOB",
                       target_route=html.escape(request.url),
                       priority=1,
                       details=f"Failed login with Email:{email}, Password: {password}")
            return redirect(url_for('login'))
        # elif bcrypt.checkpw(createloginform.password.data.encode('utf-8'), check_user_exist.get_password()):
        #     flash("Password Incorrect, please try again")
        #     return redirect(url_for('login'))

        if check_user_exist.check_locked_time_done() is False:
            flash("Account is locked")
            return redirect(url_for('login'))

        if check_user_exist and bcrypt.checkpw(password,
                                               check_user_exist.get_password().encode()) and check_user_exist.check_locked_time_done():
            check_user_exist.reset_failed_login_count()
            db.session.commit()
            if check_user_exist.get_enable_2fa_email() == "Not Enabled":
                if createloginform.rememberme.data == "Enabled":
                    login_user(check_user_exist, remember=True)
                else:
                    login_user(check_user_exist)
                db.session.commit()
            else:
                return redirect(
                    url_for('confirm_2fa_login', user_id=check_user_exist.get_id(), email=check_user_exist.get_email(), rememberme=createloginform.rememberme.data))

            return redirect(url_for('authenticated_user', username=check_user_exist.get_username()))
        else:
            flash("Invalid Credentials")
            check_user_exist.failed_login_increment()
            db.session.commit()
            print("Incremented")

    return render_template("login.html", form=createloginform, logged_in=current_user.is_authenticated)


# @app.route('/updateUser', methods=["GET", "POST"])
# @login_required
# def updateUser():
#     # exit if not a USER or ADMIN
#     # if not(current_user.get_role() == "ADMIN" or current_user.get_role() == "USER"):
#     #     return redirect(url_for('get_dashboard', username=current_user.get_username()))
#
#     updateuserform = UpdateUserForm(request.form)
#     # if im updating
#     if request.method == "POST" and updateuserform.validate():
#         new_username = updateuserform.username.data
#         new_email = updateuserform.email.data
#         new_phone = updateuserform.phone.data
#         new_password = updateuserform.password.data
#         new_password = new_password.encode('utf-8')
#         mySalt = bcrypt.gensalt()
#         pwd_hash = bcrypt.hashpw(new_password, mySalt)
#         pwd_hash = pwd_hash.decode('utf-8')
#
#         current_user_to_update = UserModel.query.filter_by(email=current_user.get_email()).first()
#         # current_user_to_update.first_name = new_first_name
#         # current_user_to_update.last_name = new_last_name
#         # current_user_to_update.email = new_email
#         # current_user_to_update.password = bcrypt_hash
#         current_user_to_update.set_username(new_username)
#         current_user_to_update.set_email(new_email)
#         current_user_to_update.set_phone(new_phone)
#         current_user_to_update.set_password(pwd_hash)
#
#         db.session.commit()
#         login_user(current_user_to_update, remember=True)
#         return redirect(url_for('get_dashboard', username=current_user_to_update.get_username(),
#                                 logged_in=current_user.is_authenticated))
#     else:
#         current_user_to_update = UserModel.query.filter_by(email=current_user.email).first()
#         updateuserform.username.data = current_user_to_update.get_username()
#         updateuserform.email.data = current_user_to_update.get_email()
#         updateuserform.phone.data = current_user_to_update.get_phone()
#
#         # updateuserform.password = current_user_to_update.password
#
#         return render_template("updateUser.html", username=current_user_to_update.get_username(), form=updateuserform,
#                                logged_in=current_user.is_authenticated)


# forget password section
@app.route('/forgetpassword', methods=['GET', 'POST'])
def forget_password():
    email_verification_form = EmailVerificationForm(request.form)

    if request.method == "POST" and email_verification_form.validate():
        email = email_verification_form.email.data
        print(email)
        user_to_update = UserModel.query.filter_by(email=email).first()

        # set serverside verification token
        token = secrets.token_urlsafe(32)
        user_to_update.set_forget_password_token(token)

        otp_token = totp.now()
        user_to_update.set_otp_token(otp_token)

        db.session.commit()

        return redirect(url_for('send_reset_link', email=email, random_code=otp_token, token=token))

    return render_template('email_verification.html', form=email_verification_form)


# first verification is the email
# second verfication is a code sent to user in email to enter in reset password
# third verification is the server side verification using the forget password token to check if url arg is same

def login_2fa_email(email_to_send_to):
    email = email_to_send_to
    email_sender = 'medusapc123@gmail.com'
    email_receiver = str(email)
    app_password = "hourgtepdumwweou"

    # last for 30 seconds
    otp_code = totp.now()
    body = f"""
    Your OTP is {otp_code}
        
        """
    em = EmailMessage()
    em['From'] = email_sender
    em['To'] = email_receiver
    em.set_content(body)

    context = ssl.create_default_context()

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
            smtp.login(email_sender, app_password)
            smtp.sendmail(email_sender, email_receiver, em.as_string())

        return render_template("email_success_sent.html")
    except:
        return render_template("email_failure_sent.html")


@app.route('/confirm-login', methods=['GET', 'POST'])
def confirm_2fa_login():
    confirmloginform = Login2FAForm(request.form)
    email_received = request.args.get('email')
    rememberme = request.args.get('rememberme')
    login_2fa_email(email_to_send_to=email_received)

    if request.method == "POST" and confirmloginform.validate_on_submit():
        otp_submitted = confirmloginform.OTP.data
        if totp.verify(otp_submitted):
            userid = request.args.get('user_id')
            get_user = db.session.execute(db.Select(UserModel).filter_by(user_id=userid)).scalar_one()
            if rememberme == "Enabled":
                login_user(get_user, remember=True)
            else:
                login_user(get_user)
            return redirect(url_for('authenticated_user', username=get_user.get_username()))
        else:
            flash("Expired OTP token")
            return redirect(url_for('login'))

    return render_template('login_2fa_form.html', form=confirmloginform)


@app.route('/send_reset_link', methods=['GET', 'POST'])
def send_reset_link():
    email = request.args.get('email')
    token = request.args.get('token')
    otp = request.args.get('random_code')
    email_sender = 'medusapc123@gmail.com'
    email_receiver = str(email)
    app_password = "hourgtepdumwweou"

    email_encoded = urllib.parse.quote_plus(email)

    subject = "Below is the password recovery link for Medusa PC"
    body = f"""
    Your OTP is {otp}
    Click on this link to reset your password: https://localhost:5000/reset-password/{token}/{email_encoded}
    """
    em = EmailMessage()
    em['From'] = email_sender
    em['To'] = email_receiver
    em.set_content(body)

    context = ssl.create_default_context()

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
            smtp.login(email_sender, app_password)
            smtp.sendmail(email_sender, email_receiver, em.as_string())

        return render_template("email_success_sent.html")
    except:
        return render_template("email_failure_sent.html")


@app.route('/reset-password/<path:token>/<path:email>', methods=['GET', 'POST'])
def reset_password(token, email):
    print("Here")
    user_token = token
    email = email
    current_user_to_reset_password = UserModel.query.filter_by(email=email).first()

    if user_token != current_user_to_reset_password.get_forget_password_token():
        return redirect(url_for('index'))

    forgetpasswordform = ForgetPasswordForm(request.form)
    if request.method == "POST" and forgetpasswordform.validate():
        while True:
            new_password = forgetpasswordform.password.data
            new_password_confirm = forgetpasswordform.confirm_password.data
            user_input_OTP = forgetpasswordform.OTP.data
            if new_password == new_password_confirm or user_input_OTP != current_user_to_reset_password.get_OTP_token():
                break
            else:
                forgetpasswordform = ForgetPasswordForm(request.form)

        new_password = new_password.encode('utf-8')
        mySalt = bcrypt.gensalt()
        pwd_hash = bcrypt.hashpw(new_password, mySalt)
        pwd_hash = pwd_hash.decode('utf-8')

        current_user_to_reset_password.set_password(pwd_hash)
        db.session.commit()
        # login_user(current_user_to_reset_password)
        # return redirect(url_for('get_dashboard', username=current_user_to_reset_password.get_username(),
        #                         logged_in=current_user.is_authenticated))
        return redirect(url_for('login'))

    return render_template("forgot_password_form.html", form=forgetpasswordform)


@app.route('/view_all_users/<path:username>')
@login_required
@roles_required('SUPER_ADMIN')
def user_management(username):
    current_user = username
    # if not(flask_login.current_user.get_role() == "ADMIN"):
    #     return redirect(url_for('index'))
    all_users = UserModel.query.all()
    count = 0
    admin_count = 0
    for user in all_users:
        count += 1
        if user.get_role() == "ADMIN":
            admin_count += 1

    app.logger.info("Admin User " + str(username) + " viewed all users")
    return render_template('view_all_users.html', users_db=all_users,
                           logged_in=flask_login.current_user.is_authenticated,
                           username=flask_login.current_user.username(), user=str(current_user), count=count,
                           admin_count=admin_count)


@app.route('/deleteUser', methods=['GET', 'POST'])
@login_required
def deleteUser():
    # if not(current_user.get_role() == "ADMIN" or current_user.get_role() == "USER" or current_user.get_role() == "GUEST"):
    #     return redirect(url_for('get_dashboard', username=current_user.get_username()))

    current_user_to_delete = UserModel.query.filter_by(email=current_user.get_email()).first()

    current_account_to_delete = AccountModel.query.filter_by(user_id=current_user.get_id()).first()

    try:
        # delete account first
        if current_user_to_delete.get_role() == "USER":
            db.session.delete(current_account_to_delete)

        # then logout user
        logout_user()

        # then delete
        db.session.delete(UserModel.query.filter_by(user_id=current_user_to_delete.get_id()).first())

        os.remove('static/profile_pics/' + current_user_to_delete.get_profile_pic())

        # db.session.delete(current_user_to_delete)
        db.session.commit()
    except IntegrityError as e:
        db.session.rollback()
        print(f"IntegrityError: {str(e)}")

    # app.logger.info("User deleted")
    return redirect(url_for("index"))


@app.route('/deleteUser_Admin/<path:email>', methods=['GET', 'POST'])
@login_required
@roles_required('SUPER_ADMIN')
def deleteUser_admin(email):
    current_user_to_delete = UserModel.query.filter_by(email=email).first()
    current_account_to_delete = AccountModel.query.filter_by(user_id=current_user_to_delete.get_id()).first()
    user_id = current_user_to_delete.get_id()
    # delete account first
    try:
        db.session.delete(current_account_to_delete)
    except:
        pass

    if current_user.get_email() == email:
        logout_user()

    # then delete
    db.session.delete(UserModel.query.filter_by(user_id=current_user_to_delete.get_id()).first())
    os.remove('static/profile_pics/' + current_user_to_delete.get_profile_pic())
    # db.session.delete(current_user_to_delete)
    db.session.commit()

    add_to_log(classification="JOB",
               target_route=html.escape(request.url),
               priority=0,
               details=f"User with user id of {user_id} deleted")

    return redirect(url_for("get_admin_dashboard", username=flask_login.current_user.get_username(),
                            profile_pic_name=flask_login.current_user.get_profile_pic()))


# router
@app.route("/logged_in")
@login_required
def authenticated_user():
    print(flask.session)
    current_user_role = current_user.get_role()
    print(current_user_role)
    if db.session.execute(db.select(RoleModel).filter_by(
            rolename=current_user_role)).scalar_one().get_superadmin_permission() == "Authorized":
        add_to_log(classification="JOB",
                   target_route=html.escape(request.url),
                   priority=0,
                   details=f"Admin with user id of {current_user.get_id()} logged in")
        return redirect(url_for("get_admin_dashboard", username=flask_login.current_user.get_username(),
                                profile_pic_name=flask_login.current_user.get_profile_pic()))
    elif db.session.execute(db.select(RoleModel).filter_by(
            rolename=current_user_role)).scalar_one().get_productadmin_permission() == "Authorized":
        add_to_log(classification="JOB",
                   target_route=html.escape(request.url),
                   priority=0,
                   details=f"Admin with user id of {current_user.get_id()} logged in")
        return redirect(url_for("get_admin_product_dashboard", username=flask_login.current_user.get_username(),
                                profile_pic_name=flask_login.current_user.get_profile_pic()))
    elif db.session.execute(db.select(RoleModel).filter_by(
            rolename=current_user_role)).scalar_one().get_financeadmin_permission() == "Authorized":
        add_to_log(classification="JOB",
                   target_route=html.escape(request.url),
                   priority=0,
                   details=f"Admin with user id of {current_user.get_id()} logged in")
        return redirect(url_for("get_admin_finance_dashboard", username=flask_login.current_user.get_username(),
                                profile_pic_name=flask_login.current_user.get_profile_pic()))
    elif db.session.execute(db.select(RoleModel).filter_by(
            rolename=current_user_role)).scalar_one().get_blogadmin_permission() == "Authorized":
        add_to_log(classification="JOB",
                   target_route=html.escape(request.url),
                   priority=0,
                   details=f"Admin with user id of {current_user.get_id()} logged in")
        return redirect(url_for("get_admin_blog_dashboard", username=flask_login.current_user.get_username(),
                                profile_pic_name=flask_login.current_user.get_profile_pic()))
    elif db.session.execute(db.select(RoleModel).filter_by(
            rolename=current_user_role)).scalar_one().get_pradmin_permission() == "Authorized":
        add_to_log(classification="JOB",
                   target_route=html.escape(request.url),
                   priority=0,
                   details=f"Admin with user id of {current_user.get_id()} logged in")
        return redirect(url_for("get_admin_pr_dashboard", username=flask_login.current_user.get_username(),
                                profile_pic_name=flask_login.current_user.get_profile_pic()))

    else:
        add_to_log(classification="JOB",
                   target_route=html.escape(request.url),
                   priority=0,
                   details=f"User with user id of {current_user.get_id()} logged in")
        return redirect(url_for("get_dashboard", username=flask_login.current_user.get_username(),
                                profile_pic_name=flask_login.current_user.get_profile_pic()))


@app.route('/logout')
@login_required
def logout():
    if not (
            current_user.is_authenticated):
        return redirect(url_for('index'))
    user_id = current_user.get_id()
    add_to_log(classification="JOB",
               target_route=html.escape(request.url),
               priority=0,
               details=f"User with user id of {user_id} logged out")
    logout_user()

    return redirect(url_for("index"))


@app.route('/dashboard/<path:username>', methods=['GET', 'POST'])
@login_required
@roles_required('USER')
def get_dashboard(username):
    profile_pic_name = request.args.get('profile_pic_name')

    if profile_pic_name is None:
        profile_pic_name = flask_login.current_user.get_profile_pic()
    # if flask_login.current_user.get_role() == "ADMIN":
    #     return redirect(url_for('get_admin_dashboard', username=flask_login.current_user.get_username()))
    # print(flask_login.current_user.get_first_name())
    if username == flask_login.current_user.get_username():
        current_user = username
        print(current_user)
        add_to_log(classification="JOB",
                   target_route=html.escape(request.url),
                   priority=0,
                   details=f"User with user id of {flask_login.current_user.get_id()} logged into dashboard")
        return render_template("dashboard_user.html", profile_pic_name=profile_pic_name, username=username)
    else:
        return redirect(url_for('get_dashboard', username=flask_login.current_user.get_username(),
                                profile_pic_name=flask_login.current_user.get_profile_pic()))


@app.route('/dashboard/<path:username>/profile', methods=['GET', 'POST'])
@login_required
@roles_required('USER')
def userProfile(username):
    profile_pic_name = request.args.get('profile_pic_name')
    # if flask_login.current_user.get_role() == "ADMIN":
    #     return redirect(url_for('get_admin_dashboard', username=flask_login.current_user.get_username()))
    # print(flask_login.current_user.get_first_name())
    updateuserform = UpdateUserForm(request.form)
    # if im updating
    if request.method == "POST" and updateuserform.validate():
        new_username = updateuserform.username.data
        new_email = updateuserform.email.data
        new_phone = updateuserform.phone.data
        old_password = updateuserform.old_password.data.encode("utf-8")
        enable_2fa = updateuserform.enable_2fa.data
        if bcrypt.checkpw(old_password, flask_login.current_user.get_password().encode()):
            new_password = updateuserform.password.data
            new_password = new_password.encode('utf-8')
            mySalt = bcrypt.gensalt()
            pwd_hash = bcrypt.hashpw(new_password, mySalt)
            pwd_hash = pwd_hash.decode('utf-8')

            file = request.files["profile_pic"]
            main_file = file
            file_to_test = file.stream
            file_name = file.filename
            new_file_name = None

            # only check if they choose to update the profile pic
            if file.filename:
                # MARKER FOR FILE UPLOAD PROTECTION
                # use sentinel to check for filename, content and extension, file signature as well
                if Sentinel.FileChecker.is_file_safe(file_to_test, file_name):
                     # reset buffer position before save
                    main_file.seek(0)

                    # prevents double extension vulnerability and command injection via file name
                    extension = file.filename.split(".")[1]
                    new_file_name = new_username + "." + extension
                    file.save('static/profile_pics/' + new_file_name)
                else:
                    add_to_log("SUSPICIOUS FILE UPLOAD", request.url, 2, f"Suspicious File rejected: {file.filename}")
                    new_file_name = None

            current_user_to_update = UserModel.query.filter_by(email=flask_login.current_user.get_email()).first()
            # current_user_to_update.first_name = new_first_name
            # current_user_to_update.last_name = new_last_name
            # current_user_to_update.email = new_email
            # current_user_to_update.password = bcrypt_hash
            current_user_to_update.set_username(new_username)
            current_user_to_update.set_email(new_email)
            current_user_to_update.set_phone(new_phone)
            current_user_to_update.set_password(pwd_hash)
            current_user_to_update.set_enable_2fa_email(enable_2fa)

            if new_file_name:
                current_user_to_update.set_profile_pic(new_file_name)

            db.session.commit()
            login_user(current_user_to_update, remember=True)
            add_to_log(classification="JOB",
                       target_route=html.escape(request.url),
                       priority=0,
                       details=f"User with user id of {current_user_to_update.get_id()} updated profile")
            return redirect(url_for('get_dashboard', username=current_user_to_update.get_username(),
                                    logged_in=flask_login.current_user.is_authenticated,
                                    profile_pic_name=current_user_to_update.get_profile_pic()))
        else:
            return redirect(url_for('userProfile', username=flask_login.current_user.get_username(),
                                    profile_pic_name=flask_login.current_user.get_profile_pic()))
    else:
        if username == flask_login.current_user.get_username():
            current_user = username
            print(current_user)
            current_user_to_update = UserModel.query.filter_by(email=flask_login.current_user.email).first()
            updateuserform.username.data = current_user_to_update.get_username()
            updateuserform.email.data = current_user_to_update.get_email()
            updateuserform.phone.data = current_user_to_update.get_phone()
            updateuserform.enable_2fa.data = current_user_to_update.get_enable_2fa_email()

            return render_template("dashboard_user_profile.html", profile_pic_name=profile_pic_name, username=username,
                                   form=updateuserform)

        else:
            return redirect(url_for('get_dashboard', username=flask_login.current_user.get_username(),
                                    profile_pic_name=flask_login.current_user.get_profile_pic()))


# admin side user profile
@app.route('/admin/dashboard/<path:username>/profile', methods=['GET', 'POST'])
@login_required
@roles_required('ADMIN')
def userProfile_admin(username):
    profile_pic_name = request.args.get('profile_pic_name')
    # if flask_login.current_user.get_role() == "ADMIN":
    #     return redirect(url_for('get_admin_dashboard', username=flask_login.current_user.get_username()))
    # print(flask_login.current_user.get_first_name())
    updateuserform = UpdateUserForm(request.form)
    # if im updating
    if request.method == "POST" and updateuserform.validate():
        new_username = updateuserform.username.data
        new_email = updateuserform.email.data
        new_phone = updateuserform.phone.data
        old_password = updateuserform.old_password.data.encode("utf-8")
        enable_2fa = updateuserform.enable_2fa.data
        if bcrypt.checkpw(old_password, flask_login.current_user.get_password().encode()):
            new_password = updateuserform.password.data
            new_password = new_password.encode('utf-8')
            mySalt = bcrypt.gensalt()
            pwd_hash = bcrypt.hashpw(new_password, mySalt)
            pwd_hash = pwd_hash.decode('utf-8')

            file = request.files["profile_pic"]
            main_file = file
            file_to_test = file.stream
            file_name = file.filename
            new_file_name = None

            # only call if there is input to change the profile pic
            if file.filename:
                # MARKER FOR FILE UPLOAD PROTECTION
                # use sentinel to check for filename, content and extension, file signature as well
                if Sentinel.FileChecker.is_file_safe(file_to_test, file_name):
                     # reset buffer position before save
                    main_file.seek(0)

                    # prevents double extension vulnerability and command injection via file name
                    extension = file.filename.split(".")[1]
                    new_file_name = new_username + "." + extension
                    file.save('static/profile_pics/' + new_file_name)
                else:
                    add_to_log("SUSPICIOUS FILE UPLOAD", request.url, 2, f"Suspicious File rejected: {file.filename}")
                    new_file_name = None

            current_user_to_update = UserModel.query.filter_by(email=flask_login.current_user.get_email()).first()
            # current_user_to_update.first_name = new_first_name
            # current_user_to_update.last_name = new_last_name
            # current_user_to_update.email = new_email
            # current_user_to_update.password = bcrypt_hash
            current_user_to_update.set_username(new_username)
            current_user_to_update.set_email(new_email)
            current_user_to_update.set_phone(new_phone)
            current_user_to_update.set_password(pwd_hash)
            current_user_to_update.set_enable_2fa_email(enable_2fa)

            if new_file_name:
                current_user_to_update.set_profile_pic(new_file_name)

            db.session.commit()
            login_user(current_user_to_update, remember=True)
            add_to_log(classification="JOB",
                       target_route=html.escape(request.url),
                       priority=0,
                       details=f"Admin with user id of {current_user_to_update.get_id()} updated profile")
            return redirect(url_for('get_admin_dashboard', username=current_user_to_update.get_username(),
                                    logged_in=flask_login.current_user.is_authenticated,
                                    profile_pic_name=current_user_to_update.get_profile_pic()))
        else:
            return redirect(url_for('userProfile_admin', username=flask_login.current_user.get_username(),
                                    profile_pic_name=flask_login.current_user.get_profile_pic()))
    else:
        if username == flask_login.current_user.get_username():
            current_user = username
            print(current_user)
            current_user_to_update = UserModel.query.filter_by(email=flask_login.current_user.email).first()
            updateuserform.username.data = current_user_to_update.get_username()
            updateuserform.email.data = current_user_to_update.get_email()
            updateuserform.phone.data = current_user_to_update.get_phone()
            updateuserform.enable_2fa.data = current_user_to_update.get_enable_2fa_email()

            return render_template("dashboard_admin_user_profile.html", profile_pic_name=profile_pic_name,
                                   username=username,
                                   form=updateuserform)

        else:
            return redirect(url_for('get_admin_dashboard', username=flask_login.current_user.get_username(),
                                    profile_pic_name=flask_login.current_user.get_profile_pic()))


# create a product


# exporting logs
@app.route('/uwiebciwepciewpciowpeicnpownecownoc/export')
@login_required
def export_data():
    logs = LogsModel.query.all()

    # convert to pandas dataframe
    data = [(log.get_log_id(), log.get_user_id(), log.get_classification(), log.get_priority(), log.get_time(),
             log.get_target(), log.get_details()) for log in logs]
    df = pandas.DataFrame(data, columns=['Log_id', 'User_id', 'Class', 'Priority', 'Time', 'Target', 'Details'])

    # export the dataframe to an excel file
    current_date = datetime.datetime.now().strftime('%Y-%m-%d')
    excel_file = f'{current_date}.xlsx'

    # export the dataframe to excel file
    file_path = os.path.join('static/log_reports', excel_file)
    df.to_excel(file_path, index=False)

    # to sql file
    # sql_file = f'{current_date}.xlsx'
    #
    # sql_file_path = os.path.join('static/log_reports', sql_file)
    # df.to_sql('logs_model', db.engine, if_exists='replace', index=False)

    return redirect(url_for('get_admin_dashboard', username=flask_login.current_user.get_username(),
                            logged_in=flask_login.current_user.is_authenticated,
                            profile_pic_name=flask_login.current_user.get_profile_pic()))


@app.route('/static/log_reports/<path:filename>')
def serve_log_file(filename):
    return send_from_directory('static/log_reports', filename)


@app.route('/admin/dashboard/<path:username>', methods=['GET', 'POST'])
@login_required
@roles_required('SUPER_ADMIN')
def get_admin_dashboard(username):
    profile_pic_name = request.args.get('profile_pic_name')
    if username == flask_login.current_user.get_username():
        current_user = username
        print(current_user)

        # Retrieve filter values from request arguments
        start_date = request.args.get('start_date', type=str)
        end_date = request.args.get('end_date', type=str)
        priority = request.args.get('priority', type=str)
        classification = request.args.get('classification', type=str)
        log_id = request.args.get('log_id', type=str)
        user_id = request.args.get('user_id', type=str)
        target = request.args.get('target', type=str)
        detail = request.args.get('detail', type=str)
        sourceip = request.args.get('sourceip', type=str)

        # # Parse filter values if provided
        # start_date = start_date.strftime('%Y-%m-%d %H:%M:%S.%f') if start_date else None
        # end_date = end_date.strftime('%Y-%m-%d %H:%M:%S.%f') if end_date else None

        # print(f"Start Date: {start_date}")
        # print(f"End Date: {end_date}")
        # print(f"Priority: {priority}")
        # print(f"Classification: {classification}")
        #
        # if classification == "None":
        #     print("True")

        # get all logs model and sort by time first
        # logsmodel = LogsModel.query.all()
        # logsmodel = sorted(logsmodel, key=lambda x: x.time)

        query = LogsModel.query

        # filter logs based on provided filters
        if start_date and end_date:
            query = query.filter(LogsModel.time.between(start_date, end_date))

        if priority:
            query = query.filter(LogsModel.priority == priority)

        if classification is not None and classification != 'None':
            # matches input at beginning, middle or end
            query = query.filter(
                or_(LogsModel.classification.ilike(f"%{classification}%"),
                    LogsModel.classification.ilike(f"{classification}%"),
                    LogsModel.classification.ilike(f"%{classification}"))
            )

        if log_id is not None and log_id != 'None':
            query = query.filter(
                or_(LogsModel.log_id.ilike(f"%{log_id}%"),
                    LogsModel.log_id.ilike(f"{log_id}%"),
                    LogsModel.log_id.ilike(f"%{log_id}"))
            )

        if user_id is not None and user_id != 'None':
            query = query.filter(
                or_(LogsModel.user_id.ilike(f"%{user_id}%"),
                    LogsModel.user_id.ilike(f"{user_id}%"),
                    LogsModel.user_id.ilike(f"%{user_id}"))
            )

        if target is not None and target != 'None':
            query = query.filter(
                or_(LogsModel.target.ilike(f"%{target}%"),
                    LogsModel.target.ilike(f"{target}%"),
                    LogsModel.target.ilike(f"%{target}"))
            )

        if detail is not None and detail != 'None':
            query = query.filter(
                or_(LogsModel.details.ilike(f"%{detail}%"),
                    LogsModel.details.ilike(f"{detail}%"),
                    LogsModel.details.ilike(f"%{detail}"))
            )

        if sourceip is not None and sourceip != 'None':
            query = query.filter(
                or_(LogsModel.source_ip.ilike(f"%{sourceip}%"),
                    LogsModel.source_ip.ilike(f"{sourceip}%"),
                    LogsModel.source_ip.ilike(f"%{sourceip}"))
            )

        logsmodel = query.order_by(LogsModel.time).all()
        logsmodel = sorted(logsmodel, key=lambda x: x.time)

        original_logs_model = LogsModel.query.all()
        original_logs_model = sorted(original_logs_model, key=lambda x: x.time)

        total_logs_count = len(logsmodel)

        # Assuming you want to get the count of each distinct value in the "column_name" column
        result = db.session.query(LogsModel.classification, func.count(LogsModel.classification)).group_by(
            LogsModel.classification).all()

        priority_result = db.session.query(LogsModel.priority, func.count(LogsModel.priority)).group_by(
            LogsModel.priority).all()

        # date_results = db.session.query(LogsModel.time,
        #                                 func.count(LogsModel.time)).group_by(LogsModel.time).all()
        date_results = db.session.query(func.date(LogsModel.time),
                                        func.count(func.date(LogsModel.time))).group_by(func.date(LogsModel.time)).all()

        date_results = sorted(date_results, key=lambda x: x[0])
        print(date_results)
        # Store the results in a list of tuples
        count_list = [(value, count) for value, count in result]

        priority_list = [(value, count) for value, count in priority_result]

        date_list = [(value.strftime("%Y-%m-%d"), count) for value, count in date_results]

        logs_classification_list = []
        logs_count = []

        logs_priority_list = []
        logs_priority_count = []

        logs_date_list = []
        logs_date_count = []

        for count_tuple in count_list:
            logs_classification_list.append(count_tuple[0])
            logs_count.append(count_tuple[1])

        for count_tuple in priority_list:
            logs_priority_list.append(count_tuple[0])
            logs_priority_count.append(count_tuple[1])

        # i need a list of dates for the labels
        for tup in date_list:
            logs_date_list.append(tup[0])
            logs_date_count.append(tup[1])

        add_to_log(classification="JOB",
                   target_route=html.escape(request.url),
                   priority=0,
                   details=f"Admin with user id of {flask_login.current_user.get_id()} accessed Security Logging System")

        filename_list = os.listdir("static/log_reports")

        createevirecform = AddToEvirec(request.form)

        page = request.args.get("page", 1, type=int)
        per_page = 10  # display 10 logs per page

        pagination_logs = query.paginate(page=page,
                                         per_page=per_page)  # i want to paginate the logs model to 10 per page and order by time

        # since i want the start_date to reset
        start_date = original_logs_model[0].get_time()
        end_date = original_logs_model[-1].get_time()

        return render_template("dashboard_admin_ver2.html", profile_pic_name=profile_pic_name, username=username,
                               logs_classes=logs_classification_list, logs_count=logs_count,
                               logs_priority=logs_priority_list, logs_priority_count=logs_priority_count,
                               logs_model=logsmodel, log_files=filename_list,
                               logs_dates=logs_date_list, logs_date_count=logs_date_count,
                               createevirec=createevirecform, logs_pages=pagination_logs,
                               start_date=start_date, end_date=end_date, priority=priority,
                               classification=classification, log_id=log_id, user_id=user_id, target=target, detail=detail,
                               sourceip=sourceip,
                               total_logs_count=total_logs_count,
                               original_logs_model=original_logs_model)
    else:
        add_to_log(classification="JOB",
                   target_route=html.escape(request.url),
                   priority=2,
                   details=f"User with user id of {flask_login.current_user.get_id()} unauthorized access to Security Logging System")
        return redirect(url_for('get_dashboard', username=flask_login.current_user.get_username()))


@app.route('/admin/dashboard/<path:username>/user_interface', methods=['GET', 'POST'])
@login_required
@roles_required('SUPER_ADMIN')
def get_admin_user_dashboard(username):
    profile_pic_name = request.args.get('profile_pic_name')
    if username == flask_login.current_user.get_username():
        current_user = username
        print(current_user)

        usermodel = UserModel.query.all()
        add_to_log(classification="JOB",
                   target_route=html.escape(request.url),
                   priority=0,
                   details=f"SuperAdmin with user id of {flask_login.current_user.get_id()} accessed user management interface.")
        return render_template("dashboard_admin_usermanage.html", profile_pic_name=profile_pic_name, username=username,
                               usermodel=usermodel)
    else:
        add_to_log(classification="JOB",
                   target_route=html.escape(request.url),
                   priority=2,
                   details=f"User with user id of {flask_login.current_user.get_id()} unauthorized to access user management interface.")
        return redirect(url_for('get_dashboard', username=flask_login.current_user.get_username()))


@app.route('/admin/dashboard/<path:username>/role_interface', methods=['GET', 'POST'])
@login_required
@roles_required('SUPER_ADMIN')
def get_admin_roles_dashboard(username):
    profile_pic_name = request.args.get('profile_pic_name')
    if username == flask_login.current_user.get_username():
        rolemodel = RoleModel.query.all()
        createroleform = CreateRoleForm(request.form)

        add_to_log(classification="JOB",
                   target_route=html.escape(request.url),
                   priority=0,
                   details=f"SuperAdmin with user id of {flask_login.current_user.get_id()} accessed role management interface.")
        return render_template("dashboard_admin_rolemanage.html", profile_pic_name=profile_pic_name, username=username,
                               rolemodel=rolemodel, createform=createroleform)
    else:
        return redirect(url_for('get_dashboard', username=flask_login.current_user.get_username(),
                                profile_pic_name=flask_login.current_user.get_profile_pic()))


@app.route('/admin/dashboard/<path:username>/roles/add_role', methods=['GET', 'POST'])
@login_required
@roles_required('SUPER_ADMIN')
def createRole_Admin(username):
    profile_pic_name = request.args.get('profile_pic_name')

    createroleform = CreateRoleForm(request.form)

    if request.method == "POST" and createroleform.validate_on_submit():
        role_name = createroleform.rolename.data
        superadmin_permission = createroleform.havesuperadmin_permission.data
        financeadmin_permission = createroleform.havefinanceadmin_permission.data
        productadmin_permission = createroleform.haveproductadmin_permission.data
        blogadmin_permission = createroleform.haveblogadmin_permission.data
        pradmin_permission = createroleform.havepradmin_permission.data
        user_permission = createroleform.haveuser_permission.data

        new_role = RoleModel(rolename=role_name)

        db.session.add(new_role)

        new_role.set_superadmin_permission(superadmin_permission)
        new_role.set_financeadmin_permission(financeadmin_permission)
        new_role.set_productadmin_permission(productadmin_permission)
        new_role.set_blogadmin_permission(blogadmin_permission)
        new_role.set_pradmin_permission(pradmin_permission)
        new_role.set_user_permission(user_permission)

        if superadmin_permission == "Authorized" or financeadmin_permission == "Authorized" or productadmin_permission == "Authorized" or blogadmin_permission == "Authorized" or pradmin_permission == "Authorized":
            new_role.set_admin_permission("Authorized")
        else:
            new_role.set_admin_permission("Unauthorized")

        db.session.commit()

        return redirect(url_for('get_admin_roles_dashboard', profile_pic_name=profile_pic_name, username=username))


@app.route('/admin/updateRole/<path:username>', methods=['GET', 'POST'])
@login_required
@roles_required('SUPER_ADMIN')
def updateRole_Admin(username):
    role_id = request.args.get('role_id')

    updateroleform = UpdateRoleForm(request.form)

    if request.method == "POST" and updateroleform.validate_on_submit():
        rolename = updateroleform.rolename.data
        superadmin_permission = updateroleform.havesuperadmin_permission.data
        financeadmin_permission = updateroleform.havefinanceadmin_permission.data
        productadmin_permission = updateroleform.haveproductadmin_permission.data
        blogadmin_permission = updateroleform.haveblogadmin_permission.data
        pradmin_permission = updateroleform.havepradmin_permission.data
        user_permission = updateroleform.haveuser_permission.data

        role_to_update = db.session.execute(db.select(RoleModel).filter_by(id=role_id)).scalar_one()

        role_to_update.set_rolename(rolename)
        role_to_update.set_superadmin_permission(superadmin_permission)
        role_to_update.set_financeadmin_permission(financeadmin_permission)
        role_to_update.set_productadmin_permission(productadmin_permission)
        role_to_update.set_blogadmin_permission(blogadmin_permission)
        role_to_update.set_pradmin_permission(pradmin_permission)
        role_to_update.set_user_permission(user_permission)

        if superadmin_permission == "Authorized" or financeadmin_permission == "Authorized" or productadmin_permission == "Authorized" or blogadmin_permission == "Authorized" or pradmin_permission == "Authorized":
            role_to_update.set_admin_permission("Authorized")
        else:
            role_to_update.set_admin_permission("Unauthorized")

        db.session.commit()

        return redirect(
            url_for('get_admin_roles_dashboard', profile_pic_name=current_user.get_profile_pic(), username=username))

    else:
        role_update = db.session.execute(db.select(RoleModel).filter_by(id=role_id)).scalar_one()

        updateroleform.rolename.data = role_update.get_rolename()
        updateroleform.havesuperadmin_permission.data = role_update.get_superadmin_permission()
        updateroleform.havefinanceadmin_permission.data = role_update.get_financeadmin_permission()
        updateroleform.haveproductadmin_permission.data = role_update.get_productadmin_permission()
        updateroleform.haveblogadmin_permission.data = role_update.get_blogadmin_permission()
        updateroleform.havepradmin_permission.data = role_update.get_pradmin_permission()
        updateroleform.haveuser_permission.data = role_update.get_user_permission()

        # updateuserform.password = current_user_to_update.password

        return render_template("updateRole.html", updateform=updateroleform, logged_in=current_user.is_authenticated)


@app.route('/admin/dashboard/<path:username>/roles/delete_role', methods=['GET', 'POST'])
@login_required
@roles_required('SUPER_ADMIN')
def deleteRole_Admin(username):
    role_id = request.args.get('role_id')

    if request.method == "POST":
        role_to_delete = db.session.execute(db.select(RoleModel).filter_by(id=role_id)).scalar_one()

        db.session.delete(role_to_delete)

        db.session.commit()

        return redirect(
            url_for('get_admin_roles_dashboard', profile_pic_name=current_user.get_profile_pic(), username=username))


@app.route('/admin/updateUser_Admin/<email>', methods=["GET", "POST"])
@login_required
@roles_required('SUPER_ADMIN')
def updateUser_admin(email):
    # exit if not a USER or ADMIN
    # if not(current_user.get_role() == "ADMIN" or current_user.get_role() == "USER"):
    #     return redirect(url_for('get_dashboard', username=current_user.get_username()))

    # get all admin permission roles
    role_with_admin = db.session.execute(db.select(RoleModel).filter_by(admin_permission="Authorized")).scalars()
    choices = [(role.get_rolename(), role.get_rolename()) for role in role_with_admin]
    updateuserform = UpdateUserAdminForm(request.form)

    updateuserform.role.choices = choices

    # if im updating
    if request.method == "POST" and updateuserform.validate():
        new_username = updateuserform.username.data
        new_email = updateuserform.email.data
        new_phone = updateuserform.phone.data
        new_password = updateuserform.password.data
        new_password = new_password.encode('utf-8')
        new_role = updateuserform.role.data
        mySalt = bcrypt.gensalt()
        pwd_hash = bcrypt.hashpw(new_password, mySalt)
        pwd_hash = pwd_hash.decode('utf-8')
        enable_2fa = updateuserform.enable_2fa.data

        file = request.files["profile_pic"]
        main_file = file
        file_to_test = file.stream
        file_name = file.filename
        new_file_name = None

        # only update if input is given for profile pic to be updated
        if file.filename:
             # MARKER FOR FILE UPLOAD PROTECTION
            # use sentinel to check for filename, content and extension, file signature as well
            if Sentinel.FileChecker.is_file_safe(file_to_test, file_name):
                # reset buffer position before save
                main_file.seek(0)

                # prevents double extension vulnerability and command injection via file name
                extension = file.filename.split(".")[1]
                new_file_name = new_username + "." + extension
                file.save('static/profile_pics/' + new_file_name)
            else:
                add_to_log("SUSPICIOUS FILE UPLOAD", request.url, 2, f"Suspicious File rejected: {file.filename}")
                new_file_name = None

        current_user_to_update = UserModel.query.filter_by(email=email).first()
        # current_user_to_update.first_name = new_first_name
        # current_user_to_update.last_name = new_last_name
        # current_user_to_update.email = new_email
        # current_user_to_update.password = bcrypt_hash
        current_user_to_update.set_username(new_username)
        current_user_to_update.set_email(new_email)
        current_user_to_update.set_phone(new_phone)
        current_user_to_update.set_password(pwd_hash)
        current_user_to_update.set_enable_2fa_email(enable_2fa)

        if current_user_to_update.get_role() != 'USER':
            current_user_to_update.set_role(new_role)

        if new_file_name:
            current_user_to_update.set_profile_pic(new_file_name)

        db.session.commit()
        add_to_log(classification="JOB",
                   target_route=html.escape(request.url),
                   priority=0,
                   details=f"Admin with user id of {flask_login.current_user.get_id()} updated user profile with id of {current_user_to_update.get_id()}.")
        return redirect(url_for('get_admin_dashboard', username=flask_login.current_user.get_username(),
                                logged_in=flask_login.current_user.is_authenticated,
                                profile_pic_name=flask_login.current_user.get_profile_pic()))
    else:
        current_user_to_update = UserModel.query.filter_by(email=email).first()
        updateuserform.username.data = current_user_to_update.get_username()
        updateuserform.email.data = current_user_to_update.get_email()
        updateuserform.phone.data = current_user_to_update.get_phone()
        updateuserform.role.data = current_user_to_update.get_role()
        updateuserform.enable_2fa.data = current_user_to_update.get_enable_2fa_email()

        # updateuserform.password = current_user_to_update.password

        return render_template("updateUser.html", form=updateuserform, logged_in=current_user.is_authenticated)


@app.route('/admin/dashboard/<path:username>/finance', methods=['GET', 'POST'])
@login_required
@roles_required('FINANCE_ADMIN')
def get_admin_finance_dashboard(username):
    profile_pic_name = request.args.get('profile_pic_name')
    if username == flask_login.current_user.get_username():
        current_user = username
        print(current_user)
        print(profile_pic_name)
        add_to_log(classification="JOB",
                   target_route=html.escape(request.url),
                   priority=0,
                   details=f"Admin with user id of {flask_login.current_user.get_id()} accessed finance dashboard.")

        return render_template("dashboard_admin_finance.html", profile_pic_name=profile_pic_name, username=username)
    else:
        return redirect(url_for('get_dashboard', username=flask_login.current_user.get_username(),
                                profile_pic_name=flask_login.current_user.get_profile_pic()))


@app.route('/admin/dashboard/<path:username>/products', methods=['GET', 'POST'])
@login_required
@roles_required('PRODUCT_ADMIN')
def get_admin_product_dashboard(username):
    profile_pic_name = request.args.get('profile_pic_name')
    if username == flask_login.current_user.get_username():
        current_user = username
        print(current_user)
        print(profile_pic_name)

        all_products = InventoryModel.query.all()

        createproductform = CreateProductForm(request.form)
        updateproductform = UpdateProductForm(request.form)
        add_to_log(classification="JOB",
                   target_route=html.escape(request.url),
                   priority=0,
                   details=f"Admin with user id of {flask_login.current_user.get_id()} accessed product dashboard.")

        return render_template("dashboard_admin_product.html", profile_pic_name=profile_pic_name,
                               username=username, all_products=all_products, updateform=updateproductform,
                               createform=createproductform)
    else:
        return redirect(url_for('get_dashboard', username=flask_login.current_user.get_username(),
                                profile_pic_name=flask_login.current_user.get_profile_pic()))


@app.route('/dashboard/<path:username>/MerchStore', methods=['GET', 'POST'])
@login_required
@roles_required('USER')
def get_merch_store(username):
    # if flask_login.current_user.get_role() == "ADMIN":
    #     return redirect(url_for('get_admin_dashboard', username=flask_login.current_user.get_username()))
    # print(flask_login.current_user.get_first_name())
    if username == flask_login.current_user.get_username():
        current_user = username
        print(current_user)
        inventory_db = db.session.execute(db.Select(InventoryModel)).scalars()
        return render_template("dashboard_user_merchstore.html", username=flask_login.current_user.get_username(),
                               profile_pic_name=flask_login.current_user.get_profile_pic(), inventorymodel=inventory_db)
    else:
        return redirect(url_for('get_dashboard', username=flask_login.current_user.get_username()))


@app.route('/dashboard/<path:username>/MerchStore/ViewProduct', methods=['GET', 'POST'])
@login_required
@roles_required('USER')
def view_product(username):
    product_id = request.args.get('product_id')
    product_to_view = db.session.execute(db.Select(InventoryModel).filter_by(product_id=product_id)).scalar_one()
    quantity_form = QuantityForm(max_value=product_to_view.get_quantity())

    if username == flask_login.current_user.get_username():

        return render_template("dashboard_user_view_product.html", username=flask_login.current_user.get_username(),
                               profile_pic_name=flask_login.current_user.get_profile_pic(), product=product_to_view,
                               form=quantity_form)
    else:
        return redirect(url_for('get_dashboard', username=flask_login.current_user.get_username()))


@app.route('/dashboard/<path:username>/MerchStore/AddToCart', methods=['GET', 'POST'])
@login_required
@roles_required('USER')
def add_to_cart(username):
    product_id = request.args.get('product_id')
    get_quantity = QuantityForm(request.form)
    quantity = get_quantity.quantity.data

    if request.method == "POST":
        get_product = db.session.execute(db.Select(InventoryModel).filter_by(product_id=product_id)).scalar_one()

        # should check if product_stripe_id is in Cart already
        # if it is in cart, then it should just update the quantity
        try:
            cart_item = db.session.execute(
                db.Select(CartModel).filter_by(product_stripe_id=get_product.get_product_stripe_id())).scalar_one()
            new_quantity = quantity + cart_item.get_quantity()
            edit_quantity_helper(cart_item.get_cart_id(), new_quantity)
        except:
            add_to_cart_helper(get_product.get_product_stripe_id(), quantity=quantity,
                               user_id=flask_login.current_user.get_id())

        return redirect(url_for('get_cart', username=flask_login.current_user.get_username(),
                                profile_pic_name=flask_login.current_user.get_profile_pic()))


@app.route('/dashboard/<path:username>/Cart', methods=['GET', 'POST'])
@login_required
@roles_required('USER')
def get_cart(username):
    quantityForm = QuantityFormUpdate()
    checkoutcodeform = CheckoutVoucherForm(request.form)
    if username == flask_login.current_user.get_username():

        # this is to get all cart items
        cart_db = db.session.execute(
            db.Select(CartModel).filter_by(user_id=flask_login.current_user.get_id())).scalars()
        cart_items_length = db.session.execute(
            db.Select(func.count()).where(CartModel.user_id==flask_login.current_user.get_id())).scalar()
        # now we need to match the cart product id with the product id that is in the inventory
        # inventory_db = db.session.execute(db.Select(InventoryModel)).scalars()

        return render_template("dashboard_user_cart.html", username=flask_login.current_user.get_username(),
                               profile_pic_name=flask_login.current_user.get_profile_pic(), cartdb=cart_db,
                               form=quantityForm, checkoutcodeform=checkoutcodeform, cart_length=cart_items_length)
    else:
        return redirect(url_for('get_dashboard', username=flask_login.current_user.get_username()))


@app.route('/dashboard/<path:username>/Cart/remove', methods=['GET', 'POST'])
@login_required
@roles_required('USER')
def remove_from_cart(username):
    cart_id = request.args.get('cart_id')

    if request.method == "POST":
        get_product = db.session.execute(db.Select(CartModel).filter_by(cart_id=cart_id)).scalar_one()
        remove_from_cart_helper(cart_id=cart_id, quantity=get_product.get_quantity())

        return redirect(url_for('get_cart', username=flask_login.current_user.get_username(),
                                profile_pic_name=flask_login.current_user.get_profile_pic()))


@app.route('/dashboard/<path:username>/Cart/edit_quantity', methods=['GET', 'POST'])
@login_required
@roles_required('USER')
def edit_cart_quantity(username):
    cart_id = request.args.get('cart_id')
    quantityForm = QuantityFormUpdate(request.form)
    if request.method == "POST":
        # should pass in the cart item to update quantity, the relevant product_id for which quantity should change
        # as well as the new quantity

        edit_quantity_helper(cart_id=cart_id, quantity=quantityForm.quantity.data)

        return redirect(url_for('get_cart', username=flask_login.current_user.get_username(),
                                profile_pic_name=flask_login.current_user.get_profile_pic()))


@app.route('/dashboard/<path:username>/checkout', methods=['GET', 'POST'])
@login_required
@roles_required('USER')
def checkout(username):
    user_id = request.args.get('user_id')
    code = CheckoutVoucherForm(request.form).code.data
    user_for_checkout = db.session.execute(db.Select(UserModel).filter_by(user_id=user_id)).scalar_one()

    # activate one time pass for checkout that expires in 1 minute
    one_time_pass_config = Sentinel.generate_time_based_one_time_pass()

    # now add to AuthModel

    one_time_pass = AuthenticationModel(user_id=user_id,
                                        one_time_pass=one_time_pass_config["one_time_pass"],
                                        created_at=one_time_pass_config["current time"],
                                        expiration_date=one_time_pass_config["expiration time"])

    db.session.add(one_time_pass)
    db.session.commit()

    if code == None or code == "":
        discounts = []
    else:
        discounts = [{'coupon': code}]
    print(discounts)
    try:
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=["card", "alipay", "grabpay", "paynow"],
            line_items=checkout_helper(user_id),
            mode='payment',
            discounts=discounts,
            # change to https
            success_url=f"https://localhost:5000/dashboard/checkout_finalise?username={user_for_checkout.get_username()}&logged_in=True&onetimepass={one_time_pass_config['one_time_pass']}&userid={user_id}&discountcode={code}",
            cancel_url=f"https://localhost:5000/dashboard/{flask_login.current_user.get_username()}/Cart",
        )
    except Exception as e:
        return str(e)

    return redirect(checkout_session.url, code=303)


@app.route('/dashboard/checkout_finalise', methods=['GET', 'POST'])
@login_required
@roles_required('USER')
def checkout_finalise():
    onetimepass = request.args.get('onetimepass')
    userid = request.args.get('userid')
    discountcode = request.args.get('discountcode')

    # verify one time pass
    one_time_pass = db.session.execute(db.Select(AuthenticationModel).filter_by(one_time_pass=onetimepass)).scalar_one()

    if one_time_pass.get_expiration_date() > datetime.datetime.now():
        # need to create transaction log
        checkout_confirmation_helper(user_id=userid)
        if discountcode != None and discountcode != "":
            redeem_voucher(discountcode)

        return redirect(
            url_for('get_cart', username=current_user.get_username(), profile_pic_name=current_user.get_profile_pic()))


@app.route('/admin/dashboard/<path:username>/products/add_product', methods=['GET', 'POST'])
@login_required
@roles_required('PRODUCT_ADMIN')
def create_new_product(username):
    profile_pic_name = request.args.get('profile_pic_name')

    createproductform = CreateProductForm(request.form)

    if request.method == "POST":
        product_id = "PROD_" + secrets.token_urlsafe(32)
        product_name = createproductform.product_name.data
        product_description = createproductform.description.data
        product_quantity = createproductform.quantity.data
        unit_price = createproductform.unit_price.data

        file = request.files["product_pic"]
        main_file = file
        file_to_test = file.stream
        file_name = file.filename
        if file.filename:
             # MARKER FOR FILE UPLOAD PROTECTION
            # use sentinel to check for filename, content and extension, file signature as well
            if Sentinel.FileChecker.is_file_safe(file_to_test, file_name):
                # reset buffer position before save
                main_file.seek(0)

                # prevents double extension vulnerability and command injection via file name
                extension = file.filename.split(".")[1]
                # new_file_name = secrets.randbits(32) + "." + extension
                new_file_name = Sentinel.generate_secure_filename(extension)
                file.save('static/product_pics/' + new_file_name)
            else:
                add_to_log("SUSPICIOUS FILE UPLOAD", request.url, 2, f"Suspicious File rejected: {file.filename}")
                new_file_name = "default.jpg"
        else:
            new_file_name = "default.jpg"

        create_product(
            product_id=product_id,
            product_name=product_name,
            description=product_description,
            quantity=product_quantity,
            unit_price=unit_price,
            product_pic=new_file_name
        )

        return redirect(url_for('get_admin_product_dashboard', profile_pic_name=profile_pic_name, username=username))

    # if username == flask_login.current_user.get_username():
    #     current_user = username
    #     print(current_user)
    #     print(profile_pic_name)
    #
    #     return render_template("dashboard_admin_product.html", profile_pic_name=profile_pic_name, username=username)
    # else:
    #     return redirect(url_for('get_dashboard', username=flask_login.current_user.get_username(), profile_pic_name=flask_login.current_user.get_profile_pic()))


@app.route('/admin/dashboard/<path:username>/products/update_product', methods=['GET', 'POST'])
@login_required
@roles_required('PRODUCT_ADMIN')
def update_product(username):
    # profile_pic_name = request.args.get('profile_pic_name')

    prod_id = request.args.get('product_id')

    createproductform = UpdateProductForm(request.form)

    if request.method == "POST":
        product_name = createproductform.product_name.data
        product_description = createproductform.description.data
        product_quantity = createproductform.quantity.data
        unit_price = createproductform.unit_price.data

        file = request.files["product_pic"]
        main_file = file
        file_to_test = file.stream
        file_name = file.filename
        if file.filename:
            # MARKER FOR FILE UPLOAD PROTECTION
            # use sentinel to check for filename, content and extension, file signature as well
            if Sentinel.FileChecker.is_file_safe(file_to_test, file_name):
                # reset buffer position before save
                main_file.seek(0)

                # prevents double extension vulnerability and command injection via file name
                extension = file.filename.split(".")[1]
                new_file_name = Sentinel.generate_secure_filename(extension)
                file.save('static/product_pics/' + new_file_name)
            else:
                add_to_log("SUSPICIOUS FILE UPLOAD", request.url, 2, f"Suspicious File rejected: {file.filename}")
                product_update = InventoryModel.query.filter_by(product_id=prod_id).first()
                new_file_name = product_update.get_product_pic()
        else:
            product_update = InventoryModel.query.filter_by(product_id=prod_id).first()
            new_file_name = product_update.get_product_pic()

        update_product_helper(
            product_id=prod_id,
            product_name=product_name,
            description=product_description,
            quantity=product_quantity,
            unit_price=unit_price,
            product_pic=new_file_name
        )

        return redirect(
            url_for('get_admin_product_dashboard', profile_pic_name=current_user.get_profile_pic(), username=username))


@app.route('/admin/dashboard/<path:username>/products/delete_product', methods=['GET', 'POST'])
@login_required
@roles_required('PRODUCT_ADMIN')
def delete_product(username):
    product_id = request.args.get('product_id')

    if request.method == "POST":
        product_to_delete = InventoryModel.query.filter_by(product_id=product_id).first()
        if product_to_delete.get_product_pic() != 'default.jpg':
            os.remove('static/product_pics/' + product_to_delete.get_product_pic())

        delete_product_helper(prod_id=product_id)

        return redirect(
            url_for('get_admin_product_dashboard', profile_pic_name=current_user.get_profile_pic(), username=username))


# EVIREC FUNCTIONS

def create_new_evirec_path_helper(logidlist, pathname, desc):
    for id in logidlist:
        evirec_item = EVIRECModel(logid=id, pathname=pathname, description=desc)
        db.session.add(evirec_item)

    db.session.commit()


def get_evirec_log_id_path_list_helper(pathname):
    id_list = []
    list_of_pathname_evirec = db.session.execute(db.Select(EVIRECModel).filter_by(path_name=pathname)).scalars()
    for item in list_of_pathname_evirec:
        id_list.append(item.get_log_id())
    return id_list


def update_evirec_path_helper(logidlist, pathname, desc):
    current_id = get_evirec_log_id_path_list_helper(pathname)
    for id in logidlist:
        if id not in current_id:
            evirec_item = EVIRECModel(logid=id, pathname=pathname, description=desc)
            db.session.add(evirec_item)
        else:
            evirec_it = db.session.execute(db.Select(EVIRECModel).filter_by(evirec_id=id)).scalar_one()
            evirec_it.set_time_updated(datetime.datetime.now())
    db.session.commit()


def update_evirec_path_name_helper(old_path, new_pathname):
    list_of_pathname_evirec = db.session.execute(db.Select(EVIRECModel).filter_by(path_name=old_path)).scalars()
    for entry in list_of_pathname_evirec:
        entry.set_path_name(new_pathname)
        entry.set_time_updated(datetime.datetime.now())
    db.session.commit()


def update_evirec_path_name_and_description_helper(old_path, new_pathname, new_description):
    list_of_pathname_evirec = db.session.execute(db.Select(EVIRECModel).filter_by(path_name=old_path)).scalars()
    for entry in list_of_pathname_evirec:
        entry.set_path_name(new_pathname)
        entry.set_description(new_description)
        entry.set_time_updated(datetime.datetime.now())
    db.session.commit()


def delete_evirec_path_helper(pathName):
    list_of_pathname_evirec = db.session.execute(db.Select(EVIRECModel).filter_by(path_name=pathName)).scalars()
    for entry in list_of_pathname_evirec:
        db.session.delete(entry)
    db.session.commit()
    # db.session.execute(db.Select(AuthenticationModel).filter_by(one_time_pass=onetimepass)).scalar_one()


def delete_evirec_item_helper(evirec_id):
    entry_to_delete = db.session.execute(db.Select(EVIRECModel).filter_by(evirec_id=evirec_id)).scalar_one()
    db.session.delete(entry_to_delete)
    db.session.commit()


def get_all_evirec_of_pathname_helper(pathname):
    # given a evirec pathname
    # return all logs with that pathname as a list
    return EVIRECModel.query.join(LogsModel).filter(EVIRECModel.path_name == pathname).all()


app.jinja_env.globals.update(get_all_evirec_of_pathname=get_all_evirec_of_pathname_helper)


@app.route('/admin/dashboard/<path:username>/evirec/add_path', methods=['POST'])
@login_required
@roles_required('SUPER_ADMIN')
def add_evirec_path(username):
    log_ids_json = request.form.get('log_ids')

    # this is in the form of a list
    log_ids = json.loads(log_ids_json)
    createevirecform = AddToEvirec(request.form)

    pathname = createevirecform.path_name.data
    description = createevirecform.description.data
    if request.method == "POST":

        # write helper function to get log_ids for each id in LogsModel
        # then add to the EVIREC Model table

        # if path does not exist
        if EVIRECModel.query.filter_by(path_name=pathname).first() is None:
            create_new_evirec_path_helper(log_ids, pathname, description)
        else:
            update_evirec_path_helper(log_ids, pathname=pathname, desc=description)

        # then do the same for product where there are tables
        # then when you click show path it will show a table with logs under there

        # then do the click function to allow deletion of logs from the path

        # also allow deletion of path

        # finally if user decides to use same name, it will update the path instead of creating a new path

        return redirect(url_for("view_evirec_paths", username=flask_login.current_user.get_username(),
                                profile_pic_name=flask_login.current_user.get_profile_pic()))


@app.route('/admin/dashboard/<path:username>/evirec', methods=['GET', 'POST'])
@login_required
@roles_required('SUPER_ADMIN')
def view_evirec_paths(username):
    # need to get list of all evirec in log time order
    # evirecmodel = db.session.query(EVIRECModel).join(LogsModel).order_by(LogsModel.time).all()
    updateevirec = UpdateEvirec(request.form)

    evirec_pathname = request.args.get("evirec_pathname")

    # unique rows based on path name
    # i want distince rows based on path name and group by path name
    evirec_model = db.session.query(EVIRECModel).distinct(EVIRECModel.path_name).group_by(EVIRECModel.path_name,
                                                                                          EVIRECModel.evirec_id,
                                                                                          EVIRECModel.log_id).all()

    if request.method == "POST":
        new_path_name = updateevirec.path_name.data
        new_description = updateevirec.description.data
        if new_description == "":
            update_evirec_path_name_helper(old_path=evirec_pathname, new_pathname=new_path_name)
        else:
            update_evirec_path_name_and_description_helper(old_path=evirec_pathname, new_pathname=new_path_name,
                                                           new_description=new_description)

    # needs to have table of evirecs

    return render_template("dashboard_admin_evirec.html", username=flask_login.current_user.get_username(),
                           profile_pic_name=flask_login.current_user.get_profile_pic(), evirec_model=evirec_model,
                           updateevirec=updateevirec)


@app.route('/admin/dashboard/<path:username>/evirec/delete_path', methods=['POST'])
@login_required
@roles_required('SUPER_ADMIN')
def delete_evirec_path(username):
    # need to get list of all evirec

    evirec_path = request.args.get("evirec_path")
    # needs to have table of evirecs
    if request.method == "POST":
        delete_evirec_path_helper(pathName=evirec_path)

    return redirect(url_for("view_evirec_paths", username=flask_login.current_user.get_username(),
                            profile_pic_name=flask_login.current_user.get_profile_pic()))


@app.route('/admin/dashboard/<path:username>/evirec/delete_item', methods=['POST'])
@login_required
@roles_required('SUPER_ADMIN')
def delete_evirec_item(username):
    # need to get list of all evirec

    evirec_id = request.args.get("evirec_id")
    # needs to have table of evirecs
    if request.method == "POST":
        delete_evirec_item_helper(evirec_id=evirec_id)

    return redirect(url_for("view_evirec_paths", username=flask_login.current_user.get_username(),
                            profile_pic_name=flask_login.current_user.get_profile_pic()))

####################################################################################################
# blog section

@app.route('/dashboard/<path:username>/blog', methods=['GET', 'POST'])
@login_required
@roles_required('USER')
def view_user_blog(username):
    if username == flask_login.current_user.get_username():

        # this is to get all blog items
        blogdb = get_all_blog_post_helper()

        # now we need to match the cart product id with the product id that is in the inventory
        # inventory_db = db.session.execute(db.Select(InventoryModel)).scalars()

        return render_template("dashboard_user_view_blog.html", username=flask_login.current_user.get_username(),
                               profile_pic_name=flask_login.current_user.get_profile_pic(), blogmodel=blogdb,
                               )
    else:
        return redirect(url_for('get_dashboard', username=flask_login.current_user.get_username()))


####################################################################################################
# feedback section

@app.route('/dashboard/<path:username>/feedback', methods=['GET', 'POST'])
@login_required
@roles_required('USER')
def view_user_feedback(username):
    updateform = UpdateFeedback(request.form)
    createform = CreateFeedback(request.form)
    if username == flask_login.current_user.get_username():

        # this is to get all blog items
        feedback_db = get_feedback_made_by_user(user_who_created=flask_login.current_user)

        # now we need to match the cart product id with the product id that is in the inventory
        # inventory_db = db.session.execute(db.Select(InventoryModel)).scalars()

        return render_template("dashboard_user_view_feedback.html", username=flask_login.current_user.get_username(),
                               profile_pic_name=flask_login.current_user.get_profile_pic(), feedback_model=feedback_db,
                               updateform=updateform, createform=createform)
    else:
        return redirect(url_for('get_dashboard', username=flask_login.current_user.get_username()))

@app.route('/dashboard/<path:username>/feedback/update', methods=['POST'])
@login_required
@roles_required('USER')
def update_feedback(username):
    updateform = UpdateFeedback(request.form)
    new_title = updateform.new_title.data
    new_desc = updateform.new_desc.data
    id_feedback = request.args.get('feedback_id')

    if username == flask_login.current_user.get_username():

        update_specific_feedback(id_feedback, new_title, new_desc)

        return redirect(url_for('view_user_feedback', username=flask_login.current_user.get_username(),
                               profile_pic_name=flask_login.current_user.get_profile_pic()))
    else:
        return redirect(url_for('get_dashboard', username=flask_login.current_user.get_username()))

# need to create and delete feedback

@app.route('/dashboard/<path:username>/feedback/delete', methods=['POST'])
@login_required
@roles_required('USER')
def delete_feedback(username):
    id_feedback = request.args.get('feedback_id')
    if username == flask_login.current_user.get_username():

        delete_feedback_helper(feedback_id=id_feedback)

        return redirect(url_for('view_user_feedback', username=flask_login.current_user.get_username(),
                               profile_pic_name=flask_login.current_user.get_profile_pic()))
    else:
        return redirect(url_for('get_dashboard', username=flask_login.current_user.get_username()))

@app.route('/dashboard/<path:username>/feedback/create', methods=['POST'])
@login_required
@roles_required('USER')
def create_new_feedback(username):
    createform = CreateFeedback(request.form)
    title = createform.new_title.data
    desc = createform.new_desc.data
    if username == flask_login.current_user.get_username():

        create_feedback_helper(flask_login.current_user, title, desc)

        return redirect(url_for('view_user_feedback', username=flask_login.current_user.get_username(),
                               profile_pic_name=flask_login.current_user.get_profile_pic()))
    else:
        return redirect(url_for('get_dashboard', username=flask_login.current_user.get_username()))

@app.route('/admin/dashboard/<path:username>/feedbackmanagement', methods=['GET'])
@login_required
@roles_required('PR_ADMIN')
def admin_view_all_feedback(username):
    if username == flask_login.current_user.get_username():

        # this is to get all blog items
        feedback_db = get_all_feedback_for_admin()

        # now we need to match the cart product id with the product id that is in the inventory
        # inventory_db = db.session.execute(db.Select(InventoryModel)).scalars()

        return render_template("dashboard_admin_feedback.html", username=flask_login.current_user.get_username(),
                               profile_pic_name=flask_login.current_user.get_profile_pic(), feedback_model=feedback_db,
                               )
    else:
        return redirect(url_for('get_dashboard', username=flask_login.current_user.get_username()))


######################################################################################
# blog
@app.route('/dashboard/<path:username>/blogs', methods=['GET'])
@login_required
@roles_required('USER')
def user_view_all_blogpost(username):
    if username == flask_login.current_user.get_username():

        # this is to get all blog items
        blogdb = get_all_blog_post_helper()

        # now we need to match the cart product id with the product id that is in the inventory
        # inventory_db = db.session.execute(db.Select(InventoryModel)).scalars()

        return render_template("dashboard_user_blog.html", username=flask_login.current_user.get_username(),
                               profile_pic_name=flask_login.current_user.get_profile_pic(), blogmodel=blogdb,
                               )
    else:
        return redirect(url_for('get_dashboard', username=flask_login.current_user.get_username()))

@app.route('/admin/dashboard/<path:username>/blogmanagement', methods=['GET', 'POST'])
@login_required
@roles_required('BLOG_ADMIN')
def admin_view_all_blogpost(username):
    updateform = UpdateBlogPost(request.form)
    createform = CreateBlogPost(request.form)
    if username == flask_login.current_user.get_username():

        # this is to get all blog items
        blogdb = get_all_blog_post_helper()

        # now we need to match the cart product id with the product id that is in the inventory
        # inventory_db = db.session.execute(db.Select(InventoryModel)).scalars()

        return render_template("dashboard_admin_blog.html", username=flask_login.current_user.get_username(),
                               profile_pic_name=flask_login.current_user.get_profile_pic(), blogmodel=blogdb,
                               updateform=updateform, createform=createform)
    else:
        return redirect(url_for('get_dashboard', username=flask_login.current_user.get_username()))

@app.route('/admin/dashboard/<path:username>/blogmanagement/create', methods=['POST'])
@login_required
@roles_required('BLOG_ADMIN')
def admin_create_new_blog(username):
    createform = CreateBlogPost(request.form)
    title = createform.new_title.data
    description = createform.new_desc.data
    file = request.files['blog_pic']
    main_file = file
    file_to_test = file.stream
    file_name = file.filename
    if username == flask_login.current_user.get_username() and createform.validate_on_submit():
        user_who_submitted = db.session.execute(db.Select(UserModel).filter_by(username=username)).scalar_one()

        if file.filename:
            # MARKER FOR FILE UPLOAD PROTECTION
            # use sentinel to check for filename, content and extension, file signature as well
            if Sentinel.FileChecker.is_file_safe(file_to_test, file_name):
                # reset buffer position before save
                main_file.seek(0)
                # prevents double extension vulnerability and command injection via file name
                extension = file.filename.split(".")[1]
                # new_file_name = secrets.randbits(32) + "." + extension
                new_file_name = Sentinel.generate_secure_filename(extension)
                file.save('static/blog_pics/' + new_file_name)
            else:
                add_to_log("SUSPICIOUS FILE UPLOAD", request.url, 2, f"Suspicious File rejected: {file.filename}")
                new_file_name = "default.jpg"
        else:
            new_file_name = "default.jpg"

        create_blog_post_helper(user_who_submitted, title=title, description=description, picture_name=new_file_name)

        return redirect(url_for('admin_view_all_blogpost', username=flask_login.current_user.get_username(),
                               profile_pic_name=flask_login.current_user.get_profile_pic()))
    else:
        return redirect(url_for('authenticated_user'))

@app.route('/admin/dashboard/<path:username>/blogmanagement/update', methods=['POST'])
@login_required
@roles_required('BLOG_ADMIN')
def admin_update_blog(username):
    blog_id = request.args.get('blog_id')
    updateform = UpdateBlogPost(request.form)
    title = updateform.new_title.data
    description = updateform.new_desc.data
    file = request.files['blog_pic']
    main_file = file
    file_to_test = file.stream
    file_name = file.filename
    if username == flask_login.current_user.get_username() and updateform.validate_on_submit():
        user_who_updated = db.session.execute(db.Select(UserModel).filter_by(username=username)).scalar_one()
        if file.filename:
             # MARKER FOR FILE UPLOAD PROTECTION
            # use sentinel to check for filename, content and extension, file signature as well
            if Sentinel.FileChecker.is_file_safe(file_to_test, file_name):
                # reset buffer position before save
                main_file.seek(0)
                # prevents double extension vulnerability and command injection via file name
                extension = file.filename.split(".")[1]
                # new_file_name = secrets.randbits(32) + "." + extension
                new_file_name = Sentinel.generate_secure_filename(extension)
                file.save('static/blog_pics/' + new_file_name)
            else:
                 add_to_log("SUSPICIOUS FILE UPLOAD", request.url, 2, f"Suspicious File rejected: {file.filename}")
                 blog_update = BlogModel.query.filter_by(id=blog_id).first()
                 new_file_name = blog_update.get_picture_name()
        else:
            blog_update = BlogModel.query.filter_by(id=blog_id).first()
            new_file_name = blog_update.get_picture_name()
        update_blog_post_helper(blog_id=blog_id, title=title, description=description, picture_name=new_file_name, user_who_updated=user_who_updated)

        return redirect(url_for('admin_view_all_blogpost', username=flask_login.current_user.get_username(),
                               profile_pic_name=flask_login.current_user.get_profile_pic()))
    else:
        return redirect(url_for('authenticated_user'))

@app.route('/admin/dashboard/<path:username>/blogmanagement/delete', methods=['POST'])
@login_required
@roles_required('BLOG_ADMIN')
def admin_delete_blog(username):
    blog_id = request.args.get('blog_id')
    if username == flask_login.current_user.get_username():
        delete_blog_helper(blog_id)

        return redirect(url_for('admin_view_all_blogpost', username=flask_login.current_user.get_username(),
                               profile_pic_name=flask_login.current_user.get_profile_pic()))
    else:
        return redirect(url_for('authenticated_user'))

@app.route('/admin/dashboard/<path:username>/vouchermanagement', methods=['GET', 'POST'])
@login_required
@roles_required('FINANCE_ADMIN')
def admin_view_all_vouchers(username):
    updateform = UpdateVoucherForm(request.form)
    createform = CreateVoucherForm(request.form)
    if username == flask_login.current_user.get_username():

        # this is to get all blog items
        voucherinventorydb = get_all_admin_voucher_blueprints()

        # now we need to match the cart product id with the product id that is in the inventory
        # inventory_db = db.session.execute(db.Select(InventoryModel)).scalars()

        return render_template("dashboard_admin_voucher.html", username=flask_login.current_user.get_username(),
                               profile_pic_name=flask_login.current_user.get_profile_pic(), voucherinventorymodel=voucherinventorydb,
                               updateform=updateform, createform=createform)
    else:
        return redirect(url_for('authenticated_user'))

@app.route('/admin/dashboard/<path:username>/vouchermanagement/create', methods=['POST'])
@login_required
@roles_required('FINANCE_ADMIN')
def admin_create_new_voucher(username):
    createform = CreateVoucherForm(request.form)
    name = createform.name.data
    description = createform.description.data
    percent = createform.percent.data
    quantity = createform.quantity.data
    unit_points = createform.unit_points_needed.data

    if username == flask_login.current_user.get_username() and createform.validate_on_submit():
        user_who_submitted = db.session.execute(db.Select(UserModel).filter_by(username=username)).scalar_one()


        create_voucher_blueprint_admin(name=name,
                                       desc=description,
                                       percent=percent,
                                       quantity=quantity,
                                       points_needed=unit_points)

        return redirect(url_for('admin_view_all_vouchers', username=flask_login.current_user.get_username(),
                               profile_pic_name=flask_login.current_user.get_profile_pic()))
    else:
        return redirect(url_for('authenticated_user'))

@app.route('/admin/dashboard/<path:username>/vouchermanagement/update', methods=['POST'])
@login_required
@roles_required('FINANCE_ADMIN')
def admin_update_voucher(username):
    voucher_id = request.args.get('voucher_id')
    updateform = UpdateVoucherForm(request.form)
    name = updateform.name.data
    description = updateform.description.data
    percent = updateform.percent.data
    quantity = updateform.quantity.data
    unit_points = updateform.unit_points_needed.data

    if username == flask_login.current_user.get_username() and updateform.validate_on_submit():
        print("Here")
        user_who_updated = db.session.execute(db.Select(UserModel).filter_by(username=username)).scalar_one()

        update_voucher_blueprint_admin(voucher_blueprint_id=voucher_id,
                                       name=name,
                                       desc=description,
                                       percent=percent,
                                       quantity=quantity,
                                       points_needed=unit_points)

        return redirect(url_for('admin_view_all_vouchers', username=flask_login.current_user.get_username(),
                               profile_pic_name=flask_login.current_user.get_profile_pic()))
    else:
        return redirect(url_for('authenticated_user'))

@app.route('/admin/dashboard/<path:username>/vouchermanagement/delete', methods=['POST'])
@login_required
@roles_required('FINANCE_ADMIN')
def admin_delete_voucher_blueprint(username):
    voucher_id = request.args.get('voucher_id')
    if username == flask_login.current_user.get_username():
        delete_voucher_blueprint_admin(voucher_id)

        return redirect(url_for('admin_view_all_vouchers', username=flask_login.current_user.get_username(),
                               profile_pic_name=flask_login.current_user.get_profile_pic()))
    else:
        return redirect(url_for('authenticated_user'))

######################################################################################
# user redeem voucher
@app.route('/dashboard/<path:username>/vouchers', methods=['GET'])
@login_required
@roles_required('USER')
def user_view_all_vouchers(username):
    codepointsform = RedeemCodeForm(request.form)
    if username == flask_login.current_user.get_username():

        # this is to get all blog items
        vouchers_to_redeem = get_all_user_voucher_can_redeem()

        user_owned_vouchers = get_all_user_voucher(flask_login.current_user)

        current_user_balance = flask_login.current_user.account.get_points_balance()

        # now we need to match the cart product id with the product id that is in the inventory
        # inventory_db = db.session.execute(db.Select(InventoryModel)).scalars()

        return render_template("dashboard_user_voucher.html", username=flask_login.current_user.get_username(),
                               profile_pic_name=flask_login.current_user.get_profile_pic(), voucherinventorymodel=vouchers_to_redeem,
                               vouchercartmodel = user_owned_vouchers,
                               current_balance=current_user_balance,
                               codepointsform=codepointsform)
    else:
        return redirect(url_for('get_dashboard', username=flask_login.current_user.get_username()))

@app.route('/dashboard/<path:username>/vouchers/get_points', methods=['POST'])
@login_required
@roles_required('USER')
def user_add_points(username):
    codepointsform = RedeemCodeForm(request.form)
    code = codepointsform.code.data
    if username == flask_login.current_user.get_username():

        if code == "TESTING":
            curr_user = flask_login.current_user
            redeem_code_for_points(curr_user, 1000)
            print("Success")

        return redirect(url_for("user_view_all_vouchers", username=flask_login.current_user.get_username(),
                               profile_pic_name=flask_login.current_user.get_profile_pic()))
    else:
        return redirect(url_for('get_dashboard', username=flask_login.current_user.get_username()))



@app.route('/dashboard/<path:username>/vouchers/generate', methods=['GET', 'POST'])
@login_required
@roles_required('USER')
def user_generate_voucher(username):
    voucher_id = request.args.get('voucher_id')
    if username == flask_login.current_user.get_username():
        generate_voucher_user(voucher_blueprint_id=voucher_id,
                              user_obj=flask_login.current_user)


        # now we need to match the cart product id with the product id that is in the inventory
        # inventory_db = db.session.execute(db.Select(InventoryModel)).scalars()

        return redirect(url_for('user_view_all_vouchers', username=flask_login.current_user.get_username(),
                               profile_pic_name=flask_login.current_user.get_profile_pic()))
    else:
        return redirect(url_for('get_dashboard', username=flask_login.current_user.get_username()))




@login_manager.unauthorized_handler
def unauthorized():
    print("Unauthorized access")
    return redirect(url_for("index"))


if __name__ == '__main__':
    website_url = 'localhost:5000'
    app.config['SERVER_NAME'] = website_url
    app.run(debug=True, ssl_context=('cert.pem', 'key.pem'))

    # 7310 lines
