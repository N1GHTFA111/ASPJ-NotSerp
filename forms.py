import secrets
import uuid

from wtforms import Form, StringField, RadioField, SelectField, TextAreaField, validators, IntegerField, FloatField, \
    DecimalRangeField, FileField, BooleanField
from wtforms.fields import EmailField, DateField, PasswordField, SubmitField
from flask_wtf import FlaskForm, RecaptchaField

from flask_wtf.csrf import CSRFProtect


class CreateLoginForm(FlaskForm):
    email = EmailField('Email', [validators.Email(), validators.DataRequired()])
    password = PasswordField('Password', [validators.Length(min=1, max=200), validators.DataRequired()])
    rememberme = SelectField('Remember Me', choices=['Not Enabled', 'Enabled'])
    recaptcha = RecaptchaField()

class CreateUserForm(FlaskForm):
    username = StringField('Username', [validators.Length(min=1, max=200), validators.DataRequired()])
    email = EmailField('Email', [validators.Email(), validators.DataRequired()])
    phone = StringField('Phone (+65 12345678)', [validators.Length(min=1, max=200), validators.DataRequired()])
    password = PasswordField('Password', [validators.Length(min=1, max=200), validators.DataRequired(),
                                          validators.EqualTo('password_confirm', message='Passwords do not match. Retype Password.'),
                                          validators.Regexp(
                                              r'^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[^\w\s]).{12,}$',
                                              message="Password must be at least 12 characters long and includes at least 1 uppercase, 1 lowercase, 1 digit and 1 symbol"
                                          )])
    password_confirm = PasswordField('Confirm Password', [validators.Length(min=1, max=200), validators.DataRequired(),])
    profile_pic = FileField('Upload Profile Picture')


class CreateAdminForm(FlaskForm):
    username = StringField('Username', [validators.Length(min=1, max=200), validators.DataRequired()])
    email = EmailField('Email', [validators.Email(), validators.DataRequired()])
    phone = StringField('Phone (+65 12345678)', [validators.Length(min=1, max=200), validators.DataRequired()])
    password = PasswordField('Password', [validators.Length(min=1, max=200), validators.DataRequired(),
                                          validators.EqualTo('password_confirm', message='Passwords do not match. Retype Password.'),
                                          validators.Regexp(
                                              r'^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[^\w\s]).{12,}$',
                                              message="Password must be at least 12 characters long and includes at least 1 uppercase, 1 lowercase, 1 digit and 1 symbol"
                                          )
                                          ])
    password_confirm = PasswordField('Confirm Password', [validators.Length(min=1, max=200), validators.DataRequired(), ])
    role = SelectField('Role', validators=[validators.InputRequired()], choices=[])
    profile_pic = FileField('Upload Profile Picture')

class CreateRoleForm(FlaskForm):
    rolename = StringField('Role Name', [validators.Length(min=1, max=200), validators.DataRequired()])
    havesuperadmin_permission = SelectField('Super Admin Permission',
                                           choices=[('Unauthorized', 'Unauthorized'), ('Authorized', 'Authorized')],
                                           default="Unauthorized")
    havefinanceadmin_permission = SelectField('Finance Admin Permission',
                                             choices=[('Unauthorized', 'Unauthorized'), ('Authorized', 'Authorized')],
                                             default="Unauthorized")
    haveproductadmin_permission = SelectField('Product Admin Permission',
                                             choices=[('Unauthorized', 'Unauthorized'), ('Authorized', 'Authorized')],
                                             default="Unauthorized")
    haveblogadmin_permission = SelectField('Blog Admin Permission',
                                          choices=[('Unauthorized', 'Unauthorized'), ('Authorized', 'Authorized')],
                                          default="Unauthorized")
    havepradmin_permission = SelectField('PR Admin Permission',
                                        choices=[('Unauthorized', 'Unauthorized'), ('Authorized', 'Authorized')],
                                        default="Unauthorized")
    haveuser_permission = SelectField('User Permission',
                                     choices=[('Unauthorized', 'Unauthorized'), ('Authorized', 'Authorized')],
                                     default="Unauthorized")

class UpdateRoleForm(FlaskForm):
    rolename = StringField('Role Name', [validators.Length(min=1, max=200), validators.DataRequired()])
    havesuperadmin_permission = SelectField('Super Admin Permission', choices=[('Unauthorized', 'Unauthorized'), ('Authorized', 'Authorized')], default="Unauthorized")
    havefinanceadmin_permission = SelectField('Finance Admin Permission', choices=[('Unauthorized', 'Unauthorized'), ('Authorized', 'Authorized')], default="Unauthorized")
    haveproductadmin_permission = SelectField('Product Admin Permission', choices=[('Unauthorized', 'Unauthorized'), ('Authorized', 'Authorized')], default="Unauthorized")
    haveblogadmin_permission = SelectField('Blog Admin Permission', choices=[('Unauthorized', 'Unauthorized'), ('Authorized', 'Authorized')], default="Unauthorized")
    havepradmin_permission = SelectField('PR Admin Permission', choices=[('Unauthorized', 'Unauthorized'), ('Authorized', 'Authorized')], default="Unauthorized")
    haveuser_permission = SelectField('User Permission', choices=[('Unauthorized', 'Unauthorized'), ('Authorized', 'Authorized')], default="Unauthorized")


class CustomFileField(FileField):
    def process_data(self, value):
        self.data = value

class UpdateUserForm(FlaskForm):
    username = StringField('username', [validators.Length(min=1, max=200), validators.DataRequired()])
    email = EmailField('Email', [validators.Email(), validators.DataRequired()])
    phone = StringField('Phone (+65 12345678)', [validators.Length(min=1, max=200), validators.DataRequired()])
    old_password = PasswordField('Old Password', [validators.Length(min=1, max=200), validators.DataRequired(), ])
    password = PasswordField('Password', [validators.Length(min=1, max=200), validators.DataRequired(),
                                          validators.EqualTo('password_confirm', message='Passwords do not match. Retype Password.'),
                                          validators.Regexp(
                                              r'^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[^\w\s]).{12,}$',
                                              message="Password must be at least 12 characters long and includes at least 1 uppercase, 1 lowercase, 1 digit and 1 symbol"
                                          )
                                          ])
    password_confirm = PasswordField('Confirm Password', [validators.Length(min=1, max=200), validators.DataRequired(), ])
    enable_2fa = SelectField('Enable 2FA via email OTP', choices=['Not Enabled', 'Enabled'])
    profile_pic = FileField('Upload Profile Picture')

class UpdateUserAdminForm(FlaskForm):
    username = StringField('username', [validators.Length(min=1, max=200), validators.DataRequired()])
    email = EmailField('Email', [validators.Email(), validators.DataRequired()])
    phone = StringField('Phone (+65 12345678)', [validators.Length(min=1, max=200), validators.DataRequired()])
    old_password = PasswordField('Old Password', [validators.Length(min=1, max=200), validators.DataRequired(), ])
    password = PasswordField('Password', [validators.Length(min=1, max=200), validators.DataRequired(),
                                          validators.EqualTo('password_confirm', message='Passwords do not match. Retype Password.'),
                                          validators.Regexp(
                                              r'^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[^\w\s]).{12,}$',
                                              message="Password must be at least 12 characters long and includes at least 1 uppercase, 1 lowercase, 1 digit and 1 symbol"
                                          )
                                          ])
    password_confirm = PasswordField('Confirm Password', [validators.Length(min=1, max=200), validators.DataRequired(), ])
    enable_2fa = SelectField('Enable 2FA via email OTP', choices=['Not Enabled', 'Enabled'])
    role = SelectField('Role', choices=['SUPER_ADMIN', 'FINANCE_ADMIN', 'BLOG_ADMIN', 'PR_ADMIN', 'PRODUCT_ADMIN'])
    profile_pic = FileField('Upload Profile Picture')

class EmailVerificationForm(FlaskForm):
    email = EmailField('Email', [validators.Email(), validators.DataRequired()])

class ForgetPasswordForm(FlaskForm):
    password = PasswordField('Password', [validators.Length(min=1, max=200), validators.DataRequired()])
    confirm_password = PasswordField('Password', [validators.Length(min=1, max=200), validators.DataRequired()])
    OTP = StringField('OTP Token', [validators.Length(min=1, max=200), validators.DataRequired()])

class Login2FAForm(FlaskForm):
    OTP = StringField('OTP Token', [validators.Length(min=1, max=200), validators.DataRequired()])

class CreateProductForm(FlaskForm):
    # product_id, product_name, description, quantity, unit_price,
    # product_pic
    product_name = StringField('Product Name', [validators.Length(min=1, max=200), validators.DataRequired()])
    description = StringField('Description', [validators.Length(min=1, max=200), validators.DataRequired()])
    quantity = IntegerField('Quantity', [validators.NumberRange(min=1, max=None), validators.DataRequired()])
    unit_price = FloatField('Unit Price', [validators.DataRequired(), validators.NumberRange(min=1, max=None)])
    product_pic = FileField('Upload Product Picture')

class UpdateProductForm(FlaskForm):
    # product_id, product_name, description, quantity, unit_price,
    # product_pic
    product_name = StringField('Product Name', [validators.Length(min=1, max=200), validators.DataRequired()])
    description = StringField('Description', [validators.Length(min=1, max=200), validators.DataRequired()])
    quantity = IntegerField('Quantity', [validators.NumberRange(min=1, max=None), validators.DataRequired()])
    unit_price = FloatField('Unit Price', [validators.DataRequired(), validators.NumberRange(min=1, max=None)])
    product_pic = FileField('Upload Product Picture')

class QuantityForm(FlaskForm):
    quantity = IntegerField('Quantity', [validators.NumberRange(min=1, max=None), validators.DataRequired()])

    def __init__(self, max_value, *args, **kwargs):
        super(QuantityForm, self).__init__(*args, **kwargs)
        self.quantity.validators[0].max = max_value

class QuantityFormUpdate(FlaskForm):
    quantity = IntegerField('Quantity', [validators.NumberRange(min=1, max=None), validators.DataRequired()])

class AddToEvirec(FlaskForm):
    path_name = StringField('Name of Evidence Path', [validators.Length(min=1, max=200), validators.DataRequired()])
    description = StringField('Description', [validators.Length(min=1, max=200)])

class UpdateEvirec(FlaskForm):
    path_name = StringField('New name of Evidence Path', [validators.Length(min=1, max=200), validators.DataRequired()])
    description = StringField('New Description', [validators.Length(min=1, max=200)])

class UpdateFeedback(FlaskForm):
    new_title = StringField('New Title', [validators.Length(min=1, max=200), validators.DataRequired()])
    new_desc = StringField('New Description', [validators.Length(min=1, max=200), validators.DataRequired()])

class CreateFeedback(FlaskForm):
    new_title = StringField('New Title', [validators.Length(min=1, max=200), validators.DataRequired()])
    new_desc = StringField('New Description', [validators.Length(min=1, max=200), validators.DataRequired()])

class CreateBlogPost(FlaskForm):
    new_title = StringField('New Title', [validators.Length(min=1, max=200), validators.DataRequired()])
    new_desc = StringField('New Description', [validators.Length(min=1, max=200), validators.DataRequired()])
    blog_pic = FileField('Upload Blog Picture')

class UpdateBlogPost(FlaskForm):
    new_title = StringField('New Title', [validators.Length(min=1, max=200), validators.DataRequired()])
    new_desc = StringField('New Description', [validators.Length(min=1, max=200), validators.DataRequired()])
    blog_pic = FileField('Upload Blog Picture')

class CreateVoucherForm(FlaskForm):
    name = StringField('Name', [validators.Length(min=1, max=100), validators.DataRequired()])
    description = StringField('Description', [validators.Length(min=1, max=100), validators.DataRequired()])
    percent = FloatField('Percent Off', [validators.DataRequired(), validators.NumberRange(min=1, max=100)])
    quantity = IntegerField('Quantity', [validators.DataRequired(), validators.NumberRange(min=1, max=None)])
    unit_points_needed = FloatField('Points Needed', [validators.DataRequired(), validators.NumberRange(min=1, max=None)])

class UpdateVoucherForm(FlaskForm):
    name = StringField('Name', [validators.Length(min=1, max=100), validators.DataRequired()])
    description = StringField('Description', [validators.Length(min=1, max=100), validators.DataRequired()])
    percent = FloatField('Percent Off', [validators.DataRequired(), validators.NumberRange(min=1, max=100)])
    quantity = IntegerField('Quantity', [validators.DataRequired(), validators.NumberRange(min=1, max=None)])
    unit_points_needed = FloatField('Points Needed', [validators.DataRequired(), validators.NumberRange(min=1, max=None)])

class RedeemCodeForm(FlaskForm):
    code = StringField('Code', [validators.Length(min=1, max=100), validators.DataRequired()])

class CheckoutVoucherForm(FlaskForm):
    code = StringField('Code', [validators.Length(min=1, max=100)])
