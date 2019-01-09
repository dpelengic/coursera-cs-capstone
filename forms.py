from flask_wtf import FlaskForm
from flask_wtf.recaptcha import RecaptchaField
from wtforms import StringField, TextField, TextAreaField, PasswordField, SubmitField
from wtforms.validators import Email, DataRequired, Length, EqualTo

class RegisterForm(FlaskForm):
    email = StringField("email", validators=[DataRequired(),Email()])
    password = PasswordField("password", validators=[DataRequired(), Length(min=8, max=50), EqualTo("confirmpassword")])
    confirmpassword = PasswordField("confirmpassword")
    submit = SubmitField("register")

class RegisterFormRecaptcha(FlaskForm):
    email = StringField("email", validators=[DataRequired(),Email()])
    password = PasswordField("password", validators=[DataRequired(), Length(min=8, max=50), EqualTo("confirmpassword")])
    confirmpassword = PasswordField("confirmpassword")
    recaptcha = RecaptchaField()
    submit = SubmitField("register")

class LoginForm(FlaskForm):
    email = StringField("email", validators=[DataRequired(),Email()])
    password = PasswordField("password", validators=[DataRequired()])
    submit = SubmitField("login")

class LoginFormRecaptcha(FlaskForm):
    email = StringField("email", validators=[DataRequired(),Email()])
    password = PasswordField("password", validators=[DataRequired()])
    recaptcha = RecaptchaField()
    submit = SubmitField("login")

class MessageForm(FlaskForm):
    email = StringField("email", validators=[DataRequired(),Email()])
    message = TextAreaField("message", validators=[DataRequired(), Length(max=120)])
    submit = SubmitField("message")
