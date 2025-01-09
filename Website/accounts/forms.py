import re

from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Length, Regexp


class RegistrationForm(FlaskForm):
    email = StringField(validators=(DataRequired(),
                                    Regexp(r"^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", flags=re.IGNORECASE,
                                           message="A valid email address must be provided")))
    firstname = StringField(validators=(DataRequired(), Regexp(r"^[a-z-]+$", flags=re.IGNORECASE,
                                                               message="First name cannot contain any spaces or special characters other than a hyphen")))
    lastname = StringField(validators=(DataRequired(), Regexp(r"^[a-z-]+$", flags=re.IGNORECASE,
                                                              message="Surname cannot contain any spaces or special characters other than a hyphen")))
    phone = StringField(validators=(DataRequired(), Regexp(
        r"^(02[0-9]-[0-9]{8}|011[0-9]-[0-9]{7}|01[0-9]1-[0-9]{7}|01[0-9]{3}-[0-9]{5,6})",
        message="A valid UK landline must be provided")))
    password = PasswordField(
        validators=[DataRequired(), Length(min=8, max=15, message="Password must be between 8 and 15 characters")
            , Regexp(r"(?=.*[a-z])", message="Password must contain a lowercase letter")
            , Regexp(r"(?=.*[A-Z])", message="Password must contain a capital letter")
            , Regexp(r"(?=.*[0-9])", message="Password must contain a number")
            , Regexp(r"(?=.*[@$!%*?&-])", message="Password must contain a special character")
                    ])

    confirm_password = PasswordField(
        validators=[DataRequired(), EqualTo('password', message='Both password fields must be equal!')])
    submit = SubmitField()


class LoginForm(FlaskForm):
    email = StringField(validators=(DataRequired(),))
    password = PasswordField(validators=(DataRequired(),))
    pin = StringField(validators=(DataRequired(), Length(min=6, max=6)))
    recaptcha = RecaptchaField()
    submit = SubmitField()
