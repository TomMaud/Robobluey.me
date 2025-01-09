import base64
import datetime
import logging
import os
import secrets
from datetime import datetime

import dotenv
from argon2 import PasswordHasher
from flask import Flask, url_for, flash, redirect, request
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_admin.menu import MenuLink
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager, UserMixin, current_user
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_talisman import Talisman
from sqlalchemy import MetaData

dotenv.set_key(dotenv_path=".env", key_to_set="SECRET_KEY", value_to_set=secrets.token_hex(16))

app = Flask(__name__)
dotenv.load_dotenv()
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("SQLALCHEMY_DATABASE_URI")
app.config["SQLALCHEMY_ECHO"] = os.getenv("SQLALCHEMY_ECHO")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = os.getenv("SQLALCHEMY_TRACK_MODIFICATIONS")

app.config["RECAPTCHA_PUBLIC_KEY"] = os.getenv("RECAPTCHA_PUBLIC_KEY")
app.config["RECAPTCHA_PRIVATE_KEY"] = os.getenv("RECAPTCHA_PRIVATE_KEY")
app.config["FLASK_ADMIN_FLUID_LAYOUT"] = os.getenv("FLASK_ADMIN_FLUID_LAYOUT")
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config['PREFERRED_URL_SCHEME'] = 'https'

csp = {
    "style-src": ['\'self\'', "https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css"],
    "script-src": [
        '\'self\'',
        '\'unsafe-inline\'',
        "https://www.google.com/recaptcha/",
        "https://www.gstatic.com/recaptcha/",
        "https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/js/bootstrap.bundle.min.js"
    ],
    "frame-src": [
        '\'self\'',
        "https://www.google.com/recaptcha/",
        "https://recaptcha.google.com/recaptcha/"
    ]
}

talisman = Talisman(app, content_security_policy=csp, force_https=True)

login_manager = LoginManager()

login_manager.init_app(app)
login_manager.login_message = 'You must be logged in to view this page'
login_manager.login_message_category = 'nologin'

logger = logging.getLogger('Tom Project Logger')
logger.setLevel(logging.INFO)
handler = logging.FileHandler('security.log', 'a')
handler.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s : %(message)s", "%d/%m/%Y %H:%M:%S")
handler.setFormatter(formatter)
logger.addHandler(handler)
ph = PasswordHasher()

metadata = MetaData(
    naming_convention={
        "ix": 'ix_%(column_0_label)s',
        "uq": "uq_%(table_name)s_%(column_0_name)s",
        "ck": "ck_%(table_name)s_%(constraint_name)s",
        "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
        "pk": "pk_%(table_name)s"
    }
)

limiter = Limiter(get_remote_address, app=app, default_limits=["500 per day"], )

db = SQLAlchemy(app, metadata=metadata)
migrate = Migrate(app, db)


class Post(db.Model):
    __tablename__ = 'posts'

    id = db.Column(db.Integer, primary_key=True)
    userid = db.Column(db.Integer, db.ForeignKey('users.id'))
    created = db.Column(db.DateTime, nullable=False)
    title = db.Column(db.Text, nullable=False)
    body = db.Column(db.Text, nullable=False)
    user = db.relationship("User", back_populates="posts")

    def __init__(self, title, body, userid, user):
        self.created = datetime.now()
        self.title = title
        self.body = body
        self.userid = userid
        self.user = user

    def update(self, title, body):
        self.created = datetime.now()
        self.title = title
        self.body = body
        db.session.commit()


class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    firstname = db.Column(db.String(100), nullable=False)
    lastname = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(100), nullable=False)
    mfakey = db.Column(db.String(32), nullable=False)
    mfaenabled = db.Column(db.Boolean(), nullable=False)
    role = db.Column(db.String(32), nullable=False)
    salt = db.Column(db.String(100), nullable=False)

    # User posts
    posts = db.relationship("Post", order_by=Post.id, back_populates="user")
    logs = db.relationship("Log", back_populates="loguser", uselist=False)

    def __init__(self, email, firstname, lastname, phone, password, mfakey, mfaenabled, role):
        self.email = email.lower()
        self.firstname = firstname
        self.lastname = lastname
        self.phone = phone
        self.password = password
        self.mfakey = mfakey
        self.mfaenabled = mfaenabled
        self.role = role
        self.salt = base64.b64encode(secrets.token_bytes(32)).decode()

    def verify_password(self, passwordcheck):
        try:
            if ph.verify(self.password, passwordcheck):
                return True
            else:
                return False
        except:
            return False

    def changemfaenabled(self):
        self.mfaenabled = True
        db.session.commit()

    def createlog(self):
        return Log(self.id)


class Log(db.Model):
    __tablename__ = 'logs'

    logid = db.Column(db.Integer, primary_key=True)
    loguserid = db.Column(db.Integer, db.ForeignKey('users.id'))
    registrationdate = db.Column(db.DateTime, nullable=False)
    latestlogindate = db.Column(db.DateTime, nullable=True)
    lastlogindate = db.Column(db.DateTime, nullable=True)
    latestip = db.Column(db.String(100), nullable=True)
    lastip = db.Column(db.String(100), nullable=True)
    loguser = db.relationship("User", back_populates="logs")

    def __init__(self, loguserid):
        self.loguserid = loguserid
        self.registrationdate = datetime.now()

    def update(self, lastlogindate, lastip, latestip):
        self.lastlogindate = lastlogindate
        self.lastip = lastip
        self.latestlogindate = datetime.now()
        self.latestip = latestip
        db.session.commit()


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))


from security.views import security_bp
from posts.views import posts_bp
from accounts.views import accounts_bp
from errors.views import errors_bp

app.register_blueprint(accounts_bp)
app.register_blueprint(posts_bp)
app.register_blueprint(security_bp)

app.register_blueprint(errors_bp)


class MainIndexLink(MenuLink):
    def get_url(self):
        return url_for('index')


class PostView(ModelView):
    column_display_pk = True
    column_hide_backrefs = False
    column_list = ('id', 'userid', 'created', 'title', 'body', 'user')

    def is_accessible(self):
        if not current_user.is_authenticated:
            return False
        else:
            user = load_user(current_user.id)
            if user.role == "db_admin":
                return True
            else:
                logger.info(
                    "{} with role {} unsuccessfully attempted to access {} from {}".format(user.email, user.role,
                                                                                           request.url,
                                                                                           request.remote_addr))
                return False

    def inaccessible_callback(self, name, **kwargs):
        flash("Admin is required to access this", "danger no-register")
        return redirect(url_for('accounts.login'))

    def accessible_callback(self, name, **kwargs):
        return True


class UserView(ModelView):
    column_display_pk = True
    column_hide_backrefs = False
    column_list = ('id', 'email', 'password', 'firstname', 'lastname', 'phone', 'posts', 'mfaenabled', 'mfakey', 'role')

    def is_accessible(self):
        if not current_user.is_authenticated:
            return False
        else:
            user = load_user(current_user.id)
            if user.role == "db_admin":
                return True
            else:
                logger.info(
                    "{} with role {} unsuccessfully attempted to access {} from {}".format(user.email, user.role,
                                                                                           request.url,
                                                                                           request.remote_addr))
                return False

    def inaccessible_callback(self, name, **kwargs):
        flash("Admin is required to access this", "danger no-register")
        return redirect(url_for('accounts.login'))

    def accessible_callback(self, name, **kwargs):
        return True


admin = Admin(app, name='DB Admin', template_mode='bootstrap4')
admin._menu = admin._menu[1:]
admin.add_link(MainIndexLink(name='Home Page'))
admin.add_view(PostView(Post, db.session))
admin.add_view(UserView(User, db.session))
