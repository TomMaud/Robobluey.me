import base64
from hashlib import scrypt

import flask_login
import pyotp
from argon2 import PasswordHasher
from cryptography.fernet import Fernet
from flask import Blueprint, render_template, flash, redirect, url_for, request, session
from flask_login import current_user
from flask_qrcode import QRcode
from markupsafe import Markup

from accounts.forms import RegistrationForm, LoginForm
from config import User, Log, db, limiter, load_user, logger

numattempts = 3  # allows for number of attempts to be easily changed
accounts_bp = Blueprint('accounts', __name__, template_folder='templates')
qrcode = QRcode()
ph = PasswordHasher()


@accounts_bp.route('/registration', methods=['GET', 'POST'])
def registration():
    if current_user.is_authenticated:
        user = load_user(current_user.get_id())
        logger.info(
            "{} with role {} unsuccessfully attempted to access {} from {}".format(user.email, user.role, request.url,
                                                                                   request.remote_addr))
        flash("You must be logged out to register or login", category="warning")
        return redirect(url_for('posts.posts'))
    form = RegistrationForm()

    if form.validate_on_submit():
        print(form.email.data)

        if User.query.filter_by(email=form.email.data.lower()).first():
            print("ANAIUFN")
            flash('Email already exists', category="danger no-register")
            return render_template('accounts/registration.html', form=form)
        mfakey = pyotp.random_base32()
        new_user = User(email=form.email.data,
                        firstname=form.firstname.data,
                        lastname=form.lastname.data,
                        phone=form.phone.data,
                        password=ph.hash(form.password.data),
                        mfakey=mfakey,
                        mfaenabled=False,
                        role='end_user',
                        )
        db.session.add(new_user)
        db.session.commit()
        logger.info("{} Successfully registered with role {} from {}".format(form.email.data, new_user.role,
                                                                             request.remote_addr))
        db.session.add(User.query.filter_by(email=form.email.data.lower()).first().createlog())
        db.session.commit()

        mfaqrcode = str(pyotp.totp.TOTP('mfa key').provisioning_uri(new_user.email, 'TomBlog'))
        mfaqrcode = qrcode.qrcode(mfaqrcode, box_size=10, border=0)
        flash('Account Created, please register for 2FA', category='success')
        return render_template('accounts/mfasetup.html', key=mfakey, mfaqrcode=mfaqrcode)

    return render_template('accounts/registration.html', form=form)


@accounts_bp.route('/account')
def account():
    try:
        user = load_user(current_user.get_id())
    except:
        flash("You must be logged in to view your account", category="warning")
        logger.info("An unauthorised user unsuccessfully attempted to access {} from {}".format(request.url,
                                                                                                request.remote_addr))
        return redirect(url_for('accounts.login'))
    for i in user.posts:
        key = scrypt(password=i.user.password.encode(), salt=i.user.salt.encode(), n=2048, r=8, p=1, dklen=32)
        encoded_key = base64.b64encode(key)
        cipher = Fernet(encoded_key)
        i.title = cipher.decrypt(i.title).decode()
        i.body = cipher.decrypt(i.body).decode()
    return render_template('accounts/account.html', user=user)


@accounts_bp.route('/unlock')
def unlock():
    session['attempts'] = 0
    return redirect(url_for('accounts.login'))


@accounts_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("20 per minute")
def login():
    if current_user.is_authenticated:
        flash("You must be logged out to register or login", category="warning")
        user = load_user(current_user.get_id())
        logger.info(
            "{} with role {} unsuccessfully attempted to access {} from {}".format(user.email, user.role, request.url,
                                                                                   request.remote_addr))
        return redirect(url_for('posts.posts'))
    if 'attempts' not in session:
        session['attempts'] = 0
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()

        if user and user.verify_password(form.password.data):
            if pyotp.TOTP(user.mfakey).verify(form.pin.data):
                if user.mfaenabled == False:
                    user.mfaenabled = True
                    user.changemfaenabled()
                flash("You have been logged in", category="success")
                logger.info(
                    "{} successfully logged in with role {} from {}".format(user.email, user.role, request.remote_addr))
                session['attempts'] = 0
                flask_login.login_user(user)
                current_user.role = user.role
                print(user.id)
                userlog = Log.query.filter_by(loguserid=user.id).first()
                lastlogindate = userlog.latestlogindate
                lastip = userlog.latestip
                latestip = request.remote_addr
                userlog.update(lastlogindate=lastlogindate, lastip=lastip, latestip=latestip)
                if user.role == "sec_admin":
                    return redirect(url_for('security.security'))
                if user.role == "db_admin":
                    return redirect("https://127.0.0.1:5000/admin")
                else:
                    return redirect(url_for('posts.posts'))
            else:
                if user.mfaenabled:
                    flash("MFA pin invalid, please try again", category="danger no-register")
                    session['attempts'] += 1
                    logger.info("{} unsuccessfully attempted to log in with attempt number {} from {}".format(
                        form.email.data.lower(), numattempts - session["attempts"], request.remote_addr))
                    return render_template('accounts/login.html', form=form)
                else:
                    flash("MFA must be enabled to log in", category="warning")
                    mfakey = user.mfakey
                    mfaqrcode = str(pyotp.totp.TOTP('mfa key').provisioning_uri(user.email, 'TomBlog'))
                    mfaqrcode = qrcode.qrcode(mfaqrcode, box_size=10, border=0)
                    return render_template('accounts/mfasetup.html', key=mfakey, mfaqrcode=mfaqrcode)
        else:
            session['attempts'] += 1
            if session['attempts'] >= numattempts:
                logger.info("{} reached maximum attempts to log in with attempt number {} from {}".format(
                    form.email.data.lower(), numattempts - session["attempts"], request.remote_addr))
                flash(Markup('Out of login attempts, please click here to <a href="/unlock">unlock account</a>'),
                      category="danger no-register")
                return render_template('accounts/login.html')
            logger.info(
                "{} unsuccessfully attempted to log in with attempt number {} from {}".format(form.email.data.lower(),
                                                                                              numattempts - session["attempts"],
                                                                                              request.remote_addr))
            flash(
                'Email or Password was incorrect, you have {} more attempts'.format(numattempts - session["attempts"]),
                category="warning")
            return render_template('accounts/login.html', form=form)
    elif request.method == 'POST':
        flash('Captcha not valid, please try again', category="warning")

    return render_template('accounts/login.html', form=form)


@accounts_bp.route('/logout', methods=['GET', 'POST'])
def logout():
    try:
        user = load_user(current_user.get_id())
    except:
        flash("You must be logged in to log out", category="warning")
        return redirect(url_for('accounts.login'))
    flask_login.logout_user()
    flash("You have been successfully logged out", category="success")
    return redirect(url_for('accounts.login'))
