from flask import Blueprint, render_template, redirect, flash, url_for, request
from flask_login import current_user
from sqlalchemy import asc

from config import load_user, Log, logger

security_bp = Blueprint('security', __name__, template_folder='templates')


@security_bp.route('/security')
def security():
    try:
        user = load_user(current_user.get_id())
        if user.role != "sec_admin":
            logger.info("{} with role {} unsuccessfully attempted to access {} from {}".format(user.email, user.role,
                                                                                               request.url,
                                                                                               request.remote_addr))
            return redirect(url_for('errors.adminerror'))
    except:
        flash("You must be logged in to view this page", category="warning")
        return redirect(url_for('accounts.login'))
    all_logs = Log.query.order_by(asc('logid')).all()
    with open("security.log", "r") as file:
        logfiles = file.readlines()
    logfiles = logfiles[(len(logfiles) - 10):]
    logfiles.reverse()
    return render_template('security/Security.html', logs=all_logs, logfiles=logfiles)
