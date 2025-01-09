from flask import Blueprint, render_template
from flask_login import current_user
from config import load_user

errors_bp = Blueprint('errors', __name__, template_folder='templates')


@errors_bp.route('/adminerror')
def admintest():
        return render_template('errors/adminerror.html')
