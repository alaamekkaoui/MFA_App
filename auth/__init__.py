from flask import Blueprint
from auth.email import send_email_otp

# Define Blueprints
login_bp = Blueprint('login', __name__)
signup_bp = Blueprint('signup', __name__)
qr_bp = Blueprint('qr', __name__)

# Import modules
from auth.models import User
from auth.login import login, logout, protected
from auth.signup import signup
from auth.security import generate_qr_code, verify_totp

# Register routes with Blueprints

login_bp.add_url_rule('/login', 'login', login)
login_bp.add_url_rule('/protected', 'protected', protected)
login_bp.add_url_rule('/logout', 'logout', logout)
signup_bp.add_url_rule('/signup', 'signup', signup)
qr_bp.add_url_rule('/qrcode/<username>', ' generate_qr_code',  generate_qr_code )
qr_bp.add_url_rule('/otp_verify', 'otp_verify',  verify_totp )
qr_bp.add_url_rule('/email_otp', 'send_email_otp',  send_email_otp )
qr_bp.add_url_rule('/email_verify', 'email_verify',  verify_totp )


