import pyotp
import qrcode
from auth.Security.email import send_email_otp
from functools import wraps
from flask import jsonify, session
import jwt
from datetime import datetime


EMAIL_EXPIRATION_WINDOW = 10 * 60  # 10 minutes in seconds
#-------------------------------------JWT--------------------------------------
def token_required(route_function):
    @wraps(route_function)
    def wrapper(*args, **kwargs):
        # Get JWT token from session
        token = session.get('jwt_token')
        username = session.get('username')
        if not token:
            return jsonify({'message': 'Missing JWT token'}), 401
        # Verify JWT token
        try:
            payload = jwt.decode(token, 'SECRET_KEY', algorithms=['HS256'])
            identity = payload.get('identity')
            exp = payload.get('exp')

            if exp and datetime.utcfromtimestamp(exp) < datetime.utcnow():
                return jsonify({'message': 'JWT token has expired'}), 401
            
            return route_function(*args, **kwargs)

        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'JWT token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid JWT token'}), 401

    return wrapper
#-------------------------------------TOTP--------------------------------------
# Generate TOTP URI
def generate_totp_uri(username):
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    otp_uri = totp.provisioning_uri(name=username, issuer_name='Secure App')
    return otp_uri

# Generate QR code for TOTP
def generate_qr_code(otp_uri):
    qr = qrcode.QRCode(version=1, box_size=5, border=5)
    qr.add_data(otp_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    return img

# Verify TOTP
def verify_totp(secret, code):
    totp = pyotp.TOTP(secret)
    return totp.verify(code)

#-------------------------------------Email--------------------------------------
def generate_hotp_email(counter):
    secret = pyotp.random_base32()
    hotp = pyotp.HOTP(secret)
    code = hotp.at(counter)
    return code , secret

def verify_hotp(secret, code, counter):
    hotp = pyotp.HOTP(secret)
    return hotp.verify(code, counter)

def send_email(email, code):
    if email:
        send_email_otp(email, code)
    else:
        return "Email not found"


