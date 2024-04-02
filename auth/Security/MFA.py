from flask import render_template, Blueprint, request, jsonify, url_for,redirect
from itsdangerous import SignatureExpired, URLSafeTimedSerializer
from auth.Security.security import generate_hotp_email, generate_qr_code, send_email, token_required, verify_hotp, verify_totp
from io import BytesIO
import base64
from auth.mongodb import connect_to_mongodb
from auth.models import User

s = URLSafeTimedSerializer('your_secret_key')

qr_bp = Blueprint('qr_bp', __name__)

client, db, users_collection = connect_to_mongodb()

user_model = User(client, db, users_collection)

@qr_bp.route('/qrcode/<username>', methods=['GET'])
@token_required
def generate_1fa_qr(username):
    user = user_model.get_user_by_username(username)
    otp_uri= user_model.get_otp_uri(username)
    otp_uri_str = str(otp_uri.get('otp_uri'))
    secret = otp_uri_str.split('secret=')[1].split('&')[0]
    if user:
        otp_uri = user.get('otp_uri')
        username = user.get('username')
        img = generate_qr_code(otp_uri)
        img_io = BytesIO()
        img.save(img_io, 'PNG')
        img_io.seek(0)
        img_data = base64.b64encode(img_io.getvalue()).decode()
        qr_image = f"data:image/png;base64,{img_data}"
        return render_template('qr_display.html', qr_image=qr_image, username=username,secret=secret)
    else:
        return "User not found", 404

@qr_bp.route('/otp_verify/<username>', methods=['POST'])
@token_required
def verify_otp(username):
    code = request.form.get('code')
    user = user_model.get_user_by_username(username)
    print('Code entered by user:', code)
    if user:
        otp_uri = user_model.get_otp_uri(username)
        otp_uri_str = str(otp_uri.get('otp_uri'))
        secret = otp_uri_str.split('secret=')[1].split('&')[0]
        
        if verify_totp(secret, code):
            user_model.set_totp_verification(username, True)
            print('OTP verification successful')
            return redirect(url_for('qr_bp.send_email_otp', username=username))
        else:
            return jsonify({'message': 'OTP verification failed'}), 400
    else:
        return "User not found", 404
#----------------------Email section-----------------
@qr_bp.route('/email_otp/<username>', methods=['GET', 'POST'])
@token_required
def send_email_otp(username):
    if request.method == 'GET':
        email = user_model.get_email_by_username(username)
        email = email.get('email')
        if not email:
            return jsonify({'message': 'No email found for this username'}), 400
        else : 
            code, secret = generate_hotp_email(counter=0)
            print("code ", code , "secret ", secret)
            send_email(email, code)
            return render_template('email_otp.html', email=email , username=username , secret = secret)
        
@qr_bp.route('/email_verify/<username>', methods=['POST'])
@token_required
def email_verify(username):
    code = request.form.get('code')
    secret = request.form.get('secret')  # Retrieve the secret from the form
    
    if verify_hotp(secret, code, counter=0):
        print('OTP verification successful')
        user_model.set_totp_verification(username, True)
        return jsonify({'message': 'OTP verified successfully'}), 200
    else:
        return jsonify({'message': 'OTP verification failed'}), 400

@qr_bp.route('/approve/<token>')
def approve(token):
    try:
        email = s.loads(token, salt='email-approve', max_age=3600)
        return "Approval confirmed."
    except SignatureExpired:
        # Handle the case where the token has expired
        return "The approval link has expired."
    
@qr_bp.route('/deny/<token>')
def deny(token):
    try:
        email = s.loads(token, salt='email-approve', max_age=3600)
        return "Request denied."
    except SignatureExpired:
        # Address the scenario where the token expires
        return "The denial link has expired."
