from flask import render_template, Blueprint, request, jsonify
from auth.models import User 
from auth.security import generate_qr_code, verify_totp
from io import BytesIO
import base64
from auth.mongodb import connect_to_mongodb

qr_bp = Blueprint('qr_bp', __name__)

client, db, users_collection = connect_to_mongodb()

user_model = User(client, db, users_collection)

@qr_bp.route('/qrcode/<username>', methods=['GET'])
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
            #change it in the database as well
            return jsonify({'message': 'OTP verified successfully'}), 200
        else:
            return jsonify({'message': 'OTP verification failed'}), 400
    else:
        return "User not found", 404


