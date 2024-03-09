from flask import app, render_template , Blueprint
from auth.models import User 
from auth.security import generate_qr_code
from io import BytesIO
import base64
from auth.models import User
from auth.mongodb import connect_to_mongodb

qr_bp = Blueprint('qr_bp', __name__)

client, db, users_collection = connect_to_mongodb()

user_model = User(client, db, users_collection)

@qr_bp.route('/qrcode/<username>')
def generate_1fa_qr(username):
    user = user_model.get_user_by_username(username)
    otp_uri = user_model.get_otp_uri(username)
    if user:
        otp_uri = user.get('otp_uri')
        username = user.get('username')
        print("Username :" , username)
        print("-------------------")
        print("URI : " , otp_uri)
        img = generate_qr_code(otp_uri)
        img_io = BytesIO()
        img.save(img_io, 'PNG')
        img_io.seek(0)
        img_data = base64.b64encode(img_io.getvalue()).decode()
        qr_image = f"data:image/png;base64,{img_data}"
        return render_template('qr_display.html', qr_image=qr_image, username = username)
    else:
        return "User not found", 404


