import base64
from datetime import datetime, timedelta 
from io import BytesIO
from flask import Blueprint, jsonify, request, render_template, session, url_for , redirect
from flask_jwt_extended import create_access_token, decode_token
from auth.models import User
from auth.mongodb import connect_to_mongodb
from auth.security import generate_qr_code, token_required


# Establish MongoDB connection
client, db, users_collection = connect_to_mongodb()

# Initialize User model with MongoDB configuration
user_model = User(client, db, users_collection)

# Create a Blueprint for login routes
login_bp = Blueprint('login', __name__)

@login_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get form data
        username = request.form.get('username')
        password = request.form.get('password')
        session['username'] = username

        otp_uri = user_model.get_otp_uri(username)
        otp_uri_str = str(otp_uri.get('otp_uri'))
        secret = otp_uri_str.split('secret=')[1].split('&')[0]
        
        if not username or not password:
            print("error : user not found ")
            return jsonify({'message': 'Missing username or password'}), 400

        # Check if user exists
        user = user_model.get_user_by_username(username)
        if not user:
            return jsonify({'message': 'User does not exist'}), 404

        # Verify password
        if not user_model.verify_password(username, password):
            return jsonify({'message': 'Incorrect password'}), 401
       
        # Generate JWT token
        expiration_time = timedelta(hours=1)
        access_token = create_access_token(identity=username, expires_delta=expiration_time)
        print(access_token)

        # Save the JWT token in the session
        session['jwt_token'] = access_token
        

        # Return success response with JWT token
        response_data = {
            'username': username,
            'jwt_token': access_token,  # Include JWT token in the response
            'message': 'Login successful'
        }
        if user.get('is_otp_verified'):
            #return jsonify(response_data), 200
            return render_template('otp_totp.html', username=user.get('username'), email=user.get('email'))
        else:
            otp_uri = user.get('otp_uri')
            username = user.get('username')
            img = generate_qr_code(otp_uri)
            img_io = BytesIO()
            img.save(img_io, 'PNG')
            img_io.seek(0)
            img_data = base64.b64encode(img_io.getvalue()).decode()
            qr_image = f"data:image/png;base64,{img_data}"

            return render_template('qr_display.html', username=user.get('username'), email=user.get('email'), qr_image=qr_image, secret=secret,response_data=response_data)
        
    else:
        return render_template('login.html')
    
@login_bp.route('/logout', methods=['POST', 'GET'])
@token_required
def logout(identity):
    print(identity)
    if 'jwt_token' in session:
        # Clear session
        session.pop('jwt_token', None)
        
        return jsonify({'message': 'Logged out successfully'}), 200
    else:
        return jsonify({'message': 'Failed to log out. JWT token not found in session.'}), 500




@login_bp.route('/protected')
@token_required
def protected_route():
    # Accessible only if the JWT token is valid
    return jsonify({'message': 'This is a protected route'})


