from flask import Blueprint, jsonify, request, render_template, url_for , redirect
from auth.models import User
from auth.mongodb import connect_to_mongodb


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

        # Return success response
        response_data = {
            'username': username,
            'email':"email", 
            'otp_uri' : "otp_uri",
            'message': 'Login successful'
        }
        if user.get('is_otp_verified'):
            return render_template('otp_totp.html', username = user.get('username'), email = user.get('email'),)
        else :
            return render_template('qr_display.html', username = user.get('username'), email = user.get('email'),)
        
    else:
        # If the request method is GET, render the login form
        return render_template('login.html')

