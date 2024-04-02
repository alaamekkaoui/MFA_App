from flask import Blueprint, jsonify, redirect, request, render_template, url_for
from werkzeug.security import generate_password_hash
from auth.models import User
from auth.mongodb import connect_to_mongodb  # Import the MongoDB connection function

signup_bp = Blueprint('signup', __name__)

@signup_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # Get form data
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if not username or not email or not password:
            return jsonify({'message': 'Missing username, email, or password'}), 400

        # Establish MongoDB connection
        client, db, users_collection = connect_to_mongodb()

        # Check if the username or email already exists
        user_instance = User(client, db, users_collection)
        if user_instance.get_user_by_username(username):
            return jsonify({'message': 'Username already exists'}), 400

        if user_instance.get_user_by_email(email):
            return jsonify({'message': 'Email already exists'}), 400

        # Create user
        user_instance.create_user(username, email, password)

        #return jsonify({'message': 'User registered successfully'}), 201
        return redirect(url_for('qr_bp.generate_1fa_qr', username=username))
    else:
        # If the request method is GET, render the signup form
        return render_template('signup.html')
