from flask import Blueprint, session, jsonify
import requests
from auth.Security.security import token_required
from flask_jwt_extended import get_jwt_identity

# Define the blueprint
session_bp = Blueprint('session_management', __name__)

@session_bp.route('/session_check')
def session_check():
    # Correctly check for session existence before accessing keys
    if 'username' in session and 'login_method' in session:
        # Retrieve username and login method only after confirming they exist in the session
        username = session['username']
        login_method = session['login_method']
        print("Session check:", username, login_method)
        return jsonify({'valid_session': True,
                        'username': username,
                        'login_method': login_method})
    else:
        return jsonify({'valid_session': False})
    
@session_bp.route('/check-login', methods=['GET'])
def check_login():
    token = session['jwt_token'] 
    if token:
        return jsonify(logged_in=True, token=token), 200
    else:
        return jsonify(logged_in=False, message="User not logged in"), 200