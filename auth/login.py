from flask import Blueprint, redirect, request, url_for, render_template , jsonify
from auth.models import User
from auth.mongodb import connect_to_mongodb
from onelogin.saml2.auth import OneLogin_Saml2_Auth

# Establish MongoDB connection
client, db, users_collection = connect_to_mongodb()

# Initialize User model with MongoDB configuration
user_model = User(client, db, users_collection)

# Create a Blueprint for login routes
login_bp = Blueprint('login', __name__)

# SAML settings
saml_settings = {
    "strict": True,
    "debug": True,
    "sp": {
        "entityId": "YOUR_ENTITY_ID",  # Replace with your SP entity ID
        "assertionConsumerService": {
            "url": "http://localhost:5000/saml/acs",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
        },
        # Add other SP settings as needed
    },
    # Add IdP settings from your Identity Provider
    "idp": {
        "entityId": "urn:dev-b3p14x4jy3t68afr.us.auth0.com",
        "singleSignOnService": {
            "url": "https://dev-b3p14x4jy3t68afr.us.auth0.com/samlp/vsjcmhExVqp6E0YFhwjDg44CU8dUSmJ1",
        },
        "singleLogoutService": {
            "url": "https://dev-b3p14x4jy3t68afr.us.auth0.com/samlp/vsjcmhExVqp6E0YFhwjDg44CU8dUSmJ1",
        },
        "x509cert": "YOUR_IDP_CERTIFICATE",  # Replace with your IdP certificate
    }
}

# Create SAML authentication object
saml_auth = OneLogin_Saml2_Auth(request, saml_settings)

@login_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Check if SAML request
        if 'SAMLResponse' in request.form:
            saml_response = request.form['SAMLResponse']
            # Process SAML response
            saml_auth.process_response()
            errors = saml_auth.get_errors()
            if errors:
                return jsonify({'message': 'SAML authentication failed'}), 401
            # Retrieve user attributes from SAML response
            user_attributes = saml_auth.get_attributes()
            # You may need to map SAML attributes to your user model
            username = user_attributes.get('username')
            # Check if user exists in your system, if not create one
            user = user_model.get_user_by_username(username)
            if not user:
                # Create user based on SAML attributes
                user_model.create_user(username, email=user_attributes.get('email'))
            # Redirect to a success page
            return redirect(url_for('login.success'))
    else:
        # If the request method is GET, render the login form
        return render_template('login.html')

@login_bp.route('/saml/login', methods=['GET'])
def saml_login():
    # Redirect to IdP for SAML authentication
    return redirect(saml_auth.login())

@login_bp.route('/saml/acs', methods=['POST'])
def saml_acs():
    # Endpoint for receiving SAML response
    return redirect(url_for('login.login'))

@login_bp.route('/success')
def success():
    return 'Login successful'
