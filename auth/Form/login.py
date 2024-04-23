from flask import Blueprint, flash, make_response, render_template, redirect, url_for, session, request, Response, jsonify
from flask_login import logout_user
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config
import base64
import os
from datetime import timedelta
from io import BytesIO
from auth.Security.email import send_approval_email
from auth.models import User as JwtUser
from auth.mongodb import connect_to_mongodb
from auth.Security.security import generate_qr_code, token_required
from flask_jwt_extended import create_access_token, unset_jwt_cookies

login_bp = Blueprint('login', __name__)

current_dir = os.path.abspath(os.getcwd())
metadata_path = os.path.join(current_dir, 'metadata.xml')

idp_name = 'okta'

client, db, users_collection = connect_to_mongodb()

user_model = JwtUser(client, db, users_collection)

def saml_client_for():
    acs_url = url_for("login.idp_initiated", _external=True)

    settings = {
        'entityid': 'http://localhost:5000/saml/metadata',
        'metadata': {
            'local': [metadata_path],
        },
        'service': {
            'sp': {
                'endpoints': {
                    'assertion_consumer_service': [
                        (acs_url, BINDING_HTTP_POST),
                    ],
                },
                'allow_unsolicited': True,
                'authn_requests_signed': False,
                'logout_requests_signed': True,
                'want_assertions_signed': True,
                'want_response_signed': False,
            },
        },
    }
    sp_config = Saml2Config()
    sp_config.load(settings)
    saml_client = Saml2Client(config=sp_config)
    return saml_client

from flask import jsonify, render_template

@login_bp.route("/saml/sso/okta", methods=['POST', 'GET'])
def idp_initiated():
    saml_response_encoded = request.form.get('SAMLResponse')
    if not saml_response_encoded:
        return jsonify({'error': 'SAMLResponse not found'}), 400

    saml_response_decoded = base64.b64decode(saml_response_encoded).decode('utf-8')
    saml_client = saml_client_for()

    authn_response = saml_client.parse_authn_request_response(saml_response_encoded, BINDING_HTTP_POST)
    email = authn_response.get_subject().text

    if not user_model.get_user_by_username(email):
        user = user_model.create_user_sso(username=email, email=email)
        expiration_time = timedelta(hours=1)
        access_token = create_access_token(identity=email, expires_delta=expiration_time)
        session['username'] = email
        session['jwt_token'] = access_token
        session['login_method'] = 'sso'
        print("User created successfully for SAML:", user)
    else:
        print("User already exists for SAML:", email)
        expiration_time = timedelta(hours=1)
        access_token = create_access_token(identity=email, expires_delta=expiration_time)
        session['username'] = email
        session['jwt_token'] = access_token
        session['login_method'] = 'sso'
    # return render_template('saml.html', email=email)
    user = user_model.get_user_by_username(email)
    if user.get('is_otp_verified'):
        return render_template('otp_totp.html', username=email)
    else:
        otp_uri = user.get('otp_uri')
        img = generate_qr_code(otp_uri)
        img_io = BytesIO()
        img.save(img_io, 'PNG')
        img_io.seek(0)
        img_data = base64.b64encode(img_io.getvalue()).decode()
        qr_image = f"data:image/png;base64,{img_data}"

        return render_template('qr_display.html', username=email, qr_image=qr_image)


@login_bp.route("/saml/login/okta")
def sp_initiated():
    saml_client = saml_client_for()
    _, info = saml_client.prepare_for_authenticate()
    for key, value in info['headers']:
        if key == 'Location':
            return redirect(value)
    return 'Failed to redirect for SAML authentication'


@login_bp.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        session['username'] = username
        session['login_method'] = 'standard'

        email_db = user_model.get_email_by_username(username)
        email= email_db.get('email')
        print("the email --------------", email)
        email_str= str(email)
        print("the email str --------------", email_str)

        if not username or not password:
            return jsonify({'message': 'Please provide both username and password'}), 400

        otp_uri = user_model.get_otp_uri(username)
        if not otp_uri:
            return jsonify({'message': 'No OTP URI found for the user'}), 404
        
        otp_uri_str = str(otp_uri.get('otp_uri'))
        secret = otp_uri_str.split('secret=')[1].split('&')[0]

        user = user_model.get_user_by_username(username)
        if not user:
            return jsonify({'message': 'User does not exist'}), 404

        if not user_model.verify_password(username, password):
            return jsonify({'message': 'Incorrect password'}), 401

        expiration_time = timedelta(hours=1)
        access_token = create_access_token(identity=username, expires_delta=expiration_time)

        session['jwt_token'] = access_token

        response_data = {
            'username': username,
            'jwt_token': access_token,
            'message': 'Login successful'
        }
        #--------------------------------------------EMAIL
        #send_approval_email(email_str)
        
        if user.get('is_otp_verified'):
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

            return render_template('qr_display.html', username=user.get('username'), email=user.get('email'), qr_image=qr_image, secret=secret, response_data=response_data)

    else:
        return render_template('login.html')


@login_bp.route('/protected')
@token_required
def protected():
    return jsonify({'message': 'This is a protected route'})


@login_bp.route('/logout')
def logout():
    login_method = session.get('login_method', 'standard')
    session.clear()
    response = make_response(redirect(url_for('index')))
    unset_jwt_cookies(response)

    if login_method == 'sso':
        saml_client = saml_client_for()
        name_id = session.get('https://okta-dev-22490639.oamlNameId')

        destination = url_for('index', _external=True)  # Default destination for standard logout

        if name_id:
            logout_request = saml_client.create_logout_request(
                binding=BINDING_HTTP_REDIRECT
            )
            destination = "https://dev-22490639.okta.com/app/dev-22490639_samlapp_1/exkfw8im5iGIXirNR5d7/slo/saml"
            relay_state = url_for('index', _external=True)
            saml_client.send_logout_request(
                logout_request,
                destination=destination,
                relay_state=relay_state,
                binding=BINDING_HTTP_REDIRECT
            )
        return redirect(destination)
    else:
        return response
