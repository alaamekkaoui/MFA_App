import base64
from flask import Flask, jsonify, redirect, render_template, url_for, session, request
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config
from datetime import timedelta 
from flask_jwt_extended import create_access_token
from flask_jwt_extended import JWTManager
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key_here'  # Change to your JWT secret key
app.config['SECRET_KEY'] = 'your_flask_secret_key_here'  # Flask secret for session, etc.
jwt = JWTManager(app)

metadata_path = 'metadata.xml'

@app.route('/')
def login():
    return render_template('sp1.html')

metadata_path = './metadata.xml'
idp_name = 'okta'

def saml_client_for():
    acs_url = url_for("idp_initiated", _external=True)

    settings = {
        'entityid': 'http://localhost:5001/saml/metadata',
        'metadata': {
            'local': [metadata_path],
        },
        'service': {
            'sp': {
                'endpoints': {
                    'assertion_consumer_service': [
                        (acs_url, BINDING_HTTP_POST),
                    ],
                    "singleLogoutService": {
                "url": "https://dev-22490639.okta.com/app/dev-22490639_saml2_1/exkg0nvp7zC7SD9SR5d7/slo/saml",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            },
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
def prepare_saml_request(request):
    url_data = {
        'https': 'on' if request.scheme == 'https' else 'off',
        'http_host': request.host,
        'script_name': request.path,
        'get_data': request.args.copy(),
        'post_data': request.form.copy()
    }
    auth = OneLogin_Saml2_Auth(url_data, custom_base_path=os.path.join(os.getcwd(), 'saml'))
    return auth

@app.route("/saml/sso/okta", methods=['POST', 'GET'])
def idp_initiated():
    saml_response_encoded = request.form.get('SAMLResponse')
    if not saml_response_encoded:
        return jsonify({'error': 'SAMLResponse not found'}), 400

    saml_response_decoded = base64.b64decode(saml_response_encoded).decode('utf-8')
    saml_client = saml_client_for()

    authn_response = saml_client.parse_authn_request_response(saml_response_encoded, BINDING_HTTP_POST)
    email = authn_response.get_subject().text

    expiration_time = timedelta(hours=1)
    access_token = create_access_token(identity=email, expires_delta=expiration_time)
    session['username'] = email
    session['jwt_token'] = access_token
    session['login_method'] = 'sso'

    return jsonify({'message': 'Login successful'},{'access_token': access_token}, {'username': email}), 200



@app.route("/saml")
def sp_initiated():
    saml_client = saml_client_for()
    _, info = saml_client.prepare_for_authenticate()
    for key, value in info['headers']:
        if key == 'Location':
            return redirect(value)
    return 'Failed to redirect for SAML authentication'

@app.route('/logout')
def logout():
    req = prepare_saml_request(request)
    settings = saml_client_for()
    req.load_settings(settings)
    return redirect(req.logout())

    

@app.route('/index')
def index():
    # Simple landing page
    return jsonify({'message': 'Welcome to the Flask SAML SP application'}), 200

if __name__ == '__main__':
    app.run(debug=True, port=5001)
