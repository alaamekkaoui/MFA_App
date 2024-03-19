from flask import Flask, redirect, request, session, url_for, render_template_string
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from saml2 import BINDING_HTTP_POST
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config

app = Flask(__name__)
app.secret_key = 'your_super_secret_key'

login_manager = LoginManager()
login_manager.init_app(app)

# Assuming the Okta metadata file is named 'okta_metadata.xml' and placed in the same directory as this script.
metadata_path = './metadata.xml'
idp_name = 'okta'

# Flask-Login user model
class User(UserMixin):
    def __init__(self, username):
        self.id = username

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

def saml_client_for():
    acs_url = url_for("idp_initiated", _external=True)

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


@app.route("/")
def main_page():
    return render_template_string('''
        <h1>Welcome</h1>
        {% if current_user.is_authenticated %}
            <p>Logged in as {{ current_user.id }}</p>
            <p><a href="{{ url_for('logout') }}">Logout</a></p>
        {% else %}
            <p><a href="{{ url_for('sp_initiated', idp_name='okta') }}">Login with SSO</a></p>
        {% endif %}
    ''')

@app.route("/saml/sso/okta", methods=['POST'])
def idp_initiated():
    saml_client = saml_client_for()
    authn_response = saml_client.parse_authn_request_response(
        request.form['SAMLResponse'],BINDING_HTTP_POST)
    username = authn_response.get_subject().text
    user = User(username)
    login_user(user)
    return redirect(url_for('main_page'))

@app.route("/saml/login/okta")
def sp_initiated():
    saml_client = saml_client_for()
    _, info = saml_client.prepare_for_authenticate()
    for key, value in info['headers']:
        if key == 'Location':
            return redirect(value)
    return 'Failed to redirect for SAML authentication'

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('main_page'))

if __name__ == "__main__":
    app.run(debug=True)
