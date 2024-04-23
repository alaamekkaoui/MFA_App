import os
from flask import Flask, render_template, request, jsonify, redirect, session, url_for
from saml2 import BINDING_HTTP_POST
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config
from flask_jwt_extended import create_access_token, JWTManager
import nmap
import base64

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key_here'  # Change to your JWT secret key
app.config['SECRET_KEY'] = 'your_flask_secret_key_here'  # Flask secret for session, etc.
jwt = JWTManager(app)


current_dir = os.path.abspath(os.getcwd())
metadata_path = os.path.join(current_dir, 'metadata_sp.xml')

idp_name = 'okta'

# Update the session secret key
app.secret_key = os.urandom(24)

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

def scan_network(ip_range):
    nm = nmap.PortScanner()
    open_ports = set()  # Set to store unique open ports
    vulnerabilities = set()  # Set to store vulnerabilities

    # Scan for both TCP and UDP ports with faster options
    
    nm.scan(hosts=ip_range, arguments='-p 1-10000 --verbose -sS -sU -T3 --script vulners')
    for host in nm.all_hosts():
        if 'tcp' in nm[host]:
            for port in nm[host]['tcp'].keys():
                if nm[host]['tcp'][port]['state'] == 'open':
                    open_ports.add((port, 'tcp'))  # Add tuple of (port, protocol) to set
                    vulnerabilities.update(nm[host]['tcp'][port].get('script', {}).get('vulners', []))

        if 'udp' in nm[host]:
            for port in nm[host]['udp'].keys():
                if nm[host]['udp'][port]['state'] == 'open':
                    open_ports.add((port, 'udp'))  # Add tuple of (port, protocol) to set
                    vulnerabilities.update(nm[host]['udp'][port].get('script', {}).get('vulners', []))
    print('Open ports:', open_ports, '\nVulnerabilities:', vulnerabilities)
    return list(open_ports), list(vulnerabilities)

@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('scan'))
    else:
        return redirect(url_for('login'))

@app.route('/login')
def login():
    saml_client = saml_client_for()
    _, info = saml_client.prepare_for_authenticate()
    for key, value in info['headers']:
        if key == 'Location':
            return redirect(value)
    return 'Failed to redirect for SAML authentication'

@app.route('/scan')
def scan():
    # if 'username' not in session:
    #     return redirect(url_for('login'))

    ip_range = request.remote_addr + '/24'  # Assuming you want to scan a range
    open_ports, vulnerabilities = scan_network(ip_range)

    session_email = session.get('username', 'No email found')

    return render_template('sp1.html', open_ports=open_ports, vulnerabilities=vulnerabilities, session_email=session_email)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/saml/sso/okta', methods=['POST', 'GET'])
def idp_initiated():
    saml_response_encoded = request.form.get('SAMLResponse')
    if not saml_response_encoded:
        return jsonify({'error': 'SAMLResponse not found'}), 400

    saml_response_decoded = base64.b64decode(saml_response_encoded).decode('utf-8')
    saml_client = saml_client_for()

    authn_response = saml_client.parse_authn_request_response(saml_response_encoded, BINDING_HTTP_POST)
    email = authn_response.get_subject().text

    session['username'] = email

    return redirect(url_for('scan'))

if __name__ == '__main__':
    app.run(debug=True, port=5001)
