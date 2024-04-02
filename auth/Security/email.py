import os
import pickle
import base64
from email.mime.text import MIMEText
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
s = URLSafeTimedSerializer("secret_key")

SCOPES = ['https://www.googleapis.com/auth/gmail.send']
EMAIL_ADDRESS = "otpcode288@gmail.com"

current_dir = os.path.dirname(os.path.abspath(__file__))
credentials_path = os.path.join(current_dir, 'credentials.json')

def get_credentials():
    """Get credentials from credentials.json."""
    global EMAIL_ADDRESS
    creds = None
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = Flow.from_client_secrets_file(credentials_path, scopes=SCOPES,
                redirect_uri='urn:ietf:wg:oauth:2.0:oob')
            auth_url, _ = flow.authorization_url(prompt='consent')
            print('Please go to this URL and authorize access:', auth_url)
            code = input('Enter the authorization code: ')
            flow.fetch_token(code=code)
            creds = flow.credentials
            with open('token.pickle', 'wb') as token:
                pickle.dump(creds, token)
    EMAIL_ADDRESS = creds.client_id
    return creds

def send_email_otp(email, code):
    """Creates and sends a simple text email with OTP."""
    creds = get_credentials()
    gmail_service = build('gmail', 'v1', credentials=creds)
    
    text_msg = f"""\
    Hello, {email}, Your OTP is {code},
    Thanks & Regards
    """
    print(email, code)
    
    # Convert the message to string before creating MIMEText
    text_msg_str = str(text_msg)
    
    # Create a message
    message = MIMEText(text_msg_str)
    message['to'] = email
    message['from'] = "otpcode288@gmail.com" 
    message['subject'] = "OTP code for email verification"

    raw_message = {'raw': base64.urlsafe_b64encode(message.as_bytes()).decode()}
    # Send the message
    try:
        message = gmail_service.users().messages().send(userId="me", body=raw_message).execute()
        print('Message Id: %s' % message['id'])
        print(message)
    except Exception as error:
        print('An error occurred: %s' % error)

def send_approval_email(email):
    creds = get_credentials()
    gmail_service = build('gmail', 'v1', credentials=creds)

    # Generate tokens for approval and denial
    approval_token = s.dumps({'user_id': email, 'action': 'approve'}, salt='email-action')
    deny_token = s.dumps({'user_id': email, 'action': 'deny'}, salt='email-action')

    # Construct approval and denial links with tokens
    approval_link = f"http://localhost:5000/approve/{approval_token}"
    deny_link = f"http://localhost:5000/deny/{deny_token}"

    # Email body with approval and denial links
    text_msg = f"""
    Hello, {email},

    A request has been made that requires your approval. Please click one of the following links to respond:

    Approve: {approval_link}
    \n
    Deny: {deny_link}

    Thanks & Regards,
    """
    #print("Email body:",email,"\n link of approval",approval_link,"\nlink of deny", deny_link)

    # Convert the message to string before creating MIMEText
    text_msg_str = str(text_msg)
    #print(text_msg_str)
    # Create a message
    message = MIMEText(text_msg_str)
    message['to'] = email
    message['from'] = "otpcode288@gmail.com" 
    message['subject'] = "Request for Approval"

    raw_message = {'raw': base64.urlsafe_b64encode(message.as_bytes()).decode()}
    try:
            message = gmail_service.users().messages().send(userId="me", body=raw_message).execute()
            print('Message Id: %s' % message['id'])
            print(message)
    except Exception as error:
            print('An error occurred: %s' % error)
