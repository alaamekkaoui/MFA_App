from flask import Flask, render_template, session
from auth.login import login_bp
from auth.mongodb import connect_to_mongodb
from auth.signup import signup_bp
from auth.MFA import qr_bp
from auth.models import User
from flask_jwt_extended import JWTManager

app = Flask(__name__)
app.config['SECRET_KEY'] = 'SECRET_KEY'
jwt = JWTManager(app)
client, db, users_collection = connect_to_mongodb()

# Register Blueprints
app.register_blueprint(login_bp)
app.register_blueprint(signup_bp)
app.register_blueprint(qr_bp)

def decode_jwt_token(token):
    if token : 
        decoded_token = jwt.decode(token, jwt.config['JWT_SECRET_KEY'], algorithms=["HS256"])
        return decoded_token
    else :
        return {'error': 'No token provided'}

@app.route('/')
def index():
    user_model = User(client, db, users_collection)
    users = user_model.get_all_users()
    if 'username' in session:
        # Directly access the username stored in session
        username = session['username']
        login_method = session['login_method']
        return render_template('index.html', users=users, username=username, login_method=login_method)
    else:
        # Handle case where no user identity is found in session
        return render_template('index.html', users=users, username=None)
    
if __name__ == '__main__':
    app.run(debug=True)
