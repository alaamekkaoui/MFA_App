from flask import Flask, jsonify, render_template, request, session
from auth.Form.login import login_bp
from auth.mongodb import connect_to_mongodb
from auth.Form.signup import signup_bp
from auth.Security.MFA import qr_bp
from auth.models import User
from auth.middlewears.session_manager import  session_bp
from flask_jwt_extended import JWTManager
from itsdangerous import URLSafeTimedSerializer, SignatureExpired

app = Flask(__name__)
app.config['SECRET_KEY'] = 'SECRET_KEY'
jwt = JWTManager(app)
s = URLSafeTimedSerializer(app.secret_key)
client, db, users_collection = connect_to_mongodb()

# Register Blueprints
app.register_blueprint(login_bp)
app.register_blueprint(signup_bp)
app.register_blueprint(qr_bp)
app.register_blueprint(session_bp)

def decode_jwt_token(token):
    if token : 
        decoded_token = jwt.decode(token, jwt.config['JWT_SECRET_KEY'], algorithms=["HS256"])
        return decoded_token
    else :
        return {'error': 'No token provided'}

@app.route('/')
def index():
    user_model = User(client, db, users_collection)  # Assuming User model and MongoDB setup
    users = user_model.get_all_users()
    if 'username' in session:
        username = session['username']
        login_method = session['login_method']
        jwt_token = session.get('jwt_token', '')  
        
        return render_template('index.html', users=users, username=username, login_method=login_method, jwt_token=jwt_token)
    else:
        # Handle case where no user identity is found in session
        return render_template('index.html', users=users, username=None, login_method=None, jwt_token=None)

@app.route('/delete_user', methods=['POST'])
def delete_user():
    if 'username' in session:
        username = session['username']
        delete_username = request.form.get('username')
        
        user_model = User(client, db, users_collection)
        user = users_collection.find_one({'username': delete_username})
        if user:
                result = users_collection.delete_one({'username': delete_username})
                if result.deleted_count == 1:
                    return jsonify({'message': 'User deleted successfully'}), 200
                else:
                    return jsonify({'error': 'Failed to delete user'}), 500
        else:
                return jsonify({'error': 'User not found'}), 404
    else:
        return jsonify({'error': 'User not logged in'}), 401


if __name__ == '__main__':
    app.run(debug=True,port = 5000)
