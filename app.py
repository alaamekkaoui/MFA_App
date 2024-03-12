from flask import Flask, redirect, render_template, url_for
from auth.login import login_bp
from auth.mongodb import connect_to_mongodb
from auth.signup import signup_bp
from auth.MFA import qr_bp
from auth.models import User


app = Flask(__name__)
app.config['SECRET_KEY'] = 'SECRET_KEY'

client, db, users_collection = connect_to_mongodb()

# Register Blueprints
app.register_blueprint(login_bp)
app.register_blueprint(signup_bp)
app.register_blueprint(qr_bp)

#test purpose only
@app.route('/')
def index():
    user = User(client, db, users_collection)
    users = user.get_all_users()
    return render_template('index.html', users=users)

@app.route('/delete_user/<username>', methods=['POST'])
def delete_user_route(username):
    user = User(client, db, users_collection)  # Instantiate the User class
    user.delete_user(username)  # Call delete_user method on the instance
    return redirect(url_for('index'))



if __name__ == '__main__':
    app.run(debug=True)
