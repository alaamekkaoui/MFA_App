from flask import Flask, render_template
from auth.login import login_bp
from auth.signup import signup_bp
from auth.MFA import qr_bp


app = Flask(__name__)
app.config['SECRET_KEY'] = 'SECRET_KEY'

# Register Blueprints
app.register_blueprint(login_bp)
app.register_blueprint(signup_bp)
app.register_blueprint(qr_bp)

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
