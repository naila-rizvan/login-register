from flask import Flask, render_template, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length, ValidationError, EqualTo
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import re
import os
from dotenv import load_dotenv
import requests
from requests.structures import CaseInsensitiveDict



app = Flask(__name__)
load_dotenv()
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
app.config['API_KEY'] = os.environ.get("API_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['PERMANENT_SESSION_LIFETIME'] = 1500

bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired()])
    password = PasswordField('password', validators=[InputRequired()])
    remember = BooleanField('remember me')


class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=20)])
    confirm = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password', message='Password does not match')])

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError('That username already exists. Please choose a different one.')
        
    def validate_email(self, email):
        existing_user_email = User.query.filter_by(
            email=email.data).first()
        if existing_user_email:
            raise ValidationError('That email already exists. Please choose a different one.')
        
        url = f"https://api.emailvalidation.io/v1/info?email={email.data}"

        headers = CaseInsensitiveDict()
        headers["apikey"] = app.config["API_KEY"]

        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            json_resp = response.json()
            format_valid = json_resp["format_valid"]
            mx_found = json_resp["mx_found"]
            smtp_check = json_resp["smtp_check"]
            state = json_resp["state"]

            if format_valid and mx_found and smtp_check and state == "deliverable":
                pass
            else:
                raise ValidationError('Invalid Email Address')
        
    def validate_password(self, password):       
        pattern = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!`~%*#?&])[A-Za-z\d@$!`~#%*?&]{6,20}$')
        match = pattern.search(password.data)
        if match:
            pass
        else:
            raise ValidationError('Password must contain one digit from 1 to 9, one lowercase letter, one uppercase letter, one special character')


with app.app_context():
    db.create_all()


@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return '<h1>You are already logged in!</h1>'
    
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('dashboard'))
        else:
            return '<h1>Login Unsuccessful. Please check email and password</h1>'
        
    return render_template('login.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return '<h1>You are already logged in!</h1>'
    
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)
        return redirect(url_for('dashboard'))

    return render_template('signup.html', form=form)


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))



if __name__ == '__main__':
    app.run(debug=True)