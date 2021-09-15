from datetime import timedelta
import os
from flask import Flask, url_for, redirect, session, render_template
from authlib.integrations.flask_client import OAuth

app = Flask(__name__,template_folder='templates')
app.secret_key = "APP_SECRET_KEY"
app.config['SESSION_COOKIE_NAME'] = 'google-login-session'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)

#oauth config

oauth = OAuth(app)
google = oauth.register(
    'google',
    client_id='916067415520-6isgsga928f8k0s19p35fc2uuji56usb.apps.googleusercontent.com',
    client_secret='pvayjCjhseK6thYyYnz6qcsJ',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    client_kwargs={'scope': 'openid profile email'}
)

@app.route('/')
def default():
    user_data = dict(session).get('user_data', None)
    if(user_data!=None):
        return redirect('/home')
    else:
        return render_template('login.html')

@app.route('/home')
def home():
    user_data = dict(session).get('user_data', None)
    if(user_data!=None):
        return render_template('home.html', data = user_data)
    else:
        return redirect('/')


@app.route('/login')
def login():
    google = oauth.create_client('google')
    redirect_uri = url_for('authorize',_external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/authorize')
def authorize():
    google = oauth.create_client('google')
    token = google.authorize_access_token()
    resp = google.get('userinfo')
    user_info = resp.json()
    session['user_data'] = user_info #user_info['email']
    return redirect('/home')


@app.route('/Submit')
def Submit():
    session.clear()
    return redirect('/')