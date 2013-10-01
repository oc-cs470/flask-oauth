from flask import Flask, redirect, url_for, session, request
from flask_oauth import OAuth



# You must configure these 3 values from Google APIs console
# https://code.google.com/apis/console
GOOGLE_CLIENT_ID = '87105594236.apps.googleusercontent.com'
GOOGLE_CLIENT_SECRET = 'BCoPUB2xKfKm6QIaw2ZPdyvV'
REDIRECT_URI = '/oauth2callback'  # one of the Redirect URIs from Google APIs console
FACEBOOK_APP_ID = '213615678798922'
FACEBOOK_APP_SECRET = '45c50d96482f5e32bbdb7819d9709d55'

SECRET_KEY = 'development key'
DEBUG = True

app = Flask(__name__)
app.debug = DEBUG
app.secret_key = SECRET_KEY
oauth = OAuth()

facebook = oauth.remote_app('facebook',
                            base_url='https://graph.facebook.com/',
                            request_token_url=None,
                            access_token_url='/oauth/access_token',
                            authorize_url='https://www.facebook.com/dialog/oauth',
                            consumer_key=FACEBOOK_APP_ID,
                            consumer_secret=FACEBOOK_APP_SECRET,
                            request_token_params={'scope': 'email'})

google = oauth.remote_app('google',
                          base_url='https://www.google.com/accounts/',
                          authorize_url='https://accounts.google.com/o/oauth2/auth',
                          request_token_url=None,
                          request_token_params={'scope': 'https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email',
                                                'response_type': 'code'},
                          access_token_url='https://accounts.google.com/o/oauth2/token',
                          access_token_method='POST',
                          access_token_params={'grant_type': 'authorization_code'},
                          consumer_key=GOOGLE_CLIENT_ID,
                          consumer_secret=GOOGLE_CLIENT_SECRET)


@app.route('/facebook')
def facebook_index():
    access_token = session.get('access_token')
    if access_token is None:
        return redirect(url_for('facebook_login'))

    me = facebook.get('/me')
    return str(me.data)  # Show all data in python dictionary


@app.route('/google')
def google_index():
    access_token = session.get('access_token')
    if access_token is None:
        return redirect(url_for('google_login'))

    access_token = access_token[0]
    from urllib2 import Request, urlopen, URLError

    headers = {'Authorization': 'OAuth '+access_token}
    req = Request('https://www.googleapis.com/oauth2/v2/userinfo',
                  None, headers)
    try:
        res = urlopen(req)
    except URLError, e:
        if e.code == 401:
            # Unauthorized - bad token
            session.pop('access_token', None)
            return redirect(url_for('google_login'))
        return res.read()

    return res.read()


@app.route('/facebook-login')
def facebook_login():
    callback=url_for('facebook_authorized',
                     next=request.args.get('next') or request.referrer or None,
                     _external=True)
    return facebook.authorize(callback=callback)


@app.route('/google-login')
def google_login():
    callback = url_for('authorized', _external=True)
    return google.authorize(callback=callback)


@app.route(REDIRECT_URI)
@google.authorized_handler
def authorized(resp):
    access_token = resp['access_token']
    session['access_token'] = access_token, ''
    return redirect(url_for('google_index'))


@app.route('/login/authorized')
@facebook.authorized_handler
def facebook_authorized(resp):
    if resp is None:
        return 'Access denied: reason=%s error=%s' % (
            request.args['error_reason'],
            request.args['error_description']
        )

    access_token = resp['access_token']
    session['access_token'] = access_token, ''
    return redirect(url_for('facebook_index'))


@facebook.tokengetter
@google.tokengetter
def get_access_token():
    return session.get('access_token')


if __name__ == '__main__':
    app.run()
