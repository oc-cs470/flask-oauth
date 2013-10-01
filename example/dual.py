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

method = ''
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


@app.route('/userinfo')
@app.route('/userinfo/<access_token>')
def userinfo(access_token=None):
    print 'userinfo', access_token, method
    if method == 'google':
        # Site specific stuff for google user info
        from urllib2 import Request, urlopen, URLError

        headers = {'Authorization': 'OAuth '+access_token}
        req = Request('https://www.googleapis.com/oauth2/v2/userinfo',
                      None, headers)
        try:
            res = urlopen(req)
        except URLError, e:
            if e.code == 401:
                # Unauthorized - bad token
                session.pop(method+'_access_token', None)
                return redirect(url_for('login'))
            return res.read()

        return res.read()
    elif method == 'facebook':
        # Site specific stuff for facebook user info
        me = facebook.get('/me')
        return str(me.data)  # Show all data in python dictionary
    else:
        return redirect(url_for('invalid'))


@app.route('/login/<auth_method>')
def index(auth_method):
    global method
    method = auth_method
    print 'METHOD='+method
    access_token = session.get(method+'_access_token')
    if access_token is None:
        return redirect(url_for('login'))

    return redirect(url_for('userinfo', access_token=access_token[0]))


@app.route('/login')
def login():
    if method == '' or method is None:
        return redirect(url_for('invalid'))

    callback = url_for(method+'_authorized', _external=True)

    if method == 'facebook':
        return facebook.authorize(callback=callback)
    elif method == 'google':
        return google.authorize(callback=callback)


def authorized(resp):
    print 'AUTHORIZED', resp
    if resp is None:
        return 'Access denied: reason=%s error=%s' % (
            request.args['error_reason'],
            request.args['error_description']
        )

    access_token = resp['access_token']
    session[method+'_access_token'] = access_token, ''
    return redirect(url_for('userinfo', access_token=access_token))


@app.route('/login/google/authorized')
@google.authorized_handler
def google_authorized(resp):
    return authorized(resp)


@app.route('/login/facebook/authorized')
@facebook.authorized_handler
def facebook_authorized(resp):
    return authorized(resp)


def get_access_token():
    return session.get(method+'_access_token')


@facebook.tokengetter
def facebook_tokengetter():
    return get_access_token()


@google.tokengetter
def google_tokengetter():
    return get_access_token()


# Some extra urls to control the app and respond
@app.route('/invalid')
def invalid():
    return 'Invalid'


@app.route('/reset')
def reset():
    session['google_access_token'] = None
    session['facebook_access_token'] = None
    return 'Sessions reset'


if __name__ == '__main__':
    app.run()
