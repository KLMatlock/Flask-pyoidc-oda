import datetime
import flask
import logging
from flask import Flask, jsonify

from flask_pyoidc import OIDCAuthentication
from flask_pyoidc.provider_configuration import ProviderConfiguration, ClientMetadata
from flask_pyoidc.user_session import UserSession

app = Flask(__name__)
# See http://flask.pocoo.org/docs/0.12/config/
app.config.update({
    'SECRET_KEY': 'dev_key',  # make sure to change this!!
    'PERMANENT_SESSION_LIFETIME': datetime.timedelta(days=7).total_seconds(),
    'DEBUG': True})

ISSUER1 = 'http://192.168.1.3:8890/auth/realms/mypatient'
CLIENT1 = 'flask'
PROVIDER_NAME1 = 'provider1'
client_metadata=ClientMetadata(CLIENT1, '34e4a94c-a4ce-480e-a5b5-a7b2b56e3199')
PROVIDER_CONFIG1 = ProviderConfiguration(issuer=ISSUER1,
    client_metadata=client_metadata)

# provider_dict = {PROVIDER_NAME1: PROVIDER_CONFIG1}
# provider_dict = None

app.config['OIDC_PROVIDERS'] = 'provider1'
app.config['provider1_ISSUER'] = 'http://192.168.1.3:8890/auth/realms/mypatient'
app.config['provider1_CLIENT'] = 'flask'
app.config['provider1_SECRET'] = '34e4a94c-a4ce-480e-a5b5-a7b2b56e3199'

auth = OIDCAuthentication( app=app)

@app.route('/')
@auth.oidc_auth(bearer = True)
def login1():
    user_session = UserSession(flask.session)
    return jsonify(access_token=user_session.access_token,
                   id_token=user_session.id_token,
                   userinfo=user_session.userinfo)


@app.route('/hello')
@auth.oidc_auth()
def hello_auth():
    return 'Hello world!'

@app.route('/logout')
@auth.oidc_logout
def logout():
    return "You've been successfully logged out!"


@auth.error_view
def error(error=None, error_description=None):
    return jsonify({'error': error, 'message': error_description})


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    auth.init_app(app)
    app.run(host='0.0.0.0')
