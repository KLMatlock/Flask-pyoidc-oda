import datetime
import flask
import logging
from flask import Flask, jsonify
import requests

from flask_pyoidc import OIDCAuthentication
from flask_pyoidc.provider_configuration import ProviderConfiguration, ClientMetadata
from flask_pyoidc.user_session import UserSession

app = Flask(__name__)

import logging
logging.basicConfig(format='%(asctime)s %(message)s', level=logging.DEBUG)

# See http://flask.pocoo.org/docs/0.12/config/
app.config.update({
    'SECRET_KEY': 'dev_key',  # make sure to change this!!
    'PERMANENT_SESSION_LIFETIME': datetime.timedelta(days=7).total_seconds(),
    'DEBUG': True})

ISSUER1 = 'http://localhost:8890/auth/realms/mypatient'
CLIENT1 = 'flask'
PROVIDER_NAME1 = 'provider1'
client_metadata=ClientMetadata(CLIENT1, '765cc93b-aafb-4d27-9791-327812a4a6de')
PROVIDER_CONFIG1 = ProviderConfiguration(issuer=ISSUER1,
    client_metadata=client_metadata)

# provider_dict = {PROVIDER_NAME1: PROVIDER_CONFIG1}
# provider_dict = None

app.config['OIDC_PROVIDERS'] = 'provider1'
app.config['provider1_ISSUER'] = 'http://localhost:8890/auth/realms/mypatient'
app.config['provider1_CLIENT'] = 'pathds'
app.config['provider1_SECRET'] = ''
app.config['OIDC_REQUIRED_ROLES'] = "admin"
app.config['OIDC_ROLE_CLAIM'] = "realm_access.roles"

auth = OIDCAuthentication( app=app)

@app.route('/')
@auth.oidc_auth(bearer = True)
def login1():
    user_session = UserSession(flask.session)
    return jsonify(access_token=user_session.access_token,
                   id_token=user_session.id_token,
                   userinfo=user_session.userinfo)

@app.route('/bearer_test')
@auth.oidc_auth()
def bearer_test():
    user_session = UserSession(flask.session)
    headers = {'Authorization': 'Bearer ' + user_session.access_token}

    diagnoses_response = requests.get('https://oda-mypatient360-dev.westus2.cloudapp.azure.com/ehr/name?Patient_ID=1616',
                    headers=headers)
    
    print('done!')
    return diagnoses_response.json()



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

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
auth.init_app(app)

if __name__ == '__main__':
    app.run(host='0.0.0.0')
