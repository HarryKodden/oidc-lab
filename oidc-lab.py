#!/usr/bin/env python

"""oidc-lab.py: Core functionality of the application.
"""

__author__      = "Harry Kodden"
__copyright__   = "Copyright 2018, SURFnet"
__version__     = "1.0"
__maintainer__  = "Harry Kodden"
__email__       = "harry.kodden@surfnet.nl"
__status__      = "Development"

import os
import json
import logging
import urllib
import functools
import requests

from flask import Flask, g, redirect, current_app, jsonify, request
from flask_oidc import OpenIDConnect, DummySecretsCache
from flask_restful import abort, Api, Resource
from oauth2client.client import flow_from_clientsecrets, OAuth2WebServerFlow

logging.basicConfig(level=logging.DEBUG)

logger = logging.getLogger(__name__)

PORT = 8000
HOST = os.environ.get("HOST", "localhost:%d"% (PORT))

if HOST.startswith("localhost"):
   scheme = "http"
else:
   scheme = "https"

REQUESTED_SCOPES = "openid"
REDIRECT_URL = "https://%s/oidc_callback" % (HOST)

app = Flask(__name__)

app.config.update({
    'SECRET_KEY': 'SomethingNotEntirelySecret',
    'TESTING': True,
    'DEBUG': True,
    "PREFERRED_URL_SCHEME": scheme,
    'OIDC_CLIENT_SECRETS': None,
    'OIDC_ID_TOKEN_COOKIE_SECURE': False,
    'OIDC_REQUIRE_VERIFIED_EMAIL': False,
    'OIDC_OPENID_REALM': REDIRECT_URL,
    'OIDC_USER_INFO_ENABLED': True,
    'OIDC_SCOPES': ['openid', 'email', 'profile'],
    'OIDC_INTROSPECTION_AUTH_METHOD': 'client_secret_post'
})

PROVIDERS = {}

def abort_if_provider_doesnt_exist(name):
    if name not in PROVIDERS:
        abort(404, message="Provider {} doesn't exist".format(name))

class Provider(Resource):
    def get(self, name):
        abort_if_provider_doesnt_exist(name)
        return PROVIDERS[name]

    def delete(self, name):
        abort_if_provider_doesnt_exist(name)
        del PROVIDERS[name]
        return '', 204

    def put(self, name):
        try:
            p = request.get_json()
            assert p != None, "missing provider definition"
            assert 'base_url' in p, "'base_url' missing"
        except Exception as e:
            logger.debug("Error: {}".format(str(e)))
            abort(404, message="{}".format(str(e)))

        PROVIDERS[name] = request.get_json()
        return PROVIDERS[name], 201

class Providers(Resource):
    def get(self):
        return PROVIDERS

api = Api(app)
api.add_resource(Provider, '/api/provider/<name>')
api.add_resource(Providers, '/api/providers')

from itsdangerous import JSONWebSignatureSerializer, TimedJSONWebSignatureSerializer

class MyOpenIDConnect(OpenIDConnect):

    def __init__(self, app=None, credentials_store=None, http=None, time=None,
                 urandom=None, provider=None):

        self.last_token = None

        super().__init__(credentials_store, http, time, urandom)

        self.client_secrets = None

        if app:
            self.init_app(app)

        if provider:
            self.init_provider(app, provider)

    def init_app(self, app):
        """
        Do setup that requires a Flask app.

        :param app: The application to initialize.
        :type app: Flask
        """
        # Set some default configuration options
        app.config.setdefault('OIDC_SCOPES', ['openid', 'email'])
        app.config.setdefault('OIDC_GOOGLE_APPS_DOMAIN', None)
        app.config.setdefault('OIDC_ID_TOKEN_COOKIE_NAME', 'oidc_id_token')
        app.config.setdefault('OIDC_ID_TOKEN_COOKIE_PATH', '/')
        app.config.setdefault('OIDC_ID_TOKEN_COOKIE_TTL', 7 * 86400)  # 7 days
        # should ONLY be turned off for local debugging
        app.config.setdefault('OIDC_COOKIE_SECURE', True)
        app.config.setdefault('OIDC_VALID_ISSUERS',None)
        app.config.setdefault('OIDC_CLOCK_SKEW', 60)  # 1 minute
        app.config.setdefault('OIDC_REQUIRE_VERIFIED_EMAIL', False)
        app.config.setdefault('OIDC_OPENID_REALM', None)
        app.config.setdefault('OIDC_USER_INFO_ENABLED', True)
        app.config.setdefault('OIDC_CALLBACK_ROUTE', '/oidc_callback')
        app.config.setdefault('OVERWRITE_REDIRECT_URI', REDIRECT_URL)
        # Configuration for resource servers
        app.config.setdefault('OIDC_RESOURCE_SERVER_ONLY', False)
        app.config.setdefault('OIDC_RESOURCE_CHECK_AUD', False)

        # We use client_secret_post, because that's what the Google
        # oauth2client library defaults to
        app.config.setdefault('OIDC_INTROSPECTION_AUTH_METHOD', 'client_secret_post')
        app.config.setdefault('OIDC_TOKEN_TYPE_HINT', 'access_token')

        if not 'openid' in app.config['OIDC_SCOPES']:
            raise ValueError('The value "openid" must be in the OIDC_SCOPES')

        # register callback route and cookie-setting decorator
        if not app.config['OIDC_RESOURCE_SERVER_ONLY']:
            app.route(app.config['OIDC_CALLBACK_ROUTE'])(self._oidc_callback)
            app.before_request(self._before_request)
            app.after_request(self._after_request)

        # create signers using the Flask secret key
        self.extra_data_serializer = JSONWebSignatureSerializer(
            app.config['SECRET_KEY'])
        self.cookie_serializer = TimedJSONWebSignatureSerializer(
            app.config['SECRET_KEY'])

        try:
            self.credentials_store = app.config['OIDC_CREDENTIALS_STORE']
        except KeyError:
            pass

    def _before_request(self):
        g.oidc_id_token = None

        if self.client_secrets:
            self.authenticate_or_redirect()

    def init_provider(self, provider):
        """
        Do setup for a specific provider

        :param app: The application to initialize.
        :type app: Flask
        """

        secrets = self.load_secrets(provider)
        assert secrets != None, "Problem with loading secrets"

        self.client_secrets = list(secrets.values())[0]
        secrets_cache = DummySecretsCache(secrets)

        # Initialize oauth2client
        self.flow = flow_from_clientsecrets(
            current_app.config['OIDC_CLIENT_SECRETS'],
            scope=current_app.config['OIDC_SCOPES'],
            cache=secrets_cache)
        assert isinstance(self.flow, OAuth2WebServerFlow)

        current_app.config['OIDC_VALID_ISSUERS'] = self.client_secrets.get('issuer')

    def logout(self):
        logger.debug("logging out...")

        super().logout()
        self.last_token = None

    def __exit__(self, exception_type, exception_value, traceback):
        self.logout()

        current_app.config['OIDC_VALID_ISSUERS'] = None

        if self.client_secrets:
            logger.debug("Closing connection with current provider...")
            self.client_secrets = None

    def _is_id_token_valid(self, id_token):
        if 'aud' in id_token and isinstance(id_token['aud'], list) and len(id_token['aud']) == 1:
            id_token['aud'] = id_token['aud'][0]

        self.last_token = id_token

        return super()._is_id_token_valid(id_token)

    def details(self):
        return self._retrieve_userinfo()

    def load_secrets(self, provider):
        if not provider:
            return None

        try:
            url = provider.get('base_url')

            if not url.endswith('/'):
                url += '/'

            url += ".well-known/openid-configuration"

            logger.debug("Loading: {}".format(url))

            provider_info = json.load(
                urllib.request.urlopen(url)
            )

        except Exception as e:
            raise Exception("Can not obtain well known information: {}".format(str(e)))

        for path in ['issuer', 'registration_endpoint', 'authorization_endpoint', 'token_endpoint', 'userinfo_endpoint']:
            if path in provider_info and provider_info[path].startswith('/'):
                provider_info[path] = "{}{}".format(provider.get('base_url'), provider_info[path])

        registration = provider.get('registration', None)

        if not registration:
            try:
                logger.debug("Dynamic Registration...")

                registration = requests.post(
                    provider_info['registration_endpoint'],
                    data = json.dumps({
                        "redirect_uris": REDIRECT_URL,
                        "grant_types": "authorization_code",
                        "client_name": provider.get('client_name', "Dynamic Registration"),
                        "response_types": "code",
                        "token_endpoint_auth_method": "client_secret_post",
                        "application_type": "native"
                    }),
                    headers = {
                        'Content-Type': "application/json",
                        'Cache-Control': "no-cache"
                    }
                ).json()

                logger.debug("Registration: {}".format(registration))

            except Exception as e:
                raise Exception("Can not make client registration: {}".format(str(e)))

        try:
            return {
                'web' : {
                    'client_id': registration['client_id'],
                    'client_secret': registration['client_secret'],
                    'auth_uri': provider_info['authorization_endpoint'],
                    'token_uri': provider_info['token_endpoint'],
                    'userinfo_uri': provider_info['userinfo_endpoint'],
                    'redirect_uris': REDIRECT_URL,
                    'issuer': provider_info['issuer'],
                }
            }
        except Exception as e:
            raise Exception("Error in preparing result: {}".format(str(e)))

        raise Exception("No secrets loaded !")

oidc =  MyOpenIDConnect(app)

@app.route('/login/<provider>')
def login(provider):

    logger.error("Logging in to provider: {}".format(provider))

    try:
        oidc.logout()
        oidc.init_provider(PROVIDERS[provider])
        return redirect('/private', code=302)
    except Exception as e:
        return 'Error activating provider: {}, error: {}<br/><br/><a href="/">Return</a>'.format(provider, str(e))

@app.route('/')
def hello_world():

    options = ''
    for i in PROVIDERS.keys():
        options += '<option value="{}">{}</option>'.format(i,i)

    html = """
    <h1>Welcome to my OIDC switch board</h1>
    <h2>Choose a provider...</h2>
    <select name="formal" onchange="javascript:handleSelect(this)">
        <option value="">### select a provider ###></option>
        {}
    </select>
""".format(options)

    script = """
    <script type="text/javascript">
        function handleSelect(provider) {
            if (provider > "") {
                window.location = "/login/"+provider.value;
            }
        }
    </script>
"""

    help = """
<hr><h1>Howto</h1>
<br/>You can manage provider details via RESTful API interface.
<br/><br/>
<b>Example 1. List current Providers</b><br/>
<a href="/api/providers">List Providers</a>
<br/><br/>
<b>Example 2. Add a provider that allows dynamic regfistration</b><br/>
<br/>
<pre>
curl -X PUT \\
  %s://%s/api/provider/test \\
  -H 'Content-Type: application/json' \\
  -d '{ "base_url": "https://eduid.lab.surf.nl/", "description": "My Provider", "client_name": "testing123" }'
</pre>
<br/>
Above provider will use 'dynamic client registration', off course this will only work if your provider allows you to do so.
<br/><br/>
<b>Example 3. Add a provider with client credentials</b><br/>
<br/>
If you have client_id and client_secret from your provider, then specify as follows:
<pre>
curl -X PUT \\
  %s://%s/api/provider/test \\
  -H 'Content-Type: application/json' \\
  -d '{ "base_url": "https://eduid.lab.surf.nl/", "registration": { "client_id": "<b>YOUR CLIENT_ID</b>", "client_secret": "<b>YOUR CLIENT_SECRET</b>" }  }'
</pre>
<br/>
<b>NOTE:</b> Please make sure your have registered <b>%s</b> as a valid callback uri with your provider !
<br/>
<hr/>
(c)2018 Harry Kodden, <a href="https://github.com/HarryKodden/oidc-lab">Source on Github</a>
""" % (scheme, HOST, scheme, HOST, REDIRECT_URL)

    if oidc.user_loggedin:
        return (
            'You are logged in with userid: %s<br/><br/>'
            '<a href="/private">See private</a><br/>'
            '<a href="/logout">Log out</a>'
        ) % oidc.user_getfield('sub')
    else:
        return '{}{}{}'.format(html,script,help)


@app.route('/private')
@oidc.require_login
def hello_me():

    try:
        token = '<h1>Token Details:</h1><br/><table border="1">'
        token += '<tr><th>Attribute</th><th>Value</th></tr>'
        for f in oidc.last_token.keys():
            token += '<tr><td>{}</td><td>{}</td></tr>'.format(f, oidc.last_token[f])
        token += '</table>'
    except:
        token = 'No token details available...'

    try:
        info = oidc.details()

        data = '<h1>User Info:</h1><br/><table border="1">'
        data += '<tr><th>Attribute</th><th>Value</th></tr>'
        if info:
            for f in info.keys():
                data += '<tr><td>{}</td><td>{}</td></tr>'.format(f, info[f])
        data += '</table>'
    except:
        data = 'No userdata available...'

    return ('<br/>%s<br/>%s<br/><a href="/">Return</a>' % (token, data))

@app.route('/logout')
def logout():
    oidc.logout()
    return 'Hi, you have been logged out!<br/><br/><a href="/">Return</a>'

if __name__ == "__main__":

    if app.debug:
        import os
        # Allow insecure oauth2 when debugging
        os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

    # Explicitly set `host=localhost` in order to get the correct redirect_uri.
    app.run(host="0.0.0.0", port=PORT)