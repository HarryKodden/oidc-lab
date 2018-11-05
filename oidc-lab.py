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
import jwt

from flask import Flask, g, redirect, current_app, jsonify, request, render_template
from flask_oidc import OpenIDConnect, DummySecretsCache
from flask_restful import abort, Api, Resource
from oauth2client.client import flow_from_clientsecrets, OAuth2WebServerFlow

logging.basicConfig(level=logging.DEBUG)

logger = logging.getLogger(__name__)

PORT = 8000
HOST = os.environ.get("HOST", "localhost:%d"% (PORT))

if HOST.startswith("localhost"):
   SCHEME = "http"
else:
   SCHEME = "https"

REQUESTED_SCOPES = ['openid', 'email', 'profile']

CALLBACK = "/oidc_callback"
BACKCHANNEL_LOGOUT = "/logout"

REDIRECT_URL = "{}://{}{}".format(SCHEME, HOST, CALLBACK)

app = Flask(__name__)

app.config.update({
    'server' : 'https://eduid.lab.surf.nl/auth/',
    'realm' : 'eduID',
    'client_id': 'portal',
    'SECRET_KEY': 'SomethingNotEntirelySecret',
    'TESTING': True,
    'DEBUG': True,
    "PREFERRED_URL_SCHEME": SCHEME,
    'OIDC_CLIENT_SECRETS': None,
    'OIDC_ID_TOKEN_COOKIE_SECURE': False,
    'OIDC_REQUIRE_VERIFIED_EMAIL': False,
    'OIDC_OPENID_REALM': REDIRECT_URL,
    'OIDC_USER_INFO_ENABLED': True,
    'OIDC_SCOPES': REQUESTED_SCOPES,
    'OIDC_INTROSPECTION_AUTH_METHOD': 'client_secret_post'
})

ALLOWED_REGISTRATTION_ATTRIBUTES = ['client_id', 'client_secret']

class _Registration(dict):
    def __init__(self, data):
        logger.debug('New Registration: {}'.format(data))

        assert 'client_id' in data, "'client_id' is missing in registration"
        assert 'client_secret' in data, "'client_secret' is missing in registration"

        for i in data.keys():
            self[i] = data[i]

    def __getitem__(self, key):
        if key == 'client_secret':
            return '*******'
        elif key == '*client_secret*':
            return super().__getitem__('client_secret')
        else:
            return super().__getitem__(key)

    def get(self,key,default=None):
        try:
            return self[key]
        except:
            return default

    def __setitem__(self, key, value):
        logger.debug('- [REGISTRATION] {} := {}'.format(key, value))

        assert key in ALLOWED_REGISTRATTION_ATTRIBUTES, \
            "attribute {} not valid, only {} allowed". format(key, ALLOWED_REGISTRATTION_ATTRIBUTES)

        super().__setitem__(key, value)

ALLOWED_PROVIDER_ATTRIBUTES = ['base_url', 'description', 'client_name', 'registration']

class _Provider(dict):

    def __init__(self, data):
        logger.debug('New Provider: {}'.format(data))

        assert 'base_url' in data, "'base_url' missing"

        for i in data.keys():
            self[i] = data[i]

    def get(self,key,default=None):
        try:
            return self[key]
        except:
            return default

    def __getitem__(self, key):
        return super().__getitem__(key)

    def __setitem__(self, key, value):
        logger.debug('- [PROVIDER] {} := {}'.format(key, value))

        assert key in ALLOWED_PROVIDER_ATTRIBUTES, \
            "attribute {} not valid, only {} allowed". format(key, ALLOWED_PROVIDER_ATTRIBUTES)

        if key == 'registration':
            super().__setitem__(key, _Registration(value))
        else:
            super().__setitem__(key, value)

PROVIDERS = {}

def abort_if_provider_doesnt_exist(name):
    if name not in PROVIDERS:
        abort(404, message="Provider {} doesn't exist".format(name))

def get_dict(value):

    if isinstance(value, dict):
        result = {}

        for i in value.keys():
            result[i] = get_dict(value[i])

        return result
    elif isinstance(value, list):
        result = []

        for i in value.keys():
            result.append(get_dict(value[i]))

        return result
    else:
        return value

class Provider(Resource):
    def get(self, name):
        abort_if_provider_doesnt_exist(name)
        return get_dict(PROVIDERS[name])

    def delete(self, name):
        abort_if_provider_doesnt_exist(name)
        del PROVIDERS[name]
        return '', 204

    def put(self, name):
        logger.debug("PUT Provider: {}...".format(name))

        try:
            data = request.get_json()

            assert data != None, "missing provider definition"

            PROVIDERS[name] = _Provider(data)

        except Exception as e:

            logger.debug("Error: {}".format(str(e)))
            abort(404, message="{}".format(str(e)))

        return self.get(name), 201

class Providers(Resource):
    def get(self):
        return get_dict(PROVIDERS)

api = Api(app)
api.add_resource(Provider, '/api/provider/<name>')
api.add_resource(Providers, '/api/providers')

from itsdangerous import JSONWebSignatureSerializer, TimedJSONWebSignatureSerializer

class MyOpenIDConnect(OpenIDConnect):

    def __init__(self, app=None, credentials_store=None, http=None, time=None,
                 urandom=None, provider=None):

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
        app.config.setdefault('OIDC_SCOPES', REQUESTED_SCOPES)
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
        app.config.setdefault('OIDC_CALLBACK_ROUTE', CALLBACK)
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

        :param provider: The provider to initialize.
        :type provider: Dictionary with at lease 'base_url' item
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

    def __exit__(self, exception_type, exception_value, traceback):
        self.logout()

        current_app.config['OIDC_VALID_ISSUERS'] = None

        if self.client_secrets:
            logger.debug("Closing connection with current provider...")
            self.client_secrets = None

    def _is_id_token_valid(self, id_token):
        if 'aud' in id_token and isinstance(id_token['aud'], list) and len(id_token['aud']) == 1:
            id_token['aud'] = id_token['aud'][0]

        return super()._is_id_token_valid(id_token)

    def token(self):
        try:
            return self.credentials_store[g.oidc_id_token['sub']]
        except KeyError:
            logger.debug("No Token !", exc_info=True)
            return None

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
            try:
               jwks_keys = json.load(
                 urllib.request.urlopen(provider_info['jwks_uri'])
               )
            except:
               jwks_keys = None

            return {
                'web' : {
                    'client_id': registration.get('client_id'),
                    'client_secret': registration.get('*client_secret*', registration.get('client_secret', None)),
                    'auth_uri': provider_info['authorization_endpoint'],
                    'token_uri': provider_info['token_endpoint'],
                    'userinfo_uri': provider_info['userinfo_endpoint'],
                    'jwks_keys': jwks_keys,
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
""" % (SCHEME, HOST, SCHEME, HOST, REDIRECT_URL)

    if oidc.user_loggedin:
        return (
            'You are logged in with userid: %s<br/><br/>'
            '<a href="/private">See private</a><br/>'
            '<a href="/logout">Log out</a>'
        ) % oidc.user_getfield('sub')
    else:
        return '{}{}{}'.format(html,script,help)


@app.route('/uma')
@oidc.require_login
def uma():
    return render_template('uma.html', error="", client=oidc.client_secrets, token=json.loads(oidc.token()))

@app.route('/private')
@oidc.require_login
def hello_me():

    try:
        token = '<h1>Token Details:</h1><br/><table border="1">'
        token += '<tr><th>Attribute</th><th>Value</th></tr>'

        t = json.loads(oidc.token())['token_response']
        logger.debug("TOKEN: {}".format(t))

        for k,v in t.items():
            try:
                v = jwt.decode(v, verify=False)
                v = json.dumps(v, indent=4, sort_keys=True)
            except:
                pass

            token += '<tr><td>{}</td><td><pre>{}</pre></td></tr>'.format(k, v)
        token += '</table>'
    except Exception as e:
        token = 'No token details available...{}'.format(str(e))

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

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    if request.method == 'POST':
        # Evaluate BackChannel logout
        # Refer: https://openid.net/specs/openid-connect-X-1_0.html
        # chapter 2.5 Back-Channel Logout Request

        logger.debug("Backchannel logout request")
        # need to evaluate the request...
        """        
    If the Logout Token is encrypted, decrypt it using the keys and algorithms that the Client specified during Registration that the OP was to use to encrypt ID Tokens.
    If ID Token encryption was negotiated with the OP at Registration time and the Logout Token is not encrypted, the RP SHOULD reject it.
    Validate the Logout Token signature in the same way that an ID Token signature is validated, with the following refinements.
    Validate the iss, aud, and iat Claims in the same way they are validated in ID Tokens.
    Verify that the Logout Token contains a sub Claim, a sid Claim, or both.
    Verify that the Logout Token contains an events Claim whose value is JSON object containing the member name http://schemas.openid.net/event/backchannel-logout.
    Verify that the Logout Token does not contain a nonce Claim.
    Optionally verify that another Logout Token with the same jti value has not been recently received.
"""
        logout_token = request.get_data()

        try:
            v = logout_token
            logger.debug("Logout Token 1: {}".format(v))
            v = jwt.decode(v, verify=False)
            logger.debug("Logout Token 2: {}".format(v))
            v = json.dumps(v, indent=4, sort_keys=True)
            logger.debug("Logout Token 3: {}".format(v))
        except:
            logger.debug("Logout Token: {}".format(logout_token))

        # Make response
        """
 If the logout succeeded, the RP MUST respond with HTTP 200 OK. 
 If the logout request was invalid, the RP MUST respond with HTTP 400 Bad Request. 
 If the logout failed, the RP MUST respond with 501 Not Implemented. 
 If the local logout succeeded but some downstream logouts have failed, the RP MUST respond with HTTP 504 Gateway Timeout.

The RP's response SHOULD include Cache-Control directives keeping the response from being cached to prevent cached responses from interfering with future logout requests. It is RECOMMENDED that these directives be used: 

- Cache-Control: no-cache, no-store
- Pragma: no-cache
"""
        oidc.logout()

        r = make_response('', 200)
        r.headers['Cache-Control'] = 'no-cache, no-store'
        r.headers['Pragma'] = 'no-cache'
        return r

    oidc.logout()
    return 'Hi, you have been logged out!<br/><br/><a href="/">Return</a>'

if __name__ == "__main__":

    if app.debug:
        import os
        # Allow insecure oauth2 when debugging
        os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

    # Explicitly set `host=localhost` in order to get the correct redirect_uri.
    app.run(host="0.0.0.0", port=PORT)
