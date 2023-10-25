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
import requests
import jwt
import ssl
import time
import logging
import calendar

from functools import wraps
from base64 import b64encode, b64decode, urlsafe_b64encode, urlsafe_b64decode
from copy import copy
from warnings import warn

from flask import Flask, g, redirect, current_app, request, render_template, Response, session
from flask.helpers import make_response
from flask_restful import abort, Api, Resource

from oauth2client.client import flow_from_clientsecrets, OAuth2WebServerFlow, AccessTokenRefreshError, OAuth2Credentials

import httplib2

from six.moves.urllib.parse import urlencode

import gevent
from gevent.pywsgi import WSGIServer
from gevent.queue import Queue

LOG_LEVEL = os.environ.get('LOG_LEVEL', 'DEBUG').upper()

logging.basicConfig(
    level=LOG_LEVEL,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

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
    'OIDC_OPENID_REALM': None,
    'OIDC_USER_INFO_ENABLED': True,
    'OIDC_SCOPES': REQUESTED_SCOPES,
    'OIDC_INTROSPECTION_AUTH_METHOD': 'client_secret_post'
})

ALLOWED_REGISTRATTION_ATTRIBUTES = ['client_id', 'client_secret']

def _json_loads(content):
    if not isinstance(content, str):
        content = content.decode('utf-8')
    return json.loads(content)

class MemoryCredentials(dict):
    """
    Non-persistent local credentials store.
    Use this if you only have one app server, and don't mind making everyone
    log in again after a restart.
    """
    pass


class DummySecretsCache(object):
    """
    oauth2client secrets cache
    """
    def __init__(self, client_secrets):
        self.client_secrets = client_secrets

    def get(self, filename, namespace):
        return self.client_secrets


class ErrStr(str):
    """
    This is a class to work around the time I made a terrible API decision.

    Basically, the validate_token() function returns a boolean True if all went
    right, but a string with an error message if something went wrong.

    The problem here is that this means that "if validate_token(...)" will
    always be True, even with an invalid token, and users had to do
    "if validate_token(...) is True:".

    This is counter-intuitive, so let's "fix" this by returning instances of
    this ErrStr class, which are basic strings except for their bool() results:
    they return False.
    """
    def __nonzero__(self):
        """The py2 method for bool()."""
        return False

    def __bool__(self):
        """The py3 method for bool()."""
        return False

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

ALLOWED_PROVIDER_ATTRIBUTES = ['base_url', 'description', 'client_name', 'registration', 'scopes']

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

        for i in value:
            result.append(i)

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

class OpenIDConnect(object):
    """
    The core OpenID Connect client object.
    """
    def __init__(self, app=None, credentials_store=None, http=None, time=None,
                 urandom=None):
        self.credentials_store = credentials_store\
            if credentials_store is not None\
            else MemoryCredentials()

        if http is not None:
            warn('HTTP argument is deprecated and unused', DeprecationWarning)
        if time is not None:
            warn('time argument is deprecated and unused', DeprecationWarning)
        if urandom is not None:
            warn('urandom argument is deprecated and unused',
                 DeprecationWarning)

        # By default, we do not have a custom callback
        self._custom_callback = None

        # get stuff from the app's config, which may override stuff set above
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """
        Do setup that requires a Flask app.

        :param app: The application to initialize.
        :type app: Flask
        """
        secrets = self.load_secrets(app)
        self.client_secrets = list(secrets.values())[0]
        secrets_cache = DummySecretsCache(secrets)

        # Set some default configuration options
        app.config.setdefault('OIDC_SCOPES', ['openid', 'email'])
        app.config.setdefault('OIDC_GOOGLE_APPS_DOMAIN', None)
        app.config.setdefault('OIDC_ID_TOKEN_COOKIE_NAME', 'oidc_id_token')
        app.config.setdefault('OIDC_ID_TOKEN_COOKIE_PATH', '/')
        app.config.setdefault('OIDC_ID_TOKEN_COOKIE_TTL', 7 * 86400)  # 7 days
        # should ONLY be turned off for local debugging
        app.config.setdefault('OIDC_COOKIE_SECURE', True)
        app.config.setdefault('OIDC_VALID_ISSUERS',
                              (self.client_secrets.get('issuer') or
                               GOOGLE_ISSUERS))
        app.config.setdefault('OIDC_CLOCK_SKEW', 60)  # 1 minute
        app.config.setdefault('OIDC_REQUIRE_VERIFIED_EMAIL', False)
        app.config.setdefault('OIDC_OPENID_REALM', None)
        app.config.setdefault('OIDC_USER_INFO_ENABLED', True)
        app.config.setdefault('OIDC_CALLBACK_ROUTE', '/oidc_callback')
        app.config.setdefault('OVERWRITE_REDIRECT_URI', False)
        app.config.setdefault("OIDC_EXTRA_REQUEST_AUTH_PARAMS", {})
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

        # Initialize oauth2client
        self.flow = flow_from_clientsecrets(
            app.config['OIDC_CLIENT_SECRETS'],
            scope=app.config['OIDC_SCOPES'],
            cache=secrets_cache)
        assert isinstance(self.flow, OAuth2WebServerFlow)

        self.extra_data_salt = 'flask-oidc-extra-data'
        self.cookie_salt = 'flask-oidc-cookie'
        self.extra_data_key = app.config['SECRET_KEY'] + self.extra_data_salt
        self.cookie_key = app.config['SECRET_KEY'] + self.cookie_salt

        try:
            self.credentials_store = app.config['OIDC_CREDENTIALS_STORE']
        except KeyError:
            pass

    def load_secrets(self, app):
        # Load client_secrets.json to pre-initialize some configuration
        content = app.config['OIDC_CLIENT_SECRETS']
        if isinstance(content, dict):
            return content
        else:
            return _json_loads(open(content, 'r').read())

    @property
    def user_loggedin(self):
        """
        Represents whether the user is currently logged in.

        Returns:
            bool: Whether the user is logged in with Flask-OIDC.

        .. versionadded:: 1.0
        """
        return g.oidc_id_token is not None

    def user_getfield(self, field, access_token=None):
        """
        Request a single field of information about the user.

        :param field: The name of the field requested.
        :type field: str
        :returns: The value of the field. Depending on the type, this may be
            a string, list, dict, or something else.
        :rtype: object

        .. versionadded:: 1.0
        """
        info = self.user_getinfo([field], access_token)
        return info.get(field)

    def user_getinfo(self, fields, access_token=None):
        """
        Request multiple fields of information about the user.

        :param fields: The names of the fields requested.
        :type fields: list
        :returns: The values of the current user for the fields requested.
            The keys are the field names, values are the values of the
            fields as indicated by the OpenID Provider. Note that fields
            that were not provided by the Provider are absent.
        :rtype: dict
        :raises Exception: If the user was not authenticated. Check this with
            user_loggedin.

        .. versionadded:: 1.0
        """
        if g.oidc_id_token is None and access_token is None:
            raise Exception('User was not authenticated')
        info = {}
        all_info = None
        for field in fields:
            if access_token is None and field in g.oidc_id_token:
                info[field] = g.oidc_id_token[field]
            elif current_app.config['OIDC_USER_INFO_ENABLED']:
                # This was not in the id_token. Let's get user information
                if all_info is None:
                    all_info = self._retrieve_userinfo(access_token)
                    if all_info is None:
                        # To make sure we don't retry for every field
                        all_info = {}
                if field in all_info:
                    info[field] = all_info[field]
                else:
                    # We didn't get this information
                    pass
        return info

    def get_access_token(self):
        """Method to return the current requests' access_token.

        :returns: Access token or None
        :rtype: str

        .. versionadded:: 1.2
        """
        try:
            credentials = OAuth2Credentials.from_json(
                self.credentials_store[g.oidc_id_token['sub']])
            return credentials.access_token
        except KeyError:
            logger.debug("Expired ID token, credentials missing",
                         exc_info=True)
            return None

    def get_refresh_token(self):
        """Method to return the current requests' refresh_token.

        :returns: Access token or None
        :rtype: str

        .. versionadded:: 1.2
        """
        try:
            credentials = OAuth2Credentials.from_json(
                self.credentials_store[g.oidc_id_token['sub']])
            return credentials.refresh_token
        except KeyError:
            logger.debug("Expired ID token, credentials missing",
                         exc_info=True)
            return None

    def _retrieve_userinfo(self, access_token=None):
        """
        Requests extra user information from the Provider's UserInfo and
        returns the result.

        :returns: The contents of the UserInfo endpoint.
        :rtype: dict
        """
        if 'userinfo_uri' not in self.client_secrets:
            logger.debug('Userinfo uri not specified')
            raise AssertionError('UserInfo URI not specified')

        # Cache the info from this request
        if '_oidc_userinfo' in g:
            return g._oidc_userinfo

        http = httplib2.Http()
        if access_token is None:
            try:
                credentials = OAuth2Credentials.from_json(
                    self.credentials_store[g.oidc_id_token['sub']])
            except KeyError:
                logger.debug("Expired ID token, credentials missing",
                             exc_info=True)
                return None
            credentials.authorize(http)
            resp, content = http.request(self.client_secrets['userinfo_uri'])
        else:
            # We have been manually overriden with an access token
            resp, content = http.request(
                self.client_secrets['userinfo_uri'],
                "POST",
                body=urlencode({"access_token": access_token}),
                headers={'Content-Type': 'application/x-www-form-urlencoded'})

        logger.debug('Retrieved user info: %s' % content)
        info = _json_loads(content)

        g._oidc_userinfo = info

        return info


    def get_cookie_id_token(self):
        """
        .. deprecated:: 1.0
           Use :func:`user_getinfo` instead.
        """
        warn('You are using a deprecated function (get_cookie_id_token). '
             'Please reconsider using this', DeprecationWarning)
        return self._get_cookie_id_token()

    def _get_cookie_id_token(self):
        try:
            id_token_cookie = request.cookies.get(current_app.config[
                'OIDC_ID_TOKEN_COOKIE_NAME'])
            if not id_token_cookie:
                # Do not error if we were unable to get the cookie.
                # The user can debug this themselves.
                return None
            return jwt.decode(id_token_cookie, self.cookie_key, audience=self.client_secrets['client_id'],
                              algorithms=["HS512"])
        except jwt.ExpiredSignatureError:
            logger.debug("Invalid ID token cookie", exc_info=True)
            return None
        except jwt.InvalidSignatureError:
            logger.info("Signature invalid for ID token cookie", exc_info=True)
            return None
        except:
             logger.info("Token cookie JWT error", exc_info=True)
             return None

    def set_cookie_id_token(self, id_token):
        """
        .. deprecated:: 1.0
        """
        warn('You are using a deprecated function (set_cookie_id_token). '
             'Please reconsider using this', DeprecationWarning)
        return self._set_cookie_id_token(id_token)

    def _set_cookie_id_token(self, id_token):
        """
        Cooperates with @after_request to set a new ID token cookie.
        """
        g.oidc_id_token = id_token
        g.oidc_id_token_dirty = True

    def _after_request(self, response):
        """
        Set a new ID token cookie if the ID token has changed.
        """
        # This means that if either the new or the old are False, we set
        # insecure cookies.
        # We don't define OIDC_ID_TOKEN_COOKIE_SECURE in init_app, because we
        # don't want people to find it easily.
        cookie_secure = (current_app.config['OIDC_COOKIE_SECURE'] and
                         current_app.config.get('OIDC_ID_TOKEN_COOKIE_SECURE',
                                                True))

        if getattr(g, 'oidc_id_token_dirty', False):
            if g.oidc_id_token:
                signed_id_token = jwt.encode(g.oidc_id_token, self.cookie_key, algorithm="HS512")
                response.set_cookie(
                    current_app.config['OIDC_ID_TOKEN_COOKIE_NAME'],
                    signed_id_token,
                    secure=cookie_secure,
                    httponly=True,
                    max_age=current_app.config['OIDC_ID_TOKEN_COOKIE_TTL'])
            else:
                # This was a log out
                response.set_cookie(
                    current_app.config['OIDC_ID_TOKEN_COOKIE_NAME'],
                    '',
                    path=current_app.config['OIDC_ID_TOKEN_COOKIE_PATH'],
                    secure=cookie_secure,
                    httponly=True,
                    expires=0)
        return response

    def _before_request(self):
        g.oidc_id_token = None
        self.authenticate_or_redirect()

    def authenticate_or_redirect(self):
        """
        Helper function suitable for @app.before_request and @check.
        Sets g.oidc_id_token to the ID token if the user has successfully
        authenticated, else returns a redirect object so they can go try
        to authenticate.

        :returns: A redirect object, or None if the user is logged in.
        :rtype: Redirect

        .. deprecated:: 1.0
           Use :func:`require_login` instead.
        """
        # the auth callback and error pages don't need user to be authenticated
        if request.endpoint in frozenset(['_oidc_callback', '_oidc_error']):
            return None

        # retrieve signed ID token cookie
        id_token = self._get_cookie_id_token()
        if id_token is None:
            return self.redirect_to_auth_server(request.url)

        # ID token expired
        # when Google is the IdP, this happens after one hour
        if time.time() >= id_token['exp']:
            # get credentials from store
            try:
                credentials = OAuth2Credentials.from_json(
                    self.credentials_store[id_token['sub']])
            except KeyError:
                logger.debug("Expired ID token, credentials missing",
                             exc_info=True)
                return self.redirect_to_auth_server(request.url)

            # refresh and store credentials
            try:
                credentials.refresh(httplib2.Http())
                if credentials.id_token:
                    id_token = credentials.id_token
                else:
                    # It is not guaranteed that we will get a new ID Token on
                    # refresh, so if we do not, let's just update the id token
                    # expiry field and reuse the existing ID Token.
                    if credentials.token_expiry is None:
                        logger.debug('Expired ID token, no new expiry. Falling'
                                     ' back to assuming 1 hour')
                        id_token['exp'] = time.time() + 3600
                    else:
                        id_token['exp'] = calendar.timegm(
                            credentials.token_expiry.timetuple())
                self.credentials_store[id_token['sub']] = credentials.to_json()
                self._set_cookie_id_token(id_token)
            except AccessTokenRefreshError:
                # Can't refresh. Wipe credentials and redirect user to IdP
                # for re-authentication.
                logger.debug("Expired ID token, can't refresh credentials",
                             exc_info=True)
                del self.credentials_store[id_token['sub']]
                return self.redirect_to_auth_server(request.url)

        # make ID token available to views
        g.oidc_id_token = id_token

        return None

    def require_login(self, view_func):
        """
        Use this to decorate view functions that require a user to be logged
        in. If the user is not already logged in, they will be sent to the
        Provider to log in, after which they will be returned.

        .. versionadded:: 1.0
           This was :func:`check` before.
        """
        @wraps(view_func)
        def decorated(*args, **kwargs):
            if g.oidc_id_token is None:
                return self.redirect_to_auth_server(request.url)
            return view_func(*args, **kwargs)
        return decorated
    # Backwards compatibility
    check = require_login
    """
    .. deprecated:: 1.0
       Use :func:`require_login` instead.
    """

    def require_keycloak_role(self, client, role):
        """
        Function to check for a KeyCloak client role in JWT access token.

        This is intended to be replaced with a more generic 'require this value
        in token or claims' system, at which point backwards compatibility will
        be added.

        .. versionadded:: 1.5.0
        """
        def wrapper(view_func):
            @wraps(view_func)
            def decorated(*args, **kwargs):
                pre, tkn, post = self.get_access_token().split('.')
                access_token = json.loads(b64decode(tkn))
                if role in access_token['resource_access'][client]['roles']:
                    return view_func(*args, **kwargs)
                else:
                    return abort(403)
            return decorated
        return wrapper

    def flow_for_request(self):
        """
        .. deprecated:: 1.0
           Use :func:`require_login` instead.
        """
        warn('You are using a deprecated function (flow_for_request). '
             'Please reconsider using this', DeprecationWarning)
        return self._flow_for_request()

    def _flow_for_request(self):
        """
        Build a flow with the correct absolute callback URL for this request.
        :return:
        """
        flow = copy(self.flow)
        redirect_uri = current_app.config['OVERWRITE_REDIRECT_URI']
        if not redirect_uri:
            flow.redirect_uri = url_for('_oidc_callback', _external=True)
        else:
            flow.redirect_uri = redirect_uri
        return flow

    def redirect_to_auth_server(self, destination=None, customstate=None):
        """
        Set a CSRF token in the session, and redirect to the IdP.

        :param destination: The page that the user was going to,
            before we noticed they weren't logged in.
        :type destination: Url to return the client to if a custom handler is
            not used. Not available with custom callback.
        :param customstate: The custom data passed via the ODIC state.
            Note that this only works with a custom_callback, and this will
            ignore destination.
        :type customstate: Anything that can be serialized
        :returns: A redirect response to start the login process.
        :rtype: Flask Response

        .. deprecated:: 1.0
           Use :func:`require_login` instead.
        """
        if not self._custom_callback and customstate:
            raise ValueError('Custom State is only avilable with a custom '
                             'handler')
        if 'oidc_csrf_token' not in session:
            csrf_token = urlsafe_b64encode(os.urandom(24)).decode('utf-8')
            session['oidc_csrf_token'] = csrf_token
        state = {
            'csrf_token': session['oidc_csrf_token'],
        }
        statefield = 'destination'
        statevalue = destination
        if customstate is not None:
            statefield = 'custom'
            statevalue = customstate
        state[statefield] = jwt.encode({'statevalue': statevalue}, self.extra_data_key, algorithm="HS512")

        extra_params = {
            'state': urlsafe_b64encode(json.dumps(state).encode('utf-8')),
        }
        extra_params.update(current_app.config['OIDC_EXTRA_REQUEST_AUTH_PARAMS'])
        if current_app.config['OIDC_GOOGLE_APPS_DOMAIN']:
            extra_params['hd'] = current_app.config['OIDC_GOOGLE_APPS_DOMAIN']
        if current_app.config['OIDC_OPENID_REALM']:
            extra_params['openid.realm'] = current_app.config[
                'OIDC_OPENID_REALM']

        flow = self._flow_for_request()
        auth_url = '{url}&{extra_params}'.format(
            url=flow.step1_get_authorize_url(),
            extra_params=urlencode(extra_params))
        # if the user has an ID token, it's invalid, or we wouldn't be here
        self._set_cookie_id_token(None)
        return redirect(auth_url)

    def _is_id_token_valid(self, id_token):
        """
        Check if `id_token` is a current ID token for this application,
        was issued by the Apps domain we expected,
        and that the email address has been verified.

        @see: http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
        """
        if not id_token:
            return False

        # step 2: check issuer
        if id_token['iss'] not in current_app.config['OIDC_VALID_ISSUERS']:
            logger.error('id_token issued by non-trusted issuer: %s'
                         % id_token['iss'])
            return False

        if isinstance(id_token['aud'], list):
            # step 3 for audience list
            if self.flow.client_id not in id_token['aud']:
                logger.error('We are not a valid audience')
                return False
            # step 4
            if 'azp' not in id_token and len(id_token['aud']) > 1:
                logger.error('Multiple audiences and not authorized party')
                return False
        else:
            # step 3 for single audience
            if id_token['aud'] != self.flow.client_id:
                logger.error('We are not the audience')
                return False

        # step 5
        if 'azp' in id_token and id_token['azp'] != self.flow.client_id:
            logger.error('Authorized Party is not us')
            return False

        # step 6-8: TLS checked

        # step 9: check exp
        if int(time.time()) >= int(id_token['exp']):
            logger.error('Token has expired')
            return False

        # step 10: check iat
        if id_token['iat'] < (time.time() -
                              current_app.config['OIDC_CLOCK_SKEW']):
            logger.error('Token issued in the past')
            return False

        # (not required if using HTTPS?) step 11: check nonce

        # step 12-13: not requested acr or auth_time, so not needed to test

        # additional steps specific to our usage
        if current_app.config['OIDC_GOOGLE_APPS_DOMAIN'] and \
                id_token.get('hd') != current_app.config[
                    'OIDC_GOOGLE_APPS_DOMAIN']:
            logger.error('Invalid google apps domain')
            return False

        if not id_token.get('email_verified', False) and \
                current_app.config['OIDC_REQUIRE_VERIFIED_EMAIL']:
            logger.error('Email not verified')
            return False

        return True

    WRONG_GOOGLE_APPS_DOMAIN = 'WRONG_GOOGLE_APPS_DOMAIN'

    def custom_callback(self, view_func):
        """
        Wrapper function to use a custom callback.
        The custom OIDC callback will get the custom state field passed in with
        redirect_to_auth_server.
        """
        @wraps(view_func)
        def decorated(*args, **kwargs):
            plainreturn, data = self._process_callback('custom')
            if plainreturn:
                return data
            else:
                return view_func(data, *args, **kwargs)
        self._custom_callback = decorated
        return decorated

    def _oidc_callback(self):
        plainreturn, data = self._process_callback('destination')

        if plainreturn:
            return data
        else:
            return redirect(data)

    def _process_callback(self, statefield):
        """
        Exchange the auth code for actual credentials,
        then redirect to the originally requested page.
        """
        # retrieve session and callback variables
        try:
            session_csrf_token = session.get('oidc_csrf_token')

            state = _json_loads(urlsafe_b64decode(request.args['state'].encode('utf-8')))
            csrf_token = state['csrf_token']

            code = request.args['code']
        except (KeyError, ValueError):
            logger.debug("Can't retrieve CSRF token, state, or code",
                         exc_info=True)
            return True, self._oidc_error()

        # check callback CSRF token passed to IdP
        # against session CSRF token held by user
        if csrf_token != session_csrf_token:
            logger.debug("CSRF token mismatch")
            return True, self._oidc_error()

        # make a request to IdP to exchange the auth code for OAuth credentials
        flow = self._flow_for_request()
        credentials = flow.step2_exchange(code)
        id_token = credentials.id_token
        if not self._is_id_token_valid(id_token):
            logger.debug("Invalid ID token")
            if id_token.get('hd') != current_app.config[
                    'OIDC_GOOGLE_APPS_DOMAIN']:
                return True, self._oidc_error(
                    "You must log in with an account from the {0} domain."
                    .format(current_app.config['OIDC_GOOGLE_APPS_DOMAIN']),
                    self.WRONG_GOOGLE_APPS_DOMAIN)
            return True, self._oidc_error()

        # store credentials by subject
        # when Google is the IdP, the subject is their G+ account number
        self.credentials_store[id_token['sub']] = credentials.to_json()

        try:
            response = jwt.decode(state[statefield], self.extra_data_key, algorithms=["HS512"])
            response = response['statevalue']
        except:
            logger.error('State field was invalid')
            return True, self._oidc_error()

        # set a persistent signed cookie containing the ID token
        # and redirect to the final destination
        self._set_cookie_id_token(id_token)
        return False, response

    def _oidc_error(self, message='Not Authorized', code=None):
        return (message, 401, {
            'Content-Type': 'text/plain',
        })

    def logout(self):
        """
        Request the browser to please forget the cookie we set, to clear the
        current session.

        Note that as described in [1], this will not log out in the case of a
        browser that doesn't clear cookies when requested to, and the user
        could be automatically logged in when they hit any authenticated
        endpoint.

        [1]: https://github.com/puiterwijk/flask-oidc/issues/5#issuecomment-86187023

        .. versionadded:: 1.0
        """
        # TODO: Add single logout
        self._set_cookie_id_token(None)

    # Below here is for resource servers to validate tokens
    def validate_token(self, token, scopes_required=None):
        """
        This function can be used to validate tokens.

        Note that this only works if a token introspection url is configured,
        as that URL will be queried for the validity and scopes of a token.

        :param scopes_required: List of scopes that are required to be
            granted by the token before returning True.
        :type scopes_required: list

        :returns: True if the token was valid and contained the required
            scopes. An ErrStr (subclass of string for which bool() is False) if
            an error occured.
        :rtype: Boolean or String

        .. versionadded:: 1.1
        """
        valid = self._validate_token(token, scopes_required)
        if valid is True:
            return True
        else:
            return ErrStr(valid)

    def _validate_token(self, token, scopes_required=None):
        """The actual implementation of validate_token."""
        if scopes_required is None:
            scopes_required = []
        scopes_required = set(scopes_required)

        token_info = None
        valid_token = False
        has_required_scopes = False
        if token:
            try:
                token_info = self._get_token_info(token)
            except Exception as ex:
                token_info = {'active': False}
                logger.error('ERROR: Unable to get token info')
                logger.error(str(ex))

            valid_token = token_info.get('active', False)

            if 'aud' in token_info and \
                    current_app.config['OIDC_RESOURCE_CHECK_AUD']:
                valid_audience = False
                aud = token_info['aud']
                clid = self.client_secrets['client_id']
                if isinstance(aud, list):
                    valid_audience = clid in aud
                else:
                    valid_audience = clid == aud

                if not valid_audience:
                    logger.error('Refused token because of invalid '
                                 'audience')
                    valid_token = False

            if valid_token:
                token_scopes = token_info.get('scope', '').split(' ')
            else:
                token_scopes = []
            has_required_scopes = scopes_required.issubset(
                set(token_scopes))

            if not has_required_scopes:
                logger.debug('Token missed required scopes')

        if (valid_token and has_required_scopes):
            g.oidc_token_info = token_info
            return True

        if not valid_token:
            return 'Token required but invalid'
        elif not has_required_scopes:
            return 'Token does not have required scopes'
        else:
            return 'Something went wrong checking your token'

    def accept_token(self, require_token=False, scopes_required=None,
                           render_errors=True):
        """
        Use this to decorate view functions that should accept OAuth2 tokens,
        this will most likely apply to API functions.

        Tokens are accepted as part of the query URL (access_token value) or
        a POST form value (access_token).

        Note that this only works if a token introspection url is configured,
        as that URL will be queried for the validity and scopes of a token.

        :param require_token: Whether a token is required for the current
            function. If this is True, we will abort the request if there
            was no token provided.
        :type require_token: bool
        :param scopes_required: List of scopes that are required to be
            granted by the token before being allowed to call the protected
            function.
        :type scopes_required: list
        :param render_errors: Whether or not to eagerly render error objects
            as JSON API responses. Set to False to pass the error object back
            unmodified for later rendering.
        :type render_errors: callback(obj) or None

        .. versionadded:: 1.0
        """

        def wrapper(view_func):
            @wraps(view_func)
            def decorated(*args, **kwargs):
                token = None
                if 'Authorization' in request.headers and request.headers['Authorization'].startswith('Bearer '):
                    token = request.headers['Authorization'].split(None,1)[1].strip()
                if 'access_token' in request.form:
                    token = request.form['access_token']
                elif 'access_token' in request.args:
                    token = request.args['access_token']

                validity = self.validate_token(token, scopes_required)
                if (validity is True) or (not require_token):
                    return view_func(*args, **kwargs)
                else:
                    response_body = {'error': 'invalid_token',
                                     'error_description': validity}
                    if render_errors:
                        response_body = json.dumps(response_body)
                    return response_body, 401, {'WWW-Authenticate': 'Bearer'}

            return decorated
        return wrapper

    def _get_token_info(self, token):
        # We hardcode to use client_secret_post, because that's what the Google
        # oauth2client library defaults to
        request = {'token': token}
        headers = {'Content-type': 'application/x-www-form-urlencoded'}

        hint = current_app.config['OIDC_TOKEN_TYPE_HINT']
        if hint != 'none':
            request['token_type_hint'] = hint

        auth_method = current_app.config['OIDC_INTROSPECTION_AUTH_METHOD'] 
        if (auth_method == 'client_secret_basic'):
            basic_auth_string = '%s:%s' % (self.client_secrets['client_id'], self.client_secrets['client_secret'])
            basic_auth_bytes = bytearray(basic_auth_string, 'utf-8')
            headers['Authorization'] = 'Basic %s' % b64encode(basic_auth_bytes).decode('utf-8')
        elif (auth_method == 'bearer'):
            headers['Authorization'] = 'Bearer %s' % token
        elif (auth_method == 'client_secret_post'):
            request['client_id'] = self.client_secrets['client_id']
            if self.client_secrets['client_secret'] is not None:
                request['client_secret'] = self.client_secrets['client_secret']

        _, content = httplib2.Http().request(
            self.client_secrets['token_introspection_uri'], 'POST',
            urlencode(request), headers=headers)
        # TODO: Cache this reply
        return _json_loads(content)

class MyOpenIDConnect(OpenIDConnect):

    def __init__(self, app=None, credentials_store=None, http=None, time=None,
                 urandom=None, provider=None):

        super().__init__(credentials_store, http, time, urandom)

        self.client_secrets = None

        if app:
            self.init_app(app)

        if provider:
            self.init_provider(provider)

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
        app.config.setdefault('OIDC_CLOCK_SKEW', 6000)  # 1 minute
        app.config.setdefault('OIDC_REQUIRE_VERIFIED_EMAIL', False)
        app.config.setdefault('OIDC_OPENID_REALM', None)
        app.config.setdefault('OIDC_USER_INFO_ENABLED', True)
        app.config.setdefault('OIDC_CALLBACK_ROUTE', CALLBACK)
        app.config.setdefault('OVERWRITE_REDIRECT_URI', REDIRECT_URL)
        app.config.setdefault("OIDC_EXTRA_REQUEST_AUTH_PARAMS", {})
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
        
        self.extra_data_salt = 'flask-oidc-extra-data'
        self.cookie_salt = 'flask-oidc-cookie'
        self.extra_data_key = app.config['SECRET_KEY'] + self.extra_data_salt
        self.cookie_key = app.config['SECRET_KEY'] + self.cookie_salt
       
        try:
            self.credentials_store = app.config['OIDC_CREDENTIALS_STORE']
        except KeyError:
            pass

    def refresh(self):

        id_token = self._get_cookie_id_token()

        try:
            credentials = OAuth2Credentials.from_json(
                self.credentials_store[id_token['sub']])
        except KeyError:
            logger.debug("Expired ID token, credentials missing",
                            exc_info=True)

        # refresh and store credentials
        try:
            credentials.refresh(httplib2.Http())
            if credentials.id_token:
                id_token = credentials.id_token
                self.credentials_store[id_token['sub']] = credentials.to_json()
                self._set_cookie_id_token(id_token)
        except AccessTokenRefreshError:
            logger.debug("Failed to refresh !")

    def _before_request(self):
        g.oidc_id_token = None

        if self.client_secrets:
            self.authenticate_or_redirect()

    def redirect_to_auth_server(self, destination=None, customstate=None):
        """
        Set a CSRF token in the session, and redirect to the IdP.

        :param destination: The page that the user was going to,
            before we noticed they weren't logged in.
        :type destination: Url to return the client to if a custom handler is
            not used. Not available with custom callback.
        :param customstate: The custom data passed via the ODIC state.
            Note that this only works with a custom_callback, and this will
            ignore destination.
        :type customstate: Anything that can be serialized
        :returns: A redirect response to start the login process.
        :rtype: Flask Response

        .. deprecated:: 1.0
           Use :func:`require_login` instead.
        """
        if not self._custom_callback and customstate:
            raise ValueError('Custom State is only avilable with a custom '
                             'handler')
        if 'oidc_csrf_token' not in session:
            csrf_token = urlsafe_b64encode(os.urandom(24)).decode('utf-8')
            session['oidc_csrf_token'] = csrf_token
        state = {
            'csrf_token': session['oidc_csrf_token'],
        }
        statefield = 'destination'
        statevalue = destination
        if customstate is not None:
            statefield = 'custom'
            statevalue = customstate
        state[statefield] = jwt.encode({'statevalue': statevalue}, self.extra_data_key, algorithm="HS512")

        extra_params = {
            'state': urlsafe_b64encode(json.dumps(state).encode('utf-8')),
        }
        extra_params.update(current_app.config['OIDC_EXTRA_REQUEST_AUTH_PARAMS'])
        if current_app.config['OIDC_GOOGLE_APPS_DOMAIN']:
            extra_params['hd'] = current_app.config['OIDC_GOOGLE_APPS_DOMAIN']
        if current_app.config['OIDC_OPENID_REALM']:
            extra_params['openid.realm'] = current_app.config[
                'OIDC_OPENID_REALM']

        flow = self._flow_for_request()
        auth_url = '{url}&{extra_params}'.format(
            url=flow.step1_get_authorize_url(),
            extra_params=urlencode(extra_params))
        # if the user has an ID token, it's invalid, or we wouldn't be here
        self._set_cookie_id_token(None)
        return redirect(auth_url)

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

        if current_app.config['OIDC_INTROSPECTION_AUTH_METHOD'] == 'client_secret_basic':
            basic_auth_string = '%s:%s' % (self.client_secrets['client_id'], self.client_secrets['client_secret'])
            basic_auth_bytes = bytearray(basic_auth_string, 'utf-8')
            self.flow.authorization_header = 'Basic %s' % b64encode(basic_auth_bytes).decode('utf-8')

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
            context = ssl._create_unverified_context()
            response = urllib.request.urlopen(url, context=context)
            
            provider_info = json.load(response)

        except Exception as e:
            raise Exception("Can not obtain well known information: {}".format(str(e)))

        for path in ['issuer', 'registration_endpoint', 'authorization_endpoint', 'token_endpoint', 'userinfo_endpoint']:
            if path in provider_info and provider_info[path].startswith('/'):
                provider_info[path] = "{}{}".format(provider.get('base_url'), provider_info[path])

        for method in provider_info.get('token_endpoint_auth_methods_supported',[]):
            current_app.config['OIDC_INTROSPECTION_AUTH_METHOD'] = method
            break # Just take first...

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

            current_app.config['OIDC_SCOPES'] = provider.get('scopes', provider_info.get('scopes_supported', REQUESTED_SCOPES))
            
            if 'offline_access' in current_app.config['OIDC_SCOPES']:
                current_app.config['OIDC_EXTRA_REQUEST_AUTH_PARAMS'].update({'prompt' : 'consent'})

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

subscriptions = {}

class ServerSentEvent(object):

    def __init__(self, data):
        self.data = data
        self.event = None
        self.id = None
        self.desc_map = {
            self.data : "data",
            self.event : "event",
            self.id : "id"
        }

    def encode(self):
        if not self.data:
            return ""

        lines = ["%s: %s" % (v, k) 
                 for k, v in self.desc_map.items() if k]
        
        return "%s\n\n" % "\n".join(lines)

@app.route('/subscribe/<sub>')
def subscribe(sub):
    logger.debug("Subscribing: {}".format(sub))

    if sub not in subscriptions:
        subscriptions[sub] = []

    def gen():
        logger.debug("Making Generator...")

        q = Queue()
        subscriptions[sub].append(q)
        try:
            while True:
                result = q.get(block=True)
                logger.debug("Queue Get: {}".format(result))

                ev = ServerSentEvent(str(result))
                
                logger.debug("Yielding: {}".format(ev.encode()))

                yield ev.encode()
        except GeneratorExit:
            logger.debug("Removing Generator...")
            subscriptions[sub].remove(q)

    return Response(gen(), mimetype="text/event-stream")

def publish(sub, msg):
    def notify():
        try:
            for sid in subscriptions[sub][:]:
                logger.debug("Publishing sub: {} msg: {}, sid: {}".format(sub, msg, sid))
                sid.put(msg)
        except Exception as e:
            logger.debug("Exception during notify: {}".format(str(e)))

    logger.debug("Publishing to sub: {} msg: {}".format(sub, msg))
    if sub in subscriptions:
        gevent.spawn(notify)

@app.route('/refresh')
@oidc.require_login
def refresh():
    try:
        oidc.refresh()
    except Exception as e:
        logger.debug("Error during refresh: {}".format(str(e)))
    
    return hello_me()

@app.route('/private')
@oidc.require_login
def hello_me():

    try:
        sub = oidc.details()["sub"]

        script = """
    <script>
        var eventSource = new EventSource("/subscribe/%s");

        eventSource.onmessage = function(e) {
            console.log(e.data);
            window.location.href = "/logout";
        };
    </script>
""" % sub

    except Exception as e:
        logger.debug("Error during script prepare: {}".format(str(e)))
        script = ""

    refresh = ''
    
    try:
        token = '<h1>Token Details:</h1><br/><table border="1">'
        token += '<tr><th>Attribute</th><th>Value</th></tr>'

        t = json.loads(oidc.token())['token_response']
        logger.debug("TOKEN: {}".format(t))

        for k,v in t.items():
            token += '<tr><td>{}</td><td><pre>{}</pre></td></tr>'.format(k, v)

            if k == 'refresh_token':
                refresh = '<br/><a href="/refresh">Refresh !</a><br/>'

            try:
                v = jwt.decode(v, options={"verify_signature": False})
                v = json.dumps(v, indent=4, sort_keys=True)
                token += '<tr><td>{} (decoded)</td><td><pre>{}</pre></td></tr>'.format(k, v)
            except:
                pass

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

    return ('{}<br/>{}<br/>{}<br/>{}<a href="/">Return</a>'.format(script, token, data, refresh))

@app.route('/test_logout/<sub>', methods=['GET'])
def test_logout(sub):
    publish(sub, "Logout")
    return "OK"

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    global oidc

    if request.method == 'POST':
        # Evaluate BackChannel logout
        # Refer: https://openid.net/specs/openid-connect-backchannel-1_0.html
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

        logger.debug("Data received: {}".format(request.get_data().decode('utf-8')))

        payload = {}

        try:
            logout_token = request.form.get('logout_token', None)

            if not logout_token:
                raise Exception("No logout_token")
    
            payload = jwt.decode(logout_token, verify=False)

            logger.debug("Logout Token payload: {}".format(json.dumps(payload, indent=4, sort_keys=True)))
            
            if "sub" not in payload and "sid" not in payload:
                raise Exception("Missing sub and/or sid claims")

            if "events" not in payload:
                raise Exception("Missing events claim")

            if "http://schemas.openid.net/event/backchannel-logout" not in payload["events"]:
                raise Exception("Events claim missing required member")

            if "nonce" in payload:
                raise Exception("Logout token should not contain nonce claim")

        except Exception as e:
            logger.debug("Logout Error: {}".format(str(e)))

            r = make_response(str(e), 400)
            r.headers['Cache-Control'] = 'no-cache, no-store'
            r.headers['Pragma'] = 'no-cache'
            return r

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
        if payload and "sub" in payload:
            publish(payload["sub"], "Logout")

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

    server = WSGIServer(("", 8000), app)
    server.serve_forever()
