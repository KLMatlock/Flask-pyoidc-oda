#   Copyright 2021 Kevin Matlock
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0

#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.


import functools
import json
import logging
from urllib.parse import parse_qsl, urlparse

import flask
import importlib_resources
from flask import abort, current_app
from flask.helpers import url_for
from oic import rndstr
from oic.oic.message import EndSessionRequest
from werkzeug.utils import redirect
import jwt

from .auth_response_handler import (AuthResponseErrorResponseError,
                                    AuthResponseHandler,
                                    AuthResponseProcessError)
from .provider_configuration import ClientMetadata, ProviderConfiguration
from .pyoidc_facade import PyoidcFacade
from .user_session import UninitialisedSession, UserSession
from .rbac_checker import RBACChecker

logger = logging.getLogger(__name__)

def authenticate_token(client : PyoidcFacade, token : str):
    userinfo = client.userinfo_request(token)
    authd = True
    if "error" in userinfo:
        authd = False
    return (authd, userinfo)


class NoAuthenticationError(Exception):
    pass


class OIDCAuthentication:
    """
    OIDCAuthentication object for Flask extension.
    """

    def __init__(self, provider_configurations=None, app=None):
        """
        Args:
            provider_configurations (Mapping[str, ProviderConfiguration]):
                provider configurations by name
            app (flask.app.Flask): optional Flask app
        """
        self._provider_configurations = provider_configurations
        if self._provider_configurations is not None:
            # Gets first provider configuration as default.
            self.default_provider = next(iter(self._provider_configurations))
        else:
            self.default_provider = None

        self.clients = None
        self._logout_view = None
        self._error_view = None
        self._redirect_uri_endpoint = None
        self.skew = None

        if app:
            self.init_app(app)

    def init_app(self, app):
        oidc_providers = app.config.get("OIDC_PROVIDERS", None)
        self.unauthenticated = app.config.get("UNAUTHENTICATED", False)
        self.skew = app.config.get("OIDC_SKEW", None)
        required_roles = app.config.get("OIDC_REQUIRED_ROLES", [])
        if required_roles:
            if not (type(required_roles) is list):
                required_roles = [required_roles]
        role_claim = app.config.get("OIDC_ROLE_CLAIM", None)
        source = app.config.get("OIDC_ROLE_SOURCE", "auth")
        self.rbac_checker = RBACChecker(required_roles, role_claim, source)

        if oidc_providers is not None:
            if self._provider_configurations is None:
                self._provider_configurations = {}

            if isinstance(oidc_providers, str):
                oidc_providers = [oidc_providers]

            for provider in oidc_providers:
                if str(provider).lower() == "unauthenticated":
                    self.unauthenticated = True
                    continue

                provider_config = dict_to_providers_config(provider, app.config)
                self._provider_configurations[provider] = provider_config

            if self._provider_configurations == {}:
                self._provider_configurations = None

        if self._provider_configurations is not None:
            # Gets first provider configuration as default.
            self.default_provider = next(iter(self._provider_configurations))
        elif self.unauthenticated:
            logger.warning("Running server in unauthenticated mode.")
            self.default_provider = None
        else:
            raise NoAuthenticationError("No providers passed and UNAUTHENTICATED set to False.")

        if self._provider_configurations is not None:
            self._redirect_uri_endpoint = app.config.get(
                "OIDC_REDIRECT_ENDPOINT", "redirect_uri"
            ).lstrip("/")
            # Change from relative to absolute url depending on input.
            parse_result = urlparse(self._redirect_uri_endpoint)
            route = parse_result.path.lstrip("/")
            self.route = route
            logging.info("Authentication routing to: " + route)

            # setup redirect_uri as a flask route
            app.add_url_rule(
                "/" + route, route, self._handle_authentication_response, methods=["GET", "POST"],
            )

            # dynamically add the Flask redirect uri to the client info
            with app.app_context():
                redirect_uri = self._redirect_uri_endpoint
                logging.info("Redirect URI set to :" + redirect_uri)

                self.clients = {
                    name: PyoidcFacade(configuration, redirect_uri)
                    for (name, configuration) in self._provider_configurations.items()
                }

    def _get_post_logout_redirect_uri(self, client):
        if client.post_logout_redirect_uris:
            return client.post_logout_redirect_uris[0]
        return self._get_url_for_logout_view()

    def _get_url_for_logout_view(self):
        return url_for(self._logout_view.__name__, _external=True) if self._logout_view else None

    def _register_client(self, client):
        def default_post_logout_redirect_uris():
            url_for_logout_view = self._get_url_for_logout_view()
            if url_for_logout_view:
                return [url_for_logout_view]
            return []

        client_registration_args = {}
        post_logout_redirect_uris = client._provider_configuration._client_registration_info.get(
            "post_logout_redirect_uris", default_post_logout_redirect_uris()
        )
        if post_logout_redirect_uris:
            logger.debug(
                "registering with post_logout_redirect_uris=%s", post_logout_redirect_uris,
            )
            client_registration_args["post_logout_redirect_uris"] = post_logout_redirect_uris
        client.register(client_registration_args)

    def _authenticate(self, client, interactive=True):
        if not client.is_registered():
            self._register_client(client)

        flask.session["destination"] = flask.request.url
        flask.session["state"] = rndstr()
        flask.session["nonce"] = rndstr()

        # Use silent authentication for session refresh
        # This will not show login prompt to the user
        extra_auth_params = {}
        if not interactive:
            extra_auth_params["prompt"] = "none"

        redirect_uri = url_for(self.route, _external=True)

        login_url = client.authentication_request(
            flask.session["state"], flask.session["nonce"], redirect_uri, extra_auth_params,
        )

        auth_params = dict(parse_qsl(login_url.split("?")[1]))
        flask.session[
            "fragment_encoded_response"
        ] = AuthResponseHandler.expect_fragment_encoded_response(auth_params)
        return redirect(login_url)

    def _handle_authentication_response(self):
        has_error = flask.request.args.get("error", False, lambda x: bool(int(x)))
        if has_error:
            if "error" in flask.session:
                return self._show_error_response(flask.session.pop("error"))
            return "Something went wrong."

        if flask.session.pop("fragment_encoded_response", False):
            return importlib_resources.read_binary("flask_pyoidc", "parse_fragment.html").decode(
                "utf-8"
            )

        is_processing_fragment_encoded_response = flask.request.method == "POST"

        if is_processing_fragment_encoded_response:
            auth_resp = flask.request.form
        else:
            auth_resp = flask.request.args

        client = self.clients[UserSession(flask.session).current_provider]

        authn_resp = client.parse_authentication_response(auth_resp, skew = self.skew)
        logger.debug("received authentication response: %s", authn_resp.to_json())

        try:
            auth_handler = AuthResponseHandler(client)
            result = auth_handler.process_auth_response(
                authn_resp, flask.session.pop("state"), flask.session.pop("nonce"), skew = self.skew
            )
        except AuthResponseErrorResponseError as e:
            return self._handle_error_response(
                e.error_response, is_processing_fragment_encoded_response
            )
        except AuthResponseProcessError as e:
            return self._handle_error_response(
                {"error": "unexpected_error", "error_description": str(e)},
                is_processing_fragment_encoded_response,
            )

        if current_app.config.get("OIDC_SESSION_PERMANENT", True):
            flask.session.permanent = True

        UserSession(flask.session).update(
            result.access_token,
            result.id_token_claims,
            result.id_token_jwt,
            result.userinfo_claims,
        )

        destination = flask.session.pop("destination")
        if is_processing_fragment_encoded_response:
            # if the POST request was from the JS page handling fragment encoded responses we need to return
            # the destination URL as the response body
            return destination

        return redirect(destination)

    def _handle_error_response(self, error_response, should_redirect=False):
        if should_redirect:
            # if the current request was from the JS page handling fragment encoded responses we need to return
            # a URL for the error page to redirect to
            flask.session["error"] = error_response
            return "/" + self._redirect_uri_endpoint + "?error=1"
        return self._show_error_response(error_response)

    def _show_error_response(self, error_response):
        logger.error(json.dumps(error_response))
        if self._error_view:
            error = {
                k: error_response[k] for k in ["error", "error_description"] if k in error_response
            }
            return self._error_view(**error)

        return "Something went wrong with the authentication, please try to login again."

    def oidc_auth(self, provider_name: str = None, bearer=False, bearer_only = False):
        """Authentication decorater. 
        
        Wraps a given Flask endpoint with OIDC authentication for the given provider.
        
        Args:
            provider_name str:
                Name of the provider. If None, goes to default authentication.
            bearer bool:
                Whether access using a bearer token is allowed. Default is False.

        Raises:
            ValueError: 
                If invalid provider name is provided.
        """

        def oidc_decorator(view_func):
            PROVIDER_DECORATOR = provider_name
            BEARER = bearer
            BEARER_REQ = bearer_only

            @functools.wraps(view_func)
            def wrapper(*args, **kwargs):
                PROVIDER_NAME = PROVIDER_DECORATOR
                BEARER_ALLOWED = BEARER
                BEARER_REQUIRED = BEARER_REQ

                if PROVIDER_NAME is None:
                    PROVIDER_NAME = self.default_provider
                elif PROVIDER_NAME not in self._provider_configurations:
                    raise ValueError(
                        "Provider name '{}' not in configured providers: {}.".format(
                            provider_name, self._provider_configurations.keys()
                        )
                    )

                if PROVIDER_NAME is None:
                    return view_func(*args, **kwargs)

                session = UserSession(flask.session, PROVIDER_NAME)
                client = self.clients[session.current_provider]
                bearer_auth = BEARER_ALLOWED or BEARER_REQUIRED

                token = None
                valid_header = "Authorization" in flask.request.headers.keys()
                if valid_header:
                    auth_msg = str(flask.request.headers["Authorization"])

                    if auth_msg.startswith("Bearer "):
                        token = auth_msg[7:]

                if bearer_auth and (token is not None):
                    logger.debug("accessing through bearer token")
                    (auth, userinfo) = authenticate_token(client, token)
                    if auth == False:
                        return flask.Response(
                            "Invalid Bearer Token",
                            401,
                            {"WWW-Authenticate": 'Basic realm="Login Required"'},
                        )

                    session.update(access_token=token, userinfo=userinfo.to_dict())
                    flask.g.bearer = True
                    flask.g.access_token = token
                    flask.g.userinfo = userinfo
                    # Acess token is verified by calling the "userinfo" endpoint so no need to verify JWT.
                    access_token_claimset = {}
                    if session.access_token:
                        access_token_claimset = jwt.decode(token, options={"verify_signature": False})

                    valid_rbac = self.rbac_checker.check_rbac(access_token_claimset, id_token = {}, userinfo_token = userinfo)
                    if not valid_rbac:
                        abort(401)
                    return view_func(*args, **kwargs)

                if BEARER_REQUIRED:
                    abort(401)


                if session.is_authenticated():
                    flask.g.bearer = False
                    logger.debug("user is authenticated")

                    # Acess token is verified by calling the "userinfo" endpoint so no need to verify JWT.
                    access_token_claimset = {}
                    if session.access_token:
                        access_token_claimset = jwt.decode(session.access_token, options={"verify_signature": False})

                    valid_rbac = self.rbac_checker.check_rbac(access_token_claimset, session.id_token, session.userinfo)
                    if not valid_rbac:
                        abort(401)
                    return view_func(*args, **kwargs)
                else:
                    logger.debug("user not authenticated, start flow")
                    return self._authenticate(client)

            return wrapper

        return oidc_decorator

    def _logout(self):
        logger.debug("user logout")
        try:
            session = UserSession(flask.session)
        except UninitialisedSession as e:
            logger.info("user was already logged out, doing nothing")
            return None

        id_token_jwt = session.id_token_jwt
        client = self.clients[session.current_provider]
        session.clear()

        if client.provider_end_session_endpoint:
            flask.session["end_session_state"] = rndstr()

            end_session_request = EndSessionRequest(
                id_token_hint=id_token_jwt,
                post_logout_redirect_uri=self._get_post_logout_redirect_uri(client),
                state=flask.session["end_session_state"],
            )

            logger.debug("send endsession request: %s", end_session_request.to_json())

            return redirect(end_session_request.request(client.provider_end_session_endpoint), 303)
        return None

    def oidc_logout(self, view_func):
        self._logout_view = view_func

        @functools.wraps(view_func)
        def wrapper(*args, **kwargs):
            if "state" in flask.request.args:
                # returning redirect from provider
                if flask.request.args["state"] != flask.session.pop("end_session_state"):
                    logger.error(
                        "Got unexpected state '%s' after logout redirect.",
                        flask.request.args["state"],
                    )
                return view_func(*args, **kwargs)

            redirect_to_provider = self._logout()
            if redirect_to_provider:
                return redirect_to_provider

            return view_func(*args, **kwargs)

        return wrapper

    def error_view(self, view_func):
        self._error_view = view_func
        return view_func


def dict_to_providers_config(provider_name: str, config_dict: dict) -> ProviderConfiguration:
    """Configures a provider from a simple Python Dictionary.
    
    Args:
        provider_name (str): Name of the provider. Must match the items in the config_dict.
        config_dict (dict): Dictionary to retrieve configurations from.
    
    Returns:
        ProviderConfiguration: Configured provider
        [description]
    """
    client_name = config_dict.get(provider_name + "_ISSUER")

    client_id = config_dict.get(provider_name + "_CLIENT", None)
    client_secret = config_dict.get(provider_name + "_SECRET", None)
    client_metadata = ClientMetadata(client_id=client_id, client_secret=client_secret)

    return ProviderConfiguration(issuer=client_name, client_metadata=client_metadata)

