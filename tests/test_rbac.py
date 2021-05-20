import json
import logging

import flask
import pytest
import responses
import time
from datetime import datetime
from flask import Flask
from http.cookies import SimpleCookie
from jwkest import jws
import jwt
from oic.oic import AuthorizationResponse
from oic.oic.message import IdToken
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qsl, urlparse, urlencode

from flask_pyoidc import OIDCAuthentication, NoAuthenticationError
from werkzeug.exceptions import Unauthorized
from flask_pyoidc.provider_configuration import (
    ProviderConfiguration,
    ProviderMetadata,
    ClientMetadata,
    ClientRegistrationInfo,
)
from flask_pyoidc.user_session import UserSession
from .util import signed_id_token


class TestOIDCAuthentication(object):
    PROVIDER_BASEURL = "https://op.example.com"
    PROVIDER_NAME = "test_provider"
    CLIENT_ID = "client1"
    CLIENT_DOMAIN = "client.example.com"
    CALLBACK_RETURN_VALUE = "callback called successfully"

    @pytest.fixture(autouse=True)
    def create_flask_app(self):
        self.app = Flask(__name__)
        self.app.config.update({"SERVER_NAME": self.CLIENT_DOMAIN, "SECRET_KEY": "test_key"})

    def init_app(self, provider_metadata_extras=None, client_metadata_extras=None, **kwargs):
        required_provider_metadata = {
            "issuer": self.PROVIDER_BASEURL,
            "authorization_endpoint": self.PROVIDER_BASEURL + "/auth",
            "jwks_uri": self.PROVIDER_BASEURL + "/jwks",
        }
        if provider_metadata_extras:
            required_provider_metadata.update(provider_metadata_extras)
        provider_metadata = ProviderMetadata(**required_provider_metadata)

        required_client_metadata = {"client_id": self.CLIENT_ID, "client_secret": "secret1"}
        if client_metadata_extras:
            required_client_metadata.update(client_metadata_extras)
        client_metadata = ClientMetadata(**required_client_metadata)

        provider_configurations = {
            self.PROVIDER_NAME: ProviderConfiguration(
                provider_metadata=provider_metadata, client_metadata=client_metadata, **kwargs
            )
        }
        authn = OIDCAuthentication(provider_configurations)
        authn.init_app(self.app)
        return authn

    def get_view_mock(self):
        mock = MagicMock()
        mock.__name__ = "test_callback"
        mock.return_value = self.CALLBACK_RETURN_VALUE
        return mock

    def get_auth_endpoint(self, authn, bearer=False):
        @authn.oidc_auth(bearer=bearer)
        def auth_end():
            return True

        return auth_end

    def assert_auth_redirect(self, auth_redirect):
        assert auth_redirect.status_code == 302
        assert auth_redirect.location.startswith(self.PROVIDER_BASEURL)

    def assert_view_mock(self, callback_mock, result):
        assert callback_mock.called
        assert result == self.CALLBACK_RETURN_VALUE

    @patch("time.time")
    @patch(
        "oic.utils.time_util.utc_time_sans_frac"
    )  # used internally by pyoidc when verifying ID Token
    @responses.activate
    @pytest.mark.parametrize(
        "claims,role_claim,value",
        [
            ({"roles": "admin"}, "roles", "admin"),
            ({"roles": ["admin", "user"]}, "roles", "admin"),
            ({"realm_acces": {"roles": "admin"}}, "realm_acces.roles", "admin"),
            ({"roles": ["admin", "user"]}, "roles", ["admin", "user"]),
        ],
    )
    @pytest.mark.parametrize("source", [("auth"), ("id"), ("userinfo")])
    def test_valid_rbac(
        self, time_mock, utc_time_sans_frac_mock, claims, role_claim, value, source
    ):
        self.app.config.update(
            {
                "OIDC_REQUIRED_ROLES": value,
                "OIDC_ROLE_CLAIM": role_claim,
                "OIDC_ROLE_SOURCE": source,
            }
        )
        # freeze time since ID Token validation includes expiration timestamps
        timestamp = time.mktime(datetime(2017, 1, 1).timetuple())
        time_mock.return_value = timestamp
        utc_time_sans_frac_mock.return_value = int(timestamp)

        # mock token response
        user_id = "user1"
        exp_time = 10
        nonce = "test_nonce"
        id_token_claims = {
            "iss": self.PROVIDER_BASEURL,
            "aud": [self.CLIENT_ID],
            "sub": user_id,
            "exp": int(timestamp) + exp_time,
            "iat": int(timestamp),
            "nonce": nonce,
        }
        id_token_claims.update(**claims)
        id_token_jwt, id_token_signing_key = signed_id_token(id_token_claims)
        access_token = claims
        access_token_jwt = jwt.encode(access_token, "secret", algorithm="HS256")
        token_response = {
            "access_token": access_token_jwt,
            "token_type": "Bearer",
            "id_token": id_token_jwt,
        }
        token_endpoint = self.PROVIDER_BASEURL + "/token"
        responses.add(responses.POST, token_endpoint, json=token_response)
        responses.add(
            responses.GET,
            self.PROVIDER_BASEURL + "/jwks",
            json={"keys": [id_token_signing_key.serialize()]},
        )

        # mock userinfo response
        userinfo = {"sub": user_id, "name": "Test User"}
        userinfo.update(**claims)
        userinfo_endpoint = self.PROVIDER_BASEURL + "/userinfo"
        responses.add(responses.GET, userinfo_endpoint, json=userinfo)

        authn = self.init_app(
            provider_metadata_extras={
                "token_endpoint": token_endpoint,
                "userinfo_endpoint": userinfo_endpoint,
            }
        )
        test_endpoint = self.get_auth_endpoint(authn)
        state = "test_state"
        with self.app.test_request_context("/redirect_uri?state={}&code=test".format(state)):
            UserSession(flask.session, self.PROVIDER_NAME)
            flask.session["destination"] = "/"
            flask.session["state"] = state
            flask.session["nonce"] = nonce
            authn._handle_authentication_response()

            assert test_endpoint()

    @patch("time.time")
    @patch(
        "oic.utils.time_util.utc_time_sans_frac"
    )  # used internally by pyoidc when verifying ID Token
    @responses.activate
    @pytest.mark.parametrize(
        "claims,role_claim,value",
        [
            ({"roles": "admin"}, "roles", "superadmin"),
            ({"roles": "admin"}, "roles", ["admin", "superadmin"]),
            ({"roles": "admin"}, "secondary_roles", "admin"),
            ({"roles": ["admin", "user"]}, "roles", "superadmin"),
            ({"roles": ["admin", "user"]}, "roles", ["admin", "superadmin"]),
            ({"realm_acces": {"roles": "admin"}}, "realm_acces.roles", "superadmin"),
        ],
    )
    @pytest.mark.parametrize("source", [("auth"), ("id"), ("userinfo")])
    def test_failed_rbac(
        self, time_mock, utc_time_sans_frac_mock, claims, role_claim, value, source
    ):
        self.app.config.update(
            {
                "OIDC_REQUIRED_ROLES": value,
                "OIDC_ROLE_CLAIM": role_claim,
                "OIDC_ROLE_SOURCE": source,
            }
        )
        # freeze time since ID Token validation includes expiration timestamps
        timestamp = time.mktime(datetime(2017, 1, 1).timetuple())
        time_mock.return_value = timestamp
        utc_time_sans_frac_mock.return_value = int(timestamp)

        # mock token response
        user_id = "user1"
        exp_time = 10
        nonce = "test_nonce"
        id_token_claims = {
            "iss": self.PROVIDER_BASEURL,
            "aud": [self.CLIENT_ID],
            "sub": user_id,
            "exp": int(timestamp) + exp_time,
            "iat": int(timestamp),
            "nonce": nonce,
        }
        id_token_claims.update(**claims)
        id_token_jwt, id_token_signing_key = signed_id_token(id_token_claims)
        access_token = claims
        access_token_jwt = jwt.encode(access_token, "secret", algorithm="HS256")
        token_response = {
            "access_token": access_token_jwt,
            "token_type": "Bearer",
            "id_token": id_token_jwt,
        }
        token_endpoint = self.PROVIDER_BASEURL + "/token"
        responses.add(responses.POST, token_endpoint, json=token_response)
        responses.add(
            responses.GET,
            self.PROVIDER_BASEURL + "/jwks",
            json={"keys": [id_token_signing_key.serialize()]},
        )

        # mock userinfo response
        userinfo = {"sub": user_id, "name": "Test User"}
        userinfo.update(**claims)
        userinfo_endpoint = self.PROVIDER_BASEURL + "/userinfo"
        responses.add(responses.GET, userinfo_endpoint, json=userinfo)

        authn = self.init_app(
            provider_metadata_extras={
                "token_endpoint": token_endpoint,
                "userinfo_endpoint": userinfo_endpoint,
            }
        )
        test_endpoint = self.get_auth_endpoint(authn)
        state = "test_state"
        with self.app.test_request_context("/redirect_uri?state={}&code=test".format(state)):
            UserSession(flask.session, self.PROVIDER_NAME)
            flask.session["destination"] = "/"
            flask.session["state"] = state
            flask.session["nonce"] = nonce
            authn._handle_authentication_response()

            with pytest.raises(Unauthorized):
                assert test_endpoint()