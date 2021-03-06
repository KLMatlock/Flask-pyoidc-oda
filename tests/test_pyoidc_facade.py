import time

import flask
from flask import Flask
import base64
import pytest
import responses
from oic.oic import (
    AuthorizationResponse,
    AccessTokenResponse,
    TokenErrorResponse,
    OpenIDSchema,
    AuthorizationErrorResponse,
)
from urllib.parse import parse_qsl, urlparse

from flask_pyoidc.provider_configuration import (
    ProviderConfiguration,
    ClientMetadata,
    ProviderMetadata,
    ClientRegistrationInfo,
)
from flask_pyoidc.pyoidc_facade import PyoidcFacade, _ClientAuthentication
from .util import signed_id_token


class TestPyoidcFacade(object):
    PROVIDER_BASEURL = "http://rp.example.com"
    PROVIDER_METADATA = ProviderMetadata(
        PROVIDER_BASEURL, PROVIDER_BASEURL + "/auth", PROVIDER_BASEURL + "/jwks"
    )
    CLIENT_METADATA = ClientMetadata("client1", "secret1")
    CLIENT_DOMAIN = "client.example.com"
    REDIRECT_URI = "redirect_uri"
    FULL_REDIRECT_URI = "http://client.example.com/redirect_uri"

    @pytest.fixture(autouse=True)
    def create_flask_app(self):
        self.app = Flask(__name__)
        self.app.add_url_rule("/redirect_uri", "redirect_uri")
        self.app.config.update(
            {"SERVER_NAME": self.CLIENT_DOMAIN, "SECRET_KEY": "test_key"}
        )

    def test_registered_client_metadata_is_forwarded_to_pyoidc(self):
        config = ProviderConfiguration(
            provider_metadata=self.PROVIDER_METADATA,
            client_metadata=self.CLIENT_METADATA,
        )
        facade = PyoidcFacade(config, self.REDIRECT_URI)
        assert facade._client.registration_response

    def test_no_registered_client_metadata_is_handled(self):
        config = ProviderConfiguration(
            provider_metadata=self.PROVIDER_METADATA,
            client_registration_info=ClientRegistrationInfo(),
        )
        facade = PyoidcFacade(config, self.REDIRECT_URI)
        assert not facade._client.registration_response

    def test_is_registered(self):
        unregistered = ProviderConfiguration(
            provider_metadata=self.PROVIDER_METADATA,
            client_registration_info=ClientRegistrationInfo(),
        )
        registered = ProviderConfiguration(
            provider_metadata=self.PROVIDER_METADATA,
            client_metadata=self.CLIENT_METADATA,
        )
        assert PyoidcFacade(unregistered, self.REDIRECT_URI).is_registered() is False
        assert PyoidcFacade(registered, self.REDIRECT_URI).is_registered() is True

    @responses.activate
    def test_register(self):
        registration_endpoint = self.PROVIDER_BASEURL + "/register"
        responses.add(
            responses.POST, registration_endpoint, json=self.CLIENT_METADATA.to_dict()
        )

        provider_metadata = self.PROVIDER_METADATA.copy(
            registration_endpoint=registration_endpoint
        )
        unregistered = ProviderConfiguration(
            provider_metadata=provider_metadata,
            client_registration_info=ClientRegistrationInfo(),
        )
        facade = PyoidcFacade(unregistered, self.REDIRECT_URI)
        facade.register()
        assert facade.is_registered() is True

    def test_authentication_request(self):
        extra_user_auth_params = {"foo": "bar", "abc": "xyz"}
        config = ProviderConfiguration(
            provider_metadata=self.PROVIDER_METADATA,
            client_metadata=self.CLIENT_METADATA,
            auth_request_params=extra_user_auth_params,
        )

        state = "test_state"
        nonce = "test_nonce"

        facade = PyoidcFacade(config, self.REDIRECT_URI)
        extra_lib_auth_params = {"foo": "baz", "qwe": "rty"}
        auth_request = facade.authentication_request(
            state, nonce, self.FULL_REDIRECT_URI, extra_lib_auth_params
        )
        assert auth_request.startswith(self.PROVIDER_METADATA["authorization_endpoint"])

        auth_request_params = dict(parse_qsl(urlparse(auth_request).query))
        expected_auth_params = {
            "scope": "openid",
            "response_type": "code",
            "client_id": self.CLIENT_METADATA["client_id"],
            "redirect_uri": self.FULL_REDIRECT_URI,
            "state": state,
            "nonce": nonce,
        }
        expected_auth_params.update(extra_user_auth_params)
        expected_auth_params.update(extra_lib_auth_params)
        assert auth_request_params == expected_auth_params

    def test_parse_authentication_response(self):
        facade = PyoidcFacade(
            ProviderConfiguration(
                provider_metadata=self.PROVIDER_METADATA,
                client_metadata=self.CLIENT_METADATA,
            ),
            self.REDIRECT_URI,
        )
        auth_code = "auth_code-1234"
        state = "state-1234"
        auth_response = AuthorizationResponse(**{"state": state, "code": auth_code})
        parsed_auth_response = facade.parse_authentication_response(
            auth_response.to_dict()
        )
        assert isinstance(parsed_auth_response, AuthorizationResponse)
        assert parsed_auth_response.to_dict() == auth_response.to_dict()

    def test_parse_authentication_response_handles_error_response(self):
        facade = PyoidcFacade(
            ProviderConfiguration(
                provider_metadata=self.PROVIDER_METADATA,
                client_metadata=self.CLIENT_METADATA,
            ),
            self.REDIRECT_URI,
        )
        error_response = AuthorizationErrorResponse(
            **{"error": "invalid_request", "state": "state-1234"}
        )
        parsed_auth_response = facade.parse_authentication_response(error_response)
        assert isinstance(parsed_auth_response, AuthorizationErrorResponse)
        assert parsed_auth_response.to_dict() == error_response.to_dict()

    @responses.activate
    def test_parse_authentication_response_preserves_id_token_jwt(self):
        facade = PyoidcFacade(
            ProviderConfiguration(
                provider_metadata=self.PROVIDER_METADATA,
                client_metadata=self.CLIENT_METADATA,
            ),
            self.REDIRECT_URI,
        )
        state = "state-1234"
        now = int(time.time())
        id_token, id_token_signing_key = signed_id_token(
            {
                "iss": self.PROVIDER_METADATA["issuer"],
                "sub": "test_sub",
                "aud": "client1",
                "exp": now + 1,
                "iat": now,
            }
        )
        responses.add(
            responses.GET,
            self.PROVIDER_METADATA["jwks_uri"],
            json={"keys": [id_token_signing_key.serialize()]},
        )
        auth_response = AuthorizationResponse(**{"state": state, "id_token": id_token})
        parsed_auth_response = facade.parse_authentication_response(auth_response)
        assert isinstance(parsed_auth_response, AuthorizationResponse)
        assert parsed_auth_response["state"] == state
        assert parsed_auth_response["id_token_jwt"] == id_token

    @responses.activate
    def test_token_request(self):
        token_endpoint = self.PROVIDER_BASEURL + "/token"
        now = int(time.time())
        id_token_claims = {
            "iss": self.PROVIDER_METADATA["issuer"],
            "sub": "test_user",
            "aud": [self.CLIENT_METADATA["client_id"]],
            "exp": now + 1,
            "iat": now,
            "nonce": "test_nonce",
        }
        id_token_jwt, id_token_signing_key = signed_id_token(id_token_claims)
        token_response = AccessTokenResponse(
            access_token="test_access_token", token_type="Bearer", id_token=id_token_jwt
        )
        responses.add(
            responses.POST, 
            token_endpoint, 
            json=token_response.to_dict()
        )

        provider_metadata = self.PROVIDER_METADATA.copy(token_endpoint=token_endpoint)
        facade = PyoidcFacade(
            ProviderConfiguration(
                provider_metadata=provider_metadata,
                client_metadata=self.CLIENT_METADATA,
            ),
            self.REDIRECT_URI,
        )

        auth_code = "auth_code-1234"
        responses.add(
            responses.GET,
            self.PROVIDER_METADATA["jwks_uri"],
            json={"keys": [id_token_signing_key.serialize()]},
        )
        with self.app.app_context():
            token_response = facade.token_request(auth_code)

        assert isinstance(token_response, AccessTokenResponse)
        expected_token_response = token_response.to_dict()
        expected_token_response["id_token"] = id_token_claims
        expected_token_response["id_token_jwt"] = id_token_jwt
        assert token_response.to_dict() == expected_token_response

        token_request = dict(parse_qsl(responses.calls[0].request.body))
        expected_token_request = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": self.FULL_REDIRECT_URI
        }
        assert token_request == expected_token_request

    @responses.activate
    def test_token_request_handles_error_response(self):
        token_endpoint = self.PROVIDER_BASEURL + "/token"
        token_response = TokenErrorResponse(
            error="invalid_request", error_description="test error description"
        )
        responses.add(
            responses.POST, token_endpoint, json=token_response.to_dict(), status=400
        )

        provider_metadata = self.PROVIDER_METADATA.copy(token_endpoint=token_endpoint)
        facade = PyoidcFacade(
            ProviderConfiguration(
                provider_metadata=provider_metadata,
                client_metadata=self.CLIENT_METADATA,
            ),
            self.REDIRECT_URI,
        )

        with self.app.app_context():
            assert facade.token_request("1234") == token_response

    def test_token_request_handles_missing_provider_token_endpoint(self):
        facade = PyoidcFacade(
            ProviderConfiguration(
                provider_metadata=self.PROVIDER_METADATA,
                client_metadata=self.CLIENT_METADATA,
            ),
            self.REDIRECT_URI,
        )
        assert facade.token_request("1234") is None

    @pytest.mark.parametrize("userinfo_http_method", ["GET", "POST"])
    @responses.activate
    def test_configurable_userinfo_endpoint_method_is_used(self, userinfo_http_method):
        userinfo_endpoint = self.PROVIDER_BASEURL + "/userinfo"
        userinfo_response = OpenIDSchema(sub="user1")
        responses.add(
            userinfo_http_method, userinfo_endpoint, json=userinfo_response.to_dict()
        )

        provider_metadata = self.PROVIDER_METADATA.copy(
            userinfo_endpoint=userinfo_endpoint
        )
        facade = PyoidcFacade(
            ProviderConfiguration(
                provider_metadata=provider_metadata,
                client_metadata=self.CLIENT_METADATA,
                userinfo_http_method=userinfo_http_method,
            ),
            self.REDIRECT_URI,
        )
        assert facade.userinfo_request("test_token") == userinfo_response

    def test_no_userinfo_request_is_made_if_no_userinfo_http_method_is_configured(self):
        facade = PyoidcFacade(
            ProviderConfiguration(
                provider_metadata=self.PROVIDER_METADATA,
                client_metadata=self.CLIENT_METADATA,
                userinfo_http_method=None,
            ),
            self.REDIRECT_URI,
        )
        assert facade.userinfo_request("test_token") is None

    def test_no_userinfo_request_is_made_if_no_userinfo_endpoint_is_configured(self):
        facade = PyoidcFacade(
            ProviderConfiguration(
                provider_metadata=self.PROVIDER_METADATA,
                client_metadata=self.CLIENT_METADATA,
            ),
            self.REDIRECT_URI,
        )
        assert facade.userinfo_request("test_token") is None

    def test_no_userinfo_request_is_made_if_no_access_token(self):
        provider_metadata = self.PROVIDER_METADATA.copy(
            userinfo_endpoint=self.PROVIDER_BASEURL + "/userinfo"
        )
        facade = PyoidcFacade(
            ProviderConfiguration(
                provider_metadata=provider_metadata,
                client_metadata=self.CLIENT_METADATA,
            ),
            self.REDIRECT_URI,
        )
        assert facade.userinfo_request(None) is None


class TestClientAuthentication(object):
    CLIENT_ID = "client1"
    CLIENT_SECRET = "secret1"

    @property
    def basic_auth(self):
        credentials = "{}:{}".format(self.CLIENT_ID, self.CLIENT_SECRET)
        return "Basic {}".format(
            base64.urlsafe_b64encode(credentials.encode("utf-8")).decode("utf-8")
        )

    @pytest.fixture(autouse=True)
    def setup(self):
        self.client_auth = _ClientAuthentication(self.CLIENT_ID, self.CLIENT_SECRET)

    def test_client_secret_basic(self):
        request = {}
        headers = self.client_auth("client_secret_basic", request)
        assert headers == {"Authorization": self.basic_auth}
        assert request == {}

    def test_client_secret_post(self):
        request = {}
        headers = self.client_auth("client_secret_post", request)
        assert headers is None
        assert request == {
            "client_id": self.CLIENT_ID,
            "client_secret": self.CLIENT_SECRET,
        }

    def test_defaults_to_client_secret_basic(self):
        assert self.client_auth("invalid_client_auth_method", {}) == self.client_auth(
            "client_secret_basic", {}
        )
