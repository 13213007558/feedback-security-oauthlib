# -*- coding: utf-8 -*-
import datetime
import json
from unittest import mock

from oauthlib.common import Request
from oauthlib.oauth2.rfc6749 import errors
from oauthlib.oauth2.rfc6749.grant_types import (
    AuthorizationCodeGrant, authorization_code,
)
from oauthlib.oauth2.rfc6749.pkce import (
    CHALLENGE_METHOD_DISALLOWED,
    CHALLENGE_METHOD_UNKNOWN,
    CHALLENGE_MISSING,
    CHALLENGE_SYNTAX_INVALID,
    LEGACY_TRANSITION_EXPIRED,
    PLAIN,
    PkcePolicy,
    PkceRejectionMetrics,
    S256,
    VERIFIER_MISMATCH,
    VERIFIER_MISSING,
    VERIFIER_SYNTAX_INVALID,
)
from oauthlib.oauth2.rfc6749.tokens import BearerToken

from tests.unittest import TestCase

# RFC 7636 Section 4.1/4.2 compliant values
valid_code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
valid_code_challenge_plain = valid_code_verifier


class AuthorizationCodeGrantTest(TestCase):

    def setUp(self):
        self.request = Request('http://a.b/path')
        self.request.scopes = ('hello', 'world')
        self.request.expires_in = 1800
        self.request.client = 'batman'
        self.request.client_id = 'abcdef'
        self.request.code = '1234'
        self.request.response_type = 'code'
        self.request.grant_type = 'authorization_code'
        self.request.redirect_uri = 'https://a.b/cb'

        self.mock_validator = mock.MagicMock()
        self.mock_validator.is_pkce_required.return_value = False
        self.mock_validator.get_code_challenge.return_value = None
        self.mock_validator.is_origin_allowed.return_value = False
        self.mock_validator.authenticate_client.side_effect = self.set_client
        self.auth = AuthorizationCodeGrant(request_validator=self.mock_validator)

    def set_client(self, request):
        request.client = mock.MagicMock()
        request.client.client_id = request.client_id
        return True

    def setup_validators(self):
        self.authval1, self.authval2 = mock.Mock(), mock.Mock()
        self.authval1.return_value = {}
        self.authval2.return_value = {}
        self.tknval1, self.tknval2 = mock.Mock(), mock.Mock()
        self.tknval1.return_value = None
        self.tknval2.return_value = None
        self.auth.custom_validators.pre_token.append(self.tknval1)
        self.auth.custom_validators.post_token.append(self.tknval2)
        self.auth.custom_validators.pre_auth.append(self.authval1)
        self.auth.custom_validators.post_auth.append(self.authval2)

    def test_custom_auth_validators(self):
        self.setup_validators()

        bearer = BearerToken(self.mock_validator)
        self.auth.create_authorization_response(self.request, bearer)
        self.assertTrue(self.authval1.called)
        self.assertTrue(self.authval2.called)
        self.assertFalse(self.tknval1.called)
        self.assertFalse(self.tknval2.called)

    def test_custom_token_validators(self):
        self.setup_validators()

        bearer = BearerToken(self.mock_validator)
        self.auth.create_token_response(self.request, bearer)
        self.assertTrue(self.tknval1.called)
        self.assertTrue(self.tknval2.called)
        self.assertFalse(self.authval1.called)
        self.assertFalse(self.authval2.called)

    def test_create_authorization_grant(self):
        bearer = BearerToken(self.mock_validator)
        self.request.response_mode = 'query'
        h, _b, _s = self.auth.create_authorization_response(self.request, bearer)
        grant = dict(Request(h['Location']).uri_query_params)
        self.assertIn('code', grant)
        self.assertTrue(self.mock_validator.validate_redirect_uri.called)
        self.assertTrue(self.mock_validator.validate_response_type.called)
        self.assertTrue(self.mock_validator.validate_scopes.called)

    def test_create_authorization_grant_no_scopes(self):
        bearer = BearerToken(self.mock_validator)
        self.request.response_mode = 'query'
        self.request.scopes = []
        self.auth.create_authorization_response(self.request, bearer)

    def test_create_authorization_grant_state(self):
        self.request.state = 'abc'
        self.request.redirect_uri = None
        self.request.response_mode = 'query'
        self.mock_validator.get_default_redirect_uri.return_value = 'https://a.b/cb'
        bearer = BearerToken(self.mock_validator)
        h, _b, _s = self.auth.create_authorization_response(self.request, bearer)
        grant = dict(Request(h['Location']).uri_query_params)
        self.assertIn('code', grant)
        self.assertIn('state', grant)
        self.assertFalse(self.mock_validator.validate_redirect_uri.called)
        self.assertTrue(self.mock_validator.get_default_redirect_uri.called)
        self.assertTrue(self.mock_validator.validate_response_type.called)
        self.assertTrue(self.mock_validator.validate_scopes.called)

    @mock.patch('oauthlib.common.generate_token')
    def test_create_authorization_response(self, generate_token):
        generate_token.return_value = 'abc'
        bearer = BearerToken(self.mock_validator)
        self.request.response_mode = 'query'
        h, _b, _s = self.auth.create_authorization_response(self.request, bearer)
        self.assertURLEqual(h['Location'], 'https://a.b/cb?code=abc')
        self.request.response_mode = 'fragment'
        h, _b, _s = self.auth.create_authorization_response(self.request, bearer)
        self.assertURLEqual(h['Location'], 'https://a.b/cb#code=abc')

    def test_create_token_response(self):
        bearer = BearerToken(self.mock_validator)

        _h, token, _s = self.auth.create_token_response(self.request, bearer)
        token = json.loads(token)
        self.assertEqual(self.mock_validator.save_token.call_count, 1)
        self.assertIn('access_token', token)
        self.assertIn('refresh_token', token)
        self.assertIn('expires_in', token)
        self.assertIn('scope', token)
        self.assertTrue(self.mock_validator.client_authentication_required.called)
        self.assertTrue(self.mock_validator.authenticate_client.called)
        self.assertTrue(self.mock_validator.validate_code.called)
        self.assertTrue(self.mock_validator.confirm_redirect_uri.called)
        self.assertTrue(self.mock_validator.validate_grant_type.called)
        self.assertTrue(self.mock_validator.invalidate_authorization_code.called)

    def test_create_token_response_without_refresh_token(self):
        self.auth.refresh_token = False  # Not to issue refresh token.

        bearer = BearerToken(self.mock_validator)
        _h, token, _s = self.auth.create_token_response(self.request, bearer)
        token = json.loads(token)
        self.assertEqual(self.mock_validator.save_token.call_count, 1)
        self.assertIn('access_token', token)
        self.assertNotIn('refresh_token', token)
        self.assertIn('expires_in', token)
        self.assertIn('scope', token)
        self.assertTrue(self.mock_validator.client_authentication_required.called)
        self.assertTrue(self.mock_validator.authenticate_client.called)
        self.assertTrue(self.mock_validator.validate_code.called)
        self.assertTrue(self.mock_validator.confirm_redirect_uri.called)
        self.assertTrue(self.mock_validator.validate_grant_type.called)
        self.assertTrue(self.mock_validator.invalidate_authorization_code.called)

    def test_invalid_request(self):
        del self.request.code
        self.assertRaises(errors.InvalidRequestError, self.auth.validate_token_request,
                          self.request)

    def test_invalid_request_duplicates(self):
        request = mock.MagicMock(wraps=self.request)
        request.grant_type = 'authorization_code'
        request.duplicate_params = ['client_id']
        self.assertRaises(errors.InvalidRequestError, self.auth.validate_token_request,
                          request)

    def test_unsupported_response_mode(self):
        self.request.response_mode = 'not-a-mode'
        bearer = BearerToken(self.mock_validator)
        self.assertRaises(errors.UnsupportedResponseModeError,
                          self.auth.validate_authorization_request, self.request)
        self.assertRaises(errors.UnsupportedResponseModeError,
                          self.auth.create_authorization_response, self.request, bearer)
        self.assertFalse(self.mock_validator.validate_response_type.called)

    def test_default_response_mode(self):
        self.auth.validate_authorization_request(self.request)
        self.assertEqual(self.request.response_mode, self.auth.default_response_mode)

    def test_error_response_uses_default_response_mode(self):
        self.mock_validator.validate_scopes.return_value = False
        bearer = BearerToken(self.mock_validator)
        separator = '#' if self.auth.default_response_mode == 'fragment' else '?'

        with self.assertRaises(errors.InvalidScopeError) as cm:
            self.auth.validate_authorization_request(self.request)
        self.assertEqual(cm.exception.response_mode, self.auth.default_response_mode)
        self.assertIn(separator + 'error=invalid_scope',
                      cm.exception.in_uri(self.request.redirect_uri))

        self.request.response_mode = None
        h, _b, s = self.auth.create_authorization_response(self.request, bearer)
        self.assertEqual(s, 302)
        self.assertIn(separator + 'error=invalid_scope', h['Location'])

    def test_error_response_uses_requested_response_mode(self):
        self.mock_validator.validate_scopes.return_value = False
        self.request.response_mode = 'fragment'
        bearer = BearerToken(self.mock_validator)
        h, _b, s = self.auth.create_authorization_response(self.request, bearer)
        self.assertEqual(s, 302)
        self.assertIn('#error=invalid_scope', h['Location'])

    def test_response_mode_set_by_failing_pre_auth_validator(self):
        def set_response_mode(request):
            request.response_mode = 'form_post'
            raise errors.InvalidRequestError(request=request)
        self.auth.custom_validators.pre_auth.append(set_response_mode)
        bearer = BearerToken(self.mock_validator)

        with self.assertRaises(errors.UnsupportedResponseModeError) as cm:
            self.auth.validate_authorization_request(self.request)
        # Not reported as raised while handling the normal error.
        self.assertIsNone(cm.exception.__context__)
        self.request.response_mode = None
        self.assertRaises(errors.UnsupportedResponseModeError,
                          self.auth.create_authorization_response, self.request, bearer)

    def test_response_mode_set_by_post_auth_validator(self):
        def set_response_mode(request):
            request.response_mode = 'form_post'
            return {}
        self.auth.custom_validators.post_auth.append(set_response_mode)
        bearer = BearerToken(self.mock_validator)

        self.assertRaises(errors.UnsupportedResponseModeError,
                          self.auth.validate_authorization_request, self.request)
        self.request.response_mode = None
        self.assertRaises(errors.UnsupportedResponseModeError,
                          self.auth.create_authorization_response, self.request, bearer)
        self.assertFalse(self.mock_validator.save_token.called)
        self.assertFalse(self.mock_validator.save_authorization_code.called)

    def test_error_without_request_gets_response_mode(self):
        def fail(request):
            raise errors.InvalidRequestError()
        self.auth.custom_validators.post_auth.append(fail)

        with self.assertRaises(errors.InvalidRequestError) as cm:
            self.auth.validate_authorization_request(self.request)
        self.assertEqual(cm.exception.response_mode, self.auth.default_response_mode)

    def test_response_mode_set_by_pre_auth_validator(self):
        def set_response_mode(request):
            request.response_mode = 'form_post'
            return {}
        self.auth.custom_validators.pre_auth.append(set_response_mode)
        bearer = BearerToken(self.mock_validator)

        self.assertRaises(errors.UnsupportedResponseModeError,
                          self.auth.validate_authorization_request, self.request)
        self.request.response_mode = None
        self.assertRaises(errors.UnsupportedResponseModeError,
                          self.auth.create_authorization_response, self.request, bearer)
        self.assertFalse(self.mock_validator.save_authorization_code.called)

    def test_response_mode_set_by_failing_post_auth_validator(self):
        def set_response_mode(request):
            request.response_mode = 'form_post'
            raise errors.InvalidRequestError(request=request)
        self.auth.custom_validators.post_auth.append(set_response_mode)
        bearer = BearerToken(self.mock_validator)

        self.assertRaises(errors.UnsupportedResponseModeError,
                          self.auth.validate_authorization_request, self.request)
        self.request.response_mode = None
        self.assertRaises(errors.UnsupportedResponseModeError,
                          self.auth.create_authorization_response, self.request, bearer)

    def test_response_mode_set_by_code_modifier(self):
        def set_response_mode(grant, token_handler, request):
            request.response_mode = 'form_post'
            return grant
        self.auth.register_code_modifier(set_response_mode)
        bearer = BearerToken(self.mock_validator)

        self.assertRaises(errors.UnsupportedResponseModeError,
                          self.auth.create_authorization_response, self.request, bearer)
        self.assertFalse(self.mock_validator.save_token.called)
        self.assertFalse(self.mock_validator.save_authorization_code.called)

    def test_prepare_authorization_response_unsupported_response_mode(self):
        self.request.response_mode = 'form_post'
        self.assertRaises(errors.UnsupportedResponseModeError,
                          self.auth.prepare_authorization_response,
                          self.request, {'code': 'abc'}, {}, None, 302)

    def test_authentication_required(self):
        """
        ensure client_authentication_required() is properly called
        """
        self.auth.validate_token_request(self.request)
        self.mock_validator.client_authentication_required.assert_called_once_with(self.request)

    def test_authenticate_client(self):
        self.mock_validator.authenticate_client.side_effect = None
        self.mock_validator.authenticate_client.return_value = False
        self.assertRaises(errors.InvalidClientError, self.auth.validate_token_request,
                          self.request)

    def test_client_id_missing(self):
        self.mock_validator.authenticate_client.side_effect = None
        request = mock.MagicMock(wraps=self.request)
        request.grant_type = 'authorization_code'
        del request.client.client_id
        self.assertRaises(NotImplementedError, self.auth.validate_token_request,
                          request)

    def test_invalid_grant(self):
        self.request.client = 'batman'
        self.mock_validator.authenticate_client = self.set_client
        self.mock_validator.validate_code.return_value = False
        self.assertRaises(errors.InvalidGrantError,
                          self.auth.validate_token_request, self.request)

    def test_invalid_grant_type(self):
        self.request.grant_type = 'foo'
        self.assertRaises(errors.UnsupportedGrantTypeError,
                          self.auth.validate_token_request, self.request)

    def test_authenticate_client_id(self):
        self.mock_validator.client_authentication_required.return_value = False
        self.mock_validator.authenticate_client_id.return_value = False
        self.request.state = 'abc'
        self.assertRaises(errors.InvalidClientError,
                          self.auth.validate_token_request, self.request)

    def test_client_id_discrepancy(self):
        """ServerError raised when authenticate_client sets a different client_id."""
        def set_mismatched_client(request):
            request.client = mock.MagicMock()
            request.client.client_id = 'different_from_abcdef'
            return True
        self.mock_validator.authenticate_client.side_effect = set_mismatched_client
        self.assertRaises(errors.ServerError,
                          self.auth.validate_token_request, self.request)

    def test_public_client_id_missing(self):
        """NotImplementedError raised when authenticate_client_id does not set request.client."""
        self.mock_validator.client_authentication_required.return_value = False
        self.mock_validator.authenticate_client_id.return_value = True
        self.request.client = mock.MagicMock()
        del self.request.client.client_id
        self.assertRaises(NotImplementedError,
                          self.auth.validate_token_request, self.request)

    def test_public_client_id_discrepancy(self):
        """ServerError raised when authenticate_client_id sets a different client_id."""
        def set_mismatched_client(client_id, request):
            request.client = mock.MagicMock()
            request.client.client_id = 'different_from_abcdef'
            return True
        self.mock_validator.client_authentication_required.return_value = False
        self.mock_validator.authenticate_client_id.side_effect = set_mismatched_client
        self.assertRaises(errors.ServerError,
                          self.auth.validate_token_request, self.request)

    def test_invalid_redirect_uri(self):
        self.mock_validator.confirm_redirect_uri.return_value = False
        self.assertRaises(errors.MismatchingRedirectURIError,
                          self.auth.validate_token_request, self.request)

    # PKCE validate_authorization_request
    def test_pkce_challenge_missing(self):
        self.mock_validator.is_pkce_required.return_value = True
        self.assertRaises(errors.MissingCodeChallengeError,
                          self.auth.validate_authorization_request, self.request)

    def test_pkce_default_method(self):
        for required in [True, False]:
            self.mock_validator.is_pkce_required.return_value = required
            self.request.code_challenge = valid_code_challenge_plain
            _, ri = self.auth.validate_authorization_request(self.request)
            self.assertIn("code_challenge", ri)
            self.assertIn("code_challenge_method", ri)
            self.assertEqual(ri["code_challenge"], valid_code_challenge_plain)
            self.assertEqual(ri["code_challenge_method"], "plain")

    def test_pkce_wrong_method(self):
        for required in [True, False]:
            self.mock_validator.is_pkce_required.return_value = required
            self.request.code_challenge = valid_code_challenge_plain
            self.request.code_challenge_method = "foobar"
            self.assertRaises(errors.UnsupportedCodeChallengeMethodError,
                              self.auth.validate_authorization_request, self.request)

    def test_pkce_invalid_challenge_syntax(self):
        # RFC 7636 Section 4.2: challenge must be 43*128 unreserved chars
        for required in [True, False]:
            self.mock_validator.is_pkce_required.return_value = required
            for invalid in ["too_short", "\u00e9" + "a" * 42,
                            "a" * 129, "bad" + "a" * 40 + "=+",
                            42]:
                self.request.code_challenge = invalid
                self.assertRaises(errors.InvalidRequestError,
                                  self.auth.validate_authorization_request, self.request)

    def test_pkce_valid_s256_challenge_syntax(self):
        # RFC 7636 Section 4.2: S256 challenge is 43 base64url chars
        self.request.code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        self.request.code_challenge_method = "S256"
        self.auth.validate_authorization_request(self.request)

    def test_pkce_invalid_s256_challenge_syntax(self):
        self.request.code_challenge = "a" * 44
        self.request.code_challenge_method = "S256"
        self.assertRaises(errors.InvalidRequestError,
                          self.auth.validate_authorization_request, self.request)

    # PKCE validate_token_request
    def test_pkce_verifier_missing(self):
        self.mock_validator.is_pkce_required.return_value = True
        self.assertRaises(errors.MissingCodeVerifierError,
                          self.auth.validate_token_request, self.request)

    # PKCE validate_token_request
    def test_pkce_required_verifier_missing_challenge_missing(self):
        self.mock_validator.is_pkce_required.return_value = True
        self.request.code_verifier = None
        self.mock_validator.get_code_challenge.return_value = None
        self.assertRaises(errors.MissingCodeVerifierError,
                          self.auth.validate_token_request, self.request)

    def test_pkce_required_verifier_missing_challenge_valid(self):
        self.mock_validator.is_pkce_required.return_value = True
        self.request.code_verifier = None
        self.mock_validator.get_code_challenge.return_value = valid_code_challenge_plain
        self.assertRaises(errors.MissingCodeVerifierError,
                          self.auth.validate_token_request, self.request)

    def test_pkce_required_verifier_valid_challenge_missing(self):
        self.mock_validator.is_pkce_required.return_value = True
        self.request.code_verifier = valid_code_verifier
        self.mock_validator.get_code_challenge.return_value = None
        self.assertRaises(errors.InvalidGrantError,
                          self.auth.validate_token_request, self.request)

    def test_pkce_required_verifier_valid_challenge_valid_method_valid(self):
        self.mock_validator.is_pkce_required.return_value = True
        self.request.code_verifier = valid_code_verifier
        self.mock_validator.get_code_challenge.return_value = valid_code_verifier
        self.mock_validator.get_code_challenge_method.return_value = "plain"
        self.auth.validate_token_request(self.request)

    def test_pkce_required_verifier_invalid_challenge_valid_method_valid(self):
        self.mock_validator.is_pkce_required.return_value = True
        self.request.code_verifier = valid_code_verifier
        self.mock_validator.get_code_challenge.return_value = "raboof-raboof-raboof-raboof-raboof-raboof"
        self.mock_validator.get_code_challenge_method.return_value = "plain"
        self.assertRaises(errors.InvalidGrantError,
                          self.auth.validate_token_request, self.request)

    def test_pkce_required_verifier_valid_challenge_valid_method_wrong(self):
        self.mock_validator.is_pkce_required.return_value = True
        self.request.code_verifier = valid_code_verifier
        self.mock_validator.get_code_challenge.return_value = valid_code_verifier
        self.mock_validator.get_code_challenge_method.return_value = "cryptic_method"
        self.assertRaises(errors.ServerError,
                          self.auth.validate_token_request, self.request)

    def test_pkce_verifier_valid_challenge_valid_method_missing(self):
        self.mock_validator.is_pkce_required.return_value = True
        self.request.code_verifier = valid_code_verifier
        self.mock_validator.get_code_challenge.return_value = valid_code_verifier
        self.mock_validator.get_code_challenge_method.return_value = None
        self.assertRaises(errors.InvalidGrantError,
                          self.auth.validate_token_request, self.request)

    def test_pkce_optional_verifier_valid_challenge_missing(self):
        # RFC 9700 Section 4.8.2: reject a code_verifier when the
        # authorization request had no code_challenge.
        self.mock_validator.is_pkce_required.return_value = False
        self.request.code_verifier = valid_code_verifier
        self.mock_validator.get_code_challenge.return_value = None
        self.assertRaises(errors.InvalidGrantError,
                          self.auth.validate_token_request, self.request)

    def test_pkce_optional_verifier_missing_challenge_valid(self):
        self.mock_validator.is_pkce_required.return_value = False
        self.request.code_verifier = None
        self.mock_validator.get_code_challenge.return_value = valid_code_verifier
        self.assertRaises(errors.MissingCodeVerifierError,
                          self.auth.validate_token_request, self.request)

    def test_pkce_required_verifier_invalid_syntax(self):
        # RFC 7636 Section 4.1: verifier must be 43*128 unreserved chars
        self.mock_validator.is_pkce_required.return_value = True
        self.mock_validator.get_code_challenge.return_value = valid_code_challenge_plain
        self.mock_validator.get_code_challenge_method.return_value = "plain"
        for invalid in ["too_short", "\u00e9" + "a" * 42, "a" * 129,
                        "bad" + "a" * 40 + "=+", 42, b"a" * 43]:
            self.request.code_verifier = invalid
            self.assertRaises(errors.InvalidGrantError,
                              self.auth.validate_token_request, self.request)

    def test_pkce_validator_returning_invalid_type_raises(self):
        # A RequestValidator.get_code_challenge implementation returning a
        # non-string is a server implementation error and must surface as
        # an internal error, not as invalid_grant.
        self.mock_validator.is_pkce_required.return_value = True
        self.request.code_verifier = valid_code_verifier
        self.mock_validator.get_code_challenge_method.return_value = "plain"
        for bad in [{"a": 1}, 42, b"a" * 43]:
            self.mock_validator.get_code_challenge.return_value = bad
            self.assertRaises((AttributeError, TypeError),
                              self.auth.validate_token_request, self.request)

    # PKCE functions
    def test_wrong_code_challenge_method_plain(self):
        self.assertFalse(authorization_code.code_challenge_method_plain("foo", "bar"))

    def test_correct_code_challenge_method_plain(self):
        self.assertTrue(authorization_code.code_challenge_method_plain("foo", "foo"))

    def test_plain_non_ascii_verifier_matches_non_ascii_challenge(self):
        # Regression test: non-ASCII values previously raised TypeError
        # from hmac.compare_digest, causing a server error instead of
        # invalid_grant. (github issue #988)
        self.assertTrue(
            authorization_code.code_challenge_method_plain("verifier-\u00e9", "verifier-\u00e9"))
        self.assertFalse(
            authorization_code.code_challenge_method_plain("verifier-\u00e9", "verifier"))
        self.assertFalse(
            authorization_code.code_challenge_method_plain("verifier", "verifier-\u00e9"))

    def test_plain_invalid_types_raise(self):
        # A RequestValidator.get_code_challenge implementation returning
        # a non-string is a server implementation error and must surface
        # as such, not as invalid_grant.
        self.assertRaises((AttributeError, TypeError),
                          authorization_code.code_challenge_method_plain, None, "foo")
        self.assertRaises((AttributeError, TypeError),
                          authorization_code.code_challenge_method_plain, "foo", None)
        self.assertRaises((AttributeError, TypeError),
                          authorization_code.code_challenge_method_plain, "foo", {"a": 1})
        self.assertRaises((AttributeError, TypeError),
                          authorization_code.code_challenge_method_plain, 42, "foo")
        self.assertRaises((AttributeError, TypeError),
                          authorization_code.code_challenge_method_plain, b"foo", "foo")

    def test_wrong_code_challenge_method_s256(self):
        self.assertFalse(authorization_code.code_challenge_method_s256("foo", "bar"))

    def test_s256_non_ascii_verifier_does_not_raise(self):
        self.assertFalse(
            authorization_code.code_challenge_method_s256("verifier-\u00e9", "foo"))

    def test_s256_invalid_types_raise(self):
        self.assertRaises((AttributeError, TypeError),
                          authorization_code.code_challenge_method_s256, None, "foo")
        self.assertRaises((AttributeError, TypeError),
                          authorization_code.code_challenge_method_s256, "foo", 42)

    def test_correct_code_challenge_method_s256(self):
        # "abcd" as verifier gives a '+' to base64
        self.assertTrue(
            authorization_code.code_challenge_method_s256("abcd",
                                                          "iNQmb9TmM40TuEX88olXnSCciXgjuSF9o-Fhk28DFYk")
        )
        # "/" as verifier gives a '/' and '+' to base64
        self.assertTrue(
            authorization_code.code_challenge_method_s256("/",
                                                          "il7asoJjJEMhngUeSt4tHVu8Zxx4EFG_FDeJfL3-oPE")
        )
        # Example from PKCE RFCE
        self.assertTrue(
            authorization_code.code_challenge_method_s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                                                          "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
        )

    def test_code_modifier_called(self):
        bearer = BearerToken(self.mock_validator)
        code_modifier = mock.MagicMock(wraps=lambda grant, *a: grant)
        self.auth.register_code_modifier(code_modifier)
        self.auth.create_authorization_response(self.request, bearer)
        code_modifier.assert_called_once()

    def test_hybrid_token_save(self):
        bearer = BearerToken(self.mock_validator)
        self.auth.register_code_modifier(
            lambda grant, *a: dict(list(grant.items()) + [('access_token', 1)])
        )
        self.auth.create_authorization_response(self.request, bearer)
        self.mock_validator.save_token.assert_called_once()

    # CORS

    def test_create_cors_headers(self):
        bearer = BearerToken(self.mock_validator)
        self.request.headers['origin'] = 'https://foo.bar'
        self.mock_validator.is_origin_allowed.return_value = True

        headers = self.auth.create_token_response(self.request, bearer)[0]
        self.assertEqual(
            headers['Access-Control-Allow-Origin'], 'https://foo.bar'
        )
        self.mock_validator.is_origin_allowed.assert_called_once_with(
            'abcdef', 'https://foo.bar', self.request
        )

    def test_create_cors_headers_no_origin(self):
        bearer = BearerToken(self.mock_validator)
        headers = self.auth.create_token_response(self.request, bearer)[0]
        self.assertNotIn('Access-Control-Allow-Origin', headers)
        self.mock_validator.is_origin_allowed.assert_not_called()

    def test_create_cors_headers_insecure_origin(self):
        bearer = BearerToken(self.mock_validator)
        self.request.headers['origin'] = 'http://foo.bar'

        headers = self.auth.create_token_response(self.request, bearer)[0]
        self.assertNotIn('Access-Control-Allow-Origin', headers)
        self.mock_validator.is_origin_allowed.assert_not_called()

    def test_create_cors_headers_invalid_origin(self):
        bearer = BearerToken(self.mock_validator)
        self.request.headers['origin'] = 'https://foo.bar'
        self.mock_validator.is_origin_allowed.return_value = False

        headers = self.auth.create_token_response(self.request, bearer)[0]
        self.assertNotIn('Access-Control-Allow-Origin', headers)
        self.mock_validator.is_origin_allowed.assert_called_once_with(
            'abcdef', 'https://foo.bar', self.request
        )


class PkcePolicyGrantTest(TestCase):
    """Unit tests for the per-client PkcePolicy enforcement path."""

    valid_s256_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

    def setUp(self):
        self.request = Request('http://a.b/path')
        self.request.scopes = ('hello', 'world')
        self.request.client = 'batman'
        self.request.client_id = 'abcdef'
        self.request.code = '1234'
        self.request.response_type = 'code'
        self.request.grant_type = 'authorization_code'
        self.request.redirect_uri = 'https://a.b/cb'

        self.metrics = PkceRejectionMetrics()
        self.now = datetime.datetime(2026, 11, 10,
                                     tzinfo=datetime.timezone.utc)
        self.clock = mock.Mock(return_value=self.now)
        self.mock_validator = mock.MagicMock()
        # A plain MagicMock return value must be treated as "not enrolled".
        self.assertNotIsInstance(
            self.mock_validator.get_pkce_policy.return_value, PkcePolicy)
        self.mock_validator.authenticate_client.side_effect = self.set_client
        self.auth = AuthorizationCodeGrant(
            request_validator=self.mock_validator,
            pkce_metrics=self.metrics, clock=self.clock)

    def set_client(self, request):
        request.client = mock.MagicMock()
        request.client.client_id = request.client_id
        return True

    def set_policy(self, policy):
        self.mock_validator.get_pkce_policy.return_value = policy

    # Authorization endpoint ---------------------------------------------------
    def test_mandatory_policy_requires_challenge(self):
        self.set_policy(PkcePolicy.mandatory_s256())
        self.assertRaises(
            errors.MissingCodeChallengeError,
            self.auth.validate_authorization_request, self.request)
        self.assertEqual(self.metrics.get(CHALLENGE_MISSING), 1)

    def test_mandatory_policy_rejects_plain_method(self):
        self.set_policy(PkcePolicy.mandatory_s256())
        self.request.code_challenge = valid_code_verifier
        self.request.code_challenge_method = PLAIN
        self.assertRaises(
            errors.UnsupportedCodeChallengeMethodError,
            self.auth.validate_authorization_request, self.request)
        self.assertEqual(self.metrics.get(CHALLENGE_METHOD_DISALLOWED), 1)

    def test_mandatory_policy_rejects_implicit_plain_default(self):
        # Omitting the method must not create a silent plain downgrade.
        self.set_policy(PkcePolicy.mandatory_s256())
        self.request.code_challenge = self.valid_s256_challenge
        self.assertRaises(
            errors.UnsupportedCodeChallengeMethodError,
            self.auth.validate_authorization_request, self.request)
        self.assertEqual(self.metrics.get(CHALLENGE_METHOD_DISALLOWED), 1)

    def test_mandatory_policy_rejects_unknown_method(self):
        self.set_policy(PkcePolicy.mandatory_s256())
        self.request.code_challenge = self.valid_s256_challenge
        self.request.code_challenge_method = 'rot13'
        self.assertRaises(
            errors.UnsupportedCodeChallengeMethodError,
            self.auth.validate_authorization_request, self.request)
        self.assertEqual(self.metrics.get(CHALLENGE_METHOD_UNKNOWN), 1)

    def test_mandatory_policy_rejects_bad_challenge_length(self):
        self.set_policy(PkcePolicy.mandatory_s256())
        self.request.code_challenge = 'a' * 44
        self.request.code_challenge_method = S256
        self.assertRaises(
            errors.InvalidRequestError,
            self.auth.validate_authorization_request, self.request)
        self.assertEqual(self.metrics.get(CHALLENGE_SYNTAX_INVALID), 1)

    def test_mandatory_policy_accepts_s256(self):
        policy = PkcePolicy.mandatory_s256(version='s256-v9')
        self.set_policy(policy)
        self.request.code_challenge = self.valid_s256_challenge
        self.request.code_challenge_method = S256
        _scopes, info = self.auth.validate_authorization_request(self.request)
        self.assertEqual(info['code_challenge_method'], S256)
        self.assertIs(self.request.pkce_policy, policy)
        self.assertEqual(self.metrics.snapshot(), {})

    def test_optional_policy_allows_missing_challenge_and_plain(self):
        self.set_policy(PkcePolicy.optional())
        _scopes, info = self.auth.validate_authorization_request(self.request)
        self.assertNotIn('code_challenge', info)

        self.request.code_challenge = valid_code_challenge_plain
        self.request.code_challenge_method = PLAIN
        _scopes, info = self.auth.validate_authorization_request(self.request)
        self.assertEqual(info['code_challenge_method'], PLAIN)

    def test_authorization_code_stamps_policy_version(self):
        self.set_policy(PkcePolicy.mandatory_s256(version='stamped-v1'))
        self.request.code_challenge = self.valid_s256_challenge
        self.request.code_challenge_method = S256
        self.auth.validate_authorization_request(self.request)
        grant = self.auth.create_authorization_code(self.request)
        self.assertEqual(grant['pkce_policy_version'], 'stamped-v1')

    def test_legacy_mode_does_not_stamp_policy_version(self):
        # get_pkce_policy returns a non-policy mock -> legacy path.
        self.request.code_challenge = self.valid_s256_challenge
        self.request.code_challenge_method = S256
        self.auth.validate_authorization_request(self.request)
        grant = self.auth.create_authorization_code(self.request)
        self.assertNotIn('pkce_policy_version', grant)

    # Token endpoint -----------------------------------------------------------
    def configure_bound_code(self, method=S256, challenge=None):
        self.mock_validator.get_code_challenge.return_value = \
            challenge or self.valid_s256_challenge
        self.mock_validator.get_code_challenge_method.return_value = method
        self.mock_validator.get_code_challenge_policy_version.return_value = \
            'stamped-v1'
    def test_bound_challenge_still_verified_after_policy_disabled(self):
        # The token-side policy object can even change; a stored challenge
        # remains binding regardless of today's configuration.
        self.set_policy(PkcePolicy.mandatory_s256(version='new-v2'))
        # Store an unrelated S256 challenge so the RFC-example verifier cannot
        # match, proving verification uses the record rather than current config.
        self.configure_bound_code(challenge='a' * 43)
        self.request.code_verifier = valid_code_verifier
        self.assertRaises(
            errors.InvalidGrantError,
            self.auth.validate_token_request, self.request)
        self.assertEqual(self.metrics.get(VERIFIER_MISMATCH), 1)
        self.mock_validator.invalidate_authorization_code.assert_not_called()

    def test_bound_code_missing_verifier_is_counted(self):
        self.set_policy(PkcePolicy.mandatory_s256())
        self.configure_bound_code()
        self.request.code_verifier = None
        self.assertRaises(
            errors.MissingCodeVerifierError,
            self.auth.validate_token_request, self.request)
        self.assertEqual(self.metrics.get(VERIFIER_MISSING), 1)

    def test_bound_code_invalid_verifier_syntax_is_counted(self):
        self.set_policy(PkcePolicy.mandatory_s256())
        self.configure_bound_code(method=PLAIN,
                                  challenge=valid_code_challenge_plain)
        self.request.code_verifier = 'short'
        self.assertRaises(
            errors.InvalidGrantError,
            self.auth.validate_token_request, self.request)
        self.assertEqual(self.metrics.get(VERIFIER_SYNTAX_INVALID), 1)

    def test_bound_code_without_stored_policy_version_is_rejected(self):
        self.set_policy(PkcePolicy.mandatory_s256())
        self.configure_bound_code()
        self.mock_validator.get_code_challenge_policy_version.return_value = \
            None
        self.request.code_verifier = valid_code_verifier
        self.assertRaises(
            errors.InvalidGrantError,
            self.auth.validate_token_request, self.request)
        # The challenge itself is never verified when the binding record is
        # missing, so no verifier mismatch counter is produced.
        self.assertEqual(self.metrics.get(VERIFIER_MISMATCH), 0)

    def test_legacy_code_accepted_within_transition_window(self):
        policy = PkcePolicy.mandatory_s256(
            legacy_no_challenge_accepted_until=self.now +
            datetime.timedelta(minutes=1))
        self.set_policy(policy)
        self.mock_validator.get_code_challenge.return_value = None
        self.request.code_verifier = None
        self.auth.validate_token_request(self.request)
        self.assertEqual(self.metrics.snapshot(), {})

    def test_legacy_code_rejected_after_transition_window(self):
        policy = PkcePolicy.mandatory_s256(
            legacy_no_challenge_accepted_until=self.now -
            datetime.timedelta(minutes=1))
        self.set_policy(policy)
        self.mock_validator.get_code_challenge.return_value = None
        self.request.code_verifier = None
        self.assertRaises(
            errors.PkceTransitionExpiredError,
            self.auth.validate_token_request, self.request)
        self.assertEqual(self.metrics.get(LEGACY_TRANSITION_EXPIRED), 1)

    def test_no_deadline_means_legacy_code_never_accepted(self):
        self.set_policy(PkcePolicy.mandatory_s256())
        self.mock_validator.get_code_challenge.return_value = None
        self.request.code_verifier = None
        self.assertRaises(
            errors.PkceTransitionExpiredError,
            self.auth.validate_token_request, self.request)

    def test_verifier_on_challenge_less_code_is_downgrade(self):
        self.set_policy(PkcePolicy.mandatory_s256(
            legacy_no_challenge_accepted_until=self.now +
            datetime.timedelta(days=1)))
        self.mock_validator.get_code_challenge.return_value = None
        self.request.code_verifier = valid_code_verifier
        self.assertRaises(
            errors.InvalidGrantError,
            self.auth.validate_token_request, self.request)
        self.assertEqual(self.metrics.get(VERIFIER_MISMATCH), 1)
        self.assertEqual(self.metrics.get(LEGACY_TRANSITION_EXPIRED), 0)


class CustomDefaultResponseModeTest(TestCase):
    """A subclass may support another response mode as its default."""

    class FormPostGrant(AuthorizationCodeGrant):
        default_response_mode = 'form_post'

        def prepare_authorization_response(self, request, token, headers, body, status):
            if request.response_mode == 'form_post':
                return headers, 'form_post:%s' % token['code'], 200
            return super().prepare_authorization_response(
                request, token, headers, body, status)

    def setUp(self):
        self.mock_validator = mock.MagicMock()
        self.mock_validator.is_pkce_required.return_value = False
        self.auth = self.FormPostGrant(request_validator=self.mock_validator)
        self.bearer = BearerToken(self.mock_validator)

    def make_request(self, response_mode):
        request = Request('http://a.b/path')
        request.client_id = 'abcdef'
        request.response_type = 'code'
        request.redirect_uri = 'https://a.b/cb'
        request.response_mode = response_mode
        return request

    @mock.patch('oauthlib.common.generate_token')
    def test_default_response_mode(self, generate_token):
        generate_token.return_value = 'abc'
        for response_mode in (None, 'form_post'):
            with self.subTest(response_mode=response_mode):
                _h, b, s = self.auth.create_authorization_response(
                    self.make_request(response_mode), self.bearer)
                self.assertEqual((b, s), ('form_post:abc', 200))

    @mock.patch('oauthlib.common.generate_token')
    def test_other_response_modes(self, generate_token):
        generate_token.return_value = 'abc'
        h, _b, s = self.auth.create_authorization_response(
            self.make_request('query'), self.bearer)
        self.assertEqual(s, 302)
        self.assertURLEqual(h['Location'], 'https://a.b/cb?code=abc')
        self.assertRaises(errors.UnsupportedResponseModeError,
                          self.auth.create_authorization_response,
                          self.make_request('web_message'), self.bearer)
