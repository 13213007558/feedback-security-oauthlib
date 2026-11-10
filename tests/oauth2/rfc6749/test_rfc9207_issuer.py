# -*- coding: utf-8 -*-
"""Round-trip tests for RFC 9207 authorization server issuer identification.

A single backend client talks to two authorization servers. Each server is
configured with its own trusted issuer and appends ``iss`` to authorization
redirects; the client keeps the ``expected_issuer`` in the per-request
authorization transaction and verifies it when parsing the callback.

Standard: https://www.rfc-editor.org/rfc/rfc9207.html#section-2
"""
import urllib.parse as urlparse

from oauthlib.oauth2 import (
    InvalidIssuerError, InvalidRequestError, RequestValidator,
    WebApplicationClient, WebApplicationServer,
)
from oauthlib.oauth2.rfc6749 import errors

from tests.unittest import TestCase


CLIENT_ID = 'shared-client'
REDIRECT_URI = 'https://client.example.com/cb'
ISSUERS = {
    'one': 'https://as-one.example/issuer',
    'two': 'https://as-two.example/issuer',
}
AUTHORIZATION_URIS = {
    'one': 'https://as-one.example/authorize',
    'two': 'https://as-two.example/authorize',
}


class LocalValidator(RequestValidator):
    """In-process validator backing both authorization servers."""

    def __init__(self):
        self.codes = {}
        self.tokens = []

    def validate_client_id(self, client_id, request, *args, **kwargs):
        return client_id == CLIENT_ID

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        return client_id == CLIENT_ID and redirect_uri == REDIRECT_URI

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        return REDIRECT_URI if client_id == CLIENT_ID else None

    def validate_response_type(self, client_id, response_type, client, request, *args, **kwargs):
        return client_id == CLIENT_ID and response_type == 'code'

    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        return client_id == CLIENT_ID

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        return ['profile']

    def is_pkce_required(self, client_id, request):
        return False

    def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        self.codes[code['code']] = {
            'client_id': client_id,
            'redirect_uri': request.redirect_uri,
            'scopes': request.scopes,
        }

    def client_authentication_required(self, request, *args, **kwargs):
        return False

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        if client_id != CLIENT_ID:
            return False
        request.client = type('Client', (), {'client_id': client_id})()
        return True

    def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
        return grant_type == 'authorization_code'

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        saved = self.codes.get(code)
        if not saved or saved['client_id'] != client_id:
            return False
        request.scopes = saved['scopes']
        request.user = 'resource-owner'
        return True

    def confirm_redirect_uri(self, client_id, code, redirect_uri, client, request, *args, **kwargs):
        saved = self.codes.get(code)
        return bool(saved) and saved['redirect_uri'] == redirect_uri

    def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
        self.codes.pop(code, None)

    def save_bearer_token(self, token, request, *args, **kwargs):
        self.tokens.append(token)


class RFC9207RoundTripTest(TestCase):

    def setUp(self):
        self.validator = LocalValidator()
        self.servers = {
            name: WebApplicationServer(self.validator, issuer=issuer)
            for name, issuer in ISSUERS.items()
        }
        self.client = WebApplicationClient(CLIENT_ID)

    def _start_transaction(self, name, state):
        """Build the authorization request and persist per-transaction data."""
        uri = self.client.prepare_request_uri(
            AUTHORIZATION_URIS[name],
            redirect_uri=REDIRECT_URI,
            scope=['profile'],
            state=state,
        )
        return {
            'state': state,
            # The issuer selected for THIS transaction is stored beside the
            # state and retrieved on callback; the shared client keeps none.
            'expected_issuer': ISSUERS[name],
            'authorization_uri': uri,
        }

    def _authorize(self, name, transaction):
        headers, _body, status = self.servers[name].create_authorization_response(
            transaction['authorization_uri'], scopes=['profile'])
        self.assertEqual(status, 302)
        return headers['Location']

    def _callback(self, transaction, location, state=None, expected_issuer=None):
        return self.client.parse_request_uri_response(
            location,
            state=state if state is not None else transaction['state'],
            expected_issuer=(expected_issuer if expected_issuer is not None
                             else transaction['expected_issuer']),
        )

    def test_issuer_configuration_must_be_https_without_query_or_fragment(self):
        for invalid in (
            'http://as.example/issuer',
            'https://as.example/issuer?x=1',
            'https://as.example/issuer#f',
            'not-an-https-url',
        ):
            with self.subTest(invalid=invalid):
                self.assertRaises(
                    ValueError, WebApplicationServer, self.validator, issuer=invalid)

    def test_success_round_trip_for_each_issuer(self):
        for name in ('one', 'two'):
            transaction = self._start_transaction(name, 'state-' + name)
            location = self._authorize(name, transaction)
            params = dict(urlparse.parse_qsl(urlparse.urlparse(location).query))
            self.assertEqual(params['iss'], ISSUERS[name])
            response = self._callback(transaction, location)
            self.assertEqual(response['iss'], ISSUERS[name])
            self.assertTrue(response['code'])
            self.assertEqual(self.client.code, response['code'])

    def test_two_issuers_interleaved_callbacks(self):
        tx_one = self._start_transaction('one', 'state-one')
        tx_two = self._start_transaction('two', 'state-two')
        # Server one responds first, then server two; parsing is interleaved.
        location_one = self._authorize('one', tx_one)
        location_two = self._authorize('two', tx_two)
        response_two = self._callback(tx_two, location_two)
        response_one = self._callback(tx_one, location_one)
        self.assertEqual(response_one['iss'], ISSUERS['one'])
        self.assertEqual(response_two['iss'], ISSUERS['two'])
        # No issuer lingers as shared client state.
        self.assertFalse(hasattr(self.client, 'expected_issuer'))
        self.assertFalse(hasattr(self.client, 'issuer'))

    def test_authorization_denied_keeps_issuer_and_raises_oauth_error(self):
        self.validator.validate_scopes = lambda *a, **k: False
        tx = self._start_transaction('one', 'state-denied')
        headers, _body, status = self.servers['one'].create_authorization_response(
            tx['authorization_uri'], scopes=['profile'])
        self.assertEqual(status, 302)
        params = dict(urlparse.parse_qsl(urlparse.urlparse(headers['Location']).query))
        self.assertEqual(params['error'], 'invalid_scope')
        self.assertEqual(params['iss'], ISSUERS['one'])
        # Source and state are validated first, then the OAuth error surfaces.
        with self.assertRaises(errors.InvalidScopeError):
            self._callback(tx, headers['Location'])
        self.assertIsNone(self.client.code)

    def test_spoofed_other_issuer_rejected(self):
        tx = self._start_transaction('one', 'state-spoof')
        location = self._authorize('one', tx)
        spoofed = location.replace(
            urlparse.quote(ISSUERS['one'], safe=''),
            urlparse.quote(ISSUERS['two'], safe=''))
        # The spoofed value really is the other (otherwise valid) issuer.
        self.assertIn(urlparse.quote(ISSUERS['two'], safe=''), spoofed)
        with self.assertRaises(InvalidIssuerError):
            self._callback(tx, spoofed)
        self.assertIsNone(self.client.code)

    def test_response_from_other_server_rejected_in_transaction(self):
        # A genuine callback produced by server two cannot be accepted by a
        # transaction started against server one.
        tx_one = self._start_transaction('one', 'state-one')
        location_two = self._authorize('two', self._start_transaction('two', 'state-two'))
        with self.assertRaises(InvalidIssuerError):
            self.client.parse_request_uri_response(
                location_two, state=tx_one['state'],
                expected_issuer=tx_one['expected_issuer'])

    def test_duplicate_parameters_rejected(self):
        tx = self._start_transaction('one', 'state-dup')
        location = self._authorize('one', tx)
        actual_code = dict(urlparse.parse_qsl(
            urlparse.urlparse(location).query))['code']
        encoded_iss = urlparse.quote(ISSUERS['one'], safe='')
        cases = {
            'code': ('code=X&code=Y', 'code=' + actual_code),
            'state': ('state=x&state=y', 'state=state-dup'),
            'iss': (
                'iss=' + encoded_iss + '&iss=' + encoded_iss,
                'iss=' + encoded_iss),
        }
        for name, (replacement, original) in cases.items():
            tampered = location.replace(original, replacement)
            with self.subTest(name=name):
                raised = self._expect_raise(tampered, tx)
                self.assertIsInstance(raised, (InvalidIssuerError, InvalidRequestError))
                self.assertIsNone(self.client.code)

    def test_encoding_differences_are_exact_string_mismatches(self):
        tx = self._start_transaction('one', 'state-encoding')
        location = self._authorize('one', tx)
        base = urlparse.quote(ISSUERS['one'], safe='')
        variants = (
            ('double encoded', base.replace('%', '%25')),
            ('extra trailing path slash',
             urlparse.quote(ISSUERS['one'] + '/', safe='')),
            ('upper case scheme',
             urlparse.quote('HTTPS://as-one.example/issuer', safe='')),
        )
        for name, encoded in variants:
            tampered = location.replace(base, encoded)
            with self.subTest(name=name):
                self.assertIsInstance(
                    self._expect_raise(tampered, tx), InvalidIssuerError)

    def _expect_raise(self, location, transaction):
        try:
            self._callback(transaction, location)
        except Exception as exc:  # noqa: BLE001 - asserted by the caller
            return exc
        self.fail('expected the callback to be rejected: %s' % location)

    def test_illegal_redirect_uri_is_fatal_and_never_redirected(self):
        validator = LocalValidator()
        server = WebApplicationServer(validator, issuer=ISSUERS['one'])
        illegal_uri = (
            'https://as-one.example/authorize?response_type=code'
            '&client_id=' + CLIENT_ID
            + '&redirect_uri=https%3A%2F%2Fevil.example%2Fcb'
            + '&state=state-illegal')
        with self.assertRaises(errors.MismatchingRedirectURIError):
            server.create_authorization_response(
                illegal_uri, scopes=['profile'])
        # No grant (and thus no code) was created for the bad redirect.
        self.assertEqual(validator.codes, {})

    def test_issuer_is_not_taken_from_request_parameters(self):
        tx = self._start_transaction('one', 'state-injected')
        injected = tx['authorization_uri'] + '&iss=' + urlparse.quote(ISSUERS['two'], safe='')
        headers, _body, status = self.servers['one'].create_authorization_response(
            injected, scopes=['profile'])
        self.assertEqual(status, 302)
        params = dict(urlparse.parse_qsl(urlparse.urlparse(headers['Location']).query))
        self.assertEqual(params['iss'], ISSUERS['one'])
        response = self._callback(tx, headers['Location'])
        self.assertEqual(response['iss'], ISSUERS['one'])
