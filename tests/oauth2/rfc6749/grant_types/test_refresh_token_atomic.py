# -*- coding: utf-8 -*-
import json
import threading
from unittest import mock

from oauthlib.common import Request
from oauthlib.oauth2.rfc6749 import errors
from oauthlib.oauth2.rfc6749.grant_types import RefreshTokenGrant
from oauthlib.oauth2.rfc6749.request_validator import (
    AtomicRefreshTokenStore,
    RequestValidator,
)
from oauthlib.oauth2.rfc6749.tokens import BearerToken

from tests.unittest import TestCase


class Client:
    def __init__(self, client_id):
        self.client_id = client_id


class InMemoryAtomicStore(RequestValidator, AtomicRefreshTokenStore):
    """Thread-safe in-memory store implementing the atomic contract.

    Only suitable for a single process; multi-process deployments must
    push the same guarantees down into shared storage.
    """

    def __init__(self, after_validation_hook=None):
        self._lock = threading.Lock()
        self._tokens = {}
        self.after_validation_hook = after_validation_hook

    def add_refresh_token(self, token, client_id, user, family, scopes):
        self._tokens[token] = {
            'client_id': client_id, 'user': user, 'family': family,
            'scopes': list(scopes), 'consumed': False, 'revoked': False,
        }

    def client_authentication_required(self, request):
        return False

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        request.client = Client(client_id)
        return True

    def validate_grant_type(self, client_id, grant_type, client, request):
        return grant_type == 'refresh_token'

    def validate_refresh_token(self, refresh_token, client, request):
        with self._lock:
            row = self._tokens.get(refresh_token)
            return bool(row and row['client_id'] == client.client_id
                        and not row['consumed'] and not row['revoked'])

    def get_original_scopes(self, refresh_token, request):
        row = self._tokens.get(refresh_token)
        return list(row['scopes']) if row else []

    def rotate_refresh_token(self, request):
        return True

    def save_token(self, token, request):
        raise AssertionError('save_token must not be called in atomic mode')

    def rotate_refresh_token_atomic(self, request, token_factory):
        if self.after_validation_hook:
            self.after_validation_hook()
        with self._lock:
            row = self._tokens.get(request.refresh_token)
            if (row is None or row['revoked']
                    or row['client_id'] != request.client_id):
                raise errors.InvalidGrantError(request=request)
            if row['consumed']:
                # Replay: revoke this token family, and only this family.
                for other in self._tokens.values():
                    if other['family'] == row['family']:
                        other['revoked'] = True
                raise errors.InvalidGrantError(request=request)
            row['consumed'] = True
            try:
                token = token_factory(request)
            except Exception:
                # Roll back: never leave a consumed token without successor.
                row['consumed'] = False
                raise
            self._tokens[token['refresh_token']] = {
                'client_id': row['client_id'], 'user': row['user'],
                'family': row['family'], 'scopes': list(row['scopes']),
                'consumed': False, 'revoked': False,
            }
            return token


def make_request(refresh_token, client_id):
    request = Request('http://a.b/token')
    request.grant_type = 'refresh_token'
    request.refresh_token = refresh_token
    request.client_id = client_id
    request.client = Client(client_id)
    return request


class AtomicRefreshTokenRotationTest(TestCase):

    def setUp(self):
        self.store = InMemoryAtomicStore()
        self.store.add_refresh_token(
            'rt-alice-1', 'client-a', 'alice', 'fam-alice', ['read'])
        self.store.add_refresh_token(
            'rt-bob-1', 'client-b', 'bob', 'fam-bob', ['read'])
        self.grant = RefreshTokenGrant(request_validator=self.store)
        self.bearer = BearerToken(request_validator=self.store)

    def refresh(self, refresh_token='rt-alice-1', client_id='client-a'):
        headers, body, status = self.grant.create_token_response(
            make_request(refresh_token, client_id), self.bearer)
        return status, json.loads(body)

    def test_atomic_rotation_success(self):
        status, body = self.refresh()
        self.assertEqual(status, 200)
        self.assertIn('access_token', body)
        self.assertIn('refresh_token', body)
        old = self.store._tokens['rt-alice-1']
        new = self.store._tokens[body['refresh_token']]
        self.assertTrue(old['consumed'])
        self.assertFalse(old['revoked'])
        self.assertEqual(new['family'], 'fam-alice')
        self.assertFalse(new['consumed'])

    def test_concurrent_rotation_single_winner(self):
        barrier = threading.Barrier(2)
        self.store.after_validation_hook = barrier.wait
        results = []

        def worker():
            results.append(self.refresh())

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        statuses = sorted(status for status, _ in results)
        self.assertEqual(statuses, [200, 400])
        failure = next(body for status, body in results if status == 400)
        self.assertEqual(failure['error'], 'invalid_grant')

        # The rejection must not leak family identifiers or token plaintext.
        rejection = json.dumps(failure)
        self.assertNotIn('fam-alice', rejection)
        self.assertNotIn('rt-alice-1', rejection)

        # Old token consumed, successor persisted, whole family revoked by
        # the replay policy; the other user's tokens are untouched.
        self.assertTrue(self.store._tokens['rt-alice-1']['consumed'])
        alice_family = [row for row in self.store._tokens.values()
                        if row['family'] == 'fam-alice']
        self.assertEqual(len(alice_family), 2)
        self.assertTrue(all(row['revoked'] for row in alice_family))
        bob = self.store._tokens['rt-bob-1']
        self.assertFalse(bob['consumed'])
        self.assertFalse(bob['revoked'])

    def test_replay_of_consumed_token_revokes_family(self):
        status, body = self.refresh()
        self.assertEqual(status, 200)
        status, body = self.refresh()  # reuse the same old token
        self.assertEqual(status, 400)
        self.assertEqual(body['error'], 'invalid_grant')
        alice_family = [row for row in self.store._tokens.values()
                        if row['family'] == 'fam-alice']
        self.assertTrue(all(row['revoked'] for row in alice_family))
        self.assertFalse(self.store._tokens['rt-bob-1']['revoked'])

    def test_token_modifier_failure_rolls_back(self):
        def broken_modifier(token, token_handler, request):
            raise RuntimeError('modifier blew up')

        broken_grant = RefreshTokenGrant(request_validator=self.store)
        broken_grant.register_token_modifier(broken_modifier)
        with self.assertRaises(RuntimeError):
            broken_grant.create_token_response(
                make_request('rt-alice-1', 'client-a'), self.bearer)

        # No consumed-without-successor state, nothing persisted.
        self.assertFalse(self.store._tokens['rt-alice-1']['consumed'])
        self.assertEqual(len(self.store._tokens), 2)

        # The old token is still usable after the rolled-back attempt.
        status, body = self.refresh()
        self.assertEqual(status, 200)

    def test_generator_failure_rolls_back(self):
        def broken_generator(request):
            raise RuntimeError('generator blew up')

        bearer = BearerToken(request_validator=self.store,
                             refresh_token_generator=broken_generator)
        with self.assertRaises(RuntimeError):
            self.grant.create_token_response(
                make_request('rt-alice-1', 'client-a'), bearer)
        self.assertFalse(self.store._tokens['rt-alice-1']['consumed'])
        self.assertEqual(len(self.store._tokens), 2)

    def test_unknown_token_rejected(self):
        status, body = self.refresh('rt-unknown', 'client-a')
        self.assertEqual(status, 400)
        self.assertEqual(body['error'], 'invalid_grant')

    def test_wrong_client_rejected(self):
        status, body = self.refresh('rt-alice-1', 'client-b')
        self.assertEqual(status, 400)
        self.assertEqual(body['error'], 'invalid_grant')
        self.assertFalse(self.store._tokens['rt-alice-1']['consumed'])


class IncompleteAtomicStore(RequestValidator, AtomicRefreshTokenStore):
    """Opts into atomic mode but does not implement the contract."""

    def client_authentication_required(self, request):
        return False

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        request.client = Client(client_id)
        return True

    def validate_grant_type(self, client_id, grant_type, client, request):
        return True

    def validate_refresh_token(self, refresh_token, client, request):
        return True

    def get_original_scopes(self, refresh_token, request):
        return ['read']


class AtomicContractOptInTest(TestCase):

    def test_missing_implementation_raises(self):
        grant = RefreshTokenGrant(request_validator=IncompleteAtomicStore())
        bearer = BearerToken(request_validator=grant.request_validator)
        with self.assertRaises(NotImplementedError):
            grant.create_token_response(
                make_request('rt-1', 'client-a'), bearer)

    def test_legacy_validator_still_uses_save_token(self):
        validator = mock.MagicMock()
        validator.get_original_scopes.return_value = ['read']
        grant = RefreshTokenGrant(request_validator=validator)
        bearer = BearerToken(request_validator=validator)
        headers, body, status = grant.create_token_response(
            make_request('rt-1', 'client-a'), bearer)
        self.assertEqual(status, 200)
        self.assertEqual(validator.save_token.call_count, 1)
