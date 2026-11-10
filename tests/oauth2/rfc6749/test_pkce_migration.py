# -*- coding: utf-8 -*-
"""End-to-end tests for per-client, phased mandatory-S256 PKCE migration.

The sequence "issue code -> switch policy -> exchange code -> transition
expires" is driven by an explicit, controllable clock against an in-memory
storage backend, so nothing here depends on wall-clock timing or on test
doubles for the grant type itself.
"""
import datetime
import hashlib
import base64
import logging
from contextlib import contextmanager

from oauthlib.common import Request
from oauthlib.oauth2 import (
    AuthorizationCodeGrant,
    BearerToken,
    CHALLENGE_METHOD_DISALLOWED,
    CHALLENGE_METHOD_UNKNOWN,
    CHALLENGE_MISSING,
    CHALLENGE_SYNTAX_INVALID,
    LEGACY_TRANSITION_EXPIRED,
    PkcePolicy,
    PkceRejectionMetrics,
    PkceTransitionExpiredError,
    VERIFIER_MISMATCH,
    VERIFIER_MISSING,
)
from oauthlib.oauth2.rfc6749 import errors
from oauthlib.oauth2.rfc6749.request_validator import RequestValidator

from tests.unittest import TestCase

REDIRECT_URI = 'https://client.example/cb'
CLIENT_A = 'client-a'
CLIENT_B = 'client-b'

VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
S256_CHALLENGE = base64.urlsafe_b64encode(
    hashlib.sha256(VERIFIER.encode()).digest()).decode().rstrip('=')
# A second valid verifier/challenge pair used to prove isolation.
VERIFIER_B = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV'
S256_CHALLENGE_B = base64.urlsafe_b64encode(
    hashlib.sha256(VERIFIER_B.encode()).digest()).decode().rstrip('=')


class ControllableClock:
    """Mutable clock passed to the grant for transition-deadline checks."""

    def __init__(self, start):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, **delta):
        self.now += datetime.timedelta(**delta)


class InMemoryPkceValidator(RequestValidator):
    """Storage-backed validator implementing the migration interfaces."""

    def __init__(self, policies):
        # client_id -> PkcePolicy or None. Mutated mid-sequence to simulate
        # a policy switch without touching already-stored codes.
        self.policies = dict(policies)
        self.codes = {}
        self.invalidated = set()
        self.tokens = []

    # Client / redirect plumbing ------------------------------------------------
    def validate_client_id(self, client_id, request, *args, **kwargs):
        request.client = type('Client', (), {'client_id': client_id})()
        return client_id in self.policies

    def validate_redirect_uri(self, client_id, redirect_uri, request,
                              *args, **kwargs):
        return redirect_uri == REDIRECT_URI

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        return REDIRECT_URI

    def validate_response_type(self, client_id, response_type, client, request,
                                *args, **kwargs):
        return response_type == 'code'

    def validate_scopes(self, client_id, scopes, client, request,
                        *args, **kwargs):
        return True

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        return ['read']

    def validate_grant_type(self, client_id, grant_type, client, request,
                            *args, **kwargs):
        return grant_type == 'authorization_code'

    def authenticate_client(self, request, *args, **kwargs):
        request.client = type('Client', (), {
            'client_id': request.client_id})()
        return True

    def confirm_redirect_uri(self, client_id, code, redirect_uri, client,
                             request, *args, **kwargs):
        return self.codes.get(code, {}).get('redirect_uri') == redirect_uri

    # Migration policy interfaces ----------------------------------------------
    def get_pkce_policy(self, client_id, request):
        return self.policies.get(client_id)

    def get_code_challenge_policy_version(self, code, request):
        return self.codes.get(code, {}).get('pkce_policy_version')

    def get_code_challenge(self, code, request):
        return self.codes.get(code, {}).get('code_challenge')

    def get_code_challenge_method(self, code, request):
        return self.codes.get(code, {}).get('code_challenge_method')

    # Storage -------------------------------------------------------------------
    def save_authorization_code(self, client_id, code, request, *args,
                                **kwargs):
        self.codes[code['code']] = {
            'client_id': client_id,
            'redirect_uri': request.redirect_uri,
            'scopes': list(request.scopes or []),
            'user': 'resource-owner',
            'code_challenge': request.code_challenge,
            'code_challenge_method': request.code_challenge_method,
            'pkce_policy_version': code.get('pkce_policy_version'),
        }

    def validate_code(self, client_id, code, client, request, *args,
                      **kwargs):
        if code in self.invalidated:
            return False
        record = self.codes.get(code)
        if record is None or record['client_id'] != client_id:
            return False
        request.user = record['user']
        request.scopes = record['scopes']
        request.code_challenge = record['code_challenge']
        request.code_challenge_method = record['code_challenge_method']
        return True

    def invalidate_authorization_code(self, client_id, code, request,
                                      *args, **kwargs):
        self.invalidated.add(code)

    def save_bearer_token(self, token, request, *args, **kwargs):
        self.tokens.append(dict(token))
        return REDIRECT_URI


@contextmanager
def capture_logs(logger_name):
    records = []
    handler = logging.Handler()
    handler.emit = records.append
    logger = logging.getLogger(logger_name)
    logger.addHandler(handler)
    previous_level = logger.level
    logger.setLevel(logging.DEBUG)
    try:
        yield records
    finally:
        logger.setLevel(previous_level)
        logger.removeHandler(handler)


class PkceMigrationSequenceTest(TestCase):

    def setUp(self):
        self.start = datetime.datetime(2026, 11, 10, 12, 0,
                                       tzinfo=datetime.timezone.utc)
        self.clock = ControllableClock(self.start)
        self.metrics = PkceRejectionMetrics()
        # Client A starts in the optional observation phase; client B is not
        # enrolled at all and must keep the legacy behaviour throughout.
        self.validator = InMemoryPkceValidator({
            CLIENT_A: PkcePolicy.optional(
                version='a-optional-v1',
                legacy_no_challenge_accepted_until=self.start +
                datetime.timedelta(days=1)),
            CLIENT_B: None,
        })
        self.grant = AuthorizationCodeGrant(
            request_validator=self.validator,
            pkce_metrics=self.metrics,
            clock=self.clock)
        self.bearer = BearerToken(self.validator)

    def auth_request(self, client_id, challenge=None, method=None,
                     verifier=None):
        uri = 'https://as.example/authorize?response_type=code&client_id=%s' \
              '&redirect_uri=%s' % (client_id, REDIRECT_URI)
        request = Request(uri)
        request.scopes = ['read']
        if challenge is not None:
            request.code_challenge = challenge
        if method is not None:
            request.code_challenge_method = method
        return request

    def token_request(self, client_id, code, verifier=None):
        request = Request(
            'https://as.example/token',
            http_method='POST',
            body='grant_type=authorization_code&client_id=%s&code=%s'
                 '&redirect_uri=%s' % (client_id, code, REDIRECT_URI))
        request.scopes = ['read']
        if verifier is not None:
            request.code_verifier = verifier
        return request

    def issue_code(self, client_id, challenge=None, method=None):
        headers, _body, status = self.grant.create_authorization_response(
            self.auth_request(client_id, challenge, method), self.bearer)
        self.assertEqual(status, 302)
        return dict(Request(headers['Location']).uri_query_params)['code']

    def exchange(self, client_id, code, verifier=None):
        return self.grant.create_token_response(
            self.token_request(client_id, code, verifier), self.bearer)

    def test_full_migration_sequence_with_policy_switch_and_expiry(self):
        # 1. Optional phase: a legacy code without any challenge is issued.
        legacy_code = self.issue_code(CLIENT_A)
        legacy_record = self.validator.codes[legacy_code]
        self.assertIsNone(legacy_record['code_challenge'])
        self.assertIsNone(legacy_record['pkce_policy_version'])

        # 2. Still in the optional phase, an S256-bound code is issued and the
        #    policy version is stored with it.
        bound_code = self.issue_code(CLIENT_A, S256_CHALLENGE, 'S256')
        self.assertEqual(
            self.validator.codes[bound_code]['code_challenge'], S256_CHALLENGE)
        self.assertEqual(
            self.validator.codes[bound_code]['code_challenge_method'], 'S256')
        self.assertEqual(
            self.validator.codes[bound_code]['pkce_policy_version'],
            'a-optional-v1')

        # 3. Switch client A to mandatory S256. Already-stored codes are
        #    untouched; the new policy only governs new requests.
        self.validator.policies[CLIENT_A] = PkcePolicy.mandatory_s256(
            version='a-s256-v2',
            legacy_no_challenge_accepted_until=self.start +
            datetime.timedelta(days=1))

        # 4. A new request without a challenge is rejected before any code is
        #    saved.
        before = len(self.validator.codes)
        with self.assertRaises(errors.MissingCodeChallengeError):
            self.grant.validate_authorization_request(
                self.auth_request(CLIENT_A))
        self.assertEqual(len(self.validator.codes), before)
        self.assertEqual(self.metrics.get(CHALLENGE_MISSING), 1)

        # 5. plain is a downgrade under the mandatory policy, even when the
        #    method is omitted (RFC 7636 would default it to plain).
        with self.assertRaises(errors.UnsupportedCodeChallengeMethodError):
            self.grant.validate_authorization_request(
                self.auth_request(CLIENT_A, VERIFIER, 'plain'))
        with self.assertRaises(errors.UnsupportedCodeChallengeMethodError):
            self.grant.validate_authorization_request(
                self.auth_request(CLIENT_A, S256_CHALLENGE))
        self.assertEqual(self.metrics.get(CHALLENGE_METHOD_DISALLOWED), 2)

        # 6. Unknown method and illegal challenge length are also rejected.
        with self.assertRaises(errors.UnsupportedCodeChallengeMethodError):
            self.grant.validate_authorization_request(
                self.auth_request(CLIENT_A, S256_CHALLENGE, 'rot13'))
        self.assertEqual(self.metrics.get(CHALLENGE_METHOD_UNKNOWN), 1)
        with self.assertRaises(errors.InvalidRequestError):
            self.grant.validate_authorization_request(
                self.auth_request(CLIENT_A, 'too-short', 'S256'))
        self.assertEqual(self.metrics.get(CHALLENGE_SYNTAX_INVALID), 1)

        # 7. A fresh S256 code under the new policy carries the new version.
        new_code = self.issue_code(CLIENT_A, S256_CHALLENGE, 'S256')
        self.assertEqual(
            self.validator.codes[new_code]['pkce_policy_version'],
            'a-s256-v2')

        # 8. Switching the policy off again must not bypass the challenge
        #    bound to the code issued while it was on.
        self.validator.policies[CLIENT_A] = None
        headers, body, status = self.exchange(CLIENT_A, bound_code,
                                              verifier=VERIFIER)
        self.assertEqual(status, 200, body)
        # Then re-enable and verify the opposite direction stays bound too.
        self.validator.policies[CLIENT_A] = PkcePolicy.mandatory_s256(
            version='a-s256-v2',
            legacy_no_challenge_accepted_until=self.start +
            datetime.timedelta(days=1))

        # 9. Wrong verifier rejects and leaves the code usable afterwards:
        #    the failed attempt must not consume or invalidate the code.
        headers, body, status = self.exchange(
            CLIENT_A, new_code, verifier=VERIFIER_B)
        self.assertEqual(status, 400)
        self.assertIn('invalid_grant', body)
        self.assertNotIn(new_code, self.validator.invalidated)
        self.assertEqual(self.metrics.get(VERIFIER_MISMATCH), 1)
        headers, body, status = self.exchange(
            CLIENT_A, new_code, verifier=VERIFIER)
        self.assertEqual(status, 200, body)
        self.assertIn(new_code, self.validator.invalidated)

        # 10. The legacy, challenge-less code works inside the transition
        #     window, including without any verifier.
        headers, body, status = self.exchange(CLIENT_A, legacy_code)
        self.assertEqual(status, 200, body)
        # It was a one-time use code.
        headers, body, status = self.exchange(CLIENT_A, legacy_code)
        self.assertEqual(status, 400)

        # 11. After the transition deadline, a challenge-less code issued
        #     before enrollment is rejected rather than accepted forever.
        #     The mandatory policy refuses issuing such a code now, so the
        #     pre-enrollment records are inserted through storage directly.
        pre_enrollment = 'pre-enrollment-code'
        self.validator.codes[pre_enrollment] = {
            'client_id': CLIENT_A,
            'redirect_uri': REDIRECT_URI,
            'scopes': ['read'],
            'user': 'resource-owner',
            'code_challenge': None,
            'code_challenge_method': None,
            'pkce_policy_version': None,
        }
        headers, body, status = self.exchange(CLIENT_A, pre_enrollment)
        self.assertEqual(status, 200, body)
        # A second, still-unused record is needed after the clock moves,
        # because the first exchange consumed its code.
        expired_legacy = 'expired-legacy-code'
        self.validator.codes[expired_legacy] = dict(
            self.validator.codes[pre_enrollment])
        self.clock.advance(days=2)
        headers, body, status = self.exchange(CLIENT_A, expired_legacy)
        self.assertEqual(status, 400)
        self.assertIn('invalid_grant', body)
        self.assertEqual(self.metrics.get(LEGACY_TRANSITION_EXPIRED), 1)
        with self.assertRaises(PkceTransitionExpiredError):
            self.grant.validate_token_request(
                self.token_request(CLIENT_A, expired_legacy))
        # A verifier on a challenge-less code is still a downgrade, not a
        # transition acceptance.
        self.assertRaises(
            errors.InvalidGrantError,
            self.grant.validate_token_request,
            self.token_request(CLIENT_A, expired_legacy, verifier=VERIFIER))
        self.assertEqual(self.metrics.get(VERIFIER_MISMATCH), 2)

    def test_client_policies_are_isolated(self):
        # Enroll A in mandatory S256; B remains on legacy optional PKCE.
        self.validator.policies[CLIENT_A] = PkcePolicy.mandatory_s256(
            version='a-s256-v2',
            legacy_no_challenge_accepted_until=self.start +
            datetime.timedelta(hours=1))

        with self.assertRaises(errors.MissingCodeChallengeError):
            self.grant.validate_authorization_request(
                self.auth_request(CLIENT_A))
        # From here on only client B traffic is exercised; its legacy path
        # must never touch the policy metrics.
        self.metrics.reset()

        # Client B can still issue a code with no challenge at all...
        code_b = self.issue_code(CLIENT_B)
        self.assertIsNone(
            self.validator.codes[code_b]['code_challenge'])
        # ...and exchange it, while A's mandatory policy never touches B.
        headers, body, status = self.exchange(CLIENT_B, code_b)
        self.assertEqual(status, 200, body)

        # A challenge sent by B keeps working under the legacy path.
        code_b_pkce = self.issue_code(
            CLIENT_B, S256_CHALLENGE_B, 'S256')
        headers, body, status = self.exchange(
            CLIENT_B, code_b_pkce, verifier=VERIFIER_B)
        self.assertEqual(status, 200, body)

        # No policy rejection was ever recorded on B's traffic.
        self.assertEqual(self.metrics.snapshot(), {})

    def test_missing_verifier_for_bound_code_is_counted(self):
        self.validator.policies[CLIENT_A] = PkcePolicy.mandatory_s256(
            version='a-s256-v2')
        code = self.issue_code(CLIENT_A, S256_CHALLENGE, 'S256')
        headers, body, status = self.exchange(CLIENT_A, code)
        self.assertEqual(status, 400)
        self.assertIn('invalid_request', body)
        self.assertEqual(self.metrics.get(VERIFIER_MISSING), 1)
        self.assertNotIn(code, self.validator.invalidated)

    def test_unenrolled_integration_keeps_legacy_behavior(self):
        # No policy, no metrics wiring beyond the default empty instance:
        # is_pkce_required stays the single switch and defaults to False.
        plain_grant = AuthorizationCodeGrant(
            request_validator=self.validator, clock=self.clock)
        code = plain_grant.create_authorization_response(
            self.auth_request(CLIENT_B), self.bearer)
        headers, _body, status = code
        self.assertEqual(status, 302)
        issued = dict(Request(headers['Location']).uri_query_params)['code']
        headers, body, status = plain_grant.create_token_response(
            self.token_request(CLIENT_B, issued), self.bearer)
        self.assertEqual(status, 200, body)
        self.assertEqual(plain_grant.pkce_metrics.snapshot(), {})

    def test_policy_rejects_invalid_construction(self):
        with self.assertRaises(ValueError):
            PkcePolicy(require_challenge=True, allowed_methods=('plain',))
        with self.assertRaises(ValueError):
            PkcePolicy(require_challenge=True, allowed_methods=())
        with self.assertRaises(ValueError):
            PkcePolicy(require_challenge=True, allowed_methods=('rot13',))
        with self.assertRaises(ValueError):
            PkcePolicy(require_challenge=True, version='')

    def test_naive_deadline_is_interpreted_as_utc(self):
        naive = datetime.datetime(2026, 11, 11, 12, 0)
        policy = PkcePolicy.mandatory_s256(
            legacy_no_challenge_accepted_until=naive)
        self.assertEqual(
            policy.legacy_no_challenge_accepted_until.tzinfo,
            datetime.timezone.utc)

    def test_rejection_logs_and_metrics_never_contain_secrets(self):
        self.validator.policies[CLIENT_A] = PkcePolicy.mandatory_s256(
            version='a-s256-v2')
        with capture_logs('oauthlib.oauth2.rfc6749.pkce') as records:
            with self.assertRaises(errors.MissingCodeChallengeError):
                self.grant.validate_authorization_request(
                    self.auth_request(CLIENT_A))
            with self.assertRaises(errors.InvalidRequestError):
                self.grant.validate_authorization_request(
                    self.auth_request(CLIENT_A, S256_CHALLENGE + 'x',
                                      'S256'))
            logged = '\n'.join(r.getMessage() for r in records)
        # Only reason codes and the public client id are observable.
        self.assertIn(CHALLENGE_MISSING, logged)
        self.assertIn(CLIENT_A, logged)
        self.assertNotIn(S256_CHALLENGE, logged)
        self.assertNotIn(VERIFIER, logged)
        # Counters hold reason strings only, never request material.
        for reason in self.metrics.snapshot():
            self.assertIsInstance(reason, str)
            self.assertNotIn(S256_CHALLENGE, reason)
            self.assertNotIn(VERIFIER, reason)

    def test_saved_grant_logs_are_sanitized(self):
        self.validator.policies[CLIENT_A] = PkcePolicy.optional(
            version='a-optional-v1')
        with capture_logs(
                'oauthlib.oauth2.rfc6749.grant_types.authorization_code') \
                as records:
            self.issue_code(CLIENT_A, S256_CHALLENGE, 'S256')
            logged = '\n'.join(r.getMessage() for r in records)
        # The raw authorization code must not appear in any log line.
        for code in self.validator.codes:
            self.assertNotIn(code, logged)
        self.assertNotIn(S256_CHALLENGE, logged)
