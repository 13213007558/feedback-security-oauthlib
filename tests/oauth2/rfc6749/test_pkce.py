# -*- coding: utf-8 -*-
import datetime

from oauthlib.oauth2.rfc6749.pkce import (
    CHALLENGE_MISSING,
    LEGACY_TRANSITION_EXPIRED,
    PLAIN,
    S256,
    PkcePolicy,
    PkceRejectionMetrics,
    utcnow,
)

from tests.unittest import TestCase


class PkcePolicyTest(TestCase):

    def test_mandatory_s256_constructor(self):
        policy = PkcePolicy.mandatory_s256(version='v2')
        self.assertTrue(policy.require_challenge)
        self.assertEqual(policy.allowed_methods, (S256,))
        self.assertEqual(policy.version, 'v2')
        self.assertFalse(policy.allows_method(PLAIN))
        self.assertTrue(policy.allows_method(S256))

    def test_optional_constructor_allows_plain(self):
        policy = PkcePolicy.optional()
        self.assertFalse(policy.require_challenge)
        self.assertEqual(policy.allowed_methods, (PLAIN, S256))
        self.assertTrue(policy.allows_method(PLAIN))

    def test_policy_is_immutable(self):
        policy = PkcePolicy.mandatory_s256()
        with self.assertRaises(Exception):
            policy.version = 'other'

    def test_s256_must_remain_available(self):
        with self.assertRaises(ValueError):
            PkcePolicy(require_challenge=True, allowed_methods=(PLAIN,))

    def test_unknown_method_rejected(self):
        with self.assertRaises(ValueError):
            PkcePolicy(require_challenge=True, allowed_methods=('rot13',))

    def test_empty_methods_and_version_rejected(self):
        with self.assertRaises(ValueError):
            PkcePolicy(require_challenge=False, allowed_methods=())
        with self.assertRaises(ValueError):
            PkcePolicy(require_challenge=True, version='')

    def test_naive_deadline_normalized_to_utc(self):
        naive = datetime.datetime(2026, 11, 10)
        policy = PkcePolicy.mandatory_s256(
            legacy_no_challenge_accepted_until=naive)
        self.assertEqual(
            policy.legacy_no_challenge_accepted_until.tzinfo,
            datetime.timezone.utc)

    def test_transition_window_boundary_is_inclusive(self):
        deadline = datetime.datetime(2026, 11, 10, 12, 0,
                                     tzinfo=datetime.timezone.utc)
        policy = PkcePolicy.mandatory_s256(
            legacy_no_challenge_accepted_until=deadline)
        self.assertTrue(policy.allows_legacy_no_challenge(deadline))
        self.assertFalse(policy.allows_legacy_no_challenge(
            deadline + datetime.timedelta(seconds=1)))

    def test_missing_deadline_never_allows_legacy(self):
        policy = PkcePolicy.mandatory_s256()
        self.assertIsNone(policy.legacy_no_challenge_accepted_until)
        self.assertFalse(policy.allows_legacy_no_challenge(utcnow()))

    def test_aware_deadline_converted_to_utc(self):
        tokyo = datetime.timezone(datetime.timedelta(hours=9))
        deadline_local = datetime.datetime(2026, 11, 10, 21, 0,
                                           tzinfo=tokyo)
        policy = PkcePolicy.mandatory_s256(
            legacy_no_challenge_accepted_until=deadline_local)
        self.assertEqual(
            policy.legacy_no_challenge_accepted_until,
            datetime.datetime(2026, 11, 10, 12, 0,
                              tzinfo=datetime.timezone.utc))


class PkceRejectionMetricsTest(TestCase):

    def test_counts_and_snapshot(self):
        metrics = PkceRejectionMetrics()
        metrics.record(CHALLENGE_MISSING, 'client-a')
        metrics.record(CHALLENGE_MISSING, 'client-a')
        metrics.record(LEGACY_TRANSITION_EXPIRED, 'client-a')
        self.assertEqual(metrics.get(CHALLENGE_MISSING), 2)
        self.assertEqual(metrics.get(LEGACY_TRANSITION_EXPIRED), 1)
        self.assertEqual(metrics.get('never'), 0)
        snapshot = metrics.snapshot()
        snapshot['tampered'] = 1
        self.assertNotIn('tampered', metrics.snapshot())

    def test_reset(self):
        metrics = PkceRejectionMetrics()
        metrics.record(CHALLENGE_MISSING)
        metrics.reset()
        self.assertEqual(metrics.snapshot(), {})
