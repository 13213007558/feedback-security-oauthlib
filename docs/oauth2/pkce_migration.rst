Migrating clients to mandatory PKCE (S256)
==========================================

OAuthLib supports rolling mandatory :rfc:`7636` PKCE out one client at a
time without a ``plain`` downgrade and without accepting legacy
authorization codes forever.  The building blocks live in
:mod:`oauthlib.oauth2.rfc6749.pkce`:

* :class:`~oauthlib.oauth2.rfc6749.pkce.PkcePolicy` describes the current
  policy of a single client.
* :class:`~oauthlib.oauth2.rfc6749.pkce.PkceRejectionMetrics` exposes
  per-reason rejection counters.
* Two new :class:`~oauthlib.oauth2.RequestValidator` methods connect the
  policy to your client registry and storage:
  :meth:`~oauthlib.oauth2.RequestValidator.get_pkce_policy` and
  :meth:`~oauthlib.oauth2.RequestValidator.get_code_challenge_policy_version`.

Clients whose validator returns ``None`` from ``get_pkce_policy`` keep the
historical, fully optional behaviour driven by
:meth:`~oauthlib.oauth2.RequestValidator.is_pkce_required`.  Only an actual
``PkcePolicy`` instance enables the migration path, so existing
integrations continue to work unchanged until you enroll them.

Phases
------

Two policy constructors cover the typical staged rollout:

``PkcePolicy.optional(version=...)``
    Observation phase.  A ``code_challenge`` is not yet required and both
    ``plain`` and ``S256`` are accepted.  Use it to confirm that a client
    is actually sending PKCE parameters before enforcement begins.

``PkcePolicy.mandatory_s256(version=..., legacy_no_challenge_accepted_until=...)``
    Enforcement phase.  New authorization requests must carry a
    ``code_challenge`` using ``S256``.  Missing challenges, unknown
    methods (including an implicit ``plain`` default) and challenges whose
    length or syntax is not a 43-character base64url SHA-256 digest are
    rejected with ``invalid_request`` *before* any authorization code is
    issued.

Every time the policy for a client changes, give it a new ``version``.
The version is stamped onto each issued authorization code (in the
``pkce_policy_version`` grant field) and must be persisted by
:meth:`~oauthlib.oauth2.RequestValidator.save_authorization_code`.

What gets stored with a code
----------------------------

In addition to the existing ``code_challenge`` and
``code_challenge_method``, persist:

* ``code["pkce_policy_version"]`` - the policy revision in force when the
  code was issued.

At the token endpoint the grant verifies the challenge and method stored
with the code, and also requires the stored policy version to be present.
A code that was issued with a challenge is always verified, even if the
client's policy has since been relaxed or switched off: turning the
policy off today cannot bypass a challenge bound to a code yesterday.
A bound challenge whose policy-version record is missing (for example a
row written before the storage migration) fails with ``invalid_grant``
rather than being trusted.

Time-bounded transition for legacy codes
----------------------------------------

Codes issued *before* enrollment carry no challenge.  They cannot be
challenged, but they must not be accepted forever either.  Pass
``legacy_no_challenge_accepted_until`` when constructing the policy:

.. code-block:: python

    import datetime

    deadline = datetime.datetime.now(tz=datetime.timezone.utc) + \
        datetime.timedelta(days=7)
    policy = PkcePolicy.mandatory_s256(
        version="client-a-s256-2026-11",
        legacy_no_challenge_accepted_until=deadline,
    )

While the current time (as reported by the grant's clock) is within the
deadline, challenge-less codes may still be exchanged.  Afterwards the
grant raises
:class:`~oauthlib.oauth2.PkceTransitionExpiredError` (an
``invalid_grant``) and records the ``legacy_transition_expired`` reason.
A ``code_verifier`` presented for a challenge-less code is always treated
as a downgrade attempt, regardless of the deadline.

The clock is injected through the ``clock`` parameter of
:class:`~oauthlib.oauth2.AuthorizationCodeGrant`, which makes the
transition deterministic to test.  It defaults to the UTC wall clock and
must be a zero-argument callable returning a timezone-aware
``datetime``.

Observable rejection reasons
----------------------------

Pass a :class:`~oauthlib.oauth2.rfc6749.pkce.PkceRejectionMetrics`
instance to the grant and read ``snapshot()`` for dashboards or alarms:

.. code-block:: python

    from oauthlib.oauth2 import (
        AuthorizationCodeGrant, PkceRejectionMetrics,
    )

    metrics = PkceRejectionMetrics()
    grant = AuthorizationCodeGrant(validator, pkce_metrics=metrics)

The counters use stable reason codes such as ``challenge_missing``,
``challenge_method_disallowed``, ``challenge_method_unknown``,
``challenge_syntax_invalid``, ``verifier_missing``,
``verifier_syntax_invalid``, ``verifier_mismatch`` and
``legacy_transition_expired``.  Only these codes and the public client
identifier are logged.  ``code_challenge``, ``code_verifier`` and
authorization codes are never written to logs; grant-level debug logging
renders them through :func:`oauthlib.common.log_safe`.

Validator example
-----------------

.. code-block:: python

    from oauthlib.oauth2 import PkcePolicy, RequestValidator


    class MyValidator(RequestValidator):

        # client_id -> current policy; absent means legacy behaviour
        pkce_policies = {
            "client-a": PkcePolicy.mandatory_s256(
                version="client-a-s256-2026-11",
                legacy_no_challenge_accepted_until=deadline,
            ),
        }

        def get_pkce_policy(self, client_id, request):
            return self.pkce_policies.get(client_id)

        def save_authorization_code(self, client_id, code, request, *args,
                                    **kwargs):
            record = {
                "code": code["code"],
                "code_challenge": request.code_challenge,
                "code_challenge_method": request.code_challenge_method,
                "pkce_policy_version": code.get("pkce_policy_version"),
                # ... client, redirect URI, scopes, user, expiry ...
            }
            storage.insert(record)

        def get_code_challenge(self, code, request):
            return storage.find(code)["code_challenge"]

        def get_code_challenge_method(self, code, request):
            return storage.find(code)["code_challenge_method"]

        def get_code_challenge_policy_version(self, code, request):
            return storage.find(code)["pkce_policy_version"]

A complete, runnable reference implementation driven by a controllable
clock, including two-client isolation and the state of a code after a
wrong verifier, is available in
``tests/oauth2/rfc6749/test_pkce_migration.py``.
