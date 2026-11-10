"""Per-client PKCE enforcement policies and phased migration support.

This module adds an opt-in policy layer on top of the legacy
``RequestValidator.is_pkce_required`` boolean.  A client that is not enrolled
in a policy keeps the historical, fully optional PKCE behaviour.  Enrolled
clients get an immutable :class:`PkcePolicy` that describes:

* whether a ``code_challenge`` is required on new authorization requests;
* which ``code_challenge_method`` values are accepted (a policy that only
  lists ``S256`` can never fall back to ``plain``);
* the policy version stamped onto every issued authorization code, so the
  token endpoint verifies a code against the policy in force when it was
  issued rather than whatever is configured today;
* an optional, time-bounded transition deadline for authorization codes that
  were issued before enrollment and therefore carry no challenge at all.

Neither ``code_challenge``, ``code_verifier`` nor authorization codes are
ever logged or retained by this module; observability is limited to the
machine-readable rejection reason codes in :class:`PkceRejectionMetrics`.
"""
import datetime
import logging
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

#: The only transform mandated by RFC 7636 and RFC 9700 best practice.
S256 = 'S256'

#: The legacy direct-comparison transform.  Retained so codes issued under an
#: older policy can still be exchanged, but never offered by the mandatory
#: policy constructors.
PLAIN = 'plain'

# Rejection reason codes.  These are stable identifiers intended for counters
# and dashboards; they never contain request material.
CHALLENGE_MISSING = 'challenge_missing'
CHALLENGE_METHOD_DISALLOWED = 'challenge_method_disallowed'
CHALLENGE_METHOD_UNKNOWN = 'challenge_method_unknown'
CHALLENGE_SYNTAX_INVALID = 'challenge_syntax_invalid'
VERIFIER_MISSING = 'verifier_missing'
VERIFIER_SYNTAX_INVALID = 'verifier_syntax_invalid'
VERIFIER_MISMATCH = 'verifier_mismatch'
LEGACY_TRANSITION_EXPIRED = 'legacy_transition_expired'


def _as_utc(value):
    """Normalize a datetime to a timezone-aware UTC datetime."""
    if value.tzinfo is None:
        return value.replace(tzinfo=datetime.timezone.utc)
    return value.astimezone(datetime.timezone.utc)


def utcnow():
    """Default clock: the current instant as a timezone-aware UTC datetime."""
    return datetime.datetime.now(tz=datetime.timezone.utc)


@dataclass(frozen=True)
class PkcePolicy:
    """Immutable PKCE enforcement policy for a single client.

    :param require_challenge: When ``True`` every new authorization request
        must carry a ``code_challenge``.
    :param allowed_methods: Accepted ``code_challenge_method`` values, in
        preference order.  Must contain :data:`S256`.
    :param version: Identifier of this policy revision.  It is stamped onto
        each issued authorization code and must change whenever the policy is
        changed, so stored codes remain bound to the policy in force at
        issuance time.
    :param legacy_no_challenge_accepted_until: Optional deadline after which
        authorization codes without any stored challenge (i.e. codes issued
        before the client was enrolled) are rejected at the token endpoint.
        Timezone-naive datetimes are interpreted as UTC.  When ``None`` such
        codes are never accepted once the client is enrolled.
    """

    require_challenge: bool
    allowed_methods: tuple = (S256,)
    version: str = 'pkce-v1'
    legacy_no_challenge_accepted_until: object = None

    def __post_init__(self):
        if not self.allowed_methods:
            raise ValueError('A PKCE policy must allow at least one method.')
        methods = tuple(self.allowed_methods)
        if S256 not in methods:
            raise ValueError(
                'S256 must always be an allowed method; got %r' % (methods,))
        for method in methods:
            if method not in (PLAIN, S256):
                raise ValueError('Unknown code_challenge_method %r' % method)
        object.__setattr__(self, 'allowed_methods', methods)
        if not isinstance(self.version, str) or not self.version:
            raise ValueError('PkcePolicy.version must be a non-empty string.')
        if self.legacy_no_challenge_accepted_until is not None:
            object.__setattr__(
                self,
                'legacy_no_challenge_accepted_until',
                _as_utc(self.legacy_no_challenge_accepted_until))

    @classmethod
    def optional(cls, version='pkce-optional-v1',
                 legacy_no_challenge_accepted_until=None):
        """Observation phase: challenges are optional, plain or S256.

        Plain is only accepted here so in-flight clients keep working while
        they are being updated; move to :meth:`mandatory_s256` to cut the
        plain downgrade path.
        """
        return cls(
            require_challenge=False,
            allowed_methods=(PLAIN, S256),
            version=version,
            legacy_no_challenge_accepted_until=
            legacy_no_challenge_accepted_until,
        )

    @classmethod
    def mandatory_s256(cls, version='pkce-s256-v1',
                       legacy_no_challenge_accepted_until=None):
        """Enforcement phase: a challenge is required and only S256 is valid.

        A request without a challenge, with an unknown method or with a
        challenge whose syntax is not a 43-character base64url SHA-256 digest
        is rejected before any authorization code is issued.
        """
        return cls(
            require_challenge=True,
            allowed_methods=(S256,),
            version=version,
            legacy_no_challenge_accepted_until=
            legacy_no_challenge_accepted_until,
        )

    def allows_legacy_no_challenge(self, now):
        """Return whether a challenge-less code may still be exchanged now."""
        deadline = self.legacy_no_challenge_accepted_until
        if deadline is None:
            return False
        return _as_utc(now) <= deadline

    def allows_method(self, method):
        """Return whether the policy accepts the given challenge method."""
        return method in self.allowed_methods


@dataclass
class PkceRejectionMetrics:
    """Observable counters for PKCE policy rejections.

    Only stable reason codes are counted.  Challenge values, verifiers,
    authorization codes and any other request material must never be passed
    here; :meth:`record` only stores the reason and an opaque client
    identifier label.
    """

    counts: dict = field(default_factory=dict)

    def record(self, reason, client_id=None):
        """Increment the counter for a rejection reason.

        :param reason: One of the module-level reason constants.
        :param client_id: Optional client identifier, used only to tag the
            debug log line.  Secrets must not be passed as the label.
        """
        bucket = self.counts.setdefault(reason, 0)
        self.counts[reason] = bucket + 1
        log.debug('PKCE policy rejection reason=%s client_id=%r',
                  reason, client_id)

    def get(self, reason):
        """Return the number of times ``reason`` has been recorded."""
        return self.counts.get(reason, 0)

    def snapshot(self):
        """Return a copy of the current counters."""
        return dict(self.counts)

    def reset(self):
        """Drop all recorded counters."""
        self.counts.clear()
