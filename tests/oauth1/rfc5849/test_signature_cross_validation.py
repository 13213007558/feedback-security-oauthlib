# -*- coding: utf-8 -*-
"""Client/resource cross-validation of OAuth 1.0 (RFC 5849) signatures.

Signature failures are often blamed on the shared secrets, but a more common
root cause is parameter normalization differing between the client and the
resource server.  The tests in this module therefore do not trust a single
implementation to define the expected answer.

The :mod:`third_party_oracle` section near the top of this file is a short,
independent re-implementation of the RFC 5849 section 3.4.1 machinery written
using only the Python standard library.  It never imports anything from
:mod:`oauthlib`, so it cannot accidentally call the helper under test: the
expected signature base strings and HMAC-SHA1 signatures are computed by this
third-party oracle, while the values being checked come from the actual
:class:`~oauthlib.oauth1.rfc5849.Client` request on the wire and the
parameters the :class:`~oauthlib.oauth1.rfc5849.endpoints.ResourceEndpoint`
collects from that same wire request.

Coverage of the normalization edge cases called out in the task:

* same-name multi-valued business parameters (``item``/``dup``), including a
  legitimate repeated business parameter -- the duplicates are expected to be
  kept and ordered by value, not rejected;
* empty values (``blank=``);
* the ``+`` versus space distinction in form encoded bodies;
* already percent-encoded content (``%2B`` and ``%2520``);
* non-ASCII names and values, encoded as UTF-8;
* default ports (80/443) being stripped from the base string URI;
* the relationship between the ``Host`` header and the request URI.

Only bodies whose ``Content-Type`` is ``application/x-www-form-urlencoded`` may
enter the parameter collection; a raw JSON body is transported untouched and is
never split into form parameters.  The handling of ``oauth_signature`` itself
and of the optional ``realm`` Authorization header parameter is checked too.

Mutation variants (each is a deliberately broken one-line edit that is *not*
kept in the tree; see the module docstring of the task write-up):

1. parameter ordering -- sorting in reverse breaks every normalized vector;
2. encoding order -- sorting the raw decoded pairs and only then
   percent-encoding them (instead of encoding first and sorting on the
   encoded bytes) is exposed by the non-ASCII key vector, since decoded
   U+00E6 sorts after 'a' while the encoded leading '%' (0x25) sorts before
   'a' (0x61);
3. body content type -- negating the form content type gate makes the server
   swallow the JSON body as if it were form parameters.
"""
import base64 as _base64
import hashlib as _hashlib
import hmac as _hmac
import urllib.parse as _urlparse
import urllib.request as _urlrequest
from unittest.mock import MagicMock

from oauthlib.common import Request
from oauthlib.oauth1 import RequestValidator
from oauthlib.oauth1.rfc5849 import (
    Client, SIGNATURE_TYPE_BODY, SIGNATURE_TYPE_QUERY,
)
from oauthlib.oauth1.rfc5849 import signature
from oauthlib.oauth1.rfc5849.endpoints import ResourceEndpoint

from tests.unittest import TestCase


# ==== Third-party oracle =========================================
# Every function in this section is an independent RFC 5849 implementation
# built exclusively from the Python standard library.  No name from the
# oauthlib package is referenced here, so the expected values cannot inherit a
# bug from the helpers under test.

_ORACLE_UNRESERVED = set(
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~'
)


def oracle_escape(value):
    """RFC 5849 section 3.6 percent-encoding, independent of oauthlib."""
    pieces = []
    for byte in value.encode('utf-8'):
        char = chr(byte)
        if char in _ORACLE_UNRESERVED:
            pieces.append(char)
        else:
            pieces.append('%%%02X' % byte)
    return ''.join(pieces)


def oracle_form_pairs(raw_body):
    """Parse an application/x-www-form-urlencoded body into (name, value)."""
    pairs = []
    for field in raw_body.split('&'):
        if not field:
            continue
        name, has_equals, value = field.partition('=')
        if not has_equals:
            value = ''
        # unquote_plus turns form '+' into a space and removes percent escapes.
        pairs.append((_urlparse.unquote_plus(name),
                      _urlparse.unquote_plus(value)))
    return pairs


def oracle_query_pairs(uri):
    return oracle_form_pairs(_urlparse.urlparse(uri).query)


def oracle_authorization_pairs(header, with_realm=False):
    """Parse an OAuth Authorization header independently of oauthlib."""
    if not header[:6].lower() == 'oauth ':
        raise ValueError('not an OAuth authorization header')
    items = _urlrequest.parse_http_list(header[6:])
    values = _urlrequest.parse_keqv_list(items)
    return [(name, _urlparse.unquote(value)) for name, value in values.items()
            if with_realm or name != 'realm']


def oracle_normalize(pairs):
    """RFC 5849 section 3.4.1.3.2 normalization of name/value pairs."""
    encoded = sorted((oracle_escape(name), oracle_escape(value))
                     for name, value in pairs)
    return '&'.join('%s=%s' % (name, value) for name, value in encoded)


def oracle_base_string_uri(uri):
    """RFC 5849 section 3.4.1.2 base string URI, without a Host override."""
    parsed = _urlparse.urlparse(uri)
    if not parsed.scheme or parsed.hostname is None:
        raise ValueError('absolute http(s) URI required')
    scheme = parsed.scheme.lower()
    host = parsed.hostname.lower()
    port = parsed.port
    if (scheme, port) in (('http', 80), ('https', 443)):
        port = None
    netloc = host if port is None else '%s:%s' % (host, port)
    path = parsed.path or '/'
    rebuilt = _urlparse.urlunparse(
        (scheme, netloc, path, parsed.params, '', ''))
    return rebuilt.replace(' ', '%20')


def oracle_collect_pairs(uri, body, headers, form_content_type,
                         with_realm=False, exclude_signature=True):
    """Collect signing parameters exactly as RFC 5849 section 3.4.1.3.1 says."""
    pairs = oracle_query_pairs(uri)
    authorization = headers.get('Authorization') or headers.get('authorization')
    if authorization is not None:
        pairs.extend(oracle_authorization_pairs(
            authorization, with_realm=with_realm))
    if body and form_content_type:
        pairs.extend(oracle_form_pairs(body))
    if exclude_signature:
        pairs = [pair for pair in pairs if pair[0] != 'oauth_signature']
    return pairs


def oracle_signature_base_string(method, uri, pairs, host=None):
    """Build the signature base string from independently collected pairs."""
    normalized = oracle_normalize(pairs)
    if host is not None:
        # The client lets a Host header override the URI netloc.  Mirror that
        # by re-parsing a synthetic URI with the same scheme.
        scheme = _urlparse.urlparse(uri).scheme.lower()
        host_parsed = _urlparse.urlparse('%s://%s' % (scheme, host.lower()))
        port = host_parsed.port
        if (scheme, port) in (('http', 80), ('https', 443)):
            port = None
        netloc = (host_parsed.hostname.lower()
                  if port is None else '%s:%s' % (host_parsed.hostname, port))
        base_uri_value = _urlparse.urlunparse(
            (scheme, netloc, _urlparse.urlparse(uri).path or '/', '', '', '')
        ).replace(' ', '%20')
    else:
        base_uri_value = oracle_base_string_uri(uri)
    return '&'.join((oracle_escape(method.upper()),
                     oracle_escape(base_uri_value),
                     oracle_escape(normalized)))


def oracle_hmac_sha1(base_string_value, client_secret, token_secret):
    """Compute an HMAC-SHA1 OAuth signature with the standard library only."""
    key = (oracle_escape(client_secret or '') + '&'
           + oracle_escape(token_secret or '')).encode('utf-8')
    digest = _hmac.new(key, base_string_value.encode('utf-8'),
                       _hashlib.sha1).digest()
    return _base64.b64encode(digest).decode('ascii')


# ==== Shared test fixtures =======================================

FORM_CONTENT_TYPE = 'application/x-www-form-urlencoded'

CLIENT_KEY = 'ck'
CLIENT_SECRET = 'cs'
RESOURCE_OWNER_KEY = 'tok'
RESOURCE_OWNER_SECRET = 'tos'
FIXED_NONCE = 'n0nce-fixed-0123456789abcdef'
FIXED_TIMESTAMP = '1700000000'


def build_client(**overrides):
    kwargs = dict(
        client_key=CLIENT_KEY,
        client_secret=CLIENT_SECRET,
        resource_owner_key=RESOURCE_OWNER_KEY,
        resource_owner_secret=RESOURCE_OWNER_SECRET,
        nonce=FIXED_NONCE,
        timestamp=FIXED_TIMESTAMP,
    )
    kwargs.update(overrides)
    return Client(**kwargs)


def build_endpoint(enforce_ssl=True):
    validator = MagicMock(wraps=RequestValidator())
    validator.check_client_key.return_value = True
    validator.check_nonce.return_value = True
    validator.check_access_token.return_value = True
    validator.allowed_signature_methods = ['HMAC-SHA1']
    validator.get_client_secret.return_value = CLIENT_SECRET
    validator.get_access_token_secret.return_value = RESOURCE_OWNER_SECRET
    validator.timestamp_lifetime = 10 ** 12
    validator.validate_client_key.return_value = True
    validator.validate_access_token.return_value = True
    validator.validate_timestamp_and_nonce.return_value = True
    validator.validate_realms.return_value = True
    validator.enforce_ssl = enforce_ssl
    validator.dummy_client = 'dummy'
    validator.dummy_secret = 'dummy'
    validator.dummy_access_token = 'dummy'
    return ResourceEndpoint(validator)


def server_request(uri, method, body, headers, enforce_ssl=True):
    """Run the wire request through the resource endpoint's request builder."""
    endpoint = build_endpoint(enforce_ssl=enforce_ssl)
    valid, request = endpoint.validate_protected_resource_request(
        uri, http_method=method, body=body, headers=headers)
    return endpoint, valid, request


def server_base_string(request):
    """Base string the resource server actually verifies."""
    return signature.signature_base_string(
        request.http_method,
        signature.base_string_uri(request.uri),
        signature.normalize_parameters(request.params))


def wire_signature(headers):
    authorization = (headers.get('Authorization')
                     or headers.get('authorization'))
    return dict(oracle_authorization_pairs(
        authorization, with_realm=True))['oauth_signature']


def wire_signature_from_parts(uri, headers, body):
    """Find oauth_signature regardless of the signature transport."""
    authorization = (headers.get('Authorization')
                     or headers.get('authorization'))
    if authorization is not None:
        return wire_signature(headers)
    carrier = body if body else _urlparse.urlparse(uri).query
    return dict(oracle_form_pairs(carrier))['oauth_signature']


# ==== Oracle self-check against the RFC 5849 reference vector ====

class ThirdPartyOracleTests(TestCase):
    """The oracle must reproduce the published RFC 5849 worked example."""

    RFC_PARAMS = [
        ('b5', '=%3D'),
        ('a3', 'a'),
        ('c@', ''),
        ('a2', 'r b'),
        ('oauth_consumer_key', '9djdj82h48djs9d2'),
        ('oauth_token', 'kkk9d7dh3k39sjv7'),
        ('oauth_signature_method', 'HMAC-SHA1'),
        ('oauth_timestamp', '137131201'),
        ('oauth_nonce', '7d8f3e4a'),
        ('c2', ''),
        ('a3', '2 q'),
    ]

    RFC_NORMALIZED = (
        'a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9dj'
        'dj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1'
        '&oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7'
    )

    RFC_BASE_STRING = (
        'POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q'
        '%26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_'
        'key%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a%26oauth_signature_m'
        'ethod%3DHMAC-SHA1%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk'
        '9d7dh3k39sjv7'
    )

    def test_oracle_matches_rfc_normalized_parameters(self):
        self.assertEqual(self.RFC_NORMALIZED,
                         oracle_normalize(self.RFC_PARAMS))

    def test_oracle_matches_rfc_signature_base_string(self):
        self.assertEqual(
            self.RFC_BASE_STRING,
            oracle_signature_base_string(
                'POST', 'http://example.com/request', self.RFC_PARAMS))

    def test_oracle_matches_rfc_hmac_signature(self):
        # Expected value from tests/oauth1/rfc5849/test_signatures.py, itself
        # produced independently with the openssl command line.
        self.assertEqual(
            'wsdNmjGB7lvis0UJuPAmjvX/PXw=',
            oracle_hmac_sha1(
                self.RFC_BASE_STRING,
                'ECrDNoq1VYzzzzzzzzzyAK7TwZNtPnkqatqZZZZ',
                'just-a-string    asdasd'))


# ==== Client side: the request actually put on the wire =========

class ClientWireNormalizationTests(TestCase):
    """The signed wire request must match the third-party oracle."""

    def test_kitchen_sink_vector_covers_every_normalization_case(self):
        uri = ('https://api.example.com:443/v1/orders'
               '?item=%C3%A6ble&z%2Bz=1&blank=&dup=q1')
        body = ('item=second+item&dup=q2&plus=a%2Bb&enc=%2520'
                '&note=caf%C3%A9')

        signed_uri, headers, signed_body = build_client().sign(
            uri, http_method='POST', body=body,
            headers={'Content-Type': FORM_CONTENT_TYPE})

        # The form body must be re-emitted, not replaced by a parsed dict.
        self.assertEqual(body, signed_body)

        oracle_pairs = oracle_collect_pairs(
            signed_uri, signed_body, headers, form_content_type=True)

        # Hard-coded oracle answers: same-name duplicates survive and are
        # value-ordered, empty value kept, '+' decoded, pre-encoded octets and
        # non-ASCII text re-encoded per section 3.6.
        expected_normalized = (
            'blank=&dup=q1&dup=q2&enc=%2520&item=%C3%A6ble'
            '&item=second%20item&note=caf%C3%A9&oauth_consumer_key=ck'
            '&oauth_nonce=n0nce-fixed-0123456789abcdef'
            '&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1700000000'
            '&oauth_token=tok&oauth_version=1.0&plus=a%2Bb&z%2Bz=1'
        )
        self.assertEqual(expected_normalized, oracle_normalize(oracle_pairs))

        expected_base_string = (
            'POST&https%3A%2F%2Fapi.example.com%2Fv1%2Forders'
            '&blank%3D%26dup%3Dq1%26dup%3Dq2%26enc%3D%252520'
            '%26item%3D%25C3%25A6ble%26item%3Dsecond%2520item'
            '%26note%3Dcaf%25C3%25A9%26oauth_consumer_key%3Dck'
            '%26oauth_nonce%3Dn0nce-fixed-0123456789abcdef'
            '%26oauth_signature_method%3DHMAC-SHA1'
            '%26oauth_timestamp%3D1700000000%26oauth_token%3Dtok'
            '%26oauth_version%3D1.0%26plus%3Da%252Bb%26z%252Bz%3D1'
        )
        oracle_base = oracle_signature_base_string(
            'POST', signed_uri, oracle_pairs)
        self.assertEqual(expected_base_string, oracle_base)

        # The signature on the wire must be the one the oracle computes,
        # proving the client signed the same base string.
        self.assertEqual(
            'yHnG6vN3rOImSVwUEcpUGexRp2o=',
            oracle_hmac_sha1(oracle_base, CLIENT_SECRET,
                             RESOURCE_OWNER_SECRET))
        self.assertEqual(
            oracle_hmac_sha1(oracle_base, CLIENT_SECRET,
                             RESOURCE_OWNER_SECRET),
            wire_signature(headers))

        # oauth_signature must never be part of the signed parameter set.
        self.assertNotIn('oauth_signature', [name for name, _ in oracle_pairs])

    def test_client_collected_parameters_match_oracle(self):
        """Inspect the parameters the client itself gathered before signing."""
        uri = ('https://api.example.com:443/v1/orders'
               '?item=%C3%A6ble&z%2Bz=1&blank=&dup=q1')
        body = ('item=second+item&dup=q2&plus=a%2Bb&enc=%2520'
                '&note=caf%C3%A9')
        client = build_client()
        signed_uri, headers, signed_body = client.sign(
            uri, http_method='POST', body=body,
            headers={'Content-Type': FORM_CONTENT_TYPE})

        request = Request(uri, 'POST', body,
                          {'Content-Type': FORM_CONTENT_TYPE})
        client_pairs = signature.collect_parameters(
            uri_query=request.uri_query, body=signed_body, headers=headers)

        oracle_pairs = oracle_collect_pairs(
            signed_uri, signed_body, headers, form_content_type=True)
        self.assertEqual(sorted(oracle_pairs), sorted(client_pairs))

        # A legitimate repeated business parameter must remain: the test must
        # not pass by rejecting all duplicates.
        self.assertEqual(2, sum(1 for name, _ in client_pairs if name == 'dup'))
        self.assertEqual(2, sum(1 for name, _ in client_pairs if name == 'item'))

    def test_repeated_business_parameter_is_signed_twice(self):
        """Rejecting duplicates wholesale would lose this signature."""
        signed_uri, headers, signed_body = build_client().sign(
            'https://api.example.com/tags', http_method='POST',
            body='tag=a&tag=b',
            headers={'Content-Type': FORM_CONTENT_TYPE})
        oracle_pairs = oracle_collect_pairs(
            signed_uri, signed_body, headers, form_content_type=True)
        normalized = oracle_normalize(oracle_pairs)
        self.assertIn('tag=a&tag=b', normalized)
        oracle_base = oracle_signature_base_string(
            'POST', signed_uri, oracle_pairs)
        self.assertEqual(
            oracle_hmac_sha1(oracle_base, CLIENT_SECRET,
                             RESOURCE_OWNER_SECRET),
            wire_signature(headers))

    def test_host_header_overrides_uri_netloc_in_client_base_string(self):
        uri = 'http://internal.example.com:80/path?x=1'
        signed_uri, headers, _ = build_client().sign(
            uri, http_method='POST',
            headers={'Host': 'gateway.example.com:8080'})

        # The client-side helper honors the Host header.
        self.assertEqual(
            'http://gateway.example.com:8080/path',
            signature.base_string_uri(signed_uri, headers['Host']))

        oracle_pairs = oracle_collect_pairs(
            signed_uri, '', headers, form_content_type=False)
        oracle_base = oracle_signature_base_string(
            'POST', signed_uri, oracle_pairs,
            host=headers['Host'])
        self.assertEqual(
            oracle_hmac_sha1(oracle_base, CLIENT_SECRET,
                             RESOURCE_OWNER_SECRET),
            wire_signature(headers))

    def test_default_ports_are_stripped_and_others_kept(self):
        cases = [
            ('http://h.example.com:80/p?a=1', 'http://h.example.com/p'),
            ('https://h.example.com:443/p?a=1', 'https://h.example.com/p'),
            ('http://h.example.com:8080/p?a=1',
             'http://h.example.com:8080/p'),
            ('https://h.example.com:80/p?a=1',
             'https://h.example.com:80/p'),
        ]
        for uri, expected_base_uri in cases:
            signed_uri, headers, _ = build_client().sign(
                uri, http_method='POST')
            self.assertEqual(
                expected_base_uri,
                signature.base_string_uri(signed_uri))
            self.assertEqual(
                expected_base_uri, oracle_base_string_uri(signed_uri))


# ==== Server side: parameters collected from the wire ===========

class ServerCollectionTests(TestCase):
    """The resource endpoint must collect exactly what RFC 5849 mandates."""

    def test_form_body_enters_parameter_collection(self):
        uri = ('https://api.example.com:443/v1/orders'
               '?item=%C3%A6ble&z%2Bz=1&blank=&dup=q1')
        body = ('item=second+item&dup=q2&plus=a%2Bb&enc=%2520'
                '&note=caf%C3%A9')
        signed_uri, headers, signed_body = build_client().sign(
            uri, http_method='POST', body=body,
            headers={'Content-Type': FORM_CONTENT_TYPE})

        endpoint, valid, request = server_request(
            signed_uri, 'POST', signed_body, headers)
        self.assertTrue(valid)
        self.assertTrue(request.validator_log['signature'])

        oracle_pairs = oracle_collect_pairs(
            signed_uri, signed_body, headers, form_content_type=True)
        self.assertEqual(sorted(oracle_pairs), sorted(request.params))

        # Server-side base string equals the independent oracle's answer.
        self.assertEqual(
            oracle_signature_base_string(
                'POST', signed_uri, oracle_pairs),
            server_base_string(request))

    def test_charset_suffixed_form_content_type_still_collected(self):
        # The Client.sign sanity check demands an exact form content type, so
        # the charset parameter is added to the wire afterwards (as a real
        # framework might) to exercise the server's substring match.
        body = 'colour=%C3%A6&colour=blue'
        signed_uri, headers, signed_body = build_client().sign(
            'https://api.example.com/colour', http_method='POST', body=body,
            headers={'Content-Type': FORM_CONTENT_TYPE})
        headers['Content-Type'] = (
            'application/x-www-form-urlencoded; charset=utf-8')
        _endpoint, valid, request = server_request(
            signed_uri, 'POST', signed_body, headers)
        self.assertTrue(valid)
        colours = [value for name, value in request.params if name == 'colour']
        self.assertEqual(['blue', 'æ'], sorted(colours))

    def test_json_body_is_never_split_into_form_parameters(self):
        json_body = '{"note": "a=1&b=2", "x": "+ %20"}'
        signed_uri, headers, signed_body = build_client().sign(
            'https://api.example.com/json', http_method='POST',
            body=json_body, headers={'Content-Type': 'application/json'})

        # The JSON document travels byte-for-byte untouched.
        self.assertEqual(json_body, signed_body)

        _endpoint, valid, request = server_request(
            signed_uri, 'POST', signed_body, headers)
        self.assertTrue(valid)

        # No key from inside the JSON text may leak into the parameter set.
        collected_names = {name for name, _ in request.params}
        self.assertNotIn('note', collected_names)
        self.assertNotIn('x', collected_names)
        self.assertNotIn('b', collected_names)

        # The non-form body is instead covered by oauth_body_hash.
        expected_body_hash = _base64.b64encode(
            _hashlib.sha1(json_body.encode('utf-8')).digest()).decode('ascii')
        self.assertEqual(
            expected_body_hash, request.oauth_params['oauth_body_hash'])

        oracle_pairs = oracle_collect_pairs(
            signed_uri, signed_body, headers, form_content_type=False)
        self.assertIn(('oauth_body_hash', expected_body_hash), oracle_pairs)
        self.assertEqual(
            oracle_signature_base_string(
                'POST', signed_uri, oracle_pairs),
            server_base_string(request))

    def test_non_form_content_type_excludes_even_form_looking_body(self):
        # Sign a genuinely non-form document, then relabel a form-looking
        # payload as text/plain: the content type gate must block parsing.
        # The body hash extension means the wire body still has to match the
        # bytes that were hashed, so the form-looking text is what gets signed
        # through a JSON-labelled request (the client sanity check forbids
        # signing a decodable form body without the form content type).
        raw_body = '{"marker": true}'
        form_looking = 'sneaky=1&sneaky=2'
        signed_uri, headers, signed_body = build_client().sign(
            'https://api.example.com/plain', http_method='POST',
            body=raw_body, headers={'Content-Type': 'application/json'})
        self.assertEqual(raw_body, signed_body)
        headers['Content-Type'] = 'text/plain'
        _endpoint, valid, request = server_request(
            signed_uri, 'POST', form_looking, headers)
        self.assertTrue(valid)
        self.assertNotIn('sneaky', [name for name, _ in request.params])
        self.assertEqual(
            _base64.b64encode(
                _hashlib.sha1(raw_body.encode('utf-8')).digest()
            ).decode('ascii'),
            request.oauth_params['oauth_body_hash'])

    def test_oauth_signature_is_excluded_but_realm_handling_is_checked(self):
        signed_uri, headers, signed_body = build_client(realm='photos').sign(
            'https://api.example.com/realm', http_method='POST', body='a=1',
            headers={'Content-Type': FORM_CONTENT_TYPE})

        # With realm requested it appears on the wire ...
        self.assertTrue(
            headers['Authorization'].startswith('OAuth realm="photos",'))

        _endpoint, valid, request = server_request(
            signed_uri, 'POST', signed_body, headers)
        self.assertTrue(valid)

        # ... but neither realm nor oauth_signature enter the signed params.
        names = [name for name, _ in request.params]
        self.assertNotIn('realm', names)
        self.assertNotIn('oauth_signature', names)

        # The raw collection helper can be asked to retain both, proving the
        # exclusion is an explicit policy rather than accidental loss.
        raw = signature.collect_parameters(
            headers=headers, exclude_oauth_signature=False, with_realm=True)
        raw_names = [name for name, _ in raw]
        self.assertIn('realm', raw_names)
        self.assertIn('oauth_signature', raw_names)

        oracle_pairs = oracle_collect_pairs(
            signed_uri, signed_body, headers, form_content_type=True)
        self.assertEqual(
            oracle_signature_base_string(
                'POST', signed_uri, oracle_pairs),
            server_base_string(request))

    def test_plus_and_space_are_distinguished(self):
        # '+' in a form body decodes to a space; an encoded plus stays '+'.
        body = 'space=one+two&plus=one%2Btwo'
        signed_uri, headers, signed_body = build_client().sign(
            'https://api.example.com/plus', http_method='POST', body=body,
            headers={'Content-Type': FORM_CONTENT_TYPE})
        _endpoint, valid, request = server_request(
            signed_uri, 'POST', signed_body, headers)
        self.assertTrue(valid)
        values = dict(request.params)
        self.assertEqual('one two', values['space'])
        self.assertEqual('one+two', values['plus'])
        normalized = signature.normalize_parameters(request.params)
        self.assertIn('plus=one%2Btwo', normalized)
        self.assertIn('space=one%20two', normalized)


# ==== Both directions converge on the oracle =====================

class CrossDirectionTests(TestCase):
    """Client signing and server verification must meet at the oracle."""

    def _assert_both_directions_match_oracle(self, uri, method, body, headers,
                                             form_content_type,
                                             client_kwargs=None):
        signed_uri, signed_headers, signed_body = build_client(
            **(client_kwargs or {})).sign(
            uri, http_method=method, body=body, headers=headers)

        endpoint, valid, request = server_request(
            signed_uri, method, signed_body, signed_headers)
        self.assertTrue(valid)
        self.assertTrue(request.validator_log['signature'])

        oracle_pairs = oracle_collect_pairs(
            signed_uri, signed_body, signed_headers,
            form_content_type=form_content_type)
        oracle_base = oracle_signature_base_string(
            method, signed_uri, oracle_pairs)

        # Server reconstruction equals the oracle ...
        self.assertEqual(oracle_base, server_base_string(request))

        # ... and the wire signature itself equals the oracle HMAC.
        self.assertEqual(
            oracle_hmac_sha1(oracle_base, CLIENT_SECRET,
                             RESOURCE_OWNER_SECRET),
            wire_signature_from_parts(
                signed_uri, signed_headers, signed_body))
        return signed_uri, signed_headers, signed_body, oracle_pairs
    def test_header_signature_type_with_duplicate_business_params(self):
        self._assert_both_directions_match_oracle(
            'https://api.example.com/orders?dup=q1',
            'POST', 'dup=q2&item=a%20b',
            {'Content-Type': FORM_CONTENT_TYPE}, form_content_type=True)

    def test_body_signature_type_keeps_duplicates(self):
        _uri, _headers, signed_body, oracle_pairs = (
            self._assert_both_directions_match_oracle(
                'https://api.example.com/body', 'POST', 'tag=a&tag=b',
                {'Content-Type': FORM_CONTENT_TYPE},
                form_content_type=True,
                client_kwargs={'signature_type': SIGNATURE_TYPE_BODY}))
        self.assertEqual(2, sum(1 for name, _ in oracle_pairs if name == 'tag'))
        self.assertIn('tag=a&tag=b', signed_body)

    def test_query_signature_type(self):
        self._assert_both_directions_match_oracle(
            'https://api.example.com/q?color=red', 'POST', None, {},
            form_content_type=False,
            client_kwargs={'signature_type': SIGNATURE_TYPE_QUERY})

    def test_non_ascii_key_distinguishes_encode_before_sort(self):
        # The names are percent-encoded first and then sorted by ascending
        # byte value.  Encoded '%' is 0x25 and 'a' is 0x61, so the encoded
        # %C3%A6ble sorts before apple even though the decoded character
        # U+00E6 would sort after 'a'.  A broken implementation that sorts the
        # raw decoded values first emits apple then %C3%A6ble.  The oracle
        # reproduces oauthlib's encode-then-byte-sort and pins the order, so
        # that mutation flips this assertion.
        _uri, _h, _b, oracle_pairs = (
            self._assert_both_directions_match_oracle(
                'https://api.example.com/u', 'POST',
                'apple=1&%C3%A6ble=2',
                {'Content-Type': FORM_CONTENT_TYPE},
                form_content_type=True))
        normalized = oracle_normalize(oracle_pairs)
        self.assertIn('%C3%A6ble=2&apple=1', normalized)
        self.assertNotIn('apple=1&%C3%A6ble=2', normalized)

    def test_server_uses_absolute_uri_not_host_header(self):
        # Client signs with a Host override; the server reconstructs from the
        # absolute URI it is handed (RFC 2616 5.2.1), ignoring any Host item.
        signed_uri, headers, _ = build_client().sign(
            'http://internal.example.com:80/path?x=1', http_method='POST',
            headers={'Host': 'gateway.example.com:8080'})
        absolute_gateway_uri = 'http://gateway.example.com:8080/path?x=1'
        endpoint = build_endpoint(enforce_ssl=False)
        headers_without_host = {
            key: value for key, value in headers.items()
            if key.lower() != 'host'}
        valid, request = endpoint.validate_protected_resource_request(
            absolute_gateway_uri, http_method='POST', body='',
            headers=headers_without_host)
        self.assertTrue(valid)
        self.assertEqual(
            'http://gateway.example.com:8080/path',
            signature.base_string_uri(request.uri))
