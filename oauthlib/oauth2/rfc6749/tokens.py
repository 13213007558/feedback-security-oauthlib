"""
oauthlib.oauth2.rfc6749.tokens
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This module contains methods for adding two types of access tokens to requests.

- Bearer https://tools.ietf.org/html/rfc6750
- MAC https://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-01
"""
import hashlib
import hmac
import warnings
from binascii import b2a_base64
from urllib.parse import urlparse

from oauthlib import common
from oauthlib.common import add_params_to_qs, add_params_to_uri, urldecode

from . import utils
from .errors import InvalidRequestError

FORM_URLENCODED_CONTENT_TYPE = 'application/x-www-form-urlencoded'


class OAuth2Token(dict):

    def __init__(self, params, old_scope=None):
        super().__init__(params)
        self._new_scope = None
        if params.get('scope'):
            self._new_scope = set(utils.scope_to_list(params['scope']))
        if old_scope is not None:
            self._old_scope = set(utils.scope_to_list(old_scope))
            if self._new_scope is None:
                # the rfc says that if the scope hasn't changed, it's optional
                # in params so set the new scope to the old scope
                self._new_scope = self._old_scope
        else:
            self._old_scope = self._new_scope

    @property
    def scope_changed(self):
        return self._new_scope != self._old_scope

    @property
    def old_scope(self):
        return utils.list_to_scope(self._old_scope)

    @property
    def old_scopes(self):
        return list(self._old_scope)

    @property
    def scope(self):
        return utils.list_to_scope(self._new_scope)

    @property
    def scopes(self):
        return list(self._new_scope)

    @property
    def missing_scopes(self):
        return list(self._old_scope - self._new_scope)

    @property
    def additional_scopes(self):
        return list(self._new_scope - self._old_scope)


def prepare_mac_header(token, uri, key, http_method,
                       nonce=None,
                       headers=None,
                       body=None,
                       ext='',
                       hash_algorithm='hmac-sha-1',
                       issue_time=None,
                       draft=0):
    """Add an `MAC Access Authentication`_ signature to headers.

    Unlike OAuth 1, this HMAC signature does not require inclusion of the
    request payload/body, neither does it use a combination of client_secret
    and token_secret but rather a mac_key provided together with the access
    token.

    Currently two algorithms are supported, "hmac-sha-1" and "hmac-sha-256",
    `extension algorithms`_ are not supported.

    Example MAC Authorization header, linebreaks added for clarity

    Authorization: MAC id="h480djs93hd8",
                       nonce="1336363200:dj83hs9s",
                       mac="bhCQXTVyfj5cmA9uKkPFx1zeOXM="

    .. _`MAC Access Authentication`: https://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-01
    .. _`extension algorithms`: https://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-01#section-7.1

    :param token:
    :param uri: Request URI.
    :param key: MAC given provided by token endpoint.
    :param http_method: HTTP Request method.
    :param nonce:
    :param headers: Request headers as a dictionary.
    :param body:
    :param ext:
    :param hash_algorithm: HMAC algorithm provided by token endpoint.
    :param issue_time: Time when the MAC credentials were issued (datetime).
    :param draft: MAC authentication specification version.
    :return: headers dictionary with the authorization field added.
    """
    http_method = http_method.upper()
    host, port = utils.host_from_uri(uri)

    common.check_http_header_value('nonce', nonce)
    common.check_http_header_value('ext', ext)

    if hash_algorithm.lower() == 'hmac-sha-1':
        h = hashlib.sha1
    elif hash_algorithm.lower() == 'hmac-sha-256':
        h = hashlib.sha256
    else:
        raise ValueError('unknown hash algorithm')

    if draft == 0:
        nonce = nonce or '{}:{}'.format(utils.generate_age(issue_time),
                                          common.generate_nonce())
    else:
        ts = common.generate_timestamp()
        nonce = common.generate_nonce()

    _sch, _net, path, _par, query, _fra = urlparse(uri)

    request_uri = path + '?' + query if query else path

    # Hash the body/payload
    if body is not None and draft == 0:
        body = body.encode('utf-8')
        bodyhash = b2a_base64(h(body).digest())[:-1].decode('utf-8')
    else:
        bodyhash = ''

    # Create the normalized base string
    base = []
    if draft == 0:
        base.append(nonce)
    else:
        base.append(ts)
        base.append(nonce)
    base.append(http_method.upper())
    base.append(request_uri)
    base.append(host)
    base.append(port)
    if draft == 0:
        base.append(bodyhash)
    base.append(ext or '')
    base_string = '\n'.join(base) + '\n'

    # hmac struggles with unicode strings - http://bugs.python.org/issue5285
    if isinstance(key, str):
        key = key.encode('utf-8')
    sign = hmac.new(key, base_string.encode('utf-8'), h)
    sign = b2a_base64(sign.digest())[:-1].decode('utf-8')

    header = []
    header.append('MAC id="%s"' % token)
    if draft != 0:
        header.append('ts="%s"' % ts)
    header.append('nonce="%s"' % nonce)
    if bodyhash:
        header.append('bodyhash="%s"' % bodyhash)
    if ext:
        header.append('ext="%s"' % ext)
    header.append('mac="%s"' % sign)

    headers = headers or {}
    headers['Authorization'] = ', '.join(header)
    return headers


def prepare_bearer_uri(token, uri):
    """Add a `Bearer Token`_ to the request URI.
    Not recommended, use only if client can't use authorization header or body.

    http://www.example.com/path?access_token=h480djs93hd8

    .. _`Bearer Token`: https://tools.ietf.org/html/rfc6750

    :param token:
    :param uri:
    """
    return add_params_to_uri(uri, [(('access_token', token))])


def prepare_bearer_headers(token, headers=None):
    """Add a `Bearer Token`_ to the request URI.
    Recommended method of passing bearer tokens.

    Authorization: Bearer h480djs93hd8

    .. _`Bearer Token`: https://tools.ietf.org/html/rfc6750

    :param token:
    :param headers:
    """
    headers = headers or {}
    headers['Authorization'] = 'Bearer %s' % token
    return headers


def prepare_bearer_body(token, body=''):
    """Add a `Bearer Token`_ to the request body.

    access_token=h480djs93hd8

    .. _`Bearer Token`: https://tools.ietf.org/html/rfc6750

    :param token:
    :param body:
    """
    return add_params_to_qs(body, [(('access_token', token))])


def random_token_generator(request, refresh_token=False):
    """
    :param request: OAuthlib request.
    :type request: oauthlib.common.Request
    :param refresh_token:
    """
    return common.generate_token()


def signed_token_generator(private_pem, **kwargs):
    """
    :param private_pem:
    """
    def signed_token_generator(request):
        request.claims = kwargs
        return common.generate_signed_token(private_pem, request)

    return signed_token_generator


def get_token_from_header(request):
    """
    Helper function to extract a token from the request header.

    :param request: OAuthlib request.
    :type request: oauthlib.common.Request
    :return: Return the token or None if the Authorization header is malformed.
    """
    token = None

    if 'Authorization' in request.headers:
        split_header = request.headers.get('Authorization').split()
        if len(split_header) == 2 and split_header[0].lower() == 'bearer':
            token = split_header[1]
    else:
        token = request.access_token

    return token


class BearerTokenExtractor:
    """Extract Bearer access tokens from the three RFC 6750 carriers.

    RFC 6750 allows a client to present an access token in exactly one of:

    1. the ``Authorization`` request header using the ``Bearer`` scheme;
    2. the ``access_token`` parameter of an ``application/x-www-form-urlencoded``
       request body (only when the method and content type permit a form body);
    3. the ``access_token`` query parameter in the request URI.

    The default (lenient) behaviour mirrors :func:`get_token_from_header` and
    keeps the first usable token without complaining about extras. The strict
    policy instead enforces that a request carries at most one token, using the
    raw multi-valued parameter lists kept on the request so that duplicates a
    dict would collapse are still visible.
    """

    HEADER = 'header'
    QUERY = 'query'
    BODY = 'body'

    def _header_tokens(self, request):
        """Return ``(carrier_present, tokens)`` for the Authorization header.

        A present ``Bearer`` header (the scheme name is case-insensitive per
        RFC 7235) contributes exactly one entry. An empty or otherwise
        malformed ``Bearer`` header contributes an empty string so that strict
        mode rejects it instead of silently looking elsewhere. Headers using
        any other scheme are not Bearer carriers and are ignored.
        """
        authorization = request.headers.get('Authorization')
        if authorization is None:
            return False, []
        parts = authorization.split()
        if not parts or parts[0].lower() != 'bearer':
            return False, []
        token = parts[1] if len(parts) == 2 else ''
        return True, [token]

    def _query_tokens(self, request):
        """Return every ``access_token`` value in the URI query, in order."""
        return [value for name, value in urldecode(request.uri_query)
                if name == 'access_token']

    def _body_tokens(self, request):
        """Return the form-body ``access_token`` values when permitted.

        RFC 6750 section 2.2 only allows the body carrier for form-encoded
        bodies. A JSON body is therefore never a form carrier, even if it
        happens to contain an ``access_token`` field. A form body carrying an
        ``access_token`` on a disallowed method or with a disallowed content
        type is rejected up front rather than silently ignored.
        """
        decoded_body = request.decoded_body
        if not decoded_body:
            return []
        has_token = any(name == 'access_token' for name, _ in decoded_body)
        if request.http_method.upper() != 'POST':
            if has_token:
                raise InvalidRequestError(
                    description='Form-encoded access_token is only permitted '
                                'for HTTP POST requests.',
                    request=request,
                )
            return []
        content_type = request.headers.get('Content-Type', '')
        content_type = content_type.split(';')[0].strip().lower()
        if content_type != FORM_URLENCODED_CONTENT_TYPE:
            if has_token:
                raise InvalidRequestError(
                    description='Form-encoded access_token requires the '
                                '%s content type.' % FORM_URLENCODED_CONTENT_TYPE,
                    request=request,
                )
            return []
        return [value for name, value in decoded_body
                if name == 'access_token']

    def _sources(self, request):
        """Yield ``(carrier, tokens)`` for every possible carrier."""
        header_present, header_tokens = self._header_tokens(request)
        if header_present:
            yield self.HEADER, header_tokens
        query_tokens = self._query_tokens(request)
        if query_tokens:
            yield self.QUERY, query_tokens
        body_tokens = self._body_tokens(request)
        if body_tokens:
            yield self.BODY, body_tokens

    def extract_strict(self, request):
        """Extract the single Bearer token or raise an OAuth2 error.

        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :raises InvalidRequestError: if credentials appear in more than one
            carrier, a carrier repeats the parameter, a form carrier is used
            with a disallowed method/content type, or the token is empty.
        :return: The one access token presented by the request.
        :rtype: str
        """
        carriers = list(self._sources(request))

        if len(carriers) > 1:
            raise InvalidRequestError(
                description='Access token presented in multiple credential '
                            'carriers: %s.' % ', '.join(
                                carrier for carrier, _ in carriers),
                request=request,
            )

        if not carriers:
            return None

        carrier, tokens = carriers[0]
        if len(tokens) > 1:
            raise InvalidRequestError(
                description='Multiple access_token parameters in the '
                            'request %s.' % carrier,
                request=request,
            )
        if not tokens[0]:
            raise InvalidRequestError(
                description='Empty Bearer access token.',
                request=request,
            )
        return tokens[0]


class TokenBase:
    __slots__ = ()

    def __call__(self, request, refresh_token=False):
        raise NotImplementedError('Subclasses must implement this method.')

    def validate_request(self, request):
        """
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def estimate_type(self, request):
        """
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        """
        raise NotImplementedError('Subclasses must implement this method.')


class BearerToken(TokenBase):
    __slots__ = (
        'request_validator', 'token_generator',
        'refresh_token_generator', 'expires_in', 'token_extractor'
    )

    def __init__(self, request_validator=None, token_generator=None,
                 expires_in=None, refresh_token_generator=None):
        self.request_validator = request_validator
        self.token_generator = token_generator or random_token_generator
        self.refresh_token_generator = (
            refresh_token_generator or self.token_generator
        )
        self.expires_in = expires_in or 3600
        self.token_extractor = BearerTokenExtractor()

    def create_token(self, request, refresh_token=False, **kwargs):
        """
        Create a BearerToken, by default without refresh token.

        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        :param refresh_token:
        """
        if "save_token" in kwargs:
            warnings.warn("`save_token` has been deprecated, it was not called internally."
                          "If you do, call `request_validator.save_token()` instead.",
                          DeprecationWarning)

        expires_in = self.expires_in(request) if callable(self.expires_in) else self.expires_in

        request.expires_in = expires_in

        token = {
            'access_token': self.token_generator(request),
            'expires_in': expires_in,
            'token_type': 'Bearer',
        }

        # If provided, include - this is optional in some cases https://tools.ietf.org/html/rfc6749#section-3.3 but
        # there is currently no mechanism to coordinate issuing a token for only a subset of the requested scopes so
        # all tokens issued are for the entire set of requested scopes.
        if request.scopes is not None:
            token['scope'] = ' '.join(request.scopes)

        if refresh_token:
            if (request.refresh_token and
                    not self.request_validator.rotate_refresh_token(request)):
                token['refresh_token'] = request.refresh_token
            else:
                token['refresh_token'] = self.refresh_token_generator(request)

        token.update(request.extra_credentials or {})
        return OAuth2Token(token)

    def validate_request(self, request):
        """
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        """
        if getattr(request, 'strict_bearer', False):  # noqa: SIM108
            # Strict extraction raises InvalidRequestError before any token is
            # handed to the validator, so malformed/ambiguous requests never
            # reach validate_bearer_token.
            token = self.token_extractor.extract_strict(request)
        else:
            token = get_token_from_header(request)
        return self.request_validator.validate_bearer_token(
            token, request.scopes, request)

    def estimate_type(self, request):
        """
        :param request: OAuthlib request.
        :type request: oauthlib.common.Request
        """
        if request.headers.get('Authorization', '').split(' ')[0].lower() == 'bearer':
            return 9
        elif request.access_token is not None:
            return 5
        else:
            return 0
