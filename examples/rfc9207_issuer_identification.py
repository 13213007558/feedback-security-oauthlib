"""RFC 9207 authorization server issuer identification in the auth code flow.

Standard: https://www.rfc-editor.org/rfc/rfc9207.html#section-2

One backend client is registered with two authorization servers. Each server
is configured with a trusted ``issuer`` and appends an ``iss`` parameter to
every authorization redirect (success or redirectable error). The client
saves the ``expected_issuer`` *inside the per-authorization transaction*, next
to the ``state``, and passes it back when parsing the callback. It is never
stored on the shared :class:`WebApplicationClient`, so interleaved
transactions cannot be mixed up.

The example is self-contained: a tiny in-memory validator stands in for a
real deployment, and no web framework, dynamic discovery or metadata fetch is
involved.
"""
from unittest import mock

from oauthlib.oauth2 import (
    InvalidIssuerError, RequestValidator, WebApplicationClient,
    WebApplicationServer,
)

CLIENT_ID = 'shared-backend-client'
REDIRECT_URI = 'https://client.example.com/callback'

# Trusted, out-of-band configuration of the two authorization servers.
# Both values are HTTPS URLs without query or fragment components.
SERVERS = {
    'idp-a': {
        'issuer': 'https://idp-a.example/',
        'authorization_uri': 'https://idp-a.example/authorize',
    },
    'idp-b': {
        'issuer': 'https://idp-b.example/',
        'authorization_uri': 'https://idp-b.example/authorize',
    },
}


def build_validator():
    validator = mock.MagicMock(spec=RequestValidator)
    validator.validate_client_id.return_value = True
    validator.validate_redirect_uri.side_effect = (
        lambda client_id, redirect_uri, request:
            client_id == CLIENT_ID and redirect_uri == REDIRECT_URI)
    validator.get_default_redirect_uri.return_value = REDIRECT_URI
    validator.validate_response_type.return_value = True
    validator.validate_scopes.return_value = True
    validator.is_pkce_required.return_value = False
    validator.get_code_challenge.return_value = None
    return validator


# One shared, stateless client instance.
client = WebApplicationClient(CLIENT_ID)
servers = {
    name: WebApplicationServer(build_validator(), issuer=config['issuer'])
    for name, config in SERVERS.items()
}

# A real application would persist these records in its session/database store.
transactions = {}


def start_authorization(server_name, state):
    """Create the authorization request and remember the chosen issuer."""
    config = SERVERS[server_name]
    authorization_uri = client.prepare_request_uri(
        config['authorization_uri'],
        redirect_uri=REDIRECT_URI,
        scope=['profile'],
        state=state,
    )
    # The issuer is saved PER TRANSACTION, beside the state that binds the
    # callback. Do not keep a "last issuer" on the shared client: another
    # request to the other server would overwrite it.
    transactions[state] = {
        'server': server_name,
        'expected_issuer': config['issuer'],
    }
    return authorization_uri


def handle_callback(callback_uri, state):
    """Parse a redirect using the issuer saved for this transaction."""
    transaction = transactions.pop(state)
    return client.parse_request_uri_response(
        callback_uri,
        state=state,
        expected_issuer=transaction['expected_issuer'],
    )


if __name__ == '__main__':
    # Two interleaved transactions against the two authorization servers.
    uri_a = start_authorization('idp-a', 'state-a')
    uri_b = start_authorization('idp-b', 'state-b')

    headers_a, _, _ = servers['idp-a'].create_authorization_response(
        uri_a, scopes=['profile'])
    headers_b, _, _ = servers['idp-b'].create_authorization_response(
        uri_b, scopes=['profile'])

    response_b = handle_callback(headers_b['Location'], 'state-b')
    response_a = handle_callback(headers_a['Location'], 'state-a')
    if response_a['iss'] != SERVERS['idp-a']['issuer']:
        raise RuntimeError('unexpected issuer in idp-a callback')
    if response_b['iss'] != SERVERS['idp-b']['issuer']:
        raise RuntimeError('unexpected issuer in idp-b callback')
    print('accepted callbacks:', response_a['iss'], response_b['iss'])

    # A callback carrying the other server's issuer is rejected even though
    # that issuer itself is a perfectly valid, trusted issuer.
    spoofed = headers_a['Location'].replace(
        'https%3A%2F%2Fidp-a.example%2F',
        'https%3A%2F%2Fidp-b.example%2F')
    transactions['state-a'] = {
        'server': 'idp-a', 'expected_issuer': SERVERS['idp-a']['issuer']}
    try:
        handle_callback(spoofed, 'state-a')
    except InvalidIssuerError as exc:
        print('rejected spoofed callback:', exc.error)

    # The parameter only identifies the authorization server; it is not a
    # digital signature and does not authenticate the response on its own.
