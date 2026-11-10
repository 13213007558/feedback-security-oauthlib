Authorization Server Issuer Identification (RFC 9207)
=====================================================

`RFC 9207 section 2`_ lets a client tell which authorization server produced
an authorization redirect, which matters when the same backend talks to more
than one authorization server. The server adds an ``iss`` parameter to every
authorization response it is allowed to redirect, and the client compares it
with the issuer it selected when starting that authorization transaction.

.. _`RFC 9207 section 2`: https://www.rfc-editor.org/rfc/rfc9207.html#section-2

Server configuration
--------------------

The issuer comes from trusted server configuration. It must be an HTTPS URL
without query or fragment components, and request parameters can never change
it. Pass it to the grant or to a pre-configured server::

    from oauthlib.oauth2 import AuthorizationCodeGrant, WebApplicationServer

    grant = AuthorizationCodeGrant(validator, issuer='https://as.example/')
    server = WebApplicationServer(validator, issuer='https://as.example/')

An invalid value raises ``ValueError`` at construction time. When configured,
the same ``iss`` value is added to both the successful code redirect and any
OAuth error response that is safe to redirect. Fatal errors (unknown client
or unregistered ``redirect_uri``) are still raised instead of redirected, so
no response is ever sent to an unverified URI.

Client verification
-------------------

Save the expected issuer in the per-authorization transaction, next to the
``state``, and pass it back when parsing the callback::

    # When starting the transaction:
    authorization_uri = client.prepare_request_uri(
        'https://as.example/authorize',
        redirect_uri='https://client.example.com/callback',
        state=state,
    )
    session[state] = {'expected_issuer': 'https://as.example/'}

    # When handling the redirect:
    response = client.parse_request_uri_response(
        callback_uri,
        state=state,
        expected_issuer=session[state]['expected_issuer'],
    )

The issuer must be supplied per call. OAuthLib deliberately keeps no global
or "most recent" issuer on the shared client, so interleaved transactions
against different servers cannot be mixed up.

When ``expected_issuer`` is provided:

* a missing or duplicated ``iss`` parameter, or a value that does not match
  exactly, raises :class:`oauthlib.oauth2.InvalidIssuerError`;
* the value is decoded once with the form rules and compared as an exact
  string — trailing slashes, paths and case are not normalized;
* the issuer is checked before ``state`` and before redirectable OAuth errors
  are raised;
* any failure leaves client attributes such as ``code`` and the token fields
  untouched.

Duplicated ``state``, ``code`` or ``error`` parameters are always rejected
before the response is collapsed into a dictionary, even without
``expected_issuer``. Calls that omit ``expected_issuer`` keep their previous
behavior, so existing integrations are unaffected.

The ``iss`` parameter identifies the authorization server; it is not a
digital signature and does not by itself authenticate the response.

A complete, runnable example is available at
``examples/rfc9207_issuer_identification.py``.
