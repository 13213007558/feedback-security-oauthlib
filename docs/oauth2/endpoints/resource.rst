======================
Resource authorization
======================

Resource endpoints verify that the token presented is valid and granted access
to the scopes associated with the resource in question.

**Request Verification**
    Each view may set certain scopes under which it is bound. Only requests
    that present an access token bound to the correct scopes may access the
    view. Access tokens are commonly embedded in the authorization header but
    may appear in the query or the body as well.

    .. code-block:: python

        # Initial setup
        from your_validator import your_validator
        server = WebApplicationServer(your_validator)

        # Per view scopes
        required_scopes = ['https://example.com/userProfile']

        # Validate request
        uri = 'https://example.com/userProfile?access_token=sldafh309sdf'
        headers, body, http_method = {}, '', 'GET'

        valid, oauthlib_request = server.verify_request(
            uri, http_method, body, headers, required_scopes)

        # oauthlib_request has a few convenient attributes set such as
        # oauthlib_request.client = the client associated with the token
        # oauthlib_request.user = the user associated with the token
        # oauthlib_request.scopes = the scopes bound to this token

        if valid:
            # return the protected resource / view
        else:
            # return an http forbidden 403

Strict Bearer extraction
------------------------

RFC 6750 defines three places an access token may be presented: the
``Authorization: Bearer`` header, the ``access_token`` form-body parameter, and
the ``access_token`` URI query parameter. By default OAuthLib keeps its
historical, lenient behaviour and uses the first usable token it finds. A
resource server that wants to reject ambiguous requests instead can opt in to
the strict Bearer extraction policy when constructing the endpoint or any of
the preconfigured servers::

    from oauthlib.oauth2 import WebApplicationServer

    # Defaults to strict_bearer=False for backwards compatibility.
    server = WebApplicationServer(your_validator, strict_bearer=True)

    # The flag can also be toggled on an existing endpoint.
    server.strict_bearer = True

In strict mode the request is rejected with a standard OAuth 2
``invalid_request`` error (HTTP 400) *before*
``RequestValidator.validate_bearer_token`` is called whenever:

- an access token appears in more than one carrier, even when both carriers
  carry the identical token value (for example a ``Bearer`` header *and* an
  ``access_token`` query parameter);
- a single carrier contains the parameter more than once
  (``?access_token=a&access_token=b`` or a repeated form field);
- a form-body token is sent with a method other than ``POST`` or without the
  ``application/x-www-form-urlencoded`` content type; a JSON body is never a
  form carrier, so an ``access_token`` JSON field is simply ignored;
- the ``Bearer`` header is empty or otherwise malformed (an empty token, or
  more than one token in the header). Other authentication schemes such as
  ``Basic`` are not Bearer carriers and are ignored rather than rejected. The
  ``Bearer`` scheme name itself is matched case-insensitively.

The strict policy works on the request's **raw, multi-valued** parameters.
OAuthLib keeps the full ordered list of query and form values internally, so
the framework integration must pass the original values instead of collapsing
them into a single value first:

- pass the complete URI (including the full query string) to
  ``verify_request``; OAuthLib re-parses every repeated query parameter;
- pass the form body either as the raw ``application/x-www-form-urlencoded``
  string or as a list of ``(name, value)`` tuples. A plain ``dict`` body cannot
  represent repeated fields, so do not convert the framework's multi-value
  query/multi-dict into one before calling OAuthLib;
- pass headers as received. The ``Authorization`` header is matched
  case-insensitively and the ``Content-Type`` may include parameters such as
  ``; charset=utf-8``.

For example, a framework that exposes multi-value parameters as lists can hand
them straight to OAuthLib without losing the duplicate::

    # body keeps both repeated values as tuples:
    body = [("access_token", "first"), ("access_token", "second")]
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    # raises oauthlib.oauth2.InvalidRequestError in strict mode, and
    # validate_bearer_token is never invoked
    valid, oauthlib_request = server.verify_request(
        "https://example.com/resource", "POST", body, headers)

.. autoclass:: oauthlib.oauth2.ResourceEndpoint
    :members:
