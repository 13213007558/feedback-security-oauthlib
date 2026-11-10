Refresh Token Grant
------------------------

.. autoclass:: oauthlib.oauth2.RefreshTokenGrant
    :members:
    :inherited-members:

Atomic refresh token rotation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

By default the grant validates the presented refresh token and later saves
the newly issued token as two separate steps
(``validate_refresh_token`` / ``save_token``). Two concurrent requests
presenting the same refresh token can therefore both pass validation.

Validators may instead opt into the
:class:`oauthlib.oauth2.AtomicRefreshTokenStore` contract, which consumes
the old token and persists its successor - including token generation and
token modifiers - in a single atomic commit. If generation or a modifier
fails, the whole operation rolls back, so a token is never left consumed
without a successor. Only one concurrent request can win; any later reuse
of the consumed token is a replay and triggers the store's explicit
policy, revoking that token family only. Rejection responses never reveal
family identifiers or token plaintext.

See ``examples/atomic_refresh_token_rotation.py`` for a runnable SQLite
in-memory implementation that lines two concurrent requests up on a
barrier and verifies the persisted state and both responses.

.. note::
    In deployments spanning multiple processes or hosts, the storage layer
    itself must guarantee the atomic consume-and-replace (e.g. a database
    transaction with a conditional ``UPDATE``). In-process locks only
    serialize threads of a single process and are not sufficient on their
    own.

.. autoclass:: oauthlib.oauth2.AtomicRefreshTokenStore
    :members:
