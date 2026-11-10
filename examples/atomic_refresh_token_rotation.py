"""Atomic refresh token rotation with single-consumption and replay detection.

Demonstrates the optional :class:`AtomicRefreshTokenStore` contract on top of
an SQLite in-memory database (shared cache, one connection per call so the
write lock serializes concurrent transactions, exactly as a file-backed
database would across connections).

Two concurrent refresh requests presenting the *same* refresh token are held
on a barrier right after validation and then released together: exactly one
wins, the loser is treated as a replay and its whole token family (and only
that family) is revoked. The error response never reveals family identifiers
or token plaintext.

Run it directly::

    python examples/atomic_refresh_token_rotation.py

.. note::
    This example serializes connections of a single process. In a
    multi-process or multi-host deployment the storage layer itself must
    guarantee the atomic consume-and-replace (e.g. ``BEGIN IMMEDIATE`` /
    conditional ``UPDATE`` against a shared database); an in-process lock
    does not protect you there.
"""
import json
import sqlite3
import sys
import threading
import time

from oauthlib.common import Request
from oauthlib.oauth2 import (
    AtomicRefreshTokenStore,
    BearerToken,
    RequestValidator,
    RefreshTokenGrant,
)
from oauthlib.oauth2.rfc6749 import errors

SCHEMA = """
CREATE TABLE refresh_tokens (
    token      TEXT PRIMARY KEY,
    client_id  TEXT NOT NULL,
    user       TEXT NOT NULL,
    family_id  TEXT NOT NULL,
    scopes     TEXT NOT NULL,
    consumed   INTEGER NOT NULL DEFAULT 0,
    revoked    INTEGER NOT NULL DEFAULT 0
);
"""


class Client:
    def __init__(self, client_id):
        self.client_id = client_id


class SQLiteAtomicRefreshTokenStore(RequestValidator, AtomicRefreshTokenStore):
    """Refresh token store honoring the atomic rotation contract.

    The consume of the old token, the token generation/modifiers and the
    insert of the successor happen inside one ``BEGIN IMMEDIATE``
    transaction: any failure rolls everything back, so a token is never
    left consumed without a persisted successor.
    """

    def __init__(self, after_validation_hook=None):
        # Shared-cache in-memory database; the keeper connection keeps it
        # alive while per-call connections contend on the write lock.
        self._dsn = 'file:atomic_refresh_demo?mode=memory&cache=shared'
        self._keeper = self._connect()
        self._keeper.executescript(SCHEMA)
        # Demo/test hook invoked after validation, before the transaction,
        # e.g. a threading.Barrier lining up concurrent requests.
        self.after_validation_hook = after_validation_hook

    def _connect(self):
        return sqlite3.connect(self._dsn, uri=True, timeout=30,
                               isolation_level=None)

    # -- seeding / inspection helpers (not part of the contract) ----------

    def add_refresh_token(self, token, client_id, user, family_id, scopes):
        self._keeper.execute(
            'INSERT INTO refresh_tokens (token, client_id, user, family_id, scopes)'
            ' VALUES (?, ?, ?, ?, ?)',
            (token, client_id, user, family_id, ' '.join(scopes)))
        self._keeper.commit()

    def token_row(self, token):
        connection = self._connect()
        try:
            cursor = connection.execute(
                'SELECT token, client_id, user, family_id, scopes, consumed, revoked'
                ' FROM refresh_tokens WHERE token = ?', (token,))
            columns = [column[0] for column in cursor.description]
            row = cursor.fetchone()
            return dict(zip(columns, row)) if row else None
        finally:
            connection.close()

    def family_rows(self, family_id):
        connection = self._connect()
        try:
            cursor = connection.execute(
                'SELECT token, consumed, revoked FROM refresh_tokens WHERE family_id = ?',
                (family_id,))
            return cursor.fetchall()
        finally:
            connection.close()

    # -- read-only RequestValidator methods --------------------------------

    def client_authentication_required(self, request, *args, **kwargs):
        return False

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        request.client = Client(client_id)
        return True

    def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
        return grant_type == 'refresh_token'

    def validate_refresh_token(self, refresh_token, client, request, *args, **kwargs):
        # Not used by the Refresh Token Grant in atomic mode (all checks
        # happen inside rotate_refresh_token_atomic); kept for other
        # callers of the RequestValidator interface. Must stay
        # non-consuming.
        row = self.token_row(refresh_token)
        return bool(row and row['client_id'] == client.client_id
                    and not row['consumed'] and not row['revoked'])

    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        row = self.token_row(refresh_token)
        return row['scopes'].split() if row else []

    def rotate_refresh_token(self, request):
        return True

    def save_token(self, token, request, *args, **kwargs):
        raise NotImplementedError(
            'AtomicRefreshTokenStore persists tokens inside '
            'rotate_refresh_token_atomic; save_token is never called.')

    # -- the atomic contract ------------------------------------------------

    def rotate_refresh_token_atomic(self, request, token_factory):
        connection = self._connect()
        try:
            if self.after_validation_hook:
                self.after_validation_hook()
            # Shared-cache connections raise instead of blocking on a held
            # table lock, so retry until the competing transaction commits.
            deadline = time.monotonic() + 30
            while True:
                try:
                    connection.execute('BEGIN IMMEDIATE')
                    break
                except sqlite3.OperationalError as error:
                    if 'locked' not in str(error) or time.monotonic() > deadline:
                        raise
                    time.sleep(0.01)
            row = connection.execute(
                'SELECT client_id, user, family_id, scopes, consumed, revoked'
                ' FROM refresh_tokens WHERE token = ?',
                (request.refresh_token,)).fetchone()
            if (row is None or row[5] or row[0] != request.client_id):
                connection.execute('ROLLBACK')
                raise errors.InvalidGrantError(request=request)
            if row[4]:  # already consumed: replay -> revoke this family only
                connection.execute(
                    'UPDATE refresh_tokens SET revoked = 1 WHERE family_id = ?',
                    (row[2],))
                connection.execute('COMMIT')
                # Generic error: no family id, no token plaintext.
                raise errors.InvalidGrantError(request=request)
            cursor = connection.execute(
                'UPDATE refresh_tokens SET consumed = 1'
                ' WHERE token = ? AND consumed = 0',
                (request.refresh_token,))
            if cursor.rowcount != 1:
                connection.execute('ROLLBACK')
                raise errors.InvalidGrantError(request=request)
            # Generators and token modifiers run inside the transaction:
            # if anything raises, the consume above is rolled back too.
            token = token_factory(request)
            connection.execute(
                'INSERT INTO refresh_tokens (token, client_id, user, family_id, scopes)'
                ' VALUES (?, ?, ?, ?, ?)',
                (token['refresh_token'], row[0], row[1], row[2], row[3]))
            connection.execute('COMMIT')
            return token
        except Exception:
            if connection.in_transaction:
                connection.execute('ROLLBACK')
            raise
        finally:
            connection.close()


def make_refresh_request(refresh_token, client_id):
    request = Request('https://provider.example/token')
    request.grant_type = 'refresh_token'
    request.refresh_token = refresh_token
    request.client_id = client_id
    return request


def require(condition, message):
    if not condition:
        raise RuntimeError('demo verification failed: %s' % message)


def report(line):
    sys.stdout.write(line + '\n')


def main():
    barrier = threading.Barrier(2)
    store = SQLiteAtomicRefreshTokenStore(after_validation_hook=barrier.wait)
    store.add_refresh_token('rt-alice-1', 'client-a', 'alice', 'fam-alice', ['read'])
    store.add_refresh_token('rt-bob-1', 'client-b', 'bob', 'fam-bob', ['read'])

    grant = RefreshTokenGrant(request_validator=store)
    bearer = BearerToken(request_validator=store)

    results = []

    def refresh(refresh_token, client_id):
        headers, body, status = grant.create_token_response(
            make_refresh_request(refresh_token, client_id), bearer)
        results.append((status, json.loads(body)))

    threads = [
        threading.Thread(target=refresh, args=('rt-alice-1', 'client-a')),
        threading.Thread(target=refresh, args=('rt-alice-1', 'client-a')),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    successes = [body for status, body in results if status == 200]
    failures = [body for status, body in results if status != 200]

    require(len(successes) == 1, 'expected exactly one winner, got %r' % (results,))
    require(len(failures) == 1, 'expected exactly one loser, got %r' % (results,))
    require(failures[0]['error'] == 'invalid_grant', 'unexpected error %r' % (failures,))

    # The rejection must not leak family identifiers or token plaintext.
    rejection = json.dumps(failures[0])
    require('fam-alice' not in rejection, 'rejection leaks the family id')
    require('rt-alice-1' not in rejection, 'rejection leaks token plaintext')

    new_token = successes[0]['refresh_token']
    old_row = store.token_row('rt-alice-1')
    new_row = store.token_row(new_token)
    require(old_row['consumed'] == 1, 'old token was not consumed')
    require(new_row is not None, 'successor token was not persisted')
    require(new_row['family_id'] == 'fam-alice', 'successor lost its family')

    # The replay revoked alice's whole family, including the successor the
    # winner just received; bob's tokens are untouched.
    require(all(revoked for _, _, revoked in store.family_rows('fam-alice')),
            'replay did not revoke the whole family')
    require(all(not revoked for _, _, revoked in store.family_rows('fam-bob')),
            'replay affected another user\'s tokens')

    report('winner:  200, new refresh token issued (family fam-alice)')
    report('loser:   400 invalid_grant (replay detected, family revoked)')
    report('persisted state:')
    for token, consumed, revoked in store.family_rows('fam-alice'):
        report('  fam-alice token=%s... consumed=%d revoked=%d'
               % (token[:12], consumed, revoked))
    for token, consumed, revoked in store.family_rows('fam-bob'):
        report('  fam-bob   token=%s... consumed=%d revoked=%d'
               % (token[:12], consumed, revoked))


if __name__ == '__main__':
    main()
