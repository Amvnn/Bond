/// Accessors for `auth_state`: the ACCOUNT session, not cryptographic identity.
///
/// The two are separate tables because they are separate concepts with separate
/// lifetimes, and the brief is explicit that conflating them is the mistake to
/// avoid. Concretely: logging out destroys the account session but may leave
/// the device's cryptographic identity intact, whereas revocation destroys
/// both. Keeping them apart is what makes that distinction expressible.
///
/// Tokens are stored inside the SQLCipher database, so they are encrypted at
/// rest under a key held by the OS secure store. They are never written to a
/// plain file, a preferences store, or a log.
library;

import 'encrypted_database.dart';

/// The persisted account session.
class StoredSession {
  const StoredSession({
    required this.userId,
    required this.username,
    required this.accessToken,
    required this.refreshToken,
  });

  final String userId;
  final String username;
  final String? accessToken;
  final String? refreshToken;

  bool get hasTokens => accessToken != null && refreshToken != null;

  @override
  String toString() =>
      'StoredSession(userId: $userId, username: $username, tokens: <redacted>)';
}

class AuthStore {
  const AuthStore(this._db);

  final EncryptedDatabase _db;

  /// Creates or replaces the single session row.
  void save({
    required String userId,
    required String username,
    String? accessToken,
    String? refreshToken,
  }) {
    _db.raw.execute(
      'INSERT INTO auth_state '
      '(id, user_id, username, access_token, refresh_token, updated_at) '
      'VALUES (1, ?, ?, ?, ?, ?) '
      'ON CONFLICT (id) DO UPDATE SET '
      '  user_id = excluded.user_id, '
      '  username = excluded.username, '
      '  access_token = excluded.access_token, '
      '  refresh_token = excluded.refresh_token, '
      '  updated_at = excluded.updated_at',
      [
        userId,
        username,
        accessToken,
        refreshToken,
        DateTime.now().millisecondsSinceEpoch,
      ],
    );
  }

  /// Updates only the identity columns, leaving any stored tokens alone.
  ///
  /// Separate from [save] because registration writes the two halves at
  /// different moments: the tokens arrive inside the API call, through the
  /// token callback, and the user id comes back in its result. Using [save]
  /// for the second half would pass `accessToken: null` and wipe the tokens
  /// that had just been stored — which left a freshly registered account
  /// signed out on the next restart.
  void saveIdentity({required String userId, required String username}) {
    _db.raw.execute(
      'INSERT INTO auth_state '
      '(id, user_id, username, access_token, refresh_token, updated_at) '
      'VALUES (1, ?, ?, NULL, NULL, ?) '
      'ON CONFLICT (id) DO UPDATE SET '
      '  user_id = excluded.user_id, '
      '  username = excluded.username, '
      '  updated_at = excluded.updated_at',
      [userId, username, DateTime.now().millisecondsSinceEpoch],
    );
  }

  /// Updates only the tokens, leaving the identity columns alone.
  ///
  /// Called on every refresh. The rotated refresh token must be persisted
  /// before the next refresh, or the client replays a spent token and the
  /// server revokes the entire session family as suspected theft.
  void updateTokens({
    required String accessToken,
    required String refreshToken,
  }) {
    _db.raw.execute(
      'UPDATE auth_state SET access_token = ?, refresh_token = ?, updated_at = ? '
      'WHERE id = 1',
      [accessToken, refreshToken, DateTime.now().millisecondsSinceEpoch],
    );
  }

  StoredSession? read() {
    final rows = _db.raw.select(
      'SELECT user_id, username, access_token, refresh_token '
      '  FROM auth_state WHERE id = 1',
    );
    if (rows.isEmpty) return null;
    final row = rows.first;
    return StoredSession(
      userId: row['user_id'] as String,
      username: row['username'] as String,
      accessToken: row['access_token'] as String?,
      refreshToken: row['refresh_token'] as String?,
    );
  }

  /// Forgets the tokens but keeps the identity, so the sign-in screen can
  /// prefill the username without holding a credential.
  void clearTokens() {
    _db.raw.execute(
      'UPDATE auth_state SET access_token = NULL, refresh_token = NULL, '
      'updated_at = ? WHERE id = 1',
      [DateTime.now().millisecondsSinceEpoch],
    );
  }

  void clear() => _db.raw.execute('DELETE FROM auth_state WHERE id = 1');
}
