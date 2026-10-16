/// Encrypted local database.
///
/// Everything the client must keep across restarts lives here: libsignal
/// session and prekey state, peer identity keys and their verification status,
/// cached messages, and authentication tokens. The database key itself lives in
/// the platform secure key store, so one OS-protected secret guards the rest.
///
/// THE FAILURE MODE THIS CLASS EXISTS TO PREVENT
///
/// `PRAGMA key` against a build of sqlite3 WITHOUT SQLCipher does nothing and
/// reports nothing. No exception, no warning — you get a fully working,
/// completely unencrypted database. Every message and every private key would
/// sit in plaintext on disk while the code looks correct.
///
/// So [open] probes `PRAGMA cipher_version` and refuses to continue if the
/// build is not SQLCipher. Fail closed, per the project's error-handling rules.
library;

import 'dart:math';
import 'dart:typed_data';

import 'package:sqlite3/sqlite3.dart';

import 'secure_key_store.dart';

/// Key under which the database key is held in the secure key store.
const String databaseKeyName = 'local_db_key';

/// 256-bit database key.
const int _databaseKeyBytes = 32;

class LocalDatabaseException implements Exception {
  const LocalDatabaseException(this.message);
  final String message;
  @override
  String toString() => 'LocalDatabaseException: $message';
}

class EncryptedDatabase {
  EncryptedDatabase._(this._db);

  final Database _db;

  /// Exposed for the libsignal stores, which own their own tables.
  Database get raw => _db;

  /// Opens (creating if needed) the encrypted database at [path].
  ///
  /// The key is fetched from [keyStore], and generated on first run. If the key
  /// store is unavailable this throws rather than falling back to an
  /// unencrypted database.
  static Future<EncryptedDatabase> open({
    required String path,
    required SecureKeyStore keyStore,
  }) async {
    final key = await _loadOrCreateKey(keyStore);
    final db = sqlite3.open(path);

    try {
      // Must be the first statement on the connection.
      db.execute("PRAGMA key = \"x'${_hex(key)}'\";");

      _assertCipherAvailable(db);
      _assertKeyCorrect(db, path);

      db.execute('PRAGMA journal_mode = WAL;');
      db.execute('PRAGMA foreign_keys = ON;');
      // Durability matters here beyond the usual: libsignal requires a store
      // write to reach stable storage before the operation's output is
      // released, or a crash rewinds the ratchet and the next send reuses a
      // message key. FULL, not NORMAL.
      db.execute('PRAGMA synchronous = FULL;');

      _migrate(db);
      return EncryptedDatabase._(db);
    } catch (_) {
      db.close();
      rethrow;
    }
  }

  /// Opens an in-memory database for tests. NEVER used by the app.
  ///
  /// It is still keyed, so the same code path runs — but an in-memory database
  /// cannot test restart survival, which is what [open] with a real file is for.
  static EncryptedDatabase openInMemoryForTests() {
    final db = sqlite3.openInMemory();
    db.execute("PRAGMA key = \"x'${_hex(generateDatabaseKey())}'\";");
    _assertCipherAvailable(db);
    _migrate(db);
    return EncryptedDatabase._(db);
  }

  /// Probes for SQLCipher. Plain SQLite returns no rows for this pragma.
  static void _assertCipherAvailable(Database db) {
    ResultSet result;
    try {
      result = db.select('PRAGMA cipher_version;');
    } on SqliteException catch (error) {
      throw LocalDatabaseException(
        'could not query PRAGMA cipher_version (${error.message}); '
        'refusing to use a possibly unencrypted database',
      );
    }

    if (result.isEmpty || (result.first.values.first?.toString() ?? '').isEmpty) {
      throw const LocalDatabaseException(
        'sqlite3 was built WITHOUT SQLCipher: PRAGMA key silently does nothing, '
        'so this database would be stored in plaintext. Check the '
        '`hooks: user_defines: sqlite3: source: sqlcipher` block in pubspec.yaml. '
        'Refusing to continue.',
      );
    }
  }

  /// Confirms the key actually decrypts the file.
  ///
  /// With a wrong key, SQLCipher cannot read the header and the first real
  /// query fails. Checking here turns that into a clear error at startup
  /// instead of a confusing failure later.
  static void _assertKeyCorrect(Database db, String path) {
    try {
      db.select('SELECT count(*) FROM sqlite_master;');
    } on SqliteException catch (error) {
      throw LocalDatabaseException(
        'cannot read $path with the stored key (${error.message}). '
        'The key store and the database file have diverged; the local data is '
        'unrecoverable and the device must be re-provisioned.',
      );
    }
  }

  static Uint8List generateDatabaseKey() {
    final random = Random.secure();
    return Uint8List.fromList(
      List<int>.generate(_databaseKeyBytes, (_) => random.nextInt(256)),
    );
  }

  static Future<Uint8List> _loadOrCreateKey(SecureKeyStore keyStore) async {
    final existing = await keyStore.read(databaseKeyName);
    if (existing != null) {
      if (existing.length != _databaseKeyBytes) {
        throw LocalDatabaseException(
          'stored database key has wrong length (${existing.length} bytes); '
          'refusing to guess',
        );
      }
      return existing;
    }
    final fresh = generateDatabaseKey();
    await keyStore.write(databaseKeyName, fresh);
    return fresh;
  }

  static String _hex(Uint8List bytes) =>
      bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

  // -------------------------------------------------------------------------
  // Schema
  //
  // Note the separation the brief requires: `auth_state` (account session) is a
  // different table from `identities` / `sessions` (cryptographic identity).
  // They are different kinds of secret with different lifetimes, and conflating
  // them is the mistake that separation exists to prevent.
  // -------------------------------------------------------------------------
  static void _migrate(Database db) {
    db.execute('''
      CREATE TABLE IF NOT EXISTS meta (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );

      -- Account session. NOT cryptographic identity.
      CREATE TABLE IF NOT EXISTS auth_state (
        id             INTEGER PRIMARY KEY CHECK (id = 1),
        user_id        TEXT    NOT NULL,
        username       TEXT    NOT NULL,
        access_token   TEXT,
        refresh_token  TEXT,
        updated_at     INTEGER NOT NULL
      );

      -- This device's cryptographic identity.
      CREATE TABLE IF NOT EXISTS device_identity (
        id                   INTEGER PRIMARY KEY CHECK (id = 1),
        device_id            TEXT    NOT NULL,
        device_index         INTEGER NOT NULL,
        registration_id      INTEGER NOT NULL,
        identity_key_pair    BLOB    NOT NULL,
        created_at           INTEGER NOT NULL
      );

      -- libsignal session records, one per remote protocol address.
      CREATE TABLE IF NOT EXISTS sessions (
        address_name  TEXT    NOT NULL,
        device_index  INTEGER NOT NULL,
        record        BLOB    NOT NULL,
        updated_at    INTEGER NOT NULL,
        PRIMARY KEY (address_name, device_index)
      );

      -- Peer identity keys, and the trust decision about them.
      --
      -- previous_identity_key + changed_at exist so an identity CHANGE is a
      -- durable fact the UI can surface, not a transient event that is lost if
      -- the app closes before the user sees the warning.
      CREATE TABLE IF NOT EXISTS peer_identities (
        address_name          TEXT    NOT NULL,
        device_index          INTEGER NOT NULL,
        identity_key          BLOB    NOT NULL,
        first_seen_at         INTEGER NOT NULL,
        verified_at           INTEGER,
        previous_identity_key BLOB,
        changed_at            INTEGER,
        PRIMARY KEY (address_name, device_index)
      );

      CREATE TABLE IF NOT EXISTS pre_keys (
        id         INTEGER PRIMARY KEY,
        record     BLOB    NOT NULL,
        created_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS signed_pre_keys (
        id         INTEGER PRIMARY KEY,
        record     BLOB    NOT NULL,
        created_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS kyber_pre_keys (
        id         INTEGER PRIMARY KEY,
        record     BLOB    NOT NULL,
        used       INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL
      );

      -- Local message history. Plaintext bodies, protected at rest by the
      -- database encryption above and by nothing else — which is why the
      -- cipher probe is not optional.
      --
      -- `message_id` is the LOCAL identity of a message. For an incoming
      -- message that is the server's id. For an outgoing one it is a locally
      -- generated id, because one message the user typed becomes one envelope
      -- per recipient device and therefore several server ids — see
      -- outgoing_targets below.
      CREATE TABLE IF NOT EXISTS local_messages (
        message_id       TEXT PRIMARY KEY,
        peer_user_id     TEXT    NOT NULL,
        peer_device_index INTEGER,
        outgoing         INTEGER NOT NULL,
        body             TEXT    NOT NULL,
        sender_sequence  INTEGER,
        state            TEXT    NOT NULL,
        created_at       INTEGER NOT NULL
      );

      CREATE INDEX IF NOT EXISTS local_messages_peer_idx
        ON local_messages (peer_user_id, created_at);

      -- Per-recipient-device fan-out of one outgoing message.
      --
      -- A contact with two devices gets two envelopes with two server ids, and
      -- receipts arrive per envelope. Without this mapping a `message.delivered`
      -- frame could not be attributed to anything, and the displayed state of a
      -- message would have to come from whichever receipt arrived last rather
      -- than from all of them.
      -- The ciphertext is kept here, and not re-derived, so that a retry after
      -- an ambiguous network failure resends the IDENTICAL bytes and sequence.
      -- Re-encrypting would advance the ratchet and produce a new sequence, so
      -- the server's duplicate detection would not recognise it and the
      -- recipient would receive the message twice.
      CREATE TABLE IF NOT EXISTS outgoing_targets (
        local_id            TEXT    NOT NULL,
        recipient_device_id TEXT    NOT NULL,
        server_message_id   TEXT,
        state               TEXT    NOT NULL,
        message_type        TEXT    NOT NULL DEFAULT '',
        ciphertext          TEXT    NOT NULL DEFAULT '',
        sender_sequence     INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (local_id, recipient_device_id)
      );

      CREATE INDEX IF NOT EXISTS outgoing_targets_server_idx
        ON outgoing_targets (server_message_id);

      -- Outgoing sequence counter per remote device, so sender_sequence is
      -- monotonic across restarts.
      CREATE TABLE IF NOT EXISTS send_counters (
        recipient_device_id TEXT PRIMARY KEY,
        next_sequence       INTEGER NOT NULL
      );
    ''');
  }

  /// Runs [action] inside a transaction and commits before returning.
  ///
  /// Every libsignal store write goes through this. The library persists
  /// ratchet state through the store callbacks before releasing its output, so
  /// the callback must not resolve until the write is durable — otherwise a
  /// crash rewinds the ratchet.
  T transaction<T>(T Function() action) {
    _db.execute('BEGIN IMMEDIATE;');
    try {
      final result = action();
      _db.execute('COMMIT;');
      return result;
    } catch (_) {
      try {
        _db.execute('ROLLBACK;');
      } catch (_) {
        // A failed rollback must not mask the original error.
      }
      rethrow;
    }
  }

  void dispose() => _db.close();

  /// Destroys all local state. Used on logout and on device revocation.
  void wipe() {
    transaction(() {
      for (final table in const [
        'auth_state',
        'device_identity',
        'sessions',
        'peer_identities',
        'pre_keys',
        'signed_pre_keys',
        'kyber_pre_keys',
        'local_messages',
        'outgoing_targets',
        'send_counters',
        'meta',
      ]) {
        _db.execute('DELETE FROM $table;');
      }
    });
  }
}
