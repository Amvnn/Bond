/// Persistent prekey stores: one-time, signed, and Kyber.
///
/// Consumption writes matter as much as session writes. A one-time prekey that
/// is used but not recorded as removed can be handed to a second session,
/// which breaks the forward secrecy the one-time key exists to provide. Same
/// for [PersistentKyberPreKeyStore.markKyberPreKeyUsed].
///
/// All three run inside the transaction opened by the crypto service, so a
/// consumption either commits with the rest of the operation or not at all.
library;

import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';

import '../../storage/encrypted_database.dart';

Uint8List _bytes(Object? value) =>
    value is Uint8List ? value : Uint8List.fromList((value as List).cast<int>());

int _now() => DateTime.now().millisecondsSinceEpoch;

class PersistentPreKeyStore implements PreKeyStore {
  PersistentPreKeyStore(this._db);

  final EncryptedDatabase _db;

  @override
  Future<PreKeyRecord?> loadPreKey(int preKeyId) async {
    final rows = _db.raw.select('SELECT record FROM pre_keys WHERE id = ?', [preKeyId]);
    if (rows.isEmpty) return null;
    return PreKeyRecord.deserialize(bytes: _bytes(rows.first['record']));
  }

  @override
  Future<void> storePreKey(int preKeyId, PreKeyRecord record) async {
    _db.raw.execute(
      'INSERT INTO pre_keys (id, record, created_at) VALUES (?, ?, ?) '
      'ON CONFLICT (id) DO UPDATE SET record = excluded.record',
      [preKeyId, record.serialize(), _now()],
    );
  }

  @override
  Future<bool> containsPreKey(int preKeyId) async {
    return _db.raw.select('SELECT 1 FROM pre_keys WHERE id = ?', [preKeyId]).isNotEmpty;
  }

  @override
  Future<void> removePreKey(int preKeyId) async {
    // Consumption. Must be durable: a one-time prekey reused across two
    // sessions defeats the forward secrecy it exists for.
    _db.raw.execute('DELETE FROM pre_keys WHERE id = ?', [preKeyId]);
  }

  @override
  Future<List<int>> getAllPreKeyIds() async {
    final rows = _db.raw.select('SELECT id FROM pre_keys ORDER BY id');
    return rows.map((row) => row['id'] as int).toList(growable: false);
  }

  /// How many unused one-time prekeys remain, so the app knows when to
  /// replenish the server's supply.
  int availableCount() =>
      _db.raw.select('SELECT count(*) AS c FROM pre_keys').first['c'] as int;

  /// Highest id issued so far, so replenishment never reuses an id the server
  /// may still be handing out.
  int highestId() {
    final rows = _db.raw.select('SELECT COALESCE(MAX(id), 0) AS m FROM pre_keys');
    return rows.first['m'] as int;
  }
}

class PersistentSignedPreKeyStore implements SignedPreKeyStore {
  PersistentSignedPreKeyStore(this._db);

  final EncryptedDatabase _db;

  @override
  Future<SignedPreKeyRecord?> loadSignedPreKey(int signedPreKeyId) async {
    final rows = _db.raw
        .select('SELECT record FROM signed_pre_keys WHERE id = ?', [signedPreKeyId]);
    if (rows.isEmpty) return null;
    return SignedPreKeyRecord.deserialize(bytes: _bytes(rows.first['record']));
  }

  @override
  Future<void> storeSignedPreKey(int signedPreKeyId, SignedPreKeyRecord record) async {
    _db.raw.execute(
      'INSERT INTO signed_pre_keys (id, record, created_at) VALUES (?, ?, ?) '
      'ON CONFLICT (id) DO UPDATE SET record = excluded.record',
      [signedPreKeyId, record.serialize(), _now()],
    );
  }

  @override
  Future<bool> containsSignedPreKey(int signedPreKeyId) async {
    return _db.raw
        .select('SELECT 1 FROM signed_pre_keys WHERE id = ?', [signedPreKeyId])
        .isNotEmpty;
  }

  @override
  Future<void> removeSignedPreKey(int signedPreKeyId) async {
    _db.raw.execute('DELETE FROM signed_pre_keys WHERE id = ?', [signedPreKeyId]);
  }

  @override
  Future<List<int>> getAllSignedPreKeyIds() async {
    final rows = _db.raw.select('SELECT id FROM signed_pre_keys ORDER BY id');
    return rows.map((row) => row['id'] as int).toList(growable: false);
  }
}

class PersistentKyberPreKeyStore implements KyberPreKeyStore {
  PersistentKyberPreKeyStore(this._db);

  final EncryptedDatabase _db;

  @override
  Future<KyberPreKeyRecord?> loadKyberPreKey(int kyberPreKeyId) async {
    final rows = _db.raw
        .select('SELECT record FROM kyber_pre_keys WHERE id = ?', [kyberPreKeyId]);
    if (rows.isEmpty) return null;
    return KyberPreKeyRecord.deserialize(bytes: _bytes(rows.first['record']));
  }

  @override
  Future<void> storeKyberPreKey(int kyberPreKeyId, KyberPreKeyRecord record) async {
    _db.raw.execute(
      'INSERT INTO kyber_pre_keys (id, record, used, created_at) VALUES (?, ?, 0, ?) '
      'ON CONFLICT (id) DO UPDATE SET record = excluded.record',
      [kyberPreKeyId, record.serialize(), _now()],
    );
  }

  @override
  Future<bool> containsKyberPreKey(int kyberPreKeyId) async {
    return _db.raw
        .select('SELECT 1 FROM kyber_pre_keys WHERE id = ?', [kyberPreKeyId])
        .isNotEmpty;
  }

  @override
  Future<void> markKyberPreKeyUsed(
    int kyberPreKeyId,
    int signedPreKeyId,
    PublicKey baseKey,
  ) async {
    // Consumption write. Recorded rather than deleted: a last-resort Kyber key
    // is reusable, so the record must survive while the flag tracks use.
    _db.raw.execute('UPDATE kyber_pre_keys SET used = 1 WHERE id = ?', [kyberPreKeyId]);
  }

  @override
  Future<void> removeKyberPreKey(int kyberPreKeyId) async {
    _db.raw.execute('DELETE FROM kyber_pre_keys WHERE id = ?', [kyberPreKeyId]);
  }

  @override
  Future<List<int>> getAllKyberPreKeyIds() async {
    final rows = _db.raw.select('SELECT id FROM kyber_pre_keys ORDER BY id');
    return rows.map((row) => row['id'] as int).toList(growable: false);
  }

  bool isUsed(int kyberPreKeyId) {
    final rows =
        _db.raw.select('SELECT used FROM kyber_pre_keys WHERE id = ?', [kyberPreKeyId]);
    return rows.isNotEmpty && (rows.first['used'] as int) == 1;
  }
}
