/// Persistent session (ratchet state) store.
///
/// Session records hold the Double Ratchet state. Losing or rewinding one is
/// not a cosmetic bug: the next send re-derives a message key and IV that were
/// already used. So every write here must be durable before the caller acts on
/// the result, which is why the database runs with `synchronous = FULL` and the
/// crypto service wraps each libsignal call in a single transaction.
///
/// These writes are synchronous against sqlite3 and the enclosing transaction
/// commits before the service returns, so the "persist before releasing the
/// output" contract holds by construction rather than by convention.
library;

import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';

import '../../storage/encrypted_database.dart';

class PersistentSessionStore implements SessionStore {
  PersistentSessionStore(this._db);

  final EncryptedDatabase _db;

  @override
  Future<SessionRecord?> loadSession(ProtocolAddress address) async {
    final rows = _db.raw.select(
      'SELECT record FROM sessions WHERE address_name = ? AND device_index = ?',
      [address.name(), address.deviceId()],
    );
    if (rows.isEmpty) return null;
    return SessionRecord.deserialize(bytes: _bytes(rows.first['record']));
  }

  @override
  Future<void> storeSession(ProtocolAddress address, SessionRecord record) async {
    _db.raw.execute(
      'INSERT INTO sessions (address_name, device_index, record, updated_at) '
      'VALUES (?, ?, ?, ?) '
      'ON CONFLICT (address_name, device_index) DO UPDATE SET '
      '  record = excluded.record, updated_at = excluded.updated_at',
      [
        address.name(),
        address.deviceId(),
        record.serialize(),
        DateTime.now().millisecondsSinceEpoch,
      ],
    );
  }

  @override
  Future<bool> containsSession(ProtocolAddress address) async {
    final rows = _db.raw.select(
      'SELECT 1 FROM sessions WHERE address_name = ? AND device_index = ?',
      [address.name(), address.deviceId()],
    );
    return rows.isNotEmpty;
  }

  @override
  Future<void> deleteSession(ProtocolAddress address) async {
    _db.raw.execute(
      'DELETE FROM sessions WHERE address_name = ? AND device_index = ?',
      [address.name(), address.deviceId()],
    );
  }

  @override
  Future<void> deleteAllSessions(String name) async {
    _db.raw.execute('DELETE FROM sessions WHERE address_name = ?', [name]);
  }

  @override
  Future<List<int>> getSubDeviceSessions(String name) async {
    final rows = _db.raw.select(
      'SELECT device_index FROM sessions WHERE address_name = ? ORDER BY device_index',
      [name],
    );
    return rows.map((row) => row['device_index'] as int).toList(growable: false);
  }

  static Uint8List _bytes(Object? value) => value is Uint8List
      ? value
      : Uint8List.fromList((value as List).cast<int>());
}
