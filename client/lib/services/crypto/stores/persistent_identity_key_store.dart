// ignore_for_file: prefer_initializing_formals
// The suggested fix is illegal: Dart forbids named parameters that begin
// with an underscore, so `required this._field` does not compile for the
// named constructors below.
/// Persistent identity key store, with identity-change detection.
///
/// WHY THIS EXISTS RATHER THAN THE BUNDLED ONE
///
/// libsignal ships `InMemoryIdentityKeyStore`, whose own documentation says it
/// uses trust-on-first-use and "trusts any new identity automatically". It also
/// loses everything on restart, which disables change detection entirely. Using
/// it would mean the app has no defence against the one attack that key
/// verification exists to catch — a server substituting a contact's key
/// (threat T2).
///
/// THE TRUST POLICY, and why it is asymmetric
///
///   * **New address** (first contact): trusted. Nothing is known yet, so there
///     is nothing to compare against. The conversation is marked unverified and
///     the UI must say so. This is the inherent limit of first contact, not a
///     weakness we chose.
///
///   * **Unchanged key**: trusted.
///
///   * **Changed key, receiving**: trusted, but the change is RECORDED durably,
///     verification is revoked, and the UI must warn. Refusing here would mean
///     the user cannot read incoming messages at all, which pushes them to
///     reinstall and lose the warning. Accepting-and-shouting is strictly more
///     informative than silently failing. It is not "silently trusting": the
///     change is persisted and surfaced.
///
///   * **Changed key, sending**: REFUSED until the user acknowledges it.
///     This is the direction where trusting a substituted key hands new
///     plaintext to an attacker, so it fails closed. The user must explicitly
///     accept the new identity (re-verify) before sending resumes.
library;

import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';
import 'package:sqlite3/sqlite3.dart';

import '../../storage/encrypted_database.dart';

class PersistentIdentityKeyStore implements IdentityKeyStore {
  PersistentIdentityKeyStore({
    required EncryptedDatabase database,
    required IdentityKeyPair identityKeyPair,
    required int localRegistrationId,
  })  : _db = database,
        _identityKeyPair = identityKeyPair,
        _localRegistrationId = localRegistrationId;

  final EncryptedDatabase _db;
  final IdentityKeyPair _identityKeyPair;
  final int _localRegistrationId;

  @override
  Future<IdentityKeyPair> getIdentityKeyPair() async => _identityKeyPair;

  @override
  Future<int> getLocalRegistrationId() async => _localRegistrationId;

  @override
  Future<bool> saveIdentity(ProtocolAddress address, PublicKey identityKey) async {
    final incoming = identityKey.serialize();
    final existing = _readRow(address);
    final now = DateTime.now().millisecondsSinceEpoch;

    if (existing == null) {
      _db.raw.execute(
        'INSERT INTO peer_identities '
        '(address_name, device_index, identity_key, first_seen_at) '
        'VALUES (?, ?, ?, ?)',
        [address.name(), address.deviceId(), incoming, now],
      );
      return true;
    }

    if (_sameBytes(existing.identityKey, incoming)) return false;

    // An identity change. Record the previous key and the time, and revoke any
    // verification — a verified status earned by the OLD key says nothing about
    // this one. `changed_at` stays set until the user acknowledges, and
    // isTrustedIdentity refuses to SEND while it is set.
    _db.raw.execute(
      'UPDATE peer_identities '
      '   SET previous_identity_key = identity_key, '
      '       identity_key = ?, '
      '       changed_at = ?, '
      '       verified_at = NULL '
      ' WHERE address_name = ? AND device_index = ?',
      [incoming, now, address.name(), address.deviceId()],
    );
    return true;
  }

  @override
  Future<PublicKey?> getIdentity(ProtocolAddress address) async {
    final row = _readRow(address);
    if (row == null) return null;
    return PublicKey.deserialize(bytes: row.identityKey);
  }

  @override
  Future<bool> isTrustedIdentity(
    ProtocolAddress address,
    PublicKey identityKey,
    Direction direction,
  ) async {
    final row = _readRow(address);

    // First contact: nothing to compare against.
    if (row == null) return true;

    final incoming = identityKey.serialize();
    if (_sameBytes(row.identityKey, incoming)) {
      // Known key. If a change is still unacknowledged for this address, a
      // send stays blocked even for the matching key, because the user has not
      // yet confirmed which identity they mean to talk to.
      if (direction == Direction.sending && row.changedAt != null) return false;
      return true;
    }

    // Changed key.
    if (direction == Direction.receiving) {
      // Accept so the message can be read, but saveIdentity will record the
      // change and revoke verification, and the UI must warn.
      return true;
    }

    // Sending to a changed identity: fail closed.
    return false;
  }

  // -------------------------------------------------------------------------
  // Application-facing helpers. Not part of the libsignal interface.
  // -------------------------------------------------------------------------

  /// Durable record of a pending identity change, for the warning UI.
  PeerIdentityState? identityState(ProtocolAddress address) => _readRow(address);

  /// All addresses whose identity changed and has not been acknowledged.
  List<PeerIdentityState> unacknowledgedChanges() {
    final rows = _db.raw.select(
      'SELECT address_name, device_index, identity_key, first_seen_at, '
      '       verified_at, previous_identity_key, changed_at '
      '  FROM peer_identities WHERE changed_at IS NOT NULL',
    );
    return rows.map(_mapRow).toList(growable: false).cast<PeerIdentityState>();
  }

  /// Records that the user accepted the new identity after being warned.
  ///
  /// Deliberately separate from verification: acknowledging a change only
  /// unblocks sending. Marking the contact verified again is a further,
  /// explicit act that requires comparing safety numbers out of band.
  void acknowledgeChange(ProtocolAddress address) {
    _db.raw.execute(
      'UPDATE peer_identities SET changed_at = NULL '
      ' WHERE address_name = ? AND device_index = ?',
      [address.name(), address.deviceId()],
    );
  }

  /// Records that the user verified one SPECIFIC key, pinning it if nothing is
  /// pinned for this address yet.
  ///
  /// This is what makes verifying BEFORE the first message meaningful. Without
  /// it, there is no row until a cryptographic operation creates one, so a user
  /// who compared digits and pressed "they match" would have recorded nothing —
  /// and first contact would then trust-on-first-use whatever key the server
  /// supplied, with the comparison having bought them nothing.
  ///
  /// Pinning here is the stronger behaviour: the user asserted something about
  /// a particular key, so that key becomes the trusted one. If the server later
  /// serves a different key, [saveIdentity] sees a change and sending fails
  /// closed, exactly as it would after a message had been exchanged.
  ///
  /// Returns false when a DIFFERENT key is already pinned. That is not a
  /// verification, it is an identity change, and it must go through
  /// acknowledgement rather than being quietly overwritten.
  bool verifyIdentityKey(ProtocolAddress address, Uint8List identityKey) {
    final existing = _readRow(address);
    final now = DateTime.now().millisecondsSinceEpoch;

    if (existing == null) {
      _db.raw.execute(
        'INSERT INTO peer_identities '
        '(address_name, device_index, identity_key, first_seen_at, verified_at) '
        'VALUES (?, ?, ?, ?, ?)',
        [address.name(), address.deviceId(), identityKey, now, now],
      );
      return true;
    }

    if (!_sameBytes(existing.identityKey, identityKey)) return false;

    _db.raw.execute(
      'UPDATE peer_identities SET verified_at = ?, changed_at = NULL '
      ' WHERE address_name = ? AND device_index = ?',
      [now, address.name(), address.deviceId()],
    );
    return true;
  }

  /// Marks the stored identity verified, or clears it.
  ///
  /// This is the authoritative verification state — the server's
  /// `verified_at` is advisory only (docs/decisions.md D4).
  void setVerified(ProtocolAddress address, {required bool verified}) {
    _db.raw.execute(
      'UPDATE peer_identities '
      '   SET verified_at = ?, changed_at = NULL '
      ' WHERE address_name = ? AND device_index = ?',
      [
        verified ? DateTime.now().millisecondsSinceEpoch : null,
        address.name(),
        address.deviceId(),
      ],
    );
  }

  PeerIdentityState? _readRow(ProtocolAddress address) {
    final rows = _db.raw.select(
      'SELECT address_name, device_index, identity_key, first_seen_at, '
      '       verified_at, previous_identity_key, changed_at '
      '  FROM peer_identities WHERE address_name = ? AND device_index = ?',
      [address.name(), address.deviceId()],
    );
    if (rows.isEmpty) return null;
    return _mapRow(rows.first);
  }

  PeerIdentityState _mapRow(Row row) => PeerIdentityState(
        addressName: row['address_name'] as String,
        deviceIndex: row['device_index'] as int,
        identityKey: _bytes(row['identity_key']),
        firstSeenAt: row['first_seen_at'] as int,
        verifiedAt: row['verified_at'] as int?,
        previousIdentityKey: row['previous_identity_key'] == null
            ? null
            : _bytes(row['previous_identity_key']),
        changedAt: row['changed_at'] as int?,
      );

  static Uint8List _bytes(Object? value) => value is Uint8List
      ? value
      : Uint8List.fromList((value as List).cast<int>());

  static bool _sameBytes(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}

/// Durable trust state for one remote protocol address.
class PeerIdentityState {
  const PeerIdentityState({
    required this.addressName,
    required this.deviceIndex,
    required this.identityKey,
    required this.firstSeenAt,
    required this.verifiedAt,
    required this.previousIdentityKey,
    required this.changedAt,
  });

  final String addressName;
  final int deviceIndex;
  final Uint8List identityKey;
  final int firstSeenAt;
  final int? verifiedAt;
  final Uint8List? previousIdentityKey;
  final int? changedAt;

  /// Verified by a human comparing safety numbers, and not since changed.
  bool get isVerified => verifiedAt != null && changedAt == null;

  /// The key changed and the user has not acknowledged it. Sending is blocked.
  bool get hasUnacknowledgedChange => changedAt != null;
}
