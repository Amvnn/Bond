// ignore_for_file: prefer_initializing_formals
// The suggested fix is illegal: Dart forbids named parameters that begin
// with an underscore, so `required this._field` does not compile for the
// named constructors below.
/// The only caller of libsignal in this application.
///
/// Feature code and widgets go through this class. A widget importing
/// `package:libsignal` is a defect — see docs/architecture.md section 3.
///
/// Three contracts are enforced here, each guarding a failure mode that is
/// silent if you get it wrong:
///
///   1. **Serialisation.** Every ratchet operation for one remote address runs
///      under [AddressLock]. Overlapping calls would derive the same message
///      key with no crash and no symptom.
///   2. **Atomicity.** Each operation runs in ONE database transaction, so the
///      session record and the remote identity — written through two separate
///      store callbacks — can never be left inconsistent by a crash between
///      them.
///   3. **Durability.** The transaction commits before the ciphertext or
///      plaintext is returned, on a connection with `synchronous = FULL`. A
///      callback that resolved before the write was durable would let a crash
///      rewind the ratchet.
///
/// Where the private identity key lives: serialised inside the SQLCipher
/// database, whose key is held by the platform secure store (DPAPI on Windows).
/// That satisfies the brief's rule against plain SQLite — the file is
/// encrypted and the key is OS-protected — but note the indirection honestly:
/// compromise of the database key compromises the identity key.
library;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:libsignal/libsignal.dart';

import '../storage/encrypted_database.dart';
import 'address_lock.dart';
import 'stores/persistent_identity_key_store.dart';
import 'stores/persistent_pre_key_stores.dart';
import 'stores/persistent_session_store.dart';

/// Number of one-time prekeys generated per batch.
const int preKeyBatchSize = 20;

/// Signal's safety-number iteration count and version.
const int _fingerprintIterations = 5200;
const int _fingerprintVersion = 1;

class CryptoException implements Exception {
  const CryptoException(this.message, {this.cause});
  final String message;
  final Object? cause;
  @override
  String toString() => 'CryptoException: $message';
}

/// Raised when sending is blocked because a contact's identity key changed and
/// the user has not acknowledged it. Fail closed, per the brief.
class IdentityChangedException implements Exception {
  const IdentityChangedException(this.addressName, this.deviceIndex);
  final String addressName;
  final int deviceIndex;
  @override
  String toString() =>
      'IdentityChangedException: identity key changed for $addressName:$deviceIndex; '
      'the user must acknowledge the change before sending';
}

/// Public key material to publish at device registration.
class DeviceKeyMaterial {
  const DeviceKeyMaterial({
    required this.registrationId,
    required this.publicIdentityKey,
    required this.signedPreKeyId,
    required this.signedPreKeyPublic,
    required this.signedPreKeySignature,
    required this.kyberPreKeyId,
    required this.kyberPreKeyPublic,
    required this.kyberPreKeySignature,
    required this.oneTimePreKeys,
  });

  final int registrationId;
  final String publicIdentityKey;
  final int signedPreKeyId;
  final String signedPreKeyPublic;
  final String signedPreKeySignature;
  final int kyberPreKeyId;
  final String kyberPreKeyPublic;
  final String kyberPreKeySignature;
  final List<({int id, String publicKey})> oneTimePreKeys;
}

/// A peer's prekey bundle, as fetched from the server.
class PreKeyBundleData {
  const PreKeyBundleData({
    required this.userId,
    required this.deviceIndex,
    required this.registrationId,
    required this.publicIdentityKey,
    required this.signedPreKeyId,
    required this.signedPreKeyPublic,
    required this.signedPreKeySignature,
    required this.kyberPreKeyId,
    required this.kyberPreKeyPublic,
    required this.kyberPreKeySignature,
    required this.oneTimePreKeyId,
    required this.oneTimePreKeyPublic,
  });

  final String userId;
  final int deviceIndex;
  final int registrationId;
  final String publicIdentityKey;
  final int signedPreKeyId;
  final String signedPreKeyPublic;
  final String signedPreKeySignature;
  final int kyberPreKeyId;
  final String kyberPreKeyPublic;
  final String kyberPreKeySignature;
  final int? oneTimePreKeyId;
  final String? oneTimePreKeyPublic;
}

/// An encrypted envelope ready to send.
class EncryptedEnvelope {
  const EncryptedEnvelope({required this.messageType, required this.ciphertext});

  /// 'prekey' or 'signal', matching the server's `message_type`.
  final String messageType;
  final String ciphertext;
}

class CryptoService {
  CryptoService._({
    required EncryptedDatabase database,
    required IdentityKeyPair identityKeyPair,
    required int registrationId,
  })  : _db = database,
        _identityKeyPair = identityKeyPair,
        _registrationId = registrationId {
    _identityStore = PersistentIdentityKeyStore(
      database: _db,
      identityKeyPair: _identityKeyPair,
      localRegistrationId: _registrationId,
    );
    _sessionStore = PersistentSessionStore(_db);
    _preKeyStore = PersistentPreKeyStore(_db);
    _signedPreKeyStore = PersistentSignedPreKeyStore(_db);
    _kyberPreKeyStore = PersistentKyberPreKeyStore(_db);
  }

  final EncryptedDatabase _db;
  final IdentityKeyPair _identityKeyPair;
  final int _registrationId;

  // One lock map for the service's lifetime. Scoping it to a cipher object
  // would create one map per cipher and serialise nothing.
  final AddressLock _locks = AddressLock();

  late final PersistentIdentityKeyStore _identityStore;
  late final PersistentSessionStore _sessionStore;
  late final PersistentPreKeyStore _preKeyStore;
  late final PersistentSignedPreKeyStore _signedPreKeyStore;
  late final PersistentKyberPreKeyStore _kyberPreKeyStore;

  int get registrationId => _registrationId;

  String get publicIdentityKeyBase64 => base64.encode(_identityKeyPair.publicKey);

  PersistentIdentityKeyStore get identityStore => _identityStore;

  /// Must be called once before any other library use.
  static Future<void> initialise() => LibSignal.init();

  /// Creates a brand-new cryptographic identity for this installation.
  ///
  /// Generates the identity key pair, a signed prekey, a last-resort Kyber
  /// prekey and a batch of one-time prekeys, persists all private material, and
  /// returns only the PUBLIC half for publication.
  static Future<(CryptoService, DeviceKeyMaterial)> provision({
    required EncryptedDatabase database,
  }) async {
    final existing = database.raw.select('SELECT 1 FROM device_identity WHERE id = 1');
    if (existing.isNotEmpty) {
      throw const CryptoException(
        'this installation already has a cryptographic identity; '
        'provisioning again would orphan every existing session',
      );
    }

    final identity = IdentityKeyPair.generate();
    // 14-bit, per libsignal.
    final registrationId = Random.secure().nextInt(16383) + 1;

    final service = CryptoService._(
      database: database,
      identityKeyPair: identity,
      registrationId: registrationId,
    );

    final material = database.transaction(() {
      database.raw.execute(
        'INSERT INTO device_identity '
        '(id, device_id, device_index, registration_id, identity_key_pair, created_at) '
        'VALUES (1, ?, ?, ?, ?, ?)',
        [
          '', // filled in once the server assigns one
          0,
          registrationId,
          identity.serialize(),
          DateTime.now().millisecondsSinceEpoch,
        ],
      );
      return service._generateKeyMaterialSync(identity, registrationId);
    });

    return (service, material);
  }

  /// Loads the identity created by a previous [provision].
  static Future<CryptoService?> restore({required EncryptedDatabase database}) async {
    final rows = database.raw.select(
      'SELECT registration_id, identity_key_pair FROM device_identity WHERE id = 1',
    );
    if (rows.isEmpty) return null;

    final raw = rows.first['identity_key_pair'];
    final bytes = raw is Uint8List ? raw : Uint8List.fromList((raw as List).cast<int>());

    return CryptoService._(
      database: database,
      identityKeyPair: IdentityKeyPair.deserialize(bytes: bytes),
      registrationId: rows.first['registration_id'] as int,
    );
  }

  /// Records the server-assigned identifiers once registration completes.
  void recordServerIdentifiers({required String deviceId, required int deviceIndex}) {
    _db.raw.execute(
      'UPDATE device_identity SET device_id = ?, device_index = ? WHERE id = 1',
      [deviceId, deviceIndex],
    );
  }

  ({String deviceId, int deviceIndex})? serverIdentifiers() {
    final rows =
        _db.raw.select('SELECT device_id, device_index FROM device_identity WHERE id = 1');
    if (rows.isEmpty) return null;
    final deviceId = rows.first['device_id'] as String;
    if (deviceId.isEmpty) return null;
    return (deviceId: deviceId, deviceIndex: rows.first['device_index'] as int);
  }

  DeviceKeyMaterial _generateKeyMaterialSync(IdentityKeyPair identity, int registrationId) {
    const signedPreKeyId = 1;
    const kyberPreKeyId = 1;
    final now = BigInt.from(DateTime.now().millisecondsSinceEpoch);

    // Signed prekey.
    final signedPrivate = PrivateKey.generate();
    final signedPublic = signedPrivate.getPublicKey();
    final signedPublicBytes = signedPublic.serialize();
    final signedSignature = identity.sign(message: signedPublicBytes.toList());
    _signedPreKeyStore.storeSignedPreKey(
      signedPreKeyId,
      SignedPreKeyRecord(
        id: signedPreKeyId,
        timestamp: now,
        publicKey: signedPublic,
        privateKey: signedPrivate,
        signature: signedSignature.toList(),
      ),
    );

    // Kyber prekey. Not optional: libsignal's PreKeyBundle requires it, so the
    // protocol is PQXDH. Marked last-resort so it can be reused if the
    // one-time supply runs out.
    final kyberPair = KyberKeyPair.generate();
    final kyberPublicBytes = kyberPair.getPublicKey().serialize();
    final kyberSignature = identity.sign(message: kyberPublicBytes.toList());
    _kyberPreKeyStore.storeKyberPreKey(
      kyberPreKeyId,
      KyberPreKeyRecord.create(
        id: kyberPreKeyId,
        timestamp: now,
        keyPair: kyberPair,
        signature: kyberSignature.toList(),
      ),
    );

    // One-time prekeys.
    final oneTime = <({int id, String publicKey})>[];
    for (var id = 1; id <= preKeyBatchSize; id++) {
      final private = PrivateKey.generate();
      final public = private.getPublicKey();
      _preKeyStore.storePreKey(
        id,
        PreKeyRecord(id: id, publicKey: public, privateKey: private),
      );
      oneTime.add((id: id, publicKey: base64.encode(public.serialize())));
    }

    return DeviceKeyMaterial(
      registrationId: registrationId,
      publicIdentityKey: base64.encode(identity.publicKey),
      signedPreKeyId: signedPreKeyId,
      signedPreKeyPublic: base64.encode(signedPublicBytes),
      signedPreKeySignature: base64.encode(signedSignature),
      kyberPreKeyId: kyberPreKeyId,
      kyberPreKeyPublic: base64.encode(kyberPublicBytes),
      kyberPreKeySignature: base64.encode(kyberSignature),
      oneTimePreKeys: oneTime,
    );
  }

  /// Rebuilds the publishable PUBLIC material from what is already stored.
  ///
  /// Needed for one specific recovery: [provision] writes the private material
  /// and then the caller publishes the public half over the network. If that
  /// publication fails, the installation holds an identity the server has never
  /// seen. Generating a second identity would orphan it, so the only safe
  /// recovery is to republish the material that already exists.
  ///
  /// Returns null when the expected records are missing, which means the local
  /// state is damaged rather than merely unpublished — the caller must not
  /// paper over that.
  Future<DeviceKeyMaterial?> republishableKeyMaterial() async {
    const signedPreKeyId = 1;
    const kyberPreKeyId = 1;

    final signed = await _signedPreKeyStore.loadSignedPreKey(signedPreKeyId);
    final kyber = await _kyberPreKeyStore.loadKyberPreKey(kyberPreKeyId);
    if (signed == null || kyber == null) return null;

    // The server requires at least 10 one-time prekeys at registration. None
    // should have been consumed yet, but top up rather than fail if they have.
    var ids = await _preKeyStore.getAllPreKeyIds();
    if (ids.length < 10) {
      await generateMoreOneTimePreKeys(count: preKeyBatchSize);
      ids = await _preKeyStore.getAllPreKeyIds();
    }

    final oneTime = <({int id, String publicKey})>[];
    for (final id in ids.take(preKeyBatchSize)) {
      final record = await _preKeyStore.loadPreKey(id);
      if (record == null) continue;
      oneTime.add((id: id, publicKey: base64.encode(record.publicKey())));
    }
    if (oneTime.length < 10) return null;

    return DeviceKeyMaterial(
      registrationId: _registrationId,
      publicIdentityKey: base64.encode(_identityKeyPair.publicKey),
      signedPreKeyId: signed.id(),
      signedPreKeyPublic: base64.encode(signed.publicKey()),
      signedPreKeySignature: base64.encode(signed.signature()),
      kyberPreKeyId: kyber.id(),
      kyberPreKeyPublic: base64.encode(kyber.getPublicKey().serialize()),
      kyberPreKeySignature: base64.encode(kyber.signature()),
      oneTimePreKeys: oneTime,
    );
  }

  /// Generates a further batch of one-time prekeys for replenishment.
  ///
  /// Ids continue from the highest ever issued, so an id the server may still
  /// be handing out is never reused with different key bytes.
  Future<List<({int id, String publicKey})>> generateMoreOneTimePreKeys({
    int count = preKeyBatchSize,
  }) async {
    return _db.transaction(() {
      final start = _preKeyStore.highestId() + 1;
      final generated = <({int id, String publicKey})>[];
      for (var id = start; id < start + count; id++) {
        final private = PrivateKey.generate();
        final public = private.getPublicKey();
        _preKeyStore.storePreKey(
          id,
          PreKeyRecord(id: id, publicKey: public, privateKey: private),
        );
        generated.add((id: id, publicKey: base64.encode(public.serialize())));
      }
      return generated;
    });
  }

  int availableOneTimePreKeys() => _preKeyStore.availableCount();

  ProtocolAddress addressFor(String userId, int deviceIndex) =>
      ProtocolAddress(name: userId, deviceId: deviceIndex);

  /// Runs [action] serialised per address and inside one committed transaction.
  Future<T> _guarded<T>(ProtocolAddress address, Future<T> Function() action) {
    final key = '${address.name()}:${address.deviceId()}';
    return _locks.synchronized(key, () async {
      _db.raw.execute('BEGIN IMMEDIATE;');
      try {
        final result = await action();
        // Commits before the caller sees the result, on synchronous = FULL.
        _db.raw.execute('COMMIT;');
        return result;
      } catch (error) {
        try {
          _db.raw.execute('ROLLBACK;');
        } catch (_) {
          // Must not mask the original failure.
        }
        rethrow;
      }
    });
  }

  /// Establishes a session from a peer's prekey bundle (X3DH/PQXDH).
  ///
  /// libsignal verifies the signed-prekey signature against the identity key in
  /// the bundle and throws if it does not match — which is the check that makes
  /// server-side key substitution detectable. Validated in
  /// test/libsignal_validation_test.dart.
  Future<void> establishSession(PreKeyBundleData bundle) async {
    final address = addressFor(bundle.userId, bundle.deviceIndex);

    await _guarded(address, () async {
      final builder = SessionBuilder(
        localAddress: _localAddress(),
        sessionStore: _sessionStore,
        identityKeyStore: _identityStore,
      );

      final oneTimeBytes = bundle.oneTimePreKeyPublic == null
          ? null
          : base64.decode(bundle.oneTimePreKeyPublic!);

      final preKeyBundle = PreKeyBundle(
        registrationId: bundle.registrationId,
        deviceId: bundle.deviceIndex,
        preKeyId: bundle.oneTimePreKeyId,
        preKeyPublic: oneTimeBytes,
        signedPreKeyId: bundle.signedPreKeyId,
        signedPreKeyPublic: base64.decode(bundle.signedPreKeyPublic),
        signedPreKeySignature: base64.decode(bundle.signedPreKeySignature),
        identityKey: base64.decode(bundle.publicIdentityKey),
        kyberPreKeyId: bundle.kyberPreKeyId,
        kyberPreKeyPublic: base64.decode(bundle.kyberPreKeyPublic),
        kyberPreKeySignature: base64.decode(bundle.kyberPreKeySignature),
      );

      try {
        await builder.processPreKeyBundle(address, preKeyBundle);
      } catch (error) {
        // Do not retry a cryptographic failure. A bad signature here means the
        // bundle was not produced by the identity it claims.
        throw CryptoException(
          'could not establish a session with ${bundle.userId}:${bundle.deviceIndex}; '
          'the prekey bundle failed verification',
          cause: error,
        );
      }
    });
  }

  Future<bool> hasSession(String userId, int deviceIndex) =>
      _sessionStore.containsSession(addressFor(userId, deviceIndex));

  /// Encrypts [plaintext] for one peer device.
  ///
  /// Refuses if the peer's identity key changed and the user has not
  /// acknowledged it: that is the direction where trusting a substituted key
  /// hands new plaintext to an attacker.
  Future<EncryptedEnvelope> encrypt({
    required String userId,
    required int deviceIndex,
    required String plaintext,
  }) async {
    final address = addressFor(userId, deviceIndex);

    final state = _identityStore.identityState(address);
    if (state != null && state.hasUnacknowledgedChange) {
      throw IdentityChangedException(userId, deviceIndex);
    }

    return _guarded(address, () async {
      final cipher = _sessionCipher();
      final CiphertextMessage message;
      try {
        message = await cipher.encrypt(
          address,
          Uint8List.fromList(utf8.encode(plaintext)),
        );
      } catch (error) {
        throw CryptoException('encryption failed for $userId:$deviceIndex', cause: error);
      }

      return EncryptedEnvelope(
        messageType: switch (message.type) {
          CiphertextMessageType.preKey => 'prekey',
          CiphertextMessageType.signal => 'signal',
          _ => throw CryptoException('unexpected ciphertext type ${message.type}'),
        },
        ciphertext: base64.encode(message.ciphertext),
      );
    });
  }

  /// Decrypts an envelope from one peer device.
  ///
  /// A failure here is a security event, not a transient error: it means the
  /// ciphertext was tampered with, replayed, or encrypted for someone else.
  /// The caller must surface it rather than retrying.
  Future<String> decrypt({
    required String userId,
    required int deviceIndex,
    required String messageType,
    required String ciphertext,
  }) async {
    final address = addressFor(userId, deviceIndex);

    return _guarded(address, () async {
      final cipher = _sessionCipher();
      final envelope = CiphertextMessage(
        type: switch (messageType) {
          'prekey' => CiphertextMessageType.preKey,
          'signal' => CiphertextMessageType.signal,
          _ => throw CryptoException('unsupported message type "$messageType"'),
        },
        ciphertext: base64.decode(ciphertext),
      );

      try {
        final plaintext = await cipher.decrypt(address, envelope);
        return utf8.decode(plaintext);
      } catch (error) {
        throw CryptoException(
          'decryption failed for $userId:$deviceIndex — the message was tampered '
          'with, replayed, or not meant for this device',
          cause: error,
        );
      }
    });
  }

  /// Safety number for out-of-band comparison: 60 digits, identical on both
  /// sides. Also rendered as a QR code by the verification screen.
  String safetyNumber({
    required String localUserId,
    required String remoteUserId,
    required String remoteIdentityKeyBase64,
  }) {
    final fingerprint = Fingerprint(
      iterations: _fingerprintIterations,
      version: _fingerprintVersion,
      localIdentifier: utf8.encode(localUserId),
      localPublicKey: _identityKeyPair.publicKey.toList(),
      remoteIdentifier: utf8.encode(remoteUserId),
      remotePublicKey: base64.decode(remoteIdentityKeyBase64).toList(),
    );
    return fingerprint.displayString();
  }

  /// Records that the user compared safety numbers out of band, for the
  /// specific key those digits were derived from.
  ///
  /// Pins the key if this address has none yet, so verification before the
  /// first message is meaningful rather than a no-op. Returns false when a
  /// different key is already pinned — that is an identity change and belongs
  /// in [acknowledgeIdentityChange], not here.
  bool verifyIdentityKey({
    required String userId,
    required int deviceIndex,
    required String identityKeyBase64,
  }) =>
      _identityStore.verifyIdentityKey(
        addressFor(userId, deviceIndex),
        base64.decode(identityKeyBase64),
      );

  /// Clears verification, or sets it on an identity already pinned.
  ///
  /// This is the authoritative verification state. The server's field is
  /// advisory only (docs/decisions.md D4).
  void setVerified({
    required String userId,
    required int deviceIndex,
    required bool verified,
  }) =>
      _identityStore.setVerified(addressFor(userId, deviceIndex), verified: verified);

  /// Unblocks sending after the user has been warned about a changed identity.
  void acknowledgeIdentityChange({required String userId, required int deviceIndex}) =>
      _identityStore.acknowledgeChange(addressFor(userId, deviceIndex));

  PeerIdentityState? peerIdentity({required String userId, required int deviceIndex}) =>
      _identityStore.identityState(addressFor(userId, deviceIndex));

  List<PeerIdentityState> pendingIdentityWarnings() =>
      _identityStore.unacknowledgedChanges();

  /// Next outgoing sequence number for a recipient device, monotonic across
  /// restarts because it is persisted rather than held in memory.
  int nextSenderSequence(String recipientDeviceId) {
    return _db.transaction(() {
      final rows = _db.raw.select(
        'SELECT next_sequence FROM send_counters WHERE recipient_device_id = ?',
        [recipientDeviceId],
      );
      final next = rows.isEmpty ? 0 : rows.first['next_sequence'] as int;
      _db.raw.execute(
        'INSERT INTO send_counters (recipient_device_id, next_sequence) VALUES (?, ?) '
        'ON CONFLICT (recipient_device_id) DO UPDATE SET next_sequence = ?',
        [recipientDeviceId, next + 1, next + 1],
      );
      return next;
    });
  }

  ProtocolAddress _localAddress() {
    final identifiers = serverIdentifiers();
    return ProtocolAddress(
      name: _localUserId() ?? 'self',
      deviceId: identifiers?.deviceIndex ?? 1,
    );
  }

  String? _localUserId() {
    final rows = _db.raw.select('SELECT user_id FROM auth_state WHERE id = 1');
    return rows.isEmpty ? null : rows.first['user_id'] as String;
  }

  SessionCipher _sessionCipher() => SessionCipher(
        localAddress: _localAddress(),
        sessionStore: _sessionStore,
        identityKeyStore: _identityStore,
        preKeyStore: _preKeyStore,
        signedPreKeyStore: _signedPreKeyStore,
        kyberPreKeyStore: _kyberPreKeyStore,
      );

  /// Test helper: how many addresses currently have queued ratchet work.
  int get pendingLockedAddresses => _locks.pendingAddresses;
}
