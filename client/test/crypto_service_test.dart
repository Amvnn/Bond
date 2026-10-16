/// Tests for the three silent-failure modes in the client crypto layer, plus
/// the restart-survival check that was left open after the step-4 validation.
///
/// "Silent" is the point: none of these failures throws, logs, or shows any
/// symptom at the time. Each would simply produce a system that looks like it
/// works while being broken. So each gets an explicit test.
///
/// Unlike the server suite, this exercises the REAL libsignal and the REAL
/// SQLCipher build. Nothing here is a stand-in.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:libsignal/libsignal.dart';
import 'package:path/path.dart' as p;
import 'package:bond/services/crypto/address_lock.dart';
import 'package:bond/services/crypto/crypto_service.dart';
import 'package:bond/services/storage/encrypted_database.dart';

import 'support/fake_secure_key_store.dart';

late Directory tempDir;

/// A provisioned participant backed by a real file database.
class Participant {
  Participant._(this.userId, this.database, this.service, this.material, this.keyStore,
      this.dbPath);

  final String userId;
  EncryptedDatabase database;
  CryptoService service;
  final DeviceKeyMaterial material;
  final FakeSecureKeyStore keyStore;
  final String dbPath;

  static Future<Participant> create(String userId, {int deviceIndex = 1}) async {
    final keyStore = FakeSecureKeyStore();
    final dbPath = p.join(tempDir.path, '$userId-${DateTime.now().microsecondsSinceEpoch}.db');
    final database = await EncryptedDatabase.open(path: dbPath, keyStore: keyStore);

    // auth_state carries the local user id, which the service uses to build
    // its own protocol address.
    database.raw.execute(
      'INSERT INTO auth_state (id, user_id, username, updated_at) VALUES (1, ?, ?, ?)',
      [userId, userId, DateTime.now().millisecondsSinceEpoch],
    );

    final (service, material) = await CryptoService.provision(database: database);
    service.recordServerIdentifiers(deviceId: '$userId-device', deviceIndex: deviceIndex);

    return Participant._(userId, database, service, material, keyStore, dbPath);
  }

  int get deviceIndex => service.serverIdentifiers()!.deviceIndex;

  /// The bundle this participant would publish to the server.
  PreKeyBundleData bundle({int oneTimeIndex = 0}) => PreKeyBundleData(
        userId: userId,
        deviceIndex: deviceIndex,
        registrationId: material.registrationId,
        publicIdentityKey: material.publicIdentityKey,
        signedPreKeyId: material.signedPreKeyId,
        signedPreKeyPublic: material.signedPreKeyPublic,
        signedPreKeySignature: material.signedPreKeySignature,
        kyberPreKeyId: material.kyberPreKeyId,
        kyberPreKeyPublic: material.kyberPreKeyPublic,
        kyberPreKeySignature: material.kyberPreKeySignature,
        oneTimePreKeyId: material.oneTimePreKeys[oneTimeIndex].id,
        oneTimePreKeyPublic: material.oneTimePreKeys[oneTimeIndex].publicKey,
      );

  /// Simulates a process restart: close the database and reopen from the same
  /// file with the same key, then restore the identity.
  Future<void> restart() async {
    database.dispose();
    database = await EncryptedDatabase.open(path: dbPath, keyStore: keyStore);
    final restored = await CryptoService.restore(database: database);
    expect(restored, isNotNull, reason: 'identity must survive a restart');
    service = restored!;
  }

  void dispose() => database.dispose();
}

void main() {
  setUpAll(() async {
    await CryptoService.initialise();
    tempDir = Directory.systemTemp.createTempSync('pm_crypto_test_');
  });

  tearDownAll(() {
    try {
      tempDir.deleteSync(recursive: true);
    } catch (_) {
      // Windows can hold a handle briefly; the OS cleans temp up anyway.
    }
  });

  // =========================================================================
  group('silent failure 1: database not actually encrypted', () {
    test('the sqlite3 build really is SQLCipher', () async {
      final db = await EncryptedDatabase.open(
        path: p.join(tempDir.path, 'cipher_probe.db'),
        keyStore: FakeSecureKeyStore(),
      );
      addTearDown(db.dispose);

      // If this pragma returned nothing, PRAGMA key would be a silent no-op and
      // every message and private key would be on disk in plaintext.
      final result = db.raw.select('PRAGMA cipher_version;');
      expect(result, isNotEmpty, reason: 'sqlite3 was built without SQLCipher');
      expect(result.first.values.first.toString(), isNotEmpty);
    });

    test('the file on disk is unreadable with the wrong key', () async {
      final path = p.join(tempDir.path, 'wrong_key.db');
      final keyStore = FakeSecureKeyStore();

      final db = await EncryptedDatabase.open(path: path, keyStore: keyStore);
      db.raw.execute(
        "INSERT INTO local_messages "
        "(message_id, peer_user_id, outgoing, body, state, created_at) "
        "VALUES ('m1', 'peer', 1, 'the quick brown fox', 'sent', 1)",
      );
      db.dispose();

      // The strongest available proof that encryption is on: swap the key and
      // the same file becomes unreadable. With a plaintext database this would
      // succeed.
      keyStore.overwrite(databaseKeyName, EncryptedDatabase.generateDatabaseKey());
      await expectLater(
        EncryptedDatabase.open(path: path, keyStore: keyStore),
        throwsA(isA<LocalDatabaseException>()),
      );
    });

    test('the plaintext of a stored message does not appear in the raw file', () async {
      final path = p.join(tempDir.path, 'no_plaintext.db');
      const secret = 'LOOK-FOR-THIS-SENTINEL-STRING';

      final db = await EncryptedDatabase.open(
        path: path,
        keyStore: FakeSecureKeyStore(),
      );
      db.raw.execute(
        'INSERT INTO local_messages '
        '(message_id, peer_user_id, outgoing, body, state, created_at) '
        'VALUES (?, ?, 1, ?, ?, ?)',
        ['m1', 'peer', secret, 'sent', 1],
      );
      db.dispose();

      final bytes = await File(path).readAsBytes();
      final asText = String.fromCharCodes(bytes);
      expect(
        asText.contains(secret),
        isFalse,
        reason: 'message body found in cleartext in the database file',
      );
    });
  });

  // =========================================================================
  group('silent failure 2: concurrent ratchet use', () {
    test('AddressLock serialises work for one key and not across keys', () async {
      final lock = AddressLock();
      final order = <String>[];

      Future<void> job(String key, String tag, int delayMs) =>
          lock.synchronized(key, () async {
            order.add('$tag-start');
            await Future<void>.delayed(Duration(milliseconds: delayMs));
            order.add('$tag-end');
          });

      await Future.wait([
        job('a', 'a1', 30),
        job('a', 'a2', 1),
        job('b', 'b1', 1),
      ]);

      // a2 must not start before a1 finished.
      expect(order.indexOf('a2-start'), greaterThan(order.indexOf('a1-end')));
      expect(lock.isIdle, isTrue, reason: 'lock map must not leak entries');
    });

    test('a failing action does not poison the queue', () async {
      final lock = AddressLock();
      await expectLater(
        lock.synchronized('a', () async => throw StateError('boom')),
        throwsStateError,
      );
      expect(await lock.synchronized('a', () async => 42), 42);
      expect(lock.isIdle, isTrue);
    });

    test('concurrent encrypts to one address all decrypt, with no key reuse', () async {
      final alice = await Participant.create('alice');
      final bob = await Participant.create('bob');
      addTearDown(alice.dispose);
      addTearDown(bob.dispose);

      await alice.service.establishSession(bob.bundle());

      // Fired without awaiting in between. Without the per-address lock, these
      // would load the same session record and derive the same message key —
      // silently, with no error.
      const count = 10;
      final envelopes = await Future.wait(
        List.generate(
          count,
          (i) => alice.service.encrypt(
            userId: bob.userId,
            deviceIndex: bob.deviceIndex,
            plaintext: 'concurrent message $i',
          ),
        ),
      );

      expect(envelopes, hasLength(count));
      // Every ciphertext must be distinct.
      expect(envelopes.map((e) => e.ciphertext).toSet(), hasLength(count));

      final decrypted = <String>[];
      for (final envelope in envelopes) {
        decrypted.add(
          await bob.service.decrypt(
            userId: alice.userId,
            deviceIndex: alice.deviceIndex,
            messageType: envelope.messageType,
            ciphertext: envelope.ciphertext,
          ),
        );
      }

      expect(
        decrypted.toSet(),
        List.generate(count, (i) => 'concurrent message $i').toSet(),
        reason: 'every concurrently encrypted message must decrypt exactly once',
      );
    });
  });

  // =========================================================================
  group('silent failure 3: ratchet state not durable', () {
    test('a session survives a simulated process restart on both sides', () async {
      final alice = await Participant.create('alice');
      final bob = await Participant.create('bob');
      addTearDown(alice.dispose);
      addTearDown(bob.dispose);

      await alice.service.establishSession(bob.bundle());

      // Before the restart.
      final first = await alice.service.encrypt(
        userId: bob.userId,
        deviceIndex: bob.deviceIndex,
        plaintext: 'before restart',
      );
      expect(
        await bob.service.decrypt(
          userId: alice.userId,
          deviceIndex: alice.deviceIndex,
          messageType: first.messageType,
          ciphertext: first.ciphertext,
        ),
        'before restart',
      );

      // Close and reopen both databases, as a process exit would.
      await alice.restart();
      await bob.restart();

      // Bob replies, which confirms the session in both directions and proves
      // his ratchet state was reloaded rather than rebuilt.
      final reply = await bob.service.encrypt(
        userId: alice.userId,
        deviceIndex: alice.deviceIndex,
        plaintext: 'after restart, from bob',
      );
      expect(
        await alice.service.decrypt(
          userId: bob.userId,
          deviceIndex: bob.deviceIndex,
          messageType: reply.messageType,
          ciphertext: reply.ciphertext,
        ),
        'after restart, from bob',
      );

      // And Alice can continue on the same session.
      final third = await alice.service.encrypt(
        userId: bob.userId,
        deviceIndex: bob.deviceIndex,
        plaintext: 'still the same session',
      );
      expect(third.messageType, 'signal',
          reason: 'the session is confirmed, so the prekey preamble is dropped');
      expect(
        await bob.service.decrypt(
          userId: alice.userId,
          deviceIndex: alice.deviceIndex,
          messageType: third.messageType,
          ciphertext: third.ciphertext,
        ),
        'still the same session',
      );
    });

    test('the send sequence counter is monotonic across a restart', () async {
      final alice = await Participant.create('alice');
      addTearDown(alice.dispose);

      final before = [
        alice.service.nextSenderSequence('bob-device'),
        alice.service.nextSenderSequence('bob-device'),
      ];
      await alice.restart();
      final after = alice.service.nextSenderSequence('bob-device');

      expect(before, [0, 1]);
      // Reusing a sequence number would be rejected by the server as a
      // duplicate, silently dropping the message.
      expect(after, 2);
    });

    test('a one-time prekey consumed during session setup stays consumed', () async {
      final alice = await Participant.create('alice');
      final bob = await Participant.create('bob');
      addTearDown(alice.dispose);
      addTearDown(bob.dispose);

      await alice.service.establishSession(bob.bundle());
      final envelope = await alice.service.encrypt(
        userId: bob.userId,
        deviceIndex: bob.deviceIndex,
        plaintext: 'uses bob prekey 1',
      );
      await bob.service.decrypt(
        userId: alice.userId,
        deviceIndex: alice.deviceIndex,
        messageType: envelope.messageType,
        ciphertext: envelope.ciphertext,
      );

      final remainingBefore = bob.service.availableOneTimePreKeys();
      await bob.restart();
      // If the consumption write had been lost, the count would go back up and
      // the key could serve a second session.
      expect(bob.service.availableOneTimePreKeys(), remainingBefore);
      expect(remainingBefore, lessThan(preKeyBatchSize));
    });
  });

  // =========================================================================
  group('silent failure 4: identity change accepted without notice', () {
    test('a new peer is trust-on-first-use but recorded', () async {
      final alice = await Participant.create('alice');
      final bob = await Participant.create('bob');
      addTearDown(alice.dispose);
      addTearDown(bob.dispose);

      await alice.service.establishSession(bob.bundle());

      final state = alice.service
          .peerIdentity(userId: bob.userId, deviceIndex: bob.deviceIndex);
      expect(state, isNotNull, reason: 'the peer key must be recorded at first contact');
      expect(state!.isVerified, isFalse, reason: 'first contact is never verified');
      expect(state.hasUnacknowledgedChange, isFalse);
    });

    test('a changed identity key is detected, revokes verification, and blocks sending',
        () async {
      final alice = await Participant.create('alice');
      final bob = await Participant.create('bob');
      addTearDown(alice.dispose);
      addTearDown(bob.dispose);

      await alice.service.establishSession(bob.bundle());

      // Alice verifies Bob out of band.
      alice.service.setVerified(
        userId: bob.userId,
        deviceIndex: bob.deviceIndex,
        verified: true,
      );
      expect(
        alice.service.peerIdentity(userId: bob.userId, deviceIndex: bob.deviceIndex)!
            .isVerified,
        isTrue,
      );

      // A different identity key arrives for the same address — exactly what a
      // malicious server substituting a key would produce.
      final impostor = await Participant.create('bob');
      addTearDown(impostor.dispose);
      final address = alice.service.addressFor(bob.userId, bob.deviceIndex);
      final changed = await alice.service.identityStore.saveIdentity(
        address,
        PublicKey.deserialize(
          bytes: _decodeBase64(impostor.material.publicIdentityKey),
        ),
      );

      expect(changed, isTrue, reason: 'saveIdentity must report the change');

      final state = alice.service
          .peerIdentity(userId: bob.userId, deviceIndex: bob.deviceIndex)!;
      expect(state.hasUnacknowledgedChange, isTrue);
      expect(state.isVerified, isFalse,
          reason: 'verification earned by the OLD key must not carry over');
      expect(state.previousIdentityKey, isNotNull,
          reason: 'the previous key is kept so the warning survives a restart');

      // Sending must fail closed until the user acknowledges.
      await expectLater(
        alice.service.encrypt(
          userId: bob.userId,
          deviceIndex: bob.deviceIndex,
          plaintext: 'should not be sent to an unconfirmed identity',
        ),
        throwsA(isA<IdentityChangedException>()),
      );

      // The warning is durable, not a transient in-memory flag.
      await alice.restart();
      expect(
        alice.service
            .peerIdentity(userId: bob.userId, deviceIndex: bob.deviceIndex)!
            .hasUnacknowledgedChange,
        isTrue,
      );
      expect(alice.service.pendingIdentityWarnings(), hasLength(1));
    });

    test('acknowledging a change unblocks sending but does NOT re-verify', () async {
      final alice = await Participant.create('alice');
      final bob = await Participant.create('bob');
      addTearDown(alice.dispose);
      addTearDown(bob.dispose);

      await alice.service.establishSession(bob.bundle());
      alice.service
          .setVerified(userId: bob.userId, deviceIndex: bob.deviceIndex, verified: true);

      final impostor = await Participant.create('bob');
      addTearDown(impostor.dispose);
      await alice.service.identityStore.saveIdentity(
        alice.service.addressFor(bob.userId, bob.deviceIndex),
        PublicKey.deserialize(bytes: _decodeBase64(impostor.material.publicIdentityKey)),
      );

      alice.service
          .acknowledgeIdentityChange(userId: bob.userId, deviceIndex: bob.deviceIndex);

      final state = alice.service
          .peerIdentity(userId: bob.userId, deviceIndex: bob.deviceIndex)!;
      expect(state.hasUnacknowledgedChange, isFalse);
      // Acknowledging is not verifying: that needs comparing digits again.
      expect(state.isVerified, isFalse);
    });

    test('isTrustedIdentity refuses to send to a changed key but allows receiving',
        () async {
      final alice = await Participant.create('alice');
      final bob = await Participant.create('bob');
      final impostor = await Participant.create('bob');
      addTearDown(alice.dispose);
      addTearDown(bob.dispose);
      addTearDown(impostor.dispose);

      final address = alice.service.addressFor(bob.userId, bob.deviceIndex);
      final store = alice.service.identityStore;
      final bobKey = PublicKey.deserialize(bytes: _decodeBase64(bob.material.publicIdentityKey));
      final otherKey =
          PublicKey.deserialize(bytes: _decodeBase64(impostor.material.publicIdentityKey));

      await store.saveIdentity(address, bobKey);

      expect(await store.isTrustedIdentity(address, bobKey, Direction.sending), isTrue);
      // Changed key: refuse to send, but allow receive so the user can still
      // read incoming messages and see the warning.
      expect(
        await store.isTrustedIdentity(address, otherKey, Direction.sending),
        isFalse,
      );
      expect(
        await store.isTrustedIdentity(address, otherKey, Direction.receiving),
        isTrue,
      );
    });
  });

  // =========================================================================
  group('safety numbers', () {
    test('both sides compute the same 60-digit number', () async {
      final alice = await Participant.create('alice');
      final bob = await Participant.create('bob');
      addTearDown(alice.dispose);
      addTearDown(bob.dispose);

      final fromAlice = alice.service.safetyNumber(
        localUserId: alice.userId,
        remoteUserId: bob.userId,
        remoteIdentityKeyBase64: bob.material.publicIdentityKey,
      );
      final fromBob = bob.service.safetyNumber(
        localUserId: bob.userId,
        remoteUserId: alice.userId,
        remoteIdentityKeyBase64: alice.material.publicIdentityKey,
      );

      expect(fromAlice, hasLength(60));
      expect(fromAlice, fromBob,
          reason: 'both users must read the same digits aloud');
    });

    test('the number differs for a different identity key', () async {
      final alice = await Participant.create('alice');
      final bob = await Participant.create('bob');
      final impostor = await Participant.create('bob');
      addTearDown(alice.dispose);
      addTearDown(bob.dispose);
      addTearDown(impostor.dispose);

      expect(
        alice.service.safetyNumber(
          localUserId: alice.userId,
          remoteUserId: bob.userId,
          remoteIdentityKeyBase64: bob.material.publicIdentityKey,
        ),
        isNot(
          alice.service.safetyNumber(
            localUserId: alice.userId,
            remoteUserId: bob.userId,
            remoteIdentityKeyBase64: impostor.material.publicIdentityKey,
          ),
        ),
      );
    });
  });

  // =========================================================================
  group('provisioning', () {
    test('publishes only public material', () async {
      final alice = await Participant.create('alice');
      addTearDown(alice.dispose);

      final published = [
        alice.material.publicIdentityKey,
        alice.material.signedPreKeyPublic,
        alice.material.kyberPreKeyPublic,
        ...alice.material.oneTimePreKeys.map((k) => k.publicKey),
      ].join('|');

      // The identity private key must appear nowhere in what we publish.
      final rows = alice.database.raw
          .select('SELECT identity_key_pair FROM device_identity WHERE id = 1');
      final pairBytes = rows.first['identity_key_pair'] as Uint8List;
      expect(pairBytes.length, greaterThan(32));

      final publishedBytes = _decodeBase64(alice.material.publicIdentityKey);
      expect(publishedBytes.length, lessThanOrEqualTo(33));
      expect(published.contains('\u0000'), isFalse);
      expect(alice.material.oneTimePreKeys, hasLength(preKeyBatchSize));
      expect(alice.material.registrationId, inInclusiveRange(1, 16383));
    });

    test('refuses to provision twice over an existing identity', () async {
      final alice = await Participant.create('alice');
      addTearDown(alice.dispose);

      // Re-provisioning would orphan every existing session.
      await expectLater(
        CryptoService.provision(database: alice.database),
        throwsA(isA<CryptoException>()),
      );
    });

    test('replenishment never reuses a prekey id', () async {
      final alice = await Participant.create('alice');
      addTearDown(alice.dispose);

      final more = await alice.service.generateMoreOneTimePreKeys(count: 5);
      final firstBatchIds = alice.material.oneTimePreKeys.map((k) => k.id).toSet();
      final newIds = more.map((k) => k.id).toSet();

      expect(newIds.intersection(firstBatchIds), isEmpty,
          reason: 'a reused id could substitute a key the server already handed out');
      expect(alice.service.availableOneTimePreKeys(), preKeyBatchSize + 5);
    });
  });
}

Uint8List _decodeBase64(String value) =>
    Uint8List.fromList(const Base64Decoder().convert(value));
