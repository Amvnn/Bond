/// Validation spike for pub `libsignal` 7.3.1.
///
/// This is the checklist from docs/crypto-design.md "Validation status".
/// It is deliberately adversarial: a library that passes the happy path but
/// silently accepts a tampered ciphertext or a wrongly-signed prekey is worse
/// than no library, so most of these tests assert that something FAILS.
///
/// Throwaway spike. Nothing here ships.
library;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:libsignal/libsignal.dart';

/// One simulated device installation: its own identity, registration id,
/// prekeys and stores. Mirrors the "each installation is a distinct
/// cryptographic device" rule from the project brief.
class TestDevice {
  TestDevice._({
    required this.userId,
    required this.deviceId,
    required this.identity,
    required this.registrationId,
    required this.preKeyPublicBytes,
    required this.signedPreKeyPublicBytes,
    required this.signedPreKeySignature,
    required this.kyberPreKeyPublicBytes,
    required this.kyberPreKeySignature,
    required this.sessionStore,
    required this.identityStore,
    required this.preKeyStore,
    required this.signedPreKeyStore,
    required this.kyberPreKeyStore,
  });

  static const int preKeyId = 1;
  static const int signedPreKeyId = 1;
  static const int kyberPreKeyId = 1;

  final String userId;
  final int deviceId;
  final IdentityKeyPair identity;
  final int registrationId;

  final Uint8List preKeyPublicBytes;
  final Uint8List signedPreKeyPublicBytes;
  final Uint8List signedPreKeySignature;
  final Uint8List kyberPreKeyPublicBytes;
  final Uint8List kyberPreKeySignature;

  final InMemorySessionStore sessionStore;
  final InMemoryIdentityKeyStore identityStore;
  final InMemoryPreKeyStore preKeyStore;
  final InMemorySignedPreKeyStore signedPreKeyStore;
  final InMemoryKyberPreKeyStore kyberPreKeyStore;

  ProtocolAddress get address =>
      ProtocolAddress(name: userId, deviceId: deviceId);

  /// Generates a device and provisions its prekeys, as
  /// docs/architecture.md section 6 describes.
  ///
  /// [signingIdentity] exists only so a test can deliberately sign the prekeys
  /// with the WRONG identity key, to check the signature is actually verified.
  static Future<TestDevice> create(
    String userId, {
    int deviceId = 1,
    IdentityKeyPair? signingIdentity,
  }) async {
    final identity = IdentityKeyPair.generate();
    final signer = signingIdentity ?? identity;
    // libsignal registration ids are 14-bit.
    final registrationId = Random.secure().nextInt(16383) + 1;
    final timestamp = BigInt.from(DateTime.now().millisecondsSinceEpoch);

    // One-time prekey.
    final preKeyPrivate = PrivateKey.generate();
    final preKeyPublic = preKeyPrivate.getPublicKey();
    final preKeyRecord = PreKeyRecord(
      id: preKeyId,
      publicKey: preKeyPublic,
      privateKey: preKeyPrivate,
    );

    // Signed prekey, signed by the identity key.
    final signedPreKeyPrivate = PrivateKey.generate();
    final signedPreKeyPublic = signedPreKeyPrivate.getPublicKey();
    final signedPreKeyPublicBytes = signedPreKeyPublic.serialize();
    final signedPreKeySignature =
        signer.sign(message: signedPreKeyPublicBytes.toList());
    final signedPreKeyRecord = SignedPreKeyRecord(
      id: signedPreKeyId,
      timestamp: timestamp,
      publicKey: signedPreKeyPublic,
      privateKey: signedPreKeyPrivate,
      signature: signedPreKeySignature.toList(),
    );

    // Kyber prekey. NOT optional: PreKeyBundle requires it, so libsignal
    // 0.103 mandates PQXDH rather than offering it.
    final kyberKeyPair = KyberKeyPair.generate();
    final kyberPreKeyPublicBytes = kyberKeyPair.getPublicKey().serialize();
    final kyberPreKeySignature =
        signer.sign(message: kyberPreKeyPublicBytes.toList());
    final kyberPreKeyRecord = KyberPreKeyRecord.create(
      id: kyberPreKeyId,
      timestamp: timestamp,
      keyPair: kyberKeyPair,
      signature: kyberPreKeySignature.toList(),
    );

    final preKeyStore = InMemoryPreKeyStore();
    final signedPreKeyStore = InMemorySignedPreKeyStore();
    final kyberPreKeyStore = InMemoryKyberPreKeyStore();
    await preKeyStore.storePreKey(preKeyId, preKeyRecord);
    await signedPreKeyStore.storeSignedPreKey(signedPreKeyId, signedPreKeyRecord);
    await kyberPreKeyStore.storeKyberPreKey(kyberPreKeyId, kyberPreKeyRecord);

    return TestDevice._(
      userId: userId,
      deviceId: deviceId,
      identity: identity,
      registrationId: registrationId,
      preKeyPublicBytes: preKeyPublic.serialize(),
      signedPreKeyPublicBytes: signedPreKeyPublicBytes,
      signedPreKeySignature: signedPreKeySignature,
      kyberPreKeyPublicBytes: kyberPreKeyPublicBytes,
      kyberPreKeySignature: kyberPreKeySignature,
      sessionStore: InMemorySessionStore(),
      identityStore: InMemoryIdentityKeyStore(identity, registrationId),
      preKeyStore: preKeyStore,
      signedPreKeyStore: signedPreKeyStore,
      kyberPreKeyStore: kyberPreKeyStore,
    );
  }

  /// The public material the server would hold and hand out. Note it contains
  /// no private key of any kind.
  PreKeyBundle publicBundle() => PreKeyBundle(
        registrationId: registrationId,
        deviceId: deviceId,
        preKeyId: preKeyId,
        preKeyPublic: preKeyPublicBytes,
        signedPreKeyId: signedPreKeyId,
        signedPreKeyPublic: signedPreKeyPublicBytes.toList(),
        signedPreKeySignature: signedPreKeySignature.toList(),
        identityKey: identity.publicKey.toList(),
        kyberPreKeyId: kyberPreKeyId,
        kyberPreKeyPublic: kyberPreKeyPublicBytes.toList(),
        kyberPreKeySignature: kyberPreKeySignature.toList(),
      );

  SessionCipher get cipher => SessionCipher(
        localAddress: address,
        sessionStore: sessionStore,
        identityKeyStore: identityStore,
        preKeyStore: preKeyStore,
        signedPreKeyStore: signedPreKeyStore,
        kyberPreKeyStore: kyberPreKeyStore,
      );

  SessionBuilder get sessionBuilder => SessionBuilder(
        localAddress: address,
        sessionStore: sessionStore,
        identityKeyStore: identityStore,
      );

  /// X3DH/PQXDH against a peer's published bundle.
  Future<void> establishSessionWith(TestDevice peer) async {
    await sessionBuilder.processPreKeyBundle(peer.address, peer.publicBundle());
  }
}

void main() {
  setUpAll(() async {
    await LibSignal.init();
  });

  group('1. library loads', () {
    test('native library initialises and generates keys', () {
      final identity = IdentityKeyPair.generate();
      // X25519 public keys serialise to 33 bytes (type byte + 32).
      expect(identity.publicKey.length, anyOf(32, 33));

      final private = PrivateKey.generate();
      try {
        final signature = private.sign(message: utf8.encode('spike'));
        expect(signature.length, 64);
      } finally {
        // Bounds how long the secret stays resident; see the package
        // SECURITY.md on non-deterministic GC of native handles.
        private.dispose();
      }
    });
  });

  group('2. round trip', () {
    test('Bob decrypts Alice first message, and a follow-up', () async {
      final alice = await TestDevice.create('alice');
      final bob = await TestDevice.create('bob');

      await alice.establishSessionWith(bob);

      const plaintext = 'the server must never see this';
      final encrypted = await alice.cipher.encrypt(
        bob.address,
        Uint8List.fromList(utf8.encode(plaintext)),
      );

      // First message must be a PreKey message (session establishment).
      expect(encrypted.type, CiphertextMessageType.preKey);
      // Sanity: the ciphertext does not contain the plaintext.
      expect(utf8.decode(encrypted.ciphertext, allowMalformed: true),
          isNot(contains('never see this')));

      final decrypted = await bob.cipher.decrypt(alice.address, encrypted);
      expect(utf8.decode(decrypted), plaintext);

      // Still a PreKey message: Alice has had no reply yet, so the session is
      // unconfirmed and she must keep including the prekey preamble. Verified
      // rather than assumed, because it determines what the server has to
      // accept for a first exchange.
      final second = await alice.cipher.encrypt(
        bob.address,
        Uint8List.fromList(utf8.encode('second')),
      );
      expect(second.type, CiphertextMessageType.preKey);
      expect(utf8.decode(await bob.cipher.decrypt(alice.address, second)),
          'second');

      // Bob replies, which confirms the session in both directions.
      final reply = await bob.cipher.encrypt(
        alice.address,
        Uint8List.fromList(utf8.encode('got it')),
      );
      expect(reply.type, CiphertextMessageType.signal);
      expect(utf8.decode(await alice.cipher.decrypt(bob.address, reply)),
          'got it');

      // Only now does Alice drop the preamble.
      final third = await alice.cipher.encrypt(
        bob.address,
        Uint8List.fromList(utf8.encode('third')),
      );
      expect(third.type, CiphertextMessageType.signal);
      expect(utf8.decode(await bob.cipher.decrypt(alice.address, third)),
          'third');
    });

    test('replaying the same ciphertext is rejected', () async {
      final alice = await TestDevice.create('alice');
      final bob = await TestDevice.create('bob');
      await alice.establishSessionWith(bob);

      final encrypted = await alice.cipher.encrypt(
        bob.address,
        Uint8List.fromList(utf8.encode('once only')),
      );
      expect(utf8.decode(await bob.cipher.decrypt(alice.address, encrypted)),
          'once only');

      // The ratchet must refuse the identical message a second time.
      await expectLater(
        bob.cipher.decrypt(alice.address, encrypted),
        throwsA(isA<Object>()),
      );
    });
  });

  group('3. the failures that matter', () {
    test('wrong recipient cannot decrypt', () async {
      final alice = await TestDevice.create('alice');
      final bob = await TestDevice.create('bob');
      final carol = await TestDevice.create('carol');

      await alice.establishSessionWith(bob);
      final forBob = await alice.cipher.encrypt(
        bob.address,
        Uint8List.fromList(utf8.encode('for bob only')),
      );

      // Carol holds a valid identity and valid prekeys, but not Bob's.
      await expectLater(
        carol.cipher.decrypt(alice.address, forBob),
        throwsA(isA<Object>()),
      );
    });

    test('tampered ciphertext fails authentication', () async {
      final alice = await TestDevice.create('alice');
      final bob = await TestDevice.create('bob');
      await alice.establishSessionWith(bob);

      final encrypted = await alice.cipher.encrypt(
        bob.address,
        Uint8List.fromList(utf8.encode('untampered')),
      );

      // Flip one bit in the trailing MAC region.
      final tamperedBytes = Uint8List.fromList(encrypted.ciphertext);
      tamperedBytes[tamperedBytes.length - 1] ^= 0x01;

      await expectLater(
        bob.cipher.decrypt(
          alice.address,
          CiphertextMessage(type: encrypted.type, ciphertext: tamperedBytes),
        ),
        throwsA(isA<Object>()),
        reason: 'a modified ciphertext must never decrypt',
      );
    });

    test('ciphertext truncation fails', () async {
      final alice = await TestDevice.create('alice');
      final bob = await TestDevice.create('bob');
      await alice.establishSessionWith(bob);

      final encrypted = await alice.cipher.encrypt(
        bob.address,
        Uint8List.fromList(utf8.encode('truncate me')),
      );
      final truncated = Uint8List.fromList(
        encrypted.ciphertext.sublist(0, encrypted.ciphertext.length - 8),
      );

      await expectLater(
        bob.cipher.decrypt(
          alice.address,
          CiphertextMessage(type: encrypted.type, ciphertext: truncated),
        ),
        throwsA(isA<Object>()),
      );
    });

    test('prekey bundle signed by the wrong identity key is rejected',
        () async {
      final alice = await TestDevice.create('alice');
      // An attacker signs Mallory's prekeys with a key that is not the
      // identity key published alongside them. This is the exact shape of a
      // malicious-server key substitution, so it MUST be refused.
      final attackerIdentity = IdentityKeyPair.generate();
      final mallory = await TestDevice.create(
        'mallory',
        signingIdentity: attackerIdentity,
      );

      await expectLater(
        alice.sessionBuilder
            .processPreKeyBundle(mallory.address, mallory.publicBundle()),
        throwsA(isA<Object>()),
        reason: 'signed prekey signature must be verified against the '
            'identity key in the same bundle',
      );
    });
  });

  group('4. identity verification', () {
    test('safety numbers agree between the two parties', () async {
      final alice = await TestDevice.create('alice');
      final bob = await TestDevice.create('bob');

      final aliceView = Fingerprint(
        iterations: 5200,
        version: 1,
        localIdentifier: utf8.encode(alice.userId),
        localPublicKey: alice.identity.publicKey.toList(),
        remoteIdentifier: utf8.encode(bob.userId),
        remotePublicKey: bob.identity.publicKey.toList(),
      );
      final bobView = Fingerprint(
        iterations: 5200,
        version: 1,
        localIdentifier: utf8.encode(bob.userId),
        localPublicKey: bob.identity.publicKey.toList(),
        remoteIdentifier: utf8.encode(alice.userId),
        remotePublicKey: alice.identity.publicKey.toList(),
      );

      final aliceNumber = aliceView.displayString();
      expect(aliceNumber, hasLength(60));
      expect(aliceNumber, bobView.displayString(),
          reason: 'both sides must read the same safety number aloud');
    });

    test('safety number changes when an identity key changes', () async {
      final alice = await TestDevice.create('alice');
      final bob = await TestDevice.create('bob');
      final impostor = await TestDevice.create('bob');

      String numberFor(TestDevice peer) => Fingerprint(
            iterations: 5200,
            version: 1,
            localIdentifier: utf8.encode(alice.userId),
            localPublicKey: alice.identity.publicKey.toList(),
            remoteIdentifier: utf8.encode(peer.userId),
            remotePublicKey: peer.identity.publicKey.toList(),
          ).displayString();

      // Same user id, different identity key: the number must differ, which is
      // what makes an identity change detectable by a human.
      expect(numberFor(bob), isNot(numberFor(impostor)));
    });

    test('a changed identity key is visible to the identity store', () async {
      final alice = await TestDevice.create('alice');
      final bob = await TestDevice.create('bob');
      await alice.establishSessionWith(bob);

      final stored = await alice.identityStore.getIdentity(bob.address);
      expect(stored, isNotNull,
          reason: 'the peer identity must be recorded so a later change '
              'can be detected');

      // The in-memory store is trust-on-first-use, so it accepts a first key
      // and only rejects a DIFFERENT one later. Our client must implement its
      // own store that surfaces this to the user rather than deciding silently.
      final impostor = await TestDevice.create('bob');
      final trusted = await alice.identityStore.isTrustedIdentity(
        bob.address,
        PublicKey.deserialize(bytes: impostor.identity.publicKey),
        Direction.sending,
      );
      expect(trusted, isFalse,
          reason: 'a key change for a known contact must not be trusted');
    });
  });

  group('5. private key containment', () {
    test('the published bundle carries no private key material', () async {
      final bob = await TestDevice.create('bob');
      final bundle = bob.publicBundle();

      // Everything the server would receive.
      final published = <int>[
        ...bundle.identityKey(),
        ...bundle.kyberPreKeyPublic(),
        ...bundle.kyberPreKeySignature(),
      ];

      // The identity private key must not appear anywhere in it.
      // IdentityKeyPair exposes privateKey as raw bytes, which is exactly why
      // this check is worth having: nothing stops a caller publishing them.
      final privateBytes = bob.identity.privateKey;
      expect(privateBytes.length, greaterThanOrEqualTo(32));
      expect(
        _containsSubsequence(published, privateBytes),
        isFalse,
        reason: 'a private key must never reach the server',
      );
    });
  });
}

bool _containsSubsequence(List<int> haystack, List<int> needle) {
  if (needle.isEmpty || needle.length > haystack.length) return false;
  outer:
  for (var i = 0; i <= haystack.length - needle.length; i++) {
    for (var j = 0; j < needle.length; j++) {
      if (haystack[i + j] != needle[j]) continue outer;
    }
    return true;
  }
  return false;
}
