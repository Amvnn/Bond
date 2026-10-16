/// The Phase 1 vertical slice, end to end, against a live server.
///
/// This is the test the whole project has been building toward. Everything in
/// it is real: the real Signal Protocol through libsignal, real SQLCipher
/// databases, real Windows DPAPI protecting their keys, real HTTP and a real
/// WebSocket against a real Fastify server backed by real PostgreSQL and Redis.
/// Nothing is stubbed. That matters because the two earlier proofs each had a
/// gap: the server suite exercises the API with an AES-GCM stand-in for the
/// protocol, and the client crypto suite exercises the real protocol with no
/// server at all. This closes the seam between them.
///
/// It drives [AppController] rather than the services underneath, so the
/// orchestration the real app uses is what gets tested — session establishment,
/// envelope persistence, queue draining, receipts, restart recovery and
/// revocation.
///
/// ONE RULE FOR EDITING THIS FILE: never open a second connection to a
/// database while a controller still holds it. SQLCipher verifies a per-page
/// HMAC, and a concurrent reader can land on a page the owning connection is
/// part-way through writing, which surfaces as "file is not a database" and
/// looks exactly like corruption. The ciphertext inspection therefore happens
/// at the end, after every controller is disposed.
///
/// PREREQUISITES. The test skips rather than fails when they are absent,
/// because a missing server is not a defect in the code under test:
///
/// ```
/// docker compose --env-file infra/.env -f infra/docker-compose.yml up -d
/// cd server && ./node_modules/.bin/tsx --env-file=.env src/database/migrate.ts
/// cd server && ./node_modules/.bin/tsx --env-file=.env scripts/reset-dev.ts
/// cd server && ALLOW_BOOTSTRAP_ACCOUNT=true ./node_modules/.bin/tsx \
///   --env-file=.env src/server.ts
/// ```
///
/// The reset is required, not tidiness: registration is invite-only, so the
/// first account can only be created through the env-gated bootstrap path, and
/// that path refuses once any user exists.
library;

import 'dart:convert';
import 'dart:io';

import 'package:bond/core/app_controller.dart';
import 'package:bond/services/storage/dpapi_secure_key_store.dart';
import 'package:bond/services/storage/encrypted_database.dart';
import 'package:bond/services/storage/message_store.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:path/path.dart' as p;

final Uri serverUri = Uri.parse(
  const String.fromEnvironment(
    'BOND_SERVER',
    defaultValue: 'http://127.0.0.1:3000',
  ),
);

/// Comfortably over the 12-character minimum the server enforces.
const String password = 'correct-horse-battery-staple';

/// The strings that must never appear in anything the server handles.
const String firstMessage = 'the trout rises at dusk, 41.9028N 12.4964E';
const String offlineMessage = 'sent while you were away: bring the maps';

void main() {
  late Directory tempDir;
  late bool serverUp;

  setUpAll(() async {
    tempDir = Directory.systemTemp.createTempSync('bond-slice');
    serverUp = await _serverReachable();
  });

  tearDownAll(() {
    try {
      tempDir.deleteSync(recursive: true);
    } on FileSystemException {
      // Windows may still hold a database handle. Not a failure.
    }
  });

  test(
    'two clients complete the whole Phase 1 journey against a live server',
    () async {
      if (!serverUp) {
        markTestSkipped(
          'no server at $serverUri — see the prerequisites at the top of this '
          'file. A missing server is not a defect in the code under test.',
        );
        return;
      }

      // A suffix so a re-run against a reset database does not collide, and so
      // a failure leaves identifiable rows behind.
      final run = DateTime.now().millisecondsSinceEpoch.toRadixString(36);
      final aliceName = 'alice_$run';
      final bobName = 'bob_$run';

      final aliceKeys = p.join(tempDir.path, 'alice', 'keys');
      final aliceDb = p.join(tempDir.path, 'alice', 'bond.db');
      final bobKeys = p.join(tempDir.path, 'bob', 'keys');
      final bobDb = p.join(tempDir.path, 'bob', 'bond.db');
      Directory(p.dirname(aliceDb)).createSync(recursive: true);
      Directory(p.dirname(bobDb)).createSync(recursive: true);

      // =====================================================================
      _step('alice registers as user #1 via the bootstrap path');
      // =====================================================================
      final alice = AppController(
        serverUri: serverUri,
        keyStoreOverride: DpapiSecureKeyStore(aliceKeys),
        databasePathOverride: aliceDb,
      );

      await alice.start();
      expect(alice.phase, AppPhase.needsAuth);

      // The bootstrap path creates user #1 and nobody else, so this test needs
      // an empty database. When the server already has accounts the right
      // answer is to SKIP, not to fail: the precondition is missing, the code
      // under test is not broken — and failing here used to push whoever ran
      // the suite into wiping a database that might hold real accounts.
      //
      // It cannot be detected in advance: the client has no way to count
      // users, and the server answers `invitation_unusable` identically for
      // unknown, expired, spent, revoked and bootstrap-refused, so that the
      // endpoint cannot be used to probe. Attempting it is the only test.
      if (!await alice.register(username: aliceName, password: password)) {
        alice.dispose();
        markTestSkipped(
          'the bootstrap account is unavailable: ${alice.lastError}\n'
          'Either the server was started without ALLOW_BOOTSTRAP_ACCOUNT=true, '
          'or it already has accounts. If the accounts are disposable, reset '
          'with:\n'
          '  cd server && ./node_modules/.bin/tsx --env-file=.env '
          'scripts/reset-dev.ts',
        );
        return;
      }
      expect(alice.phase, AppPhase.needsDevice);
      expect(alice.userId, isNotNull);

      // =====================================================================
      _step('alice generates a device identity, publishing the public half');
      // =====================================================================
      expect(
        await alice.provisionDevice(deviceName: 'alice-windows'),
        isTrue,
        reason: 'alice could not register a device: ${alice.lastError}',
      );
      expect(alice.phase, AppPhase.ready);
      expect(alice.deviceIndex, inInclusiveRange(1, 127));

      // =====================================================================
      _step('alice creates a single-use invitation');
      // =====================================================================
      final invitation = await alice.createInvitation();
      expect(
        invitation,
        isNotNull,
        reason: 'alice could not create an invitation: ${alice.lastError}',
      );
      expect(invitation!.token.length, 43);

      // =====================================================================
      _step('bob redeems it to register, then provisions his own device');
      // =====================================================================
      var bob = AppController(
        serverUri: serverUri,
        keyStoreOverride: DpapiSecureKeyStore(bobKeys),
        databasePathOverride: bobDb,
      );

      await bob.start();
      expect(
        await bob.register(
          username: bobName,
          password: password,
          invitationToken: invitation.token,
        ),
        isTrue,
        reason: 'bob could not register with the invitation: ${bob.lastError}',
      );

      // ---------------------------------------------------------------------
      // Regression: a registered account must survive a restart taken BEFORE
      // the device is provisioned.
      //
      // The tokens and the user id are written at two different moments —
      // the tokens by the API layer's token callback, the user id from the
      // call's result — and the second write used to clobber the first, which
      // left a freshly registered account signed out on next launch. Device
      // registration happened to rewrite the tokens, so every path that
      // provisioned immediately hid it.
      // ---------------------------------------------------------------------
      bob.dispose();
      await Future<void>.delayed(const Duration(milliseconds: 500));
      bob = AppController(
        serverUri: serverUri,
        keyStoreOverride: DpapiSecureKeyStore(bobKeys),
        databasePathOverride: bobDb,
      );
      await bob.start();
      expect(
        bob.phase,
        AppPhase.needsDevice,
        reason: 'a registered account did not survive a restart before device '
            'provisioning (phase ${bob.phase.name}, '
            '${bob.fatalMessage ?? bob.lastError})',
      );
      expect(bob.userId, isNotNull);
      expect(bob.username, bobName);

      expect(
        await bob.provisionDevice(deviceName: 'bob-windows'),
        isTrue,
        reason: 'bob could not register a device: ${bob.lastError}',
      );
      expect(bob.phase, AppPhase.ready);

      final aliceUserId = alice.userId!;
      final bobUserId = bob.userId!;

      // The token was single-use: redeeming it again must fail.
      expect(
        await alice.acceptInvitation(invitation.token),
        isFalse,
        reason: 'a spent invitation was accepted a second time',
      );

      // =====================================================================
      _step('they are now contacts, reachable no other way');
      // =====================================================================
      await alice.refreshContacts();
      await bob.refreshContacts();

      expect(alice.contacts, hasLength(1));
      expect(alice.contacts.single.contactUserId, bobUserId);
      expect(alice.contacts.single.username, bobName);
      expect(bob.contacts.single.contactUserId, aliceUserId);

      final bobDevice = alice.contacts.single.devices.single;
      final aliceDevice = bob.contacts.single.devices.single;
      expect(bobDevice.deviceIndex, bob.deviceIndex);
      expect(aliceDevice.deviceIndex, alice.deviceIndex);

      // =====================================================================
      _step('both sides derive the same safety number, and verify');
      // =====================================================================
      final aliceSeesNumber = alice.safetyNumber(
        contactUserId: bobUserId,
        deviceIndex: bobDevice.deviceIndex,
      );
      final bobSeesNumber = bob.safetyNumber(
        contactUserId: aliceUserId,
        deviceIndex: aliceDevice.deviceIndex,
      );

      expect(aliceSeesNumber, isNotNull);
      expect(aliceSeesNumber, hasLength(60));
      expect(
        aliceSeesNumber,
        bobSeesNumber,
        reason: 'the two sides derived different safety numbers, so an '
            'out-of-band comparison would always fail',
      );

      // Verifying BEFORE any message is exchanged must stick: it pins the
      // compared key, so a later substitution is detected rather than trusted
      // on first use.
      await alice.setVerified(
        contactUserId: bobUserId,
        deviceIndex: bobDevice.deviceIndex,
        verified: true,
      );
      expect(
        alice
            .peerIdentity(
              contactUserId: bobUserId,
              deviceIndex: bobDevice.deviceIndex,
            )
            ?.isVerified,
        isTrue,
        reason: 'verification before first contact recorded nothing',
      );

      // =====================================================================
      _step('alice sends, establishing the session on the way');
      // =====================================================================
      expect(
        await alice.sendMessage(contactUserId: bobUserId, body: firstMessage),
        isTrue,
        reason: 'alice could not send: ${alice.lastError}',
      );

      await _waitFor(
        () => alice
            .conversation(bobUserId)
            .any((m) => m.outgoing && m.state != MessageState.sending),
        "the server to acknowledge alice's message",
        onTimeout: () => 'lastError: ${alice.lastError}',
      );

      final sent = alice.conversation(bobUserId).single;
      expect(sent.body, firstMessage);
      expect(
        sent.state,
        isNot(MessageState.failed),
        reason: 'the send failed: ${alice.lastError}',
      );

      // =====================================================================
      _step('bob fetches and decrypts it locally');
      // =====================================================================
      await bob.drainQueue();
      await _waitFor(
        () => bob.conversation(aliceUserId).isNotEmpty,
        'bob to receive and decrypt the message',
        onTimeout: () => 'decryption failures: '
            '${bob.decryptionFailures.map((f) => f.reason).join(' | ')}; '
            'lastError: ${bob.lastError}',
      );

      final received = bob.conversation(aliceUserId).single;
      expect(received.body, firstMessage);
      expect(received.outgoing, isFalse);
      expect(bob.decryptionFailures, isEmpty);

      // =====================================================================
      _step('receipts reach alice over her own socket, carrying no plaintext');
      // =====================================================================
      await bob.markConversationRead(aliceUserId);
      await _waitFor(
        () => alice.conversation(bobUserId).single.state == MessageState.read,
        'alice to see the read receipt',
        onTimeout: () =>
            'state was ${alice.conversation(bobUserId).single.state.name}',
      );

      // =====================================================================
      _step('offline delivery across a real restart');
      //
      // Bob's controller is disposed, closing his socket and his database as
      // quitting the application would. Alice sends. A NEW controller then
      // opens the same database through the same DPAPI store, and must both
      // resume the session and collect the message. Store-and-forward and
      // ratchet durability in one step.
      // =====================================================================
      bob.dispose();
      // Let the disposed controller's in-flight work settle before the file is
      // reopened, so this tests a clean restart rather than a torn one.
      await Future<void>.delayed(const Duration(milliseconds: 500));

      expect(
        await alice.sendMessage(contactUserId: bobUserId, body: offlineMessage),
        isTrue,
        reason: 'alice could not send while bob was offline: ${alice.lastError}',
      );

      bob = AppController(
        serverUri: serverUri,
        keyStoreOverride: DpapiSecureKeyStore(bobKeys),
        databasePathOverride: bobDb,
      );

      await bob.start();
      expect(
        bob.phase,
        AppPhase.ready,
        reason: 'bob did not resume his session and device after restart: '
            '${bob.fatalMessage ?? bob.lastError}',
      );

      // History decrypted before the restart is still readable, so the
      // encrypted database really did persist.
      expect(
        bob.conversation(aliceUserId).map((m) => m.body),
        contains(firstMessage),
      );

      await bob.drainQueue();
      await _waitFor(
        () =>
            bob.conversation(aliceUserId).any((m) => m.body == offlineMessage),
        'bob to collect the message queued while he was offline',
        onTimeout: () => 'decryption failures: '
            '${bob.decryptionFailures.map((f) => f.reason).join(' | ')}',
      );
      expect(
        bob.decryptionFailures,
        isEmpty,
        reason: 'the ratchet did not survive the restart',
      );

      // =====================================================================
      _step('bob revokes his own device');
      //
      // Server-side refusal of a revoked device's credential on REST and the
      // WebSocket is covered by the server suite. What is checked here is the
      // CLIENT half: the local secrets are destroyed, and the contact becomes
      // unaddressable rather than appearing to work and failing later.
      // =====================================================================
      final bobDeviceId = bob.deviceId!;
      expect(await bob.revokeDevice(bobDeviceId), isTrue);
      expect(bob.phase, AppPhase.revoked);

      expect(bob.conversation(aliceUserId), isEmpty);
      expect(bob.deviceId, isNull);

      await alice.refreshContacts();
      expect(
        alice.contacts.single.devices,
        isEmpty,
        reason: 'a revoked device is still listed as addressable',
      );
      expect(
        await alice.sendMessage(contactUserId: bobUserId, body: 'should fail'),
        isFalse,
        reason: 'alice sent a message to a fully revoked contact',
      );

      // =====================================================================
      _step('what left the device was opaque');
      //
      // Read AFTER both controllers are disposed, so nothing else holds the
      // database. These are the exact bytes that were transmitted, stored at
      // send time rather than re-derived.
      // =====================================================================
      alice.dispose();
      bob.dispose();
      await Future<void>.delayed(const Duration(milliseconds: 500));

      final transmitted = await _readTransmittedEnvelopes(aliceDb, aliceKeys);
      expect(
        transmitted,
        hasLength(greaterThanOrEqualTo(2)),
        reason: 'both sent messages should have stored envelopes',
      );
      for (final ciphertextBase64 in transmitted) {
        final bytes = base64.decode(ciphertextBase64);
        for (final secret in const [firstMessage, offlineMessage]) {
          expect(
            _containsSequence(bytes, utf8.encode(secret)),
            isFalse,
            reason: 'plaintext appears inside the ciphertext that was sent',
          );
        }
        expect(ciphertextBase64.contains(firstMessage), isFalse);
      }
    },
    timeout: const Timeout(Duration(minutes: 3)),
  );
}

void _step(String what) {
  // ignore: avoid_print
  print('--- $what');
}

Future<bool> _serverReachable() async {
  final client = HttpClient()..connectionTimeout = const Duration(seconds: 2);
  try {
    final request = await client.getUrl(serverUri.resolve('/health'));
    final response = await request.close();
    await response.drain<void>();
    return response.statusCode == 200;
  } on Object {
    return false;
  } finally {
    client.close(force: true);
  }
}

/// The ciphertexts Alice actually transmitted, read out of her own database.
///
/// Only safe once no controller holds the file — see the rule at the top.
Future<List<String>> _readTransmittedEnvelopes(
  String dbPath,
  String keysDir,
) async {
  final database = await EncryptedDatabase.open(
    path: dbPath,
    keyStore: DpapiSecureKeyStore(keysDir),
  );
  try {
    final rows = database.raw.select(
      "SELECT ciphertext FROM outgoing_targets WHERE ciphertext <> ''",
    );
    return rows.map((r) => r['ciphertext'] as String).toList(growable: false);
  } finally {
    database.dispose();
  }
}

Future<void> _waitFor(
  bool Function() condition,
  String description, {
  String Function()? onTimeout,
  Duration timeout = const Duration(seconds: 20),
}) async {
  final deadline = DateTime.now().add(timeout);
  while (DateTime.now().isBefore(deadline)) {
    if (condition()) return;
    await Future<void>.delayed(const Duration(milliseconds: 100));
  }
  final extra = onTimeout == null ? '' : ' (${onTimeout()})';
  fail('timed out waiting for $description$extra');
}

bool _containsSequence(List<int> haystack, List<int> needle) {
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
