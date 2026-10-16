// ignore_for_file: prefer_initializing_formals
// The suggested fix is illegal: Dart forbids named parameters that begin with
// an underscore, so `required this._keyStoreOverride` does not compile.
/// Application state and orchestration.
///
/// This is the only layer that knows about crypto, storage and the network at
/// the same time, which is deliberate: it keeps that coordination out of the
/// widgets. A widget calls a method here and rebuilds; it never touches
/// libsignal, never holds a token, and never sees a ciphertext.
///
/// THE ORDER OF OPERATIONS THAT MATTERS
///
/// Sending is: ensure a session, encrypt, persist the envelope, then transmit.
/// Persisting before transmitting is what makes a retry safe — the ratchet has
/// already advanced, so the only correct retry is replaying identical bytes.
/// Encrypting after persisting would be simpler to read and wrong.
///
/// Receiving is: fetch, decrypt, store, acknowledge. Acknowledging before
/// storing would let a crash between the two lose a message permanently, since
/// the server drops an acknowledged envelope and the ratchet cannot decrypt the
/// same ciphertext twice.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:flutter/foundation.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';

import '../services/crypto/crypto_service.dart';
import '../services/crypto/stores/persistent_identity_key_store.dart';
import '../services/network/api_client.dart';
import '../services/network/api_exception.dart';
import '../services/network/api_models.dart';
import '../services/network/realtime_client.dart';
import '../services/storage/auth_store.dart';
import '../services/storage/dpapi_secure_key_store.dart';
import '../services/storage/encrypted_database.dart';
import '../services/storage/message_store.dart';
import '../services/storage/secure_key_store.dart';

/// Where the app is in its lifecycle. The UI switches on this and nothing else.
enum AppPhase {
  /// Opening the key store and the database.
  starting,

  /// No account session. Register or sign in.
  needsAuth,

  /// Signed in, but this installation has no cryptographic device identity yet.
  needsDevice,

  /// Fully provisioned.
  ready,

  /// This device was revoked. Local state has been destroyed.
  revoked,

  /// Startup failed in a way that must not be worked around — most likely the
  /// secure key store refusing, or a database that cannot be decrypted. Failing
  /// visibly is the documented behaviour; degrading to unprotected storage is
  /// not an option.
  fatal,
}

/// One row in the conversation list.
class ConversationSummary {
  const ConversationSummary({
    required this.contact,
    required this.lastMessage,
    required this.unreadCount,
    required this.isVerified,
    required this.hasIdentityWarning,
    required this.serverKeyDiffers,
  });

  final Contact contact;
  final LocalMessage? lastMessage;
  final int unreadCount;

  /// Verified by a human comparing safety numbers, locally recorded. NOT the
  /// server's advisory field.
  final bool isVerified;

  /// A changed identity key the user has not acknowledged. Sending is blocked.
  final bool hasIdentityWarning;

  /// The key the server now reports differs from the one stored locally.
  ///
  /// A softer signal than [hasIdentityWarning]: it comes from the contact list
  /// rather than from a cryptographic operation, so it can also mean the
  /// contact legitimately reinstalled. It is surfaced because this is precisely
  /// the shape of a server substituting a key (threat T2).
  final bool serverKeyDiffers;
}

/// A decryption that failed. Surfaced, never retried.
class DecryptionFailure {
  const DecryptionFailure({
    required this.messageId,
    required this.senderUserId,
    required this.reason,
    required this.at,
  });

  final String messageId;
  final String senderUserId;
  final String reason;
  final DateTime at;
}

class AppController extends ChangeNotifier {
  AppController({
    Uri? serverUri,
    String? profile,
    SecureKeyStore? keyStoreOverride,
    String? databasePathOverride,
  })  : serverUri = serverUri ?? Uri.parse(resolveServer()),
        profile = validateProfile(profile ?? resolveProfile()),
        _keyStoreOverride = keyStoreOverride,
        _databasePathOverride = databasePathOverride;

  /// Which installation this process is. Separate profiles get separate
  /// encrypted databases and separate OS-protected keys, so two of them on one
  /// machine are genuinely distinct installations rather than two windows onto
  /// the same state.
  ///
  /// Resolved at RUNTIME from the environment, falling back to a compile-time
  /// define and then to `default`. Runtime first is what lets one build be
  /// launched twice:
  ///
  /// ```powershell
  /// $env:BOND_PROFILE='bob'; .\bond.exe
  /// ```
  ///
  /// A compile-time-only define would mean a separate build per profile, which
  /// makes running two clients side by side a chore rather than a command.
  static String resolveProfile() {
    final fromEnv = Platform.environment['BOND_PROFILE'];
    if (fromEnv != null && fromEnv.trim().isNotEmpty) return fromEnv.trim();
    const compiled = String.fromEnvironment('BOND_PROFILE');
    return compiled.isEmpty ? 'default' : compiled;
  }

  /// Same precedence for the server origin: `BOND_SERVER` in the environment,
  /// then `--dart-define=BOND_SERVER=...`, then local development.
  static String resolveServer() {
    final fromEnv = Platform.environment['BOND_SERVER'];
    if (fromEnv != null && fromEnv.trim().isNotEmpty) return fromEnv.trim();
    const compiled = String.fromEnvironment('BOND_SERVER');
    return compiled.isEmpty ? 'http://127.0.0.1:3000' : compiled;
  }

  /// A profile name becomes a directory name, so it is validated rather than
  /// sanitised: anything outside this set is refused, and nothing is quietly
  /// rewritten into something that looks safe. `..` and separators cannot
  /// survive this, so a profile cannot escape the application data directory.
  static String validateProfile(String value) {
    if (!RegExp(r'^[A-Za-z0-9_-]{1,32}$').hasMatch(value)) {
      throw ArgumentError.value(
        value,
        'profile',
        'a profile name must be 1-32 characters of letters, digits, '
            'underscore or hyphen',
      );
    }
    return value;
  }

  final Uri serverUri;
  final String profile;
  final SecureKeyStore? _keyStoreOverride;
  final String? _databasePathOverride;

  /// Below this, top up the server's one-time prekey supply. A drained supply
  /// does not break messaging — X3DH falls back to the signed prekey — but it
  /// loses the forward secrecy the one-time key provides for a first message.
  static const int _preKeyLowWaterMark = 10;

  late final ApiClient _api = ApiClient(
    baseUri: serverUri,
    onTokensChanged: _persistTokens,
    onDeviceRevoked: _onDeviceRevokedSignal,
  );

  late final RealtimeClient _realtime = RealtimeClient(baseUri: serverUri);

  EncryptedDatabase? _db;
  SecureKeyStore? _keyStore;
  CryptoService? _crypto;
  AuthStore? _authStore;
  MessageStore? _messageStore;

  StreamSubscription<RealtimeEvent>? _eventSubscription;
  StreamSubscription<ConnectionState>? _stateSubscription;

  AppPhase _phase = AppPhase.starting;
  String? _fatalMessage;
  String? _userId;
  String? _username;
  String? _deviceId;
  int? _deviceIndex;
  List<Contact> _contacts = const [];
  ConnectionState _connection = ConnectionState.disconnected;
  final List<DecryptionFailure> _decryptionFailures = [];
  String? _lastError;
  bool _busy = false;

  /// Serialises queue drains. Two overlapping drains would fetch the same
  /// envelope twice and the second decrypt would fail, because the ratchet has
  /// already consumed it.
  Future<void>? _drainInFlight;

  // -------------------------------------------------------------------------
  // Exposed state
  // -------------------------------------------------------------------------

  AppPhase get phase => _phase;
  String? get fatalMessage => _fatalMessage;
  String? get userId => _userId;
  String? get username => _username;
  String? get deviceId => _deviceId;
  int? get deviceIndex => _deviceIndex;
  List<Contact> get contacts => _contacts;
  ConnectionState get connection => _connection;
  bool get isOnline => _connection == ConnectionState.connected;

  /// Exposed as a boolean because the realtime layer's `ConnectionState`
  /// collides by name with Flutter's own, and widgets should not have to
  /// import the networking layer with a prefix to render a status line.
  bool get isConnecting => _connection == ConnectionState.connecting;
  List<DecryptionFailure> get decryptionFailures =>
      List.unmodifiable(_decryptionFailures);
  String? get lastError => _lastError;
  bool get busy => _busy;

  String get secureStorageDescription =>
      _keyStore?.backendDescription ?? 'not initialised';

  CryptoService? get crypto => _crypto;

  void clearError() {
    if (_lastError == null) return;
    _lastError = null;
    notifyListeners();
  }

  // -------------------------------------------------------------------------
  // Startup
  // -------------------------------------------------------------------------

  /// Opens local storage and restores whatever session exists.
  ///
  /// Any failure here is fatal rather than degraded: the alternatives would be
  /// an unencrypted database or an unprotected key, both of which the brief
  /// forbids.
  Future<void> start() async {
    try {
      await CryptoService.initialise();

      // Only consult path_provider when something actually needs the default
      // location. Both overrides supplied means this runs under test, where
      // the platform channel is unavailable.
      final keyStoreOverride = _keyStoreOverride;
      final databasePathOverride = _databasePathOverride;
      final directory =
          (keyStoreOverride != null && databasePathOverride != null)
              ? null
              : await _dataDirectory();

      _keyStore = keyStoreOverride ?? _platformKeyStore(directory!);

      _db = await EncryptedDatabase.open(
        path: databasePathOverride ?? p.join(directory!, 'bond.db'),
        keyStore: _keyStore!,
      );
      _authStore = AuthStore(_db!);
      _messageStore = MessageStore(_db!);

      final session = _authStore!.read();
      // An empty user id means the tokens were written by the callback but the
      // process died before the identity landed. There is nothing usable to
      // resume, so start over rather than carrying a half-written session.
      if (session == null || !session.hasTokens || session.userId.isEmpty) {
        _setPhase(AppPhase.needsAuth);
        return;
      }

      _userId = session.userId;
      _username = session.username;
      _api.adoptTokens(
        SessionTokens(
          accessToken: session.accessToken!,
          refreshToken: session.refreshToken!,
        ),
      );

      _crypto = await CryptoService.restore(database: _db!);
      final identifiers = _crypto?.serverIdentifiers();
      if (_crypto == null || identifiers == null) {
        _setPhase(AppPhase.needsDevice);
        return;
      }

      _deviceId = identifiers.deviceId;
      _deviceIndex = identifiers.deviceIndex;
      await _enterReady();
    } on SecureStorageException catch (error) {
      _fail(
        'Secure storage is unavailable, so this device cannot hold key '
        'material safely: ${error.message}',
      );
    } on LocalDatabaseException catch (error) {
      _fail(error.message);
    } on Object catch (error) {
      _fail('Startup failed: $error');
    }
  }

  SecureKeyStore _platformKeyStore(String directory) {
    final keyDirectory = p.join(directory, 'keys');
    if (Platform.isWindows) return DpapiSecureKeyStore(keyDirectory);
    // Android Keystore, iOS Keychain, Secret Service and macOS Keychain are
    // not implemented yet. Refusing is the documented fallback; storing key
    // material in a plain file is not.
    return UnavailableSecureKeyStore(Platform.operatingSystem);
  }

  Future<String> _dataDirectory() async {
    final base = await getApplicationSupportDirectory();
    final directory = Directory(p.join(base.path, 'profiles', profile));
    if (!directory.existsSync()) directory.createSync(recursive: true);
    return directory.path;
  }

  // -------------------------------------------------------------------------
  // Account
  // -------------------------------------------------------------------------

  Future<bool> register({
    required String username,
    required String password,
    String? invitationToken,
  }) =>
      _guard(() async {
        final tokens = await _api.register(
          username: username,
          password: password,
          invitationToken: invitationToken,
        );
        _adoptAccount(tokens.userId, username);
        _setPhase(AppPhase.needsDevice);
      });

  Future<bool> login({
    required String username,
    required String password,
  }) =>
      _guard(() async {
        final tokens = await _api.login(username: username, password: password);
        _adoptAccount(tokens.userId, username);

        // A different account signing in on this installation must not inherit
        // the previous account's sessions and contacts.
        final existing = _crypto ?? await CryptoService.restore(database: _db!);
        final identifiers = existing?.serverIdentifiers();
        if (existing != null && identifiers != null) {
          _crypto = existing;
          _deviceId = identifiers.deviceId;
          _deviceIndex = identifiers.deviceIndex;
          await _enterReady();
        } else {
          _setPhase(AppPhase.needsDevice);
        }
      });

  void _adoptAccount(String userId, String username) {
    _userId = userId;
    _username = username;
    // Identity only. The tokens were already written by the onTokensChanged
    // callback, which fired inside the API call above, and must not be
    // overwritten here.
    _authStore!.saveIdentity(userId: userId, username: username);
  }

  Future<void> _persistTokens(SessionTokens tokens) async {
    final store = _authStore;
    if (store == null) return;
    final existing = store.read();
    if (existing == null) {
      // Registration: the identity columns arrive a moment later, in
      // _adoptAccount. Write a placeholder row so the tokens are not lost if
      // the app dies in between.
      store.save(
        userId: _userId ?? '',
        username: _username ?? '',
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
      );
    } else {
      store.updateTokens(
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
      );
    }
  }

  // -------------------------------------------------------------------------
  // Device provisioning
  // -------------------------------------------------------------------------

  /// Generates this installation's cryptographic identity and publishes the
  /// public half.
  ///
  /// The private material is written to the encrypted database first, inside
  /// `provision`. If publication then fails the identity still exists locally,
  /// which is why `provision` refuses to run twice: generating a second
  /// identity would orphan every session built on the first.
  Future<bool> provisionDevice({String? deviceName}) => _guard(() async {
        final database = _db!;
        var service = _crypto ?? await CryptoService.restore(database: database);
        DeviceKeyMaterial material;

        if (service == null) {
          final (created, generated) =
              await CryptoService.provision(database: database);
          service = created;
          material = generated;
        } else {
          // An identity exists but was never registered, so a previous publish
          // failed. Republish the material that is already stored rather than
          // generating a second identity, which would orphan the first.
          final recovered = await service.republishableKeyMaterial();
          if (recovered == null) {
            throw const CryptoException(
              'this installation holds a cryptographic identity whose key '
              'material is incomplete, so it cannot be registered or '
              'recovered. Sign out and reinstall to generate a fresh identity.',
            );
          }
          material = recovered;
        }

        final registration = await _api.registerDevice(
          deviceName: deviceName ?? _suggestedDeviceName(),
          platform: _platformName(),
          registrationId: material.registrationId,
          publicIdentityKey: material.publicIdentityKey,
          signedPreKeyId: material.signedPreKeyId,
          signedPreKeyPublic: material.signedPreKeyPublic,
          signedPreKeySignature: material.signedPreKeySignature,
          kyberPreKeyId: material.kyberPreKeyId,
          kyberPreKeyPublic: material.kyberPreKeyPublic,
          kyberPreKeySignature: material.kyberPreKeySignature,
          oneTimePreKeys: material.oneTimePreKeys,
        );

        service.recordServerIdentifiers(
          deviceId: registration.deviceId,
          deviceIndex: registration.deviceIndex,
        );

        _crypto = service;
        _deviceId = registration.deviceId;
        _deviceIndex = registration.deviceIndex;
        await _enterReady();
      });

  String _suggestedDeviceName() {
    final host = Platform.localHostname;
    final name = host.isEmpty ? Platform.operatingSystem : host;
    return name.length <= 64 ? name : name.substring(0, 64);
  }

  String _platformName() {
    if (Platform.isWindows) return 'windows';
    if (Platform.isAndroid) return 'android';
    if (Platform.isIOS) return 'ios';
    if (Platform.isMacOS) return 'macos';
    return 'linux';
  }

  // -------------------------------------------------------------------------
  // Ready state
  // -------------------------------------------------------------------------

  Future<void> _enterReady() async {
    _setPhase(AppPhase.ready);
    _realtime.tokenProvider = _currentAccessToken;

    await _eventSubscription?.cancel();
    _eventSubscription = _realtime.events.listen(_onRealtimeEvent);
    await _stateSubscription?.cancel();
    _stateSubscription = _realtime.connectionState.listen((state) {
      _connection = state;
      notifyListeners();
    });

    await _realtime.connect();

    // Order matters on a cold start: contacts first, because a replay or a
    // drain needs to know who the peers are.
    await refreshContacts();
    await _replayUnconfirmedSends();
    await drainQueue();
    await _topUpPreKeysIfLow();
  }

  /// The realtime client asks for this before every connect attempt, so a
  /// reconnect after a long sleep does not present a stale token. Touching a
  /// cheap authenticated endpoint lets the REST layer refresh if needed.
  Future<String?> _currentAccessToken() async {
    final store = _authStore;
    if (store == null) return null;
    try {
      // Cheap, authenticated, and device-scoped — the same scope /ws needs. If
      // the access token has expired this refreshes it as a side effect.
      await _api.listDevices();
    } on ApiException catch (error) {
      if (error.isDeviceRevoked) return null;
    } on NetworkException {
      // Offline. Try the stored token anyway; the socket will fail and back off.
    } on SessionExpiredException {
      _onSessionExpired();
      return null;
    }
    return store.read()?.accessToken;
  }

  // -------------------------------------------------------------------------
  // Contacts and invitations
  // -------------------------------------------------------------------------

  Future<void> refreshContacts() async {
    try {
      _contacts = (await _api.listContacts())
          .where((c) => c.isActive)
          .toList(growable: false);
      notifyListeners();
    } on ApiException catch (error) {
      _note(error.userMessage);
    } on NetworkException {
      // Keep whatever list we had; the UI shows the offline state separately.
    } on SessionExpiredException {
      _onSessionExpired();
    }
  }

  Future<CreatedInvitation?> createInvitation() async {
    CreatedInvitation? created;
    await _guard(() async {
      created = await _api.createInvitation();
    });
    return created;
  }

  Future<List<InvitationSummary>> listInvitations() async {
    try {
      return await _api.listInvitations();
    } on ApiException catch (error) {
      _note(error.userMessage);
      return const [];
    } on NetworkException {
      return const [];
    }
  }

  Future<bool> revokeInvitation(String invitationId) => _guard(() async {
        await _api.revokeInvitation(invitationId);
      });

  /// Accepts an invitation as an existing account.
  Future<bool> acceptInvitation(String token) => _guard(() async {
        await _api.acceptInvitation(token.trim());
        await refreshContacts();
      });

  // -------------------------------------------------------------------------
  // Conversations
  // -------------------------------------------------------------------------

  List<ConversationSummary> conversations() {
    final store = _messageStore;
    final service = _crypto;
    if (store == null || service == null) return const [];

    final summaries = _contacts.map((contact) {
      final devices = contact.devices;
      final verified = devices.isNotEmpty &&
          devices.every(
            (d) =>
                service
                    .peerIdentity(
                      userId: contact.contactUserId,
                      deviceIndex: d.deviceIndex,
                    )
                    ?.isVerified ??
                false,
          );
      final warning = devices.any(
        (d) =>
            service
                .peerIdentity(
                  userId: contact.contactUserId,
                  deviceIndex: d.deviceIndex,
                )
                ?.hasUnacknowledgedChange ??
            false,
      );
      final differs = devices.any((d) {
        final known = service.peerIdentity(
          userId: contact.contactUserId,
          deviceIndex: d.deviceIndex,
        );
        if (known == null) return false;
        return _base64Of(known) != d.publicIdentityKey;
      });

      return ConversationSummary(
        contact: contact,
        lastMessage: store.latestWith(contact.contactUserId),
        unreadCount: store.unreadCountFrom(contact.contactUserId),
        isVerified: verified,
        hasIdentityWarning: warning,
        serverKeyDiffers: differs,
      );
    }).toList();

    summaries.sort((a, b) {
      final at = a.lastMessage?.createdAt;
      final bt = b.lastMessage?.createdAt;
      if (at == null && bt == null) {
        return a.contact.username.compareTo(b.contact.username);
      }
      if (at == null) return 1;
      if (bt == null) return -1;
      return bt.compareTo(at);
    });
    return summaries;
  }

  List<LocalMessage> conversation(String peerUserId) =>
      _messageStore?.conversation(peerUserId) ?? const [];

  Contact? contactById(String userId) {
    for (final contact in _contacts) {
      if (contact.contactUserId == userId) return contact;
    }
    return null;
  }

  // -------------------------------------------------------------------------
  // Sending
  // -------------------------------------------------------------------------

  /// Encrypts [body] once per recipient device, persists the envelopes, then
  /// transmits.
  ///
  /// Fails closed on a changed identity: [IdentityChangedException] propagates
  /// so the UI can demand acknowledgement rather than sending plaintext into a
  /// key the user has not accepted.
  Future<bool> sendMessage({
    required String contactUserId,
    required String body,
  }) =>
      _guard(() async {
        final text = body.trim();
        if (text.isEmpty) return;

        final contact = contactById(contactUserId);
        if (contact == null) {
          throw StateError('not a contact');
        }
        if (contact.devices.isEmpty) {
          throw const CryptoException(
            'that contact has no active devices, so there is nowhere to send',
          );
        }

        final service = _crypto!;
        final store = _messageStore!;
        final localId = _randomId();

        final prepared = <({
          String recipientDeviceId,
          String messageType,
          String ciphertext,
          int senderSequence,
        })>[];

        for (final device in contact.devices) {
          await _ensureSession(contact, device);
          final envelope = await service.encrypt(
            userId: contact.contactUserId,
            deviceIndex: device.deviceIndex,
            plaintext: text,
          );
          prepared.add((
            recipientDeviceId: device.deviceId,
            messageType: envelope.messageType,
            ciphertext: envelope.ciphertext,
            senderSequence: service.nextSenderSequence(device.deviceId),
          ));
        }

        // Durable before transmission: the ratchet has moved, so the only
        // correct retry is a replay of exactly these bytes.
        store.insertOutgoing(
          localId: localId,
          peerUserId: contactUserId,
          body: text,
          targets: prepared,
        );
        notifyListeners();

        await _transmit(
          localId,
          prepared
              .map(
                (t) => OutgoingEnvelope(
                  recipientDeviceId: t.recipientDeviceId,
                  messageType: t.messageType,
                  ciphertext: t.ciphertext,
                  senderSequence: t.senderSequence,
                ),
              )
              .toList(growable: false),
        );
      });

  Future<void> _transmit(
    String localId,
    List<OutgoingEnvelope> envelopes,
  ) async {
    final store = _messageStore!;
    try {
      final results = await _api.sendMessages(envelopes);
      for (final result in results) {
        store.recordSendResult(
          localId: localId,
          recipientDeviceId: result.recipientDeviceId,
          serverMessageId: result.messageId,
          // `duplicate` means the envelope was already stored, so the message
          // did arrive. Treating it as a failure would show the user an error
          // for a message that was delivered.
          accepted: result.isAccepted || result.isDuplicate,
        );
      }
      notifyListeners();
    } on NetworkException {
      // Unconfirmed, not failed-forever: the envelope is on disk and
      // _replayUnconfirmedSends will resend the identical bytes.
      store.markOutgoingFailed(localId);
      notifyListeners();
      rethrow;
    } on ApiException {
      store.markOutgoingFailed(localId);
      notifyListeners();
      rethrow;
    }
  }

  /// Resends envelopes the server never confirmed, replaying identical bytes.
  Future<void> _replayUnconfirmedSends() async {
    final store = _messageStore;
    if (store == null) return;

    final pending = store.unconfirmedTargets();
    if (pending.isEmpty) return;

    // Group by message so one call carries one message's fan-out.
    final byMessage = <String, List<OutgoingTarget>>{};
    for (final target in pending) {
      byMessage.putIfAbsent(target.localId, () => []).add(target);
    }

    for (final entry in byMessage.entries) {
      try {
        await _transmit(
          entry.key,
          entry.value
              .map(
                (t) => OutgoingEnvelope(
                  recipientDeviceId: t.recipientDeviceId,
                  messageType: t.messageType,
                  ciphertext: t.ciphertext,
                  senderSequence: t.senderSequence,
                ),
              )
              .toList(growable: false),
        );
      } on Object {
        // Still unreachable or still refused. It stays on disk; the next
        // reconnect tries again. Give up on this pass rather than hammering.
        return;
      }
    }
  }

  /// Fetches the peer's prekey bundle and establishes a session, if needed.
  ///
  /// The protocol address is built from the contact data this client already
  /// holds, and the bundle's own claims are cross-checked against it. A server
  /// that returned a bundle for a different user or device index would
  /// otherwise silently establish a session with the wrong address.
  Future<void> _ensureSession(Contact contact, ContactDevice device) async {
    final service = _crypto!;
    if (await service.hasSession(contact.contactUserId, device.deviceIndex)) {
      return;
    }

    final bundle = await _api.fetchPreKeyBundle(device.deviceId);

    if (bundle.userId != contact.contactUserId ||
        bundle.deviceIndex != device.deviceIndex) {
      throw const CryptoException(
        'the prekey bundle the server returned is for a different user or '
        'device than the one requested; refusing to establish a session',
      );
    }

    await service.establishSession(
      PreKeyBundleData(
        userId: contact.contactUserId,
        deviceIndex: device.deviceIndex,
        registrationId: bundle.registrationId,
        publicIdentityKey: bundle.publicIdentityKey,
        signedPreKeyId: bundle.signedPreKeyId,
        signedPreKeyPublic: bundle.signedPreKeyPublic,
        signedPreKeySignature: bundle.signedPreKeySignature,
        kyberPreKeyId: bundle.kyberPreKeyId,
        kyberPreKeyPublic: bundle.kyberPreKeyPublic,
        kyberPreKeySignature: bundle.kyberPreKeySignature,
        oneTimePreKeyId: bundle.oneTimePreKeyId,
        oneTimePreKeyPublic: bundle.oneTimePreKeyPublic,
      ),
    );
  }

  // -------------------------------------------------------------------------
  // Receiving
  // -------------------------------------------------------------------------

  /// Fetches, decrypts, stores and acknowledges queued messages.
  ///
  /// Serialised: a second concurrent drain would fetch the same envelope and
  /// its decrypt would fail, because the first drain already advanced the
  /// ratchet past it.
  Future<void> drainQueue() {
    final existing = _drainInFlight;
    if (existing != null) return existing;
    final future = _drainOnce();
    _drainInFlight = future;
    return future.whenComplete(() => _drainInFlight = null);
  }

  Future<void> _drainOnce() async {
    final store = _messageStore;
    final service = _crypto;
    if (store == null || service == null) return;

    List<IncomingEnvelope> envelopes;
    try {
      envelopes = await _api.fetchMessages();
    } on ApiException catch (error) {
      if (!error.isDeviceRevoked) _note(error.userMessage);
      return;
    } on NetworkException {
      return;
    } on SessionExpiredException {
      _onSessionExpired();
      return;
    }

    var changed = false;
    var newContactSeen = false;

    for (final envelope in envelopes) {
      if (store.hasMessage(envelope.messageId)) {
        // Already stored on an earlier pass whose acknowledgement did not
        // land. Acknowledge again — it is idempotent — and move on without
        // decrypting, which would fail anyway.
        await _acknowledgeDelivered(envelope.messageId);
        continue;
      }

      String plaintext;
      try {
        plaintext = await service.decrypt(
          userId: envelope.senderUserId,
          deviceIndex: envelope.senderDeviceIndex,
          messageType: envelope.messageType,
          ciphertext: envelope.ciphertext,
        );
      } on CryptoException catch (error) {
        // A security event, not a transient error. Record it, acknowledge
        // delivery so the queue does not wedge on it forever, and never retry:
        // the ratchet state for this message is already consumed.
        _decryptionFailures.add(
          DecryptionFailure(
            messageId: envelope.messageId,
            senderUserId: envelope.senderUserId,
            reason: error.message,
            at: DateTime.now(),
          ),
        );
        changed = true;
        await _acknowledgeDelivered(envelope.messageId);
        continue;
      }

      store.insertIncoming(
        messageId: envelope.messageId,
        peerUserId: envelope.senderUserId,
        peerDeviceIndex: envelope.senderDeviceIndex,
        body: plaintext,
        senderSequence: envelope.senderSequence,
        createdAt:
            DateTime.tryParse(envelope.createdAt)?.toLocal() ?? DateTime.now(),
      );
      changed = true;

      // Acknowledge only after the plaintext is durably stored. The other
      // order loses the message if the process dies in between.
      await _acknowledgeDelivered(envelope.messageId);

      if (contactById(envelope.senderUserId) == null) newContactSeen = true;
    }

    // A first message from a brand-new contact arrives before the contact list
    // has been refreshed, so the conversation would have no name to show.
    if (newContactSeen) await refreshContacts();

    // Decrypting consumed one-time prekeys; top the supply back up.
    await _topUpPreKeysIfLow();

    if (changed) notifyListeners();
  }

  Future<void> _acknowledgeDelivered(String messageId) async {
    try {
      await _api.acknowledgeDelivered(messageId);
    } on ApiException {
      // Idempotent and retried on the next drain.
    } on NetworkException {
      // Same.
    } on SessionExpiredException {
      _onSessionExpired();
    }
  }

  /// Marks every unread incoming message from one peer as read, locally and on
  /// the server, which notifies the sender.
  Future<void> markConversationRead(String peerUserId) async {
    final store = _messageStore;
    if (store == null) return;

    final unread = store.unreadIncomingFrom(peerUserId);
    if (unread.isEmpty) return;

    store.markIncomingRead(unread);
    notifyListeners();

    for (final messageId in unread) {
      try {
        await _api.acknowledgeRead(messageId);
      } on ApiException {
        // The local state is what the user sees; the receipt is a courtesy.
      } on NetworkException {
        break;
      } on SessionExpiredException {
        _onSessionExpired();
        return;
      }
    }
  }

  Future<void> _topUpPreKeysIfLow() async {
    final service = _crypto;
    final currentDeviceId = _deviceId;
    if (service == null || currentDeviceId == null) return;

    try {
      final devices = await _api.listDevices();
      final mine = devices.where((d) => d.deviceId == currentDeviceId);
      if (mine.isEmpty) return;
      if (mine.first.availableOneTimePreKeys > _preKeyLowWaterMark) return;

      final generated = await service.generateMoreOneTimePreKeys();
      if (generated.isEmpty) return;
      await _api.publishMoreOneTimePreKeys(
        deviceId: currentDeviceId,
        oneTimePreKeys: generated,
      );
    } on ApiException {
      // Not fatal: a drained supply degrades to signed-prekey-only X3DH rather
      // than failing, so this can wait for the next opportunity.
    } on NetworkException {
      // Same.
    } on SessionExpiredException {
      _onSessionExpired();
    }
  }

  // -------------------------------------------------------------------------
  // Verification
  // -------------------------------------------------------------------------

  /// The 60-digit safety number to compare out of band.
  ///
  /// Derived from the two identity keys. Both sides compute the same digits, so
  /// matching digits mean both ends hold the key they think they do — which is
  /// exactly what a substituting server cannot fake.
  String? safetyNumber({
    required String contactUserId,
    required int deviceIndex,
  }) {
    final service = _crypto;
    final localUserId = _userId;
    if (service == null || localUserId == null) return null;

    final keyBase64 = _comparisonKey(contactUserId, deviceIndex);
    if (keyBase64 == null) return null;

    try {
      return service.safetyNumber(
        localUserId: localUserId,
        remoteUserId: contactUserId,
        remoteIdentityKeyBase64: keyBase64,
      );
    } on Object {
      return null;
    }
  }

  /// The identity key the displayed safety number is derived from.
  ///
  /// Prefers the locally PINNED key over the server's current answer, so the
  /// digits describe what this client actually trusts. Falls back to the
  /// contact list only before anything is pinned, which is the one case where
  /// there is nothing else to show.
  ///
  /// [safetyNumber] and [setVerified] both go through here deliberately: if
  /// they resolved the key separately they could drift, and the user would
  /// verify one key while a different one was recorded.
  String? _comparisonKey(String contactUserId, int deviceIndex) {
    final service = _crypto;
    if (service == null) return null;

    final known = service.peerIdentity(
      userId: contactUserId,
      deviceIndex: deviceIndex,
    );
    if (known != null) return _base64Of(known);

    final contact = contactById(contactUserId);
    if (contact == null) return null;
    for (final candidate in contact.devices) {
      if (candidate.deviceIndex == deviceIndex) {
        return candidate.publicIdentityKey;
      }
    }
    return null;
  }

  /// True once a session exists, which is when a safety number is meaningful.
  Future<bool> hasSessionWith(String contactUserId, int deviceIndex) async =>
      await _crypto?.hasSession(contactUserId, deviceIndex) ?? false;

  PeerIdentityState? peerIdentity({
    required String contactUserId,
    required int deviceIndex,
  }) =>
      _crypto?.peerIdentity(userId: contactUserId, deviceIndex: deviceIndex);

  /// Records the user's out-of-band comparison. This is the authoritative
  /// verification state; the server's field is advisory (decisions.md D4).
  Future<void> setVerified({
    required String contactUserId,
    required int deviceIndex,
    required bool verified,
  }) async {
    final service = _crypto;
    if (service == null) return;

    if (verified) {
      final keyBase64 = _comparisonKey(contactUserId, deviceIndex);
      if (keyBase64 == null) {
        _note('There is no identity key to verify for that device yet.');
        return;
      }
      final pinned = service.verifyIdentityKey(
        userId: contactUserId,
        deviceIndex: deviceIndex,
        identityKeyBase64: keyBase64,
      );
      if (!pinned) {
        // A different key is already pinned: this is an identity change, and
        // overwriting it here would let the warning be dismissed by pressing
        // "verified" instead of acknowledging the change.
        _note(
          'That device\'s identity key has changed since it was pinned. '
          'Review the change before verifying.',
        );
        return;
      }
    } else {
      service.setVerified(
        userId: contactUserId,
        deviceIndex: deviceIndex,
        verified: false,
      );
    }
    notifyListeners();

    // Advisory hint for the account's other devices. Never read back as truth.
    try {
      await _api.setServerVerified(
        contactUserId: contactUserId,
        verified: verified,
      );
    } on ApiException {
      // The local record is what counts.
    } on NetworkException {
      // Same.
    } on SessionExpiredException {
      _onSessionExpired();
    }
  }

  /// Unblocks sending after the user has seen the identity-change warning.
  /// Does NOT mark the contact verified — that needs a fresh comparison.
  void acknowledgeIdentityChange({
    required String contactUserId,
    required int deviceIndex,
  }) {
    _crypto?.acknowledgeIdentityChange(
      userId: contactUserId,
      deviceIndex: deviceIndex,
    );
    notifyListeners();
  }

  List<PeerIdentityState> pendingIdentityWarnings() =>
      _crypto?.pendingIdentityWarnings() ?? const [];

  // -------------------------------------------------------------------------
  // Devices
  // -------------------------------------------------------------------------

  Future<List<OwnDevice>> listOwnDevices() async {
    try {
      return await _api.listDevices();
    } on ApiException catch (error) {
      _note(error.userMessage);
      return const [];
    } on NetworkException {
      return const [];
    }
  }

  /// Revokes a device. Revoking this one destroys all local state.
  Future<bool> revokeDevice(String targetDeviceId) => _guard(() async {
        await _api.revokeDevice(targetDeviceId);
        if (targetDeviceId == _deviceId) {
          await _wipeLocalState();
          _setPhase(AppPhase.revoked);
        }
      });

  // -------------------------------------------------------------------------
  // Session end
  // -------------------------------------------------------------------------

  Future<void> logout() async {
    await _api.logout();
    await _realtime.disconnect();
    // Tokens go; the cryptographic identity stays, so signing back in resumes
    // the same device rather than orphaning its sessions.
    _authStore?.clearTokens();
    _api.clearTokens();
    _contacts = const [];
    _setPhase(AppPhase.needsAuth);
  }

  void _onDeviceRevokedSignal() {
    if (_phase == AppPhase.revoked) return;
    // Called from inside an API call, so defer the teardown rather than
    // destroying state the caller is still using.
    Future.microtask(() async {
      await _wipeLocalState();
      _setPhase(AppPhase.revoked);
    });
  }

  void _onSessionExpired() {
    _api.clearTokens();
    _authStore?.clearTokens();
    _setPhase(AppPhase.needsAuth);
  }

  /// Destroys every local secret: the database contents and the OS-held key.
  Future<void> _wipeLocalState() async {
    await _realtime.disconnect();
    _api.clearTokens();
    try {
      _db?.wipe();
    } on Object {
      // Continue to the key store regardless: leaving the key behind would be
      // worse than an incomplete table wipe.
    }
    try {
      await _keyStore?.deleteAll();
    } on Object {
      // Nothing further to try.
    }
    _crypto = null;
    _contacts = const [];
    _deviceId = null;
    _deviceIndex = null;
  }

  // -------------------------------------------------------------------------
  // Realtime events
  // -------------------------------------------------------------------------

  void _onRealtimeEvent(RealtimeEvent event) {
    switch (event.type) {
      case RealtimeEventType.ready:
        // Replay first, then drain: a message we owe the peer should go out
        // before we pull theirs in.
        Future.microtask(() async {
          await _replayUnconfirmedSends();
          if (event.hasQueuedMessages) await drainQueue();
        });
      case RealtimeEventType.messageQueued:
        Future.microtask(drainQueue);
      case RealtimeEventType.messageDelivered:
        final messageId = event.messageId;
        if (messageId != null) {
          _messageStore?.applyReceipt(
            serverMessageId: messageId,
            state: MessageState.delivered,
          );
          notifyListeners();
        }
      case RealtimeEventType.messageRead:
        final messageId = event.messageId;
        if (messageId != null) {
          _messageStore?.applyReceipt(
            serverMessageId: messageId,
            state: MessageState.read,
          );
          notifyListeners();
        }
      case RealtimeEventType.deviceRevoked:
        _onDeviceRevokedSignal();
      case RealtimeEventType.unknown:
        break;
    }
  }

  // -------------------------------------------------------------------------
  // Plumbing
  // -------------------------------------------------------------------------

  /// Runs [action], turning known failures into [lastError] and returning
  /// whether it succeeded.
  ///
  /// Deliberately does not catch everything: a programming error should still
  /// crash in debug rather than become a red snackbar.
  Future<bool> _guard(Future<void> Function() action) async {
    _busy = true;
    _lastError = null;
    notifyListeners();
    try {
      await action();
      return true;
    } on ApiException catch (error) {
      _lastError = error.userMessage;
      return false;
    } on NetworkException catch (error) {
      _lastError = '${error.message}. Check that the server is reachable.';
      return false;
    } on SessionExpiredException {
      _onSessionExpired();
      _lastError = 'Your session expired. Sign in again.';
      return false;
    } on IdentityChangedException catch (error) {
      _lastError =
          'The safety number for this contact has changed. Review it before '
          'sending anything else (device ${error.deviceIndex}).';
      return false;
    } on CryptoException catch (error) {
      _lastError = error.message;
      return false;
    } on SecureStorageException catch (error) {
      _lastError = error.message;
      return false;
    } on StateError catch (error) {
      _lastError = error.message;
      return false;
    } finally {
      _busy = false;
      notifyListeners();
    }
  }

  void _note(String message) {
    _lastError = message;
    notifyListeners();
  }

  void _setPhase(AppPhase next) {
    _phase = next;
    notifyListeners();
  }

  void _fail(String message) {
    _fatalMessage = message;
    _phase = AppPhase.fatal;
    notifyListeners();
  }

  static String _base64Of(PeerIdentityState state) =>
      base64Encode(state.identityKey);

  static String _randomId() {
    final random = Random.secure();
    final bytes = List<int>.generate(16, (_) => random.nextInt(256));
    return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }

  @override
  void dispose() {
    _eventSubscription?.cancel();
    _stateSubscription?.cancel();
    _realtime.dispose();
    _api.close();
    _db?.dispose();
    super.dispose();
  }
}
