/// REST client for the Bond relay.
///
/// Responsibilities, and deliberately nothing else:
///
///   * Attach the current access token, and refresh it once on a 401.
///   * Turn `{ error: { code, message, requestId } }` into [ApiException], and
///     a transport failure into [NetworkException]. The brief requires network
///     failure and cryptographic failure to be handled separately; keeping all
///     crypto out of this file is how that separation is kept.
///   * Parse responses into the models in api_models.dart.
///
/// What this class must never do: interpret a ciphertext, hold a private key,
/// decide whether a contact is verified, or log a token.
///
/// TLS: in production [baseUri] is https and certificate verification is left
/// at its default. Nothing here disables it, and nothing should. For local
/// development the base is plain http against 127.0.0.1, which never leaves the
/// machine.
library;

import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;

import 'api_exception.dart';
import 'api_models.dart';

/// Tokens as the client currently holds them.
class SessionTokens {
  const SessionTokens({required this.accessToken, required this.refreshToken});

  final String accessToken;
  final String refreshToken;

  @override
  String toString() => 'SessionTokens(<redacted>)';
}

/// Called whenever the tokens change, so the caller can persist them.
///
/// Refresh rotates the refresh token, and the server revokes the whole session
/// family if an already-consumed one is presented. So persisting the new pair
/// is not an optimisation: dropping it means the next refresh replays a spent
/// token and logs the user out of every session.
typedef TokensChanged = Future<void> Function(SessionTokens tokens);

/// Called when the server reports this device revoked.
typedef DeviceRevoked = void Function();

class ApiClient {
  ApiClient({
    required this.baseUri,
    http.Client? httpClient,
    this.onTokensChanged,
    this.onDeviceRevoked,
  }) : _http = httpClient ?? http.Client();

  /// Origin only, e.g. `http://127.0.0.1:3000`. Paths are appended.
  final Uri baseUri;

  final http.Client _http;
  final TokensChanged? onTokensChanged;
  final DeviceRevoked? onDeviceRevoked;

  static const Duration _timeout = Duration(seconds: 20);

  String? _accessToken;
  String? _refreshToken;

  /// Guards against a refresh storm: several requests racing a 401 would each
  /// rotate the refresh token, and every rotation after the first presents a
  /// spent token, which the server treats as theft and revokes the family.
  /// So one refresh runs and the rest await it.
  Future<void>? _refreshInFlight;

  bool get hasSession => _accessToken != null;

  /// Adopts tokens restored from local storage or just issued.
  void adoptTokens(SessionTokens tokens) {
    _accessToken = tokens.accessToken;
    _refreshToken = tokens.refreshToken;
  }

  void clearTokens() {
    _accessToken = null;
    _refreshToken = null;
  }

  void close() => _http.close();

  // -------------------------------------------------------------------------
  // Auth
  // -------------------------------------------------------------------------

  /// `invitationToken` is omitted only on the env-gated bootstrap path, which
  /// can create user #1 and nobody else.
  Future<AuthTokens> register({
    required String username,
    required String password,
    String? invitationToken,
  }) async {
    final json = await _send(
      'POST',
      '/auth/register',
      body: <String, dynamic>{
        'username': username,
        'password': password,
        if (invitationToken != null && invitationToken.isNotEmpty)
          'invitationToken': invitationToken,
      },
      authenticated: false,
    );
    return _adoptAndReturn(AuthTokens.fromJson(json as Map<String, dynamic>));
  }

  Future<AuthTokens> login({
    required String username,
    required String password,
  }) async {
    final json = await _send(
      'POST',
      '/auth/login',
      body: <String, dynamic>{'username': username, 'password': password},
      authenticated: false,
    );
    return _adoptAndReturn(AuthTokens.fromJson(json as Map<String, dynamic>));
  }

  /// Server-side revocation. Answers 204 whether or not the token existed, so
  /// there is nothing to branch on.
  Future<void> logout() async {
    final refresh = _refreshToken;
    if (refresh == null) return;
    try {
      await _send(
        'POST',
        '/auth/logout',
        body: <String, dynamic>{'refreshToken': refresh},
        authenticated: false,
      );
    } on ApiException {
      // Logout is best-effort from the client's point of view: local state is
      // wiped regardless, and a failure here must not block that.
    } on NetworkException {
      // Same.
    }
    clearTokens();
  }

  // -------------------------------------------------------------------------
  // Devices
  // -------------------------------------------------------------------------

  /// Publishes PUBLIC key material only.
  ///
  /// Every field here comes from `DeviceKeyMaterial`, which CryptoService built
  /// from private material it kept. If a private key could reach this call, the
  /// bug is in CryptoService, not here.
  Future<DeviceRegistration> registerDevice({
    required String deviceName,
    required String platform,
    required int registrationId,
    required String publicIdentityKey,
    required int signedPreKeyId,
    required String signedPreKeyPublic,
    required String signedPreKeySignature,
    required int kyberPreKeyId,
    required String kyberPreKeyPublic,
    required String kyberPreKeySignature,
    required List<({int id, String publicKey})> oneTimePreKeys,
  }) async {
    final json = await _send(
      'POST',
      '/devices/register',
      body: <String, dynamic>{
        'deviceName': deviceName,
        'platform': platform,
        'registrationId': registrationId,
        'publicIdentityKey': publicIdentityKey,
        'signedPreKey': <String, dynamic>{
          'id': signedPreKeyId,
          'publicKey': signedPreKeyPublic,
          'signature': signedPreKeySignature,
        },
        'kyberPreKey': <String, dynamic>{
          'id': kyberPreKeyId,
          'publicKey': kyberPreKeyPublic,
          'signature': kyberPreKeySignature,
          'isLastResort': true,
        },
        'oneTimePreKeys': oneTimePreKeys
            .map((k) => <String, dynamic>{'id': k.id, 'publicKey': k.publicKey})
            .toList(growable: false),
      },
    );

    final registration =
        DeviceRegistration.fromJson(json as Map<String, dynamic>);

    // The returned token is device-scoped and supersedes the account-scoped
    // one. Messaging and /ws reject the account-scoped token.
    _accessToken = registration.accessToken;
    final refresh = _refreshToken;
    if (refresh != null) {
      await onTokensChanged?.call(
        SessionTokens(
          accessToken: registration.accessToken,
          refreshToken: refresh,
        ),
      );
    }
    return registration;
  }

  Future<List<OwnDevice>> listDevices() async {
    final json = await _send('GET', '/devices');
    return (json as List<dynamic>)
        .map((d) => OwnDevice.fromJson(d as Map<String, dynamic>))
        .toList(growable: false);
  }

  Future<void> revokeDevice(String deviceId) =>
      _send('POST', '/devices/$deviceId/revoke', expectEmpty: true);

  /// Tops up the one-time prekey supply. Re-sending an existing id is a no-op
  /// server-side, so this is safe to retry.
  Future<int> publishMoreOneTimePreKeys({
    required String deviceId,
    required List<({int id, String publicKey})> oneTimePreKeys,
  }) async {
    final json = await _send(
      'POST',
      '/devices/$deviceId/key-material',
      body: <String, dynamic>{
        'oneTimePreKeys': oneTimePreKeys
            .map((k) => <String, dynamic>{'id': k.id, 'publicKey': k.publicKey})
            .toList(growable: false),
      },
    );
    return (json as Map<String, dynamic>)['availableOneTimePreKeys'] as int;
  }

  /// The most security-sensitive route in the system: where a malicious server
  /// would substitute a key.
  ///
  /// The client's defence is not here — it is that libsignal verifies the
  /// signed-prekey signature against the identity key in the bundle, and that
  /// the user compares safety numbers out of band. This method only transports.
  Future<PreKeyBundleResponse> fetchPreKeyBundle(String deviceId) async {
    final json = await _send('GET', '/devices/$deviceId/public-keys');
    return PreKeyBundleResponse.fromJson(json as Map<String, dynamic>);
  }

  // -------------------------------------------------------------------------
  // Invitations
  // -------------------------------------------------------------------------

  Future<CreatedInvitation> createInvitation({
    String purpose = 'register_and_befriend',
  }) async {
    final json = await _send(
      'POST',
      '/invitations',
      body: <String, dynamic>{'purpose': purpose},
    );
    return CreatedInvitation.fromJson(json as Map<String, dynamic>);
  }

  Future<List<InvitationSummary>> listInvitations() async {
    final json = await _send('GET', '/invitations');
    return (json as List<dynamic>)
        .map((i) => InvitationSummary.fromJson(i as Map<String, dynamic>))
        .toList(growable: false);
  }

  /// For an account that already exists. A new user accepts implicitly by
  /// registering with the token instead.
  ///
  /// The token travels in the body, never the path: a credential in a URL lands
  /// in access and proxy logs (docs/decisions.md D9).
  Future<String> acceptInvitation(String token) async {
    final json = await _send(
      'POST',
      '/invitations/accept',
      body: <String, dynamic>{'token': token},
    );
    return (json as Map<String, dynamic>)['contactUserId'] as String;
  }

  Future<void> revokeInvitation(String invitationId) =>
      _send('POST', '/invitations/$invitationId/revoke', expectEmpty: true);

  // -------------------------------------------------------------------------
  // Contacts
  // -------------------------------------------------------------------------

  Future<List<Contact>> listContacts() async {
    final json = await _send('GET', '/contacts');
    return (json as List<dynamic>)
        .map((c) => Contact.fromJson(c as Map<String, dynamic>))
        .toList(growable: false);
  }

  /// Records verification server-side as ADVISORY metadata.
  ///
  /// The authoritative decision is stored locally by CryptoService. This call
  /// exists so other devices of the same account can see the hint later; it
  /// must never be what the UI reads to show a verified badge.
  Future<void> setServerVerified({
    required String contactUserId,
    required bool verified,
  }) =>
      _send(
        'POST',
        '/contacts/$contactUserId/verify',
        body: <String, dynamic>{'verified': verified},
      );

  // -------------------------------------------------------------------------
  // Messages
  // -------------------------------------------------------------------------

  /// One envelope per recipient device, 1-20 per call.
  Future<List<SendResult>> sendMessages(
    List<OutgoingEnvelope> envelopes,
  ) async {
    final json = await _send(
      'POST',
      '/messages',
      body: <String, dynamic>{
        'envelopes': envelopes.map((e) => e.toJson()).toList(growable: false),
      },
    );
    final results = (json as Map<String, dynamic>)['results'] as List<dynamic>;
    return results
        .map((r) => SendResult.fromJson(r as Map<String, dynamic>))
        .toList(growable: false);
  }

  /// Drains this device's queue. Scoped to the calling device by the token.
  Future<List<IncomingEnvelope>> fetchMessages({int limit = 50}) async {
    final json = await _send('GET', '/messages?limit=$limit');
    return (json as List<dynamic>)
        .map((m) => IncomingEnvelope.fromJson(m as Map<String, dynamic>))
        .toList(growable: false);
  }

  /// Idempotent and forward-only server-side; safe to call again after a retry.
  Future<void> acknowledgeDelivered(String messageId) =>
      _send('POST', '/messages/$messageId/delivered');

  Future<void> acknowledgeRead(String messageId) =>
      _send('POST', '/messages/$messageId/read');

  // -------------------------------------------------------------------------
  // Health
  // -------------------------------------------------------------------------

  Future<bool> isServerHealthy() async {
    try {
      await _send('GET', '/health', authenticated: false);
      return true;
    } on ApiException {
      return false;
    } on NetworkException {
      return false;
    }
  }

  // -------------------------------------------------------------------------
  // Transport
  // -------------------------------------------------------------------------

  Future<AuthTokens> _adoptAndReturn(AuthTokens tokens) async {
    _accessToken = tokens.accessToken;
    _refreshToken = tokens.refreshToken;
    await onTokensChanged?.call(
      SessionTokens(
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
      ),
    );
    return tokens;
  }

  Future<Object?> _send(
    String method,
    String path, {
    Map<String, dynamic>? body,
    bool authenticated = true,
    bool expectEmpty = false,
  }) async {
    try {
      final response = await _dispatch(method, path, body, authenticated);

      // One refresh attempt, then give up. Retrying a refresh that failed is
      // how a client talks itself into a revoked session family.
      if (response.statusCode == 401 && authenticated && _refreshToken != null) {
        final error = _decodeError(response);
        if (!error.isDeviceRevoked) {
          await _refreshOnce();
          final retried = await _dispatch(method, path, body, authenticated);
          return _interpret(retried, expectEmpty: expectEmpty);
        }
      }

      return _interpret(response, expectEmpty: expectEmpty);
    } on http.ClientException catch (error) {
      throw NetworkException('could not reach the server', cause: error);
    } on TimeoutException catch (error) {
      throw NetworkException('the server did not respond in time', cause: error);
    }
  }

  Future<http.Response> _dispatch(
    String method,
    String path,
    Map<String, dynamic>? body,
    bool authenticated,
  ) {
    final uri = baseUri.resolve(path);
    final headers = <String, String>{
      'accept': 'application/json',
      if (body != null) 'content-type': 'application/json',
      if (authenticated && _accessToken != null)
        'authorization': 'Bearer $_accessToken',
    };
    final encoded = body == null ? null : jsonEncode(body);

    final request = switch (method) {
      'GET' => _http.get(uri, headers: headers),
      'POST' => _http.post(uri, headers: headers, body: encoded),
      _ => throw ArgumentError.value(method, 'method', 'unsupported'),
    };
    return request.timeout(_timeout);
  }

  Future<void> _refreshOnce() {
    // Collapse concurrent refreshes into one.
    final existing = _refreshInFlight;
    if (existing != null) return existing;

    final future = _performRefresh();
    _refreshInFlight = future;
    return future.whenComplete(() => _refreshInFlight = null);
  }

  Future<void> _performRefresh() async {
    final refresh = _refreshToken;
    if (refresh == null) throw const SessionExpiredException();

    final response = await _dispatch(
      'POST',
      '/auth/refresh',
      <String, dynamic>{'refreshToken': refresh},
      false,
    );

    if (response.statusCode != 200) {
      final error = _decodeError(response);
      clearTokens();
      if (error.isDeviceRevoked) {
        onDeviceRevoked?.call();
        throw error;
      }
      // The server returns 401 without saying why, including when rotation
      // detected reuse and revoked the family. Either way the user signs in
      // again.
      throw const SessionExpiredException();
    }

    final decoded = jsonDecode(response.body) as Map<String, dynamic>;
    await _adoptAndReturn(AuthTokens.fromJson(decoded));
  }

  Object? _interpret(http.Response response, {required bool expectEmpty}) {
    final status = response.statusCode;

    if (status >= 200 && status < 300) {
      if (expectEmpty || status == 204 || response.body.isEmpty) return null;
      try {
        return jsonDecode(response.body);
      } on FormatException catch (error) {
        throw NetworkException(
          'the server returned a body that was not JSON',
          cause: error,
        );
      }
    }

    final error = _decodeError(response);
    if (error.isDeviceRevoked) onDeviceRevoked?.call();
    throw error;
  }

  /// Decodes the documented error envelope, tolerating a body that is not one.
  ///
  /// A proxy or a crash can produce an HTML error page; turning that into a
  /// FormatException would hide the status code that actually matters.
  ApiException _decodeError(http.Response response) {
    try {
      final decoded = jsonDecode(response.body);
      if (decoded is Map<String, dynamic>) {
        final error = decoded['error'];
        if (error is Map<String, dynamic>) {
          return ApiException(
            statusCode: response.statusCode,
            code: error['code'] as String? ?? 'unknown',
            message: error['message'] as String? ?? '',
            requestId: error['requestId'] as String?,
          );
        }
      }
    } on FormatException {
      // Fall through to the generic shape below.
    }
    return ApiException(
      statusCode: response.statusCode,
      code: 'unknown',
      message: 'unexpected response (${response.statusCode})',
    );
  }
}
