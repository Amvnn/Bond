/// Typed failures from the server.
///
/// The server answers every error as `{ error: { code, message, requestId } }`
/// with a deliberately uninformative message (docs/api.md). The `code` is the
/// part worth branching on; the `message` is for the log, not for the user.
///
/// Two codes are load-bearing for the client and must never be treated as
/// transient:
///
///   * `device_revoked` — this installation is finished. Wipe local state.
///   * `not_contacts` — the recipient is not a contact, or does not exist. The
///     server answers both identically on purpose, so the client must not
///     present it as "user not found".
library;

/// A structured error response from the API.
class ApiException implements Exception {
  const ApiException({
    required this.statusCode,
    required this.code,
    required this.message,
    this.requestId,
  });

  final int statusCode;
  final String code;
  final String message;
  final String? requestId;

  /// This device was revoked. Not retryable; the session is over.
  bool get isDeviceRevoked => code == 'device_revoked';

  /// The access token is absent, expired or rejected. `token_expired` is
  /// worth a refresh attempt; `token_invalid` is not.
  bool get isUnauthorized => statusCode == 401;

  bool get isTokenExpired => code == 'token_expired';

  /// A 403 `forbidden`. The most common cause in this client is holding an
  /// account-scoped token where a device-scoped one is required, i.e. the
  /// device has not been registered yet — but the server deliberately uses one
  /// code for every authorisation refusal, so this is not proof of that.
  bool get isForbidden => statusCode == 403 && code == 'forbidden';

  bool get isRateLimited => code == 'rate_limited';

  /// The recipient is not a contact, or the device does not exist. The server
  /// answers both identically, so neither the client nor the user learns which.
  bool get isNotContacts => code == 'not_contacts';

  /// Safe to show a user.
  ///
  /// The server's own messages are generic by design, so these add intent
  /// rather than detail. Nothing here reveals more than the code already does —
  /// in particular `invitation_unusable` stays deliberately ambiguous, because
  /// distinguishing "expired" from "already used" would make it a probing
  /// oracle.
  String get userMessage => switch (code) {
        'authentication_failed' => 'That username and password did not match.',
        'already_exists' => 'That username is already taken.',
        'invitation_unusable' =>
          'That invitation cannot be used. It may be unknown, expired, already '
              'used, or revoked.',
        'invalid_state' => message.isEmpty ? 'That action is not possible.' : message,
        'not_contacts' =>
          'That recipient is not one of your contacts, so nothing was sent.',
        'device_revoked' => 'This device has been revoked.',
        'rate_limited' => 'Too many attempts. Wait a little and try again.',
        'malformed_envelope' => 'The message envelope was rejected by the server.',
        'validation_failed' => 'The server rejected the request as malformed.',
        'service_unavailable' => 'The server is temporarily unavailable.',
        'forbidden' => 'This device is not authorised for that action.',
        'not_found' => 'Not found.',
        _ => message.isEmpty ? 'The server rejected the request.' : message,
      };

  @override
  String toString() => 'ApiException($statusCode $code): $message';
}

/// The server could not be reached, or the response was not usable.
///
/// Deliberately distinct from [ApiException]: a transport failure is retryable,
/// a rejected request generally is not. The brief requires network failure and
/// cryptographic failure to be handled separately, and this is the first half
/// of that separation.
class NetworkException implements Exception {
  const NetworkException(this.message, {this.cause});
  final String message;
  final Object? cause;
  @override
  String toString() => 'NetworkException: $message';
}

/// The local session cannot be restored and the user must sign in again.
class SessionExpiredException implements Exception {
  const SessionExpiredException([this.message = 'the session has expired']);
  final String message;
  @override
  String toString() => 'SessionExpiredException: $message';
}
