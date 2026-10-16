/// Wire models for the REST API.
///
/// These mirror docs/api.md exactly. They are deliberately dumb: parsing and
/// nothing else, no behaviour, no defaults that would paper over a missing
/// required field. A response that does not match the documented shape throws
/// here rather than producing a half-built object that fails somewhere less
/// obvious.
///
/// Note what is absent: no model carries a message body, a preview, or any
/// private key material. `ciphertext` is an opaque base64 string that only
/// CryptoService ever interprets.
library;

/// Account session returned by register, login and refresh.
class AuthTokens {
  const AuthTokens({
    required this.userId,
    required this.accessToken,
    required this.refreshToken,
    required this.accessTokenExpiresIn,
    required this.refreshTokenExpiresAt,
  });

  factory AuthTokens.fromJson(Map<String, dynamic> json) => AuthTokens(
        userId: json['userId'] as String,
        accessToken: json['accessToken'] as String,
        refreshToken: json['refreshToken'] as String,
        accessTokenExpiresIn: json['accessTokenExpiresIn'] as String? ?? '',
        refreshTokenExpiresAt: json['refreshTokenExpiresAt'] as String? ?? '',
      );

  final String userId;
  final String accessToken;
  final String refreshToken;

  /// A duration SPEC as the server configured it, such as `15m` — not a number
  /// of seconds. Carried for display and diagnostics only.
  ///
  /// The client deliberately does not schedule a refresh from it. Expiry is
  /// handled reactively, by refreshing once on a 401: a timer would drift
  /// against the server's clock, and would still have to handle the 401 for
  /// the case where a session was revoked early.
  final String accessTokenExpiresIn;

  final String refreshTokenExpiresAt;

  /// Never let a token reach a log line or an error message.
  @override
  String toString() => 'AuthTokens(userId: $userId, tokens: <redacted>)';
}

/// Result of publishing this installation's public key material.
class DeviceRegistration {
  const DeviceRegistration({
    required this.deviceId,
    required this.deviceIndex,
    required this.accessToken,
  });

  factory DeviceRegistration.fromJson(Map<String, dynamic> json) =>
      DeviceRegistration(
        deviceId: json['deviceId'] as String,
        deviceIndex: json['deviceIndex'] as int,
        accessToken: json['accessToken'] as String,
      );

  final String deviceId;

  /// The libsignal protocol address device id, 1-127.
  final int deviceIndex;

  /// Device-scoped, and replaces the account-scoped token that made this call.
  final String accessToken;

  @override
  String toString() =>
      'DeviceRegistration(deviceId: $deviceId, deviceIndex: $deviceIndex, '
      'accessToken: <redacted>)';
}

/// One of the caller's own devices.
class OwnDevice {
  const OwnDevice({
    required this.deviceId,
    required this.deviceIndex,
    required this.deviceName,
    required this.platform,
    required this.publicIdentityKey,
    required this.registrationId,
    required this.createdAt,
    required this.lastSeenAt,
    required this.revokedAt,
    required this.availableOneTimePreKeys,
  });

  factory OwnDevice.fromJson(Map<String, dynamic> json) => OwnDevice(
        deviceId: json['deviceId'] as String,
        deviceIndex: json['deviceIndex'] as int,
        deviceName: json['deviceName'] as String,
        platform: json['platform'] as String,
        publicIdentityKey: json['publicIdentityKey'] as String,
        registrationId: json['registrationId'] as int,
        createdAt: json['createdAt'] as String,
        lastSeenAt: json['lastSeenAt'] as String?,
        revokedAt: json['revokedAt'] as String?,
        availableOneTimePreKeys: json['availableOneTimePreKeys'] as int? ?? 0,
      );

  final String deviceId;
  final int deviceIndex;
  final String deviceName;
  final String platform;
  final String publicIdentityKey;
  final int registrationId;
  final String createdAt;
  final String? lastSeenAt;
  final String? revokedAt;
  final int availableOneTimePreKeys;

  bool get isRevoked => revokedAt != null;
}

/// A contact's active device, as listed by `GET /contacts`.
///
/// `publicIdentityKey` is what the safety number is derived from, and what the
/// client compares to notice a change. It is NOT authority that the key belongs
/// to the person: only an out-of-band comparison establishes that.
class ContactDevice {
  const ContactDevice({
    required this.deviceId,
    required this.deviceIndex,
    required this.publicIdentityKey,
    required this.registrationId,
    required this.deviceName,
    required this.platform,
  });

  factory ContactDevice.fromJson(Map<String, dynamic> json) => ContactDevice(
        deviceId: json['deviceId'] as String,
        deviceIndex: json['deviceIndex'] as int,
        publicIdentityKey: json['publicIdentityKey'] as String,
        registrationId: json['registrationId'] as int? ?? 0,
        deviceName: json['deviceName'] as String? ?? '',
        platform: json['platform'] as String? ?? '',
      );

  final String deviceId;
  final int deviceIndex;
  final String publicIdentityKey;
  final int registrationId;
  final String deviceName;
  final String platform;
}

class Contact {
  const Contact({
    required this.contactUserId,
    required this.username,
    required this.status,
    required this.serverVerifiedAt,
    required this.createdAt,
    required this.devices,
  });

  factory Contact.fromJson(Map<String, dynamic> json) => Contact(
        contactUserId: json['contactUserId'] as String,
        username: json['username'] as String? ?? '(unknown)',
        status: json['status'] as String,
        serverVerifiedAt: json['verifiedAt'] as String?,
        createdAt: json['createdAt'] as String? ?? '',
        devices: ((json['devices'] as List<dynamic>?) ?? const <dynamic>[])
            .map((d) => ContactDevice.fromJson(d as Map<String, dynamic>))
            .toList(growable: false),
      );

  final String contactUserId;
  final String username;
  final String status;

  /// ADVISORY ONLY. Never render "verified" from this field: a compromised
  /// server could set it for a key it substituted. The authoritative state is
  /// local, in `peer_identities.verified_at` (docs/decisions.md D4).
  final String? serverVerifiedAt;

  final String createdAt;
  final List<ContactDevice> devices;

  bool get isActive => status == 'accepted' || status == 'active';
}

/// A peer's prekey bundle.
///
/// Fetching one consumes a one-time prekey server-side, so this is never
/// fetched speculatively: only when a session actually needs establishing.
class PreKeyBundleResponse {
  const PreKeyBundleResponse({
    required this.deviceId,
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

  factory PreKeyBundleResponse.fromJson(Map<String, dynamic> json) {
    final signed = json['signedPreKey'] as Map<String, dynamic>;
    final kyber = json['kyberPreKey'] as Map<String, dynamic>;
    final oneTime = json['oneTimePreKey'] as Map<String, dynamic>?;
    return PreKeyBundleResponse(
      deviceId: json['deviceId'] as String,
      userId: json['userId'] as String,
      deviceIndex: json['deviceIndex'] as int,
      registrationId: json['registrationId'] as int,
      publicIdentityKey: json['publicIdentityKey'] as String,
      signedPreKeyId: signed['id'] as int,
      signedPreKeyPublic: signed['publicKey'] as String,
      signedPreKeySignature: signed['signature'] as String,
      kyberPreKeyId: kyber['id'] as int,
      kyberPreKeyPublic: kyber['publicKey'] as String,
      kyberPreKeySignature: kyber['signature'] as String,
      oneTimePreKeyId: oneTime == null ? null : oneTime['id'] as int,
      oneTimePreKeyPublic:
          oneTime == null ? null : oneTime['publicKey'] as String,
    );
  }

  final String deviceId;
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

  /// Null when the peer's one-time supply is exhausted. The bundle is still
  /// usable then (signed-prekey-only X3DH); it never fails open and never
  /// recycles a spent key.
  final int? oneTimePreKeyId;
  final String? oneTimePreKeyPublic;

  bool get usedOneTimePreKey => oneTimePreKeyId != null;
}

/// An invitation the user created. `token` is present only at creation.
class CreatedInvitation {
  const CreatedInvitation({
    required this.invitationId,
    required this.token,
    required this.expiresAt,
    required this.purpose,
  });

  factory CreatedInvitation.fromJson(Map<String, dynamic> json) =>
      CreatedInvitation(
        invitationId: json['invitationId'] as String,
        token: json['token'] as String,
        expiresAt: json['expiresAt'] as String,
        purpose: json['purpose'] as String,
      );

  final String invitationId;

  /// Returned exactly once by the server and never retrievable again, because
  /// only its HMAC is stored. It is a credential: show it, let the user copy
  /// it, and never log or persist it.
  final String token;

  final String expiresAt;
  final String purpose;

  @override
  String toString() =>
      'CreatedInvitation(invitationId: $invitationId, token: <redacted>)';
}

class InvitationSummary {
  const InvitationSummary({
    required this.invitationId,
    required this.purpose,
    required this.createdAt,
    required this.expiresAt,
    required this.usedAt,
    required this.revokedAt,
    required this.status,
  });

  factory InvitationSummary.fromJson(Map<String, dynamic> json) =>
      InvitationSummary(
        invitationId: json['invitationId'] as String,
        purpose: json['purpose'] as String,
        createdAt: json['createdAt'] as String,
        expiresAt: json['expiresAt'] as String,
        usedAt: json['usedAt'] as String?,
        revokedAt: json['revokedAt'] as String?,
        status: json['status'] as String,
      );

  final String invitationId;
  final String purpose;
  final String createdAt;
  final String expiresAt;
  final String? usedAt;
  final String? revokedAt;
  final String status;

  bool get isPending => status == 'pending';
}

/// One envelope to send. Produced by CryptoService and passed straight through.
class OutgoingEnvelope {
  const OutgoingEnvelope({
    required this.recipientDeviceId,
    required this.messageType,
    required this.ciphertext,
    required this.senderSequence,
  });

  final String recipientDeviceId;
  final String messageType;
  final String ciphertext;
  final int senderSequence;

  Map<String, dynamic> toJson() => <String, dynamic>{
        'recipientDeviceId': recipientDeviceId,
        'envelopeVersion': 1,
        'messageType': messageType,
        'ciphertext': ciphertext,
        'senderSequence': senderSequence,
      };
}

/// Per-recipient outcome of `POST /messages`.
///
/// `duplicate` is a success, not an error: it means this exact
/// (sender, recipient, sequence) was already stored, so retrying after an
/// ambiguous network failure is harmless rather than duplicating a message.
class SendResult {
  const SendResult({
    required this.recipientDeviceId,
    required this.status,
    required this.messageId,
  });

  factory SendResult.fromJson(Map<String, dynamic> json) => SendResult(
        recipientDeviceId: json['recipientDeviceId'] as String,
        status: json['status'] as String,
        messageId: json['messageId'] as String?,
      );

  final String recipientDeviceId;
  final String status;
  final String? messageId;

  bool get isAccepted => status == 'accepted';
  bool get isDuplicate => status == 'duplicate';
}

/// A queued envelope for this device. The body is still encrypted here.
class IncomingEnvelope {
  const IncomingEnvelope({
    required this.messageId,
    required this.senderUserId,
    required this.senderDeviceId,
    required this.senderDeviceIndex,
    required this.messageType,
    required this.ciphertext,
    required this.senderSequence,
    required this.createdAt,
  });

  factory IncomingEnvelope.fromJson(Map<String, dynamic> json) =>
      IncomingEnvelope(
        messageId: json['messageId'] as String,
        senderUserId: json['senderUserId'] as String,
        senderDeviceId: json['senderDeviceId'] as String,
        senderDeviceIndex: json['senderDeviceIndex'] as int,
        messageType: json['messageType'] as String,
        ciphertext: json['ciphertext'] as String,
        senderSequence: json['senderSequence'] as int? ?? 0,
        createdAt: json['createdAt'] as String,
      );

  final String messageId;
  final String senderUserId;
  final String senderDeviceId;

  /// The sender's libsignal protocol address device id, needed to pick the
  /// session to decrypt with.
  final int senderDeviceIndex;

  final String messageType;

  /// Opaque. Only CryptoService ever interprets this.
  final String ciphertext;

  final int senderSequence;
  final String createdAt;

  @override
  String toString() => 'IncomingEnvelope(messageId: $messageId, '
      'from: $senderUserId:$senderDeviceIndex, '
      'ciphertext: <${ciphertext.length} chars, opaque>)';
}
