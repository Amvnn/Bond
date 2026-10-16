/// Platform-backed storage for secrets that must never touch ordinary files.
///
/// What belongs here: the encrypted database key, and nothing else that can be
/// avoided. Private identity keys live inside the encrypted database, whose key
/// lives here — one secret protected by the OS, everything else protected by
/// that secret.
///
/// What must NEVER go here or anywhere else in plaintext: see
/// `docs/secure_storage` rules in the project brief — no SharedPreferences, no
/// plain SQLite, no unencrypted JSON, no logs, no crash reports.
///
/// Implementations are platform-specific on purpose. If a platform cannot offer
/// an OS-backed secret store, the correct behaviour is to FAIL rather than
/// silently fall back to a plain file. See [UnavailableSecureKeyStore].
library;

import 'dart:typed_data';

/// Thrown when secure storage is unavailable or refuses an operation.
///
/// Callers must treat this as fatal for any flow involving key material. The
/// fallback is never "store it unprotected".
class SecureStorageException implements Exception {
  const SecureStorageException(this.message, {this.osErrorCode});

  final String message;
  final int? osErrorCode;

  @override
  String toString() => osErrorCode == null
      ? 'SecureStorageException: $message'
      : 'SecureStorageException: $message (os error $osErrorCode)';
}

abstract interface class SecureKeyStore {
  /// Human-readable name of the backing mechanism, for the security info screen.
  String get backendDescription;

  Future<void> write(String key, Uint8List value);

  /// Returns null when the key is absent. Throws on a storage failure, which
  /// must not be confused with absence.
  Future<Uint8List?> read(String key);

  Future<void> delete(String key);

  /// Used on logout, to destroy local key material.
  Future<void> deleteAll();
}

/// Placeholder for platforms with no implementation yet.
///
/// Every method throws. This exists so that adding a platform target cannot
/// accidentally degrade to insecure storage — the app refuses to operate
/// instead, which is the documented fallback behaviour.
class UnavailableSecureKeyStore implements SecureKeyStore {
  const UnavailableSecureKeyStore(this.platformName);

  final String platformName;

  @override
  String get backendDescription => 'unavailable on $platformName';

  Never _fail() => throw SecureStorageException(
        'no secure key store is implemented for $platformName; '
        'refusing to store key material unprotected',
      );

  @override
  Future<void> write(String key, Uint8List value) async => _fail();

  @override
  Future<Uint8List?> read(String key) async => _fail();

  @override
  Future<void> delete(String key) async => _fail();

  @override
  Future<void> deleteAll() async => _fail();
}
