/// In-memory secure key store for tests.
///
/// Used so the crypto tests do not depend on a platform keychain. The real
/// DPAPI implementation has its own test.
library;

import 'dart:typed_data';

import 'package:bond/services/storage/secure_key_store.dart';

class FakeSecureKeyStore implements SecureKeyStore {
  FakeSecureKeyStore([Map<String, Uint8List>? seed])
      : _values = {...?seed};

  final Map<String, Uint8List> _values;

  @override
  String get backendDescription => 'in-memory (tests only)';

  @override
  Future<void> write(String key, Uint8List value) async => _values[key] = value;

  @override
  Future<Uint8List?> read(String key) async => _values[key];

  @override
  Future<void> delete(String key) async => _values.remove(key);

  @override
  Future<void> deleteAll() async => _values.clear();

  /// Test helper: replace a stored value, to simulate a key/database mismatch.
  void overwrite(String key, Uint8List value) => _values[key] = value;
}
