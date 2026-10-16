/// Tests for the real Windows DPAPI key store.
///
/// This exercises the actual `CryptProtectData` / `CryptUnprotectData` FFI
/// path, not a stand-in. It is the store that protects the encrypted database
/// key, so the whole local-storage security model rests on it behaving the way
/// the rest of the code assumes.
///
/// What is checked, and why each one matters:
///
///   * A round trip works, and the blob ON DISK does not contain the secret.
///     If it did, DPAPI would not be protecting anything.
///   * The value survives a NEW store instance over the same directory. The
///     database key must outlive a process restart or every restart loses the
///     local data.
///   * Absence and failure are distinguishable. `read` returning null for a
///     missing key, and throwing on a damaged one, is what lets
///     EncryptedDatabase tell "first run" apart from "something is wrong" —
///     conflating them would generate a fresh key and orphan the database.
///   * A key name cannot escape the directory. The name reaches a file path, so
///     traversal is rejected rather than sanitised.
///
/// These tests are Windows-only, which is honest rather than limiting: DPAPI is
/// a Windows service and the class refuses to construct anywhere else.
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:bond/services/storage/dpapi_secure_key_store.dart';
import 'package:bond/services/storage/encrypted_database.dart';
import 'package:bond/services/storage/secure_key_store.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:path/path.dart' as p;

void main() {
  late Directory tempDir;

  setUp(() {
    tempDir = Directory.systemTemp.createTempSync('bond-dpapi-test');
  });

  tearDown(() {
    try {
      tempDir.deleteSync(recursive: true);
    } on FileSystemException {
      // Windows can hold a handle briefly; not a test failure.
    }
  });

  String dir(String name) => p.join(tempDir.path, name);

  group(
    'DPAPI secure key store',
    () {
      test('round-trips a value, and the on-disk blob does not contain it',
          () async {
        final store = DpapiSecureKeyStore(dir('round-trip'));
        final secret = Uint8List.fromList(
          List<int>.generate(32, (i) => (i * 7 + 13) & 0xff),
        );

        await store.write('local_db_key', secret);
        final read = await store.read('local_db_key');

        expect(read, isNotNull);
        expect(read, equals(secret));

        // The protection has to be real: the plaintext key must not appear in
        // the file DPAPI produced.
        final blobFile = File(p.join(dir('round-trip'), 'local_db_key.dpapi'));
        expect(blobFile.existsSync(), isTrue);
        final blob = blobFile.readAsBytesSync();
        expect(
          _containsSequence(blob, secret),
          isFalse,
          reason: 'the protected blob contains the raw secret, so DPAPI is '
              'not actually protecting it',
        );
        expect(blob.length, greaterThan(secret.length));
      });

      test('a value written by one instance is readable by a new one',
          () async {
        final directory = dir('persistence');
        final secret = EncryptedDatabase.generateDatabaseKey();

        await DpapiSecureKeyStore(directory).write('local_db_key', secret);

        // A separate instance, as a later process would construct.
        final reopened = DpapiSecureKeyStore(directory);
        expect(await reopened.read('local_db_key'), equals(secret));
      });

      test('a missing key reads as null rather than throwing', () async {
        final store = DpapiSecureKeyStore(dir('missing'));
        expect(await store.read('local_db_key'), isNull);
      });

      test('a damaged blob throws instead of reading as absent', () async {
        final directory = dir('damaged');
        final store = DpapiSecureKeyStore(directory);
        await store.write('local_db_key', EncryptedDatabase.generateDatabaseKey());

        // Corrupt the protected blob. DPAPI is authenticated, so this must be
        // detected rather than silently producing different bytes.
        final blobFile = File(p.join(directory, 'local_db_key.dpapi'));
        final blob = blobFile.readAsBytesSync();
        blob[blob.length ~/ 2] ^= 0xff;
        blobFile.writeAsBytesSync(blob);

        // The distinction that matters: NOT null. A null would read as "first
        // run" and generate a new key, orphaning the existing database.
        await expectLater(
          store.read('local_db_key'),
          throwsA(isA<SecureStorageException>()),
        );
      });

      test('delete removes one key, deleteAll removes every blob', () async {
        final store = DpapiSecureKeyStore(dir('deletion'));
        await store.write('local_db_key', Uint8List.fromList([1, 2, 3]));
        await store.write('other_key', Uint8List.fromList([4, 5, 6]));

        await store.delete('local_db_key');
        expect(await store.read('local_db_key'), isNull);
        expect(await store.read('other_key'), isNotNull);

        await store.deleteAll();
        expect(await store.read('other_key'), isNull);
        expect(
          Directory(dir('deletion'))
              .listSync()
              .whereType<File>()
              .where((f) => f.path.endsWith('.dpapi'))
              .isEmpty,
          isTrue,
        );
      });

      test('rejects key names that could escape the directory', () async {
        final store = DpapiSecureKeyStore(dir('traversal'));
        for (final bad in const [
          '../escape',
          'sub/dir',
          r'sub\dir',
          'UPPERCASE',
          '',
          'has space',
        ]) {
          await expectLater(
            store.read(bad),
            throwsA(isA<SecureStorageException>()),
            reason: 'key name "$bad" should be rejected',
          );
        }
      });

      test('the database key survives a reopen through this store', () async {
        final directory = dir('end-to-end');
        final dbPath = p.join(tempDir.path, 'through-dpapi.db');

        // First run: the store generates and protects the key.
        final first = await EncryptedDatabase.open(
          path: dbPath,
          keyStore: DpapiSecureKeyStore(directory),
        );
        first.raw.execute(
          'INSERT INTO meta (key, value) VALUES (?, ?)',
          ['probe', 'survives'],
        );
        first.dispose();

        // Second run: a fresh store instance must unprotect the same key, or
        // the database cannot be opened at all.
        final second = await EncryptedDatabase.open(
          path: dbPath,
          keyStore: DpapiSecureKeyStore(directory),
        );
        addTearDown(second.dispose);

        final rows =
            second.raw.select('SELECT value FROM meta WHERE key = ?', ['probe']);
        expect(rows.single['value'], 'survives');
      });
    },
    skip: Platform.isWindows
        ? null
        : 'DPAPI is a Windows service; this store refuses to construct elsewhere',
  );
}

/// True if [haystack] contains [needle] as a contiguous run.
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
