/// Windows secure key store backed by DPAPI.
///
/// DPAPI (`CryptProtectData` / `CryptUnprotectData`) is an operating system
/// service, not cryptography we are inventing: the OS derives the protection
/// key from the logged-in user's credentials and keeps it out of our process.
/// We call two documented Win32 functions and store the resulting blob.
///
/// Why this rather than a package: `flutter_secure_storage` is the better
/// long-term choice and covers all five platforms, but it requires the C++ ATL
/// libraries, which need an elevated Visual Studio Installer run. This keeps
/// the MVP moving with no admin action. See docs/decisions.md D10.
///
/// Scope and limits, stated plainly:
///
///   * Protection is tied to the **Windows user account**. Anything running as
///     that user can unprotect these blobs. It protects against another user on
///     the machine and against an offline disk copy, NOT against malware
///     running as the user — which is the endpoint-compromise case no design
///     here defends (threat T16).
///   * `CRYPTPROTECT_UI_FORBIDDEN` is set, so the OS never shows a prompt; a
///     call that would need one fails instead of hanging a background task.
///   * An app-specific entropy value is mixed in, so a blob written by another
///     application cannot be substituted for one of ours.
library;

import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:path/path.dart' as p;

import 'secure_key_store.dart';

// ---------------------------------------------------------------------------
// Win32 bindings
// ---------------------------------------------------------------------------

/// Win32 `DATA_BLOB`.
final class _DataBlob extends Struct {
  @Uint32()
  external int cbData;

  external Pointer<Uint8> pbData;
}

typedef _CryptProtectDataNative = Int32 Function(
  Pointer<_DataBlob> pDataIn,
  Pointer<Utf16> szDataDescr,
  Pointer<_DataBlob> pOptionalEntropy,
  Pointer<Void> pvReserved,
  Pointer<Void> pPromptStruct,
  Uint32 dwFlags,
  Pointer<_DataBlob> pDataOut,
);
typedef _CryptProtectDataDart = int Function(
  Pointer<_DataBlob> pDataIn,
  Pointer<Utf16> szDataDescr,
  Pointer<_DataBlob> pOptionalEntropy,
  Pointer<Void> pvReserved,
  Pointer<Void> pPromptStruct,
  int dwFlags,
  Pointer<_DataBlob> pDataOut,
);

typedef _LocalFreeNative = Pointer<Void> Function(Pointer<Void> hMem);
typedef _LocalFreeDart = Pointer<Void> Function(Pointer<Void> hMem);

typedef _GetLastErrorNative = Uint32 Function();
typedef _GetLastErrorDart = int Function();

/// Never prompt the user. A prompt in a background operation would hang it.
const int _cryptprotectUiForbidden = 0x1;

/// Mixed into every blob so one application's protected data cannot be
/// substituted for another's. Not a secret — it is a domain separator.
const String _entropyTag = 'dev.privateconv.private_messenger.v1';

/// Filenames must be predictable and contained; anything else is rejected
/// rather than sanitised, so a key name can never escape the directory.
final RegExp _keyPattern = RegExp(r'^[a-z0-9_.-]{1,64}$');

class DpapiSecureKeyStore implements SecureKeyStore {
  DpapiSecureKeyStore._(this._directory, this._crypt32, this._kernel32) {
    _protect = _crypt32.lookupFunction<_CryptProtectDataNative, _CryptProtectDataDart>(
      'CryptProtectData',
    );
    _unprotect = _crypt32.lookupFunction<_CryptProtectDataNative, _CryptProtectDataDart>(
      'CryptUnprotectData',
    );
    _localFree = _kernel32.lookupFunction<_LocalFreeNative, _LocalFreeDart>('LocalFree');
    _getLastError =
        _kernel32.lookupFunction<_GetLastErrorNative, _GetLastErrorDart>('GetLastError');
  }

  /// [directory] holds the protected blobs. It is created if absent.
  factory DpapiSecureKeyStore(String directory) {
    if (!Platform.isWindows) {
      throw const SecureStorageException('DpapiSecureKeyStore requires Windows');
    }
    final dir = Directory(directory);
    if (!dir.existsSync()) dir.createSync(recursive: true);
    return DpapiSecureKeyStore._(
      dir,
      DynamicLibrary.open('Crypt32.dll'),
      DynamicLibrary.open('Kernel32.dll'),
    );
  }

  final Directory _directory;
  final DynamicLibrary _crypt32;
  final DynamicLibrary _kernel32;

  late final _CryptProtectDataDart _protect;
  late final _CryptProtectDataDart _unprotect;
  late final _LocalFreeDart _localFree;
  late final _GetLastErrorDart _getLastError;

  @override
  String get backendDescription => 'Windows DPAPI (per-user), blobs in ${_directory.path}';

  File _fileFor(String key) {
    if (!_keyPattern.hasMatch(key)) {
      throw SecureStorageException('invalid secure-storage key: "$key"');
    }
    return File(p.join(_directory.path, '$key.dpapi'));
  }

  @override
  Future<void> write(String key, Uint8List value) async {
    final file = _fileFor(key);
    final protected = _callDpapi(value, protect: true);
    // Write to a temporary file and rename, so a crash mid-write cannot leave a
    // truncated blob that would be indistinguishable from corruption.
    final temp = File('${file.path}.tmp');
    await temp.writeAsBytes(protected, flush: true);
    await temp.rename(file.path);
  }

  @override
  Future<Uint8List?> read(String key) async {
    final file = _fileFor(key);
    if (!await file.exists()) return null;
    final protected = await file.readAsBytes();
    return _callDpapi(protected, protect: false);
  }

  @override
  Future<void> delete(String key) async {
    final file = _fileFor(key);
    if (await file.exists()) await file.delete();
  }

  @override
  Future<void> deleteAll() async {
    if (!await _directory.exists()) return;
    await for (final entity in _directory.list()) {
      if (entity is File && entity.path.endsWith('.dpapi')) {
        await entity.delete();
      }
    }
  }

  /// Single path through the FFI boundary, so allocation and freeing are in one
  /// place rather than duplicated per direction.
  Uint8List _callDpapi(Uint8List input, {required bool protect}) {
    final arena = Arena();
    try {
      final inBlob = arena<_DataBlob>();
      final inBytes = arena<Uint8>(input.length);
      inBytes.asTypedList(input.length).setAll(0, input);
      inBlob.ref
        ..cbData = input.length
        ..pbData = inBytes;

      final entropyBytes = Uint8List.fromList(_entropyTag.codeUnits);
      final entropyBlob = arena<_DataBlob>();
      final entropyPtr = arena<Uint8>(entropyBytes.length);
      entropyPtr.asTypedList(entropyBytes.length).setAll(0, entropyBytes);
      entropyBlob.ref
        ..cbData = entropyBytes.length
        ..pbData = entropyPtr;

      final outBlob = arena<_DataBlob>();

      final result = (protect ? _protect : _unprotect)(
        inBlob,
        nullptr,
        entropyBlob,
        nullptr,
        nullptr,
        _cryptprotectUiForbidden,
        outBlob,
      );

      if (result == 0) {
        final code = _getLastError();
        throw SecureStorageException(
          protect ? 'CryptProtectData failed' : 'CryptUnprotectData failed',
          osErrorCode: code,
        );
      }

      // Copy out before freeing: the pointer belongs to the OS allocator.
      final output = Uint8List.fromList(
        outBlob.ref.pbData.asTypedList(outBlob.ref.cbData),
      );
      _localFree(outBlob.ref.pbData.cast<Void>());
      return output;
    } finally {
      arena.releaseAll();
    }
  }
}
