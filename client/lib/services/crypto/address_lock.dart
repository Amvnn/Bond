/// Per-address serialisation for ratchet operations.
///
/// THE FAILURE MODE THIS EXISTS TO PREVENT
///
/// `encrypt` loads the session record, advances the Double Ratchet, and stores
/// it back. That whole cycle is the critical section. Two overlapping calls for
/// the same remote address both start from the same record and derive the SAME
/// message key and IV — with no crash, no exception and no visible symptom.
/// Reusing a message key in a stream cipher is catastrophic: an attacker with
/// both ciphertexts recovers the XOR of the plaintexts.
///
/// A lock *inside* the store does not help, because the store sees three
/// separate calls (load, ratchet, store) and cannot know they belong together.
/// The lock has to wrap the entire libsignal call, which is what
/// [AddressLock.synchronized] is for.
///
/// The map is keyed per address rather than global so conversations do not
/// block each other, and lives on the store-owning service rather than on a
/// short-lived cipher object — otherwise two ciphers would hold two maps and
/// neither would serialise against the other.
library;

import 'dart:async';

class AddressLock {
  /// Tail of the queue per key. Completes when the last queued action finishes.
  final Map<String, Future<void>> _tails = <String, Future<void>>{};

  /// Runs [action] after any previously queued action for [key] has finished.
  ///
  /// Failures do not poison the queue: the next waiter runs regardless of
  /// whether the previous action threw.
  Future<T> synchronized<T>(String key, Future<T> Function() action) {
    final previous = _tails[key];
    final completer = Completer<void>();

    // Install this call as the new tail before awaiting anything, so a
    // concurrent caller queues behind it rather than racing it.
    _tails[key] = completer.future;

    Future<T> run() async {
      try {
        return await action();
      } finally {
        // Release the queue slot, and drop the entry entirely if nobody else
        // queued behind us, so the map does not grow without bound.
        completer.complete();
        if (_tails[key] == completer.future) {
          _tails.remove(key);
        }
      }
    }

    if (previous == null) return run();
    // Ignore the predecessor's error; it belongs to its own caller.
    return previous.then((_) => run(), onError: (_) => run());
  }

  /// True when nothing is queued. Test helper.
  bool get isIdle => _tails.isEmpty;

  /// Number of addresses with queued work. Test helper.
  int get pendingAddresses => _tails.length;
}
