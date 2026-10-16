/// Local message history, inside the encrypted database.
///
/// This is the only place in the client that holds plaintext message bodies at
/// rest. They are protected by SQLCipher and by nothing else, which is why
/// EncryptedDatabase refuses to open a non-SQLCipher build rather than trusting
/// that `PRAGMA key` worked.
///
/// The delivery-state model is deliberately forward-only and aggregated:
///
///   * One message the user typed is one [LocalMessage] row.
///   * It fans out to one `outgoing_targets` row per recipient device.
///   * The displayed state is the WEAKEST state across its targets, so a
///     message to a two-device contact shows "delivered" only once both
///     devices have it. Showing the strongest would tell the user their
///     message had arrived when one device had never seen it.
///
/// A receipt never moves a message backwards: `read` implies delivered, and a
/// late-arriving `delivered` frame cannot undo a `read`. The server guarantees
/// the same thing on its side, so both ends agree.
library;

import 'encrypted_database.dart';

/// Delivery state, ordered weakest to strongest.
///
/// The order is the comparison used for aggregation, so it is not cosmetic.
enum MessageState {
  /// Encrypted and handed to the transport; no server acknowledgement yet.
  sending,

  /// The server stored the envelope.
  sent,

  /// The recipient device fetched it.
  delivered,

  /// The recipient opened the conversation.
  read,

  /// Send failed. Terminal until the user retries; never silently retried,
  /// because a failure here can be a refused authorisation rather than a
  /// network blip.
  failed,

  /// Incoming, decrypted and stored.
  received,

  /// Incoming, and the local user has read it.
  readLocally;

  String get wire => name;

  static MessageState fromWire(String value) => MessageState.values.firstWhere(
        (s) => s.name == value,
        orElse: () => MessageState.sending,
      );

  /// Rank for aggregation. Terminal and incoming states sit outside the
  /// outgoing progression and are never aggregated.
  int get _rank => switch (this) {
        MessageState.sending => 0,
        MessageState.sent => 1,
        MessageState.delivered => 2,
        MessageState.read => 3,
        MessageState.failed => -1,
        MessageState.received => 0,
        MessageState.readLocally => 1,
      };
}

/// One message as the UI shows it.
class LocalMessage {
  const LocalMessage({
    required this.messageId,
    required this.peerUserId,
    required this.outgoing,
    required this.body,
    required this.state,
    required this.createdAt,
  });

  final String messageId;
  final String peerUserId;
  final bool outgoing;
  final String body;
  final MessageState state;
  final DateTime createdAt;
}

/// One recipient device of an outgoing message, with the exact bytes sent.
///
/// [ciphertext] and [senderSequence] are stored rather than re-derived so that
/// a retry replays identical bytes. The server deduplicates on
/// `(senderDevice, recipientDevice, senderSequence)`, so an identical replay is
/// recognised as a duplicate and stored once; a re-encrypted one would not be.
class OutgoingTarget {
  const OutgoingTarget({
    required this.localId,
    required this.recipientDeviceId,
    required this.serverMessageId,
    required this.state,
    required this.messageType,
    required this.ciphertext,
    required this.senderSequence,
  });

  final String localId;
  final String recipientDeviceId;
  final String? serverMessageId;
  final MessageState state;
  final String messageType;
  final String ciphertext;
  final int senderSequence;

  /// Only a target that actually has stored bytes can be replayed.
  bool get isReplayable => ciphertext.isNotEmpty;
}

class MessageStore {
  const MessageStore(this._db);

  final EncryptedDatabase _db;

  // -------------------------------------------------------------------------
  // Outgoing
  // -------------------------------------------------------------------------

  /// Records a message the user just sent, with the exact envelopes produced
  /// for it, before the server has answered.
  ///
  /// Written in one transaction: a message row without its targets would be
  /// permanently stuck at "sending" with nothing to update, and a target
  /// without its ciphertext could never be retried.
  void insertOutgoing({
    required String localId,
    required String peerUserId,
    required String body,
    required List<
            ({
              String recipientDeviceId,
              String messageType,
              String ciphertext,
              int senderSequence,
            })>
        targets,
  }) {
    _db.transaction(() {
      _db.raw.execute(
        'INSERT INTO local_messages '
        '(message_id, peer_user_id, peer_device_index, outgoing, body, '
        ' sender_sequence, state, created_at) '
        'VALUES (?, ?, NULL, 1, ?, NULL, ?, ?)',
        [
          localId,
          peerUserId,
          body,
          MessageState.sending.wire,
          DateTime.now().millisecondsSinceEpoch,
        ],
      );
      for (final target in targets) {
        _db.raw.execute(
          'INSERT INTO outgoing_targets '
          '(local_id, recipient_device_id, server_message_id, state, '
          ' message_type, ciphertext, sender_sequence) '
          'VALUES (?, ?, NULL, ?, ?, ?, ?)',
          [
            localId,
            target.recipientDeviceId,
            MessageState.sending.wire,
            target.messageType,
            target.ciphertext,
            target.senderSequence,
          ],
        );
      }
    });
  }

  /// Records what the server said about one recipient device.
  ///
  /// `duplicate` counts as sent: it means the envelope was already stored, so
  /// the message did arrive and a retry simply found it there.
  void recordSendResult({
    required String localId,
    required String recipientDeviceId,
    required String? serverMessageId,
    required bool accepted,
  }) {
    _db.transaction(() {
      _db.raw.execute(
        'UPDATE outgoing_targets SET server_message_id = ?, state = ? '
        ' WHERE local_id = ? AND recipient_device_id = ?',
        [
          serverMessageId,
          accepted ? MessageState.sent.wire : MessageState.failed.wire,
          localId,
          recipientDeviceId,
        ],
      );
      _recomputeOutgoingState(localId);
    });
  }

  /// Marks the unconfirmed targets of a message failed.
  ///
  /// Only targets the server never acknowledged: a device that already has the
  /// message must not be walked backwards because a later device failed.
  void markOutgoingFailed(String localId) {
    _db.transaction(() {
      _db.raw.execute(
        'UPDATE outgoing_targets SET state = ? '
        ' WHERE local_id = ? AND server_message_id IS NULL',
        [MessageState.failed.wire, localId],
      );
      _recomputeOutgoingState(localId);
    });
  }

  /// Applies a `message.delivered` or `message.read` receipt.
  ///
  /// Keyed by the server's message id, which is the only identifier the receipt
  /// carries. Forward-only: a `delivered` arriving after a `read` is ignored.
  void applyReceipt({
    required String serverMessageId,
    required MessageState state,
  }) {
    _db.transaction(() {
      final rows = _db.raw.select(
        'SELECT local_id, state FROM outgoing_targets '
        ' WHERE server_message_id = ?',
        [serverMessageId],
      );
      if (rows.isEmpty) return;

      final localId = rows.first['local_id'] as String;
      final current = MessageState.fromWire(rows.first['state'] as String);
      if (state._rank <= current._rank) return;

      _db.raw.execute(
        'UPDATE outgoing_targets SET state = ? WHERE server_message_id = ?',
        [state.wire, serverMessageId],
      );
      _recomputeOutgoingState(localId);
    });
  }

  /// Sets the message's state to the weakest state across its targets.
  ///
  /// Caller must already hold the transaction.
  void _recomputeOutgoingState(String localId) {
    final rows = _db.raw.select(
      'SELECT state FROM outgoing_targets WHERE local_id = ?',
      [localId],
    );
    if (rows.isEmpty) return;

    final states = rows
        .map((r) => MessageState.fromWire(r['state'] as String))
        .toList(growable: false);

    // One refused recipient makes the whole message failed: reporting "sent"
    // while a device never received it would be a lie the user acts on.
    final aggregate = states.any((s) => s == MessageState.failed)
        ? MessageState.failed
        : states.reduce((a, b) => a._rank <= b._rank ? a : b);

    _db.raw.execute(
      'UPDATE local_messages SET state = ? WHERE message_id = ?',
      [aggregate.wire, localId],
    );
  }

  List<OutgoingTarget> targetsFor(String localId) => _mapTargets(
        _db.raw.select(
          'SELECT local_id, recipient_device_id, server_message_id, state, '
          '       message_type, ciphertext, sender_sequence '
          '  FROM outgoing_targets WHERE local_id = ?',
          [localId],
        ),
      );

  /// Targets that were never confirmed by the server, oldest first.
  ///
  /// These are the sends to replay on reconnect. `failed` is included because a
  /// failure here is usually a transport failure; an authorisation refusal is
  /// replayed too and simply refused again, which is correct — it must not be
  /// quietly dropped.
  List<OutgoingTarget> unconfirmedTargets({int limit = 50}) => _mapTargets(
        _db.raw.select(
          'SELECT t.local_id, t.recipient_device_id, t.server_message_id, '
          '       t.state, t.message_type, t.ciphertext, t.sender_sequence '
          '  FROM outgoing_targets t '
          '  JOIN local_messages m ON m.message_id = t.local_id '
          ' WHERE t.server_message_id IS NULL AND t.ciphertext <> \'\' '
          '   AND t.state IN (?, ?) '
          ' ORDER BY m.created_at ASC LIMIT ?',
          [MessageState.sending.wire, MessageState.failed.wire, limit],
        ),
      );

  List<OutgoingTarget> _mapTargets(Iterable<dynamic> rows) => rows
      .map(
        (r) => OutgoingTarget(
          localId: r['local_id'] as String,
          recipientDeviceId: r['recipient_device_id'] as String,
          serverMessageId: r['server_message_id'] as String?,
          state: MessageState.fromWire(r['state'] as String),
          messageType: r['message_type'] as String? ?? '',
          ciphertext: r['ciphertext'] as String? ?? '',
          senderSequence: r['sender_sequence'] as int? ?? 0,
        ),
      )
      .toList(growable: false);

  // -------------------------------------------------------------------------
  // Incoming
  // -------------------------------------------------------------------------

  /// True if this server message id was already stored.
  ///
  /// Delivery is at-least-once, so the same envelope can arrive twice. The
  /// server also rejects duplicates, but the client must not rely on that: a
  /// second decrypt of the same ciphertext would fail anyway, since the ratchet
  /// has moved on.
  bool hasMessage(String messageId) => _db.raw
      .select(
        'SELECT 1 FROM local_messages WHERE message_id = ?',
        [messageId],
      )
      .isNotEmpty;

  void insertIncoming({
    required String messageId,
    required String peerUserId,
    required int peerDeviceIndex,
    required String body,
    required int senderSequence,
    required DateTime createdAt,
  }) {
    _db.raw.execute(
      'INSERT OR IGNORE INTO local_messages '
      '(message_id, peer_user_id, peer_device_index, outgoing, body, '
      ' sender_sequence, state, created_at) '
      'VALUES (?, ?, ?, 0, ?, ?, ?, ?)',
      [
        messageId,
        peerUserId,
        peerDeviceIndex,
        body,
        senderSequence,
        MessageState.received.wire,
        createdAt.millisecondsSinceEpoch,
      ],
    );
  }

  /// Ids of unread incoming messages from one peer, for read acknowledgement.
  List<String> unreadIncomingFrom(String peerUserId) {
    final rows = _db.raw.select(
      'SELECT message_id FROM local_messages '
      ' WHERE peer_user_id = ? AND outgoing = 0 AND state = ? '
      ' ORDER BY created_at',
      [peerUserId, MessageState.received.wire],
    );
    return rows.map((r) => r['message_id'] as String).toList(growable: false);
  }

  void markIncomingRead(List<String> messageIds) {
    if (messageIds.isEmpty) return;
    _db.transaction(() {
      for (final id in messageIds) {
        _db.raw.execute(
          'UPDATE local_messages SET state = ? WHERE message_id = ? AND outgoing = 0',
          [MessageState.readLocally.wire, id],
        );
      }
    });
  }

  int unreadCountFrom(String peerUserId) {
    final rows = _db.raw.select(
      'SELECT count(*) AS n FROM local_messages '
      ' WHERE peer_user_id = ? AND outgoing = 0 AND state = ?',
      [peerUserId, MessageState.received.wire],
    );
    return rows.first['n'] as int;
  }

  // -------------------------------------------------------------------------
  // Reading
  // -------------------------------------------------------------------------

  List<LocalMessage> conversation(String peerUserId, {int limit = 500}) {
    final rows = _db.raw.select(
      'SELECT message_id, peer_user_id, outgoing, body, state, created_at '
      '  FROM local_messages WHERE peer_user_id = ? '
      ' ORDER BY created_at ASC, rowid ASC LIMIT ?',
      [peerUserId, limit],
    );
    return rows
        .map(
          (r) => LocalMessage(
            messageId: r['message_id'] as String,
            peerUserId: r['peer_user_id'] as String,
            outgoing: (r['outgoing'] as int) == 1,
            body: r['body'] as String,
            state: MessageState.fromWire(r['state'] as String),
            createdAt: DateTime.fromMillisecondsSinceEpoch(
              r['created_at'] as int,
            ),
          ),
        )
        .toList(growable: false);
  }

  /// Most recent message per peer, for the conversation list.
  LocalMessage? latestWith(String peerUserId) {
    final rows = _db.raw.select(
      'SELECT message_id, peer_user_id, outgoing, body, state, created_at '
      '  FROM local_messages WHERE peer_user_id = ? '
      ' ORDER BY created_at DESC, rowid DESC LIMIT 1',
      [peerUserId],
    );
    if (rows.isEmpty) return null;
    final r = rows.first;
    return LocalMessage(
      messageId: r['message_id'] as String,
      peerUserId: r['peer_user_id'] as String,
      outgoing: (r['outgoing'] as int) == 1,
      body: r['body'] as String,
      state: MessageState.fromWire(r['state'] as String),
      createdAt: DateTime.fromMillisecondsSinceEpoch(r['created_at'] as int),
    );
  }
}
