/// WebSocket client for delivery notifications.
///
/// WHAT THE SOCKET IS, AND IS NOT
///
/// It carries notifications only: "something arrived", "your message was
/// delivered", "this device was revoked". It never carries message bodies.
/// That is a server design choice with two consequences the client must honour:
///
///   1. On `message.queued` the client fetches over HTTPS. There is exactly one
///      authorisation path for content, not two.
///   2. A duplicate or stale socket cannot corrupt delivery. Both sockets get
///      notified, both fetch, and acknowledgement is idempotent. So this class
///      does not need to guarantee a single connection, only to reconnect.
///
/// `dart:io`'s WebSocket is used rather than a package because the token must
/// travel in the `Authorization` header: a token in a query string lands in
/// access logs. This is also why there is no web support here, which is fine —
/// a web client is out of scope and blocked upstream anyway.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

/// A frame from the server, already classified.
enum RealtimeEventType {
  /// Connected. [RealtimeEvent.hasQueuedMessages] says whether to drain now.
  ready,

  /// Something arrived for this device. Fetch it over HTTPS.
  messageQueued,

  /// A receipt for a message this device sent.
  messageDelivered,
  messageRead,

  /// This device was revoked. The socket closes immediately after.
  deviceRevoked,

  /// An unrecognised frame. Ignored rather than interpreted, so a future
  /// server frame cannot be mistaken for a command.
  unknown,
}

class RealtimeEvent {
  const RealtimeEvent({
    required this.type,
    this.messageId,
    this.hasQueuedMessages = false,
  });

  final RealtimeEventType type;
  final String? messageId;
  final bool hasQueuedMessages;
}

enum ConnectionState { disconnected, connecting, connected }

/// Maintains one authenticated socket, reconnecting with backoff.
class RealtimeClient {
  RealtimeClient({required this.baseUri});

  /// The REST origin. `http` is mapped to `ws`, `https` to `wss`.
  final Uri baseUri;

  static const Duration _pingInterval = Duration(seconds: 25);
  static const Duration _connectTimeout = Duration(seconds: 15);
  static const Duration _baseBackoff = Duration(seconds: 1);
  static const Duration _maxBackoff = Duration(seconds: 30);

  final StreamController<RealtimeEvent> _events =
      StreamController<RealtimeEvent>.broadcast();
  final StreamController<ConnectionState> _states =
      StreamController<ConnectionState>.broadcast();

  Stream<RealtimeEvent> get events => _events.stream;
  Stream<ConnectionState> get connectionState => _states.stream;

  ConnectionState _state = ConnectionState.disconnected;
  ConnectionState get state => _state;

  WebSocket? _socket;
  StreamSubscription<dynamic>? _subscription;
  Timer? _pingTimer;
  Timer? _reconnectTimer;
  int _attempt = 0;

  /// Set when the device is revoked. Reconnecting would be pointless and would
  /// hammer a server that is correctly refusing us.
  bool _stopped = false;

  String? _accessToken;

  /// Called with a fresh token before each connect attempt, so a reconnect
  /// after a long offline period does not present an expired token.
  Future<String?> Function()? tokenProvider;

  bool get isConnected => _state == ConnectionState.connected;

  /// Opens the socket and keeps it open until [disconnect].
  Future<void> connect() async {
    _stopped = false;
    _attempt = 0;
    await _openOnce();
  }

  Future<void> disconnect() async {
    _stopped = true;
    _reconnectTimer?.cancel();
    _reconnectTimer = null;
    await _teardown();
    _setState(ConnectionState.disconnected);
  }

  Future<void> dispose() async {
    await disconnect();
    await _events.close();
    await _states.close();
  }

  Future<void> _openOnce() async {
    if (_stopped) return;
    _setState(ConnectionState.connecting);

    final token = await tokenProvider?.call() ?? _accessToken;
    if (token == null) {
      _setState(ConnectionState.disconnected);
      return;
    }
    _accessToken = token;

    final wsUri = baseUri.replace(
      scheme: baseUri.scheme == 'https' ? 'wss' : 'ws',
      path: '/ws',
    );

    try {
      final socket = await WebSocket.connect(
        wsUri.toString(),
        headers: <String, dynamic>{'authorization': 'Bearer $token'},
      ).timeout(_connectTimeout);

      _socket = socket;
      _attempt = 0;
      _setState(ConnectionState.connected);

      _subscription = socket.listen(
        _onFrame,
        onDone: _onClosed,
        onError: (Object _) => _onClosed(),
        cancelOnError: true,
      );

      _pingTimer?.cancel();
      _pingTimer = Timer.periodic(_pingInterval, (_) => _sendPing());
    } on Object {
      // Any failure to connect — refused, DNS, timeout, 401 on the upgrade —
      // is treated the same: back off and try again. A 401 resolves itself
      // once the REST layer refreshes the token, since tokenProvider is
      // consulted on every attempt.
      _socket = null;
      _setState(ConnectionState.disconnected);
      _scheduleReconnect();
    }
  }

  void _sendPing() {
    final socket = _socket;
    if (socket == null) return;
    try {
      socket.add(jsonEncode(<String, dynamic>{'type': 'ping'}));
    } on Object {
      _onClosed();
    }
  }

  void _onFrame(dynamic raw) {
    if (raw is! String) return;

    Map<String, dynamic> frame;
    try {
      final decoded = jsonDecode(raw);
      if (decoded is! Map<String, dynamic>) return;
      frame = decoded;
    } on FormatException {
      return;
    }

    switch (frame['type']) {
      case 'ready':
        _events.add(
          RealtimeEvent(
            type: RealtimeEventType.ready,
            hasQueuedMessages: frame['hasQueuedMessages'] as bool? ?? false,
          ),
        );
      case 'message.queued':
        _events.add(
          const RealtimeEvent(type: RealtimeEventType.messageQueued),
        );
      case 'message.delivered':
        _events.add(
          RealtimeEvent(
            type: RealtimeEventType.messageDelivered,
            messageId: frame['messageId'] as String?,
          ),
        );
      case 'message.read':
        _events.add(
          RealtimeEvent(
            type: RealtimeEventType.messageRead,
            messageId: frame['messageId'] as String?,
          ),
        );
      case 'device.revoked':
        // Stop before the server closes the socket, so the reconnect loop does
        // not fight a refusal it cannot win.
        _stopped = true;
        _events.add(
          const RealtimeEvent(type: RealtimeEventType.deviceRevoked),
        );
      case 'pong':
        break;
      default:
        _events.add(const RealtimeEvent(type: RealtimeEventType.unknown));
    }
  }

  void _onClosed() {
    _pingTimer?.cancel();
    _pingTimer = null;
    _socket = null;
    _subscription = null;
    _setState(ConnectionState.disconnected);
    _scheduleReconnect();
  }

  void _scheduleReconnect() {
    if (_stopped) return;
    _reconnectTimer?.cancel();

    // Exponential with full jitter. Jitter matters: without it, every client
    // that dropped on a server restart comes back in the same instant.
    final exponent = min(_attempt, 5);
    final ceiling = min(
      _baseBackoff.inMilliseconds * (1 << exponent),
      _maxBackoff.inMilliseconds,
    );
    final delay = Duration(
      milliseconds: _baseBackoff.inMilliseconds +
          Random().nextInt(max(1, ceiling - _baseBackoff.inMilliseconds + 1)),
    );
    _attempt++;

    _reconnectTimer = Timer(delay, _openOnce);
  }

  Future<void> _teardown() async {
    _pingTimer?.cancel();
    _pingTimer = null;
    final subscription = _subscription;
    _subscription = null;
    await subscription?.cancel();
    final socket = _socket;
    _socket = null;
    try {
      await socket?.close();
    } on Object {
      // Closing a socket that is already gone is not a failure.
    }
  }

  void _setState(ConnectionState next) {
    if (_state == next) return;
    _state = next;
    if (!_states.isClosed) _states.add(next);
  }
}
