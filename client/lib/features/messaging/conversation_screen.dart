/// One 1-to-1 conversation.
///
/// [ConversationView] is the conversation itself and knows nothing about how
/// it got on screen: on a narrow window it is pushed as a route over the
/// contact list, and on a wide one it sits permanently in the right-hand pane.
/// [ConversationScreen] is the thin route wrapper for the first case.
///
/// The column is capped at a readable width rather than filling the pane. Left
/// and right aligned bubbles a metre apart stop reading as a conversation, and
/// a line of text that wide loses the eye on the way back to the next line.
///
/// Two things here are security surface rather than decoration:
///
///   1. **The identity-changed banner.** It is not dismissible, and while it is
///      showing the composer is disabled. The user must either acknowledge the
///      change explicitly or go and compare safety numbers. Letting them type
///      past it would hand plaintext to a key nobody has checked.
///
///   2. **Message state.** `sent` means the server stored the envelope;
///      `delivered` means the recipient's device fetched it; `read` means they
///      opened it. These are distinct and shown distinctly, because "sent" is
///      routinely mistaken for "they have it".
library;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show MaxLengthEnforcement;

import '../../core/app_scope.dart';
import '../../core/theme.dart';
import '../../services/network/api_models.dart';
import '../../services/storage/message_store.dart';
import '../security/verification_screen.dart';
import '../shell/layout.dart';

/// Route wrapper, for the narrow layout where a conversation is pushed.
class ConversationScreen extends StatelessWidget {
  const ConversationScreen({super.key, required this.contactUserId});

  final String contactUserId;

  @override
  Widget build(BuildContext context) =>
      ConversationView(contactUserId: contactUserId, showBack: true);
}

class ConversationView extends StatefulWidget {
  const ConversationView({
    super.key,
    required this.contactUserId,
    this.showBack = false,
  });

  final String contactUserId;

  /// Only the pushed route owns a back button. In the two-pane layout there is
  /// nothing to go back to — the list is already beside it.
  final bool showBack;

  @override
  State<ConversationView> createState() => _ConversationViewState();
}

class _ConversationViewState extends State<ConversationView> {
  final _composer = TextEditingController();
  final _scroll = ScrollController();

  int _knownMessageCount = 0;

  @override
  void initState() {
    super.initState();
    _onOpened();
  }

  @override
  void didUpdateWidget(ConversationView old) {
    super.didUpdateWidget(old);
    // In the two-pane layout this widget is REUSED when another contact is
    // selected, so initState does not run again. Without this the new
    // conversation would never be marked read and the composer would still
    // hold the previous draft.
    if (old.contactUserId != widget.contactUserId) {
      _composer.clear();
      _knownMessageCount = 0;
      _onOpened();
    }
  }

  void _onOpened() {
    // Marking read is what notifies the sender, so it belongs on open.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!mounted) return;
      AppScope.read(context).markConversationRead(widget.contactUserId);
      _scrollToEnd(animated: false);
    });
  }

  @override
  void dispose() {
    _composer.dispose();
    _scroll.dispose();
    super.dispose();
  }

  Future<void> _send() async {
    final text = _composer.text.trim();
    if (text.isEmpty) return;

    final controller = AppScope.read(context);
    _composer.clear();

    final ok = await controller.sendMessage(
      contactUserId: widget.contactUserId,
      body: text,
    );

    if (!ok && mounted) {
      // Put the text back so a failed send does not silently lose what the
      // user wrote.
      _composer.text = text;
      final error = controller.lastError;
      if (error != null) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(error)),
        );
      }
    }
    _scrollToEnd();
  }

  void _scrollToEnd({bool animated = true}) {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!_scroll.hasClients) return;
      final target = _scroll.position.maxScrollExtent;
      if (animated) {
        _scroll.animateTo(
          target,
          duration: const Duration(milliseconds: 280),
          curve: Curves.easeOutCubic,
        );
      } else {
        _scroll.jumpTo(target);
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    final controller = AppScope.of(context);
    final colors = context.bond;
    final text = Theme.of(context).textTheme;
    final contact = controller.contactById(widget.contactUserId);
    final messages = controller.conversation(widget.contactUserId);

    // A message arriving while the view is open should bring itself into
    // sight, the way every chat app does.
    if (messages.length != _knownMessageCount) {
      _knownMessageCount = messages.length;
      _scrollToEnd();
    }

    if (contact == null) {
      return Scaffold(
        appBar: AppBar(
          automaticallyImplyLeading: widget.showBack,
          title: const Text('Conversation'),
        ),
        body: Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: BondLayout.readable),
            child: Padding(
              padding: const EdgeInsets.all(BondSpacing.xl),
              child: Text(
                'This contact is no longer available. The friendship may have '
                'been removed, or every one of their devices revoked.',
                textAlign: TextAlign.center,
                style: text.bodyMedium?.copyWith(color: colors.labelSecondary),
              ),
            ),
          ),
        ),
      );
    }

    final blockedDevices = contact.devices
        .where(
          (d) =>
              controller
                  .peerIdentity(
                    contactUserId: contact.contactUserId,
                    deviceIndex: d.deviceIndex,
                  )
                  ?.hasUnacknowledgedChange ??
              false,
        )
        .toList(growable: false);

    final verified = contact.devices.isNotEmpty &&
        contact.devices.every(
          (d) =>
              controller
                  .peerIdentity(
                    contactUserId: contact.contactUserId,
                    deviceIndex: d.deviceIndex,
                  )
                  ?.isVerified ??
              false,
        );

    return Scaffold(
      appBar: AppBar(
        automaticallyImplyLeading: widget.showBack,
        titleSpacing: widget.showBack ? 0 : BondSpacing.lg,
        title: Row(
          children: [
            _Initial(name: contact.username, size: 34),
            const SizedBox(width: BondSpacing.md),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text(contact.username, style: text.titleMedium),
                  Row(
                    children: [
                      Icon(
                        verified ? Icons.verified_user : Icons.lock_outline,
                        size: 11,
                        color: verified ? colors.success : colors.labelTertiary,
                      ),
                      const SizedBox(width: 4),
                      Text(
                        verified
                            ? 'Verified · end-to-end encrypted'
                            : 'Not verified · end-to-end encrypted',
                        style: text.labelSmall
                            ?.copyWith(color: colors.labelTertiary),
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ],
        ),
        actions: [
          IconButton(
            icon: Icon(
              verified ? Icons.verified_user : Icons.verified_user_outlined,
              size: 21,
              color: verified ? colors.success : colors.label,
            ),
            tooltip: 'Verify safety number',
            onPressed: () => Navigator.of(context).push(
              MaterialPageRoute(
                builder: (_) =>
                    VerificationScreen(contactUserId: contact.contactUserId),
              ),
            ),
          ),
          const SizedBox(width: BondSpacing.sm),
        ],
      ),
      body: Column(
        children: [
          Divider(height: 0.5, color: colors.separator),
          if (blockedDevices.isNotEmpty)
            _IdentityChangedBanner(contact: contact, affected: blockedDevices),
          Expanded(
            child: messages.isEmpty
                ? _FirstContactNotice(verified: verified)
                : Align(
                    alignment: Alignment.topCenter,
                    child: ConstrainedBox(
                      constraints: const BoxConstraints(
                        maxWidth: BondLayout.conversation,
                      ),
                      child: ListView.builder(
                        controller: _scroll,
                        padding: const EdgeInsets.symmetric(
                          horizontal: BondSpacing.lg,
                          vertical: BondSpacing.lg,
                        ),
                        itemCount: messages.length,
                        itemBuilder: (context, index) {
                          final message = messages[index];
                          final previous =
                              index == 0 ? null : messages[index - 1];
                          // Group consecutive messages from the same side: the
                          // tighter spacing is most of what makes a thread read
                          // as a conversation rather than a list of records.
                          final grouped = previous != null &&
                              previous.outgoing == message.outgoing;
                          return _Bubble(message: message, grouped: grouped);
                        },
                      ),
                    ),
                  ),
          ),
          _Composer(
            controller: _composer,
            enabled: blockedDevices.isEmpty && !controller.busy,
            blockedReason: blockedDevices.isEmpty
                ? null
                : 'Sending is blocked until you review the changed safety '
                    'number.',
            onSend: _send,
          ),
        ],
      ),
    );
  }
}

/// A round initial. Used for contacts in place of a photo, which Phase 1 has
/// no way to exchange privately.
class _Initial extends StatelessWidget {
  const _Initial({required this.name, this.size = 46});

  final String name;
  final double size;

  @override
  Widget build(BuildContext context) {
    final colors = context.bond;
    return Container(
      width: size,
      height: size,
      decoration: BoxDecoration(
        color: colors.surfaceElevated,
        shape: BoxShape.circle,
        border: Border.all(color: colors.separator, width: 0.5),
      ),
      alignment: Alignment.center,
      child: Text(
        name.isEmpty ? '?' : name.characters.first.toUpperCase(),
        style: TextStyle(
          fontSize: size * 0.38,
          fontWeight: FontWeight.w600,
          color: colors.labelSecondary,
        ),
      ),
    );
  }
}

/// Not dismissible, by design.
///
/// The two choices offered are the two honest ones: go and compare the number,
/// or accept the new identity explicitly. There is no "ignore", because
/// ignoring is what the attack needs.
class _IdentityChangedBanner extends StatelessWidget {
  const _IdentityChangedBanner({required this.contact, required this.affected});

  final Contact contact;
  final List<ContactDevice> affected;

  @override
  Widget build(BuildContext context) {
    final colors = context.bond;
    final text = Theme.of(context).textTheme;

    return Container(
      width: double.infinity,
      color: colors.dangerSurface,
      padding: const EdgeInsets.symmetric(
        horizontal: BondSpacing.lg,
        vertical: BondSpacing.lg,
      ),
      child: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: BondLayout.conversation),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Icon(Icons.gpp_maybe, color: colors.danger, size: 19),
                  const SizedBox(width: BondSpacing.sm + 2),
                  Expanded(
                    child: Text(
                      'The safety number with ${contact.username} has changed',
                      style: text.titleSmall
                          ?.copyWith(color: colors.onDangerSurface),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: BondSpacing.sm),
              Text(
                'This happens when someone reinstalls or switches device — and '
                'it is also what an attacker substituting keys would look '
                'like. Bond cannot tell the difference, so it has stopped '
                'sending and is asking you.',
                style: text.bodySmall?.copyWith(color: colors.onDangerSurface),
              ),
              const SizedBox(height: BondSpacing.md),
              Wrap(
                spacing: BondSpacing.sm,
                runSpacing: BondSpacing.sm,
                children: [
                  FilledButton(
                    style: FilledButton.styleFrom(
                      backgroundColor: colors.danger,
                      foregroundColor: Colors.white,
                      padding: const EdgeInsets.symmetric(
                        horizontal: BondSpacing.lg,
                        vertical: 12,
                      ),
                    ),
                    onPressed: () => Navigator.of(context).push(
                      MaterialPageRoute(
                        builder: (_) => VerificationScreen(
                          contactUserId: contact.contactUserId,
                        ),
                      ),
                    ),
                    child: const Text('Compare the new number'),
                  ),
                  OutlinedButton(
                    style: OutlinedButton.styleFrom(
                      foregroundColor: colors.onDangerSurface,
                      side: BorderSide(
                        color: colors.danger.withValues(alpha: 0.4),
                        width: 0.5,
                      ),
                      padding: const EdgeInsets.symmetric(
                        horizontal: BondSpacing.lg,
                        vertical: 12,
                      ),
                    ),
                    onPressed: () => _confirmAcknowledge(context),
                    child: const Text('Accept without checking'),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }

  Future<void> _confirmAcknowledge(BuildContext context) async {
    final controller = AppScope.read(context);
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: const Text('Accept the new identity?'),
        content: const Text(
          'This unblocks sending without checking who holds the new key. If '
          'the change was not genuine, your next messages can be read by '
          'whoever substituted it.\n\n'
          'The conversation stays marked unverified either way: accepting a '
          'change is not the same as verifying it.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(false),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(true),
            child: Text(
              'Accept',
              style: TextStyle(color: dialogContext.bond.danger),
            ),
          ),
        ],
      ),
    );

    if (confirmed != true) return;
    for (final device in affected) {
      controller.acknowledgeIdentityChange(
        contactUserId: contact.contactUserId,
        deviceIndex: device.deviceIndex,
      );
    }
  }
}

class _FirstContactNotice extends StatelessWidget {
  const _FirstContactNotice({required this.verified});

  final bool verified;

  @override
  Widget build(BuildContext context) {
    final colors = context.bond;
    return Center(
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 320),
        child: Padding(
          padding: const EdgeInsets.all(BondSpacing.xl),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Container(
                padding: const EdgeInsets.all(BondSpacing.md),
                decoration: BoxDecoration(
                  color: colors.surface,
                  shape: BoxShape.circle,
                  border: Border.all(color: colors.separator, width: 0.5),
                ),
                child: Icon(
                  Icons.lock_outline,
                  size: 20,
                  color: colors.labelTertiary,
                ),
              ),
              const SizedBox(height: BondSpacing.lg),
              Text(
                verified
                    ? 'Messages here are encrypted end to end, and you have '
                        'verified this contact.'
                    : 'Messages here are encrypted end to end. You have not '
                        'verified this contact yet — compare safety numbers to '
                        'be sure who holds the other key.',
                textAlign: TextAlign.center,
                style: Theme.of(context).textTheme.bodySmall,
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _Bubble extends StatelessWidget {
  const _Bubble({required this.message, required this.grouped});

  final LocalMessage message;
  final bool grouped;

  @override
  Widget build(BuildContext context) {
    final colors = context.bond;
    final text = Theme.of(context).textTheme;
    final outgoing = message.outgoing;
    final failed = message.state == MessageState.failed;

    final background = failed
        ? colors.dangerSurface
        : outgoing
            ? colors.bubbleOutgoing
            : colors.bubbleIncoming;
    final foreground = failed
        ? colors.onDangerSurface
        : outgoing
            ? colors.onBubbleOutgoing
            : colors.onBubbleIncoming;

    // The tail corner is squared off only on the first bubble of a run, so a
    // group reads as one utterance.
    final radius = BorderRadius.only(
      topLeft: Radius.circular(
        outgoing ? BondRadius.bubble : (grouped ? 6 : BondRadius.bubble),
      ),
      topRight: Radius.circular(
        outgoing ? (grouped ? 6 : BondRadius.bubble) : BondRadius.bubble,
      ),
      bottomLeft: const Radius.circular(BondRadius.bubble),
      bottomRight: const Radius.circular(BondRadius.bubble),
    );

    return Align(
      alignment: outgoing ? Alignment.centerRight : Alignment.centerLeft,
      child: ConstrainedBox(
        // A hard cap, not a percentage. A percentage of a maximised window is
        // how you end up with a half-metre-wide bubble holding "ok".
        constraints: const BoxConstraints(maxWidth: BondLayout.bubble),
        child: Container(
          margin: EdgeInsets.only(top: grouped ? 2 : BondSpacing.sm),
          padding: const EdgeInsets.fromLTRB(14, 9, 14, 7),
          decoration: BoxDecoration(
            color: background,
            borderRadius: radius,
            border: outgoing || failed
                ? null
                : Border.all(color: colors.separator, width: 0.5),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.end,
            children: [
              Text(
                message.body,
                style:
                    text.bodyMedium?.copyWith(color: foreground, height: 1.3),
              ),
              const SizedBox(height: 3),
              Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text(
                    _time(message.createdAt),
                    style: text.labelSmall?.copyWith(
                      fontSize: 10.5,
                      color: foreground.withValues(alpha: 0.55),
                    ),
                  ),
                  if (outgoing) ...[
                    const SizedBox(width: 5),
                    Text(
                      _stateLabel(message.state),
                      style: text.labelSmall?.copyWith(
                        fontSize: 10.5,
                        color: failed
                            ? colors.danger
                            : foreground.withValues(alpha: 0.55),
                      ),
                    ),
                  ],
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }

  static String _time(DateTime at) =>
      '${at.hour.toString().padLeft(2, '0')}:'
      '${at.minute.toString().padLeft(2, '0')}';

  /// Words rather than ticks: "sent" and "delivered" mean genuinely different
  /// things here and a pair of checkmarks does not convey which.
  static String _stateLabel(MessageState state) => switch (state) {
        MessageState.sending => 'sending',
        MessageState.sent => 'sent',
        MessageState.delivered => 'delivered',
        MessageState.read => 'read',
        MessageState.failed => 'not sent',
        MessageState.received => '',
        MessageState.readLocally => '',
      };
}

class _Composer extends StatefulWidget {
  const _Composer({
    required this.controller,
    required this.enabled,
    required this.blockedReason,
    required this.onSend,
  });

  final TextEditingController controller;
  final bool enabled;
  final String? blockedReason;
  final VoidCallback onSend;

  @override
  State<_Composer> createState() => _ComposerState();
}

class _ComposerState extends State<_Composer> {
  bool _hasText = false;

  @override
  void initState() {
    super.initState();
    widget.controller.addListener(_syncHasText);
  }

  @override
  void dispose() {
    widget.controller.removeListener(_syncHasText);
    super.dispose();
  }

  void _syncHasText() {
    final has = widget.controller.text.trim().isNotEmpty;
    if (has != _hasText) setState(() => _hasText = has);
  }

  @override
  Widget build(BuildContext context) {
    final colors = context.bond;
    final text = Theme.of(context).textTheme;
    final canSend = widget.enabled && _hasText;

    return SafeArea(
      top: false,
      child: Container(
        decoration: BoxDecoration(
          color: colors.canvas,
          border: Border(top: BorderSide(color: colors.separator, width: 0.5)),
        ),
        padding: const EdgeInsets.fromLTRB(
          BondSpacing.lg,
          BondSpacing.sm,
          BondSpacing.lg,
          BondSpacing.md,
        ),
        // Tracks the message column, so the composer sits under the bubbles
        // rather than running the full width of the window beneath them.
        child: Center(
          child: ConstrainedBox(
            constraints:
                const BoxConstraints(maxWidth: BondLayout.conversation),
            child: Column(
              children: [
                if (widget.blockedReason != null)
                  Padding(
                    padding: const EdgeInsets.only(bottom: BondSpacing.sm),
                    child: Row(
                      children: [
                        Icon(Icons.block, size: 13, color: colors.danger),
                        const SizedBox(width: 6),
                        Expanded(
                          child: Text(
                            widget.blockedReason!,
                            style:
                                text.labelSmall?.copyWith(color: colors.danger),
                          ),
                        ),
                      ],
                    ),
                  ),
                Row(
                  crossAxisAlignment: CrossAxisAlignment.end,
                  children: [
                    Expanded(
                      child: Container(
                        decoration: BoxDecoration(
                          color: colors.surface,
                          borderRadius:
                              BorderRadius.circular(BondRadius.large),
                          border:
                              Border.all(color: colors.separator, width: 0.5),
                        ),
                        padding: const EdgeInsets.symmetric(
                          horizontal: BondSpacing.lg,
                          vertical: 2,
                        ),
                        child: TextField(
                          controller: widget.controller,
                          enabled: widget.enabled,
                          minLines: 1,
                          maxLines: 6,
                          // The server bounds a ciphertext at 64 KiB; this
                          // keeps a single message far inside that without the
                          // user ever meeting the limit.
                          maxLength: 4000,
                          maxLengthEnforcement: MaxLengthEnforcement.enforced,
                          textInputAction: TextInputAction.send,
                          onSubmitted: widget.enabled
                              ? (_) => widget.onSend()
                              : null,
                          style: text.bodyLarge,
                          decoration: InputDecoration(
                            hintText: widget.enabled
                                ? 'Message'
                                : 'Sending is blocked',
                            counterText: '',
                            border: InputBorder.none,
                            enabledBorder: InputBorder.none,
                            focusedBorder: InputBorder.none,
                            disabledBorder: InputBorder.none,
                            filled: false,
                            isDense: true,
                            contentPadding:
                                const EdgeInsets.symmetric(vertical: 11),
                          ),
                        ),
                      ),
                    ),
                    const SizedBox(width: BondSpacing.sm),
                    // Scales in rather than appearing: a button that pops into
                    // existence under the cursor is the kind of jump this pass
                    // is meant to remove.
                    AnimatedScale(
                      scale: canSend ? 1 : 0.86,
                      duration: const Duration(milliseconds: 160),
                      curve: Curves.easeOutBack,
                      child: AnimatedOpacity(
                        opacity: canSend ? 1 : 0.35,
                        duration: const Duration(milliseconds: 160),
                        child: SizedBox(
                          width: 42,
                          height: 42,
                          child: Material(
                            color: colors.accent,
                            shape: const CircleBorder(),
                            child: InkWell(
                              customBorder: const CircleBorder(),
                              onTap: canSend ? widget.onSend : null,
                              child: Icon(
                                Icons.arrow_upward_rounded,
                                size: 20,
                                color: colors.onAccent,
                              ),
                            ),
                          ),
                        ),
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
