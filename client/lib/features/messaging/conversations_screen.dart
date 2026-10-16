/// The home screen: contacts, their security state, and the way in to a chat.
///
/// Adaptive by width, because a desktop window and a phone want genuinely
/// different things rather than the same thing at two scales:
///
///   * **Wide** — the contact list sits in a fixed left pane beside the open
///     conversation. Switching contacts does not cover anything up, and the
///     list stays a navigation surface instead of becoming a screen you have
///     to leave.
///   * **Narrow** — the list is the screen and a conversation is pushed over
///     it, which is the only thing that fits.
///
/// The row layout is the one people already know — avatar, name, last message,
/// time, unread count — because there is nothing to gain from being novel
/// here, and a familiar list is one less thing between the user and the part
/// that is genuinely unusual.
///
/// What IS unusual stays visible rather than tucked away: every row carries
/// its security state, because an unverified conversation is the normal case
/// at first contact and the user needs to know which ones they have actually
/// checked. Three distinct states, deliberately not collapsed into one badge:
///
///   * **Verified** — safety numbers were compared out of band, locally.
///   * **Not verified** — nothing is wrong, nothing has been checked either.
///   * **Identity changed** — the contact's key is not the one we knew.
///     Sending is blocked until acknowledged. This one is loud on purpose.
library;

import 'package:flutter/material.dart';

import '../../core/app_controller.dart';
import '../../core/app_scope.dart';
import '../../core/theme.dart';
import '../../services/storage/message_store.dart';
import '../devices/devices_screen.dart';
import '../invitations/invite_screen.dart';
import '../security/security_info_screen.dart';
import '../shell/brand.dart';
import '../shell/layout.dart';
import 'conversation_screen.dart';

class ConversationsScreen extends StatefulWidget {
  const ConversationsScreen({super.key});

  @override
  State<ConversationsScreen> createState() => _ConversationsScreenState();
}

class _ConversationsScreenState extends State<ConversationsScreen> {
  /// Only meaningful in the two-pane layout; the narrow one pushes a route.
  String? _selected;

  @override
  Widget build(BuildContext context) {
    final controller = AppScope.of(context);
    final colors = context.bond;
    final conversations = controller.conversations();

    if (!usesTwoPanes(context)) {
      return _ListPane(
        conversations: conversations,
        selected: null,
        onSelect: (id) => Navigator.of(context).push(
          MaterialPageRoute(
            builder: (_) => ConversationScreen(contactUserId: id),
          ),
        ),
      );
    }

    // A contact can disappear — unfriended, or every device revoked — and a
    // stale selection would leave the right pane showing a dead conversation.
    final selected = conversations.any((c) => c.contact.contactUserId == _selected)
        ? _selected
        : null;

    return Scaffold(
      body: Row(
        children: [
          SizedBox(
            width: BondLayout.listPane,
            child: _ListPane(
              conversations: conversations,
              selected: selected,
              onSelect: (id) => setState(() => _selected = id),
            ),
          ),
          VerticalDivider(width: 0.5, thickness: 0.5, color: colors.separator),
          Expanded(
            child: selected == null
                ? const _NothingSelected()
                : ConversationView(
                    // Keyed so switching contacts rebuilds the composer and
                    // scroll position rather than carrying them across.
                    key: ValueKey(selected),
                    contactUserId: selected,
                  ),
          ),
        ],
      ),
    );
  }
}

class _ListPane extends StatelessWidget {
  const _ListPane({
    required this.conversations,
    required this.selected,
    required this.onSelect,
  });

  final List<ConversationSummary> conversations;
  final String? selected;
  final ValueChanged<String> onSelect;

  @override
  Widget build(BuildContext context) {
    final controller = AppScope.of(context);
    final colors = context.bond;
    final compact = selected != null || usesTwoPanes(context);

    return Scaffold(
      appBar: AppBar(
        titleSpacing: BondSpacing.lg,
        // The mark alone is allowed here: the window is titled Bond and the
        // name is already established by this point (brand/README.md).
        title: Row(
          children: [
            const BondMark(size: 24),
            const SizedBox(width: BondSpacing.md),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text('Chats', style: Theme.of(context).textTheme.titleLarge),
                  if (controller.username != null)
                    Text(
                      controller.profile == 'default'
                          ? controller.username!
                          : '${controller.username!} · ${controller.profile}',
                      overflow: TextOverflow.ellipsis,
                      style: Theme.of(context)
                          .textTheme
                          .labelSmall
                          ?.copyWith(color: colors.labelTertiary),
                    ),
                ],
              ),
            ),
          ],
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.person_add_alt_1_outlined, size: 20),
            tooltip: 'Invite or accept',
            color: colors.label,
            onPressed: () => Navigator.of(context).push(
              MaterialPageRoute(builder: (_) => const InviteScreen()),
            ),
          ),
          PopupMenuButton<String>(
            icon: Icon(Icons.more_horiz, color: colors.label, size: 21),
            position: PopupMenuPosition.under,
            color: colors.surfaceElevated,
            elevation: 0,
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(BondRadius.medium),
              side: BorderSide(color: colors.separator, width: 0.5),
            ),
            onSelected: (value) async {
              switch (value) {
                case 'devices':
                  await Navigator.of(context).push(
                    MaterialPageRoute(builder: (_) => const DevicesScreen()),
                  );
                case 'security':
                  await Navigator.of(context).push(
                    MaterialPageRoute(
                      builder: (_) => const SecurityInfoScreen(),
                    ),
                  );
                case 'refresh':
                  await controller.refreshContacts();
                  await controller.drainQueue();
                case 'signout':
                  await controller.logout();
              }
            },
            itemBuilder: (_) => const [
              PopupMenuItem(value: 'devices', child: Text('Devices')),
              PopupMenuItem(value: 'security', child: Text('Security')),
              PopupMenuItem(value: 'refresh', child: Text('Refresh')),
              PopupMenuItem(value: 'signout', child: Text('Sign out')),
            ],
          ),
          const SizedBox(width: BondSpacing.sm),
        ],
        bottom: _ConnectionBar(controller: controller),
      ),
      body: Column(
        children: [
          Divider(height: 0.5, color: colors.separator),
          Expanded(
            child: RefreshIndicator(
              onRefresh: () async {
                await controller.refreshContacts();
                await controller.drainQueue();
              },
              color: colors.label,
              backgroundColor: colors.surface,
              child: conversations.isEmpty
                  ? const _EmptyState()
                  : ListView.separated(
                      padding: const EdgeInsets.only(bottom: BondSpacing.xl),
                      itemCount: conversations.length,
                      separatorBuilder: (_, _) => Padding(
                        // Inset to clear the avatar, the way a native list does.
                        padding: const EdgeInsets.only(left: 70),
                        child: Divider(height: 0.5, color: colors.separator),
                      ),
                      itemBuilder: (context, index) {
                        final summary = conversations[index];
                        return _ConversationTile(
                          summary: summary,
                          dense: compact,
                          selected:
                              summary.contact.contactUserId == selected,
                          onTap: () =>
                              onSelect(summary.contact.contactUserId),
                        );
                      },
                    ),
            ),
          ),
        ],
      ),
    );
  }
}

/// The right pane before anything is chosen.
class _NothingSelected extends StatelessWidget {
  const _NothingSelected();

  @override
  Widget build(BuildContext context) {
    final colors = context.bond;
    return Scaffold(
      backgroundColor: colors.canvas,
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 320),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Opacity(opacity: 0.35, child: BondMark(size: 44)),
              const SizedBox(height: BondSpacing.xl),
              Text(
                'Choose a conversation',
                style: Theme.of(context).textTheme.titleMedium,
              ),
              const SizedBox(height: BondSpacing.sm),
              Text(
                'Messages are encrypted on this device and decrypted on '
                'theirs. The server only moves the bytes between.',
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

/// Connection state, shown whenever it is not simply "connected".
///
/// Worth the space: offline means messages will not arrive until the socket is
/// back, and a user who does not know that reads silence as "no messages".
/// It animates its own height so appearing and disappearing does not snap the
/// list up and down.
class _ConnectionBar extends StatelessWidget implements PreferredSizeWidget {
  const _ConnectionBar({required this.controller});

  final AppController controller;

  @override
  Size get preferredSize => const Size.fromHeight(26);

  @override
  Widget build(BuildContext context) {
    final colors = context.bond;
    final online = controller.isOnline;
    final connecting = controller.isConnecting;

    return AnimatedContainer(
      duration: const Duration(milliseconds: 240),
      curve: Curves.easeOutCubic,
      height: online ? 0 : 26,
      width: double.infinity,
      color: colors.surfaceElevated,
      alignment: Alignment.center,
      child: online
          ? null
          : ClipRect(
              child: Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  SizedBox(
                    width: 10,
                    height: 10,
                    child: connecting
                        ? CircularProgressIndicator(
                            strokeWidth: 1.6,
                            color: colors.labelSecondary,
                          )
                        : Icon(
                            Icons.cloud_off_outlined,
                            size: 10,
                            color: colors.labelSecondary,
                          ),
                  ),
                  const SizedBox(width: BondSpacing.sm),
                  Flexible(
                    child: Text(
                      connecting ? 'Connecting…' : 'Offline',
                      overflow: TextOverflow.ellipsis,
                      style: Theme.of(context).textTheme.labelSmall,
                    ),
                  ),
                ],
              ),
            ),
    );
  }
}

class _ConversationTile extends StatelessWidget {
  const _ConversationTile({
    required this.summary,
    required this.selected,
    required this.onTap,
    required this.dense,
  });

  final ConversationSummary summary;
  final bool selected;
  final bool dense;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final colors = context.bond;
    final text = Theme.of(context).textTheme;
    final last = summary.lastMessage;
    final unread = summary.unreadCount > 0;

    return Material(
      color: selected ? colors.surfaceElevated : Colors.transparent,
      child: InkWell(
        onTap: onTap,
        child: Padding(
          padding: const EdgeInsets.symmetric(
            horizontal: BondSpacing.lg,
            vertical: BondSpacing.md,
          ),
          child: Row(
            children: [
              _Avatar(name: summary.contact.username, size: dense ? 40 : 46),
              const SizedBox(width: BondSpacing.md),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Flexible(
                          child: Text(
                            summary.contact.username,
                            overflow: TextOverflow.ellipsis,
                            style: text.titleSmall,
                          ),
                        ),
                        const SizedBox(width: 5),
                        _SecurityGlyph(summary: summary),
                        const Spacer(),
                        if (last != null)
                          Text(
                            _relativeTime(last.createdAt),
                            style: text.labelSmall?.copyWith(
                              color:
                                  unread ? colors.label : colors.labelTertiary,
                            ),
                          ),
                      ],
                    ),
                    const SizedBox(height: 3),
                    Row(
                      children: [
                        if (last != null && last.outgoing) ...[
                          Icon(
                            _stateIcon(last.state),
                            size: 13,
                            color: last.state == MessageState.failed
                                ? colors.danger
                                : colors.labelTertiary,
                          ),
                          const SizedBox(width: 4),
                        ],
                        Expanded(
                          child: Text(
                            last == null ? 'No messages yet' : last.body,
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                            style: text.bodySmall?.copyWith(
                              color:
                                  unread ? colors.label : colors.labelSecondary,
                              fontWeight:
                                  unread ? FontWeight.w500 : FontWeight.w400,
                            ),
                          ),
                        ),
                        if (unread) ...[
                          const SizedBox(width: BondSpacing.sm),
                          Container(
                            constraints: const BoxConstraints(minWidth: 19),
                            height: 19,
                            padding: const EdgeInsets.symmetric(horizontal: 6),
                            decoration: BoxDecoration(
                              color: colors.accent,
                              borderRadius:
                                  BorderRadius.circular(BondRadius.pill),
                            ),
                            alignment: Alignment.center,
                            child: Text(
                              '${summary.unreadCount}',
                              style: text.labelSmall?.copyWith(
                                color: colors.onAccent,
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                          ),
                        ],
                      ],
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  static IconData _stateIcon(MessageState state) => switch (state) {
        MessageState.sending => Icons.schedule,
        MessageState.sent => Icons.check,
        MessageState.delivered => Icons.done_all,
        MessageState.read => Icons.done_all,
        MessageState.failed => Icons.error_outline,
        MessageState.received => Icons.south_west,
        MessageState.readLocally => Icons.south_west,
      };
}

class _Avatar extends StatelessWidget {
  const _Avatar({required this.name, this.size = 46});

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

/// The one badge that must never be wrong.
///
/// "Verified" renders ONLY from the local record of a human comparison. The
/// server's advisory `verifiedAt` is deliberately not consulted: a compromised
/// server could set it for a key it had substituted, which is the exact attack
/// verification exists to catch (docs/decisions.md D4).
///
/// A glyph rather than a text chip, so the row stays scannable — but the
/// warning states keep their words, because those are the ones a user must
/// not skim past.
class _SecurityGlyph extends StatelessWidget {
  const _SecurityGlyph({required this.summary});

  final ConversationSummary summary;

  @override
  Widget build(BuildContext context) {
    final colors = context.bond;

    if (summary.hasIdentityWarning) {
      return _pill(context, Icons.gpp_maybe, 'Identity changed', colors);
    }
    if (summary.serverKeyDiffers) {
      return _pill(context, Icons.help_outline, 'Key differs', colors);
    }
    if (summary.isVerified) {
      return Icon(Icons.verified_user, size: 13, color: colors.success);
    }
    // Not verified is the normal first state, so it gets the quietest
    // treatment that is still present: an outline lock, not nothing.
    return Icon(Icons.lock_outline, size: 13, color: colors.labelTertiary);
  }

  Widget _pill(
    BuildContext context,
    IconData icon,
    String label,
    BondColors colors,
  ) =>
      Container(
        padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
        decoration: BoxDecoration(
          color: colors.dangerSurface,
          borderRadius: BorderRadius.circular(BondRadius.pill),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, size: 11, color: colors.onDangerSurface),
            const SizedBox(width: 3),
            Text(
              label,
              style: Theme.of(context).textTheme.labelSmall?.copyWith(
                    fontSize: 10.5,
                    color: colors.onDangerSurface,
                  ),
            ),
          ],
        ),
      );
}

class _EmptyState extends StatelessWidget {
  const _EmptyState();

  @override
  Widget build(BuildContext context) {
    final colors = context.bond;
    final text = Theme.of(context).textTheme;

    return ListView(
      children: [
        const SizedBox(height: 72),
        Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 300),
            child: Padding(
              padding: const EdgeInsets.all(BondSpacing.xl),
              child: Column(
                children: [
                  Container(
                    width: 58,
                    height: 58,
                    decoration: BoxDecoration(
                      color: colors.surface,
                      shape: BoxShape.circle,
                      border: Border.all(color: colors.separator, width: 0.5),
                    ),
                    child: Icon(
                      Icons.forum_outlined,
                      size: 25,
                      color: colors.labelTertiary,
                    ),
                  ),
                  const SizedBox(height: BondSpacing.lg),
                  Text('No contacts yet', style: text.titleMedium),
                  const SizedBox(height: BondSpacing.sm),
                  Text(
                    'Bond has no user directory and no search: you cannot be '
                    'found by strangers, and you cannot look anyone up. A '
                    'contact exists only once an invitation has been accepted.',
                    textAlign: TextAlign.center,
                    style: text.bodySmall,
                  ),
                ],
              ),
            ),
          ),
        ),
      ],
    );
  }
}

/// Short, like every messaging app: time today, weekday this week, date beyond.
String _relativeTime(DateTime at) {
  final now = DateTime.now();
  final today = DateTime(now.year, now.month, now.day);
  final day = DateTime(at.year, at.month, at.day);
  final difference = today.difference(day).inDays;

  if (difference == 0) {
    return '${at.hour.toString().padLeft(2, '0')}:'
        '${at.minute.toString().padLeft(2, '0')}';
  }
  if (difference == 1) return 'Yesterday';
  if (difference < 7) {
    const names = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
    return names[at.weekday - 1];
  }
  return '${at.day.toString().padLeft(2, '0')}/'
      '${at.month.toString().padLeft(2, '0')}/${at.year % 100}';
}
