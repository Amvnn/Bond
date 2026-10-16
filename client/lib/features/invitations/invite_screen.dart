/// Create an invitation, or accept one.
///
/// This is the only way a contact comes into existence. There is no directory,
/// no search and no friend suggestion, so an invitation token is the entire
/// admission mechanism — which makes it a credential, and it is treated like
/// one: shown once, never logged, never stored locally, and transferred by the
/// user over a channel they already trust.
library;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../core/app_scope.dart';
import '../../core/theme.dart';
import '../../services/network/api_models.dart';
import '../shell/layout.dart';

class InviteScreen extends StatefulWidget {
  const InviteScreen({super.key});

  @override
  State<InviteScreen> createState() => _InviteScreenState();
}

class _InviteScreenState extends State<InviteScreen> {
  final _tokenField = TextEditingController();

  CreatedInvitation? _created;
  List<InvitationSummary> _invitations = const [];
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _load());
  }

  @override
  void dispose() {
    _tokenField.dispose();
    super.dispose();
  }

  Future<void> _load() async {
    final invitations = await AppScope.read(context).listInvitations();
    if (!mounted) return;
    setState(() {
      _invitations = invitations;
      _loading = false;
    });
  }

  Future<void> _create() async {
    final created = await AppScope.read(context).createInvitation();
    if (!mounted) return;
    setState(() => _created = created);
    await _load();
  }

  Future<void> _accept() async {
    final controller = AppScope.read(context);
    final ok = await controller.acceptInvitation(_tokenField.text);
    if (!mounted) return;

    if (ok) {
      _tokenField.clear();
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Invitation accepted. Contact added.')),
      );
      Navigator.of(context).pop();
    } else {
      final error = controller.lastError;
      if (error != null) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(error)),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final controller = AppScope.of(context);
    final colors = context.bond;
    final text = Theme.of(context).textTheme;

    return Scaffold(
      appBar: AppBar(title: const Text('Invite or accept')),
      body: BondPage(
        children: [
          _Section(
            title: 'Invite someone',
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Text(
                  'Creates a single-use token that expires. Send it over a '
                  'channel you already trust — anyone who gets hold of it can '
                  'use it.',
                  style: text.bodySmall,
                ),
                const SizedBox(height: BondSpacing.lg),
                // Sized to its label, not to the card. A button is an object
                // you aim at; stretching it to the full width of a panel makes
                // it a bar and loses that affordance.
                Align(
                  alignment: Alignment.centerLeft,
                  child: FilledButton(
                    onPressed: controller.busy ? null : _create,
                    child: const Text('Create an invitation'),
                  ),
                ),
                AnimatedSize(
                  duration: const Duration(milliseconds: 240),
                  curve: Curves.easeOutCubic,
                  alignment: Alignment.topCenter,
                  child: _created == null
                      ? const SizedBox(width: double.infinity)
                      : Padding(
                          padding: const EdgeInsets.only(top: BondSpacing.lg),
                          child: _TokenCard(invitation: _created!),
                        ),
                ),
              ],
            ),
          ),
          const SizedBox(height: BondSpacing.lg),
          _Section(
            title: 'Accept an invitation',
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Text(
                  'Paste a token someone sent you. Use this when you already '
                  'have an account; a new account enters its token on the '
                  'registration screen instead.',
                  style: text.bodySmall,
                ),
                const SizedBox(height: BondSpacing.lg),
                TextField(
                  controller: _tokenField,
                  style: text.bodyMedium?.copyWith(fontFamily: 'Consolas'),
                  decoration: const InputDecoration(
                    hintText: 'Invitation token — 43 characters',
                  ),
                  onSubmitted: (_) => _accept(),
                ),
                const SizedBox(height: BondSpacing.md),
                Align(
                  alignment: Alignment.centerLeft,
                  child: OutlinedButton(
                    onPressed: controller.busy ? null : _accept,
                    child: const Text('Accept'),
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: BondSpacing.lg),
          _Section(
            title: 'Your invitations',
            child: _loading
                ? Padding(
                    padding: const EdgeInsets.symmetric(
                      vertical: BondSpacing.lg,
                    ),
                    child: Center(
                      child: SizedBox(
                        width: 18,
                        height: 18,
                        child: CircularProgressIndicator(
                          strokeWidth: 2,
                          color: colors.labelTertiary,
                        ),
                      ),
                    ),
                  )
                : _invitations.isEmpty
                    ? Text('None yet.', style: text.bodySmall)
                    : Column(
                        children: [
                          for (var i = 0; i < _invitations.length; i++) ...[
                            if (i > 0)
                              Divider(height: 1, color: colors.separator),
                            _InvitationRow(
                              invitation: _invitations[i],
                              onRevoke: () async {
                                await AppScope.read(context).revokeInvitation(
                                  _invitations[i].invitationId,
                                );
                                await _load();
                              },
                            ),
                          ],
                        ],
                      ),
          ),
        ],
      ),
    );
  }
}

/// Shows the token once.
///
/// The server stores only an HMAC of it, so there is genuinely no way to show
/// it again — saying so prevents the user from closing this and expecting to
/// find it later.
class _TokenCard extends StatelessWidget {
  const _TokenCard({required this.invitation});

  final CreatedInvitation invitation;

  @override
  Widget build(BuildContext context) {
    final colors = context.bond;
    final text = Theme.of(context).textTheme;

    return Container(
      padding: const EdgeInsets.all(BondSpacing.lg),
      decoration: BoxDecoration(
        color: colors.canvas,
        borderRadius: BorderRadius.circular(BondRadius.medium),
        border: Border.all(color: colors.separator, width: 0.5),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Row(
            children: [
              Icon(Icons.vpn_key_outlined, size: 16, color: colors.label),
              const SizedBox(width: BondSpacing.sm),
              Expanded(
                child: Text(
                  'Copy this now — it is shown only once',
                  style: text.titleSmall,
                ),
              ),
            ],
          ),
          const SizedBox(height: BondSpacing.md),
          SelectableText(
            invitation.token,
            style: text.bodyMedium?.copyWith(
              fontFamily: 'Consolas',
              letterSpacing: 0.3,
              color: colors.label,
            ),
          ),
          const SizedBox(height: BondSpacing.md),
          Row(
            children: [
              OutlinedButton.icon(
                onPressed: () async {
                  await Clipboard.setData(
                    ClipboardData(text: invitation.token),
                  );
                  if (!context.mounted) return;
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('Token copied')),
                  );
                },
                icon: const Icon(Icons.copy, size: 15),
                label: const Text('Copy'),
              ),
              const SizedBox(width: BondSpacing.md),
              Expanded(
                child: Text(
                  'Expires ${_shortDate(invitation.expiresAt)}',
                  style: text.labelSmall,
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }
}

class _InvitationRow extends StatelessWidget {
  const _InvitationRow({required this.invitation, required this.onRevoke});

  final InvitationSummary invitation;
  final VoidCallback onRevoke;

  @override
  Widget build(BuildContext context) {
    final colors = context.bond;
    final text = Theme.of(context).textTheme;

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: BondSpacing.md),
      child: Row(
        children: [
          Icon(
            invitation.isPending
                ? Icons.hourglass_empty
                : invitation.usedAt != null
                    ? Icons.check_circle_outline
                    : Icons.block,
            size: 17,
            color: colors.labelSecondary,
          ),
          const SizedBox(width: BondSpacing.md),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(invitation.status, style: text.labelMedium),
                Text(
                  'expires ${_shortDate(invitation.expiresAt)}',
                  style: text.labelSmall,
                ),
              ],
            ),
          ),
          if (invitation.isPending)
            TextButton(
              onPressed: onRevoke,
              child: Text(
                'Revoke',
                style: text.labelMedium?.copyWith(color: colors.danger),
              ),
            ),
        ],
      ),
    );
  }
}

class _Section extends StatelessWidget {
  const _Section({required this.title, required this.child});

  final String title;
  final Widget child;

  @override
  Widget build(BuildContext context) {
    final colors = context.bond;
    return Container(
      padding: const EdgeInsets.all(BondSpacing.lg),
      decoration: BoxDecoration(
        color: colors.surface,
        borderRadius: BorderRadius.circular(BondRadius.large),
        border: Border.all(color: colors.separator, width: 0.5),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text(title, style: Theme.of(context).textTheme.titleMedium),
          const SizedBox(height: BondSpacing.md),
          child,
        ],
      ),
    );
  }
}

String _shortDate(String iso) {
  final parsed = DateTime.tryParse(iso);
  if (parsed == null) return iso;
  final local = parsed.toLocal();
  return '${local.year}-${local.month.toString().padLeft(2, '0')}-'
      '${local.day.toString().padLeft(2, '0')} '
      '${local.hour.toString().padLeft(2, '0')}:'
      '${local.minute.toString().padLeft(2, '0')}';
}
