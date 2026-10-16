/// What Bond protects, and what it does not.
///
/// This screen exists because of a rule in the brief: do not call the system
/// secure merely because it has encryption. Say what is protected, from whom,
/// and what is not. A user who believes metadata is private will make decisions
/// this system cannot support, so the limits are stated here as plainly as the
/// guarantees — and the limits come BEFORE the known-good list, because a page
/// that opens with reassurance tends not to get read to the end.
///
/// It also surfaces decryption failures. A failed decrypt is a security event —
/// tampering, replay, or a message meant for someone else — and hiding it would
/// mean the one signal the user gets of an attack in progress is a message that
/// silently never arrives.
library;

import 'package:flutter/material.dart';

import '../../core/app_scope.dart';
import '../../core/theme.dart';
import '../shell/layout.dart';

class SecurityInfoScreen extends StatelessWidget {
  const SecurityInfoScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final controller = AppScope.of(context);
    final colors = context.bond;
    final failures = controller.decryptionFailures;

    return Scaffold(
      appBar: AppBar(title: const Text('Security')),
      body: BondPage(
        children: [
          _Card(
            title: 'This device',
            children: [
              _Row(label: 'Account', value: controller.username ?? '—'),
              _Row(label: 'User id', value: controller.userId ?? '—'),
              _Row(
                label: 'Protocol device id',
                value: controller.deviceIndex?.toString() ?? '—',
              ),
              _Row(label: 'Installation profile', value: controller.profile),
              _Row(label: 'Server', value: controller.serverUri.toString()),
              _Row(
                label: 'Key storage',
                value: controller.secureStorageDescription,
              ),
              _Row(
                label: 'Connection',
                value: controller.isOnline
                    ? 'connected'
                    : controller.isConnecting
                        ? 'connecting'
                        : 'disconnected',
              ),
            ],
          ),
          const SizedBox(height: BondSpacing.md),
          _Card(
            title: 'What the server does see',
            subtitle: 'Protecting content is not the same as being private. '
                'These are real limits, not oversights.',
            accent: colors.danger,
            children: const [
              _Bullet('Who you exchange messages with, and when.'),
              _Bullet('How often you message, and roughly how large each '
                  'message is.'),
              _Bullet('Your IP address, and when your device is online.'),
              _Bullet('Your username and the public keys of your devices.'),
            ],
          ),
          const SizedBox(height: BondSpacing.md),
          _Card(
            title: 'What the server cannot read',
            accent: colors.success,
            children: const [
              _Bullet('Message text. It is encrypted on the sending device and '
                  'decrypted only on the receiving one.'),
              _Bullet('Your private identity key, which never leaves this '
                  'machine.'),
              _Bullet('Anything that would let it decrypt stored messages '
                  'later, even with full database access.'),
            ],
          ),
          const SizedBox(height: BondSpacing.md),
          _Card(
            title: 'Three different kinds of encryption',
            subtitle: 'They are often conflated. Bond uses the first and the '
                'third, and neither substitutes for the other.',
            children: const [
              _Bullet('Transport encryption (TLS) protects bytes on the wire. '
                  'The server can still read what arrives.'),
              _Bullet('Encryption at rest protects stolen disks. The server '
                  'holds the key, so it can still read the data.'),
              _Bullet('End-to-end encryption protects content between two '
                  'devices. The server cannot read it at all.'),
            ],
          ),
          const SizedBox(height: BondSpacing.md),
          _Card(
            title: 'Known limits of this version',
            children: const [
              _Bullet('No key backup. Losing this device loses its message '
                  'history, permanently.'),
              _Bullet('No metadata protection: no sealed sender, no padding, '
                  'no cover traffic.'),
              _Bullet('A compromised device defeats everything here. '
                  'End-to-end encryption protects the channel, not the ends.'),
              _Bullet('This application has not been independently audited. '
                  'Only the upstream cryptographic library has.'),
            ],
          ),
          const SizedBox(height: BondSpacing.md),
          _Card(
            title: 'Decryption failures',
            subtitle: failures.isEmpty
                ? 'None. A failure here would mean a message was tampered '
                    'with, replayed, or not meant for this device.'
                : 'Each of these means a message could not be authenticated. '
                    'Bond did not display it.',
            accent: failures.isEmpty ? null : colors.danger,
            children: [
              for (final failure in failures)
                Padding(
                  padding: const EdgeInsets.only(bottom: BondSpacing.md),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'From ${failure.senderUserId}',
                        style: Theme.of(context).textTheme.labelMedium,
                      ),
                      Text(
                        failure.reason,
                        style: Theme.of(context)
                            .textTheme
                            .labelSmall
                            ?.copyWith(color: colors.danger),
                      ),
                    ],
                  ),
                ),
            ],
          ),
        ],
      ),
    );
  }
}

class _Card extends StatelessWidget {
  const _Card({
    required this.title,
    this.subtitle,
    this.accent,
    required this.children,
  });

  final String title;
  final String? subtitle;

  /// A 2px rule down the left edge. Used sparingly — only where a section is
  /// specifically good or specifically limiting — so it keeps meaning.
  final Color? accent;

  final List<Widget> children;

  @override
  Widget build(BuildContext context) {
    final colors = context.bond;
    final text = Theme.of(context).textTheme;

    return Container(
      decoration: BoxDecoration(
        color: colors.surface,
        borderRadius: BorderRadius.circular(BondRadius.large),
        border: Border.all(color: colors.separator, width: 0.5),
      ),
      clipBehavior: Clip.antiAlias,
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          if (accent != null) Container(width: 2.5, color: accent),
          Expanded(
            child: Padding(
              padding: const EdgeInsets.all(BondSpacing.lg),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(title, style: text.titleMedium),
                  if (subtitle != null) ...[
                    const SizedBox(height: 6),
                    Text(subtitle!, style: text.bodySmall),
                  ],
                  if (children.isNotEmpty) ...[
                    const SizedBox(height: BondSpacing.md),
                    ...children,
                  ],
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _Bullet extends StatelessWidget {
  const _Bullet(this.text);

  final String text;

  @override
  Widget build(BuildContext context) {
    final colors = context.bond;
    return Padding(
      padding: const EdgeInsets.only(bottom: BondSpacing.sm + 2),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Padding(
            padding: const EdgeInsets.only(top: 6, right: BondSpacing.md),
            child: Container(
              width: 3,
              height: 3,
              decoration: BoxDecoration(
                color: colors.labelTertiary,
                shape: BoxShape.circle,
              ),
            ),
          ),
          Expanded(
            child: Text(
              text,
              style: Theme.of(context).textTheme.bodySmall,
            ),
          ),
        ],
      ),
    );
  }
}

class _Row extends StatelessWidget {
  const _Row({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    final text = Theme.of(context).textTheme;
    return Padding(
      padding: const EdgeInsets.only(bottom: 6),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(width: 150, child: Text(label, style: text.labelSmall)),
          Expanded(
            child: SelectableText(
              value,
              style: text.labelSmall?.copyWith(color: context.bond.label),
            ),
          ),
        ],
      ),
    );
  }
}
