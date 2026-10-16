/// Generates this installation's cryptographic device identity.
///
/// A separate step from signing in, because an account and a cryptographic
/// device are separate concepts: the account proves who you are to the server,
/// the device identity is what messages are actually encrypted to. One account
/// can hold several devices, and each generates its own identity key that never
/// leaves the machine it was generated on.
library;

import 'package:flutter/material.dart';

import '../../core/app_scope.dart';
import '../../core/theme.dart';
import '../shell/brand.dart';

class DeviceSetupScreen extends StatelessWidget {
  const DeviceSetupScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final controller = AppScope.of(context);
    final colors = context.bond;
    final text = Theme.of(context).textTheme;

    return Scaffold(
      appBar: AppBar(
        title: const BondLogotype(width: 100),
        actions: [
          TextButton(
            onPressed: controller.busy ? null : controller.logout,
            child: Text(
              'Sign out',
              style: text.labelMedium?.copyWith(color: colors.labelSecondary),
            ),
          ),
          const SizedBox(width: BondSpacing.sm),
        ],
      ),
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(BondSpacing.xl),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 440),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Center(
                  child: Container(
                    width: 64,
                    height: 64,
                    decoration: BoxDecoration(
                      color: colors.surface,
                      shape: BoxShape.circle,
                      border: Border.all(color: colors.separator, width: 0.5),
                    ),
                    child: Icon(
                      Icons.key_outlined,
                      size: 28,
                      color: colors.label,
                    ),
                  ),
                ),
                const SizedBox(height: BondSpacing.xl),
                Text(
                  'Set up this device',
                  textAlign: TextAlign.center,
                  style: text.headlineSmall,
                ),
                const SizedBox(height: BondSpacing.sm),
                Text(
                  'Signed in as ${controller.username ?? ''}',
                  textAlign: TextAlign.center,
                  style: text.bodySmall,
                ),
                const SizedBox(height: BondSpacing.xl),
                Text(
                  'This installation needs its own cryptographic identity '
                  'before it can send or receive messages. Bond will generate '
                  'one now and publish only the public half.',
                  style: text.bodyMedium?.copyWith(
                    color: colors.labelSecondary,
                  ),
                ),
                const SizedBox(height: BondSpacing.xl),
                _FactCard(
                  items: [
                    (
                      Icons.phonelink_lock_outlined,
                      'The private identity key is generated here and stays '
                          'here. The server never receives it.'
                    ),
                    (
                      Icons.shield_outlined,
                      'It is stored in an encrypted database whose key is held '
                          'by ${controller.secureStorageDescription}.'
                    ),
                    (
                      Icons.history_toggle_off_outlined,
                      'Message history belongs to this device. There is no key '
                          'backup in this version, so losing it loses the '
                          'history — deliberately.'
                    ),
                  ],
                ),
                if (controller.lastError != null) ...[
                  const SizedBox(height: BondSpacing.lg),
                  Container(
                    padding: const EdgeInsets.all(BondSpacing.md),
                    decoration: BoxDecoration(
                      color: colors.dangerSurface,
                      borderRadius: BorderRadius.circular(BondRadius.medium),
                    ),
                    child: Text(
                      controller.lastError!,
                      style: text.bodySmall?.copyWith(
                        color: colors.onDangerSurface,
                      ),
                    ),
                  ),
                ],
                const SizedBox(height: BondSpacing.xl),
                FilledButton(
                  onPressed:
                      controller.busy ? null : () => controller.provisionDevice(),
                  child: controller.busy
                      ? Row(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            SizedBox(
                              width: 16,
                              height: 16,
                              child: CircularProgressIndicator(
                                strokeWidth: 2,
                                color: colors.onAccent,
                              ),
                            ),
                            const SizedBox(width: BondSpacing.md),
                            const Text('Generating keys…'),
                          ],
                        )
                      : const Text('Generate and register this device'),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _FactCard extends StatelessWidget {
  const _FactCard({required this.items});

  final List<(IconData, String)> items;

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
        children: [
          for (var i = 0; i < items.length; i++) ...[
            if (i > 0) const SizedBox(height: BondSpacing.lg),
            Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Icon(items[i].$1, size: 18, color: colors.labelSecondary),
                const SizedBox(width: BondSpacing.md),
                Expanded(
                  child: Text(
                    items[i].$2,
                    style: Theme.of(context).textTheme.bodySmall,
                  ),
                ),
              ],
            ),
          ],
        ],
      ),
    );
  }
}
