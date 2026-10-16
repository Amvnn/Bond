/// The three screens that are not a feature: starting, revoked, and refusing
/// to start.
///
/// Kept together because they share a property no feature screen has — none of
/// them offers a way forward. Starting has nothing to act on yet; the other two
/// are terminal, and presenting an action on either would imply a recovery that
/// does not exist.
library;

import 'package:flutter/material.dart';

import '../../core/theme.dart';
import 'brand.dart';

/// Shown while local storage opens.
///
/// The lockup rather than the bare logotype: this is the one moment the
/// product introduces itself, which is exactly what the lockup is for.
class SplashScreen extends StatelessWidget {
  const SplashScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final colors = context.bond;
    return Scaffold(
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const BondLockup(width: 240),
            const SizedBox(height: BondSpacing.xxl),
            SizedBox(
              width: 18,
              height: 18,
              child: CircularProgressIndicator(
                strokeWidth: 2,
                color: colors.labelTertiary,
              ),
            ),
            const SizedBox(height: BondSpacing.lg),
            Text(
              'Opening encrypted storage',
              style: Theme.of(context).textTheme.bodySmall,
            ),
          ],
        ),
      ),
    );
  }
}

/// Shown after this device is revoked.
///
/// There is deliberately no "continue anyway": the local secrets are already
/// destroyed and the server refuses this device. An action here would imply
/// otherwise.
class RevokedScreen extends StatelessWidget {
  const RevokedScreen({super.key});

  @override
  Widget build(BuildContext context) => _TerminalScreen(
        icon: Icons.gpp_bad_outlined,
        title: 'This device has been revoked',
        body: 'Its sessions, prekeys and local message history have been '
            'destroyed, and the server will not accept it again. The message '
            'history on this device is gone: it was encrypted with keys that '
            'no longer exist, which is the point of revoking.\n\n'
            'To use Bond on this machine again, reinstall it and register a '
            'new device.',
      );
}

/// Startup failed in a way that must not be worked around.
///
/// The two realistic causes are a secure key store that refused and a database
/// that cannot be decrypted. Both have the same correct response: stop. The
/// alternatives are an unencrypted database or an unprotected key, and the
/// brief forbids both.
class FatalScreen extends StatelessWidget {
  const FatalScreen({super.key, required this.message});

  final String message;

  @override
  Widget build(BuildContext context) => _TerminalScreen(
        icon: Icons.lock_outline,
        title: 'Bond cannot start securely',
        body: 'Rather than continue with weaker protection, Bond stops. The '
            'reason reported was:',
        detail: message,
      );
}

class _TerminalScreen extends StatelessWidget {
  const _TerminalScreen({
    required this.icon,
    required this.title,
    required this.body,
    this.detail,
  });

  final IconData icon;
  final String title;
  final String body;
  final String? detail;

  @override
  Widget build(BuildContext context) {
    final colors = context.bond;
    final text = Theme.of(context).textTheme;

    return Scaffold(
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(BondSpacing.xl),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 480),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Container(
                  width: 52,
                  height: 52,
                  decoration: BoxDecoration(
                    color: colors.dangerSurface,
                    borderRadius: BorderRadius.circular(BondRadius.medium),
                  ),
                  child: Icon(icon, size: 26, color: colors.danger),
                ),
                const SizedBox(height: BondSpacing.xl),
                Text(title, style: text.headlineSmall),
                const SizedBox(height: BondSpacing.md),
                Text(
                  body,
                  style: text.bodyMedium?.copyWith(
                    color: colors.labelSecondary,
                  ),
                ),
                if (detail != null) ...[
                  const SizedBox(height: BondSpacing.lg),
                  Container(
                    width: double.infinity,
                    padding: const EdgeInsets.all(BondSpacing.lg),
                    decoration: BoxDecoration(
                      color: colors.surface,
                      borderRadius: BorderRadius.circular(BondRadius.medium),
                      border: Border.all(color: colors.separator, width: 0.5),
                    ),
                    child: SelectableText(
                      detail!,
                      style: text.bodySmall?.copyWith(color: colors.label),
                    ),
                  ),
                ],
              ],
            ),
          ),
        ),
      ),
    );
  }
}
