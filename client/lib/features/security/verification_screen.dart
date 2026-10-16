/// Compare safety numbers out of band.
///
/// This screen is where the system's trust actually comes from. Everything
/// else — TLS, the ratchet, the encrypted database — protects a conversation
/// between two keys. Only this step establishes that those keys belong to the
/// people involved.
///
/// So the wording is careful about one thing in particular: the server supplied
/// the contact's key, and the server is only partially trusted. Matching digits
/// prove the key was not substituted. A green badge the user never earned by
/// comparing would be a lie, which is why marking verified requires an explicit
/// action here and is stored locally, never read back from the server
/// (docs/decisions.md D4).
library;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../../core/app_scope.dart';
import '../../core/theme.dart';
import '../../services/network/api_models.dart';
import '../shell/layout.dart';

class VerificationScreen extends StatelessWidget {
  const VerificationScreen({super.key, required this.contactUserId});

  final String contactUserId;

  @override
  Widget build(BuildContext context) {
    final controller = AppScope.of(context);
    final contact = controller.contactById(contactUserId);

    if (contact == null) {
      return Scaffold(
        appBar: AppBar(title: const Text('Verify')),
        body: const Center(child: Text('This contact is no longer available.')),
      );
    }

    return Scaffold(
      appBar: AppBar(title: Text('Verify ${contact.username}')),
      body: BondPage(
        children: [
          const _Explainer(),
          const SizedBox(height: BondSpacing.lg),
          for (final device in contact.devices)
            Padding(
              padding: const EdgeInsets.only(bottom: BondSpacing.md),
              child: _DeviceVerification(contact: contact, device: device),
            ),
          if (contact.devices.isEmpty)
            Padding(
              padding: const EdgeInsets.all(BondSpacing.lg),
              child: Text(
                'This contact has no active devices, so there is nothing to '
                'verify yet.',
                style: Theme.of(context).textTheme.bodySmall,
              ),
            ),
        ],
      ),
    );
  }
}

class _Explainer extends StatelessWidget {
  const _Explainer();

  @override
  Widget build(BuildContext context) {
    final colors = context.bond;
    final text = Theme.of(context).textTheme;

    return Container(
      padding: const EdgeInsets.all(BondSpacing.lg),
      decoration: BoxDecoration(
        color: colors.surface,
        borderRadius: BorderRadius.circular(BondRadius.large),
        border: Border.all(color: colors.separator, width: 0.5),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('How to compare', style: text.titleMedium),
          const SizedBox(height: BondSpacing.md),
          Text(
            'Read the digits below to your contact over a channel you already '
            'trust — in person, or a phone call where you recognise their '
            'voice. They should see exactly the same digits on their screen.\n\n'
            'If the numbers match, nobody substituted a key. If they do not '
            'match, stop and do not send anything sensitive.',
            style: text.bodySmall,
          ),
          const SizedBox(height: BondSpacing.md),
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Icon(Icons.info_outline, size: 14, color: colors.labelTertiary),
              const SizedBox(width: BondSpacing.sm),
              Expanded(
                child: Text(
                  'Do not compare them over Bond itself, or over any channel '
                  'an attacker who could substitute a key might also control.',
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

class _DeviceVerification extends StatelessWidget {
  const _DeviceVerification({required this.contact, required this.device});

  final Contact contact;
  final ContactDevice device;

  @override
  Widget build(BuildContext context) {
    final controller = AppScope.of(context);
    final colors = context.bond;
    final text = Theme.of(context).textTheme;

    final identity = controller.peerIdentity(
      contactUserId: contact.contactUserId,
      deviceIndex: device.deviceIndex,
    );
    final number = controller.safetyNumber(
      contactUserId: contact.contactUserId,
      deviceIndex: device.deviceIndex,
    );
    final verified = identity?.isVerified ?? false;
    final changed = identity?.hasUnacknowledgedChange ?? false;

    return Container(
      padding: const EdgeInsets.all(BondSpacing.lg),
      decoration: BoxDecoration(
        color: colors.surface,
        borderRadius: BorderRadius.circular(BondRadius.large),
        border: Border.all(
          color: changed ? colors.danger.withValues(alpha: 0.5) : colors.separator,
          width: changed ? 1 : 0.5,
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Row(
            children: [
              Icon(
                changed
                    ? Icons.gpp_maybe
                    : verified
                        ? Icons.verified_user
                        : Icons.lock_outline,
                size: 18,
                color: changed
                    ? colors.danger
                    : verified
                        ? colors.success
                        : colors.labelTertiary,
              ),
              const SizedBox(width: BondSpacing.sm + 2),
              Expanded(
                child: Text(
                  device.deviceName.isEmpty
                      ? 'Device ${device.deviceIndex}'
                      : '${device.deviceName} (device ${device.deviceIndex})',
                  style: text.titleSmall,
                ),
              ),
            ],
          ),
          const SizedBox(height: BondSpacing.md),
          if (identity == null)
            Padding(
              padding: const EdgeInsets.only(bottom: BondSpacing.md),
              child: Text(
                'No session with this device yet. The safety number below is '
                'derived from the key the server currently reports; verifying '
                'now pins that key, so a later substitution is detected rather '
                'than trusted.',
                style: text.labelSmall,
              ),
            ),
          if (changed) ...[
            Container(
              padding: const EdgeInsets.all(BondSpacing.md),
              decoration: BoxDecoration(
                color: colors.dangerSurface,
                borderRadius: BorderRadius.circular(BondRadius.small),
              ),
              child: Text(
                'This key changed since you last saw it. Sending is blocked '
                'until you compare the new number or accept the change.',
                style: text.bodySmall?.copyWith(color: colors.onDangerSurface),
              ),
            ),
            const SizedBox(height: BondSpacing.md),
          ],
          if (number == null)
            Text(
              'The safety number could not be derived.',
              style: text.bodySmall,
            )
          else
            _SafetyNumber(digits: number),
          const SizedBox(height: BondSpacing.lg),
          Row(
            children: [
              Expanded(
                child: verified
                    ? OutlinedButton(
                        onPressed: () => controller.setVerified(
                          contactUserId: contact.contactUserId,
                          deviceIndex: device.deviceIndex,
                          verified: false,
                        ),
                        child: const Text('Clear verification'),
                      )
                    : FilledButton(
                        onPressed: number == null
                            ? null
                            : () => controller.setVerified(
                                  contactUserId: contact.contactUserId,
                                  deviceIndex: device.deviceIndex,
                                  verified: true,
                                ),
                        child: const Text('The numbers match'),
                      ),
              ),
              if (number != null) ...[
                const SizedBox(width: BondSpacing.sm),
                IconButton(
                  tooltip: 'Copy digits',
                  icon: Icon(Icons.copy, size: 18, color: colors.labelSecondary),
                  onPressed: () async {
                    await Clipboard.setData(ClipboardData(text: number));
                    if (!context.mounted) return;
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(content: Text('Safety number copied')),
                    );
                  },
                ),
              ],
            ],
          ),
        ],
      ),
    );
  }
}

/// 60 digits, in twelve groups of five.
///
/// The grouping is not decoration: reading 60 digits aloud without it is where
/// comparison mistakes come from, and a mistaken "yes, they match" is worse
/// than no verification at all. Laid out in a fixed grid rather than a wrap so
/// both sides see the same shape and can compare row by row.
class _SafetyNumber extends StatelessWidget {
  const _SafetyNumber({required this.digits});

  final String digits;

  @override
  Widget build(BuildContext context) {
    final colors = context.bond;
    final groups = <String>[];
    for (var i = 0; i < digits.length; i += 5) {
      groups.add(digits.substring(i, (i + 5).clamp(0, digits.length)));
    }

    return Container(
      padding: const EdgeInsets.symmetric(
        horizontal: BondSpacing.md,
        vertical: BondSpacing.lg,
      ),
      decoration: BoxDecoration(
        color: colors.canvas,
        borderRadius: BorderRadius.circular(BondRadius.medium),
        border: Border.all(color: colors.separator, width: 0.5),
      ),
      child: GridView.builder(
        shrinkWrap: true,
        physics: const NeverScrollableScrollPhysics(),
        itemCount: groups.length,
        gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
          crossAxisCount: 4,
          mainAxisSpacing: BondSpacing.sm,
          childAspectRatio: 2.6,
        ),
        itemBuilder: (context, index) => Center(
          child: SelectableText(
            groups[index],
            style: TextStyle(
              fontFamily: 'Consolas',
              fontSize: 19,
              height: 1.1,
              letterSpacing: 1.5,
              color: colors.label,
            ),
          ),
        ),
      ),
    );
  }
}
