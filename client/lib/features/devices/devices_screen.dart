/// Your devices, and revocation.
///
/// Revoking the device you are using is destructive and irreversible: the
/// server drops its sessions and prekeys and closes its socket, and the client
/// destroys the local database and the OS-held key that protects it. The
/// message history on that device goes with it, because it was encrypted under
/// a key that no longer exists. That is the point of revoking, so the
/// confirmation says so plainly rather than asking a vague "are you sure?".
library;

import 'package:flutter/material.dart';

import '../../core/app_scope.dart';
import '../../core/theme.dart';
import '../../services/network/api_models.dart';
import '../shell/layout.dart';

class DevicesScreen extends StatefulWidget {
  const DevicesScreen({super.key});

  @override
  State<DevicesScreen> createState() => _DevicesScreenState();
}

class _DevicesScreenState extends State<DevicesScreen> {
  List<OwnDevice> _devices = const [];
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _load());
  }

  Future<void> _load() async {
    final devices = await AppScope.read(context).listOwnDevices();
    if (!mounted) return;
    setState(() {
      _devices = devices;
      _loading = false;
    });
  }

  @override
  Widget build(BuildContext context) {
    final controller = AppScope.of(context);
    final colors = context.bond;
    final currentDeviceId = controller.deviceId;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Devices'),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh, size: 20),
            onPressed: _loading ? null : _load,
            tooltip: 'Refresh',
          ),
          const SizedBox(width: BondSpacing.sm),
        ],
      ),
      body: _loading
          ? Center(
              child: SizedBox(
                width: 20,
                height: 20,
                child: CircularProgressIndicator(
                  strokeWidth: 2,
                  color: colors.labelTertiary,
                ),
              ),
            )
          : BondPage(
              children: [
                Text(
                  'Each installation is a separate cryptographic device with '
                  'its own identity key. Messages are encrypted to a device, '
                  'not to an account.',
                  style: Theme.of(context).textTheme.bodySmall,
                ),
                const SizedBox(height: BondSpacing.lg),
                for (final device in _devices)
                  Padding(
                    padding: const EdgeInsets.only(bottom: BondSpacing.md),
                    child: _DeviceCard(
                      device: device,
                      isCurrent: device.deviceId == currentDeviceId,
                      onRevoke: () => _confirmRevoke(device, currentDeviceId),
                    ),
                  ),
                if (_devices.isEmpty)
                  Text(
                    'No devices registered.',
                    style: Theme.of(context).textTheme.bodySmall,
                  ),
              ],
            ),
    );
  }

  Future<void> _confirmRevoke(OwnDevice device, String? currentDeviceId) async {
    final isCurrent = device.deviceId == currentDeviceId;
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: Text(isCurrent ? 'Revoke this device?' : 'Revoke device?'),
        content: Text(
          isCurrent
              ? 'This signs you out of this installation permanently and '
                  'destroys its local data: the encrypted database, the key '
                  'protecting it, and all message history stored here.\n\n'
                  'The history cannot be recovered. It was encrypted with keys '
                  'that are about to be deleted, and there is no key backup in '
                  'this version.\n\n'
                  'You would need to reinstall and register a new device to '
                  'use Bond on this machine again.'
              : 'That device will no longer be able to send or receive '
                  'messages. Its sessions are dropped, its unused prekeys are '
                  'deleted and its connection is closed immediately.\n\n'
                  'Its local message history stays on that machine until it is '
                  'opened again, at which point it destroys its own data.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(false),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(true),
            child: Text(
              'Revoke',
              style: TextStyle(color: dialogContext.bond.danger),
            ),
          ),
        ],
      ),
    );

    if (confirmed != true || !mounted) return;

    final controller = AppScope.read(context);
    final ok = await controller.revokeDevice(device.deviceId);
    if (!mounted) return;

    if (!ok) {
      final error = controller.lastError;
      if (error != null) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(error)),
        );
      }
      return;
    }

    if (isCurrent) {
      // The phase router takes over from here; this screen must not stay on
      // top of a destroyed session.
      Navigator.of(context).popUntil((route) => route.isFirst);
    } else {
      await _load();
    }
  }
}

class _DeviceCard extends StatelessWidget {
  const _DeviceCard({
    required this.device,
    required this.isCurrent,
    required this.onRevoke,
  });

  final OwnDevice device;
  final bool isCurrent;
  final VoidCallback onRevoke;

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
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Row(
            children: [
              Icon(
                device.isRevoked
                    ? Icons.phonelink_erase
                    : Icons.laptop_mac_outlined,
                size: 18,
                color: device.isRevoked ? colors.danger : colors.label,
              ),
              const SizedBox(width: BondSpacing.sm + 2),
              Expanded(child: Text(device.deviceName, style: text.titleSmall)),
              if (isCurrent)
                Container(
                  padding: const EdgeInsets.symmetric(
                    horizontal: 8,
                    vertical: 2,
                  ),
                  decoration: BoxDecoration(
                    color: colors.canvas,
                    borderRadius: BorderRadius.circular(BondRadius.pill),
                    border: Border.all(color: colors.separator, width: 0.5),
                  ),
                  child: Text('This device', style: text.labelSmall),
                ),
            ],
          ),
          const SizedBox(height: BondSpacing.md),
          _Row(label: 'Platform', value: device.platform),
          _Row(label: 'Protocol device id', value: '${device.deviceIndex}'),
          _Row(
            label: 'One-time prekeys left',
            value: '${device.availableOneTimePreKeys}',
          ),
          _Row(label: 'Registered', value: _shortDate(device.createdAt)),
          if (device.lastSeenAt != null)
            _Row(label: 'Last seen', value: _shortDate(device.lastSeenAt!)),
          if (device.isRevoked)
            _Row(label: 'Revoked', value: _shortDate(device.revokedAt!)),
          if (!device.isRevoked) ...[
            const SizedBox(height: BondSpacing.md),
            Align(
              alignment: Alignment.centerLeft,
              child: OutlinedButton(
                style: OutlinedButton.styleFrom(
                  foregroundColor: colors.danger,
                  side: BorderSide(
                    color: colors.danger.withValues(alpha: 0.35),
                    width: 0.5,
                  ),
                  padding: const EdgeInsets.symmetric(
                    horizontal: BondSpacing.lg,
                    vertical: 10,
                  ),
                ),
                onPressed: onRevoke,
                child: Text(isCurrent ? 'Revoke this device' : 'Revoke'),
              ),
            ),
          ],
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
      padding: const EdgeInsets.only(bottom: 5),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(width: 170, child: Text(label, style: text.labelSmall)),
          Expanded(
            child: Text(
              value,
              style: text.labelSmall?.copyWith(color: context.bond.label),
            ),
          ),
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
