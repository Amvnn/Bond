/// Register or sign in.
///
/// Registration is invite-controlled: there is no public sign-up, and no way to
/// look up another user. The invitation field is therefore not optional in
/// normal operation — it is omitted only for the env-gated bootstrap account,
/// which the server will refuse unless it is explicitly enabled.
///
/// The field constraints mirror the server's schema exactly. Validating here is
/// a courtesy to the user, not a security control: the server revalidates
/// everything and is the only authority.
library;

import 'package:flutter/material.dart';

import '../../core/app_scope.dart';
import '../../core/theme.dart';
import '../shell/brand.dart';

class AuthScreen extends StatefulWidget {
  const AuthScreen({super.key});

  @override
  State<AuthScreen> createState() => _AuthScreenState();
}

class _AuthScreenState extends State<AuthScreen> {
  final _formKey = GlobalKey<FormState>();
  final _username = TextEditingController();
  final _password = TextEditingController();
  final _invitation = TextEditingController();

  bool _registering = false;
  bool _obscure = true;

  @override
  void dispose() {
    _username.dispose();
    _password.dispose();
    _invitation.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    if (!_formKey.currentState!.validate()) return;
    final controller = AppScope.read(context);

    final ok = _registering
        ? await controller.register(
            username: _username.text.trim(),
            password: _password.text,
            invitationToken: _invitation.text.trim(),
          )
        : await controller.login(
            username: _username.text.trim(),
            password: _password.text,
          );

    if (!ok && mounted) {
      // Clear the password on failure so a retry cannot submit a stale value,
      // and so it does not sit in a controller longer than needed.
      _password.clear();
    }
  }

  @override
  Widget build(BuildContext context) {
    final controller = AppScope.of(context);
    final colors = context.bond;
    final text = Theme.of(context).textTheme;
    final error = controller.lastError;

    return Scaffold(
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.symmetric(
            horizontal: BondSpacing.xl,
            vertical: BondSpacing.xxl,
          ),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 400),
            child: Form(
              key: _formKey,
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  const Center(child: BondLockup(width: 216)),
                  const SizedBox(height: BondSpacing.xxl + BondSpacing.sm),

                  // A segmented control rather than tabs or a link: two
                  // mutually exclusive modes of one form is exactly what it is
                  // for, and it keeps the form from jumping position.
                  Center(
                    child: SegmentedButton<bool>(
                      segments: const [
                        ButtonSegment(value: false, label: Text('Sign in')),
                        ButtonSegment(value: true, label: Text('Register')),
                      ],
                      selected: {_registering},
                      showSelectedIcon: false,
                      onSelectionChanged: (selection) {
                        setState(() => _registering = selection.first);
                        controller.clearError();
                      },
                    ),
                  ),
                  const SizedBox(height: BondSpacing.xl),

                  _Field(
                    controller: _username,
                    label: 'Username',
                    helper: '3–32 characters: letters, digits, underscore',
                    autofocus: true,
                    textInputAction: TextInputAction.next,
                    validator: (value) {
                      final v = (value ?? '').trim();
                      if (v.isEmpty) return 'Required';
                      if (!RegExp(r'^[A-Za-z0-9_]{3,32}$').hasMatch(v)) {
                        return 'Letters, digits and underscore only, 3–32 long';
                      }
                      return null;
                    },
                  ),
                  const SizedBox(height: BondSpacing.lg),

                  _Field(
                    controller: _password,
                    label: 'Password',
                    helper: _registering ? 'At least 12 characters' : null,
                    obscureText: _obscure,
                    textInputAction: _registering
                        ? TextInputAction.next
                        : TextInputAction.done,
                    onSubmitted: (_) => _submit(),
                    suffix: IconButton(
                      icon: Icon(
                        _obscure
                            ? Icons.visibility_outlined
                            : Icons.visibility_off_outlined,
                        size: 20,
                        color: colors.labelSecondary,
                      ),
                      onPressed: () => setState(() => _obscure = !_obscure),
                      tooltip: _obscure ? 'Show password' : 'Hide password',
                    ),
                    validator: (value) {
                      final v = value ?? '';
                      if (v.isEmpty) return 'Required';
                      // Only enforced on registration: an existing account may
                      // predate the rule, and the server decides regardless.
                      //
                      // Worded differently from the helper above on purpose.
                      // When the two matched, a test asserting on the message
                      // passed whether or not validation had actually run.
                      if (_registering && v.length < 12) {
                        return 'Too short — use at least 12 characters';
                      }
                      if (v.length > 256) return 'At most 256 characters';
                      return null;
                    },
                  ),

                  // Animated so switching modes slides the field in rather
                  // than making the button jump down a row.
                  AnimatedSize(
                    duration: const Duration(milliseconds: 220),
                    curve: Curves.easeOutCubic,
                    alignment: Alignment.topCenter,
                    child: _registering
                        ? Padding(
                            padding: const EdgeInsets.only(top: BondSpacing.lg),
                            child: _Field(
                              controller: _invitation,
                              label: 'Invitation token',
                              helper: 'From someone who already uses Bond. '
                                  'Leave empty only for the first account on a '
                                  'new server.',
                              textInputAction: TextInputAction.done,
                              onSubmitted: (_) => _submit(),
                              validator: (value) {
                                final v = (value ?? '').trim();
                                // Empty is allowed: the bootstrap path. The
                                // server refuses it unless explicitly enabled,
                                // which is the control that matters.
                                if (v.isEmpty) return null;
                                if (v.length != 43) {
                                  return 'An invitation token is exactly 43 '
                                      'characters';
                                }
                                if (!RegExp(r'^[A-Za-z0-9_-]+$').hasMatch(v)) {
                                  return 'That does not look like an '
                                      'invitation token';
                                }
                                return null;
                              },
                            ),
                          )
                        : const SizedBox(width: double.infinity),
                  ),

                  AnimatedSize(
                    duration: const Duration(milliseconds: 200),
                    curve: Curves.easeOutCubic,
                    alignment: Alignment.topCenter,
                    child: error == null
                        ? const SizedBox(width: double.infinity)
                        : Padding(
                            padding: const EdgeInsets.only(top: BondSpacing.lg),
                            child: _ErrorBanner(message: error),
                          ),
                  ),

                  const SizedBox(height: BondSpacing.xl),
                  FilledButton(
                    onPressed: controller.busy ? null : _submit,
                    child: controller.busy
                        ? SizedBox(
                            width: 18,
                            height: 18,
                            child: CircularProgressIndicator(
                              strokeWidth: 2,
                              color: colors.onAccent,
                            ),
                          )
                        : Text(_registering ? 'Register' : 'Sign in'),
                  ),

                  const SizedBox(height: BondSpacing.xl),
                  Text(
                    'Bond protects message content from the server. It does '
                    'not hide who you talk to, when, or how often.',
                    textAlign: TextAlign.center,
                    style: text.bodySmall?.copyWith(
                      color: colors.labelTertiary,
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

/// A labelled field in the house style.
///
/// The label sits above the field rather than floating inside it: a floating
/// label animating on focus is a Material signature, and it also means the
/// field's purpose disappears once it has content.
class _Field extends StatelessWidget {
  const _Field({
    required this.controller,
    required this.label,
    required this.validator,
    this.helper,
    this.obscureText = false,
    this.autofocus = false,
    this.textInputAction,
    this.onSubmitted,
    this.suffix,
  });

  final TextEditingController controller;
  final String label;
  final String? helper;
  final String? Function(String?) validator;
  final bool obscureText;
  final bool autofocus;
  final TextInputAction? textInputAction;
  final void Function(String)? onSubmitted;
  final Widget? suffix;

  @override
  Widget build(BuildContext context) {
    final colors = context.bond;
    final text = Theme.of(context).textTheme;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Padding(
          padding: const EdgeInsets.only(left: 2, bottom: 6),
          child: Text(
            label,
            style: text.labelMedium?.copyWith(color: colors.labelSecondary),
          ),
        ),
        TextFormField(
          controller: controller,
          obscureText: obscureText,
          autofocus: autofocus,
          textInputAction: textInputAction,
          onFieldSubmitted: onSubmitted,
          validator: validator,
          style: text.bodyLarge,
          decoration: InputDecoration(
            helperText: helper,
            suffixIcon: suffix,
          ),
        ),
      ],
    );
  }
}

class _ErrorBanner extends StatelessWidget {
  const _ErrorBanner({required this.message});

  final String message;

  @override
  Widget build(BuildContext context) {
    final colors = context.bond;
    return Container(
      padding: const EdgeInsets.all(BondSpacing.md),
      decoration: BoxDecoration(
        color: colors.dangerSurface,
        borderRadius: BorderRadius.circular(BondRadius.medium),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(Icons.error_outline, size: 18, color: colors.danger),
          const SizedBox(width: BondSpacing.sm + 2),
          Expanded(
            child: Text(
              message,
              style: Theme.of(context)
                  .textTheme
                  .bodySmall
                  ?.copyWith(color: colors.onDangerSurface),
            ),
          ),
        ],
      ),
    );
  }
}
