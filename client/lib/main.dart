/// Bond — invite-only, end-to-end encrypted 1-to-1 messenger.
///
/// This file does three things and no more: start the controller, hold the
/// theme, and route on [AppPhase]. No cryptography, no network calls, no
/// storage — those live behind `services/`, and a widget reaching past that
/// boundary is a defect (docs/architecture.md section 3).
library;

import 'package:flutter/material.dart';

import 'core/app_controller.dart';
import 'core/app_scope.dart';
import 'core/theme.dart';
import 'features/auth/auth_screen.dart';
import 'features/devices/device_setup_screen.dart';
import 'features/messaging/conversations_screen.dart';
import 'features/shell/phase_screens.dart';
import 'features/shell/splash.dart';

void main() {
  runApp(const BondApp());
}

class BondApp extends StatefulWidget {
  const BondApp({super.key});

  @override
  State<BondApp> createState() => _BondAppState();
}

class _BondAppState extends State<BondApp> {
  late final AppController _controller;

  @override
  void initState() {
    super.initState();
    _controller = AppController();
    // Deliberately not awaited: the UI renders the `starting` phase while
    // local storage opens, and any failure lands in the `fatal` phase rather
    // than a silent hang.
    _controller.start();
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AppScope(
      controller: _controller,
      child: MaterialApp(
        title: 'Bond',
        debugShowCheckedModeBanner: false,
        theme: bondTheme(Brightness.light),
        darkTheme: bondTheme(Brightness.dark),
        scrollBehavior: const BondScrollBehavior(),
        // The launch animation covers the real UI while it builds, and lifts
        // once it has played through. Wrapping here rather than inside the
        // router keeps it a property of launching the app, not of being in any
        // particular phase.
        home: const SplashGate(child: PhaseRouter()),
      ),
    );
  }
}

/// Chooses a screen from the controller's phase, and nothing else.
///
/// Public so tests can exercise the real routing rather than a copy of it.
class PhaseRouter extends StatelessWidget {
  const PhaseRouter({super.key});

  @override
  Widget build(BuildContext context) {
    final controller = AppScope.of(context);

    final screen = switch (controller.phase) {
      AppPhase.starting => const SplashScreen(),
      AppPhase.needsAuth => const AuthScreen(),
      AppPhase.needsDevice => const DeviceSetupScreen(),
      AppPhase.ready => const ConversationsScreen(),
      AppPhase.revoked => const RevokedScreen(),
      AppPhase.fatal => FatalScreen(message: controller.fatalMessage ?? ''),
    };

    // A phase change is a whole-app change, so it cross-fades rather than
    // cutting. The short duration keeps it from feeling like a loading state;
    // the point is only to avoid a hard flash between two full screens.
    return AnimatedSwitcher(
      duration: const Duration(milliseconds: 280),
      switchInCurve: Curves.easeOutCubic,
      switchOutCurve: Curves.easeInCubic,
      child: KeyedSubtree(
        key: ValueKey<AppPhase>(controller.phase),
        child: screen,
      ),
    );
  }
}
