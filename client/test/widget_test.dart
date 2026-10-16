/// Widget-level tests for the invariants a user could be misled by.
///
/// These run without a server. What they check is not layout but behaviour
/// that would be a security defect if it regressed:
///
///   * Startup FAILS VISIBLY when secure storage is unavailable, rather than
///     continuing with an unprotected database.
///   * The fatal screen offers no way to proceed anyway.
///   * Registration will not submit a password the server would reject, and
///     an invitation token is optional in the form but shaped when present.
///
/// The end-to-end behaviour — real sessions, real ciphertext, real delivery —
/// is covered by vertical_slice_test.dart against a live server, because
/// faking any of it here would prove nothing about the real thing.
library;

import 'dart:io';

import 'package:bond/core/app_controller.dart';
import 'package:bond/core/app_scope.dart';
import 'package:bond/core/theme.dart';
import 'package:bond/features/auth/auth_screen.dart';
import 'package:bond/main.dart';
import 'package:bond/services/storage/secure_key_store.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:path/path.dart' as p;

import 'support/fake_secure_key_store.dart';

late Directory tempDir;

void main() {
  setUpAll(() {
    tempDir = Directory.systemTemp.createTempSync('bond-widget-test');

    // A tap whose target sits outside the viewport only WARNS by default, so
    // the gesture silently goes nowhere and the assertions after it run
    // against an untouched form. That is exactly how the password case below
    // used to pass without validation ever running. Make it an error.
    WidgetController.hitTestWarningShouldBeFatal = true;
  });

  tearDownAll(() {
    try {
      tempDir.deleteSync(recursive: true);
    } on FileSystemException {
      // A held file handle on Windows must not fail the suite.
    }
  });

  String dbPath(String name) =>
      p.join(tempDir.path, '$name-${DateTime.now().microsecondsSinceEpoch}.db');

  group('startup fails closed', () {
    testWidgets(
      'an unavailable secure key store produces the fatal phase, not a '
      'working app on an unprotected database',
      (tester) async {
        final controller = AppController(
          keyStoreOverride: const UnavailableSecureKeyStore('test-platform'),
          databasePathOverride: dbPath('unavailable'),
        );
        addTearDown(controller.dispose);

        await controller.start();

        expect(controller.phase, AppPhase.fatal);
        expect(
          controller.fatalMessage,
          contains('refusing to store key material unprotected'),
        );
      },
    );

    testWidgets('the fatal screen offers no way to continue', (tester) async {
      final controller = AppController(
        keyStoreOverride: const UnavailableSecureKeyStore('test-platform'),
        databasePathOverride: dbPath('fatal-ui'),
      );
      addTearDown(controller.dispose);
      await controller.start();

      await tester.pumpWidget(_host(controller));
      await tester.pump();

      expect(find.text('Bond cannot start securely'), findsOneWidget);
      // No affordance to proceed: not a button, not a link, nothing.
      expect(find.byType(FilledButton), findsNothing);
      expect(find.byType(TextButton), findsNothing);
      expect(find.byType(OutlinedButton), findsNothing);
    });
  });

  group('cold start with working storage', () {
    testWidgets('lands on the auth screen when there is no session',
        (tester) async {
      final controller = AppController(
        keyStoreOverride: FakeSecureKeyStore(),
        databasePathOverride: dbPath('cold'),
      );
      addTearDown(controller.dispose);

      await controller.start();
      expect(controller.phase, AppPhase.needsAuth);

      await tester.pumpWidget(_host(controller));
      await tester.pump();

      expect(find.byType(AuthScreen), findsOneWidget);
      // The honest summary is on the first screen, not buried in a submenu.
      expect(
        find.textContaining('does not hide who you talk to'),
        findsOneWidget,
      );
    });
  });

  group('registration form', () {
    Future<void> pumpAuth(WidgetTester tester) async {
      final controller = AppController(
        keyStoreOverride: FakeSecureKeyStore(),
        databasePathOverride: dbPath('form'),
      );
      addTearDown(controller.dispose);
      await controller.start();
      await tester.pumpWidget(_host(controller));
      await tester.pump();
      await tester.tap(find.text('Register'));
      await tester.pumpAndSettle();
    }

    testWidgets('refuses a password shorter than the server would accept',
        (tester) async {
      await pumpAuth(tester);

      await tester.enterText(find.byType(TextFormField).at(0), 'alice');
      await tester.enterText(find.byType(TextFormField).at(1), 'short');
      await _submitRegistration(tester);

      // Worded differently from the field's helper text, so this can only
      // match if the validator actually ran.
      expect(
        find.text('Too short — use at least 12 characters'),
        findsOneWidget,
      );
    });

    testWidgets('refuses a username the server pattern would reject',
        (tester) async {
      await pumpAuth(tester);

      await tester.enterText(find.byType(TextFormField).at(0), 'no spaces!');
      await tester.enterText(
        find.byType(TextFormField).at(1),
        'a-sufficiently-long-password',
      );
      await _submitRegistration(tester);

      expect(
        find.text('Letters, digits and underscore only, 3–32 long'),
        findsOneWidget,
      );
    });

    testWidgets('rejects a malformed invitation token but allows an empty one',
        (tester) async {
      await pumpAuth(tester);

      await tester.enterText(find.byType(TextFormField).at(0), 'alice');
      await tester.enterText(
        find.byType(TextFormField).at(1),
        'a-sufficiently-long-password',
      );
      await tester.enterText(find.byType(TextFormField).at(2), 'too-short');
      await _submitRegistration(tester);

      expect(
        find.text('An invitation token is exactly 43 characters'),
        findsOneWidget,
      );

      // Empty is permitted by the form: the bootstrap path exists, and the
      // server is the thing that refuses it unless explicitly enabled.
      await tester.enterText(find.byType(TextFormField).at(2), '');
      await _submitRegistration(tester);

      expect(
        find.text('An invitation token is exactly 43 characters'),
        findsNothing,
      );
    });
  });
}

/// Scrolls the submit button into view, then taps it.
///
/// The form is taller than the default 600px test viewport, and an off-screen
/// tap does not fail on its own — it just misses. Every test that submits goes
/// through here so a layout change cannot quietly turn these into no-ops.
Future<void> _submitRegistration(WidgetTester tester) async {
  final button = find.widgetWithText(FilledButton, 'Register');
  await tester.ensureVisible(button);
  await tester.pumpAndSettle();
  await tester.tap(button);
  await tester.pumpAndSettle();
}

/// The real app shell and the real router, around a controller the test owns.
///
/// Using [PhaseRouter] rather than a copy of its logic matters: a test that
/// reimplemented the routing could pass while the app routed somewhere else.
Widget _host(AppController controller) => AppScope(
      controller: controller,
      child: MaterialApp(
        theme: bondTheme(Brightness.light),
        home: const PhaseRouter(),
      ),
    );
