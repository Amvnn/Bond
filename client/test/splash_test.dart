/// Tests for the launch animation.
///
/// The interesting failure here is not that the animation looks wrong — a test
/// cannot judge that — but that it never ENDS. [SplashGate] covers the whole
/// app, so a controller that does not complete, or a completion callback that
/// is never wired up, leaves the user staring at a logo with no way through.
/// That is silent, total, and would survive every other test in the suite.
///
/// The rest of what is checked is the contract the animation has to keep: it
/// plays to the end even when startup was instant (a splash cut off halfway
/// reads as a glitch), it can be skipped by someone who has seen it four
/// hundred times, and it collapses to a brief hold when the platform asks for
/// reduced motion.
library;

import 'package:bond/features/shell/splash.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  /// Comfortably past the full timeline, so "did it finish" cannot be confused
  /// with "was the test too impatient".
  const beyondTheEnd = Duration(seconds: 6);

  group('SplashGate', () {
    testWidgets('reveals the app once the animation has played', (tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: SplashGate(child: Text('the app', textDirection: TextDirection.ltr)),
        ),
      );

      // The child is built underneath from the first frame — it has to be, or
      // the handover would stutter while the app lays itself out — but the
      // splash covers it.
      expect(find.byType(BondSplash), findsOneWidget);

      await tester.pump(const Duration(milliseconds: 500));
      expect(
        find.byType(BondSplash),
        findsOneWidget,
        reason: 'the splash ended early; a cut-off launch animation reads as a '
            'glitch rather than as speed',
      );

      await tester.pumpAndSettle(beyondTheEnd);

      expect(
        find.byType(BondSplash),
        findsNothing,
        reason: 'the splash never finished, so the app is unreachable behind it',
      );
      expect(find.text('the app'), findsOneWidget);
    });

    testWidgets('a tap skips to the handover', (tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: SplashGate(child: Text('the app', textDirection: TextDirection.ltr)),
        ),
      );

      await tester.pump(const Duration(milliseconds: 200));
      await tester.tap(find.byType(BondSplash));
      await tester.pumpAndSettle(beyondTheEnd);

      expect(find.byType(BondSplash), findsNothing);
    });

    testWidgets('reduced motion still reaches the app', (tester) async {
      await tester.pumpWidget(
        const MediaQuery(
          data: MediaQueryData(disableAnimations: true),
          child: MaterialApp(
            home: SplashGate(
              child: Text('the app', textDirection: TextDirection.ltr),
            ),
          ),
        ),
      );

      await tester.pumpAndSettle(beyondTheEnd);
      expect(find.byType(BondSplash), findsNothing);
      expect(find.text('the app'), findsOneWidget);
    });
  });

  group('BondSplash', () {
    testWidgets('reports completion exactly once', (tester) async {
      var finished = 0;

      await tester.pumpWidget(
        MaterialApp(home: BondSplash(onFinished: () => finished++)),
      );

      await tester.pumpAndSettle(beyondTheEnd);
      expect(finished, 1);
    });

    testWidgets('paints without throwing across the whole timeline',
        (tester) async {
      // Steps through the animation rather than jumping to the end: the
      // painter does different work in each phase — nothing drawn before the
      // ring starts, a partial arc while it draws, the glow only after the dot
      // lands — and a division or a shader built from a zero-size rect would
      // only show up inside one of them.
      await tester.pumpWidget(const MaterialApp(home: BondSplash()));

      for (var elapsed = 0; elapsed <= 3000; elapsed += 50) {
        await tester.pump(const Duration(milliseconds: 50));
        expect(tester.takeException(), isNull, reason: 'threw at ${elapsed}ms');
      }
    });
  });
}
