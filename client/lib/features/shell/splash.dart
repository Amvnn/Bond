/// The launch animation: "Orbit".
///
/// A faithful port of the `orbit` demo from `Demo-testing/brand/splash-lab.html`,
/// which is the version that was chosen. The dot travels the full circle while
/// the ring appears behind it as a trail — the dot lays the channel, then
/// settles into the gap it left. It is the only one of the six where the mark
/// explains itself: an O, cut open, with one person let in.
///
/// WHY THE GEOMETRY IS SPELLED OUT RATHER THAN IMPORTED
///
/// The mark is drawn here with a painter instead of loading the SVG, because
/// the ring has to be drawn *progressively* and the dot has to orbit
/// independently of it. Both numbers come from one place — the construction
/// block in `brand/README.md` — and are restated in [_MarkGeometry] so a change
/// to the mark has exactly one place to land here.
///
/// TIMING
///
/// The durations and curves are the lab's, not approximations of them:
///
/// ```
/// ring draw     0ms → 1150ms   cubic-bezier(.45, .05, .2, 1)
/// dot orbit     0ms → 1150ms   same curve, 25° → 360°
/// dot pop in    0ms →  260ms   ease-out, 0 → 1.22 → 1
/// dot settle 1140ms → 1480ms   ease-out, 1 → 1.28 → 1
/// word rise  1450ms → 1900ms   ease-out, 11px up + fade
/// tagline    1750ms → 2150ms   ease-out, fade
/// ```
///
/// Everything after 2150ms is this file's own: a short hold so the finished
/// mark is actually seen, then an exit that scales up a touch as it fades —
/// the gesture iOS uses when an app opens out of its icon, and the reason the
/// handover to the first screen reads as one motion rather than a cut.
library;

import 'dart:math' as math;

import 'package:flutter/material.dart';

import '../../core/theme.dart';
import 'brand.dart';

/// The construction from `brand/README.md`, on its 64-unit grid.
abstract final class _MarkGeometry {
  static const double grid = 64;
  static const double centre = 32;
  static const double radius = 21;
  static const double stroke = 10.8;

  /// Exactly half the stroke width, per the spec.
  static const double dotRadius = 5.4;

  /// The ring runs from the gap's trailing edge clockwise to its leading one.
  ///
  /// Derived from the published path `M52.80 29.08 A21 21 0 1 1 41.86 13.46`:
  /// the start point sits at −8° from the centre and the end at −62°, so the
  /// drawn arc is the remaining 306° and the opening is the 54° between them.
  static const double startDegrees = -8;
  static const double sweepDegrees = 306;

  /// The dot rests in the middle of the opening, on the ring's centreline.
  static const double dotRestDegrees = -35;
}

/// Milestones, in milliseconds from the first frame.
abstract final class _T {
  static const int ringDraw = 1150;
  static const int dotPop = 260;
  static const int dotSettleStart = 1140;
  static const int dotSettleEnd = 1480;
  static const int wordStart = 1450;
  static const int wordEnd = 1900;
  static const int taglineStart = 1750;
  static const int taglineEnd = 2150;

  /// Beyond the lab: let the finished mark stand, then hand over.
  static const int holdEnd = 2420;
  static const int exitEnd = 2760;

  static const int total = exitEnd;
}

/// The lab's easing for the draw and the orbit.
const Curve _orbitCurve = Cubic(0.45, 0.05, 0.2, 1);

/// Plays the launch animation, then reveals [child].
///
/// The animation always runs to completion even when startup finishes sooner.
/// A splash that is cut off halfway reads as a glitch, and storage usually
/// opens in well under a second, so without this the animation would almost
/// never be seen whole.
class SplashGate extends StatefulWidget {
  const SplashGate({super.key, required this.child});

  final Widget child;

  @override
  State<SplashGate> createState() => _SplashGateState();
}

class _SplashGateState extends State<SplashGate> {
  bool _done = false;

  /// Drives the app's half of the handover.
  ///
  /// The splash lifting and the app arriving are ONE movement, so they share a
  /// clock. Cross-fading two independently-timed animations is what makes a
  /// launch feel like two events with a seam between them.
  double _handover = 0;

  @override
  Widget build(BuildContext context) {
    // The app rises the last of the way as the splash lifts off it: the iOS
    // app-open gesture, where the content you are going to is already there
    // and simply comes into focus.
    final eased = Curves.easeOutCubic.transform(_handover);

    return Stack(
      children: [
        // Built underneath from the start, so the app has finished laying out
        // by the time the splash lifts and the handover costs nothing.
        Opacity(
          opacity: _done ? 1 : eased,
          child: Transform.scale(
            scale: _done ? 1 : 0.96 + 0.04 * eased,
            child: widget.child,
          ),
        ),
        if (!_done)
          BondSplash(
            onHandover: (value) {
              if (value != _handover) setState(() => _handover = value);
            },
            onFinished: () => setState(() => _done = true),
          ),
      ],
    );
  }
}

class BondSplash extends StatefulWidget {
  const BondSplash({super.key, this.onFinished, this.onHandover});

  final VoidCallback? onFinished;

  /// 0 while the splash owns the screen, rising to 1 as it lifts. Lets the
  /// app underneath move on the same clock instead of starting its own.
  final ValueChanged<double>? onHandover;

  @override
  State<BondSplash> createState() => _BondSplashState();
}

class _BondSplashState extends State<BondSplash>
    with SingleTickerProviderStateMixin {
  late final AnimationController _controller = AnimationController(
    vsync: this,
    duration: const Duration(milliseconds: _T.total),
  );

  bool _reducedMotionApplied = false;

  @override
  void initState() {
    super.initState();
    _controller.addStatusListener((status) {
      if (status == AnimationStatus.completed) widget.onFinished?.call();
    });
    _controller.forward();
  }

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    // Honour the platform's reduced-motion setting: hold the finished mark for
    // a moment instead of animating it in. Someone who has asked the system to
    // stop moving things has asked this too.
    if (!_reducedMotionApplied &&
        MediaQuery.maybeDisableAnimationsOf(context) == true) {
      _reducedMotionApplied = true;
      _controller
        ..value = _progressAt(_T.taglineEnd)
        ..forward();
    }
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  /// Lets an impatient user through without making the animation feel like a
  /// toll gate. Not advertised — it is there for the four-hundredth launch.
  void _skip() {
    if (_controller.value >= _progressAt(_T.holdEnd)) return;
    _controller
      ..value = _progressAt(_T.holdEnd)
      ..forward();
  }

  static double _progressAt(int milliseconds) => milliseconds / _T.total;

  @override
  Widget build(BuildContext context) {
    final colors = context.bond;

    return AnimatedBuilder(
      animation: _controller,
      builder: (context, _) {
        final elapsed = _controller.value * _T.total;

        // The whole composition lifts and fades as it hands over.
        final exit = _span(elapsed, _T.holdEnd, _T.exitEnd);
        final exitEased = Curves.easeInOutCubic.transform(exit);

        // Report on the frame rather than from a listener, so the app's half
        // of the movement is computed from the same value in the same frame.
        if (widget.onHandover != null) {
          WidgetsBinding.instance.addPostFrameCallback(
            (_) => widget.onHandover?.call(exit),
          );
        }

        // Material, not a bare ColoredBox: Text outside a Material ancestor
        // falls back to Flutter's debug style and renders with a yellow
        // underline. It also gives the background a single owner, so the
        // splash and the canvas behind it cannot drift apart.
        return IgnorePointer(
          ignoring: exit > 0,
          child: Opacity(
            opacity: 1 - exitEased,
            child: GestureDetector(
              behavior: HitTestBehavior.opaque,
              onTap: _skip,
              child: Material(
                color: colors.canvas,
                child: Center(
                  child: Transform.scale(
                    // Lifts toward the viewer as it clears, so it reads as
                    // moving out of the way rather than dissolving.
                    scale: 1 + 0.06 * exitEased,
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        _Mark(elapsed: elapsed, size: 132),
                        const SizedBox(height: 26),
                        _Word(elapsed: elapsed),
                        const SizedBox(height: 14),
                        _Tagline(elapsed: elapsed, color: colors.label),
                      ],
                    ),
                  ),
                ),
              ),
            ),
          ),
        );
      },
    );
  }
}

class _Mark extends StatelessWidget {
  const _Mark({required this.elapsed, required this.size});

  final double elapsed;
  final double size;

  @override
  Widget build(BuildContext context) {
    final colors = context.bond;

    final drawProgress =
        _orbitCurve.transform(_span(elapsed, 0, _T.ringDraw));

    // 25° → 360°. The dot sets off from the ring's own starting edge and
    // arrives back in the gap exactly as the trail closes behind it.
    final orbitDegrees = 25 + (360 - 25) * drawProgress;

    return SizedBox(
      width: size,
      height: size,
      child: CustomPaint(
        painter: _MarkPainter(
          drawProgress: drawProgress,
          orbitDegrees: orbitDegrees,
          dotScale: _dotScale(elapsed),
          ringColor: colors.label,
          dotColor: BondPalette.flare,
          glow: _span(elapsed, _T.dotSettleStart, _T.exitEnd),
        ),
      ),
    );
  }

  /// Pop in, then a second smaller swell as it lands in the gap.
  static double _dotScale(double elapsed) {
    final settle = _span(elapsed, _T.dotSettleStart, _T.dotSettleEnd);
    if (settle > 0) {
      // 1 → 1.28 at 45% → 1
      final eased = Curves.easeOut.transform(settle);
      return eased < 0.45
          ? 1 + 0.28 * (eased / 0.45)
          : 1.28 - 0.28 * ((eased - 0.45) / 0.55);
    }

    final pop = Curves.easeOut.transform(_span(elapsed, 0, _T.dotPop));
    // 0 → 1.22 at 65% → 1
    return pop < 0.65
        ? 1.22 * (pop / 0.65)
        : 1.22 - 0.22 * ((pop - 0.65) / 0.35);
  }
}

class _MarkPainter extends CustomPainter {
  const _MarkPainter({
    required this.drawProgress,
    required this.orbitDegrees,
    required this.dotScale,
    required this.ringColor,
    required this.dotColor,
    required this.glow,
  });

  final double drawProgress;
  final double orbitDegrees;
  final double dotScale;
  final Color ringColor;
  final Color dotColor;
  final double glow;

  @override
  void paint(Canvas canvas, Size size) {
    final scale = size.width / _MarkGeometry.grid;
    final centre = Offset(
      _MarkGeometry.centre * scale,
      _MarkGeometry.centre * scale,
    );
    final radius = _MarkGeometry.radius * scale;

    // A soft bloom under the dot once it has landed. Barely visible by design:
    // it reads as the dot sitting in the opening rather than on top of it.
    if (glow > 0) {
      final dotCentre = _dotCentre(centre, radius);
      final glowRadius = _MarkGeometry.dotRadius * scale * 4.5;
      canvas.drawCircle(
        dotCentre,
        glowRadius,
        Paint()
          ..shader = RadialGradient(
            colors: [
              dotColor.withValues(alpha: 0.26 * glow),
              dotColor.withValues(alpha: 0),
            ],
          ).createShader(
            Rect.fromCircle(center: dotCentre, radius: glowRadius),
          ),
      );
    }

    // The ring. Drawn as a plain arc rather than a trimmed path: it IS a
    // circular arc, so sweeping the angle is both exact and far cheaper than
    // walking PathMetrics every frame.
    if (drawProgress > 0) {
      canvas.drawArc(
        Rect.fromCircle(center: centre, radius: radius),
        _radians(_MarkGeometry.startDegrees),
        _radians(_MarkGeometry.sweepDegrees) * drawProgress,
        false,
        Paint()
          ..style = PaintingStyle.stroke
          ..strokeWidth = _MarkGeometry.stroke * scale
          ..strokeCap = StrokeCap.round
          ..color = ringColor
          ..isAntiAlias = true,
      );
    }

    if (dotScale > 0) {
      canvas.drawCircle(
        _dotCentre(centre, radius),
        _MarkGeometry.dotRadius * scale * dotScale,
        Paint()
          ..color = dotColor
          ..isAntiAlias = true,
      );
    }
  }

  Offset _dotCentre(Offset centre, double radius) {
    final angle = _radians(_MarkGeometry.dotRestDegrees + orbitDegrees);
    return centre + Offset(math.cos(angle), math.sin(angle)) * radius;
  }

  static double _radians(double degrees) => degrees * math.pi / 180;

  @override
  bool shouldRepaint(_MarkPainter old) =>
      old.drawProgress != drawProgress ||
      old.orbitDegrees != orbitDegrees ||
      old.dotScale != dotScale ||
      old.glow != glow ||
      old.ringColor != ringColor;
}

/// The logotype, rising into place.
///
/// The real artwork rather than text: the O in BOND is the mark itself, and
/// setting the word in a font would put a plain letter where the logo goes —
/// the one thing `brand/README.md` says never to do.
class _Word extends StatelessWidget {
  const _Word({required this.elapsed});

  final double elapsed;

  @override
  Widget build(BuildContext context) {
    final progress =
        Curves.easeOut.transform(_span(elapsed, _T.wordStart, _T.wordEnd));

    return Opacity(
      opacity: progress,
      child: Transform.translate(
        offset: Offset(0, 11 * (1 - progress)),
        child: Image.asset(
          Theme.of(context).brightness == Brightness.dark
              ? 'assets/brand/bond-logotype-on-dark-1024w.png'
              : 'assets/brand/bond-logotype-1024w.png',
          width: 206,
          filterQuality: FilterQuality.medium,
          isAntiAlias: true,
          semanticLabel: 'Bond',
        ),
      ),
    );
  }
}

class _Tagline extends StatelessWidget {
  const _Tagline({required this.elapsed, required this.color});

  final double elapsed;
  final Color color;

  @override
  Widget build(BuildContext context) {
    final progress = Curves.easeOut
        .transform(_span(elapsed, _T.taglineStart, _T.taglineEnd));

    return Opacity(
      opacity: progress,
      child: BondTagline(color: color),
    );
  }
}

/// How far [elapsed] has travelled through the window [start]..[end], clamped.
double _span(double elapsed, int start, int end) {
  if (elapsed <= start) return 0;
  if (elapsed >= end) return 1;
  return (elapsed - start) / (end - start);
}
