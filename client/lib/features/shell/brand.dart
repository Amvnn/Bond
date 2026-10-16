/// The logo, as widgets that cannot be misused.
///
/// The rules in `brand/README.md` are encoded here rather than left to each
/// call site, because the ways a logo gets damaged are all small and local:
/// someone stretches it to fill a box, puts it at 40px where the tagline stops
/// being legible, crops the clear space to save a few pixels, or uses the
/// light artwork on a dark background and gets black letters on black.
///
///   * **Aspect ratio is fixed.** Logotype 3.8554:1, lockup 2.5062:1, mark
///     square. Callers give a width; height follows.
///   * **Minimum widths are enforced** by clamping, not by asserting: a logo
///     that quietly grows to its floor is better than a crash in a release
///     build, and better than a logo too small to read.
///   * **Clear space** is one ring stroke on every side, which is the dot's
///     diameter — 0.1455em of the logotype's cap height. It is baked into the
///     padding so nothing can sit inside the margin.
///   * **The artwork follows the theme brightness**, so the on-dark cut is
///     used on dark surfaces without the caller having to remember.
///
/// The red dot lives inside these images and nowhere else in the app. See the
/// note at the top of `core/theme.dart`.
library;

import 'package:flutter/material.dart';

/// Proportions and floors, straight from `brand/README.md`.
abstract final class _Brand {
  static const double logotypeRatio = 3.8554;
  static const double lockupRatio = 2.5062;

  static const double logotypeMinWidth = 96;
  static const double lockupMinWidth = 160;
  static const double markMinSize = 24;

  /// Clear space as a fraction of the asset's width. One stroke width of the
  /// ring; for the logotype that is the ring stroke relative to the full
  /// lockup width.
  static const double clearSpaceFraction = 0.038;
}

/// The full name. The default wherever there is room for a word.
class BondLogotype extends StatelessWidget {
  const BondLogotype({
    super.key,
    this.width = 180,
    this.semanticLabel = 'Bond',
    this.bare = false,
  });

  final double width;
  final String semanticLabel;

  /// Skips the clear-space padding. Only for compositions that reserve the
  /// margin themselves — [BondLockup] does, and nesting the two would double
  /// the gap between the logotype and its tagline.
  final bool bare;

  @override
  Widget build(BuildContext context) {
    final effective = width < _Brand.logotypeMinWidth
        ? _Brand.logotypeMinWidth
        : width;
    final onDark = Theme.of(context).brightness == Brightness.dark;

    final image = Image.asset(
        onDark
            ? 'assets/brand/bond-logotype-on-dark-1024w.png'
            : 'assets/brand/bond-logotype-1024w.png',
        width: effective,
        height: effective / _Brand.logotypeRatio,
        // The asset is far larger than any on-screen size, so quality here is
        // entirely about the downscale filter.
      filterQuality: FilterQuality.medium,
      isAntiAlias: true,
      semanticLabel: semanticLabel,
    );

    return bare ? image : _ClearSpace(width: effective, child: image);
  }
}

/// The product's tagline, in the brand's tagline treatment.
///
/// Uppercase with 0.20em tracking, per `brand/README.md`. No terminal full
/// stop: at this tracking a period floats as a separate speck, and a stray dot
/// beside a logo whose entire idea IS a single dot is the one ambiguity this
/// mark cannot afford.
const String bondTagline = 'ONLY YOUR CIRCLE';

/// Logotype plus the tagline.
///
/// COMPOSED rather than drawn from `bond-lockup-*.png`, because that artwork
/// has the older "INVITE ONLY" wording baked into its outlines. Building the
/// lockup from the logotype plus live text means the tagline is a string in one
/// place instead of a render in four files — and it keeps the two in step when
/// the wording changes again.
///
/// The proportions still match the published lockup: 2.5062:1 overall against
/// the logotype's 3.8554:1 leaves 0.1396 of the width for the gap and the
/// tagline, which is what the sizes below divide up.
class BondLockup extends StatelessWidget {
  const BondLockup({super.key, this.width = 260, this.taglineColor});

  final double width;

  /// Defaults to the logotype's own ink, which is what the artwork uses.
  final Color? taglineColor;

  @override
  Widget build(BuildContext context) {
    final effective =
        width < _Brand.lockupMinWidth ? _Brand.lockupMinWidth : width;
    final onDark = Theme.of(context).brightness == Brightness.dark;

    return _ClearSpace(
      width: effective,
      child: Builder(
        builder: (context) {
          // What the published lockup leaves below the logotype, derived from
          // the two ratios rather than guessed: at 2.5062:1 overall and
          // 3.8554:1 for the logotype, this is the band the gap and the
          // tagline share.
          final band =
              effective * (1 / _Brand.lockupRatio - 1 / _Brand.logotypeRatio);

          return Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              BondLogotype(width: effective, bare: true),
              SizedBox(height: band * 0.40),
              BondTagline(
                // The rest of the band is the tagline's line box, which is
                // taller than its glyphs; 0.35 leaves that slack.
                fontSize: band * 0.35,
                color: taglineColor ??
                    (onDark
                        ? const Color(0xFFFFFFFF)
                        : const Color(0xFF0B0B0C)),
              ),
            ],
          );
        },
      ),
    );
  }
}

/// The tagline on its own, for layouts that time it separately from the
/// logotype — the launch animation, for one.
class BondTagline extends StatelessWidget {
  const BondTagline({super.key, required this.color, this.fontSize = 10.5});

  final Color color;
  final double fontSize;

  @override
  Widget build(BuildContext context) => Text(
        bondTagline,
        textAlign: TextAlign.center,
        style: TextStyle(
          color: color,
          fontSize: fontSize,
          fontWeight: FontWeight.w500,
          letterSpacing: fontSize * 0.2,
          // The tracking is applied to the right of every glyph including the
          // last, which optically shifts a centred line left. Half of it back
          // as padding re-centres it.
          height: 1.2,
        ),
      );
}

/// The mark alone.
///
/// Only where the name is already established or obviously nearby — the brand
/// guide is specific about this, and an app window titled "Bond" qualifies.
class BondMark extends StatelessWidget {
  const BondMark({super.key, this.size = 28});

  final double size;

  @override
  Widget build(BuildContext context) {
    final effective = size < _Brand.markMinSize ? _Brand.markMinSize : size;
    final onDark = Theme.of(context).brightness == Brightness.dark;

    return Image.asset(
      onDark
          ? 'assets/brand/bond-mark-on-dark-256.png'
          : 'assets/brand/bond-mark-256.png',
      width: effective,
      height: effective,
      filterQuality: FilterQuality.medium,
      isAntiAlias: true,
      semanticLabel: 'Bond',
    );
  }
}

/// Reserves the margin the brand guide requires on all four sides.
class _ClearSpace extends StatelessWidget {
  const _ClearSpace({required this.width, required this.child});

  final double width;
  final Widget child;

  @override
  Widget build(BuildContext context) => Padding(
        padding: EdgeInsets.all(width * _Brand.clearSpaceFraction),
        child: child,
      );
}
