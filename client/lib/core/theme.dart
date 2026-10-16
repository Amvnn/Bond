/// Bond's design system.
///
/// Two influences, deliberately separated:
///
///   * **Apple** for the surface language — near-monochrome, hairline
///     separators, generous whitespace, large rounded rectangles, type that
///     carries hierarchy through weight and size rather than colour, and
///     physics that feel like the platform rather than like a web page.
///   * **WhatsApp** for the chat layout — a dense, scannable conversation list
///     and bubbles that get out of the way of the words.
///
/// ONE BRAND RULE IS LOAD-BEARING HERE
///
/// Flare (`#FF4D2E`) is the colour of the dot in the logo and of nothing else.
/// `brand/README.md` is explicit about it, and the reason is structural: the
/// mark is an O with a single dot resting in its opening, and that dot is the
/// whole idea — the one person let in. Spending the colour on buttons, badges
/// or links would make the logo's dot just another red thing on the screen.
///
/// So this palette is monochrome. Interactive emphasis comes from ink on paper
/// in light mode and white on near-black in dark mode, which is also why it
/// reads as Apple rather than as a generic Material app: contrast and spacing
/// do the work that colour usually does.
///
/// Destructive and warning states use Apple's system red (`#FF3B30`), NOT
/// Flare. They are close enough to be mistaken for each other at a glance,
/// which is exactly why they are kept apart in code: if an alert ever shares a
/// token with the logo, the next person to adjust one will silently change the
/// other.
library;

import 'package:flutter/cupertino.dart';
import 'package:flutter/gestures.dart' show PointerDeviceKind;
import 'package:flutter/material.dart';

/// The raw brand values from `brand/README.md`. Nothing outside this file
/// should reference a hex literal.
abstract final class BondPalette {
  /// The mark and the letters on light backgrounds.
  static const Color ink = Color(0xFF0B0B0C);

  /// The dot. ONLY the dot. See the library comment.
  static const Color flare = Color(0xFFFF4D2E);

  /// The light background.
  static const Color paper = Color(0xFFF6F7F9);

  static const Color white = Color(0xFFFFFFFF);
}

/// Semantic colours, resolved per brightness.
///
/// Screens read these rather than [BondPalette] so that a surface can be
/// retuned in one place. The greys are Apple's system greys, which are not
/// neutral — they carry a slight blue cast that keeps large dark areas from
/// looking muddy next to pure white text.
@immutable
class BondColors extends ThemeExtension<BondColors> {
  const BondColors({
    required this.canvas,
    required this.surface,
    required this.surfaceElevated,
    required this.separator,
    required this.label,
    required this.labelSecondary,
    required this.labelTertiary,
    required this.accent,
    required this.onAccent,
    required this.bubbleOutgoing,
    required this.onBubbleOutgoing,
    required this.bubbleIncoming,
    required this.onBubbleIncoming,
    required this.danger,
    required this.dangerSurface,
    required this.onDangerSurface,
    required this.success,
  });

  /// The window background.
  final Color canvas;

  /// Cards, sheets, the composer bar.
  final Color surface;

  /// A surface that needs to sit above another surface.
  final Color surfaceElevated;

  /// Hairline dividers. Apple's separators are translucent so they darken
  /// whatever is behind them rather than painting a fixed grey line.
  final Color separator;

  final Color label;
  final Color labelSecondary;
  final Color labelTertiary;

  /// Primary interactive colour. Monochrome by design — see the library note.
  final Color accent;
  final Color onAccent;

  final Color bubbleOutgoing;
  final Color onBubbleOutgoing;
  final Color bubbleIncoming;
  final Color onBubbleIncoming;

  /// Apple system red. Deliberately NOT [BondPalette.flare].
  final Color danger;
  final Color dangerSurface;
  final Color onDangerSurface;

  /// Used only for the verified state, where green is the near-universal
  /// convention and inventing something else would cost comprehension.
  final Color success;

  static const BondColors light = BondColors(
    canvas: BondPalette.paper,
    surface: BondPalette.white,
    surfaceElevated: BondPalette.white,
    separator: Color(0x1F0B0B0C),
    label: BondPalette.ink,
    labelSecondary: Color(0x990B0B0C),
    labelTertiary: Color(0x610B0B0C),
    accent: BondPalette.ink,
    onAccent: BondPalette.white,
    bubbleOutgoing: BondPalette.ink,
    onBubbleOutgoing: BondPalette.white,
    bubbleIncoming: BondPalette.white,
    onBubbleIncoming: BondPalette.ink,
    danger: Color(0xFFD70015),
    dangerSurface: Color(0xFFFFE9E7),
    onDangerSurface: Color(0xFF7A0C12),
    success: Color(0xFF248A3D),
  );

  static const BondColors dark = BondColors(
    canvas: BondPalette.ink,
    surface: Color(0xFF1C1C1E),
    surfaceElevated: Color(0xFF2C2C2E),
    separator: Color(0x26FFFFFF),
    label: BondPalette.white,
    labelSecondary: Color(0x99FFFFFF),
    labelTertiary: Color(0x61FFFFFF),
    accent: BondPalette.white,
    onAccent: BondPalette.ink,
    bubbleOutgoing: Color(0xFFE8E8EA),
    onBubbleOutgoing: BondPalette.ink,
    bubbleIncoming: Color(0xFF2C2C2E),
    onBubbleIncoming: BondPalette.white,
    danger: Color(0xFFFF453A),
    dangerSurface: Color(0xFF3A1714),
    onDangerSurface: Color(0xFFFFB4AB),
    success: Color(0xFF30D158),
  );

  @override
  BondColors copyWith() => this;

  @override
  BondColors lerp(ThemeExtension<BondColors>? other, double t) {
    if (other is! BondColors) return this;
    return t < 0.5 ? this : other;
  }

  /// Convenience accessor so widgets read `context.bond.label`.
  static BondColors of(BuildContext context) =>
      Theme.of(context).extension<BondColors>() ?? light;
}

extension BondThemeContext on BuildContext {
  BondColors get bond => BondColors.of(this);
}

/// Corner radii. Apple's are large and consistent; a single scale keeps the
/// whole app feeling like one surface rather than a pile of components.
abstract final class BondRadius {
  static const double small = 10;
  static const double medium = 14;
  static const double large = 20;
  static const double bubble = 20;

  /// Fully rounded, for pills and avatars.
  static const double pill = 999;
}

abstract final class BondSpacing {
  static const double xs = 4;
  static const double sm = 8;
  static const double md = 12;
  static const double lg = 16;
  static const double xl = 24;
  static const double xxl = 32;
}

/// Scroll physics with iOS rubber-banding on every platform.
///
/// Worth forcing rather than leaving to the platform default: the whole point
/// of this pass is that the app feels the same way everywhere, and Windows'
/// clamping scroll is the single biggest tell that it does not.
class BondScrollBehavior extends MaterialScrollBehavior {
  const BondScrollBehavior();

  @override
  ScrollPhysics getScrollPhysics(BuildContext context) =>
      const BouncingScrollPhysics(parent: AlwaysScrollableScrollPhysics());

  // Desktop needs mouse drag to scroll lists that have no visible scrollbar.
  @override
  Set<PointerDeviceKind> get dragDevices => PointerDeviceKind.values.toSet();

  @override
  Widget buildOverscrollIndicator(
    BuildContext context,
    Widget child,
    ScrollableDetails details,
  ) =>
      child; // The bounce IS the indicator; a glow on top of it looks wrong.
}

ThemeData bondTheme(Brightness brightness) {
  final isDark = brightness == Brightness.dark;
  final colors = isDark ? BondColors.dark : BondColors.light;

  // Monochrome by construction. The seed-based schemes Material generates
  // would reintroduce a hue, which is what this design is avoiding.
  final scheme = ColorScheme(
    brightness: brightness,
    primary: colors.accent,
    onPrimary: colors.onAccent,
    secondary: colors.accent,
    onSecondary: colors.onAccent,
    error: colors.danger,
    onError: BondPalette.white,
    surface: colors.surface,
    onSurface: colors.label,
    surfaceContainerHighest: colors.surfaceElevated,
    outline: colors.labelTertiary,
    outlineVariant: colors.separator,
  );

  final text = _textTheme(colors);

  return ThemeData(
    useMaterial3: true,
    brightness: brightness,
    colorScheme: scheme,
    scaffoldBackgroundColor: colors.canvas,
    canvasColor: colors.canvas,
    splashFactory: NoSplash.splashFactory,
    // Material's ink ripple is the loudest non-Apple thing in a Flutter app.
    // Removing it leaves the subtle opacity change that iOS uses.
    highlightColor: colors.separator,
    hoverColor: colors.separator.withValues(alpha: 0.04),
    dividerColor: colors.separator,
    textTheme: text,
    fontFamily: _uiFontFamily,
    extensions: <ThemeExtension<dynamic>>[colors],

    // Cupertino page transitions everywhere, including Windows: the slide-and-
    // parallax push is a large part of why iOS navigation feels continuous.
    pageTransitionsTheme: const PageTransitionsTheme(
      builders: <TargetPlatform, PageTransitionsBuilder>{
        TargetPlatform.windows: CupertinoPageTransitionsBuilder(),
        TargetPlatform.linux: CupertinoPageTransitionsBuilder(),
        TargetPlatform.macOS: CupertinoPageTransitionsBuilder(),
        TargetPlatform.iOS: CupertinoPageTransitionsBuilder(),
        TargetPlatform.android: CupertinoPageTransitionsBuilder(),
      },
    ),

    appBarTheme: AppBarTheme(
      backgroundColor: colors.canvas,
      foregroundColor: colors.label,
      surfaceTintColor: Colors.transparent,
      elevation: 0,
      scrolledUnderElevation: 0,
      centerTitle: false,
      titleTextStyle: text.titleMedium,
      iconTheme: IconThemeData(color: colors.label, size: 22),
    ),

    dividerTheme: DividerThemeData(
      color: colors.separator,
      thickness: 0.5,
      space: 0.5,
    ),

    cardTheme: CardThemeData(
      color: colors.surface,
      surfaceTintColor: Colors.transparent,
      elevation: 0,
      margin: EdgeInsets.zero,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(BondRadius.large),
      ),
    ),

    filledButtonTheme: FilledButtonThemeData(
      style: ButtonStyle(
        backgroundColor: WidgetStateProperty.resolveWith((states) =>
            states.contains(WidgetState.disabled)
                ? colors.accent.withValues(alpha: 0.3)
                : colors.accent),
        foregroundColor: WidgetStatePropertyAll(colors.onAccent),
        elevation: const WidgetStatePropertyAll(0),
        padding: const WidgetStatePropertyAll(
          EdgeInsets.symmetric(horizontal: BondSpacing.xl, vertical: 16),
        ),
        shape: WidgetStatePropertyAll(
          RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(BondRadius.medium),
          ),
        ),
        textStyle: WidgetStatePropertyAll(text.labelLarge),
      ),
    ),

    outlinedButtonTheme: OutlinedButtonThemeData(
      style: ButtonStyle(
        foregroundColor: WidgetStatePropertyAll(colors.label),
        side: WidgetStatePropertyAll(
          BorderSide(color: colors.separator, width: 0.5),
        ),
        padding: const WidgetStatePropertyAll(
          EdgeInsets.symmetric(horizontal: BondSpacing.lg, vertical: 14),
        ),
        shape: WidgetStatePropertyAll(
          RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(BondRadius.medium),
          ),
        ),
        textStyle: WidgetStatePropertyAll(text.labelLarge),
      ),
    ),

    textButtonTheme: TextButtonThemeData(
      style: ButtonStyle(
        foregroundColor: WidgetStatePropertyAll(colors.label),
        textStyle: WidgetStatePropertyAll(text.labelLarge),
        shape: WidgetStatePropertyAll(
          RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(BondRadius.small),
          ),
        ),
      ),
    ),

    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: colors.surface,
      contentPadding: const EdgeInsets.symmetric(
        horizontal: BondSpacing.lg,
        vertical: 16,
      ),
      hintStyle: text.bodyMedium?.copyWith(color: colors.labelTertiary),
      helperStyle: text.bodySmall?.copyWith(color: colors.labelSecondary),
      helperMaxLines: 3,
      errorStyle: text.bodySmall?.copyWith(color: colors.danger),
      errorMaxLines: 3,
      border: _inputBorder(colors.separator),
      enabledBorder: _inputBorder(colors.separator),
      focusedBorder: _inputBorder(colors.accent, width: 1.5),
      errorBorder: _inputBorder(colors.danger),
      focusedErrorBorder: _inputBorder(colors.danger, width: 1.5),
    ),

    snackBarTheme: SnackBarThemeData(
      backgroundColor: colors.surfaceElevated,
      contentTextStyle: text.bodyMedium?.copyWith(color: colors.label),
      behavior: SnackBarBehavior.floating,
      elevation: 0,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(BondRadius.medium),
      ),
    ),

    dialogTheme: DialogThemeData(
      backgroundColor: colors.surfaceElevated,
      surfaceTintColor: Colors.transparent,
      elevation: 0,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(BondRadius.large),
      ),
      titleTextStyle: text.titleMedium,
      contentTextStyle: text.bodyMedium?.copyWith(color: colors.labelSecondary),
    ),

    listTileTheme: ListTileThemeData(
      iconColor: colors.labelSecondary,
      textColor: colors.label,
      contentPadding: const EdgeInsets.symmetric(
        horizontal: BondSpacing.lg,
        vertical: BondSpacing.xs,
      ),
    ),

    segmentedButtonTheme: SegmentedButtonThemeData(
      style: ButtonStyle(
        backgroundColor: WidgetStateProperty.resolveWith((states) =>
            states.contains(WidgetState.selected)
                ? colors.surface
                : Colors.transparent),
        foregroundColor: WidgetStatePropertyAll(colors.label),
        side: WidgetStatePropertyAll(BorderSide(color: colors.separator)),
        textStyle: WidgetStatePropertyAll(text.labelMedium),
        shape: WidgetStatePropertyAll(
          RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(BondRadius.small),
          ),
        ),
      ),
    ),

    progressIndicatorTheme: ProgressIndicatorThemeData(
      color: colors.labelSecondary,
      linearTrackColor: colors.separator,
      circularTrackColor: Colors.transparent,
    ),

    tooltipTheme: TooltipThemeData(
      decoration: BoxDecoration(
        color: colors.surfaceElevated,
        borderRadius: BorderRadius.circular(BondRadius.small),
        border: Border.all(color: colors.separator, width: 0.5),
      ),
      textStyle: text.bodySmall?.copyWith(color: colors.label),
    ),
  );
}

/// Windows has no SF Pro, and Apple's fonts are not redistributable.
///
/// Segoe UI Variable is the closest native match on Windows 11: a humanist
/// sans with similar proportions and good optical sizing. Naming it explicitly
/// rather than letting Flutter pick Roboto matters — Roboto's narrower,
/// more geometric letterforms are what make a Flutter app look like Android no
/// matter how it is styled.
const String _uiFontFamily = 'Segoe UI Variable Display';

/// Apple's type scale, which leans on weight and tight tracking rather than
/// many sizes. Negative letter spacing on the large sizes is most of what
/// makes headings read as iOS rather than as Material.
TextTheme _textTheme(BondColors colors) {
  TextStyle style(
    double size,
    FontWeight weight, {
    double tracking = 0,
    double? height,
    Color? color,
  }) =>
      TextStyle(
        fontSize: size,
        fontWeight: weight,
        letterSpacing: tracking,
        height: height,
        color: color ?? colors.label,
      );

  return TextTheme(
    displaySmall: style(34, FontWeight.w700, tracking: -0.8, height: 1.1),
    headlineMedium: style(28, FontWeight.w700, tracking: -0.6, height: 1.15),
    headlineSmall: style(22, FontWeight.w700, tracking: -0.4, height: 1.2),
    titleLarge: style(20, FontWeight.w600, tracking: -0.3),
    titleMedium: style(17, FontWeight.w600, tracking: -0.2),
    titleSmall: style(15, FontWeight.w600, tracking: -0.1),
    bodyLarge: style(17, FontWeight.w400, tracking: -0.2, height: 1.35),
    bodyMedium: style(15, FontWeight.w400, tracking: -0.1, height: 1.4),
    bodySmall: style(13, FontWeight.w400, height: 1.35, color: colors.labelSecondary),
    labelLarge: style(16, FontWeight.w600, tracking: -0.2),
    labelMedium: style(14, FontWeight.w500),
    labelSmall: style(12, FontWeight.w500, color: colors.labelSecondary),
  );
}

OutlineInputBorder _inputBorder(Color color, {double width = 0.5}) =>
    OutlineInputBorder(
      borderRadius: BorderRadius.circular(BondRadius.medium),
      borderSide: BorderSide(color: color, width: width),
    );
