/// Layout rules for a window that can be any width.
///
/// THE PROBLEM THESE SOLVE
///
/// A phone layout run at 1900px is not a phone layout scaled up — it is a
/// broken one. Cards stretch edge to edge, buttons become metre-wide slabs,
/// and a line of text runs so far that the eye loses its place returning to
/// the next one. Nothing about it is wrong at 400px, which is exactly why it
/// survives until someone maximises the window.
///
/// So width is capped by PURPOSE rather than filled by default:
///
///   * Reading and filling in forms has an optimal measure — roughly 60-75
///     characters — and more width past that actively hurts.
///   * A conversation wants to stay near the centre of attention, not spread
///     across a monitor.
///   * A list of contacts is a navigation surface. On a wide window it belongs
///     beside the conversation, not stacked in front of it, which is why every
///     desktop messenger worth using is two panes.
library;

import 'package:flutter/material.dart';

import '../../core/theme.dart';

abstract final class BondLayout {
  /// Forms and prose. Around 65 characters at this type size.
  static const double readable = 460;

  /// Settings-style pages: cards of label/value rows, which tolerate a little
  /// more width than prose before they start to feel sparse.
  static const double content = 620;

  /// A conversation column. Wider than prose because bubbles are short and
  /// alternate sides, but nowhere near the full window.
  static const double conversation = 720;

  /// The widest a single message bubble may be, regardless of the column.
  static const double bubble = 520;

  /// The contact list when it sits beside a conversation.
  static const double listPane = 340;

  /// Below this the two panes would both be cramped, so the app falls back to
  /// pushing the conversation over the list.
  static const double twoPaneBreakpoint = 900;
}

/// A scrollable page whose content stops growing at [maxWidth].
///
/// The scroll view stays full-bleed so the scrollbar sits at the window edge
/// where it belongs; only the content inside is constrained.
class BondPage extends StatelessWidget {
  const BondPage({
    super.key,
    required this.children,
    this.maxWidth = BondLayout.content,
    this.padding = const EdgeInsets.fromLTRB(
      BondSpacing.lg,
      BondSpacing.sm,
      BondSpacing.lg,
      BondSpacing.xxl,
    ),
  });

  final List<Widget> children;
  final double maxWidth;
  final EdgeInsets padding;

  @override
  Widget build(BuildContext context) => Align(
        alignment: Alignment.topCenter,
        child: ConstrainedBox(
          constraints: BoxConstraints(maxWidth: maxWidth + padding.horizontal),
          child: ListView(padding: padding, children: children),
        ),
      );
}

/// Centres a non-scrolling block, for screens that are a single statement.
class BondCentered extends StatelessWidget {
  const BondCentered({
    super.key,
    required this.child,
    this.maxWidth = BondLayout.readable,
  });

  final Widget child;
  final double maxWidth;

  @override
  Widget build(BuildContext context) => Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.symmetric(
            horizontal: BondSpacing.xl,
            vertical: BondSpacing.xxl,
          ),
          child: ConstrainedBox(
            constraints: BoxConstraints(maxWidth: maxWidth),
            child: child,
          ),
        ),
      );
}

/// A card in the house style: surface, hairline border, large radius.
///
/// Used everywhere instead of Material's `Card` so elevation never creeps in —
/// this design separates surfaces with a 0.5px line, not a shadow.
class BondCard extends StatelessWidget {
  const BondCard({
    super.key,
    required this.child,
    this.padding = const EdgeInsets.all(BondSpacing.lg),
    this.accent,
  });

  final Widget child;
  final EdgeInsets padding;

  /// A 2.5px rule down the left edge. Used sparingly, so it keeps meaning.
  final Color? accent;

  @override
  Widget build(BuildContext context) {
    final colors = context.bond;
    return Container(
      decoration: BoxDecoration(
        color: colors.surface,
        borderRadius: BorderRadius.circular(BondRadius.large),
        border: Border.all(color: colors.separator, width: 0.5),
      ),
      clipBehavior: Clip.antiAlias,
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          if (accent != null) Container(width: 2.5, color: accent),
          Expanded(child: Padding(padding: padding, child: child)),
        ],
      ),
    );
  }
}

/// True when there is room to show the contact list and a conversation at once.
bool usesTwoPanes(BuildContext context) =>
    MediaQuery.sizeOf(context).width >= BondLayout.twoPaneBreakpoint;
