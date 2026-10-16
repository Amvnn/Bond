/// Makes the [AppController] available to the widget tree.
///
/// An `InheritedNotifier` rather than a state-management package: the app has
/// exactly one controller and one kind of change notification, so a dependency
/// would add surface area without removing any.
library;

import 'package:flutter/widgets.dart';

import 'app_controller.dart';

class AppScope extends InheritedNotifier<AppController> {
  const AppScope({
    super.key,
    required AppController controller,
    required super.child,
  }) : super(notifier: controller);

  static AppController of(BuildContext context) {
    final scope = context.dependOnInheritedWidgetOfExactType<AppScope>();
    assert(scope?.notifier != null, 'No AppScope found in the widget tree');
    return scope!.notifier!;
  }

  /// For callbacks that need the controller without subscribing to rebuilds.
  static AppController read(BuildContext context) {
    final scope = context.getInheritedWidgetOfExactType<AppScope>();
    assert(scope?.notifier != null, 'No AppScope found in the widget tree');
    return scope!.notifier!;
  }
}
