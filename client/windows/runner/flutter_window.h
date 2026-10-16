#ifndef RUNNER_FLUTTER_WINDOW_H_
#define RUNNER_FLUTTER_WINDOW_H_

#include <flutter/dart_project.h>
#include <flutter/flutter_view_controller.h>

#include <memory>

#include "win32_window.h"

// A window that does nothing but host a Flutter view.
class FlutterWindow : public Win32Window {
 public:
  // Creates a new FlutterWindow hosting a Flutter view running |project|.
  explicit FlutterWindow(const flutter::DartProject& project);
  virtual ~FlutterWindow();

  // Adopts the pre-splash window put up before the engine started, so it can
  // be retired at the exact moment this window becomes visible. See the
  // comment on ShowPreSplash in main.cpp for why it exists.
  //
  // Must be called before Create(), which registers the first-frame callback
  // that retires it.
  void SetPreSplash(HWND window) { pre_splash_ = window; }

 protected:
  // Win32Window:
  bool OnCreate() override;
  void OnDestroy() override;
  LRESULT MessageHandler(HWND window, UINT const message, WPARAM const wparam,
                         LPARAM const lparam) noexcept override;

 private:
  // The project to run.
  flutter::DartProject project_;

  // The Flutter instance hosted by this window.
  std::unique_ptr<flutter::FlutterViewController> flutter_controller_;

  // Destroyed once the first frame is on screen. Null when there is none.
  HWND pre_splash_ = nullptr;
};

#endif  // RUNNER_FLUTTER_WINDOW_H_
