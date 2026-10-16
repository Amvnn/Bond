#include <flutter/dart_project.h>
#include <flutter/flutter_view_controller.h>
#include <flutter_windows.h>
#include <windows.h>
#include <stdlib.h>
#include <string>

#include "flutter_window.h"
#include "utils.h"

namespace {

// Brand colours, from brand/README.md. Only these two: the pre-splash is a
// flat field, and Flare belongs to the dot in the logo and nowhere else.
constexpr COLORREF kBondInk = RGB(0x0B, 0x0B, 0x0C);
constexpr COLORREF kBondPaper = RGB(0xF6, 0xF7, 0xF9);

constexpr wchar_t kPreSplashClassName[] = L"BOND_PRESPLASH";

// True when Windows is set to a light app theme. Defaults to light if the
// value is missing, which is what Windows itself does.
bool AppsUseLightTheme() {
  DWORD value = 1;
  DWORD size = sizeof(value);
  LSTATUS status = ::RegGetValueW(
      HKEY_CURRENT_USER,
      L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
      L"AppsUseLightTheme", RRF_RT_REG_DWORD, nullptr, &value, &size);
  if (status != ERROR_SUCCESS) {
    return true;
  }
  return value != 0;
}

// Paints the brand background in the main window's place, immediately.
//
// WHY THIS EXISTS
//
// Measured on this machine: 2.32 of the 2.75 seconds between double-clicking
// the icon and anything appearing on screen is spent before Dart `main()` even
// runs. That is the engine and the Dart VM starting, and no amount of work in
// the application can shorten it. Meanwhile Flutter's runner deliberately
// keeps the window hidden until the first frame, to avoid a white flash — a
// correct trade that turns the delay into a complete absence of feedback. The
// user clicks, and for over two seconds the machine appears to have ignored
// them.
//
// So this puts up a plain window of exactly the right size, in exactly the
// right place, filled with exactly the colour the Flutter splash will paint.
// The handover is invisible because there is nothing to hand over: the same
// rectangle stays the same colour, and the logo animation simply begins
// inside it.
//
// It carries no logo on purpose. A static mark here would have to vanish the
// instant the animated one starts drawing itself from nothing, and that flicker
// is more noticeable than the blank field it replaced.
HWND ShowPreSplash(HINSTANCE instance,
                   const Win32Window::Point& origin,
                   const Win32Window::Size& size) {
  const COLORREF colour = AppsUseLightTheme() ? kBondPaper : kBondInk;

  WNDCLASSW window_class{};
  window_class.lpfnWndProc = ::DefWindowProcW;
  window_class.hInstance = instance;
  window_class.lpszClassName = kPreSplashClassName;
  window_class.hbrBackground = ::CreateSolidBrush(colour);
  window_class.hCursor = ::LoadCursor(nullptr, IDC_APPSTARTING);
  if (!::RegisterClassW(&window_class)) {
    return nullptr;
  }

  // The same DPI maths Win32Window::Create uses, so the two rectangles line
  // up to the pixel. A mismatch would show as the window resizing itself at
  // the moment of handover.
  const POINT target_point = {static_cast<LONG>(origin.x),
                              static_cast<LONG>(origin.y)};
  HMONITOR monitor = ::MonitorFromPoint(target_point, MONITOR_DEFAULTTONEAREST);
  const double scale_factor = FlutterDesktopGetDpiForMonitor(monitor) / 96.0;
  const auto scaled = [scale_factor](double value) {
    return static_cast<int>(value * scale_factor);
  };

  // WS_EX_TOOLWINDOW keeps it out of the taskbar and Alt-Tab: two Bond entries
  // during launch would be worse than the delay this is fixing.
  HWND window = ::CreateWindowExW(
      WS_EX_TOOLWINDOW, kPreSplashClassName, L"Bond", WS_POPUP,
      scaled(origin.x), scaled(origin.y), scaled(size.width),
      scaled(size.height), nullptr, nullptr, instance, nullptr);
  if (!window) {
    return nullptr;
  }

  ::ShowWindow(window, SW_SHOWNORMAL);
  // Paint synchronously rather than waiting for the message loop, which does
  // not start running until after the engine has been built.
  ::UpdateWindow(window);
  return window;
}

// Asks the engine for the Skia renderer instead of Impeller.
//
// MEASURED, not assumed. Profile build, this machine, 1920x1080 maximised,
// the same scripted push/pop journey through Devices, Security and Invite:
//
//                     Impeller (default)      Skia
//   raster p50          57 - 111 ms          0.9 - 1.9 ms
//   frames / 900ms        5 - 6 (~7fps)       27 - 30 (full rate)
//   frames over 16.7ms   60 - 100%            0%
//
// Widget BUILD time was 0.3-5 ms in both, so none of this was the application
// doing too much work. It is entirely rasterisation.
//
// The cause is the hardware path: this is a hybrid-graphics laptop and the app
// runs on the Intel UHD iGPU, where Impeller falls back to its OpenGLES
// backend ("Using the Impeller rendering backend (OpenGLESSDF)" in the log)
// rather than getting Vulkan. That fallback is not viable here. Skia on the
// same iGPU is fine, so the answer is the renderer - not forcing the discrete
// GPU, which would cost battery for an application that needs almost no GPU.
//
// WHY THIS RELAUNCHES INSTEAD OF JUST SETTING THE VARIABLE
//
// The engine reads FLUTTER_ENGINE_SWITCHES out of the environment, but it has
// already done so by the time wWinMain runs: flutter_windows.dll is imported
// by this executable, so it is loaded and initialised first. Setting the
// variable here - with SetEnvironmentVariableW, with _putenv_s, with both -
// compiles, runs, and changes nothing. Both were tried and measured; the
// numbers did not move.
//
// So the variable has to exist before the process starts, which means starting
// the process again. It costs one CreateProcess, happens before any window is
// created so nothing flashes, and only ever happens once because the child
// inherits the variable that suppresses it.
//
// Returns false when it has relaunched and this process should exit.
// Set BOND_USE_IMPELLER=1 to skip all of this and measure Impeller again.
bool EnsureFastRenderer() {
  if (::GetEnvironmentVariableW(L"FLUTTER_ENGINE_SWITCHES", nullptr, 0) != 0) {
    return true;  // Someone is configuring the engine deliberately.
  }
  if (::GetEnvironmentVariableW(L"BOND_USE_IMPELLER", nullptr, 0) != 0) {
    return true;
  }

  ::SetEnvironmentVariableW(L"FLUTTER_ENGINE_SWITCHES", L"1");
  ::SetEnvironmentVariableW(L"FLUTTER_ENGINE_SWITCH_1", L"enable-impeller=false");

  wchar_t executable[MAX_PATH];
  if (::GetModuleFileNameW(nullptr, executable, MAX_PATH) == 0) {
    return true;  // Cannot find ourselves; run slowly rather than not at all.
  }

  // A null environment block means "inherit mine", and mine now carries the
  // switch. The command line is forwarded so arguments survive the hop.
  std::wstring command_line = ::GetCommandLineW();
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION process{};

  // Handles ARE inherited, so the child keeps this process's stdout and
  // stderr. Without that, console output vanishes - which is both how
  // `flutter run` loses its logs and how the first measurement of this change
  // came back empty.
  if (!::CreateProcessW(executable, command_line.data(), nullptr, nullptr,
                        TRUE, 0, nullptr, nullptr, &startup, &process)) {
    return true;  // Relaunch refused; carry on in this process.
  }

  ::CloseHandle(process.hThread);
  ::CloseHandle(process.hProcess);
  return false;
}

}  // namespace


int APIENTRY wWinMain(_In_ HINSTANCE instance, _In_opt_ HINSTANCE prev,
                      _In_ wchar_t *command_line, _In_ int show_command) {
  // Attach to console when present (e.g., 'flutter run') or create a
  // new console when running with a debugger.
  if (!::AttachConsole(ATTACH_PARENT_PROCESS) && ::IsDebuggerPresent()) {
    CreateAndAttachConsole();
  }

  // Before anything else, including the pre-splash: this may relaunch.
  if (!EnsureFastRenderer()) {
    return EXIT_SUCCESS;
  }

  // Initialize COM, so that it is available for use in the library and/or
  // plugins.
  ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

  Win32Window::Point origin(10, 10);
  Win32Window::Size size(1280, 720);

  // Before anything expensive: give the user something to look at.
  HWND pre_splash = ShowPreSplash(instance, origin, size);

  flutter::DartProject project(L"data");

  std::vector<std::string> command_line_arguments =
      GetCommandLineArguments();

  project.set_dart_entrypoint_arguments(std::move(command_line_arguments));

  FlutterWindow window(project);

  // Handed over before Create, because Create registers the first-frame
  // callback that retires it.
  window.SetPreSplash(pre_splash);

  // Name the window after the profile when one is set, so two installations
  // running side by side are distinguishable in the taskbar and by Alt-Tab.
  // Dart reads the same variable to pick its database and key store, so the
  // title always matches the state the window is actually showing.
  //
  // Length-capped and left unsanitised beyond that on purpose: this value only
  // ever reaches a window caption. Dart validates it properly before it is
  // used as a directory name, and will refuse to start on anything malformed.
  std::wstring title = L"Bond";
  wchar_t profile[64];
  DWORD profile_length =
      ::GetEnvironmentVariableW(L"BOND_PROFILE", profile, 64);
  if (profile_length > 0 && profile_length < 64) {
    title += L" \x2014 ";  // em dash
    title += profile;
  }

  if (!window.Create(title, origin, size)) {
    if (pre_splash) {
      ::DestroyWindow(pre_splash);
    }
    return EXIT_FAILURE;
  }
  window.SetQuitOnClose(true);

  ::MSG msg;
  while (::GetMessage(&msg, nullptr, 0, 0)) {
    ::TranslateMessage(&msg);
    ::DispatchMessage(&msg);
  }

  ::CoUninitialize();
  return EXIT_SUCCESS;
}
