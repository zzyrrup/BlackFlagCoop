#include "splash.h"

// GDI+ needs COM stream types that WIN32_LEAN_AND_MEAN would otherwise omit.
#include <Windows.h>
#include <objidl.h>
#include <gdiplus.h>

#include <algorithm>
#include <string>

#pragma comment(lib, "gdiplus.lib")

namespace bfc {
namespace {

constexpr wchar_t kWindowClass[] = L"BlackFlagCoopSplashWindow";
constexpr UINT_PTR kFadeTimerId = 1;
constexpr UINT kFadeTimerMs = 30;
constexpr DWORD kHoldDurationMs = 3500;
constexpr DWORD kFadeDurationMs = 700;
constexpr int kSplashWidth = 1280;
constexpr int kSplashHeight = 720;

ULONG_PTR g_gdiplusToken = 0;
int g_moduleAnchor = 0;
Gdiplus::Image* g_splashImage = nullptr;
DWORD g_startedAt = 0;
BYTE g_alpha = 255;

// Ensures StartSplashScreen creates at most one splash thread.
volatile LONG g_splashStarted = 0;

std::wstring GetPluginDirectory() {
    HMODULE module = nullptr;
    if (!GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(&g_moduleAnchor),
            &module)) {
        return {};
    }

    wchar_t path[MAX_PATH] = {};
    const DWORD length = GetModuleFileNameW(module, path, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) {
        return {};
    }

    std::wstring result(path, length);
    const size_t slash = result.find_last_of(L"\\/");
    if (slash == std::wstring::npos) {
        return {};
    }
    result.resize(slash + 1);
    return result;
}

void PaintSplash(HWND window) {
    PAINTSTRUCT paint {};
    HDC dc = BeginPaint(window, &paint);

    RECT client {};
    GetClientRect(window, &client);

    Gdiplus::Graphics graphics(dc);
    graphics.SetInterpolationMode(Gdiplus::InterpolationModeHighQualityBicubic);
    graphics.Clear(Gdiplus::Color(255, 12, 10, 9));

    if (g_splashImage &&
        g_splashImage->GetLastStatus() == Gdiplus::Ok &&
        g_splashImage->GetWidth() > 0 &&
        g_splashImage->GetHeight() > 0) {
        const float sourceW = static_cast<float>(g_splashImage->GetWidth());
        const float sourceH = static_cast<float>(g_splashImage->GetHeight());
        const float targetW = static_cast<float>(client.right);
        const float targetH = static_cast<float>(client.bottom);
        const float scale = (std::min)(targetW / sourceW, targetH / sourceH);
        const float drawW = sourceW * scale;
        const float drawH = sourceH * scale;
        const float x = (targetW - drawW) * 0.5f;
        const float y = (targetH - drawH) * 0.5f;
        graphics.DrawImage(g_splashImage, x, y, drawW, drawH);
    } else {
        // Visible fallback if the optional PNG is missing.
        const float targetW = static_cast<float>(client.right);
        Gdiplus::SolidBrush background(Gdiplus::Color(255, 12, 10, 9));
        graphics.FillRectangle(&background, 0, 0, client.right, client.bottom);

        Gdiplus::FontFamily family(L"Georgia");
        Gdiplus::Font titleFont(&family, 72.0f, Gdiplus::FontStyleBold);
        Gdiplus::Font subtitleFont(&family, 46.0f, Gdiplus::FontStyleBold);
        Gdiplus::SolidBrush ivory(Gdiplus::Color(255, 220, 211, 187));
        Gdiplus::SolidBrush red(Gdiplus::Color(255, 160, 25, 25));
        Gdiplus::StringFormat format;
        format.SetAlignment(Gdiplus::StringAlignmentCenter);
        graphics.DrawString(L"BLACK FLAG", -1, &titleFont,
            Gdiplus::RectF(0, client.bottom * 0.36f, targetW, 100), &format, &ivory);
        graphics.DrawString(L"CO-OP", -1, &subtitleFont,
            Gdiplus::RectF(0, client.bottom * 0.51f, targetW, 80), &format, &red);
    }

    EndPaint(window, &paint);
}

LRESULT CALLBACK SplashWindowProc(HWND window, UINT message,
                                  WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_PAINT:
        PaintSplash(window);
        return 0;

    case WM_TIMER:
        if (wParam == kFadeTimerId) {
            const DWORD elapsed = GetTickCount() - g_startedAt;
            if (elapsed <= kHoldDurationMs) {
                return 0;
            }

            const DWORD fadeElapsed = elapsed - kHoldDurationMs;
            if (fadeElapsed >= kFadeDurationMs) {
                DestroyWindow(window);
                return 0;
            }

            const float remaining =
                1.0f - static_cast<float>(fadeElapsed) /
                           static_cast<float>(kFadeDurationMs);
            g_alpha = static_cast<BYTE>(255.0f * remaining);
            SetLayeredWindowAttributes(window, 0, g_alpha, LWA_ALPHA);
        }
        return 0;

    case WM_ERASEBKGND:
        return 1;

    case WM_DESTROY:
        KillTimer(window, kFadeTimerId);
        PostQuitMessage(0);
        return 0;

    default:
        return DefWindowProcW(window, message, wParam, lParam);
    }
}

DWORD WINAPI SplashThread(void*) {
    Gdiplus::GdiplusStartupInput startupInput;
    if (Gdiplus::GdiplusStartup(&g_gdiplusToken, &startupInput, nullptr) != Gdiplus::Ok) {
        return 1;
    }

    const std::wstring imagePath = GetPluginDirectory() + L"BlackFlagCoop_splash.png";
    if (!imagePath.empty()) {
        g_splashImage = new Gdiplus::Image(imagePath.c_str());
        if (g_splashImage->GetLastStatus() != Gdiplus::Ok) {
            delete g_splashImage;
            g_splashImage = nullptr;
        }
    }

    WNDCLASSEXW windowClass {};
    windowClass.cbSize = sizeof(windowClass);
    windowClass.lpfnWndProc = SplashWindowProc;
    windowClass.hInstance = GetModuleHandleW(nullptr);
    windowClass.lpszClassName = kWindowClass;
    windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);

    if (!RegisterClassExW(&windowClass) &&
        GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        delete g_splashImage;
        g_splashImage = nullptr;
        Gdiplus::GdiplusShutdown(g_gdiplusToken);
        return 2;
    }

    const int screenW = GetSystemMetrics(SM_CXSCREEN);
    const int screenH = GetSystemMetrics(SM_CYSCREEN);
    const int width = (std::min)(kSplashWidth, screenW);
    const int height = (std::min)(kSplashHeight, screenH);
    const int x = (screenW - width) / 2;
    const int y = (screenH - height) / 2;

    HWND window = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW,
        kWindowClass, L"BlackFlagCoop",
        WS_POPUP, x, y, width, height,
        nullptr, nullptr, windowClass.hInstance, nullptr);

    if (window) {
        g_alpha = 255;
        SetLayeredWindowAttributes(window, 0, g_alpha, LWA_ALPHA);
        g_startedAt = GetTickCount();
        ShowWindow(window, SW_SHOWNOACTIVATE);
        UpdateWindow(window);
        SetTimer(window, kFadeTimerId, kFadeTimerMs, nullptr);

        MSG message {};
        while (GetMessageW(&message, nullptr, 0, 0) > 0) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }

    delete g_splashImage;
    g_splashImage = nullptr;
    UnregisterClassW(kWindowClass, windowClass.hInstance);
    Gdiplus::GdiplusShutdown(g_gdiplusToken);
    return 0;
}

}  // namespace

bool StartSplashScreen() {
    if (InterlockedCompareExchange(&g_splashStarted, 1, 0) != 0) {
        // Already requested once for this process.
        return false;
    }

    HANDLE thread = CreateThread(nullptr, 0, SplashThread, nullptr, 0, nullptr);
    if (!thread) {
        InterlockedExchange(&g_splashStarted, 0);
        return false;
    }
    CloseHandle(thread);
    return true;
}

}  // namespace bfc
