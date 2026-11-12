#include "ui/session_overlay.h"

#include <Windows.h>

#include <string>

namespace bfc {
namespace {

constexpr wchar_t kWindowClass[] = L"BlackFlagCoopSessionPanel";
constexpr int kPanelWidth = 640;
constexpr int kPanelHeight = 280;
constexpr int kPanelMargin = 24;

std::wstring g_panelText;
volatile LONG g_overlayStarted = 0;

std::wstring Utf8ToWide(const std::string& text) {
    if (text.empty()) {
        return {};
    }
    const int needed = MultiByteToWideChar(
        CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (needed <= 0) {
        return {};
    }
    std::wstring wide(static_cast<size_t>(needed), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                        wide.data(), needed);
    return wide;
}

void PaintPanel(HWND window) {
    PAINTSTRUCT paint {};
    HDC dc = BeginPaint(window, &paint);

    RECT client {};
    GetClientRect(window, &client);

    HBRUSH background = CreateSolidBrush(RGB(18, 16, 14));
    FillRect(dc, &client, background);
    DeleteObject(background);

    HFONT font = CreateFontW(
        18, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
        FIXED_PITCH | FF_MODERN, L"Consolas");
    HFONT previous = static_cast<HFONT>(SelectObject(dc, font));
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, RGB(232, 224, 204));

    RECT textRect = client;
    textRect.left += 16;
    textRect.top += 14;
    textRect.right -= 16;
    textRect.bottom -= 14;
    DrawTextW(dc, g_panelText.c_str(), -1, &textRect,
              DT_LEFT | DT_TOP | DT_NOPREFIX | DT_WORDBREAK);

    SelectObject(dc, previous);
    DeleteObject(font);
    EndPaint(window, &paint);
}

LRESULT CALLBACK PanelWindowProc(HWND window, UINT message, WPARAM wParam,
                                 LPARAM lParam) {
    switch (message) {
    case WM_PAINT:
        PaintPanel(window);
        return 0;
    case WM_ERASEBKGND:
        return 1;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    default:
        return DefWindowProcW(window, message, wParam, lParam);
    }
}

DWORD WINAPI OverlayThread(void*) {
    WNDCLASSEXW windowClass {};
    windowClass.cbSize = sizeof(windowClass);
    windowClass.lpfnWndProc = PanelWindowProc;
    windowClass.hInstance = GetModuleHandleW(nullptr);
    windowClass.lpszClassName = kWindowClass;
    windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);

    if (!RegisterClassExW(&windowClass) &&
        GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        return 1;
    }

    const int screenW = GetSystemMetrics(SM_CXSCREEN);
    const int screenH = GetSystemMetrics(SM_CYSCREEN);
    int width = kPanelWidth;
    int height = kPanelHeight;
    if (width > screenW - kPanelMargin) {
        width = screenW - kPanelMargin;
    }
    if (height > screenH - kPanelMargin) {
        height = screenH - kPanelMargin;
    }
    const int x = screenW - width - kPanelMargin;
    const int y = kPanelMargin;

    HWND window = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW |
            WS_EX_TRANSPARENT,
        kWindowClass, L"BlackFlagCoop Session", WS_POPUP, x, y, width, height,
        nullptr, nullptr, windowClass.hInstance, nullptr);

    if (window) {
        SetLayeredWindowAttributes(window, 0, 230, LWA_ALPHA);
        ShowWindow(window, SW_SHOWNOACTIVATE);
        UpdateWindow(window);

        MSG message {};
        while (GetMessageW(&message, nullptr, 0, 0) > 0) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }

    UnregisterClassW(kWindowClass, windowClass.hInstance);
    return 0;
}

}  // namespace

bool StartSessionPanelOverlay(const std::string& panelText) {
    if (panelText.empty()) {
        return false;
    }
    if (InterlockedCompareExchange(&g_overlayStarted, 1, 0) != 0) {
        return false;
    }

    g_panelText = Utf8ToWide(panelText);
    if (g_panelText.empty()) {
        InterlockedExchange(&g_overlayStarted, 0);
        return false;
    }

    HANDLE thread = CreateThread(nullptr, 0, OverlayThread, nullptr, 0, nullptr);
    if (!thread) {
        InterlockedExchange(&g_overlayStarted, 0);
        return false;
    }
    CloseHandle(thread);
    return true;
}

}  // namespace bfc
