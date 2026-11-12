#include "game/player_probe.h"
#include "game/player_telemetry.h"
#include "game/runtime_diag.h"
#include "logger.h"
#include "network/network.h"
#include "splash.h"
#include "ui/session_overlay.h"
#include "ui/session_panel.h"

#include <Windows.h>

#include <string>

namespace {

constexpr const char* kPluginVersion = bfc::kSessionPanelVersion;

void LogSessionPanelLines(const std::string& text) {
    std::string line;
    for (char ch : text) {
        if (ch == '\n') {
            if (!line.empty()) {
                bfc::Logger::Info("SessionPanel: " + line);
            }
            line.clear();
        } else if (ch != '\r') {
            line.push_back(ch);
        }
    }
    if (!line.empty()) {
        bfc::Logger::Info("SessionPanel: " + line);
    }
}

// 0 = not started, 1 = initialization in progress or finished.
volatile LONG g_initializeOnce = 0;

static_assert(!bfc::PlayerProbe::kEnabledDuringPluginInit,
              "Full-module string probe must never be enabled during ASI init");

}  // namespace

// Ultimate ASI Loader calls this after LoadLibrary, outside the loader lock.
// Keep real startup work here — not inside DllMain.
extern "C" __declspec(dllexport) void InitializeASI() {
    // Thread-safe once-only gate. Any later call is ignored and logged.
    if (InterlockedCompareExchange(&g_initializeOnce, 1, 0) != 0) {
        if (bfc::Logger::Initialize()) {
            bfc::Logger::Info(
                "Duplicate InitializeASI call ignored (already initialized)");
        }
        return;
    }

    if (!bfc::Logger::Initialize()) {
        // Allow a later retry if logging itself failed to start.
        InterlockedExchange(&g_initializeOnce, 0);
        return;
    }

    const DWORD processId = GetCurrentProcessId();
    const std::string timestamp = bfc::Logger::FormatLocalTimestamp();

    bfc::Logger::Info("Plugin initialization successful");
    bfc::Logger::Info(std::string("Plugin version ") + kPluginVersion);
    bfc::Logger::Info(
        "Process ID " +
        std::to_string(static_cast<unsigned long long>(processId)));
    bfc::Logger::Info("Initialization timestamp " + timestamp);
    bfc::Logger::Info(
        "Phase: v0.7.0-dev session panel (gated overlay, no spawn, no session socket)");

    // Prepare Winsock foundation only. Do not open host/client sessions yet.
    if (bfc::Network::Initialize()) {
        bfc::Logger::Info("Network subsystem initialized (Winsock ready)");
    } else {
        bfc::Logger::Info("Network subsystem failed to initialize");
    }

    // Fast, bounded diagnostics only (PID/path/arch/modules/windows).
    const bfc::RuntimeSnapshot runtime = bfc::RuntimeDiagnostics::Capture();
    bfc::RuntimeDiagnostics::LogSnapshot(runtime);
    if (bfc::RuntimeDiagnostics::LooksLikeBlackFlagProcess(runtime)) {
        bfc::Logger::Info("Game-runtime detection: ACBlackFlag.exe host confirmed");
    } else {
        bfc::Logger::Info(
            "Game-runtime detection: host is not ACBlackFlag.exe "
            "(offline/tool load)");
    }

    // Pose investigation status only — no memory scanning here.
    bfc::PlayerTelemetry::LogInvestigationStatus();
    bfc::PlayerProbe::LogDeferredNotice();
    if (!bfc::PlayerTelemetry::HasVerifiedCoordinateSource()) {
        bfc::Logger::Info(
            "Coordinate reader: DISABLED (no verified Edward world-position source)");
    }

    if (bfc::StartSplashScreen()) {
        bfc::Logger::Info("Startup splash requested");
    } else {
        bfc::Logger::Info("Startup splash could not be started");
    }

    // Idle roster only. Do not host, join, scan memory, or claim a second Edward.
    const bfc::SessionPanelSnapshot panel =
        bfc::BuildSessionPanel(bfc::MakeIdleSessionPanelInput());
    const std::string panelText = bfc::RenderSessionPanel(panel);
    bfc::Logger::Info("Session panel snapshot (sockets closed, spawn disabled)");
    LogSessionPanelLines(panelText);
    if (bfc::SessionPanelClaimsInWorldEdward(panel)) {
        bfc::Logger::Info("Session panel safety fault: in-world Edward claim");
    } else {
        bfc::Logger::Info("Session panel safety: no in-world second Edward");
    }

    if (bfc::SessionPanelDisplayModeFromEnvironment() ==
        bfc::SessionPanelDisplayMode::Overlay) {
        if (bfc::StartSessionPanelOverlay(panelText)) {
            bfc::Logger::Info(
                "Session panel overlay started (BFC_SESSION_PANEL opt-in)");
        } else {
            bfc::Logger::Info("Session panel overlay requested but could not start");
        }
    } else {
        bfc::Logger::Info(
            "Session panel overlay disabled (default). Set BFC_SESSION_PANEL=1 to draw.");
    }
}

// Keep DllMain minimal. Do not open files, create threads, or load other DLLs here.
BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved) {
    (void)reserved;

    switch (reason) {
    case DLL_PROCESS_ATTACH:
        // Disable thread attach/detach notifications; we do not need them.
        DisableThreadLibraryCalls(module);
        break;

    default:
        break;
    }

    return TRUE;
}
