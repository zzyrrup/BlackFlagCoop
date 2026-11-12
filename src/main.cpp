#include "game/builder_path.h"
#include "game/player_probe.h"
#include "game/puppet_lifecycle.h"
#include "game/player_telemetry.h"
#include "game/runtime_diag.h"
#include "game/spawn_contract.h"
#include "logger.h"
#include "network/network.h"
#include "splash.h"

#include <Windows.h>

#include <string>

namespace {

constexpr const char* kPluginVersion = "0.8.0-dev";

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
        "Phase: v0.8.0-dev second Edward gate "
        "(native spawn refused, no factory proven)");
    bfc::SpawnContract::LogGate();
    bfc::PuppetLifecycle::LogGate();
    bfc::BuilderPath::LogGate();

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
