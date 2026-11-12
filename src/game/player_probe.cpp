#include "player_probe.h"

#include "../logger.h"

namespace bfc {

void PlayerProbe::LogDeferredNotice() {
    Logger::Info("=== Player probe policy (v0.5.1) ===");
    Logger::Info(
        "Full-module string-hint scanning is DISABLED during InitializeASI");
    Logger::Info(
        "Reason: v0.5.0 hung scanning ~501 MB ACBlackFlag image synchronously");
    Logger::Info(
        "Use standalone tool BlackFlagCoopExeStringProbe on the on-disk "
        "executable for research (never required to launch the game)");
    Logger::Info("=== Player probe policy end ===");
}

}  // namespace bfc
