#pragma once

namespace bfc {

// v0.5.1+: full-module / large string probing is forbidden during ASI init.
// Offline file scanning lives in tools/exe_string_probe (BlackFlagCoopExeStringProbe).
class PlayerProbe {
public:
    // Policy flag used by diagnostics regression tests.
    static constexpr bool kEnabledDuringPluginInit = false;

    // Logs that heavy string probing is deferred; does no scanning.
    static void LogDeferredNotice();
};

}  // namespace bfc
