#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace bfc {

struct ModuleInfo {
    std::string name;
    std::string path;
    std::uintptr_t base = 0;
    std::size_t size = 0;
};

struct WindowInfo {
    std::uintptr_t hwnd = 0;
    std::string title;
    std::string className;
    int width = 0;
    int height = 0;
};

struct RuntimeSnapshot {
    std::uint32_t processId = 0;
    std::uint32_t threadId = 0;
    bool isWow64 = false;
    bool is64BitProcess = true;
    std::string executablePath;
    std::string executableName;
    std::uintptr_t mainModuleBase = 0;
    std::size_t mainModuleSize = 0;
    std::vector<ModuleInfo> modules;
    std::vector<WindowInfo> windows;
    std::string notes;
};

// Safe, read-only diagnostics about the process hosting the ASI/plugin.
class RuntimeDiagnostics {
public:
    static RuntimeSnapshot Capture();
    static void LogSnapshot(const RuntimeSnapshot& snapshot);
    static bool LooksLikeBlackFlagProcess(const RuntimeSnapshot& snapshot);
};

}  // namespace bfc
