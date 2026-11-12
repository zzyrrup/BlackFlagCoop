#include "runtime_diag.h"

#include "../logger.h"

#include <Windows.h>
#include <Psapi.h>

#include <algorithm>
#include <sstream>
#include <string>
#include <vector>

namespace bfc {
namespace {

std::string NarrowPath(const wchar_t* wide) {
    if (wide == nullptr || wide[0] == L'\0') {
        return {};
    }
    const int needed = WideCharToMultiByte(CP_UTF8, 0, wide, -1, nullptr, 0, nullptr, nullptr);
    if (needed <= 1) {
        return {};
    }
    std::string out(static_cast<size_t>(needed - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide, -1, out.data(), needed, nullptr, nullptr);
    return out;
}

std::string FileNameOnly(const std::string& path) {
    const auto pos = path.find_last_of("\\/");
    if (pos == std::string::npos) {
        return path;
    }
    return path.substr(pos + 1);
}

std::string HexPtr(std::uintptr_t value) {
    std::ostringstream oss;
    oss << "0x" << std::hex << value;
    return oss.str();
}

struct EnumWindowsContext {
    DWORD processId = 0;
    std::vector<WindowInfo>* windows = nullptr;
};

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    auto* ctx = reinterpret_cast<EnumWindowsContext*>(lParam);
    DWORD windowPid = 0;
    GetWindowThreadProcessId(hwnd, &windowPid);
    if (windowPid != ctx->processId) {
        return TRUE;
    }
    if (!IsWindowVisible(hwnd)) {
        return TRUE;
    }

    wchar_t titleWide[512] = {};
    wchar_t classWide[256] = {};
    GetWindowTextW(hwnd, titleWide, 512);
    GetClassNameW(hwnd, classWide, 256);

    RECT rect {};
    GetClientRect(hwnd, &rect);

    WindowInfo info;
    info.hwnd = reinterpret_cast<std::uintptr_t>(hwnd);
    info.title = NarrowPath(titleWide);
    info.className = NarrowPath(classWide);
    info.width = rect.right - rect.left;
    info.height = rect.bottom - rect.top;
    ctx->windows->push_back(info);
    return TRUE;
}

}  // namespace

RuntimeSnapshot RuntimeDiagnostics::Capture() {
    RuntimeSnapshot snap;
    snap.processId = GetCurrentProcessId();
    snap.threadId = GetCurrentThreadId();
    snap.is64BitProcess = (sizeof(void*) == 8);

    BOOL wow64 = FALSE;
    IsWow64Process(GetCurrentProcess(), &wow64);
    snap.isWow64 = wow64 == TRUE;

    wchar_t exePath[MAX_PATH] = {};
    const DWORD pathLen = GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    if (pathLen > 0 && pathLen < MAX_PATH) {
        snap.executablePath = NarrowPath(exePath);
        snap.executableName = FileNameOnly(snap.executablePath);
    }

    HMODULE modules[512] = {};
    DWORD bytesNeeded = 0;
    HANDLE process = GetCurrentProcess();
    if (EnumProcessModulesEx(process, modules, sizeof(modules), &bytesNeeded,
                             LIST_MODULES_ALL)) {
        const unsigned count = bytesNeeded / sizeof(HMODULE);
        const unsigned limit = (std::min)(count, 512u);
        for (unsigned i = 0; i < limit; ++i) {
            MODULEINFO modInfo {};
            wchar_t modPath[MAX_PATH] = {};
            GetModuleInformation(process, modules[i], &modInfo, sizeof(modInfo));
            GetModuleFileNameW(modules[i], modPath, MAX_PATH);

            ModuleInfo entry;
            entry.path = NarrowPath(modPath);
            entry.name = FileNameOnly(entry.path);
            entry.base = reinterpret_cast<std::uintptr_t>(modInfo.lpBaseOfDll);
            entry.size = static_cast<std::size_t>(modInfo.SizeOfImage);
            snap.modules.push_back(entry);

            if (i == 0) {
                snap.mainModuleBase = entry.base;
                snap.mainModuleSize = entry.size;
            }
        }
    } else {
        snap.notes += "EnumProcessModulesEx failed; ";
    }

    EnumWindowsContext ctx;
    ctx.processId = snap.processId;
    ctx.windows = &snap.windows;
    EnumWindows(EnumWindowsProc, reinterpret_cast<LPARAM>(&ctx));

    if (LooksLikeBlackFlagProcess(snap)) {
        snap.notes += "Host process name matches ACBlackFlag.exe; ";
    } else {
        snap.notes += "Host process name does not match ACBlackFlag.exe (diag may be outside game); ";
    }

    return snap;
}

bool RuntimeDiagnostics::LooksLikeBlackFlagProcess(const RuntimeSnapshot& snapshot) {
    std::string name = snapshot.executableName;
    for (char& c : name) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    return name == "acblackflag.exe";
}

void RuntimeDiagnostics::LogSnapshot(const RuntimeSnapshot& snapshot) {
    Logger::Info("=== Runtime diagnostics begin ===");
    Logger::Info("PID " + std::to_string(snapshot.processId));
    Logger::Info("TID " + std::to_string(snapshot.threadId));
    Logger::Info(std::string("Architecture ") +
                 (snapshot.is64BitProcess ? "x64" : "x86") +
                 (snapshot.isWow64 ? " (WOW64 flag set)" : ""));
    Logger::Info("Executable " + snapshot.executablePath);
    Logger::Info("Main module base " + HexPtr(snapshot.mainModuleBase) +
                 " size " + std::to_string(snapshot.mainModuleSize));
    Logger::Info("Loaded module count " + std::to_string(snapshot.modules.size()));

    // Log a focused subset: main exe + plugin-related + graphics/input common deps.
    unsigned logged = 0;
    for (const auto& mod : snapshot.modules) {
        std::string lower = mod.name;
        for (char& c : lower) {
            if (c >= 'A' && c <= 'Z') {
                c = static_cast<char>(c - 'A' + 'a');
            }
        }
        const bool interesting =
            lower.find("acblackflag") != std::string::npos ||
            lower.find("blackflagcoop") != std::string::npos ||
            lower == "version.dll" ||
            lower.find("d3d") != std::string::npos ||
            lower.find("dxgi") != std::string::npos ||
            lower.find("steam") != std::string::npos ||
            lower.find("upc_") != std::string::npos;
        if (!interesting && logged > 12) {
            continue;
        }
        if (interesting || logged < 8) {
            Logger::Info("Module " + mod.name + " base " + HexPtr(mod.base) +
                         " size " + std::to_string(mod.size));
            ++logged;
        }
    }

    if (snapshot.windows.empty()) {
        Logger::Info("No visible windows for this PID yet");
    } else {
        for (const auto& window : snapshot.windows) {
            Logger::Info("Window hwnd " + HexPtr(window.hwnd) +
                         " title \"" + window.title + "\"" +
                         " class \"" + window.className + "\"" +
                         " client " + std::to_string(window.width) + "x" +
                         std::to_string(window.height));
        }
    }

    if (!snapshot.notes.empty()) {
        Logger::Info("Diag notes: " + snapshot.notes);
    }
    Logger::Info("=== Runtime diagnostics end ===");
}

}  // namespace bfc
