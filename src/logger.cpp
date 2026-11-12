#include "logger.h"

#include <Windows.h>

#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>

namespace bfc {
namespace {

std::mutex g_logMutex;
std::ofstream g_logFile;
bool g_initialized = false;

}  // namespace

bool Logger::EnsureLogDirectory(std::wstring& outDirectory) {
    const DWORD length = GetEnvironmentVariableW(L"LOCALAPPDATA", nullptr, 0);
    if (length == 0) {
        return false;
    }

    std::wstring buffer(static_cast<size_t>(length), L'\0');
    const DWORD written = GetEnvironmentVariableW(
        L"LOCALAPPDATA",
        buffer.data(),
        length);
    if (written == 0 || written >= length) {
        return false;
    }

    // GetEnvironmentVariableW null-terminates; trim the extra slot.
    buffer.resize(written);

    outDirectory = buffer + L"\\BlackFlagCoop";

    // CreateDirectoryW succeeds if the folder already exists when ERROR_ALREADY_EXISTS.
    if (!CreateDirectoryW(outDirectory.c_str(), nullptr)) {
        const DWORD error = GetLastError();
        if (error != ERROR_ALREADY_EXISTS) {
            return false;
        }
    }

    return true;
}

std::string Logger::FormatLocalTimestamp() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t timeValue = std::chrono::system_clock::to_time_t(now);

    std::tm localTime {};
    if (localtime_s(&localTime, &timeValue) != 0) {
        return "unknown-time";
    }

    char buffer[32] = {};
    if (std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &localTime) == 0) {
        return "unknown-time";
    }

    return std::string(buffer);
}

bool Logger::Initialize() {
    std::lock_guard<std::mutex> lock(g_logMutex);
    if (g_initialized) {
        return true;
    }

    std::wstring directory;
    if (!EnsureLogDirectory(directory)) {
        return false;
    }

    const std::filesystem::path logPath =
        std::filesystem::path(directory) / L"BlackFlagCoop.log";

    g_logFile.open(logPath, std::ios::out | std::ios::app);
    if (!g_logFile.is_open()) {
        return false;
    }

    g_initialized = true;
    return true;
}

void Logger::Info(const std::string& message) {
    std::lock_guard<std::mutex> lock(g_logMutex);
    if (!g_initialized || !g_logFile.is_open()) {
        return;
    }

    g_logFile << '[' << FormatLocalTimestamp() << "] " << message << '\n';
    g_logFile.flush();
}

void Logger::Shutdown() {
    std::lock_guard<std::mutex> lock(g_logMutex);
    if (g_logFile.is_open()) {
        g_logFile.close();
    }
    g_initialized = false;
}

}  // namespace bfc
