#pragma once

#include <string>

namespace bfc {

// Simple file logger for BlackFlagCoop.
// Writes to: %LOCALAPPDATA%\BlackFlagCoop\BlackFlagCoop.log
class Logger {
public:
    // Creates the log directory if needed and opens the log file for append.
    // Returns true on success.
    static bool Initialize();

    // Appends one line with a timestamp prefix.
    static void Info(const std::string& message);

    // Local wall-clock timestamp used in log lines and init reporting.
    static std::string FormatLocalTimestamp();

    // Closes the log file handle if open.
    static void Shutdown();

private:
    static bool EnsureLogDirectory(std::wstring& outDirectory);
};

}  // namespace bfc
