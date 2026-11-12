#include <Windows.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace {

const char* kHintNeedles[] = {
    "PlayerPosition",
    "WorldPosition",
    "Edward",
    "LocalPlayer",
    "CharacterPosition",
    "Transform",
    "GetPosition",
};

constexpr std::size_t kDefaultChunkBytes = 4ull * 1024ull * 1024ull;
constexpr std::size_t kDefaultMaxHits = 64;
constexpr std::uint64_t kDefaultMaxSeconds = 120;

void PrintUsage() {
    std::cout
        << "BlackFlagCoopExeStringProbe v0.5.1\n"
        << "Read-only, bounded string scan of a PE/executable file on disk.\n"
        << "Does NOT attach to a running game. Not required for launch.\n"
        << "\n"
        << "  --exe <path>           path to ACBlackFlag.exe (required)\n"
        << "  --chunk-mb N           read chunk size in MiB (default 4)\n"
        << "  --max-hits N           stop after N total hits (default 64)\n"
        << "  --max-seconds N        soft time budget (default 120)\n"
        << "  --max-bytes N          optional hard byte cap (0 = whole file)\n"
        << "  --help\n";
}

bool Equals(const char* a, const char* b) {
    return a != nullptr && b != nullptr && std::string(a) == b;
}

bool IsPrintableAscii(unsigned char c) {
    return c >= 32 && c < 127;
}

std::size_t MaxNeedleLength() {
    std::size_t maxLen = 1;
    for (const char* needle : kHintNeedles) {
        const std::size_t len = std::strlen(needle);
        if (len > maxLen) {
            maxLen = len;
        }
    }
    return maxLen;
}

struct Hit {
    std::uint64_t fileOffset = 0;
    std::string text;
};

void ScanBuffer(const std::uint8_t* base,
                std::size_t size,
                std::uint64_t fileOffsetOfBase,
                std::vector<Hit>& hits,
                std::size_t maxHits) {
    if (size == 0 || hits.size() >= maxHits) {
        return;
    }

    for (const char* needle : kHintNeedles) {
        const std::size_t needleLen = std::strlen(needle);
        if (needleLen == 0 || size < needleLen) {
            continue;
        }
        for (std::size_t i = 0; i + needleLen <= size; ++i) {
            if (std::memcmp(base + i, needle, needleLen) != 0) {
                continue;
            }
            std::size_t start = i;
            while (start > 0 && IsPrintableAscii(base[start - 1]) &&
                   (i - start) < 48) {
                --start;
            }
            std::size_t end = i + needleLen;
            while (end < size && IsPrintableAscii(base[end]) &&
                   (end - start) < 96) {
                ++end;
            }
            Hit hit;
            hit.fileOffset = fileOffsetOfBase + i;
            hit.text.assign(reinterpret_cast<const char*>(base + start),
                            end - start);
            hits.push_back(hit);
            if (hits.size() >= maxHits) {
                return;
            }
            i += needleLen;
        }
        if (hits.size() >= maxHits) {
            return;
        }
    }
}

int RunProbe(const std::wstring& exePath,
             std::size_t chunkBytes,
             std::size_t maxHits,
             std::uint64_t maxSeconds,
             std::uint64_t maxBytes) {
    // MinGW libstdc++ accepts const wchar_t* here, not std::wstring.
    std::ifstream file(exePath.c_str(), std::ios::binary);
    if (!file) {
        std::cerr << "[PROBE] Failed to open file for read\n";
        return 2;
    }

    file.seekg(0, std::ios::end);
    const auto fileSize = static_cast<std::uint64_t>(file.tellg());
    file.seekg(0, std::ios::beg);
    if (!file || fileSize == 0) {
        std::cerr << "[PROBE] Empty or unreadable file\n";
        return 3;
    }

    const std::uint64_t scanLimit =
        (maxBytes == 0) ? fileSize : (std::min)(fileSize, maxBytes);
    const std::size_t overlap = MaxNeedleLength() > 0 ? MaxNeedleLength() - 1 : 0;

    std::cout << "[PROBE] File size          : " << fileSize << " bytes\n"
              << "[PROBE] Scan limit         : " << scanLimit << " bytes\n"
              << "[PROBE] Chunk size         : " << chunkBytes << " bytes\n"
              << "[PROBE] Max hits           : " << maxHits << "\n"
              << "[PROBE] Max seconds        : " << maxSeconds << "\n"
              << "[PROBE] Status             : scanning (read-only)\n";

    const auto started = std::chrono::steady_clock::now();
    std::vector<Hit> hits;
    std::vector<std::uint8_t> chunk(chunkBytes);
    std::vector<std::uint8_t> window;
    window.reserve(chunkBytes + overlap);

    std::vector<std::uint8_t> prevTail;
    std::uint64_t offset = 0;
    std::uint64_t lastProgressMb = 0;
    bool stoppedEarly = false;
    std::string stopReason;

    while (offset < scanLimit) {
        const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                                 std::chrono::steady_clock::now() - started)
                                 .count();
        if (static_cast<std::uint64_t>(elapsed) >= maxSeconds) {
            stoppedEarly = true;
            stopReason = "max-seconds budget reached";
            break;
        }
        if (hits.size() >= maxHits) {
            stoppedEarly = true;
            stopReason = "max-hits reached";
            break;
        }

        const std::uint64_t remaining = scanLimit - offset;
        const std::size_t toRead = static_cast<std::size_t>(
            (std::min)(remaining, static_cast<std::uint64_t>(chunkBytes)));

        file.read(reinterpret_cast<char*>(chunk.data()),
                  static_cast<std::streamsize>(toRead));
        const auto got = static_cast<std::size_t>(file.gcount());
        if (got == 0) {
            break;
        }

        window.clear();
        if (!prevTail.empty()) {
            window.insert(window.end(), prevTail.begin(), prevTail.end());
        }
        window.insert(window.end(), chunk.begin(), chunk.begin() + got);

        const std::uint64_t windowFileOffset =
            offset >= prevTail.size() ? offset - prevTail.size() : 0;
        ScanBuffer(window.data(), window.size(), windowFileOffset, hits, maxHits);

        if (overlap > 0) {
            const std::size_t tailLen = (std::min)(overlap, got);
            prevTail.assign(chunk.begin() + (got - tailLen), chunk.begin() + got);
        } else {
            prevTail.clear();
        }

        offset += got;
        const std::uint64_t progressMb = offset / (1024ull * 1024ull);
        if (progressMb >= lastProgressMb + 32 || offset >= scanLimit) {
            const int pct = static_cast<int>((offset * 100ull) / scanLimit);
            std::cout << "[PROBE] Progress           : " << offset << " / "
                      << scanLimit << " bytes (" << pct
                      << "%), hits=" << hits.size() << "\n";
            lastProgressMb = progressMb;
        }

        if (got < toRead) {
            break;
        }
    }

    if (!stoppedEarly && hits.size() >= maxHits) {
        stoppedEarly = true;
        stopReason = "max-hits reached";
    }

    const auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                               std::chrono::steady_clock::now() - started)
                               .count();

    std::cout << "[PROBE] Hits found         : " << hits.size() << "\n";
    for (const auto& hit : hits) {
        std::cout << "[PROBE]   offset 0x" << std::hex << hit.fileOffset
                  << std::dec << " \"" << hit.text << "\"\n";
    }

    if (stoppedEarly) {
        std::cout << "[PROBE] Stopped early      : " << stopReason << "\n";
    }
    std::cout << "[PROBE] Elapsed            : " << elapsedMs << " ms\n";
    std::cout << "[PROBE] Reminder           : string hits are NOT verified "
                 "Edward world-position sources\n";
    std::cout << "[PROBE] COMPLETE\n";
    return 0;
}

std::wstring Utf8ToWide(const std::string& utf8) {
    if (utf8.empty()) {
        return {};
    }
    const int needed =
        MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
    if (needed <= 1) {
        return {};
    }
    std::wstring wide(static_cast<size_t>(needed - 1), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, wide.data(), needed);
    return wide;
}

}  // namespace

int main(int argc, char** argv) {
    std::string exePathUtf8;
    std::size_t chunkBytes = kDefaultChunkBytes;
    std::size_t maxHits = kDefaultMaxHits;
    std::uint64_t maxSeconds = kDefaultMaxSeconds;
    std::uint64_t maxBytes = 0;

    for (int i = 1; i < argc; ++i) {
        if (Equals(argv[i], "--help") || Equals(argv[i], "-h")) {
            PrintUsage();
            return 0;
        }
        if (Equals(argv[i], "--exe") && i + 1 < argc) {
            exePathUtf8 = argv[++i];
        } else if (Equals(argv[i], "--chunk-mb") && i + 1 < argc) {
            const int mb = std::atoi(argv[++i]);
            if (mb < 1) {
                std::cerr << "Invalid --chunk-mb\n";
                return 1;
            }
            chunkBytes = static_cast<std::size_t>(mb) * 1024ull * 1024ull;
        } else if (Equals(argv[i], "--max-hits") && i + 1 < argc) {
            maxHits = static_cast<std::size_t>(std::atoi(argv[++i]));
            if (maxHits < 1) {
                maxHits = 1;
            }
        } else if (Equals(argv[i], "--max-seconds") && i + 1 < argc) {
            maxSeconds = static_cast<std::uint64_t>(std::atoll(argv[++i]));
            if (maxSeconds < 1) {
                maxSeconds = 1;
            }
        } else if (Equals(argv[i], "--max-bytes") && i + 1 < argc) {
            maxBytes = static_cast<std::uint64_t>(std::atoll(argv[++i]));
        } else {
            std::cerr << "Unknown argument: " << argv[i] << "\n";
            PrintUsage();
            return 1;
        }
    }

    if (exePathUtf8.empty()) {
        PrintUsage();
        return 1;
    }

    return RunProbe(Utf8ToWide(exePathUtf8), chunkBytes, maxHits, maxSeconds,
                    maxBytes);
}
