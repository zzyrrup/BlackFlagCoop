#include "spawn_contract.h"

#include "../logger.h"

namespace bfc {
namespace {

void AppendHex(std::string& text, std::uint32_t value) {
    static const char* kDigits = "0123456789ABCDEF";
    text += "0x";
    bool started = false;
    for (int shift = 28; shift >= 0; shift -= 4) {
        const unsigned digit = (value >> shift) & 0xFu;
        if (!started && digit == 0u && shift != 0) {
            continue;
        }
        started = true;
        text += kDigits[digit];
    }
}

}  // namespace

bool SpawnContract::IsExcluded(std::uint32_t rva) {
    for (const SpawnExclusion& item : kExcluded) {
        if (item.rva == rva) {
            return true;
        }
    }
    return false;
}

const UnprovenSameTableAlloc* SpawnContract::FindUnprovenAlloc(std::uint32_t rva) {
    for (const UnprovenSameTableAlloc& item : kUnprovenAllocs) {
        if (item.rva == rva) {
            return &item;
        }
    }
    return nullptr;
}

SpawnAttempt SpawnContract::AttemptSpawn() {
    // kInvokeNativeSpawn is compiled as false. There is no function-pointer call
    // behind this return. A future change has to flip the flag and name a proven
    // factory before any game code can run.
    return SpawnAttempt{false, 0u, kMissingLink};
}

std::string SpawnContract::Describe() {
    std::string text = "SpawnContract ";
    text += kVersion;
    text += kInvokeNativeSpawn ? " invoke=on" : " invoke=off";
    text += "\n";
    text += kMissingLink;
    text += "\nExcluded:";
    for (const SpawnExclusion& item : kExcluded) {
        text += "\n  ";
        AppendHex(text, item.rva);
        text += " ";
        text += item.reason;
    }
    text += "\nUnproven same-table allocators (not called):";
    for (const UnprovenSameTableAlloc& item : kUnprovenAllocs) {
        text += "\n  ";
        AppendHex(text, item.rva);
        text += " size=";
        AppendHex(text, item.sizeBytes);
        text += " finalVt=";
        AppendHex(text, item.finalVtable);
        text += " ";
        text += item.note;
    }
    return text;
}

void SpawnContract::LogGate() {
    Logger::Info(std::string("SpawnContract ") + kVersion +
                 " native spawn invoke=off");
    Logger::Info(kMissingLink);
    Logger::Info(
        "Allocators 0x34730 and 0x3DE6300 install vtables 0x92F9108 and 0x92F9048. "
        "No RTTI name. Not a character. Not called");
}

}  // namespace bfc
