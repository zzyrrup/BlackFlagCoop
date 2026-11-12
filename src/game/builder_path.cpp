#include "builder_path.h"

#include "../logger.h"

namespace bfc {

const char* BuilderPath::StageName(BuilderPathStage stage) {
    switch (stage) {
    case BuilderPathStage::Idle:
        return "Idle";
    case BuilderPathStage::PlayerProgressionNameFound:
        return "PlayerProgressionNameFound";
    case BuilderPathStage::SpawnPlayerParamsFound:
        return "SpawnPlayerParamsFound";
    case BuilderPathStage::CachedBuilderUnresolved:
        return "CachedBuilderUnresolved";
    case BuilderPathStage::Blocked:
        return "Blocked";
    }
    return "Unknown";
}

std::size_t BuilderPath::LeadCount() {
    return sizeof(kLeads) / sizeof(kLeads[0]);
}

BuilderPathStage BuilderPath::CurrentStage() {
    // Offline evidence reached the name leads. The cache itself is unresolved,
    // so the runtime stage stays blocked and never calls the engine.
    return BuilderPathStage::Blocked;
}

std::string BuilderPath::Describe() {
    std::string text = "BuilderPath ";
    text += kVersion;
    text += kCallEngine ? " callEngine=on" : " callEngine=off";
    text += "\nstage=";
    text += StageName(CurrentStage());
    text += "\n";
    text += kBlocker;
    text += "\nLeads:";
    for (const BuilderPathLead& lead : kLeads) {
        text += "\n  0x";
        static const char* kDigits = "0123456789ABCDEF";
        bool started = false;
        for (int shift = 28; shift >= 0; shift -= 4) {
            const unsigned digit = (lead.rva >> shift) & 0xFu;
            if (!started && digit == 0u && shift != 0) {
                continue;
            }
            started = true;
            text += kDigits[digit];
        }
        text += " ";
        text += lead.role;
    }
    return text;
}

void BuilderPath::LogGate() {
    Logger::Info(std::string("BuilderPath ") + kVersion + " callEngine=off");
    Logger::Info(kBlocker);
    Logger::Info(
        "PlayerProgression is a name-range label via 0x1C75AB0; "
        "SpawnPlayerParams at 0x80F2A20 is a schema visitor");
}

}  // namespace bfc
