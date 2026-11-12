#include "puppet_lifecycle.h"

#include "../logger.h"

namespace bfc {

const char* PuppetLifecycle::StageName(PuppetStage stage) {
    switch (stage) {
    case PuppetStage::Idle: return "Idle";
    case PuppetStage::NeedWorldAndPlayer: return "NeedWorldAndPlayer";
    case PuppetStage::NeedCachedBuilder: return "NeedCachedBuilder";
    case PuppetStage::DuplicateSelector: return "DuplicateSelector";
    case PuppetStage::BuildEntity: return "BuildEntity";
    case PuppetStage::AddToWorld: return "AddToWorld";
    case PuppetStage::PlaceTransform: return "PlaceTransform";
    case PuppetStage::DriveOrTeardown: return "DriveOrTeardown";
    case PuppetStage::Blocked: return "Blocked";
    }
    return "Blocked";
}

std::size_t PuppetLifecycle::SourceStepCount() {
    return sizeof(kSourceSequence) / sizeof(kSourceSequence[0]);
}

PuppetTick PuppetLifecycle::Tick() {
    // kCallEngine is false. There is no function pointer and no x86 address
    // from AC4Coop in this function.
    return PuppetTick{false, false, PuppetStage::NeedCachedBuilder, kBlocker};
}

std::string PuppetLifecycle::Describe() {
    std::string text = "PuppetLifecycle ";
    text += kVersion;
    text += kCallEngine ? " engine=on" : " engine=off";
    text += "\n";
    text += kBlocker;
    text += "\nAC4Coop sequence:";
    for (std::size_t i = 0; i < SourceStepCount(); ++i) {
        text += "\n  ";
        text += std::to_string(i + 1);
        text += " ";
        text += kSourceSequence[i];
    }
    return text;
}

void PuppetLifecycle::LogGate() {
    Logger::Info(std::string("PuppetLifecycle ") + kVersion + " engine=off");
    Logger::Info(kBlocker);
    Logger::Info(
        "AC4Coop path is cached EntityBuilder, Duplicate selector, "
        "BuildEntityWithSelector, AddEntity. Not bound on Resynced.");
}

}  // namespace bfc
