#pragma once

#include <cstddef>
#include <string>

namespace bfc {

// Source-confirmed AC4Coop puppet order, from Kamzik123/AC4Coop src/phase1.cpp
// Phase1::TrySpawnPuppet and Phase1::DespawnPuppet. This type does not call the
// game. The original x86 file addresses are not stored here.
enum class PuppetStage {
    Idle = 0,
    NeedWorldAndPlayer,
    NeedCachedBuilder,
    DuplicateSelector,
    BuildEntity,
    AddToWorld,
    PlaceTransform,
    DriveOrTeardown,
    Blocked
};

struct PuppetTick {
    bool invokedEngine;
    bool instantiated;
    PuppetStage blockedAt;
    const char* blocker;
};

class PuppetLifecycle {
public:
    static constexpr bool kCallEngine = false;
    static constexpr const char* kVersion = "0.8.0-dev";

    // Order is the source sequence. Names are citation labels, not Resynced symbols.
    static constexpr const char* kSourceSequence[] = {
        "World::GetCurrentWorld",
        "World::GetPlayer",
        "PlayerProgression::GetCachedSelector",
        "PlayerProgression::GetCachedBuilderHandle",
        "DuplicationManager::Begin",
        "RowSelector::Duplicate",
        "DuplicationManager::End",
        "EntityBuilder::BuildEntityWithSelector",
        "World::AddEntity",
        "Entity::SetPosition",
        "World::RemoveEntity",
    };

    static constexpr const char* kBlocker =
        "Resynced equivalents of the cached EntityBuilder, the DuplicationManager "
        "scope, BuildEntityWithSelector, and World::AddEntity are not identified. "
        "No engine function is called.";

    static const char* StageName(PuppetStage stage);
    static std::size_t SourceStepCount();

    // Always refuses. instantiated and invokedEngine stay false.
    static PuppetTick Tick();
    static std::string Describe();
    static void LogGate();
};

}  // namespace bfc
