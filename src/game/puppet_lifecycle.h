#pragma once

#include <cstddef>
#include <string>

namespace bfc {

// Source-confirmed AC4Coop puppet order, from Kamzik123/AC4Coop src/phase1.cpp
// Phase1::TrySpawnPuppet and Phase1::DespawnPuppet. This type does not call the
// game. The original x86 file addresses are not stored here.
// Stages map to Agent 1 clean-room contracts C0–C10 (docs/v0.8.0-ac4coop-contracts.md).
enum class PuppetStage {
    Idle = 0,                 // pre-C0
    NeedWorldAndPlayer,       // C0/C1 inputs
    NeedCachedBuilder,        // C1
    DuplicateSelector,        // C2
    BuildEntity,              // C3
    AddToWorld,               // C4 (+ C5 pad arming)
    PlaceTransform,           // C7
    DriveOrTeardown,          // C6/C8/C9/C10
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
        "PlayerProgression and SpawnPlayerParams were found offline but are not "
        "that cache. No engine function is called.";

    static const char* StageName(PuppetStage stage);
    static std::size_t SourceStepCount();

    // Always refuses. instantiated and invokedEngine stay false.
    static PuppetTick Tick();
    static std::string Describe();
    static void LogGate();
};

}  // namespace bfc
