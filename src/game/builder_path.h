#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace bfc {

// Offline Resynced leads toward the AC4Coop cached EntityBuilder + RowSelector.
// This type never calls the game.
enum class BuilderPathStage {
    Idle = 0,
    PlayerProgressionNameFound,
    SpawnPlayerParamsFound,
    CachedBuilderUnresolved,
    Blocked
};

struct BuilderPathLead {
    std::uint32_t rva;
    const char* role;
};

class BuilderPath {
public:
    static constexpr bool kCallEngine = false;
    static constexpr const char* kVersion = "0.8.0-dev";

    // Confirmed offline. None of these is BuildEntityWithSelector.
    static constexpr BuilderPathLead kLeads[] = {
        {0xA14482Au, "string PlayerProgression"},
        {0x1C75AB0u, "name-range registrar used with PlayerProgression indices 0x141-0x14B"},
        {0x1C71A0Bu, "LEA PlayerProgression inside large initializer"},
        {0x6386663u, "LEA PlayerProgression second site"},
        {0xA11DD92u, "string SpawnPlayerParams"},
        {0x80F2A20u, "SpawnPlayerParams schema visitor -> 0x4572C60 then 0x80F2330"},
        {0xA11DD1Cu, "string SpawnPlayerBoatParams"},
        {0x821ABC0u, "SpawnPlayerBoatParams schema visitor"},
        {0xA15C4FFu, "string LoadingAdvisorUpdate (phase name)"},
    };

    static constexpr const char* kBlocker =
        "PlayerProgression and SpawnPlayerParams exist, but the cached "
        "EntityBuilder handle and RowSelector globals are not identified. "
        "No engine function is called.";

    static const char* StageName(BuilderPathStage stage);
    static std::size_t LeadCount();
    static BuilderPathStage CurrentStage();
    static std::string Describe();
    static void LogGate();
};

}  // namespace bfc
