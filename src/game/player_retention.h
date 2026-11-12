#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace bfc {

// Offline Resynced local-player Entity / handle retention leads.
// Blueprint: Agent 1 docs/v0.8.0-ac4coop-source-map.md + PR #28 answers (reference-only).
// This type never calls the game.
enum class PlayerRetentionStage {
    Idle = 0,
    SelectorTableFound,
    ProcessCandidateFound,
    AllocatorResolveFound,
    HandleDerefShapeFound,
    EntityOwnerUnresolved,
    Blocked
};

struct PlayerRetentionLead {
    std::uint32_t rva;
    const char* role;
    const char* evidenceClass;  // binary-confirmed | source-derived | hypothesis
};

class PlayerRetention {
public:
    static constexpr bool kCallEngine = false;
    static constexpr const char* kVersion = "0.8.0-dev";

    // Confirmed offline. None of these is invoked.
    static constexpr PlayerRetentionLead kLeads[] = {
        {0xA118077u, "string PlayerEntitySelector::Process", "binary-confirmed"},
        {0x62F12E0u, "selector family registrar (hashes name, stores method table)",
         "binary-confirmed"},
        {0x919F9D0u, "PlayerEntitySelector method table in .edata", "binary-confirmed"},
        {0x69B05F0u, "table[0] shared ctor wrapper (calls 0x755F340)", "binary-confirmed"},
        {0x3016DB0u, "table[1] small-object factory (Alloc 0x30, vt 0x919F8D0)",
         "binary-confirmed"},
        {0x7CA9B70u, "table[2] Process candidate (allocator resolve + virtual dispatch)",
         "binary-confirmed"},
        {0x16FAA0u,
         "allocator-pointer resolve used by Process (error: Invalid pointer not allocated...)",
         "binary-confirmed"},
        {0x1214C00u, "ref/list clear helper called before Process virtuals",
         "binary-confirmed"},
        {0x50AB0u,
         "handleDeref shape sample: sign-bit dword@+8 masks object qword@+0",
         "binary-confirmed"},
        {0xA15C4FFu,
         "string LoadingAdvisorUpdate (phase name; not yet linked to player Entity)",
         "binary-confirmed"},
        {0x0u,
         "AC4Coop GetPlayer = unresolved thiscall; no in-tree m_Player writer (PR#28 Q1)",
         "source-derived"},
        {0x0u,
         "AC4Coop HandleContainer packed {obj*, soft i32, hard i32, objectId u64}; "
         "cache fill outside repo (PR#28 Q2/Q3)",
         "source-derived"},
        {0x0u,
         "AC4Coop Human-update hook: esi=Human*; filter GetHuman(GetPlayer()) (PR#28 Q4)",
         "source-derived"},
        {0x0u,
         "AC4Coop net puppet: AddEntity enough to drive; force empty pad, no RegisterPlayer "
         "(PR#28 Q5)",
         "source-derived"},
        {0x0u,
         "PlayerEntitySelector::Process returns or retains World player Entity*",
         "hypothesis"},
        {0x0u,
         "Resynced dword@+8 validity bit is the hard-ref field of a HandleContainer equivalent",
         "hypothesis"},
    };

    static constexpr const char* kBlocker =
        "Selector Process + allocator-pointer resolve + handleDeref-shaped validity checks "
        "are identified, but the World/local-player Entity retention owner and any "
        "builder/selector construction cache remain unproven. No engine function is called.";

    static const char* StageName(PlayerRetentionStage stage);
    static std::size_t LeadCount();
    static PlayerRetentionStage CurrentStage();
    static std::string Describe();
    static std::string EvidenceTable();
    static std::string FlowGraph();
    static void LogGate();
};

}  // namespace bfc
