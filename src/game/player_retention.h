#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace bfc {

// Offline Resynced local-player Entity / handle retention leads.
// Blueprint: Agent 1 critical path C1 + PR #28 answers (reference-only).
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

// Clean-room C1 acquire result (docs/v0.8.0-ac4coop-contracts.md). Offline only.
enum class C1AcquireState {
    Failed = 0,
    NeedReload,
    Ready,
    BlockedUnproven
};

struct PlayerRetentionLead {
    std::uint32_t rva;
    const char* role;
    const char* evidenceClass;  // binary-confirmed | source-derived | hypothesis
};

struct C1AcquireResult {
    C1AcquireState state;
    bool callEngine;
    const char* reason;
};

class PlayerRetention {
public:
    static constexpr bool kCallEngine = false;
    static constexpr const char* kVersion = "0.8.0-dev";
    static constexpr const char* kContractId = "C1";

    // Confirmed offline. None of these is invoked.
    static constexpr PlayerRetentionLead kLeads[] = {
        {0xA118077u, "string PlayerEntitySelector::Process", "binary-confirmed"},
        {0x62F12E0u, "selector family registrar (hashes name, stores method table)",
         "binary-confirmed"},
        {0x919F9D0u, "PlayerEntitySelector method table in .edata", "binary-confirmed"},
        {0x69B05F0u, "table[0] shared ctor wrapper (calls 0x755F340)", "binary-confirmed"},
        {0x3016DB0u, "table[1] small-object factory (Alloc 0x30, vt 0x919F8D0)",
         "binary-confirmed"},
        {0x7CA9B70u,
         "table[2] Process — SHARED by Reference/Player/Distance/Minion selectors "
         "(NOT unique player retention / C1 owner)",
         "binary-confirmed"},
        {0xADA320u,
         "LoadingAdvisorUpdate phase handler (body @0xADA340); uses this+0x2D0/+0x2A0; "
         "not proven builder cache",
         "binary-confirmed"},
        {0x16FAA0u,
         "allocator-pointer resolve used by Process (NOT ObjectID CreateReference)",
         "binary-confirmed"},
        {0x1214C00u, "ref/list clear helper called before Process virtuals",
         "binary-confirmed"},
        {0x50AB0u,
         "handleDeref shape sample: sign-bit dword@+8 masks object qword@+0",
         "binary-confirmed"},
        {0x2C65A80u,
         "FastLoadStreamerDirectStorageMainQueue LEA site (load queue; not proven reload-by-id)",
         "binary-confirmed"},
        {0xA15C4FFu,
         "string LoadingAdvisorUpdate (phase name; not yet linked to player Entity)",
         "binary-confirmed"},
        {0x0u,
         "CreateReference/HandleManager/AddLoadTask strings absent from Resynced",
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
         "hypothesis-falsified"},
        {0x0u,
         "Resynced dword@+8 validity bit is the hard-ref field of a HandleContainer equivalent",
         "hypothesis"},
        {0x0u,
         "Agent1: TrySpawnPuppet C1 never uses EntitySelector::Process — only "
         "GetCachedSelector/GetCachedBuilderHandle (+reload). Process falsify stands.",
         "source-derived"},
        {0x0u,
         "Agent1 next edge: dual adjacent static/BSS pointer publish "
         "(AC4 0x04DEEF90 RowSelector* / 0x04DEEF94 HandleContainer*)",
         "source-derived"},
        {0xAC028E0u,
         "tight dual slot @.trace with 0xAC028E8 — publisher 0x67FD520 is dual CLEAR "
         "(xor0), not cache FILL; PhoenixCore teardown shape",
         "binary-confirmed"},
        {0xA998888u,
         "tight dual FILL rax/rcx @0x520180 — rorx decode of nested +0x50/+0x58; "
         "NOT selector*+HandleContainer* publish",
         "binary-confirmed"},
        {0x0u,
         ".bss has zero RIP-rel tight (dist<=16) adjacent QWORD co-publishes",
         "binary-confirmed"},
    };

    static constexpr const char* kBlocker =
        "C1 blocked: dual-adjacent static publish hunted; top RIP-rel candidates "
        "falsified as teardown/rorx-pack/registrar. No proven selector*+"
        "HandleContainer* fill. Next: singleton member-pair [obj+0]/[obj+8] "
        "then one static publish of obj*. callEngine=off.";

    static const char* StageName(PlayerRetentionStage stage);
    static const char* AcquireStateName(C1AcquireState state);
    static std::size_t LeadCount();
    static PlayerRetentionStage CurrentStage();

    // Offline C1 acquire evaluator. Never invokes the engine.
    // readableObject / knownObjectId mirror AC4Coop reloadBuilder inputs.
    static C1AcquireResult EvaluateAcquire(bool readableBuilderObject,
                                           bool knownObjectId,
                                           bool provenReloadPrimitive,
                                           bool provenBuildTemplate);

    static std::string Describe();
    static std::string EvidenceTable();
    static std::string FlowGraph();
    static void LogGate();
};

}  // namespace bfc
