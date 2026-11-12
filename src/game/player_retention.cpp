#include "player_retention.h"

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

const char* PlayerRetention::StageName(PlayerRetentionStage stage) {
    switch (stage) {
    case PlayerRetentionStage::Idle:
        return "Idle";
    case PlayerRetentionStage::SelectorTableFound:
        return "SelectorTableFound";
    case PlayerRetentionStage::ProcessCandidateFound:
        return "ProcessCandidateFound";
    case PlayerRetentionStage::AllocatorResolveFound:
        return "AllocatorResolveFound";
    case PlayerRetentionStage::HandleDerefShapeFound:
        return "HandleDerefShapeFound";
    case PlayerRetentionStage::EntityOwnerUnresolved:
        return "EntityOwnerUnresolved";
    case PlayerRetentionStage::Blocked:
        return "Blocked";
    }
    return "Unknown";
}

const char* PlayerRetention::AcquireStateName(C1AcquireState state) {
    switch (state) {
    case C1AcquireState::Failed:
        return "Failed";
    case C1AcquireState::NeedReload:
        return "NeedReload";
    case C1AcquireState::Ready:
        return "Ready";
    case C1AcquireState::BlockedUnproven:
        return "BlockedUnproven";
    }
    return "Unknown";
}

std::size_t PlayerRetention::LeadCount() {
    return sizeof(kLeads) / sizeof(kLeads[0]);
}

PlayerRetentionStage PlayerRetention::CurrentStage() {
    return PlayerRetentionStage::Blocked;
}

C1AcquireResult PlayerRetention::EvaluateAcquire(bool readableBuilderObject,
                                                 bool knownObjectId,
                                                 bool provenReloadPrimitive,
                                                 bool provenBuildTemplate) {
    C1AcquireResult result;
    result.callEngine = false;

    // Until Resynced proves a build template / reload primitive, stay blocked.
    if (!provenBuildTemplate) {
        result.state = C1AcquireState::BlockedUnproven;
        result.reason =
            "No proven Edward build template / selector cache on Resynced (C1)";
        return result;
    }

    if (readableBuilderObject) {
        result.state = C1AcquireState::Ready;
        result.reason = "Builder object readable";
        return result;
    }

    if (knownObjectId) {
        if (!provenReloadPrimitive) {
            result.state = C1AcquireState::BlockedUnproven;
            result.reason =
                "Object id known but CreateReference/reload-by-id not proven";
            return result;
        }
        result.state = C1AcquireState::NeedReload;
        result.reason = "Builder object released; reload-by-id required";
        return result;
    }

    result.state = C1AcquireState::Failed;
    result.reason = "No readable builder object and no object id";
    return result;
}

std::string PlayerRetention::EvidenceTable() {
    std::string text = "PlayerRetention evidence table (contract ";
    text += kContractId;
    text += ")\n";
    text += "| RVA | Role | Class |\n";
    text += "|-----|------|-------|\n";
    for (const PlayerRetentionLead& lead : kLeads) {
        text += "| ";
        if (lead.rva == 0u) {
            text += "(none)";
        } else {
            AppendHex(text, lead.rva);
        }
        text += " | ";
        text += lead.role;
        text += " | ";
        text += lead.evidenceClass;
        text += " |\n";
    }
    return text;
}

std::string PlayerRetention::FlowGraph() {
    return
        "critical path: C1 (this gate) -> C2 -> C3 -> C5 -> C4 -> C7/C6\n"
        "binary-confirmed call/data flow (offline):\n"
        "  registrar 0x62F12E0\n"
        "    ├─ hash/register \"PlayerEntitySelector::Process\" via 0x1ABC160\n"
        "    └─ store method table 0x919F9D0 into descriptor 0xB33D978\n"
        "         table[2] 0x7CA9B70  Process — SHARED across EntitySelectors (C1 falsified)\n"
        "              ├─ 0x16FAA0  allocator-pointer resolve (NOT CreateReference)\n"
        "              ├─ 0x1214C00 ref/list clear\n"
        "              ├─ virtual [vt+0x18]\n"
        "              └─ jmp virtual [vt+0x88]\n"
        "  handleDeref shape (sample 0x50AB0): obj@[+0] masked by signbit@[+8]; "
        "sole caller 0x4A640 (no global player store)\n"
        "  LoadingAdvisorUpdate 0xADA320/0xADA340: streaming advisor; not proven C1\n"
        "C1 negatives (binary-confirmed):\n"
        "  CreateReference / HandleManager / AddLoadTask strings absent\n"
        "  Process path is not the construction-resource owner\n"
        "  B33D978 consumers are typeinfo dtor/getter only (0x7C8DE60 / 0x7C8DE70)\n"
        "C1 prove: writer of builder+selector (or ObjectID reload→builder used by build)\n"
        "C1 falsify (done for Process): shared non-player selector Process body\n"
        "source-derived (Agent 1):\n"
        "  GetPlayer opaque; cache fill outside repo; HandleContainer fingerprint;\n"
        "  Human-update esi=Human*; net = AddEntity + empty pad\n"
        "unresolved C1:\n"
        "  builder+selector retention owner; ObjectID reload-by-id primitive\n";
}

std::string PlayerRetention::Describe() {
    const C1AcquireResult acquire =
        EvaluateAcquire(false, false, false, false);

    std::string text = "PlayerRetention ";
    text += kVersion;
    text += " contract=";
    text += kContractId;
    text += kCallEngine ? " callEngine=on" : " callEngine=off";
    text += "\nstage=";
    text += StageName(CurrentStage());
    text += "\nacquire=";
    text += AcquireStateName(acquire.state);
    text += " reason=";
    text += acquire.reason;
    text += "\n";
    text += kBlocker;
    text += "\n";
    text += EvidenceTable();
    text += FlowGraph();
    return text;
}

void PlayerRetention::LogGate() {
    Logger::Info(std::string("PlayerRetention ") + kVersion + " contract=C1 callEngine=off");
    Logger::Info(kBlocker);
    Logger::Info(
        "C1 acquire stays BlockedUnproven until builder template + reload are proven");
}

}  // namespace bfc
