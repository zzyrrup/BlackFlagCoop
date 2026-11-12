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

std::size_t PlayerRetention::LeadCount() {
    return sizeof(kLeads) / sizeof(kLeads[0]);
}

PlayerRetentionStage PlayerRetention::CurrentStage() {
    // Offline evidence reached allocator resolve + handleDeref shape, but Entity owner
    // remains unresolved.
    return PlayerRetentionStage::Blocked;
}

std::string PlayerRetention::EvidenceTable() {
    std::string text = "PlayerRetention evidence table\n";
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
        "binary-confirmed call/data flow (offline):\n"
        "  registrar 0x62F12E0\n"
        "    ├─ hash/register \"PlayerEntitySelector::Process\" via 0x1ABC160\n"
        "    └─ store method table 0x919F9D0 into descriptor 0xB33D978\n"
        "         table[0] 0x69B05F0  shared ctor wrapper -> 0x755F340\n"
        "         table[1] 0x3016DB0  Alloc(0x30) + vt 0x919F8D0\n"
        "         table[2] 0x7CA9B70  Process candidate\n"
        "              ├─ 0x16FAA0  allocator-pointer resolve (manager @ 0xAF676D8)\n"
        "              ├─ 0x1214C00 ref/list clear on selector object\n"
        "              ├─ virtual [vt+0x18]\n"
        "              └─ jmp virtual [vt+0x88]\n"
        "  handleDeref shape (many sites; sample 0x50AB0):\n"
        "    obj = *(qword*)HC; valid = (int32)HC[+8] >> 31; use (obj & valid)\n"
        "source-derived (Agent 1 PR#28 answers, AC4Coop only):\n"
        "  GetPlayer = unresolved thiscall; no in-tree m_Player writer\n"
        "  builder/selector cache fill outside repo\n"
        "  HandleContainer packed {obj*, soft, hard, objectId}; reload waits m_Object\n"
        "  Human-update hook esi=Human*; filter GetHuman(GetPlayer())\n"
        "  net puppet: AddEntity + empty pad; no RegisterPlayer\n"
        "unresolved:\n"
        "  which object owns the live local-player Entity*\n"
        "  whether any builder/selector construction cache survives player spawn\n"
        "  whether 0x16FAA0 is related to HandleManager::CreateReference(id)\n";
}

std::string PlayerRetention::Describe() {
    std::string text = "PlayerRetention ";
    text += kVersion;
    text += kCallEngine ? " callEngine=on" : " callEngine=off";
    text += "\nstage=";
    text += StageName(CurrentStage());
    text += "\n";
    text += kBlocker;
    text += "\n";
    text += EvidenceTable();
    text += FlowGraph();
    return text;
}

void PlayerRetention::LogGate() {
    Logger::Info(std::string("PlayerRetention ") + kVersion + " callEngine=off");
    Logger::Info(kBlocker);
    Logger::Info(
        "PlayerEntitySelector table 0x919F9D0; Process 0x7CA9B70; "
        "allocator resolve 0x16FAA0; handleDeref shape sample 0x50AB0");
}

}  // namespace bfc
