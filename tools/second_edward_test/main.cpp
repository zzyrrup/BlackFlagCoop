#include "game/second_edward.h"

#include <iostream>
#include <string>

namespace {

int g_failed = 0;

void Expect(bool condition, const char* name) {
    if (condition) {
        std::cout << "PASS " << name << "\n";
        return;
    }
    std::cout << "FAIL " << name << "\n";
    ++g_failed;
}

void ExpectContains(const std::string& haystack, const char* needle, const char* name) {
    Expect(haystack.find(needle) != std::string::npos, name);
}

}  // namespace

int main() {
    std::cout << "BlackFlagCoopSecondEdwardTest " << bfc::kSecondEdwardVersion << "\n";

    Expect(!bfc::kNativeSpawnCallable, "native spawn is not callable");
    Expect(bfc::kSpawnParamTypeCount == 7, "seven spawn param types");

    const bfc::SpawnParamType* npc = bfc::FindSpawnParamType("SpawnNPCParams");
    const bfc::SpawnParamType* player = bfc::FindSpawnParamType("SpawnPlayerParams");
    const bfc::SpawnParamType* character = bfc::FindSpawnParamType("SpawnCharacterParams");
    Expect(npc != nullptr && npc->registrarRva == 0x80F23E0u, "npc registrar");
    Expect(npc != nullptr && npc->typeHash == 0x94D05600u, "npc hash");
    Expect(npc != nullptr && !npc->hasDirectCreateCall, "npc has no create call");
    Expect(player != nullptr && player->registrarRva == 0x80F2A20u, "player registrar");
    Expect(player != nullptr && !player->hasDirectCreateCall, "player has no create call");
    Expect(character != nullptr && character->registrarRva == 0x80F2330u, "character registrar");
    Expect(bfc::FindSpawnParamType("CreateActorsDeferredSingleThreaded") == nullptr,
           "deferred queue is not a spawn param type");
    Expect(std::string(bfc::kSecondEdwardCandidateType) == "SpawnNPCParams",
           "candidate is npc params, not the player path");

    Expect(!bfc::SecondEdwardGateEnabled(nullptr), "null gate is off");
    Expect(!bfc::SecondEdwardGateEnabled(""), "empty gate is off");
    Expect(!bfc::SecondEdwardGateEnabled("0"), "zero gate is off");
    Expect(!bfc::SecondEdwardGateEnabled("false"), "false gate is off");
    Expect(bfc::SecondEdwardGateEnabled("1"), "1 enables gate");
    Expect(bfc::SecondEdwardGateEnabled("ON"), "on enables gate");
    Expect(bfc::SecondEdwardGateEnabled("true"), "true enables gate");

    {
        const bfc::SecondEdwardDecision off = bfc::EvaluateSecondEdward(false);
        const std::string text = bfc::FormatSecondEdwardDecision(off);
        Expect(!off.gateEnabled, "default decision gate off");
        Expect(!off.nativeSpawnCallable, "default does not call native spawn");
        Expect(!off.actorCreated, "default creates no actor");
        Expect(off.player1LeftIntact, "default leaves player 1 intact");
        Expect(off.blocker == bfc::SecondEdwardBlocker::GateOff, "default blocker is gate");
        ExpectContains(text, "gate off", "off text names the gate");
        ExpectContains(text, "Actor created: no", "off text creates nothing");
        ExpectContains(text, "Player 1 left intact", "off text keeps player 1");
        Expect(text.find("Actor created: yes") == std::string::npos, "off text does not claim a spawn");
    }

    {
        const bfc::SecondEdwardDecision on = bfc::EvaluateSecondEdward(true);
        const std::string text = bfc::FormatSecondEdwardDecision(on);
        Expect(on.gateEnabled, "requested gate is recorded");
        Expect(!on.nativeSpawnCallable, "gate on still cannot call native spawn");
        Expect(!on.actorCreated, "gate on still creates no actor");
        Expect(on.player1LeftIntact, "gate on leaves player 1 intact");
        Expect(on.blocker == bfc::SecondEdwardBlocker::MissingCreateCallsite,
               "gate on reports the missing callsite");
        ExpectContains(text, "REFUSED", "on text refuses");
        ExpectContains(text, "SpawnNPCParams", "on text names the candidate");
        ExpectContains(text, "not a character factory", "on text is not a fake spawn");
        ExpectContains(text, "Missing link:", "on text states the missing link");
        Expect(text.find("Actor created: yes") == std::string::npos, "on text does not claim a spawn");
    }

    if (g_failed != 0) {
        std::cout << "FAILED " << g_failed << "\n";
        return 1;
    }
    std::cout << "ALL PASS\n";
    return 0;
}
