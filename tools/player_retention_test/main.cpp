#include "game/player_retention.h"

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

}  // namespace

int main() {
    std::cout << "BlackFlagCoopPlayerRetentionTest " << bfc::PlayerRetention::kVersion
              << "\n";

    Expect(!bfc::PlayerRetention::kCallEngine, "retention path never calls the engine");
    Expect(std::string(bfc::PlayerRetention::kContractId) == "C1",
           "gate is labeled as critical-path contract C1");
    Expect(bfc::PlayerRetention::CurrentStage() == bfc::PlayerRetentionStage::Blocked,
           "stage stays blocked until Entity owner is proven");
    Expect(bfc::PlayerRetention::LeadCount() >= 12u, "offline leads include Agent 1 answers");

    // C1 acquire state machine (offline; no engine).
    {
        const bfc::C1AcquireResult blocked =
            bfc::PlayerRetention::EvaluateAcquire(false, false, false, false);
        Expect(blocked.state == bfc::C1AcquireState::BlockedUnproven,
               "unproven template => BlockedUnproven");
        Expect(!blocked.callEngine, "acquire evaluator never sets callEngine");
    }
    {
        const bfc::C1AcquireResult ready =
            bfc::PlayerRetention::EvaluateAcquire(true, false, false, true);
        Expect(ready.state == bfc::C1AcquireState::Ready,
               "readable builder + proven template => Ready");
        Expect(!ready.callEngine, "Ready path still callEngine=false");
    }
    {
        const bfc::C1AcquireResult need =
            bfc::PlayerRetention::EvaluateAcquire(false, true, true, true);
        Expect(need.state == bfc::C1AcquireState::NeedReload,
               "id known + proven reload => NeedReload");
    }
    {
        const bfc::C1AcquireResult blockedReload =
            bfc::PlayerRetention::EvaluateAcquire(false, true, false, true);
        Expect(blockedReload.state == bfc::C1AcquireState::BlockedUnproven,
               "id known without proven reload => BlockedUnproven");
    }
    {
        const bfc::C1AcquireResult failed =
            bfc::PlayerRetention::EvaluateAcquire(false, false, true, true);
        Expect(failed.state == bfc::C1AcquireState::Failed,
               "no object and no id => Failed");
    }

    const std::string text = bfc::PlayerRetention::Describe();
    Expect(text.find("callEngine=off") != std::string::npos, "description says callEngine off");
    Expect(text.find("contract=C1") != std::string::npos, "description names contract C1");
    Expect(text.find("BlockedUnproven") != std::string::npos,
           "description reports current acquire BlockedUnproven");
    Expect(text.find("PlayerEntitySelector") != std::string::npos,
           "description names PlayerEntitySelector");
    Expect(text.find("0x919F9D0") != std::string::npos, "description records method table");
    Expect(text.find("0x7CA9B70") != std::string::npos, "description records Process candidate");
    Expect(text.find("0x16FAA0") != std::string::npos, "description records allocator resolve");
    Expect(text.find("0x50AB0") != std::string::npos, "description records handleDeref sample");
    Expect(text.find("CreateReference") != std::string::npos,
           "description records CreateReference absence");
    Expect(text.find("binary-confirmed") != std::string::npos, "evidence classes are labeled");
    Expect(text.find("source-derived") != std::string::npos, "source-derived rows are labeled");
    Expect(text.find("hypothesis") != std::string::npos, "hypotheses are labeled");
    Expect(text.find("unresolved") != std::string::npos, "unresolved gaps are stated");

    const std::string graph = bfc::PlayerRetention::FlowGraph();
    Expect(graph.find("C1") != std::string::npos, "flow graph starts at C1");
    Expect(graph.find("0x62F12E0") != std::string::npos, "flow graph names registrar");
    Expect(graph.find("virtual [vt+0x88]") != std::string::npos,
           "flow graph includes Process virtual tail");
    Expect(graph.find("handleDeref shape") != std::string::npos,
           "flow graph records handleDeref shape");
    Expect(graph.find("CreateReference") != std::string::npos,
           "flow graph records CreateReference negative");

    if (g_failed != 0) {
        std::cout << "FAILED " << g_failed << "\n";
        return 1;
    }
    std::cout << "ALL PASSED\n";
    return 0;
}
