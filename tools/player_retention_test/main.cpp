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
    Expect(bfc::PlayerRetention::CurrentStage() == bfc::PlayerRetentionStage::Blocked,
           "stage stays blocked until Entity owner is proven");
    Expect(bfc::PlayerRetention::LeadCount() >= 8u, "offline leads are recorded");

    const std::string text = bfc::PlayerRetention::Describe();
    Expect(text.find("callEngine=off") != std::string::npos, "description says callEngine off");
    Expect(text.find("PlayerEntitySelector") != std::string::npos,
           "description names PlayerEntitySelector");
    Expect(text.find("0x919F9D0") != std::string::npos, "description records method table");
    Expect(text.find("0x7CA9B70") != std::string::npos, "description records Process candidate");
    Expect(text.find("0x16FAA0") != std::string::npos, "description records handle resolve");
    Expect(text.find("binary-confirmed") != std::string::npos, "evidence classes are labeled");
    Expect(text.find("source-derived") != std::string::npos, "source-derived rows are labeled");
    Expect(text.find("hypothesis") != std::string::npos, "hypotheses are labeled");
    Expect(text.find("unresolved") != std::string::npos, "unresolved gaps are stated");

    const std::string graph = bfc::PlayerRetention::FlowGraph();
    Expect(graph.find("0x62F12E0") != std::string::npos, "flow graph starts at registrar");
    Expect(graph.find("virtual [vt+0x88]") != std::string::npos,
           "flow graph includes Process virtual tail");

    if (g_failed != 0) {
        std::cout << "FAILED " << g_failed << "\n";
        return 1;
    }
    std::cout << "ALL PASSED\n";
    return 0;
}
