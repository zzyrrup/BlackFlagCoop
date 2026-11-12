#include "game/builder_path.h"

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
    std::cout << "BlackFlagCoopBuilderPathTest " << bfc::BuilderPath::kVersion << "\n";

    Expect(!bfc::BuilderPath::kCallEngine, "builder path never calls the engine");
    Expect(bfc::BuilderPath::CurrentStage() == bfc::BuilderPathStage::Blocked,
           "stage stays blocked until the cache is proven");
    Expect(bfc::BuilderPath::LeadCount() >= 8u, "offline leads are recorded");

    const std::string text = bfc::BuilderPath::Describe();
    Expect(text.find("callEngine=off") != std::string::npos, "description says callEngine off");
    Expect(text.find("PlayerProgression") != std::string::npos,
           "description names PlayerProgression");
    Expect(text.find("SpawnPlayerParams") != std::string::npos,
           "description names SpawnPlayerParams");
    Expect(text.find("0x1C75AB0") != std::string::npos,
           "description records the name-range registrar");
    Expect(text.find("0x80F2A20") != std::string::npos,
           "description records the SpawnPlayerParams visitor");
    Expect(text.find("not identified") != std::string::npos,
           "description states the cache is unresolved");

    if (g_failed != 0) {
        std::cout << "FAILED " << g_failed << "\n";
        return 1;
    }
    std::cout << "ALL PASSED\n";
    return 0;
}
