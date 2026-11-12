#include "game/puppet_lifecycle.h"

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

int IndexOf(const std::string& text, const char* needle) {
    const auto at = text.find(needle);
    return at == std::string::npos ? -1 : static_cast<int>(at);
}

}  // namespace

int main() {
    std::cout << "BlackFlagCoopPuppetLifecycleTest " << bfc::PuppetLifecycle::kVersion << "\n";

    Expect(!bfc::PuppetLifecycle::kCallEngine, "engine calls stay off");
    Expect(bfc::PuppetLifecycle::SourceStepCount() == 11, "source sequence length");

    const bfc::PuppetTick tick = bfc::PuppetLifecycle::Tick();
    Expect(!tick.invokedEngine, "tick does not call the engine");
    Expect(!tick.instantiated, "tick does not instantiate a puppet");
    Expect(tick.blockedAt == bfc::PuppetStage::NeedCachedBuilder,
           "tick blocks on the cached builder");
    Expect(tick.blocker != nullptr &&
               std::string(tick.blocker).find("BuildEntityWithSelector") != std::string::npos,
           "blocker names BuildEntityWithSelector");

    const std::string text = bfc::PuppetLifecycle::Describe();
    const auto seqMark = text.find("AC4Coop sequence:");
    Expect(seqMark != std::string::npos, "description has the source sequence");
    const std::string seq = seqMark == std::string::npos ? text : text.substr(seqMark);
    const int builder = IndexOf(seq, "PlayerProgression::GetCachedBuilderHandle");
    const int begin = IndexOf(seq, "DuplicationManager::Begin");
    const int duplicate = IndexOf(seq, "RowSelector::Duplicate");
    const int end = IndexOf(seq, "DuplicationManager::End");
    const int build = IndexOf(seq, "EntityBuilder::BuildEntityWithSelector");
    const int add = IndexOf(seq, "World::AddEntity");
    const int place = IndexOf(seq, "Entity::SetPosition");
    const int remove = IndexOf(seq, "World::RemoveEntity");
    Expect(builder >= 0 && begin > builder && duplicate > begin && end > duplicate,
           "duplicate stays inside the duplication scope");
    Expect(build > end && add > build && place > add && remove > place,
           "build, add, place, then remove");
    Expect(text.find("engine=off") != std::string::npos, "description says engine off");
    Expect(text.find("0x5FAC00") == std::string::npos, "original x86 build address is absent");
    Expect(text.find("0x0070E860") == std::string::npos, "original x86 AddEntity address is absent");

    if (g_failed != 0) {
        std::cout << "FAILED " << g_failed << "\n";
        return 1;
    }
    std::cout << "ALL PASSED\n";
    return 0;
}
