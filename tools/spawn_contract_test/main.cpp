#include "game/spawn_contract.h"

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
    std::cout << "BlackFlagCoopSpawnContractTest " << bfc::SpawnContract::kVersion << "\n";

    Expect(!bfc::SpawnContract::kInvokeNativeSpawn, "native spawn stays off");

    const bfc::SpawnAttempt attempt = bfc::SpawnContract::AttemptSpawn();
    Expect(!attempt.invoked, "attempt does not invoke");
    Expect(attempt.targetRva == 0u, "attempt has no target rva");
    Expect(attempt.reason != nullptr &&
               std::string(attempt.reason).find("No proven native Edward factory") !=
                   std::string::npos,
           "attempt names the missing factory");

    Expect(bfc::SpawnContract::IsExcluded(0x1AC380u), "deferred queue is excluded");
    Expect(bfc::SpawnContract::IsExcluded(0x2E97B60u), "lod enqueue is excluded");
    Expect(bfc::SpawnContract::IsExcluded(0x2E97FC0u), "lod wrapper is excluded");
    Expect(bfc::SpawnContract::IsExcluded(0xE95E80u), "side-block alloc is excluded");
    Expect(bfc::SpawnContract::IsExcluded(0x426EE50u), "generic allocator is excluded");
    Expect(bfc::SpawnContract::IsExcluded(0x80F2330u), "character params visitor is excluded");
    Expect(bfc::SpawnContract::IsExcluded(0x8DFFB90u), "entity params visitor is excluded");
    Expect(bfc::SpawnContract::IsExcluded(0x8E02960u), "builder params visitor is excluded");
    Expect(bfc::SpawnContract::IsExcluded(0x4572C60u), "schema registrar is excluded");
    Expect(!bfc::SpawnContract::IsExcluded(0u), "zero is not an exclusion");

    const bfc::UnprovenSameTableAlloc* entity =
        bfc::SpawnContract::FindUnprovenAlloc(0x34730u);
    const bfc::UnprovenSameTableAlloc* builder =
        bfc::SpawnContract::FindUnprovenAlloc(0x3DE6300u);
    const bfc::UnprovenSameTableAlloc* builderLate =
        bfc::SpawnContract::FindUnprovenAlloc(0x32FF450u);
    Expect(entity != nullptr && entity->sizeBytes == 0x1528u && entity->slot == 3,
           "entity-table alloc size is recorded");
    Expect(builder != nullptr && builder->sizeBytes == 0x1530u && builder->slot == 3,
           "builder-table alloc size is recorded");
    Expect(builderLate != nullptr && builderLate->sizeBytes == 0u,
           "late allocator size stays unknown");
    Expect(bfc::SpawnContract::FindUnprovenAlloc(0x80F2330u) == nullptr,
           "schema visitor is not recorded as an allocator");

    const std::string text = bfc::SpawnContract::Describe();
    Expect(text.find("invoke=off") != std::string::npos, "description says invoke off");
    Expect(text.find("SpawnEntityBuilderParams") != std::string::npos,
           "description names the builder params");
    Expect(text.find("not called") != std::string::npos,
           "description says the allocators are not called");
    Expect(text.find("0x34730") != std::string::npos, "description records 0x34730");
    Expect(text.find("0x1528") != std::string::npos, "description records size 0x1528");

    if (g_failed != 0) {
        std::cout << "FAILED " << g_failed << "\n";
        return 1;
    }
    std::cout << "ALL PASSED\n";
    return 0;
}
