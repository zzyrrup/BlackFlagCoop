#pragma once

#include <cstdint>
#include <string>

namespace bfc {

// Offline record of the v0.8.0 spawn-path decision.
// These RVAs are evidence. This type never calls them.
struct SpawnExclusion {
    std::uint32_t rva;
    const char* reason;
};

// Allocator call on the same code-pointer run as a schema visitor.
// finalVtable is the last vptr stored into the returned object. 0 means not recovered.
// None of these vtables has an MSVC RTTI name, and none is a confirmed character type.
struct UnprovenSameTableAlloc {
    std::uint32_t rva;
    std::uint32_t runBase;
    int slot;
    std::uint32_t sizeBytes;
    std::uint32_t finalVtable;
    const char* note;
};

struct SpawnAttempt {
    bool invoked;
    std::uint32_t targetRva;
    const char* reason;
};

class SpawnContract {
public:
    static constexpr const char* kVersion = "0.8.0-dev";
    static constexpr bool kInvokeNativeSpawn = false;

    static constexpr SpawnExclusion kExcluded[] = {
        {0x1AC380u, "deferred queue drain"},
        {0x2E97B60u, "LOD enqueue helper"},
        {0x2E97FC0u, "LOD enqueue wrapper"},
        {0xE95E80u, "side-block allocator"},
        {0x426EE50u, "generic allocator"},
        {0x80F2330u, "SpawnCharacterParams schema visitor"},
        {0x8DFFB90u, "SpawnEntityParams schema visitor"},
        {0x8E02960u, "SpawnEntityBuilderParams schema visitor"},
        {0x4572C60u, "schema type-name registrar"},
    };

    static constexpr UnprovenSameTableAlloc kUnprovenAllocs[] = {
        {0x34730u, 0x92D2030u, 3, 0x1528u, 0x92F9108u,
         "returned object stores base 0x92F91C8 then final 0x92F9108; "
         "vt-8 is 0 so there is no MSVC RTTI name; not a character"},
        {0x3DE6300u, 0x92D1F70u, 3, 0x1530u, 0x92F9048u,
         "returned object stores 0x92F91C8, then 0x92F9108, then final 0x92F9048; "
         "vt-8 is 0 so there is no MSVC RTTI name; not a character"},
        {0x32FF450u, 0x92D1EB0u, 3, 0u, 0u,
         "Allocator call is past the decoded head; size and vtable not recovered"},
    };

    static constexpr const char* kMissingLink =
        "No proven native Edward factory. SpawnCharacterParams, SpawnEntityParams, "
        "and SpawnEntityBuilderParams only register schema names through 0x4572C60. "
        "The missing call is the one that fills a builder and inserts a character "
        "into the world.";

    static bool IsExcluded(std::uint32_t rva);
    static const UnprovenSameTableAlloc* FindUnprovenAlloc(std::uint32_t rva);

    // Always refuses. targetRva stays 0. No game function is called.
    static SpawnAttempt AttemptSpawn();

    static std::string Describe();
    static void LogGate();
};

}  // namespace bfc
