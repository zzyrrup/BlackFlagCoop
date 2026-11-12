#pragma once

#include <cstdint>
#include <string>

namespace bfc {

// v0.8.0 — second-Edward proof-of-life gate.
//
// Offline evidence identifies Anvil spawn-parameter types and their
// serializer/copy descriptors. It does not identify a callsite that builds
// one of those objects and creates a world actor. This module therefore
// never calls into the game. kNativeSpawnCallable stays false until a
// later milestone proves the create/apply function and its arguments.

inline constexpr const char* kSecondEdwardVersion = "0.8.0-dev";
inline constexpr bool kNativeSpawnCallable = false;
inline constexpr const char* kSecondEdwardGateName = "BFC_SECOND_EDWARD";

// Preferred candidate for a second body. SpawnPlayerParams is the existing
// player path and is intentionally not the call target.
inline constexpr const char* kSecondEdwardCandidateType = "SpawnNPCParams";

enum class SecondEdwardBlocker {
    GateOff,
    MissingCreateCallsite,
};

struct SpawnParamType {
    const char* name;
    std::uint32_t registrarRva;
    std::uint32_t typeHash;
    std::uint32_t descriptorRva;
    bool hasDirectCreateCall;
};

// Confirmed serializer registrars. hasDirectCreateCall is false for every
// row: direct callers are parent serializers or absent, not world spawn.
inline constexpr SpawnParamType kSpawnParamTypes[] = {
    {"SpawnEntityParams", 0x8DFFB90u, 0xB5BAEE39u, 0x92D2068u, false},
    {"SpawnEntityBuilderParams", 0x8E02960u, 0x6A484E77u, 0x92D1EE8u, false},
    {"SpawnCharacterParams", 0x80F2330u, 0xFB7FF6A5u, 0x92D19C8u, false},
    {"SpawnNPCParams", 0x80F23E0u, 0x94D05600u, 0x92D1AA8u, false},
    {"SpawnFirstPersonPlayerParams", 0x80F2580u, 0xAAB0218Fu, 0x92D1B88u, false},
    {"SpawnPlayerParams", 0x80F2A20u, 0x51BA3541u, 0x92D1C68u, false},
    {"SpawnPlayerBoatParams", 0x821ABC0u, 0x3DF9C374u, 0x92D1D48u, false},
};

inline constexpr int kSpawnParamTypeCount =
    static_cast<int>(sizeof(kSpawnParamTypes) / sizeof(kSpawnParamTypes[0]));

struct SecondEdwardDecision {
    bool gateEnabled = false;
    bool nativeSpawnCallable = false;
    bool actorCreated = false;
    bool player1LeftIntact = true;
    SecondEdwardBlocker blocker = SecondEdwardBlocker::GateOff;
    const char* candidateType = kSecondEdwardCandidateType;
    const char* missingLink =
        "no callsite builds SpawnNPCParams or SpawnCharacterParams and creates an entity";
};

// "1", "on", and "true" request the proof-of-life. Every other value,
// including a missing variable, stays off.
bool SecondEdwardGateEnabled(const char* value);

SecondEdwardDecision EvaluateSecondEdward(bool gateEnabled);

std::string FormatSecondEdwardDecision(const SecondEdwardDecision& decision);

// Reads BFC_SECOND_EDWARD. Used by the ASI only.
bool SecondEdwardGateFromEnvironment();

const SpawnParamType* FindSpawnParamType(const char* name);

}  // namespace bfc
