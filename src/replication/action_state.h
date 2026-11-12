#pragma once

// Clean-room action/blend replication model.
//
// Behavioral source: BlackFlagCoop docs/v0.8.0-ac4coop-contracts.md contract C8
// (and C0/C6), which paraphrase Kamzik123/AC4Coop without copying it.
// This header contains no game addresses, no struct layouts from the original
// x86 mod, and no calls into Assassin's Creed.
//
// kReferenceBlendCapacity is the original mod's transport width (46). It is
// NOT a recovered Resynced 1.0.6 array size. The planner uses it only as a
// ceiling for our own snapshot.

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace bfc::action {

inline constexpr uint16_t kReferenceBlendCapacity = 46;
// Blend, time-scale, and action-set controller ops use these literals.
// They are mod-local constants (value 0), not a recovered engine enum.
// Target-action channel and layer stay separate wire fields.
inline constexpr uint16_t kPrimaryControllerChannel = 0;
inline constexpr uint16_t kPrimaryLayer = 0;
inline constexpr int kBehaviorSwitchCooldownFrames = 4;
inline constexpr uint32_t kActionSnapshotVersion = 1;
// Packed little-endian layout (not a C struct):
// u32 version, u32 alias, u16 targetChannel, u16 targetLayer,
// f32 ratio, f32 timeScale, u16 blendCount, u8 hardCut, u8 flags,
// f32 blendInLength, u32 sequence, f32 blend[46].
// 4+4+2+2+4+4+2+1+1+4+4+184 = 216.
inline constexpr std::size_t kEncodedActionSnapshotBytes = 216;

enum class ThreadAffinity : uint8_t {
    Main = 1,
    Other = 2,
};

// Single action writer. Replication and behavior must not both write.
enum class DriveMode : uint8_t {
    Idle = 0,
    ReplicationOnly = 1,
    BehaviorOnly = 2,
    HybridGround = 3,
};

enum class RefuseReason : uint8_t {
    None = 0,
    WrongThread,
    BadVersion,
    NonFinite,
    TimeScaleNotPositive,
    BlendInLengthNegative,
    ReplicationNotWriter,
    DualWriter,
    BehaviorOwnsGait,
    Cooldown,
};

struct BlendIn {
    float length = 0.0f;
    uint8_t hardCut = 0;
    uint8_t flags = 0;
};

struct ActionSnapshot {
    uint32_t version = kActionSnapshotVersion;
    uint32_t alias = 0;
    uint16_t targetChannel = 0;
    uint16_t targetLayer = 0;
    float ratio = 0.0f;
    float timeScale = 1.0f;
    uint16_t blendCount = 0;
    std::array<float, kReferenceBlendCapacity> blend{};
    BlendIn blendIn{};
    uint32_t sequence = 0;
};

struct ValidationResult {
    bool ok = false;
    bool clampedBlendCount = false;
    RefuseReason reason = RefuseReason::None;
    uint16_t acceptedBlendCount = 0;
};

struct DriveMemory {
    bool actionSetActivated = false;
    bool hasAlias = false;
    uint32_t lastAlias = 0;
    int cooldownFrames = 0;
    bool behaviorEnabled = false;
    DriveMode mode = DriveMode::Idle;
};

struct ApplyPlan {
    bool allowed = false;
    RefuseReason reason = RefuseReason::None;
    bool activateActionSet = false;
    bool setTarget = false;
    bool seekRatio = false;
    bool fixBlendIn = false;
    bool persistBlends = false;
    bool writeBlends = false;
    bool writeTimeScale = false;
    uint16_t blendChannel = kPrimaryControllerChannel;
    uint16_t blendLayer = kPrimaryLayer;
    uint16_t blendCount = 0;
};

// In-memory stand-in for a future action component. Not a game object.
struct FakeActionComponent {
    int actionSetActivations = 0;
    int setTargetCalls = 0;
    int seekCalls = 0;
    int blendInFixes = 0;
    int persistCalls = 0;
    int blendWrites = 0;
    int timeScaleWrites = 0;
    uint32_t currentAlias = 0;
    uint16_t currentTargetChannel = 0;
    uint16_t currentTargetLayer = 0;
    float currentRatio = 0.0f;
    float currentTimeScale = 0.0f;
    float currentBlendInLength = 0.0f;
    uint8_t currentHardCut = 0;
    uint16_t lastBlendChannel = 0xFFFF;
    uint16_t lastBlendLayer = 0xFFFF;
    std::array<float, kReferenceBlendCapacity> blends{};
};

// Seek gate from the original apply path: open interval (0, 1).
// 0 and 1 stay valid wire values and are not sought. A comment that calls
// the ratio a normalized [0, 1] range is author-documented only.
inline bool RatioWarrantsSeek(float ratio) {
    return ratio > 0.0f && ratio < 1.0f;
}

ValidationResult Validate(const ActionSnapshot& snapshot);

bool Encode(const ActionSnapshot& snapshot, std::vector<uint8_t>& out, std::string& error);
bool Decode(const uint8_t* data, std::size_t size, ActionSnapshot& out, std::string& error);

void NoteBehaviorToggle(DriveMemory& memory);

// One call per main-thread player tick. Commits edge/once/cooldown state.
// Never calls the game. Blend writes are planned on the primary channel/layer,
// which is independent of snapshot.targetChannel (the body-part target).
ApplyPlan PlanApply(const ActionSnapshot& snapshot,
                    DriveMemory& memory,
                    ThreadAffinity thread);

bool ApplyToFake(const ApplyPlan& plan,
                 const ActionSnapshot& snapshot,
                 FakeActionComponent& component);

const char* RefuseReasonName(RefuseReason reason);

}  // namespace bfc::action
