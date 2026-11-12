#pragma once

// Clean-room action / ground-blend replication model for a remote Edward puppet.
//
// This header does not call the game. DecideNativeApply() is permanently refused
// until a later milestone proves Resynced ActionComponent callsites on
// ACBlackFlag.exe 1.0.6 x64. Upstream AC4Coop is a behavioral reference only:
// constants marked upstream-reference are NOT Resynced layouts or addresses.
//
// Apply planning refusal order (first match wins):
//   1. update site is not the local player's Human tick
//   2. locomotion is swim (swim action path is unproven)
//   3. drive mode is refused
//   4. hybrid mode with unknown locomotion
//   5. hybrid mode on ground (behavior FSM owns gait / blends)
//   6. external writing was not requested
//   7. authority-switch cooldown still open
//   8. stale snapshot tick
//   9. snapshot fails apply validation (width, channel, finite values)

#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace bfc::action {

inline constexpr bool kNativeActionApplyAuthorized = false;

// AC4Coop wire width for the ground move-cycle blender. Not a Resynced field size.
inline constexpr uint32_t kUpstreamReferenceBlendSlots = 46;
// Hard ceiling for untrusted packets. Independent of the game.
inline constexpr uint32_t kSafetyBlendSlotCap = 64;
// Wire safety caps. These are packet limits, not discovered game limits.
inline constexpr float kWireSafetyMaxTimeScale = 64.f;
inline constexpr float kWireSafetyMaxBlendInSeconds = 30.f;
// AC4Coop waits this many frames after a behavior/replication writer switch
// before either side writes actions. Not a proven Resynced frame count.
inline constexpr uint32_t kUpstreamAuthorityCooldownFrames = 4;

inline constexpr uint32_t kActionSnapshotMagic = 0x31414642u;  // 'BFA1' LE
inline constexpr uint16_t kActionSnapshotVersion = 1;
inline constexpr std::size_t kActionSnapshotPrefixBytes = 64;

inline constexpr uint32_t kFlagTargetValid = 1u << 0;
inline constexpr uint32_t kFlagHasPhase = 1u << 1;
inline constexpr uint32_t kFlagBlendInPresent = 1u << 2;
inline constexpr uint32_t kFlagBlendInHardCut = 1u << 3;
inline constexpr uint32_t kFlagKnownMask =
    kFlagTargetValid | kFlagHasPhase | kFlagBlendInPresent | kFlagBlendInHardCut;

enum class UpdateSite : uint8_t {
    Unknown = 0,
    PlayerHumanTick = 1,
    OtherHumanTick = 2,
    OffThread = 3,
};

enum class ActionDriveMode : uint8_t {
    Refused = 0,
    ExternalReplication = 1,
    HybridGroundFsm = 2,
};

enum class LocomotionContext : uint8_t {
    Unknown = 0,
    Ground = 1,
    OffGround = 2,
    Swim = 3,
};

enum class ApplyStep : uint8_t {
    ActivateCharacterActionSetOnce = 1,
    SetTargetAction = 2,
    SeekPhase = 3,
    PatchBlendIn = 4,
    PersistAndWriteBlends = 5,
    WriteTimeScale = 6,
};

struct ActionSnapshot {
    uint32_t alias = 0;
    uint32_t channel = 0;
    uint32_t layer = 0;
    // Captured for diagnostics. Never the channel used for blend writes.
    uint32_t bodyPartChannel = 0;
    bool targetValid = false;
    bool hasPhase = false;
    float phaseRatio = 0.f;
    float timeScale = 1.f;
    bool blendInPresent = false;
    bool blendInHardCut = false;
    float blendInLength = 0.f;
    uint32_t blendInFlags = 0;
    uint32_t blendCount = 0;
    std::array<float, kSafetyBlendSlotCap> blend{};
    uint64_t characterActionSetId = 0;
    uint64_t tick = 0;
};

struct ApplyContext {
    UpdateSite site = UpdateSite::Unknown;
    ActionDriveMode mode = ActionDriveMode::Refused;
    bool writeActions = false;
    LocomotionContext locomotion = LocomotionContext::Unknown;
    uint32_t authorityCooldownRemaining = 0;
    bool enforceStaleTick = false;
    uint64_t minAcceptedTick = 0;
    uint32_t expectedBlendSlots = kUpstreamReferenceBlendSlots;
    bool requireFullBlendWidth = true;
    bool enforceControllerChannel = true;
    uint32_t controllerChannel = 0;
};

struct PuppetActionMemory {
    bool casApplied = false;
    bool hasLastTarget = false;
    uint32_t lastAlias = 0;
    uint32_t lastChannel = 0;
    uint32_t lastLayer = 0;

    void Reset() { *this = PuppetActionMemory{}; }
};

struct ApplyPlan {
    bool allowed = false;
    const char* code = "uninitialized";
    std::array<ApplyStep, 6> steps{};
    uint8_t stepCount = 0;
    // Blend writes use snapshot.channel, never bodyPartChannel.
    uint32_t blendChannelApplied = 0;
    uint32_t ignoredBodyPartChannel = 0;

    void ClearSteps() { stepCount = 0; }

    bool Add(ApplyStep step) {
        if (stepCount >= steps.size()) {
            return false;
        }
        steps[stepCount++] = step;
        return true;
    }

    bool Contains(ApplyStep step) const {
        for (uint8_t i = 0; i < stepCount; ++i) {
            if (steps[i] == step) {
                return true;
            }
        }
        return false;
    }
};

struct CodecResult {
    bool ok = false;
    const char* code = "uninitialized";
    ActionSnapshot snapshot{};
    std::vector<uint8_t> bytes{};
};

struct NativeApplyDecision {
    bool callEngine = false;
    const char* code = "native_action_apply_refused";
};

inline NativeApplyDecision DecideNativeApply(const ApplyPlan&) {
    return NativeApplyDecision{false, "native_action_apply_refused"};
}

inline bool IsFinite(float value) { return std::isfinite(value) != 0; }

inline const char* ValidateSnapshotNumbers(const ActionSnapshot& snapshot) {
    if (!IsFinite(snapshot.timeScale) || !(snapshot.timeScale > 0.f) ||
        snapshot.timeScale > kWireSafetyMaxTimeScale) {
        return "time_scale";
    }
    if (snapshot.blendCount > kSafetyBlendSlotCap) {
        return "blend_count";
    }
    for (uint32_t i = 0; i < snapshot.blendCount; ++i) {
        if (!IsFinite(snapshot.blend[i])) {
            return "blend_factor";
        }
    }
    if (snapshot.hasPhase) {
        if (!IsFinite(snapshot.phaseRatio) || snapshot.phaseRatio < 0.f ||
            snapshot.phaseRatio > 1.f) {
            return "phase_ratio";
        }
    }
    if (snapshot.blendInHardCut && !snapshot.blendInPresent) {
        return "hard_cut_without_blend_in";
    }
    if (snapshot.blendInPresent) {
        if (!IsFinite(snapshot.blendInLength) || snapshot.blendInLength < 0.f ||
            snapshot.blendInLength > kWireSafetyMaxBlendInSeconds) {
            return "blend_in";
        }
    }
    return nullptr;
}

inline const char* ValidateForApply(const ActionSnapshot& snapshot,
                                    const ApplyContext& context) {
    if (context.expectedBlendSlots > kSafetyBlendSlotCap) {
        return "blend_width_config";
    }
    if (const char* numbers = ValidateSnapshotNumbers(snapshot)) {
        return numbers;
    }
    if (!snapshot.targetValid) {
        return "target_missing";
    }
    if (context.requireFullBlendWidth &&
        snapshot.blendCount != context.expectedBlendSlots) {
        return "partial_blend_width";
    }
    if (context.enforceControllerChannel &&
        snapshot.channel != context.controllerChannel) {
        return "blend_channel";
    }
    return nullptr;
}

inline bool SameTarget(const PuppetActionMemory& memory, const ActionSnapshot& snapshot) {
    return memory.hasLastTarget && memory.lastAlias == snapshot.alias &&
           memory.lastChannel == snapshot.channel && memory.lastLayer == snapshot.layer;
}

inline ApplyPlan MakeIdle(const char* code) {
    ApplyPlan plan;
    plan.allowed = true;
    plan.code = code;
    return plan;
}

inline ApplyPlan MakeRefusal(const char* code) {
    ApplyPlan plan;
    plan.allowed = false;
    plan.code = code;
    return plan;
}

inline ApplyPlan PlanActionApply(const ActionSnapshot& snapshot,
                                 const ApplyContext& context,
                                 const PuppetActionMemory& memory) {
    if (context.site == UpdateSite::OffThread) {
        return MakeRefusal("off_thread");
    }
    if (context.site == UpdateSite::OtherHumanTick) {
        return MakeRefusal("not_player_human_tick");
    }
    if (context.site != UpdateSite::PlayerHumanTick) {
        return MakeRefusal("update_site_unknown");
    }
    if (context.locomotion == LocomotionContext::Swim) {
        return MakeRefusal("swim_action_path_unproven");
    }
    if (context.mode == ActionDriveMode::Refused) {
        return MakeRefusal("drive_mode_refused");
    }

    const bool hybrid = context.mode == ActionDriveMode::HybridGroundFsm;
    if (hybrid && context.locomotion == LocomotionContext::Unknown) {
        return MakeRefusal("locomotion_context_unknown");
    }
    if (hybrid && context.locomotion == LocomotionContext::Ground) {
        if (context.writeActions) {
            return MakeRefusal("ground_fsm_owns_blend");
        }
        return MakeIdle("behavior_owns_actions");
    }
    if (!context.writeActions) {
        return MakeRefusal("write_not_permitted");
    }
    if (context.authorityCooldownRemaining > 0) {
        return MakeRefusal("authority_switch_cooldown");
    }
    if (context.enforceStaleTick && snapshot.tick < context.minAcceptedTick) {
        return MakeRefusal("stale_snapshot");
    }
    if (const char* invalid = ValidateForApply(snapshot, context)) {
        return MakeRefusal(invalid);
    }

    ApplyPlan plan;
    plan.allowed = true;
    plan.code = "apply";
    plan.blendChannelApplied = snapshot.channel;
    plan.ignoredBodyPartChannel = snapshot.bodyPartChannel;

    if (snapshot.characterActionSetId != 0 && !memory.casApplied) {
        plan.Add(ApplyStep::ActivateCharacterActionSetOnce);
    }
    const bool issueTarget = !SameTarget(memory, snapshot);
    if (issueTarget) {
        plan.Add(ApplyStep::SetTargetAction);
        if (snapshot.hasPhase) {
            plan.Add(ApplyStep::SeekPhase);
        }
        if (snapshot.blendInPresent) {
            plan.Add(ApplyStep::PatchBlendIn);
        }
    }
    plan.Add(ApplyStep::PersistAndWriteBlends);
    plan.Add(ApplyStep::WriteTimeScale);
    return plan;
}

inline void CommitApply(PuppetActionMemory& memory,
                        const ActionSnapshot& snapshot,
                        const ApplyPlan& plan) {
    if (!plan.allowed) {
        return;
    }
    if (plan.Contains(ApplyStep::ActivateCharacterActionSetOnce)) {
        memory.casApplied = true;
    }
    if (plan.Contains(ApplyStep::SetTargetAction)) {
        memory.hasLastTarget = true;
        memory.lastAlias = snapshot.alias;
        memory.lastChannel = snapshot.channel;
        memory.lastLayer = snapshot.layer;
    }
}

namespace detail {

inline void AppendU16(std::vector<uint8_t>& out, uint16_t value) {
    out.push_back(static_cast<uint8_t>(value & 0xffu));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xffu));
}

inline void AppendU32(std::vector<uint8_t>& out, uint32_t value) {
    for (int shift = 0; shift < 32; shift += 8) {
        out.push_back(static_cast<uint8_t>((value >> shift) & 0xffu));
    }
}

inline void AppendU64(std::vector<uint8_t>& out, uint64_t value) {
    for (int shift = 0; shift < 64; shift += 8) {
        out.push_back(static_cast<uint8_t>((value >> shift) & 0xffu));
    }
}

inline void AppendF32(std::vector<uint8_t>& out, float value) {
    uint32_t bits = 0;
    static_assert(sizeof(float) == 4, "IEEE754 float required");
    std::memcpy(&bits, &value, sizeof(bits));
    AppendU32(out, bits);
}

inline bool ReadU16(const std::vector<uint8_t>& in, std::size_t& cursor, uint16_t& out) {
    if (cursor + 2 > in.size()) {
        return false;
    }
    out = static_cast<uint16_t>(in[cursor] | (static_cast<uint16_t>(in[cursor + 1]) << 8));
    cursor += 2;
    return true;
}

inline bool ReadU32(const std::vector<uint8_t>& in, std::size_t& cursor, uint32_t& out) {
    if (cursor + 4 > in.size()) {
        return false;
    }
    out = static_cast<uint32_t>(in[cursor]) |
          (static_cast<uint32_t>(in[cursor + 1]) << 8) |
          (static_cast<uint32_t>(in[cursor + 2]) << 16) |
          (static_cast<uint32_t>(in[cursor + 3]) << 24);
    cursor += 4;
    return true;
}

inline bool ReadU64(const std::vector<uint8_t>& in, std::size_t& cursor, uint64_t& out) {
    if (cursor + 8 > in.size()) {
        return false;
    }
    out = 0;
    for (int i = 0; i < 8; ++i) {
        out |= static_cast<uint64_t>(in[cursor + static_cast<std::size_t>(i)]) << (8 * i);
    }
    cursor += 8;
    return true;
}

inline bool ReadF32(const std::vector<uint8_t>& in, std::size_t& cursor, float& out) {
    uint32_t bits = 0;
    if (!ReadU32(in, cursor, bits)) {
        return false;
    }
    std::memcpy(&out, &bits, sizeof(out));
    return true;
}

}  // namespace detail

inline CodecResult EncodeSnapshot(const ActionSnapshot& snapshot) {
    CodecResult result;
    result.snapshot = snapshot;
    if (const char* invalid = ValidateSnapshotNumbers(snapshot)) {
        result.ok = false;
        result.code = invalid;
        return result;
    }
    std::vector<uint8_t> bytes;
    bytes.reserve(kActionSnapshotPrefixBytes +
                  static_cast<std::size_t>(snapshot.blendCount) * 4u);
    detail::AppendU32(bytes, kActionSnapshotMagic);
    detail::AppendU16(bytes, kActionSnapshotVersion);
    detail::AppendU16(bytes, 0);
    detail::AppendU32(bytes, snapshot.alias);
    detail::AppendU32(bytes, snapshot.channel);
    detail::AppendU32(bytes, snapshot.layer);
    detail::AppendU32(bytes, snapshot.bodyPartChannel);
    uint32_t flags = 0;
    if (snapshot.targetValid) {
        flags |= kFlagTargetValid;
    }
    if (snapshot.hasPhase) {
        flags |= kFlagHasPhase;
    }
    if (snapshot.blendInPresent) {
        flags |= kFlagBlendInPresent;
    }
    if (snapshot.blendInHardCut) {
        flags |= kFlagBlendInHardCut;
    }
    detail::AppendU32(bytes, flags);
    detail::AppendU32(bytes, snapshot.blendCount);
    detail::AppendF32(bytes, snapshot.timeScale);
    detail::AppendF32(bytes, snapshot.phaseRatio);
    detail::AppendF32(bytes, snapshot.blendInLength);
    detail::AppendU32(bytes, snapshot.blendInFlags);
    detail::AppendU64(bytes, snapshot.characterActionSetId);
    detail::AppendU64(bytes, snapshot.tick);
    for (uint32_t i = 0; i < snapshot.blendCount; ++i) {
        detail::AppendF32(bytes, snapshot.blend[i]);
    }
    result.ok = bytes.size() ==
                kActionSnapshotPrefixBytes + static_cast<std::size_t>(snapshot.blendCount) * 4u;
    result.code = result.ok ? "ok" : "encode_size";
    result.bytes = std::move(bytes);
    return result;
}

inline CodecResult DecodeSnapshot(const std::vector<uint8_t>& bytes) {
    CodecResult result;
    if (bytes.size() < kActionSnapshotPrefixBytes) {
        result.code = "truncated";
        return result;
    }
    std::size_t cursor = 0;
    uint32_t magic = 0;
    uint16_t version = 0;
    uint16_t reserved = 0;
    if (!detail::ReadU32(bytes, cursor, magic) || !detail::ReadU16(bytes, cursor, version) ||
        !detail::ReadU16(bytes, cursor, reserved)) {
        result.code = "truncated";
        return result;
    }
    if (magic != kActionSnapshotMagic) {
        result.code = "bad_magic";
        return result;
    }
    if (version != kActionSnapshotVersion || reserved != 0) {
        result.code = "bad_version";
        return result;
    }
    ActionSnapshot snapshot;
    uint32_t flags = 0;
    if (!detail::ReadU32(bytes, cursor, snapshot.alias) ||
        !detail::ReadU32(bytes, cursor, snapshot.channel) ||
        !detail::ReadU32(bytes, cursor, snapshot.layer) ||
        !detail::ReadU32(bytes, cursor, snapshot.bodyPartChannel) ||
        !detail::ReadU32(bytes, cursor, flags) ||
        !detail::ReadU32(bytes, cursor, snapshot.blendCount) ||
        !detail::ReadF32(bytes, cursor, snapshot.timeScale) ||
        !detail::ReadF32(bytes, cursor, snapshot.phaseRatio) ||
        !detail::ReadF32(bytes, cursor, snapshot.blendInLength) ||
        !detail::ReadU32(bytes, cursor, snapshot.blendInFlags) ||
        !detail::ReadU64(bytes, cursor, snapshot.characterActionSetId) ||
        !detail::ReadU64(bytes, cursor, snapshot.tick)) {
        result.code = "truncated";
        return result;
    }
    if ((flags & ~kFlagKnownMask) != 0) {
        result.code = "unknown_flags";
        return result;
    }
    if (snapshot.blendCount > kSafetyBlendSlotCap) {
        result.code = "blend_count";
        return result;
    }
    const std::size_t expected =
        kActionSnapshotPrefixBytes + static_cast<std::size_t>(snapshot.blendCount) * 4u;
    if (bytes.size() != expected) {
        result.code = bytes.size() < expected ? "truncated" : "trailing_bytes";
        return result;
    }
    for (uint32_t i = 0; i < snapshot.blendCount; ++i) {
        if (!detail::ReadF32(bytes, cursor, snapshot.blend[i])) {
            result.code = "truncated";
            return result;
        }
    }
    snapshot.targetValid = (flags & kFlagTargetValid) != 0;
    snapshot.hasPhase = (flags & kFlagHasPhase) != 0;
    snapshot.blendInPresent = (flags & kFlagBlendInPresent) != 0;
    snapshot.blendInHardCut = (flags & kFlagBlendInHardCut) != 0;
    if (const char* invalid = ValidateSnapshotNumbers(snapshot)) {
        result.code = invalid;
        return result;
    }
    result.ok = true;
    result.code = "ok";
    result.snapshot = snapshot;
    result.bytes = bytes;
    return result;
}

}  // namespace bfc::action
