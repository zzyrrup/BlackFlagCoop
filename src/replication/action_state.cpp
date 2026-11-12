#include "replication/action_state.h"

#include <cmath>
#include <cstring>

namespace bfc::action {
namespace {

bool Finite(float value) {
    return std::isfinite(value) != 0;
}

void AppendU8(std::vector<uint8_t>& out, uint8_t value) {
    out.push_back(value);
}

void AppendU16(std::vector<uint8_t>& out, uint16_t value) {
    out.push_back(static_cast<uint8_t>(value & 0xFFu));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xFFu));
}

void AppendU32(std::vector<uint8_t>& out, uint32_t value) {
    out.push_back(static_cast<uint8_t>(value & 0xFFu));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xFFu));
    out.push_back(static_cast<uint8_t>((value >> 16) & 0xFFu));
    out.push_back(static_cast<uint8_t>((value >> 24) & 0xFFu));
}

void AppendF32(std::vector<uint8_t>& out, float value) {
    static_assert(sizeof(float) == 4, "float must be 4 bytes");
    uint32_t bits = 0;
    std::memcpy(&bits, &value, sizeof(bits));
    AppendU32(out, bits);
}

bool ReadU8(const uint8_t*& cursor, const uint8_t* end, uint8_t& value) {
    if (cursor >= end) {
        return false;
    }
    value = *cursor++;
    return true;
}

bool ReadU16(const uint8_t*& cursor, const uint8_t* end, uint16_t& value) {
    if (end - cursor < 2) {
        return false;
    }
    value = static_cast<uint16_t>(cursor[0] | (static_cast<uint16_t>(cursor[1]) << 8));
    cursor += 2;
    return true;
}

bool ReadU32(const uint8_t*& cursor, const uint8_t* end, uint32_t& value) {
    if (end - cursor < 4) {
        return false;
    }
    value = static_cast<uint32_t>(cursor[0])
        | (static_cast<uint32_t>(cursor[1]) << 8)
        | (static_cast<uint32_t>(cursor[2]) << 16)
        | (static_cast<uint32_t>(cursor[3]) << 24);
    cursor += 4;
    return true;
}

bool ReadF32(const uint8_t*& cursor, const uint8_t* end, float& value) {
    uint32_t bits = 0;
    if (!ReadU32(cursor, end, bits)) {
        return false;
    }
    std::memcpy(&value, &bits, sizeof(value));
    return true;
}

ApplyPlan Refuse(RefuseReason reason) {
    ApplyPlan plan;
    plan.allowed = false;
    plan.reason = reason;
    return plan;
}

bool ReplicationWouldWrite(const DriveMemory& memory) {
    // Ground vs air is not known here. The host sets behaviorEnabled from
    // that rule before calling PlanApply. Hybrid + behavior enabled is
    // rejected earlier as BehaviorOwnsGait.
    switch (memory.mode) {
    case DriveMode::ReplicationOnly:
    case DriveMode::HybridGround:
        return !memory.behaviorEnabled;
    case DriveMode::Idle:
    case DriveMode::BehaviorOnly:
        return false;
    }
    return false;
}

}  // namespace

const char* RefuseReasonName(RefuseReason reason) {
    switch (reason) {
    case RefuseReason::None:
        return "none";
    case RefuseReason::WrongThread:
        return "wrong-thread";
    case RefuseReason::BadVersion:
        return "bad-version";
    case RefuseReason::NonFinite:
        return "non-finite";
    case RefuseReason::TimeScaleNotPositive:
        return "timescale-not-positive";
    case RefuseReason::BlendInLengthNegative:
        return "blend-in-length-negative";
    case RefuseReason::ReplicationNotWriter:
        return "replication-not-writer";
    case RefuseReason::DualWriter:
        return "dual-writer";
    case RefuseReason::BehaviorOwnsGait:
        return "behavior-owns-gait";
    case RefuseReason::Cooldown:
        return "cooldown";
    }
    return "unknown";
}

ValidationResult Validate(const ActionSnapshot& snapshot) {
    ValidationResult result;
    if (snapshot.version != kActionSnapshotVersion) {
        result.reason = RefuseReason::BadVersion;
        return result;
    }
    if (!Finite(snapshot.ratio) || !Finite(snapshot.timeScale) || !Finite(snapshot.blendIn.length)) {
        result.reason = !Finite(snapshot.timeScale) ? RefuseReason::TimeScaleNotPositive
                                                     : RefuseReason::NonFinite;
        if (!Finite(snapshot.ratio) || !Finite(snapshot.blendIn.length)) {
            result.reason = RefuseReason::NonFinite;
        }
        return result;
    }
    if (!(snapshot.timeScale > 0.0f)) {
        result.reason = RefuseReason::TimeScaleNotPositive;
        return result;
    }
    if (snapshot.blendIn.length < 0.0f) {
        result.reason = RefuseReason::BlendInLengthNegative;
        return result;
    }

    uint16_t count = snapshot.blendCount;
    if (count > kReferenceBlendCapacity) {
        result.clampedBlendCount = true;
        count = kReferenceBlendCapacity;
    }
    for (uint16_t i = 0; i < count; ++i) {
        if (!Finite(snapshot.blend[i])) {
            result.reason = RefuseReason::NonFinite;
            result.clampedBlendCount = false;
            return result;
        }
    }

    result.ok = true;
    result.reason = RefuseReason::None;
    result.acceptedBlendCount = count;
    return result;
}

bool Encode(const ActionSnapshot& snapshot, std::vector<uint8_t>& out, std::string& error) {
    out.clear();
    const ValidationResult validation = Validate(snapshot);
    if (!validation.ok) {
        error = RefuseReasonName(validation.reason);
        return false;
    }

    ActionSnapshot normalized = snapshot;
    normalized.blendCount = validation.acceptedBlendCount;
    if (validation.clampedBlendCount) {
        for (uint16_t i = normalized.blendCount; i < kReferenceBlendCapacity; ++i) {
            normalized.blend[i] = 0.0f;
        }
    }

    out.reserve(kEncodedActionSnapshotBytes);
    AppendU32(out, normalized.version);
    AppendU32(out, normalized.alias);
    AppendU16(out, normalized.targetChannel);
    AppendU16(out, normalized.targetLayer);
    AppendF32(out, normalized.ratio);
    AppendF32(out, normalized.timeScale);
    AppendU16(out, normalized.blendCount);
    AppendU8(out, normalized.blendIn.hardCut);
    AppendU8(out, normalized.blendIn.flags);
    AppendF32(out, normalized.blendIn.length);
    AppendU32(out, normalized.sequence);
    for (float factor : normalized.blend) {
        AppendF32(out, factor);
    }

    if (out.size() != kEncodedActionSnapshotBytes) {
        out.clear();
        error = "encoded-size";
        return false;
    }
    error.clear();
    return true;
}

bool Decode(const uint8_t* data, std::size_t size, ActionSnapshot& out, std::string& error) {
    out = ActionSnapshot{};
    if (data == nullptr || size != kEncodedActionSnapshotBytes) {
        error = "encoded-size";
        return false;
    }
    const uint8_t* cursor = data;
    const uint8_t* end = data + size;
    ActionSnapshot snapshot;
    if (!ReadU32(cursor, end, snapshot.version)
        || !ReadU32(cursor, end, snapshot.alias)
        || !ReadU16(cursor, end, snapshot.targetChannel)
        || !ReadU16(cursor, end, snapshot.targetLayer)
        || !ReadF32(cursor, end, snapshot.ratio)
        || !ReadF32(cursor, end, snapshot.timeScale)
        || !ReadU16(cursor, end, snapshot.blendCount)
        || !ReadU8(cursor, end, snapshot.blendIn.hardCut)
        || !ReadU8(cursor, end, snapshot.blendIn.flags)
        || !ReadF32(cursor, end, snapshot.blendIn.length)
        || !ReadU32(cursor, end, snapshot.sequence)) {
        error = "truncated";
        return false;
    }
    for (float& factor : snapshot.blend) {
        if (!ReadF32(cursor, end, factor)) {
            error = "truncated";
            return false;
        }
    }
    if (cursor != end) {
        error = "trailing";
        return false;
    }
    const ValidationResult validation = Validate(snapshot);
    if (!validation.ok) {
        error = RefuseReasonName(validation.reason);
        return false;
    }
    snapshot.blendCount = validation.acceptedBlendCount;
    out = snapshot;
    error.clear();
    return true;
}

void NoteBehaviorToggle(DriveMemory& memory) {
    memory.cooldownFrames = kBehaviorSwitchCooldownFrames;
}

ApplyPlan PlanApply(const ActionSnapshot& snapshot,
                    DriveMemory& memory,
                    ThreadAffinity thread) {
    if (thread != ThreadAffinity::Main) {
        return Refuse(RefuseReason::WrongThread);
    }

    const ValidationResult validation = Validate(snapshot);
    if (!validation.ok) {
        return Refuse(validation.reason);
    }

    if (memory.cooldownFrames > 0) {
        --memory.cooldownFrames;
        return Refuse(RefuseReason::Cooldown);
    }

    if (memory.mode == DriveMode::HybridGround && memory.behaviorEnabled) {
        return Refuse(RefuseReason::BehaviorOwnsGait);
    }
    if (memory.mode == DriveMode::Idle || memory.mode == DriveMode::BehaviorOnly) {
        return Refuse(RefuseReason::ReplicationNotWriter);
    }
    if (memory.behaviorEnabled && memory.mode == DriveMode::ReplicationOnly) {
        return Refuse(RefuseReason::DualWriter);
    }
    if (!ReplicationWouldWrite(memory)) {
        return Refuse(RefuseReason::ReplicationNotWriter);
    }

    ApplyPlan plan;
    plan.allowed = true;
    plan.reason = RefuseReason::None;
    plan.blendChannel = kPrimaryControllerChannel;
    plan.blendLayer = kPrimaryLayer;
    plan.blendCount = validation.acceptedBlendCount;
    plan.activateActionSet = !memory.actionSetActivated;
    plan.setTarget = !memory.hasAlias || memory.lastAlias != snapshot.alias;
    plan.seekRatio = plan.setTarget;
    plan.fixBlendIn = plan.setTarget;
    plan.persistBlends = true;
    plan.writeBlends = true;
    plan.writeTimeScale = true;

    memory.actionSetActivated = true;
    memory.hasAlias = true;
    memory.lastAlias = snapshot.alias;
    return plan;
}

bool ApplyToFake(const ApplyPlan& plan,
                 const ActionSnapshot& snapshot,
                 FakeActionComponent& component) {
    if (!plan.allowed) {
        return false;
    }
    if (plan.activateActionSet) {
        ++component.actionSetActivations;
    }
    if (plan.setTarget) {
        ++component.setTargetCalls;
        component.currentAlias = snapshot.alias;
        component.currentTargetChannel = snapshot.targetChannel;
        component.currentTargetLayer = snapshot.targetLayer;
    }
    if (plan.seekRatio) {
        ++component.seekCalls;
        component.currentRatio = snapshot.ratio;
    }
    if (plan.fixBlendIn) {
        ++component.blendInFixes;
        component.currentBlendInLength = snapshot.blendIn.length;
        component.currentHardCut = snapshot.blendIn.hardCut;
    }
    if (plan.persistBlends) {
        ++component.persistCalls;
    }
    if (plan.writeBlends) {
        ++component.blendWrites;
        component.lastBlendChannel = plan.blendChannel;
        component.lastBlendLayer = plan.blendLayer;
        const uint16_t count = plan.blendCount;
        for (uint16_t i = 0; i < count; ++i) {
            component.blends[i] = snapshot.blend[i];
        }
        for (uint16_t i = count; i < kReferenceBlendCapacity; ++i) {
            component.blends[i] = 0.0f;
        }
    }
    if (plan.writeTimeScale) {
        ++component.timeScaleWrites;
        component.currentTimeScale = snapshot.timeScale;
    }
    return true;
}

}  // namespace bfc::action
