#include "replication/action_state.h"

#include <cmath>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

namespace {

int g_failed = 0;

void Expect(bool condition, const char* name) {
    if (!condition) {
        std::cerr << "FAIL " << name << "\n";
        ++g_failed;
        return;
    }
    std::cout << "PASS " << name << "\n";
}

bfc::action::ActionSnapshot Sample() {
    bfc::action::ActionSnapshot snapshot;
    snapshot.alias = 42;
    snapshot.targetChannel = 7;
    snapshot.targetLayer = 3;
    snapshot.ratio = 0.25f;
    snapshot.timeScale = 1.5f;
    snapshot.blendCount = 4;
    snapshot.blend[0] = 0.1f;
    snapshot.blend[1] = 0.2f;
    snapshot.blend[2] = 0.3f;
    snapshot.blend[3] = 0.4f;
    snapshot.blendIn.length = 0.05f;
    snapshot.blendIn.hardCut = 1;
    snapshot.blendIn.flags = 2;
    snapshot.sequence = 9;
    return snapshot;
}

bfc::action::DriveMemory ReplicationDrive() {
    bfc::action::DriveMemory memory;
    memory.mode = bfc::action::DriveMode::ReplicationOnly;
    memory.behaviorEnabled = false;
    return memory;
}

}  // namespace

int main() {
    using namespace bfc::action;

    {
        const ActionSnapshot snapshot = Sample();
        const ValidationResult result = Validate(snapshot);
        Expect(result.ok && result.acceptedBlendCount == 4 && !result.clampedBlendCount,
               "valid-sample");
    }

    {
        ActionSnapshot snapshot = Sample();
        snapshot.timeScale = 0.0f;
        Expect(!Validate(snapshot).ok
                   && Validate(snapshot).reason == RefuseReason::TimeScaleNotPositive,
               "reject-timescale-zero");
        snapshot.timeScale = -1.0f;
        Expect(Validate(snapshot).reason == RefuseReason::TimeScaleNotPositive,
               "reject-timescale-negative");
        snapshot.timeScale = std::nanf("");
        Expect(Validate(snapshot).reason == RefuseReason::TimeScaleNotPositive,
               "reject-timescale-nan");
    }

    {
        ActionSnapshot snapshot = Sample();
        snapshot.ratio = std::numeric_limits<float>::infinity();
        Expect(Validate(snapshot).reason == RefuseReason::NonFinite, "reject-ratio-inf");
        snapshot = Sample();
        snapshot.blend[1] = std::nanf("");
        Expect(Validate(snapshot).reason == RefuseReason::NonFinite, "reject-blend-nan");
        snapshot = Sample();
        snapshot.blendIn.length = -0.01f;
        Expect(Validate(snapshot).reason == RefuseReason::BlendInLengthNegative,
               "reject-negative-blend-in");
    }

    {
        ActionSnapshot snapshot = Sample();
        snapshot.blendCount = 80;
        snapshot.blend[45] = 0.5f;
        const ValidationResult result = Validate(snapshot);
        Expect(result.ok && result.clampedBlendCount
                   && result.acceptedBlendCount == kReferenceBlendCapacity,
               "clamp-blend-count");
    }

    {
        ActionSnapshot snapshot = Sample();
        std::vector<uint8_t> bytes;
        std::string error;
        Expect(Encode(snapshot, bytes, error) && bytes.size() == kEncodedActionSnapshotBytes,
               "encode-size");
        ActionSnapshot decoded;
        Expect(Decode(bytes.data(), bytes.size(), decoded, error), "decode-ok");
        Expect(decoded.alias == snapshot.alias && decoded.targetChannel == 7
                   && decoded.targetLayer == 3 && decoded.ratio == snapshot.ratio
                   && decoded.timeScale == snapshot.timeScale && decoded.blendCount == 4
                   && decoded.blend[3] == 0.4f && decoded.blendIn.hardCut == 1
                   && decoded.blendIn.flags == 2 && decoded.sequence == 9,
               "round-trip-fields");
        Expect(!Decode(bytes.data(), bytes.size() - 1, decoded, error), "reject-short-packet");
        snapshot.timeScale = 0.0f;
        Expect(!Encode(snapshot, bytes, error) && bytes.empty(), "encode-rejects-bad-timescale");
    }

    {
        ActionSnapshot snapshot = Sample();
        snapshot.blendCount = 50;
        std::vector<uint8_t> bytes;
        std::string error;
        Expect(Encode(snapshot, bytes, error), "encode-clamped");
        ActionSnapshot decoded;
        Expect(Decode(bytes.data(), bytes.size(), decoded, error)
                   && decoded.blendCount == kReferenceBlendCapacity,
               "wire-count-is-clamped");
    }

    {
        DriveMemory memory = ReplicationDrive();
        FakeActionComponent component;
        const ActionSnapshot snapshot = Sample();
        const ApplyPlan first = PlanApply(snapshot, memory, ThreadAffinity::Main);
        Expect(first.allowed && first.activateActionSet && first.setTarget && first.seekRatio
                   && first.fixBlendIn && first.persistBlends && first.writeBlends
                   && first.writeTimeScale && first.blendChannel == kPrimaryControllerChannel
                   && first.blendLayer == kPrimaryLayer && first.blendChannel != snapshot.targetChannel,
               "first-frame-plan");
        Expect(ApplyToFake(first, snapshot, component), "first-frame-apply");
        const ApplyPlan second = PlanApply(snapshot, memory, ThreadAffinity::Main);
        Expect(second.allowed && !second.activateActionSet && !second.setTarget && !second.seekRatio
                   && second.persistBlends && second.writeBlends,
               "same-alias-does-not-retarget");
        Expect(ApplyToFake(second, snapshot, component), "second-frame-apply");
        Expect(component.actionSetActivations == 1 && component.setTargetCalls == 1
                   && component.seekCalls == 1 && component.persistCalls == 2
                   && component.blendWrites == 2 && component.lastBlendChannel == 0
                   && component.lastBlendLayer == 0 && component.currentAlias == 42
                   && component.currentTargetChannel == 7 && component.blends[3] == 0.4f
                   && component.currentTimeScale == 1.5f,
               "fake-component-counts");

        ActionSnapshot changed = snapshot;
        changed.alias = 99;
        const ApplyPlan third = PlanApply(changed, memory, ThreadAffinity::Main);
        Expect(third.allowed && third.setTarget && !third.activateActionSet, "alias-edge");
        Expect(ApplyToFake(third, changed, component) && component.setTargetCalls == 2
                   && component.seekCalls == 2 && component.actionSetActivations == 1
                   && component.currentAlias == 99,
               "alias-edge-applied");
    }

    {
        DriveMemory memory = ReplicationDrive();
        ActionSnapshot endpoint = Sample();
        endpoint.ratio = 0.0f;
        const ApplyPlan atZero = PlanApply(endpoint, memory, ThreadAffinity::Main);
        Expect(atZero.allowed && atZero.setTarget && !atZero.seekRatio, "ratio-zero-skips-seek");
        endpoint.alias = 43;
        endpoint.ratio = 1.0f;
        const ApplyPlan atOne = PlanApply(endpoint, memory, ThreadAffinity::Main);
        Expect(atOne.allowed && atOne.setTarget && !atOne.seekRatio, "ratio-one-skips-seek");
        endpoint.alias = 44;
        endpoint.ratio = 2.0f;
        const ApplyPlan outside = PlanApply(endpoint, memory, ThreadAffinity::Main);
        Expect(outside.allowed && outside.setTarget && !outside.seekRatio, "ratio-outside-unit-skips-seek");
        FakeActionComponent component;
        Expect(ApplyToFake(outside, endpoint, component) && component.seekCalls == 0
                   && component.setTargetCalls == 1 && component.currentRatio == 0.0f,
               "unseeked-ratio-is-not-written");
    }

    {
        ActionSnapshot snapshot = Sample();
        snapshot.blend[0] = -0.25f;
        snapshot.blend[1] = 1.5f;
        const ValidationResult result = Validate(snapshot);
        Expect(result.ok && result.acceptedBlendCount == 4, "blend-factors-stay-raw-finite");
        DriveMemory memory = ReplicationDrive();
        const ApplyPlan plan = PlanApply(snapshot, memory, ThreadAffinity::Main);
        FakeActionComponent component;
        Expect(plan.allowed && ApplyToFake(plan, snapshot, component)
                   && component.blends[0] == -0.25f && component.blends[1] == 1.5f,
               "raw-blend-factors-applied");
    }

    {
        DriveMemory memory = ReplicationDrive();
        NoteBehaviorToggle(memory);
        FakeActionComponent component;
        const ActionSnapshot snapshot = Sample();
        bool cooled = true;
        for (int i = 0; i < kBehaviorSwitchCooldownFrames; ++i) {
            const ApplyPlan plan = PlanApply(snapshot, memory, ThreadAffinity::Main);
            cooled = cooled && !plan.allowed && plan.reason == RefuseReason::Cooldown
                && !ApplyToFake(plan, snapshot, component);
        }
        Expect(cooled && component.setTargetCalls == 0 && memory.cooldownFrames == 0,
               "cooldown-suppresses-writes");
        const ApplyPlan plan = PlanApply(snapshot, memory, ThreadAffinity::Main);
        Expect(plan.allowed && ApplyToFake(plan, snapshot, component)
                   && component.setTargetCalls == 1,
               "write-after-cooldown");
    }

    {
        DriveMemory memory = ReplicationDrive();
        NoteBehaviorToggle(memory);
        const int before = memory.cooldownFrames;
        const ApplyPlan plan = PlanApply(Sample(), memory, ThreadAffinity::Other);
        Expect(!plan.allowed && plan.reason == RefuseReason::WrongThread
                   && memory.cooldownFrames == before,
               "off-thread-does-not-settle-cooldown");
    }

    {
        DriveMemory memory = ReplicationDrive();
        memory.behaviorEnabled = true;
        FakeActionComponent component;
        const ApplyPlan plan = PlanApply(Sample(), memory, ThreadAffinity::Main);
        Expect(!plan.allowed && plan.reason == RefuseReason::DualWriter
                   && !ApplyToFake(plan, Sample(), component)
                   && component.actionSetActivations == 0 && !memory.actionSetActivated,
               "dual-writer-refused");
    }

    {
        DriveMemory memory;
        memory.mode = DriveMode::HybridGround;
        memory.behaviorEnabled = true;
        const ApplyPlan ground = PlanApply(Sample(), memory, ThreadAffinity::Main);
        Expect(!ground.allowed && ground.reason == RefuseReason::BehaviorOwnsGait,
               "hybrid-ground-fsm-owns-gait");
        memory.behaviorEnabled = false;
        const ApplyPlan air = PlanApply(Sample(), memory, ThreadAffinity::Main);
        Expect(air.allowed && air.writeBlends, "hybrid-air-replication-writes");
    }

    {
        DriveMemory memory;
        memory.mode = DriveMode::BehaviorOnly;
        const ApplyPlan plan = PlanApply(Sample(), memory, ThreadAffinity::Main);
        Expect(!plan.allowed && plan.reason == RefuseReason::ReplicationNotWriter,
               "behavior-only-no-replication");
        memory.mode = DriveMode::Idle;
        const ApplyPlan idle = PlanApply(Sample(), memory, ThreadAffinity::Main);
        Expect(!idle.allowed && idle.reason == RefuseReason::ReplicationNotWriter,
               "idle-no-replication");
    }

    if (g_failed != 0) {
        std::cerr << g_failed << " failed\n";
        return EXIT_FAILURE;
    }
    std::cout << "all passed\n";
    return EXIT_SUCCESS;
}
