#include "coop/action_replication.h"

#include <cmath>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

int g_failures = 0;

void Expect(bool condition, const char* name) {
    if (!condition) {
        std::fprintf(stderr, "FAIL %s\n", name);
        ++g_failures;
    }
}

void ExpectCode(const char* actual, const char* expected, const char* name) {
    if (actual == nullptr || std::strcmp(actual, expected) != 0) {
        std::fprintf(stderr, "FAIL %s (got %s expected %s)\n", name,
                     actual != nullptr ? actual : "(null)", expected);
        ++g_failures;
    }
}

bfc::action::ActionSnapshot FullSnapshot() {
    bfc::action::ActionSnapshot snapshot;
    snapshot.alias = 0x11u;
    snapshot.channel = 0;
    snapshot.layer = 7;
    snapshot.bodyPartChannel = 3;
    snapshot.targetValid = true;
    snapshot.hasPhase = true;
    snapshot.phaseRatio = 0.25f;
    snapshot.timeScale = 1.f;
    snapshot.blendInPresent = true;
    snapshot.blendInHardCut = false;
    snapshot.blendInLength = 0.1f;
    snapshot.blendInFlags = 0x4u;
    snapshot.blendCount = bfc::action::kUpstreamReferenceBlendSlots;
    for (uint32_t i = 0; i < snapshot.blendCount; ++i) {
        snapshot.blend[i] = static_cast<float>(i) / 46.f;
    }
    snapshot.characterActionSetId = 0xABCDu;
    snapshot.tick = 100;
    return snapshot;
}

bfc::action::ApplyContext PlayerExternal() {
    bfc::action::ApplyContext context;
    context.site = bfc::action::UpdateSite::PlayerHumanTick;
    context.mode = bfc::action::ActionDriveMode::ExternalReplication;
    context.writeActions = true;
    context.locomotion = bfc::action::LocomotionContext::OffGround;
    return context;
}

bool SameFloat(float a, float b) { return std::memcmp(&a, &b, sizeof(float)) == 0; }

void TestRoundTrip() {
    const bfc::action::ActionSnapshot original = FullSnapshot();
    const bfc::action::CodecResult encoded = bfc::action::EncodeSnapshot(original);
    Expect(encoded.ok, "encode ok");
    Expect(encoded.bytes.size() ==
               bfc::action::kActionSnapshotPrefixBytes +
                   static_cast<std::size_t>(bfc::action::kUpstreamReferenceBlendSlots) * 4u,
           "encode size");
    const bfc::action::CodecResult decoded = bfc::action::DecodeSnapshot(encoded.bytes);
    Expect(decoded.ok, "decode ok");
    Expect(decoded.snapshot.alias == original.alias, "alias");
    Expect(decoded.snapshot.channel == 0u, "channel");
    Expect(decoded.snapshot.layer == 7u, "layer");
    Expect(decoded.snapshot.bodyPartChannel == 3u, "body channel kept separate");
    Expect(decoded.snapshot.targetValid, "target valid");
    Expect(decoded.snapshot.hasPhase && SameFloat(decoded.snapshot.phaseRatio, 0.25f), "phase");
    Expect(decoded.snapshot.blendCount == original.blendCount, "blend count");
    Expect(SameFloat(decoded.snapshot.blend[45], original.blend[45]), "last blend");
    Expect(decoded.snapshot.characterActionSetId == original.characterActionSetId, "cas id");
    Expect(decoded.snapshot.tick == 100u, "tick");
}

void TestCodecRejections() {
    bfc::action::ActionSnapshot snapshot = FullSnapshot();
    bfc::action::CodecResult encoded = bfc::action::EncodeSnapshot(snapshot);
    Expect(encoded.ok, "baseline encode");

    std::vector<uint8_t> badMagic = encoded.bytes;
    badMagic[0] ^= 0xffu;
    ExpectCode(bfc::action::DecodeSnapshot(badMagic).code, "bad_magic", "bad magic");

    std::vector<uint8_t> shortBytes(encoded.bytes.begin(), encoded.bytes.begin() + 10);
    ExpectCode(bfc::action::DecodeSnapshot(shortBytes).code, "truncated", "truncated");

    std::vector<uint8_t> trailing = encoded.bytes;
    trailing.push_back(0);
    ExpectCode(bfc::action::DecodeSnapshot(trailing).code, "trailing_bytes", "trailing");

    std::vector<uint8_t> version = encoded.bytes;
    version[4] = 2;
    ExpectCode(bfc::action::DecodeSnapshot(version).code, "bad_version", "version");

    snapshot.blendCount = bfc::action::kSafetyBlendSlotCap + 1;
    ExpectCode(bfc::action::EncodeSnapshot(snapshot).code, "blend_count", "count over cap");

    snapshot = FullSnapshot();
    snapshot.timeScale = 0.f;
    ExpectCode(bfc::action::EncodeSnapshot(snapshot).code, "time_scale", "timescale 0");
    snapshot.timeScale = -1.f;
    ExpectCode(bfc::action::EncodeSnapshot(snapshot).code, "time_scale", "timescale negative");
    snapshot.timeScale = std::nanf("");
    ExpectCode(bfc::action::EncodeSnapshot(snapshot).code, "time_scale", "timescale nan");
    snapshot.timeScale = bfc::action::kWireSafetyMaxTimeScale + 1.f;
    ExpectCode(bfc::action::EncodeSnapshot(snapshot).code, "time_scale", "timescale cap");

    snapshot = FullSnapshot();
    snapshot.blend[3] = std::nanf("");
    ExpectCode(bfc::action::EncodeSnapshot(snapshot).code, "blend_factor", "nan blend");

    snapshot = FullSnapshot();
    snapshot.phaseRatio = 1.5f;
    ExpectCode(bfc::action::EncodeSnapshot(snapshot).code, "phase_ratio", "phase high");
    snapshot.phaseRatio = -0.01f;
    ExpectCode(bfc::action::EncodeSnapshot(snapshot).code, "phase_ratio", "phase negative");

    snapshot = FullSnapshot();
    snapshot.blendInPresent = false;
    snapshot.blendInHardCut = true;
    ExpectCode(bfc::action::EncodeSnapshot(snapshot).code, "hard_cut_without_blend_in", "hard cut");

    encoded = bfc::action::EncodeSnapshot(FullSnapshot());
    std::vector<uint8_t> flags = encoded.bytes;
    // flags sit at prefix offset: magic4 + ver2 + reserved2 + 4 u32s = 24
    flags[24] = static_cast<uint8_t>(flags[24] | 0x10u);
    ExpectCode(bfc::action::DecodeSnapshot(flags).code, "unknown_flags", "unknown flags");

    std::vector<uint8_t> mismatch = encoded.bytes;
    mismatch.resize(bfc::action::kActionSnapshotPrefixBytes + 4u);
    // blendCount is the u32 immediately after flags. flags at 24, count at 28.
    mismatch[28] = 2;
    mismatch[29] = 0;
    mismatch[30] = 0;
    mismatch[31] = 0;
    ExpectCode(bfc::action::DecodeSnapshot(mismatch).code, "truncated", "count payload mismatch");
}

void TestPlannerHappyPathAndEdge() {
    const bfc::action::ActionSnapshot snapshot = FullSnapshot();
    bfc::action::PuppetActionMemory memory;
    const bfc::action::ApplyPlan first =
        bfc::action::PlanActionApply(snapshot, PlayerExternal(), memory);
    Expect(first.allowed, "first allowed");
    ExpectCode(first.code, "apply", "first code");
    Expect(first.stepCount == 6, "six steps");
    Expect(first.steps[0] == bfc::action::ApplyStep::ActivateCharacterActionSetOnce, "cas first");
    Expect(first.steps[1] == bfc::action::ApplyStep::SetTargetAction, "target");
    Expect(first.steps[2] == bfc::action::ApplyStep::SeekPhase, "seek");
    Expect(first.steps[3] == bfc::action::ApplyStep::PatchBlendIn, "blend in");
    Expect(first.steps[4] == bfc::action::ApplyStep::PersistAndWriteBlends, "persist");
    Expect(first.steps[5] == bfc::action::ApplyStep::WriteTimeScale, "timescale step");
    Expect(first.blendChannelApplied == 0u, "apply uses controller channel");
    Expect(first.ignoredBodyPartChannel == 3u, "body channel not applied");
    Expect(bfc::action::DecideNativeApply(first).callEngine == false, "native stays off");
    ExpectCode(bfc::action::DecideNativeApply(first).code, "native_action_apply_refused",
               "native code");

    bfc::action::CommitApply(memory, snapshot, first);
    const bfc::action::ApplyPlan second =
        bfc::action::PlanActionApply(snapshot, PlayerExternal(), memory);
    Expect(second.allowed, "second allowed");
    Expect(!second.Contains(bfc::action::ApplyStep::ActivateCharacterActionSetOnce), "cas once");
    Expect(!second.Contains(bfc::action::ApplyStep::SetTargetAction), "no redundant target");
    Expect(second.Contains(bfc::action::ApplyStep::PersistAndWriteBlends), "persist every frame");
    Expect(second.Contains(bfc::action::ApplyStep::WriteTimeScale), "timescale every frame");

    bfc::action::ActionSnapshot changed = snapshot;
    changed.alias = 0x22u;
    const bfc::action::ApplyPlan third =
        bfc::action::PlanActionApply(changed, PlayerExternal(), memory);
    Expect(third.Contains(bfc::action::ApplyStep::SetTargetAction), "alias edge");
    Expect(!third.Contains(bfc::action::ApplyStep::ActivateCharacterActionSetOnce),
           "cas remains");

    bfc::action::ActionSnapshot noExtras = snapshot;
    noExtras.characterActionSetId = 0;
    noExtras.hasPhase = false;
    noExtras.blendInPresent = false;
    bfc::action::PuppetActionMemory fresh;
    const bfc::action::ApplyPlan sparse =
        bfc::action::PlanActionApply(noExtras, PlayerExternal(), fresh);
    Expect(sparse.allowed, "sparse allowed");
    Expect(!sparse.Contains(bfc::action::ApplyStep::ActivateCharacterActionSetOnce), "no cas id");
    Expect(!sparse.Contains(bfc::action::ApplyStep::SeekPhase), "no seek");
    Expect(!sparse.Contains(bfc::action::ApplyStep::PatchBlendIn), "no blend-in");
    Expect(sparse.Contains(bfc::action::ApplyStep::SetTargetAction), "still targets");
}

void TestRefusals() {
    const bfc::action::ActionSnapshot snapshot = FullSnapshot();
    bfc::action::PuppetActionMemory memory;
    bfc::action::ApplyContext context = PlayerExternal();

    context.site = bfc::action::UpdateSite::OffThread;
    ExpectCode(bfc::action::PlanActionApply(snapshot, context, memory).code, "off_thread",
               "off thread");
    context.site = bfc::action::UpdateSite::OtherHumanTick;
    ExpectCode(bfc::action::PlanActionApply(snapshot, context, memory).code, "not_player_human_tick",
               "npc tick");
    context.site = bfc::action::UpdateSite::Unknown;
    ExpectCode(bfc::action::PlanActionApply(snapshot, context, memory).code, "update_site_unknown",
               "unknown site");

    context = PlayerExternal();
    context.locomotion = bfc::action::LocomotionContext::Swim;
    ExpectCode(bfc::action::PlanActionApply(snapshot, context, memory).code,
               "swim_action_path_unproven", "swim");

    context = PlayerExternal();
    context.mode = bfc::action::ActionDriveMode::Refused;
    ExpectCode(bfc::action::PlanActionApply(snapshot, context, memory).code, "drive_mode_refused",
               "refused mode");

    context = PlayerExternal();
    context.mode = bfc::action::ActionDriveMode::HybridGroundFsm;
    context.locomotion = bfc::action::LocomotionContext::Unknown;
    ExpectCode(bfc::action::PlanActionApply(snapshot, context, memory).code,
               "locomotion_context_unknown", "hybrid unknown");

    context.locomotion = bfc::action::LocomotionContext::Ground;
    context.writeActions = true;
    ExpectCode(bfc::action::PlanActionApply(snapshot, context, memory).code, "ground_fsm_owns_blend",
               "ground refuses external blend");
    context.writeActions = false;
    const bfc::action::ApplyPlan idle = bfc::action::PlanActionApply(snapshot, context, memory);
    Expect(idle.allowed && idle.stepCount == 0, "ground idle has no steps");
    ExpectCode(idle.code, "behavior_owns_actions", "ground fsm owns");

    context.locomotion = bfc::action::LocomotionContext::OffGround;
    context.writeActions = true;
    ExpectCode(bfc::action::PlanActionApply(snapshot, context, memory).code, "apply",
               "hybrid off-ground applies");

    context = PlayerExternal();
    context.locomotion = bfc::action::LocomotionContext::Ground;
    ExpectCode(bfc::action::PlanActionApply(snapshot, context, memory).code, "apply",
               "external mode still writes on ground");

    context = PlayerExternal();
    context.writeActions = false;
    ExpectCode(bfc::action::PlanActionApply(snapshot, context, memory).code, "write_not_permitted",
               "write off");

    context = PlayerExternal();
    context.authorityCooldownRemaining = bfc::action::kUpstreamAuthorityCooldownFrames;
    ExpectCode(bfc::action::PlanActionApply(snapshot, context, memory).code,
               "authority_switch_cooldown", "cooldown");

    context = PlayerExternal();
    context.enforceStaleTick = true;
    context.minAcceptedTick = 101;
    ExpectCode(bfc::action::PlanActionApply(snapshot, context, memory).code, "stale_snapshot",
               "stale");

    bfc::action::ActionSnapshot partial = snapshot;
    partial.blendCount = 4;
    ExpectCode(bfc::action::PlanActionApply(partial, PlayerExternal(), memory).code,
               "partial_blend_width", "four-slot blend refused");

    bfc::action::ActionSnapshot wrongChannel = snapshot;
    wrongChannel.channel = 3;
    ExpectCode(bfc::action::PlanActionApply(wrongChannel, PlayerExternal(), memory).code,
               "blend_channel", "non-zero blend channel");

    bfc::action::ApplyContext wide = PlayerExternal();
    wide.expectedBlendSlots = bfc::action::kSafetyBlendSlotCap + 1;
    wide.requireFullBlendWidth = true;
    ExpectCode(bfc::action::PlanActionApply(snapshot, wide, memory).code, "blend_width_config",
               "width config");

    const bfc::action::ApplyPlan refused =
        bfc::action::PlanActionApply(partial, PlayerExternal(), memory);
    bfc::action::CommitApply(memory, partial, refused);
    Expect(!memory.casApplied && !memory.hasLastTarget, "commit ignores refusal");

    memory.casApplied = true;
    memory.hasLastTarget = true;
    memory.Reset();
    Expect(!memory.casApplied && !memory.hasLastTarget, "reset");
}

}  // namespace

int main() {
    TestRoundTrip();
    TestCodecRejections();
    TestPlannerHappyPathAndEdge();
    TestRefusals();
    if (g_failures != 0) {
        std::fprintf(stderr, "%d failure(s)\n", g_failures);
        return 1;
    }
    std::puts("action_replication_test: all checks passed");
    return 0;
}
