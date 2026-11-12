#pragma once

// Offline remote-puppet lifecycle for one peer.
//
// Engine creation, world enroll, and world removal are behind EngineOps.
// Those methods are not called unless AllowScriptedOpsForTests(true) is set.
// The shipping default never calls them and never reports a visible puppet.
//
// This type does not include Windows headers and does not know Resynced addresses.

#include <array>
#include <cstdint>
#include <string>

namespace bfc::puppet {

enum class Phase : uint8_t {
    Absent = 0,
    Waiting,
    AwaitingReload,
    Building,
    Unintegrated,
    Integrating,
    Present,
    Preserved,
    PeerGrace,
    Removing,
    RemovalBlocked,
    Dropped,
    TornDown,
    Count
};

enum class Visibility : uint8_t {
    None = 0,
    BuiltHidden,
    PendingEnroll,
    Visible,
    Preserved,
    Count
};

enum class EngineOp : uint8_t {
    None = 0,
    BeginDuplication,
    DuplicateSelector,
    EndDuplication,
    ReloadBuilder,
    BuildEntity,
    AddToWorld,
    RemoveFromWorld,
    Count
};

enum class OpStatus : uint8_t {
    Ok = 0,
    Refused,
    Failed,
    Pending,
    Count
};

// How the last in-world (or built) entity left our bookkeeping.
enum class ReleaseKind : uint8_t {
    None = 0,
    Removed,
    DroppedWithoutRemove,
    DiscardedUnintegrated,
    RemoveUnconfirmed,
    Count
};

struct Handle {
    uint64_t id = 0;
    uint32_t generation = 0;
    uint64_t worldId = 0;

    bool valid() const { return id != 0 && generation != 0; }

    void clear() {
        id = 0;
        generation = 0;
        worldId = 0;
    }
};

// Frame counts follow the AC4Coop net path (phase1.cpp OnFrame): spawn only
// after more than minStableFrames of successful local capture, peer-absent
// removal only after grace exceeds peerAbsentGraceFrames, and a world-freed
// entity waits worldSettleFrames before another attempt. Thresholds are
// overridable so tests can exercise the same inequalities without looping
// hundreds of frames.
struct Policy {
    uint32_t minStableFrames = 60;
    uint32_t peerAbsentGraceFrames = 180;
    uint32_t retryCooldownFrames = 120;
    uint32_t worldSettleFrames = 180;
    uint32_t reloadTimeoutFrames = 200;
    uint32_t buildTimeoutFrames = 30;
    uint32_t integrateTimeoutFrames = 2;
    uint32_t removeTimeoutFrames = 2;
    // Networked puppets integrate. Build-only (no Add) is the offline gate
    // that matches Coop.IntegratePuppet=0 with networking disabled.
    bool integrate = true;
};

// Caller-supplied view of one simulation frame. White-room, pause, menu, and
// a missing local player are all localCaptureOk=false. The machine does not
// inspect the game.
struct Observation {
    bool shutdown = false;
    bool sessionAlive = false;
    bool localCaptureOk = false;
    bool engineLoading = false;
    bool peerPacketValid = false;
    bool peerSameWorld = false;
    bool peerFresh = false;
    bool builderReady = false;
    bool selectorReady = false;
    bool builderResourceKnown = false;
    // Ignored when this machine is not holding an entity.
    bool entityStillAlive = true;
    uint64_t localWorldId = 0;
    uint64_t peerWorldId = 0;
};

struct Transition {
    Phase from = Phase::Absent;
    Phase to = Phase::Absent;
    EngineOp op = EngineOp::None;
    OpStatus status = OpStatus::Ok;
    uint32_t frame = 0;
    const char* reason = "";
};

struct StepResult {
    Phase phase = Phase::Absent;
    bool changed = false;
    bool engineInvoked = false;
    OpStatus engineStatus = OpStatus::Ok;
    const char* reason = "";
};

// Abstract world operations. The default body refuses every call.
// A future Resynced backend may override these only after the corresponding
// native primitive is proven. Returning Ok from an unproven override is a
// contract violation; the machine will not call overrides at all unless a
// test explicitly enables scripted ops.
class EngineOps {
public:
    virtual ~EngineOps() = default;

    virtual OpStatus BeginDuplication() { return OpStatus::Refused; }
    virtual OpStatus DuplicateSelector() { return OpStatus::Refused; }
    virtual OpStatus EndDuplication() { return OpStatus::Refused; }
    virtual OpStatus ReloadBuilder() { return OpStatus::Refused; }
    virtual OpStatus BuildEntity(Handle& out) {
        (void)out;
        return OpStatus::Refused;
    }
    virtual OpStatus AddToWorld(const Handle& handle) {
        (void)handle;
        return OpStatus::Refused;
    }
    virtual OpStatus RemoveFromWorld(const Handle& handle) {
        (void)handle;
        return OpStatus::Refused;
    }
};

const char* PhaseName(Phase phase);
const char* VisibilityName(Visibility visibility);
const char* EngineOpName(EngineOp op);
const char* OpStatusName(OpStatus status);
const char* ReleaseKindName(ReleaseKind kind);

// One remote puppet. Not thread-safe. Call from the simulation thread only.
// The machine never assigns a local pad: ClaimsLocalPad() is always false.
class RemotePuppetLifecycle {
public:
    static constexpr uint32_t kHistoryCap = 64;

    explicit RemotePuppetLifecycle(Policy policy = {});

    void SetOps(EngineOps* ops);
    void AllowScriptedOpsForTests(bool allow);
    bool scriptedOpsAllowed() const { return allowScripted_; }

    const Policy& policy() const { return policy_; }
    Phase phase() const { return phase_; }
    Visibility visibility() const { return visibility_; }
    Handle driveHandle() const { return drive_; }
    Handle pendingRemoval() const { return pendingRemoval_; }
    Handle unintegratedHandle() const { return unintegrated_; }
    uint32_t generation() const { return generation_; }
    uint32_t stableFrames() const { return stableFrames_; }
    uint32_t cooldownFrames() const { return cooldown_; }
    uint32_t graceFrames() const { return grace_; }
    bool duplicationBalanced() const { return duplicationBalanced_; }
    int duplicationDepth() const { return duplicationDepth_; }
    bool claimsLocalPad() const { return false; }
    bool driveAllowed() const;
    bool driveSuppressed() const { return driveSuppressed_; }
    ReleaseKind lastRelease() const { return lastRelease_; }
    bool removalConfirmed() const { return removalConfirmed_; }
    bool leakRisk() const { return leakRisk_; }
    const char* lastReason() const { return lastReason_; }
    uint32_t frame() const { return frame_; }
    uint32_t transitionCount() const { return transitionCount_; }
    uint32_t historySize() const { return historyCount_; }
    const Transition& historyAt(uint32_t chronologicalIndex) const;
    uint32_t ignoredCount() const { return ignored_; }
    uint32_t refusalCount() const { return refusals_; }
    uint32_t spawnAttempts() const { return spawnAttempts_; }
    uint32_t rollbackCount() const { return rollbacks_; }
    uint32_t dropCount() const { return drops_; }
    uint32_t removeAttempts() const { return removeAttempts_; }
    uint32_t engineCallCount() const { return engineCalls_; }

    StepResult Tick(const Observation& obs);
    StepResult Shutdown();
    StepResult Reset();
    StepResult PeerLeft();
    StepResult NotifyEntityFreed(uint32_t generation);
    StepResult NotifyOp(EngineOp op, OpStatus status, uint32_t generation);

    std::string Describe() const;

private:
    StepResult Note(Phase to,
                    const char* reason,
                    EngineOp op = EngineOp::None,
                    OpStatus status = OpStatus::Ok,
                    bool invoked = false);
    StepResult Quiet(const char* reason);
    StepResult Ignore(const char* reason);

    void UpdateStable(const Observation& obs);
    void SettleEnroll(const Observation& obs);
    bool PeerPresent(const Observation& obs) const;
    bool SpawnEligible(const Observation& obs) const;
    Handle HeldEntity() const;

    StepResult DropHeldEntity(const char* reason);
    StepResult DiscardUnintegrated(const char* reason);
    StepResult StartRemove(const char* reason, Phase afterConfirmed);
    StepResult ConsiderSpawn(const Observation& obs);
    StepResult BeginSpawnAttempt(const Observation& obs);
    StepResult OnBuilt(Handle built, const char* reason);
    StepResult ConsiderPresence(const Observation& obs);
    StepResult PollReload(const Observation& obs);
    StepResult PollBuilding(const Observation& obs);
    StepResult PollIntegrating(const Observation& obs);
    StepResult PollRemoving(const Observation& obs);
    OpStatus Invoke(EngineOp op, Handle* handle);

    Policy policy_{};
    EngineOps* ops_ = nullptr;
    bool allowScripted_ = false;

    Phase phase_ = Phase::Absent;
    Visibility visibility_ = Visibility::None;
    Handle drive_{};
    Handle integrating_{};
    Handle unintegrated_{};
    Handle pendingRemoval_{};
    uint32_t generation_ = 0;
    uint32_t pendingGeneration_ = 0;
    EngineOp pendingOp_ = EngineOp::None;

    uint32_t frame_ = 0;
    uint32_t stableFrames_ = 0;
    uint32_t cooldown_ = 0;
    uint32_t grace_ = 0;
    uint32_t presentFrames_ = 0;
    uint32_t opWait_ = 0;

    bool duplicationBalanced_ = true;
    int duplicationDepth_ = 0;
    bool driveSuppressed_ = false;
    bool removalConfirmed_ = false;
    bool removeIssued_ = false;
    bool shutdownRequested_ = false;
    bool leakRisk_ = false;
    bool enrollSettled_ = false;
    ReleaseKind lastRelease_ = ReleaseKind::None;
    const char* lastReason_ = "absent";

    uint32_t transitionCount_ = 0;
    uint32_t historyCount_ = 0;
    uint32_t historyWrite_ = 0;
    uint32_t ignored_ = 0;
    uint32_t refusals_ = 0;
    uint32_t spawnAttempts_ = 0;
    uint32_t rollbacks_ = 0;
    uint32_t drops_ = 0;
    uint32_t removeAttempts_ = 0;
    uint32_t engineCalls_ = 0;
    bool stepInvoked_ = false;

    std::array<Transition, kHistoryCap> history_{};
};

}  // namespace bfc::puppet
