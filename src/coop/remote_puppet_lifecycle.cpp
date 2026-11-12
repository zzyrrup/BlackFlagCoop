#include "coop/remote_puppet_lifecycle.h"

#include <sstream>
#include <stdexcept>

namespace bfc::puppet {
namespace {

constexpr uint32_t kMaxCounter = 1000000u;

uint32_t SaturatingInc(uint32_t value) {
    return value < kMaxCounter ? value + 1u : value;
}

}  // namespace

const char* PhaseName(Phase phase) {
    switch (phase) {
    case Phase::Absent: return "Absent";
    case Phase::Waiting: return "Waiting";
    case Phase::AwaitingReload: return "AwaitingReload";
    case Phase::Building: return "Building";
    case Phase::Unintegrated: return "Unintegrated";
    case Phase::Integrating: return "Integrating";
    case Phase::Present: return "Present";
    case Phase::Preserved: return "Preserved";
    case Phase::PeerGrace: return "PeerGrace";
    case Phase::Removing: return "Removing";
    case Phase::RemovalBlocked: return "RemovalBlocked";
    case Phase::Dropped: return "Dropped";
    case Phase::TornDown: return "TornDown";
    case Phase::Count: break;
    }
    return "Unknown";
}

const char* VisibilityName(Visibility visibility) {
    switch (visibility) {
    case Visibility::None: return "None";
    case Visibility::BuiltHidden: return "BuiltHidden";
    case Visibility::PendingEnroll: return "PendingEnroll";
    case Visibility::Visible: return "Visible";
    case Visibility::Preserved: return "Preserved";
    case Visibility::Count: break;
    }
    return "Unknown";
}

const char* EngineOpName(EngineOp op) {
    switch (op) {
    case EngineOp::None: return "None";
    case EngineOp::BeginDuplication: return "BeginDuplication";
    case EngineOp::DuplicateSelector: return "DuplicateSelector";
    case EngineOp::EndDuplication: return "EndDuplication";
    case EngineOp::ReloadBuilder: return "ReloadBuilder";
    case EngineOp::BuildEntity: return "BuildEntity";
    case EngineOp::AddToWorld: return "AddToWorld";
    case EngineOp::RemoveFromWorld: return "RemoveFromWorld";
    case EngineOp::Count: break;
    }
    return "Unknown";
}

const char* OpStatusName(OpStatus status) {
    switch (status) {
    case OpStatus::Ok: return "Ok";
    case OpStatus::Refused: return "Refused";
    case OpStatus::Failed: return "Failed";
    case OpStatus::Pending: return "Pending";
    case OpStatus::Count: break;
    }
    return "Unknown";
}

const char* ReleaseKindName(ReleaseKind kind) {
    switch (kind) {
    case ReleaseKind::None: return "None";
    case ReleaseKind::Removed: return "Removed";
    case ReleaseKind::DroppedWithoutRemove: return "DroppedWithoutRemove";
    case ReleaseKind::DiscardedUnintegrated: return "DiscardedUnintegrated";
    case ReleaseKind::RemoveUnconfirmed: return "RemoveUnconfirmed";
    case ReleaseKind::Count: break;
    }
    return "Unknown";
}

RemotePuppetLifecycle::RemotePuppetLifecycle(Policy policy) : policy_(policy) {}

void RemotePuppetLifecycle::SetOps(EngineOps* ops) { ops_ = ops; }

void RemotePuppetLifecycle::AllowScriptedOpsForTests(bool allow) {
    allowScripted_ = allow;
}

bool RemotePuppetLifecycle::driveAllowed() const {
    return phase_ == Phase::Present && drive_.valid() && !driveSuppressed_;
}

const Transition& RemotePuppetLifecycle::historyAt(uint32_t chronologicalIndex) const {
    if (chronologicalIndex >= historyCount_) {
        throw std::out_of_range("puppet lifecycle history index");
    }
    const uint32_t start =
        (historyWrite_ + kHistoryCap - historyCount_) % kHistoryCap;
    return history_[(start + chronologicalIndex) % kHistoryCap];
}

StepResult RemotePuppetLifecycle::Note(Phase to,
                                       const char* reason,
                                       EngineOp op,
                                       OpStatus status,
                                       bool invoked) {
    Transition record;
    record.from = phase_;
    record.to = to;
    record.op = op;
    record.status = status;
    record.frame = frame_;
    record.reason = reason;
    history_[historyWrite_] = record;
    historyWrite_ = (historyWrite_ + 1u) % kHistoryCap;
    if (historyCount_ < kHistoryCap) {
        ++historyCount_;
    }
    ++transitionCount_;

    const bool changed = phase_ != to;
    phase_ = to;
    lastReason_ = reason;
    (void)invoked;
    if (status == OpStatus::Refused) {
        ++refusals_;
    }
    if (to != Phase::Present) {
        presentFrames_ = 0;
    }
    StepResult result;
    result.phase = to;
    result.changed = changed;
    result.engineInvoked = stepInvoked_;
    result.engineStatus = status;
    result.reason = reason;
    return result;
}

StepResult RemotePuppetLifecycle::Quiet(const char* reason) {
    lastReason_ = reason;
    StepResult result;
    result.phase = phase_;
    result.changed = false;
    result.engineInvoked = stepInvoked_;
    result.engineStatus = OpStatus::Ok;
    result.reason = reason;
    return result;
}

StepResult RemotePuppetLifecycle::Ignore(const char* reason) {
    ++ignored_;
    return Quiet(reason);
}

void RemotePuppetLifecycle::UpdateStable(const Observation& obs) {
    if (obs.localCaptureOk) {
        stableFrames_ = SaturatingInc(stableFrames_);
    } else {
        stableFrames_ = 0;
    }
}

void RemotePuppetLifecycle::SettleEnroll(const Observation& obs) {
    driveSuppressed_ = false;
    if (phase_ != Phase::Present || !drive_.valid()) {
        return;
    }
    if (obs.engineLoading) {
        driveSuppressed_ = true;
        return;
    }
    presentFrames_ = SaturatingInc(presentFrames_);
    if (presentFrames_ >= 1u && visibility_ == Visibility::PendingEnroll) {
        visibility_ = Visibility::Visible;
        enrollSettled_ = true;
    }
}

bool RemotePuppetLifecycle::PeerPresent(const Observation& obs) const {
    return obs.sessionAlive && obs.peerPacketValid && obs.peerSameWorld &&
           obs.peerFresh && obs.localWorldId != 0 &&
           obs.peerWorldId == obs.localWorldId;
}

bool RemotePuppetLifecycle::SpawnEligible(const Observation& obs) const {
    return obs.localCaptureOk && !obs.engineLoading && PeerPresent(obs) &&
           stableFrames_ > policy_.minStableFrames && !drive_.valid() &&
           !integrating_.valid() && !unintegrated_.valid() &&
           !pendingRemoval_.valid();
}

Handle RemotePuppetLifecycle::HeldEntity() const {
    if (drive_.valid()) {
        return drive_;
    }
    if (integrating_.valid()) {
        return integrating_;
    }
    if (unintegrated_.valid()) {
        return unintegrated_;
    }
    return {};
}

OpStatus RemotePuppetLifecycle::Invoke(EngineOp op, Handle* handle) {
    if (!allowScripted_ || ops_ == nullptr) {
        return OpStatus::Refused;
    }
    OpStatus status = OpStatus::Refused;
    switch (op) {
    case EngineOp::BeginDuplication:
        status = ops_->BeginDuplication();
        break;
    case EngineOp::DuplicateSelector:
        status = ops_->DuplicateSelector();
        break;
    case EngineOp::EndDuplication:
        status = ops_->EndDuplication();
        break;
    case EngineOp::ReloadBuilder:
        status = ops_->ReloadBuilder();
        break;
    case EngineOp::BuildEntity:
        status = ops_->BuildEntity(*handle);
        break;
    case EngineOp::AddToWorld:
        status = ops_->AddToWorld(*handle);
        break;
    case EngineOp::RemoveFromWorld:
        status = ops_->RemoveFromWorld(*handle);
        break;
    case EngineOp::None:
    case EngineOp::Count:
        status = OpStatus::Refused;
        break;
    }
    ++engineCalls_;
    stepInvoked_ = true;
    return status;
}

StepResult RemotePuppetLifecycle::DropHeldEntity(const char* reason) {
    const bool had =
        drive_.valid() || integrating_.valid() || unintegrated_.valid();
    drive_.clear();
    integrating_.clear();
    unintegrated_.clear();
    pendingRemoval_.clear();
    pendingOp_ = EngineOp::None;
    pendingGeneration_ = 0;
    removeIssued_ = false;
    visibility_ = Visibility::None;
    driveSuppressed_ = false;
    enrollSettled_ = false;
    grace_ = 0;
    presentFrames_ = 0;
    opWait_ = 0;
    if (had) {
        ++drops_;
        lastRelease_ = ReleaseKind::DroppedWithoutRemove;
        cooldown_ = policy_.worldSettleFrames;
        removalConfirmed_ = false;
    }
    return Note(Phase::Dropped, reason, EngineOp::None, OpStatus::Ok, false);
}

StepResult RemotePuppetLifecycle::DiscardUnintegrated(const char* reason) {
    unintegrated_.clear();
    visibility_ = Visibility::None;
    leakRisk_ = true;
    ++rollbacks_;
    lastRelease_ = ReleaseKind::DiscardedUnintegrated;
    cooldown_ = policy_.retryCooldownFrames;
    return Note(Phase::Waiting, reason, EngineOp::None, OpStatus::Failed, false);
}

StepResult RemotePuppetLifecycle::StartRemove(const char* reason,
                                              Phase afterConfirmed) {
    if (phase_ == Phase::RemovalBlocked ||
        (removeIssued_ && pendingRemoval_.valid())) {
        return Quiet("remove already outstanding");
    }

    Handle token = drive_.valid() ? drive_ : integrating_;
    // Stop driving before any removal request. A later failure must not
    // leave Apply-style consumers with the handle.
    drive_.clear();
    integrating_.clear();
    visibility_ = Visibility::None;
    driveSuppressed_ = false;
    grace_ = 0;
    presentFrames_ = 0;

    if (unintegrated_.valid() && !token.valid()) {
        return DiscardUnintegrated(reason);
    }
    if (!token.valid()) {
        Phase dest = afterConfirmed == Phase::TornDown ? Phase::TornDown
                                                       : Phase::Absent;
        if (phase_ == dest) {
            return Quiet(reason);
        }
        return Note(dest, reason);
    }

    pendingRemoval_ = token;
    pendingGeneration_ = token.generation;
    removalConfirmed_ = false;

    const bool invoked = allowScripted_ && ops_ != nullptr;
    if (!invoked) {
        removeIssued_ = false;
        lastRelease_ = ReleaseKind::RemoveUnconfirmed;
        leakRisk_ = true;
        return Note(Phase::RemovalBlocked,
                    reason,
                    EngineOp::RemoveFromWorld,
                    OpStatus::Refused,
                    false);
    }

    removeIssued_ = true;
    ++removeAttempts_;
    const OpStatus status = Invoke(EngineOp::RemoveFromWorld, &token);
    if (status == OpStatus::Ok) {
        pendingRemoval_.clear();
        pendingOp_ = EngineOp::None;
        pendingGeneration_ = 0;
        removeIssued_ = false;
        removalConfirmed_ = true;
        lastRelease_ = ReleaseKind::Removed;
        const Phase dest =
            shutdownRequested_ ? Phase::TornDown : afterConfirmed;
        return Note(dest, reason, EngineOp::RemoveFromWorld, status, true);
    }
    if (status == OpStatus::Pending) {
        pendingOp_ = EngineOp::RemoveFromWorld;
        opWait_ = 0;
        lastRelease_ = ReleaseKind::RemoveUnconfirmed;
        return Note(Phase::Removing, reason, EngineOp::RemoveFromWorld, status, true);
    }
    lastRelease_ = ReleaseKind::RemoveUnconfirmed;
    leakRisk_ = true;
    pendingOp_ = EngineOp::None;
    return Note(Phase::RemovalBlocked,
                reason,
                EngineOp::RemoveFromWorld,
                status,
                true);
}

StepResult RemotePuppetLifecycle::OnBuilt(Handle built, const char* reason) {
    if (!built.valid()) {
        built.id = generation_;
        built.generation = generation_;
    }
    pendingOp_ = EngineOp::None;
    pendingGeneration_ = 0;
    opWait_ = 0;

    if (!policy_.integrate) {
        unintegrated_ = built;
        visibility_ = Visibility::BuiltHidden;
        leakRisk_ = true;
        return Note(Phase::Unintegrated, reason, EngineOp::BuildEntity, OpStatus::Ok, false);
    }

    const bool invoked = allowScripted_ && ops_ != nullptr;
    if (!invoked) {
        unintegrated_ = built;
        leakRisk_ = true;
        ++rollbacks_;
        lastRelease_ = ReleaseKind::DiscardedUnintegrated;
        unintegrated_.clear();
        visibility_ = Visibility::None;
        return Note(Phase::Waiting,
                    "add refused after build; unintegrated handle discarded",
                    EngineOp::AddToWorld,
                    OpStatus::Refused,
                    false);
    }

    const OpStatus status = Invoke(EngineOp::AddToWorld, &built);
    if (status == OpStatus::Ok) {
        drive_ = built;
        visibility_ = Visibility::PendingEnroll;
        presentFrames_ = 0;
        enrollSettled_ = false;
        return Note(Phase::Present, reason, EngineOp::AddToWorld, status, true);
    }
    if (status == OpStatus::Pending) {
        integrating_ = built;
        pendingOp_ = EngineOp::AddToWorld;
        pendingGeneration_ = built.generation;
        opWait_ = 0;
        visibility_ = Visibility::PendingEnroll;
        return Note(Phase::Integrating, reason, EngineOp::AddToWorld, status, true);
    }

    leakRisk_ = true;
    ++rollbacks_;
    lastRelease_ = ReleaseKind::DiscardedUnintegrated;
    visibility_ = Visibility::None;
    cooldown_ = policy_.retryCooldownFrames;
    return Note(Phase::Waiting,
                "add failed; unintegrated handle discarded without Remove",
                EngineOp::AddToWorld,
                status,
                true);
}

StepResult RemotePuppetLifecycle::BeginSpawnAttempt(const Observation& obs) {
    spawnAttempts_ = SaturatingInc(spawnAttempts_);
    cooldown_ = policy_.retryCooldownFrames;
    duplicationDepth_ = 0;

    const bool canCall = allowScripted_ && ops_ != nullptr;
    if (!canCall) {
        return Note(Phase::Waiting,
                    "native spawn sequence refused",
                    EngineOp::BuildEntity,
                    OpStatus::Refused,
                    false);
    }

    const OpStatus began = Invoke(EngineOp::BeginDuplication, nullptr);
    if (began != OpStatus::Ok) {
        return Note(Phase::Waiting,
                    "duplication begin refused or failed",
                    EngineOp::BeginDuplication,
                    began,
                    true);
    }

    duplicationDepth_ = 1;
    const OpStatus duplicated = Invoke(EngineOp::DuplicateSelector, nullptr);
    const OpStatus ended = Invoke(EngineOp::EndDuplication, nullptr);
    duplicationDepth_ = 0;
    if (ended != OpStatus::Ok) {
        duplicationBalanced_ = false;
        cooldown_ = policy_.retryCooldownFrames;
        return Note(Phase::Waiting,
                    "duplication end failed after begin",
                    EngineOp::EndDuplication,
                    ended,
                    true);
    }
    if (duplicated != OpStatus::Ok) {
        return Note(Phase::Waiting,
                    "selector duplicate failed; duplication scope closed",
                    EngineOp::DuplicateSelector,
                    duplicated,
                    true);
    }

    Handle built;
    built.worldId = obs.localWorldId;
    generation_ = SaturatingInc(generation_);
    built.generation = generation_;
    const OpStatus builtStatus = Invoke(EngineOp::BuildEntity, &built);
    if (builtStatus == OpStatus::Pending) {
        pendingOp_ = EngineOp::BuildEntity;
        pendingGeneration_ = generation_;
        opWait_ = 0;
        return Note(Phase::Building,
                    "build pending",
                    EngineOp::BuildEntity,
                    builtStatus,
                    true);
    }
    if (builtStatus != OpStatus::Ok) {
        return Note(Phase::Waiting,
                    "build failed after balanced duplication",
                    EngineOp::BuildEntity,
                    builtStatus,
                    true);
    }
    if (built.generation == 0) {
        built.generation = generation_;
    }
    if (built.id == 0) {
        built.id = generation_;
    }
    built.worldId = obs.localWorldId;
    return OnBuilt(built, "entity built");
}

StepResult RemotePuppetLifecycle::ConsiderSpawn(const Observation& obs) {
    if (phase_ == Phase::Dropped && !SpawnEligible(obs)) {
        return Quiet("dropped; waiting for settle and prerequisites");
    }
    if (!SpawnEligible(obs)) {
        if (phase_ == Phase::Dropped && cooldown_ == 0) {
            return Note(Phase::Waiting, "world settle complete");
        }
        return Quiet("spawn prerequisites unmet");
    }
    if (cooldown_ > 0) {
        --cooldown_;
        if (phase_ == Phase::Dropped && cooldown_ == 0) {
            return Note(Phase::Waiting, "world settle cooldown elapsed");
        }
        return Quiet("spawn cooldown");
    }
    if (!obs.builderReady || !obs.selectorReady) {
        spawnAttempts_ = SaturatingInc(spawnAttempts_);
        cooldown_ = policy_.retryCooldownFrames;
        if (!obs.builderResourceKnown) {
            return Note(Phase::Waiting,
                        "builder or selector not ready",
                        EngineOp::None,
                        OpStatus::Ok,
                        false);
        }
        const bool canCall = allowScripted_ && ops_ != nullptr;
        if (!canCall) {
            return Note(Phase::Waiting,
                        "builder reload refused",
                        EngineOp::ReloadBuilder,
                        OpStatus::Refused,
                        false);
        }
        const OpStatus status = Invoke(EngineOp::ReloadBuilder, nullptr);
        if (status == OpStatus::Pending) {
            pendingOp_ = EngineOp::ReloadBuilder;
            pendingGeneration_ = generation_;
            opWait_ = 0;
            return Note(Phase::AwaitingReload,
                        "builder reload pending",
                        EngineOp::ReloadBuilder,
                        status,
                        true);
        }
        if (status == OpStatus::Ok) {
            return Note(Phase::Waiting,
                        "builder reload completed; waiting for ready observation",
                        EngineOp::ReloadBuilder,
                        status,
                        true);
        }
        return Note(Phase::Waiting,
                    "builder reload failed",
                    EngineOp::ReloadBuilder,
                    status,
                    true);
    }

    return BeginSpawnAttempt(obs);
}

StepResult RemotePuppetLifecycle::ConsiderPresence(const Observation& obs) {
    if (!drive_.valid()) {
        visibility_ = Visibility::None;
        return Note(Phase::Waiting, "present without a drive handle");
    }
    if (!obs.localCaptureOk) {
        grace_ = 0;
        driveSuppressed_ = true;
        visibility_ = Visibility::Preserved;
        if (phase_ == Phase::Preserved) {
            return Quiet("local capture failed; puppet preserved");
        }
        return Note(Phase::Preserved, "local capture failed; puppet preserved");
    }
    if (PeerPresent(obs)) {
        grace_ = 0;
        if (obs.engineLoading) {
            driveSuppressed_ = true;
        }
        if (phase_ == Phase::Present) {
            return Quiet(obs.engineLoading ? "loading; drive suppressed"
                                           : "peer present");
        }
        visibility_ = enrollSettled_ ? Visibility::Visible
                                    : Visibility::PendingEnroll;
        return Note(Phase::Present, "peer present");
    }

    grace_ = SaturatingInc(grace_);
    driveSuppressed_ = true;
    if (grace_ > policy_.peerAbsentGraceFrames) {
        grace_ = 0;
        const Phase after =
            obs.sessionAlive ? Phase::Waiting : Phase::Absent;
        return StartRemove("peer absent past grace; remove", after);
    }
    if (phase_ == Phase::PeerGrace) {
        return Quiet("peer absent; grace counting");
    }
    return Note(Phase::PeerGrace, "peer absent; grace started");
}

StepResult RemotePuppetLifecycle::PollReload(const Observation& obs) {
    if (obs.builderReady && obs.selectorReady) {
        pendingOp_ = EngineOp::None;
        return Note(Phase::Waiting, "builder became ready");
    }
    opWait_ = SaturatingInc(opWait_);
    if (opWait_ > policy_.reloadTimeoutFrames) {
        pendingOp_ = EngineOp::None;
        cooldown_ = policy_.retryCooldownFrames;
        return Note(Phase::Waiting,
                    "builder reload timed out",
                    EngineOp::ReloadBuilder,
                    OpStatus::Failed,
                    false);
    }
    return Quiet("awaiting builder reload");
}

StepResult RemotePuppetLifecycle::PollBuilding(const Observation& obs) {
    (void)obs;
    opWait_ = SaturatingInc(opWait_);
    if (opWait_ > policy_.buildTimeoutFrames) {
        pendingOp_ = EngineOp::None;
        cooldown_ = policy_.retryCooldownFrames;
        return Note(Phase::Waiting,
                    "build timed out",
                    EngineOp::BuildEntity,
                    OpStatus::Failed,
                    false);
    }
    return Quiet("build pending");
}

StepResult RemotePuppetLifecycle::PollIntegrating(const Observation& obs) {
    (void)obs;
    opWait_ = SaturatingInc(opWait_);
    if (opWait_ > policy_.integrateTimeoutFrames) {
        integrating_.clear();
        pendingOp_ = EngineOp::None;
        visibility_ = Visibility::None;
        leakRisk_ = true;
        ++rollbacks_;
        lastRelease_ = ReleaseKind::DiscardedUnintegrated;
        cooldown_ = policy_.retryCooldownFrames;
        return Note(Phase::Waiting,
                    "integrate timed out; handle discarded without Remove",
                    EngineOp::AddToWorld,
                    OpStatus::Failed,
                    false);
    }
    return Quiet("add pending");
}

StepResult RemotePuppetLifecycle::PollRemoving(const Observation& obs) {
    (void)obs;
    opWait_ = SaturatingInc(opWait_);
    if (opWait_ > policy_.removeTimeoutFrames) {
        pendingOp_ = EngineOp::None;
        lastRelease_ = ReleaseKind::RemoveUnconfirmed;
        leakRisk_ = true;
        const StepResult blocked =
            Note(Phase::RemovalBlocked,
                 "remove timed out",
                 EngineOp::RemoveFromWorld,
                 OpStatus::Failed,
                 false);
        if (shutdownRequested_) {
            return Note(Phase::TornDown, "shutdown with unconfirmed removal");
        }
        return blocked;
    }
    return Quiet("remove pending");
}

StepResult RemotePuppetLifecycle::Shutdown() {
    if (phase_ == Phase::TornDown) {
        return Ignore("shutdown already complete");
    }
    shutdownRequested_ = true;
    if (phase_ == Phase::Removing) {
        return Quiet("shutdown waiting for in-flight remove");
    }
    if (phase_ == Phase::RemovalBlocked) {
        // Do not issue a second remove. Teardown of our state is explicit
        // about the engine remove never being confirmed.
        pendingOp_ = EngineOp::None;
        pendingRemoval_.clear();
        removeIssued_ = false;
        drive_.clear();
        integrating_.clear();
        visibility_ = Visibility::None;
        enrollSettled_ = false;
        leakRisk_ = true;
        lastRelease_ = ReleaseKind::RemoveUnconfirmed;
        grace_ = 0;
        return Note(Phase::TornDown, "shutdown with unconfirmed removal");
    }
    if (unintegrated_.valid() && !drive_.valid() && !integrating_.valid()) {
        unintegrated_.clear();
        visibility_ = Visibility::None;
        leakRisk_ = true;
        lastRelease_ = ReleaseKind::DiscardedUnintegrated;
        return Note(Phase::TornDown, "shutdown discarded unintegrated entity");
    }
    if (drive_.valid() || integrating_.valid()) {
        const StepResult removed =
            StartRemove("shutdown", Phase::TornDown);
        if (phase_ == Phase::RemovalBlocked) {
            return Shutdown();
        }
        return removed;
    }
    visibility_ = Visibility::None;
    grace_ = 0;
    driveSuppressed_ = false;
    return Note(Phase::TornDown, "shutdown with no entity");
}

StepResult RemotePuppetLifecycle::Reset() {
    if (drive_.valid() || integrating_.valid() || unintegrated_.valid() ||
        pendingRemoval_.valid() || phase_ == Phase::RemovalBlocked ||
        phase_ == Phase::Removing) {
        return Ignore("reset refused while an entity or removal is outstanding");
    }
    phase_ = Phase::Absent;
    visibility_ = Visibility::None;
    stableFrames_ = 0;
    cooldown_ = 0;
    grace_ = 0;
    presentFrames_ = 0;
    opWait_ = 0;
    pendingOp_ = EngineOp::None;
    pendingGeneration_ = 0;
    driveSuppressed_ = false;
    shutdownRequested_ = false;
    enrollSettled_ = false;
    removalConfirmed_ = false;
    removeIssued_ = false;
    lastRelease_ = ReleaseKind::None;
    lastReason_ = "reset";
    StepResult result;
    result.phase = Phase::Absent;
    result.changed = true;
    result.reason = "reset";
    return result;
}

StepResult RemotePuppetLifecycle::PeerLeft() {
    if (phase_ == Phase::TornDown) {
        return Ignore("peer left ignored after teardown");
    }
    if (phase_ == Phase::RemovalBlocked || phase_ == Phase::Removing) {
        return Quiet("peer left while removal outstanding");
    }
    if (drive_.valid() || integrating_.valid() || unintegrated_.valid()) {
        return StartRemove("peer left", Phase::Absent);
    }
    if (phase_ == Phase::Absent) {
        return Ignore("peer left with no session");
    }
    grace_ = 0;
    cooldown_ = 0;
    visibility_ = Visibility::None;
    return Note(Phase::Absent, "peer left before spawn");
}

StepResult RemotePuppetLifecycle::NotifyEntityFreed(uint32_t generation) {
    Handle held = HeldEntity();
    if (!held.valid() && pendingRemoval_.valid()) {
        held = pendingRemoval_;
    }
    if (!held.valid()) {
        return Ignore("entity-freed with no handle");
    }
    if (generation != 0 && generation != held.generation) {
        return Ignore("stale entity-freed generation");
    }
    if (phase_ == Phase::Removing || phase_ == Phase::RemovalBlocked) {
        pendingRemoval_.clear();
        pendingOp_ = EngineOp::None;
        removeIssued_ = false;
        removalConfirmed_ = false;
        lastRelease_ = ReleaseKind::DroppedWithoutRemove;
        ++drops_;
        visibility_ = Visibility::None;
        enrollSettled_ = false;
        cooldown_ = policy_.worldSettleFrames;
        return Note(Phase::Dropped,
                    "entity freed during removal; remove not repeated");
    }
    return DropHeldEntity("entity freed");
}

StepResult RemotePuppetLifecycle::NotifyOp(EngineOp op,
                                           OpStatus status,
                                           uint32_t generation) {
    if (pendingOp_ == EngineOp::None || op != pendingOp_) {
        return Ignore("stale or unexpected op completion");
    }
    if (generation != 0 && pendingGeneration_ != 0 &&
        generation != pendingGeneration_) {
        return Ignore("stale op generation");
    }
    if (status == OpStatus::Pending) {
        return Quiet("op still pending");
    }

    if (op == EngineOp::BuildEntity && phase_ == Phase::Building) {
        pendingOp_ = EngineOp::None;
        if (status != OpStatus::Ok) {
            cooldown_ = policy_.retryCooldownFrames;
            return Note(Phase::Waiting, "build completion failed", op, status, false);
        }
        Handle built;
        built.id = generation_ == 0 ? 1 : generation_;
        built.generation = generation_;
        return OnBuilt(built, "build completion");
    }
    if (op == EngineOp::AddToWorld && phase_ == Phase::Integrating) {
        pendingOp_ = EngineOp::None;
        if (status != OpStatus::Ok) {
            integrating_.clear();
            visibility_ = Visibility::None;
            leakRisk_ = true;
            ++rollbacks_;
            lastRelease_ = ReleaseKind::DiscardedUnintegrated;
            cooldown_ = policy_.retryCooldownFrames;
            return Note(Phase::Waiting,
                        "add completion failed; handle discarded without Remove",
                        op,
                        status,
                        false);
        }
        drive_ = integrating_;
        integrating_.clear();
        visibility_ = Visibility::PendingEnroll;
        presentFrames_ = 0;
        enrollSettled_ = false;
        return Note(Phase::Present, "add completion", op, status, false);
    }
    if (op == EngineOp::RemoveFromWorld &&
        (phase_ == Phase::Removing || phase_ == Phase::RemovalBlocked)) {
        pendingOp_ = EngineOp::None;
        if (status != OpStatus::Ok) {
            lastRelease_ = ReleaseKind::RemoveUnconfirmed;
            leakRisk_ = true;
            return Note(Phase::RemovalBlocked, "remove completion failed", op, status, false);
        }
        pendingRemoval_.clear();
        removeIssued_ = false;
        removalConfirmed_ = true;
        lastRelease_ = ReleaseKind::Removed;
        visibility_ = Visibility::None;
        enrollSettled_ = false;
        const Phase dest = shutdownRequested_ ? Phase::TornDown : Phase::Waiting;
        return Note(dest, "remove completion", op, status, false);
    }
    if (op == EngineOp::ReloadBuilder && phase_ == Phase::AwaitingReload) {
        pendingOp_ = EngineOp::None;
        if (status != OpStatus::Ok) {
            cooldown_ = policy_.retryCooldownFrames;
            return Note(Phase::Waiting, "reload completion failed", op, status, false);
        }
        return Note(Phase::Waiting,
                    "reload completion; waiting for ready observation",
                    op,
                    status,
                    false);
    }
    return Ignore("op completion does not match phase");
}

StepResult RemotePuppetLifecycle::Tick(const Observation& obs) {
    stepInvoked_ = false;
    frame_ = SaturatingInc(frame_);

    if ((drive_.valid() || integrating_.valid()) && !obs.entityStillAlive) {
        const StepResult dropped = DropHeldEntity("in-world entity not alive");
        if (!obs.shutdown) {
            return dropped;
        }
    } else if (phase_ == Phase::Removing && pendingRemoval_.valid() &&
               !obs.entityStillAlive) {
        const StepResult dropped =
            NotifyEntityFreed(pendingRemoval_.generation);
        if (!obs.shutdown) {
            return dropped;
        }
    } else if (unintegrated_.valid() && !obs.entityStillAlive) {
        const StepResult discarded =
            DiscardUnintegrated("unintegrated entity not alive");
        if (!obs.shutdown) {
            return discarded;
        }
    }
    if (obs.shutdown) {
        if (phase_ == Phase::Removing) {
            shutdownRequested_ = true;
        } else {
            return Shutdown();
        }
    }
    if (phase_ == Phase::TornDown) {
        return Ignore("torn down");
    }
    if (!obs.sessionAlive && phase_ != Phase::Absent &&
        phase_ != Phase::Removing) {
        return PeerLeft();
    }

    UpdateStable(obs);
    SettleEnroll(obs);

    switch (phase_) {
    case Phase::Absent:
        if (obs.sessionAlive) {
            return Note(Phase::Waiting, "session alive");
        }
        return Quiet("no session");
    case Phase::Waiting:
    case Phase::Dropped:
        return ConsiderSpawn(obs);
    case Phase::AwaitingReload:
        return PollReload(obs);
    case Phase::Building:
        return PollBuilding(obs);
    case Phase::Unintegrated:
        if (!policy_.integrate) {
            return Quiet("built and not integrated");
        }
        return Quiet("unintegrated");
    case Phase::Integrating:
        return PollIntegrating(obs);
    case Phase::Present:
    case Phase::Preserved:
    case Phase::PeerGrace:
        return ConsiderPresence(obs);
    case Phase::Removing:
        return PollRemoving(obs);
    case Phase::RemovalBlocked:
        return Quiet("removal blocked");
    case Phase::TornDown:
        return Ignore("torn down");
    case Phase::Count:
        break;
    }
    return Ignore("unhandled phase");
}

std::string RemotePuppetLifecycle::Describe() const {
    std::ostringstream out;
    out << "RemotePuppetLifecycle phase=" << PhaseName(phase_)
        << " visibility=" << VisibilityName(visibility_)
        << " frame=" << frame_
        << " generation=" << generation_
        << " drive=" << drive_.id
        << " scripted=" << (allowScripted_ ? "on" : "off")
        << " pad=" << (claimsLocalPad() ? "claimed" : "none")
        << " balanced=" << (duplicationBalanced_ ? "yes" : "no")
        << " depth=" << duplicationDepth_
        << " release=" << ReleaseKindName(lastRelease_)
        << " removalConfirmed=" << (removalConfirmed_ ? "yes" : "no")
        << " leakRisk=" << (leakRisk_ ? "yes" : "no")
        << " refusals=" << refusals_
        << " spawns=" << spawnAttempts_
        << " reason=" << lastReason_;
    return out.str();
}

}  // namespace bfc::puppet
