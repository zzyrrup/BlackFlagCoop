#include "coop/remote_puppet_lifecycle.h"

#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

namespace {

int g_failed = 0;

void Check(bool condition, const char* expr, const char* file, int line) {
    if (condition) {
        return;
    }
    ++g_failed;
    std::cerr << "FAIL " << file << ":" << line << " " << expr << "\n";
}

#define CHECK(expr) ::Check(static_cast<bool>(expr), #expr, __FILE__, __LINE__)

using bfc::puppet::EngineOp;
using bfc::puppet::EngineOps;
using bfc::puppet::Handle;
using bfc::puppet::Observation;
using bfc::puppet::OpStatus;
using bfc::puppet::Phase;
using bfc::puppet::Policy;
using bfc::puppet::ReleaseKind;
using bfc::puppet::RemotePuppetLifecycle;
using bfc::puppet::Visibility;

Policy FastPolicy() {
    Policy policy;
    policy.minStableFrames = 0;
    policy.peerAbsentGraceFrames = 1;
    policy.retryCooldownFrames = 0;
    policy.worldSettleFrames = 2;
    policy.reloadTimeoutFrames = 4;
    policy.buildTimeoutFrames = 4;
    policy.integrateTimeoutFrames = 4;
    policy.removeTimeoutFrames = 4;
    policy.integrate = true;
    return policy;
}

Observation ReadyPeer() {
    Observation obs;
    obs.sessionAlive = true;
    obs.localCaptureOk = true;
    obs.engineLoading = false;
    obs.peerPacketValid = true;
    obs.peerSameWorld = true;
    obs.peerFresh = true;
    obs.builderReady = true;
    obs.selectorReady = true;
    obs.builderResourceKnown = true;
    obs.entityStillAlive = true;
    obs.localWorldId = 42;
    obs.peerWorldId = 42;
    return obs;
}

class ScriptedOps final : public EngineOps {
public:
    RemotePuppetLifecycle* machine = nullptr;
    OpStatus beginStatus = OpStatus::Ok;
    OpStatus duplicateStatus = OpStatus::Ok;
    OpStatus endStatus = OpStatus::Ok;
    OpStatus reloadStatus = OpStatus::Ok;
    OpStatus buildStatus = OpStatus::Ok;
    OpStatus addStatus = OpStatus::Ok;
    OpStatus removeStatus = OpStatus::Ok;
    std::vector<std::string> calls;
    int removeWhileDriveOccupied = 0;
    int depthAtDuplicate = -1;

    OpStatus BeginDuplication() override {
        calls.emplace_back("begin");
        return beginStatus;
    }
    OpStatus DuplicateSelector() override {
        calls.emplace_back("duplicate");
        depthAtDuplicate = machine == nullptr ? -1 : machine->duplicationDepth();
        return duplicateStatus;
    }
    OpStatus EndDuplication() override {
        calls.emplace_back("end");
        return endStatus;
    }
    OpStatus ReloadBuilder() override {
        calls.emplace_back("reload");
        return reloadStatus;
    }
    OpStatus BuildEntity(Handle& out) override {
        calls.emplace_back("build");
        if (out.id == 0) {
            out.id = 7000 + out.generation;
        }
        return buildStatus;
    }
    OpStatus AddToWorld(const Handle&) override {
        calls.emplace_back("add");
        return addStatus;
    }
    OpStatus RemoveFromWorld(const Handle&) override {
        calls.emplace_back("remove");
        if (machine != nullptr && machine->driveHandle().valid()) {
            ++removeWhileDriveOccupied;
        }
        return removeStatus;
    }
};

bool HasCall(const ScriptedOps& ops, const char* name) {
    for (const std::string& call : ops.calls) {
        if (call == name) {
            return true;
        }
    }
    return false;
}

bool HistoryHas(const RemotePuppetLifecycle& machine, const char* fragment) {
    for (uint32_t i = 0; i < machine.historySize(); ++i) {
        const char* reason = machine.historyAt(i).reason;
        if (reason != nullptr && std::string(reason).find(fragment) != std::string::npos) {
            return true;
        }
    }
    return false;
}

void Pump(RemotePuppetLifecycle& machine, const Observation& obs, int ticks) {
    for (int i = 0; i < ticks; ++i) {
        machine.Tick(obs);
    }
}

bool ReachPresent(RemotePuppetLifecycle& machine, const Observation& obs) {
    for (int i = 0; i < 12; ++i) {
        machine.Tick(obs);
        if (machine.phase() == Phase::Present && machine.driveHandle().valid()) {
            return true;
        }
    }
    return false;
}

void TestNames() {
    for (uint8_t i = 0; i < static_cast<uint8_t>(Phase::Count); ++i) {
        CHECK(std::string(bfc::puppet::PhaseName(static_cast<Phase>(i))) != "Unknown");
    }
    for (uint8_t i = 0; i < static_cast<uint8_t>(Visibility::Count); ++i) {
        CHECK(std::string(bfc::puppet::VisibilityName(static_cast<Visibility>(i))) !=
              "Unknown");
    }
    for (uint8_t i = 0; i < static_cast<uint8_t>(EngineOp::Count); ++i) {
        CHECK(std::string(bfc::puppet::EngineOpName(static_cast<EngineOp>(i))) != "Unknown");
    }
    for (uint8_t i = 0; i < static_cast<uint8_t>(OpStatus::Count); ++i) {
        CHECK(std::string(bfc::puppet::OpStatusName(static_cast<OpStatus>(i))) != "Unknown");
    }
    CHECK(std::string(bfc::puppet::PhaseName(Phase::Count)) == "Unknown");
}

void TestDefaultThresholdsMatchSource() {
    const RemotePuppetLifecycle machine;
    CHECK(machine.policy().minStableFrames == 60);
    CHECK(machine.policy().peerAbsentGraceFrames == 180);
    CHECK(machine.policy().retryCooldownFrames == 120);
    CHECK(machine.policy().worldSettleFrames == 180);
    CHECK(machine.scriptedOpsAllowed() == false);
    CHECK(machine.claimsLocalPad() == false);
    CHECK(machine.phase() == Phase::Absent);
}

void TestRefusingEngineNeverSpawns() {
    RemotePuppetLifecycle machine(FastPolicy());
    const Observation obs = ReadyPeer();
    Pump(machine, obs, 6);
    CHECK(machine.phase() == Phase::Waiting);
    CHECK(machine.driveHandle().valid() == false);
    CHECK(machine.visibility() == Visibility::None);
    CHECK(machine.engineCallCount() == 0);
    CHECK(machine.refusalCount() >= 1);
    CHECK(machine.duplicationDepth() == 0);
    CHECK(machine.duplicationBalanced());
    CHECK(machine.claimsLocalPad() == false);
    CHECK(machine.driveAllowed() == false);
    CHECK(HistoryHas(machine, "native spawn sequence refused"));

    machine.Shutdown();
    CHECK(machine.phase() == Phase::TornDown);
    CHECK(machine.engineCallCount() == 0);
    machine.Shutdown();
    CHECK(machine.phase() == Phase::TornDown);
    CHECK(machine.ignoredCount() >= 1);

    CHECK(machine.Reset().phase == Phase::Absent);
    CHECK(machine.phase() == Phase::Absent);
}

void TestRefusalRespectsCooldown() {
    Policy policy = FastPolicy();
    policy.retryCooldownFrames = 1;
    RemotePuppetLifecycle machine(policy);
    const Observation obs = ReadyPeer();
    machine.Tick(obs);
    machine.Tick(obs);
    CHECK(machine.refusalCount() == 1);
    machine.Tick(obs);
    CHECK(machine.refusalCount() == 1);
    machine.Tick(obs);
    CHECK(machine.refusalCount() == 2);
    CHECK(machine.engineCallCount() == 0);
}

void TestScriptedSpawnOrderAndVisibility() {
    ScriptedOps ops;
    RemotePuppetLifecycle machine(FastPolicy());
    ops.machine = &machine;
    machine.SetOps(&ops);
    machine.AllowScriptedOpsForTests(true);
    const Observation obs = ReadyPeer();
    CHECK(ReachPresent(machine, obs));
    CHECK(ops.calls.size() == 5);
    CHECK(ops.calls[0] == "begin");
    CHECK(ops.calls[1] == "duplicate");
    CHECK(ops.calls[2] == "end");
    CHECK(ops.calls[3] == "build");
    CHECK(ops.calls[4] == "add");
    CHECK(ops.depthAtDuplicate == 1);
    CHECK(machine.duplicationDepth() == 0);
    CHECK(machine.duplicationBalanced());
    CHECK(machine.visibility() == Visibility::PendingEnroll);
    CHECK(machine.driveAllowed());
    CHECK(machine.claimsLocalPad() == false);
    CHECK(machine.generation() == 1);
    CHECK(machine.driveHandle().worldId == 42);
    CHECK(HasCall(ops, "remove") == false);

    machine.Tick(obs);
    CHECK(machine.visibility() == Visibility::Visible);
    CHECK(machine.phase() == Phase::Present);
    CHECK(ops.calls.size() == 5);
}

void TestDuplicateFailureStillEndsScope() {
    ScriptedOps ops;
    ops.duplicateStatus = OpStatus::Failed;
    RemotePuppetLifecycle machine(FastPolicy());
    ops.machine = &machine;
    machine.SetOps(&ops);
    machine.AllowScriptedOpsForTests(true);
    Observation obs = ReadyPeer();
    machine.Tick(obs);
    machine.Tick(obs);
    CHECK(machine.phase() == Phase::Waiting);
    CHECK(ops.calls.size() == 3);
    CHECK(ops.calls[2] == "end");
    CHECK(HasCall(ops, "build") == false);
    CHECK(machine.duplicationDepth() == 0);
    CHECK(machine.duplicationBalanced());
    CHECK(machine.driveHandle().valid() == false);
}

void TestEndFailureLatchesUnbalanced() {
    ScriptedOps ops;
    ops.endStatus = OpStatus::Failed;
    RemotePuppetLifecycle machine(FastPolicy());
    ops.machine = &machine;
    machine.SetOps(&ops);
    machine.AllowScriptedOpsForTests(true);
    Pump(machine, ReadyPeer(), 3);
    CHECK(machine.duplicationBalanced() == false);
    CHECK(machine.duplicationDepth() == 0);
    CHECK(HasCall(ops, "build") == false);
    CHECK(machine.phase() == Phase::Waiting);
}

void TestAddFailureDiscardsWithoutRemove() {
    ScriptedOps ops;
    ops.addStatus = OpStatus::Failed;
    RemotePuppetLifecycle machine(FastPolicy());
    ops.machine = &machine;
    machine.SetOps(&ops);
    machine.AllowScriptedOpsForTests(true);
    Observation obs = ReadyPeer();
    machine.Tick(obs);
    machine.Tick(obs);
    CHECK(machine.phase() == Phase::Waiting);
    CHECK(HasCall(ops, "add"));
    CHECK(HasCall(ops, "remove") == false);
    CHECK(machine.rollbackCount() == 1);
    CHECK(machine.leakRisk());
    CHECK(machine.lastRelease() == ReleaseKind::DiscardedUnintegrated);
    CHECK(machine.driveHandle().valid() == false);
    CHECK(machine.visibility() == Visibility::None);
}

void TestIntegrateDisabledStaysHidden() {
    ScriptedOps ops;
    Policy policy = FastPolicy();
    policy.integrate = false;
    RemotePuppetLifecycle machine(policy);
    ops.machine = &machine;
    machine.SetOps(&ops);
    machine.AllowScriptedOpsForTests(true);
    Pump(machine, ReadyPeer(), 3);
    CHECK(machine.phase() == Phase::Unintegrated);
    CHECK(machine.visibility() == Visibility::BuiltHidden);
    CHECK(HasCall(ops, "add") == false);
    CHECK(machine.driveHandle().valid() == false);
    CHECK(machine.unintegratedHandle().valid());
    CHECK(machine.driveAllowed() == false);
    CHECK(machine.leakRisk());
    machine.Shutdown();
    CHECK(machine.phase() == Phase::TornDown);
    CHECK(HasCall(ops, "remove") == false);
    CHECK(machine.lastRelease() == ReleaseKind::DiscardedUnintegrated);
}

void TestPausePreservesAndWorldIdDoesNotDrop() {
    ScriptedOps ops;
    RemotePuppetLifecycle machine(FastPolicy());
    ops.machine = &machine;
    machine.SetOps(&ops);
    machine.AllowScriptedOpsForTests(true);
    Observation obs = ReadyPeer();
    CHECK(ReachPresent(machine, obs));
    machine.Tick(obs);
    CHECK(machine.visibility() == Visibility::Visible);
    const uint64_t id = machine.driveHandle().id;
    const uint32_t generation = machine.driveHandle().generation;

    obs.localCaptureOk = false;
    obs.localWorldId = 99;
    obs.peerWorldId = 99;
    machine.Tick(obs);
    CHECK(machine.phase() == Phase::Preserved);
    CHECK(machine.visibility() == Visibility::Preserved);
    CHECK(machine.driveHandle().id == id);
    CHECK(machine.graceFrames() == 0);
    CHECK(HasCall(ops, "remove") == false);
    CHECK(machine.dropCount() == 0);

    obs.localCaptureOk = true;
    obs.localWorldId = 42;
    obs.peerWorldId = 42;
    machine.Tick(obs);
    CHECK(machine.phase() == Phase::Present);
    CHECK(machine.visibility() == Visibility::Visible);
    CHECK(machine.driveHandle().generation == generation);
}

void TestLoadingSuppressesDriveWithoutDespawn() {
    ScriptedOps ops;
    RemotePuppetLifecycle machine(FastPolicy());
    ops.machine = &machine;
    machine.SetOps(&ops);
    machine.AllowScriptedOpsForTests(true);
    Observation obs = ReadyPeer();
    obs.engineLoading = true;
    Pump(machine, obs, 4);
    CHECK(machine.phase() == Phase::Waiting);
    CHECK(ops.calls.empty());

    obs.engineLoading = false;
    CHECK(ReachPresent(machine, obs));
    machine.Tick(obs);
    CHECK(machine.visibility() == Visibility::Visible);

    obs.engineLoading = true;
    machine.Tick(obs);
    CHECK(machine.phase() == Phase::Present);
    CHECK(machine.driveSuppressed());
    CHECK(machine.driveAllowed() == false);
    CHECK(machine.driveHandle().valid());
    CHECK(HasCall(ops, "remove") == false);
}

void TestEntityFreedDropsWithoutRemove() {
    ScriptedOps ops;
    RemotePuppetLifecycle machine(FastPolicy());
    ops.machine = &machine;
    machine.SetOps(&ops);
    machine.AllowScriptedOpsForTests(true);
    Observation obs = ReadyPeer();
    CHECK(ReachPresent(machine, obs));
    const uint32_t generation = machine.generation();
    CHECK(machine.NotifyEntityFreed(generation + 5).phase == Phase::Present);
    CHECK(machine.ignoredCount() >= 1);

    obs.entityStillAlive = false;
    machine.Tick(obs);
    CHECK(machine.phase() == Phase::Dropped);
    CHECK(machine.dropCount() == 1);
    CHECK(machine.lastRelease() == ReleaseKind::DroppedWithoutRemove);
    CHECK(HasCall(ops, "remove") == false);
    CHECK(machine.driveHandle().valid() == false);
    CHECK(machine.cooldownFrames() == machine.policy().worldSettleFrames);

    obs.entityStillAlive = true;
    // Settle cooldown counts down only on eligible frames, and the frame it
    // hits zero does not also build. worldSettleFrames is 2.
    machine.Tick(obs);
    CHECK(machine.phase() == Phase::Dropped);
    CHECK(machine.cooldownFrames() == 1);
    machine.Tick(obs);
    CHECK(machine.phase() == Phase::Waiting);
    CHECK(machine.cooldownFrames() == 0);
    CHECK(machine.driveHandle().valid() == false);
    machine.Tick(obs);
    CHECK(machine.phase() == Phase::Present);
    CHECK(machine.generation() == generation + 1);
}

void TestPeerGraceThenRemoveClearsDriveFirst() {
    ScriptedOps ops;
    RemotePuppetLifecycle machine(FastPolicy());
    ops.machine = &machine;
    machine.SetOps(&ops);
    machine.AllowScriptedOpsForTests(true);
    Observation obs = ReadyPeer();
    CHECK(ReachPresent(machine, obs));
    obs.peerFresh = false;
    machine.Tick(obs);
    CHECK(machine.phase() == Phase::PeerGrace);
    CHECK(machine.graceFrames() == 1);
    CHECK(HasCall(ops, "remove") == false);
    machine.Tick(obs);
    CHECK(machine.phase() == Phase::Waiting);
    CHECK(ops.removeWhileDriveOccupied == 0);
    CHECK(HasCall(ops, "remove"));
    CHECK(machine.removeAttempts() == 1);
    CHECK(machine.removalConfirmed());
    CHECK(machine.lastRelease() == ReleaseKind::Removed);
    CHECK(machine.driveHandle().valid() == false);

    machine.PeerLeft();
    CHECK(machine.removeAttempts() == 1);
    CHECK(machine.phase() == Phase::Absent);
}

void TestExplicitPeerLeftIsImmediate() {
    ScriptedOps ops;
    RemotePuppetLifecycle machine(FastPolicy());
    ops.machine = &machine;
    machine.SetOps(&ops);
    machine.AllowScriptedOpsForTests(true);
    CHECK(ReachPresent(machine, ReadyPeer()));
    machine.PeerLeft();
    CHECK(machine.phase() == Phase::Absent);
    CHECK(machine.removeAttempts() == 1);
    machine.PeerLeft();
    CHECK(machine.removeAttempts() == 1);
}

void TestRemoveFailureBlocksAndShutdownDoesNotRetry() {
    ScriptedOps ops;
    ops.removeStatus = OpStatus::Failed;
    RemotePuppetLifecycle machine(FastPolicy());
    ops.machine = &machine;
    machine.SetOps(&ops);
    machine.AllowScriptedOpsForTests(true);
    CHECK(ReachPresent(machine, ReadyPeer()));
    machine.PeerLeft();
    CHECK(machine.phase() == Phase::RemovalBlocked);
    CHECK(machine.removalConfirmed() == false);
    CHECK(machine.leakRisk());
    CHECK(machine.removeAttempts() == 1);
    machine.PeerLeft();
    CHECK(machine.removeAttempts() == 1);
    CHECK(machine.Reset().changed == false);
    machine.Shutdown();
    CHECK(machine.phase() == Phase::TornDown);
    CHECK(machine.removeAttempts() == 1);
    CHECK(machine.removalConfirmed() == false);
    machine.Shutdown();
    CHECK(machine.removeAttempts() == 1);
}

void TestDisablingScriptedOpsRefusesRemove() {
    ScriptedOps ops;
    RemotePuppetLifecycle machine(FastPolicy());
    ops.machine = &machine;
    machine.SetOps(&ops);
    machine.AllowScriptedOpsForTests(true);
    CHECK(ReachPresent(machine, ReadyPeer()));
    const uint32_t callsAfterSpawn = machine.engineCallCount();
    machine.AllowScriptedOpsForTests(false);
    machine.Shutdown();
    CHECK(machine.phase() == Phase::TornDown);
    CHECK(machine.engineCallCount() == callsAfterSpawn);
    CHECK(machine.removeAttempts() == 0);
    CHECK(machine.removalConfirmed() == false);
    CHECK(machine.leakRisk());
    CHECK(machine.lastRelease() == ReleaseKind::RemoveUnconfirmed);
    CHECK(machine.driveHandle().valid() == false);
}

void TestPendingBuildAddRemoveAndStaleCompletion() {
    ScriptedOps ops;
    ops.buildStatus = OpStatus::Pending;
    RemotePuppetLifecycle machine(FastPolicy());
    ops.machine = &machine;
    machine.SetOps(&ops);
    machine.AllowScriptedOpsForTests(true);
    Observation obs = ReadyPeer();
    machine.Tick(obs);
    machine.Tick(obs);
    CHECK(machine.phase() == Phase::Building);
    CHECK(machine.NotifyOp(EngineOp::BuildEntity, OpStatus::Ok, 99).phase ==
          Phase::Building);
    CHECK(machine.ignoredCount() >= 1);

    ops.addStatus = OpStatus::Pending;
    CHECK(machine.NotifyOp(EngineOp::BuildEntity, OpStatus::Ok, machine.generation())
              .phase == Phase::Integrating);
    CHECK(machine.driveHandle().valid() == false);
    CHECK(machine.NotifyOp(EngineOp::AddToWorld, OpStatus::Ok, 1).phase == Phase::Present);

    ops.removeStatus = OpStatus::Pending;
    machine.PeerLeft();
    CHECK(machine.phase() == Phase::Removing);
    CHECK(machine.NotifyOp(EngineOp::RemoveFromWorld, OpStatus::Failed, 1).phase ==
          Phase::RemovalBlocked);
    CHECK(machine.NotifyOp(EngineOp::RemoveFromWorld, OpStatus::Ok, 1).phase ==
          Phase::RemovalBlocked);
}

void TestReloadTimeoutAndSuccess() {
    ScriptedOps ops;
    ops.reloadStatus = OpStatus::Pending;
    Policy policy = FastPolicy();
    policy.reloadTimeoutFrames = 1;
    policy.retryCooldownFrames = 5;
    RemotePuppetLifecycle machine(policy);
    ops.machine = &machine;
    machine.SetOps(&ops);
    machine.AllowScriptedOpsForTests(true);
    Observation obs = ReadyPeer();
    obs.builderReady = false;
    machine.Tick(obs);
    machine.Tick(obs);
    CHECK(machine.phase() == Phase::AwaitingReload);
    machine.Tick(obs);
    CHECK(machine.phase() == Phase::AwaitingReload);
    machine.Tick(obs);
    CHECK(machine.phase() == Phase::Waiting);
    CHECK(HistoryHas(machine, "builder reload timed out"));

    ops.reloadStatus = OpStatus::Ok;
    ops.calls.clear();
    // Drain the post-timeout cooldown (5 eligible frames decrement it to 0
    // without a new attempt; the next eligible frame reloads).
    for (int i = 0; i < 5; ++i) {
        machine.Tick(obs);
    }
    CHECK(ops.calls.empty());
    machine.Tick(obs);
    CHECK(ops.calls.size() == 1);
    CHECK(ops.calls[0] == "reload");
    CHECK(machine.phase() == Phase::Waiting);
    obs.builderReady = true;
    for (int i = 0; i < 5; ++i) {
        machine.Tick(obs);
        CHECK(machine.phase() == Phase::Waiting);
    }
    machine.Tick(obs);
    CHECK(machine.phase() == Phase::Present);
    CHECK(HasCall(ops, "add"));
}

void TestBuildTimeout() {
    ScriptedOps ops;
    ops.buildStatus = OpStatus::Pending;
    Policy policy = FastPolicy();
    policy.buildTimeoutFrames = 1;
    RemotePuppetLifecycle machine(policy);
    ops.machine = &machine;
    machine.SetOps(&ops);
    machine.AllowScriptedOpsForTests(true);
    machine.Tick(ReadyPeer());
    machine.Tick(ReadyPeer());
    CHECK(machine.phase() == Phase::Building);
    machine.Tick(ReadyPeer());
    CHECK(machine.phase() == Phase::Building);
    machine.Tick(ReadyPeer());
    CHECK(machine.phase() == Phase::Waiting);
    CHECK(machine.driveHandle().valid() == false);
    CHECK(HistoryHas(machine, "build timed out"));
    CHECK(machine.duplicationDepth() == 0);
}

void TestRemoveTimeoutThenEntityFreed() {
    ScriptedOps ops;
    ops.removeStatus = OpStatus::Pending;
    Policy policy = FastPolicy();
    policy.removeTimeoutFrames = 1;
    RemotePuppetLifecycle machine(policy);
    ops.machine = &machine;
    machine.SetOps(&ops);
    machine.AllowScriptedOpsForTests(true);
    CHECK(ReachPresent(machine, ReadyPeer()));
    machine.PeerLeft();
    CHECK(machine.phase() == Phase::Removing);
    Observation obs = ReadyPeer();
    obs.sessionAlive = false;
    Pump(machine, obs, 3);
    CHECK(machine.phase() == Phase::RemovalBlocked);
    CHECK(machine.removeAttempts() == 1);

    RemotePuppetLifecycle second(policy);
    ops.calls.clear();
    ops.machine = &second;
    second.SetOps(&ops);
    second.AllowScriptedOpsForTests(true);
    CHECK(ReachPresent(second, ReadyPeer()));
    second.PeerLeft();
    CHECK(second.phase() == Phase::Removing);
    const uint32_t removes = second.removeAttempts();
    Observation dead = ReadyPeer();
    dead.entityStillAlive = false;
    second.Tick(dead);
    CHECK(second.phase() == Phase::Dropped);
    CHECK(second.removeAttempts() == removes);
    CHECK(second.lastRelease() == ReleaseKind::DroppedWithoutRemove);
}

void TestShutdownDuringPendingRemove() {
    ScriptedOps ops;
    ops.removeStatus = OpStatus::Pending;
    RemotePuppetLifecycle machine(FastPolicy());
    ops.machine = &machine;
    machine.SetOps(&ops);
    machine.AllowScriptedOpsForTests(true);
    CHECK(ReachPresent(machine, ReadyPeer()));
    machine.PeerLeft();
    CHECK(machine.phase() == Phase::Removing);
    machine.Shutdown();
    CHECK(machine.phase() == Phase::Removing);
    CHECK(machine.NotifyOp(EngineOp::RemoveFromWorld, OpStatus::Ok, 1).phase ==
          Phase::TornDown);
    CHECK(machine.removalConfirmed());
    machine.Shutdown();
    CHECK(machine.phase() == Phase::TornDown);
    CHECK(machine.removeAttempts() == 1);
}

void TestResetRejectedWhilePresent() {
    ScriptedOps ops;
    RemotePuppetLifecycle machine(FastPolicy());
    ops.machine = &machine;
    machine.SetOps(&ops);
    machine.AllowScriptedOpsForTests(true);
    CHECK(ReachPresent(machine, ReadyPeer()));
    CHECK(machine.Reset().changed == false);
    CHECK(machine.phase() == Phase::Present);
    machine.Shutdown();
    CHECK(machine.phase() == Phase::TornDown);
    CHECK(machine.Reset().phase == Phase::Absent);
    const uint32_t generation = machine.generation();
    CHECK(ReachPresent(machine, ReadyPeer()));
    CHECK(machine.generation() == generation + 1);
}

void TestSessionDropBeforeSpawn() {
    RemotePuppetLifecycle machine(FastPolicy());
    Observation obs = ReadyPeer();
    machine.Tick(obs);
    CHECK(machine.phase() == Phase::Waiting);
    obs.sessionAlive = false;
    machine.Tick(obs);
    CHECK(machine.phase() == Phase::Absent);
    CHECK(machine.engineCallCount() == 0);
    obs.sessionAlive = true;
    machine.Tick(obs);
    CHECK(machine.phase() == Phase::Waiting);
}

void TestBuilderMissingDoesNotPretendSuccess() {
    RemotePuppetLifecycle machine(FastPolicy());
    Observation obs = ReadyPeer();
    obs.builderReady = false;
    obs.builderResourceKnown = false;
    Pump(machine, obs, 4);
    CHECK(machine.phase() == Phase::Waiting);
    CHECK(machine.engineCallCount() == 0);
    CHECK(HistoryHas(machine, "builder or selector not ready"));
    CHECK(machine.visibility() == Visibility::None);
}

void TestHistoryRingAndScriptedInvariants() {
    Policy policy = FastPolicy();
    policy.retryCooldownFrames = 0;
    RemotePuppetLifecycle refusing(policy);
    Pump(refusing, ReadyPeer(), 80);
    CHECK(refusing.historySize() == RemotePuppetLifecycle::kHistoryCap);
    CHECK(refusing.historyAt(0).reason != nullptr);
    CHECK(refusing.historyAt(refusing.historySize() - 1).reason != nullptr);

    ScriptedOps ops;
    RemotePuppetLifecycle machine(policy);
    ops.machine = &machine;
    machine.SetOps(&ops);
    machine.AllowScriptedOpsForTests(true);
    uint32_t seed = 1;
    uint32_t lastGeneration = 0;
    for (int i = 0; i < 200; ++i) {
        seed = seed * 1664525u + 1013904223u;
        Observation obs = ReadyPeer();
        obs.sessionAlive = (seed % 5u) != 0;
        obs.localCaptureOk = (seed % 7u) != 0;
        obs.engineLoading = (seed % 11u) == 0;
        obs.peerFresh = (seed % 4u) != 0;
        obs.entityStillAlive = (seed % 13u) != 0;
        obs.shutdown = (seed % 41u) == 0;
        if ((seed % 17u) == 0) {
            ops.addStatus = OpStatus::Failed;
        } else if ((seed % 19u) == 0) {
            ops.removeStatus = OpStatus::Pending;
        } else {
            ops.addStatus = OpStatus::Ok;
            ops.removeStatus = OpStatus::Ok;
        }
        machine.Tick(obs);
        CHECK(machine.duplicationDepth() == 0);
        CHECK(machine.claimsLocalPad() == false);
        CHECK(machine.generation() >= lastGeneration);
        lastGeneration = machine.generation();
        if (machine.phase() == Phase::TornDown) {
            machine.Reset();
        }
    }
    CHECK(ops.removeWhileDriveOccupied == 0);
}

void TestRefusingFuzzNeverBecomesVisible() {
    RemotePuppetLifecycle machine(FastPolicy());
    uint32_t seed = 7;
    for (int i = 0; i < 300; ++i) {
        seed = seed * 1664525u + 1013904223u;
        Observation obs;
        obs.shutdown = (seed % 37u) == 0;
        obs.sessionAlive = (seed % 3u) != 0;
        obs.localCaptureOk = (seed % 2u) == 0;
        obs.engineLoading = (seed % 5u) == 0;
        obs.peerPacketValid = true;
        obs.peerSameWorld = true;
        obs.peerFresh = (seed % 4u) != 0;
        obs.builderReady = true;
        obs.selectorReady = true;
        obs.entityStillAlive = true;
        obs.localWorldId = 3;
        obs.peerWorldId = 3;
        machine.Tick(obs);
        CHECK(machine.engineCallCount() == 0);
        CHECK(machine.driveHandle().valid() == false);
        CHECK(machine.visibility() != Visibility::Visible);
        CHECK(machine.visibility() != Visibility::PendingEnroll);
        CHECK(machine.duplicationDepth() == 0);
        CHECK(machine.claimsLocalPad() == false);
        const Phase phase = machine.phase();
        CHECK(phase == Phase::Absent || phase == Phase::Waiting ||
              phase == Phase::TornDown);
    }
}

}  // namespace

int main() {
    TestNames();
    TestDefaultThresholdsMatchSource();
    TestRefusingEngineNeverSpawns();
    TestRefusalRespectsCooldown();
    TestScriptedSpawnOrderAndVisibility();
    TestDuplicateFailureStillEndsScope();
    TestEndFailureLatchesUnbalanced();
    TestAddFailureDiscardsWithoutRemove();
    TestIntegrateDisabledStaysHidden();
    TestPausePreservesAndWorldIdDoesNotDrop();
    TestLoadingSuppressesDriveWithoutDespawn();
    TestEntityFreedDropsWithoutRemove();
    TestPeerGraceThenRemoveClearsDriveFirst();
    TestExplicitPeerLeftIsImmediate();
    TestRemoveFailureBlocksAndShutdownDoesNotRetry();
    TestDisablingScriptedOpsRefusesRemove();
    TestPendingBuildAddRemoveAndStaleCompletion();
    TestReloadTimeoutAndSuccess();
    TestBuildTimeout();
    TestRemoveTimeoutThenEntityFreed();
    TestShutdownDuringPendingRemove();
    TestResetRejectedWhilePresent();
    TestSessionDropBeforeSpawn();
    TestBuilderMissingDoesNotPretendSuccess();
    TestHistoryRingAndScriptedInvariants();
    TestRefusingFuzzNeverBecomesVisible();

    if (g_failed != 0) {
        std::cerr << g_failed << " check(s) failed\n";
        return 1;
    }
    std::cout << "remote_puppet_lifecycle_test: all checks passed\n";
    return 0;
}
