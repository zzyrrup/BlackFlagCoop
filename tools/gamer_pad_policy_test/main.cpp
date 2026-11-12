#include "coop/gamer_pad_policy.h"

#include <cstdio>
#include <cstring>

namespace {

int g_failures = 0;

void Expect(bool condition, const char* name) {
    if (condition) {
        std::printf("PASS %s\n", name);
        return;
    }
    std::printf("FAIL %s\n", name);
    ++g_failures;
}

using bfc::gamer_pad::ArmIsolationMarker;
using bfc::gamer_pad::CheckEnrollPreconditions;
using bfc::gamer_pad::ClearIsolationMarker;
using bfc::gamer_pad::DecideRegisterPlayer;
using bfc::gamer_pad::EvaluateIsolation;
using bfc::gamer_pad::GameTarget;
using bfc::gamer_pad::IsolationMarker;
using bfc::gamer_pad::IsolationPreconditions;
using bfc::gamer_pad::IsolationSnapshot;
using bfc::gamer_pad::MarkerState;
using bfc::gamer_pad::PadBindRequirement;
using bfc::gamer_pad::PadBindRequirementFor;
using bfc::gamer_pad::PeerRole;
using bfc::gamer_pad::QueryDisposition;
using bfc::gamer_pad::RegisterDecision;
using bfc::gamer_pad::ResyncedPadCapacity;
using bfc::gamer_pad::SelectStatus;
using bfc::gamer_pad::SelectUnusedSlot;
using bfc::gamer_pad::SlotBindMode;
using bfc::gamer_pad::kAc4SourceLoopCapacity;

void TestCapacityIsNotAssumed() {
    Expect(ResyncedPadCapacity() == 0, "resynced capacity stays unknown");
    Expect(kAc4SourceLoopCapacity == 8, "ac4 source loop bound is 8");

    bool occupied[8] = {};
    const auto unknown = SelectUnusedSlot(occupied, ResyncedPadCapacity(), 0, true);
    Expect(unknown.status == SelectStatus::CapacityUnknown, "unknown capacity refuses selection");
    Expect(unknown.slot == -1, "unknown capacity selects no slot");

    const auto missing = SelectUnusedSlot(nullptr, kAc4SourceLoopCapacity, 0, true);
    Expect(missing.status == SelectStatus::InvalidArgument, "null occupancy is invalid");
}

void TestSlotSelectionSkipsLocalAndOccupied() {
    bool occupied[8] = {};
    occupied[0] = true;
    occupied[2] = true;

    const auto first = SelectUnusedSlot(occupied, kAc4SourceLoopCapacity, 0, true);
    Expect(first.status == SelectStatus::Selected && first.slot == 1,
           "first empty non-local slot is 1");

    // Slot 0 is empty but reserved for the local player. Do not hand it out.
    bool localEmpty[8] = {};
    const auto skipReserved = SelectUnusedSlot(localEmpty, kAc4SourceLoopCapacity, 0, true);
    Expect(skipReserved.status == SelectStatus::Selected && skipReserved.slot == 1,
           "reserved local slot is never selected");

    const auto unknownLocal = SelectUnusedSlot(localEmpty, kAc4SourceLoopCapacity, -1, false);
    Expect(unknownLocal.status == SelectStatus::LocalSlotUnknown,
           "unknown local slot refuses selection");

    bool full[8];
    std::memset(full, 1, sizeof(full));
    const auto none = SelectUnusedSlot(full, kAc4SourceLoopCapacity, 0, true);
    Expect(none.status == SelectStatus::NoFreeSlot && none.slot == -1,
           "full table does not fall back to the local slot");

    const auto badReserve = SelectUnusedSlot(localEmpty, 4, 7, true);
    Expect(badReserve.status == SelectStatus::IndexOutOfRange, "reserve outside capacity is rejected");
}

void TestRegisterPlayerPolicy() {
    bool occupied[8] = {};
    occupied[1] = true;

    Expect(DecideRegisterPlayer(PeerRole::RemotePuppet, SlotBindMode::NeverBind, 2, occupied,
                                kAc4SourceLoopCapacity, 0, true) ==
               RegisterDecision::RefuseRemoteMustNotBind,
           "remote never-bind is refused");
    Expect(DecideRegisterPlayer(PeerRole::RemotePuppet, SlotBindMode::BindSpecificSlot, 2, occupied,
                                kAc4SourceLoopCapacity, 0, true) ==
               RegisterDecision::RefuseRemoteMustNotBind,
           "remote specific-slot request is still refused");
    Expect(DecideRegisterPlayer(PeerRole::LocalHuman, SlotBindMode::NeverBind, 1, occupied,
                                kAc4SourceLoopCapacity, 0, true) ==
               RegisterDecision::SkipNoBindRequested,
           "local never-bind does not register");
    Expect(DecideRegisterPlayer(PeerRole::LocalHuman, SlotBindMode::BindSpecificSlot, 0, occupied,
                                kAc4SourceLoopCapacity, 0, true) == RegisterDecision::RefuseReserved,
           "local slot itself is reserved");
    Expect(DecideRegisterPlayer(PeerRole::LocalHuman, SlotBindMode::BindSpecificSlot, 1, occupied,
                                kAc4SourceLoopCapacity, 0, true) == RegisterDecision::RefuseOccupied,
           "occupied slot is refused");
    Expect(DecideRegisterPlayer(PeerRole::LocalHuman, SlotBindMode::BindSpecificSlot, 3, occupied,
                                kAc4SourceLoopCapacity, 0, true) == RegisterDecision::Allow,
           "empty non-local slot can be allowed for an explicit local bind");
    Expect(DecideRegisterPlayer(PeerRole::LocalHuman, SlotBindMode::BindSpecificSlot, 3, occupied,
                                0, 0, true) == RegisterDecision::RefuseCapacityUnknown,
           "unproven capacity refuses a bind");
    Expect(DecideRegisterPlayer(PeerRole::LocalHuman, SlotBindMode::BindSpecificSlot, 3, occupied,
                                kAc4SourceLoopCapacity, 0, false) ==
               RegisterDecision::RefuseLocalSlotUnknown,
           "unknown local owner refuses a bind");
    Expect(DecideRegisterPlayer(PeerRole::LocalHuman, SlotBindMode::BindSpecificSlot, 9, occupied,
                                kAc4SourceLoopCapacity, 0, true) == RegisterDecision::RefuseOutOfRange,
           "out-of-range slot is refused");
}

void TestMarkerAndEnrollGate() {
    IsolationMarker marker;
    Expect(marker.state == MarkerState::Clear, "marker starts clear");
    Expect(CheckEnrollPreconditions(marker, PeerRole::RemotePuppet, SlotBindMode::NeverBind) ==
               IsolationPreconditions::BlockedMarkerClear,
           "enroll blocked while marker is clear");

    Expect(ArmIsolationMarker(marker), "arm succeeds");
    Expect(marker.state == MarkerState::Armed, "arm sets armed");
    Expect(ArmIsolationMarker(marker), "second arm is idempotent");
    Expect(marker.state == MarkerState::Armed, "second arm stays armed");
    Expect(CheckEnrollPreconditions(marker, PeerRole::RemotePuppet, SlotBindMode::NeverBind) ==
               IsolationPreconditions::Ready,
           "armed remote never-bind is ready");
    Expect(CheckEnrollPreconditions(marker, PeerRole::RemotePuppet, SlotBindMode::BindSpecificSlot) ==
               IsolationPreconditions::BlockedRemoteBindRequested,
           "remote bind request blocks enroll");
    Expect(CheckEnrollPreconditions(marker, PeerRole::LocalHuman, SlotBindMode::NeverBind) ==
               IsolationPreconditions::BlockedNotRemote,
           "local human is not a puppet enroll");

    Expect(ClearIsolationMarker(marker), "clear succeeds");
    Expect(marker.state == MarkerState::Clear, "clear resets marker");
    Expect(ClearIsolationMarker(marker), "second clear is idempotent");
    Expect(CheckEnrollPreconditions(marker, PeerRole::RemotePuppet, SlotBindMode::NeverBind) ==
               IsolationPreconditions::BlockedMarkerClear,
           "cleared marker blocks the next enroll");
}

void TestIsolationInvariants() {
    IsolationSnapshot clean;
    clean.localSlotKnown = true;
    clean.localSlot = 0;
    clean.markerArmedAtEnroll = true;
    clean.markerClearedBeforeTeardown = true;
    const auto ok = EvaluateIsolation(clean);
    Expect(ok.holds, "clean remote snapshot holds");
    Expect(!ok.acquiredLocalInput && !ok.alteredInventory && !ok.alteredControl &&
               !ok.registeredAsLocalPlayer && !ok.stoleOccupiedOrLocalPad,
           "clean snapshot has no isolation violations");

    IsolationSnapshot input = clean;
    input.acquiresLocalInput = true;
    Expect(!EvaluateIsolation(input).holds && EvaluateIsolation(input).acquiredLocalInput,
           "local input acquisition fails");

    IsolationSnapshot inventory = clean;
    inventory.writesLocalInventory = true;
    Expect(!EvaluateIsolation(inventory).holds && EvaluateIsolation(inventory).alteredInventory,
           "inventory write fails");

    IsolationSnapshot control = clean;
    control.writesLocalControl = true;
    Expect(!EvaluateIsolation(control).holds && EvaluateIsolation(control).alteredControl,
           "control write fails");

    IsolationSnapshot secondLocal = clean;
    secondLocal.registeredAsSecondLocalPlayer = true;
    Expect(!EvaluateIsolation(secondLocal).holds &&
               EvaluateIsolation(secondLocal).registeredAsLocalPlayer,
           "second local player registration fails");

    IsolationSnapshot called = clean;
    called.registerPlayerCalled = true;
    Expect(!EvaluateIsolation(called).holds && EvaluateIsolation(called).registerPlayerCalledForRemote,
           "remote RegisterPlayer fails");

    IsolationSnapshot stolen = clean;
    stolen.padBound = true;
    stolen.boundSlot = 0;
    stolen.queryDisposition = QueryDisposition::AllowEmptyNonLocal;
    Expect(!EvaluateIsolation(stolen).holds && EvaluateIsolation(stolen).stoleOccupiedOrLocalPad,
           "binding the local slot fails");

    IsolationSnapshot occupied = clean;
    occupied.padBound = true;
    occupied.boundSlot = 2;
    occupied.boundSlotOccupied = true;
    occupied.queryDisposition = QueryDisposition::AllowEmptyNonLocal;
    Expect(!EvaluateIsolation(occupied).holds, "binding an occupied slot fails");

    IsolationSnapshot unknownOwner = clean;
    unknownOwner.localSlotKnown = false;
    unknownOwner.padBound = true;
    unknownOwner.boundSlot = 3;
    unknownOwner.queryDisposition = QueryDisposition::AllowEmptyNonLocal;
    Expect(!EvaluateIsolation(unknownOwner).holds, "bind with unknown local owner fails");

    IsolationSnapshot strict = clean;
    strict.padBound = true;
    strict.boundSlot = 3;
    strict.queryDisposition = QueryDisposition::RefuseAll;
    Expect(!EvaluateIsolation(strict).holds, "strict mode rejects every pad bind");

    IsolationSnapshot redirected = clean;
    redirected.padBound = true;
    redirected.boundSlot = 3;
    redirected.boundSlotOccupied = false;
    redirected.queryDisposition = QueryDisposition::AllowEmptyNonLocal;
    Expect(EvaluateIsolation(redirected).holds, "empty non-local query is allowed only when opted in");

    IsolationSnapshot disarmed = clean;
    disarmed.markerArmedAtEnroll = false;
    Expect(!EvaluateIsolation(disarmed).holds && EvaluateIsolation(disarmed).markerMissingAtEnroll,
           "enroll without marker fails");

    IsolationSnapshot sticky = clean;
    sticky.markerClearedBeforeTeardown = false;
    Expect(!EvaluateIsolation(sticky).holds && EvaluateIsolation(sticky).markerLeftSetAfterTeardown,
           "marker left armed after teardown fails");
}

void TestEvidenceGates() {
    Expect(PadBindRequirementFor(GameTarget::OriginalAc4) ==
               PadBindRequirement::SourceSkipsRegisterPlayer,
           "ac4 net path skips RegisterPlayer");
    Expect(PadBindRequirementFor(GameTarget::Resynced106) == PadBindRequirement::Unknown,
           "resynced pad requirement is unknown");
}

}  // namespace

int main() {
    TestCapacityIsNotAssumed();
    TestSlotSelectionSkipsLocalAndOccupied();
    TestRegisterPlayerPolicy();
    TestMarkerAndEnrollGate();
    TestIsolationInvariants();
    TestEvidenceGates();

    if (g_failures != 0) {
        std::printf("RESULT FAIL %d\n", g_failures);
        return 1;
    }
    std::printf("RESULT PASS\n");
    return 0;
}
