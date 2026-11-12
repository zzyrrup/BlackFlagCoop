#include "coop/gamer_pad_policy.h"

namespace bfc::gamer_pad {

int ResyncedPadCapacity() {
    return 0;
}

SelectResult SelectUnusedSlot(const bool* occupied, int capacity, int reservedLocalSlot,
                               bool localSlotKnown) {
    SelectResult result;
    if (capacity < 0 || occupied == nullptr) {
        result.status = SelectStatus::InvalidArgument;
        return result;
    }
    if (capacity == 0) {
        result.status = SelectStatus::CapacityUnknown;
        return result;
    }
    if (!localSlotKnown) {
        result.status = SelectStatus::LocalSlotUnknown;
        return result;
    }
    if (reservedLocalSlot < 0 || reservedLocalSlot >= capacity) {
        result.status = SelectStatus::IndexOutOfRange;
        return result;
    }

    for (int slot = 0; slot < capacity; ++slot) {
        if (slot == reservedLocalSlot) {
            continue;
        }
        if (!occupied[slot]) {
            result.status = SelectStatus::Selected;
            result.slot = slot;
            return result;
        }
    }

    result.status = SelectStatus::NoFreeSlot;
    return result;
}

RegisterDecision DecideRegisterPlayer(PeerRole role, SlotBindMode mode, int requestedSlot,
                                      const bool* occupied, int capacity, int reservedLocalSlot,
                                      bool localSlotKnown) {
    if (role == PeerRole::RemotePuppet) {
        return RegisterDecision::RefuseRemoteMustNotBind;
    }
    if (mode == SlotBindMode::NeverBind) {
        return RegisterDecision::SkipNoBindRequested;
    }
    if (capacity <= 0 || occupied == nullptr) {
        return RegisterDecision::RefuseCapacityUnknown;
    }
    if (requestedSlot < 0 || requestedSlot >= capacity) {
        return RegisterDecision::RefuseOutOfRange;
    }
    if (!localSlotKnown) {
        return RegisterDecision::RefuseLocalSlotUnknown;
    }
    if (reservedLocalSlot < 0 || reservedLocalSlot >= capacity) {
        return RegisterDecision::RefuseOutOfRange;
    }
    if (requestedSlot == reservedLocalSlot) {
        return RegisterDecision::RefuseReserved;
    }
    if (occupied[requestedSlot]) {
        return RegisterDecision::RefuseOccupied;
    }
    return RegisterDecision::Allow;
}

bool ArmIsolationMarker(IsolationMarker& marker) {
    marker.state = MarkerState::Armed;
    return true;
}

bool ClearIsolationMarker(IsolationMarker& marker) {
    marker.state = MarkerState::Clear;
    return true;
}

IsolationPreconditions CheckEnrollPreconditions(const IsolationMarker& marker, PeerRole role,
                                                 SlotBindMode mode) {
    if (role != PeerRole::RemotePuppet) {
        return IsolationPreconditions::BlockedNotRemote;
    }
    if (mode != SlotBindMode::NeverBind) {
        return IsolationPreconditions::BlockedRemoteBindRequested;
    }
    if (marker.state != MarkerState::Armed) {
        return IsolationPreconditions::BlockedMarkerClear;
    }
    return IsolationPreconditions::Ready;
}

PadBindRequirement PadBindRequirementFor(GameTarget target) {
    if (target == GameTarget::OriginalAc4) {
        return PadBindRequirement::SourceSkipsRegisterPlayer;
    }
    return PadBindRequirement::Unknown;
}

IsolationReport EvaluateIsolation(const IsolationSnapshot& snapshot) {
    IsolationReport report;
    const bool remote = snapshot.role == PeerRole::RemotePuppet;

    report.registerPlayerCalledForRemote = remote && snapshot.registerPlayerCalled;
    report.acquiredLocalInput = snapshot.acquiresLocalInput;
    report.alteredInventory = snapshot.writesLocalInventory;
    report.alteredControl = snapshot.writesLocalControl;
    report.registeredAsLocalPlayer = snapshot.registeredAsSecondLocalPlayer;
    report.markerMissingAtEnroll = remote && !snapshot.markerArmedAtEnroll;
    report.markerLeftSetAfterTeardown = remote && !snapshot.markerClearedBeforeTeardown;
    report.remoteBoundPad = remote && snapshot.padBound;

    bool stole = false;
    if (remote && snapshot.padBound) {
        if (snapshot.boundSlotOccupied) {
            stole = true;
        }
        if (!snapshot.localSlotKnown) {
            stole = true;
        } else if (snapshot.boundSlot == snapshot.localSlot) {
            stole = true;
        }
        if (snapshot.queryDisposition == QueryDisposition::RefuseAll) {
            stole = true;
        }
        if (snapshot.queryDisposition == QueryDisposition::AllowEmptyNonLocal &&
            (snapshot.boundSlot < 0 || snapshot.boundSlotOccupied || !snapshot.localSlotKnown ||
             snapshot.boundSlot == snapshot.localSlot)) {
            stole = true;
        }
    }
    report.stoleOccupiedOrLocalPad = stole;

    report.holds = !report.registerPlayerCalledForRemote && !report.stoleOccupiedOrLocalPad &&
                   !report.acquiredLocalInput && !report.alteredInventory && !report.alteredControl &&
                   !report.registeredAsLocalPlayer && !report.markerMissingAtEnroll &&
                   !report.markerLeftSetAfterTeardown;
    return report;
}

}  // namespace bfc::gamer_pad
