#pragma once

// Engine-free pad/gamer isolation policy for a remote puppet.
//
// This module does not call the game, read game memory, or assume Resynced
// slot counts. The original AC4Coop x86 loop bound is available only as a
// named constant for tests that explicitly model that source. Resynced
// capacity stays unknown until a later offline proof.

#include <cstdint>

namespace bfc::gamer_pad {

// Original MyGetUnusedPadID scans i < 8. That bound is x86-source evidence
// only. Do not treat it as the Resynced pad table size.
constexpr int kAc4SourceLoopCapacity = 8;

enum class PeerRole {
    LocalHuman,
    RemotePuppet,
};

enum class SlotBindMode {
    NeverBind,
    BindSpecificSlot,
};

// What to do if an engine query asks for a pad while a puppet marker is armed.
// Default is refuse: Resynced has no proven query site.
enum class QueryDisposition {
    RefuseAll,
    AllowEmptyNonLocal,
};

enum class SelectStatus {
    Selected,
    NoFreeSlot,
    CapacityUnknown,
    InvalidArgument,
    LocalSlotUnknown,
    IndexOutOfRange,
};

struct SelectResult {
    SelectStatus status = SelectStatus::InvalidArgument;
    int slot = -1;
};

enum class RegisterDecision {
    Allow,
    SkipNoBindRequested,
    RefuseRemoteMustNotBind,
    RefuseOccupied,
    RefuseReserved,
    RefuseLocalSlotUnknown,
    RefuseCapacityUnknown,
    RefuseOutOfRange,
};

enum class MarkerState {
    Clear,
    Armed,
};

struct IsolationMarker {
    MarkerState state = MarkerState::Clear;
};

// Preconditions for a future world-enroll call. Ready does not perform one.
enum class IsolationPreconditions {
    Ready,
    BlockedMarkerClear,
    BlockedRemoteBindRequested,
    BlockedNotRemote,
};

enum class GameTarget {
    OriginalAc4,
    Resynced106,
};

// How the original net path treats RegisterPlayer, versus what Resynced has proven.
enum class PadBindRequirement {
    SourceSkipsRegisterPlayer,
    Unknown,
};

struct IsolationSnapshot {
    PeerRole role = PeerRole::RemotePuppet;
    bool registerPlayerCalled = false;
    bool padBound = false;
    int boundSlot = -1;
    bool boundSlotOccupied = false;
    bool localSlotKnown = false;
    int localSlot = -1;
    bool acquiresLocalInput = false;
    bool writesLocalInventory = false;
    bool writesLocalControl = false;
    bool registeredAsSecondLocalPlayer = false;
    bool markerArmedAtEnroll = false;
    bool markerClearedBeforeTeardown = false;
    QueryDisposition queryDisposition = QueryDisposition::RefuseAll;
};

struct IsolationReport {
    bool holds = false;
    bool remoteBoundPad = false;
    bool stoleOccupiedOrLocalPad = false;
    bool acquiredLocalInput = false;
    bool alteredInventory = false;
    bool alteredControl = false;
    bool registeredAsLocalPlayer = false;
    bool markerMissingAtEnroll = false;
    bool markerLeftSetAfterTeardown = false;
    bool registerPlayerCalledForRemote = false;
};

// 0 means "not proven". Selection refuses that instead of assuming 8.
int ResyncedPadCapacity();

SelectResult SelectUnusedSlot(const bool* occupied, int capacity, int reservedLocalSlot,
                               bool localSlotKnown);

RegisterDecision DecideRegisterPlayer(PeerRole role, SlotBindMode mode, int requestedSlot,
                                      const bool* occupied, int capacity, int reservedLocalSlot,
                                      bool localSlotKnown);

bool ArmIsolationMarker(IsolationMarker& marker);
bool ClearIsolationMarker(IsolationMarker& marker);

IsolationPreconditions CheckEnrollPreconditions(const IsolationMarker& marker, PeerRole role,
                                                 SlotBindMode mode);

PadBindRequirement PadBindRequirementFor(GameTarget target);

IsolationReport EvaluateIsolation(const IsolationSnapshot& snapshot);

}  // namespace bfc::gamer_pad
