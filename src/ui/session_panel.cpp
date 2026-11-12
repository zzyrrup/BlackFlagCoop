#include "ui/session_panel.h"

#include <cctype>
#include <cstdlib>
#include <sstream>

namespace bfc {
namespace {

constexpr const char* kSafetyBanner =
    "No second Edward is spawned. Player 2 is a session slot only.";
constexpr const char* kEdwardDetail = "Edward: not spawned";

bool SessionHasIdentity(const SessionPanelInput& input) {
    return input.sessionState != SessionState::Idle &&
           input.role != NetworkRole::None;
}

PlayerId EffectiveLocalPlayerId(const SessionPanelInput& input) {
    if (input.localPlayerId != kInvalidPlayerId) {
        return input.localPlayerId;
    }
    // Host reserves slot 1 as soon as a session exists, matching the handshake.
    if (input.role == NetworkRole::Host && SessionHasIdentity(input)) {
        return kHostPlayerId;
    }
    return kInvalidPlayerId;
}

PanelPresence RemotePresence(const SessionPanelInput& input) {
    if (!input.remoteSeen) {
        return PanelPresence::NotJoined;
    }
    if (input.remoteConnectionStatus == kConnectionStatusLeaving) {
        return PanelPresence::Leaving;
    }
    if (input.remoteJoined &&
        input.remoteConnectionStatus == kConnectionStatusConnected) {
        return PanelPresence::Connected;
    }
    return PanelPresence::Disconnected;
}

PanelPresence LocalPresence(const SessionPanelInput& input, bool slotIsLocal) {
    if (!slotIsLocal) {
        return PanelPresence::NotJoined;
    }
    switch (input.sessionState) {
    case SessionState::Hosting:
    case SessionState::Joining:
    case SessionState::Active:
        return PanelPresence::Connected;
    case SessionState::Ending:
        return PanelPresence::Leaving;
    case SessionState::Error:
        return PanelPresence::Disconnected;
    case SessionState::Idle:
        return PanelPresence::NotJoined;
    }
    return PanelPresence::NotJoined;
}

PanelReady ReadyFor(PanelPresence presence, bool ready) {
    if (presence != PanelPresence::Connected) {
        return PanelReady::NotApplicable;
    }
    return ready ? PanelReady::Ready : PanelReady::NotReady;
}

std::string AssignmentFor(bool sessionOpen, PlayerId localId, PlayerId slotId) {
    if (!sessionOpen || localId == kInvalidPlayerId) {
        return "Unassigned";
    }
    if (slotId == localId) {
        return "Local";
    }
    return "Remote";
}

std::string ConnectionSummary(const SessionPanelInput& input,
                              PanelPresence remotePresence) {
    if (input.sessionState == SessionState::Error) {
        return "error";
    }
    if (input.sessionState == SessionState::Ending) {
        return "session ending";
    }
    if (!SessionHasIdentity(input)) {
        return "not started";
    }
    if (remotePresence == PanelPresence::Connected) {
        return "player 2 connected";
    }
    if (remotePresence == PanelPresence::Disconnected) {
        return "player 2 disconnected";
    }
    if (remotePresence == PanelPresence::Leaving) {
        return "player 2 leaving";
    }
    if (input.role == NetworkRole::Host) {
        return "hosting; waiting for player 2";
    }
    if (input.role == NetworkRole::Client) {
        return "joining host";
    }
    return "not started";
}

SessionSlotView MakeSlot(const SessionPanelInput& input,
                         PlayerId slotId,
                         PlayerId localId,
                         bool sessionOpen) {
    SessionSlotView slot;
    slot.playerId = slotId;
    slot.displayName = slotId == kHostPlayerId ? "Player 1" : "Player 2";
    slot.assignment = AssignmentFor(sessionOpen, localId, slotId);
    const bool isLocal = slot.assignment == "Local";
    if (isLocal) {
        slot.presence = LocalPresence(input, true);
        slot.ready = ReadyFor(slot.presence, input.localReady);
    } else if (slot.assignment == "Remote") {
        slot.presence = RemotePresence(input);
        slot.ready = ReadyFor(slot.presence, input.remoteReady);
    } else {
        slot.presence = PanelPresence::NotJoined;
        slot.ready = PanelReady::NotApplicable;
    }
    slot.inWorldEdward = false;
    slot.detail = kEdwardDetail;
    return slot;
}

std::string LowerCopy(const char* value) {
    std::string lowered(value);
    for (char& ch : lowered) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    return lowered;
}

}  // namespace

const char* SessionStateLabel(SessionState state) {
    switch (state) {
    case SessionState::Idle:
        return "Idle";
    case SessionState::Hosting:
        return "Hosting";
    case SessionState::Joining:
        return "Joining";
    case SessionState::Active:
        return "Active";
    case SessionState::Ending:
        return "Ending";
    case SessionState::Error:
        return "Error";
    }
    return "Idle";
}

const char* NetworkRoleLabel(NetworkRole role) {
    switch (role) {
    case NetworkRole::None:
        return "Idle";
    case NetworkRole::Host:
        return "Host";
    case NetworkRole::Client:
        return "Client";
    }
    return "Idle";
}

const char* PanelPresenceLabel(PanelPresence presence) {
    switch (presence) {
    case PanelPresence::NotJoined:
        return "Not joined";
    case PanelPresence::Connected:
        return "Connected";
    case PanelPresence::Leaving:
        return "Leaving";
    case PanelPresence::Disconnected:
        return "Disconnected";
    }
    return "Not joined";
}

const char* PanelReadyLabel(PanelReady ready) {
    switch (ready) {
    case PanelReady::NotApplicable:
        return "n/a";
    case PanelReady::NotReady:
        return "not ready";
    case PanelReady::Ready:
        return "ready";
    }
    return "n/a";
}

SessionPanelInput MakeIdleSessionPanelInput() {
    return {};
}

SessionPanelSnapshot BuildSessionPanel(const SessionPanelInput& input) {
    SessionPanelSnapshot snapshot;
    snapshot.pluginVersion = kSessionPanelVersion;
    snapshot.sessionState = input.sessionState;
    snapshot.role = input.role;
    snapshot.sessionId = input.sessionId;
    snapshot.lastError = input.lastError;
    snapshot.safetyBanner = kSafetyBanner;

    const bool sessionOpen = SessionHasIdentity(input);
    const PlayerId localId = EffectiveLocalPlayerId(input);
    snapshot.player1 = MakeSlot(input, kHostPlayerId, localId, sessionOpen);
    snapshot.player2 = MakeSlot(input, kClientPlayerId, localId, sessionOpen);
    snapshot.connectionSummary = ConnectionSummary(input, RemotePresence(input));
    snapshot.player1.inWorldEdward = false;
    snapshot.player2.inWorldEdward = false;
    return snapshot;
}

std::string RenderSessionPanel(const SessionPanelSnapshot& snapshot) {
    std::ostringstream out;
    out << "BlackFlagCoop session panel " << snapshot.pluginVersion << "\n";
    out << "Role: " << NetworkRoleLabel(snapshot.role) << "\n";
    out << "State: " << SessionStateLabel(snapshot.sessionState) << "\n";
    out << "Session: "
        << (snapshot.sessionId == 0 ? "none" : std::to_string(snapshot.sessionId))
        << "\n";
    out << "Connection: " << snapshot.connectionSummary << "\n";
    out << "Safety: " << snapshot.safetyBanner << "\n";

    const SessionSlotView* slots[] = {&snapshot.player1, &snapshot.player2};
    for (const SessionSlotView* slot : slots) {
        out << "Slot " << slot->playerId << " | " << slot->displayName << " | "
            << slot->assignment << " | " << PanelPresenceLabel(slot->presence)
            << " | Ready: " << PanelReadyLabel(slot->ready) << " | " << slot->detail
            << "\n";
    }

    if (snapshot.sessionState == SessionState::Error || !snapshot.lastError.empty()) {
        out << "Error: "
            << (snapshot.lastError.empty() ? "unspecified" : snapshot.lastError)
            << "\n";
    }
    return out.str();
}

bool SessionPanelClaimsInWorldEdward(const SessionPanelSnapshot& snapshot) {
    return snapshot.player1.inWorldEdward || snapshot.player2.inWorldEdward;
}

SessionPanelDisplayMode ParseSessionPanelDisplayMode(const char* value) {
    if (value == nullptr || value[0] == '\0') {
        return SessionPanelDisplayMode::LogOnly;
    }
    const std::string lowered = LowerCopy(value);
    if (lowered == "1" || lowered == "on" || lowered == "overlay" ||
        lowered == "true") {
        return SessionPanelDisplayMode::Overlay;
    }
    return SessionPanelDisplayMode::LogOnly;
}

SessionPanelDisplayMode SessionPanelDisplayModeFromEnvironment() {
    char* buffer = nullptr;
    size_t length = 0;
    if (_dupenv_s(&buffer, &length, "BFC_SESSION_PANEL") != 0 || buffer == nullptr) {
        return SessionPanelDisplayMode::LogOnly;
    }
    const SessionPanelDisplayMode mode = ParseSessionPanelDisplayMode(buffer);
    std::free(buffer);
    return mode;
}

}  // namespace bfc
