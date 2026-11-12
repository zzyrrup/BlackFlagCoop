#pragma once

#include "network/network.h"
#include "network/session.h"

#include <cstdint>
#include <string>

namespace bfc {

// Candidate build identity. The installed in-game ASI remains v0.5.1.
inline constexpr const char* kSessionPanelVersion = "0.7.0-dev";

// v0.7.0 draws this panel only when the process opts in.
// The default is structured log lines and no extra window.
enum class SessionPanelDisplayMode {
    LogOnly,
    Overlay
};

enum class PanelPresence {
    NotJoined,
    Connected,
    Leaving,
    Disconnected
};

enum class PanelReady {
    NotApplicable,
    NotReady,
    Ready
};

// Plain inputs so tests and a future session loop share one snapshot path.
// There is no field that can claim an in-world Edward. v0.6.5/v0.6.6 did not
// recover a character factory, so this panel must not invent one.
struct SessionPanelInput {
    SessionState sessionState = SessionState::Idle;
    NetworkRole role = NetworkRole::None;
    SessionId sessionId = 0;
    PlayerId localPlayerId = kInvalidPlayerId;
    PlayerId remotePlayerId = kInvalidPlayerId;
    bool remoteSeen = false;
    bool remoteJoined = false;
    uint32_t remoteConnectionStatus = kConnectionStatusDisconnected;
    bool localReady = false;
    bool remoteReady = false;
    std::string lastError;
};

struct SessionSlotView {
    PlayerId playerId = kInvalidPlayerId;
    std::string displayName;
    std::string assignment;
    PanelPresence presence = PanelPresence::NotJoined;
    PanelReady ready = PanelReady::NotApplicable;
    // Always false. Kept on the snapshot so tests can reject a future claim.
    bool inWorldEdward = false;
    std::string detail;
};

struct SessionPanelSnapshot {
    std::string pluginVersion;
    SessionState sessionState = SessionState::Idle;
    NetworkRole role = NetworkRole::None;
    SessionId sessionId = 0;
    std::string connectionSummary;
    std::string safetyBanner;
    SessionSlotView player1;
    SessionSlotView player2;
    std::string lastError;
};

SessionPanelInput MakeIdleSessionPanelInput();
SessionPanelSnapshot BuildSessionPanel(const SessionPanelInput& input);
std::string RenderSessionPanel(const SessionPanelSnapshot& snapshot);
bool SessionPanelClaimsInWorldEdward(const SessionPanelSnapshot& snapshot);

const char* SessionStateLabel(SessionState state);
const char* NetworkRoleLabel(NetworkRole role);
const char* PanelPresenceLabel(PanelPresence presence);
const char* PanelReadyLabel(PanelReady ready);

SessionPanelDisplayMode ParseSessionPanelDisplayMode(const char* value);
SessionPanelDisplayMode SessionPanelDisplayModeFromEnvironment();

}  // namespace bfc
