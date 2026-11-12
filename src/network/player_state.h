#pragma once

#include "protocol.h"
#include "session.h"

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace bfc {

struct TrackedPlayerState {
    PlayerId playerId = kInvalidPlayerId;
    uint32_t connectionStatus = kConnectionStatusDisconnected;
    float x = 0.0f;
    float y = 0.0f;
    float z = 0.0f;
    float yawDegrees = 0.0f;
    float pitchDegrees = 0.0f;
    uint32_t movementState = kMovementStateUnknown;
    uint32_t flags = 0;
    uint64_t tick = 0;
    uint64_t sessionId = 0;
    bool present = false;
    bool hasExtendedPose = false;
};

// Tracks the latest known presence/state for each player ID.
// Placeholder positions only — not real game-world coordinates.
class PlayerStateTracker {
public:
    void Clear();

    bool ApplyPresence(const PlayerPresencePayload& presence, std::string& error);
    bool ApplyState(const PlayerStatePayload& state, std::string& error);
    bool ApplyStateEx(const PlayerStateExPayload& state, std::string& error);
    void MarkDisconnected(PlayerId playerId);

    void SetLocalState(PlayerId playerId,
                       float x,
                       float y,
                       float z,
                       uint64_t tick,
                       uint32_t connectionStatus = kConnectionStatusConnected);

    void SetLocalStateEx(PlayerId playerId,
                         const PlayerStateExPayload& state);

    std::optional<TrackedPlayerState> Get(PlayerId playerId) const;
    size_t CountPresent() const;
    size_t CountConnected() const;

private:
    mutable std::mutex mutex_;
    std::unordered_map<PlayerId, TrackedPlayerState> players_;
};

}  // namespace bfc
