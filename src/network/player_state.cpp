#include "player_state.h"

namespace bfc {

void PlayerStateTracker::Clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    players_.clear();
}

bool PlayerStateTracker::ApplyPresence(const PlayerPresencePayload& presence,
                                       std::string& error) {
    if (presence.magic != kProtocolMagic) {
        error = "presence magic mismatch";
        return false;
    }
    if (presence.playerId == kInvalidPlayerId) {
        error = "presence missing player id";
        return false;
    }
    if (presence.event != kPresenceEventJoin &&
        presence.event != kPresenceEventLeave) {
        error = "presence event invalid";
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    TrackedPlayerState& entry = players_[presence.playerId];
    entry.playerId = presence.playerId;

    if (presence.event == kPresenceEventJoin) {
        entry.present = true;
        entry.connectionStatus = kConnectionStatusConnected;
    } else {
        entry.present = false;
        entry.connectionStatus = kConnectionStatusDisconnected;
    }
    error.clear();
    return true;
}

bool PlayerStateTracker::ApplyState(const PlayerStatePayload& state,
                                    std::string& error) {
    if (state.magic != kProtocolMagic) {
        error = "state magic mismatch";
        return false;
    }
    if (state.playerId == kInvalidPlayerId) {
        error = "state missing player id";
        return false;
    }
    if (state.connectionStatus > kConnectionStatusLeaving) {
        error = "state connection status invalid";
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    TrackedPlayerState& entry = players_[state.playerId];
    entry.playerId = state.playerId;
    entry.connectionStatus = state.connectionStatus;
    entry.x = state.x;
    entry.y = state.y;
    entry.z = state.z;
    entry.tick = state.tick;
    entry.present = (state.connectionStatus != kConnectionStatusDisconnected);
    // V1 updates do not clear extended fields if previously set.
    error.clear();
    return true;
}

bool PlayerStateTracker::ApplyStateEx(const PlayerStateExPayload& state,
                                      std::string& error) {
    if (state.magic != kProtocolMagic) {
        error = "state-ex magic mismatch";
        return false;
    }
    if (state.playerId == kInvalidPlayerId) {
        error = "state-ex missing player id";
        return false;
    }
    if (state.connectionStatus > kConnectionStatusLeaving) {
        error = "state-ex connection status invalid";
        return false;
    }

    PlayerStateExPayload sanitized = state;
    SanitizePlayerStateExFlags(sanitized);

    std::lock_guard<std::mutex> lock(mutex_);
    TrackedPlayerState& entry = players_[sanitized.playerId];
    entry.playerId = sanitized.playerId;
    entry.connectionStatus = sanitized.connectionStatus;
    entry.x = sanitized.x;
    entry.y = sanitized.y;
    entry.z = sanitized.z;
    entry.yawDegrees = sanitized.yawDegrees;
    entry.pitchDegrees = sanitized.pitchDegrees;
    entry.movementState = sanitized.movementState;
    entry.flags = sanitized.flags;
    entry.tick = sanitized.tick;
    entry.sessionId = sanitized.sessionId;
    entry.hasExtendedPose = true;
    entry.present =
        (sanitized.connectionStatus != kConnectionStatusDisconnected);
    error.clear();
    return true;
}

void PlayerStateTracker::MarkDisconnected(PlayerId playerId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = players_.find(playerId);
    if (it == players_.end()) {
        return;
    }
    it->second.present = false;
    it->second.connectionStatus = kConnectionStatusDisconnected;
}

void PlayerStateTracker::SetLocalState(PlayerId playerId,
                                       float x,
                                       float y,
                                       float z,
                                       uint64_t tick,
                                       uint32_t connectionStatus) {
    std::lock_guard<std::mutex> lock(mutex_);
    TrackedPlayerState& entry = players_[playerId];
    entry.playerId = playerId;
    entry.x = x;
    entry.y = y;
    entry.z = z;
    entry.tick = tick;
    entry.connectionStatus = connectionStatus;
    entry.present = (connectionStatus != kConnectionStatusDisconnected);
}

void PlayerStateTracker::SetLocalStateEx(PlayerId playerId,
                                         const PlayerStateExPayload& state) {
    PlayerStateExPayload sanitized = state;
    SanitizePlayerStateExFlags(sanitized);

    std::lock_guard<std::mutex> lock(mutex_);
    TrackedPlayerState& entry = players_[playerId];
    entry.playerId = playerId;
    entry.connectionStatus = sanitized.connectionStatus;
    entry.x = sanitized.x;
    entry.y = sanitized.y;
    entry.z = sanitized.z;
    entry.yawDegrees = sanitized.yawDegrees;
    entry.pitchDegrees = sanitized.pitchDegrees;
    entry.movementState = sanitized.movementState;
    entry.flags = sanitized.flags;
    entry.tick = sanitized.tick;
    entry.sessionId = sanitized.sessionId;
    entry.hasExtendedPose = true;
    entry.present =
        (sanitized.connectionStatus != kConnectionStatusDisconnected);
}

std::optional<TrackedPlayerState> PlayerStateTracker::Get(PlayerId playerId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = players_.find(playerId);
    if (it == players_.end()) {
        return std::nullopt;
    }
    return it->second;
}

size_t PlayerStateTracker::CountPresent() const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t count = 0;
    for (const auto& pair : players_) {
        if (pair.second.present) {
            ++count;
        }
    }
    return count;
}

size_t PlayerStateTracker::CountConnected() const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t count = 0;
    for (const auto& pair : players_) {
        if (pair.second.connectionStatus == kConnectionStatusConnected) {
            ++count;
        }
    }
    return count;
}

}  // namespace bfc
