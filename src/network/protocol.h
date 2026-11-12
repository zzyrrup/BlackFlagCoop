#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "network.h"

namespace bfc {

// Shared co-op protocol message types (standalone networking only).
// Handshake/ping framing from v0.3.2 is preserved.
constexpr uint32_t kMsgHandshakeRequest = 1;
constexpr uint32_t kMsgHandshakeResponse = 2;
constexpr uint32_t kMsgPing = 3;
constexpr uint32_t kMsgPong = 4;
constexpr uint32_t kMsgPlayerPresence = 5;
constexpr uint32_t kMsgPlayerState = 6;
// Extended pose/movement for future verified game telemetry (v0.5.0+).
// Framing and handshake (msgs 1-4) are unchanged. V1 state (msg 6) remains valid.
constexpr uint32_t kMsgPlayerStateEx = 7;
// Optional keepalive; peers may ignore unknown types safely.
constexpr uint32_t kMsgHeartbeat = 8;

constexpr uint32_t kProtocolMagic = 0x31434642;  // 'BFC1' little-endian
constexpr uint32_t kProtocolVersion = 1;

constexpr uint32_t kPresenceEventJoin = 1;
constexpr uint32_t kPresenceEventLeave = 2;

constexpr uint32_t kConnectionStatusDisconnected = 0;
constexpr uint32_t kConnectionStatusConnected = 1;
constexpr uint32_t kConnectionStatusLeaving = 2;

constexpr uint32_t kMovementStateUnknown = 0;
constexpr uint32_t kMovementStateIdle = 1;
constexpr uint32_t kMovementStateWalking = 2;
constexpr uint32_t kMovementStateRunning = 3;
constexpr uint32_t kMovementStateSprinting = 4;
constexpr uint32_t kMovementStateClimbing = 5;
constexpr uint32_t kMovementStateSwimming = 6;
constexpr uint32_t kMovementStateSailing = 7;

#pragma pack(push, 1)
struct HandshakeRequestPayload {
    uint32_t magic = kProtocolMagic;
    uint32_t version = kProtocolVersion;
};

struct HandshakeResponsePayload {
    uint32_t magic = kProtocolMagic;
    uint32_t version = kProtocolVersion;
    uint64_t sessionId = 0;
    uint32_t assignedLocalPlayerId = 0;
    uint32_t assignedRemotePlayerId = 0;
};

struct PlayerPresencePayload {
    uint32_t magic = kProtocolMagic;
    uint32_t playerId = 0;
    uint32_t event = kPresenceEventJoin;
    uint32_t reserved = 0;
};

struct PlayerStatePayload {
    uint32_t magic = kProtocolMagic;
    uint32_t playerId = 0;
    uint32_t connectionStatus = kConnectionStatusConnected;
    float x = 0.0f;
    float y = 0.0f;
    float z = 0.0f;
    uint64_t tick = 0;
};

// Extends PlayerStatePayload with rotation + movement + session presence flags.
// Values remain placeholders until PlayerTelemetry has a verified source.
struct PlayerStateExPayload {
    uint32_t magic = kProtocolMagic;
    uint32_t playerId = 0;
    uint32_t connectionStatus = kConnectionStatusConnected;
    float x = 0.0f;
    float y = 0.0f;
    float z = 0.0f;
    float yawDegrees = 0.0f;
    float pitchDegrees = 0.0f;
    uint32_t movementState = kMovementStateUnknown;
    uint32_t flags = 0;  // bit0 = poseVerifiedFromGame
    uint64_t tick = 0;
    uint64_t sessionId = 0;
};

struct HeartbeatPayload {
    uint32_t magic = kProtocolMagic;
    uint64_t senderTick = 0;
};
#pragma pack(pop)

constexpr uint32_t kStateExFlagPoseVerified = 1u << 0;

inline bool IsRecognizedMessageType(uint32_t type) {
    return type >= kMsgHandshakeRequest && type <= kMsgHeartbeat;
}

// Until a verified in-game pose source exists, clear the verified bit on receive.
inline void SanitizePlayerStateExFlags(PlayerStateExPayload& payload) {
    payload.flags &= ~kStateExFlagPoseVerified;
}

inline NetworkMessage MakeMessage(uint32_t type, const void* data, size_t size) {
    NetworkMessage message;
    message.type = type;
    message.payload.resize(size);
    if (size > 0 && data != nullptr) {
        std::memcpy(message.payload.data(), data, size);
    }
    return message;
}

inline NetworkMessage MakeHandshakeRequest() {
    HandshakeRequestPayload payload {};
    return MakeMessage(kMsgHandshakeRequest, &payload, sizeof(payload));
}

inline NetworkMessage MakeHandshakeResponse(uint64_t sessionId,
                                            uint32_t assignedLocalPlayerId,
                                            uint32_t assignedRemotePlayerId) {
    HandshakeResponsePayload payload {};
    payload.sessionId = sessionId;
    payload.assignedLocalPlayerId = assignedLocalPlayerId;
    payload.assignedRemotePlayerId = assignedRemotePlayerId;
    return MakeMessage(kMsgHandshakeResponse, &payload, sizeof(payload));
}

inline NetworkMessage MakePing(const std::string& text) {
    return MakeMessage(kMsgPing, text.data(), text.size());
}

inline NetworkMessage MakePong(const std::string& text) {
    return MakeMessage(kMsgPong, text.data(), text.size());
}

inline NetworkMessage MakePlayerPresence(uint32_t playerId, uint32_t event) {
    PlayerPresencePayload payload {};
    payload.playerId = playerId;
    payload.event = event;
    return MakeMessage(kMsgPlayerPresence, &payload, sizeof(payload));
}

inline NetworkMessage MakePlayerState(uint32_t playerId,
                                      uint32_t connectionStatus,
                                      float x,
                                      float y,
                                      float z,
                                      uint64_t tick) {
    PlayerStatePayload payload {};
    payload.playerId = playerId;
    payload.connectionStatus = connectionStatus;
    payload.x = x;
    payload.y = y;
    payload.z = z;
    payload.tick = tick;
    return MakeMessage(kMsgPlayerState, &payload, sizeof(payload));
}

inline NetworkMessage MakePlayerStateEx(const PlayerStateExPayload& payloadIn) {
    PlayerStateExPayload payload = payloadIn;
    payload.magic = kProtocolMagic;
    return MakeMessage(kMsgPlayerStateEx, &payload, sizeof(payload));
}

inline NetworkMessage MakeHeartbeat(uint64_t senderTick) {
    HeartbeatPayload payload {};
    payload.senderTick = senderTick;
    return MakeMessage(kMsgHeartbeat, &payload, sizeof(payload));
}

inline bool ParsePlayerPresence(const NetworkMessage& message,
                                PlayerPresencePayload& outPayload) {
    if (message.type != kMsgPlayerPresence ||
        message.payload.size() < sizeof(PlayerPresencePayload)) {
        return false;
    }
    std::memcpy(&outPayload, message.payload.data(), sizeof(outPayload));
    if (outPayload.magic != kProtocolMagic) {
        return false;
    }
    if (outPayload.event != kPresenceEventJoin &&
        outPayload.event != kPresenceEventLeave) {
        return false;
    }
    if (outPayload.playerId == 0) {
        return false;
    }
    return true;
}

inline bool ParsePlayerState(const NetworkMessage& message,
                             PlayerStatePayload& outPayload) {
    if (message.type != kMsgPlayerState ||
        message.payload.size() < sizeof(PlayerStatePayload)) {
        return false;
    }
    std::memcpy(&outPayload, message.payload.data(), sizeof(outPayload));
    if (outPayload.magic != kProtocolMagic) {
        return false;
    }
    if (outPayload.playerId == 0) {
        return false;
    }
    if (outPayload.connectionStatus > kConnectionStatusLeaving) {
        return false;
    }
    return true;
}

inline bool ParsePlayerStateEx(const NetworkMessage& message,
                               PlayerStateExPayload& outPayload) {
    if (message.type != kMsgPlayerStateEx ||
        message.payload.size() < sizeof(PlayerStateExPayload)) {
        return false;
    }
    std::memcpy(&outPayload, message.payload.data(), sizeof(outPayload));
    if (outPayload.magic != kProtocolMagic) {
        return false;
    }
    if (outPayload.playerId == 0) {
        return false;
    }
    if (outPayload.connectionStatus > kConnectionStatusLeaving) {
        return false;
    }
    // Policy: do not accept "verified pose" claims until game telemetry is proven.
    SanitizePlayerStateExFlags(outPayload);
    return true;
}

inline bool ParseHeartbeat(const NetworkMessage& message,
                           HeartbeatPayload& outPayload) {
    if (message.type != kMsgHeartbeat ||
        message.payload.size() < sizeof(HeartbeatPayload)) {
        return false;
    }
    std::memcpy(&outPayload, message.payload.data(), sizeof(outPayload));
    return outPayload.magic == kProtocolMagic;
}

inline const char* MovementStateName(uint32_t state) {
    switch (state) {
    case kMovementStateUnknown:
        return "Unknown";
    case kMovementStateIdle:
        return "Idle";
    case kMovementStateWalking:
        return "Walking";
    case kMovementStateRunning:
        return "Running";
    case kMovementStateSprinting:
        return "Sprinting";
    case kMovementStateClimbing:
        return "Climbing";
    case kMovementStateSwimming:
        return "Swimming";
    case kMovementStateSailing:
        return "Sailing";
    default:
        return "Unknown";
    }
}

inline std::string PayloadAsString(const NetworkMessage& message) {
    if (message.payload.empty()) {
        return {};
    }
    return std::string(reinterpret_cast<const char*>(message.payload.data()),
                       message.payload.size());
}

inline const char* ConnectionStatusName(uint32_t status) {
    switch (status) {
    case kConnectionStatusDisconnected:
        return "Disconnected";
    case kConnectionStatusConnected:
        return "Connected";
    case kConnectionStatusLeaving:
        return "Leaving";
    default:
        return "Unknown";
    }
}

inline const char* PresenceEventName(uint32_t event) {
    switch (event) {
    case kPresenceEventJoin:
        return "Join";
    case kPresenceEventLeave:
        return "Leave";
    default:
        return "Unknown";
    }
}

}  // namespace bfc
