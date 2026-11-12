#pragma once

#include "network.h"
#include "protocol.h"

#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>

namespace bfc {

using PlayerId = uint32_t;
using SessionId = uint64_t;

constexpr PlayerId kInvalidPlayerId = 0;
constexpr PlayerId kHostPlayerId = 1;
constexpr PlayerId kClientPlayerId = 2;

enum class SessionState {
    Idle,
    Hosting,
    Joining,
    Active,
    Ending,
    Error
};

// Result of Session::Poll — distinguishes app traffic from reliability traffic.
enum class SessionPollResult {
    AppMessage,       // outMessage is a non-heartbeat application message
    HeartbeatHandled, // valid heartbeat consumed; no app message
    TimedOut,         // wait elapsed; session still active
    IdleTimeout,      // peer silent beyond idleTimeoutMs; session ended
    Disconnected,     // socket closed / receive error
    Rejected          // framed but invalid (e.g. malformed heartbeat); session kept
};

// Optional keepalive / idle detection (v0.5.8).
// Defaults are intentionally generous so ordinary quiet gameplay is not dropped.
// Heartbeats never mutate PlayerStateTracker pose fields.
struct ReliabilityConfig {
    bool enabled = false;
    // How often this peer sends kMsgHeartbeat while Active.
    uint32_t heartbeatIntervalMs = 5000;
    // Disconnect if no *valid* inbound framed message for this long.
    // Default = 6x heartbeat interval.
    uint32_t idleTimeoutMs = 30000;
};

// High-level co-op session wrapper around Network.
// Performs a lightweight handshake that exchanges session/player IDs.
class Session {
public:
    Session();

    // bindAddress: "127.0.0.1" for localhost tests, "0.0.0.0" for future LAN.
    bool Host(uint16_t port,
              const std::string& bindAddress = "0.0.0.0",
              uint32_t acceptTimeoutMs = 60000);
    bool Join(const std::string& host, uint16_t port);
    void Leave();

    bool Send(const NetworkMessage& message);
    bool Receive(NetworkMessage& outMessage, uint32_t timeoutMs, bool& timedOut);

    // Reliability-aware receive loop helper. Prefer this when ReliabilityConfig.enabled.
    // Uses steady_clock; does not busy-wait (delegates to Network::Receive timeouts).
    SessionPollResult Poll(NetworkMessage& outMessage, uint32_t waitMs);

    void SetReliabilityConfig(const ReliabilityConfig& config);
    ReliabilityConfig GetReliabilityConfig() const;

    // Valid inbound activity age (ms). 0 if never noted / not active.
    uint64_t MillisecondsSinceLastValidInbound() const;
    uint64_t HeartbeatsSent() const;
    uint64_t HeartbeatsReceived() const;
    bool IdleTimedOutFlag() const;

    // Direct access for reliability tests that need raw frames.
    Network& GetNetwork();

    SessionState State() const;
    NetworkRole Role() const;
    SessionId GetSessionId() const;
    PlayerId LocalPlayerId() const;
    PlayerId RemotePlayerId() const;
    std::string LastError() const;

private:
    using SteadyClock = std::chrono::steady_clock;

    SessionId GenerateSessionId() const;
    void SetState(SessionState state);
    void SetError(const std::string& message);
    void ResetLocked();
    bool CompleteHostHandshakeLocked();
    bool CompleteClientHandshakeLocked();
    void NoteValidInboundLocked();
    void ArmReliabilityLocked();
    bool MaybeSendHeartbeatLocked();
    bool CheckIdleTimeoutLocked();
    bool MessageCountsAsValidInbound(const NetworkMessage& message) const;

    mutable std::mutex mutex_;
    Network network_;
    SessionState state_ = SessionState::Idle;
    SessionId sessionId_ = 0;
    PlayerId localPlayerId_ = kInvalidPlayerId;
    PlayerId remotePlayerId_ = kInvalidPlayerId;
    std::string lastError_;

    ReliabilityConfig reliability_ {};
    SteadyClock::time_point lastValidInbound_ {};
    SteadyClock::time_point lastHeartbeatSent_ {};
    uint64_t heartbeatsSent_ = 0;
    uint64_t heartbeatsReceived_ = 0;
    bool idleTimedOut_ = false;
    uint64_t outboundTick_ = 0;
};

}  // namespace bfc
