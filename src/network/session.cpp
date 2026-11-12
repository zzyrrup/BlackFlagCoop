#include "session.h"

#include "../logger.h"

#include <Windows.h>

#include <chrono>
#include <cstring>
#include <string>

namespace bfc {

Session::Session() = default;

SessionId Session::GenerateSessionId() const {
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    const auto nanos =
        std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
    const uint64_t pid = static_cast<uint64_t>(GetCurrentProcessId());
    const uint64_t tid = static_cast<uint64_t>(GetCurrentThreadId());
    return (pid << 32) ^ tid ^ static_cast<uint64_t>(nanos);
}

void Session::SetState(SessionState state) {
    state_ = state;
}

void Session::SetError(const std::string& message) {
    lastError_ = message;
    state_ = SessionState::Error;
    Logger::Info(std::string("Session error: ") + message);
}

void Session::NoteValidInboundLocked() {
    lastValidInbound_ = SteadyClock::now();
}

void Session::ArmReliabilityLocked() {
    const auto now = SteadyClock::now();
    lastValidInbound_ = now;
    lastHeartbeatSent_ = now;
    heartbeatsSent_ = 0;
    heartbeatsReceived_ = 0;
    idleTimedOut_ = false;
    outboundTick_ = 0;
}

void Session::ResetLocked() {
    if (state_ == SessionState::Active ||
        state_ == SessionState::Hosting ||
        state_ == SessionState::Joining) {
        SetState(SessionState::Ending);
        Logger::Info("Leaving session " + std::to_string(sessionId_));
    }

    network_.Disconnect();
    localPlayerId_ = kInvalidPlayerId;
    remotePlayerId_ = kInvalidPlayerId;
    sessionId_ = 0;
    heartbeatsSent_ = 0;
    heartbeatsReceived_ = 0;
    // Preserve idleTimedOut_ so callers can observe why Leave happened via Poll.
    SetState(SessionState::Idle);
}

bool Session::MessageCountsAsValidInbound(const NetworkMessage& message) const {
    switch (message.type) {
    case kMsgHandshakeRequest:
    case kMsgHandshakeResponse:
        return message.payload.size() >= sizeof(HandshakeRequestPayload);
    case kMsgPing:
    case kMsgPong:
        return true;
    case kMsgPlayerPresence: {
        PlayerPresencePayload payload {};
        return ParsePlayerPresence(message, payload);
    }
    case kMsgPlayerState: {
        PlayerStatePayload payload {};
        return ParsePlayerState(message, payload);
    }
    case kMsgPlayerStateEx: {
        PlayerStateExPayload payload {};
        return ParsePlayerStateEx(message, payload);
    }
    case kMsgHeartbeat: {
        HeartbeatPayload payload {};
        return ParseHeartbeat(message, payload);
    }
    default:
        return false;
    }
}

bool Session::MaybeSendHeartbeatLocked() {
    if (!reliability_.enabled || state_ != SessionState::Active) {
        return true;
    }
    if (reliability_.heartbeatIntervalMs == 0) {
        return true;
    }

    const auto now = SteadyClock::now();
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                             now - lastHeartbeatSent_)
                             .count();
    if (elapsed < static_cast<std::chrono::milliseconds::rep>(
                      reliability_.heartbeatIntervalMs)) {
        return true;
    }

    ++outboundTick_;
    if (!network_.Send(MakeHeartbeat(outboundTick_))) {
        SetError(network_.LastError().empty() ? "Heartbeat send failed"
                                              : network_.LastError());
        return false;
    }
    lastHeartbeatSent_ = now;
    ++heartbeatsSent_;
    return true;
}

bool Session::CheckIdleTimeoutLocked() {
    if (!reliability_.enabled || state_ != SessionState::Active) {
        return false;
    }
    if (reliability_.idleTimeoutMs == 0) {
        return false;
    }

    const auto now = SteadyClock::now();
    const auto silentMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                              now - lastValidInbound_)
                              .count();
    if (silentMs < static_cast<std::chrono::milliseconds::rep>(
                       reliability_.idleTimeoutMs)) {
        return false;
    }

    idleTimedOut_ = true;
    Logger::Info("Session idle timeout after " + std::to_string(silentMs) +
                 "ms without valid inbound (limit=" +
                 std::to_string(reliability_.idleTimeoutMs) + "ms)");
    ResetLocked();
    return true;
}

bool Session::CompleteHostHandshakeLocked() {
    bool timedOut = false;
    NetworkMessage request;
    if (!network_.Receive(request, 10000, timedOut) || timedOut) {
        SetError(timedOut ? "Host handshake timed out"
                          : "Host failed to receive handshake request");
        return false;
    }

    if (request.type != kMsgHandshakeRequest ||
        request.payload.size() < sizeof(HandshakeRequestPayload)) {
        SetError("Host received invalid handshake request");
        return false;
    }

    HandshakeRequestPayload req {};
    std::memcpy(&req, request.payload.data(), sizeof(req));
    if (req.magic != kProtocolMagic || req.version != kProtocolVersion) {
        SetError("Host handshake magic/version mismatch");
        return false;
    }

    // Response tells the client its local ID (2) and remote ID (1 = host).
    const NetworkMessage response = MakeHandshakeResponse(
        sessionId_, kClientPlayerId, kHostPlayerId);
    if (!network_.Send(response)) {
        SetError("Host failed to send handshake response");
        return false;
    }

    Logger::Info("Host handshake complete for session " +
                 std::to_string(sessionId_));
    return true;
}

bool Session::CompleteClientHandshakeLocked() {
    if (!network_.Send(MakeHandshakeRequest())) {
        SetError("Client failed to send handshake request");
        return false;
    }

    bool timedOut = false;
    NetworkMessage response;
    if (!network_.Receive(response, 10000, timedOut) || timedOut) {
        SetError(timedOut ? "Client handshake timed out"
                          : "Client failed to receive handshake response");
        return false;
    }

    if (response.type != kMsgHandshakeResponse ||
        response.payload.size() < sizeof(HandshakeResponsePayload)) {
        SetError("Client received invalid handshake response");
        return false;
    }

    HandshakeResponsePayload resp {};
    std::memcpy(&resp, response.payload.data(), sizeof(resp));
    if (resp.magic != kProtocolMagic || resp.version != kProtocolVersion) {
        SetError("Client handshake magic/version mismatch");
        return false;
    }

    sessionId_ = resp.sessionId;
    localPlayerId_ = resp.assignedLocalPlayerId;
    remotePlayerId_ = resp.assignedRemotePlayerId;

    Logger::Info(
        "Client handshake complete: session=" + std::to_string(sessionId_) +
        " localPlayer=" + std::to_string(localPlayerId_) +
        " remotePlayer=" + std::to_string(remotePlayerId_));
    return true;
}

bool Session::Host(uint16_t port,
                   const std::string& bindAddress,
                   uint32_t acceptTimeoutMs) {
    std::lock_guard<std::mutex> lock(mutex_);

    idleTimedOut_ = false;
    ResetLocked();
    SetState(SessionState::Hosting);
    lastError_.clear();
    sessionId_ = GenerateSessionId();
    localPlayerId_ = kHostPlayerId;
    remotePlayerId_ = kClientPlayerId;

    Logger::Info(
        "Hosting session " + std::to_string(sessionId_) +
        " as player " + std::to_string(localPlayerId_) +
        " on " + bindAddress + ":" + std::to_string(port));

    if (!network_.StartHost(port, bindAddress, acceptTimeoutMs)) {
        SetError(network_.LastError().empty() ? "Host start failed"
                                              : network_.LastError());
        localPlayerId_ = kInvalidPlayerId;
        remotePlayerId_ = kInvalidPlayerId;
        sessionId_ = 0;
        return false;
    }

    if (!CompleteHostHandshakeLocked()) {
        network_.Disconnect();
        localPlayerId_ = kInvalidPlayerId;
        remotePlayerId_ = kInvalidPlayerId;
        sessionId_ = 0;
        return false;
    }

    SetState(SessionState::Active);
    ArmReliabilityLocked();
    Logger::Info("Session active (host)");
    return true;
}

bool Session::Join(const std::string& host, uint16_t port) {
    std::lock_guard<std::mutex> lock(mutex_);

    idleTimedOut_ = false;
    ResetLocked();
    SetState(SessionState::Joining);
    lastError_.clear();
    sessionId_ = 0;
    localPlayerId_ = kInvalidPlayerId;
    remotePlayerId_ = kInvalidPlayerId;

    Logger::Info("Joining host " + host + ":" + std::to_string(port));

    if (!network_.ConnectToHost(host, port)) {
        SetError(network_.LastError().empty() ? "Join failed"
                                              : network_.LastError());
        return false;
    }

    if (!CompleteClientHandshakeLocked()) {
        network_.Disconnect();
        localPlayerId_ = kInvalidPlayerId;
        remotePlayerId_ = kInvalidPlayerId;
        sessionId_ = 0;
        return false;
    }

    SetState(SessionState::Active);
    ArmReliabilityLocked();
    Logger::Info("Session active (client)");
    return true;
}

void Session::Leave() {
    std::lock_guard<std::mutex> lock(mutex_);
    ResetLocked();
}

bool Session::Send(const NetworkMessage& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    return network_.Send(message);
}

bool Session::Receive(NetworkMessage& outMessage, uint32_t timeoutMs,
                      bool& timedOut) {
    std::lock_guard<std::mutex> lock(mutex_);
    const bool ok = network_.Receive(outMessage, timeoutMs, timedOut);
    if (ok && !timedOut && MessageCountsAsValidInbound(outMessage)) {
        NoteValidInboundLocked();
        if (outMessage.type == kMsgHeartbeat) {
            ++heartbeatsReceived_;
        }
    }
    return ok;
}

SessionPollResult Session::Poll(NetworkMessage& outMessage, uint32_t waitMs) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (state_ != SessionState::Active) {
        return idleTimedOut_ ? SessionPollResult::IdleTimeout
                             : SessionPollResult::Disconnected;
    }

    if (CheckIdleTimeoutLocked()) {
        return SessionPollResult::IdleTimeout;
    }

    if (!MaybeSendHeartbeatLocked()) {
        return SessionPollResult::Disconnected;
    }

    bool timedOut = false;
    if (!network_.Receive(outMessage, waitMs, timedOut)) {
        if (timedOut) {
            if (CheckIdleTimeoutLocked()) {
                return SessionPollResult::IdleTimeout;
            }
            return SessionPollResult::TimedOut;
        }
        ResetLocked();
        return SessionPollResult::Disconnected;
    }

    if (outMessage.type == kMsgHeartbeat) {
        HeartbeatPayload payload {};
        if (!ParseHeartbeat(outMessage, payload)) {
            Logger::Info("Malformed heartbeat rejected");
            return SessionPollResult::Rejected;
        }
        NoteValidInboundLocked();
        ++heartbeatsReceived_;
        return SessionPollResult::HeartbeatHandled;
    }

    if (MessageCountsAsValidInbound(outMessage)) {
        NoteValidInboundLocked();
        return SessionPollResult::AppMessage;
    }

    // Framed but unrecognized/invalid — do not refresh idle timer.
    return SessionPollResult::Rejected;
}

void Session::SetReliabilityConfig(const ReliabilityConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    reliability_ = config;
    // Defaults (5s / 30s) keep healthy quiet peers alive. Tests may set shorter
    // idleTimeoutMs with heartbeatIntervalMs=0 to simulate a silent peer.
    if (reliability_.enabled && reliability_.heartbeatIntervalMs > 0 &&
        reliability_.idleTimeoutMs > 0 &&
        reliability_.idleTimeoutMs < reliability_.heartbeatIntervalMs * 2) {
        Logger::Info(
            "Reliability warning: idleTimeoutMs < 2x heartbeatIntervalMs; "
            "healthy peers may idle-timeout under load");
    }
}

ReliabilityConfig Session::GetReliabilityConfig() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return reliability_;
}

uint64_t Session::MillisecondsSinceLastValidInbound() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ != SessionState::Active) {
        return 0;
    }
    const auto now = SteadyClock::now();
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            now - lastValidInbound_)
            .count());
}

uint64_t Session::HeartbeatsSent() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return heartbeatsSent_;
}

uint64_t Session::HeartbeatsReceived() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return heartbeatsReceived_;
}

bool Session::IdleTimedOutFlag() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return idleTimedOut_;
}

Network& Session::GetNetwork() {
    return network_;
}

SessionState Session::State() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return state_;
}

NetworkRole Session::Role() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return network_.Role();
}

SessionId Session::GetSessionId() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return sessionId_;
}

PlayerId Session::LocalPlayerId() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return localPlayerId_;
}

PlayerId Session::RemotePlayerId() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return remotePlayerId_;
}

std::string Session::LastError() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return lastError_;
}

}  // namespace bfc
