#pragma once

// BlackFlagCoop peer protocol v2.
// Transport-independent encode/decode. This file does not include Winsock,
// session.h, or any game/engine header. It is not wired into Network::Send.
//
// Ownership (lane E): src/network/peer_protocol.h, src/network/peer_protocol.cpp,
// tests/peer_protocol/. Existing v1 files (protocol.h, network.*, session.*,
// player_state.*) are intentionally unchanged.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace bfc {
namespace peer {

// ASCII 'BFC2' little-endian. Distinct from v1 magic 'BFC1' (0x31434642).
constexpr uint32_t kMagic = 0x32434642u;
constexpr uint16_t kHeaderVersion = 2;
constexpr uint32_t kProtocolVersion = 2;

constexpr std::size_t kHeaderBytes = 28;
constexpr std::size_t kMaxPacketBytes = 512;
constexpr std::size_t kMaxPayloadBytes = kMaxPacketBytes - kHeaderBytes;
constexpr std::size_t kMaxBufferedBytes = kMaxPacketBytes * 2;
constexpr std::size_t kMaxIdentityBytes = 24;
constexpr std::size_t kMaxBuildTagBytes = 16;
constexpr std::size_t kMaxErrorTextBytes = 160;
constexpr std::size_t kMaxActionParams = 4;
constexpr uint32_t kActionSchemaProvisional = 0;
constexpr uint32_t kMaxProtocolFaults = 8;

// Same numeric slot ids as session.h (kInvalid/kHost/kClient). Not included
// here so this codec stays free of the Winsock session stack.
constexpr uint32_t kInvalidPlayerId = 0;
constexpr uint32_t kHostPlayerId = 1;
constexpr uint32_t kPeerPlayerId = 2;

constexpr uint16_t kFlagMustUnderstand = 1u << 0;

constexpr uint32_t kCapabilityHeartbeat = 1u << 0;
constexpr uint32_t kCapabilityError = 1u << 1;
constexpr uint32_t kCapabilityTransform = 1u << 2;
constexpr uint32_t kCapabilityAction = 1u << 3;
constexpr uint32_t kKnownCapabilities =
    kCapabilityHeartbeat | kCapabilityError | kCapabilityTransform |
    kCapabilityAction;
// Bits 4..15 may be offered by a newer peer and are ignored.
constexpr uint32_t kOptionalFutureCapabilities = 0x0000FFF0u;
// Bits 16..31 are must-understand. An unknown bit here rejects negotiation.
constexpr uint32_t kCriticalUnknownCapabilities = 0xFFFF0000u;
constexpr uint32_t kOfferedCapabilities = kKnownCapabilities;

enum class MessageType : uint16_t {
    Hello = 1,
    HelloAck = 2,
    Heartbeat = 3,
    Disconnect = 4,
    ErrorReport = 5,
    TransformSnapshot = 6,
    ActionSnapshot = 7
};

enum class CodecStatus {
    Ok,
    NeedMoreData,
    BadMagic,
    UnsupportedVersion,
    Malformed,
    TooLarge,
    TrailingBytes,
    BadSequence,
    Stale,
    UnknownIgnored,
    MustUnderstandRejected,
    Incompatible,
    SchemaNotFrozen,
    UnexpectedMessage,
    Closed
};

enum class DisconnectReason : uint32_t {
    Unspecified = 0,
    PeerLeaving = 1,
    HostShutdown = 2,
    IdleTimeout = 3,
    VersionRejected = 4,
    ProtocolError = 5
};

enum class ErrorCode : uint32_t {
    VersionMismatch = 1,
    MalformedPacket = 2,
    UnsupportedCapability = 3,
    PayloadTooLarge = 4,
    BadIdentity = 5,
    UnexpectedMessage = 6,
    SchemaNotFrozen = 7,
    ProtocolFault = 8
};

enum class Role : uint8_t { Host, Client };

enum class Phase : uint8_t {
    Idle,
    WaitHello,
    WaitHelloAck,
    Open,
    Closed,
    Failed
};

struct PacketHeader {
    uint32_t magic = 0;
    uint16_t headerVersion = 0;
    uint16_t flags = 0;
    uint16_t messageType = 0;
    uint16_t reserved = 0;
    uint32_t sequence = 0;
    uint64_t sendTimeMs = 0;
    uint32_t payloadBytes = 0;
};

struct Hello {
    uint32_t protocolVersion = kProtocolVersion;
    uint32_t minCompatibleVersion = kProtocolVersion;
    uint32_t capabilities = kOfferedCapabilities;
    // 0 = no preference, 1 = host slot, 2 = peer slot.
    // The host keeps slot 1 regardless of this preference.
    uint32_t slotPreference = 0;
    std::string displayName;
    std::string buildTag;
};

struct HelloAck {
    uint32_t negotiatedVersion = 0;
    uint32_t acceptedCapabilities = 0;
    // Id assigned to the Hello sender. Recommended value is kPeerPlayerId.
    uint32_t assignedPeerPlayerId = 0;
    // Id of the HelloAck sender. Recommended value is kHostPlayerId.
    uint32_t hostPlayerId = 0;
    uint64_t sessionId = 0;
    uint32_t preferenceOverridden = 0;
};

struct Heartbeat {
    uint64_t senderTick = 0;
};

struct Disconnect {
    DisconnectReason reason = DisconnectReason::Unspecified;
};

struct ErrorReport {
    ErrorCode code = ErrorCode::ProtocolFault;
    uint32_t relatedSequence = 0;
    std::string text;
};

// Plain data. Not an engine transform and not a verified world pose.
// claimFlags is always 0 after a successful decode. The codec refuses to
// encode a verified-pose claim.
struct TransformSnapshot {
    uint32_t playerId = kInvalidPlayerId;
    uint32_t movementState = 0;
    uint32_t claimFlags = 0;
    float x = 0.0f;
    float y = 0.0f;
    float z = 0.0f;
    float yawDegrees = 0.0f;
    float pitchDegrees = 0.0f;
    uint64_t tick = 0;
    bool verifiedClaimStripped = false;
};

// Provisional action contract. schemaVersion must stay 0 until the
// coordinator freezes an id list with the input and lifecycle lanes.
// mayApplyToLocalInput is always false: a remote action is observation data.
struct ActionSnapshot {
    uint32_t playerId = kInvalidPlayerId;
    uint32_t actionId = 0;
    uint32_t schemaVersion = kActionSchemaProvisional;
    std::vector<float> params;
    bool mayApplyToLocalInput = false;
};

struct Message {
    PacketHeader header;
    MessageType type = MessageType::Hello;
    Hello hello;
    HelloAck helloAck;
    Heartbeat heartbeat;
    Disconnect disconnect;
    ErrorReport error;
    TransformSnapshot transform;
    ActionSnapshot action;
    bool timestampRegressed = false;
};

struct DecodeResult {
    CodecStatus status = CodecStatus::Malformed;
    std::size_t bytesConsumed = 0;
    Message message;
};

struct EncodedPacket {
    CodecStatus status = CodecStatus::Malformed;
    std::vector<uint8_t> bytes;
};

struct PacketMeta {
    uint32_t sequence = 1;
    uint64_t sendTimeMs = 0;
    uint16_t flags = 0;
};

struct NegotiateRequest {
    uint32_t protocolVersion = kProtocolVersion;
    uint32_t capabilities = kOfferedCapabilities;
};

struct NegotiateResult {
    CodecStatus status = CodecStatus::Incompatible;
    uint32_t negotiatedVersion = 0;
    uint32_t acceptedCapabilities = 0;
};

struct SlotAssignment {
    uint32_t hostPlayerId = kHostPlayerId;
    uint32_t peerPlayerId = kPeerPlayerId;
    bool preferenceOverridden = false;
};

struct ObserveResult {
    CodecStatus status = CodecStatus::Ok;
    bool timestampRegressed = false;
};

struct Step {
    CodecStatus status = CodecStatus::Ok;
    Phase phase = Phase::Idle;
    std::vector<EncodedPacket> outbound;
    bool timestampRegressed = false;
    bool verifiedClaimStripped = false;
};

// One complete packet. A short buffer returns NeedMoreData and consumes nothing.
// A declared payload above kMaxPayloadBytes returns TooLarge and consumes nothing.
// There is no byte-scan resynchronization.
DecodeResult Decode(const uint8_t* data, std::size_t size);

// Decode exactly one packet. Extra trailing bytes become TrailingBytes.
DecodeResult DecodeExact(const uint8_t* data, std::size_t size);

EncodedPacket EncodeHello(const PacketMeta& meta, const Hello& body);
EncodedPacket EncodeHelloAck(const PacketMeta& meta, const HelloAck& body);
EncodedPacket EncodeHeartbeat(const PacketMeta& meta, const Heartbeat& body);
EncodedPacket EncodeDisconnect(const PacketMeta& meta, const Disconnect& body);
EncodedPacket EncodeError(const PacketMeta& meta, const ErrorReport& body);
EncodedPacket EncodeTransform(const PacketMeta& meta,
                              const TransformSnapshot& body);
EncodedPacket EncodeAction(const PacketMeta& meta, const ActionSnapshot& body);

NegotiateResult Negotiate(const NegotiateRequest& local, const Hello& remote);
SlotAssignment AssignSlots(uint32_t slotPreference);

// Always false. Remote actions are not local input.
bool MayApplyActionToLocalInput(const ActionSnapshot& action);

const char* StatusName(CodecStatus status);
const char* PhaseName(Phase phase);
const char* MessageTypeName(MessageType type);

// Reassembles self-framed packets from arbitrary chunks. A fatal frame clears
// the buffer and sticks; the caller must drop the connection.
class FrameBuffer {
public:
    CodecStatus Append(const uint8_t* data, std::size_t size);
    DecodeResult Pop();
    bool failed() const;
    std::size_t buffered() const;

private:
    std::vector<uint8_t> buffer_;
    CodecStatus sticky_ = CodecStatus::Ok;
};

// Per-message-type sequence filter. Gaps are allowed. A sequence less than or
// equal to the last accepted sequence for that type is stale. sendTimeMs is
// informational and never overrides sequence order. Zero means unspecified.
class IngressFilter {
public:
    ObserveResult Observe(MessageType type,
                          uint32_t sequence,
                          uint64_t sendTimeMs);

private:
    uint32_t lastSequence_[8] = {};
    uint64_t lastTimeMs_[8] = {};
    bool seen_[8] = {};
};

struct SessionConfig {
    Role role = Role::Host;
    uint64_t sessionId = 0;
    uint32_t capabilities = kOfferedCapabilities;
    std::string displayName;
    std::string buildTag;
    uint32_t slotPreference = 0;
    uint64_t sendTimeMs = 0;
};

// In-memory handshake and ingress. No sockets and no engine calls.
class SessionMachine {
public:
    explicit SessionMachine(SessionConfig config);

    Step Start();
    Step HandleDatagram(const uint8_t* data, std::size_t size);
    Step Leave(DisconnectReason reason);

    void SetSendTimeMs(uint64_t sendTimeMs);

    Phase phase() const;
    Role role() const;
    uint32_t localPlayerId() const;
    uint32_t remotePlayerId() const;
    uint32_t acceptedCapabilities() const;
    uint64_t sessionId() const;
    uint64_t lastHeartbeatTick() const;
    uint32_t faultCount() const;
    const TransformSnapshot* lastTransform() const;
    const ActionSnapshot* lastAction() const;
    const std::string& lastErrorText() const;

private:
    Step MakeStep(CodecStatus status) const;
    EncodedPacket NextPacket(EncodedPacket packet);
    Step Fail(CodecStatus status, ErrorCode code, uint32_t relatedSequence,
              const std::string& text, bool sendError);
    Step AcceptOpen(CodecStatus status, bool timestampRegressed,
                    bool verifiedClaimStripped);

    SessionConfig config_;
    Phase phase_ = Phase::Idle;
    uint32_t nextSequence_ = 1;
    uint32_t localPlayerId_ = kInvalidPlayerId;
    uint32_t remotePlayerId_ = kInvalidPlayerId;
    uint32_t acceptedCapabilities_ = 0;
    uint64_t sessionId_ = 0;
    uint64_t lastHeartbeatTick_ = 0;
    uint32_t faultCount_ = 0;
    bool hasTransform_ = false;
    bool hasAction_ = false;
    TransformSnapshot lastTransform_;
    ActionSnapshot lastAction_;
    std::string lastErrorText_;
    IngressFilter ingress_;
};

}  // namespace peer
}  // namespace bfc
