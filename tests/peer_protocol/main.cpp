#include "network/peer_protocol.h"
#include "network/protocol.h"
#include "network/session.h"

#include <cmath>
#include <cstdint>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

namespace {

int g_failed = 0;
int g_passed = 0;

void Check(bool condition, const char* name) {
    if (condition) {
        ++g_passed;
        return;
    }
    ++g_failed;
    std::cerr << "FAIL " << name << "\n";
}

bfc::peer::PacketMeta Meta(uint32_t sequence, uint64_t sendTimeMs = 0) {
    bfc::peer::PacketMeta meta;
    meta.sequence = sequence;
    meta.sendTimeMs = sendTimeMs;
    return meta;
}

bfc::peer::Hello SampleHello() {
    bfc::peer::Hello hello;
    hello.protocolVersion = bfc::peer::kProtocolVersion;
    hello.minCompatibleVersion = 1;
    hello.capabilities = bfc::peer::kOfferedCapabilities;
    hello.slotPreference = bfc::peer::kHostPlayerId;
    hello.displayName = "p2";
    hello.buildTag = "dev";
    return hello;
}

bfc::peer::SessionConfig HostConfig() {
    bfc::peer::SessionConfig config;
    config.role = bfc::peer::Role::Host;
    config.sessionId = 0x4C414E4554ULL;
    config.displayName = "host";
    config.buildTag = "dev";
    config.sendTimeMs = 1000;
    return config;
}

bfc::peer::SessionConfig ClientConfig() {
    bfc::peer::SessionConfig config;
    config.role = bfc::peer::Role::Client;
    config.displayName = "p2";
    config.buildTag = "dev";
    config.slotPreference = bfc::peer::kHostPlayerId;
    config.sendTimeMs = 1000;
    return config;
}

bool SameBytes(const std::vector<uint8_t>& left,
               const std::vector<uint8_t>& right) {
    return left == right;
}

void CheckRoundTrip(const bfc::peer::EncodedPacket& packet,
                    bfc::peer::MessageType type,
                    const char* name) {
    Check(packet.status == bfc::peer::CodecStatus::Ok, name);
    if (packet.status != bfc::peer::CodecStatus::Ok) {
        return;
    }
    const bfc::peer::DecodeResult decoded =
        bfc::peer::DecodeExact(packet.bytes.data(), packet.bytes.size());
    Check(decoded.status == bfc::peer::CodecStatus::Ok, name);
    Check(decoded.bytesConsumed == packet.bytes.size(), name);
    Check(decoded.message.type == type, name);
    Check(decoded.message.header.magic == bfc::peer::kMagic, name);
    Check(decoded.message.header.headerVersion == bfc::peer::kHeaderVersion, name);
    Check(decoded.message.header.sequence == 1, name);
    Check(decoded.message.header.sendTimeMs == 1000, name);

    bfc::peer::EncodedPacket again;
    const bfc::peer::PacketMeta meta = Meta(decoded.message.header.sequence,
                                            decoded.message.header.sendTimeMs);
    switch (type) {
    case bfc::peer::MessageType::Hello:
        again = bfc::peer::EncodeHello(meta, decoded.message.hello);
        break;
    case bfc::peer::MessageType::HelloAck:
        again = bfc::peer::EncodeHelloAck(meta, decoded.message.helloAck);
        break;
    case bfc::peer::MessageType::Heartbeat:
        again = bfc::peer::EncodeHeartbeat(meta, decoded.message.heartbeat);
        break;
    case bfc::peer::MessageType::Disconnect:
        again = bfc::peer::EncodeDisconnect(meta, decoded.message.disconnect);
        break;
    case bfc::peer::MessageType::ErrorReport:
        again = bfc::peer::EncodeError(meta, decoded.message.error);
        break;
    case bfc::peer::MessageType::TransformSnapshot:
        again = bfc::peer::EncodeTransform(meta, decoded.message.transform);
        break;
    case bfc::peer::MessageType::ActionSnapshot:
        again = bfc::peer::EncodeAction(meta, decoded.message.action);
        break;
    }
    Check(again.status == bfc::peer::CodecStatus::Ok &&
              SameBytes(again.bytes, packet.bytes),
          name);
}

void TestHeaderFixture() {
    const bfc::peer::EncodedPacket packet =
        bfc::peer::EncodeHello(Meta(1, 1000), SampleHello());
    Check(packet.status == bfc::peer::CodecStatus::Ok, "hello encodes");
    if (packet.bytes.size() < bfc::peer::kHeaderBytes) {
        Check(false, "hello header size");
        return;
    }
    const uint8_t expectedPrefix[] = {
        0x42, 0x46, 0x43, 0x32, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0xE8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    bool prefix = true;
    for (std::size_t i = 0; i < sizeof(expectedPrefix); ++i) {
        if (packet.bytes[i] != expectedPrefix[i]) {
            prefix = false;
        }
    }
    Check(prefix, "hello header is little-endian BFC2");
    const uint32_t payload = static_cast<uint32_t>(packet.bytes[24]) |
                             (static_cast<uint32_t>(packet.bytes[25]) << 8) |
                             (static_cast<uint32_t>(packet.bytes[26]) << 16) |
                             (static_cast<uint32_t>(packet.bytes[27]) << 24);
    Check(payload + bfc::peer::kHeaderBytes == packet.bytes.size(),
          "payload length matches packet");
    CheckRoundTrip(packet, bfc::peer::MessageType::Hello, "hello round trip");
}

void TestAllBodiesRoundTrip() {
    bfc::peer::HelloAck ack;
    ack.negotiatedVersion = bfc::peer::kProtocolVersion;
    ack.acceptedCapabilities = bfc::peer::kCapabilityHeartbeat;
    ack.assignedPeerPlayerId = bfc::peer::kPeerPlayerId;
    ack.hostPlayerId = bfc::peer::kHostPlayerId;
    ack.sessionId = 99;
    ack.preferenceOverridden = 1;
    CheckRoundTrip(bfc::peer::EncodeHelloAck(Meta(1, 1000), ack),
                   bfc::peer::MessageType::HelloAck, "hello ack round trip");

    bfc::peer::Heartbeat heartbeat;
    heartbeat.senderTick = std::numeric_limits<uint64_t>::max();
    CheckRoundTrip(bfc::peer::EncodeHeartbeat(Meta(1, 1000), heartbeat),
                   bfc::peer::MessageType::Heartbeat, "heartbeat round trip");

    bfc::peer::Disconnect disconnect;
    disconnect.reason = bfc::peer::DisconnectReason::HostShutdown;
    CheckRoundTrip(bfc::peer::EncodeDisconnect(Meta(1, 1000), disconnect),
                   bfc::peer::MessageType::Disconnect, "disconnect round trip");

    bfc::peer::ErrorReport error;
    error.code = bfc::peer::ErrorCode::PayloadTooLarge;
    error.relatedSequence = 4;
    error.text = "bounded";
    CheckRoundTrip(bfc::peer::EncodeError(Meta(1, 1000), error),
                   bfc::peer::MessageType::ErrorReport, "error round trip");

    bfc::peer::TransformSnapshot transform;
    transform.playerId = bfc::peer::kPeerPlayerId;
    transform.movementState = 7;
    transform.x = 1.5f;
    transform.y = -2.0f;
    transform.z = 0.0f;
    transform.yawDegrees = 90.0f;
    transform.pitchDegrees = -5.0f;
    transform.tick = 42;
    CheckRoundTrip(bfc::peer::EncodeTransform(Meta(1, 1000), transform),
                   bfc::peer::MessageType::TransformSnapshot,
                   "transform round trip");

    bfc::peer::ActionSnapshot action;
    action.playerId = bfc::peer::kPeerPlayerId;
    action.actionId = 17;
    action.schemaVersion = bfc::peer::kActionSchemaProvisional;
    action.params = {1.0f, -1.0f, 0.25f, 8.0f};
    CheckRoundTrip(bfc::peer::EncodeAction(Meta(1, 1000), action),
                   bfc::peer::MessageType::ActionSnapshot, "action round trip");
    Check(bfc::peer::MayApplyActionToLocalInput(action) == false,
          "action helper never grants local input");
}

void TestRejections() {
    bfc::peer::Hello hello = SampleHello();
    hello.displayName.clear();
    Check(bfc::peer::EncodeHello(Meta(1), hello).status ==
              bfc::peer::CodecStatus::Malformed,
          "empty identity rejected");
    hello = SampleHello();
    hello.displayName = " Edward";
    Check(bfc::peer::EncodeHello(Meta(1), hello).status ==
              bfc::peer::CodecStatus::Malformed,
          "padded identity rejected");
    hello = SampleHello();
    hello.displayName.assign(bfc::peer::kMaxIdentityBytes, 'a');
    hello.buildTag.assign(bfc::peer::kMaxBuildTagBytes, 'b');
    Check(bfc::peer::EncodeHello(Meta(1), hello).status == bfc::peer::CodecStatus::Ok,
          "max identity accepted");
    hello.displayName.assign(bfc::peer::kMaxIdentityBytes + 1, 'a');
    Check(bfc::peer::EncodeHello(Meta(1), hello).status ==
              bfc::peer::CodecStatus::Malformed,
          "overlong identity rejected");

    bfc::peer::TransformSnapshot transform;
    transform.playerId = 2;
    transform.movementState = 8;
    Check(bfc::peer::EncodeTransform(Meta(1), transform).status ==
              bfc::peer::CodecStatus::Malformed,
          "unknown movement rejected");
    transform.movementState = 0;
    transform.claimFlags = 1;
    Check(bfc::peer::EncodeTransform(Meta(1), transform).status ==
              bfc::peer::CodecStatus::Malformed,
          "verified pose claim cannot be encoded");
    transform.claimFlags = 0;
    transform.x = std::numeric_limits<float>::quiet_NaN();
    Check(bfc::peer::EncodeTransform(Meta(1), transform).status ==
              bfc::peer::CodecStatus::Malformed,
          "non-finite transform rejected");

    bfc::peer::ActionSnapshot action;
    action.playerId = 2;
    action.actionId = 1;
    action.schemaVersion = 1;
    Check(bfc::peer::EncodeAction(Meta(1), action).status ==
              bfc::peer::CodecStatus::SchemaNotFrozen,
          "non-provisional action schema cannot be encoded");
    action.schemaVersion = 0;
    action.params.assign(bfc::peer::kMaxActionParams + 1, 1.0f);
    Check(bfc::peer::EncodeAction(Meta(1), action).status ==
              bfc::peer::CodecStatus::Malformed,
          "too many action params rejected");

    bfc::peer::ErrorReport error;
    error.code = bfc::peer::ErrorCode::ProtocolFault;
    error.text.assign(bfc::peer::kMaxErrorTextBytes, 'e');
    Check(bfc::peer::EncodeError(Meta(1), error).status == bfc::peer::CodecStatus::Ok,
          "max error text accepted");
    error.text.push_back('e');
    Check(bfc::peer::EncodeError(Meta(1), error).status ==
              bfc::peer::CodecStatus::TooLarge,
          "error text is bounded");
    error.text = "bad\n";
    Check(bfc::peer::EncodeError(Meta(1), error).status ==
              bfc::peer::CodecStatus::Malformed,
          "error text must be printable");

    Check(bfc::peer::EncodeHeartbeat(Meta(0), {}).status ==
              bfc::peer::CodecStatus::BadSequence,
          "sequence 0 rejected on encode");
}

void TestMalformedCorpus() {
    const bfc::peer::EncodedPacket hello =
        bfc::peer::EncodeHello(Meta(1, 1000), SampleHello());
    Check(bfc::peer::Decode(nullptr, 0).status == bfc::peer::CodecStatus::NeedMoreData,
          "empty buffer needs more data");
    Check(bfc::peer::Decode(nullptr, 4).status == bfc::peer::CodecStatus::Malformed,
          "null payload is malformed");
    Check(bfc::peer::Decode(hello.bytes.data(), 27).status ==
              bfc::peer::CodecStatus::NeedMoreData,
          "short header needs more data");

    std::vector<uint8_t> v1 = hello.bytes;
    v1[3] = 0x31;
    Check(bfc::peer::Decode(v1.data(), v1.size()).status ==
              bfc::peer::CodecStatus::BadMagic,
          "v1 BFC1 magic is not a v2 packet");

    std::vector<uint8_t> version = hello.bytes;
    version[4] = 1;
    Check(bfc::peer::Decode(version.data(), version.size()).status ==
              bfc::peer::CodecStatus::UnsupportedVersion,
          "header version 1 is unsupported");
    version[4] = 3;
    Check(bfc::peer::Decode(version.data(), version.size()).status ==
              bfc::peer::CodecStatus::UnsupportedVersion,
          "header version 3 is unsupported");

    std::vector<uint8_t> reserved = hello.bytes;
    reserved[10] = 1;
    Check(bfc::peer::Decode(reserved.data(), reserved.size()).status ==
              bfc::peer::CodecStatus::Malformed,
          "reserved header field must be zero");

    std::vector<uint8_t> flags = hello.bytes;
    flags[6] = 0x02;
    Check(bfc::peer::Decode(flags.data(), flags.size()).status ==
              bfc::peer::CodecStatus::Malformed,
          "unknown header flag is rejected");

    std::vector<uint8_t> sequence = hello.bytes;
    sequence[12] = 0;
    Check(bfc::peer::Decode(sequence.data(), sequence.size()).status ==
              bfc::peer::CodecStatus::BadSequence,
          "sequence 0 is rejected");

    std::vector<uint8_t> huge(bfc::peer::kHeaderBytes, 0);
    huge[0] = 0x42;
    huge[1] = 0x46;
    huge[2] = 0x43;
    huge[3] = 0x32;
    huge[4] = 2;
    huge[8] = 3;
    huge[12] = 1;
    huge[27] = 1;
    const bfc::peer::DecodeResult hugeDecoded =
        bfc::peer::Decode(huge.data(), huge.size());
    Check(hugeDecoded.status == bfc::peer::CodecStatus::TooLarge &&
              hugeDecoded.bytesConsumed == 0,
          "16MiB-style length is too large and is not buffered");

    bfc::peer::Heartbeat heartbeat;
    heartbeat.senderTick = 9;
    std::vector<uint8_t> trailing =
        bfc::peer::EncodeHeartbeat(Meta(1), heartbeat).bytes;
    trailing.push_back(0xAB);
    Check(bfc::peer::DecodeExact(trailing.data(), trailing.size()).status ==
              bfc::peer::CodecStatus::TrailingBytes,
          "trailing byte after one packet is rejected");

    std::vector<uint8_t> type8 =
        bfc::peer::EncodeHeartbeat(Meta(4, 50), heartbeat).bytes;
    type8[8] = 8;
    type8[9] = 0;
    const bfc::peer::DecodeResult ignored =
        bfc::peer::DecodeExact(type8.data(), type8.size());
    Check(ignored.status == bfc::peer::CodecStatus::UnknownIgnored &&
              ignored.message.heartbeat.senderTick == 0,
          "v2 type 8 is ignored and is not a v1 heartbeat");

    type8[6] = static_cast<uint8_t>(bfc::peer::kFlagMustUnderstand);
    Check(bfc::peer::DecodeExact(type8.data(), type8.size()).status ==
              bfc::peer::CodecStatus::MustUnderstandRejected,
          "unknown must-understand type is rejected");

    bfc::peer::TransformSnapshot transform;
    transform.playerId = 2;
    transform.x = 3.0f;
    std::vector<uint8_t> claimed =
        bfc::peer::EncodeTransform(Meta(1), transform).bytes;
    claimed[bfc::peer::kHeaderBytes + 8] = 1;
    const bfc::peer::DecodeResult stripped =
        bfc::peer::DecodeExact(claimed.data(), claimed.size());
    Check(stripped.status == bfc::peer::CodecStatus::Ok &&
              stripped.message.transform.verifiedClaimStripped &&
              stripped.message.transform.claimFlags == 0 &&
              stripped.message.transform.x == 3.0f,
          "verified pose bit is stripped and never stored");

    claimed[bfc::peer::kHeaderBytes + 8] = 2;
    Check(bfc::peer::DecodeExact(claimed.data(), claimed.size()).status ==
              bfc::peer::CodecStatus::Malformed,
          "unknown pose claim bit is malformed");

    std::vector<uint8_t> nonFinite = bfc::peer::EncodeTransform(Meta(1), transform).bytes;
    const std::size_t xOffset = bfc::peer::kHeaderBytes + 12;
    nonFinite[xOffset] = 0x00;
    nonFinite[xOffset + 1] = 0x00;
    nonFinite[xOffset + 2] = 0xC0;
    nonFinite[xOffset + 3] = 0x7F;
    Check(bfc::peer::DecodeExact(nonFinite.data(), nonFinite.size()).status ==
              bfc::peer::CodecStatus::Malformed,
          "NaN payload is malformed");

    bfc::peer::ActionSnapshot action;
    action.playerId = 2;
    action.actionId = 3;
    std::vector<uint8_t> schema =
        bfc::peer::EncodeAction(Meta(2), action).bytes;
    schema[bfc::peer::kHeaderBytes + 8] = 1;
    const bfc::peer::DecodeResult frozen =
        bfc::peer::DecodeExact(schema.data(), schema.size());
    Check(frozen.status == bfc::peer::CodecStatus::SchemaNotFrozen &&
              frozen.message.action.mayApplyToLocalInput == false,
          "schemaVersion 1 is not frozen and cannot drive input");
}

void TestNegotiationAndSlots() {
    bfc::peer::NegotiateRequest local;
    bfc::peer::Hello hello = SampleHello();
    bfc::peer::NegotiateResult result = bfc::peer::Negotiate(local, hello);
    Check(result.status == bfc::peer::CodecStatus::Ok &&
              result.negotiatedVersion == 2 &&
              result.acceptedCapabilities == bfc::peer::kKnownCapabilities,
          "matching hello negotiates version 2");

    hello.protocolVersion = 4;
    hello.minCompatibleVersion = 2;
    result = bfc::peer::Negotiate(local, hello);
    Check(result.status == bfc::peer::CodecStatus::Ok &&
              result.negotiatedVersion == 2,
          "newer peer with min 2 negotiates down to 2");

    hello.minCompatibleVersion = 4;
    result = bfc::peer::Negotiate(local, hello);
    Check(result.status == bfc::peer::CodecStatus::Incompatible,
          "min version above ours is incompatible");

    hello = SampleHello();
    hello.protocolVersion = 1;
    hello.minCompatibleVersion = 1;
    Check(bfc::peer::Negotiate(local, hello).status ==
              bfc::peer::CodecStatus::Incompatible,
          "older protocol version is incompatible");

    hello = SampleHello();
    hello.capabilities = bfc::peer::kCapabilityHeartbeat | (1u << 4);
    result = bfc::peer::Negotiate(local, hello);
    Check(result.status == bfc::peer::CodecStatus::Ok &&
              result.acceptedCapabilities == bfc::peer::kCapabilityHeartbeat,
          "optional future capability bits are ignored");

    hello.capabilities = bfc::peer::kCapabilityHeartbeat | (1u << 16);
    Check(bfc::peer::Negotiate(local, hello).status ==
              bfc::peer::CodecStatus::Incompatible,
          "critical unknown capability is rejected");

    hello.capabilities = bfc::peer::kCapabilityTransform;
    Check(bfc::peer::Negotiate(local, hello).status ==
              bfc::peer::CodecStatus::Incompatible,
          "heartbeat capability is mandatory");

    const bfc::peer::SlotAssignment overridden =
        bfc::peer::AssignSlots(bfc::peer::kHostPlayerId);
    Check(overridden.hostPlayerId == 1 && overridden.peerPlayerId == 2 &&
              overridden.preferenceOverridden,
          "remote cannot take the host slot");
    const bfc::peer::SlotAssignment peerSlot =
        bfc::peer::AssignSlots(bfc::peer::kPeerPlayerId);
    Check(peerSlot.hostPlayerId == 1 && peerSlot.peerPlayerId == 2 &&
              !peerSlot.preferenceOverridden,
          "peer slot preference keeps host on slot 1");
}

void TestIngress() {
    bfc::peer::IngressFilter filter;
    bfc::peer::ObserveResult observed = filter.Observe(
        bfc::peer::MessageType::TransformSnapshot, 1, 100);
    Check(observed.status == bfc::peer::CodecStatus::Ok &&
              !observed.timestampRegressed,
          "first sequence is fresh");
    observed = filter.Observe(bfc::peer::MessageType::TransformSnapshot, 5, 50);
    Check(observed.status == bfc::peer::CodecStatus::Ok &&
              observed.timestampRegressed,
          "sequence gap is allowed and a backward timestamp is only a flag");
    observed = filter.Observe(bfc::peer::MessageType::TransformSnapshot, 4, 200);
    Check(observed.status == bfc::peer::CodecStatus::Stale,
          "older sequence is stale");
    observed = filter.Observe(bfc::peer::MessageType::TransformSnapshot, 5, 300);
    Check(observed.status == bfc::peer::CodecStatus::Stale,
          "duplicate sequence is stale");
    observed = filter.Observe(bfc::peer::MessageType::Heartbeat, 1, 0);
    Check(observed.status == bfc::peer::CodecStatus::Ok,
          "heartbeat sequence space is independent");
    observed = filter.Observe(bfc::peer::MessageType::TransformSnapshot, 6, 0);
    Check(observed.status == bfc::peer::CodecStatus::Ok &&
              !observed.timestampRegressed,
          "unspecified timestamp does not move the baseline");
    observed = filter.Observe(bfc::peer::MessageType::TransformSnapshot, 7, 40);
    Check(observed.timestampRegressed, "later time still compares with the last real timestamp");
    observed = filter.Observe(static_cast<bfc::peer::MessageType>(0), 1, 0);
    Check(observed.status == bfc::peer::CodecStatus::BadSequence,
          "type 0 is not a sequence space");
}

void TestFrameBuffer() {
    bfc::peer::Heartbeat first;
    first.senderTick = 1;
    bfc::peer::Heartbeat second;
    second.senderTick = 2;
    const std::vector<uint8_t> a = bfc::peer::EncodeHeartbeat(Meta(1), first).bytes;
    const std::vector<uint8_t> b = bfc::peer::EncodeHeartbeat(Meta(2), second).bytes;
    std::vector<uint8_t> both = a;
    both.insert(both.end(), b.begin(), b.end());

    bfc::peer::FrameBuffer stream;
    for (uint8_t byte : both) {
        Check(stream.Append(&byte, 1) == bfc::peer::CodecStatus::Ok,
              "byte append stays open");
    }
    const bfc::peer::DecodeResult one = stream.Pop();
    const bfc::peer::DecodeResult two = stream.Pop();
    Check(one.status == bfc::peer::CodecStatus::Ok &&
              one.message.heartbeat.senderTick == 1,
          "first framed heartbeat");
    Check(two.status == bfc::peer::CodecStatus::Ok &&
              two.message.heartbeat.senderTick == 2,
          "second framed heartbeat");
    Check(stream.Pop().status == bfc::peer::CodecStatus::NeedMoreData &&
              stream.buffered() == 0,
          "frame buffer drains");

    std::vector<uint8_t> huge(bfc::peer::kHeaderBytes, 0);
    huge[0] = 0x42;
    huge[1] = 0x46;
    huge[2] = 0x43;
    huge[3] = 0x32;
    huge[4] = 2;
    huge[8] = 3;
    huge[12] = 1;
    huge[27] = 1;
    bfc::peer::FrameBuffer fatal;
    Check(fatal.Append(huge.data(), huge.size()) == bfc::peer::CodecStatus::TooLarge &&
              fatal.failed(),
          "illegal length fails the frame buffer");
    Check(fatal.Append(a.data(), a.size()) == bfc::peer::CodecStatus::TooLarge,
          "failed frame buffer stays failed");
}

void TestSession() {
    bfc::peer::SessionMachine host(HostConfig());
    bfc::peer::SessionMachine client(ClientConfig());
    const bfc::peer::Step hostStart = host.Start();
    const bfc::peer::Step clientStart = client.Start();
    Check(hostStart.status == bfc::peer::CodecStatus::Ok &&
              host.phase() == bfc::peer::Phase::WaitHello &&
              host.localPlayerId() == bfc::peer::kHostPlayerId,
          "host waits for hello on slot 1");
    Check(clientStart.status == bfc::peer::CodecStatus::Ok &&
              clientStart.outbound.size() == 1 &&
              client.phase() == bfc::peer::Phase::WaitHelloAck,
          "client emits hello");
    Check(host.Start().status == bfc::peer::CodecStatus::UnexpectedMessage,
          "start is not repeatable");

    const bfc::peer::Step hostHello =
        host.HandleDatagram(clientStart.outbound[0].bytes.data(),
                            clientStart.outbound[0].bytes.size());
    Check(hostHello.status == bfc::peer::CodecStatus::Ok &&
              host.phase() == bfc::peer::Phase::Open &&
              host.localPlayerId() == 1 && host.remotePlayerId() == 2 &&
              hostHello.outbound.size() == 1,
          "host keeps slot 1 and assigns slot 2");
    const bfc::peer::DecodeResult ack = bfc::peer::DecodeExact(
        hostHello.outbound[0].bytes.data(), hostHello.outbound[0].bytes.size());
    Check(ack.status == bfc::peer::CodecStatus::Ok &&
              ack.message.helloAck.assignedPeerPlayerId == 2 &&
              ack.message.helloAck.hostPlayerId == 1 &&
              ack.message.helloAck.preferenceOverridden == 1 &&
              ack.message.helloAck.negotiatedVersion == 2 &&
              ack.message.helloAck.sessionId == host.sessionId(),
          "hello ack records the overridden slot preference");

    const bfc::peer::Step clientAck =
        client.HandleDatagram(hostHello.outbound[0].bytes.data(),
                              hostHello.outbound[0].bytes.size());
    Check(clientAck.status == bfc::peer::CodecStatus::Ok &&
              client.phase() == bfc::peer::Phase::Open &&
              client.localPlayerId() == 2 && client.remotePlayerId() == 1 &&
              client.sessionId() == host.sessionId(),
          "client accepts slot 2");

    bfc::peer::Heartbeat heartbeat;
    heartbeat.senderTick = 10;
    const std::vector<uint8_t> beat =
        bfc::peer::EncodeHeartbeat(Meta(1, 5000), heartbeat).bytes;
    Check(host.HandleDatagram(beat.data(), beat.size()).status ==
                  bfc::peer::CodecStatus::Ok &&
              host.lastHeartbeatTick() == 10,
          "fresh heartbeat updates liveness");
    heartbeat.senderTick = 99;
    const std::vector<uint8_t> staleBeat =
        bfc::peer::EncodeHeartbeat(Meta(1, 9000), heartbeat).bytes;
    Check(host.HandleDatagram(staleBeat.data(), staleBeat.size()).status ==
                  bfc::peer::CodecStatus::Stale &&
              host.lastHeartbeatTick() == 10 &&
              host.phase() == bfc::peer::Phase::Open,
          "stale heartbeat does not refresh liveness");

    bfc::peer::TransformSnapshot transform;
    transform.playerId = 2;
    transform.x = 1.0f;
    transform.tick = 1;
    std::vector<uint8_t> pose =
        bfc::peer::EncodeTransform(Meta(1, 100), transform).bytes;
    pose[bfc::peer::kHeaderBytes + 8] = 1;
    const bfc::peer::Step posed = host.HandleDatagram(pose.data(), pose.size());
    Check(posed.status == bfc::peer::CodecStatus::Ok && posed.verifiedClaimStripped &&
              host.lastTransform() != nullptr && host.lastTransform()->x == 1.0f &&
              host.lastTransform()->claimFlags == 0,
          "remote transform is stored without a verified pose claim");
    transform.x = 8.0f;
    const std::vector<uint8_t> stalePose =
        bfc::peer::EncodeTransform(Meta(1, 50), transform).bytes;
    Check(host.HandleDatagram(stalePose.data(), stalePose.size()).status ==
                  bfc::peer::CodecStatus::Stale &&
              host.lastTransform()->x == 1.0f,
          "stale transform does not replace the snapshot");
    transform.x = 4.0f;
    transform.tick = 5;
    const std::vector<uint8_t> nextPose =
        bfc::peer::EncodeTransform(Meta(5, 40), transform).bytes;
    const bfc::peer::Step regressed =
        host.HandleDatagram(nextPose.data(), nextPose.size());
    Check(regressed.status == bfc::peer::CodecStatus::Ok &&
              regressed.timestampRegressed && host.lastTransform()->x == 4.0f,
          "a newer sequence applies even when the timestamp moves backward");

    bfc::peer::ActionSnapshot action;
    action.playerId = 2;
    action.actionId = 9;
    action.mayApplyToLocalInput = true;
    const std::vector<uint8_t> act =
        bfc::peer::EncodeAction(Meta(1), action).bytes;
    const bfc::peer::Step applied = host.HandleDatagram(act.data(), act.size());
    Check(applied.status == bfc::peer::CodecStatus::Ok &&
              host.lastAction() != nullptr &&
              host.lastAction()->mayApplyToLocalInput == false &&
              bfc::peer::MayApplyActionToLocalInput(*host.lastAction()) == false,
          "remote action cannot apply to local input");

    std::vector<uint8_t> frozen = act;
    frozen[bfc::peer::kHeaderBytes + 8] = 1;
    frozen[12] = 2;
    const bfc::peer::Step schema = host.HandleDatagram(frozen.data(), frozen.size());
    Check(schema.status == bfc::peer::CodecStatus::SchemaNotFrozen &&
              host.phase() == bfc::peer::Phase::Open &&
              schema.outbound.size() == 1 && host.lastAction()->actionId == 9,
          "unfrozen schema is reported and not applied");

    std::vector<uint8_t> unknown = beat;
    unknown[8] = 9;
    unknown[9] = 0;
    Check(host.HandleDatagram(unknown.data(), unknown.size()).status ==
                  bfc::peer::CodecStatus::UnknownIgnored &&
              host.phase() == bfc::peer::Phase::Open &&
              host.lastHeartbeatTick() == 10,
          "an unknown type does not change the open session");

    const std::vector<uint8_t> replay = clientStart.outbound[0].bytes;
    Check(host.HandleDatagram(replay.data(), replay.size()).status ==
                  bfc::peer::CodecStatus::UnexpectedMessage &&
              host.phase() == bfc::peer::Phase::Failed,
          "handshake replay fails the open session");
}

void TestBoundsAndFaults() {
    bfc::peer::SessionMachine host(HostConfig());
    Check(host.Start().status == bfc::peer::CodecStatus::Ok, "host starts");

    bfc::peer::Hello hello = SampleHello();
    hello.capabilities = bfc::peer::kCapabilityHeartbeat | (1u << 31);
    const std::vector<uint8_t> critical =
        bfc::peer::EncodeHello(Meta(1), hello).bytes;
    const bfc::peer::Step rejected = host.HandleDatagram(critical.data(), critical.size());
    Check(rejected.status == bfc::peer::CodecStatus::Incompatible &&
              host.phase() == bfc::peer::Phase::Failed &&
              rejected.outbound.size() == 1,
          "critical capability fails negotiation with an error packet");
    if (rejected.outbound.size() == 1) {
        const bfc::peer::DecodeResult error = bfc::peer::DecodeExact(
            rejected.outbound[0].bytes.data(), rejected.outbound[0].bytes.size());
        Check(error.status == bfc::peer::CodecStatus::Ok &&
                  error.message.error.code == bfc::peer::ErrorCode::VersionMismatch,
              "negotiation failure uses the version mismatch code");
    }

    bfc::peer::SessionConfig config = HostConfig();
    config.capabilities = bfc::peer::kCapabilityHeartbeat;

    bfc::peer::SessionMachine limited(config);
    limited.Start();
    hello.capabilities = bfc::peer::kCapabilityHeartbeat;
    hello.slotPreference = 0;
    const std::vector<uint8_t> plain =
        bfc::peer::EncodeHello(Meta(1), hello).bytes;
    Check(limited.HandleDatagram(plain.data(), plain.size()).status ==
              bfc::peer::CodecStatus::Ok,
          "heartbeat-only session opens");

    bfc::peer::TransformSnapshot transform;
    transform.playerId = 2;
    const std::vector<uint8_t> pose =
        bfc::peer::EncodeTransform(Meta(1), transform).bytes;
    for (uint32_t i = 1; i < bfc::peer::kMaxProtocolFaults; ++i) {
        const bfc::peer::Step step = limited.HandleDatagram(pose.data(), pose.size());
        Check(step.status == bfc::peer::CodecStatus::UnexpectedMessage &&
                  limited.phase() == bfc::peer::Phase::Open,
              "unnegotiated transform stays bounded");
    }
    Check(limited.HandleDatagram(pose.data(), pose.size()).status ==
                  bfc::peer::CodecStatus::UnexpectedMessage &&
              limited.phase() == bfc::peer::Phase::Failed,
          "fault budget closes the session");

    bfc::peer::SessionMachine errors(HostConfig());
    errors.Start();
    const std::vector<uint8_t> openHello =
        bfc::peer::EncodeHello(Meta(1), SampleHello()).bytes;
    Check(errors.HandleDatagram(openHello.data(), openHello.size()).status ==
              bfc::peer::CodecStatus::Ok,
          "error-budget host opens");
    bfc::peer::ErrorReport report;
    report.code = bfc::peer::ErrorCode::ProtocolFault;
    report.text = "nope";
    const std::vector<uint8_t> err =
        bfc::peer::EncodeError(Meta(1), report).bytes;
    for (uint32_t i = 1; i < bfc::peer::kMaxProtocolFaults; ++i) {
        Check(errors.HandleDatagram(err.data(), err.size()).status ==
                      bfc::peer::CodecStatus::Ok &&
                  errors.phase() == bfc::peer::Phase::Open,
              "error reports stay bounded");
    }
    Check(errors.HandleDatagram(err.data(), err.size()).status ==
                  bfc::peer::CodecStatus::Incompatible &&
              errors.phase() == bfc::peer::Phase::Failed &&
              errors.lastErrorText() == "nope",
          "the eighth error fails the session");

    bfc::peer::SessionMachine leaving(HostConfig());
    leaving.Start();
    bfc::peer::Disconnect disconnect;
    disconnect.reason = bfc::peer::DisconnectReason::PeerLeaving;
    const std::vector<uint8_t> bye =
        bfc::peer::EncodeDisconnect(Meta(1), disconnect).bytes;
    Check(leaving.HandleDatagram(bye.data(), bye.size()).status ==
                  bfc::peer::CodecStatus::Closed &&
              leaving.phase() == bfc::peer::Phase::Closed &&
              leaving.faultCount() == 0,
          "disconnect before hello closes cleanly");
    Check(leaving.HandleDatagram(bye.data(), bye.size()).status ==
              bfc::peer::CodecStatus::Closed,
          "packets after close are ignored");

    bfc::peer::SessionMachine client(ClientConfig());
    const bfc::peer::Step started = client.Start();
    const bfc::peer::Step left = client.Leave(bfc::peer::DisconnectReason::PeerLeaving);
    Check(left.status == bfc::peer::CodecStatus::Closed && left.outbound.size() == 1 &&
              client.phase() == bfc::peer::Phase::Closed,
          "leave emits one disconnect");
    const bfc::peer::DecodeResult decoded = bfc::peer::DecodeExact(
        left.outbound[0].bytes.data(), left.outbound[0].bytes.size());
    Check(decoded.status == bfc::peer::CodecStatus::Ok &&
              decoded.message.disconnect.reason ==
                  bfc::peer::DisconnectReason::PeerLeaving,
          "leave reason is peer leaving");
    Check(client.Leave(bfc::peer::DisconnectReason::PeerLeaving).outbound.empty(),
          "second leave is idempotent");
    (void)started;

    bfc::peer::SessionConfig bad = HostConfig();
    bad.sessionId = 0;
    bfc::peer::SessionMachine noSession(bad);
    Check(noSession.Start().status == bfc::peer::CodecStatus::Malformed &&
              noSession.phase() == bfc::peer::Phase::Failed,
          "host without a session id fails closed");

    std::vector<uint8_t> partial = openHello;
    partial.resize(10);
    bfc::peer::SessionMachine waiting(HostConfig());
    waiting.Start();
    Check(waiting.HandleDatagram(partial.data(), partial.size()).status ==
                  bfc::peer::CodecStatus::NeedMoreData &&
              waiting.phase() == bfc::peer::Phase::WaitHello,
          "a short datagram does not change phase");

    std::vector<uint8_t> required = bye;
    required[8] = 99;
    required[9] = 0;
    required[6] = static_cast<uint8_t>(bfc::peer::kFlagMustUnderstand);
    const bfc::peer::Step forced =
        waiting.HandleDatagram(required.data(), required.size());
    Check(forced.status == bfc::peer::CodecStatus::MustUnderstandRejected &&
              waiting.phase() == bfc::peer::Phase::Failed &&
              !forced.outbound.empty(),
          "a must-understand unknown type fails the handshake");
}

void TestFuzz() {
    const std::vector<std::vector<uint8_t>> corpus = {
        bfc::peer::EncodeHello(Meta(1, 1000), SampleHello()).bytes,
        bfc::peer::EncodeHeartbeat(Meta(3, 20), bfc::peer::Heartbeat{7}).bytes,
        bfc::peer::EncodeTransform(
            Meta(2, 20),
            bfc::peer::TransformSnapshot{2, 1, 0, 1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6,
                                         false})
            .bytes,
        bfc::peer::EncodeAction(Meta(2, 20),
                                bfc::peer::ActionSnapshot{2, 4, 0, {1.0f}, false})
            .bytes};
    uint32_t seed = 0xBFC2u;
    for (int n = 0; n < 256; ++n) {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        if (seed == 0) {
            seed = 1;
        }
        for (const std::vector<uint8_t>& original : corpus) {
            std::vector<uint8_t> bytes = original;
            const int ops = static_cast<int>(seed % 8u) + 1;
            for (int op = 0; op < ops; ++op) {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                if (bytes.empty()) {
                    bytes.push_back(static_cast<uint8_t>(seed));
                    continue;
                }
                const std::size_t index = static_cast<std::size_t>(seed) % bytes.size();
                switch (seed % 5u) {
                case 0:
                    bytes[index] = static_cast<uint8_t>(bytes[index] ^ (1u << (seed & 7u)));
                    break;
                case 1:
                    bytes[index] = static_cast<uint8_t>(seed >> 8);
                    break;
                case 2:
                    bytes.resize(index);
                    break;
                case 3:
                    bytes.push_back(static_cast<uint8_t>(seed));
                    break;
                default:
                    bytes[index] = bytes[(index + 1) % bytes.size()];
                    break;
                }
            }
            const bfc::peer::DecodeResult decoded =
                bfc::peer::Decode(bytes.empty() ? nullptr : bytes.data(), bytes.size());
            const bool consumedOk = decoded.bytesConsumed <= bytes.size();
            const bool needMoreClean =
                decoded.status != bfc::peer::CodecStatus::NeedMoreData ||
                decoded.bytesConsumed == 0;
            const bool poseSafe =
                decoded.status != bfc::peer::CodecStatus::Ok ||
                decoded.message.type != bfc::peer::MessageType::TransformSnapshot ||
                decoded.message.transform.claimFlags == 0;
            const bool inputSafe =
                decoded.status != bfc::peer::CodecStatus::Ok ||
                decoded.message.type != bfc::peer::MessageType::ActionSnapshot ||
                decoded.message.action.mayApplyToLocalInput == false;
            Check(consumedOk && needMoreClean && poseSafe && inputSafe,
                  "fuzz decode stays inside the buffer");

            bfc::peer::FrameBuffer buffer;
            if (!bytes.empty()) {
                (void)buffer.Append(bytes.data(), bytes.size());
                (void)buffer.Pop();
            }
        }
    }
}

}  // namespace

static_assert(bfc::kInvalidPlayerId == bfc::peer::kInvalidPlayerId,
              "peer slot 0 must match the v1 invalid player id");
static_assert(bfc::kHostPlayerId == bfc::peer::kHostPlayerId,
              "peer slot 1 must match the v1 host player id");
static_assert(bfc::kClientPlayerId == bfc::peer::kPeerPlayerId,
              "peer slot 2 must match the v1 client player id");
static_assert(bfc::kMovementStateUnknown == 0, "movement 0 stays unknown");
static_assert(bfc::kMovementStateSailing == 7, "movement 7 stays sailing");
static_assert(bfc::kProtocolMagic == 0x31434642u, "v1 magic stays BFC1");
static_assert(bfc::peer::kMagic != bfc::kProtocolMagic,
              "v2 magic must not alias v1");

int main() {
    TestHeaderFixture();
    TestAllBodiesRoundTrip();
    TestRejections();
    TestMalformedCorpus();
    TestNegotiationAndSlots();
    TestIngress();
    TestFrameBuffer();
    TestSession();
    TestBoundsAndFaults();
    TestFuzz();

    if (g_failed != 0) {
        std::cerr << g_failed << " failed, " << g_passed << " passed\n";
        return 1;
    }
    std::cout << "PeerProtocolCodec PASS " << g_passed << "\n";
    return 0;
}
