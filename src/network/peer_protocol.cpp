#include "network/peer_protocol.h"

#include <cmath>
#include <cstring>
#include <limits>
#include <string_view>
#include <utility>

namespace bfc {
namespace peer {
namespace {

void WriteU16(std::vector<uint8_t>& out, uint16_t value) {
    out.push_back(static_cast<uint8_t>(value & 0xFFu));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xFFu));
}

void WriteU32(std::vector<uint8_t>& out, uint32_t value) {
    out.push_back(static_cast<uint8_t>(value & 0xFFu));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xFFu));
    out.push_back(static_cast<uint8_t>((value >> 16) & 0xFFu));
    out.push_back(static_cast<uint8_t>((value >> 24) & 0xFFu));
}

void WriteU64(std::vector<uint8_t>& out, uint64_t value) {
    for (int shift = 0; shift < 64; shift += 8) {
        out.push_back(static_cast<uint8_t>((value >> shift) & 0xFFu));
    }
}

uint16_t ReadU16(const uint8_t* data) {
    return static_cast<uint16_t>(data[0] |
                                 (static_cast<uint16_t>(data[1]) << 8));
}

uint32_t ReadU32(const uint8_t* data) {
    return static_cast<uint32_t>(data[0]) |
           (static_cast<uint32_t>(data[1]) << 8) |
           (static_cast<uint32_t>(data[2]) << 16) |
           (static_cast<uint32_t>(data[3]) << 24);
}

uint64_t ReadU64(const uint8_t* data) {
    uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
        value |= static_cast<uint64_t>(data[i]) << (8 * i);
    }
    return value;
}

bool HostIsLittleEndian() {
    const uint16_t value = 1;
    uint8_t bytes[2] = {};
    std::memcpy(bytes, &value, sizeof(value));
    return bytes[0] == 1;
}

bool WriteF32(std::vector<uint8_t>& out, float value) {
    if (!std::isfinite(value)) {
        return false;
    }
    static_assert(sizeof(float) == 4, "IEEE754 binary32 required");
    uint8_t bytes[4] = {};
    std::memcpy(bytes, &value, sizeof(bytes));
    if (!HostIsLittleEndian()) {
        std::swap(bytes[0], bytes[3]);
        std::swap(bytes[1], bytes[2]);
    }
    out.insert(out.end(), bytes, bytes + 4);
    return true;
}

bool ReadF32(const uint8_t* data, float& out) {
    uint8_t bytes[4] = {data[0], data[1], data[2], data[3]};
    if (!HostIsLittleEndian()) {
        std::swap(bytes[0], bytes[3]);
        std::swap(bytes[1], bytes[2]);
    }
    std::memcpy(&out, bytes, sizeof(out));
    return std::isfinite(out);
}

bool IsPrintableAscii(std::string_view text) {
    for (unsigned char ch : text) {
        if (ch < 0x20u || ch > 0x7Eu) {
            return false;
        }
    }
    return true;
}

bool IsValidToken(std::string_view text, std::size_t minLen, std::size_t maxLen) {
    if (text.size() < minLen || text.size() > maxLen) {
        return false;
    }
    if (!IsPrintableAscii(text)) {
        return false;
    }
    if (!text.empty() && (text.front() == ' ' || text.back() == ' ')) {
        return false;
    }
    return true;
}

class Reader {
public:
    Reader(const uint8_t* data, std::size_t size) : cursor_(data), end_(data + size) {}

    bool ok() const { return ok_; }
    std::size_t remaining() const {
        return cursor_ <= end_ ? static_cast<std::size_t>(end_ - cursor_) : 0;
    }

    uint8_t U8() {
        if (remaining() < 1) {
            ok_ = false;
            return 0;
        }
        return *cursor_++;
    }

    uint16_t U16() {
        if (remaining() < 2) {
            ok_ = false;
            return 0;
        }
        const uint16_t value = ReadU16(cursor_);
        cursor_ += 2;
        return value;
    }

    uint32_t U32() {
        if (remaining() < 4) {
            ok_ = false;
            return 0;
        }
        const uint32_t value = ReadU32(cursor_);
        cursor_ += 4;
        return value;
    }

    uint64_t U64() {
        if (remaining() < 8) {
            ok_ = false;
            return 0;
        }
        const uint64_t value = ReadU64(cursor_);
        cursor_ += 8;
        return value;
    }

    bool F32(float& out) {
        if (remaining() < 4) {
            ok_ = false;
            out = 0.0f;
            return false;
        }
        const bool finite = ReadF32(cursor_, out);
        cursor_ += 4;
        if (!finite) {
            ok_ = false;
        }
        return finite;
    }

    bool Bytes(std::size_t size, std::string& out) {
        if (remaining() < size) {
            ok_ = false;
            return false;
        }
        out.assign(reinterpret_cast<const char*>(cursor_), size);
        cursor_ += size;
        return true;
    }

private:
    const uint8_t* cursor_ = nullptr;
    const uint8_t* end_ = nullptr;
    bool ok_ = true;
};

CodecStatus ReadHeader(const uint8_t* data, PacketHeader& header) {
    header.magic = ReadU32(data);
    if (header.magic != kMagic) {
        return CodecStatus::BadMagic;
    }
    header.headerVersion = ReadU16(data + 4);
    header.flags = ReadU16(data + 6);
    header.messageType = ReadU16(data + 8);
    header.reserved = ReadU16(data + 10);
    header.sequence = ReadU32(data + 12);
    header.sendTimeMs = ReadU64(data + 16);
    header.payloadBytes = ReadU32(data + 24);
    if (header.headerVersion != kHeaderVersion) {
        return CodecStatus::UnsupportedVersion;
    }
    if (header.reserved != 0 ||
        (header.flags & static_cast<uint16_t>(~kFlagMustUnderstand)) != 0 ||
        header.messageType == 0) {
        return CodecStatus::Malformed;
    }
    if (header.sequence == 0) {
        return CodecStatus::BadSequence;
    }
    if (header.payloadBytes > kMaxPayloadBytes) {
        return CodecStatus::TooLarge;
    }
    return CodecStatus::Ok;
}

EncodedPacket BeginPacket(const PacketMeta& meta, MessageType type) {
    EncodedPacket packet;
    if (meta.sequence == 0 ||
        (meta.flags & static_cast<uint16_t>(~kFlagMustUnderstand)) != 0) {
        packet.status = meta.sequence == 0 ? CodecStatus::BadSequence
                                           : CodecStatus::Malformed;
        return packet;
    }
    packet.bytes.reserve(kHeaderBytes);
    WriteU32(packet.bytes, kMagic);
    WriteU16(packet.bytes, kHeaderVersion);
    WriteU16(packet.bytes, meta.flags);
    WriteU16(packet.bytes, static_cast<uint16_t>(type));
    WriteU16(packet.bytes, 0);
    WriteU32(packet.bytes, meta.sequence);
    WriteU64(packet.bytes, meta.sendTimeMs);
    WriteU32(packet.bytes, 0);
    packet.status = CodecStatus::Ok;
    return packet;
}

EncodedPacket FinishPacket(EncodedPacket packet) {
    if (packet.status != CodecStatus::Ok) {
        packet.bytes.clear();
        return packet;
    }
    if (packet.bytes.size() < kHeaderBytes ||
        packet.bytes.size() > kMaxPacketBytes) {
        packet.status = CodecStatus::TooLarge;
        packet.bytes.clear();
        return packet;
    }
    const uint32_t payloadBytes =
        static_cast<uint32_t>(packet.bytes.size() - kHeaderBytes);
    packet.bytes[24] = static_cast<uint8_t>(payloadBytes & 0xFFu);
    packet.bytes[25] = static_cast<uint8_t>((payloadBytes >> 8) & 0xFFu);
    packet.bytes[26] = static_cast<uint8_t>((payloadBytes >> 16) & 0xFFu);
    packet.bytes[27] = static_cast<uint8_t>((payloadBytes >> 24) & 0xFFu);
    return packet;
}

EncodedPacket FailPacket(CodecStatus status) {
    EncodedPacket packet;
    packet.status = status;
    return packet;
}

bool KnownType(uint16_t type) {
    return type >= static_cast<uint16_t>(MessageType::Hello) &&
           type <= static_cast<uint16_t>(MessageType::ActionSnapshot);
}

int TypeIndex(MessageType type) {
    return static_cast<int>(static_cast<uint16_t>(type));
}

CodecStatus ParseHello(Reader& reader, Hello& out) {
    out.protocolVersion = reader.U32();
    out.minCompatibleVersion = reader.U32();
    out.capabilities = reader.U32();
    out.slotPreference = reader.U32();
    const uint8_t nameLen = reader.U8();
    if (!reader.Bytes(nameLen, out.displayName)) {
        return CodecStatus::Malformed;
    }
    const uint8_t buildLen = reader.U8();
    if (!reader.Bytes(buildLen, out.buildTag)) {
        return CodecStatus::Malformed;
    }
    if (!reader.ok() || reader.remaining() != 0) {
        return CodecStatus::Malformed;
    }
    if (out.protocolVersion == 0 || out.minCompatibleVersion == 0 ||
        out.minCompatibleVersion > out.protocolVersion ||
        out.slotPreference > 2 ||
        !IsValidToken(out.displayName, 1, kMaxIdentityBytes) ||
        !IsValidToken(out.buildTag, 0, kMaxBuildTagBytes)) {
        return CodecStatus::Malformed;
    }
    return CodecStatus::Ok;
}

CodecStatus ParseHelloAck(Reader& reader, HelloAck& out) {
    out.negotiatedVersion = reader.U32();
    out.acceptedCapabilities = reader.U32();
    out.assignedPeerPlayerId = reader.U32();
    out.hostPlayerId = reader.U32();
    out.sessionId = reader.U64();
    out.preferenceOverridden = reader.U32();
    if (!reader.ok() || reader.remaining() != 0) {
        return CodecStatus::Malformed;
    }
    if (out.negotiatedVersion == 0 || out.assignedPeerPlayerId == 0 ||
        out.hostPlayerId == 0 ||
        out.assignedPeerPlayerId == out.hostPlayerId || out.sessionId == 0 ||
        out.preferenceOverridden > 1) {
        return CodecStatus::Malformed;
    }
    return CodecStatus::Ok;
}

CodecStatus ParseHeartbeat(Reader& reader, Heartbeat& out) {
    out.senderTick = reader.U64();
    if (!reader.ok() || reader.remaining() != 0) {
        return CodecStatus::Malformed;
    }
    return CodecStatus::Ok;
}

CodecStatus ParseDisconnect(Reader& reader, Disconnect& out) {
    const uint32_t reason = reader.U32();
    if (!reader.ok() || reader.remaining() != 0) {
        return CodecStatus::Malformed;
    }
    if (reason > static_cast<uint32_t>(DisconnectReason::ProtocolError)) {
        return CodecStatus::Malformed;
    }
    out.reason = static_cast<DisconnectReason>(reason);
    return CodecStatus::Ok;
}

CodecStatus ParseError(Reader& reader, ErrorReport& out) {
    const uint32_t code = reader.U32();
    out.relatedSequence = reader.U32();
    const uint16_t textLen = reader.U16();
    if (textLen > kMaxErrorTextBytes) {
        return CodecStatus::TooLarge;
    }
    if (!reader.Bytes(textLen, out.text) || !reader.ok() ||
        reader.remaining() != 0) {
        return CodecStatus::Malformed;
    }
    if (code < static_cast<uint32_t>(ErrorCode::VersionMismatch) ||
        code > static_cast<uint32_t>(ErrorCode::ProtocolFault) ||
        !IsPrintableAscii(out.text)) {
        return CodecStatus::Malformed;
    }
    out.code = static_cast<ErrorCode>(code);
    return CodecStatus::Ok;
}

CodecStatus ParseTransform(Reader& reader, TransformSnapshot& out) {
    out.playerId = reader.U32();
    out.movementState = reader.U32();
    const uint32_t claimFlags = reader.U32();
    const bool xOk = reader.F32(out.x);
    const bool yOk = reader.F32(out.y);
    const bool zOk = reader.F32(out.z);
    const bool yawOk = reader.F32(out.yawDegrees);
    const bool pitchOk = reader.F32(out.pitchDegrees);
    out.tick = reader.U64();
    if (!reader.ok() || reader.remaining() != 0 || !xOk || !yOk || !zOk ||
        !yawOk || !pitchOk) {
        return CodecStatus::Malformed;
    }
    if (out.playerId == kInvalidPlayerId || out.movementState > 7 ||
        (claimFlags & ~1u) != 0) {
        return CodecStatus::Malformed;
    }
    out.verifiedClaimStripped = (claimFlags & 1u) != 0;
    out.claimFlags = 0;
    return CodecStatus::Ok;
}

CodecStatus ParseAction(Reader& reader, ActionSnapshot& out) {
    out.playerId = reader.U32();
    out.actionId = reader.U32();
    out.schemaVersion = reader.U32();
    const uint16_t paramCount = reader.U16();
    if (paramCount > kMaxActionParams) {
        return CodecStatus::Malformed;
    }
    out.params.clear();
    out.params.reserve(paramCount);
    for (uint16_t i = 0; i < paramCount; ++i) {
        float value = 0.0f;
        if (!reader.F32(value)) {
            return CodecStatus::Malformed;
        }
        out.params.push_back(value);
    }
    if (!reader.ok() || reader.remaining() != 0) {
        return CodecStatus::Malformed;
    }
    if (out.schemaVersion != kActionSchemaProvisional) {
        return CodecStatus::SchemaNotFrozen;
    }
    if (out.playerId == kInvalidPlayerId || out.actionId == 0) {
        return CodecStatus::Malformed;
    }
    out.mayApplyToLocalInput = false;
    return CodecStatus::Ok;
}

bool ConsumingStatus(CodecStatus status) {
    return status == CodecStatus::Ok || status == CodecStatus::UnknownIgnored ||
           status == CodecStatus::MustUnderstandRejected ||
           status == CodecStatus::SchemaNotFrozen ||
           status == CodecStatus::Malformed || status == CodecStatus::TooLarge;
}

}  // namespace

const char* StatusName(CodecStatus status) {
    switch (status) {
    case CodecStatus::Ok:
        return "Ok";
    case CodecStatus::NeedMoreData:
        return "NeedMoreData";
    case CodecStatus::BadMagic:
        return "BadMagic";
    case CodecStatus::UnsupportedVersion:
        return "UnsupportedVersion";
    case CodecStatus::Malformed:
        return "Malformed";
    case CodecStatus::TooLarge:
        return "TooLarge";
    case CodecStatus::TrailingBytes:
        return "TrailingBytes";
    case CodecStatus::BadSequence:
        return "BadSequence";
    case CodecStatus::Stale:
        return "Stale";
    case CodecStatus::UnknownIgnored:
        return "UnknownIgnored";
    case CodecStatus::MustUnderstandRejected:
        return "MustUnderstandRejected";
    case CodecStatus::Incompatible:
        return "Incompatible";
    case CodecStatus::SchemaNotFrozen:
        return "SchemaNotFrozen";
    case CodecStatus::UnexpectedMessage:
        return "UnexpectedMessage";
    case CodecStatus::Closed:
        return "Closed";
    }
    return "Malformed";
}

const char* PhaseName(Phase phase) {
    switch (phase) {
    case Phase::Idle:
        return "Idle";
    case Phase::WaitHello:
        return "WaitHello";
    case Phase::WaitHelloAck:
        return "WaitHelloAck";
    case Phase::Open:
        return "Open";
    case Phase::Closed:
        return "Closed";
    case Phase::Failed:
        return "Failed";
    }
    return "Failed";
}

const char* MessageTypeName(MessageType type) {
    switch (type) {
    case MessageType::Hello:
        return "Hello";
    case MessageType::HelloAck:
        return "HelloAck";
    case MessageType::Heartbeat:
        return "Heartbeat";
    case MessageType::Disconnect:
        return "Disconnect";
    case MessageType::ErrorReport:
        return "ErrorReport";
    case MessageType::TransformSnapshot:
        return "TransformSnapshot";
    case MessageType::ActionSnapshot:
        return "ActionSnapshot";
    }
    return "Unknown";
}

DecodeResult Decode(const uint8_t* data, std::size_t size) {
    DecodeResult result;
    if (data == nullptr && size != 0) {
        result.status = CodecStatus::Malformed;
        return result;
    }
    if (size < kHeaderBytes) {
        result.status = CodecStatus::NeedMoreData;
        return result;
    }

    const CodecStatus headerStatus = ReadHeader(data, result.message.header);
    if (headerStatus != CodecStatus::Ok) {
        result.status = headerStatus;
        return result;
    }

    const std::size_t frameBytes =
        kHeaderBytes + static_cast<std::size_t>(result.message.header.payloadBytes);
    if (size < frameBytes) {
        result.status = CodecStatus::NeedMoreData;
        return result;
    }

    result.bytesConsumed = frameBytes;
    const uint16_t rawType = result.message.header.messageType;
    const bool mustUnderstand =
        (result.message.header.flags & kFlagMustUnderstand) != 0;
    if (!KnownType(rawType)) {
        result.status = mustUnderstand ? CodecStatus::MustUnderstandRejected
                                       : CodecStatus::UnknownIgnored;
        return result;
    }

    result.message.type = static_cast<MessageType>(rawType);
    Reader reader(data + kHeaderBytes, result.message.header.payloadBytes);
    CodecStatus bodyStatus = CodecStatus::Malformed;
    switch (result.message.type) {
    case MessageType::Hello:
        bodyStatus = ParseHello(reader, result.message.hello);
        break;
    case MessageType::HelloAck:
        bodyStatus = ParseHelloAck(reader, result.message.helloAck);
        break;
    case MessageType::Heartbeat:
        bodyStatus = ParseHeartbeat(reader, result.message.heartbeat);
        break;
    case MessageType::Disconnect:
        bodyStatus = ParseDisconnect(reader, result.message.disconnect);
        break;
    case MessageType::ErrorReport:
        bodyStatus = ParseError(reader, result.message.error);
        break;
    case MessageType::TransformSnapshot:
        bodyStatus = ParseTransform(reader, result.message.transform);
        break;
    case MessageType::ActionSnapshot:
        bodyStatus = ParseAction(reader, result.message.action);
        break;
    }
    result.status = bodyStatus;
    if (bodyStatus != CodecStatus::Ok &&
        bodyStatus != CodecStatus::SchemaNotFrozen) {
        result.message = Message{};
        result.message.header.payloadBytes =
            static_cast<uint32_t>(frameBytes - kHeaderBytes);
    }
    return result;
}

DecodeResult DecodeExact(const uint8_t* data, std::size_t size) {
    DecodeResult result = Decode(data, size);
    if (ConsumingStatus(result.status) && result.bytesConsumed != 0 &&
        result.bytesConsumed != size &&
        (result.status == CodecStatus::Ok ||
         result.status == CodecStatus::UnknownIgnored ||
         result.status == CodecStatus::MustUnderstandRejected ||
         result.status == CodecStatus::SchemaNotFrozen)) {
        result.status = CodecStatus::TrailingBytes;
        result.message = Message{};
    }
    return result;
}

EncodedPacket EncodeHello(const PacketMeta& meta, const Hello& body) {
    if (body.protocolVersion == 0 || body.minCompatibleVersion == 0 ||
        body.minCompatibleVersion > body.protocolVersion ||
        body.slotPreference > 2 ||
        !IsValidToken(body.displayName, 1, kMaxIdentityBytes) ||
        !IsValidToken(body.buildTag, 0, kMaxBuildTagBytes) ||
        body.displayName.size() > 0xFFu || body.buildTag.size() > 0xFFu) {
        return FailPacket(CodecStatus::Malformed);
    }
    EncodedPacket packet = BeginPacket(meta, MessageType::Hello);
    if (packet.status != CodecStatus::Ok) {
        return packet;
    }
    WriteU32(packet.bytes, body.protocolVersion);
    WriteU32(packet.bytes, body.minCompatibleVersion);
    WriteU32(packet.bytes, body.capabilities);
    WriteU32(packet.bytes, body.slotPreference);
    packet.bytes.push_back(static_cast<uint8_t>(body.displayName.size()));
    packet.bytes.insert(packet.bytes.end(), body.displayName.begin(),
                        body.displayName.end());
    packet.bytes.push_back(static_cast<uint8_t>(body.buildTag.size()));
    packet.bytes.insert(packet.bytes.end(), body.buildTag.begin(),
                        body.buildTag.end());
    return FinishPacket(std::move(packet));
}

EncodedPacket EncodeHelloAck(const PacketMeta& meta, const HelloAck& body) {
    if (body.negotiatedVersion == 0 || body.assignedPeerPlayerId == 0 ||
        body.hostPlayerId == 0 ||
        body.assignedPeerPlayerId == body.hostPlayerId || body.sessionId == 0 ||
        body.preferenceOverridden > 1) {
        return FailPacket(CodecStatus::Malformed);
    }
    EncodedPacket packet = BeginPacket(meta, MessageType::HelloAck);
    if (packet.status != CodecStatus::Ok) {
        return packet;
    }
    WriteU32(packet.bytes, body.negotiatedVersion);
    WriteU32(packet.bytes, body.acceptedCapabilities);
    WriteU32(packet.bytes, body.assignedPeerPlayerId);
    WriteU32(packet.bytes, body.hostPlayerId);
    WriteU64(packet.bytes, body.sessionId);
    WriteU32(packet.bytes, body.preferenceOverridden);
    return FinishPacket(std::move(packet));
}

EncodedPacket EncodeHeartbeat(const PacketMeta& meta, const Heartbeat& body) {
    EncodedPacket packet = BeginPacket(meta, MessageType::Heartbeat);
    if (packet.status != CodecStatus::Ok) {
        return packet;
    }
    WriteU64(packet.bytes, body.senderTick);
    return FinishPacket(std::move(packet));
}

EncodedPacket EncodeDisconnect(const PacketMeta& meta, const Disconnect& body) {
    if (static_cast<uint32_t>(body.reason) >
        static_cast<uint32_t>(DisconnectReason::ProtocolError)) {
        return FailPacket(CodecStatus::Malformed);
    }
    EncodedPacket packet = BeginPacket(meta, MessageType::Disconnect);
    if (packet.status != CodecStatus::Ok) {
        return packet;
    }
    WriteU32(packet.bytes, static_cast<uint32_t>(body.reason));
    return FinishPacket(std::move(packet));
}

EncodedPacket EncodeError(const PacketMeta& meta, const ErrorReport& body) {
    if (static_cast<uint32_t>(body.code) <
            static_cast<uint32_t>(ErrorCode::VersionMismatch) ||
        static_cast<uint32_t>(body.code) >
            static_cast<uint32_t>(ErrorCode::ProtocolFault) ||
        body.text.size() > kMaxErrorTextBytes || !IsPrintableAscii(body.text)) {
        return FailPacket(body.text.size() > kMaxErrorTextBytes
                              ? CodecStatus::TooLarge
                              : CodecStatus::Malformed);
    }
    EncodedPacket packet = BeginPacket(meta, MessageType::ErrorReport);
    if (packet.status != CodecStatus::Ok) {
        return packet;
    }
    WriteU32(packet.bytes, static_cast<uint32_t>(body.code));
    WriteU32(packet.bytes, body.relatedSequence);
    WriteU16(packet.bytes, static_cast<uint16_t>(body.text.size()));
    packet.bytes.insert(packet.bytes.end(), body.text.begin(), body.text.end());
    return FinishPacket(std::move(packet));
}

EncodedPacket EncodeTransform(const PacketMeta& meta,
                              const TransformSnapshot& body) {
    if (body.playerId == kInvalidPlayerId || body.movementState > 7 ||
        body.claimFlags != 0) {
        return FailPacket(CodecStatus::Malformed);
    }
    EncodedPacket packet = BeginPacket(meta, MessageType::TransformSnapshot);
    if (packet.status != CodecStatus::Ok) {
        return packet;
    }
    WriteU32(packet.bytes, body.playerId);
    WriteU32(packet.bytes, body.movementState);
    WriteU32(packet.bytes, 0);
    if (!WriteF32(packet.bytes, body.x) || !WriteF32(packet.bytes, body.y) ||
        !WriteF32(packet.bytes, body.z) ||
        !WriteF32(packet.bytes, body.yawDegrees) ||
        !WriteF32(packet.bytes, body.pitchDegrees)) {
        return FailPacket(CodecStatus::Malformed);
    }
    WriteU64(packet.bytes, body.tick);
    return FinishPacket(std::move(packet));
}

EncodedPacket EncodeAction(const PacketMeta& meta, const ActionSnapshot& body) {
    if (body.schemaVersion != kActionSchemaProvisional) {
        return FailPacket(CodecStatus::SchemaNotFrozen);
    }
    if (body.playerId == kInvalidPlayerId || body.actionId == 0 ||
        body.params.size() > kMaxActionParams) {
        return FailPacket(CodecStatus::Malformed);
    }
    EncodedPacket packet = BeginPacket(meta, MessageType::ActionSnapshot);
    if (packet.status != CodecStatus::Ok) {
        return packet;
    }
    WriteU32(packet.bytes, body.playerId);
    WriteU32(packet.bytes, body.actionId);
    WriteU32(packet.bytes, body.schemaVersion);
    WriteU16(packet.bytes, static_cast<uint16_t>(body.params.size()));
    for (float value : body.params) {
        if (!WriteF32(packet.bytes, value)) {
            return FailPacket(CodecStatus::Malformed);
        }
    }
    return FinishPacket(std::move(packet));
}

NegotiateResult Negotiate(const NegotiateRequest& local, const Hello& remote) {
    NegotiateResult result;
    if (local.protocolVersion != kProtocolVersion ||
        remote.protocolVersion < local.protocolVersion ||
        remote.minCompatibleVersion == 0 ||
        remote.minCompatibleVersion > local.protocolVersion ||
        remote.minCompatibleVersion > remote.protocolVersion ||
        (remote.capabilities & kCriticalUnknownCapabilities) != 0) {
        result.status = CodecStatus::Incompatible;
        return result;
    }
    result.acceptedCapabilities =
        remote.capabilities & local.capabilities & kKnownCapabilities;
    if ((result.acceptedCapabilities & kCapabilityHeartbeat) == 0) {
        result.status = CodecStatus::Incompatible;
        result.acceptedCapabilities = 0;
        return result;
    }
    result.negotiatedVersion = local.protocolVersion;
    result.status = CodecStatus::Ok;
    return result;
}

SlotAssignment AssignSlots(uint32_t slotPreference) {
    SlotAssignment assignment;
    assignment.hostPlayerId = kHostPlayerId;
    assignment.peerPlayerId = kPeerPlayerId;
    assignment.preferenceOverridden = slotPreference == kHostPlayerId;
    return assignment;
}

bool MayApplyActionToLocalInput(const ActionSnapshot& action) {
    (void)action;
    return false;
}

CodecStatus FrameBuffer::Append(const uint8_t* data, std::size_t size) {
    if (sticky_ != CodecStatus::Ok) {
        return sticky_;
    }
    if (data == nullptr && size != 0) {
        sticky_ = CodecStatus::Malformed;
        buffer_.clear();
        return sticky_;
    }
    if (size == 0) {
        return CodecStatus::Ok;
    }
    if (buffer_.size() + size > kMaxBufferedBytes) {
        sticky_ = CodecStatus::TooLarge;
        buffer_.clear();
        return sticky_;
    }
    buffer_.insert(buffer_.end(), data, data + size);
    if (buffer_.size() >= kHeaderBytes) {
        PacketHeader header;
        const CodecStatus headerStatus = ReadHeader(buffer_.data(), header);
        if (headerStatus == CodecStatus::TooLarge ||
            headerStatus == CodecStatus::BadMagic ||
            headerStatus == CodecStatus::UnsupportedVersion ||
            headerStatus == CodecStatus::BadSequence ||
            headerStatus == CodecStatus::Malformed) {
            sticky_ = headerStatus;
            buffer_.clear();
            return sticky_;
        }
    }
    return CodecStatus::Ok;
}

DecodeResult FrameBuffer::Pop() {
    DecodeResult result;
    if (sticky_ != CodecStatus::Ok) {
        result.status = sticky_;
        return result;
    }
    result = Decode(buffer_.data(), buffer_.size());
    if (result.status == CodecStatus::NeedMoreData) {
        return result;
    }
    if (result.bytesConsumed > 0 && result.bytesConsumed <= buffer_.size() &&
        (result.status == CodecStatus::Ok ||
         result.status == CodecStatus::UnknownIgnored ||
         result.status == CodecStatus::MustUnderstandRejected ||
         result.status == CodecStatus::SchemaNotFrozen)) {
        buffer_.erase(buffer_.begin(),
                      buffer_.begin() +
                          static_cast<std::ptrdiff_t>(result.bytesConsumed));
        return result;
    }
    sticky_ = result.status == CodecStatus::Ok ? CodecStatus::Malformed
                                               : result.status;
    buffer_.clear();
    result.status = sticky_;
    result.message = Message{};
    return result;
}

bool FrameBuffer::failed() const { return sticky_ != CodecStatus::Ok; }

std::size_t FrameBuffer::buffered() const { return buffer_.size(); }

ObserveResult IngressFilter::Observe(MessageType type,
                                     uint32_t sequence,
                                     uint64_t sendTimeMs) {
    ObserveResult result;
    const int index = TypeIndex(type);
    if (index <= 0 || index >= 8 || sequence == 0) {
        result.status = CodecStatus::BadSequence;
        return result;
    }
    if (seen_[index] && sequence <= lastSequence_[index]) {
        result.status = CodecStatus::Stale;
        return result;
    }
    if (sendTimeMs != 0 && lastTimeMs_[index] != 0 &&
        sendTimeMs < lastTimeMs_[index]) {
        result.timestampRegressed = true;
    }
    seen_[index] = true;
    lastSequence_[index] = sequence;
    if (sendTimeMs != 0) {
        lastTimeMs_[index] = sendTimeMs;
    }
    result.status = CodecStatus::Ok;
    return result;
}

SessionMachine::SessionMachine(SessionConfig config)
    : config_(std::move(config)) {}

void SessionMachine::SetSendTimeMs(uint64_t sendTimeMs) {
    config_.sendTimeMs = sendTimeMs;
}

Phase SessionMachine::phase() const { return phase_; }
Role SessionMachine::role() const { return config_.role; }
uint32_t SessionMachine::localPlayerId() const { return localPlayerId_; }
uint32_t SessionMachine::remotePlayerId() const { return remotePlayerId_; }
uint32_t SessionMachine::acceptedCapabilities() const {
    return acceptedCapabilities_;
}
uint64_t SessionMachine::sessionId() const { return sessionId_; }
uint64_t SessionMachine::lastHeartbeatTick() const { return lastHeartbeatTick_; }
uint32_t SessionMachine::faultCount() const { return faultCount_; }
const std::string& SessionMachine::lastErrorText() const {
    return lastErrorText_;
}

const TransformSnapshot* SessionMachine::lastTransform() const {
    return hasTransform_ ? &lastTransform_ : nullptr;
}

const ActionSnapshot* SessionMachine::lastAction() const {
    return hasAction_ ? &lastAction_ : nullptr;
}

Step SessionMachine::MakeStep(CodecStatus status) const {
    Step step;
    step.status = status;
    step.phase = phase_;
    return step;
}

EncodedPacket SessionMachine::NextPacket(EncodedPacket packet) {
    if (packet.status == CodecStatus::Ok) {
        if (nextSequence_ == std::numeric_limits<uint32_t>::max()) {
            nextSequence_ = 0;
        } else {
            ++nextSequence_;
        }
    }
    return packet;
}

Step SessionMachine::Fail(CodecStatus status, ErrorCode code,
                          uint32_t relatedSequence, const std::string& text,
                          bool sendError) {
    phase_ = Phase::Failed;
    lastErrorText_ = text;
    Step step = MakeStep(status);
    if (sendError && (config_.capabilities & kCapabilityError) != 0) {
        ErrorReport report;
        report.code = code;
        report.relatedSequence = relatedSequence;
        report.text = text;
        PacketMeta meta;
        meta.sequence = nextSequence_ == 0 ? 1 : nextSequence_;
        meta.sendTimeMs = config_.sendTimeMs;
        if (nextSequence_ != 0) {
            EncodedPacket packet = NextPacket(EncodeError(meta, report));
            if (packet.status == CodecStatus::Ok) {
                step.outbound.push_back(std::move(packet));
            }
        }
    }
    return step;
}

Step SessionMachine::AcceptOpen(CodecStatus status, bool timestampRegressed,
                                bool verifiedClaimStripped) {
    phase_ = Phase::Open;
    Step step = MakeStep(status);
    step.timestampRegressed = timestampRegressed;
    step.verifiedClaimStripped = verifiedClaimStripped;
    return step;
}

Step SessionMachine::Start() {
    if (phase_ != Phase::Idle) {
        return MakeStep(CodecStatus::UnexpectedMessage);
    }
    if ((config_.capabilities & kCapabilityHeartbeat) == 0 ||
        (config_.capabilities & kCriticalUnknownCapabilities) != 0 ||
        !IsValidToken(config_.displayName, 1, kMaxIdentityBytes) ||
        !IsValidToken(config_.buildTag, 0, kMaxBuildTagBytes) ||
        config_.slotPreference > 2) {
        return Fail(CodecStatus::Malformed, ErrorCode::BadIdentity, 0,
                    "local identity or capabilities rejected", false);
    }

    if (config_.role == Role::Host) {
        if (config_.sessionId == 0) {
            return Fail(CodecStatus::Malformed, ErrorCode::ProtocolFault, 0,
                        "host session id is required", false);
        }
        sessionId_ = config_.sessionId;
        localPlayerId_ = kHostPlayerId;
        phase_ = Phase::WaitHello;
        return MakeStep(CodecStatus::Ok);
    }

    Hello hello;
    hello.protocolVersion = kProtocolVersion;
    hello.minCompatibleVersion = kProtocolVersion;
    hello.capabilities = config_.capabilities;
    hello.slotPreference = config_.slotPreference;
    hello.displayName = config_.displayName;
    hello.buildTag = config_.buildTag;
    PacketMeta meta;
    meta.sequence = nextSequence_;
    meta.sendTimeMs = config_.sendTimeMs;
    EncodedPacket packet = NextPacket(EncodeHello(meta, hello));
    if (packet.status != CodecStatus::Ok) {
        return Fail(CodecStatus::Malformed, ErrorCode::BadIdentity, 0,
                    "hello encode failed", false);
    }
    phase_ = Phase::WaitHelloAck;
    Step step = MakeStep(CodecStatus::Ok);
    step.outbound.push_back(std::move(packet));
    return step;
}

Step SessionMachine::Leave(DisconnectReason reason) {
    if (phase_ == Phase::Closed) {
        return MakeStep(CodecStatus::Closed);
    }
    if (phase_ == Phase::Failed || phase_ == Phase::Idle) {
        phase_ = Phase::Closed;
        return MakeStep(CodecStatus::Closed);
    }
    Disconnect body;
    body.reason = reason;
    PacketMeta meta;
    meta.sequence = nextSequence_ == 0 ? 1 : nextSequence_;
    meta.sendTimeMs = config_.sendTimeMs;
    Step step;
    if (nextSequence_ != 0) {
        step.outbound.push_back(NextPacket(EncodeDisconnect(meta, body)));
    }
    phase_ = Phase::Closed;
    step.status = CodecStatus::Closed;
    step.phase = phase_;
    return step;
}

Step SessionMachine::HandleDatagram(const uint8_t* data, std::size_t size) {
    if (phase_ == Phase::Closed || phase_ == Phase::Failed) {
        return MakeStep(phase_ == Phase::Closed ? CodecStatus::Closed
                                               : CodecStatus::Malformed);
    }
    if (phase_ == Phase::Idle) {
        return MakeStep(CodecStatus::UnexpectedMessage);
    }

    const DecodeResult decoded = DecodeExact(data, size);
    if (decoded.status == CodecStatus::NeedMoreData) {
        return MakeStep(decoded.status);
    }
    if (decoded.status == CodecStatus::UnknownIgnored) {
        return MakeStep(decoded.status);
    }
    if (decoded.status != CodecStatus::Ok &&
        decoded.status != CodecStatus::SchemaNotFrozen) {
        const bool fatalFraming = decoded.status == CodecStatus::BadMagic ||
                                  decoded.status == CodecStatus::UnsupportedVersion ||
                                  decoded.status == CodecStatus::TooLarge ||
                                  decoded.status == CodecStatus::BadSequence;
        ErrorCode code = ErrorCode::MalformedPacket;
        if (decoded.status == CodecStatus::TooLarge) {
            code = ErrorCode::PayloadTooLarge;
        } else if (decoded.status == CodecStatus::UnsupportedVersion ||
                   decoded.status == CodecStatus::BadMagic) {
            code = ErrorCode::VersionMismatch;
        } else if (decoded.status == CodecStatus::MustUnderstandRejected) {
            code = ErrorCode::UnsupportedCapability;
        }
        ++faultCount_;
        return Fail(decoded.status, code, 0, StatusName(decoded.status),
                    !fatalFraming);
    }

    const Message& message = decoded.message;
    if (phase_ == Phase::WaitHello) {
        if (message.type != MessageType::Hello) {
            if (message.type == MessageType::Disconnect) {
                phase_ = Phase::Closed;
                return MakeStep(CodecStatus::Closed);
            }
            ++faultCount_;
            return Fail(CodecStatus::UnexpectedMessage,
                        ErrorCode::UnexpectedMessage, message.header.sequence,
                        "expected Hello", true);
        }
        NegotiateRequest local;
        local.protocolVersion = kProtocolVersion;
        local.capabilities = config_.capabilities;
        const NegotiateResult negotiated = Negotiate(local, message.hello);
        if (negotiated.status != CodecStatus::Ok) {
            ++faultCount_;
            return Fail(CodecStatus::Incompatible, ErrorCode::VersionMismatch,
                        message.header.sequence, "version or capability rejected",
                        true);
        }
        const ObserveResult observed = ingress_.Observe(
            MessageType::Hello, message.header.sequence, message.header.sendTimeMs);
        if (observed.status != CodecStatus::Ok) {
            return MakeStep(observed.status);
        }
        const SlotAssignment slots = AssignSlots(message.hello.slotPreference);
        HelloAck ack;
        ack.negotiatedVersion = negotiated.negotiatedVersion;
        ack.acceptedCapabilities = negotiated.acceptedCapabilities;
        ack.assignedPeerPlayerId = slots.peerPlayerId;
        ack.hostPlayerId = slots.hostPlayerId;
        ack.sessionId = sessionId_;
        ack.preferenceOverridden = slots.preferenceOverridden ? 1u : 0u;
        PacketMeta meta;
        meta.sequence = nextSequence_;
        meta.sendTimeMs = config_.sendTimeMs;
        EncodedPacket packet = NextPacket(EncodeHelloAck(meta, ack));
        if (packet.status != CodecStatus::Ok) {
            return Fail(packet.status, ErrorCode::ProtocolFault, 0,
                        "hello ack encode failed", false);
        }
        acceptedCapabilities_ = negotiated.acceptedCapabilities;
        localPlayerId_ = slots.hostPlayerId;
        remotePlayerId_ = slots.peerPlayerId;
        phase_ = Phase::Open;
        Step step = MakeStep(CodecStatus::Ok);
        step.outbound.push_back(std::move(packet));
        return step;
    }

    if (phase_ == Phase::WaitHelloAck) {
        if (message.type == MessageType::Disconnect) {
            phase_ = Phase::Closed;
            return MakeStep(CodecStatus::Closed);
        }
        if (message.type == MessageType::ErrorReport) {
            lastErrorText_ = message.error.text;
            ++faultCount_;
            phase_ = Phase::Failed;
            return MakeStep(CodecStatus::Incompatible);
        }
        if (message.type != MessageType::HelloAck) {
            ++faultCount_;
            return Fail(CodecStatus::UnexpectedMessage,
                        ErrorCode::UnexpectedMessage, message.header.sequence,
                        "expected HelloAck", true);
        }
        if (message.helloAck.negotiatedVersion != kProtocolVersion ||
            (message.helloAck.acceptedCapabilities &
             kCriticalUnknownCapabilities) != 0 ||
            (message.helloAck.acceptedCapabilities & ~config_.capabilities) != 0 ||
            (message.helloAck.acceptedCapabilities & kCapabilityHeartbeat) == 0) {
            ++faultCount_;
            return Fail(CodecStatus::Incompatible, ErrorCode::VersionMismatch,
                        message.header.sequence, "hello ack rejected", true);
        }
        const ObserveResult observed = ingress_.Observe(
            MessageType::HelloAck, message.header.sequence,
            message.header.sendTimeMs);
        if (observed.status != CodecStatus::Ok) {
            return MakeStep(observed.status);
        }
        acceptedCapabilities_ = message.helloAck.acceptedCapabilities;
        localPlayerId_ = message.helloAck.assignedPeerPlayerId;
        remotePlayerId_ = message.helloAck.hostPlayerId;
        sessionId_ = message.helloAck.sessionId;
        phase_ = Phase::Open;
        return MakeStep(CodecStatus::Ok);
    }

    if (message.type == MessageType::Hello ||
        message.type == MessageType::HelloAck) {
        ++faultCount_;
        return Fail(CodecStatus::UnexpectedMessage, ErrorCode::UnexpectedMessage,
                    message.header.sequence, "handshake replay", true);
    }
    if (decoded.status == CodecStatus::SchemaNotFrozen) {
        ++faultCount_;
        lastErrorText_ = "action schema is not frozen";
        if (faultCount_ >= kMaxProtocolFaults) {
            return Fail(CodecStatus::SchemaNotFrozen, ErrorCode::SchemaNotFrozen,
                        message.header.sequence, lastErrorText_, true);
        }
        Step step = MakeStep(CodecStatus::SchemaNotFrozen);
        ErrorReport report;
        report.code = ErrorCode::SchemaNotFrozen;
        report.relatedSequence = message.header.sequence;
        report.text = lastErrorText_;
        PacketMeta meta;
        meta.sequence = nextSequence_;
        meta.sendTimeMs = config_.sendTimeMs;
        if (nextSequence_ != 0) {
            step.outbound.push_back(NextPacket(EncodeError(meta, report)));
        }
        return step;
    }

    if (message.type == MessageType::Disconnect) {
        const ObserveResult observed = ingress_.Observe(
            MessageType::Disconnect, message.header.sequence,
            message.header.sendTimeMs);
        if (observed.status == CodecStatus::Stale) {
            return MakeStep(CodecStatus::Stale);
        }
        phase_ = Phase::Closed;
        return MakeStep(CodecStatus::Closed);
    }

    if (message.type == MessageType::ErrorReport) {
        lastErrorText_ = message.error.text;
        ++faultCount_;
        if (message.error.code == ErrorCode::VersionMismatch ||
            faultCount_ >= kMaxProtocolFaults) {
            phase_ = Phase::Failed;
            return MakeStep(CodecStatus::Incompatible);
        }
        return MakeStep(CodecStatus::Ok);
    }

    const bool capabilityOk =
        (message.type == MessageType::Heartbeat &&
         (acceptedCapabilities_ & kCapabilityHeartbeat) != 0) ||
        (message.type == MessageType::TransformSnapshot &&
         (acceptedCapabilities_ & kCapabilityTransform) != 0) ||
        (message.type == MessageType::ActionSnapshot &&
         (acceptedCapabilities_ & kCapabilityAction) != 0);
    if (!capabilityOk) {
        ++faultCount_;
        if (faultCount_ >= kMaxProtocolFaults) {
            return Fail(CodecStatus::UnexpectedMessage,
                        ErrorCode::UnsupportedCapability, message.header.sequence,
                        "capability not negotiated", true);
        }
        Step step = MakeStep(CodecStatus::UnexpectedMessage);
        ErrorReport report;
        report.code = ErrorCode::UnsupportedCapability;
        report.relatedSequence = message.header.sequence;
        report.text = "capability not negotiated";
        PacketMeta meta;
        meta.sequence = nextSequence_;
        meta.sendTimeMs = config_.sendTimeMs;
        if (nextSequence_ != 0) {
            step.outbound.push_back(NextPacket(EncodeError(meta, report)));
        }
        return step;
    }

    const ObserveResult observed = ingress_.Observe(
        message.type, message.header.sequence, message.header.sendTimeMs);
    if (observed.status == CodecStatus::Stale) {
        return MakeStep(CodecStatus::Stale);
    }
    if (observed.status != CodecStatus::Ok) {
        ++faultCount_;
        return Fail(observed.status, ErrorCode::MalformedPacket,
                    message.header.sequence, StatusName(observed.status), true);
    }

    if (message.type == MessageType::Heartbeat) {
        lastHeartbeatTick_ = message.heartbeat.senderTick;
        return AcceptOpen(CodecStatus::Ok, observed.timestampRegressed, false);
    }
    if (message.type == MessageType::TransformSnapshot) {
        lastTransform_ = message.transform;
        lastTransform_.claimFlags = 0;
        lastTransform_.verifiedClaimStripped = message.transform.verifiedClaimStripped;
        hasTransform_ = true;
        return AcceptOpen(CodecStatus::Ok, observed.timestampRegressed,
                          lastTransform_.verifiedClaimStripped);
    }
    lastAction_ = message.action;
    lastAction_.mayApplyToLocalInput = false;
    hasAction_ = true;
    return AcceptOpen(CodecStatus::Ok, observed.timestampRegressed, false);
}

}  // namespace peer
}  // namespace bfc
