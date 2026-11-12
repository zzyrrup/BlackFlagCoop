#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace bfc {

enum class NetworkRole {
    None,
    Host,
    Client
};

enum class ConnectionState {
    Disconnected,
    Listening,
    Connecting,
    Connected,
    Closing,
    Error
};

// Length-prefixed TCP message frame used by BlackFlagCoop.
// Layout on the wire (little-endian):
//   uint32 messageType
//   uint32 payloadSize
//   payload bytes[payloadSize]
struct NetworkMessage {
    uint32_t type = 0;
    std::vector<uint8_t> payload;
};

// Winsock TCP foundation. No gameplay sync lives here yet.
class Network {
public:
    static bool Initialize();
    static void Shutdown();
    static bool IsInitialized();

    // Convenience: Listen + Accept with timeout.
    // bindAddress examples: "127.0.0.1" (localhost) or "0.0.0.0" (all interfaces).
    bool StartHost(uint16_t port,
                   const std::string& bindAddress = "0.0.0.0",
                   uint32_t acceptTimeoutMs = 60000);

    bool Listen(uint16_t port, const std::string& bindAddress = "0.0.0.0");
    bool Accept(uint32_t timeoutMs);

    // Client: connect to host:port.
    bool ConnectToHost(const std::string& host, uint16_t port);

    // Graceful close of listen/peer sockets.
    void Disconnect();

    bool Send(const NetworkMessage& message);
    // Returns false on disconnect/error. Sets timedOut=true when no full frame yet.
    bool Receive(NetworkMessage& outMessage, uint32_t timeoutMs, bool& timedOut);

    // Sends exact bytes (used by reliability tests to inject malformed frames).
    bool SendRawBytes(const uint8_t* data, size_t size);

    NetworkRole Role() const;
    ConnectionState State() const;
    std::string LastError() const;

private:
    bool EnsureWinsockReady();
    void SetState(ConnectionState state);
    void SetError(const std::string& message);
    void CloseSocket(uintptr_t& socketHandle);
    bool SendAll(uintptr_t socketHandle, const uint8_t* data, size_t size);
    bool RecvExact(uintptr_t socketHandle, uint8_t* data, size_t size,
                   uint32_t timeoutMs, bool& timedOut);

    mutable std::mutex mutex_;
    NetworkRole role_ = NetworkRole::None;
    ConnectionState state_ = ConnectionState::Disconnected;
    uintptr_t listenSocket_ = ~uintptr_t{0};
    uintptr_t peerSocket_ = ~uintptr_t{0};
    std::string lastError_;
};

}  // namespace bfc
