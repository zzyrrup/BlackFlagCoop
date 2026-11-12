#include "network.h"

#include "../logger.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>

#include <cstring>
#include <mutex>
#include <string>
#include <vector>

namespace bfc {
namespace {

std::mutex g_winsockMutex;
bool g_winsockReady = false;
int g_winsockUsers = 0;

constexpr uintptr_t kInvalidSocketHandle = static_cast<uintptr_t>(INVALID_SOCKET);
constexpr uint32_t kMaxPayloadBytes = 16u * 1024u * 1024u;

std::string WinsockErrorMessage(const char* prefix, int errorCode) {
    return std::string(prefix) + " (WSA " + std::to_string(errorCode) + ")";
}

}  // namespace

bool Network::Initialize() {
    std::lock_guard<std::mutex> lock(g_winsockMutex);
    if (g_winsockReady) {
        ++g_winsockUsers;
        return true;
    }

    WSADATA data {};
    const int result = WSAStartup(MAKEWORD(2, 2), &data);
    if (result != 0) {
        Logger::Info(WinsockErrorMessage("WSAStartup failed", result));
        return false;
    }

    g_winsockReady = true;
    g_winsockUsers = 1;
    Logger::Info("Winsock 2.2 started");
    return true;
}

void Network::Shutdown() {
    std::lock_guard<std::mutex> lock(g_winsockMutex);
    if (!g_winsockReady) {
        return;
    }

    if (g_winsockUsers > 0) {
        --g_winsockUsers;
    }
    if (g_winsockUsers == 0) {
        WSACleanup();
        g_winsockReady = false;
        Logger::Info("Winsock shut down");
    }
}

bool Network::IsInitialized() {
    std::lock_guard<std::mutex> lock(g_winsockMutex);
    return g_winsockReady;
}

bool Network::EnsureWinsockReady() {
    return Initialize();
}

void Network::SetState(ConnectionState state) {
    state_ = state;
}

void Network::SetError(const std::string& message) {
    lastError_ = message;
    state_ = ConnectionState::Error;
    Logger::Info(std::string("Network error: ") + message);
}

void Network::CloseSocket(uintptr_t& socketHandle) {
    if (socketHandle != kInvalidSocketHandle) {
        closesocket(static_cast<SOCKET>(socketHandle));
        socketHandle = kInvalidSocketHandle;
    }
}

NetworkRole Network::Role() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return role_;
}

ConnectionState Network::State() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return state_;
}

std::string Network::LastError() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return lastError_;
}

bool Network::Listen(uint16_t port, const std::string& bindAddress) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!EnsureWinsockReady()) {
        SetError("Winsock is not ready");
        return false;
    }

    CloseSocket(peerSocket_);
    CloseSocket(listenSocket_);
    role_ = NetworkRole::Host;
    SetState(ConnectionState::Listening);
    lastError_.clear();

    SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == INVALID_SOCKET) {
        SetError(WinsockErrorMessage("socket() failed", WSAGetLastError()));
        return false;
    }

    BOOL reuse = TRUE;
    setsockopt(listenSocket, SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<const char*>(&reuse), sizeof(reuse));

    sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    if (inet_pton(AF_INET, bindAddress.c_str(), &address.sin_addr) != 1) {
        closesocket(listenSocket);
        SetError("Invalid bind address: " + bindAddress);
        return false;
    }

    if (bind(listenSocket, reinterpret_cast<sockaddr*>(&address),
             sizeof(address)) == SOCKET_ERROR) {
        const int error = WSAGetLastError();
        closesocket(listenSocket);
        SetError(WinsockErrorMessage("bind() failed", error));
        return false;
    }

    if (listen(listenSocket, 1) == SOCKET_ERROR) {
        const int error = WSAGetLastError();
        closesocket(listenSocket);
        SetError(WinsockErrorMessage("listen() failed", error));
        return false;
    }

    listenSocket_ = static_cast<uintptr_t>(listenSocket);
    Logger::Info("Host listening on " + bindAddress + ":" + std::to_string(port));
    return true;
}

bool Network::Accept(uint32_t timeoutMs) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (role_ != NetworkRole::Host ||
        state_ != ConnectionState::Listening ||
        listenSocket_ == kInvalidSocketHandle) {
        SetError("Accept failed: not listening");
        return false;
    }

    fd_set readSet;
    FD_ZERO(&readSet);
    FD_SET(static_cast<SOCKET>(listenSocket_), &readSet);

    timeval timeout {};
    timeout.tv_sec = static_cast<long>(timeoutMs / 1000);
    timeout.tv_usec = static_cast<long>((timeoutMs % 1000) * 1000);

    const int ready = select(0, &readSet, nullptr, nullptr, &timeout);
    if (ready == 0) {
        SetError("Accept timed out waiting for client");
        return false;
    }
    if (ready == SOCKET_ERROR) {
        SetError(WinsockErrorMessage("Accept select() failed", WSAGetLastError()));
        return false;
    }

    SOCKET peer = accept(static_cast<SOCKET>(listenSocket_), nullptr, nullptr);
    if (peer == INVALID_SOCKET) {
        SetError(WinsockErrorMessage("accept() failed", WSAGetLastError()));
        return false;
    }

    peerSocket_ = static_cast<uintptr_t>(peer);
    SetState(ConnectionState::Connected);
    Logger::Info("Host accepted client connection");
    return true;
}

bool Network::StartHost(uint16_t port,
                        const std::string& bindAddress,
                        uint32_t acceptTimeoutMs) {
    if (!Listen(port, bindAddress)) {
        return false;
    }
    if (!Accept(acceptTimeoutMs)) {
        Disconnect();
        return false;
    }
    return true;
}

bool Network::ConnectToHost(const std::string& host, uint16_t port) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!EnsureWinsockReady()) {
        SetError("Winsock is not ready");
        return false;
    }

    CloseSocket(peerSocket_);
    CloseSocket(listenSocket_);
    role_ = NetworkRole::Client;
    SetState(ConnectionState::Connecting);
    lastError_.clear();

    addrinfo hints {};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* result = nullptr;
    const std::string portText = std::to_string(port);
    const int lookup = getaddrinfo(host.c_str(), portText.c_str(), &hints, &result);
    if (lookup != 0 || result == nullptr) {
        SetError(WinsockErrorMessage("getaddrinfo() failed", lookup));
        return false;
    }

    SOCKET peer = INVALID_SOCKET;
    for (addrinfo* ptr = result; ptr != nullptr; ptr = ptr->ai_next) {
        peer = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (peer == INVALID_SOCKET) {
            continue;
        }
        if (connect(peer, ptr->ai_addr, static_cast<int>(ptr->ai_addrlen)) == 0) {
            break;
        }
        closesocket(peer);
        peer = INVALID_SOCKET;
    }
    freeaddrinfo(result);

    if (peer == INVALID_SOCKET) {
        SetError(WinsockErrorMessage("connect() failed", WSAGetLastError()));
        return false;
    }

    peerSocket_ = static_cast<uintptr_t>(peer);
    SetState(ConnectionState::Connected);
    Logger::Info("Client connected to " + host + ":" + std::to_string(port));
    return true;
}

void Network::Disconnect() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (state_ == ConnectionState::Connected ||
        state_ == ConnectionState::Listening ||
        state_ == ConnectionState::Connecting) {
        SetState(ConnectionState::Closing);
        Logger::Info("Network disconnect requested");
    }

    CloseSocket(peerSocket_);
    CloseSocket(listenSocket_);
    role_ = NetworkRole::None;
    SetState(ConnectionState::Disconnected);
}

bool Network::SendAll(uintptr_t socketHandle, const uint8_t* data, size_t size) {
    size_t sentTotal = 0;
    while (sentTotal < size) {
        const int sent = send(static_cast<SOCKET>(socketHandle),
                              reinterpret_cast<const char*>(data + sentTotal),
                              static_cast<int>(size - sentTotal), 0);
        if (sent == SOCKET_ERROR || sent == 0) {
            return false;
        }
        sentTotal += static_cast<size_t>(sent);
    }
    return true;
}

bool Network::RecvExact(uintptr_t socketHandle, uint8_t* data, size_t size,
                        uint32_t timeoutMs, bool& timedOut) {
    timedOut = false;
    size_t receivedTotal = 0;

    while (receivedTotal < size) {
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(static_cast<SOCKET>(socketHandle), &readSet);

        timeval timeout {};
        timeout.tv_sec = static_cast<long>(timeoutMs / 1000);
        timeout.tv_usec = static_cast<long>((timeoutMs % 1000) * 1000);

        const int ready = select(0, &readSet, nullptr, nullptr, &timeout);
        if (ready == 0) {
            timedOut = true;
            return false;
        }
        if (ready == SOCKET_ERROR) {
            return false;
        }

        const int received = recv(static_cast<SOCKET>(socketHandle),
                                  reinterpret_cast<char*>(data + receivedTotal),
                                  static_cast<int>(size - receivedTotal), 0);
        if (received == 0) {
            return false;
        }
        if (received == SOCKET_ERROR) {
            return false;
        }
        receivedTotal += static_cast<size_t>(received);
    }

    return true;
}

bool Network::Send(const NetworkMessage& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ != ConnectionState::Connected ||
        peerSocket_ == kInvalidSocketHandle) {
        SetError("Send failed: not connected");
        return false;
    }

    if (message.payload.size() > kMaxPayloadBytes) {
        SetError("Send failed: payload too large");
        return false;
    }

    uint8_t header[8] = {};
    const uint32_t type = message.type;
    const uint32_t payloadSize = static_cast<uint32_t>(message.payload.size());
    std::memcpy(header + 0, &type, sizeof(type));
    std::memcpy(header + 4, &payloadSize, sizeof(payloadSize));

    if (!SendAll(peerSocket_, header, sizeof(header))) {
        SetError(WinsockErrorMessage("Send header failed", WSAGetLastError()));
        CloseSocket(peerSocket_);
        SetState(ConnectionState::Disconnected);
        return false;
    }

    if (payloadSize > 0 &&
        !SendAll(peerSocket_, message.payload.data(), message.payload.size())) {
        SetError(WinsockErrorMessage("Send payload failed", WSAGetLastError()));
        CloseSocket(peerSocket_);
        SetState(ConnectionState::Disconnected);
        return false;
    }

    return true;
}

bool Network::SendRawBytes(const uint8_t* data, size_t size) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ != ConnectionState::Connected ||
        peerSocket_ == kInvalidSocketHandle) {
        SetError("SendRawBytes failed: not connected");
        return false;
    }
    if (!SendAll(peerSocket_, data, size)) {
        SetError(WinsockErrorMessage("SendRawBytes failed", WSAGetLastError()));
        CloseSocket(peerSocket_);
        SetState(ConnectionState::Disconnected);
        return false;
    }
    return true;
}

bool Network::Receive(NetworkMessage& outMessage, uint32_t timeoutMs,
                      bool& timedOut) {
    std::lock_guard<std::mutex> lock(mutex_);
    timedOut = false;
    outMessage = {};

    if (state_ != ConnectionState::Connected ||
        peerSocket_ == kInvalidSocketHandle) {
        SetError("Receive failed: not connected");
        return false;
    }

    uint8_t header[8] = {};
    if (!RecvExact(peerSocket_, header, sizeof(header), timeoutMs, timedOut)) {
        if (timedOut) {
            return false;
        }
        SetError(WinsockErrorMessage("Receive header failed", WSAGetLastError()));
        CloseSocket(peerSocket_);
        SetState(ConnectionState::Disconnected);
        return false;
    }

    uint32_t type = 0;
    uint32_t payloadSize = 0;
    std::memcpy(&type, header + 0, sizeof(type));
    std::memcpy(&payloadSize, header + 4, sizeof(payloadSize));

    if (payloadSize > kMaxPayloadBytes) {
        SetError("Receive failed: invalid payload length " +
                 std::to_string(payloadSize));
        CloseSocket(peerSocket_);
        SetState(ConnectionState::Disconnected);
        return false;
    }

    outMessage.type = type;
    outMessage.payload.resize(payloadSize);
    if (payloadSize > 0) {
        bool payloadTimedOut = false;
        if (!RecvExact(peerSocket_, outMessage.payload.data(), payloadSize,
                       timeoutMs, payloadTimedOut)) {
            timedOut = payloadTimedOut;
            if (!payloadTimedOut) {
                SetError(WinsockErrorMessage("Receive payload failed",
                                            WSAGetLastError()));
                CloseSocket(peerSocket_);
                SetState(ConnectionState::Disconnected);
            }
            outMessage = {};
            return false;
        }
    }

    return true;
}

}  // namespace bfc
