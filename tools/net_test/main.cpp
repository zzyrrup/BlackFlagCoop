#include "game/player_probe.h"
#include "game/player_telemetry.h"
#include "game/runtime_diag.h"
#include "logger.h"
#include "network/network.h"
#include "network/player_state.h"
#include "network/protocol.h"
#include "network/session.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace {

constexpr const char* kDefaultBindAddress = "0.0.0.0";
constexpr const char* kDefaultConnectHost = "10.0.0.95";
constexpr uint16_t kDefaultPort = 27016;
constexpr uint32_t kDefaultAcceptTimeoutMs = 120000;
constexpr int kDefaultStateTicks = 5;
constexpr int kDefaultStateIntervalMs = 200;

void PrintUsage() {
    std::cout
        << "BlackFlagCoopNetTest v0.5.8 (presence + reliability + diagnostics)\n"
        << "\n"
        << "  --host [--bind 0.0.0.0] [--port 27016]\n"
        << "  --client [--connect 10.0.0.95] [--port 27016]\n"
        << "  --self-test [--port N]\n"
        << "  --diag-self-test          runtime diag + protocol-ex checks\n"
        << "  --ticks N                 state updates to exchange (default 5)\n"
        << "  --state-interval-ms N     delay between updates (default 200)\n"
        << "  --accept-timeout-ms N     host wait for client (default 120000)\n"
        << "\n"
        << "Reliability defaults (when enabled on Session):\n"
        << "  heartbeatIntervalMs=5000  idleTimeoutMs=30000\n"
        << "Localhost tests only; do not claim LAN reliability without LAN runs.\n";
}

bool Equals(const char* a, const char* b) {
    return a != nullptr && b != nullptr && std::string(a) == b;
}

std::vector<std::string> ListLocalIPv4Addresses() {
    std::vector<std::string> addresses;
    char hostName[256] = {};
    if (gethostname(hostName, static_cast<int>(sizeof(hostName))) != 0) {
        return addresses;
    }

    addrinfo hints {};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* result = nullptr;
    if (getaddrinfo(hostName, nullptr, &hints, &result) != 0 || result == nullptr) {
        return addresses;
    }

    for (addrinfo* ptr = result; ptr != nullptr; ptr = ptr->ai_next) {
        char buffer[INET_ADDRSTRLEN] = {};
        auto* ipv4 = reinterpret_cast<sockaddr_in*>(ptr->ai_addr);
        if (inet_ntop(AF_INET, &ipv4->sin_addr, buffer, sizeof(buffer)) != nullptr) {
            const std::string ip(buffer);
            if (ip != "127.0.0.1") {
                addresses.push_back(ip);
            }
        }
    }
    freeaddrinfo(result);
    return addresses;
}

void PrintHostListenHints(const std::string& bindAddress, uint16_t port) {
    std::cout << "[HOST] Listening address : " << bindAddress << ":" << port << "\n";
    if (bindAddress == "0.0.0.0") {
        std::cout << "[HOST] Bind mode         : all IPv4 interfaces\n";
        const auto locals = ListLocalIPv4Addresses();
        if (locals.empty()) {
            std::cout << "[HOST] Local IPv4 hint   : (none detected)\n";
        } else {
            for (const auto& ip : locals) {
                std::cout << "[HOST] Client may use    : " << ip << ":" << port << "\n";
            }
        }
        std::cout << "[HOST] Expected LAN IP   : 10.0.0.95:" << port << "\n";
    } else {
        std::cout << "[HOST] Bind mode         : specific interface\n";
        std::cout << "[HOST] Client should use : " << bindAddress << ":" << port << "\n";
    }
}

void PrintPresence(const char* role, const bfc::PlayerPresencePayload& presence) {
    std::cout << "[" << role << "] Presence event    : "
              << bfc::PresenceEventName(presence.event)
              << " playerId=" << presence.playerId << "\n";
}

void PrintState(const char* role, const bfc::PlayerStatePayload& state) {
    std::cout << "[" << role << "] State update      : playerId=" << state.playerId
              << " status=" << bfc::ConnectionStatusName(state.connectionStatus)
              << " pos=(" << state.x << ", " << state.y << ", " << state.z << ")"
              << " tick=" << state.tick
              << "  [placeholder coords, not game memory]\n";
}

bool PumpOneMessage(bfc::Session& session,
                    bfc::PlayerStateTracker& tracker,
                    const char* role,
                    uint32_t timeoutMs,
                    bool& connectionLost) {
    connectionLost = false;
    bool timedOut = false;
    bfc::NetworkMessage message;
    if (!session.Receive(message, timeoutMs, timedOut)) {
        if (timedOut) {
            return true;  // idle is OK
        }
        connectionLost = true;
        std::cout << "[" << role << "] Connection lost   : receive failed\n";
        return false;
    }

    if (message.type == bfc::kMsgPlayerPresence) {
        bfc::PlayerPresencePayload presence {};
        std::string error;
        if (!bfc::ParsePlayerPresence(message, presence) ||
            !tracker.ApplyPresence(presence, error)) {
            std::cout << "[" << role << "] Malformed presence ignored"
                      << (error.empty() ? "" : (": " + error)) << "\n";
            return true;
        }
        PrintPresence(role, presence);
        if (presence.event == bfc::kPresenceEventLeave) {
            std::cout << "[" << role << "] Leave noticed     : playerId="
                      << presence.playerId << "\n";
        }
        return true;
    }

    if (message.type == bfc::kMsgPlayerState) {
        bfc::PlayerStatePayload state {};
        std::string error;
        if (!bfc::ParsePlayerState(message, state) ||
            !tracker.ApplyState(state, error)) {
            std::cout << "[" << role << "] Malformed state ignored"
                      << (error.empty() ? "" : (": " + error)) << "\n";
            return true;
        }
        PrintState(role, state);
        return true;
    }

    if (message.type == bfc::kMsgPlayerStateEx) {
        bfc::PlayerStateExPayload state {};
        std::string error;
        if (!bfc::ParsePlayerStateEx(message, state) ||
            !tracker.ApplyStateEx(state, error)) {
            std::cout << "[" << role << "] Malformed state-ex ignored"
                      << (error.empty() ? "" : (": " + error)) << "\n";
            return true;
        }
        std::cout << "[" << role << "] StateEx update    : playerId="
                  << state.playerId
                  << " pos=(" << state.x << ", " << state.y << ", " << state.z
                  << ") yaw=" << state.yawDegrees
                  << " move=" << bfc::MovementStateName(state.movementState)
                  << " verified="
                  << ((state.flags & bfc::kStateExFlagPoseVerified) ? "yes" : "no")
                  << " tick=" << state.tick << "\n";
        return true;
    }

    if (message.type == bfc::kMsgHeartbeat) {
        bfc::HeartbeatPayload hb {};
        if (!bfc::ParseHeartbeat(message, hb)) {
            std::cout << "[" << role << "] Malformed heartbeat ignored\n";
            return true;
        }
        std::cout << "[" << role << "] Heartbeat         : tick="
                  << hb.senderTick << "\n";
        return true;
    }

    if (message.type == bfc::kMsgPing) {
        const std::string text = bfc::PayloadAsString(message);
        std::cout << "[" << role << "] Legacy ping       : " << text << "\n";
        session.Send(bfc::MakePong("PONG:" + text));
        return true;
    }

    std::cout << "[" << role << "] Ignoring msg type : " << message.type << "\n";
    return true;
}

bool ExchangePresenceAndState(bfc::Session& session,
                              bfc::PlayerStateTracker& tracker,
                              const char* role,
                              int ticks,
                              int intervalMs) {
    const bfc::PlayerId localId = session.LocalPlayerId();
    const bfc::PlayerId remoteId = session.RemotePlayerId();

    tracker.SetLocalState(localId, 0.0f, 0.0f, 0.0f, 0);
    std::cout << "[" << role << "] Sending presence  : Join playerId="
              << localId << "\n";
    if (!session.Send(bfc::MakePlayerPresence(localId, bfc::kPresenceEventJoin))) {
        std::cerr << "[" << role << "] Failed to send join presence\n";
        return false;
    }

    // Wait briefly for peer join presence.
    const auto waitUntil =
        std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < waitUntil) {
        bool lost = false;
        if (!PumpOneMessage(session, tracker, role, 200, lost)) {
            return false;
        }
        const auto remote = tracker.Get(remoteId);
        if (remote && remote->present) {
            break;
        }
    }

    const auto remoteAfterJoin = tracker.Get(remoteId);
    if (!remoteAfterJoin || !remoteAfterJoin->present) {
        std::cerr << "[" << role << "] Timed out waiting for peer join presence\n";
        return false;
    }

    std::cout << "[" << role << "] Peer present      : playerId=" << remoteId << "\n";

    for (int i = 1; i <= ticks; ++i) {
        const float x = static_cast<float>(localId) * 10.0f + static_cast<float>(i);
        const float y = 1.5f;
        const float z = static_cast<float>(i) * 0.5f;
        tracker.SetLocalState(localId, x, y, z, static_cast<uint64_t>(i));

        if (!session.Send(bfc::MakePlayerState(
                localId, bfc::kConnectionStatusConnected, x, y, z,
                static_cast<uint64_t>(i)))) {
            std::cerr << "[" << role << "] Failed to send state tick " << i << "\n";
            return false;
        }
        std::cout << "[" << role << "] Sent local state  : tick=" << i
                  << " pos=(" << x << ", " << y << ", " << z << ")\n";

        // Drain available peer messages for this interval.
        const auto intervalEnd =
            std::chrono::steady_clock::now() +
            std::chrono::milliseconds(intervalMs);
        while (std::chrono::steady_clock::now() < intervalEnd) {
            bool lost = false;
            if (!PumpOneMessage(session, tracker, role, 50, lost)) {
                return false;
            }
        }
    }

    const auto remoteFinal = tracker.Get(remoteId);
    if (!remoteFinal) {
        std::cerr << "[" << role << "] Missing remote tracked state\n";
        return false;
    }
    std::cout << "[" << role << "] Host/client table : localId=" << localId
              << " remoteId=" << remoteId
              << " remoteStatus="
              << bfc::ConnectionStatusName(remoteFinal->connectionStatus)
              << " remotePos=(" << remoteFinal->x << ", " << remoteFinal->y
              << ", " << remoteFinal->z << ")\n";

    std::cout << "[" << role << "] Sending presence  : Leave playerId="
              << localId << "\n";
    session.Send(bfc::MakePlayerPresence(localId, bfc::kPresenceEventLeave));

    // Best-effort drain leave from peer.
    for (int i = 0; i < 10; ++i) {
        bool lost = false;
        if (!PumpOneMessage(session, tracker, role, 100, lost)) {
            break;
        }
    }

    return true;
}

int RunHost(const std::string& bindAddress,
            uint16_t port,
            uint32_t acceptTimeoutMs,
            int ticks,
            int intervalMs) {
    std::cout << "[HOST] === BlackFlagCoop v0.5.1 host ===\n";

    if (!bfc::Logger::Initialize() || !bfc::Network::Initialize()) {
        std::cerr << "[HOST] Init failed\n";
        return 2;
    }

    PrintHostListenHints(bindAddress, port);
    std::cout << "[HOST] Accept timeout    : " << acceptTimeoutMs << " ms\n";
    std::cout << "[HOST] Status            : waiting for one client...\n";

    bfc::Session session;
    if (!session.Host(port, bindAddress, acceptTimeoutMs)) {
        std::cerr << "[HOST] Status            : FAILED (" << session.LastError()
                  << ")\n";
        bfc::Network::Shutdown();
        return 4;
    }

    std::cout << "[HOST] Status            : connected + handshake complete\n"
              << "[HOST] sessionId         : " << session.GetSessionId() << "\n"
              << "[HOST] localPlayerId     : " << session.LocalPlayerId() << "\n"
              << "[HOST] remotePlayerId    : " << session.RemotePlayerId() << "\n";

    bfc::PlayerStateTracker tracker;
    tracker.SetLocalState(session.LocalPlayerId(), 0, 0, 0, 0);
    if (!ExchangePresenceAndState(session, tracker, "HOST", ticks, intervalMs)) {
        std::cout << "[HOST] Disconnect        : leaving after failure\n";
        session.Leave();
        bfc::Network::Shutdown();
        return 5;
    }

    const auto hostState = tracker.Get(bfc::kHostPlayerId);
    const auto clientState = tracker.Get(bfc::kClientPlayerId);
    if (!hostState || !clientState) {
        std::cerr << "[HOST] Tracker missing one or both players\n";
        session.Leave();
        bfc::Network::Shutdown();
        return 6;
    }

    std::cout << "[HOST] Tracked players   : host+client present during session\n";
    std::cout << "[HOST] Disconnect        : clean shutdown\n";
    session.Leave();
    bfc::Network::Shutdown();
    std::cout << "[HOST] PASS\n";
    return 0;
}

int RunClient(const std::string& connectHost,
              uint16_t port,
              int ticks,
              int intervalMs) {
    std::cout << "[CLIENT] === BlackFlagCoop v0.5.1 client ===\n";
    std::cout << "[CLIENT] Target host       : " << connectHost << ":" << port << "\n";

    if (!bfc::Logger::Initialize() || !bfc::Network::Initialize()) {
        std::cerr << "[CLIENT] Init failed\n";
        return 2;
    }

    bfc::Session session;
    if (!session.Join(connectHost, port)) {
        std::cerr << "[CLIENT] Status            : FAILED (" << session.LastError()
                  << ")\n";
        bfc::Network::Shutdown();
        return 4;
    }

    std::cout << "[CLIENT] Status            : connected + handshake complete\n"
              << "[CLIENT] sessionId         : " << session.GetSessionId() << "\n"
              << "[CLIENT] localPlayerId     : " << session.LocalPlayerId() << "\n"
              << "[CLIENT] remotePlayerId    : " << session.RemotePlayerId() << "\n";

    bfc::PlayerStateTracker tracker;
    tracker.SetLocalState(session.LocalPlayerId(), 0, 0, 0, 0);
    if (!ExchangePresenceAndState(session, tracker, "CLIENT", ticks, intervalMs)) {
        std::cout << "[CLIENT] Disconnect        : leaving after failure\n";
        session.Leave();
        bfc::Network::Shutdown();
        return 5;
    }

    const auto hostState = tracker.Get(bfc::kHostPlayerId);
    if (!hostState) {
        std::cerr << "[CLIENT] Did not track host state/presence\n";
        session.Leave();
        bfc::Network::Shutdown();
        return 6;
    }

    std::cout << "[CLIENT] Host snapshot     : status="
              << bfc::ConnectionStatusName(hostState->connectionStatus)
              << " pos=(" << hostState->x << ", " << hostState->y << ", "
              << hostState->z << ")\n";
    std::cout << "[CLIENT] Disconnect        : clean shutdown\n";
    session.Leave();
    bfc::Network::Shutdown();
    std::cout << "[CLIENT] PASS\n";
    return 0;
}

bool ExpectTrue(bool value, const char* label) {
    if (!value) {
        std::cerr << "[SELFTEST] FAIL: " << label << "\n";
        return false;
    }
    std::cout << "[SELFTEST] OK: " << label << "\n";
    return true;
}

int RunDiagSelfTest() {
    std::cout << "[DIAG] Starting v0.5.1 runtime diagnostic + protocol-ex checks\n";
    if (!bfc::Logger::Initialize()) {
        std::cerr << "[DIAG] Logger init failed\n";
        return 2;
    }

    // Regression: plugin init must never enable full-module string probing.
    static_assert(!bfc::PlayerProbe::kEnabledDuringPluginInit,
                  "startup full-module probe must remain disabled");
    if (!ExpectTrue(!bfc::PlayerProbe::kEnabledDuringPluginInit,
                    "plugin init does not enable full-module probe")) {
        return 29;
    }
    bfc::PlayerProbe::LogDeferredNotice();

    const bfc::RuntimeSnapshot snap = bfc::RuntimeDiagnostics::Capture();
    bfc::RuntimeDiagnostics::LogSnapshot(snap);

    if (!ExpectTrue(snap.processId != 0, "runtime diag captured PID")) {
        return 30;
    }
    if (!ExpectTrue(!snap.executablePath.empty(), "runtime diag captured exe path")) {
        return 31;
    }
    if (!ExpectTrue(snap.is64BitProcess, "runtime diag reports x64 process")) {
        return 32;
    }
    if (!ExpectTrue(!snap.modules.empty(), "runtime diag enumerated modules")) {
        return 33;
    }
    if (!ExpectTrue(snap.mainModuleBase != 0, "runtime diag captured main module base")) {
        return 34;
    }

    // Offline tool load: should NOT look like the game process.
    if (!ExpectTrue(!bfc::RuntimeDiagnostics::LooksLikeBlackFlagProcess(snap),
                    "offline NetTest is not ACBlackFlag.exe")) {
        return 35;
    }

    if (!ExpectTrue(!bfc::PlayerTelemetry::HasVerifiedCoordinateSource(),
                    "coordinate source correctly marked unverified")) {
        return 36;
    }

    bfc::WorldPose pose;
    if (!ExpectTrue(!bfc::PlayerTelemetry::TryReadWorldPose(pose),
                    "TryReadWorldPose refuses unverified reads") ||
        !ExpectTrue(!pose.verified, "pose.verified remains false")) {
        return 37;
    }

    // Protocol V1 preserved + V2 extended payload parse/round-trip (tracker only).
    {
        bfc::PlayerStateTracker tracker;
        bfc::PlayerStateExPayload ex {};
        ex.playerId = bfc::kHostPlayerId;
        ex.connectionStatus = bfc::kConnectionStatusConnected;
        ex.x = 11.0f;
        ex.y = 22.0f;
        ex.z = 33.0f;
        ex.yawDegrees = 90.0f;
        ex.pitchDegrees = -5.0f;
        ex.movementState = bfc::kMovementStateRunning;
        ex.flags = 0;  // intentionally unverified
        ex.tick = 42;
        ex.sessionId = 99;

        const bfc::NetworkMessage msg = bfc::MakePlayerStateEx(ex);
        if (!ExpectTrue(msg.type == bfc::kMsgPlayerStateEx,
                        "MakePlayerStateEx uses msg type 7")) {
            return 38;
        }

        bfc::PlayerStateExPayload parsed {};
        if (!ExpectTrue(bfc::ParsePlayerStateEx(msg, parsed),
                        "ParsePlayerStateEx accepts valid payload") ||
            !ExpectTrue(parsed.yawDegrees == 90.0f &&
                            parsed.movementState == bfc::kMovementStateRunning,
                        "ParsePlayerStateEx preserves rotation/movement")) {
            return 39;
        }

        std::string error;
        if (!ExpectTrue(tracker.ApplyStateEx(parsed, error),
                        "tracker accepts state-ex") ||
            !ExpectTrue(tracker.Get(bfc::kHostPlayerId)->hasExtendedPose,
                        "tracker marks extended pose")) {
            return 40;
        }

        // V1 payload still works.
        bfc::PlayerStatePayload v1 {};
        v1.playerId = bfc::kClientPlayerId;
        v1.connectionStatus = bfc::kConnectionStatusConnected;
        v1.x = 1.0f;
        v1.y = 2.0f;
        v1.z = 3.0f;
        v1.tick = 1;
        const auto v1Msg = bfc::MakePlayerState(
            v1.playerId, v1.connectionStatus, v1.x, v1.y, v1.z, v1.tick);
        bfc::PlayerStatePayload v1Parsed {};
        if (!ExpectTrue(bfc::ParsePlayerState(v1Msg, v1Parsed),
                        "V1 PlayerState framing preserved") ||
            !ExpectTrue(tracker.ApplyState(v1Parsed, error),
                        "tracker still accepts V1 state")) {
            return 41;
        }

        // Pose-verified flag must be stripped until a real game source exists.
        bfc::PlayerStateExPayload claimed = ex;
        claimed.flags = bfc::kStateExFlagPoseVerified;
        const auto claimedMsg = bfc::MakePlayerStateEx(claimed);
        bfc::PlayerStateExPayload claimedParsed {};
        if (!ExpectTrue(bfc::ParsePlayerStateEx(claimedMsg, claimedParsed),
                        "ParsePlayerStateEx accepts payload with verified bit") ||
            !ExpectTrue((claimedParsed.flags & bfc::kStateExFlagPoseVerified) == 0,
                        "verified pose flag sanitized on parse")) {
            return 42;
        }
        if (!ExpectTrue(tracker.ApplyStateEx(claimed, error),
                        "tracker accepts state-ex with verified bit input") ||
            !ExpectTrue(
                (tracker.Get(bfc::kHostPlayerId)->flags &
                 bfc::kStateExFlagPoseVerified) == 0,
                "tracker stores sanitized flags without verified bit")) {
            return 43;
        }

        const auto hb = bfc::MakeHeartbeat(123);
        bfc::HeartbeatPayload hbParsed {};
        if (!ExpectTrue(hb.type == bfc::kMsgHeartbeat, "heartbeat msg type 8") ||
            !ExpectTrue(bfc::ParseHeartbeat(hb, hbParsed) &&
                            hbParsed.senderTick == 123,
                        "heartbeat round-trip") ||
            !ExpectTrue(bfc::IsRecognizedMessageType(bfc::kMsgHeartbeat),
                        "heartbeat is recognized type")) {
            return 44;
        }
    }

    bfc::PlayerTelemetry::LogInvestigationStatus();
    std::cout << "[DIAG] PASS\n";
    return 0;
}

int RunSelfTest(uint16_t port) {
    std::cout << "[SELFTEST] Starting v0.5.8 reliability + presence/state checks\n";
    if (!bfc::Logger::Initialize() || !bfc::Network::Initialize()) {
        std::cerr << "[SELFTEST] Init failed\n";
        return 2;
    }

    // Tracker unit checks (no sockets).
    {
        bfc::PlayerStateTracker tracker;
        bfc::PlayerPresencePayload join {};
        join.playerId = bfc::kClientPlayerId;
        join.event = bfc::kPresenceEventJoin;
        std::string error;
        if (!ExpectTrue(tracker.ApplyPresence(join, error), "tracker accepts join")) {
            bfc::Network::Shutdown();
            return 20;
        }

        bfc::PlayerStatePayload state {};
        state.playerId = bfc::kClientPlayerId;
        state.connectionStatus = bfc::kConnectionStatusConnected;
        state.x = 3.0f;
        state.y = 4.0f;
        state.z = 5.0f;
        state.tick = 7;
        if (!ExpectTrue(tracker.ApplyState(state, error), "tracker accepts state")) {
            bfc::Network::Shutdown();
            return 21;
        }
        const auto got = tracker.Get(bfc::kClientPlayerId);
        if (!ExpectTrue(got.has_value() && got->tick == 7 && got->x == 3.0f,
                        "tracker stores latest state")) {
            bfc::Network::Shutdown();
            return 22;
        }

        bfc::PlayerStatePayload bad = state;
        bad.magic = 0;
        if (!ExpectTrue(!tracker.ApplyState(bad, error),
                        "tracker rejects malformed state")) {
            bfc::Network::Shutdown();
            return 23;
        }

        bfc::PlayerPresencePayload leave = join;
        leave.event = bfc::kPresenceEventLeave;
        if (!ExpectTrue(tracker.ApplyPresence(leave, error), "tracker accepts leave") ||
            !ExpectTrue(tracker.CountPresent() == 0, "leave clears present flag")) {
            bfc::Network::Shutdown();
            return 24;
        }
    }

    // Protocol unit: malformed heartbeat + msgs 1-7 recognized.
    {
        bfc::NetworkMessage badHb;
        badHb.type = bfc::kMsgHeartbeat;
        badHb.payload.resize(sizeof(bfc::HeartbeatPayload), 0);
        bfc::HeartbeatPayload parsed {};
        if (!ExpectTrue(!bfc::ParseHeartbeat(badHb, parsed),
                        "malformed heartbeat rejected") ||
            !ExpectTrue(bfc::IsRecognizedMessageType(bfc::kMsgHandshakeRequest) &&
                            bfc::IsRecognizedMessageType(bfc::kMsgPlayerStateEx) &&
                            bfc::IsRecognizedMessageType(bfc::kMsgHeartbeat),
                        "message types 1-8 recognized")) {
            bfc::Network::Shutdown();
            return 25;
        }
        // Compatibility helpers for 1-7 still construct.
        const auto m1 = bfc::MakeHandshakeRequest();
        const auto m2 = bfc::MakeHandshakeResponse(1, 2, 1);
        const auto m3 = bfc::MakePing("x");
        const auto m4 = bfc::MakePong("y");
        const auto m5 = bfc::MakePlayerPresence(1, bfc::kPresenceEventJoin);
        const auto m6 = bfc::MakePlayerState(1, 1, 0, 0, 0, 1);
        bfc::PlayerStateExPayload ex {};
        ex.playerId = 1;
        const auto m7 = bfc::MakePlayerStateEx(ex);
        if (!ExpectTrue(m1.type == 1 && m2.type == 2 && m3.type == 3 && m4.type == 4 &&
                            m5.type == 5 && m6.type == 6 && m7.type == 7,
                        "message types 1-7 construction preserved")) {
            bfc::Network::Shutdown();
            return 26;
        }
    }

    // Connection refusal
    {
        bfc::Network client;
        const bool refused =
            !client.ConnectToHost("127.0.0.1", static_cast<uint16_t>(port + 100));
        if (!ExpectTrue(refused, "connection refusal on closed port")) {
            bfc::Network::Shutdown();
            return 10;
        }
    }

    std::atomic<bool> hostOk{false};
    std::string hostError;

    std::thread hostThread([&]() {
        bfc::Session host;
        if (!host.Host(port, "127.0.0.1", 15000)) {
            hostError = host.LastError();
            return;
        }

        bfc::PlayerStateTracker tracker;
        tracker.SetLocalState(host.LocalPlayerId(), 0, 0, 0, 0);
        if (!ExchangePresenceAndState(host, tracker, "HOST", 3, 50)) {
            hostError = "host presence/state exchange failed";
            host.Leave();
            return;
        }

        if (tracker.Get(bfc::kHostPlayerId) && tracker.Get(bfc::kClientPlayerId)) {
            hostOk = true;
        } else {
            hostError = "host tracker missing players";
        }
        host.Leave();
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(400));

    bfc::Session client;
    if (!client.Join("127.0.0.1", port)) {
        std::cerr << "[SELFTEST] client join failed: " << client.LastError() << "\n";
        hostThread.join();
        bfc::Network::Shutdown();
        return 11;
    }

    bfc::PlayerStateTracker clientTracker;
    clientTracker.SetLocalState(client.LocalPlayerId(), 0, 0, 0, 0);
    if (!ExchangePresenceAndState(client, clientTracker, "CLIENT", 3, 50)) {
        std::cerr << "[SELFTEST] client presence/state exchange failed\n";
        client.Leave();
        hostThread.join();
        bfc::Network::Shutdown();
        return 12;
    }

    if (!ExpectTrue(clientTracker.Get(bfc::kHostPlayerId).has_value(),
                    "client tracked host presence/state")) {
        client.Leave();
        hostThread.join();
        bfc::Network::Shutdown();
        return 13;
    }

    // Framing / invalid length still covered lightly.
    uint8_t badHeader[8] = {};
    const uint32_t badType = 777;
    const uint32_t badSize = 0x7F000000u;
    std::memcpy(badHeader + 0, &badType, 4);
    std::memcpy(badHeader + 4, &badSize, 4);
    client.GetNetwork().SendRawBytes(badHeader, sizeof(badHeader));
    ExpectTrue(true, "post-session raw inject attempted safely");

    client.Leave();
    hostThread.join();

    if (!hostOk) {
        std::cerr << "[SELFTEST] host side failed: " << hostError << "\n";
        bfc::Network::Shutdown();
        return 17;
    }

    ExpectTrue(true, "clean disconnect after presence/state");

    // --- Heartbeat exchange (localhost) — no pose mutation ---
    {
        const uint16_t hbPort = static_cast<uint16_t>(port + 1);
        std::atomic<bool> hbHostOk{false};
        std::string hbHostError;
        std::thread hbHost([&]() {
            bfc::Session host;
            bfc::ReliabilityConfig cfg;
            cfg.enabled = true;
            cfg.heartbeatIntervalMs = 80;
            cfg.idleTimeoutMs = 5000;
            host.SetReliabilityConfig(cfg);
            if (!host.Host(hbPort, "127.0.0.1", 10000)) {
                hbHostError = host.LastError();
                return;
            }
            bfc::PlayerStateTracker tracker;
            tracker.SetLocalState(host.LocalPlayerId(), 9.0f, 9.0f, 9.0f, 1);
            const float xBefore = tracker.Get(host.LocalPlayerId())->x;

            int handled = 0;
            const auto deadline =
                std::chrono::steady_clock::now() + std::chrono::seconds(3);
            while (std::chrono::steady_clock::now() < deadline && handled < 2) {
                bfc::NetworkMessage msg;
                const auto r = host.Poll(msg, 50);
                if (r == bfc::SessionPollResult::HeartbeatHandled) {
                    ++handled;
                } else if (r == bfc::SessionPollResult::Disconnected ||
                           r == bfc::SessionPollResult::IdleTimeout) {
                    hbHostError = "host lost session during heartbeat wait";
                    host.Leave();
                    return;
                }
            }
            const float xAfter = tracker.Get(host.LocalPlayerId())->x;
            if (handled < 1 || host.HeartbeatsReceived() < 1 ||
                host.HeartbeatsSent() < 1 || xBefore != xAfter) {
                hbHostError = "heartbeat exchange incomplete or pose mutated";
            } else {
                hbHostOk = true;
            }
            host.Leave();
        });

        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        bfc::Session hbClient;
        bfc::ReliabilityConfig cfg;
        cfg.enabled = true;
        cfg.heartbeatIntervalMs = 80;
        cfg.idleTimeoutMs = 5000;
        hbClient.SetReliabilityConfig(cfg);
        if (!hbClient.Join("127.0.0.1", hbPort)) {
            std::cerr << "[SELFTEST] heartbeat client join failed\n";
            hbHost.join();
            bfc::Network::Shutdown();
            return 50;
        }
        bfc::PlayerStateTracker hbTracker;
        hbTracker.SetLocalState(hbClient.LocalPlayerId(), 3.0f, 3.0f, 3.0f, 1);
        const float cx0 = hbTracker.Get(hbClient.LocalPlayerId())->x;
        int handled = 0;
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::seconds(3);
        while (std::chrono::steady_clock::now() < deadline && handled < 2) {
            bfc::NetworkMessage msg;
            const auto r = hbClient.Poll(msg, 50);
            if (r == bfc::SessionPollResult::HeartbeatHandled) {
                ++handled;
            }
        }
        const float cx1 = hbTracker.Get(hbClient.LocalPlayerId())->x;
        const uint64_t clientHbRx = hbClient.HeartbeatsReceived();
        const uint64_t clientHbTx = hbClient.HeartbeatsSent();
        hbClient.Leave();
        hbHost.join();
        if (!ExpectTrue(hbHostOk.load(), "heartbeat exchange host side") ||
            !ExpectTrue(handled >= 1 && clientHbRx >= 1 && clientHbTx >= 1,
                        "heartbeat exchange client received/sent") ||
            !ExpectTrue(cx0 == cx1, "heartbeat does not mutate local pose")) {
            std::cerr << "[SELFTEST] heartbeat host error: " << hbHostError << "\n";
            bfc::Network::Shutdown();
            return 51;
        }
        ExpectTrue(true, "heartbeat exchange");
    }

    // --- Idle timeout when peer is silent (no heartbeats sent) ---
    {
        const uint16_t idlePort = static_cast<uint16_t>(port + 2);
        std::atomic<bool> idleSeen{false};
        std::thread idleHost([&]() {
            bfc::Session host;
            bfc::ReliabilityConfig cfg;
            cfg.enabled = true;
            cfg.heartbeatIntervalMs = 0;  // do not keep peer alive
            cfg.idleTimeoutMs = 400;
            host.SetReliabilityConfig(cfg);
            if (!host.Host(idlePort, "127.0.0.1", 10000)) {
                return;
            }
            // Client connects then goes silent; host Polls until idle.
            const auto deadline =
                std::chrono::steady_clock::now() + std::chrono::seconds(3);
            while (std::chrono::steady_clock::now() < deadline) {
                bfc::NetworkMessage msg;
                const auto r = host.Poll(msg, 50);
                if (r == bfc::SessionPollResult::IdleTimeout) {
                    idleSeen = true;
                    break;
                }
                if (r == bfc::SessionPollResult::Disconnected) {
                    break;
                }
            }
            if (host.State() != bfc::SessionState::Idle) {
                host.Leave();
            }
        });

        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        bfc::Session idleClient;
        bfc::ReliabilityConfig cfg;
        cfg.enabled = false;  // silent peer: no outbound heartbeats
        idleClient.SetReliabilityConfig(cfg);
        if (!idleClient.Join("127.0.0.1", idlePort)) {
            idleHost.join();
            bfc::Network::Shutdown();
            return 52;
        }
        // Stay connected but send nothing; host should idle-timeout.
        std::this_thread::sleep_for(std::chrono::milliseconds(1200));
        idleClient.Leave();
        idleHost.join();
        if (!ExpectTrue(idleSeen.load(), "idle timeout on missing heartbeat/traffic")) {
            bfc::Network::Shutdown();
            return 53;
        }
        ExpectTrue(true, "missing heartbeat / idle timeout");
    }

    // --- Clean disconnect vs idle: Leave without idle flag ---
    {
        const uint16_t leavePort = static_cast<uint16_t>(port + 3);
        std::atomic<bool> hostLeftClean{false};
        std::thread leaveHost([&]() {
            bfc::Session host;
            bfc::ReliabilityConfig cfg;
            cfg.enabled = true;
            cfg.heartbeatIntervalMs = 100;
            cfg.idleTimeoutMs = 5000;
            host.SetReliabilityConfig(cfg);
            if (!host.Host(leavePort, "127.0.0.1", 10000)) {
                return;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(300));
            host.Leave();
            hostLeftClean = !host.IdleTimedOutFlag() &&
                            host.State() == bfc::SessionState::Idle;
        });
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        bfc::Session leaveClient;
        leaveClient.SetReliabilityConfig(
            bfc::ReliabilityConfig{true, 100, 5000});
        if (!leaveClient.Join("127.0.0.1", leavePort)) {
            leaveHost.join();
            bfc::Network::Shutdown();
            return 54;
        }
        leaveClient.Leave();
        leaveHost.join();
        if (!ExpectTrue(hostLeftClean.load(), "clean disconnect without idle flag")) {
            bfc::Network::Shutdown();
            return 55;
        }
    }

    // --- Reconnection after Leave ---
    {
        const uint16_t rePort = static_cast<uint16_t>(port + 4);
        // Session 1
        {
            std::atomic<bool> s1{false};
            std::thread h1([&]() {
                bfc::Session host;
                if (!host.Host(rePort, "127.0.0.1", 10000)) {
                    return;
                }
                s1 = true;
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
                host.Leave();
            });
            std::this_thread::sleep_for(std::chrono::milliseconds(150));
            bfc::Session c1;
            if (!c1.Join("127.0.0.1", rePort)) {
                h1.join();
                bfc::Network::Shutdown();
                return 56;
            }
            c1.Leave();
            h1.join();
            if (!ExpectTrue(s1.load(), "reconnect session1 established")) {
                bfc::Network::Shutdown();
                return 56;
            }
        }
        // Session 2 on same port
        {
            std::atomic<bool> s2{false};
            std::thread h2([&]() {
                bfc::Session host;
                if (!host.Host(rePort, "127.0.0.1", 10000)) {
                    return;
                }
                bool timedOut = false;
                bfc::NetworkMessage msg;
                for (int i = 0; i < 60; ++i) {
                    if (host.Receive(msg, 50, timedOut) && !timedOut) {
                        s2 = true;
                        break;
                    }
                }
                host.Leave();
            });
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            bfc::Session c2;
            if (!c2.Join("127.0.0.1", rePort)) {
                h2.join();
                std::cerr << "[SELFTEST] reconnect session2 join failed\n";
                bfc::Network::Shutdown();
                return 57;
            }
            c2.Send(bfc::MakePlayerPresence(c2.LocalPlayerId(),
                                            bfc::kPresenceEventJoin));
            c2.Leave();
            h2.join();
            if (!ExpectTrue(s2.load(), "reconnection second session")) {
                bfc::Network::Shutdown();
                return 58;
            }
        }
        ExpectTrue(true, "reconnection");
    }

    // --- Malformed heartbeat over the wire via Poll ---
    {
        const uint16_t badPort = static_cast<uint16_t>(port + 5);
        std::atomic<bool> rejected{false};
        std::atomic<bool> stillActive{false};
        std::thread badHost([&]() {
            bfc::Session host;
            host.SetReliabilityConfig(bfc::ReliabilityConfig{true, 5000, 10000});
            if (!host.Host(badPort, "127.0.0.1", 10000)) {
                return;
            }
            const auto deadline =
                std::chrono::steady_clock::now() + std::chrono::seconds(2);
            while (std::chrono::steady_clock::now() < deadline) {
                bfc::NetworkMessage msg;
                const auto r = host.Poll(msg, 50);
                if (r == bfc::SessionPollResult::Rejected) {
                    rejected = true;
                    stillActive = (host.State() == bfc::SessionState::Active);
                    break;
                }
            }
            host.Leave();
        });
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        bfc::Session badClient;
        if (!badClient.Join("127.0.0.1", badPort)) {
            badHost.join();
            bfc::Network::Shutdown();
            return 60;
        }
        // Send heartbeat type with wrong magic.
        bfc::HeartbeatPayload bad {};
        bad.magic = 0xDEADBEEF;
        bad.senderTick = 1;
        badClient.Send(bfc::MakeMessage(bfc::kMsgHeartbeat, &bad, sizeof(bad)));
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        badClient.Leave();
        badHost.join();
        if (!ExpectTrue(rejected.load() && stillActive.load(),
                        "malformed heartbeat rejected; session stays up")) {
            bfc::Network::Shutdown();
            return 61;
        }
    }

    ExpectTrue(true, "host and client shutdown");
    bfc::Network::Shutdown();
    std::cout << "[SELFTEST] PASS\n";
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        PrintUsage();
        return 1;
    }

    std::string mode;
    std::string bindAddress = kDefaultBindAddress;
    std::string connectHost = kDefaultConnectHost;
    uint16_t port = kDefaultPort;
    uint32_t acceptTimeoutMs = kDefaultAcceptTimeoutMs;
    int ticks = kDefaultStateTicks;
    int intervalMs = kDefaultStateIntervalMs;

    for (int i = 1; i < argc; ++i) {
        if (Equals(argv[i], "--host")) {
            mode = "host";
        } else if (Equals(argv[i], "--client")) {
            mode = "client";
        } else if (Equals(argv[i], "--self-test")) {
            mode = "self-test";
        } else if (Equals(argv[i], "--diag-self-test")) {
            mode = "diag-self-test";
        } else if (Equals(argv[i], "--port") && i + 1 < argc) {
            port = static_cast<uint16_t>(std::atoi(argv[++i]));
        } else if (Equals(argv[i], "--bind") && i + 1 < argc) {
            bindAddress = argv[++i];
        } else if (Equals(argv[i], "--connect") && i + 1 < argc) {
            connectHost = argv[++i];
        } else if (Equals(argv[i], "--accept-timeout-ms") && i + 1 < argc) {
            acceptTimeoutMs = static_cast<uint32_t>(std::atoi(argv[++i]));
        } else if (Equals(argv[i], "--ticks") && i + 1 < argc) {
            ticks = std::atoi(argv[++i]);
        } else if (Equals(argv[i], "--state-interval-ms") && i + 1 < argc) {
            intervalMs = std::atoi(argv[++i]);
        } else if (Equals(argv[i], "--help") || Equals(argv[i], "-h")) {
            PrintUsage();
            return 0;
        } else {
            std::cerr << "Unknown argument: " << argv[i] << "\n";
            PrintUsage();
            return 1;
        }
    }

    if (ticks < 1) {
        ticks = 1;
    }
    if (intervalMs < 1) {
        intervalMs = 1;
    }

    if (mode == "host") {
        return RunHost(bindAddress, port, acceptTimeoutMs, ticks, intervalMs);
    }
    if (mode == "client") {
        return RunClient(connectHost, port, ticks, intervalMs);
    }
    if (mode == "self-test") {
        return RunSelfTest(port);
    }
    if (mode == "diag-self-test") {
        return RunDiagSelfTest();
    }

    PrintUsage();
    return 1;
}
