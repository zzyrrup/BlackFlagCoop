#include "ui/session_panel.h"

#include <iostream>
#include <string>

namespace {

int g_failed = 0;

void Expect(bool condition, const char* name) {
    if (condition) {
        std::cout << "PASS " << name << "\n";
        return;
    }
    std::cout << "FAIL " << name << "\n";
    ++g_failed;
}

void ExpectContains(const std::string& haystack, const char* needle, const char* name) {
    Expect(haystack.find(needle) != std::string::npos, name);
}

void ExpectAbsent(const std::string& haystack, const char* needle, const char* name) {
    Expect(haystack.find(needle) == std::string::npos, name);
}

void ExpectNoEdward(const bfc::SessionPanelSnapshot& snapshot, const std::string& text,
                    const char* name) {
    const bool ok = !bfc::SessionPanelClaimsInWorldEdward(snapshot) &&
                    !snapshot.player1.inWorldEdward && !snapshot.player2.inWorldEdward &&
                    text.find("Edward: not spawned") != std::string::npos &&
                    text.find("Edward: spawned") == std::string::npos &&
                    text.find("Player 2 is a session slot only") != std::string::npos;
    Expect(ok, name);
}

bfc::SessionPanelInput HostWaiting() {
    bfc::SessionPanelInput input;
    input.sessionState = bfc::SessionState::Hosting;
    input.role = bfc::NetworkRole::Host;
    input.sessionId = 42;
    input.localPlayerId = bfc::kHostPlayerId;
    input.remotePlayerId = bfc::kClientPlayerId;
    return input;
}

}  // namespace

int main() {
    std::cout << "BlackFlagCoopSessionPanelTest " << bfc::kSessionPanelVersion << "\n";

    {
        const auto input = bfc::MakeIdleSessionPanelInput();
        const auto snapshot = bfc::BuildSessionPanel(input);
        const std::string text = bfc::RenderSessionPanel(snapshot);
        Expect(snapshot.pluginVersion == bfc::kSessionPanelVersion, "idle version");
        ExpectContains(text, "Role: Idle", "idle role");
        ExpectContains(text, "State: Idle", "idle state");
        ExpectContains(text, "Session: none", "idle session");
        ExpectContains(text, "Connection: not started", "idle connection");
        ExpectContains(text, "Slot 1 | Player 1 | Unassigned | Not joined | Ready: n/a",
                       "idle slot 1");
        ExpectContains(text, "Slot 2 | Player 2 | Unassigned | Not joined | Ready: n/a",
                       "idle slot 2");
        ExpectNoEdward(snapshot, text, "idle has no edward");
        Expect(text == bfc::RenderSessionPanel(bfc::BuildSessionPanel(input)),
               "idle render is stable");
    }

    {
        bfc::SessionPanelInput input = bfc::MakeIdleSessionPanelInput();
        input.localReady = true;
        input.remoteReady = true;
        const auto snapshot = bfc::BuildSessionPanel(input);
        const std::string text = bfc::RenderSessionPanel(snapshot);
        ExpectContains(text, "Slot 1 | Player 1 | Unassigned | Not joined | Ready: n/a",
                       "idle ignores local ready");
        ExpectContains(text, "Slot 2 | Player 2 | Unassigned | Not joined | Ready: n/a",
                       "idle ignores remote ready");
        ExpectNoEdward(snapshot, text, "ready flags do not spawn edward");
    }

    {
        const auto snapshot = bfc::BuildSessionPanel(HostWaiting());
        const std::string text = bfc::RenderSessionPanel(snapshot);
        ExpectContains(text, "Role: Host", "host role");
        ExpectContains(text, "State: Hosting", "host state");
        ExpectContains(text, "Session: 42", "host session id");
        ExpectContains(text, "Connection: hosting; waiting for player 2", "host waiting");
        ExpectContains(text, "Slot 1 | Player 1 | Local | Connected | Ready: not ready",
                       "host local not ready");
        ExpectContains(text, "Slot 2 | Player 2 | Remote | Not joined | Ready: n/a",
                       "host remote not joined");
        ExpectNoEdward(snapshot, text, "host waiting has no edward");
    }

    {
        bfc::SessionPanelInput input = HostWaiting();
        input.sessionState = bfc::SessionState::Active;
        input.remoteSeen = true;
        input.remoteJoined = true;
        input.remoteConnectionStatus = bfc::kConnectionStatusConnected;
        input.localReady = true;
        const auto snapshot = bfc::BuildSessionPanel(input);
        const std::string text = bfc::RenderSessionPanel(snapshot);
        ExpectContains(text, "Connection: player 2 connected", "active connection");
        ExpectContains(text, "Slot 1 | Player 1 | Local | Connected | Ready: ready",
                       "active local ready");
        ExpectContains(text,
                       "Slot 2 | Player 2 | Remote | Connected | Ready: not ready",
                       "active remote not ready");
        Expect(snapshot.player1.playerId == bfc::kHostPlayerId, "player 1 id");
        Expect(snapshot.player2.playerId == bfc::kClientPlayerId, "player 2 id");
        ExpectNoEdward(snapshot, text, "active session has no edward");
    }

    {
        bfc::SessionPanelInput input;
        input.sessionState = bfc::SessionState::Active;
        input.role = bfc::NetworkRole::Client;
        input.sessionId = 99;
        input.localPlayerId = bfc::kClientPlayerId;
        input.remotePlayerId = bfc::kHostPlayerId;
        input.remoteSeen = true;
        input.remoteJoined = true;
        input.remoteConnectionStatus = bfc::kConnectionStatusConnected;
        input.remoteReady = true;
        const auto snapshot = bfc::BuildSessionPanel(input);
        const std::string text = bfc::RenderSessionPanel(snapshot);
        ExpectContains(text, "Role: Client", "client role");
        ExpectContains(text, "Session: 99", "client session");
        ExpectContains(text, "Slot 1 | Player 1 | Remote | Connected | Ready: ready",
                       "client sees player 1 remote");
        ExpectContains(text, "Slot 2 | Player 2 | Local | Connected | Ready: not ready",
                       "client is player 2");
        ExpectNoEdward(snapshot, text, "client view has no edward");
    }

    {
        bfc::SessionPanelInput input = HostWaiting();
        input.sessionState = bfc::SessionState::Active;
        input.remoteSeen = true;
        input.remoteJoined = false;
        input.remoteConnectionStatus = bfc::kConnectionStatusDisconnected;
        input.remoteReady = true;
        const auto snapshot = bfc::BuildSessionPanel(input);
        const std::string text = bfc::RenderSessionPanel(snapshot);
        ExpectContains(text, "Connection: player 2 disconnected", "disconnect summary");
        ExpectContains(text, "Slot 1 | Player 1 | Local | Connected | Ready: not ready",
                       "local stays connected after peer drop");
        ExpectContains(text, "Slot 2 | Player 2 | Remote | Disconnected | Ready: n/a",
                       "remote disconnect clears ready");
        ExpectNoEdward(snapshot, text, "disconnect does not spawn edward");
    }

    {
        bfc::SessionPanelInput input = HostWaiting();
        input.remoteSeen = true;
        input.remoteJoined = true;
        input.remoteConnectionStatus = bfc::kConnectionStatusLeaving;
        const auto snapshot = bfc::BuildSessionPanel(input);
        const std::string text = bfc::RenderSessionPanel(snapshot);
        ExpectContains(text, "Connection: player 2 leaving", "leaving summary");
        ExpectContains(text, "Slot 2 | Player 2 | Remote | Leaving | Ready: n/a",
                       "leaving slot");
        ExpectNoEdward(snapshot, text, "leaving has no edward");
    }

    {
        bfc::SessionPanelInput input;
        input.sessionState = bfc::SessionState::Error;
        input.role = bfc::NetworkRole::Host;
        input.sessionId = 7;
        input.localPlayerId = bfc::kHostPlayerId;
        input.lastError = "bind failed";
        const auto snapshot = bfc::BuildSessionPanel(input);
        const std::string text = bfc::RenderSessionPanel(snapshot);
        ExpectContains(text, "State: Error", "error state");
        ExpectContains(text, "Connection: error", "error connection");
        ExpectContains(text, "Error: bind failed", "error detail");
        ExpectContains(text, "Slot 1 | Player 1 | Local | Disconnected | Ready: n/a",
                       "error local disconnected");
        ExpectContains(text, "Slot 2 | Player 2 | Remote | Not joined | Ready: n/a",
                       "error remote still empty");
        ExpectNoEdward(snapshot, text, "error has no edward");
    }

    {
        using bfc::SessionPanelDisplayMode;
        Expect(bfc::ParseSessionPanelDisplayMode(nullptr) ==
                   SessionPanelDisplayMode::LogOnly,
               "null display mode is log only");
        Expect(bfc::ParseSessionPanelDisplayMode("") == SessionPanelDisplayMode::LogOnly,
               "empty display mode is log only");
        Expect(bfc::ParseSessionPanelDisplayMode("0") == SessionPanelDisplayMode::LogOnly,
               "zero display mode is log only");
        Expect(bfc::ParseSessionPanelDisplayMode("off") == SessionPanelDisplayMode::LogOnly,
               "off display mode is log only");
        Expect(bfc::ParseSessionPanelDisplayMode("log") == SessionPanelDisplayMode::LogOnly,
               "log display mode is log only");
        Expect(bfc::ParseSessionPanelDisplayMode("surprise") ==
                   SessionPanelDisplayMode::LogOnly,
               "unknown display mode is log only");
        Expect(bfc::ParseSessionPanelDisplayMode("1") == SessionPanelDisplayMode::Overlay,
               "1 enables overlay");
        Expect(bfc::ParseSessionPanelDisplayMode("on") == SessionPanelDisplayMode::Overlay,
               "on enables overlay");
        Expect(bfc::ParseSessionPanelDisplayMode("overlay") ==
                   SessionPanelDisplayMode::Overlay,
               "overlay enables overlay");
        Expect(bfc::ParseSessionPanelDisplayMode("TRUE") ==
                   SessionPanelDisplayMode::Overlay,
               "TRUE enables overlay");
    }

    if (g_failed != 0) {
        std::cout << "FAILED " << g_failed << " assertion(s)\n";
        return 1;
    }
    std::cout << "ALL PASSED\n";
    return 0;
}
