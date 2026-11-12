#pragma once

#include <string>

namespace bfc {

// Opt-in desktop sidebar. Draws the already-rendered panel text.
// Does not read game memory, hook the game, or open a session socket.
// Call only from InitializeASI(), never from DllMain.
bool StartSessionPanelOverlay(const std::string& panelText);

}  // namespace bfc
