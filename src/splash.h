#pragma once

namespace bfc {

// Starts a non-activating, temporary desktop splash overlay.
// Call only from InitializeASI(), never from DllMain.
bool StartSplashScreen();

}  // namespace bfc
