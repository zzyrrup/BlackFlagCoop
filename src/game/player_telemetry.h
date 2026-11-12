#pragma once

#include <cstdint>
#include <string>

namespace bfc {

// Verified-or-not gate for reading real Edward world pose from the game.
// Until a data source is proven, TryRead returns false and never invents coords.
struct WorldPose {
    float x = 0.0f;
    float y = 0.0f;
    float z = 0.0f;
    float yawDegrees = 0.0f;
    float pitchDegrees = 0.0f;
    std::uint32_t movementState = 0;
    bool verified = false;
    std::string sourceDescription;
};

class PlayerTelemetry {
public:
    // Logs investigation status: symbols/exports/RTTI availability notes,
    // and explicitly states that coordinates are unverified.
    static void LogInvestigationStatus();

    // Read-only pose read. Returns false until a verified source exists.
    static bool TryReadWorldPose(WorldPose& outPose);

    static bool HasVerifiedCoordinateSource();
};

}  // namespace bfc
