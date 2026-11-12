#include "player_telemetry.h"

#include "../logger.h"

#include <Windows.h>

#include <string>

namespace bfc {
namespace {

bool ModuleHasInterestingExports(HMODULE module, std::string& notes) {
    if (module == nullptr) {
        return false;
    }

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(module);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        notes += "DOS signature mismatch; ";
        return false;
    }

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(
        reinterpret_cast<std::uint8_t*>(module) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        notes += "NT signature mismatch; ";
        return false;
    }

    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dir.VirtualAddress == 0 || dir.Size == 0) {
        notes += "no export table; ";
        return false;
    }

    auto* exports = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
        reinterpret_cast<std::uint8_t*>(module) + dir.VirtualAddress);
    notes += "export count=" + std::to_string(exports->NumberOfNames) + "; ";
    return exports->NumberOfNames > 0;
}

}  // namespace

bool PlayerTelemetry::HasVerifiedCoordinateSource() {
    // Intentionally hard-coded false until a reproducible, evidence-backed
    // coordinate path is discovered and documented for Resynced 1.0.6.
    return false;
}

bool PlayerTelemetry::TryReadWorldPose(WorldPose& outPose) {
    outPose = {};
    outPose.verified = false;
    outPose.sourceDescription =
        "No verified Edward world-position source for Resynced 1.0.6 yet";
    return false;
}

void PlayerTelemetry::LogInvestigationStatus() {
    Logger::Info("=== Player telemetry investigation ===");
    Logger::Info(
        "Goal: locate Edward world position/rotation/movement for read-only use");
    Logger::Info(
        "Policy: do not invent offsets; do not write game memory; placeholders are not game data");

    HMODULE mainModule = GetModuleHandleW(nullptr);
    std::string exportNotes;
    const bool hasExports = ModuleHasInterestingExports(mainModule, exportNotes);
    Logger::Info(std::string("Main module export probe: ") +
                 (hasExports ? "has named exports; " : "limited/no useful exports; ") +
                 exportNotes);

    // RTTI / scripting interfaces: no public Resynced SDK. Record unknown.
    Logger::Info(
        "Official scripting/SDK interface: not present (unknown / unavailable)");
    Logger::Info(
        "RTTI / engine structure map for Edward actor: unknown (not verified)");
    Logger::Info(
        "Community trainers claim position access exists externally; those "
        "addresses are build-specific and are NOT adopted here without re-verification");

    if (HasVerifiedCoordinateSource()) {
        Logger::Info("Verified coordinate source: AVAILABLE");
    } else {
        Logger::Info("Verified coordinate source: NOT AVAILABLE");
        Logger::Info(
            "Next steps: capture live position while moving Edward using a "
            "controlled research method on pinned 1.0.6 build, then prove a "
            "stable read path before enabling telemetry");
    }

    WorldPose pose;
    if (TryReadWorldPose(pose)) {
        Logger::Info("TryReadWorldPose succeeded via " + pose.sourceDescription);
    } else {
        Logger::Info("TryReadWorldPose unavailable: " + pose.sourceDescription);
    }
    Logger::Info("=== Player telemetry investigation end ===");
}

}  // namespace bfc
