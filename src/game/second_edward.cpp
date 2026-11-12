#include "game/second_edward.h"

#include <cstdlib>
#include <cstring>

namespace bfc {
namespace {

std::string LowerCopy(const char* value) {
    std::string out(value);
    for (char& ch : out) {
        if (ch >= 'A' && ch <= 'Z') {
            ch = static_cast<char>(ch - 'A' + 'a');
        }
    }
    return out;
}

}  // namespace

bool SecondEdwardGateEnabled(const char* value) {
    if (value == nullptr || value[0] == '\0') {
        return false;
    }
    const std::string lowered = LowerCopy(value);
    return lowered == "1" || lowered == "on" || lowered == "true";
}

SecondEdwardDecision EvaluateSecondEdward(bool gateEnabled) {
    SecondEdwardDecision decision;
    decision.gateEnabled = gateEnabled;
    decision.nativeSpawnCallable = kNativeSpawnCallable;
    decision.actorCreated = false;
    decision.player1LeftIntact = true;
    decision.candidateType = kSecondEdwardCandidateType;
    decision.missingLink =
        "SpawnNPCParams type-attach virtuals are field accessors, not a world create; leave this reflected family";
    decision.blocker = gateEnabled ? SecondEdwardBlocker::MissingCreateCallsite
                                   : SecondEdwardBlocker::GateOff;
    return decision;
}

std::string FormatSecondEdwardDecision(const SecondEdwardDecision& decision) {
    std::string line = "Second Edward ";
    line += kSecondEdwardVersion;
    line += ": ";
    if (!decision.gateEnabled) {
        line += "gate off (";
        line += kSecondEdwardGateName;
        line += " unset). ";
    } else {
        line += "gate on. REFUSED. ";
    }
    line += "Native spawn callable: no. Actor created: no. Player 1 left intact. ";
    line += "Candidate type ";
    line += decision.candidateType;
    line += " is a parameter serializer, not a character factory. Missing link: ";
    line += decision.missingLink;
    line += ".";
    return line;
}

bool SecondEdwardGateFromEnvironment() {
    char* buffer = nullptr;
    size_t length = 0;
    if (_dupenv_s(&buffer, &length, kSecondEdwardGateName) != 0 || buffer == nullptr) {
        return false;
    }
    const bool enabled = SecondEdwardGateEnabled(buffer);
    std::free(buffer);
    return enabled;
}

const SpawnParamType* FindSpawnParamType(const char* name) {
    if (name == nullptr) {
        return nullptr;
    }
    for (int i = 0; i < kSpawnParamTypeCount; ++i) {
        if (std::strcmp(kSpawnParamTypes[i].name, name) == 0) {
            return &kSpawnParamTypes[i];
        }
    }
    return nullptr;
}

}  // namespace bfc
