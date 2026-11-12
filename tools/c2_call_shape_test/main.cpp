#include "coop/c2_call_shape.h"

#include <cstdio>

namespace {

int g_failed = 0;

void Expect(bool condition, const char* label) {
    if (condition) {
        std::printf("ok %s\n", label);
        return;
    }
    std::printf("FAIL %s\n", label);
    ++g_failed;
}

}  // namespace

int main() {
    using bfc::c2::Classify;
    using bfc::c2::EdgeKind;
    using bfc::c2::ObservedCall;

    const auto primary = Classify(bfc::c2::Site1F75EA7());
    Expect(primary.kind == EdgeKind::FourArgStaticRdx, "1F75EA7 consumer is 4-arg static rdx");
    Expect(primary.duplicateShaped, "1F75EA7 virtual call is Duplicate-shaped");
    Expect(!primary.buildShaped, "1F75EA7 is not BuildEntityWithSelector");
    Expect(!primary.callEngine, "1F75EA7 does not authorize an engine call");

    const auto handleGet = Classify(bfc::c2::Site30F1D6());
    Expect(handleGet.kind == EdgeKind::TaggedHandleGet, "30F1D6 reads [rax+0x88] and clears the tag");
    Expect(!handleGet.duplicateShaped && !handleGet.buildShaped, "30F1D6 is not Duplicate or Build");
    Expect(!handleGet.callEngine, "30F1D6 does not authorize an engine call");

    const auto sibling = Classify(bfc::c2::Site44A8A5());
    Expect(sibling.kind == primary.kind, "44A8A5 matches the same tail");
    Expect(sibling.duplicateShaped && !sibling.buildShaped, "44A8A5 is not a build");
    Expect(!sibling.callEngine, "44A8A5 does not authorize an engine call");

    // The scanner's tags on this window are different instructions.
    ObservedCall taggedDirect;
    taggedDirect.siteRva = 0x1F75EC1;
    taggedDirect.indirect = false;
    taggedDirect.edxIsZero = true;
    taggedDirect.consumerArgCount = 2;
    const auto tagged = Classify(taggedDirect);
    Expect(tagged.kind == EdgeKind::NotContract, "BF3100 tag is not Duplicate or Build");
    Expect(!tagged.duplicateShaped && !tagged.buildShaped, "direct (return, 0) is not the contract");

    ObservedCall virtualOnly;
    virtualOnly.indirect = true;
    virtualOnly.vtableSlot = 0x90;
    virtualOnly.edxIsZero = true;
    virtualOnly.r8IsZero = true;
    virtualOnly.returnNullChecked = true;
    virtualOnly.returnSaved = true;
    const auto onlyDup = Classify(virtualOnly);
    Expect(onlyDup.kind == EdgeKind::VirtualDuplicateCandidate, "slot +0x90 with no consumer stays a candidate");
    Expect(onlyDup.duplicateShaped && !onlyDup.buildShaped && !onlyDup.callEngine,
           "candidate still refuses the engine");

    ObservedCall realBuild;
    realBuild.consumerArgCount = 3;
    realBuild.consumerRdxIsStackOut = true;
    realBuild.consumerR8IsSavedReturn = true;
    realBuild.consumerHasFourthArg = false;
    const auto build = Classify(realBuild);
    Expect(build.kind == EdgeKind::BuildWithSelector, "3-arg out-pointer shape is Build");
    Expect(build.buildShaped && !build.callEngine, "build shape still refuses the engine");

    if (g_failed != 0) {
        std::printf("%d failed\n", g_failed);
        return 1;
    }
    std::printf("c2_call_shape: all checks passed\n");
    return 0;
}
