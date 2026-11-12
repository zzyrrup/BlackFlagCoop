#pragma once

#include <cstdint>

// Offline classification of one Resynced callsite against the AC4Coop
// consumer contract. This header does not call the game.
//
// Source-confirmed contract (AC4Coop reference only, not a Resynced layout):
//   Begin(1, 0) -> selector->Duplicate(0, 0) -> End() ->
//   BuildEntityWithSelector(builder, &out, duplicate)
// Duplicate is a thiscall on the selector that returns a new pointer.
// Build takes three arguments: builder this, out-pointer, duplicated selector.
// End runs from a __finally funclet in the reference, so an in-function
// direct call is not required to recognize the other three steps.

namespace bfc::c2 {

enum class EdgeKind {
    NotContract,
    VirtualDuplicateCandidate,
    BuildWithSelector,
    FourArgStaticRdx,
    // call [vt+0x90](0,0) then [rax+0x88], low tag bit cleared.
    // Callers use that as an existing object, not as a fresh selector
    // passed into Build. Drop as RowSelector::Duplicate.
    TaggedHandleGet,
};

struct ObservedCall {
    std::uint32_t siteRva = 0;
    bool indirect = false;
    int vtableSlot = -1;
    bool edxIsZero = false;
    bool r8IsZero = false;
    bool returnNullChecked = false;
    bool returnSaved = false;
    int consumerArgCount = 0;
    bool consumerRdxIsStackOut = false;
    bool consumerR8IsSavedReturn = false;
    bool consumerHasFourthArg = false;
    // True when the next use of rax is a field load at +0x88, not a
    // store of rax itself into Build's r8.
    bool readsReturnField0x88 = false;
    bool clearsLowTagBit = false;
};

struct Verdict {
    EdgeKind kind = EdgeKind::NotContract;
    bool duplicateShaped = false;
    bool buildShaped = false;
    // Native creation stays refused until target, args, owner, thread, and
    // teardown are proven. This classifier never authorizes an engine call.
    bool callEngine = false;
};

inline Verdict Classify(const ObservedCall& call) {
    Verdict verdict;
    const bool virtualDuplicateArgs =
        call.indirect && call.vtableSlot == 0x90 && call.edxIsZero &&
        call.r8IsZero && call.returnNullChecked && call.returnSaved;
    const bool buildArgs =
        call.consumerArgCount == 3 && call.consumerRdxIsStackOut &&
        call.consumerR8IsSavedReturn && !call.consumerHasFourthArg;
    const bool fourArgStaticRdx =
        call.consumerArgCount == 4 && call.consumerHasFourthArg &&
        !call.consumerRdxIsStackOut && call.consumerR8IsSavedReturn;
    const bool taggedHandleGet =
        call.indirect && call.vtableSlot == 0x90 && call.edxIsZero &&
        call.r8IsZero && call.readsReturnField0x88 && call.clearsLowTagBit;

    if (taggedHandleGet) {
        verdict.kind = EdgeKind::TaggedHandleGet;
    } else if (virtualDuplicateArgs && fourArgStaticRdx) {
        // Duplicate-shaped call whose immediate consumer is not Build.
        verdict.kind = EdgeKind::FourArgStaticRdx;
        verdict.duplicateShaped = true;
    } else if (virtualDuplicateArgs && !buildArgs) {
        verdict.kind = EdgeKind::VirtualDuplicateCandidate;
        verdict.duplicateShaped = true;
    } else if (buildArgs) {
        verdict.kind = EdgeKind::BuildWithSelector;
        verdict.buildShaped = true;
    } else if (fourArgStaticRdx) {
        verdict.kind = EdgeKind::FourArgStaticRdx;
    }
    return verdict;
}

// The two windows below are copied from the strict-triad dump at
// cursor/v080-spawn-callers-a9fe 768ad21
// (reports/v080-triad-strict-raw/deep.txt). They are observations, not a
// claim that the slot is RowSelector::Duplicate.

inline ObservedCall Site1F75EA7() {
    ObservedCall call;
    call.siteRva = 0x1F75EA7;
    call.indirect = true;
    call.vtableSlot = 0x90;
    call.edxIsZero = true;
    call.r8IsZero = true;
    call.returnNullChecked = true;
    call.returnSaved = true;
    // Immediate consumer is 0xBF2EF0(global, rip-static, saved rax, extra).
    call.consumerArgCount = 4;
    call.consumerRdxIsStackOut = false;
    call.consumerR8IsSavedReturn = true;
    call.consumerHasFourthArg = true;
    return call;
}

// Agent 2 a12d5b1 sample. Same flag/[obj+0]/[vt+0x90](0,0) prologue as
// 0x1F75EA7, then the return is consumed as a tagged pointer at +0x88.
inline ObservedCall Site30F1D6() {
    ObservedCall call;
    call.siteRva = 0x30F1D6;
    call.indirect = true;
    call.vtableSlot = 0x90;
    call.edxIsZero = true;
    call.r8IsZero = true;
    call.readsReturnField0x88 = true;
    call.clearsLowTagBit = true;
    return call;
}

inline ObservedCall Site44A8A5() {
    ObservedCall call;
    call.siteRva = 0x44A8A5;
    call.indirect = true;
    call.vtableSlot = 0x90;
    call.edxIsZero = true;
    call.r8IsZero = true;
    call.returnNullChecked = true;
    call.returnSaved = true;
    call.consumerArgCount = 4;
    call.consumerRdxIsStackOut = false;
    call.consumerR8IsSavedReturn = true;
    call.consumerHasFourthArg = true;
    return call;
}

}  // namespace bfc::c2
