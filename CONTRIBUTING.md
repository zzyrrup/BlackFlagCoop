# Contributing to BlackFlagCoop

Thanks for helping bring cooperative play to **Assassin's Creed Black Flag Resynced 1.0.6 (Windows x64)**.

The long-term goal is two genuine, separately rendered and independently controlled Edwards sharing the same adventure. We are early in development: a second Edward has not yet been spawned in Resynced, and playable co-op is not yet achieved.

## Useful starting points

- [Project roadmap](docs/PROJECT_ROADMAP.md)
- [Latest development update](docs/DEVELOPMENT_UPDATE_2026-11-13.md)
- [Community hub and roadmap tracker](https://github.com/zzyrrup/BlackFlagCoop/issues/45)
- [Research leads and contributor call](https://github.com/zzyrrup/BlackFlagCoop/issues/54)
- [Current entity-discovery blocker](https://github.com/zzyrrup/BlackFlagCoop/issues/47)

## Contributions we welcome

- Evidence-backed reverse-engineering of Resynced 1.0.6 x64.
- Independent review of research findings and rejected hypotheses.
- Networking, replication, input isolation, and lifecycle reviews.
- Offline tests, reproducible tools, build fixes, and documentation.
- Ideas for cooperative Jackdaw, traversal, combat, missions, and player experience.

## What makes a useful technical report

Include as many of these as apply:

1. Exact game version and executable identity/hash.
2. Function RVA, symbol, file, or reproducible search target.
3. Disassembly, call-site context, data-flow evidence, or test output.
4. The conclusion and confidence level.
5. Reproduction steps and what would falsify the hypothesis.
6. Whether the work was offline-only, built, automatically tested, or verified in-game.

Negative findings are valuable. Clearly document candidates that were investigated and rejected so others do not repeat the same dead ends.

## Reverse-engineering rules

- Resynced 1.0.6 is x64. Original AC4 x86 addresses, offsets, object layouts, and calling conventions are behavioral references only; do not transplant them.
- Do not propose native engine calls based only on nearby strings, guessed vtable slots, or unverified signatures.
- Before a native call is enabled, prove its target, arguments, ownership/lifetime, thread affinity, and cleanup behavior.
- Distinguish a real in-world Edward from an NPC, UI slot, roster entry, placeholder, or unrendered entity.
- Do not report offline scaffolding as in-game functionality.

## Code and pull requests

- Work on a dedicated branch; do not push directly to `main`.
- Keep changes focused and preserve existing research artifacts.
- Add or update automated tests for behavior that can be tested offline.
- Record exact configure/build/test commands and results.
- Use the repository's Visual Studio 18 2026 x64 CMake generator for Windows validation:

```powershell
cmake -S . -B build -G "Visual Studio 18 2026" -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

- In the PR description, state what changed, what was tested, what was not tested, and any remaining risks.

## Safety and testing boundaries

- Do not launch the game, load or modify saves, deploy an ASI, or test on a second PC unless the project owner explicitly authorizes that specific activity.
- Preserve known-good builds and user data. Avoid destructive Git operations and overwriting existing reports.
- No gameplay feature is complete until it has been demonstrated in the actual game under the agreed test process.

Thanks for helping us make the original co-op dream sail again.
