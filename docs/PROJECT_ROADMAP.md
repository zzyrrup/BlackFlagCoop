# BlackFlagCoop — Project Roadmap

![BlackFlagCoop](../BlackFlagCoop_splash.png)

**Bringing the original Black Flag co-op vision into Black Flag Resynced.**

**Two Edwards. One Jackdaw. One shared adventure.**

Target: **Assassin's Creed Black Flag Resynced 1.0.6, Windows x64**.

BlackFlagCoop aims to become the successor to the original BlackFlagCoop project. The goal is a real co-op campaign with two separately rendered, independently controlled Edwards sharing one world.

> **Status honesty:** this is early development. A genuine second Edward has not been spawned in Resynced, independent in-game control is not implemented, and playable co-op has not been achieved. Images of the intended two-Edward Jackdaw scene are concept art, not gameplay captures.

## At a glance

| Area | Current state |
|---|---|
| x64 plugin/build foundation | Established |
| Standalone networking and localhost tests | Implemented |
| Offline protocol/replication scaffolding | Implemented and tested in isolated components |
| Input-isolation and remote-puppet lifecycle policies | Offline scaffolding; no native application |
| Original AC4 co-op spawn route | Researched as behavioral reference |
| Resynced native creation pipeline | Unresolved |
| Genuine second Edward | Not achieved |
| Independent in-game control | Not achieved |
| Two-player gameplay | Not achieved or tested |

## Milestone progression

| Milestone | Deliverable | Status |
|---|---|---|
| [0.1 Foundations](../issues/46) | x64 project, plugin, networking and offline test base | Foundations established; integration audit remains |
| [0.2 Resynced Entity Discovery](../issues/47) | Prove builder/selector, creation, world and input lifecycle | **In progress / blocker** |
| [0.3 Second Edward](../issues/48) | Genuine rendered second Edward in the world | Planned |
| [0.4 Independent Control](../issues/49) | Separate Player 2 input and movement | Planned |
| [0.5 Co-op Synchronization](../issues/50) | Replicate real player state | Planned |
| [0.6 Shared Gameplay](../issues/51) | Shared mission and cooperative systems | Planned |
| [0.7 First Playable Co-op](../issues/52) | Controlled two-player playable test | Planned |
| [1.0 Stable Release](../issues/53) | Stable, documented public release | Planned |

## Research findings worth preserving

### Original AC4 route — behavioral blueprint

The original AC4 co-op work demonstrates a useful sequence to investigate: obtain the cached player selector and EntityBuilder handle, resolve/reload the builder when needed, enter a duplication scope, duplicate the selector inside that scope, always close the scope, build an entity from the fresh selector, then enroll the puppet in the world. Input assignment must also avoid stealing the local player's pad.

This is a behavioral blueprint only. Original AC4 is x86; Resynced is x64. **No original x86 addresses, offsets, layouts, or calling conventions are being transplanted.**

### Resynced findings and negative results

- The deferred actor queue at the investigated path handles existing objects and side-block/list work; its workers were not proven to construct Edward or characters.
- A candidate virtual `+0x90` call family was rejected as selector duplication. Across 191 candidate sites there were zero unbroken return-to-build matches, and no matching Begin/End scope.
- Several apparent TypeInfo, factory, queue, and vtable candidates were classified and closed rather than promoted without evidence.
- The cache writer/owner for the player selector and EntityBuilder handle remains unresolved.
- The exact Resynced duplication/build/enrollment/input path remains unresolved.

These are useful results: they prevent repeated work on false leads and keep native calls gated until the evidence is complete.

## Existing engineering groundwork

Separate workstreams have produced offline-tested pieces for:
- A versioned peer protocol codec.
- Action/replication planning.
- Input/pad isolation policy.
- Remote-puppet lifecycle transitions.
- Session roster UI state (explicitly not an in-world character).
- Build-validation recording and automated checks.

These components are scaffolding. They do not prove native engine integration, a rendered second Edward, or playable co-op.

## Contribution wanted

We welcome:
- Evidence-backed reverse-engineering leads for Resynced 1.0.6 x64 entity/player creation.
- Independent review of the original AC4 behavior and its limits.
- Networking, synchronization, lifecycle, and input-isolation reviews.
- Offline tests, reproducible tooling, docs, and compatibility notes.
- Ideas for cooperative Jackdaw, traversal, combat, missions, and user experience.

For a technical lead, include the exact game build, function/RVA or file, evidence, reproduction steps, and what would falsify the hypothesis. Guessed offsets and unverified native calls are not actionable.

**Join the crew:** [open the community contribution call](../issues/54) or post a new issue with your idea.

## Safety and evidence rules

- Target only Resynced 1.0.6 x64.
- Native engine calls stay disabled/refused until target, arguments, ownership, thread affinity, and lifecycle are proven.
- Keep original saves and known-good installed files safe.
- Distinguish offline tests, builds, and research from in-game verification.
- No claim of co-op success until two real game instances demonstrate two Edwards, independent control, synchronization, and supported shared gameplay.

---

*The ambition is to carry the original co-op spirit forward—not to claim we've already reached the finish line.*
