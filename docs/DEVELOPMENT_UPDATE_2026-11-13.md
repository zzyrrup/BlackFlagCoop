# BlackFlagCoop — Development Update (13 November 2026)

![BlackFlagCoop](../BlackFlagCoop_splash.png)

**Bringing the original Black Flag co-op vision into Black Flag Resynced.**

**Two Edwards. One Jackdaw. One shared adventure.**

Target: **Resynced 1.0.6 x64**.

## The vision

We want to build the successor to the original BlackFlagCoop: a genuine co-op experience where two players can share the Jackdaw and the wider adventure as two independently controlled Edwards.

The visual target is simple: one Edward at the wheel, the other beside him on deck. Concept art illustrates that goal; it is not a screenshot of working gameplay.

## Where development stands

**The foundations are real; the second Edward is still the hard problem.**

- x64 plugin/build infrastructure and safe logging/splash foundation established.
- Standalone networking and localhost host/client test foundation implemented.
- Offline protocol, action/replication, input-policy and remote-puppet lifecycle components have been developed and tested in isolation.
- Original AC4 co-op spawn behavior researched as a clean-room behavioral reference.
- Resynced entity builder/selector ownership and native character creation remain unresolved.
- No genuine second Edward has been spawned in Resynced.
- Independent in-game control and playable co-op are not yet achieved.

## Findings we've published

### 1. The original route gives us a concrete research target

The original AC4 route uses a cached player selector and EntityBuilder, a duplication scope, a fresh duplicated selector, an entity build, world enrollment, and careful input-pad isolation.

This is not permission to reuse old addresses. AC4 is x86; Resynced is x64. We are carrying forward the behavioral sequence, not its addresses or memory layouts.

### 2. We eliminated a false lead

A tempting Resynced virtual-call family at `+0x90` was investigated and rejected as the selector-duplication function: 191 candidate sites, zero unbroken return-to-build matches, and no matching Begin/End scope.

### 3. The deferred queue is not our Edward factory

The investigated deferred actor queue and workers process existing objects and side-block/list behavior. They were not proven to create a character. That closes one tempting route and redirects effort toward the actual owner/cache writer.

### 4. The critical blocker is now clearly defined

We still need evidence for:
- Who owns and writes the cached player selector and EntityBuilder handle/resource.
- The Resynced duplication/build sequence and exact argument/ownership contract.
- World enrollment, retention, removal and cleanup.
- How a second entity avoids taking Player 1's input.

Native engine calls remain off until these contracts are proven.

## Roadmap

1. **0.1 Foundations** — project, plugin, networking and offline test base.
2. **0.2 Entity Discovery** — prove the Resynced creation and enrollment path.
3. **0.3 Second Edward** — get a genuine Edward rendered in-world.
4. **0.4 Independent Control** — separate input and movement.
5. **0.5 Co-op Synchronization** — replicate real player state.
6. **0.6 Shared Gameplay** — cooperative world and mission systems.
7. **0.7 First Playable Co-op** — controlled two-player test.
8. **1.0 Stable Release** — documented, reproducible public release.

See the [full roadmap](PROJECT_ROADMAP.md) and [community hub](https://github.com/zzyrrup/BlackFlagCoop/issues/45).

## Help shape the project

We're looking for evidence-backed reverse-engineering ideas, code and test reviews, networking insight, documentation, and co-op gameplay ideas.

- [Share a research lead or contribution idea](https://github.com/zzyrrup/BlackFlagCoop/issues/54)
- [Track the entity-discovery blocker](https://github.com/zzyrrup/BlackFlagCoop/issues/47)
- [Follow the full roadmap](PROJECT_ROADMAP.md)

If you have a lead, please include the exact game build, function/RVA or file, evidence, and what would disprove the hypothesis. Good negative results are valuable too.

**Let's make the original co-op dream sail again.**
