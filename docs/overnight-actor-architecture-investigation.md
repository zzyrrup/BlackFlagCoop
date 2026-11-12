# Overnight — Actor Creation & Character Architecture

**Date:** 2026-11-12  
**Mode:** offline string / context harvest in `ACBlackFlag.exe` `.edata`  
**Evidence source:** `reports/overnight-multitrack-string-harvest.json`, `reports/overnight-key-context-extracts.json`

## Safety

No spawn attempts, no injection, no live process access, no asset edits.

## Verified string evidence

| Needle | Hits | Interpretation |
|--------|------|----------------|
| `CreateActorsDeferred` | ≥1 | Update-phase label `CreateActorsDeferredSingleThreaded` among AI/job update stages — suggests deferred actor create exists in the frame pipeline |
| `DestroyActors` | ≥1 (via `DestroyActor` prefix) | Appears in Havok/swarm operator naming (`DestroyActors.SwarmLinkEvaluators…`) — not proven as a player API |
| `EntityId` | ≥4 | Telemetry/schema field names (e.g. `EnemyAtkDamagingEntityId`) — entity IDs exist as **telemetry attributes**, not proven as spawn handles |
| `Archetype` | ≥8 | Combat/target schema fields (`EnemyTgtArchetype`, etc.) |
| `Npc` | ≥1 | Noise/false-positive-prone binary fragment; **do not treat as Edward actor definition** |

## Absent / negative results

- No `ActorFactory`, `CharacterFactory`, `SpawnActor`, `PlayerCharacter`, `LocalPlayer` string hits in the harvested `.edata` scan window.  
- No proven Edward → actor-definition binding beyond prior v0.5.6 edward-entity link analysis (still unproven).

## Dual-Edward assessment

| Question | Verdict |
|----------|---------|
| Does the engine appear to have *some* multi-actor create/destroy pipeline? | **Plausible** (deferred create + destroy-related names) |
| Evidence of two concurrent playable Edward instances? | **None** |
| Evidence player vs NPC actor factory split? | **Insufficient** (`NPC` hit was `NPCRulesetEntry` in Havok/property tables, not player spawning) |
| Safe to attempt spawn overnight? | **No** (explicitly forbidden; architecture not mapped) |

## Conclusion

The executable contains **pipeline vocabulary** consistent with multi-actor simulation (deferred creation, entity IDs, archetypes). That is **not** evidence that two independently controlled Edwards are supported or that factories are reachable for co-op. Treat dual-Edward as an open research problem, not an engine feature.

## Next safe offline experiment

Map call graphs into `CreateActorsDeferred*` phase handlers via relative xrefs; catalog any character template / Domino spawn nodes near mission scripts — still without runtime spawn.
