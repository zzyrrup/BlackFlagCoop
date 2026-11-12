# Overnight — Mission & Campaign Synchronization

**Date:** 2026-11-12  
**Mode:** offline string harvest only  
**Safety:** no save edits, no progression changes, no game launch

## Verified

| Needle | Hits | Notes |
|--------|------|-------|
| `Objective` | ≥8 | Runtime error text for `QuestObjectiveInstance` / `QuestInstance` key mismatches — real quest-objective machinery |
| `QuestStep` / `QuestStepKey` | ≥6 | Telemetry schema string attributes |
| `MainQuestsCompleted` | ≥2 | Typed int telemetry attribute |
| `Checkpoint` | ≥8 | Mix of DominoCheckpoint + named location checkpoints |
| `SaveGame*` | ≥8 | Save compatibility / save-data entry naming |
| `Progression` | ≥8 | Includes online season progression / scimitar Online types |
| `Cutscene` | ≥1 | `DialogueResumeCutscene` |
| `Mission` | ≥3 | Mixed (“Out Of Mission”, session wording) — weaker as a sole API name |
| Composition `QuestCancelSignal` | context extract | `custom.questupdate` composition path |

## Shared vs local progression

| Question | Verdict |
|----------|---------|
| Host-authoritative campaign sync reusable from engine MP? | **Not evidenced** (no replication layer) |
| Quest/objective state exists as first-class systems? | **Yes** (instance keys, objectives, quest steps, save entries) |
| Feasible co-op approach (hypothesis only) | Host tracks objective/checkpoint events via future telemetry or mission hooks; client mirrors UI/state — **unverified** |

## Explicit non-claims

- No verified mission ownership API for two local Edwards.  
- No safe sync of saves between PCs established.  
- Telemetry fields like `MainQuestsCompleted` prove **schema interest**, not a live host→client pipeline.

## Next safe offline experiment

Catalog Domino / quest signal compositions adjacent to `QuestCancelSignal`; map save-data entry names for campaign-critical blobs — still read-only PE analysis.
