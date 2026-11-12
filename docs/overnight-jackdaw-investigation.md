# Overnight — Jackdaw & Shared World Architecture

**Date:** 2026-11-12  
**Mode:** offline string / schema harvest  
**Safety:** no ship behavior or asset modification

## Verified

| Needle | Hits | Notes |
|--------|------|-------|
| `Jackdaw` | ≥1 | Literal ship name in packed string table (`.edata` ~`0xA104B4F`) |
| `ShipKill` / `ShipDespawn` | ≥3 each | Signal/composition names (`ShipKillSignal`, `ShipDespawnSignal`) |
| `ShipLoadout` | ≥3 | Custom composition with ship attributes (e.g. broadside cannons) |
| `Naval*` | ≥8 | Difficulty / conflict context (`NavalDifficulty`, `NavalConflict`) |
| `Boarding` | ≥8 | Includes `CLBoardingRealization::Orientating` — boarding realization class exists |
| `CaptainCamera*` | ≥4 | Telemetry ints for captain-camera time/uses |
| `ShipWeapon*` | ≥4 | Schema attributes |
| `Crew*` | ≥8 | Includes `CrewRoleGameSaveDataEntry` — crew roles persist in saves |

## Shared Jackdaw with two players aboard?

| Question | Verdict |
|----------|---------|
| Jackdaw treated as a named world/ship entity in data? | **Plausible** (explicit name + ship signals) |
| Engine support for two independent characters aboard one ship? | **Unknown / unproven** |
| Vehicle possession / dual helm APIs found? | **Not under searched needles** |
| Theoretical shared networked ship entity? | Only as a **future BFC-synced object** mirroring host ship transform + boarding state — **not** engine-native co-op |

## Conclusion

Naval/ship systems are rich in telemetry and realization code. That supports **studying** Jackdaw as a sync candidate later. It does **not** establish shared ownership or dual-player ship control tonight.

## Next safe offline experiment

Expand ship composition harvest (`custom.Ship*`); locate boarding state enums near `CLBoardingRealization` via RTTI/string adjacency — offline only.
