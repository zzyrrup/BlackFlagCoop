# Overnight — Player Control & Input Architecture

**Date:** 2026-11-12  
**Mode:** offline string / context harvest  
**Evidence:** `reports/overnight-multitrack-string-harvest.json`, `reports/overnight-key-context-extracts.json`

## Verified

| Needle | Hits | Notes |
|--------|------|-------|
| `Pad_*` | many | Gamepad/player-input action names (`Pad_LockAndTurnMovement`, `Pad_PlayerInput_*`, `Pad_GlideSprint`) — single-player style input action table |
| `ConnectedInputDeviceList` | ≥2 | Telemetry/schema string attribute — device list reporting, not multi-controller possession API |
| `Key_PlayerInput_*` | adjacent to Pad_ | Keyboard aliases paired with pad actions |

## Absent / negative

- **No** `PlayerController`, `LocalPlayer`, `PlayerContext`, `Possess`, `Unpossess`, `ControllerId`, `GameInput`  
- **No** `SplitScreen`, `LocalCoop`, `local multiplayer`, `split screen`

## Assessment

| Question | Verdict |
|----------|---------|
| Separate player-controller instances evident? | **No evidence** |
| Input tied to a single local player action map? | **Consistent with that model** (Pad_/Key_ tables) |
| Existing local multiplayer / split-player architecture? | **No string evidence found** |
| Camera ownership / possession APIs named in cleartext? | **Not found** under searched needles |

Control appears architecturally oriented around **one local input consumer** with a rich action name table. Nothing offline establishes a second independent possession slot for a second Edward.

## Co-op implication

BlackFlagCoop must assume **plugin-side ownership of “who is player 2”** until engine multi-controller/possession APIs are proven. Do not invent Unreal-style possess hooks from missing symbols.

## Next safe offline experiment

Harvest camera / freelook / “follow target” strings; search Domino/input routing RTTI or scimitar namespaces for multi-slot player indices (still offline).
