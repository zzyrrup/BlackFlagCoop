# Overnight — Multiplayer & Replication Architecture (Engine)

**Date:** 2026-11-12  
**Mode:** offline string / context harvest of `ACBlackFlag.exe`  
**Important:** BlackFlagCoop TCP (`src/network/*`) is **plugin networking**, not engine replication.

## Verified engine-side strings

| Needle | Hits | Context summary |
|--------|------|-----------------|
| `Multiplayer` | ≥2 | e.g. **“Multiplayer Transport Client Settings not found in the UBI Service Parameters”** — Ubisoft service config, not Anvil actor replication |
| `Matchmaking` | ≥8 | Uplay/social client names (`profilesPreciseMatchmakingClient`, Friend/Persona clients) |
| `Session` | ≥8 | Telemetry/session IDs (`gameSessionId`, `playerSessionId`) and misc session wording |
| `online.activity` | ≥2 | Composition `custom.online.activity` / OnlineActivityStopSignal |

## Absent / negative (engine)

- No `Replicat*`, `NetOwner`, `HasAuthority`, `RPC`, `ClientServer`, `ServerAuthoritative`, `NetworkId`, `NetEntity` hits in the overnight harvest.

## Assessment

| Question | Verdict |
|----------|---------|
| Reusable engine actor-replication layer found? | **No** |
| Online service / session abstractions present? | **Yes (UBI/Uplay-oriented)** — not usable as co-op state sync without reverse-engineering proprietary online stack |
| Can second-player sync reuse engine replication? | **Not evidenced** — plan on **BlackFlagCoop host-authoritative protocol** |

## Plugin networking (Track 8 note)

Overnight hardening (does **not** change engine claims):

- `kMsgHeartbeat = 8` + parse helpers (optional keepalive; peers may ignore unknown types)  
- `SanitizePlayerStateExFlags` — strips `poseVerified` until telemetry is proven  
- Regression coverage in `BlackFlagCoopNetTest --diag-self-test`  
- Handshake msgs 1–4 and V1 state msg 6 remain compatible  

## Next safe offline experiment

Continue treating engine “Multiplayer” strings as **online-service debris**. Prioritize Harbour/telemetry for pose; keep BFC protocol as the sync plane.
