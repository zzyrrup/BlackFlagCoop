# BlackFlagCoop Overnight Research Log

**Started:** 2026-11-12 (local)  
**Working ASI:** v0.5.1 (do not deploy)  
**Mode:** offline only

## Session rules reminder
- No game launch/deploy/inject/live memory
- No guessed offsets in ASI
- Preserve prior reports/backups

---

## Work log

### Harbour / Track 1 (v0.5.7)
- Classified Harbour StringId exports → `reports/v0.5.7-harbour-stringid-static.json`
- Find / DumpTo / LoadFrom / ClearUnsafe: likely real prologues
- Insert + GetIdentifier*: stubs (`xor eax,eax; ret`)
- Schema parser / producer / Edward binding: **not identified**
- Doc: `docs/v0.5.7-harbour-stringid-schema-parser.md`

### Multi-track string harvest
- `reports/overnight-multitrack-string-harvest.json`
- `reports/overnight-key-context-extracts.json`
- Docs: actor, control, network-replication, campaign, jackdaw, milestone-recommendations

### Track 8 — networking (plugin only)
- Added `kMsgHeartbeat` (type 8), `HeartbeatPayload`, parse helpers
- `SanitizePlayerStateExFlags` on Parse/Apply/SetLocal StateEx
- `IsRecognizedMessageType`
- Extended `BlackFlagCoopNetTest --diag-self-test` (verified-bit strip + heartbeat)
- Files: `src/network/protocol.h`, `src/network/player_state.cpp`, `tools/net_test/main.cpp`
- Compatibility: msgs 1–6 unchanged; msg 7 still valid; msg 8 additive

### Failures / dead ends
- Absolute VA string xrefs for PlayerPos* already negative (prior); not re-proven overnight as producer
- No engine Replicat/HasAuthority/PlayerController/SplitScreen
- `NPC` / `DestroyActor` string hits are Havok/swarm-adjacent — not player spawn APIs
- `Multiplayer` string = UBI service parameters, not actor replication

### Tests
- Release build: `BlackFlagCoopNetTest` OK
- `--diag-self-test` → **PASS** (includes verified-flag sanitize + heartbeat)
- `--self-test` → **PASS** (LAN presence/state regression)

### Safety checks
- `ACBlackFlag.exe` SHA256 `19920F34…77CC0D` unchanged
- Game `BlackFlagCoop.asi` SHA256 `63B38877…A50BE` = known **v0.5.1** (not replaced overnight)
- No ASI deploy from this session; NetTest-only rebuild
- Backups directory intact (5 backup dirs)
- Overnight docs written; prior v0.5.x docs preserved
- No live game process memory access

---

## Follow-on: v0.5.8 (same day)

### Workstream A — networking reliability
- `ReliabilityConfig` + `Session::Poll` heartbeat / idle timeout (steady_clock)
- Defaults: 5s heartbeat / 30s idle; disabled unless enabled
- Docs: `docs/v0.5.8-network-reliability.md`
- Tests: `--diag-self-test` PASS, `--self-test` PASS (localhost only)

### Workstream B — Harbour call-graph
- E8/E9 scan: **0** direct callers to Find/DumpTo/LoadFrom; ClearUnsafe has 1 E9 inbound
- Shared early callee `0x5014570` = security_check_cookie-like (huge fan-in)
- No abs-VA link to PlayerPos*/player.position
- Docs: `docs/v0.5.8-harbour-callgraph-investigation.md`
- Reports: `reports/v0.5.8-harbour-*.json`
- Game/ASI still untouched; no deploy
