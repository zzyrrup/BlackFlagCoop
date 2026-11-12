# BlackFlagCoop — ChatGPT Handoff

**Last updated:** 2026-11-12  
**Machine:** PC1 only  
**Repo:** https://github.com/zzyrrup/BlackFlagCoop  
**Branch:** `cursor/v070-pc1-smoke-5709` (PR into `cursor/v070-session-panel-ba61`; do not push main)  
**Initial commit:** `e12e70150656ac80742f10b496f7e5556e7985b7`

This document is the primary human-readable bridge between Cursor (local execution) and ChatGPT (review / next instructions). Update it after every completed milestone.

---

## 1. Project identity and goals

| Item | Value |
|------|--------|
| Project | BlackFlagCoop |
| Goal | Research and eventually enable co-op for Assassin's Creed Black Flag Resynced (two Edwards / shared world / LAN–internet) |
| Nature | Experimental ASI + offline PE research; not a shipped mod yet |
| Roles | **Cursor** = local code, builds, tests, commits. **ChatGPT** = review pushed evidence, plan next milestone |

Ultimate vision is **not claimed as achieved**. Dual-Edward co-op remains unproven.

---

## 2. Current development milestone

**v0.7.0 one-time PC1 smoke recorded** — gated co-op session roster panel (`0.7.0-dev`).

The panel logs an idle two-slot roster from `InitializeASI` and draws a click-through sidebar only when `BFC_SESSION_PANEL=1`. It does not open a socket, spawn an actor, or claim an in-world Edward. The candidate `EF7EB82D…` was installed for one launch and then removed. The installed file is v0.5.1 again. The ASI loaded. The playable world was not confirmed on screen. Details: `docs/v0.7.0-pc1-smoke.md`.

---

## 3. Current ASI version and SHA256

| Item | Value |
|------|--------|
| Working in-game ASI | **v0.5.1** |
| Installed ASI SHA256 | `63B38877DDA7CC7CD9AB2619F94D3941C37F54C95A435EFE47084DC4CF2A50BE` (re-read 2026-11-12, 99840 bytes) |
| Candidate ASI | `0.7.0-dev` at `build/bin/Release/BlackFlagCoop.asi` |
| Candidate SHA256 | `EF7EB82D3F6CAAB00BFBED350BACCCFD0A2D88E56F8D023BFD62821C3C7262A0` (112640 bytes) |
| Deploy status | v0.5.1 restored after the one authorized smoke. Do not replace it again without a new approval |

---

## 4. Current game target

| Item | Value |
|------|--------|
| Game | Assassin's Creed Black Flag Resynced |
| Version | **1.0.6** |
| Executable | `ACBlackFlag.exe` |
| EXE SHA256 | `19920F34BB2FAC814023EE3C27F0CECA1872E80A2AAFB37C092C419FFF77CC0D` |
| Analysis mode preference | Offline PE for research tracks; no live memory unless explicitly authorized |

---

## 5. Build instructions

```powershell
cd C:\Users\Frees\OneDrive\Documents\BlackFlagCoop
# x64 developer environment (VS 18 2026), then:
cmake -S . -B build -G "Visual Studio 18 2026" -A x64
cmake --build build --config Release
```

- Generator: **Visual Studio 18 2026**
- Arch: **x64**
- Output ASI (local build only): `build/bin/Release/BlackFlagCoop.asi` — not for auto-deploy

---

## 6. Network architecture and LAN test status

- Plugin networking: custom BFC TCP session (messages 1–8, heartbeat, poseVerified sanitize). v0.7.0 does not change the wire protocol and does not open a session from `InitializeASI`.
- Tools: `tools/net_test`, scripts under `scripts/` (`Run-LanHost.ps1`, `Run-LanClient.ps1`, etc.).
- Reliability work landed in **v0.5.8** era (heartbeat/idle tests in net_test).
- Plugin net ≠ engine replication. PC2 / production deploy not part of current handoff setup.
- **Do not change networking** unless a milestone explicitly authorizes it.

---

## 7. Current known game-engine findings

High-signal offline findings (see `docs/v0.6.*` and `reports/v0.6.*`):

- Harbour / schema / telemetry pipeline researched through v0.6.1.
- **v0.6.2:** No PlayerController/LocalPlayer/Possess/SplitScreen-style layer recovered; deferred-create + Pad_* leads only.
- **v0.6.3:** `0x187F0550` = thin `Pad_LockAndTurnMovement` bind wrapper → helper `0x18EADD0`. `0x5CBDFB0` = frame-phase **registrar**, not factory. Registered handler for `CreateActorsDeferredSingleThreaded` = **`0x1AC380`**.
- **v0.6.4:** `0x1AC380` = deferred **queue processor** (`[obj+0xAC0]` / count `[+0xAC8]&0x3FFF`, stride 0x10); per-element `0x725400` / `0xE95E80`. Not proven as Edward/character factory. `0x7B00B60` / `0x29C6910` unlinked beyond phase table. Action vtable `0x9255320` installed by descriptor ctors; no verified input→character path.
- **v0.6.5:** Each 16-byte slot is an **object pointer at +0** plus a handler-written **f32 score at +8** (compared with 25.0). `+0xC` is unreferenced. Workers receive the object pointer, not the slot. `0x725400` is a shared flag/hash-list helper. `0xE95E80` is queue-only and attaches a **0x160** side block at `object+0x98`. No character/Edward/archetype edge. Handler body ends at `0x1AC61F` (671 bytes); v0.6.4's `0x1ACA4A` included the next function.
- **v0.6.6:** Enqueue helper **`0x2E97B60(coordinator, object)`** appends the pointer with the same `0x3FFF`/`0xFFFFC000`/stride-`0x10` packing and zeros slot+8. Sole callers are three sites in wrapper **`0x2E97FC0`**, which then **`or [object+0x61], 4`** (bit cleared later by `0x725400`). Wrapper has no direct `E8` callers (likely phase dispatch). Still no Edward/create path.

---

## 8. Confirmed facts versus hypotheses

### Confirmed

- Working ASI in field is v0.5.1 (`63B38877…`).
- `0x5CBDFB0` registers phase names/handlers; does not create actors.
- `0x1AC380` is the registered CreateActorsDeferredSingleThreaded handler and processes a deferred element array. Its body ends at `0x1AC61F` (671 bytes).
- Slot `+0` is an object pointer. Slot `+8` is an `f32` score written by the handler and compared with 25.0. Slot `+0xC` is not interpreted by the handler or either worker.
- `0x725400(object, dl)` edits `object+0x61` and can unlink that pointer from a 0x18-stride hashed list. Direct callers also exist outside the handler, with `dl = 0`.
- `0xE95E80(object)` is called only from `0x1AC4DB` and `0x1AC523`. It allocates 0x160 bytes and stores the block at `object+0x98` with a back-pointer at `block+0x100`.
- `0x2E97B60` is the deferred-queue **enqueue** helper; `0x2E97FC0` is its only wrapper caller set; post-enqueue sets `object+0x61` bit 2.
- Input lead `0x187F0550` is action-name bind, not a movement controller.
- No verified shared entity/ownership edge between input bind path and deferred handler.
- No Edward, character, archetype, player, or transform string in either worker or the producer wrapper.

### Hypotheses (not confirmed)

- The queued object is an actor or character.
- The 0x160 side block is activation state for that object.
- `0x2E97FC0` is registered as a frame phase like `0x1AC380`.
- Dual Edward / dual input context is feasible somewhere else in the engine.

### Disproven on this path

- The workers are called with the 16-byte slot address.
- Element `+8` is an input transform.
- The slot contains a callback pointer or an archetype id.
- `0xE95E80` finishes a character/Edward spawn.

---

## 9. Current blockers

- No confirmed character/Edward factory or archetype reuse path. Queue only enqueues/activates existing objects.
- Subject type / RTTI for enqueued objects still unknown.
- Registration/dispatch of wrapper `0x2E97FC0` not yet recovered.
- No verified input→character ownership/control binding.
- No safe authorized spawn/possession test design yet.
- GitHub handoff must stay free of ASI/game binaries.

---

## 10. Most recent completed milestone

**v0.7.0 — Session roster panel (automated only)**

Deliverables:

- `docs/v0.7.0-implementation-plan.md`
- `docs/v0.7.0-manual-pc1-checklist.md`
- `reports/v0.7.0-validation.json`
- `reports/v0.7.0-build-log.txt`
- `reports/v0.7.0-session-panel-test.txt`
- `src/ui/session_panel.*`, `src/ui/session_overlay.*`
- `tools/session_panel_test/main.cpp`

v0.6.6 producer reports were left in place.

**Prior completed research: v0.6.6 — Deferred queue producers**

Deliverables:

- `docs/v0.6.6-deferred-queue-producers.md`
- `reports/v0.6.6-enqueue-helper.json`
- `reports/v0.6.6-producer-scan-summary.json`
- `reports/v0.6.6-second-edward-feasibility.json`
- `reports/v066-raw/evidence.txt`
- `tools/offline/QueueProducer066/`

v0.6.4 and v0.6.5 reports were left in place.

---

## 11. Next recommended milestone

**One PC1 smoke (done, not passed):** `docs/v0.7.0-pc1-smoke.md`. The candidate loaded and was removed. The world was not confirmed. Do not launch again unless Cruz asks.

**Next code step after a passing look:** feed `SessionPanelInput` from a localhost `Session` so the roster can show Connected / Disconnected. Still no actor spawn.

Offline v0.6.7 (dispatch of `0x2E97FC0` and subject RTTI) stays a separate research track. It is not required to explain this panel.

---

## 12. Files changed in the latest milestone

- `CMakeLists.txt`
- `src/main.cpp`
- `src/ui/session_panel.h`
- `src/ui/session_panel.cpp`
- `src/ui/session_overlay.h`
- `src/ui/session_overlay.cpp`
- `tools/session_panel_test/main.cpp`
- `docs/v0.7.0-implementation-plan.md`
- `docs/v0.7.0-manual-pc1-checklist.md`
- `reports/v0.7.0-validation.json`
- `reports/v0.7.0-build-log.txt`
- `reports/v0.7.0-session-panel-test.txt`
- `docs/v0.7.0-pc1-smoke.md`
- `reports/v0.7.0-pc1-smoke.json`
- `docs/CHATGPT_HANDOFF.md`
- `reports/CHATGPT_HANDOFF.json`

---

## 13. Tests performed and their results

| Test | Result |
|------|--------|
| `ctest -C Release` SessionPanel | Pass (1/1) |
| `BlackFlagCoopSessionPanelTest` | Pass (`ALL PASSED`) |
| VS 18 2026 x64 Release build | Pass, 0 warnings |
| Installed ASI hash re-read | Restored v0.5.1 `63B38877…` (99840 bytes) |
| One PC1 launch of candidate `EF7EB82D…` | ASI loaded (`0.7.0-dev`). World not confirmed. Not repeated |
| Spawn / inject / live memory | **Not performed** |
| Network protocol changes | **None** |

---

## 14. Safety / deployment status

- PC1 only; PC2 untouched.
- `ACBlackFlag.exe` hash unchanged. The candidate ASI was installed for one launch and restored to v0.5.1.
- Campaign `AutoSave01` bytes unchanged. The pre-test backup is in `backups/v070-smoke-20261112-123002\`.
- No force-push; no credential commits.

---

## 15. Exact instructions for ChatGPT's next review

When reviewing the GitHub repository after a Cursor push:

1. Read this file, `reports/CHATGPT_HANDOFF.json`, `reports/v0.7.0-validation.json`, and `docs/v0.7.0-pc1-smoke.md` first.
2. Treat the session panel as a UI placeholder. Do not describe it as a second Edward.
3. The candidate ASI loaded on one PC1 launch. The playable world was not confirmed. Do not treat that launch as co-op.
4. Do not instruct another gameplay launch, PC2 test, or LAN test unless Cruz explicitly asks.
5. v0.6.7 RTTI/dispatch research remains optional and separate. Do not treat the deferred queue as character creation.
6. Do not instruct Cursor to leave the candidate installed, spawn, or use live memory.
7. Return instructions Cursor can execute verbatim on PC1 on a dedicated branch + PR (never push main).
