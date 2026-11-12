# BlackFlagCoop — ChatGPT Handoff

**Last updated:** 2026-11-12  
**Machine:** PC1 only  
**Repo:** https://github.com/zzyrrup/BlackFlagCoop  
**Branch:** `cursor/v065-deferred-queue-worker-007d` (based on `main` at `441bd67`)  
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

**v0.6.5 complete** — Deferred queue worker and 16-byte element layout (`0x725400`, `0xE95E80`).

Offline only. No ASI, spawn, or networking change.

---

## 3. Current ASI version and SHA256

| Item | Value |
|------|--------|
| Working in-game ASI | **v0.5.1** |
| ASI SHA256 | `63B38877DDA7CC7CD9AB2619F94D3941C37F54C95A435EFE47084DC4CF2A50BE` |
| Deploy status | **Do not replace** without explicit user approval |

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

- Plugin networking: custom BFC TCP session (messages 1–8, heartbeat, poseVerified sanitize).
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

---

## 8. Confirmed facts versus hypotheses

### Confirmed

- Working ASI in field is v0.5.1 (`63B38877…`).
- `0x5CBDFB0` registers phase names/handlers; does not create actors.
- `0x1AC380` is the registered CreateActorsDeferredSingleThreaded handler and processes a deferred element array. Its body ends at `0x1AC61F` (671 bytes).
- Slot `+0` is an object pointer. Slot `+8` is an `f32` score written by the handler and compared with 25.0. Slot `+0xC` is not interpreted by the handler or either worker.
- `0x725400(object, dl)` edits `object+0x61` and can unlink that pointer from a 0x18-stride hashed list. Direct callers also exist outside the handler, with `dl = 0`.
- `0xE95E80(object)` is called only from `0x1AC4DB` and `0x1AC523`. It allocates 0x160 bytes and stores the block at `object+0x98` with a back-pointer at `block+0x100`.
- Input lead `0x187F0550` is action-name bind, not a movement controller.
- No verified shared entity/ownership edge between input bind path and deferred handler.
- No Edward, character, archetype, player, or transform string in either worker.

### Hypotheses (not confirmed)

- The queued object is an actor or character.
- The 0x160 side block is activation state for that object.
- A producer outside this queue creates the object before the pointer is stored.
- Dual Edward / dual input context is feasible somewhere else in the engine.

### Disproven on this path

- The workers are called with the 16-byte slot address.
- Element `+8` is an input transform.
- The slot contains a callback pointer or an archetype id.
- `0xE95E80` finishes a character/Edward spawn.

---

## 9. Current blockers

- No confirmed character/Edward factory or archetype reuse path. This queue consumes existing object pointers.
- The producer that stores those pointers at `[coordinator+0xAC0]` is not yet decoded.
- No verified input→character ownership/control binding.
- No safe authorized spawn/possession test design yet.
- GitHub handoff must stay free of ASI/game binaries.

---

## 10. Most recent completed milestone

**v0.6.5 — Deferred queue worker and 16-byte element layout**

Deliverables:

- `docs/v0.6.5-deferred-queue-worker-analysis.md`
- `reports/v0.6.5-queue-element-layout.json`
- `reports/v0.6.5-worker-disassembly.json`
- `reports/v0.6.5-worker-callgraph.json`
- `reports/v0.6.5-actor-lifecycle-connections.json`
- `reports/v0.6.5-second-edward-feasibility.json`
- `tools/offline/QueueWorker065/` (offline decoder; Iced 1.21)

v0.6.4 reports were left in place.

---

## 11. Next recommended milestone

**v0.6.6 (proposed):** Offline-find the producers that **store** the object pointer into `[coordinator+0xAC0]`. That is the first place a create-versus-enqueue distinction can be made. Still no spawn, no deploy, no networking changes unless separately authorized.

---

## 12. Files changed in the latest milestone

- `docs/v0.6.5-deferred-queue-worker-analysis.md`
- `reports/v0.6.5-queue-element-layout.json`
- `reports/v0.6.5-worker-disassembly.json`
- `reports/v0.6.5-worker-callgraph.json`
- `reports/v0.6.5-actor-lifecycle-connections.json`
- `reports/v0.6.5-second-edward-feasibility.json`
- `tools/offline/QueueWorker065/Program.cs`
- `tools/offline/QueueWorker065/QueueWorker065.csproj`
- `docs/CHATGPT_HANDOFF.md`
- `reports/CHATGPT_HANDOFF.json`
- `.gitignore` (ignore `tools/offline/**/bin` and `obj`)

---

## 13. Tests performed and their results

| Test | Result |
|------|--------|
| Offline decode v0.6.5 (`QueueWorker065`, Iced 1.21) | EXE SHA256 matched. Call sites `0x1AC4D3` → `0x725400` and `0x1AC4DB` → `0xE95E80` landed on real instructions. Reports written. |
| Game launch / ASI deploy | **Not performed** |
| Spawn / inject / live memory | **Not performed** |
| Network protocol changes | **None** |

---

## 14. Safety / deployment status

- PC1 only; PC2 untouched.
- Game installs unmodified by this handoff work.
- ASI v0.5.1 preserved; no deployment.
- Backups preserved locally; excluded from Git.
- No force-push; no credential commits.

---

## 15. Exact instructions for ChatGPT's next review

When reviewing the GitHub repository after a Cursor push:

1. Read this file and `reports/CHATGPT_HANDOFF.json` first.
2. Diff against the previous handoff `milestoneId` / commit.
3. Treat only **confirmed** items as facts; keep hypotheses labeled.
4. Propose the **next single milestone** with: objective, in-scope RVAs/files, out-of-scope (spawn/deploy/PC2), required deliverables paths, and acceptance checks.
5. Prefer **v0.6.6**: offline producers of the object pointer stored at `[coordinator+0xAC0]`, unless new evidence supersedes. Do not treat the phase name as proof of actor creation.
6. Do not instruct Cursor to deploy ASI or modify the game unless the user explicitly overrides safety.
7. Return instructions Cursor can execute verbatim on PC1.
