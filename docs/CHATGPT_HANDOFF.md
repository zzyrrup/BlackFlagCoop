# BlackFlagCoop — ChatGPT Handoff

**Last updated:** 2026-11-12  
**Machine:** PC1 only  
**Repo:** https://github.com/zzyrrup/BlackFlagCoop  
**Branch:** `main` (tracks `origin/main`)  
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

**v0.6.4 complete** — Deferred actor creation handler investigation (`0x1AC380`).

**Active setup milestone:** GitHub + ChatGPT handoff scaffolding (this document + rule + JSON). No gameplay/functionality change.

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

---

## 8. Confirmed facts versus hypotheses

### Confirmed

- Working ASI in field is v0.5.1 (`63B38877…`).
- `0x5CBDFB0` registers phase names/handlers; does not create actors.
- `0x1AC380` is the registered CreateActorsDeferredSingleThreaded handler and processes a deferred element array.
- Input lead `0x187F0550` is action-name bind, not a movement controller.
- No verified shared entity/ownership edge between input bind path and deferred handler.

### Hypotheses (not confirmed)

- Deferred 16-byte elements are actor/job handles.
- `0xE95E80` finishes actor creation/activation.
- Float@element+8 is transform-related.
- Dual Edward / dual input context is feasible with current engine paths.

---

## 9. Current blockers

- No confirmed character/Edward factory or archetype reuse path.
- No verified input→character ownership/control binding.
- No safe authorized spawn/possession test design yet.
- GitHub handoff must stay free of ASI/game binaries.

---

## 10. Most recent completed milestone

**v0.6.4 — Deferred Actor Creation Handler Investigation**

Deliverables:

- `docs/v0.6.4-deferred-actor-handler.md`
- `reports/v0.6.4-handler-disassembly.json`
- `reports/v0.6.4-creation-callgraph.json`
- `reports/v0.6.4-character-connections.json`
- `reports/v0.6.4-input-action-consumers.json`
- `reports/v0.6.4-second-edward-feasibility.json`

---

## 11. Next recommended milestone

**v0.6.5 (proposed):** Offline decode of per-element callees **`0xE95E80`** and **`0x725400`**, recover 16-byte element layout at `[obj+0xAC0]`. Still no spawn, no deploy, no networking changes unless separately authorized.

---

## 12. Files changed in the latest milestone

Handoff setup (this update), in addition to existing v0.6.4 research already on disk:

- `.gitignore`
- `.cursor/rules/blackflagcoop-handoff.mdc`
- `docs/CHATGPT_HANDOFF.md`
- `reports/CHATGPT_HANDOFF.json`

(v0.6.4 research files listed in section 10.)

---

## 13. Tests performed and their results

| Test | Result |
|------|--------|
| Offline PE analysis tools (v0.6.3–v0.6.4) | Ran successfully; reports written |
| Game launch / ASI deploy | **Not performed** (by design) |
| Spawn / inject / live memory | **Not performed** |
| Network protocol changes | **None** in handoff setup |

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
5. Prefer continuing **v0.6.5** offline decode of `0xE95E80` / `0x725400` unless new evidence supersedes.
6. Do not instruct Cursor to deploy ASI or modify the game unless the user explicitly overrides safety.
7. Return instructions Cursor can execute verbatim on PC1.
