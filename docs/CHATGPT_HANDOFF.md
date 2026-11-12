# BlackFlagCoop — ChatGPT Handoff

**Last updated:** 2026-11-12  
**Machine:** PC1 only  
**Repo:** https://github.com/zzyrrup/BlackFlagCoop  
**Branch:** `cursor/v074-gate-deep-typeinfo-8285` (PR into `cursor/v073-enroll-insert-gate-8285`; do not push main)  
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

**v0.6.14 complete** — Deep-decode: gate-setter `or …,0x0A` + LOD math; bit-writer child-table `+0x61` merge; membership A/B ↔ `+0x98`/worker; TypeInfo key has no inline name (lookup uses `shr key,0x38`).

Prior: v0.6.5–v0.6.13 preserved. Offline only. No ASI, spawn, or networking change.

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
- **v0.6.6:** Enqueue helper **`0x2E97B60(coordinator, object)`** appends the pointer with the same `0x3FFF`/`0xFFFFC000`/stride-`0x10` packing and zeros slot+8. Sole callers are three sites in wrapper **`0x2E97FC0`**, which then **`or [object+0x61], 4`** (bit cleared later by `0x725400`).
- **v0.6.7:** Wrapper dispatch confirmed: phase **`UpdateActorLOD`** stores stub **`0x1A5A70`** at `coord+0xE18`; stub does `add rcx,0x10; jmp 0x2E97FC0`. No direct E8/LEA/qword to the wrapper. Subject MSVC RTTI **not** recovered; field/vcall fingerprint documented. Still no Edward/create path.
- **v0.6.8:** LOD sibling **`0x67BDB30`** is a **32-byte `[arg+8]` comparator** (bundle `+0xE28`); thunk **`0x1A5A00`** at `+0xE30`. Constructor/fingerprint scan yields candidates (`0x519E20`, `0x2D4F30`, `0x1D9CC0`) but **no** recoverable MSVC RTTI for game types (EXE has ~37 `.?AV` names, CryptoPP/STL only). Still no Edward/create path.
- **v0.6.9:** Deep-decode shows **no** candidate→enqueue/worker edges. **`0x2D4F30`** is **`ClothRagdollObject`**. LOD cmp/thunk have **0** E8 callers; LEA-installed into ~22 funcs (shared bundle primitive). Still no Edward/create path.
- **v0.6.10:** Backward nested-chain/wrapper BFS (200 nodes; 81 nest seeds). Allocator **`0x426EE50`** on **21** nodes; depth-0 highlights **`0x400B50`** / **`0x4444C0`**. LOD consumers classified; **only** phase registrar installs stub+cmp+thunk at `+0xE18` bundle. Still no Edward/create path.
- **v0.6.11:** Deep-decode shows **`0x400B50`** alloc **`0x50`**, **`0x4444C0`** alloc **`0xE0`**; both use `[+0x38]→[+0x58]→[+0xA8]→[+0x3CD0]` lookup. **No** direct/caller enrollment into enqueue/wrapper. Still no Edward/create path.
- **v0.6.12:** Enrollment feeds from **hash-bucket → packed-pointer SmallArray** with gate `([obj+0x61]&6)==2`; wrapper **does not** call allocator; near-site callee `0x537C2C0` is a list scan. Shared static lookup key **`0xB2898C8`**. Still no Edward/create path.
- **v0.6.13:** `0xB2898C8` = `.trace` TypeInfo key shared with worker `0x725400`. Gate-setter **`0x53F31A0`** (`or [obj+0x61],0x0A`); bit-writer **`0xF1C240`**; candidates `0x4B5A560`/`0x4D04450`/`0x2EA0B00`. Still no Edward/create path.
- **v0.6.14:** Deep-decode confirms gate-setter/bit-writer semantics; membership leads call worker and use `+0x98`; TypeInfo has no inline name; lookup hashes key high byte. Gate-setter/bit-writer have **0** E8/LEA callers. Still no Edward/create path.

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
- `UpdateActorLOD` registers stub `0x1A5A70` which jumps to `0x2E97FC0` (wrapper dispatch).
- `0x67BDB30` (UpdateActorLOD `+0xE28`) is a 32-byte comparator on `[arg+8]`; adjacent `0x67BDB50` is a separate helper.
- Bundle thunk `0x1A5A00` (`+0xE30`) swaps args and `jmp [rax+8]`.
- LOD cmp/thunk are LEA-installed into many (~22) bundle initializers; not called via E8.
- `0x2D4F30` is a ClothRagdollObject path (fingerprint false positive for Edward).
- Fingerprint top candidates `0x519E20` / `0x2D4F30` / `0x1D9CC0` do **not** call deferred-queue helpers.
- Nested-chain + lookup + allocator depth-0 leads: `0x400B50`, `0x4444C0` — allocate `0x50`/`0xE0`; **not** enqueue enrollers.
- Only phase registrar `0x5CBDFB0` installs the full UpdateActorLOD stub+cmp+thunk bundle.
- Wrapper enrollment loads objects from preexisting packed-pointer SmallArrays (hash-bucket); **no** allocator call on that path.
- Enrollment gate before helper: `([obj+0x61] & 6) == 2`.
- Static lookup key `0xB2898C8` shared by enrollment sites `0x2E9B3D1` / `0x2E9B481`.
- `0xB2898C8` lives in `.trace` and is also referenced by worker `0x725400` (same TypeInfo family).
- Gate-setter lead `0x53F31A0` does nested lookup then `or [obj+0x61], 0x0A` (sets bit1+bit3); also LOD-like float work; no E8/LEA callers.
- `0xF1C240` selects a child from `[container+0x138]` via index `[+0x165]`, then load/`and 0xFE`/`or bl`/store on `+0x61`; uses key + `3FFF` packing; no E8/LEA callers.
- Membership `0x4B5A560` / `0x4D04450` early-out on bit1, use `+0x98`, call worker `0x725400`.
- Lookup `0x429F9E0` indexes with `shr key, 0x38`; TypeInfo blob has no inline ASCII name.
- Input lead `0x187F0550` is action-name bind, not a movement controller.
- No verified shared entity/ownership edge between input bind path and deferred handler.
- No Edward, character, archetype, player, or transform string in either worker or the producer wrapper.
- No MSVC RTTI name recovered for queued subjects offline; game/Anvil types appear RTTI-stripped on this EXE.

### Hypotheses (not confirmed)

- The queued object is an actor or character (LOD-tracked).
- The 0x160 side block is activation state for that object.
- Dual Edward / dual input context is feasible somewhere else in the engine.

### Disproven on this path

- The workers are called with the 16-byte slot address.
- Element `+8` is an input transform.
- The slot contains a callback pointer or an archetype id.
- `0xE95E80` finishes a character/Edward spawn.
- `0x2D4F30` / the v0.6.8 top fingerprint trio are the deferred-queue subject constructors.
- Wrapper `0x2E97FC0` / enrollment sites allocate the objects they enqueue (they consume preexisting packed-pointer arrays).

---

## 9. Current blockers

- No confirmed character/Edward factory or archetype reuse path. Queue only enqueues/activates existing objects.
- Subject concrete type still unknown; indirect install sites for gate-setter/bit-writer still open.
- No verified input→character ownership/control binding.
- No safe authorized spawn/possession test design yet.
- GitHub handoff must stay free of ASI/game binaries.

---

## 10. Most recent completed milestone

**v0.6.14 — Gate/insert deep-decode + TypeInfo fields**

Deliverables:

- `docs/v0.6.14-gate-deep-typeinfo.md`
- `reports/v0.6.14-typeinfo-fields.json`
- `reports/v0.6.14-leads-deep.json`
- `reports/v0.6.14-summary.json`
- `reports/v0.6.14-second-edward-feasibility.json`
- `reports/v074-raw/evidence.txt`
- `tools/offline/GateDeep074/`

v0.6.4–v0.6.13 reports were left in place.

---

## 11. Next recommended milestone

**v0.6.15 (proposed):** Offline recover **indirect install sites** for `0x53F31A0` / `0xF1C240` (vtable/bundle qword patterns); deep-decode allocator caller `0xE2C8A0` of `0x2EA0B00`. Still no spawn, deploy, live memory, or PC2 unless separately authorized.

---

## 12. Files changed in the latest milestone

- `docs/v0.6.14-gate-deep-typeinfo.md`
- `reports/v0.6.14-*.json`
- `reports/v074-raw/evidence.txt`
- `tools/offline/GateDeep074/`
- `docs/CHATGPT_HANDOFF.md`
- `reports/CHATGPT_HANDOFF.json`

---

## 13. Tests performed and their results

| Test | Result |
|------|--------|
| Offline decode v0.6.5 (`QueueWorker065`) | Pass (prior) |
| Offline producer scan v0.6.6 (`QueueProducer066`) | Pass (prior) |
| Offline dispatch v0.6.7 (`WrapperDispatch067`) | Pass; `UpdateActorLOD` → `0x1A5A70` → `0x2E97FC0` |
| Offline fingerprint/LOD v0.6.8 (`SubjectCtor068`) | Pass; `0x67BDB30` = 32 B comparator |
| Offline deep-decode v0.6.9 (`CtorDeep069`) | Pass; no candidate→queue edges; ClothRagdoll false positive |
| Offline backward/LOD v0.6.10 (`BackwardTrace070`) | Pass; allocator leads `0x400B50`/`0x4444C0`; registrar-only full LOD bundle |
| Offline alloc leads v0.6.11 (`AllocLead071`) | Pass; alloc `0x50`/`0xE0`; **no** enqueue enrollment |
| Offline enqueue feed v0.6.12 (`EnqueueFeed072`) | Pass; packed-ptr array feed; **no** allocator on enrollment path |
| Offline insert/gate v0.6.13 (`EnrollInsert073`) | Pass; key shared with worker; gate-setter `0x53F31A0`; bit-writer `0xF1C240` |
| Offline deep-decode v0.6.14 (`GateDeep074`) | Pass; gate/bit/membership semantics; TypeInfo no inline name |
| Subject MSVC RTTI name | **Not found** (game types RTTI-stripped) |
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
5. Prefer **v0.6.15**: recover indirect install sites for `0x53F31A0`/`0xF1C240`; deep-decode `0xE2C8A0`. Do not treat LOD enqueue/comparator as character creation; avoid `+0x61`-only ranking; do not rely on MSVC RTTI for game types.
6. Do not instruct Cursor to deploy ASI, spawn, use live memory, or touch PC2/save data unless the user explicitly overrides safety.
7. Return instructions Cursor can execute verbatim on PC1 on a dedicated branch + PR (never push main).
