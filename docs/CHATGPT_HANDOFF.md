# BlackFlagCoop — ChatGPT Handoff

**Last updated:** 2026-11-12  
**Machine:** PC1 only  
**Repo:** https://github.com/zzyrrup/BlackFlagCoop  
**Branch:** `cursor/v080-second-edward-4d8f` (PR into `cursor/v085-vt-owner-ctors-8285`; do not push main)  
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

**v0.8.0 in review** — Spawn-parameter copy helpers have no callers and do not submit an entity. Gate `BFC_SECOND_EDWARD` stays default-off and refused. CI on `4024a28` was `pending` with zero status entries; do not treat that as a pass.

Prior: v0.6.25 complete on `cursor/v085-vt-owner-ctors-8285`. v0.6.5–v0.6.24 preserved. No deploy, no gameplay test, no networking change.

---

## 3. Current ASI version and SHA256

| Item | Value |
|------|--------|
| Working in-game ASI | **v0.5.1** (still installed; verified this milestone) |
| ASI SHA256 | `63B38877DDA7CC7CD9AB2619F94D3941C37F54C95A435EFE47084DC4CF2A50BE` |
| Candidate ASI | **v0.8.0-dev**, not deployed. SHA256 `570F0F91A4B2D4A0B37093FF55BBA601BCC3C296603FE99EF4CD780EC38040B8` (102,400 bytes) |
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
- **v0.6.15:** Gate install = `.edata 0x9490078` → `0x21085D0` → stub `0x7BB020` → `jmp 0x53F31A0` (alt `jmp 0xE95E80`). Bit-writer = `.edata` thunks `0xF1C230`/`0x210A9F0`. `0xE2C8A0` = sorted 0x18-stride ensure/insert feeding `0x2EA0B00`. Still no Edward/create path.
- **v0.6.16:** `.edata` slots consumed as vtable entries (ctors `0x2E97A50`/`0x59D9B90` install table bases). Neighbor A→`0x4D04450`/`0x725400`; neighbor B validates `[vt+0x2B0]`/`[vt+0x2B8]`; arming helper `jmp [vt+0x2B0]` with `edx=2`. Still no Edward/create path.
- **v0.6.17:** Expected `+0x2B0=0x4656C80` trampoline→`+0x2B8`; canonical `+0x2B8=0x479E3B0`; arm-table `+0x2B8=0x2108620` wraps it with `+0x98` work. Ctor A installs `0x948FF50`; ctor B installs `0x9303E28` at `+0x1D0`. Still no Edward/create path.
- **v0.6.18:** Wrap `0x2108620` modes 0–3 on side-block `+0x158` + list helpers; `.edata 0x9490208` is arm-table `+0x2B8`. Post-2B8 `0x479E440` compares mode vs `[+0x26]`. Installer A registers ctor A via LEA; installer B calls ctor B then inits through `+0xE38`. Still no Edward/create path.
- **v0.6.19:** Modes 2/3 have **no** enroll edge (≠ `+0x61` gate). `0x59D9660` = header `0xB169D0` + InstallerB at `+0x20`; outer lower bound `0x20E0`; no allocator. `AnimatedOnActiveChanged` @ `0xA179A9F` owned by `0x2335040` (also E8-calls `0x479E440`). Still no Edward/create path.
- **v0.6.20:** `0x2335040` sets `+0x26`, calls `0x479E440` + shared notify `0x8CD620`. Neighbor `0x2335140` does `edx=3` `[vt+0x2B0]`. TypeInfo size **`0xB2898E8=0x20F0`** with ctor at `0xB289918`. Still no Edward/create path.
- **v0.6.21:** No `Allocator(0x20F0)` / absolute `0xB2898E8` readers; `0x20F0` also field offsets. Helper **`0x546D150`** (491 B, 40 callers). edx=3 shares arm trampoline/wrap with edx=2. Still no Edward/create path.
- **v0.6.22:** Tight TypeInfo factories **`0x238590`/`0x256280`** (+ clones); idiom matches size/ctor fields; **no** key-tied tight site. Helper consumers: **32** funcs / **31** beyond neighbor (mostly block-copy). Still no Edward/create path.
- **v0.6.23:** Tight-factory callers do **not** LEA key/`0x20F0` (186 records, 0 hits). Helper deep-decode: `0x2336560` position extract; `0x1D25E20` spatial math — not possession. Still no Edward/create path.
- **v0.6.24:** Outer `0x59D9660` = InstallerA TypeInfo registration only (0 E8). Neighbor/Spatial = `.edata` methods; owner vtables `0x976B2D0`/`0x9236E00`. Still no Edward/create path.
- **v0.6.25:** Owner VT[0] ctors `0x13612B0`/`0x5781490` (0 E8); spat/neigh ctors init `+0x98` (enrollment side-block field). Still no Edward/create path.
- **v0.8.0:** Spawn-parameter registrars confirmed (`SpawnNPCParams` `0x80F23E0` hash `0x94D05600`, `SpawnPlayerParams` `0x80F2A20` hash `0x51BA3541`, `SpawnCharacterParams` `0x80F2330` hash `0xFB7FF6A5`). Descriptor stride `0x20`; slot +0 is `ret` `0x53741F0`; +0x10 is a field visitor; +0x18 is a params copy. **No** create/apply callsite. Candidate gate refuses the call.

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
- Gate-setter install: arming helper **`0x21085D0`** (`.edata 0x9490078`) calls stub **`0x7BB020`**, which tail-jmps to **`0x53F31A0`** (alt **`0xE95E80`**). Arming requires `+0x98==0`, nested `+0x18/+0xA8`, bit1 clear; then vcall `[vt+0x2B0]` with `edx=2`.
- Bit-writer install: `.edata` adjacent slots publish thunks **`0x210A9F0` (bit=0)** and **`0xF1C230` (bit=1)** that jmp to **`0xF1C240`**.
- `0xE2C8A0` is a sorted 0x18-stride packed-array ensure/insert that calls allocator then **`0x2EA0B00`** (no key/`+0x61`).
- `.edata` slots are **vtable entries**: ctors install table bases (`0x2E97A50`→`0x948FF50`, `0x59D9B90`→`0x9303E28`); arming slot at base+`0x128`.
- Neighbor A `0x2108530`→`0x129E5190` calls membership **`0x4D04450`** and worker **`0x725400`**.
- Neighbor B `0x2108830`→`0x43E7750` **compares** `[vt+0x2B0]`/`[vt+0x2B8]` to expected code pointers.
- Arming helper tail-calls **`[vt+0x2B0]` with `edx=2`**.
- Validator expected methods: **`+0x2B0=0x4656C80`** (trampoline to `+0x2B8`), **`+0x2B8=0x479E3B0`**. Arm table uses **`+0x2B8=0x2108620`** which calls `0x479E3B0` then does `+0x98` side-block work.
- Validator `test edx,0xFFFFFFFD` selects the compare path when **`edx=2`**.
- Ctor `0x2E97A50` installs vtable **`0x948FF50`** (LEA from `0x5F11A40`); sits before enqueue helper.
- Ctor `0x59D9B90` installs **`0x9303E28`** at `+0x1D0`; caller `0x59D96A0`.
- Arm wrap `0x2108620` calls `0x479E3B0`, then gates on `+0x98` / flags and writes modes **0–3** at side-block **`+0x158`**; installed at arm-table **`.edata 0x9490208`**.
- Post-2B8 `0x479E440` compares **`[obj+0x26]`** to mode; walks context SmallArray stride `0x58`; nearby string **`AnimatedOnActiveChanged`**.
- Installer A `0x5F11A40` **LEA-registers** ctor A (does not call); uses LookupKey. Installer B `0x59D96A0` **calls** ctor B then continues composite init through `+0xE38`.
- Modes **2/3** write side-block `+0x158` / listHelper args only — **no** edge to enqueue/wrapper/gate/membership; **not** the enrollment `([+0x61]&6)==2` test.
- `0x59D9660` calls `0xB169D0` then InstallerB at **`[obj+0x20]`**; outer layout lower bound **`0x20E0`**; **no** allocator on chain; Fill imm **`0x140`** in ctor B.
- `AnimatedOnActiveChanged` string **`0xA179A9F`**; same-owner **`0x2335040`** LEAs it (→`0x8CD620`) and E8-calls **`0x479E440`**.
- `0x2335040` sets **`[obj+0x26]=1`**, may `call [vt+0x2C0]`, then post-2B8 and/or shared notify.
- `0x8CD620` is a **shared** typed-event notify (**30** E8 callers) dispatching via **`[handler+0xA0]`**.
- Neighbor `0x2335140`: `or [+0x23],1`; **`test edx,~2`** then **`edx=3; call [vt+0x2B0]`**; copies nested transforms; helper **`0x546D150`**.
- TypeInfo registration: size **`0xB2898E8=0x20F0`**, ctor **`0xB289918←0x59D9660`** (matches layout bound `0x20E0+0x10`).
- **No** hard-coded `Allocator(0x20F0)` and **no** absolute RIP readers of `0xB2898E8`; `0x20F0` also appears as field offsets inside larger objects.
- Helper **`0x546D150`** (491 B, **40** E8 callers) returns a transform/source pointer from `+0x98` side-block or nested `+0xA0` search.
- edx=3 `[vt+0x2B0]` uses the **same** arm-table trampoline **`0x4656C80` → wrap `0x2108620`** as edx=2.
- Generic TypeInfo factory idiom (tight): dword **`[ti+0x20]`** size → **`Allocator(edx=size)`** → **`icall [ti+0x50]`** ctor; exemplars **`0x238590`** / **`0x256280`** (many E8 callers). **Not** RIP-tied to LookupKey `0xB2898C8`.
- Helper `0x546D150` has **32** unique caller funcs (**31** beyond neighbor); decoded beyond-neighbor roles are mostly **block-copy** consumers.
- **No** tight-factory caller offline-feeds TypeInfo for key `0xB2898C8` / size `0x20F0` (0 key LEA / 0 size-imm / 0 key∩factory among 186 caller records).
- Helper `0x2336560` = thin **position extract**; `0x1D25E20` = **spatial/matrix** consumer — not proven possession/control.
- Outer ctor `0x59D9660` has **0** E8 callers; InstallerA LEA-stores it into TypeInfo ctor field only; InstallerA published at `.edata 0xA240B20`.
- Lookup+Alloc cands `0x1B6AFF0`/`0x26D28E0`/`0x2F2C1A0` are **not** on the Outer reverse path.
- Neighbor/Spatial are **vtable methods** (`.edata 0x976B3E0` / `0x9236E58`); owner table bases `0x976B2D0` (+0x110) / `0x9236E00` (+0x58); installers `0x13612B0` / `0x5563CF0`/`0x6CF34A0` (spatial inits `+0x98`).
- Owner **VT[0]** ctors: neigh `0x13612B0`, spat `0x5781490` (+ family `0x3D522C0`/`0x5563CF0`/`0x6CF34A0`/`0x6CF3750`); **0 E8** callers; spat/neigh ctors init shared **`+0x98`** field (enrollment side-block offset).
- Spawn-parameter registrars and hashes listed in `docs/v0.8.0-second-edward-plan.md`. Player/NPC/first-person/boat registrars have **0** direct `E8` callers. `SpawnCharacterParams` is called only by those derived registrars.
- Descriptor record stride **`0x20`**. Shared `+0` slot `0x53741F0` is `ret`. NPC `+0x18` `0x5E3DB0` and player `+0x18` `0x21F5950` copy a params object via `0x43DCB00`. They are not a world spawn.
- Input lead `0x187F0550` is action-name bind, not a movement controller.
- No verified shared entity/ownership edge between input bind path and deferred handler.
- No Edward, character, archetype, player, or transform string in either worker or the producer wrapper.
- No MSVC RTTI name recovered for queued subjects offline; game/Anvil types appear RTTI-stripped on this EXE.

### Hypotheses (not confirmed)

- The queued object is an actor or character (LOD-tracked).
- The 0x160 side block is activation state for that object.
- Runtime (non-RIP) TypeInfo pointer for `0xB2898C8` may still reach a tight factory.
- `0xE95E80` attaches side-blocks onto these same owner instances before arming (structural `+0x98` link confirmed; instance identity unproven).
- Dual Edward / dual input context is feasible somewhere else in the engine.

### Disproven on this path

- The workers are called with the 16-byte slot address.
- Element `+8` is an input transform.
- The slot contains a callback pointer or an archetype id.
- `0xE95E80` finishes a character/Edward spawn.
- `0x2D4F30` / the v0.6.8 top fingerprint trio are the deferred-queue subject constructors.
- Wrapper `0x2E97FC0` / enrollment sites allocate the objects they enqueue (they consume preexisting packed-pointer arrays).
- Arm-wrap modes 2/3 are the enrollment gate value / feed enqueue eligibility (no edge; different `+0x61` vs `+0x158` domains).
- `AnimatedOnActiveChanged` is a nearby string inside `0x479E440` (it lives at `0xA179A9F`; same-owner is caller `0x2335040`).
- Hard-coded `Allocator(0x20F0)` constructs the registered composite (no such site; size is TypeInfo-registered only).
- Loose “fullPattern” alone proves a TypeInfo factory (many +0x20 false positives; require tight edx/size + `[ti+0x50]`).
- Tight-factory **callers** RIP-feed TypeInfo for key `0xB2898C8` / size `0x20F0` (none found offline).
- Helper transform/position extract (`0x2336560` / `0x1D25E20`) equals possession/control (not shown).
- Expecting a direct `E8 0x59D9660` create site (none; TypeInfo icall only).
- Expecting E8 callers of owner VT[0] ctors (none; table-dispatched).

---

## 9. Current blockers

- No confirmed character/Edward **create/apply** callsite. Spawn-parameter types are serializers and copies. The deferred queue still only updates existing objects.
- Missing link: who fills `SpawnNPCParams` (`0x80F23E0` / hash `0x94D05600`) or `SpawnCharacterParams` and passes it to a world/entity create. Next xrefs: `0x5E3DB0`, `0x21F5950`, hashes `0x94D05600` and `0x51BA3541` outside the registrars.
- Who Allocates then invokes owner VT[0] ctors still open; that LOD chain is not the character factory.
- No verified input→character ownership/control binding.
- No in-game second-Edward test in this milestone. The candidate refuses the call even when `BFC_SECOND_EDWARD=1`.
- GitHub handoff must stay free of ASI/game binaries.

---

## 10. Most recent completed milestone

**v0.8.0 — Second Edward proof-of-life (gate refuses; factory callsite still missing)**

Deliverables:

- `docs/v0.8.0-second-edward-plan.md`
- `docs/v0.8.0-manual-pc1-checklist.md`
- `src/game/second_edward.cpp` / `second_edward.h`
- `tools/second_edward_test/main.cpp`
- `tools/offline/SpawnPath080/`
- `reports/v0.8.0-spawn-*.json`
- `reports/v0.8.0-validation.json`

v0.6.25 and earlier reports were left in place. Installed ASI was not replaced.

---

## 11. Next recommended milestone

**v0.8.1 (proposed):** Resolve virtual calls `0x33593D0` and `0x335A228` inside `0x33591C0`. The copy helpers and both type hashes are already traced and are not a world submit. Still no speculative call, deploy, live memory, or PC2 unless separately authorized.

---

## 12. Files changed in the latest milestone

- `docs/v0.8.0-second-edward-plan.md`
- `docs/v0.8.0-manual-pc1-checklist.md`
- `src/game/second_edward.cpp`, `src/game/second_edward.h`, `src/main.cpp`, `CMakeLists.txt`
- `tools/second_edward_test/main.cpp`
- `tools/offline/SpawnPath080/`
- `reports/v0.8.0-*.json`
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
| Offline install/E2C8A0 v0.6.15 (`InstallSite075`) | Pass; gate/bit install chains; E2C8A0→2EA0B00 |
| Offline edata/vcall v0.6.16 (`EdataConsumer076`) | Pass; vtable install; neighbor A/B; edx=2 vcall |
| Offline vt/ctors v0.6.17 (`VtSlotCtor077`) | Pass; expected slots; arm chain to 0x2108620; both ctors |
| Offline armwrap/installers v0.6.18 (`ArmWrap078`) | Pass; modes 0–3; post-2B8; installer A/B |
| Offline mode/enroll/size v0.6.19 (`ModeEnroll079`) | Pass; no mode→enroll edge; layout `0x20E0`; Animated same-owner |
| Offline activ/heap v0.6.20 (`ActivHeap080`) | Pass; notify shared; edx=3; TypeInfo size `0x20F0` |
| Offline typeinfo/edx3 v0.6.21 (`TypeInfo081`) | Pass; no Alloc(0x20F0); helper decoded; edx=3=same arm chain |
| Offline factory/consumers v0.6.22 (`TiFactory082`) | Pass; 5 tight factories; 0 key-tied; 31 beyond-neighbor helpers |
| Offline factory-feed/possession v0.6.23 (`FactoryFeed083`) | Pass; 0 key-tied factory callers; helpers = transform/position |
| Offline ctor-reverse/ownership v0.6.24 (`CtorReverse084`) | Pass; Outer=InstallerA LEA only; vtable owners mapped |
| Offline VT owner ctors v0.6.25 (`VtOwner085`) | Pass; VT[0] ctors; +0x98 enrollment link |
| Offline spawn-param scan v0.8.0 (`SpawnPath080`) | Pass; serializers found; create callsite absent |
| `BlackFlagCoopSecondEdwardTest` / ctest `SecondEdward` | Pass (35 checks, ALL PASS) |
| VS 18 2026 x64 Release `BlackFlagCoop.asi` | Pass; SHA256 `570F0F91A4B2D4A0B37093FF55BBA601BCC3C296603FE99EF4CD780EC38040B8` |
| Installed ASI still v0.5.1 | Pass; `63B38877DDA7CC7CD9AB2619F94D3941C37F54C95A435EFE47084DC4CF2A50BE` |
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
5. Prefer **v0.8.1**: resolve virtual calls `0x33593D0` and `0x335A228` inside `0x33591C0`. The copy helpers and hashes `0x94D05600` / `0x51BA3541` are already traced and are not a world submit. Do not call an RVA until a world receiver and its arguments are confirmed. CI on `4024a28` was pending with zero checks.
6. Do not instruct Cursor to deploy ASI, spawn, use live memory, or touch PC2/save data unless the user explicitly overrides safety.
7. Return instructions Cursor can execute verbatim on PC1 on a dedicated branch + PR (never push main).
