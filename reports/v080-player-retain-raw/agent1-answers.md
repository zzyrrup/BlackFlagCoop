## Agent 1 answers (AC4Coop source only @ `68355c71`)

Answers from the AC4Coop tree only. No Resynced guesses. Labels: **SC** = source-confirmed code/layout; **AD** = comment/README only.

### 1. `World::GetPlayer` retention

**SC:** `World::GetPlayer()` is a thiscall wrapper only (`World.cpp` L24â€“26 â†’ fileVA `0x0070E810`). There is **no** in-tree direct member load of a `Entity* m_Player`.

**SC layout nearby (not proven as GetPlayerâ€™s backing store):** `World.h` has `LoadingAdvisor::m_PlayerSpaceReference` (`Handle`, L167), `World::m_StartupPlayerSpawner` (`uint64_t`, L204), and entity lists (`m_CharacterList`, etc.). None of these are read by `GetPlayer` in-repo.

**SC:** No in-tree writer that stores the player Entity into World after spawn/load. Player retention after spawn is entirely behind the unresolved thiscall.

### 2. Cache fill site (`0x04DEEF90` / `0x04DEEF94`)

**SC:** Repo only **reads** those absolutes (`PlayerProgression.h` L13â€“20).

**AD only:** Comments claim `PlayerProgressionManager::LoadEntityBuilderAndSelectorsForPlayer` fills them (`PlayerProgression.h` L7â€“10; also `DuplicationManager.h` L7; `phase1.cpp` L293).

**SC:** There is **no** in-tree xref, hook, dump, or writer for those globals. Fill site is entirely outside this repository.

### 3. `HandleContainer` layout (builder reload fingerprint)

**SC** (`BaseTypes.h` L15â€“33, `#pragma pack(push,1)`):

| Field | Type | Role in reload |
|-------|------|----------------|
| `m_Object` | `ManagedObject*` | Live object; polled after load (`phase1.cpp` L219â€“223) |
| `m_SoftRefCount` | `int` | Soft refs |
| `m_HardRefCount` | `int` | Hard refs |
| `m_ObjectID` | `uint64_t` | Resource id kept after builder object released (`phase1.cpp` L265â€“269) |

Invalid sentinel: `HandleContainer::GetInvalidHandle()` (`BaseTypes.h` L23â€“26).

**SC deref helper** (`phase1.cpp` L188â€“193): `handleDeref` treats the container as three `int32`s: `obj = HC[0]`, validity = `HC[2] >> 31` (sign bit of what the struct names `m_HardRefCount`), returns `obj & vbit`. Readable probe size used at acquire is **20 bytes** (`phase1.cpp` L267: `readable(builderHC, 20)`).

**Fingerprint without transplanting addresses:** packed record â‰ˆ pointer-sized object + two 32-bit refcounts + 64-bit object id (~20 bytes on x86); reload path = read id from handle â†’ `CreateReference(id)` â†’ async load â†’ wait until `m_Object` readable. Do **not** copy the absolute invalid-handle / HandleManager globals.

### 4. Human-update hook identity

**SC:** Comments call it â€œthe Human updateâ€ from AC4Hook (`phase1.cpp` L43â€“46). Stolen site RVA `0x12FAACD`, 6 bytes `mov ecx,[esi+0x108]`. Explicitly **not** `World::LinkUpdateAction` (same comment).

**SC register contract** (`FrameDetour` L1118â€“1130; `OnFrame` L1013):
- `esi` = `Human*` being updated (pushed as the only arg to `OnFrame`)
- Stolen insn reloads `ecx` from `[Human+0x108]` after the detour
- Filter: only act when `AIEntityHelper::GetHuman(World::GetPlayer()) == updatedHuman` (`isPlayerUpdate` L885â€“896)

**SC:** No demangled/engine symbol name beyond the descriptive â€œHuman updateâ€ / AC4Hook note. No World* in the hook argsâ€”World is fetched inside `OnFrame` via `GetCurrentWorld()`.

### 5. Enrollment without pad (networked puppet)

**SC net path:** After `AddEntity`, `RegisterPlayer` is **not** called when `Net::Enabled()` (`phase1.cpp` L346â€“352). Drive uses `SetGlobalMatrixInternal` etc. on the puppet, so **world enroll is treated as sufficient for render/simulate** for the networked case.

**SC nuance (important):** `g_blockReg` does **not** skip `BhvAssassin::AddToWorldInternal`â€™s pad query. The always-installed `GetUnusedPadID` hook (`L1160â€“1172`, installed L1314) still runs during enroll; with `g_blockReg` set it returns a **genuinely empty pad** so gamer/pad enrollment creates a **new** gamer instead of hijacking the active one (`L1153â€“1156`). Comment at L334 saying â€œskips â€¦ enrollmentâ€ is looser than the hook behavior.

**Bottom line for Agent 2:** Net puppet = `AddEntity` + safe pad isolation during enroll; no `RegisterPlayer`. Do not assume enroll never touches pad/gamer machinery.

---

I will not reopen SpawnNPCParams. Use these for the Resynced retention graph on PR #29.
