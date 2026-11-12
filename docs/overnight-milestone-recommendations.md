# Overnight — Milestone Recommendations

**Date:** 2026-11-12  
**Basis:** v0.5.7 Harbour static analysis + multi-track harvest + prior v0.5.2–0.5.6 work  
**Working ASI remains v0.5.1**

## Ranked next milestones

### 1. Relative call-graph into Harbour `Registry_Find` / `DumpTo` / `LoadFrom` (highest value)

1. **Why it matters to co-op:** Without a verified path from schema names → runtime IDs → float producers, Edward pose cannot be observed honestly, and StateEx remains placeholder.  
2. **Evidence:** Find/DumpTo/LoadFrom have real x64 prologues; Insert/GetIdentifier\* are stubs; absolute VA xrefs to `PlayerPos*` strings failed (v0.5.6).  
3. **Establishable offline:** Callee/caller RVAs, likely structure layouts, whether registry keys are hashed or raw strings.  
4. **Unverified:** Link to `player.position` producer or Edward transform.  
5. **Next safe experiment:** Offline relative-call scanner over `.text` targeting those three RVAs; document hits only — no ASI hooks.

### 2. Composition/event family map for STANDARD position-like events

1. **Why:** Identifies sibling events that may share one producer family (movement, boat nav, body drop globals).  
2. **Evidence:** `PlayerPosition`→`player.position`; `BodyDropGlobalPosition*`; boat navigation signals nearby in schema blobs.  
3. **Offline:** Full composition→event inventory JSON; classify STANDARD vs CUSTOM.  
4. **Unverified:** Which events fire for Edward in open world.  
5. **Next safe experiment:** Offline schema inventory tool (already partially done) extended to all `*Position*` / `*Pos[XYZ]*` attributes — no runtime.

### 3. BFC session reliability layer (heartbeat + disconnect policy) — plugin only

1. **Why:** Co-op needs stable LAN presence before game pose exists; reduces false “still connected” states.  
2. **Evidence:** Overnight added `kMsgHeartbeat` + poseVerified sanitization; V1 framing preserved.  
3. **Offline / NetTest:** Wire optional heartbeat in session loop behind a flag; timeout → Leave presence; full `--self-test` regression.  
4. **Unverified:** Internet NAT traversal; game-state sync.  
5. **Next safe experiment:** Implement host-side idle timeout using Heartbeat **without** ASI deploy; document protocol as additive msg 8.

## Explicitly deferred

| Idea | Why deferred |
|------|----------------|
| Dual Edward spawn | No factory/possession evidence; spawn forbidden overnight |
| Engine replication reuse | No Replicat/NetEntity/HasAuthority evidence |
| Live memory pose readers | Safety + honesty (unproven source) |
| Save-file campaign merge | Risk + unmapped formats |

## Independent milestone (Track 9) — only if Harbour call-graph stalls

**Scimitar Online / UBI transport string archaeology** — only to document *what not to rely on* for LAN co-op; do not integrate Uplay matchmaking into BFC.
