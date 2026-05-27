# H-26 Plan B — mod-side sign placement scope

Forward-looking scope for the H-26 follow-on ticket. Plan A
(`OnlineFlagAccessor`, the H-26 task #2 attempt) is in PR #9 / merged
on `harden`; this doc covers the next attempt.

## Recap — why Plan B

Plan A flipped the engine's runtime "is online?" boolean (the byte
at `[serviceMgr + 0x3A]` read by `FUN_140513600` and 33 other call
sites). It correctly removed the title-screen "Offline Mode" label
and unlocked an outbound port-80 probe (caught by the
defense-in-depth layer 3 added in the same PR), but the session/RPC
subsystem stayed entirely dormant: `Total protobuf messages processed: 0`
across a full game session.

Two single-variable experiments encoded as comments in
`src/sync/player_sync.cpp`'s `kSites` array (disabling `GameServerLogin`
and `UserPolicy` patches one at a time) falsified the hypothesis that
the session-wake lives inside an H-33-bypassed function body.

Best remaining hypothesis: the session-wake requires either a real
FROM RPC reply we'll never get, or it lives in a code path entirely
outside the title FSM (character-select activation, world-load).
Either way, chasing the engine's native RPC subsystem in a no-FROM-
contact build keeps producing diminishing returns.

Plan B sidesteps the engine entirely. Sign placement becomes the
mod's responsibility: intercept the player's "use white soapstone"
action, generate the sign in the local world directly, broadcast the
sign data to peers via the mod's existing port-27015 P2P channel,
have peers spawn the sign in their world on receive.

This is also the architecture the upstream `scheissgeist/Seamless`
mod uses for similar features (per the prior-art landmark entry).

## Goal

White soapstone sign placement works end-to-end without DS2 ever
contacting FROM and without the engine's session/RPC subsystem ever
waking up. Peer mod instances see and can interact with each other's
signs.

Out-of-scope for the first iteration: small white soapstone,
red/dragon soapstone variants, sign-list browsing UI, sign expiration.
Tracked as follow-on tickets once the white-sign happy path lands.

## High-level architecture

```
  Local player          Mod (this build)             Peer mod
  ============          ================             ========
                                                   
  [press USE on   ] -> [intercept use-item ]
  [white sign     ]    [handler for soapstone]
   soapstone]          [item IDs            ]
                       [                    ]
                       [build sign entity   ]
                       [via direct memory   ]
                       [write OR DS2's      ]
                       [internal spawn fn   ]
                       [                    ]
                       [broadcast custom    ] --> [receive SignPlace   ]
                       [SignPlace packet    ]     [packet              ]
                       [via PeerManager     ]     [                    ]
                       [                    ]     [build sign entity   ]
                       [SIGN VISIBLE LOCALLY]     [in their world      ]
                                                  [SIGN VISIBLE TO PEER]
```

Summon (peer clicks on host's sign) is a separate phase, see task #6
below.

## Decomposition

Each task is a 0.5-2 day unit, sequenced so the build is shippable
after each step.

### Task #1 — RE the soapstone use-item path

Find the function that handles "the player pressed Use on a consumable
that happens to be a white soapstone." This is the leftmost point in
the architecture diagram. Two routes to find it:

  - **AOB / RTTI**: search for any item-handler class with "Sign",
    "Soapstone", or item-ID `WhiteSignSoapstone` references. The
    existing `GrantSoapstones` flow knows the item IDs already.
  - **Empirical hook**: hook the consumable-use dispatcher (the
    handler `ItemGive` is paired with, probably reachable via the
    same `AvailableItemBag` pointer chain) and log `_ReturnAddress()`
    on every call to identify which call paths fire when the user
    presses USE on a soapstone.

Empirical preferred per `[[feedback-empirical-hook-methodology]]` if
RTTI / AOB don't converge in 2 rounds.

Deliverable: function address + signature for the soapstone-use
handler. Documented in a new `tools/ghidra_h26b_use_item.py` script
+ results.

### Task #2 — Find the engine's receive/render-side sign-entity creation

**Revised scope** (2026-05-27, after task #1 RE): sub-option 2A is dead.
The engine's use-item dispatch goes through `FUN_14024F350` into
session-manager vtable slots 0x78 / 0x98, which both reach the
dormant protobuf send layer. No standalone "spawn sign" function is
called by that path.

What we actually need is the code that runs on the *receiving* side
of a sign exchange: when DS2 normally parses a
`RequestGetSignListResponse` protobuf (from FROM's matchmaking
server), it walks the response and for each sign record creates an
in-world entity -- position, orientation, owner name, item type, the
interaction prompt. That entity-creation step is what makes signs
visible and clickable. We need to call it ourselves with data we
construct locally (for the placer) or receive via mod P2P (for
peers).

Three parallel hunting strategies, run together:

  - **Strategy 1: trace from the ParseHook.** The
    `H26_REPRO_LOGGING` empirical hooks (already in
    `src/hooks/session_hooks.cpp`) intercept every protobuf parse. If
    we could get DS2 to receive a `RequestGetSignListResponse` even
    once (synthetically, by injecting one through the parse layer),
    the resulting LOG line points at the caller chain into the
    rendering layer. Tricky because the session manager is dormant
    and won't process the parse if we just call it.
  - **Strategy 2: RTTI hunt for sign-entity classes.** Look for
    `.?AVSummonSign...@@`, `.?AVSignEntity...@@`,
    `.?AVOnlineSign...@@`, similar. Each candidate's vtable
    constructor is the spawn primitive. Same approach as the PR #9
    `tools/ghidra_h26_sign_hunt.py` script that found the protobuf
    classes. Most promising route.
  - **Strategy 3: sign-array / sign-list global hunt.** If the engine
    tracks placed signs in a global list (similar to the player list
    at NetSessionManager), find that global, dump its structure, and
    work backward from "what writes new entries to this list?" That
    writer is the spawn primitive.

Deliverable: a `SpawnSign` C++ wrapper in `src/features/sign_sync.cpp`
following the `ResolveItemGive` pattern -- pattern-scan to resolve
the spawn function, typed struct argument for position / orientation
/ type / owner, called directly from C++.

### Task #3 — Wire task #1 (intercept) to task #2 (spawn)

Replace the soapstone-use handler's default behaviour with a call to
the new `SpawnSign` wrapper. Use the same `MinHook::InstallHook` +
trampoline pattern as the existing protobuf hooks. Initial wiring:
sign spawns at the player's current position + facing.

After this task the local player can place a sign and see it. Peers
don't yet.

Pass criterion: locally placed sign is visible to the local player
in-world; quitting and reloading the area does not crash (verifies
the sign object is well-formed enough to survive the area's
entity-tracking).

### Task #4 — Define the SignPlace packet

Add to `include/packet_types.h`:

```cpp
enum class PacketType : uint8_t {
    // ... existing entries ...
    SignPlace = 0x50,    // first packet type in the H-26 Plan B range
    SignRemove = 0x51,
    SignSummon = 0x52,   // peer requests summon onto the host's sign
    SignSummonReply = 0x53,
};

struct SignPlacePacket {
    PacketHeader header;
    uint64_t playerId;       // sign owner (per PlayerPositionPacket)
    uint32_t signType;       // 0 = white, future: 1 = small-white, ...
    uint32_t areaId;         // DS2 area / map ID
    float x, y, z;           // sign position
    float rotY;              // sign facing
    uint32_t soulLevel;      // for sign-list filtering (future)
    char playerName[32];     // displayed name; mirrors HandshakePacket
};
```

Reserve 0x50-0x5F for the Plan B family so future variants (small-white,
red, dragon) have room.

### Task #5 — Send-side: broadcast SignPlace after local spawn

In the task-#3 hook, after `SpawnSign` succeeds, build and broadcast
a `SignPlacePacket`. Mirror the `SyncLocalPlayerPosition` pattern
already in `src/sync/player_sync.cpp` (build packet, set fields, call
`peerMgr.BroadcastPacket(&packet.header)`).

### Task #6 — Receive-side: spawn signs from incoming SignPlace

In `src/network/peer_manager.cpp` (or wherever the receive dispatch
lives), add a case for `PacketType::SignPlace` that calls the
`SpawnSign` wrapper with the packet's position / type / owner data.

After this task white-sign placement works end-to-end between two
mod instances on the same LAN / via the existing P2P path. **MVP
goal achieved at this point.**

### Task #7 — Sign summon (host clicks on peer's sign)

Hook the sign-interact code (USE on a placed sign). When the local
sign-array lookup returns a sign owned by another player, send a
`SignSummon` packet to that player. They respond with `SignSummonReply`
indicating their session info. The host then triggers DS2's internal
phantom-summon flow with the peer's session data.

This task piggybacks on the existing phantom-management infrastructure
(`OnPhantomJoined` / `OnPhantomLeft` in `src/hooks/session_hooks.cpp`,
session-manager AddPlayer / RemovePlayer). The bonfire-summon path
in the H-25 work establishes the pattern.

Potentially deferable to a separate ticket if Task #6 takes longer
than expected.

## Code surface

| File | Why |
|---|---|
| `tools/ghidra_h26b_use_item.py` | RE for task #1 |
| `tools/ghidra_h26b_sign_spawn.py` | RE for task #2 |
| `src/features/sign_sync.cpp` (new) | `ResolveSpawnSign`, `SpawnSign` wrappers |
| `include/features/sign_sync.h` (new) | declare `SignSync` class |
| `src/hooks/session_hooks.cpp` | use-item hook install (task #3) |
| `include/packet_types.h` | SignPlace / SignRemove / SignSummon types |
| `src/network/peer_manager.cpp` | receive dispatch for SignPlace |
| `src/CMakeLists.txt` | add `features/sign_sync.cpp` to the target sources |

The existing `GrantSoapstones` / `ItemGive` flow at
`src/sync/player_sync.cpp:929-974` is the load-bearing reference
implementation for the "scan-then-call-engine-fn" pattern. Plan B
copies the shape (pattern-scan to resolve the function, pointer-chain
walk to resolve any required context object, typed C++ wrapper that
calls the engine fn with a packed struct) but lives under
`src/features/` because it implements a feature the engine no longer
provides for us, rather than synchronising state that already exists.

## Known unknowns (RE checklist)

- [ ] Soapstone-use handler function address + arg layout
- [ ] DS2 internal sign-spawn function: exists? where?
- [ ] Sign entity in-memory layout (position offset, type offset, owner offset, ...)
- [ ] Area/map ID format (we need it for sign correctness across areas)
- [ ] Sign-array global location (for sub-option 2B if needed)
- [ ] Sign-interact (USE on placed sign) handler address
- [ ] Phantom-summon function signature when invoked outside FROM RPC
- [ ] Does DS2 spontaneously delete signs that don't have FROM-server
  backing? (sign expiration logic might reference server state)

## Pass criteria

### MVP (tasks 1-6)
- White-sign placement attempt produces a visible sign at the player's
  position in their own world
- A second mod instance on the same P2P channel sees the placed sign
  appear in their world at the correct position and orientation
- Quitting and re-entering the area: signs survive (if local) or
  refresh from peers (if remote)
- No crashes during placement / removal / area transitions
- `ds2_seamless_coop.log` shows no `[NET] BLOCKED outbound` entries
  related to sign placement (i.e. we're not accidentally triggering
  the engine's FROM RPC path)

### Full feature (with task 7)
- Clicking on a peer's placed sign summons the peer into the host's
  world (same as `OnPhantomJoined` / `OnPhantomLeft` flow today)
- Summoned peer can be dismissed via the existing dismissal flow

## Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| DS2's sign objects need backing state we can't fake (e.g. session token, server-issued sign ID) | medium | Sub-option 2B (direct memory writes) bypasses the lifecycle. If both options fail we'd need to revisit whether to invent fake server state -- task #2 is the gate |
| Concurrent sign placement causes lifecycle desync (one mod thinks the sign is gone, another keeps showing it) | low for MVP, higher for task #7 | Tombstone tracking + heartbeat: out of scope for MVP |
| Sign data leaks player position to peers regardless of their request -- some users might want to opt out | low for now (existing seamless mod is already P2P-position-share) | Defer; revisit if it becomes a UX question |
| Sign placement triggers a downstream check that DOES reach FROM RPC (e.g. sign-list upload), which the now-awake online flag lets through | medium | Layer 3 already covers this. The `[NET] BLOCKED outbound` check in the MVP pass-criteria catches regressions |

## Out of scope

- **Task #7 -- sign summon (peer clicks on host's sign and gets
  pulled in as a phantom).** Split into a separate PR/ticket after
  the MVP (tasks 1-6) merges. Already documented in the task #7
  section above but deferring it here makes the MVP scope explicit.
- Small white soapstone, red soapstone, dragon soapstone, Mirror Knight
  sign (separate item types, similar machinery; deferred to follow-on
  tickets once the white-sign path is proven)
- Sign-list browsing UI on the host side (the existing "use sign in
  world" interaction is the only entry point for MVP)
- Sign-text customization (DS2 default text only)
- Sign expiration / despawn-after-N-seconds
- Cross-area sign visibility (signs visible only when player is in the
  same area)

## Locked decisions (2026-05-27)

1. **Task #2 path**: original choice was 2A first, 2B fallback. **Sub-
   option 2A is dead** (revised 2026-05-27 after task #1 RE). The
   engine's soapstone-use path dispatches into vtable slots on the
   *session-manager* object -- the same object whose RPC subsystem we
   already confirmed dormant in Plan A. There is no standalone
   "spawn sign entity in world" function that the use-item path
   invokes; the engine's local-preview spawn happens as a side effect
   of the (now-dormant) RPC send. **Task #2 will pursue sub-option 2B
   from the start**: find the engine's receive/render-side
   sign-entity creation -- the code that turns a "sign at position X,
   owner Y" data record into a visible interactable in-world object.
   This is the code FROM's server would normally feed via
   `RequestGetSignListResponse`; we need to call it ourselves with
   peer-broadcast data. See Task #2 below for the revised approach.
2. **Code surface: `src/features/` tree**, not `src/sync/`. Plan B is
   the first explicit "mod-side feature reimplementation" and the
   directory naming should signal that pattern for follow-ons. Header
   lives at `include/features/sign_sync.h`, implementation at
   `src/features/sign_sync.cpp`.
3. **Task #7 (sign summon): split into a separate PR/ticket.** MVP
   (tasks 1-6, "I place a sign, peer sees it") lands first. Summon
   gets its own diff after the MVP merges. See "Out of scope" below
   for the explicit deferral.

## Task #1 outcome (2026-05-27)

- **Soapstone-use dispatcher**: `FUN_1401a8f70` @ exe+0x1A8F70.
  Signature: `bool __fastcall(void* ctx, uint32_t item_id, ...)`.
  Branches on `item_id` against the soapstone enumeration table at
  +0x10C3D70 (6 rows, 8 bytes each: `{u32 item_id, u32 index}`).
  On match: calls `FUN_14024F350(vector_ptr, soapstone_index)`.
  On miss: falls back to `FUN_1401A8E50` (generic item-use handler).
  Single caller: `FUN_1401a8b90` @ exe+0x1A8B90.
- **All 6 soapstone IDs** documented in
  `tools/ghidra_h26b_sign_spawn_results.txt`. Indices 2-5 are
  unknown variants (red, dragon, bell, invasion etc.); MVP only
  routes on index 0.
- **Hook strategy for task #3**: intercept at `FUN_14024F350`
  (narrower than `FUN_1401a8f70` -- only fires for soapstone
  use, not for any item). Check `EDX` (soapstone index); if 0,
  route to mod-side spawn instead of letting the original run.
  Other indices fall through to the original (probably no-op
  because session manager is dormant, but doesn't hurt).

## Related

- PR #9 (Plan A, merged into harden): the OnlineFlagAccessor patch,
  defense-in-depth, empirical hooks, and Plan A falsification trail
- `docs/repro/h26-scope.md`: H-26 task #1 scope (the bug that started
  this)
- `docs/repro/runs/h26-2026-05-27-online-flag/README.md`: evidence
  dir from the PR #9 work
- `docs/repro/runs/h26-2026-05-26-solo-confirm/README.md`: task #1
  evidence (the original "this is hypothesis #1" repro)
- `src/sync/player_sync.cpp:929-974`: load-bearing reference for the
  scan-and-call-internal-function pattern Plan B will mirror
