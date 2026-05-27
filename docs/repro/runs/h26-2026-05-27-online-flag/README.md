# H-26 task #2 — OnlineFlagAccessor patch + Plan A falsification (2026-05-27)

## Build under test (committed shape)

- Branch: `h26-online-flag` based on `harden @ 4e22771`
- Preset: `H26Repro` (RelWithDebInfo, `DS2COOP_H26_REPRO_LOGGING=1`)
- Patched DLL deployed as `dinput8.dll`; pre-patch baseline (try-11-final,
  sha256 `F618A126...44FB`) backed up to
  `D:\Applications\DS2\backups\h26-online-flag-20260527-074946\`

## What this branch adds

1. **OnlineFlagAccessor BootPatchSite** (`src/sync/player_sync.cpp`'s
   `kSites`). Five bytes at exe+0x513600 replaced from
   `0F B6 41 3A C3` (`MOVZX EAX, byte ptr [RCX+0x3A]; RET`) to
   `33 C0 FF C0 C3` (`XOR EAX,EAX; INC EAX; RET`). Forces the engine's
   "is online?" accessor `FUN_140513600` to always return 1. 34 callers
   across the binary now see online; the byte at `[serviceMgr + 0x3A]`
   itself is untouched.

2. **Defense-in-depth layers 2 + 3.** OnlineFlagAccessor flips the engine
   into "online" for code paths the existing Winsock redirect was never
   designed to handle (HTTPS, port-80 probes to Cloudflare-fronted
   status hosts, WSAConnect/ConnectEx variants). Layer 3 expands
   `ConnectHook` in `src/hooks/network_hooks.cpp` to refuse any outbound
   connect that isn't loopback or in the DS2 P2P port range, returning
   `WSAECONNREFUSED`. Layer 2 is `tools/firewall-block-ds2-outbound.ps1`,
   a one-shot script that adds a Windows Firewall rule blocking
   `DarkSoulsII.exe` outbound to anything off `LocalSubnet`.

3. **H-26 phase 2 empirical entry hooks** in `src/hooks/session_hooks.cpp`
   (gated by `H26_REPRO_LOGGING`). Probe-only MinHook entries on
   `FUN_1406a1de0` (RequestCreateSign send wrapper) and `FUN_140693cc0`
   (generic protobuf-send helper). Both log `_ReturnAddress()` and the
   first few args, then call original.

4. **Ghidra RE artifacts** in `tools/ghidra_h26_*.py` (+ `*_results.txt`).
   Six headless-runnable scripts captured the hunt trail: sign-class RTTI
   discovery, vtable layout of SignProtocol at exe+0x1113318, the indirect
   dispatch tables, the online-accessor + adjacent functions, and the
   bodies of the four H-33 patched functions (full disassembly + first
   level of callees). Future work can re-run these without redoing the
   discovery.

## What worked

- **Engine-wide "online" flag flipped.** Title screen reaches main menu
  with **no "Offline Mode" label** (compare to the H-26 task #1 evidence
  where "Offline Mode" was shown). 5/6 boot patches plus the new
  `OnlineFlagAccessor` patch all apply at DllMain time without warnings.
- **Address resolver succeeds when network is connected.** Last run's
  `GameManagerImp: [OK]` / `NetSessionManager: [OK]` confirms the
  task #1 `[FAILED]` result was offline-mode-induced boot-timing, not a
  separate bug. (See `docs/known_bugs.md` for the latent no-retry note.)
- **Layer 3 caught real outbound leaks.** During the empirical-hooks
  run, `BLOCKED outbound to 104.26.13.205:80` fired — same Cloudflare
  anycast probe seen in the original H-26 task #1 evidence, which
  would have left the process unredirected under the bare-H-33 build.
  Replicated across all four runs today with different Cloudflare edge
  IPs (104.26.12.205, 104.26.13.205, 172.67.74.152).

## What still doesn't work

- **Sign placement remains silently refused.** Both white and small
  white soapstone attempts produce no visible feedback and no error.
- **`Total protobuf messages processed: 0`** at shutdown — the engine's
  session/RPC layer is **entirely dormant** for the whole session. Not
  just sign-placement: no heartbeat, no presence, no session-state sync,
  nothing.
- **Empirical hooks confirm**:
  - `[H26 SIGN] RequestCreateSign_send ENTER` count: 0
  - `[H26 PROTO] protobuf_send_helper ENTER` count: 0

The OnlineFlagAccessor patch flipped the *low-level* "is a service
available?" boolean but did not wake the *session-layer* that actually
sends RPC. Sign placement is gated on the session being CONNECTED, not
just on the engine thinking "online."

## Plan A falsification — H-33 patched function bodies are not the kick

Hypothesis tested over two single-variable experiments (2026-05-27):

| Iter | Disabled patch | `[H26 PROTO]` count | Other regressions |
|---|---|---|---|
| 1 | `GameServerLogin` (exe+0xF9820) | 0 | `GameManagerImp` AND `NetSessionManager` resolver both failed |
| 2 | `UserPolicy` (exe+0xF9040) | 0 | `NetSessionManager` resolver failed (GameManagerImp survived) |

Both experiments left the title-screen flow clean (no popup, no
"Offline Mode") but the session layer stayed dormant. Letting the
substate bodies run *also broke* downstream resolver allocations —
removing different H-33 patches breaks different downstream init
paths, confirming the bodies do real work that has side effects we
don't want.

Conclusion: the session-wake trigger is **not** in any of the H-33
substate bodies. Most likely candidates now: (a) a real FROM RPC
reply that sets a session-ready byte we never observe, or (b) a code
path in a later phase entirely (character-select activation,
world-load). Plan A as originally framed is dead for a no-FROM-contact
build.

The negative-result findings are encoded as comments in the kSites
array next to the relevant entries, so future investigators don't
repeat the experiments.

## Files of interest

- `host.log` — the iter-2 (no-UserPolicy) experiment log, the most recent
  iteration of the day. The earlier iterations' logs were overwritten by
  later launches; their findings are preserved in the conversation-trail
  commit messages and in the kSites comments. Iter-2 specifically shows:
  the no-UserPolicy boot path; address resolver succeeded for
  GameManagerImp but failed for NetSessionManager; layer 3 caught the
  Cloudflare 104.26.12.205:80 probe; zero H-26 hook firings; zero
  protobuf sent; clean shutdown.

## State this run leaves the repo / machine in

- Source: all 6 `BootPatchSite` entries enabled (the committed shape).
  Experiment-disable variants are documented in comments adjacent to
  `GameServerLogin` and `UserPolicy` entries.
- Deployed DLL: the iter-2 (no-UserPolicy) experimental build is what's
  currently on disk in the game dir. Should be rebuilt + redeployed from
  the committed source before next session.
- Backups dir: lineage preserved across all today's iterations under
  `D:\Applications\DS2\backups\h26-*` timestamped subdirs.
- Firewall rule: still active (run
  `Remove-NetFirewallRule -DisplayName "DS2 Seamless - Block outbound to Internet"`
  from elevated PowerShell to remove).

## Next H-26 ticket

Plan B as a fresh ticket: bypass the engine's RPC subsystem entirely
and route sign placement through the mod's existing port-27015 P2P.
Pieces all fit patterns the mod already uses (`GrantSoapstones` writes
directly to game memory; `PeerManager::BroadcastPacket` already
broadcasts custom packets; `PatchPhantomReturnOnBossKill` patches
input handling). Scope doc to follow.
