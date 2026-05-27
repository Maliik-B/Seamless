# H-26 (soapstone) — scope + repro plan

## Symptom (upstream issue #5)

Three reporters in the issue thread (`hrichey2002-rgb`, `DonBetonich`,
`VaddimBalan`, `samuelspineli34`). Consistent picture:

- Equipped soapstone (white sign / small white sign) cannot be
  *placed*. The use-item action either does nothing or is refused.
- `VaddimBalan` specifically calls out: *"using Soapstones in offline
  mode, which automatically turns on at startup"*. Strong hint that
  the game settles into offline mode under the mod and offline-mode
  vanilla behaviour is to refuse sign placement.
- `hrichey2002-rgb` notes they *"are not able to connect to dark
  souls 2 servers when doing this"* — expected behaviour with
  Seamless (we don't talk to FROM servers by design), but the user
  treats it as a possible cause.

## Contradicting prior-art finding

`docs/SESSION_LOG_2026_04_03.md:9` lists *"Summoning into each
other's worlds via soapstone"* under **What Works** during a live
multiplayer session (Sean / Michael / Pissass). Latest upstream
release is `v1.2.0` from 2026-04-04 — **one day later** — so
issue #5 reporters and the dev team are using nominally the same
codebase.

This contradiction is the central question H-26 has to answer.
Five candidate explanations, ranked by my prior:

| # | Hypothesis | Prior | Test signal |
|---|---|---|---|
| 1 | Reporters' setup forces offline mode (ds3os not actually running, wrong endpoint, etc.); dev team's setup didn't | High | Solo-with-mod-loaded reproduces the bug; protobuf trace shows no `RequestSummonSign` *or* a missing server response |
| 2 | Soapstone *placement* never worked; "summoning into each other's worlds" in the 04-03 log meant *picking up* an already-placed sign (the dev team auto-placed via mod, didn't manually use soapstone) | Medium | Solo-with-mod-loaded reproduces; mod source shows no auto-place code; check if dev team's session log distinguishes place vs. summon |
| 3 | Regression between 04-03 and v1.2.0 (04-04) introduced an offline-mode side-effect | Medium-low | Diff `f72bc04..` (Hamachi IP restore) and surrounding commits for anything that affects connection state |
| 4 | Bug is character-state-dependent (hollow, soul memory, area restrictions) and the dev team's testers happened to be in a state where it worked | Low | Solo repro with varied character states; vanilla DS2 sign-placement rules in `docs/SESSION_LOG_2026_03_17.md` opcode notes |
| 5 | Bug is environmental — Hamachi vs. LAN, NAT vs. direct, DLL load timing | Low | Solo-with-mod reproduces, eliminating P2P/network from the picture |

**Hypotheses #1, #2, #5 are all confirmed-or-eliminated by a single
solo-with-mod-loaded test.** That's the high-value first move.

## Code surface today

- `src/sync/player_sync.cpp:742 GrantSoapstones()` — grants the
  soapstone *items* into inventory. Does NOT touch placement.
- `src/ui/overlay.cpp:296` — UI button to call `GrantSoapstones`.
- `src/hooks/session_hooks.cpp:401` — protobuf message classifier
  detects phantom-join via `NotifyJoinGuestPlayer` (this is *response
  handling*, not soapstone placement).
- `src/hooks/session_hooks.cpp:260 SerializeHook` already logs
  outgoing protobuf messages matching `"Sign" | "Summon" | "Item" |
  …` — so a placement attempt that reaches the protobuf layer *will*
  show up in the existing log.

**Nothing in the mod source today actively manages the game's online
state.** The mod relies on its protobuf-redirect + Winsock-redirect
hooks to make the game *believe* it's online. If that belief fails,
DS2 falls back to offline mode and refuses sign placement.

`docs/SESSION_LOG_2026_04_03.md:34` lists *"Stale DLL causing offline
mode → deployed new build"* as a fixed crash — confirming the
online-state outcome is sensitive to mod state.

## Repro plan

**Two-stage**, solo-first:

### Stage 1 — solo bare-metal (no VM, no joiner, ~5 min)

If hypotheses #1, #2, or #5 are right, this reproduces the bug. If
it doesn't reproduce, we've eliminated three candidates and need
the joiner. Either way, valuable.

1. Build the H26Repro DLL (this branch).
2. Drop it as `dinput8.dll` next to host `DarkSoulsII.exe`.
3. Launch DS2. Load a throwaway character. Walk to a quiet area.
4. Equip white sign soapstone (already in inventory or use the
   overlay "Grant Soapstones" button).
5. Attempt to place — observe in-game outcome (sign placed / button
   does nothing / "service not available" popup / other).
6. Grab `ds2_seamless_coop.log` before relaunching.

### Stage 2 — with joiner (deferred; piggyback on H-25 VM session)

Only needed if Stage 1 doesn't reproduce. Append the soapstone
attempt phases to the H-25 timeline — both bugs in one VM session.

### Capture analysis matrix

After Stage 1 log is in hand, look for:

| In log | Verdict |
|---|---|
| `[H26 >>] *RequestSummonSign*` line fires when you click | Game *did* try to send. Issue is server-side or response-handling. Check for `[H26 <<]` reply. |
| `[H26 >>] *RequestSummonSign*` **does not** fire | Game refused to send — local offline-mode check is the culprit. Need to find and bypass that check. |
| Game shows "service not available" popup | Different code path (Winsock-level HTTP probe to FROM servers). See `docs/HANDOFF_2026_04_06.md:180-184` for the port-80 check question that was previously deferred. |
| Game silently does nothing | Likely state-machine refusing the use-item input before any network call. Local-only bug, no network instrumentation will catch it. |

## Instrumentation on this branch

Adds unfiltered protobuf classname tracing in
`src/hooks/session_hooks.cpp`, gated behind `H26_REPRO_LOGGING`.
Default build unchanged. The `H26Repro` preset turns it on.

- `SerializeHook`: every outgoing message → `[H26 >>] <classname>`
- `ParseHook`: every incoming message → `[H26 <<] <classname>`

Throttling: none. A soapstone-place attempt is bounded to ~5s of
gameplay; the log file growth is acceptable for a one-off capture.
For longer sessions, hit the H-20 emergency-disable hotkey to stop
the protobuf hooks from logging.

The existing filtered logging at `session_hooks.cpp:287-298` and
`:380-387` is left intact — H-26 mode is *additive* to give us a
complete picture rather than depend on the substring filter
catching the right classnames.

## Why this is on its own branch (not folded into h25-bonfire-bits)

Per `feedback_per_ticket_pr_hygiene.md`: feature-branch-per-ticket
→ PR into `harden`. The two branches will have non-overlapping diffs
(H-25 touches `player_sync.cpp`; H-26 touches `session_hooks.cpp`),
so the user will need to either:

- Build H25Repro + H26Repro separately, swap DLLs between repro
  sessions, OR
- Cherry-pick the H-26 instrumentation onto a throwaway combined
  branch for a single mixed capture (do not PR the combined branch)

Recommended: build both, run H-26 stage 1 (solo bare metal) first
since it doesn't need the VM. Then when the VM is ready, run H-25
with the H25Repro DLL.

## Open questions for the next session

1. Is there a "service not available" popup blocking the use-item
   action, separate from the protobuf layer? Need to check Winsock
   logs during the repro.
2. Does the dev team's `auto-summon` work (mentioned in
   `SESSION_LOG_2026_04_01.md:139` as a *future* item) actually
   exist in v1.2.0? Did it ship and bypass the soapstone-place path
   for them?
3. The existing `SerializeHook` substring filter at line 287
   includes `"Sign"` and `"Summon"` — so the matched-rate log
   already covers the sign flow. Is the H-26 unfiltered mode
   actually adding anything, or does the existing log suffice?
   **Answer this on the first repro pass — if matched-mode logs
   capture the full sign flow, drop the H26 mode before PR.**
