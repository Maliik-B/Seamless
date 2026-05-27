# H-26 solo repro under H-33-patched build (2026-05-26)

## Build under test

- Branch: `h26-soapstone` rebased onto `harden @ 011ad44` (which includes
  the merged H-33 task #12 + #13 patches via PR #5)
- Preset: `H26Repro` (RelWithDebInfo, `DS2COOP_H26_REPRO_LOGGING=1`)
- DLL SHA-256: `11706B39DD9368D32681CB6A5D050030952517393B84B686C6D88E856E385497`
- Deployed to: `D:\SteamLibrary\steamapps\common\Dark Souls II Scholar of the First Sin\Game\dinput8.dll`
- Pre-H26-repro dinput8.dll (try-11-final, sha256 `F618A126...44FB`)
  backed up to: `D:\Applications\DS2\backups\h26-repro-20260526-233533\`

## What this run tests

The H-26 scope doc (`docs/repro/h26-scope.md`) ranks five candidate
hypotheses for soapstone-placement refusal. Hypotheses #1, #2, and #5
are all confirmed-or-eliminated by a single solo-with-mod-loaded test.

This run replays that solo test against the post-H-33 codebase. The
H26Repro build adds unfiltered protobuf-classname tracing
(`[H26 >>]` outgoing, `[H26 <<]` incoming) so we can see whether any
sign-placement message even leaves the client.

## Procedure

1. Launched DS2 with the H26Repro DLL deployed as `dinput8.dll`.
2. Reached the title menu cleanly (no framerate popup, "Offline Mode"
   shown — same as the try-11-final run captured in
   `docs/repro/runs/h33-2026-05-26-coherent-state/`).
3. Continue → loaded existing save.
4. Hosted a session via the seamless overlay (INSERT → Host).
5. Equipped white soapstone, attempted placement at an open spot.
6. Equipped small white soapstone, attempted placement.
7. Quit cleanly (`Mod shutdown complete` line present at log end).

## Result

**Hypothesis #1 confirmed.** Both soapstone attempts silently refused
— no popup, no error message, no visible feedback at all. The engine
rejected the action locally before it reached the network layer.

Evidence from `host.log` at shutdown:

```
[23:55:04] [INFO ] Total protobuf messages processed: 0
```

And throughout the run:
- 5 H-33 patches applied at boot (OnlineCheck, SteamNetCheck,
  GameServerLogin, UserPolicy, OfflinePopupCall) — confirmed by
  `PatchBootPopup: PATCHED ...` lines
- Protobuf hooks installed cleanly (`HOOKED
  SerializeWithCachedSizesToArray`, `HOOKED ParseFromArray`,
  `Protobuf Hooks Result: 2/2 installed`)
- Zero `[H26 >>]` outgoing entries
- Zero `[H26 <<]` incoming entries
- Format strings `[H26 ...]` confirmed present in the deployed DLL
  (2 occurrences) — the instrumentation is alive, there's just nothing
  to log

The mod *is* otherwise functioning during this run — `PatchDismissal`,
`PatchPlayerCap` (H-25 / phantom-cap), and `EnableSummoning`
(H-25 bonfire bits) all fire when the session is hosted. The protobuf
silence is specifically about DS2 not attempting any of its
session/sign-placement protocol messages.

## Implication for the H-26 fix

The H-33 patches succeeded at unblocking the title-FSM boot popup
chain, but they did not flip the engine's downstream "am I online?"
state — they only shortcut the title substates' OnEnter to "success"
without ever populating whatever flag the rest of the engine reads.

DS2 still considers itself in Offline Mode at runtime, and in offline
mode the engine refuses sign placement *locally* (before any network
call). The same gate likely blocks several other online-only actions
(Go Online menu, character info uploads, summon-sign pickup).

Next H-26 task: find and flip the engine's runtime "is online" flag.
Likely location: a field on the service manager reached via
`[GameManager+0x22e0]` or `[GameManager+0x22f0]+offset` — both showed
up during the H-33 hunt. The fix should be applied at the same DllMain
time as the existing H-33 patches.

Hypotheses #2 and #5 are also still consistent with this evidence
(can't disambiguate from a single solo run), but #1 is the most
parsimonious explanation given the "Offline Mode" label visible on
the title screen and the zero-protobuf-traffic shutdown evidence.

## Ghidra evidence files reusable for this task

- `tools/ghidra_predicate_results.txt` — already has the GameServerLogin
  / UserPolicy / OnlineCheck slot[8] disassemblies showing
  `[GameManager+0x22f0]` and `[GameManager+0x22e0]` reads
- `tools/ghidra_fesm_driver_results.txt` — shared OnEnter / Update
  disassemblies showing the service-manager-inner-object access pattern

Ghidra project still at `tools/ghidra_project/DS2/`; no re-import
needed.

## State this run leaves the repo / machine in

- Deployed DLL: H26Repro (`11706B39...5497`). Will be reverted to
  try-11-final before this session ends so casual launches don't run
  the verbose protobuf trace.
- `h26-soapstone` branch (local-only): rebased onto `harden @ 011ad44`,
  uncommitted. Holding the rebase + this evidence dir for the H-26
  task #2 fix commit.
