# H-33 task #12 — Ghidra hunt + try-7 patch deploy (2026-05-26)

## Build under test

- Branch: `h33-ghidra-patch` @ try-7 (rolled back from try-5 after FSM
  deadlock; rolled back from try-6 after framerate popup persisted).
- Preset: `Release` (no `H33_REPRO_LOGGING` — this is the fix, not
  instrumentation).
- DLL SHA-256: `6f1a4ab0108d6a3b97be4bc4750c6820b9eaf5d098c9722a74705c4a3b13049b`
  (`build/Release/bin/Release/ds2_seamless_coop.dll` ≡ `ds2_seamless_coop.dll`).
- Deployed to: `D:\SteamLibrary\steamapps\common\Dark Souls II Scholar of the First Sin\Game\dinput8.dll`.
- Pre-task-#12 dinput8.dll (task #11 H33Repro build, sha256 `9400d4c5...`)
  backed up to: `D:\Applications\DS2\backups\h33-task12-20260526-175210\`.

## What this build adds

Two runtime byte-patches on `DarkSoulsII.exe`, applied from
`SeamlessCoopMod::Initialize` at DllMain time (before the title-screen
FSM renders), called via `DS2Coop::Sync::ApplyBootPopupPatch`:

| Site | Address | Original | Patched | Effect |
|---|---|---|---|---|
| `OnlineCheck` | exe+0xF98C0 (`FeSubStateTitleOnlineCheck::slot[8]`) | `48 89 5C 24 08` | `33 C0 C3 90 90` | predicate forced to return 0 |
| `SteamNetCheck` | exe+0xF8FB0 (`FeSubStateTitleSteamNetworkCheck::OnEnter` override) | `48 89 5C 24 08 57 48 83 EC 20` | `C7 41 10 03 00 00 00 33 C0 C3` | `[this+0x10] = 3` (terminal success) |

Both patches force their respective substates to take the success arm of
the title-screen state machine, so the original "DARK SOULS II service
is not available" popup chain (which hit `FeSubStateOfflineModeWindow`
via OnlineCheck failure) never triggers.

## Result

**Original "service is not available" popup at boot: confirmed gone.**

`host.log` shows both patches apply cleanly at mod-init:

```
PatchBootPopup: PATCHED OnlineCheck at exe+0xF98C0 (5 bytes)
PatchBootPopup: PATCHED SteamNetCheck at exe+0xF8FB0 (10 bytes)
```

But a **different popup** appears at the title screen:

> Unable to play in online mode due to a detected frame rate issue.
> Please restart the game after resolving the issue to play online.

OK loops back to the same popup. (Screenshot referenced from the
in-conversation message at 2026-05-26 ~19:30.)

## Verdict on the new popup

It is **not** a genuine framerate issue. Two pieces of evidence:

1. User has played DS2 online successfully in the two weeks prior to
   this session, without any framerate complaint, on the same hardware
   without any FPS cap.
2. FPS-cap test: NVCP "Max Frame Rate = 60" set for `DarkSoulsII.exe`,
   verified, popup still appears identically.

**Working hypothesis (carry into next session):** the framerate-text
popup is DS2's generic "online mode setup failed" path firing whichever
FMG message ID the engine's error-code-to-message table maps to the
current half-initialised state. Our patches make
`OnlineCheck::slot[8]` and `SteamNetworkCheck::OnEnter` return success
**without doing the side-effect work the legitimate predicates do**
(auth token acquisition, session-manager state population, service
manager handshake at `[GameManager+0x22f0]`). A later check —
probably during or right after FSM transition into
`FeSubStateTitleGameServerLogin` — notices the inconsistent state and
fires the popup.

## Patches we tried but reverted

Why each was abandoned, for the next session's context:

- **try-4: `FailWarn::OnEnter` (+0xFD370) no-op.** Patch applied
  cleanly, popup still appeared — confirming a *second* wrapper at
  +0xFD230 also delegates to `OfflineModeWindow::OnEnter`.
- **try-5: `OfflineModeWindow::OnEnter` (+0x104DB0) no-op.** Killed the
  popup at the title screen — the user reached the main menu and could
  hit Start. **But the FSM deadlocked at "checking for online"**
  because (discovered post-hoc) +0x104DB0 is the shared OnEnter of
  *four* vtables, not just `OfflineModeWindow`'s. Nuking it broke the
  three other substates whose legitimate post-Start flow needs it.
  Vtable list:
  - +0x10BD000 / COL +0x12B01A0 (slot[0]=+0xF7240)
  - +0x10BD390 / COL +0x12B0880 (`FeSubStateOfflineModeWindow`)
  - +0x10BD6D0 / COL +0x12B0D90 (slot[0]=+0xFAC80)
  - +0x10BDDF0 / COL +0x12B17D8 (slot[0]=+0x104CF0)
- **try-6: `InfoFailWarn::OnEnter` (+0xFD230) no-op, instead of try-5.**
  The other direct wrapper. Patch applied but popup persisted because
  the framerate popup reaches +0x104DB0 via polymorphic vtable dispatch
  on one of the other three classes that share it — not via either
  wrapper.

The takeaway: every popup-wrapper-layer patch leaves a polymorphic path
unpatched, and the sink (+0x104DB0) is too heavily shared to nuke
safely.

## Ghidra evidence files for next session

All under `Seamless/tools/`:

- `ghidra_popup_hunt.py` / `_results.txt` — initial RTTI/string scan
- `ghidra_popup_drill.py` / `_results.txt` — MessageBoxW + cluster scan
- `ghidra_fesubstate.py` / `_results.txt` — first 7 FeSubState vtables
- `ghidra_fesubstate_all.py` / `_results.txt` — all 300 `.?AV*@@` classes
- `ghidra_fesm_driver.py` / `_results.txt` — title-screen FSM setup
  function FUN_1400f72e0 + shared OnEnter / Update disassembly
- `ghidra_predicate.py` / `_results.txt` — vtable slot 8-15 dumps,
  predicate functions 0x140500580 / 0x140500440
- `ghidra_steamnet.py` / `_results.txt` — SteamNetCheck OnEnter +
  related helpers
- `ghidra_failwarn.py` + `ghidra_failwarn2.py` / `_results.txt` —
  OnlineCheckFailWarn vtable + body
- `ghidra_fd230.py` / `_results.txt` — InfoFailWarn identification
- `ghidra_offline_callers.py` / `_results.txt` — **the discovery** that
  +0x104DB0 is shared by 4 vtables (vtable list above)
- Ghidra 12.1 project at `tools/ghidra_project/DS2/DarkSoulsII.exe`
  (path is gitignored — analysis took ~33 min; re-import only if the
  game binary changes)

## Next session — recommended starting point

1. Identify what side-effect fields `FeSubStateTitleOnlineCheck::slot[8]`
   (+0xF98C0) normally writes on its success path. The function queries
   `[GameManager+0x22f0]` and calls vtable methods — those methods
   presumably populate auth/session state on the service manager. List
   those fields with Ghidra.
2. Do the same for `SteamNetworkCheck::OnEnter` (+0xF8FB0).
3. Write a "set the half-init state ourselves" patch: after our
   succeed-shortcuts, fill in the fields that would have been populated
   by the real work. This should make later FSM checks see a coherent
   "online" state.
4. Alternative if (3) is too invasive: find the *consumer* of the
   half-init state (the function that fires the framerate popup as a
   side effect of detecting inconsistency) and short-circuit *that*.
   Likely a check inside `FeSubStateTitleGameServerLogin` or
   `FeSubStateTitleUserPolicy`.

## Out of scope

- The post-Start "checking for online" deadlock observed in try-5: also
  an artifact of the same half-init state, but only surfaced by the
  too-aggressive +0x104DB0 patch. Not present in try-7.
- ds3os `StartServer.bat` reliability: the bat closes its window
  immediately on Server.exe exit, masking any error. Cleanest fix is to
  add output redirection + `pause`. Out of H-33 scope; track separately.
- H-26 (sign placement protobuf retest): blocked on the framerate popup
  bypass landing.
