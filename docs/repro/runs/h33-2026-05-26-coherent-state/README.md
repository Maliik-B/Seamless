# H-33 task #13 — framerate popup bypassed, title menu reachable (2026-05-26)

## Build under test

- Branch: `h33-ghidra-patch` @ try-11
- Preset: `Release` (no `H33_REPRO_LOGGING`)
- DLL SHA-256: `56AE481C129149B1FC2D4254ADD8E6BF0886063BD9D3BFFE18E7C591BDA1AF95`
  (the with-logger build that produced this evidence; logger is removed
  for the committed try-11-final build)
- Deployed to: `D:\SteamLibrary\steamapps\common\Dark Souls II Scholar of the First Sin\Game\dinput8.dll`
- Pre-task-#13 dinput8.dll (task #12 try-7, sha256 `6f1a4ab0...049b`)
  backed up to: `D:\Applications\DS2\backups\h33-task13-20260526-215832\`

## What this build adds (over task #12 try-7)

Five runtime byte-patches on `DarkSoulsII.exe`, applied from
`SeamlessCoopMod::Initialize` at DllMain time:

| Site | Address | Original | Patched | Effect |
|---|---|---|---|---|
| `OnlineCheck` | exe+0xF98C0 | `48 89 5C 24 08` | `33 C0 C3 90 90` | predicate slot[8] forced to return 0 (carryover from try-7) |
| `SteamNetCheck` | exe+0xF8FB0 | `48 89 5C 24 08 57 48 83 EC 20` | `C7 41 10 03 00 00 00 33 C0 C3` | `[this+0x10]=3` and return (carryover from try-7) |
| `GameServerLogin` | exe+0xF9820 | `48 89 5C 24 08` | `33 C0 C3 90 90` | slot[8] forced to return 0 (new in try-8) |
| `UserPolicy` | exe+0xF9040 | `48 89 6C 24 20 56 48 83 EC 40` | `C7 41 10 03 00 00 00 33 C0 C3` | `[this+0x10]=3` and return (new in try-9) |
| `OfflinePopupCall` | exe+0x104DEA | `E8 B1 94 3F 00` | `90 90 90 90 90` | NOP the 5-byte `CALL 0x1404FE2A0` inside `FUN_140104DB0`'s popup arm (new in try-11) |

## Result

User reaches the title menu cleanly. `host.log` confirms all five
patches applied at mod-init and `[H33 POPUP FE2A0]` no longer fires
during the run (the framerate popup is dead). Screenshot at
`title-menu.png` shows New Game / Continue / Go Online / Video / Quit
with "Offline Mode" status in the top-left — the expected state given
that we bypass the real Steam handshake by shortcutting the four title
substates' OnEnter to "success".

## How the +0x104DEA fix was found

The half-init-state hypothesis from update #5 of the scope doc held up
in spirit but the original plan-A ("write the same fields the legitimate
flow populates so the post-Start consistency check sees a coherent
state") turned out to be infeasible: the legitimate
`OnlineCheck::slot[8]` and `SteamNetworkCheck::OnEnter` flows do **not
write** any fields on the service manager at `[GameManager+0x22f0]`
that downstream substates read. Their checks are procedural (vtable
queries on the service manager's inner object), not stateful — there
were no fields to fake.

The empirical approach succeeded instead:

1. Try-8 (added GameServerLogin patch): popup persisted, falsifying the
   "shared-OnEnter FailWarn from GameServerLogin::slot[8] → -1" theory.
2. Try-9 (added UserPolicy patch): popup persisted but title screen
   advanced cleanly to "Press Start" — partial progress.
3. Try-10 (added MinHook runtime logger on the four candidate
   popup-fire dispatcher functions `FUN_1404FE2A0`, `FUN_1404FE760`,
   `FUN_1400F5720`, `FUN_140051D90`): captured the exact call site —
   `exe+0x104DEA`, the `CALL 0x1404FE2A0` inside `FUN_140104DB0` (the
   shared OnEnter of FOUR vtables, the one try-5 nuked and deadlocked
   on).
4. Try-11 (5-byte NOP at `exe+0x104DEA`): kills only the popup-fire
   CALL inside the `[this+0x12]<0` arm. The legitimate JGE arm at
   `+0x104DF4` onwards (which the three sibling substates use as a
   non-popup OnEnter) is untouched, so the post-Start FSM deadlock
   from try-5 doesn't recur. The `inner.vtable[11]` side-effect call
   right before the popup-fire still runs; the
   `JMP 0x140104E80` immediately after the NOPed CALL still jumps to
   the function epilogue.

## Patches we ABANDONED (do not re-apply blindly)

Same list as task #12, plus:

- **try-5: `OfflineModeWindow::OnEnter` (+0x104DB0) full no-op** — see
  task #12 README. The surgical refinement that succeeded in try-11
  was to NOP only the inner `CALL 0x1404FE2A0` (the popup-fire) at
  `+0x104DEA` rather than the entire function entry, so the legitimate
  JGE arm survives for the other three sibling vtables.
- **plan-A from update #5 ("fake-but-coherent online state")** —
  infeasible because the legitimate upstream flow doesn't write any
  service-manager fields; all its work is in vtable queries on the
  service manager's inner object.

## What still fires but doesn't visibly block

The popup logger from try-10 also caught a `FUN_1404FE760` call from
`exe+0xFB036` inside `FUN_1400FAFF0` (popup A in the logger output).
This still fires under try-11 — the log here shows it at 22:42:08 —
but the user reaches the title menu cleanly, so popup A is either:
- a non-rendering info dialog (FMG ID with empty text), or
- queued behind the title-menu transition and auto-dismissed.

`FUN_1400FAFF0` has not been disassembled. Tracking as a followup
("H-33 task #13b") if downstream menus turn out to be affected.

## Out of scope

- `+0xFB036` popup A: see above. Doesn't block, leave for now.
- "Go Online" menu action: pressing it presumably re-runs Steam handshake
  checks that our patches don't cover, since the patches all bypass
  rather than fulfill them. Track as H-33 task #14 if needed.
- Save-slot-load → in-game world entry: untested under try-11.
- ds3os Server.exe lifecycle: still a backlog item (StartServer.bat
  swallows output on exit).

## Ghidra evidence files used this task

In `Seamless/tools/`:

- `ghidra_popup_source_hunt.py` / `_results.txt` — UserPolicy::OnEnter
  body, FPS-guard candidate disassembly (turned out to be a generic
  transcendental math function, irrelevant)
- All task-#12 scripts still load-bearing for context

## Next-session pickup

If the framerate popup or any new gate re-surfaces:

1. The popup logger is removed from the committed try-11-final build.
   To re-enable: revert the logger-removal commit, rebuild.
2. The list of unidentified popup-fire callers is still in
   `tools/ghidra_steamnet_results.txt` (5 other callers of FUN_1404FE2A0,
   6 other callers of FUN_1404FE760).
3. Ghidra project still at `tools/ghidra_project/DS2/`; no re-import
   needed unless the game binary changes.
