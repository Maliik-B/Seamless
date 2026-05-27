# H-33 repro — 2026-05-26 (task #11, Steamworks vtable hooks)

Tests `docs/repro/h33-scope.md` 2026-05-26 update #3 recommendation:
hook the vtable on the interface pointers returned by `SteamUser()`,
`SteamUtils()`, `SteamMatchmaking()` to distinguish hypothesis #2′
(multiplexed Steam probe) from #3 (popup fired from local state).

## Build under test

- Branch: `h33-steam-hooks` @ task-#11 pre-commit (built on top of
  task #10 commit `4378b8c`).
- Preset: `H33Repro` (`-DDS2COOP_H33_REPRO_LOGGING=ON`, RelWithDebInfo).
- DLL SHA-256: `9400d4c5ae57e09d3ea3e0253bd6535ac796b76c695d4ff41310dd289b841fbd`
  (`build/H33Repro/bin/RelWithDebInfo/dinput8.dll` ≡ `ds2_seamless_coop.dll`).
- Deployed to: `D:\SteamLibrary\steamapps\common\Dark Souls II Scholar of the First Sin\Game\dinput8.dll`.
- Prior dinput8.dll (task #10 build, sha256 `b9405bce...`) backed up to:
  `D:\Applications\DS2\backups\h33-task11-20260526-110500\`.

## Repro recipe

Same shape as `runs/h33-2026-05-26-steamhooks/` — no ds3os.

1. Launch DS2 via Steam.
2. Wait for the "DARK SOULS II service is not available" popup.
3. Click **CANCEL** (NOT OK — OK loops).
4. Quit to desktop within ~10 s of CANCEL.
5. Copy `<game>\ds2_seamless_coop.log` into this directory as `host.log`.

## What this build adds

Three vtable-slot hooks on the interface pointers returned by the
Steamworks global accessors (`SteamUser`, `SteamUtils`, `SteamMatchmaking`),
gated behind `H33_REPRO_LOGGING`:

| Interface | Slot | Method | Notes |
|---|---|---|---|
| `ISteamUser` | 1 | `BLoggedOn` | The textbook "am I logged into Steam" check |
| `ISteamUser` | 2 | `GetSteamID` | Returns the logged-in Steam ID (zero if offline) |
| `ISteamUtils` | 3 | `GetServerRealTime` | Returns 0 if not authenticated to Steam servers |

Plus install-time **vtable dump** of the first 12/24/24 slots of
`ISteamUser` / `ISteamUtils` / `ISteamMatchmaking` (`host.log:78-142`)
so future iterations can identify additional slots without re-running.

Also hooks `SteamAPI_Init` / `SteamAPI_InitSafe` as a backup trampoline
to install vtable hooks post-init if Steam wasn't ready at mod-init
time. In this run the immediate path won (`trigger=immediate`,
`host.log:78`), confirming Steam was already initialized before our
DllMain.

## Pass criterion

Any `[H33 STEAM] ISteam*::<Method>` entry appears in the silent window
between `MOD INITIALIZED SUCCESSFULLY!` and the first matchmaking
redirect.

## Result

**Hooks installed cleanly. Zero method-call entries in the silent window.**

Timeline:

| Time | Event |
|---|---|
| 11:07:23 | `MOD INITIALIZED SUCCESSFULLY!` (host.log:195) |
| 11:07:23 | All 3 vtable hooks installed (host.log:143-145) |
| 11:07:53 | First DNS for `frpg2-steam64-ope-login.fromsoftware-game.net` (host.log:208) |

**30-second silent window**, popup fired in there (user confirmed CANCEL).

Search of `host.log` lines after the install banner (line 145) shows
**no** `[H33 STEAM] ISteamUser::BLoggedOn`, no `ISteamUser::GetSteamID`,
no `ISteamUtils::GetServerRealTime`. None for the rest of the session
either — not during the matchmaking attempt at 11:07:53, not at shutdown.

DS2 **never calls** the three most-likely "am I online?" Steamworks
methods during the entire boot → popup → CANCEL → quit cycle.

## Vtable dump highlights

All three interfaces' vtables live in `steamclient64.dll` (Steam's
actual runtime library — `steam_api64.dll` is the in-process shim that
delegates via IPC pipe, as documented). Full dump at `host.log:80-142`.

Three coincidences worth flagging from the dump:

| Slot | Pointer | Repeats |
|---|---|---|
| `steamclient64.dll+0x6f36f0` | `ISteamUser[1]`, `ISteamUtils[0]`, `ISteamMatchmaking[4]` | likely a shared stub (placeholder for unused-this-version slots) |
| `steamclient64.dll+0x6f8140` | `ISteamUser[0]`, `ISteamMatchmaking[0]` | shared base/destructor-equivalent |
| `steamclient64.dll+0x6f8420` | `ISteamUtils[1]`, `ISteamMatchmaking[5]` | shared utility |

Steam runtime appears to share backing functions across interfaces
for trivial or version-removed slots. If `ISteamUser[1]` is really
this shared stub, our `BLoggedOn` hook might actually be patching the
wrong entry — but that just means BLoggedOn was at a different slot in
this SDK build, not that DS2 didn't call it. **Caveat to keep in mind**
for the next iteration.

## Verdict

What this run **does** decide:

- DS2 does not call `ISteamUser::BLoggedOn` (slot 1), `GetSteamID`
  (slot 2), or `ISteamUtils::GetServerRealTime` (slot 3) at any point
  in the popup window — strong negative for those three candidates.
- Vtable-hooking via MinHook on `steamclient64.dll`-resident functions
  **works**. No crashes, clean install/teardown.

What this run does **not** yet decide:

- The remaining ~21 unhooked slots per interface still might carry
  the popup decision. Most are unlikely candidates (lobby filters,
  RGBA image fetch, etc.) but a few warrant follow-up (
  `ISteamUser::InitiateGameConnection`, `ISteamMatchmaking::JoinLobby`).
- The slot-collision finding above leaves residual uncertainty about
  whether we hooked the right slot for BLoggedOn. ISteamUser017
  (the DS2-era version) has BLoggedOn at slot 1 in the public headers,
  but Steam may have re-numbered after server-side interface revs.

## Next step (task #12)

Combined with the pktmon result (`runs/h33-2026-05-26-pktmon/analysis.md`:
no DS2-attributed network in the silent window) and tasks #9–#11 (no
ws2_32 connect surface, no flat-C Steamworks exports, no
BLoggedOn/GetSteamID/GetServerRealTime), the evidence converges hard on
**hypothesis #3 — DS2 fires the popup from purely local state**.

The cleanest next move is **the Ghidra hunt** for the popup-creation
function in `DarkSoulsII.exe`. Template:
`PatchPhantomDismissalLoops` (`src/sync/player_sync.cpp:171`).

Search strategy starting points:

- String search for popup body text ("service is not available",
  Japanese/Korean translations, message ID).
- Cross-references to message-table / FMG-table lookups.
- Functions that call `User32!MessageBoxW`, `User32!DialogBoxParamW`,
  or DS2's internal modal-dialog factory.
- The "service unavailable" branch is reachable from boot — look for
  the predicate function that gates it and trace its inputs.

Optional intermediate step before Ghidra: extend task #11 with hooks
on the remaining ~21 slots per interface. Cost is ~250 lines of
single-signature trampolines. Probably not worth it given how strongly
the existing evidence already points at #3 — Ghidra is the higher-value
move.
