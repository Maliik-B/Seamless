# H-33 repro — 2026-05-26 (task #10, Steamworks SDK flat-C exports)

Tests the recommendation from `docs/repro/h33-scope.md` 2026-05-26 update #2:

> Hook the Steamworks SDK surface inside DS2's process. DS2 ships
> `steam_api64.dll` ... hooking [the flat C exports] + logging
> invocation + return value will distinguish #2′ from #3.

## Build under test

- Branch: `h33-steam-hooks` @ pre-commit (this run will be its first commit).
- Preset: `H33Repro` (`-DDS2COOP_H33_REPRO_LOGGING=ON`, RelWithDebInfo).
- DLL SHA-256: `b9405bce9ae2b3f722e0049bf1732f58dfe8cef46f011922f35f61f0a82c0b5c`
  (`build/H33Repro/bin/RelWithDebInfo/dinput8.dll` ≡ `ds2_seamless_coop.dll`).
- Deployed to: `D:\SteamLibrary\steamapps\common\Dark Souls II Scholar of the First Sin\Game\dinput8.dll`.
- Prior dinput8.dll (task #9 build, sha256 `d24ce1f5...`) backed up to:
  `D:\Applications\DS2\backups\h33-task10-20260526-101339\`.

## Repro recipe

Same shape as `runs/h33-2026-05-26/` (no ds3os — task #10 question is purely
"does DS2 call any of these Steamworks exports", which is local to Steam):

1. Launch DS2 via Steam.
2. Wait for the "DARK SOULS II service is not available" popup.
3. Click **CANCEL** (NOT OK — OK loops).
4. Quit to desktop within ~10 s of CANCEL.
5. Copy `<game>\ds2_seamless_coop.log` into this directory as `host.log`.

## Pass criterion (original)

`host.log` contains at least one `[H33 STEAM]` line in the silent window
between `MOD INITIALIZED SUCCESSFULLY!` and the first matchmaking
redirect. Whichever export was called — and especially its return value
— names the popup trigger.

## Fail criterion (original)

`host.log` shows zero `[H33 STEAM]` entries → DS2 doesn't call the flat
C wrappers. Either it uses the C++ vtable directly (pivot: `~20 lines`
to hook the vtable on `SteamUser()` / `SteamUtils()` / `SteamMatchmaking()`
return pointers) or the popup doesn't go through Steamworks at all
(Ghidra hunt).

## Result — neither, in a sharper way

**All five hooks failed to install** because `steam_api64.dll` does
**not export the flat C wrappers at all**. Lines 76–80 of `host.log`:

```
[10:15:26] [WARN ]   H33: steam_api64!SteamAPI_ISteamUser_BLoggedOn not found (older SDK?)
[10:15:26] [WARN ]   H33: steam_api64!SteamAPI_ISteamUser_GetSteamID not found (older SDK?)
[10:15:26] [WARN ]   H33: steam_api64!SteamAPI_ISteamUtils_GetServerRealTime not found (older SDK?)
[10:15:26] [WARN ]   H33: steam_api64!SteamAPI_ISteamUtils_IsOverlayEnabled not found (older SDK?)
[10:15:26] [WARN ]   H33: steam_api64!SteamAPI_ISteamMatchmaking_GetNumLobbyMembers not found (older SDK?)
```

`steam_api64-exports.txt` in this directory is the full `dumpbin /EXPORTS`
of the DLL. Highlights:

- Total exports: **57**
- Exports containing `ISteam_`: **0**
- Global accessors that DO exist: `SteamUser`, `SteamUtils`,
  `SteamMatchmaking`, `SteamApps`, `SteamClient`, `SteamFriends`,
  `SteamHTTP`, `SteamMatchmakingServers`, `SteamNetworking`,
  `SteamRemoteStorage`, `SteamScreenshots`, `SteamUnifiedMessages`,
  `SteamUserStats`.

DS2's `steam_api64.dll` is sha256 `fc20547408a7c34f0bd4946a34c21aab48a75e3b98dce9e55969f486d37b212f`,
size 119,720 bytes, mtime 2026-05-08. This matches the original ~2014-era
Steamworks SDK (v1.31 / v1.32 vintage) — the `SteamAPI_ISteam<Iface>_<Method>`
flat C wrappers weren't introduced into the SDK until much later (v1.41+,
~2017). DS2's bundled DLL predates them.

## Verdict

Hypothesis #3 is not yet decided — we couldn't test it. What this run
*does* decide:

- The **flat C export** approach is closed. There is nothing to hook.
- DS2 must be using either the **C++ vtable interfaces** (returned by
  the global accessors above) or **no Steamworks call at all** for the
  popup decision.
- The 14-s silent window from `MOD INITIALIZED SUCCESSFULLY!` at
  `10:15:27` to first DNS at `10:15:41 (frpg2-steam64-ope-login.fromsoftware-game.net)`
  is still un-instrumented at the Steamworks layer.

## Next step (task #11)

Hook the **vtable** on the interface pointers returned by the
`SteamUser` / `SteamUtils` / `SteamMatchmaking` global accessors. The
accessors themselves are exported by name and trivial to call. The
vtable slot indices for the relevant methods (`BLoggedOn`,
`GetServerRealTime`, `IsOverlayEnabled`, `GetNumLobbyMembers`, etc.) are
documented in the public Steamworks SDK v1.31/v1.32 headers — the
indices have been stable across that line of SDK releases. Same
`H33_REPRO_LOGGING` gate, similar prefix `[H33 STEAM]`.

If the vtable hooks also show nothing in the silent window, **then**
hypothesis #3 (no network call, no Steamworks call — local timer or
similar) becomes load-bearing and the ticket pivots to a Ghidra hunt
for the popup-trigger function. Template: `PatchPhantomDismissalLoops`
(`src/sync/player_sync.cpp:171`).
