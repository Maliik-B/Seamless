# H-33 repro — 2026-05-26 (task #9, hypothesis #1)

Tests revised hypothesis from `docs/repro/h33-scope.md:222-228`:

> DS2 uses `WSAConnect` / `ConnectEx` / `WSAConnectByName` instead of plain
> `connect()` for the popup-triggering probe.

In the 2026-05-25 keyed run, mod log showed **zero `[NET]` / `[H33 DNS]`
activity for 60 s** between mod init (16:23:20) and the first redirect
(16:24:20), and the popup fired in that gap. If hypothesis #1 holds, this
run should now show `[H33 NET] WSAConnect|ConnectEx|WSAConnectByName...`
entries somewhere in that previously-silent window.

## Build under test

- Branch: `h33-popup-hook` @ `e5e04f0` + uncommitted `src/hooks/network_hooks.cpp`
  extending the existing `H33_REPRO_LOGGING` block with the three additional
  Winsock connect entry points.
- Preset: `H33Repro` (`-DDS2COOP_H33_REPRO_LOGGING=ON`, RelWithDebInfo).
- DLL SHA-256: `d24ce1f5287fa3800e8788235e89b917b56c6bfe88cc0c119e49c60b35539aff`
  (`build/H33Repro/bin/RelWithDebInfo/dinput8.dll` ≡ `ds2_seamless_coop.dll`).
- Deployed to: `D:\SteamLibrary\steamapps\common\Dark Souls II Scholar of the First Sin\Game\dinput8.dll`.
- Prior dinput8.dll + log backed up to:
  `D:\Applications\DS2\backups\h33-task9-20260526-081505\`.

## Repro recipe

Same shape as `runs/h33-2026-05-25-ds3os-keyed/` so only the DLL changes:

1. ds3os server running, RSA `public.key` staged in the game folder as
   `ds2_server_public.key` (already present from prior run).
2. Launch DS2 via Steam.
3. Wait for the "DARK SOULS II service is not available" popup.
4. Click **CANCEL** (NOT OK — OK loops).
5. Quit to desktop within ~10 s of CANCEL.
6. Copy `<game>\ds2_seamless_coop.log` into this directory as `host.log`.

## Pass criterion

`host.log` contains at least one `[H33 NET]` line in the window between
the `Initializing Seamless Co-op Mod...` banner and the first known port
50031/50000/50010+ redirect. Hostname or IP captured identifies the
popup probe.

## Fail criterion (→ fallback)

`host.log` shows the same 60-s silence as the 2026-05-25 keyed run with
no new `[H33 NET]` entries. Move to hypothesis #2 / #4 via a 2-min
pktmon or Wireshark capture; see `h33-scope.md:259-265`.
