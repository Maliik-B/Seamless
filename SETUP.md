# DS2 Seamless Co-op — host + friend setup

This document describes how to run the mod against a self-hosted
[ds3os](https://github.com/TLeonardUK/ds3os) instance ("Plan E") and how
to onboard friends via [Tailscale](https://tailscale.com). It covers both
the host (you) and the friend (anyone you want to play with).

The mod also runs in a fully-offline defense-in-depth mode without any
custom server; that's the default when `use_custom_server=false`. This
doc is specifically for the custom-server flow.

---

## What this is and what to expect

The mod's network layer hooks DS2's protobuf serialization and redirects
its FROM-server connections to a server you specify in
`ds2_seamless_coop.ini`. With `use_custom_server=true`, four of the
title-FSM boot patches are skipped so DS2 actually runs the
GameServerLogin substate against your custom server.

**Known unknowns:**

- ds3os flags DS2 support as *"Experimental, high probability of things
  not behaving correctly."* First sessions will see occasional
  "communication with DS2 server interrupted" popups; the mod's
  auto-reconnect handles them and DS2 recovers within seconds.
- Custom-server use lives in a grey zone of FROM/Bandai's ToS. ds3os
  isolates its saves so retail saves aren't touched, but there is no
  written guarantee against account action.
- Phase 3 (a real friend on a separate machine) was not tested before
  this doc was written. Phase 1 (loopback) and phase 2 (LAN-direct via
  the host's own LAN IP) are both validated.

---

## Host setup

### One-time

1. **Build the mod** with the H26Repro preset:
   ```powershell
   cmake --preset H26Repro -S .
   cmake --build build\H26Repro --config RelWithDebInfo --target ds2_seamless_coop
   ```
   Output: `build\H26Repro\bin\RelWithDebInfo\dinput8.dll`.

2. **Deploy the DLL** to your DS2 install:
   ```powershell
   Copy-Item build\H26Repro\bin\RelWithDebInfo\dinput8.dll `
     "C:\…\Dark Souls II Scholar of the First Sin\Game\dinput8.dll"
   ```
   (Per repo convention, back up the destination first if you already
   have a `dinput8.dll` from a previous build.)

3. **Build ds3os from source**. Clone <https://github.com/TLeonardUK/ds3os>,
   run `Tools\generate_vs2022.bat`, then build the `Server` target in
   Release. You get `bin\x64_release\Server.exe`.

4. **First Server.exe run.** Launch it for about 8 seconds, then stop.
   This emits `Saved\default\config.json` and an RSA keypair
   (`public.key` + `private.key`).

5. **Edit `Saved\default\config.json`**:
   - `"GameType": "DarkSouls2"`
   - `"Advertise": false` — no public listing, no master-server heartbeat
   - `"LoginServerPort": 50031` — match DS2's hardcoded login port; the
     mod's `ConnectHook` rewrites destination IP but preserves the port
   - `"Password": "<some random string>"` — second factor on top of
     Steam-ticket auth, share with friends through a private channel
   - `"ServerHostname"`, `"ServerPrivateHostname"` — your Tailscale IP
     (see Tailscale section below) or LAN IP if same-network play

6. **Copy `public.key`** to your DS2 game folder as
   `ds2_server_public.key`:
   ```powershell
   Copy-Item D:\…\ds3os\bin\x64_release\Saved\default\public.key `
     "C:\…\Dark Souls II Scholar of the First Sin\Game\ds2_server_public.key"
   ```

7. **Edit `ds2_seamless_coop.ini`** in your DS2 game folder:
   ```ini
   use_custom_server=true
   server_ip=<your Tailscale IP, or LAN IP>
   server_port=50031
   ```

8. **Remove the Layer 2 firewall rule** if you previously installed it:
   ```powershell
   # elevated PowerShell:
   Remove-NetFirewallRule -DisplayName "DS2 Seamless - Block outbound to Internet"
   ```
   The mod's Layer 3 ConnectHook still blocks any DS2 outbound that
   isn't P2P-range or loopback, so removing Layer 2 doesn't open DS2
   to general internet traffic — it only lets DS2 reach the custom
   server.

### Per-session

1. Make sure Steam is running and signed in.
2. Make sure Tailscale is connected (system tray icon solid, not
   spinning).
3. Start `Server.exe`. Verify it's listening:
   ```powershell
   Get-NetTCPConnection -LocalPort 50031 -State Listen
   ```
   Should show one row with State=Listen on port 50031.
4. Launch DS2 via Steam. The mod's log
   (`ds2_seamless_coop.log` next to `DarkSoulsII.exe`) should show
   `[NET] REDIRECTING <FROM-IP>:50031 to custom server <your-IP>:50031`
   shortly after the title screen.
5. After play: close DS2, then `Stop-Process -Name Server -Force`.

### Switching back to fully-offline mode

Edit `ds2_seamless_coop.ini`, set `use_custom_server=false`. The four
FSM-bypass patches will re-engage on next launch and DS2 runs in
offline-defense-in-depth mode with no server traffic.

Re-add the Layer 2 firewall rule if you want it:
```powershell
.\tools\firewall-block-ds2-outbound.ps1   # elevated
```

---

## Tailscale (the safe network path to friends)

Tailscale is a WireGuard-backed mesh VPN; it gives each device a stable
`100.x.x.x` IP that only your "tailnet" members can reach. No router
configuration, no public WAN exposure.

### Host

1. Sign up at <https://tailscale.com> (free tier: 100 devices, 3 users
   under one account, or unlimited via the share-machine feature).
2. Install the Windows client from <https://tailscale.com/download/windows>.
3. Log in via the system tray icon. You'll be assigned a stable
   `100.x.x.x` address. Find it in either:
   - The system tray icon → "This device", or
   - <https://login.tailscale.com/admin/machines>

   This IP persists across reboots and reinstalls. Use it as
   `ServerHostname`, `ServerPrivateHostname`, and `server_ip` everywhere.

4. For each friend, choose one:
   - **Share machine** (no user-count cap): admin console → your host
     machine → Share → enter friend's email. They sign up to Tailscale
     under their own account; you're only sharing the one machine.
   - **Invite as user** (capped at 3 total users under your Personal
     tier): admin console → Users → Invite.

   Share-machine is the cleaner default for game co-op.

### Friend

1. Install Tailscale on their machine (Windows client, same URL).
2. Sign in / accept the share-link.
3. They can now reach your `100.x.x.x` address. Verify with
   `ping <your-IP>`.

---

## Friend bundle

For each friend, hand them a four-file zip:

```
dinput8.dll              your built mod
ds2_server_public.key    your ds3os public key (NOT the private one)
ds2_seamless_coop.ini    pre-configured with server_ip=<your Tailscale IP>
README.txt               instructions + your ds3os password
```

A reproducible build script lives at
`tools/build-friend-bundle.ps1`. Run it after each DLL rebuild to
emit a fresh zip at `D:\…\friend-bundle\ds2-coop-friend-pack.zip`.

### Their install

1. Install Tailscale and accept your share-link (see above).
2. Drop all four files into
   `…\Dark Souls II Scholar of the First Sin\Game\`.
3. Launch DS2 via Steam. Done.

If their session needs different `ds3os` password handling later,
update `server_password=<password>` in their `ds2_seamless_coop.ini`
(matching whatever the mod expects in the current build — check
`include/mod.h` `ModConfig` for the live key name).

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| DS2 launches but log shows no `[NET] REDIRECTING` lines | `use_custom_server` is false, or DLL not loaded | Check ini, confirm `dinput8.dll` is in the Game folder, confirm Steam launched DS2 directly (not via a third-party launcher) |
| `[NET] Game connecting to ...:50031` but no redirect | `Server redirect configured` line missing earlier in log | Check `ds2_server_public.key` exists next to `dinput8.dll` |
| `[REDIRECT] Loaded public key from ds2_server_public.key (0 bytes)` | Empty / corrupt key file | Re-copy the key from ds3os's `Saved\default\public.key` |
| "Communication with DS2 server interrupted" popup mid-session | ds3os hiccup on a specific opcode | Auto-reconnect handles it; if it persists, send the log to the host so they can check ds3os' end |
| Title screen but no DSOS announcement popup | Server not running, wrong IP, or Tailscale not connected | Verify `Server.exe` is listening + `ping <Tailscale-IP>` works from the friend's machine |

If `Ctrl+Shift+End` is pressed (the emergency-disable hotkey, configured
in the ini), the mod reverts all sticky writes and unhooks itself. The
DLL stays loaded so the game keeps running, but in vanilla behavior.
Useful if something goes badly mid-session.

---

## Operational notes

- **Don't port-forward the ds3os ports on your router**. With Tailscale,
  your `Server.exe` binds on `0.0.0.0` locally but is only reachable to
  tailnet members. A router port-forward would put it on the open
  internet where any scanner can find it.
- **Layer 3 ConnectHook stays active in both modes.** Even with
  `use_custom_server=true`, the mod still blocks any DS2 outbound that
  isn't on a P2P-range port or loopback. Custom-server traffic is on
  P2P-range ports (50031/50000/50010-50100) so it passes through; FROM's
  service-status probes on port 80 still get refused.
- **ds3os's Steam-ticket auth** runs against the Steam Gameserver API
  to verify each connecting DS2 client owns the game. Keeps random
  network scanners out even if they discover the open port.

---

## Reference architecture

```
DS2 (with mod) ─→ connect(54.201.x.x:50031)            ← FROM AWS server
                  │
                  ↓ (Winsock ConnectHook rewrites IP)
                  connect(<your-IP>:50031)
                  │
                  ↓ (Tailscale routes through WireGuard tunnel)
                  ds3os Server.exe @ <your-IP>:50031   ← login service
                  │
                  ↓ (responds with auth + game endpoints, same IP)
                  ds3os Server.exe @ <your-IP>:50000   ← auth service
                  ↓
                  ds3os Server.exe @ <your-IP>:50010   ← game service (UDP)
                  ↓
                  Steam ticket validated → session established
                  ↓
                  Protobuf flow (RequestCreateSign, RequestGetSignList, …)
                  carries co-op state between players via ds3os.
```

Same architecture works for any value of `<your-IP>`: loopback
(`127.0.0.1`), LAN (`192.168.x.x`), or Tailscale (`100.x.x.x`). The
mod's ConnectHook and ds3os's listening sockets don't care; only the
network path between host and friend changes.
