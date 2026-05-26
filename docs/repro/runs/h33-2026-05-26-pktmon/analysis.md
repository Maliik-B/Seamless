# H-33 pktmon analysis — 2026-05-26

Companion to `capture.etl/pcapng/txt` and `host.log` in this directory.

## Silent window (popup fires here)

- **Mod init complete:** `08:45:19` (host.log:125)
- **First matchmaking redirect (post-CANCEL):** `08:46:46` (host.log:142)
- **Window:** 87 s

## Method

1. Filtered `capture.txt` (UTF-16 → UTF-8 re-encode) to packet records in
   `[08:45:19, 08:46:46]`.
2. Extracted outbound TCP SYNs → first-seen new connection destinations.
3. Extracted outbound UDP → non-LAN destinations.
4. Reverse-DNS + Windows DNS-cache mining for identification.
5. Cross-checked live `Get-NetTCPConnection` against current
   `steamwebhelper.exe`, `Discord.exe`, `Steam.exe` PIDs to attribute
   long-lived suspects.

## All new outbound destinations in the silent window

| First seen | Dest | Proto | Bytes Tx/Rx | Identified as |
|---|---|---|---|---|
| 08:45:20.9 | 162.159.136.232:443 | UDP/QUIC | 32 pkts | Discord (current `discord.com` A-record) |
| 08:45:25.3 | 34.160.81.0:443 | TCP | 4.6/11.3 KB | Sentry `o137163.ingest.sentry.io` (Discord telemetry) |
| 08:45:25.9 | 104.18.37.174:443 | TCP | 21.1/28.7 KB | Cloudflare anycast — **unidentified** |
| 08:45:26.7 | 23.219.155.188:443 | TCP | — | Riot Games CDN (background) |
| 08:45:35.9 | 23.197.169.224:443 | TCP | 2.5/4.6 KB | Akamai — **confirmed steamwebhelper.exe (live)** |
| 08:45:51.8 | 199.46.35.128:443 | TCP | 3.8/11.2 KB | **unidentified** |
| 08:45:51.9 | 23.197.168.9:443 | TCP | 9.0/14.7 KB | Akamai (browser/FitGirl cache) |
| 08:45:53.1 | 40.90.8.68:443 | TCP | 6.7/10.1 KB / 1.5 s | Microsoft (login.live.com range) |
| 08:46:09.3 | 40.126.29.15:443 | TCP | 8.1/11.3 KB / 1 s | login.microsoftonline.com range |
| 08:46:11.5 | 192.178.50.67:80 | TCP | 0.4/0.4 KB / 50 ms | Google (connectivity check) |

## Verdict

Every destination that *can* be attributed belongs to a non-DS2 process
(Discord, Steam overlay, browser tabs, Windows auth). DS2.exe is
currently running and shows **zero external TCP connections**. The two
unidentified flows (`104.18.37.174`, `199.46.35.128`) both have
persistent-session shapes (10s of KB over tens of seconds), not the
short-probe shape DS2's "service check" would have.

**Hypothesis #2 falsified in its plain form**: Steam (or any other
process) is not opening a *new* TLS connection on DS2's behalf during
the silent window.

Two interpretations survive:

### 2′. Multiplexed Steam probe

The popup check rides an already-established long-lived Steam TLS
session (`52.85.78.102` cloudfront cluster has 7,678 Tx + 48,908 Rx
packets in the window). Steamworks RPCs are tunneled inside TLS so they
look like background heartbeat noise. Cannot distinguish from outside
without TLS decryption or process-attributed capture.

### 3. No network call at all

DS2 calls a Steamworks SDK function (`ISteamUser::BLoggedOn`,
`ISteamMatchmaking::*`, etc.) that returns a synchronous "not online"
result based on Steam client state — with **zero new packets**. The
popup is fired purely from that local return value.

## Recommended next moves (in cheapness order)

1. **Sysinternals Procmon + capture-network filter** — gives
   `process=DarkSoulsII.exe op=TCP_Send/Recv` rows directly. If procmon
   shows DS2 doing *any* TCP activity in the silent window, that's
   hypothesis #2′. If procmon shows DS2 making zero network operations,
   #3 is confirmed and we skip to Ghidra.
2. **Wireshark/tshark SNI extraction** on `capture.pcapng`. Identifies
   `104.18.37.174` and `199.46.35.128` by hostname. Either rules them
   in or out as Bandai/FromSoft endpoints.
3. **Hook Steamworks API in the mod** — `steam_api64.dll` exports
   `ISteamUser_BLoggedOn`, `ISteamUtils_*`, `ISteamMatchmaking_*`.
   Hook them, log returns. If DS2 calls one that returns "false" right
   before the popup, that's the trigger and we know exactly which one
   to make lie.
4. **Ghidra hunt** for the popup-creation function in
   `DarkSoulsII.exe`. Template: `PatchPhantomDismissalLoops` in
   `src/sync/player_sync.cpp:171`. Highest cost, sidesteps everything
   above.

Option 3 is the natural extension of the existing
`H33_REPRO_LOGGING` block — same shape as the Winsock hooks, but on
the Steamworks SDK surface. Probably the right next step.
