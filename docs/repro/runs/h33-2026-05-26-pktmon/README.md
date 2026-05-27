# H-33 pktmon capture — 2026-05-26 (task #9 follow-up)

Tests hypotheses #2 (Steamworks RPC) and #4 (Steam overlay / Windows
NLA) from `docs/repro/h33-scope.md:222-228`. Hypothesis #1 was
falsified in the sibling run `../h33-2026-05-26/` (host.log shows
44 s of total ws2_32 silence between mod init and the first
matchmaking redirect, despite all five connect-API hooks armed).

If a packet exists in that silent window, pktmon sees it regardless
of which API the game used to send it.

## Recipe

1. Open an **elevated** cmd / PowerShell (right-click → Run as
   administrator). pktmon needs admin to load its driver.
2. From that elevated shell:
   ```
   D:\Applications\DS2\Seamless\docs\repro\runs\h33-2026-05-26-pktmon\capture.cmd
   ```
3. When the script prompts "CAPTURE IS LIVE", switch to Steam and
   launch DS2. Wait for the "service is not available" popup. Click
   **CANCEL** (not OK). Quit DS2 via the title menu or Alt+F4.
4. Return to the cmd window. Press any key to stop the capture.
5. The script writes three artifacts next to itself:
   - `capture.etl` — raw pktmon log
   - `capture.pcapng` — Wireshark-compatible
   - `capture.txt` — text summary for `grep` / `Select-String`

## Pass criterion

`capture.txt` (or `capture.pcapng` in Wireshark) shows at least one
outbound packet from a non-Steam-CDN / non-Windows-Update destination
in the window between DS2 process start and the first matchmaking
DNS query for `frpg2-steam64-ope-login.fromsoftware-game.net`.
Destination IP/hostname identifies the popup probe target.

## Fail criterion (→ hypothesis #3)

`capture.txt` shows **nothing** unexpected in that window — only
Steam's normal background heartbeats and OS-level chatter. Means
there is **no network call at all** for the popup. Move to hypothesis
#3: find the popup-creation function in Ghidra and patch the trigger
conditional. Template: `src/sync/player_sync.cpp:171`
`PatchPhantomDismissalLoops`.

## Cross-reference to mod log

The mod log `../h33-2026-05-26/host.log` provides exact timestamps for
the "MOD INITIALIZED SUCCESSFULLY" banner (08:28:56) and the first
matchmaking redirect (08:29:38). For a fresh run we'll regenerate the
mod log alongside this capture so the timestamps align. The mod log
ends up at:

`D:\SteamLibrary\steamapps\common\Dark Souls II Scholar of the First Sin\Game\ds2_seamless_coop.log`

Copy it into this directory as `host.log` after the run.
