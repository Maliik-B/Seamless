# H-33 — Hook the port-80 HTTP probe to suppress "service unavailable" popup

(Number `H-33` is provisional — Sprint α used H-04, H-08, H-17, H-18,
H-20, H-23, H-24, H-29, H-30, H-32; Sprint β is H-25..H-28; H-31 is
the reserved single-canonical-release ticket. Renumber if the user's
ticket scheme says otherwise.)

## Why this ticket exists

H-26 repro on 2026-05-25 proved that the
"DARK SOULS II service is not available" popup at boot is **blocking**,
not cosmetic:

- Popup's OK button loops back to the same popup. CANCEL is the only
  escape, and CANCEL forces the game into offline mode at the engine
  level.
- In post-CANCEL offline mode, DS2 serialises **zero** multiplayer
  protobuf messages — confirmed by `docs/repro/runs/h26-2026-05-25/
  host.log` containing no `[H26 >>]` or `[H26 <<]` entries across a
  12-min session that included two sign-use attempts.
- Soapstone placement (issue #5) silently no-ops because the game's
  use-item handler never reaches the protobuf send path.
- Same offline-mode forcing is the load-bearing hypothesis for
  upstream issue #3 (H-28: can't join online).

`docs/HANDOFF_2026_04_06.md:180-184` explicitly predicted this
outcome: *"If popup blocks multiplayer, need to hook the port 80
HTTP check too."*

## What the H-26 log shows

`docs/repro/runs/h26-2026-05-25/host.log:146`:

```
[15:25:41] [INFO ] [NET] Game connecting to 104.26.12.205:80
```

That connection passes through the existing `ConnectHook` in
`src/hooks/network_hooks.cpp:44-76`, which only acts on
`port == 50031`, `port == 50000`, or `port in [50010, 50100]`. Port
80 is logged and forwarded unchanged. The connection fails (no real
service responds with the expected payload), DS2 shows the popup.

`104.26.12.205` is a Cloudflare anycast IP — Cloudflare returns
different IPs per query for the same hostname, so the IP alone does
**not** identify which hostname DS2 was resolving. Verified by
checking forward-DNS of the obvious candidates from this machine on
2026-05-25:

| Hostname | Resolves to |
|---|---|
| `bandainamcogames.com` | 104.21.10.199, 172.67.131.183 |
| `bandainamcoent.com` | 44.216.85.130, 52.44.174.231, 52.73.243.92 |
| `fromsoftware.jp` | 13.158.57.94, 52.192.38.155, 52.196.118.23 |

None match 104.26.12.205. **We need to hook DNS resolution to capture
the hostname at runtime.**

## Design space

Four candidate fix approaches. None is committed; the DNS-hook data
will inform the choice.

### A. Block the port-80 connect()

Return `WSAECONNREFUSED` (or similar) from `ConnectHook` when the
destination is the bandai/from HTTP endpoint.

- **Pros:** ~5 lines of code, no new hook needed.
- **Cons:** the game's HTTP code sees the failure and probably shows
  the popup *anyway* — same outcome as today. Likely a no-op fix.

### B. Redirect to a local HTTP stub

Hook getaddrinfo to return `127.0.0.1` for the bandai/from hostname.
Run a tiny HTTP listener inside the mod (on a fresh port we own)
that returns the expected "service available" response. The
`ConnectHook` rewrites port 80 → our local port for matching IPs.

- **Pros:** intercepts at a clean OS-level boundary; the game's HTTP
  client (WinINet/WinHTTP) handles the response normally.
- **Cons:** introduces a long-lived TCP listener in the mod (lifetime
  management, port collision risk). Need to know what response shape
  satisfies DS2.

### C. Hook WinHTTP / WinINet response APIs

Intercept `WinHttpReadData` (or `InternetReadFile` if DS2 uses the
older API) and inject the canned response into the read buffer
before returning control to DS2.

- **Pros:** no listener; everything stays in-process.
- **Cons:** detection-prone (timing, HTTP framing); we'd be lying to
  the game about a connection that didn't really happen. Need to
  identify which API DS2 uses (one or both?). Higher code complexity.

### D. Hook the DS2 popup-trigger / service-check function

Find the function in `DarkSoulsII.exe` that decides "online service
unavailable → show popup" and force it to return "available."
Ghidra territory. Similar in spirit to the existing
`PatchPhantomDismissalLoops` (`player_sync.cpp:171`).

- **Pros:** surgical, single-byte / single-CALL NOP, no network
  surface change. The cleanest fix if we can locate the check.
- **Cons:** requires Ghidra reverse-engineering. The function may
  also need other side-effects (set "you are online" flag, populate
  service URLs, etc.) — a simple NOP might leave DS2 in a
  half-initialised online state.

### Initial preference

**B + D combined, evaluated against B alone after Step 2.** B is the
mechanism that's most likely to work universally and not surface-area
detection. D may end up being the fix if B turns out to require more
infrastructure than expected. C is a backup if both B and D hit
dead ends.

## Stepwise plan

### Step 1 (this branch's initial commit) — DNS hostname capture

Add `getaddrinfo` / `GetAddrInfoW` instrumentation behind
`#ifdef H33_REPRO_LOGGING`. Log every hostname the game resolves,
along with the IPs returned. Default build unchanged.

Output: after a 1-min repro (boot DS2 → see popup → quit), the log
shows exactly which hostnames DS2 queries before the port-80
connect. We expect 1–3 bandai/fromsoftware hostnames.

### Step 2 — HTTP response shape capture

Once the hostname is known, capture the actual HTTP response DS2
expects:

- Run a host-side `nc -lvp 80` (or simple Python listener) on
  127.0.0.1:80, point the game at it via hostfile redirect, observe
  what DS2 sends in the HTTP GET (URL path, headers) and what status
  code / body it accepts as "online."
- Cross-reference against any ds3os / scheissgeist / forum
  documentation on the DS2 service endpoint.

### Step 3 — Implement the chosen fix (B or D)

Based on Steps 1-2:

- **If response is simple** (200 + small JSON/empty body): go with
  Option B. Add ~50 lines: getaddrinfo redirect + minimal TCP
  listener returning the canned response.
- **If response is complex or DS2 has further auth challenges**:
  go with Option D. Find the service-check function in Ghidra, NOP
  the popup-trigger conditional.

### Step 4 — Verification

Same H-26 timeline (`docs/repro/runs/h26-2026-05-25/timeline.txt`)
re-run with the H-33 fix in place. Pass criteria:

- No popup at boot (or popup auto-clears / OK proceeds cleanly).
- `[H26 >>] *RequestSummonSign*` appears when the user tries to
  place a sign.
- Sign placement either succeeds visually OR fails with a different
  error (e.g. peer-not-found), which would indicate H-26 has a
  second cause beyond this ticket.

## Out of scope

- The H-26 protobuf instrumentation (already on `h26-soapstone`).
  When H-33 lands, retest H-26 by building the H26Repro DLL against
  a merged `h26-soapstone` + `h33-popup-hook` tree to verify
  sign-flow protobuf actually fires.
- The quit-to-menu hang observed at the end of the H-26 repro. Not
  obviously related to the offline-mode forcing; likely
  H-27-adjacent. Captured as a note in
  `docs/repro/runs/h26-2026-05-25/timeline.txt` OBSERVATIONS but no
  ticket yet.

## Reference

- H-26 evidence: `docs/repro/runs/h26-2026-05-25/`
- Original deferral of this work: `docs/HANDOFF_2026_04_06.md:180-184`
- Existing Winsock redirect pattern (template for any new hook):
  `src/hooks/network_hooks.cpp:44-76` (ConnectHook), `:92-122`
  (InstallHooks).
- Existing surgical-NOP pattern (template for Option D):
  `src/sync/player_sync.cpp:171` (PatchPhantomDismissalLoops).

---

## 2026-05-25 update — popup-trigger is NOT what this ticket scoped

Three repro runs today on the H33Repro DLL — evidence in
`docs/repro/runs/h33-2026-05-25*/`:

| Run | ds3os | RSA key deployed | Popup result |
|---|---|---|---|
| `h33-2026-05-25/` | no | n/a | popup appeared, user CANCELed, quit too fast to capture port-80 |
| `h33-2026-05-25-ds3os/` | yes | **no** — `WARN: No public key file found` | popup appeared, server console: `Failed to decrypt RSA message — OAEP decoding error` |
| `h33-2026-05-25-ds3os-keyed/` | yes | yes (`public.key` copied to game folder as `ds2_server_public.key`) | **popup STILL appeared** — server console clean, login + auth handshake succeeded, then directed client to `25.35.223.224` (stale Hamachi IP — see sidebar below) |

### The load-bearing finding

In the keyed run, the mod log shows **zero network activity** —
no `[NET] Game connecting to ...`, no `[H33 DNS]` — for the full
**60 seconds between mod init (16:23:20) and the first redirect
(16:24:20)**. The popup appeared somewhere in that window. So:

- The `ConnectHook` on `ws2_32!connect` did not see it.
- The `H33GetaddrinfoHook` on `ws2_32!getaddrinfo` and
  `GetAddrInfoW` did not see it.
- The matchmaking handshake (50031 / 50000) is irrelevant — those
  succeeded cleanly in the keyed run and the popup still fired.

**The popup is triggered by something invisible to the current
instrumentation.** The original "hook port-80 HTTP probe" framing
is wrong — that probe (visible in `docs/repro/runs/h26-2026-05-25/
host.log:146` at 15:25:41) fires much later during gameplay and is
unrelated to the boot popup.

### Revised hypothesis space

| # | Hypothesis | Test |
|---|---|---|
| 1 | DS2 uses `WSAConnect` / `ConnectEx` / `WSAConnectByName` instead of plain `connect()` for the popup-triggering probe | Hook those + repro |
| 2 | DS2 uses the Steam matchmaking API (Steamworks RPC), which doesn't traverse ws2_32 at the application layer | Capture at packet level; instrument Steam API calls in `session_hooks.cpp` |
| 3 | Popup is fired by a local timer with no network call at all — "no successful service ping in N seconds → popup" — and the "success ping" path involves something else entirely | Hook into DS2's UI / popup-creation code via Ghidra |
| 4 | Popup is fired by Steam's own overlay or by a Windows-level network state check (e.g. NLA — Network Location Awareness) | Capture at packet level |

Hypothesis #1 is cheapest to test (~60 lines extending existing
Winsock infrastructure). Hypothesis #2 / #4 need packet-level
capture (Wireshark or built-in `pktmon`) to rule in/out. #3 is the
"if everything else fails, find the popup function in Ghidra"
fallback.

### Sidebar: ds3os advertises stale Hamachi IP

Server console in the keyed run:

```
Directing login client to our private ip (25.35.223.224) as
appears to be on private subnet.
```

`25.35.223.224` is Sean's Hamachi IP from
`docs/HANDOFF_2026_04_06.md:165`, baked into the shipped
`Release/Server/Saved/default/config.json`. Even after the popup
ticket lands, DS2 will be directed to an unreachable IP for the
actual game session.

This is the same class of issue as the `StartServer.bat` bug
(task #7) and the un-staged `ds2_server_public.key` — all are
joiner-distribution / fresh-install gotchas that compound to
"a new user cannot get the mod working out of the box." Probably
belongs in H-31 (single canonical release artifact) or its own
follow-up ticket; explicitly out of H-33 scope.

### Where this ticket goes next

Pick one of #1, #2, #3, #4 to investigate first. Tomorrow's session
should start with that choice. Suggested order:

1. Try #1 first (cheap, eliminates one candidate).
2. If #1 doesn't catch it, run a 2-min Wireshark/pktmon capture to
   address #2 + #4 simultaneously.
3. #3 is the fallback only if #1 + #2 + #4 all come up empty.

The H33Repro DLL is already built and DLL-tested; tomorrow's work
extends `network_hooks.cpp` with the additional hooks per the
chosen path. The four design options (A/B/C/D) at the top of this
doc are still the candidate *fix* shapes once we identify the
trigger — they just can't be evaluated until we know what to hook.

---

## 2026-05-26 update — hypothesis #1 falsified

Task #9 repro with WSAConnect / ConnectEx / WSAConnectByName{A,W}
hooks added on top of the existing connect / getaddrinfo / GetAddrInfoW
instrumentation. Evidence: `docs/repro/runs/h33-2026-05-26/`
(`host.log` + `timeline.txt`).

All five new hooks installed cleanly at boot (host.log:72-75 +
mswsock!ConnectEx @ 0x7FFD05A05FE0). User confirmed popup appeared
and CANCELed it. Yet the log shows **44 s of total silence** from the
"MOD INITIALIZED SUCCESSFULLY" banner (08:28:56) to the first matchmaking
DNS+connect (08:29:38) — no `[H33 NET]`, no `[H33 DNS]`, no `[NET]`.

The popup-triggering call does **not** traverse:

- `ws2_32!connect`
- `ws2_32!WSAConnect`
- `ws2_32!WSAConnectByNameA` / `WSAConnectByNameW`
- `mswsock!ConnectEx`
- `ws2_32!getaddrinfo` / `GetAddrInfoW`

That eliminates the entire ws2_32 connect surface. Consistent with #2
(Steamworks RPC) or #4 (Steam overlay / Windows NLA, kernel-side) —
both bypass ws2_32 at the application layer and can't be distinguished
from inside the mod.

### Where this ticket goes next (superseded by 2026-05-26 update #2)

Per the suggested order in this doc above: run a 2-min pktmon or
Wireshark capture spanning DS2 boot → popup → CANCEL. Any packet in
the previously-silent window identifies #2 or #4 by destination. If
the capture is *also* silent, #3 (pure local timer, no network at
all) becomes the active hypothesis and the work moves to Ghidra to
find the popup-trigger function directly.

---

## 2026-05-26 update #2 — pktmon result, hypothesis #2 falsified in plain form

Packet capture during a second repro: `docs/repro/runs/h33-2026-05-26-pktmon/`
(`capture.etl` / `.pcapng` / `.txt`, `host.log`, `analysis.md`).
Silent window for this run was 87 s (08:45:19 → 08:46:46).

Captured 10 new outbound TCP destinations + 1 UDP destination in the
window. Identification (via reverse DNS, Windows DNS cache mining, and
live `Get-NetTCPConnection` attribution against currently-running
processes):

- `162.159.136.232:443/UDP` = Discord (current `discord.com` A-record)
- `34.160.81.0:443` = `o137163.ingest.sentry.io` (Discord telemetry)
- `23.197.169.224:443` = **steamwebhelper.exe** (verified live)
- `23.219.155.188:443` = Riot Games CDN
- `23.197.168.9:443`, `192.178.50.x`, `34.160.81.x` = shared Akamai/Google
  CDN noise (browser background, FitGirl-cached entries share these IPs
  by virtue of CDN multi-tenancy — not actual FitGirl traffic during the
  window)
- `40.90.8.68:443` (~1.5 s), `40.126.29.15:443` (~1 s) = `login.live.com` /
  `login.microsoftonline.com` ranges (Steam OAuth / Windows auth)
- `192.178.50.67:80` (~50 ms) = Google connectivity check
- `104.18.37.174:443`, `199.46.35.128:443` = persistent sessions, both
  with long-session shapes (tens of KB over tens of seconds) — neither
  matches the short-probe shape a "service check" would have

DS2.exe currently runs with **zero external TCP connections** — it
holds none. Every identifiable flow in the silent window belongs to a
non-DS2 process.

**Conclusion**: hypothesis #2 in its plain form (Steam opens a new
TLS connection on DS2's behalf during the silent window) is falsified.

Two interpretations survive:

- **#2′ Multiplexed Steam probe** — rides an already-established
  long-lived Steam TLS session (`52.85.78.x` cloudfront cluster
  carries 7,678 Tx + 48,908 Rx packets in the window). Cannot be
  distinguished from heartbeat noise without TLS decryption or
  process-attributed capture.
- **#3 No network call at all** — DS2 reads a Steamworks SDK return
  value synchronously and fires the popup based on that, with zero
  new packets.

### Where this ticket goes next (2026-05-26 update #2)

Hook the Steamworks SDK surface inside DS2's process, gated behind
`H33_REPRO_LOGGING`. DS2 ships with `steam_api64.dll` in the game
folder; the same DLL exposes the "flat C" exports
(`SteamAPI_ISteamUser_BLoggedOn`, `SteamAPI_ISteamUtils_GetServerRealTime`,
`SteamAPI_ISteamMatchmaking_*`, etc.). Hooking those + logging
invocation + return value will, in a single ~80-line patch:

- Distinguish #2′ from #3 — if any Steamworks query fires in the
  popup window, #2′ wins; if none, #3 wins.
- Likely name the trigger directly — the call that returns "not
  online" right before the popup is almost certainly the cause.

If the C flat exports show zero hits (i.e. DS2 uses the C++ vtable
interface directly via `SteamUser()->BLoggedOn()` style), pivot to
hooking the vtable on the interface pointers returned by `SteamUser()`,
`SteamUtils()`, `SteamMatchmaking()`. Same flag gate; ~20 more lines.

Fallback if Steamworks also shows nothing: Ghidra hunt for the popup
function in `DarkSoulsII.exe`. Template:
`PatchPhantomDismissalLoops` (`src/sync/player_sync.cpp:171`).

---

## 2026-05-26 update #3 — task #10 result, flat-C-export route closed

Task #10 build (H33Repro, dinput8.dll sha256
`b9405bce9ae2b3f722e0049bf1732f58dfe8cef46f011922f35f61f0a82c0b5c`)
added MinHook detours for five Steamworks flat-C exports
(`SteamAPI_ISteamUser_BLoggedOn`, `SteamAPI_ISteamUser_GetSteamID`,
`SteamAPI_ISteamUtils_GetServerRealTime`,
`SteamAPI_ISteamUtils_IsOverlayEnabled`,
`SteamAPI_ISteamMatchmaking_GetNumLobbyMembers`). Evidence:
`docs/repro/runs/h33-2026-05-26-steamhooks/` (`host.log`, `README.md`,
`steam_api64-exports.txt`).

**All five `GetProcAddress` lookups returned null.** DS2 ships an
~2014-era Steamworks SDK (`steam_api64.dll` sha256
`fc20547408a7c34f0bd4946a34c21aab48a75e3b98dce9e55969f486d37b212f`,
57 exports, zero containing the `ISteam_` substring). The
`SteamAPI_ISteam<Iface>_<Method>` flat-C wrapper naming was not
introduced into the Steamworks SDK until v1.41 (~2017) — DS2's
bundled DLL predates them entirely.

The DLL does export every global accessor needed for the vtable
pivot: `SteamUser`, `SteamUtils`, `SteamMatchmaking`, `SteamApps`,
`SteamFriends`, `SteamClient`, `SteamNetworking`,
`SteamRemoteStorage`, etc.

### What is now decided

- Flat-C-export hooking is impossible on this binary — not "didn't
  trigger," but "no targets exist."
- DS2's call site for the popup decision (if Steamworks-based) must
  go through one of: (a) the C++ vtable on the accessor's return
  pointer, or (b) `SteamClient`'s `ISteamClient::GetISteam*` factory
  pattern.
- Hypothesis #3 is still undecided — we couldn't test it.

### What is now active

Hypothesis #2′ (multiplexed Steam probe) and #3 (no network call at
all, popup fired from local state) both remain plausible. The decisive
test is the vtable pivot: hook the relevant slots on the interface
pointers returned by `SteamUser()`, `SteamUtils()`, `SteamMatchmaking()`
(call the accessor ourselves at install time, walk the vtable, patch the
N-th entry). If those see traffic in the silent window, #2′ wins. If
they see nothing, #3 wins and the next move is Ghidra.

### Where this ticket goes next (task #11)

Implement the vtable hooks. Slot indices for the methods of interest
are documented in the public Steamworks SDK v1.31 / v1.32 headers
(`isteamuser.h`, `isteamutils.h`, `isteammatchmaking.h`) — they have
been stable across that SDK line. Same `H33_REPRO_LOGGING` gate and
`[H33 STEAM]` log prefix as task #10.
