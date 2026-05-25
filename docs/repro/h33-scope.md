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
