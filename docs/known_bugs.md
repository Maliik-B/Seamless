# Known bugs (unrelated to current hardening work)

Bugs observed but not yet root-caused or fixed. Each entry lists the
symptom, what it blocks, where the code lives, and a sketch of a fix
shape. Ordered by recency, newest first.

---

## AddressResolver doesn't retry after init

**Observed:** 2026-05-27, during H-26 task #2 solo repro
(`docs/repro/runs/h26-2026-05-27-online-flag/`).

**Symptom:** With ethernet unplugged at boot, the address resolver
reports `GameManagerImp: [FAILED]` and `NetSessionManager: [FAILED]`
at the end of DLL init even though the underlying static-global
addresses were pattern-scanned successfully. `KatanaMainApp` resolves
fine because it's an early-init engine root.

**Mechanism:** `AddressResolver::ResolveAll` (`src/utils/address_resolver.cpp:54-79`)
pattern-scans for the *addresses of* the static globals, then polls
the value at each address for up to 30 seconds (60 * 500ms) waiting
for the game to populate the pointer. If the game hasn't allocated
GameManagerImp / NetSessionManager within that window, the resolver
gives up and stores 0. The resolver is **never re-invoked** later —
not when the user reaches main menu, not when they host a session,
not when they load a save.

**Impact:** Whenever boot is slow (offline mode, slow disk, long
shader-compile), the mod stays blind to player state for the entire
session. Symptoms cascade:
  - `MaxPhantomTimer: NetSessionManager not resolved` repeats every
    5s in `PlayerSync::Update`.
  - `GrantSoapstones` / `ReadPlayerPosition` / `ReadPlayerHealth`
    all fail with "BaseA is null" or equivalent.
  - Anything reading game memory via the resolver is dead until the
    next process launch.

The byte-patches against the exe (H-33 boot patches, H-26 online-flag
accessor, PatchPhantomReturn, etc.) all land fine — they're position-
independent and don't need the resolver.

**Suggested fix shape:** retry the value-read portion lazily on each
call to `GetGameManagerImp()` / `GetNetSessionManager()` when the
cached value is 0. Keep the address-of-global from the initial pattern
scan; only retry the pointer read. No extra pattern scan needed
(pattern-scan address is stable for the life of the process).

**Workaround:** launch DS2 once with network connected, then close and
relaunch with network disconnected — the first boot warms whatever
state is needed and subsequent offline boots may be faster. Not
verified.
