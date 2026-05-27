// Player Synchronization - ACTUAL GAME MEMORY READS
//
// This file reads player position/health/state from the game's memory
// using the resolved GameManagerImp base pointer and verified offsets
// from the Bob Edition cheat table.
//
// Pointer chain: GameManagerImp -> +0x38 (PlayerData) -> offsets

#include "../../include/sync.h"
#include "../../include/session.h"
#include "../../include/network.h"
#include "../../include/addresses.h"
#include "../../include/address_resolver.h"
#include "../../include/hooks.h"
#include "../../include/pattern_scanner.h"
#include "../../include/utils.h"
#include <chrono>
#include <cfloat>
#include <cstring>
#include <mutex>
#include <unordered_map>

using namespace DS2Coop::Sync;
using namespace DS2Coop::Utils;
using namespace DS2Coop::Addresses;

// ============================================================================
// H-20: sticky-write snapshot registry
// ----------------------------------------------------------------------------
// EnableSummoning() and MaxPhantomTimer() repeatedly poke game memory to keep
// the local player visible as a host (TeamType=0), keep bonfire bits set,
// keep the phantom timer maxed, etc. The H-20 emergency-disable hotkey needs
// to undo all of that. We can't snapshot "at hook install" because most of
// these addresses are discovered dynamically (heap scan, deref chain). The
// model is snapshot-on-first-touch: every sticky write goes through
// SnapshotWrite<T>(addr, newVal), which records the original value the FIRST
// time it sees an address and then writes the new value. RevertStickyWrites
// walks the map and restores originals.
//
// After RevertStickyWrites runs, g_emergencyLatched stays true so subsequent
// EnableSummoning / MaxPhantomTimer calls become no-ops — important because
// PlayerSync::Update is still ticking from the session-manager loop.
// ============================================================================
namespace {

struct StickyEntry {
    uint8_t size;     // 1, 2, 4, or 8 — number of bytes in `bytes`
    uint8_t bytes[8]; // original value (little-endian raw)
};

std::mutex                                  g_stickyMu;
std::unordered_map<uintptr_t, StickyEntry>  g_stickyOriginals;
bool                                        g_emergencyLatched = false;

template<typename T>
bool SnapshotWrite(uintptr_t addr, const T& newVal) {
    static_assert(sizeof(T) <= 8, "SnapshotWrite only supports up to 8 bytes");

    {
        std::lock_guard<std::mutex> lk(g_stickyMu);
        if (g_emergencyLatched) return false;  // post-revert: ignore further writes

        if (g_stickyOriginals.find(addr) == g_stickyOriginals.end()) {
            T original{};
            if (!Memory::Read<T>(addr, &original)) {
                // Can't snapshot — refuse to write, so we never have an
                // untracked sticky modification we couldn't revert.
                return false;
            }
            StickyEntry e{};
            e.size = static_cast<uint8_t>(sizeof(T));
            std::memcpy(e.bytes, &original, sizeof(T));
            g_stickyOriginals[addr] = e;
        }
    }
    return Memory::Write<T>(addr, newVal);
}

} // namespace

PlayerSync& PlayerSync::GetInstance() {
    static PlayerSync instance;
    return instance;
}

// ============================================================================
// NOP the boss-kill phantom return call in the exe.
//
// Ghidra analysis (2026-04-04):
//   FUN_14044ef30 is the event dispatch. Line 12 calls FUN_140191bb0
//   which creates EventPhantomReturn objects and sends all phantoms home.
//   The CALL instruction is at exe+0x44ef7b (5 bytes: e8 30 2c d4 ff).
//   NOPing it prevents the game from dismissing phantoms on boss death.
// ============================================================================
static void PatchPhantomReturnOnBossKill() {
    uintptr_t exeBase = (uintptr_t)GetModuleHandle(nullptr);
    uintptr_t callAddr = exeBase + 0x44ef7b;

    // Verify the bytes match the expected CALL instruction
    uint8_t expected[] = { 0xe8, 0x30, 0x2c, 0xd4, 0xff };
    uint8_t actual[5] = {};

    __try {
        memcpy(actual, (void*)callAddr, 5);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        LOG_ERROR("PatchPhantomReturn: cannot read exe at 0x%llX", callAddr);
        return;
    }

    if (memcmp(actual, expected, 5) != 0) {
        // Bytes don't match — might be a different exe version or already patched
        LOG_WARNING("PatchPhantomReturn: bytes at exe+0x44ef7b don't match expected CALL "
                    "(got %02X %02X %02X %02X %02X, expected e8 30 2c d4 ff) — skipping",
                    actual[0], actual[1], actual[2], actual[3], actual[4]);
        // Check if already NOPed
        uint8_t nops[] = { 0x90, 0x90, 0x90, 0x90, 0x90 };
        if (memcmp(actual, nops, 5) == 0) {
            LOG_INFO("PatchPhantomReturn: already patched (NOPs)");
        }
        return;
    }

    // Make the page writable, write NOPs, restore protection
    DWORD oldProtect = 0;
    if (!VirtualProtect((void*)callAddr, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        LOG_ERROR("PatchPhantomReturn: VirtualProtect failed (error %u)", GetLastError());
        return;
    }

    memset((void*)callAddr, 0x90, 5);  // 5x NOP
    VirtualProtect((void*)callAddr, 5, oldProtect, &oldProtect);

    LOG_INFO("PatchPhantomReturn: PATCHED exe+0x44ef7b — boss kill will no longer dismiss phantoms");
}

// ============================================================================
// NOP the per-phantom dismissal CALLs inside FUN_140191bb0.
//
// Ghidra analysis (2026-04-06):
//   The previous PatchPhantomReturnOnBossKill NOPed the entire CALL to
//   FUN_140191bb0 at exe+0x44ef7b. That broke death/respawn because
//   FUN_140191bb0 sets a completion flag at [RSI+0x24]=1 in its epilogue
//   that the death state machine waits for. Skipping the whole call left
//   the player permanently dead-but-not-respawning, with the pause menu
//   unable to open.
//
//   The fix is more surgical: NOP only the per-phantom dismissal CALLs
//   INSIDE FUN_140191bb0's two iteration loops. The function still runs,
//   the loops still iterate (they just do nothing per phantom), and the
//   epilogue still sets the completion flag. Death proceeds normally,
//   boss kills no longer dismiss phantoms.
//
//   FUN_140191bb0 structure (Ghidra disassembly):
//     +0x191bb0  prologue, allocates EventPhantomReturn objects
//     +0x191c80  loop 1: for each phantom in [RSI+0x28..+0x30]:
//     +0x191c87    CALL FUN_140190410       <-- DISMISSAL CALL #1
//     +0x191c8c    advance pointer
//     +0x191c93    loop back
//     +0x191d10  loop 2: for each phantom in [RSI+0x48..+0x50]:
//     +0x191d17    CALL FUN_14018dea0       <-- DISMISSAL CALL #2
//     +0x191d1c    advance pointer
//     +0x191d23    loop back
//     +0x191d8d  MOV byte ptr [RSI+0x24],0x1  <-- COMPLETION FLAG (must run)
//     +0x191d98  RET
//
//   Both CALLs are 5-byte near calls (E8 + 4-byte rel32). NOPing them
//   leaves the loops intact but turns each iteration into a no-op.
//
// Confirmed by ghidra_phantom_return_results.txt (Apr 6 run).
// ============================================================================
static void PatchPhantomDismissalLoops() {
    uintptr_t exeBase = (uintptr_t)GetModuleHandle(nullptr);

    struct PatchSite {
        const char* label;
        uintptr_t offset;
    };

    PatchSite sites[] = {
        { "loop1 dismissal", 0x191c87 },  // CALL FUN_140190410
        { "loop2 dismissal", 0x191d17 },  // CALL FUN_14018dea0
    };

    for (auto& site : sites) {
        uintptr_t addr = exeBase + site.offset;
        uint8_t actual[5] = {};

        __try {
            memcpy(actual, (void*)addr, 5);
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            LOG_ERROR("PatchDismissal: cannot read exe at 0x%llX (%s)", addr, site.label);
            continue;
        }

        // Already-patched check (5x NOP)
        uint8_t nops[] = { 0x90, 0x90, 0x90, 0x90, 0x90 };
        if (memcmp(actual, nops, 5) == 0) {
            LOG_INFO("PatchDismissal: %s at exe+0x%llX already NOPed", site.label, site.offset);
            continue;
        }

        // Verify first byte is a near CALL (E8). We don't verify the
        // full 4-byte offset because Ghidra base relocation may differ
        // from runtime — but the opcode E8 is the discriminator.
        if (actual[0] != 0xe8) {
            LOG_WARNING("PatchDismissal: %s at exe+0x%llX expected CALL (E8), got %02X — skipping",
                        site.label, site.offset, actual[0]);
            continue;
        }

        DWORD oldProtect = 0;
        if (!VirtualProtect((void*)addr, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            LOG_ERROR("PatchDismissal: VirtualProtect failed at 0x%llX (error %u)",
                      addr, GetLastError());
            continue;
        }

        memset((void*)addr, 0x90, 5);
        VirtualProtect((void*)addr, 5, oldProtect, &oldProtect);

        LOG_INFO("PatchDismissal: PATCHED %s at exe+0x%llX (NOPed dismissal call)",
                 site.label, site.offset);
    }
}

// ============================================================================
// Increase the player cap from 3 to 6.
//
// Ghidra analysis (2026-04-04):
//   FUN_1406ab050 is the JoinGuestPlayer message handler.
//   At exe+0x6ab0b6: MOV dword ptr [RBP+local_6c], 0x3 (c7 45 c3 03 00 00 00)
//   The 0x03 byte at exe+0x6ab0b9 is the player cap.
//   Changing it to 0x06 allows up to 6 players.
// ============================================================================
static void PatchPlayerCap() {
    uintptr_t exeBase = (uintptr_t)GetModuleHandle(nullptr);
    // The full instruction is: c7 45 c3 03 00 00 00
    // We verify the full 7 bytes but only change the 03 to 06
    uintptr_t instrAddr = exeBase + 0x6ab0b6;

    uint8_t expected[] = { 0xc7, 0x45, 0xc3, 0x03, 0x00, 0x00, 0x00 };
    uint8_t actual[7] = {};

    __try {
        memcpy(actual, (void*)instrAddr, 7);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        LOG_ERROR("PatchPlayerCap: cannot read exe at 0x%llX", instrAddr);
        return;
    }

    if (memcmp(actual, expected, 7) != 0) {
        // Check if already patched (03 -> 06)
        uint8_t patched[] = { 0xc7, 0x45, 0xc3, 0x06, 0x00, 0x00, 0x00 };
        if (memcmp(actual, patched, 7) == 0) {
            LOG_INFO("PatchPlayerCap: already patched (cap=6)");
            return;
        }
        LOG_WARNING("PatchPlayerCap: bytes at exe+0x6ab0b6 don't match expected "
                    "(got %02X %02X %02X %02X %02X %02X %02X) - skipping",
                    actual[0], actual[1], actual[2], actual[3],
                    actual[4], actual[5], actual[6]);
        return;
    }

    DWORD oldProtect = 0;
    if (!VirtualProtect((void*)instrAddr, 7, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        LOG_ERROR("PatchPlayerCap: VirtualProtect failed (error %u)", GetLastError());
        return;
    }

    // Change 0x03 to 0x06 at the immediate value position
    *((uint8_t*)(instrAddr + 3)) = 0x06;
    VirtualProtect((void*)instrAddr, 7, oldProtect, &oldProtect);

    LOG_INFO("PatchPlayerCap: PATCHED exe+0x6ab0b9 (local_6c 3->6)");

    // Second patch: the 0x3 written into the protobuf message struct at [RBX+0x1c]
    // 1406ab15b: c7 43 1c 03 00 00 00  MOV dword ptr [RBX+0x1c], 0x3
    uintptr_t msgAddr = exeBase + 0x6ab15b;
    uint8_t expected2[] = { 0xc7, 0x43, 0x1c, 0x03, 0x00, 0x00, 0x00 };
    uint8_t actual2[7] = {};

    __try {
        memcpy(actual2, (void*)msgAddr, 7);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        LOG_WARNING("PatchPlayerCap: cannot read second patch addr 0x%llX", msgAddr);
        return;
    }

    if (memcmp(actual2, expected2, 7) == 0) {
        DWORD oldProtect2 = 0;
        VirtualProtect((void*)msgAddr, 7, PAGE_EXECUTE_READWRITE, &oldProtect2);
        *((uint8_t*)(msgAddr + 3)) = 0x06;
        VirtualProtect((void*)msgAddr, 7, oldProtect2, &oldProtect2);
        LOG_INFO("PatchPlayerCap: PATCHED exe+0x6ab15e ([RBX+0x1c] 3->6) - protobuf MaxPlayers=6");
    } else {
        uint8_t patched2[] = { 0xc7, 0x43, 0x1c, 0x06, 0x00, 0x00, 0x00 };
        if (memcmp(actual2, patched2, 7) == 0)
            LOG_INFO("PatchPlayerCap: second patch already applied");
        else
            LOG_WARNING("PatchPlayerCap: second patch bytes mismatch at exe+0x6ab15b - skipping");
    }
}

// ============================================================================
// Skip the "DARK SOULS II service is not available" popup at boot (H-33).
//
// Ghidra analysis (2026-05-26, task #12, see docs/repro/runs/h33-2026-05-26-*):
//   DS2's title screen is driven by an FSM ("FeSubState..." per MSVC RTTI:
//   .?AVFeSubStateTitleSteamNetworkCheck@@,
//   .?AVFeSubStateTitleOnlineCheck@@,
//   .?AVFeSubStateOfflineModeWindow@@,
//   .?AVFeSubStateTitleSetOfflineMode@@,
//   .?AVFeSubStateTitleGameServerLogin@@, ...).
//   The boot chain on online-check failure is:
//     SteamNetworkCheck -> OnlineCheck -> OfflineModeWindow -> SetOfflineMode.
//   OfflineModeWindow::OnEnter (vtable+8 -> exe+0x104DB0) creates the popup.
//
//   FeSubStateTitleOnlineCheck's vtable lives at exe+0x10BD318. Its
//   shared OnEnter (vtable+8 -> exe+0x104ED0) does:
//     CALL [vtable+0x40]              ; slot 8 -- the per-class predicate
//     MOV  [this+0x24], EAX
//     TEST EAX, EAX
//     JNS  ok                          ; >= 0 -> state = 3 (success)
//     ...                              ; < 0  -> state = 1 (failure -> popup)
//
//   OnlineCheck's slot 8 (vtable+0x40 -> exe+0xF98C0) is the function that
//   returns -1 in the offline case (it queries [global 0x1416148f0]+0x22f0
//   then calls a slot-9 virtual; if both indicate "online but auth failed",
//   it returns -1; if network is unavailable in the first place, it returns
//   0). When it returns -1, the FSM transitions to OfflineModeWindow.
//
//   Replacing the function entry with XOR EAX, EAX / RET forces it to
//   always return 0. OnlineCheck's OnEnter sees the >= 0 result, sets
//   state = 3 (success), and the FSM proceeds to GameServerLogin without
//   ever entering OfflineModeWindow -- no popup.
//
//   The patch is narrow: only this one function changes. OfflineModeWindow's
//   own slot 8 (a stub returning 0) and other states' slot 8 implementations
//   are untouched. GameServerLogin then runs normally; if its actual server
//   handshake fails it surfaces a different (and game-handled) error path,
//   not the boot popup loop.
//
// Patch:
//   At exe+0xF98C0 the original 5-byte instruction is
//     48 89 5C 24 08    MOV [RSP+8], RBX    ; function prologue
//   We overwrite 5 bytes with
//     33 C0 C3 90 90    XOR EAX, EAX ; RET ; NOP ; NOP
//   The trailing NOPs preserve the original 5-byte window for clean byte
//   verification on subsequent runs; only bytes 0..2 actually execute.
// ============================================================================
namespace {

struct BootPatchSite {
    const char* label;
    uintptr_t   offset;
    size_t      len;
    const uint8_t* expected;
    const uint8_t* patched;
};

// OnlineCheck patch: force FeSubStateTitleOnlineCheck's slot-8 predicate
// at exe+0xF98C0 to return 0 (success), so the title-screen FSM never
// transitions OnlineCheck -> OfflineModeWindow on a network/auth fail.
static const uint8_t kOnlineCheckExpected[] = { 0x48, 0x89, 0x5C, 0x24, 0x08 };
static const uint8_t kOnlineCheckPatched [] = { 0x33, 0xC0, 0xC3, 0x90, 0x90 };

// SteamNetCheck patch: force FeSubStateTitleSteamNetworkCheck::OnEnter at
// exe+0xF8FB0 to unconditionally set [this+0x10] = 3 (success) and return,
// skipping both failure branches that would transition the FSM into
// FeSubStateOfflineModeWindow.
//
// Original first 10 bytes: prologue (MOV [RSP+8],RBX ; PUSH RDI ; SUB RSP,0x20)
// Patched:                 MOV dword ptr [RCX+0x10], 0x3 ; XOR EAX,EAX ; RET
// RCX holds `this` (MS x64 ABI). RBX/RDI/RSP are left untouched.
static const uint8_t kSteamNetExpected[] = {
    0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20
};
static const uint8_t kSteamNetPatched[] = {
    0xC7, 0x41, 0x10, 0x03, 0x00, 0x00, 0x00,
    0x33, 0xC0,
    0xC3
};

// GameServerLogin patch: same shape as OnlineCheck. Forces slot[8] to
// return 0 so the shared OnEnter at +0x104ED0 sets state=3 (done) and
// the FSM advances past GameServerLogin instead of dispatching FailWarn.
static const uint8_t kGameServerLoginExpected[] = { 0x48, 0x89, 0x5C, 0x24, 0x08 };
static const uint8_t kGameServerLoginPatched [] = { 0x33, 0xC0, 0xC3, 0x90, 0x90 };

// UserPolicy patch: same shape as SteamNetCheck. UserPolicy is the last
// substate in the title boot chain and does NOT use the shared OnEnter
// (its slot[1] is +0xF9040, its own). The original function has three
// early-exit success arms gated on byte flags at
// [GameManager+0xA8]->[0xD8]+0x136d/e] and on [global 0x14160DE10+0xA0]
// being null. In the patched-boot world none of those flags are set,
// so the function falls through to the heavy-work arm which calls
// 0x1400F5720 and writes [this+0x10]=1.
// We force [this+0x10]=3 (matches the legitimate success arms at
// +0xF9079 and +0xF90A9->+0xF9079) and return.
static const uint8_t kUserPolicyExpected[] = {
    0x48, 0x89, 0x6C, 0x24, 0x20, 0x56, 0x48, 0x83, 0xEC, 0x40
};
static const uint8_t kUserPolicyPatched[] = {
    0xC7, 0x41, 0x10, 0x03, 0x00, 0x00, 0x00,
    0x33, 0xC0,
    0xC3
};

// OfflineModePopupCall patch (try-11): NOP just the 5-byte
//   CALL 0x1404FE2A0
// at exe+0x104DEA, inside FUN_140104DB0's [this+0x12]<0 arm.
//
// The popup-fire logger from try-10 captured this exact CALL firing the
// framerate popup post-Press-Start (FE2A0 chain). +0x104DB0 is the
// shared OnEnter of FOUR vtables, so patching the whole function (try-5)
// deadlocked the legitimate JGE arm used by the other three classes.
// This surgical NOP kills only the popup-fire CALL inside the popup-arm;
// the JGE legitimate arm at +0x104DF4 onwards is untouched, and the
// inner.vtable[11] side-effect call before the popup-fire still runs.
// After the NOPs, the JMP 0x140104E80 right after the CALL still executes
// and jumps to the function epilogue.
//
// Original CALL bytes:  E8 B1 94 3F 00   (CALL rel32, displacement = 0x4FE2A0 - (0x104DEA+5) = 0x3F94B1)
// Patched bytes:        90 90 90 90 90   (5 NOPs)
static const uint8_t kOfflinePopupCallExpected[] = { 0xE8, 0xB1, 0x94, 0x3F, 0x00 };
static const uint8_t kOfflinePopupCallPatched [] = { 0x90, 0x90, 0x90, 0x90, 0x90 };

// OnlineFlagAccessor patch (H-26): force the engine's runtime "am I online?"
// accessor to always return 1.
//
// Ghidra analysis (2026-05-27, H-26 task #2, see docs/repro/runs/h26-2026-05-26-solo-confirm/):
//   The H-33 patches above shortcut the title-FSM substates' OnEnter to
//   "success" without ever populating the engine's runtime online-state.
//   The title screen reaches the main menu, but the underlying boolean
//   "is the service online" remains 0 (offline). Multiple gates downstream
//   of the title screen — sign placement, sign-list query, summon — read
//   this boolean and silently refuse local actions when it's 0. Task #1's
//   solo repro confirmed: zero protobuf messages sent during a
//   white-soapstone-place attempt; the engine never even tried.
//
//   The boolean lives at byte offset 0x3A of the service-manager object,
//   which is reached via the GameManager singleton:
//     RAX = [0x1416148F0]      ; GameManager
//     RCX = [RAX + 0x22F0]     ; serviceMgr
//     ; is_online = serviceMgr->[0x3A]
//
//   The canonical accessor is FUN_140513600 at exe+0x513600, exactly 5
//   bytes long:
//     0F B6 41 3A   MOVZX EAX, byte ptr [RCX + 0x3A]
//     C3             RET
//
//   34 callers across the engine read through this accessor (per Ghidra
//   refMgr — see tools/ghidra_h26_online_accessor_results.txt). The
//   already-patched H-33 OnlineCheck predicate at +0xF98C0 also calls
//   into it, though that path is dead now.
//
//   Replacing the 5-byte body with the 5-byte sequence
//     33 C0          XOR EAX, EAX
//     FF C0          INC EAX
//     C3             RET
//   makes every caller see "online = 1". The byte at [serviceMgr + 0x3A]
//   is unchanged, but no in-game code reads it directly — they all go
//   through FUN_140513600. Same surgical patch style as the H-33 sites.
//
//   Plan A (writing 1 to the underlying byte at runtime) was considered
//   but rejected: would require waiting for GameManager initialization,
//   plus periodic re-writes in case the engine clears the flag mid-session.
//   Plan B (this patch) is applied once at DllMain alongside the H-33
//   patches and is timing-independent.
static const uint8_t kOnlineFlagAccessorExpected[] = { 0x0F, 0xB6, 0x41, 0x3A, 0xC3 };
static const uint8_t kOnlineFlagAccessorPatched [] = { 0x33, 0xC0, 0xFF, 0xC0, 0xC3 };

static const BootPatchSite kSites[] = {
    { "OnlineCheck",          0xF98C0,   sizeof(kOnlineCheckExpected),
      kOnlineCheckExpected,          kOnlineCheckPatched },
    { "SteamNetCheck",        0xF8FB0,   sizeof(kSteamNetExpected),
      kSteamNetExpected,             kSteamNetPatched },
    // H-26 phase 3 experiment (2026-05-27): the hypothesis that
    // FUN_1400F9820's body would wake the session/RPC subsystem was
    // FALSIFIED. With this site removed, the body's event-allocation +
    // queue-registration path ran but [H26 PROTO] count stayed 0 for the
    // full session, AND a new regression appeared: GameManagerImp /
    // NetSessionManager failed to populate within the resolver's 30s
    // window (overlay green bar broke). The body presumably blocks on or
    // slows down inner-service init when it runs without real FROM auth.
    // Re-enabled. The session-wake trigger lives somewhere else --
    // probably after the title FSM completes, or requires a real FROM
    // server response we'll never get.
    { "GameServerLogin",      0xF9820,   sizeof(kGameServerLoginExpected),
      kGameServerLoginExpected,      kGameServerLoginPatched },
    // H-26 phase 3 iter 2 experiment (2026-05-27): hypothesis that
    // UserPolicy's body would wake the session/RPC subsystem was also
    // FALSIFIED. Body ran without crash but [H26 PROTO] count stayed 0 AND
    // NetSessionManager failed to populate (resolver regression, narrower
    // than the GameServerLogin variant: GameManagerImp survived this time).
    // Combined with the GameServerLogin negative result above, Plan A
    // ("the session-wake is in an H-33-bypassed body") is essentially dead.
    // The session-wake is more likely to require a real FROM-server reply
    // or to live in a later phase entirely (character-select activation /
    // world-load). Re-enabled.
    { "UserPolicy",           0xF9040,   sizeof(kUserPolicyExpected),
      kUserPolicyExpected,           kUserPolicyPatched },
    { "OfflinePopupCall",     0x104DEA,  sizeof(kOfflinePopupCallExpected),
      kOfflinePopupCallExpected,     kOfflinePopupCallPatched },
    { "OnlineFlagAccessor",   0x513600,  sizeof(kOnlineFlagAccessorExpected),
      kOnlineFlagAccessorExpected,   kOnlineFlagAccessorPatched },
};

} // namespace

void DS2Coop::Sync::ApplyBootPopupPatch() {
    uintptr_t exeBase = (uintptr_t)GetModuleHandle(nullptr);

    for (const BootPatchSite& site : kSites) {
        uintptr_t addr = exeBase + site.offset;
        uint8_t actual[16] = {};
        if (site.len > sizeof(actual)) {
            LOG_ERROR("PatchBootPopup: site %s len %zu exceeds buffer",
                      site.label, site.len);
            continue;
        }

        __try {
            memcpy(actual, (void*)addr, site.len);
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            LOG_ERROR("PatchBootPopup: cannot read exe at 0x%llX (%s)",
                      (unsigned long long)addr, site.label);
            continue;
        }

        if (memcmp(actual, site.patched, site.len) == 0) {
            LOG_INFO("PatchBootPopup: %s at exe+0x%llX already patched",
                     site.label, (unsigned long long)site.offset);
            continue;
        }
        if (memcmp(actual, site.expected, site.len) != 0) {
            LOG_WARNING("PatchBootPopup: %s at exe+0x%llX bytes mismatch - skipping",
                        site.label, (unsigned long long)site.offset);
            continue;
        }

        DWORD oldProtect = 0;
        if (!VirtualProtect((void*)addr, site.len, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            LOG_ERROR("PatchBootPopup: VirtualProtect failed at 0x%llX (%s, error %u)",
                      (unsigned long long)addr, site.label, GetLastError());
            continue;
        }
        memcpy((void*)addr, site.patched, site.len);
        VirtualProtect((void*)addr, site.len, oldProtect, &oldProtect);

        LOG_INFO("PatchBootPopup: PATCHED %s at exe+0x%llX (%zu bytes)",
                 site.label, (unsigned long long)site.offset, site.len);
    }
}

bool PlayerSync::Initialize() {
    if (m_initialized) return true;

    LOG_INFO("Initializing player sync...");

    // Verify we have the GameManagerImp address
    auto& resolver = DS2Coop::AddressResolver::GetInstance();
    if (!resolver.GetGameManagerImp()) {
        LOG_WARNING("GameManagerImp not resolved - player sync will use session data only");
    } else {
        LOG_INFO("Player sync will read from GameManagerImp at 0x%p",
                 reinterpret_cast<void*>(resolver.GetGameManagerImp()));
    }

    // Patch out boss-kill phantom dismissal — surgical version.
    // The old PatchPhantomReturnOnBossKill() NOPed the whole call to
    // FUN_140191bb0 and broke death/respawn because that function's
    // epilogue sets a completion flag the death state machine waits for.
    // PatchPhantomDismissalLoops() instead NOPs only the per-phantom
    // dismissal CALLs inside FUN_140191bb0's two iteration loops, so
    // the function still runs to completion and sets the flag.
    PatchPhantomDismissalLoops();

    // Increase player cap from 3 to 6
    PatchPlayerCap();

    // H-33 task #12 popup patch is NOT called here — it must run at DllMain
    // time (before the title screen). See SeamlessCoopMod::Initialize.

    m_initialized = true;
    LOG_INFO("Player sync initialized");
    return true;
}

void PlayerSync::Shutdown() {
    if (!m_initialized) return;
    LOG_INFO("Shutting down player sync...");
    m_initialized = false;
}

// ============================================================================
// Read player data directly from game memory
// ============================================================================

static bool ReadPlayerDataBase(uintptr_t& outPlayerData) {
    auto& resolver = DS2Coop::AddressResolver::GetInstance();
    uintptr_t gmImp = resolver.GetGameManagerImp();
    if (!gmImp) return false;

    // GameManagerImp -> +0x38 -> PlayerData pointer
    uintptr_t playerDataPtr = 0;
    if (!Memory::Read<uintptr_t>(gmImp + Offsets::GameManager::PlayerData, &playerDataPtr)) {
        return false;
    }

    if (!playerDataPtr) return false;
    outPlayerData = playerDataPtr;
    return true;
}

static bool ReadCharacterNameRaw(uintptr_t playerData, wchar_t* nameBuf, int maxChars) {
    __try {
        for (int i = 0; i < maxChars; i++) {
            wchar_t ch = 0;
            if (!Memory::Read<wchar_t>(playerData + Offsets::GameManager::CharacterName + i * 2, &ch))
                break;
            if (ch == 0) break;
            nameBuf[i] = ch;
        }
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Try reading a wchar name from an address, convert to UTF-8. Returns "" on failure.
static std::string WcharToUtf8(const wchar_t* buf) {
    if (!buf || buf[0] == 0) return "";
    if (buf[0] < 0x20) return ""; // not printable — likely a pointer, not a name
    int len = WideCharToMultiByte(CP_UTF8, 0, buf, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 1) return "";
    std::string result(len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, buf, -1, &result[0], len, nullptr, nullptr);
    return result;
}

// SEH helper: read name wchars into a plain array, no C++ objects
static bool TryReadNameBuffer(uintptr_t addr, wchar_t* buf, int maxChars) {
    __try {
        for (int i = 0; i < maxChars; i++) {
            wchar_t ch = 0;
            if (!Memory::Read<wchar_t>(addr + i * 2, &ch) || ch == 0) break;
            if (ch < 0x20 || ch > 0x9FFF) return false;
            buf[i] = ch;
        }
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static std::string TryReadNameFrom(uintptr_t addr, const char* source) {
    wchar_t nameBuf[32] = {};
    if (!TryReadNameBuffer(addr, nameBuf, 31)) return "";
    if (nameBuf[0] == 0) return "";
    std::string result = WcharToUtf8(nameBuf);
    if (!result.empty())
        LOG_INFO("[NAME] Character name from %s: %s", source, result.c_str());
    return result;
}

static std::string ReadCharacterName() {
    auto& resolver = DS2Coop::AddressResolver::GetInstance();
    uintptr_t gmImp = resolver.GetGameManagerImp();
    uintptr_t netSession = resolver.GetNetSessionManager();

    // PATH 1: GMImp → [+0xA8] → +0x114 (wchar_t, LOCAL player's own name)
    // Confirmed by Bob Edition CT + DS2S-META: OFLD(ANYSOTFS, STRBASEA, 0xa8, 0x114)
    // This is the GameDataManager path — stores YOUR character name, not the host's.
    if (gmImp) {
        uintptr_t gdm = 0;
        if (Memory::Read<uintptr_t>(gmImp + 0xA8, &gdm) && gdm) {
            std::string name = TryReadNameFrom(gdm + 0x114, "GameDataMgr+0x114");
            if (!name.empty()) return name;
        }
    }

    // PATH 2: NSM → [+0x20] → +0x234 (host/opponent name — fallback only)
    if (netSession) {
        uintptr_t pp = 0;
        if (Memory::Read<uintptr_t>(netSession + 0x20, &pp) && pp) {
            std::string name = TryReadNameFrom(pp + 0x234, "NetSession+0x234");
            if (!name.empty()) return name;
        }
    }

    // PATH 3: GMImp → [+0x38] → +0x24 (PlayerData path — legacy fallback)
    if (gmImp) {
        uintptr_t pd = 0;
        if (Memory::Read<uintptr_t>(gmImp + 0x38, &pd) && pd) {
            std::string name = TryReadNameFrom(pd + 0x24, "PlayerData+0x24");
            if (!name.empty()) return name;
        }
    }

    return "";
}

static bool ReadPlayerPosition(float& x, float& y, float& z, float& rotY) {
    uintptr_t playerData = 0;
    if (!ReadPlayerDataBase(playerData)) return false;

    bool ok = true;
    ok &= Memory::Read<float>(playerData + Offsets::GameManager::PositionX, &x);
    ok &= Memory::Read<float>(playerData + Offsets::GameManager::PositionY, &y);
    ok &= Memory::Read<float>(playerData + Offsets::GameManager::PositionZ, &z);
    // Rotation is optional — don't fail the whole read if it's wrong
    if (!Memory::Read<float>(playerData + Offsets::GameManager::RotationY, &rotY))
        rotY = 0.0f;
    return ok;
}

static bool ReadPlayerHealth(int32_t& health, int32_t& maxHealth) {
    // HP is on PlayerCtrl (GMImp+0xD0), NOT PlayerData (GMImp+0x38).
    // PlayerCtrl + 0x168 = current HP, +0x170 = max HP (SotFS, from DS2S-META).
    auto& resolver = DS2Coop::AddressResolver::GetInstance();
    uintptr_t gmImp = resolver.GetGameManagerImp();
    if (!gmImp) return false;

    uintptr_t playerCtrl = 0;
    if (!Memory::Read<uintptr_t>(gmImp + 0xD0, &playerCtrl) || !playerCtrl) return false;

    bool ok = true;
    ok &= Memory::Read<int32_t>(playerCtrl + 0x168, &health);
    ok &= Memory::Read<int32_t>(playerCtrl + 0x170, &maxHealth);
    return ok;
}

static bool ReadPlayerLevel(uint32_t& level) {
    uintptr_t playerData = 0;
    if (!ReadPlayerDataBase(playerData)) return false;

    return Memory::Read<uint32_t>(playerData + Offsets::GameManager::Level, &level);
}

static bool ReadPlayerStamina(float& stamina) {
    uintptr_t playerData = 0;
    if (!ReadPlayerDataBase(playerData)) return false;

    return Memory::Read<float>(playerData + Offsets::GameManager::Stamina, &stamina);
}

// ============================================================================
// Sync update loop
// ============================================================================

void PlayerSync::Update(float deltaTime) {
    if (!m_initialized) return;

    __try {
        m_positionSyncTimer += deltaTime;
        m_stateSyncTimer += deltaTime;
        m_phantomTimerRefresh += deltaTime;

        if (m_positionSyncTimer >= POSITION_SYNC_INTERVAL) {
            SyncLocalPlayerPosition();
            m_positionSyncTimer = 0.0f;
        }

        if (m_stateSyncTimer >= STATE_SYNC_INTERVAL) {
            SyncLocalPlayerState();
            m_stateSyncTimer = 0.0f;
        }

        // Keep phantom timer maxed every 5s (infrequent is fine)
        if (m_phantomTimerRefresh >= 5.0f) {
            MaxPhantomTimer();
            m_phantomTimerRefresh = 0.0f;
        }

        // Keep permission patches active every 1s — bonfire bits are checked
        // every frame by the game, so 5s gaps cause intermittent blocking.
        static float s_summoningTimer = 0.0f;
        s_summoningTimer += deltaTime;
        if (s_summoningTimer >= 1.0f) {
            EnableSummoning();
            s_summoningTimer = 0.0f;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LOG_ERROR("PlayerSync::Update CRASHED (exception 0x%08X) — disabling sync",
                  GetExceptionCode());
        m_initialized = false;
    }
}

// ============================================================================
// Position sync - reads ACTUAL game memory
// ============================================================================
void PlayerSync::SyncLocalPlayerPosition() {
    auto& sessionMgr = Session::SessionManager::GetInstance();
    if (!sessionMgr.IsActive()) return;

    // Copy local player data under lock to avoid racing with network thread
    auto players = sessionMgr.GetPlayers();
    Session::SessionPlayer* localPlayer = nullptr;
    uint64_t localId = Network::PeerManager::GetInstance().GetLocalPlayerId();
    for (auto& p : players) {
        if (p.playerId == localId) { localPlayer = &p; break; }
    }
    if (!localPlayer) return;

    float x = 0, y = 0, z = 0, rotY = 0;

    // Try reading from actual game memory first
    if (ReadPlayerPosition(x, y, z, rotY)) {
        // Store back to session manager (the copy is discarded, so write directly)
        sessionMgr.UpdatePlayerPosition(localId, x, y, z);
    } else {
        x = localPlayer->x;
        y = localPlayer->y;
        z = localPlayer->z;
        //LOG_DEBUG("Could not read player position from game memory, using cached");
    }

    // Build and broadcast position packet
    static uint32_t posSequence = 0;
    Network::PlayerPositionPacket packet{};
    packet.header.magic = 0x44533243;
    packet.header.type = Network::PacketType::PlayerPosition;
    packet.header.size = sizeof(Network::PlayerPositionPacket);
    packet.header.sequence = ++posSequence;
    packet.header.timestamp = std::chrono::system_clock::now().time_since_epoch().count();
    packet.playerId = localPlayer->playerId;
    packet.x = x;
    packet.y = y;
    packet.z = z;
    packet.rotX = 0.0f;
    packet.rotY = rotY;
    packet.rotZ = 0.0f;
    packet.animation = 0;

    auto& peerMgr = Network::PeerManager::GetInstance();
    peerMgr.BroadcastPacket(&packet.header);

    //LOG_DEBUG("Synced position: (%.2f, %.2f, %.2f)", x, y, z);
}

// ============================================================================
// State sync - reads ACTUAL game memory
// ============================================================================
void PlayerSync::SyncLocalPlayerState() {
    auto& sessionMgr = Session::SessionManager::GetInstance();
    if (!sessionMgr.IsActive()) return;

    auto players = sessionMgr.GetPlayers();
    Session::SessionPlayer* localPlayer = nullptr;
    uint64_t localId = Network::PeerManager::GetInstance().GetLocalPlayerId();
    for (auto& p : players) {
        if (p.playerId == localId) { localPlayer = &p; break; }
    }
    if (!localPlayer) return;

    int32_t health = 0, maxHealth = 0;
    float stamina = 0;
    uint32_t soulLevel = 0;

    // Read actual values from game memory
    bool gotHealth = ReadPlayerHealth(health, maxHealth);
    bool gotLevel = ReadPlayerLevel(soulLevel);
    ReadPlayerStamina(stamina);

    if (gotHealth) {
        sessionMgr.UpdatePlayerHealth(localId, health, maxHealth);
    } else {
        health = localPlayer->health;
        maxHealth = localPlayer->maxHealth;
    }

    if (gotLevel) {
        sessionMgr.UpdatePlayerLevel(localId, soulLevel);
    } else {
        soulLevel = localPlayer->soulLevel;
    }

    // Build and broadcast state packet
    Network::PlayerStatePacket packet{};
    packet.header.magic = 0x44533243;
    packet.header.type = Network::PacketType::PlayerState;
    packet.header.size = sizeof(Network::PlayerStatePacket);
    packet.header.timestamp = std::chrono::system_clock::now().time_since_epoch().count();
    packet.playerId = localPlayer->playerId;
    packet.health = health;
    packet.maxHealth = maxHealth;
    packet.stamina = static_cast<int32_t>(stamina);
    packet.maxStamina = 100;
    packet.souls = 0;
    packet.soulLevel = soulLevel;

    auto& peerMgr = Network::PeerManager::GetInstance();
    peerMgr.BroadcastPacket(&packet.header);

    //LOG_DEBUG("Synced state: HP %d/%d, SL %u", health, maxHealth, soulLevel);
}

// ============================================================================
// Remote player updates (from network)
// ============================================================================

void PlayerSync::ApplyRemotePlayerPosition(uint64_t playerId, float x, float y, float z,
                                           float rotX, float rotY, float rotZ) {
    //LOG_DEBUG("Remote player position: (%.2f, %.2f, %.2f)", playerId, x, y, z);
    auto& sessionMgr = Session::SessionManager::GetInstance();
    sessionMgr.UpdatePlayerPosition(playerId, x, y, z);
}

void PlayerSync::ApplyRemotePlayerState(uint64_t playerId, int32_t health, int32_t maxHealth,
                                        int32_t stamina, int32_t maxStamina) {
    //LOG_DEBUG("Remote player state: HP %d/%d", playerId, health, maxHealth);
    auto& sessionMgr = Session::SessionManager::GetInstance();
    sessionMgr.UpdatePlayerHealth(playerId, health, maxHealth);
}

void PlayerSync::SyncAnimation(uint64_t playerId, uint32_t animationId) {
    LOG_DEBUG("Animation sync for player %llu: %u", playerId, animationId);
}

void PlayerSync::SyncEquipment(uint64_t playerId) {
    LOG_DEBUG("Equipment sync for player %llu", playerId);
}

// ============================================================================
// Item struct for the game's internal ItemGive function (16 bytes)
// ============================================================================
#pragma pack(push, 1)
struct DS2ItemStruct {
    int32_t  type;       // 3 = consumable
    int32_t  itemId;     // e.g. 0x03B280B0
    float    durability; // FLT_MAX
    int16_t  quantity;   // count
    uint8_t  upgrade;    // 0-10
    uint8_t  infusion;   // 0 = none
};
#pragma pack(pop)

// x64 fastcall: void ItemGive(void* bag, DS2ItemStruct* items, int count, int mode)
typedef void (__fastcall *ItemGiveFunc)(void* bag, DS2ItemStruct* items, int count, int mode);
static ItemGiveFunc g_itemGiveFunc = nullptr;
static bool g_itemGiveScanned = false;

// ============================================================================
// Resolve the ItemGive function and AvailableItemBag pointer
// ============================================================================
static bool ResolveItemGive(uintptr_t& outBag) {
    // Find ItemGive function via AOB (only scan once)
    if (!g_itemGiveScanned) {
        g_itemGiveScanned = true;
        uintptr_t addr = DS2Coop::Utils::PatternScanner::FindPattern(
            ItemGib::ITEM_GIVE_PATTERN,
            ItemGib::ITEM_GIVE_MASK,
            nullptr);
        if (addr) {
            g_itemGiveFunc = reinterpret_cast<ItemGiveFunc>(addr);
            LOG_INFO("ItemGive function found at %p", reinterpret_cast<void*>(addr));
        } else {
            LOG_WARNING("ItemGive function not found — soapstone grant unavailable");
        }
    }

    if (!g_itemGiveFunc) return false;

    // Resolve AvailableItemBag: [BaseA] -> +0xA8 -> +0x10 -> +0x10
    auto& resolver = DS2Coop::AddressResolver::GetInstance();
    uintptr_t baseA = resolver.GetGameManagerImp();
    if (!baseA) { LOG_WARNING("ResolveItemGive: BaseA is null"); return false; }

    uintptr_t ptr1 = 0, ptr2 = 0, bag = 0;
    if (!Memory::Read<uintptr_t>(baseA + ItemGib::AvailItemBag_Off1, &ptr1) || !ptr1) {
        LOG_WARNING("ResolveItemGive: ptr1 failed (BaseA=%p +0x%X)", (void*)baseA, ItemGib::AvailItemBag_Off1);
        return false;
    }
    if (!Memory::Read<uintptr_t>(ptr1 + ItemGib::AvailItemBag_Off2, &ptr2) || !ptr2) {
        LOG_WARNING("ResolveItemGive: ptr2 failed (ptr1=%p +0x%X)", (void*)ptr1, ItemGib::AvailItemBag_Off2);
        return false;
    }
    if (!Memory::Read<uintptr_t>(ptr2 + ItemGib::AvailItemBag_Off3, &bag) || !bag) {
        LOG_WARNING("ResolveItemGive: bag failed (ptr2=%p +0x%X)", (void*)ptr2, ItemGib::AvailItemBag_Off3);
        return false;
    }

    LOG_INFO("ResolveItemGive: BaseA=%p -> ptr1=%p -> ptr2=%p -> bag=%p",
             (void*)baseA, (void*)ptr1, (void*)ptr2, (void*)bag);
    outBag = bag;
    return true;
}

// ============================================================================
// Grant White Sign Soapstone + Small White Sign Soapstone
// Calls the game's internal ItemGive function
// ============================================================================
bool PlayerSync::GrantSoapstones() {
    uintptr_t bag = 0;
    if (!ResolveItemGive(bag)) {
        LOG_WARNING("GrantSoapstones: could not resolve ItemGive or AvailableItemBag");
        return false;
    }

    DS2ItemStruct items[2] = {};

    // White Sign Soapstone
    items[0].type       = ItemCategory::Consumable;
    items[0].itemId     = ItemIDs::WhiteSignSoapstone;
    items[0].durability = FLT_MAX;
    items[0].quantity   = 1;
    items[0].upgrade    = 0;
    items[0].infusion   = 0;

    // Small White Sign Soapstone
    items[1].type       = ItemCategory::Consumable;
    items[1].itemId     = ItemIDs::SmallWhiteSignSoapstone;
    items[1].durability = FLT_MAX;
    items[1].quantity   = 1;
    items[1].upgrade    = 0;
    items[1].infusion   = 0;

    LOG_INFO("GrantSoapstones: calling ItemGive at %p with bag=%p, 2 items",
             reinterpret_cast<void*>(g_itemGiveFunc), reinterpret_cast<void*>(bag));

    __try {
        // Give items one at a time to isolate which one crashes (if any)
        g_itemGiveFunc(reinterpret_cast<void*>(bag), &items[0], 1, 0);
        LOG_INFO("GrantSoapstones: White Sign Soapstone given");

        g_itemGiveFunc(reinterpret_cast<void*>(bag), &items[1], 1, 0);
        LOG_INFO("GrantSoapstones: Small White Sign Soapstone given");

        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        LOG_ERROR("GrantSoapstones: ItemGive crashed (exception 0x%08X)",
                  GetExceptionCode());
        // Disable further attempts
        g_itemGiveFunc = nullptr;
        return false;
    }
}

// ============================================================================
// Max out phantom AllottedTime so the summon never expires
// ============================================================================
bool PlayerSync::MaxPhantomTimer() {
    if (IsEmergencyLatched()) return false;  // H-20: post-revert no-op

    auto& resolver = DS2Coop::AddressResolver::GetInstance();
    uintptr_t netSession = resolver.GetNetSessionManager();
    if (!netSession) {
        LOG_ERROR("MaxPhantomTimer: NetSessionManager not resolved");
        return false;
    }

    // NetSessionManager -> +0x18 (SessionPointer) -> +0x17C (AllottedTime)
    uintptr_t sessionPtr = 0;
    if (!Memory::Read<uintptr_t>(netSession + Offsets::NetSession::SessionPointer, &sessionPtr) || !sessionPtr) {
        LOG_WARNING("MaxPhantomTimer: no active session pointer");
        return false;
    }

    // Set AllottedTime to a huge value (float, in seconds). H-20: routed
    // through SnapshotWrite so the original is restored on emergency disable.
    float maxTime = 99999.0f;
    if (SnapshotWrite<float>(sessionPtr + Offsets::NetSession::AllottedTime, maxTime)) {
        LOG_DEBUG("MaxPhantomTimer: AllottedTime set to %.0f", maxTime);
        return true;
    }

    LOG_DEBUG("MaxPhantomTimer: failed to write AllottedTime");
    return false;
}

// ============================================================================
// Enable summoning regardless of hollow state, and force host-equivalent
// permissions for all players (bonfire, NPC, chest, fog wall access).
// Runs every 5 seconds while seamless is active.
// ============================================================================
void PlayerSync::EnableSummoning() {
    if (!DS2Coop::Hooks::ProtobufHooks::IsSeamlessActive()) return;
    if (IsEmergencyLatched()) return;  // H-20: post-revert no-op

    auto& resolver = DS2Coop::AddressResolver::GetInstance();
    uintptr_t gmImp = resolver.GetGameManagerImp();
    if (!gmImp) return;

    // ==========================================================================
    // 1. TeamType patch (CE-verified, 2026-04-02)
    //
    // Heap-allocated uint16 written by DarkSoulsII.exe+0xDF1719.
    // 0=Host, 513=WhitePhantom, 515=Sunbro, 1799=DarkSpirit.
    // Scan for value 513 near player data, cache address, keep writing 0.
    // ==========================================================================
    static uintptr_t s_teamTypeAddr = 0;
    static int s_scanAttempts = 0;
    static bool s_teamTypeLogged = false;

    if (s_teamTypeAddr != 0) {
        __try {
            uint16_t val = 0;
            if (Memory::Read<uint16_t>(s_teamTypeAddr, &val)) {
                if (val == 513 || val == 514 || val == 515 || val == 516) {
                    SnapshotWrite<uint16_t>(s_teamTypeAddr, (uint16_t)0);
                    if (!s_teamTypeLogged) {
                        LOG_INFO("TeamType PATCHED to Host (was %u) at 0x%llX", val, s_teamTypeAddr);
                        s_teamTypeLogged = true;
                    }
                }
            } else {
                s_teamTypeAddr = 0;
                s_teamTypeLogged = false;
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            s_teamTypeAddr = 0;
            s_teamTypeLogged = false;
        }
    } else if (s_scanAttempts <= 10) {
        s_scanAttempts++;
        __try {
            uintptr_t searchBases[4] = {0};
            int baseCount = 0;

            uintptr_t pd = 0;
            if (Memory::Read<uintptr_t>(gmImp + 0x38, &pd) && pd)
                searchBases[baseCount++] = pd;

            uintptr_t npm = 0;
            if (Memory::Read<uintptr_t>(gmImp + 0x10, &npm) && npm) {
                searchBases[baseCount++] = npm;
                uintptr_t lp = 0;
                if (Memory::Read<uintptr_t>(npm + 0x18, &lp) && lp)
                    searchBases[baseCount++] = lp;
            }

            for (int b = 0; b < baseCount && s_teamTypeAddr == 0; b++) {
                uintptr_t base = searchBases[b];
                for (uintptr_t offset = 0; offset < 0x10000; offset += 2) {
                    uint16_t val = 0;
                    if (Memory::Read<uint16_t>(base + offset, &val) && val == 513) {
                        SnapshotWrite<uint16_t>(base + offset, (uint16_t)0);
                        uint16_t check = 0;
                        Memory::Read<uint16_t>(base + offset, &check);
                        if (check == 0) {
                            s_teamTypeAddr = base + offset;
                            LOG_INFO("TeamType FOUND at 0x%llX (base+0x%llX), set to 0", s_teamTypeAddr, offset);
                            break;
                        }
                    }
                }
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {}
    }

    // ==========================================================================
    // 2. Hollowing — DISABLED: caused crash (wrote 0 to wrong field, value was
    // 244 which suggests offset 0x1AC is not hollowing in this build).
    // Needs CE re-verification before re-enabling.
    // ==========================================================================

    // ==========================================================================
    // 3. Phantom field — Bob Edition CT: NetSessionManager → [+0x20] → +0x1F4
    //
    // This is the field the game checks to determine if the local player is a
    // phantom. Zeroing it makes the game treat the local player as the host
    // for permission checks (bonfire, NPC, chest, fog wall).
    // ==========================================================================
    uintptr_t netSession = resolver.GetNetSessionManager();
    if (netSession) {
        __try {
            uintptr_t playerPtr = 0;
            if (Memory::Read<uintptr_t>(netSession + Offsets::NetSession::PlayerPointer, &playerPtr) && playerPtr) {
                uint32_t phantomField = 0;
                if (Memory::Read<uint32_t>(playerPtr + 0x1F4, &phantomField) && phantomField != 0) {
                    SnapshotWrite<uint32_t>(playerPtr + 0x1F4, (uint32_t)0);
                    LOG_INFO("EnableSummoning: Phantom field zeroed (was %u) via [NSM+0x20]+0x1F4", phantomField);
                }
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {}
    }

    // ==========================================================================
    // 4. Session-slot TeamType — DISABLED: value 127 at [NSM+0x20][+0x1E8][slot*8][+0xB0]+0x4D
    // is not TeamType — wrong pointer chain. Zeroing it corrupted game state → crash.
    // Needs CE re-verification before re-enabling.
    // ==========================================================================

    // ==========================================================================
    // 5. Bonfire access bits — Bob Edition CT:
    //    GameManagerImp → [+0xD0] → [+0xB8] → +0x4C8, bits 4+5
    //
    // bit 4 = isBonfireStart, bit 5 = isBonfireLoop.
    // The host bonfire restriction checks phantom count > 0. Separately,
    // the phantom-side restriction checks these bits. Setting both forces
    // the game to allow bonfire interaction regardless of session state.
    // ==========================================================================
    __try {
        uintptr_t ptr_d0 = 0, ptr_b8 = 0;
        if (Memory::Read<uintptr_t>(gmImp + 0xD0, &ptr_d0) && ptr_d0) {
            if (Memory::Read<uintptr_t>(ptr_d0 + 0xB8, &ptr_b8) && ptr_b8) {
                uint32_t flags = 0;
                if (Memory::Read<uint32_t>(ptr_b8 + 0x4C8, &flags)) {
                    uint32_t newFlags = flags | (1u << 4) | (1u << 5);
                    if (newFlags != flags) {
                        SnapshotWrite<uint32_t>(ptr_b8 + 0x4C8, newFlags);
                        LOG_INFO("EnableSummoning: isBonfireStart/Loop bits set (0x%X -> 0x%X)", flags, newFlags);
                    }
                }
            }

            // ==========================================================================
            // 4. ChrNetworkPhantomId — Bob Edition CT:
            //    GameManagerImp → [+0xD0] → [+0xB0] → +0x3C (byte)
            //
            // This byte controls phantom rendering (ghostly white appearance).
            // 0 = normal player rendering, non-zero = phantom appearance.
            // Zeroing it makes all players appear as solid/normal.
            // ==========================================================================
            uintptr_t ptr_b0 = 0;
            if (Memory::Read<uintptr_t>(ptr_d0 + 0xB0, &ptr_b0) && ptr_b0) {
                uint8_t phantomId = 0;
                if (Memory::Read<uint8_t>(ptr_b0 + 0x3C, &phantomId) && phantomId != 0) {
                    SnapshotWrite<uint8_t>(ptr_b0 + 0x3C, (uint8_t)0);
                    LOG_INFO("EnableSummoning: ChrNetworkPhantomId zeroed (was %u) — solid appearance", phantomId);
                }
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {}
}

std::string PlayerSync::GetLocalCharacterName() {
    return ReadCharacterName();
}

// ============================================================================
// H-20 — emergency revert
// ----------------------------------------------------------------------------
// Walk the snapshot map and restore each address to its original value, then
// latch g_emergencyLatched so further EnableSummoning / MaxPhantomTimer calls
// become no-ops (PlayerSync::Update keeps ticking from the session-manager
// loop; we don't tear that down).
//
// Errors are not fatal: if an address has become invalid (player left the
// session, memory freed), Memory::Write returns false and we log + skip.
// Idempotent: calling it twice does no harm.
// ============================================================================
void PlayerSync::RevertStickyWrites() {
    std::lock_guard<std::mutex> lk(g_stickyMu);

    if (g_emergencyLatched && g_stickyOriginals.empty()) {
        return;  // already reverted
    }

    size_t total = g_stickyOriginals.size();
    size_t ok = 0, fail = 0;

    for (const auto& kv : g_stickyOriginals) {
        uintptr_t addr = kv.first;
        const StickyEntry& e = kv.second;
        bool wrote = false;

        switch (e.size) {
        case 1: {
            uint8_t v;  std::memcpy(&v, e.bytes, 1);
            wrote = Memory::Write<uint8_t>(addr, v);
            break;
        }
        case 2: {
            uint16_t v; std::memcpy(&v, e.bytes, 2);
            wrote = Memory::Write<uint16_t>(addr, v);
            break;
        }
        case 4: {
            uint32_t v; std::memcpy(&v, e.bytes, 4);
            wrote = Memory::Write<uint32_t>(addr, v);
            break;
        }
        case 8: {
            uint64_t v; std::memcpy(&v, e.bytes, 8);
            wrote = Memory::Write<uint64_t>(addr, v);
            break;
        }
        default:
            break;
        }

        if (wrote) {
            ok++;
        } else {
            fail++;
            LOG_WARNING("RevertStickyWrites: failed to restore addr 0x%llX (size %u)",
                        (unsigned long long)addr, (unsigned)e.size);
        }
    }

    g_stickyOriginals.clear();
    g_emergencyLatched = true;

    LOG_INFO("RevertStickyWrites: %zu/%zu restored, %zu failed", ok, total, fail);
}

size_t PlayerSync::StickyWriteCount() const {
    std::lock_guard<std::mutex> lk(g_stickyMu);
    return g_stickyOriginals.size();
}

bool PlayerSync::IsEmergencyLatched() const {
    std::lock_guard<std::mutex> lk(g_stickyMu);
    return g_emergencyLatched;
}
