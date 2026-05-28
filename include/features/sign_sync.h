#pragma once

// H-26 Plan B feature: mod-side sign placement.
//
// Plan A (PR #9) flipped the engine's online flag but the session/RPC
// subsystem stays dormant, so DS2's normal sign-placement code path never
// fires. Plan B reaches into the engine's render-side sign-entity manager
// and adds entries directly, bypassing the dormant RPC.
//
// The engine's sign list lives at:
//     GameManagerImp + 0x90  -> SignManager           (vtable @ exe+0x10CB668)
//     SignManager   + 0x20   -> SummonSignSetCtrl     (vtable @ exe+0x10CB698)
//     SummonSignSetCtrl + 0x18 -> TSignSet<SummonSignParam> (vtable @ exe+0x10CB7E8)
//
// The "add a sign" primitive is TSignSet vtable slot[4]:
//     FUN_140213AC0 @ exe+0x213AC0
//     signature: SummonSignParam* __fastcall push_back_default(TSignSet*)
// It bumps the set's count, default-initialises the new entry, returns its
// address. Caller then fills in position, rotation, owner, type.
//
// The full RE trail is in tools/ghidra_h26b_*_results.txt and the scope doc
// at docs/repro/h26-plan-b-scope.md. The "outer_mgr == GameManagerImp"
// assumption is verified at runtime by vtable-magic-number checks; if the
// outer is something else, the resolver fails noisily and the wrapper
// returns null.

#include <cstdint>

namespace DS2Coop::Features {

// Caller-facing parameters for spawning a sign.
// NOTE: until SummonSignParam's internal offsets are RE'd, SpawnSign() only
// allocates the slot -- the field-write step is stubbed. Use
// AllocateRawSign() if you want the raw engine pointer to inspect or write
// to manually.
struct SpawnSignParam {
    float    posX, posY, posZ;   // world-space position
    float    rotY;               // facing (radians, Y-axis rotation)
    uint32_t signType;           // 0 = white, 1 = small-white, 2-5 = TBD
    uint32_t areaId;             // DS2 map/area ID
    uint64_t ownerPlayerId;      // peer's stable ID (matches PeerManager)
    char     ownerName[32];      // displayed name; mirrors HandshakePacket
};

class SignSync {
public:
    static SignSync& GetInstance();

    // Resolves the pointer chain on first call; subsequent calls return the
    // cached result. Returns false if any link in the chain fails its
    // vtable-magic-number check (i.e. the runtime layout doesn't match
    // what task #2's RE found in the static binary).
    bool Initialize();

    // Spawn a sign in the engine's local sign list. Returns the engine's
    // SummonSignParam* on success (caller can stash it for "remove later"
    // operations) or nullptr on failure. The `param` is currently logged
    // but not written into the entry -- SummonSignParam offsets within the
    // +0x20..+0x87 region are unresolved.
    void* SpawnSign(const SpawnSignParam& param);

    // Smoke-test entry point: allocate a TSignSet slot via push_back_default
    // and return the raw engine pointer with no field writes. Useful for
    // verifying that the resolver chain works at runtime before we trust
    // the offsets.
    void* AllocateRawSign();

    // Diagnostics for the resolver.
    bool        IsResolved() const  { return m_resolverValid; }
    uintptr_t   GetSignManager() const       { return reinterpret_cast<uintptr_t>(m_signManager); }
    uintptr_t   GetSummonSignSetCtrl() const { return reinterpret_cast<uintptr_t>(m_summonSignSetCtrl); }
    uintptr_t   GetTSignSet() const          { return reinterpret_cast<uintptr_t>(m_tSignSet); }
    uintptr_t   GetPushBackDefault() const   { return reinterpret_cast<uintptr_t>(m_pushBackDefault); }

private:
    SignSync() = default;
    ~SignSync() = default;
    SignSync(const SignSync&) = delete;
    SignSync& operator=(const SignSync&) = delete;

    bool ResolveChain();

    // Returns GameManagerImp, falling back to a lazy SignSync-owned AOB
    // scan + re-read if AddressResolver's 30s startup timeout missed it.
    uintptr_t ResolveGameManagerImp();

    bool  m_resolverValid   = false;

    void* m_pushBackDefault   = nullptr;
    void* m_signManager       = nullptr;
    void* m_summonSignSetCtrl = nullptr;
    void* m_tSignSet          = nullptr;

    // SignSync-owned lazy fallback for GameManagerImp:
    // - m_gmStaticPtrAddr: the .data location where the engine stores the
    //   live pointer (resolved once via AOB)
    // - m_gmScanAttempted: AOB scan only runs once per process
    uintptr_t m_gmStaticPtrAddr  = 0;
    bool      m_gmScanAttempted  = false;
};

} // namespace DS2Coop::Features
