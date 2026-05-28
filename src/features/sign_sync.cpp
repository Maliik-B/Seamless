// H-26 Plan B feature: mod-side sign-placement engine bridge.
//
// Resolves the GameManagerImp -> SignManager -> SummonSignSetCtrl ->
// TSignSet<SummonSignParam> pointer chain identified during task #2's RE,
// then calls TSignSet::push_back_default to add a sign slot. See
// include/features/sign_sync.h for the chain layout and the RE references.

#include "../../include/features/sign_sync.h"
#include "../../include/address_resolver.h"
#include "../../include/addresses.h"
#include "../../include/pattern_scanner.h"
#include "../../include/utils.h"

namespace DS2Coop::Features {

namespace {

// All addresses are RVAs (offsets from exe module base). Rebased on the
// running module's load address inside ResolveChain().
constexpr uintptr_t PUSH_BACK_DEFAULT_RVA = 0x213AC0;  // TSignSet vtable slot[4]
constexpr uintptr_t SIGNMANAGER_VTABLE_RVA       = 0x10CB668;
constexpr uintptr_t SUMMONSIGNSETCTRL_VTABLE_RVA = 0x10CB698;
constexpr uintptr_t TSIGNSET_VTABLE_RVA          = 0x10CB7E8;

// Pointer-chain field offsets.
constexpr uint32_t OUTER_TO_SIGNMANAGER       = 0x90;
constexpr uint32_t SIGNMANAGER_TO_SUMMONCTRL  = 0x20;
constexpr uint32_t SUMMONCTRL_TO_TSIGNSET     = 0x18;

using PushBackDefaultFn = void* (__fastcall*)(void* tsignset);

} // namespace

SignSync& SignSync::GetInstance() {
    static SignSync instance;
    return instance;
}

bool SignSync::Initialize() {
    return ResolveChain();
}

uintptr_t SignSync::ResolveGameManagerImp() {
    // First try the global AddressResolver -- if it caught the engine
    // populating GameManagerImp during its 30s startup window, this hits.
    uintptr_t gm = DS2Coop::AddressResolver::GetInstance().GetGameManagerImp();
    if (gm) return gm;

    // Fallback: own the lookup. The resolver gave up because the engine
    // hadn't allocated GameManagerImp yet; re-read the static .data slot
    // fresh now. The AOB pattern scan only runs once per process; the
    // pointer read at the captured address happens every call.
    if (!m_gmScanAttempted) {
        m_gmScanAttempted = true;
        uintptr_t match = Utils::PatternScanner::FindPattern(
            Addresses::GAME_MANAGER_IMP.pattern,
            Addresses::GAME_MANAGER_IMP.mask,
            nullptr);
        if (!match) {
            LOG_WARNING("SignSync: GAME_MANAGER_IMP AOB scan failed");
            return 0;
        }
        m_gmStaticPtrAddr = Utils::PatternScanner::ResolveRIP(
            match,
            Addresses::GAME_MANAGER_IMP.offset_from_match,
            Addresses::GAME_MANAGER_IMP.pointer_offset);
        if (!m_gmStaticPtrAddr) {
            LOG_WARNING("SignSync: GAME_MANAGER_IMP RIP resolution failed");
            return 0;
        }
        LOG_INFO("SignSync: lazy GameManagerImp storage @ 0x%p",
                 reinterpret_cast<void*>(m_gmStaticPtrAddr));
    }
    if (!m_gmStaticPtrAddr) return 0;

    uintptr_t val = 0;
    if (!Utils::Memory::Read<uintptr_t>(m_gmStaticPtrAddr, &val) || !val) {
        return 0;
    }
    return val;
}

bool SignSync::ResolveChain() {
    if (m_resolverValid) return true;

    HMODULE hExe = GetModuleHandleW(nullptr);
    if (!hExe) {
        LOG_WARNING("SignSync: GetModuleHandleW(nullptr) failed");
        return false;
    }
    uintptr_t modBase = reinterpret_cast<uintptr_t>(hExe);
    m_pushBackDefault = reinterpret_cast<void*>(modBase + PUSH_BACK_DEFAULT_RVA);

    uintptr_t outerMgr = ResolveGameManagerImp();
    if (!outerMgr) {
        LOG_WARNING("SignSync: GameManagerImp still null -- engine hasn't populated it yet, try again after loading into a save");
        return false;
    }

    uintptr_t signMgr = 0;
    if (!Utils::Memory::Read<uintptr_t>(outerMgr + OUTER_TO_SIGNMANAGER, &signMgr) || !signMgr) {
        LOG_WARNING("SignSync: SignManager pointer null at outer+0x%X", OUTER_TO_SIGNMANAGER);
        return false;
    }
    uintptr_t signMgrVt = 0;
    if (!Utils::Memory::Read<uintptr_t>(signMgr, &signMgrVt)
            || signMgrVt != modBase + SIGNMANAGER_VTABLE_RVA) {
        LOG_WARNING("SignSync: SignManager vtable mismatch at %p (got 0x%llX, want 0x%llX). "
                    "Working assumption 'outer_mgr == GameManagerImp' is wrong.",
                    reinterpret_cast<void*>(signMgr),
                    static_cast<unsigned long long>(signMgrVt),
                    static_cast<unsigned long long>(modBase + SIGNMANAGER_VTABLE_RVA));
        return false;
    }
    m_signManager = reinterpret_cast<void*>(signMgr);

    // Smoke-test #3 (2026-05-27) revealed: SignManager doesn't directly own
    // a SummonSignSetCtrl. It owns a SignSetCtrlManager (vtable @ +0x10CB4A0)
    // at SignManager+0x68, plus assorted sibling SignSetCommonCtrl-derived
    // classes (ActiveSignManager, SignPreviewCtrl, SignEventAreaManager,
    // SignBlockAllocStrategy). The SummonSignSetCtrl pointer lives one level
    // deeper -- inside SignSetCtrlManager.
    //
    // SignSetCtrlManager's layout is unknown; walk a generous offset range
    // and find the slot whose vtable matches SummonSignSetCtrl.
    constexpr uintptr_t SIGNSETCTRLMANAGER_VTABLE_RVA = 0x10CB4A0;
    constexpr uint32_t  SIGNMANAGER_TO_CTRLMANAGER    = 0x68;

    uintptr_t ctrlMgr = 0;
    if (!Utils::Memory::Read<uintptr_t>(signMgr + SIGNMANAGER_TO_CTRLMANAGER, &ctrlMgr) || !ctrlMgr) {
        LOG_WARNING("SignSync: SignSetCtrlManager pointer null at SignMgr+0x%X",
                    SIGNMANAGER_TO_CTRLMANAGER);
        return false;
    }
    uintptr_t ctrlMgrVt = 0;
    if (!Utils::Memory::Read<uintptr_t>(ctrlMgr, &ctrlMgrVt)
            || ctrlMgrVt != modBase + SIGNSETCTRLMANAGER_VTABLE_RVA) {
        LOG_WARNING("SignSync: SignSetCtrlManager vtable mismatch at %p (got 0x%llX, want 0x%llX)",
                    reinterpret_cast<void*>(ctrlMgr),
                    static_cast<unsigned long long>(ctrlMgrVt),
                    static_cast<unsigned long long>(modBase + SIGNSETCTRLMANAGER_VTABLE_RVA));
        return false;
    }
    LOG_INFO("SignSync: SignSetCtrlManager @ %p (vtable validated)",
             reinterpret_cast<void*>(ctrlMgr));

    // Diagnostic dump: walk SignSetCtrlManager's first 0x100 bytes as qwords.
    // For each non-null pointer, log its vtable + RVA + a tag if it matches
    // SummonSignSetCtrl. Picks the first matching offset for the live chain.
    LOG_INFO("SignSync: dumping SignSetCtrlManager @ %p sub-pointer slots", reinterpret_cast<void*>(ctrlMgr));
    uintptr_t summonCtrl = 0;
    for (uint32_t off = 0x08; off <= 0x100; off += 0x08) {
        uintptr_t subPtr = 0;
        if (!Utils::Memory::Read<uintptr_t>(ctrlMgr + off, &subPtr) || !subPtr) {
            continue;
        }
        // Skip values too small to be heap pointers (state ints).
        if (subPtr < 0x10000) {
            LOG_INFO("  CtrlMgr+0x%-3X = 0x%llX  (looks like an int, skipping vtable check)",
                     off, static_cast<unsigned long long>(subPtr));
            continue;
        }
        uintptr_t subVt = 0;
        bool gotVt = Utils::Memory::Read<uintptr_t>(subPtr, &subVt);
        uintptr_t vtRva = gotVt ? (subVt - modBase) : 0;
        const char* tag = "";
        if (gotVt && subVt == modBase + SUMMONSIGNSETCTRL_VTABLE_RVA) {
            tag = " <-- SummonSignSetCtrl MATCH";
            if (summonCtrl == 0) summonCtrl = subPtr;
        }
        LOG_INFO("  CtrlMgr+0x%-3X = %p  vt=0x%llX (rva 0x%llX)%s",
                 off,
                 reinterpret_cast<void*>(subPtr),
                 static_cast<unsigned long long>(subVt),
                 static_cast<unsigned long long>(vtRva),
                 tag);
    }
    if (!summonCtrl) {
        LOG_WARNING("SignSync: SummonSignSetCtrl not found at any SignSetCtrlManager offset 0x08..0x100");
        return false;
    }
    m_summonSignSetCtrl = reinterpret_cast<void*>(summonCtrl);

    uintptr_t tsignset = 0;
    if (!Utils::Memory::Read<uintptr_t>(summonCtrl + SUMMONCTRL_TO_TSIGNSET, &tsignset) || !tsignset) {
        LOG_WARNING("SignSync: TSignSet pointer null at SummonCtrl+0x%X",
                    SUMMONCTRL_TO_TSIGNSET);
        return false;
    }
    uintptr_t tsignsetVt = 0;
    if (!Utils::Memory::Read<uintptr_t>(tsignset, &tsignsetVt)
            || tsignsetVt != modBase + TSIGNSET_VTABLE_RVA) {
        LOG_WARNING("SignSync: TSignSet vtable mismatch at %p (got 0x%llX, want 0x%llX)",
                    reinterpret_cast<void*>(tsignset),
                    static_cast<unsigned long long>(tsignsetVt),
                    static_cast<unsigned long long>(modBase + TSIGNSET_VTABLE_RVA));
        return false;
    }
    m_tSignSet = reinterpret_cast<void*>(tsignset);

    LOG_INFO("SignSync: chain resolved -- outer=%p signMgr=%p ctrl=%p tsignset=%p pushBack=%p",
             reinterpret_cast<void*>(outerMgr),
             m_signManager,
             m_summonSignSetCtrl,
             m_tSignSet,
             m_pushBackDefault);

    m_resolverValid = true;
    return true;
}

void* SignSync::AllocateRawSign() {
    if (!ResolveChain()) return nullptr;

    auto pb = reinterpret_cast<PushBackDefaultFn>(m_pushBackDefault);
    void* entry = nullptr;
    __try {
        entry = pb(m_tSignSet);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        LOG_WARNING("SignSync::AllocateRawSign: push_back_default threw");
        return nullptr;
    }

    if (!entry) {
        LOG_WARNING("SignSync::AllocateRawSign: push_back_default returned null");
        return nullptr;
    }

    LOG_INFO("SignSync::AllocateRawSign: new entry @ %p (sizeof=0x88)", entry);
    return entry;
}

void* SignSync::SpawnSign(const SpawnSignParam& param) {
    void* entry = AllocateRawSign();
    if (!entry) return nullptr;

    // SummonSignParam internal offsets within the +0x20..+0x87 region are
    // not yet RE'd. The static-binary disassembly told us +0x14 and +0x18
    // are bitfield dwords (sign-type + state flags), and +0x20..+0x87 is
    // 104 bytes of bulk-copyable data containing position / rotation /
    // owner / name -- but the exact offsets within that region are TBD.
    //
    // Once we get one organic sign to spawn through the normal engine path
    // (or run a full Ghidra analysis pass for vtable-dispatch xrefs to
    // push_back_default), we can fill these in. For now this logs the
    // input and leaves the entry in its default-init state.
    LOG_INFO("SignSync::SpawnSign: param pos=(%.2f,%.2f,%.2f) rotY=%.2f type=%u "
             "area=0x%X owner=%llu name='%.31s' -- field-writes are stubbed",
             param.posX, param.posY, param.posZ, param.rotY,
             param.signType, param.areaId,
             static_cast<unsigned long long>(param.ownerPlayerId),
             param.ownerName);

    return entry;
}

} // namespace DS2Coop::Features
