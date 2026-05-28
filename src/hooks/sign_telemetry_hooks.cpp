// H-26 Plan B sign-telemetry hooks.
//
// MinHooks on TSignSet<SummonSignParam>::push_back_default (slot[4],
// exe+0x213AC0) and push_back_take/move (slot[5], exe+0x213DD0). Logs
// caller PC + struct contents for the first 5 fires per function so we can
// read the engine's actual field layout when it fires these organically
// (slot[5] receives a fully-populated source SummonSignParam by ref; the
// hex dump of those 0x88 bytes is the layout itself).
//
// Why this exists: vtable-dispatch callers can't be found via Ghidra's
// reference manager even with full auto-analysis enabled (indirect calls
// require explicit C++ type info that DS2's binary doesn't have). The
// remaining cheap path is runtime capture.

#include "../../include/hooks.h"
#include "../../include/utils.h"
#include "MinHook.h"
#include <atomic>
#include <intrin.h>
#include <cstdio>

namespace DS2Coop::Hooks::SignTelemetryHooks {

namespace {

constexpr uintptr_t PUSH_BACK_DEFAULT_RVA = 0x213AC0;
constexpr uintptr_t PUSH_BACK_TAKE_RVA    = 0x213DD0;
constexpr int       LOG_LIMIT             = 5;

using PushBackDefaultFn = void* (__fastcall*)(void* tsignset);
using PushBackTakeFn    = void  (__fastcall*)(void* tsignset, void* source);

PushBackDefaultFn g_origPushBackDefault = nullptr;
PushBackTakeFn    g_origPushBackTake    = nullptr;

std::atomic<int> g_defaultCount{0};
std::atomic<int> g_takeCount{0};

void DumpHex88(const char* tag, void* ptr) {
    if (!ptr) {
        LOG_INFO("  %s = null", tag);
        return;
    }
    __try {
        const uint8_t* p = reinterpret_cast<const uint8_t*>(ptr);
        char hex[16 * 3 + 1];
        for (size_t off = 0; off < 0x88; off += 16) {
            int pos = 0;
            size_t chunk = (0x88 - off < 16) ? (0x88 - off) : 16;
            for (size_t i = 0; i < chunk; i++) {
                pos += snprintf(hex + pos, sizeof(hex) - pos, "%02X ", p[off + i]);
            }
            LOG_INFO("  %s +0x%02zX: %s", tag, off, hex);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        LOG_WARNING("  %s: SEH on read", tag);
    }
}

void* __fastcall DetourPushBackDefault(void* tsignset) {
    int count = ++g_defaultCount;
    void* caller = _ReturnAddress();
    void* result = g_origPushBackDefault(tsignset);
    if (count <= LOG_LIMIT) {
        LOG_INFO("[H26-TELEM] push_back_default #%d caller=%p tsignset=%p result=%p",
                 count, caller, tsignset, result);
        DumpHex88("[H26-TELEM] result-entry", result);
        if (count == LOG_LIMIT) {
            LOG_INFO("[H26-TELEM] push_back_default: log limit reached, suppressing further");
        }
    }
    return result;
}

void __fastcall DetourPushBackTake(void* tsignset, void* source) {
    int count = ++g_takeCount;
    void* caller = _ReturnAddress();
    if (count <= LOG_LIMIT) {
        // Log + dump source BEFORE calling original: slot[5] wipes source
        // after copying into the new entry.
        LOG_INFO("[H26-TELEM] push_back_take #%d caller=%p tsignset=%p source=%p (PRE-call dump)",
                 count, caller, tsignset, source);
        DumpHex88("[H26-TELEM] source", source);
    }
    g_origPushBackTake(tsignset, source);
    if (count == LOG_LIMIT) {
        LOG_INFO("[H26-TELEM] push_back_take: log limit reached, suppressing further");
    }
}

} // namespace

bool Install() {
    HMODULE hExe = GetModuleHandleW(nullptr);
    if (!hExe) {
        LOG_WARNING("[H26-TELEM] GetModuleHandleW(nullptr) failed");
        return false;
    }
    uintptr_t modBase = reinterpret_cast<uintptr_t>(hExe);
    void* pbd = reinterpret_cast<void*>(modBase + PUSH_BACK_DEFAULT_RVA);
    void* pbt = reinterpret_cast<void*>(modBase + PUSH_BACK_TAKE_RVA);

    MH_STATUS s = MH_CreateHook(pbd, reinterpret_cast<void*>(&DetourPushBackDefault),
                                reinterpret_cast<void**>(&g_origPushBackDefault));
    if (s != MH_OK) {
        LOG_WARNING("[H26-TELEM] MH_CreateHook push_back_default failed: %d", s);
        return false;
    }
    s = MH_CreateHook(pbt, reinterpret_cast<void*>(&DetourPushBackTake),
                      reinterpret_cast<void**>(&g_origPushBackTake));
    if (s != MH_OK) {
        LOG_WARNING("[H26-TELEM] MH_CreateHook push_back_take failed: %d", s);
        return false;
    }

    if (MH_EnableHook(pbd) != MH_OK) {
        LOG_WARNING("[H26-TELEM] MH_EnableHook push_back_default failed");
        return false;
    }
    if (MH_EnableHook(pbt) != MH_OK) {
        LOG_WARNING("[H26-TELEM] MH_EnableHook push_back_take failed");
        return false;
    }

    LOG_INFO("[H26-TELEM] installed: push_back_default=%p push_back_take=%p (limit=%d each)",
             pbd, pbt, LOG_LIMIT);
    return true;
}

} // namespace DS2Coop::Hooks::SignTelemetryHooks
