// Network Hooks - Winsock interception + Server redirect
//
// Two functions:
// 1. Hook Winsock connect() to redirect game connections from FromSoft → custom server
// 2. Patch hostname + RSA key in game memory so the game resolves to our server

// WinSock2 MUST be included before Windows.h
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <MSWSock.h>
#include <Windows.h>

#pragma comment(lib, "ws2_32.lib")

#include <Psapi.h>
#pragma comment(lib, "psapi.lib")

#include "../../include/hooks.h"
#include "../../include/addresses.h"
#include "../../include/utils.h"
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>

using namespace DS2Coop::Hooks;
using namespace DS2Coop::Utils;
using namespace DS2Coop::Addresses;

// ============================================================================
// Winsock redirect state
// ============================================================================
static int (WSAAPI* g_originalConnect)(SOCKET s, const sockaddr* name, int namelen) = nullptr;
static bool g_gameOnline = false;
static bool g_redirectActive = false;
static std::string g_redirectIP = "127.0.0.1";
static uint16_t g_redirectPort = 50031;

#ifdef H33_REPRO_LOGGING
// H-33 throwaway: hook DNS resolution so we can identify which hostname
// triggers the port-80 HTTP probe at boot. The H-26 repro proved a
// connection to 104.26.12.205:80 (Cloudflare anycast — IP doesn't identify
// the hostname). Step 1 of the H-33 plan is to capture the hostname.
// Strip or guard-flip before PR.
static int (WSAAPI* g_originalGetaddrinfo)(const char* node, const char* service,
                                            const struct addrinfo* hints,
                                            struct addrinfo** res) = nullptr;
static int (WSAAPI* g_originalGetaddrinfoW)(const wchar_t* node, const wchar_t* service,
                                             const ADDRINFOW* hints,
                                             ADDRINFOW** res) = nullptr;

static void H33LogResolvedAddrs(const char* hostname, const struct addrinfo* res) {
    int count = 0;
    for (const struct addrinfo* p = res; p && count < 8; p = p->ai_next, ++count) {
        if (p->ai_family == AF_INET && p->ai_addr) {
            char ipStr[INET_ADDRSTRLEN] = {};
            auto* sin = reinterpret_cast<const sockaddr_in*>(p->ai_addr);
            inet_ntop(AF_INET, &sin->sin_addr, ipStr, sizeof(ipStr));
            LOG_INFO("[H33 DNS] %s -> %s", hostname, ipStr);
        }
    }
    if (count == 0) {
        LOG_INFO("[H33 DNS] %s -> (no IPv4 results)", hostname);
    }
}

static int WSAAPI H33GetaddrinfoHook(const char* node, const char* service,
                                      const struct addrinfo* hints,
                                      struct addrinfo** res) {
    int rc = g_originalGetaddrinfo(node, service, hints, res);
    if (node) {
        if (rc == 0 && res && *res) {
            H33LogResolvedAddrs(node, *res);
        } else {
            LOG_INFO("[H33 DNS] %s -> FAIL (rc=%d)", node, rc);
        }
    }
    return rc;
}

static int WSAAPI H33GetaddrinfoWHook(const wchar_t* node, const wchar_t* service,
                                       const ADDRINFOW* hints,
                                       ADDRINFOW** res) {
    int rc = g_originalGetaddrinfoW(node, service, hints, res);
    if (node) {
        char nodeUtf8[256] = {};
        WideCharToMultiByte(CP_UTF8, 0, node, -1, nodeUtf8, sizeof(nodeUtf8) - 1, nullptr, nullptr);
        if (rc == 0 && res && *res) {
            int count = 0;
            for (const ADDRINFOW* p = *res; p && count < 8; p = p->ai_next, ++count) {
                if (p->ai_family == AF_INET && p->ai_addr) {
                    char ipStr[INET_ADDRSTRLEN] = {};
                    auto* sin = reinterpret_cast<const sockaddr_in*>(p->ai_addr);
                    inet_ntop(AF_INET, &sin->sin_addr, ipStr, sizeof(ipStr));
                    LOG_INFO("[H33 DNS] %s -> %s (W)", nodeUtf8, ipStr);
                }
            }
            if (count == 0) {
                LOG_INFO("[H33 DNS] %s -> (no IPv4 results) (W)", nodeUtf8);
            }
        } else {
            LOG_INFO("[H33 DNS] %s -> FAIL (rc=%d) (W)", nodeUtf8, rc);
        }
    }
    return rc;
}

// H-33 update 2026-05-25: the popup-triggering call is invisible to
// connect()/getaddrinfo. Extend the capture to the remaining Winsock
// connect entry points so we can see WHICH API DS2 is using before the
// popup fires. Hypothesis #1 from docs/repro/h33-scope.md.
static int (WSAAPI* g_originalWSAConnect)(SOCKET, const sockaddr*, int,
                                          LPWSABUF, LPWSABUF, LPQOS, LPQOS) = nullptr;
static BOOL (WSAAPI* g_originalWSAConnectByNameA)(SOCKET, LPCSTR, LPCSTR,
                                                   LPDWORD, LPSOCKADDR, LPDWORD,
                                                   LPSOCKADDR, const timeval*,
                                                   LPWSAOVERLAPPED) = nullptr;
static BOOL (WSAAPI* g_originalWSAConnectByNameW)(SOCKET, LPWSTR, LPWSTR,
                                                   LPDWORD, LPSOCKADDR, LPDWORD,
                                                   LPSOCKADDR, const timeval*,
                                                   LPWSAOVERLAPPED) = nullptr;
static LPFN_CONNECTEX g_originalConnectEx = nullptr;

static void H33LogSockaddr(const char* tag, const sockaddr* name) {
    if (!name || name->sa_family != AF_INET) {
        LOG_INFO("[H33 NET] %s -> (non-IPv4 or null sockaddr)", tag);
        return;
    }
    const auto* sin = reinterpret_cast<const sockaddr_in*>(name);
    char ipStr[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &sin->sin_addr, ipStr, sizeof(ipStr));
    LOG_INFO("[H33 NET] %s -> %s:%u", tag, ipStr, ntohs(sin->sin_port));
}

static int WSAAPI H33WSAConnectHook(SOCKET s, const sockaddr* name, int namelen,
                                     LPWSABUF caller, LPWSABUF callee,
                                     LPQOS sqos, LPQOS gqos) {
    H33LogSockaddr("WSAConnect", name);
    return g_originalWSAConnect(s, name, namelen, caller, callee, sqos, gqos);
}

static BOOL PASCAL H33ConnectExHook(SOCKET s, const sockaddr* name, int namelen,
                                     PVOID sendBuffer, DWORD sendDataLength,
                                     LPDWORD bytesSent, LPOVERLAPPED overlapped) {
    H33LogSockaddr("ConnectEx", name);
    return g_originalConnectEx(s, name, namelen, sendBuffer, sendDataLength,
                                bytesSent, overlapped);
}

static BOOL WSAAPI H33WSAConnectByNameAHook(SOCKET s, LPCSTR nodename, LPCSTR servicename,
                                             LPDWORD localLen, LPSOCKADDR localAddr,
                                             LPDWORD remoteLen, LPSOCKADDR remoteAddr,
                                             const timeval* timeout, LPWSAOVERLAPPED ov) {
    LOG_INFO("[H33 NET] WSAConnectByNameA -> %s:%s",
             nodename ? nodename : "(null)",
             servicename ? servicename : "(null)");
    return g_originalWSAConnectByNameA(s, nodename, servicename, localLen, localAddr,
                                        remoteLen, remoteAddr, timeout, ov);
}

static BOOL WSAAPI H33WSAConnectByNameWHook(SOCKET s, LPWSTR nodename, LPWSTR servicename,
                                             LPDWORD localLen, LPSOCKADDR localAddr,
                                             LPDWORD remoteLen, LPSOCKADDR remoteAddr,
                                             const timeval* timeout, LPWSAOVERLAPPED ov) {
    char nodeUtf8[256] = {};
    char svcUtf8[64] = {};
    if (nodename) WideCharToMultiByte(CP_UTF8, 0, nodename, -1, nodeUtf8, sizeof(nodeUtf8) - 1, nullptr, nullptr);
    if (servicename) WideCharToMultiByte(CP_UTF8, 0, servicename, -1, svcUtf8, sizeof(svcUtf8) - 1, nullptr, nullptr);
    LOG_INFO("[H33 NET] WSAConnectByNameW -> %s:%s",
             nodename ? nodeUtf8 : "(null)",
             servicename ? svcUtf8 : "(null)");
    return g_originalWSAConnectByNameW(s, nodename, servicename, localLen, localAddr,
                                        remoteLen, remoteAddr, timeout, ov);
}

// ConnectEx is a per-driver extension obtained via WSAIoctl, not exported by
// name from ws2_32. Resolve it once at install time using a throwaway socket.
static void* H33ResolveConnectEx() {
    WSADATA wsa = {};
    bool weStarted = (WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
    SOCKET tmp = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (tmp == INVALID_SOCKET) {
        if (weStarted) WSACleanup();
        return nullptr;
    }
    GUID guid = WSAID_CONNECTEX;
    LPFN_CONNECTEX fn = nullptr;
    DWORD bytes = 0;
    int rc = WSAIoctl(tmp, SIO_GET_EXTENSION_FUNCTION_POINTER,
                      &guid, sizeof(guid), &fn, sizeof(fn), &bytes,
                      nullptr, nullptr);
    closesocket(tmp);
    if (weStarted) WSACleanup();
    return (rc == 0) ? reinterpret_cast<void*>(fn) : nullptr;
}

// H-33 task #11 (2026-05-26 update #3): task #10 proved DS2's bundled
// steam_api64.dll predates the SteamAPI_ISteam<Iface>_<Method> flat-C
// wrappers (SDK ~v1.31/v1.32, 57 exports, zero ISteam_ wrappers). DS2 must
// be using the C++ vtable interfaces via the global accessors that DO
// exist (`SteamUser`, `SteamUtils`, `SteamMatchmaking`, ...).
//
// Strategy:
//   1. Hook SteamAPI_Init / SteamAPI_InitSafe to install vtable hooks
//      post-init (when the accessors return valid pointers).
//   2. Also attempt immediate install at mod-init time, in case Steam was
//      already initialized before our DllMain ran.
//   3. Walk each interface's vtable and log the first ~20 slots
//      (module + offset). Ground truth for any future hook additions and
//      sanity check that we're hooking the right thing.
//   4. Patch only slot indices that are stable across the SDK v1.31 line:
//        - ISteamUser  slot 1 = BLoggedOn       -> bool
//        - ISteamUser  slot 2 = GetSteamID      -> CSteamID (uint64)
//        - ISteamUtils slot 3 = GetServerRealTime -> uint32
//      Less-stable slots (IsOverlayEnabled, GetNumLobbyMembers) are NOT
//      patched in this iteration — the vtable dump tells us where they
//      live so a follow-up build can hook them with confidence.
//
// All vtable methods take `this` as the implicit first argument; on
// Windows x64 MSVC __thiscall ≡ __fastcall, so a regular C function with
// `void* self` as the first param matches binary-wise.

// MSVC x64: 8-byte trivially-copyable types (incl. CSteamID's union) are
// returned in RAX and passed by value in an integer register. Modelling
// CSteamID as uint64_t is ABI-correct for both directions.
using PFN_VT_BLoggedOn         = bool    (*)(void* self);
using PFN_VT_GetSteamID        = uint64_t(*)(void* self);
using PFN_VT_GetServerRealTime = uint32_t(*)(void* self);

static PFN_VT_BLoggedOn         g_origVT_BLoggedOn         = nullptr;
static PFN_VT_GetSteamID        g_origVT_GetSteamID        = nullptr;
static PFN_VT_GetServerRealTime g_origVT_GetServerRealTime = nullptr;

static bool H33VT_BLoggedOnHook(void* self) {
    bool rc = g_origVT_BLoggedOn(self);
    LOG_INFO("[H33 STEAM] ISteamUser::BLoggedOn -> %s", rc ? "true" : "false");
    return rc;
}

static uint64_t H33VT_GetSteamIDHook(void* self) {
    uint64_t rc = g_origVT_GetSteamID(self);
    LOG_INFO("[H33 STEAM] ISteamUser::GetSteamID -> %llu", (unsigned long long)rc);
    return rc;
}

static uint32_t H33VT_GetServerRealTimeHook(void* self) {
    uint32_t rc = g_origVT_GetServerRealTime(self);
    LOG_INFO("[H33 STEAM] ISteamUtils::GetServerRealTime -> %u", rc);
    return rc;
}

// Log the first `slots` entries of an interface's vtable, with the owning
// module's name + offset where each entry lives. Owning module is usually
// steamclient64.dll (steam_api64.dll is a thin shim that delegates via
// IPC pipe to the runtime client) — recording it makes the dump
// interpretable across SDK versions.
static void H33LogVtable(const char* tag, void* iface, int slots) {
    if (!iface) {
        LOG_INFO("[H33 STEAM] %s: null interface, skipping vtable dump", tag);
        return;
    }
    void** vtbl = *reinterpret_cast<void***>(iface);
    LOG_INFO("[H33 STEAM] %s vtbl @ %p (this=%p)", tag, vtbl, iface);
    for (int i = 0; i < slots; ++i) {
        void* fn = vtbl[i];
        HMODULE owner = nullptr;
        char modName[MAX_PATH] = {};
        if (GetModuleHandleExA(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                    GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<LPCSTR>(fn), &owner) && owner) {
            DWORD n = GetModuleBaseNameA(GetCurrentProcess(), owner,
                                          modName, sizeof(modName));
            modName[n < sizeof(modName) ? n : sizeof(modName) - 1] = '\0';
            uintptr_t offset = reinterpret_cast<uintptr_t>(fn) -
                               reinterpret_cast<uintptr_t>(owner);
            LOG_INFO("[H33 STEAM]   %s[%2d] = %s+0x%llx (%p)",
                     tag, i, modName, (unsigned long long)offset, fn);
        } else {
            LOG_INFO("[H33 STEAM]   %s[%2d] = %p (no module)", tag, i, fn);
        }
    }
}

static std::atomic<bool> g_h33SteamVtableHooksInstalled{false};

static void H33TryInstallSteamVtableHooks(const char* trigger) {
    if (g_h33SteamVtableHooksInstalled.load(std::memory_order_acquire)) return;

    HMODULE steam = GetModuleHandleA("steam_api64.dll");
    if (!steam) return;

    using PFN_Accessor = void* (*)();
    auto pSteamUser        = reinterpret_cast<PFN_Accessor>(
        GetProcAddress(steam, "SteamUser"));
    auto pSteamUtils       = reinterpret_cast<PFN_Accessor>(
        GetProcAddress(steam, "SteamUtils"));
    auto pSteamMatchmaking = reinterpret_cast<PFN_Accessor>(
        GetProcAddress(steam, "SteamMatchmaking"));

    if (!pSteamUser || !pSteamUtils || !pSteamMatchmaking) {
        LOG_WARNING("[H33 STEAM] Global accessors missing (User=%p Utils=%p Match=%p)",
                    pSteamUser, pSteamUtils, pSteamMatchmaking);
        return;
    }

    void* iUser        = pSteamUser();
    void* iUtils       = pSteamUtils();
    void* iMatchmaking = pSteamMatchmaking();

    if (!iUser || !iUtils || !iMatchmaking) {
        // Steam not initialized yet (or init failed). Allow a later retry
        // from the SteamAPI_Init hook — do NOT set the installed flag.
        LOG_INFO("[H33 STEAM] %s: interfaces not ready yet (User=%p Utils=%p Match=%p) — will retry post-init",
                 trigger, iUser, iUtils, iMatchmaking);
        return;
    }

    // CAS the flag so we install exactly once if both the immediate path
    // and the Init-hook path race.
    bool expected = false;
    if (!g_h33SteamVtableHooksInstalled.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel)) {
        return;
    }

    LOG_INFO("[H33 STEAM] Installing vtable hooks (trigger=%s)", trigger);
    LOG_INFO("[H33 STEAM] Accessors -> User=%p Utils=%p Matchmaking=%p",
             iUser, iUtils, iMatchmaking);

    H33LogVtable("ISteamUser",        iUser,        12);
    H33LogVtable("ISteamUtils",       iUtils,       24);
    H33LogVtable("ISteamMatchmaking", iMatchmaking, 24);

    void** vtUser  = *reinterpret_cast<void***>(iUser);
    void** vtUtils = *reinterpret_cast<void***>(iUtils);

    // Slot 1: ISteamUser::BLoggedOn — present from the earliest SDK
    // revisions; unchanged through v1.31/v1.32/...
    if (HookManager::GetInstance().InstallHook(
            vtUser[1],
            reinterpret_cast<void*>(&H33VT_BLoggedOnHook),
            reinterpret_cast<void**>(&g_origVT_BLoggedOn))) {
        LOG_INFO("  HOOKED ISteamUser::BLoggedOn @ %p (slot 1, H33 repro)", vtUser[1]);
    } else {
        LOG_WARNING("  H33: failed to hook ISteamUser::BLoggedOn @ %p", vtUser[1]);
    }

    // Slot 2: ISteamUser::GetSteamID — also long-standing slot.
    if (HookManager::GetInstance().InstallHook(
            vtUser[2],
            reinterpret_cast<void*>(&H33VT_GetSteamIDHook),
            reinterpret_cast<void**>(&g_origVT_GetSteamID))) {
        LOG_INFO("  HOOKED ISteamUser::GetSteamID @ %p (slot 2, H33 repro)", vtUser[2]);
    } else {
        LOG_WARNING("  H33: failed to hook ISteamUser::GetSteamID @ %p", vtUser[2]);
    }

    // Slot 3: ISteamUtils::GetServerRealTime — stable since ISteamUtils005.
    if (HookManager::GetInstance().InstallHook(
            vtUtils[3],
            reinterpret_cast<void*>(&H33VT_GetServerRealTimeHook),
            reinterpret_cast<void**>(&g_origVT_GetServerRealTime))) {
        LOG_INFO("  HOOKED ISteamUtils::GetServerRealTime @ %p (slot 3, H33 repro)", vtUtils[3]);
    } else {
        LOG_WARNING("  H33: failed to hook ISteamUtils::GetServerRealTime @ %p", vtUtils[3]);
    }
}

// SteamAPI_Init / SteamAPI_InitSafe: hook so we can install the vtable hooks
// at the moment Steam becomes ready, regardless of timing relative to our
// own init. Cdecl on x64 collapses to the default MS x64 calling convention.
using PFN_SteamAPI_Init = bool (*)();
static PFN_SteamAPI_Init g_origSteamAPI_Init     = nullptr;
static PFN_SteamAPI_Init g_origSteamAPI_InitSafe = nullptr;

static bool H33SteamAPI_InitHook() {
    bool rc = g_origSteamAPI_Init();
    LOG_INFO("[H33 STEAM] SteamAPI_Init -> %s", rc ? "true" : "false");
    if (rc) H33TryInstallSteamVtableHooks("SteamAPI_Init");
    return rc;
}

static bool H33SteamAPI_InitSafeHook() {
    bool rc = g_origSteamAPI_InitSafe();
    LOG_INFO("[H33 STEAM] SteamAPI_InitSafe -> %s", rc ? "true" : "false");
    if (rc) H33TryInstallSteamVtableHooks("SteamAPI_InitSafe");
    return rc;
}

static void H33InstallSteamHooks() {
    HMODULE steam = GetModuleHandleA("steam_api64.dll");
    if (!steam) {
        steam = LoadLibraryA("steam_api64.dll");
    }
    if (!steam) {
        LOG_WARNING("  H33: steam_api64.dll not loaded; Steamworks hooks skipped");
        return;
    }

    // Install SteamAPI_Init / InitSafe hooks first — these are the
    // post-init trampoline that walks vtables once Steam is alive.
    void* initAddr = reinterpret_cast<void*>(GetProcAddress(steam, "SteamAPI_Init"));
    if (initAddr && HookManager::GetInstance().InstallHook(
            initAddr,
            reinterpret_cast<void*>(&H33SteamAPI_InitHook),
            reinterpret_cast<void**>(&g_origSteamAPI_Init))) {
        LOG_INFO("  HOOKED steam_api64!SteamAPI_Init @ %p (H33 repro)", initAddr);
    } else {
        LOG_WARNING("  H33: failed to hook SteamAPI_Init (addr=%p)", initAddr);
    }

    void* initSafeAddr = reinterpret_cast<void*>(GetProcAddress(steam, "SteamAPI_InitSafe"));
    if (initSafeAddr && HookManager::GetInstance().InstallHook(
            initSafeAddr,
            reinterpret_cast<void*>(&H33SteamAPI_InitSafeHook),
            reinterpret_cast<void**>(&g_origSteamAPI_InitSafe))) {
        LOG_INFO("  HOOKED steam_api64!SteamAPI_InitSafe @ %p (H33 repro)", initSafeAddr);
    } else {
        LOG_WARNING("  H33: failed to hook SteamAPI_InitSafe (addr=%p)", initSafeAddr);
    }

    // Also try immediate vtable install — covers the case where DS2 called
    // SteamAPI_Init before our DllMain ran. If Steam isn't ready yet, this
    // is a no-op (logged) and the Init hook above will catch it later.
    H33TryInstallSteamVtableHooks("immediate");
}
#endif

// ============================================================================
// Hooked Winsock connect() — redirects FromSoft server to custom server
// ============================================================================
static int WSAAPI ConnectHook(SOCKET s, const sockaddr* name, int namelen) {
    if (name && name->sa_family == AF_INET) {
        sockaddr_in* addr = const_cast<sockaddr_in*>(reinterpret_cast<const sockaddr_in*>(name));
        uint16_t port = ntohs(addr->sin_port);

        char ipStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr->sin_addr, ipStr, sizeof(ipStr));

        LOG_INFO("[NET] Game connecting to %s:%u", ipStr, port);

        // Redirect all game server connections (login=50031, auth=50000, game=50010+)
        if (g_redirectActive && (port == DS2_LOGIN_PORT || port == 50000 ||
            (port >= 50010 && port <= 50100))) {
            LOG_INFO("[NET] REDIRECTING %s:%u to custom server %s:%u (keeping port)",
                     ipStr, port, g_redirectIP.c_str(), port);

            // Rewrite destination IP only — keep the port the same
            // The server listens on all these ports locally
            inet_pton(AF_INET, g_redirectIP.c_str(), &addr->sin_addr);

            char newIp[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr->sin_addr, newIp, sizeof(newIp));
            LOG_INFO("[NET] Connection redirected to %s:%u", newIp, port);

            g_gameOnline = true;
        } else if (port == DS2_LOGIN_PORT) {
            LOG_INFO("[NET] Detected DS2 login server connection (port %u) — redirect OFF", DS2_LOGIN_PORT);
            g_gameOnline = true;
        }
    }

    return g_originalConnect(s, name, namelen);
}

// ============================================================================
// WinsockHooks public interface
// ============================================================================
void WinsockHooks::SetServerRedirect(const std::string& ip, uint16_t port) {
    g_redirectIP = ip;
    g_redirectPort = port;
    g_redirectActive = true;
    LOG_INFO("[NET] Server redirect configured: %s:%u", ip.c_str(), port);
}

bool WinsockHooks::IsRedirectActive() {
    return g_redirectActive;
}

bool WinsockHooks::InstallHooks() {
    LOG_INFO("Installing Winsock hooks...");

    HMODULE ws2 = GetModuleHandleA("ws2_32.dll");
    if (!ws2) {
        ws2 = LoadLibraryA("ws2_32.dll");
    }

    if (!ws2) {
        LOG_WARNING("ws2_32.dll not loaded yet");
        return true;
    }

    void* connectAddr = GetProcAddress(ws2, "connect");
    if (!connectAddr) {
        LOG_WARNING("Could not find connect() in ws2_32.dll");
        return true;
    }

    if (HookManager::GetInstance().InstallHook(
        connectAddr,
        reinterpret_cast<void*>(&ConnectHook),
        reinterpret_cast<void**>(&g_originalConnect)
    )) {
        LOG_INFO("  HOOKED Winsock connect()");
    } else {
        LOG_WARNING("  Failed to hook connect() (non-critical)");
    }

#ifdef H33_REPRO_LOGGING
    // getaddrinfo lives in ws2_32.dll on modern Windows; GetAddrInfoW too.
    void* gaiAddr = GetProcAddress(ws2, "getaddrinfo");
    if (gaiAddr && HookManager::GetInstance().InstallHook(
        gaiAddr,
        reinterpret_cast<void*>(&H33GetaddrinfoHook),
        reinterpret_cast<void**>(&g_originalGetaddrinfo)
    )) {
        LOG_INFO("  HOOKED ws2_32!getaddrinfo (H33 repro)");
    } else {
        LOG_WARNING("  H33: failed to hook getaddrinfo");
    }

    void* gaiwAddr = GetProcAddress(ws2, "GetAddrInfoW");
    if (gaiwAddr && HookManager::GetInstance().InstallHook(
        gaiwAddr,
        reinterpret_cast<void*>(&H33GetaddrinfoWHook),
        reinterpret_cast<void**>(&g_originalGetaddrinfoW)
    )) {
        LOG_INFO("  HOOKED ws2_32!GetAddrInfoW (H33 repro)");
    } else {
        LOG_WARNING("  H33: failed to hook GetAddrInfoW");
    }

    // H-33 2026-05-25 extension: capture WSAConnect, ConnectEx, WSAConnectByName.
    void* wsaConnectAddr = GetProcAddress(ws2, "WSAConnect");
    if (wsaConnectAddr && HookManager::GetInstance().InstallHook(
        wsaConnectAddr,
        reinterpret_cast<void*>(&H33WSAConnectHook),
        reinterpret_cast<void**>(&g_originalWSAConnect)
    )) {
        LOG_INFO("  HOOKED ws2_32!WSAConnect (H33 repro)");
    } else {
        LOG_WARNING("  H33: failed to hook WSAConnect");
    }

    void* wsaConnByNameA = GetProcAddress(ws2, "WSAConnectByNameA");
    if (wsaConnByNameA && HookManager::GetInstance().InstallHook(
        wsaConnByNameA,
        reinterpret_cast<void*>(&H33WSAConnectByNameAHook),
        reinterpret_cast<void**>(&g_originalWSAConnectByNameA)
    )) {
        LOG_INFO("  HOOKED ws2_32!WSAConnectByNameA (H33 repro)");
    } else {
        LOG_WARNING("  H33: failed to hook WSAConnectByNameA");
    }

    void* wsaConnByNameW = GetProcAddress(ws2, "WSAConnectByNameW");
    if (wsaConnByNameW && HookManager::GetInstance().InstallHook(
        wsaConnByNameW,
        reinterpret_cast<void*>(&H33WSAConnectByNameWHook),
        reinterpret_cast<void**>(&g_originalWSAConnectByNameW)
    )) {
        LOG_INFO("  HOOKED ws2_32!WSAConnectByNameW (H33 repro)");
    } else {
        LOG_WARNING("  H33: failed to hook WSAConnectByNameW");
    }

    void* connectExAddr = H33ResolveConnectEx();
    if (connectExAddr && HookManager::GetInstance().InstallHook(
        connectExAddr,
        reinterpret_cast<void*>(&H33ConnectExHook),
        reinterpret_cast<void**>(&g_originalConnectEx)
    )) {
        LOG_INFO("  HOOKED mswsock!ConnectEx @ 0x%p (H33 repro)", connectExAddr);
    } else {
        LOG_WARNING("  H33: failed to hook ConnectEx (resolver=%p)", connectExAddr);
    }

    // H-33 2026-05-26 extension (task #10): Steamworks SDK flat-C exports.
    // Distinguishes hypothesis #2' (multiplexed Steam probe) from #3 (no
    // network call at all). See docs/repro/h33-scope.md 2026-05-26 update #2.
    H33InstallSteamHooks();
#endif

    return true;
}

void WinsockHooks::UninstallHooks() {
    LOG_INFO("Uninstalling Winsock hooks...");
}

// ============================================================================
// Server Redirect — Hostname + RSA key patching in game memory
//
// Adapted from ds3os DS2_ReplaceServerAddressHook.cpp
// DS2's hostname is NOT encrypted (unlike DS3), so we can patch directly.
// ============================================================================

// Search game memory for a wide string
static std::vector<uintptr_t> SearchWideString(const wchar_t* needle) {
    std::vector<uintptr_t> results;

    HMODULE gameModule = GetModuleHandleA("DarkSoulsII.exe");
    if (!gameModule) {
        LOG_ERROR("[REDIRECT] DarkSoulsII.exe module not found");
        return results;
    }

    MODULEINFO modInfo = {};
    GetModuleInformation(GetCurrentProcess(), gameModule, &modInfo, sizeof(modInfo));

    uintptr_t base = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
    size_t moduleSize = modInfo.SizeOfImage;
    size_t needleLen = wcslen(needle);
    size_t needleBytes = needleLen * sizeof(wchar_t);

    if (needleBytes >= moduleSize) return results;

    for (size_t i = 0; i < moduleSize - needleBytes; i++) {
        if (memcmp(reinterpret_cast<void*>(base + i), needle, needleBytes) == 0) {
            results.push_back(base + i);
        }
    }

    return results;
}

// Search game memory for an ASCII string
static std::vector<uintptr_t> SearchAsciiString(const char* needle) {
    std::vector<uintptr_t> results;

    HMODULE gameModule = GetModuleHandleA("DarkSoulsII.exe");
    if (!gameModule) {
        LOG_ERROR("[REDIRECT] DarkSoulsII.exe module not found");
        return results;
    }

    MODULEINFO modInfo = {};
    GetModuleInformation(GetCurrentProcess(), gameModule, &modInfo, sizeof(modInfo));

    uintptr_t base = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
    size_t moduleSize = modInfo.SizeOfImage;
    size_t needleLen = strlen(needle);

    if (needleLen >= moduleSize) return results;

    for (size_t i = 0; i < moduleSize - needleLen; i++) {
        if (memcmp(reinterpret_cast<void*>(base + i), needle, needleLen) == 0) {
            results.push_back(base + i);
        }
    }

    return results;
}

// Build a byte-swapped copy of a wide string for searching
static std::vector<wchar_t> MakeSwappedWideString(const wchar_t* src) {
    size_t len = wcslen(src);
    std::vector<wchar_t> swapped(len + 1);
    for (size_t i = 0; i <= len; i++) {
        wchar_t c = src[i];
        char* p = reinterpret_cast<char*>(&c);
        std::swap(p[0], p[1]);
        swapped[i] = c;
    }
    return swapped;
}

bool ServerRedirect::PatchHostname(const std::string& newHostname) {
    LOG_INFO("[REDIRECT] Patching server hostname to: %s", newHostname.c_str());

    const wchar_t* originalHostname = DS2_SERVER_HOSTNAME;

    // DS2 may store the hostname in normal byte order OR byte-swapped.
    // ds3os flips endian, so we search for both.
    auto swappedHostname = MakeSwappedWideString(originalHostname);

    int attempts = 0;
    const int maxAttempts = 60; // 30 seconds max wait

    while (attempts < maxAttempts) {
        // Search for normal byte order first
        auto matches = SearchWideString(originalHostname);
        // Also search for byte-swapped version
        auto swappedMatches = SearchWideString(swappedHostname.data());
        // Merge both result sets
        for (auto addr : swappedMatches) {
            matches.push_back(addr);
        }

        bool patched = false;
        for (uintptr_t addr : matches) {
            // Force memory writable
            DWORD oldProtect = 0;
            size_t hostnameBytes = (wcslen(originalHostname) + 1) * sizeof(wchar_t);
            if (!VirtualProtect(reinterpret_cast<void*>(addr),
                hostnameBytes, PAGE_READWRITE, &oldProtect)) {
                LOG_WARNING("[REDIRECT] VirtualProtect failed for hostname at 0x%p", reinterpret_cast<void*>(addr));
                continue;
            }

            // Convert hostname to wide string and write it
            // ds3os flips endian because FromSoft stores wchars byte-swapped.
            // Our SearchWideString uses memcmp against normal wchar_t, so if the
            // search matched, the memory is in normal byte order — check by reading
            // the first char to see if it's byte-swapped or not.
            std::wstring wideHostname(newHostname.begin(), newHostname.end());

            wchar_t* ptr = reinterpret_cast<wchar_t*>(addr);
            bool isSwapped = false;
            {
                // Check if 'f' (0x0066) is stored as 0x6600 (swapped)
                uint8_t* raw = reinterpret_cast<uint8_t*>(ptr);
                if (raw[0] == 0x66 && raw[1] == 0x00) {
                    isSwapped = false; // Normal LE order
                } else if (raw[0] == 0x00 && raw[1] == 0x66) {
                    isSwapped = true;  // Byte-swapped
                }
            }

            for (size_t i = 0; i < wideHostname.size() + 1; i++) {
                wchar_t chr = (i < wideHostname.size()) ? wideHostname[i] : L'\0';

                if (isSwapped) {
                    char* source = reinterpret_cast<char*>(&chr);
                    std::swap(source[0], source[1]);
                }

                memcpy(ptr, &chr, sizeof(wchar_t));
                ptr++;
            }

            // Restore protection
            VirtualProtect(reinterpret_cast<void*>(addr),
                hostnameBytes, oldProtect, &oldProtect);

            LOG_INFO("[REDIRECT] Patched hostname at 0x%p", reinterpret_cast<void*>(addr));
            patched = true;
        }

        if (patched) {
            LOG_INFO("[REDIRECT] Hostname patching complete");
            return true;
        }

        attempts++;
        Sleep(500);
    }

    LOG_ERROR("[REDIRECT] Failed to find hostname in game memory after %d attempts", maxAttempts);
    return false;
}

bool ServerRedirect::PatchRSAKey(const std::string& newPublicKey) {
    LOG_INFO("[REDIRECT] Patching RSA public key...");

    // FromSoft's original RSA public key (hardcoded in DS2 binary)
    const char* originalKey =
        "-----BEGIN RSA PUBLIC KEY-----\n"
        "MIIBCAKCAQEAxSeDuBTm3AytrIOGjDKpwJY+437i1F8leMBASVkknYdzM5HB4z8X\n"
        "YTXDylr/N6XAhgr/LcFFZ68yQNQ4AquriMONB+TWUiX0xu84ixYH3AqRtIVqLQbQ\n"
        "xKZsTfyCRC94n9EnvPeS+ueM495YhLIJQBf9T2aCeoHZBFDh2CghJQCdyd4dOT/E\n"
        "9ZxPImwj1t2fZkkKo4smpGk7GcCask2SGsnk/P2jUJxsOyFlCojaW1IldPxn+lXH\n"
        "dlgHSLjQvMlWiZ2SmOwvJqPWMv6XyUXYqsOdejRJJQjV7jeDzYG8trX+bSQxnTAw\n"
        "ENjvjslEcjBmzOCiqFTA/9H1jMjReZpI/wIBAw==\n"
        "-----END RSA PUBLIC KEY-----\n";

    int attempts = 0;
    const int maxAttempts = 60;

    while (attempts < maxAttempts) {
        auto matches = SearchAsciiString(originalKey);

        bool patched = false;
        for (uintptr_t addr : matches) {
            // Copy new key over old key (ds3os just does a straight memcpy)
            size_t copyLen = newPublicKey.size() + 1;
            size_t originalLen = strlen(originalKey) + 1;
            size_t patchLen = copyLen > originalLen ? copyLen : originalLen;

            // Force memory writable — always VirtualProtect regardless of current state
            DWORD oldProtect = 0;
            if (!VirtualProtect(reinterpret_cast<void*>(addr),
                patchLen, PAGE_READWRITE, &oldProtect)) {
                LOG_WARNING("[REDIRECT] VirtualProtect failed at 0x%p (error %u)",
                    reinterpret_cast<void*>(addr), GetLastError());
                continue;
            }

            memcpy(reinterpret_cast<void*>(addr), newPublicKey.c_str(), copyLen);

            // Zero-fill remaining bytes if new key is shorter
            if (copyLen < originalLen) {
                memset(reinterpret_cast<void*>(addr + copyLen), 0, originalLen - copyLen);
            }

            VirtualProtect(reinterpret_cast<void*>(addr),
                patchLen, oldProtect, &oldProtect);

            LOG_INFO("[REDIRECT] Patched RSA key at 0x%p", reinterpret_cast<void*>(addr));
            patched = true;
        }

        if (patched) {
            LOG_INFO("[REDIRECT] RSA key patching complete");
            return true;
        }

        attempts++;
        Sleep(500);
    }

    LOG_ERROR("[REDIRECT] Failed to find RSA key in game memory after %d attempts", maxAttempts);
    return false;
}

bool ServerRedirect::Install(const std::string& serverIp, const std::string& publicKeyPath) {
    LOG_INFO("[REDIRECT] Installing server redirect to %s", serverIp.c_str());

    // Read the public key from file
    std::string publicKey;
    std::ifstream keyFile(publicKeyPath);
    if (keyFile.is_open()) {
        publicKey.assign(std::istreambuf_iterator<char>(keyFile),
                         std::istreambuf_iterator<char>());
        keyFile.close();
        LOG_INFO("[REDIRECT] Loaded public key from %s (%zu bytes)", publicKeyPath.c_str(), publicKey.size());
    } else {
        LOG_ERROR("[REDIRECT] Could not open public key file: %s", publicKeyPath.c_str());
        return false;
    }

    // Patch hostname — the game will resolve this IP instead of FromSoft's server
    if (!PatchHostname(serverIp)) {
        LOG_ERROR("[REDIRECT] Hostname patching failed");
        return false;
    }

    // Patch RSA key — the game will use our server's key for encryption
    if (!PatchRSAKey(publicKey)) {
        LOG_ERROR("[REDIRECT] RSA key patching failed");
        return false;
    }

    LOG_INFO("[REDIRECT] Server redirect installed successfully");
    return true;
}
