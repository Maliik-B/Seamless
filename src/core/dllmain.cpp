// DLL entry point + dinput8.dll proxy
//
// When this DLL is named "dinput8.dll" and placed in the game folder,
// the game loads it automatically (Windows DLL search order).
// We forward all real DirectInput calls to the system dinput8.dll
// so controller/keyboard input keeps working.

#include <Windows.h>
#include "../include/mod.h"
#include "../include/utils.h"

using namespace DS2Coop;
using namespace DS2Coop::Utils;

// ============================================================================
// dinput8.dll proxy — forward DirectInput8Create to the real system DLL
// ============================================================================
static HMODULE g_realDinput8 = nullptr;

typedef HRESULT(WINAPI* DirectInput8Create_t)(
    HINSTANCE, DWORD, REFIID, LPVOID*, LPUNKNOWN);
static DirectInput8Create_t g_realDirectInput8Create = nullptr;

extern "C" __declspec(dllexport) HRESULT WINAPI DirectInput8Create(
    HINSTANCE hinst, DWORD dwVersion, REFIID riidltf,
    LPVOID* ppvOut, LPUNKNOWN punkOuter)
{
    if (!g_realDinput8) {
        // Load the real dinput8.dll from system32
        wchar_t sysDir[MAX_PATH];
        GetSystemDirectoryW(sysDir, MAX_PATH);
        wcscat_s(sysDir, L"\\dinput8.dll");
        g_realDinput8 = LoadLibraryW(sysDir);
    }

    if (!g_realDirectInput8Create && g_realDinput8) {
        g_realDirectInput8Create = reinterpret_cast<DirectInput8Create_t>(
            GetProcAddress(g_realDinput8, "DirectInput8Create"));
    }

    if (g_realDirectInput8Create) {
        return g_realDirectInput8Create(hinst, dwVersion, riidltf, ppvOut, punkOuter);
    }

    return E_FAIL;
}

// ============================================================================
// H-23: elevation check
// ----------------------------------------------------------------------------
// Returns true if the current process is running with an elevated token
// (i.e. launched "as Administrator"). Fails CLOSED — if we can't query the
// token for some reason, treat as elevated so the refusal path runs. This
// is defense-in-depth, not a security boundary; the cost of a false
// positive is just that the user reads the log to see why mod didn't load.
// ============================================================================
static bool IsProcessElevated() {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return true;
    }
    TOKEN_ELEVATION elevation = {};
    DWORD cbSize = sizeof(elevation);
    bool elevated = true;
    if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &cbSize)) {
        elevated = (elevation.TokenIsElevated != 0);
    }
    CloseHandle(hToken);
    return elevated;
}

// ============================================================================
// DllMain
// ============================================================================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: {
        DisableThreadLibraryCalls(hModule);

        Logger::GetInstance().Initialize(L"ds2_seamless_coop.log");

        LOG_INFO("========================================");
        LOG_INFO("DLL_PROCESS_ATTACH - DLL IS LOADING!");
        LOG_INFO("DS2 Seamless Co-op Mod v%s", MOD_VERSION);
        LOG_INFO("DLL Module Handle: 0x%p", hModule);
        LOG_INFO("Process ID: %lu", GetCurrentProcessId());
        LOG_INFO("========================================");

        // H-23: refuse to install hooks if the host process is elevated.
        // DS2 doesn't need Administrator, and loading our hooks into an
        // elevated game enlarges attack surface without any benefit. The
        // dinput8 proxy export above keeps working so the game proceeds
        // vanilla — no error dialog, just no seamless co-op.
        if (IsProcessElevated()) {
            LOG_ERROR("========================================");
            LOG_ERROR("REFUSING TO ATTACH: host process is ELEVATED.");
            LOG_ERROR("DS2 does not need to be run as Administrator.");
            LOG_ERROR("Close DS2, launch Steam as a normal user, and try again.");
            LOG_ERROR("Game will continue without seamless co-op.");
            LOG_ERROR("========================================");
            break;
        }

        HANDLE hThread = CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
            LOG_INFO("Mod initialization thread started...");
            Sleep(3000);
            LOG_INFO("Calling SeamlessCoopMod::Initialize()...");
            auto& mod = SeamlessCoopMod::GetInstance();
            if (mod.Initialize()) {
                LOG_INFO("========================================");
                LOG_INFO("MOD INITIALIZED SUCCESSFULLY!");
                LOG_INFO("Press INSERT in-game for co-op menu");
                LOG_INFO("========================================");
            } else {
                LOG_ERROR("========================================");
                LOG_ERROR("MOD INITIALIZATION FAILED!");
                LOG_ERROR("Check ds2_seamless_coop.log for details");
                LOG_ERROR("========================================");
            }
            return 0;
        }, nullptr, 0, nullptr);
        if (hThread) CloseHandle(hThread);
        else LOG_ERROR("FATAL: CreateThread failed — mod will not initialize");

        LOG_INFO("DllMain returning TRUE (success)");
        break;
    }
        
    case DLL_PROCESS_DETACH:
        LOG_INFO("Shutting down mod...");
        SeamlessCoopMod::GetInstance().Shutdown();
        Logger::GetInstance().Shutdown();
        break;
    }
    return TRUE;
}

