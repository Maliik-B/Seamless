// DLL entry point + dinput8.dll proxy
//
// When this DLL is named "dinput8.dll" and placed in the game folder,
// the game loads it automatically (Windows DLL search order).
// We forward all real DirectInput calls to the system dinput8.dll
// so controller/keyboard input keeps working.

#include <Windows.h>
#include <bcrypt.h>
#include <string.h>
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
// H-18: DarkSoulsII.exe build hash check
// ----------------------------------------------------------------------------
// Our hooks resolve byte offsets specific to one SOTFS build. Loading them
// against a different patch level (older v1.02, a future Steam update, a
// modded exe) will scribble memory at addresses that don't mean what we
// think they mean — silent corruption is much worse than no co-op. We
// compute the SHA-256 of DarkSoulsII.exe on the disk and compare against
// a compiled-in allowlist. Fails CLOSED: any error path -> refuse hooks.
//
// To add a new known-good build, see the procedure in
// docs/06-defensive-practices.md. The short version:
//   1. PowerShell:  Get-FileHash -Algorithm SHA256 <path>\DarkSoulsII.exe
//   2. Add a string entry to kKnownGameHashes below, with a comment
//      noting the build (Steam build id / version / observed date).
//   3. Re-run the validation in Phase 0 against that build before
//      shipping.
// ============================================================================
static const char* const kKnownGameHashes[] = {
    // DS2 SOTFS v1.03 (Steam, observed 2026-05-09; 28,200,992 bytes)
    "0045931B8914504531B7864A9488D396DC50CBAF524964016E1D69C3D1173131",
};
static const size_t kKnownGameHashCount =
    sizeof(kKnownGameHashes) / sizeof(kKnownGameHashes[0]);

// SHA-256 a file via Windows CNG (bcrypt). Returns true on success and
// fills outHex with the 64-char uppercase hex digest + NUL.
static bool ComputeFileSha256Hex(const wchar_t* path, char outHex[65]) {
    outHex[0] = '\0';

    HANDLE hFile = CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }

    BCRYPT_ALG_HANDLE  hAlg  = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    bool ok = false;
    NTSTATUS st;

    do {
        st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
        if (st != 0) break;

        DWORD hashLen = 0, cb = 0;
        st = BCryptGetProperty(
            hAlg, BCRYPT_HASH_LENGTH,
            reinterpret_cast<PUCHAR>(&hashLen), sizeof(hashLen), &cb, 0);
        if (st != 0 || hashLen != 32) break;

        st = BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
        if (st != 0) break;

        BYTE buf[16 * 1024];
        DWORD bytesRead = 0;
        bool readErr = false;
        for (;;) {
            if (!ReadFile(hFile, buf, sizeof(buf), &bytesRead, nullptr)) {
                readErr = true;
                break;
            }
            if (bytesRead == 0) break;  // EOF
            st = BCryptHashData(hHash, buf, bytesRead, 0);
            if (st != 0) { readErr = true; break; }
        }
        if (readErr) break;

        BYTE digest[32];
        st = BCryptFinishHash(hHash, digest, sizeof(digest), 0);
        if (st != 0) break;

        static const char kHexDigits[] = "0123456789ABCDEF";
        for (int i = 0; i < 32; ++i) {
            outHex[i * 2]     = kHexDigits[(digest[i] >> 4) & 0xF];
            outHex[i * 2 + 1] = kHexDigits[digest[i] & 0xF];
        }
        outHex[64] = '\0';
        ok = true;
    } while (false);

    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg)  BCryptCloseAlgorithmProvider(hAlg, 0);
    CloseHandle(hFile);
    return ok;
}

// Returns true iff the current process's exe matches a compiled-in hash.
// On any failure (path lookup, file open, hash compute), returns false and
// outHex is left empty/partial — caller logs that as "<hash compute failed>".
static bool IsKnownGameBuild(char outHex[65]) {
    wchar_t exePath[MAX_PATH];
    DWORD n = GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        outHex[0] = '\0';
        return false;
    }

    if (!ComputeFileSha256Hex(exePath, outHex)) {
        return false;
    }

    for (size_t i = 0; i < kKnownGameHashCount; ++i) {
        if (_stricmp(outHex, kKnownGameHashes[i]) == 0) {
            return true;
        }
    }
    return false;
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

        // H-18: refuse to install hooks unless DarkSoulsII.exe's SHA-256
        // matches a compiled-in allowlist. Our hook offsets are tied to
        // one specific SOTFS build; running them against a different patch
        // level would silently corrupt game memory. Fails CLOSED on any
        // hash-compute failure for the same reason.
        char observedHash[65] = {};
        if (!IsKnownGameBuild(observedHash)) {
            LOG_ERROR("========================================");
            LOG_ERROR("REFUSING TO ATTACH: unknown DarkSoulsII.exe build.");
            LOG_ERROR("Observed SHA-256: %s",
                observedHash[0] ? observedHash : "<hash compute failed>");
            LOG_ERROR("Allowlisted hashes (%d):", (int)kKnownGameHashCount);
            for (size_t i = 0; i < kKnownGameHashCount; ++i) {
                LOG_ERROR("  %s", kKnownGameHashes[i]);
            }
            LOG_ERROR("Hook offsets are tied to a specific SOTFS build; loading");
            LOG_ERROR("against a different patch level would corrupt game memory.");
            LOG_ERROR("Game will continue without seamless co-op.");
            LOG_ERROR("To allowlist a new build, see");
            LOG_ERROR("  docs/06-defensive-practices.md (allowlist procedure)");
            LOG_ERROR("after verifying the hook offsets still hold on that build.");
            LOG_ERROR("========================================");
            break;
        }
        LOG_INFO("DarkSoulsII.exe SHA-256: %s (allowlisted)", observedHash);

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

