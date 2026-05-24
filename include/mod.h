#pragma once

#include <Windows.h>
#include <cstdint>
#include <string>

namespace DS2Coop {

// Version information
constexpr const char* MOD_VERSION = "1.0.0";
constexpr const char* MOD_NAME = "Dark Souls 2 Seamless Co-op";

// Game version support
enum class GameVersion {
    Unknown,
    SteamLatest,      // Latest Steam version
    CalibrationVer112 // Calibration 1.12
};

// Configuration
struct ModConfig {
    bool enabled = true;
    bool debug_logging = false;
    uint16_t max_players = 6;
    uint16_t port = 27015;
    bool allow_invasions = false;
    bool sync_bonfires = true;
    bool sync_items = true;
    bool sync_enemies = false;
    // Custom server redirect
    std::string server_ip = "127.0.0.1";    // IP of the ds3os custom server
    uint16_t server_port = 50031;            // Login port of custom server
    bool use_custom_server = true;           // Enable server redirect

    // H-20: emergency-disable hotkey. Format "Mod+Mod+Key" — e.g.
    // "Ctrl+Shift+End", "Alt+F12". Supported modifiers: Ctrl, Shift, Alt.
    // Key names: A-Z, 0-9, F1-F24, End, Home, Insert, Delete, PageUp,
    // PageDown, Escape (and aliases Esc, Del, Ins, PgUp, PgDn).
    std::string emergency_disable_hotkey = "Ctrl+Shift+End";
};

// H-20: parsed representation of an emergency-disable hotkey chord.
struct HotkeyChord {
    bool need_ctrl  = false;
    bool need_shift = false;
    bool need_alt   = false;
    int  vkey       = 0;   // 0 = invalid
};

// Parse a "Mod+Mod+Key" string into a HotkeyChord. Returns a chord with
// vkey==0 on parse failure (caller can log + fall back to default).
HotkeyChord ParseHotkey(const std::string& spec);

// Main mod class
class SeamlessCoopMod {
public:
    static SeamlessCoopMod& GetInstance();
    
    bool Initialize();
    void Shutdown();

    // H-20: revert sticky writes, disable disconnect-blocking, close the UDP
    // listener. The DLL stays loaded (the dinput8 proxy is still alive), so
    // the game keeps running but in vanilla mode. Idempotent.
    // MUST NOT be called from inside a MinHook detour or the Present hook —
    // spawn a thread for it. Surface "vanilla mode active — restart to revert"
    // in the overlay before returning.
    void EmergencyDisable();
    bool IsEmergencyDisabled() const { return m_emergencyDisabled; }

    bool IsInitialized() const { return m_initialized; }
    GameVersion GetGameVersion() const { return m_gameVersion; }
    const ModConfig& GetConfig() const { return m_config; }

    void LoadConfig();
    void SaveConfig();

private:
    SeamlessCoopMod() = default;
    ~SeamlessCoopMod() = default;
    SeamlessCoopMod(const SeamlessCoopMod&) = delete;
    SeamlessCoopMod& operator=(const SeamlessCoopMod&) = delete;
    
    bool DetectGameVersion();
    bool InstallHooks();
    void UninstallHooks();
    
    bool m_initialized = false;
    bool m_emergencyDisabled = false;   // H-20 latch
    GameVersion m_gameVersion = GameVersion::Unknown;
    ModConfig m_config;
    HANDLE m_updateThread = nullptr;
};

} // namespace DS2Coop

