// Main mod initialization
//
// Hook installation order:
// 1. MinHook initialization
// 2. Address resolution (GameManagerImp, NetSessionManager via AOB scan)
// 3. Protobuf interception hooks (the core mechanism - blocks disconnect messages)
// 4. Winsock hooks (connection monitoring)
// 5. Game state hooks (optional - local event detection)
// 6. Network/session/UI subsystems

#include "../../include/mod.h"
#include "../../include/hooks.h"
#include "../../include/session.h"
#include "../../include/network.h"
#include "../../include/sync.h"
#include "../../include/ui.h"
#include "../../include/utils.h"
#include "../../include/address_resolver.h"
#include <fstream>
#include <chrono>
#include <utility>
#include <vector>

using namespace DS2Coop;
using namespace DS2Coop::Utils;

SeamlessCoopMod& SeamlessCoopMod::GetInstance() {
    static SeamlessCoopMod instance;
    return instance;
}

bool SeamlessCoopMod::Initialize() {
    if (m_initialized) {
        LOG_WARNING("Mod already initialized");
        return true;
    }

    LOG_INFO("==========================================");
    LOG_INFO("Initializing Seamless Co-op Mod...");
    LOG_INFO("==========================================");

    // Load configuration
    LoadConfig();

    if (!m_config.enabled) {
        LOG_INFO("Mod is disabled in configuration");
        return false;
    }

    // Detect game version
    DetectGameVersion();

    // ================================================================
    // STEP 1: Initialize MinHook
    // ================================================================
    LOG_INFO("[1/6] Initializing MinHook...");
    if (!Hooks::HookManager::GetInstance().Initialize()) {
        LOG_ERROR("FATAL: MinHook initialization failed");
        return false;
    }
    LOG_INFO("  MinHook ready");

    // ================================================================
    // STEP 2: Resolve game memory addresses via AOB pattern scanning
    // ================================================================
    LOG_INFO("[2/6] Scanning for game addresses...");
    bool addressesFound = AddressResolver::GetInstance().Initialize();
    if (addressesFound) {
        LOG_INFO("  GameManagerImp:    0x%p [OK]",
                 reinterpret_cast<void*>(AddressResolver::GetInstance().GetGameManagerImp()));
        LOG_INFO("  NetSessionManager: 0x%p [OK]",
                 reinterpret_cast<void*>(AddressResolver::GetInstance().GetNetSessionManager()));
    } else {
        LOG_WARNING("  Address resolution failed - player data reads will be unavailable");
        LOG_WARNING("  Protobuf hooks may still work for disconnect prevention");
    }

    // ================================================================
    // STEP 2b (H-33 task #12): suppress the boot "service unavailable"
    // popup BEFORE the title screen FSM constructs its OfflineModeWindow
    // substate. Patches the FeSubStateTitleOnlineCheck predicate at
    // exe+0xF98C0 to always report success. See player_sync.cpp.
    // ================================================================
    Sync::ApplyBootPopupPatch();

    // ================================================================
    // STEP 3: Install protobuf interception hooks (THE CRITICAL HOOKS)
    // These hook SerializeWithCachedSizesToArray and ParseFromArray
    // to intercept and block disconnect messages at the network layer.
    // ================================================================
    LOG_INFO("[3/6] Installing protobuf interception hooks...");
    bool protobufHooked = Hooks::ProtobufHooks::InstallHooks();
    if (protobufHooked) {
        LOG_INFO("  Protobuf hooks ACTIVE - disconnect blocking available");
        // Enable seamless mode immediately
        Hooks::ProtobufHooks::SetSeamlessActive(true);
    } else {
        LOG_ERROR("  Protobuf hooks FAILED - mod running in passive mode");
        LOG_ERROR("  Session disconnect prevention will NOT work");
    }

    // ================================================================
    // STEP 3b (H-26 Plan B task #2): sign-telemetry hooks. Install BEFORE
    // the game starts spawning signs so we don't miss the first organic
    // calls. Logs caller PC + struct contents for the first 5 fires per
    // function, then suppresses. Used to nail down SummonSignParam field
    // offsets empirically.
    // ================================================================
    Hooks::SignTelemetryHooks::Install();

    // ================================================================
    // STEP 4: Install Winsock hooks + server redirect
    // ================================================================
    LOG_INFO("[4/7] Installing Winsock hooks...");
    Hooks::WinsockHooks::InstallHooks();

    if (m_config.use_custom_server) {
        LOG_INFO("[4/7] Setting up server redirect to %s:%u...",
                 m_config.server_ip.c_str(), m_config.server_port);

        // Configure the Winsock hook to redirect port 50031
        Hooks::WinsockHooks::SetServerRedirect(m_config.server_ip, m_config.server_port);

        // Find the public key file — check next to the DLL, then in server dir
        std::string keyPath = "ds2_server_public.key";
        {
            std::ifstream testKey(keyPath);
            if (!testKey.good()) {
                testKey.clear();
                keyPath = "Saved/default/public.key";
                testKey.open(keyPath);
            }
            if (!testKey.good()) {
                LOG_WARNING("[4/7] No public key file found — RSA patching will be skipped");
                LOG_WARNING("[4/7] Place ds2_server_public.key in game folder for server auth");
                // Still patch hostname in background thread (needs SteamStub wait)
                std::string ip = m_config.server_ip;
                CreateThread(nullptr, 0, [](LPVOID param) -> DWORD {
                    auto* ipStr = static_cast<std::string*>(param);
                    Hooks::ServerRedirect::PatchHostname(*ipStr);
                    delete ipStr;
                    return 0;
                }, new std::string(ip), 0, nullptr);
            } else {
                testKey.close();
                // Run hostname + RSA patching in a background thread
                // (needs to wait for SteamStub to unpack)
                std::string ip = m_config.server_ip;
                std::string kp = keyPath;
                CreateThread(nullptr, 0, [](LPVOID param) -> DWORD {
                    auto* args = static_cast<std::pair<std::string, std::string>*>(param);
                    Hooks::ServerRedirect::Install(args->first, args->second);
                    delete args;
                    return 0;
                }, new std::pair<std::string, std::string>(ip, kp), 0, nullptr);
            }
        }
    }

    // ================================================================
    // STEP 5: Install game state hooks (optional local event detection)
    // ================================================================
    LOG_INFO("[5/7] Installing game state hooks...");
    Hooks::GameState::InstallHooks();

    // ================================================================
    // STEP 6: Initialize subsystems
    // ================================================================
    LOG_INFO("[6/7] Initializing subsystems...");

    // Network manager (our P2P layer)
    if (!Network::PeerManager::GetInstance().Initialize(m_config.port)) {
        LOG_WARNING("  Network manager failed to initialize (can retry from menu)");
    } else {
        LOG_INFO("  Network manager ready (port %u)", m_config.port);
    }

    // Session manager
    if (!Session::SessionManager::GetInstance().Initialize()) {
        LOG_WARNING("  Session manager failed to initialize");
    } else {
        LOG_INFO("  Session manager ready");
    }

    // UI overlay + DX11 renderer (hooks IDXGISwapChain::Present)
    if (!UI::OverlayRenderer::GetInstance().Initialize()) {
        LOG_WARNING("  DX11 Present hook failed - in-game overlay unavailable");
    } else {
        LOG_INFO("  DX11 Present hook installed");
    }
    UI::Overlay::GetInstance().Initialize();
    LOG_INFO("  UI overlay ready (Press INSERT for menu)");

    // Title notifier
    UI::TitleScreenNotifier::GetInstance().Start();

    // Start the main update loop in a background thread
    // This drives networking, sync, and session management
    m_updateThread = CreateThread(nullptr, 0, [](LPVOID param) -> DWORD {
        auto* mod = static_cast<SeamlessCoopMod*>(param);
        LOG_INFO("Update thread started");

        auto lastTime = std::chrono::steady_clock::now();

        while (mod->IsInitialized()) {
            auto now = std::chrono::steady_clock::now();
            float deltaTime = std::chrono::duration<float>(now - lastTime).count();
            lastTime = now;

            // Update session (which updates networking + player sync)
            auto& sessionMgr = Session::SessionManager::GetInstance();
            sessionMgr.Update(deltaTime);

            // ~20Hz update rate
            Sleep(50);
        }

        LOG_INFO("Update thread exiting");
        return 0;
    }, this, 0, nullptr);

    m_initialized = true;

    // Final status report
    LOG_INFO("==========================================");
    LOG_INFO("SEAMLESS CO-OP INITIALIZATION COMPLETE");
    LOG_INFO("==========================================");
    LOG_INFO("  Addresses resolved: %s", addressesFound ? "YES" : "NO");
    LOG_INFO("  Protobuf hooks:     %s", protobufHooked ? "ACTIVE" : "FAILED");
    LOG_INFO("  Disconnect blocking: %s",
             Hooks::ProtobufHooks::IsSeamlessActive() ? "ENABLED" : "DISABLED");
    LOG_INFO("");
    if (protobufHooked) {
        LOG_INFO("  Press INSERT to open co-op menu");
        LOG_INFO("  Host a session or join via IP");
        LOG_INFO("  Sessions persist through boss kills and deaths");
    } else {
        LOG_INFO("  Running in PASSIVE MODE (title bar indicator only)");
        LOG_INFO("  Protobuf patterns may not match your game version");
    }
    LOG_INFO("==========================================");

    return true;
}

void SeamlessCoopMod::Shutdown() {
    if (!m_initialized) return;

    LOG_INFO("Shutting down mod...");

    // Signal update thread to stop, then wait
    m_initialized = false;
    if (m_updateThread) {
        WaitForSingleObject(m_updateThread, 3000);
        CloseHandle(m_updateThread);
        m_updateThread = nullptr;
    }

    // Disable seamless before unhooking
    Hooks::ProtobufHooks::SetSeamlessActive(false);

    LOG_INFO("Blocked %u disconnect messages during this session",
             Hooks::ProtobufHooks::GetBlockedMessageCount());
    LOG_INFO("Total protobuf messages processed: %u",
             Hooks::ProtobufHooks::GetTotalMessageCount());

    // Stop UI
    UI::TitleScreenNotifier::GetInstance().Stop();
    UI::Overlay::GetInstance().Shutdown();

    // Shutdown subsystems
    Sync::PlayerSync::GetInstance().Shutdown();
    Sync::ProgressSync::GetInstance().Shutdown();
    Session::SessionManager::GetInstance().Shutdown();
    Network::PeerManager::GetInstance().Shutdown();

    // Unhook
    Hooks::ProtobufHooks::UninstallHooks();
    Hooks::WinsockHooks::UninstallHooks();
    Hooks::GameState::UninstallHooks();
    Hooks::HookManager::GetInstance().Shutdown();

    LOG_INFO("Mod shutdown complete");
}

// ============================================================================
// H-20 — Emergency disable
// ----------------------------------------------------------------------------
// Triggered by the user's panic hotkey (Ctrl+Shift+End by default). The user
// hit issue #1/#5/#6 territory (bonfire crash, soapstone stuck, can't respawn)
// and wants to revert to vanilla *now*, without alt-F4. We keep the DLL
// loaded (the dinput8 proxy stays up) so the game keeps running — we just
// undo our modifications.
//
// Order matters:
//   1. Latch m_emergencyDisabled (idempotency + signals consumers).
//   2. SetSeamlessActive(false) — protobuf hooks become pass-through, no
//      more disconnect blocking.
//   3. Sleep 60ms (one update-thread tick at 20Hz) — lets any in-flight
//      EnableSummoning / sync write complete.
//   4. PlayerSync::RevertStickyWrites — restore TeamType, PhantomType,
//      ChrNetworkPhantomId, bonfire bits, AllottedTime to their snapshotted
//      originals; latches PlayerSync so further calls are no-ops.
//   5. Tear down disconnect-blocking + connection hooks (but NOT
//      HookManager::Shutdown — that would also kill the Present hook in the
//      renderer, and we need it alive to show the overlay banner below).
//   6. Close the UDP listener (PeerManager::Shutdown).
//   7. Banner.
//
// MUST NOT be called from the Present hook itself — we tear down sibling
// MinHook targets and shut down subsystems that touch the render thread.
// The caller in renderer.cpp spawns a one-shot thread for this.
// ============================================================================
void SeamlessCoopMod::EmergencyDisable() {
    if (m_emergencyDisabled) {
        LOG_INFO("EmergencyDisable: already latched, ignoring");
        return;
    }
    m_emergencyDisabled = true;

    LOG_INFO("==========================================");
    LOG_INFO("H-20 EMERGENCY DISABLE TRIGGERED");
    LOG_INFO("==========================================");

    // Step 2: stop blocking disconnect messages.
    LOG_INFO("EmergencyDisable: clearing seamless-active flag");
    Hooks::ProtobufHooks::SetSeamlessActive(false);

    // Step 3: drain in-flight writes from the update loop.
    Sleep(60);

    // Step 4: revert sticky memory writes.
    {
        size_t n = Sync::PlayerSync::GetInstance().StickyWriteCount();
        LOG_INFO("EmergencyDisable: reverting %zu sticky writes", n);
        Sync::PlayerSync::GetInstance().RevertStickyWrites();
    }

    // Step 5: uninstall disconnect / connection / game-state hooks.
    // (Keep MinHook alive so the Present hook keeps rendering the overlay.)
    LOG_INFO("EmergencyDisable: uninstalling protobuf/Winsock/GameState hooks");
    Hooks::ProtobufHooks::UninstallHooks();
    Hooks::WinsockHooks::UninstallHooks();
    Hooks::GameState::UninstallHooks();

    // Step 6: shut down session + UDP listener.
    LOG_INFO("EmergencyDisable: shutting down session + peer manager");
    Session::SessionManager::GetInstance().Shutdown();
    Network::PeerManager::GetInstance().Shutdown();

    // Step 7: overlay banner. Long duration so it sticks until the user
    // closes the game. (Notification list is bounded; a long-lived item is
    // fine — see renderer's notification render path.)
    UI::Overlay::GetInstance().ShowNotification(
        "Seamless co-op DISABLED — restart the game to re-enable", 600.0f);

    LOG_INFO("==========================================");
    LOG_INFO("EMERGENCY DISABLE COMPLETE — vanilla mode");
    LOG_INFO("==========================================");
}

bool SeamlessCoopMod::DetectGameVersion() {
    LOG_INFO("Detecting game version...");

    uintptr_t baseAddress = Memory::GetModuleBase();
    if (!baseAddress) {
        LOG_ERROR("Failed to get module base address");
        return false;
    }

    LOG_INFO("  Module base: 0x%p", reinterpret_cast<void*>(baseAddress));
    m_gameVersion = GameVersion::SteamLatest;
    LOG_INFO("  Assuming Steam latest version");

    return true;
}

bool SeamlessCoopMod::InstallHooks() {
    // Hooks are now installed directly in Initialize() in the correct order
    return true;
}

void SeamlessCoopMod::UninstallHooks() {
    // Handled in Shutdown()
}

void SeamlessCoopMod::LoadConfig() {
    LOG_INFO("Loading configuration...");

    m_config = ModConfig{};

    std::ifstream configFile("ds2_seamless_coop.ini");
    if (configFile.is_open()) {
        std::string line;
        while (std::getline(configFile, line)) {
            if (line.empty() || line[0] == '#' || line[0] == ';') continue;

            size_t pos = line.find('=');
            if (pos != std::string::npos) {
                std::string key = line.substr(0, pos);
                std::string value = line.substr(pos + 1);

                // Trim
                key.erase(0, key.find_first_not_of(" \t"));
                key.erase(key.find_last_not_of(" \t") + 1);
                value.erase(0, value.find_first_not_of(" \t"));
                value.erase(value.find_last_not_of(" \t") + 1);

                if (key == "enabled") {
                    m_config.enabled = (value == "true" || value == "1");
                } else if (key == "debug_logging") {
                    m_config.debug_logging = (value == "true" || value == "1");
                } else if (key == "max_players") {
                    m_config.max_players = static_cast<uint16_t>(std::stoi(value));
                } else if (key == "port") {
                    m_config.port = static_cast<uint16_t>(std::stoi(value));
                } else if (key == "allow_invasions") {
                    m_config.allow_invasions = (value == "true" || value == "1");
                } else if (key == "sync_bonfires") {
                    m_config.sync_bonfires = (value == "true" || value == "1");
                } else if (key == "sync_items") {
                    m_config.sync_items = (value == "true" || value == "1");
                } else if (key == "sync_enemies") {
                    m_config.sync_enemies = (value == "true" || value == "1");
                } else if (key == "server_ip") {
                    m_config.server_ip = value;
                } else if (key == "server_port") {
                    m_config.server_port = static_cast<uint16_t>(std::stoi(value));
                } else if (key == "use_custom_server") {
                    m_config.use_custom_server = (value == "true" || value == "1");
                } else if (key == "emergency_disable_hotkey") {
                    if (!value.empty()) m_config.emergency_disable_hotkey = value;
                }
            }
        }
        configFile.close();
        LOG_INFO("Configuration loaded from file");
    } else {
        LOG_INFO("No configuration file found, using defaults");
        SaveConfig();
    }

    if (m_config.debug_logging) {
        Logger::GetInstance().SetMinLevel(LogLevel::Debug);
    }
}

void SeamlessCoopMod::SaveConfig() {
    std::ofstream configFile("ds2_seamless_coop.ini");
    if (configFile.is_open()) {
        configFile << "# Dark Souls 2 Seamless Co-op Configuration\n\n";
        configFile << "enabled=true\n";
        configFile << "debug_logging=" << (m_config.debug_logging ? "true" : "false") << "\n";
        configFile << "max_players=" << m_config.max_players << "\n";
        configFile << "port=" << m_config.port << "\n";
        configFile << "\n# Sync settings\n";
        configFile << "allow_invasions=" << (m_config.allow_invasions ? "true" : "false") << "\n";
        configFile << "sync_bonfires=" << (m_config.sync_bonfires ? "true" : "false") << "\n";
        configFile << "sync_items=" << (m_config.sync_items ? "true" : "false") << "\n";
        configFile << "sync_enemies=" << (m_config.sync_enemies ? "true" : "false") << "\n";
        configFile << "\n# Custom server settings\n";
        configFile << "use_custom_server=" << (m_config.use_custom_server ? "true" : "false") << "\n";
        configFile << "server_ip=" << m_config.server_ip << "\n";
        configFile << "server_port=" << m_config.server_port << "\n";
        configFile << "\n# H-20: panic hotkey — reverts sticky writes, uninstalls hooks,\n";
        configFile << "# closes UDP listener, keeps DLL loaded (game runs vanilla).\n";
        configFile << "# Format: \"Mod+Mod+Key\" — Ctrl/Shift/Alt + A-Z, 0-9, F1-F24,\n";
        configFile << "# End, Home, Insert, Delete, PageUp, PageDown, Escape.\n";
        configFile << "emergency_disable_hotkey=" << m_config.emergency_disable_hotkey << "\n";
        configFile.close();
    }
}

// H-17: DS2Coop::ParseHotkey body lives in src/core_lib/hotkey_parser.cpp
// so it can be exercised from the host-side test exe under ASan. Declaration
// remains in include/mod.h.
