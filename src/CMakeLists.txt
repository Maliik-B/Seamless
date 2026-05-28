add_library(ds2_seamless_coop SHARED
    core/dllmain.cpp
    core/mod.cpp
    features/sign_sync.cpp
    hooks/session_hooks.cpp
    hooks/network_hooks.cpp
    hooks/game_state_hooks.cpp
    hooks/sign_telemetry_hooks.cpp
    network/peer_manager.cpp
    network/packet_handler.cpp
    session/session_manager.cpp
    sync/progress_sync.cpp
    sync/player_sync.cpp
    utils/logger.cpp
    utils/memory.cpp
    utils/pattern_scanner.cpp
    utils/address_resolver.cpp
    ui/overlay.cpp
    ui/renderer.cpp
    ui/title_notifier.cpp
)

target_include_directories(ds2_seamless_coop PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${THIRD_PARTY_DIR}/minhook/include
    ${THIRD_PARTY_DIR}/imgui
    ${THIRD_PARTY_DIR}/imgui/backends
)

target_link_libraries(ds2_seamless_coop PRIVATE
    minhook
    imgui
    ws2_32
    d3d11
    dxgi
    bcrypt  # H-18: SHA-256 via Windows CNG (BCryptOpenAlgorithmProvider)
    ds2coop_core_mt  # H-17: hotkey parser + packet validator
)

# Set output name and compiler flags
set_target_properties(ds2_seamless_coop PROPERTIES
    OUTPUT_NAME "ds2_seamless_coop"
    PREFIX ""
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
)

# Static link the C++ runtime to avoid dependency issues
target_compile_options(ds2_seamless_coop PRIVATE
    $<$<CONFIG:Release>:/MT>
    $<$<CONFIG:Debug>:/MTd>
)

# Also build as dinput8.dll (drop-in auto-load, no launcher needed)
add_custom_command(TARGET ds2_seamless_coop POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
    $<TARGET_FILE:ds2_seamless_coop>
    ${CMAKE_BINARY_DIR}/bin/$<CONFIG>/dinput8.dll
)

# H-33 throwaway: hostname capture via getaddrinfo / GetAddrInfoW hooks.
# Default OFF — flip on via the `H33Repro` preset for capture sessions only.
option(DS2COOP_H33_REPRO_LOGGING "Verbose H-33 DNS-hostname capture for popup-hook design" OFF)
if(DS2COOP_H33_REPRO_LOGGING)
    target_compile_definitions(ds2_seamless_coop PRIVATE H33_REPRO_LOGGING=1)
endif()

# H-26 throwaway: unfiltered protobuf classname trace in session_hooks.
# Default OFF — flip on via the `H26Repro` preset for capture sessions only.
option(DS2COOP_H26_REPRO_LOGGING "Verbose H-26 protobuf-flow repro logging" OFF)
if(DS2COOP_H26_REPRO_LOGGING)
    target_compile_definitions(ds2_seamless_coop PRIVATE H26_REPRO_LOGGING=1)
endif()

