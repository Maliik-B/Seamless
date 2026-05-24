cmake_minimum_required(VERSION 3.25)  # H-17: CMakePresets schema v6
project(DS2SeamlessCoop VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Options
option(BUILD_LAUNCHER "Build the launcher application" ON)
option(BUILD_TESTS "Build test suite" OFF)
option(DS2COOP_ENABLE_ASAN "H-17: enable AddressSanitizer on the test exe" OFF)

# Third-party libraries directory
set(THIRD_PARTY_DIR ${CMAKE_SOURCE_DIR}/third_party)

# Add MinHook for function hooking
add_subdirectory(${THIRD_PARTY_DIR}/minhook)

# Add ImGui for in-game overlay
add_subdirectory(${THIRD_PARTY_DIR}/imgui)

# H-17: pure host-buildable layers (hotkey parser, packet validator) shared by
# the DLL and the test exe. Declared before src/ so the DLL target can link it.
add_subdirectory(src/core_lib)

# Main DLL project
add_subdirectory(src)

# Launcher
if(BUILD_LAUNCHER)
    add_subdirectory(launcher)
endif()

# Tests
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

