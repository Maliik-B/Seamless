# H-17: pure C++ layers shared by the DLL (/MT) and the test exe (/MD + ASan).
# Two STATIC libs from the same source list — see commit message and
# docs/plan for the static-vs-object-library tradeoff.

set(DS2COOP_CORE_SOURCES
    hotkey_parser.cpp
    packet_parse.cpp
)

# Consumer: ds2_seamless_coop.dll — must match the DLL's /MT runtime.
add_library(ds2coop_core_mt STATIC ${DS2COOP_CORE_SOURCES})
target_include_directories(ds2coop_core_mt PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)
set_target_properties(ds2coop_core_mt PROPERTIES
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
)
target_compile_options(ds2coop_core_mt PRIVATE
    $<$<CONFIG:Release>:/MT>
    $<$<CONFIG:Debug>:/MTd>
)

# Consumer: ds2coop_test — /MD so AddressSanitizer can hook the CRT.
if(BUILD_TESTS)
    add_library(ds2coop_core_asan STATIC ${DS2COOP_CORE_SOURCES})
    target_include_directories(ds2coop_core_asan PUBLIC
        ${CMAKE_SOURCE_DIR}/include
    )
    set_target_properties(ds2coop_core_asan PROPERTIES
        MSVC_RUNTIME_LIBRARY "MultiThreadedDLL"
    )
    if(DS2COOP_ENABLE_ASAN)
        target_compile_options(ds2coop_core_asan PRIVATE /fsanitize=address /Zi)
        set_target_properties(ds2coop_core_asan PROPERTIES
            INTERPROCEDURAL_OPTIMIZATION OFF)
    endif()
endif()
