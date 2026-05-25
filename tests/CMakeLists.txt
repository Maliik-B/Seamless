# H-17: regression test exe. Links ds2coop_core_asan (the /MD twin of
# the DLL's /MT core_lib). When DS2COOP_ENABLE_ASAN=ON, builds with
# /fsanitize=address + post-build copies the ASan runtime DLL next to
# the exe so PATH isn't required.

add_executable(ds2coop_test
    test_runner.cpp
    test_addresses.cpp
    test_hotkey.cpp
    test_packet.cpp
    test_deadlock.cpp
)

target_include_directories(ds2coop_test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(ds2coop_test PRIVATE ds2coop_core_asan)

set_target_properties(ds2coop_test PROPERTIES
    MSVC_RUNTIME_LIBRARY "MultiThreadedDLL"
)

if(DS2COOP_ENABLE_ASAN)
    target_compile_options(ds2coop_test PRIVATE /fsanitize=address /Zi)
    target_link_options(ds2coop_test PRIVATE /INCREMENTAL:NO)
    set_target_properties(ds2coop_test PROPERTIES
        INTERPROCEDURAL_OPTIMIZATION OFF
    )

    # Best-effort POST_BUILD copy of the ASan runtime DLL so the test
    # exe runs without PATH munging. If $ENV{VCToolsInstallDir} isn't
    # set (some VS configurations) the copy is skipped — the user can
    # put the DLL on PATH manually or fix the env.
    if(DEFINED ENV{VCToolsInstallDir})
        add_custom_command(TARGET ds2coop_test POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "$ENV{VCToolsInstallDir}/bin/Hostx64/x64/clang_rt.asan_dynamic-x86_64.dll"
                "$<TARGET_FILE_DIR:ds2coop_test>"
            COMMENT "H-17: copying ASan runtime DLL next to ds2coop_test")
    endif()
endif()

add_test(NAME unit COMMAND ds2coop_test)
