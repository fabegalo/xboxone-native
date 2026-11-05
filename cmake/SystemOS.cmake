# SPDX-License-Identifier: BSD-3-Clause
# Independent bootstrap; deliberately has no dependency on presentation code.
add_library(xboxone_systemos STATIC ${PROJECT_SOURCE_DIR}/src/bootstrap.cpp)
target_link_libraries(xboxone_systemos PUBLIC xboxone_inspection)
target_compile_features(xboxone_systemos PUBLIC cxx_std_20)
if(MSVC)
    target_compile_options(xboxone_systemos PRIVATE /W4 /permissive-)
else()
    target_compile_options(xboxone_systemos PRIVATE -Wall -Wextra -Wpedantic)
endif()
add_executable(xboxone-systemos ${PROJECT_SOURCE_DIR}/src/bootstrap_main.cpp)
target_link_libraries(xboxone-systemos PRIVATE xboxone_systemos)

if(XBOXONE_NATIVE_BUILD_TESTS)
    if(DEFINED ENV{GITHUB_ACTIONS} AND NOT Python3_Interpreter_FOUND)
        message(FATAL_ERROR "CI requires Python regression coverage")
    endif()
    add_executable(xboxone_bootstrap_tests ${PROJECT_SOURCE_DIR}/tests/bootstrap_tests.cpp)
    target_link_libraries(xboxone_bootstrap_tests PRIVATE xboxone_systemos)
    add_test(NAME bootstrap_regressions COMMAND xboxone_bootstrap_tests)
    set_tests_properties(bootstrap_regressions PROPERTIES TIMEOUT 20)
    if(Python3_Interpreter_FOUND)
        add_test(NAME pe_dependency_regressions
            COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/pe_dependency_tests.py"
                    $<TARGET_FILE:xboxone-native> $<TARGET_FILE:xboxone-systemos>)
        set_tests_properties(pe_dependency_regressions PROPERTIES TIMEOUT 30)
    endif()
    if(WIN32 AND MSVC AND CMAKE_SIZEOF_VOID_P EQUAL 8 AND
       CMAKE_SYSTEM_PROCESSOR MATCHES "^(AMD64|amd64|x86_64)$")
        foreach(variant IN ITEMS ok hang fail)
            add_executable(bootstrap_component_${variant} ${PROJECT_SOURCE_DIR}/tests/bootstrap_component.cpp)
            target_compile_options(bootstrap_component_${variant} PRIVATE /GS- /Zl)
            target_link_libraries(bootstrap_component_${variant} PRIVATE kernel32)
            target_link_options(bootstrap_component_${variant} PRIVATE /NODEFAULTLIB /ENTRY:bootstrap_test_entry
                                /SUBSYSTEM:CONSOLE /MANIFEST:NO /INCREMENTAL:NO)
        endforeach()
        target_compile_definitions(bootstrap_component_hang PRIVATE BOOTSTRAP_TEST_HANG)
        target_compile_definitions(bootstrap_component_fail PRIVATE BOOTSTRAP_TEST_FAIL)
        add_test(NAME bootstrap_native_execution COMMAND xboxone_bootstrap_tests
                 $<TARGET_FILE:bootstrap_component_ok> $<TARGET_FILE:bootstrap_component_hang>
                 $<TARGET_FILE:bootstrap_component_fail>)
        set_tests_properties(bootstrap_native_execution PROPERTIES TIMEOUT 20)
        if(Python3_Interpreter_FOUND)
            add_test(NAME bootstrap_cli_regressions
                COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/bootstrap_cli_tests.py"
                        $<TARGET_FILE:xboxone-systemos> $<TARGET_FILE:bootstrap_component_ok>
                        "${CMAKE_CURRENT_BINARY_DIR}/m1-bootstrap-evidence.json")
            set_tests_properties(bootstrap_cli_regressions PROPERTIES TIMEOUT 20)
        endif()
    endif()
endif()
