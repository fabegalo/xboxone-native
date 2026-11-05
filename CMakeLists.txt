cmake_minimum_required(VERSION 3.21)
project(xboxone_native VERSION 0.1.0 LANGUAGES CXX)

option(XBOXONE_NATIVE_BUILD_TESTS "Build M0 regression tests" ON)

add_library(xboxone_inspection STATIC
    src/inspection.cpp
    src/inventory.cpp
)
target_include_directories(xboxone_inspection PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_compile_features(xboxone_inspection PUBLIC cxx_std_20)
if(MSVC)
    target_compile_options(xboxone_inspection PRIVATE /W4 /permissive-)
else()
    target_compile_options(xboxone_inspection PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(xboxone-native src/main.cpp)
target_link_libraries(xboxone-native PRIVATE xboxone_inspection)

if(XBOXONE_NATIVE_BUILD_TESTS)
    enable_testing()
    add_executable(xboxone_inspection_tests tests/inspection_tests.cpp)
    target_link_libraries(xboxone_inspection_tests PRIVATE xboxone_inspection)
    add_test(NAME inspection_regressions COMMAND xboxone_inspection_tests)
    add_executable(xboxone_inventory_tests tests/inventory_tests.cpp)
    target_include_directories(xboxone_inventory_tests PRIVATE src)
    target_link_libraries(xboxone_inventory_tests PRIVATE xboxone_inspection)
    add_test(NAME inventory_regressions COMMAND xboxone_inventory_tests)
    add_test(NAME cli_help COMMAND xboxone-native --help)
    find_package(Python3 QUIET COMPONENTS Interpreter)
    if(Python3_Interpreter_FOUND)
        add_test(NAME update_zip_and_cli_regressions
            COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/update_zip_tests.py"
                    $<TARGET_FILE:xboxone-native>)
        add_test(NAME systemos_preflight_regressions
            COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/systemos_preflight_tests.py"
                    $<TARGET_FILE:xboxone-native>)
    endif()
endif()

include(cmake/SystemOS.cmake)
