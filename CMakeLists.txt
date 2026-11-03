# SPDX-License-Identifier: CDDL-1.0
cmake_minimum_required(VERSION 3.24)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
    message(FATAL_ERROR "Use a separate build directory: cmake -S . -B build")
endif()

project(convert_ddt LANGUAGES C)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "The pinned OpenZFS maintenance tools require Linux")
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
find_path(JANSSON_INCLUDE_DIR NAMES jansson.h REQUIRED)
find_library(JANSSON_LIBRARY NAMES jansson REQUIRED)
mark_as_advanced(JANSSON_INCLUDE_DIR JANSSON_LIBRARY)
add_library(Jansson::Jansson UNKNOWN IMPORTED)
set_target_properties(Jansson::Jansson PROPERTIES
    IMPORTED_LOCATION "${JANSSON_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${JANSSON_INCLUDE_DIR}")

include(cmake/OpenZFS.cmake)

function(add_openzfs_executable target)
    add_executable(${target} ${ARGN})
    target_include_directories(${target} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(${target} PRIVATE OpenZFS::Zpool)
    add_dependencies(${target} openzfs_native)
endfunction()

add_openzfs_executable(convert-ddt convert_ddt.c)
add_openzfs_executable(clone-pool tests/clone_pool.c)
target_link_options(clone-pool PRIVATE "LINKER:--wrap=zfs_file_open")

add_openzfs_executable(validate-ddt tests/validate_ddt.c)
add_openzfs_executable(validate-content tests/validate_content.c)
foreach(target IN ITEMS validate-ddt validate-content)
    target_link_libraries(${target} PRIVATE OpenSSL::Crypto Jansson::Jansson)
    target_link_options(${target} PRIVATE "LINKER:--wrap=zfs_file_open")
endforeach()

add_openzfs_executable(test_transform tests/test_transform.c)
set(native_test_targets test_transform)
foreach(target IN LISTS native_test_targets)
    # CMake's Release flags define NDEBUG; every helper must still assert.
    target_compile_options(${target} PRIVATE -UNDEBUG)
endforeach()

include(CTest)
if(BUILD_TESTING)
    foreach(target IN LISTS native_test_targets)
        add_test(NAME ${target} COMMAND $<TARGET_FILE:${target}>)
    endforeach()
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    add_test(NAME python_unittest
        COMMAND "${Python3_EXECUTABLE}" -m unittest discover
            -s "${CMAKE_CURRENT_SOURCE_DIR}/tests" -p "test_*.py")
    set_tests_properties(python_unittest PROPERTIES
        WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
endif()
