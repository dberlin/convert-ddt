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

# These sources use only standard userspace headers. In particular, helpers
# using libc assert must not inherit libspl's replacement assert.h.
add_library(dedup_fdt_common STATIC
    dedup_fdt_resources.c
    dedup_fdt_index.c
    dedup_fdt_sort.c
    dedup_fdt_workers.c)
target_include_directories(dedup_fdt_common PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_definitions(dedup_fdt_common PUBLIC
    _FILE_OFFSET_BITS=64 _LARGEFILE64_SOURCE)
target_link_libraries(dedup_fdt_common PUBLIC Threads::Threads)

function(add_openzfs_executable target)
    add_executable(${target} ${ARGN})
    target_include_directories(${target} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(${target} PRIVATE OpenZFS::Zpool)
    add_dependencies(${target} openzfs_native)
endfunction()

add_openzfs_executable(convert-ddt convert_ddt.c)
add_openzfs_executable(dedup-fdt
    dedup_fdt.c
    dedup_fdt_plan.c
    dedup_fdt_native.c
    dedup_fdt_admission.c
    rebuild_keys.c
    rebuild_bridge.c
    rebuild_brt_native.c
    rebuild_ddt_native.c
    rebuild_history.c
    rebuild_history_native.c
    rebuild_quota.c
    rebuild_owners.c
    rebuild_zil.c
    rebuild_sync.c
    rebuild_io_fault.c
    dedup_fdt_traverse_native.c)
# The replacement DDT/BRT objects are executable sources, so they precede the
# upstream static archives. Keep maintenance wrappers confined to this writer.
target_link_libraries(dedup-fdt PRIVATE dedup_fdt_common OpenSSL::Crypto)
target_link_options(dedup-fdt PRIVATE
    "LINKER:--wrap=bpobj_iterate,--wrap=dsl_scan_sync,--wrap=zthr_create,--wrap=zfs_file_pwrite,--wrap=ddt_sync,--wrap=brt_sync,--wrap=brt_pending_apply,--wrap=zil_claim")

add_openzfs_executable(clone-pool tests/clone_pool.c)
target_link_options(clone-pool PRIVATE "LINKER:--wrap=zfs_file_open")

add_openzfs_executable(validate-ddt tests/validate_ddt.c)
add_openzfs_executable(validate-content tests/validate_content.c)
foreach(target IN ITEMS validate-ddt validate-content)
    target_link_libraries(${target} PRIVATE OpenSSL::Crypto Jansson::Jansson)
    target_link_options(${target} PRIVATE "LINKER:--wrap=zfs_file_open")
endforeach()

add_openzfs_executable(test_transform tests/test_transform.c)
add_executable(test_dedup_fdt_resources tests/test_dedup_fdt_resources.c)
target_link_libraries(test_dedup_fdt_resources PRIVATE dedup_fdt_common)
target_link_options(test_dedup_fdt_resources PRIVATE
    "LINKER:--wrap=pwrite,--wrap=pwrite64")
add_executable(dedup_fdt_sort_test tests/dedup_fdt_sort_test.c)
target_link_libraries(dedup_fdt_sort_test PRIVATE dedup_fdt_common)
add_executable(dedup_fdt_workers_test tests/dedup_fdt_workers_test.c)
target_link_libraries(dedup_fdt_workers_test PRIVATE dedup_fdt_common)
add_executable(rebuild_ddt_quota_test tests/rebuild_ddt_quota_test.c)
target_include_directories(rebuild_ddt_quota_test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}")

set(native_test_targets
    test_transform
    test_dedup_fdt_resources
    dedup_fdt_sort_test
    dedup_fdt_workers_test
    rebuild_ddt_quota_test)
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
