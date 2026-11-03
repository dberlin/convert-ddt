include_guard(GLOBAL)
include(ExternalProject)
include(ProcessorCount)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux" OR CMAKE_CROSSCOMPILING)
    message(FATAL_ERROR "The pinned private OpenZFS runtime requires a native Linux build")
endif()

set(OPENZFS_ARCHIVE "" CACHE FILEPATH "Optional local, SHA256-verified OpenZFS 2.4.4 release archive")
ProcessorCount(_openzfs_cpus)
if(NOT _openzfs_cpus GREATER 0)
    set(_openzfs_cpus 2)
endif()
if(_openzfs_cpus GREATER 8)
    set(_openzfs_cpus 8)
endif()
set(OPENZFS_BUILD_JOBS "${_openzfs_cpus}" CACHE STRING "GNU Make jobs for OpenZFS, independent of cmake --build --parallel")
if(NOT OPENZFS_BUILD_JOBS MATCHES "^[1-9][0-9]*$")
    message(FATAL_ERROR "OPENZFS_BUILD_JOBS must be a positive integer")
endif()
find_program(OPENZFS_MAKE_EXECUTABLE NAMES gmake make REQUIRED)
execute_process(COMMAND "${OPENZFS_MAKE_EXECUTABLE}" --version
    OUTPUT_VARIABLE _openzfs_make_version RESULT_VARIABLE _openzfs_make_result)
if(NOT _openzfs_make_result EQUAL 0 OR NOT _openzfs_make_version MATCHES "GNU Make")
    message(FATAL_ERROR "OPENZFS_MAKE_EXECUTABLE must name GNU Make, even with the Ninja generator")
endif()
find_program(OPENZFS_PATCH_EXECUTABLE NAMES patch REQUIRED)
find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)
find_package(ZLIB REQUIRED)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)

# These paths are outputs, never a way to adopt an installed/configured tree.
set(_openzfs_root "${CMAKE_BINARY_DIR}/_deps/openzfs")
set(OPENZFS_SOURCE_DIR "${_openzfs_root}/src")
set(OPENZFS_BINARY_DIR "${_openzfs_root}/build")
set(_openzfs_system_libdir "${_openzfs_root}/system-libs")
set(_openzfs_response "${OPENZFS_BINARY_DIR}/system-dependencies.rsp")
# Upstream Automake target names cannot safely represent these characters.
foreach(_path "${OPENZFS_SOURCE_DIR}" "${OPENZFS_BINARY_DIR}")
    if(_path MATCHES "[ \t\r\n#$:\\\\;'\"]")
        message(FATAL_ERROR "OpenZFS requires a binary directory without whitespace or Make-special characters")
    endif()
endforeach()
file(MAKE_DIRECTORY "${_openzfs_system_libdir}")

# CMake prefix/cache discovery is also passed to the upstream Autoconf build.
# Quotes embedded in Autoconf flag variables are literal compiler arguments.
# Upstream Make rules require unquoted, whitespace-free path fragments.
function(_openzfs_flag_path output value)
    if(value MATCHES "[ \t\r\n#$:\\\\;'\"]")
        message(FATAL_ERROR "OpenZFS dependency paths cannot contain whitespace or Make-special characters: ${value}")
    endif()
    set(${output} "${value}" PARENT_SCOPE)
endfunction()
set(_openzfs_cppflags "$ENV{CPPFLAGS}")
set(_openzfs_ldflags "$ENV{LDFLAGS}")
set(_openzfs_pcpaths)
set(_openzfs_include_dirs ${CMAKE_INCLUDE_PATH})
set(_openzfs_library_dirs ${CMAKE_LIBRARY_PATH} "${_openzfs_system_libdir}")
foreach(_prefix IN LISTS CMAKE_PREFIX_PATH)
    list(APPEND _openzfs_include_dirs "${_prefix}/include")
    foreach(_suffix "lib/${CMAKE_LIBRARY_ARCHITECTURE}" lib64 lib)
        if(IS_DIRECTORY "${_prefix}/${_suffix}")
            list(APPEND _openzfs_library_dirs "${_prefix}/${_suffix}")
        endif()
        if(IS_DIRECTORY "${_prefix}/${_suffix}/pkgconfig")
            list(APPEND _openzfs_pcpaths "${_prefix}/${_suffix}/pkgconfig")
        endif()
    endforeach()
    if(IS_DIRECTORY "${_prefix}/share/pkgconfig")
        list(APPEND _openzfs_pcpaths "${_prefix}/share/pkgconfig")
    endif()
endforeach()
foreach(_include IN LISTS _openzfs_include_dirs)
    _openzfs_flag_path(_quoted "${_include}")
    string(APPEND _openzfs_cppflags " -I${_quoted}")
endforeach()
# Put the explicitly selected library symlinks first, ahead of optional prefixes.
list(REMOVE_ITEM _openzfs_library_dirs "${_openzfs_system_libdir}")
list(PREPEND _openzfs_library_dirs "${_openzfs_system_libdir}")
foreach(_library_dir IN LISTS _openzfs_library_dirs)
    _openzfs_flag_path(_quoted "${_library_dir}")
    string(APPEND _openzfs_ldflags " -L${_quoted}")
endforeach()
list(APPEND _openzfs_pcpaths "$ENV{PKG_CONFIG_PATH}")
list(JOIN _openzfs_pcpaths ":" _openzfs_pkg_config_path)

# An explicit LIBRARY may name a versioned, host-compatible runtime without a
# development symlink. Autoconf still checks -lNAME; provide that name privately
# in the binary tree rather than silently choosing a different system runtime.
function(_openzfs_select_library name library)
    if(NOT EXISTS "${library}" OR IS_DIRECTORY "${library}")
        message(FATAL_ERROR "Invalid OpenZFS ${name} library: ${library}")
    endif()
    set(_openzfs_selected_libraries ${_openzfs_selected_libraries} "${library}" PARENT_SCOPE)
    set(_link "${_openzfs_system_libdir}/lib${name}.so")
    if(IS_SYMLINK "${_link}")
        file(READ_SYMLINK "${_link}" _old)
        if(_old STREQUAL library)
            return()
        endif()
    endif()
    file(REMOVE "${_link}")
    file(CREATE_LINK "${library}" "${_link}" SYMBOLIC RESULT _result)
    if(NOT _result STREQUAL "0")
        message(FATAL_ERROR "Cannot select OpenZFS ${name} library: ${_result}")
    endif()
endfunction()

set(_openzfs_dependency_environment)
set(_openzfs_dependency_includes)
foreach(_dependency UDEV BLKID UUID TIRPC)
    if(_dependency STREQUAL "UDEV")
        set(_name udev)
        set(_header libudev.h)
        set(_suffix "")
    elseif(_dependency STREQUAL "BLKID")
        set(_name blkid)
        set(_header blkid/blkid.h)
        set(_suffix "")
    elseif(_dependency STREQUAL "UUID")
        set(_name uuid)
        set(_header uuid/uuid.h)
        set(_suffix "")
    else()
        set(_name tirpc)
        set(_header rpc/xdr.h)
        set(_suffix tirpc)
    endif()
    find_path(OPENZFS_${_dependency}_INCLUDE_DIR NAMES "${_header}"
        PATH_SUFFIXES "${_suffix}" REQUIRED)
    find_library(OPENZFS_${_dependency}_LIBRARY NAMES "${_name}" REQUIRED)
    _openzfs_select_library("${_name}" "${OPENZFS_${_dependency}_LIBRARY}")
    _openzfs_flag_path(_quoted "${OPENZFS_${_dependency}_INCLUDE_DIR}")
    list(APPEND _openzfs_dependency_environment
        "LIB${_dependency}_CFLAGS=-I${_quoted}"
        "LIB${_dependency}_LIBS=-L${_openzfs_system_libdir} -l${_name}")
    list(APPEND _openzfs_dependency_includes "${OPENZFS_${_dependency}_INCLUDE_DIR}")
endforeach()
_openzfs_select_library(crypto "${OPENSSL_CRYPTO_LIBRARY}")
# FindZLIB can return a debug/optimized list; the imported target itself remains
# responsible for project linkage, while configure needs one native file.
get_target_property(_openzfs_zlib ZLIB::ZLIB IMPORTED_LOCATION)
if(NOT _openzfs_zlib)
    get_target_property(_openzfs_zlib ZLIB::ZLIB IMPORTED_LOCATION_RELEASE)
endif()
if(NOT _openzfs_zlib)
    get_target_property(_openzfs_zlib ZLIB::ZLIB IMPORTED_LOCATION_DEBUG)
endif()
_openzfs_select_library(z "${_openzfs_zlib}")
_openzfs_flag_path(_openzfs_crypto_include "${OPENSSL_INCLUDE_DIR}")
_openzfs_flag_path(_openzfs_zlib_include "${ZLIB_INCLUDE_DIR}")
list(APPEND _openzfs_dependency_environment
    "LIBCRYPTO_CFLAGS=-I${_openzfs_crypto_include}"
    "LIBCRYPTO_LIBS=-L${_openzfs_system_libdir} -lcrypto"
    "ZLIB_CFLAGS=-I${_openzfs_zlib_include}"
    "ZLIB_LIBS=-L${_openzfs_system_libdir} -lz")
set(_openzfs_library_selection "${_openzfs_root}/selected-libraries.txt")
file(CONFIGURE OUTPUT "${_openzfs_library_selection}"
    CONTENT "${_openzfs_selected_libraries}\n" @ONLY)

set(_openzfs_url "https://github.com/openzfs/zfs/releases/download/zfs-2.4.4/zfs-2.4.4.tar.gz")
if(OPENZFS_ARCHIVE)
    get_filename_component(_openzfs_url "${OPENZFS_ARCHIVE}" ABSOLUTE BASE_DIR "${CMAKE_SOURCE_DIR}")
    if(NOT EXISTS "${_openzfs_url}")
        message(FATAL_ERROR "OPENZFS_ARCHIVE does not exist: ${_openzfs_url}")
    endif()
endif()
set(_openzfs_patch "${CMAKE_CURRENT_LIST_DIR}/../patches/zfs-2.4.4-claimed-zil-checkpoint.patch")
set(_openzfs_patch_script "${CMAKE_CURRENT_LIST_DIR}/PatchOpenZFS.cmake")
set(_openzfs_link_script "${CMAKE_CURRENT_LIST_DIR}/OpenZFSLinkDependencies.cmake")
set(_openzfs_prepare_script "${CMAKE_CURRENT_LIST_DIR}/PrepareOpenZFSBuild.cmake")
set(_openzfs_patch_command "${CMAKE_COMMAND}"
    "-DSOURCE_DIR=${OPENZFS_SOURCE_DIR}" "-DPATCH_FILE=${_openzfs_patch}"
    "-DPATCH_EXECUTABLE=${OPENZFS_PATCH_EXECUTABLE}" -P "${_openzfs_patch_script}")
set(_openzfs_cc "${CMAKE_C_COMPILER}")
if(CMAKE_C_COMPILER_ARG1)
    string(APPEND _openzfs_cc " ${CMAKE_C_COMPILER_ARG1}")
endif()

ExternalProject_Add(openzfs_native
    PREFIX "${_openzfs_root}/ep"
    SOURCE_DIR "${OPENZFS_SOURCE_DIR}"
    BINARY_DIR "${OPENZFS_BINARY_DIR}"
    URL "${_openzfs_url}"
    URL_HASH SHA256=2a3c70d55a37cc71618a95a60e81ad66530201eb118d37741dc92efcf848c8b1
    DOWNLOAD_EXTRACT_TIMESTAMP FALSE
    TLS_VERIFY TRUE
    UPDATE_COMMAND ""
    PATCH_COMMAND ${_openzfs_patch_command}
    CONFIGURE_COMMAND ${_openzfs_patch_command}
        COMMAND "${CMAKE_COMMAND}" -E env
            "CC=${_openzfs_cc}" "CFLAGS=${CMAKE_C_FLAGS} -O2 -g"
            "CPPFLAGS=${_openzfs_cppflags}" "LDFLAGS=${_openzfs_ldflags}"
            "PKG_CONFIG=${PKG_CONFIG_EXECUTABLE}"
            "PKG_CONFIG_PATH=${_openzfs_pkg_config_path}"
            ${_openzfs_dependency_environment}
            <SOURCE_DIR>/configure --with-config=user --disable-pyzfs --disable-nls
                --disable-shared --enable-static
    BUILD_COMMAND ${_openzfs_patch_command}
        COMMAND "${CMAKE_COMMAND}" "-DBINARY_DIR=${OPENZFS_BINARY_DIR}"
            -P "${_openzfs_prepare_script}"
        COMMAND "${CMAKE_COMMAND}" -E env "MAKEFLAGS=" "MFLAGS="
            "${OPENZFS_MAKE_EXECUTABLE}" "-j${OPENZFS_BUILD_JOBS}"
            gitrev libzpool.la libzfs_core.la libnvpair.la
        COMMAND "${CMAKE_COMMAND}" "-DBINARY_DIR=${OPENZFS_BINARY_DIR}"
            "-DOUTPUT_FILE=${_openzfs_response}" -P "${_openzfs_link_script}"
    BUILD_BYPRODUCTS
        "${OPENZFS_BINARY_DIR}/.libs/libzpool.a"
        "${OPENZFS_BINARY_DIR}/.libs/libzfs_core.a"
        "${OPENZFS_BINARY_DIR}/.libs/libnvpair.a"
        "${OPENZFS_BINARY_DIR}/libzpool.la"
        "${OPENZFS_BINARY_DIR}/libzfs_core.la"
        "${OPENZFS_BINARY_DIR}/libnvpair.la"
        "${OPENZFS_BINARY_DIR}/include/zfs_gitrev.h"
        "${_openzfs_response}"
    INSTALL_COMMAND "")
ExternalProject_Add_StepDependencies(openzfs_native patch
    "${_openzfs_patch}" "${_openzfs_patch_script}")
ExternalProject_Add_StepDependencies(openzfs_native configure
    "${_openzfs_library_selection}" ${_openzfs_selected_libraries})
ExternalProject_Add_StepDependencies(openzfs_native build
    "${_openzfs_prepare_script}" "${_openzfs_link_script}"
    "${_openzfs_patch}" "${_openzfs_patch_script}")
# Configure owns this generated header. In particular Ninja must not see it as
# an unbuildable input when compiler depfiles refer to it after the first build.
ExternalProject_Add_Step(openzfs_native configured_headers
    COMMAND <BINARY_DIR>/config.status zfs_config.h
    WORKING_DIRECTORY <BINARY_DIR>
    DEPENDEES configure DEPENDERS build
    BYPRODUCTS "${OPENZFS_BINARY_DIR}/zfs_config.h")

foreach(_archive zpool zfs_core nvpair)
    add_library(openzfs_${_archive} STATIC IMPORTED GLOBAL)
    set_target_properties(openzfs_${_archive} PROPERTIES
        IMPORTED_LOCATION "${OPENZFS_BINARY_DIR}/.libs/lib${_archive}.a")
    add_dependencies(openzfs_${_archive} openzfs_native)
endforeach()

add_library(openzfs_zpool_interface INTERFACE)
add_library(OpenZFS::Zpool ALIAS openzfs_zpool_interface)
set_property(TARGET openzfs_zpool_interface PROPERTY
    INTERFACE_LINK_DEPENDS "${_openzfs_library_selection};${_openzfs_selected_libraries}")
add_dependencies(openzfs_zpool_interface openzfs_native)
# Upstream's zhack_CPPFLAGS, plus source root for the maintained native adapters.
# Keep ordinary -I ordering: libspl intentionally overrides libc headers.
target_include_directories(openzfs_zpool_interface INTERFACE
    "${OPENZFS_BINARY_DIR}" "${OPENZFS_BINARY_DIR}/include"
    "${OPENZFS_SOURCE_DIR}/include" "${OPENZFS_SOURCE_DIR}/module/icp/include"
    "${OPENZFS_SOURCE_DIR}/lib/libspl/include"
    "${OPENZFS_SOURCE_DIR}/lib/libspl/include/os/linux"
    "${OPENZFS_SOURCE_DIR}" ${_openzfs_dependency_includes})
target_compile_definitions(openzfs_zpool_interface INTERFACE
    HAVE_CONFIG_H _GNU_SOURCE _REENTRANT _FILE_OFFSET_BITS=64 _LARGEFILE64_SOURCE)
# Put ABI switches after configuration-specific -DNDEBUG, just as upstream's
# LIBZPOOL_CPPFLAGS overrides its normal non-debug library compile flags.
target_compile_options(openzfs_zpool_interface INTERFACE
    -include "${OPENZFS_BINARY_DIR}/zfs_config.h"
    -DDEBUG -DZFS_DEBUG -UNDEBUG -fno-strict-aliasing -pthread)
target_link_options(openzfs_zpool_interface INTERFACE -pthread)
target_link_libraries(openzfs_zpool_interface INTERFACE
    openzfs_zpool openzfs_zfs_core openzfs_nvpair
    "-Wl,@${_openzfs_response}" Threads::Threads)
set_property(TARGET openzfs_zpool_interface APPEND PROPERTY
    INTERFACE_LINK_DEPENDS "${_openzfs_response}")
