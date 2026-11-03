# libtool merges convenience archives into the three public static archives.
# Read only the remaining system dependencies, including optional dependencies
# selected by the fresh configure (execinfo, unwind, atomic, gettext, etc.).
cmake_minimum_required(VERSION 3.24)
if(NOT DEFINED BINARY_DIR OR NOT DEFINED OUTPUT_FILE)
    message(FATAL_ERROR "OpenZFSLinkDependencies requires BINARY_DIR and OUTPUT_FILE")
endif()
set(_flags)
foreach(_name zpool zfs_core nvpair)
    file(READ "${BINARY_DIR}/lib${_name}.la" _metadata)
    if(NOT _metadata MATCHES "\ndependency_libs='([^'\n]*)'")
        message(FATAL_ERROR "Missing dependency_libs in native lib${_name}.la")
    endif()
    separate_arguments(_dependencies UNIX_COMMAND "${CMAKE_MATCH_1}")
    foreach(_dependency IN LISTS _dependencies)
        if(_dependency MATCHES "\\.la$")
            # These are already explicitly linked in upstream zhack order.
            get_filename_component(_basename "${_dependency}" NAME)
            if(NOT _basename MATCHES "^lib(zpool|zfs_core|nvpair)\\.la$")
                message(FATAL_ERROR "Unexpected non-merged native archive: ${_dependency}")
            endif()
        elseif(_dependency STREQUAL "-pthread")
            # The consuming target uses Threads::Threads and -pthread.
        elseif(_dependency MATCHES "^-L" OR _dependency MATCHES "^-l"
                OR IS_ABSOLUTE "${_dependency}")
            list(APPEND _flags "${_dependency}")
        else()
            message(FATAL_ERROR "Unsupported native link dependency: ${_dependency}")
        endif()
    endforeach()
endforeach()
# An ld response file keeps optional native dependency detection authoritative
# without a second CMake configure or fragile duplication of Autoconf probes.
# It is linked after the imported archives, not through early driver options.
set(_response "")
foreach(_flag IN LISTS _flags)
    string(REPLACE "\\" "\\\\" _quoted "${_flag}")
    string(REPLACE "\"" "\\\"" _quoted "${_quoted}")
    string(APPEND _response "\"${_quoted}\"\n")
endforeach()
set(_temporary "${OUTPUT_FILE}.tmp")
file(WRITE "${_temporary}" "${_response}")
execute_process(COMMAND "${CMAKE_COMMAND}" -E copy_if_different
    "${_temporary}" "${OUTPUT_FILE}" COMMAND_ERROR_IS_FATAL ANY)
file(REMOVE "${_temporary}")
