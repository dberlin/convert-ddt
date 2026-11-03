if(NOT DEFINED BINARY_DIR OR NOT IS_DIRECTORY "${BINARY_DIR}")
    message(FATAL_ERROR "BINARY_DIR must name the configured OpenZFS build directory")
endif()

# Libtool's Make target is the .la file, not the static archive it owns.
# Invalidate that target when an archive has been removed independently.
foreach(_library zpool zfs_core nvpair)
    if(NOT EXISTS "${BINARY_DIR}/.libs/lib${_library}.a")
        file(REMOVE "${BINARY_DIR}/lib${_library}.la")
    endif()
endforeach()
