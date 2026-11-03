# The release archive and this correction form one pinned native source input.
cmake_minimum_required(VERSION 3.24)
foreach(_required SOURCE_DIR PATCH_FILE PATCH_EXECUTABLE)
    if(NOT DEFINED ${_required} OR "${${_required}}" STREQUAL "")
        message(FATAL_ERROR "PatchOpenZFS requires ${_required}")
    endif()
endforeach()

function(require_hash path expected)
    if(NOT EXISTS "${path}")
        message(FATAL_ERROR "Missing pinned OpenZFS input: ${path}")
    endif()
    file(SHA256 "${path}" actual)
    if(NOT actual STREQUAL expected)
        message(FATAL_ERROR "Unrecognized OpenZFS input: ${path} (SHA256 ${actual})")
    endif()
endfunction()

require_hash("${SOURCE_DIR}/META"
    3655f5a583a51e62daefae4ef28cfd7d3a41bf496f59a6064b71affb30c497b2)
require_hash("${SOURCE_DIR}/configure"
    f5cbb09b337be7164390e34753177d643112bc4f53802ca9e4d2e48a5a020e34)
require_hash("${PATCH_FILE}"
    cefd43ad858de051680ed9b4c588cc261c5e7c5cc9fa31a7fee13db5ccdcf49b)

set(_zil "${SOURCE_DIR}/module/zfs/zil.c")
if(NOT EXISTS "${_zil}")
    message(FATAL_ERROR "Missing pinned OpenZFS zil.c")
endif()
file(SHA256 "${_zil}" _hash)
set(_original aff082bff393836fd3d415cf6441fee1c034e1f8378a94a4a1a573d21ce64ad6)
set(_corrected fee736dca22aed9ad55c8828835c715440c864bb77a2ef8943a074f758132912)
if(_hash STREQUAL _original)
    execute_process(
        COMMAND "${PATCH_EXECUTABLE}" --directory "${SOURCE_DIR}"
            --batch --forward --fuzz=0 -p1 -i "${PATCH_FILE}"
        RESULT_VARIABLE _result)
    if(NOT _result EQUAL 0)
        message(FATAL_ERROR "The pinned claimed-ZIL correction failed: ${_result}")
    endif()
elseif(NOT _hash STREQUAL _corrected)
    message(FATAL_ERROR "Unrecognized OpenZFS zil.c; refusing to patch or build it")
endif()
require_hash("${_zil}" "${_corrected}")
