"""Observe committed checkpoint identity through the imported pool's kernel history."""

import ctypes
import ctypes.util
import re


class CheckpointHistory:
    """Retain a contiguous native-history cursor for one imported pool GUID."""

    def __init__(self, pool: str, guid: str) -> None:
        self._pool = pool
        self._handle = None
        self._pool_handle = None
        self._offset = 0
        self._txg = None
        self._observed = False
        self._failure = None
        if not isinstance(pool, str) or not pool or "\0" in pool:
            raise self._error("invalid source pool name")
        if not isinstance(guid, str) or re.fullmatch(r"[0-9]+", guid) is None:
            raise self._error("invalid expected source pool GUID")
        self._guid = int(guid)
        if not 0 < self._guid < 2 ** 64:
            raise self._error("expected source pool GUID is outside uint64 range")
        try:
            zfs_path = ctypes.util.find_library("zfs")
            nvpair_path = ctypes.util.find_library("nvpair")
            if not zfs_path or not nvpair_path:
                raise self._error("system libzfs and libnvpair are required")
            self._libzfs = ctypes.CDLL(zfs_path)
            self._nvpair = ctypes.CDLL(nvpair_path)
            self._bind()
            self._handle = self._libzfs.libzfs_init()
            if not self._handle:
                raise self._error("libzfs_init failed")
            self._pool_handle = self._libzfs.zpool_open(self._handle, pool.encode())
            if not self._pool_handle:
                raise self._native_error("cannot open imported source pool")
            self._verify_guid()
        except Exception as error:
            self.close()
            raise self._error("cannot initialize native checkpoint observation: " + str(error)) from error

    def _bind(self) -> None:
        pointer = ctypes.c_void_p
        pointer_out = ctypes.POINTER(pointer)
        uint64_out = ctypes.POINTER(ctypes.c_uint64)
        string_out = ctypes.POINTER(ctypes.c_char_p)
        lib = self._libzfs
        lib.libzfs_init.argtypes = []
        lib.libzfs_init.restype = pointer
        lib.libzfs_fini.argtypes = [pointer]
        lib.libzfs_fini.restype = None
        lib.libzfs_error_description.argtypes = [pointer]
        lib.libzfs_error_description.restype = ctypes.c_char_p
        lib.zpool_open.argtypes = [pointer, ctypes.c_char_p]
        lib.zpool_open.restype = pointer
        lib.zpool_close.argtypes = [pointer]
        lib.zpool_close.restype = None
        lib.zpool_refresh_stats.argtypes = [pointer, ctypes.POINTER(ctypes.c_int)]
        lib.zpool_refresh_stats.restype = ctypes.c_int
        lib.zpool_get_config.argtypes = [pointer, pointer_out]
        lib.zpool_get_config.restype = pointer
        lib.zpool_get_history.argtypes = [pointer, pointer_out, uint64_out,
                                         ctypes.POINTER(ctypes.c_int)]
        lib.zpool_get_history.restype = ctypes.c_int
        nv = self._nvpair
        nv.nvlist_free.argtypes = [pointer]
        nv.nvlist_free.restype = None
        nv.nvlist_size.argtypes = [pointer, ctypes.POINTER(ctypes.c_size_t), ctypes.c_int]
        nv.nvlist_size.restype = ctypes.c_int
        nv.nvlist_exists.argtypes = [pointer, ctypes.c_char_p]
        nv.nvlist_exists.restype = ctypes.c_int
        nv.nvlist_lookup_uint64.argtypes = [pointer, ctypes.c_char_p, uint64_out]
        nv.nvlist_lookup_uint64.restype = ctypes.c_int
        nv.nvlist_lookup_string.argtypes = [pointer, ctypes.c_char_p, string_out]
        nv.nvlist_lookup_string.restype = ctypes.c_int
        nv.nvlist_lookup_nvlist_array.argtypes = [pointer, ctypes.c_char_p,
                                                 ctypes.POINTER(pointer_out),
                                                 ctypes.POINTER(ctypes.c_uint)]
        nv.nvlist_lookup_nvlist_array.restype = ctypes.c_int

    def _error(self, message: str) -> RuntimeError:
        return RuntimeError("Checkpoint history safety for %r: %s; preserve resources and source lease" %
                            (self._pool, message))

    def _native_error(self, message: str) -> RuntimeError:
        description = self._libzfs.libzfs_error_description(self._handle)
        if description:
            message += ": " + description.decode(errors="replace")
        return self._error(message)

    def _uint64(self, record: ctypes.c_void_p, key: bytes) -> int:
        value = ctypes.c_uint64()
        if self._nvpair.nvlist_lookup_uint64(record, key, ctypes.byref(value)) != 0:
            raise self._error("missing or malformed native field " + key.decode())
        return value.value

    def _string(self, record: ctypes.c_void_p, key: bytes) -> bytes:
        value = ctypes.c_char_p()
        if self._nvpair.nvlist_lookup_string(record, key, ctypes.byref(value)) != 0 or value.value is None:
            raise self._error("missing or malformed native field " + key.decode())
        return value.value

    def _verify_guid(self) -> None:
        missing = ctypes.c_int()
        if self._libzfs.zpool_refresh_stats(self._pool_handle, ctypes.byref(missing)) != 0:
            raise self._native_error("cannot refresh kernel source pool identity")
        if missing.value:
            raise self._error("source pool disappeared from the kernel")
        config = self._libzfs.zpool_get_config(self._pool_handle, None)
        if not config or self._uint64(config, b"pool_guid") != self._guid:
            raise self._error("kernel source pool GUID mismatch")

    def _consume(self, record: ctypes.c_void_p) -> None:
        if self._uint64(record, b"history time") == 0:
            raise self._error("history record has no valid commit time")
        if not self._nvpair.nvlist_exists(record, b"internal_name"):
            return
        name = self._string(record, b"internal_name")
        message = self._string(record, b"history internal str")
        history_txg = self._uint64(record, b"history txg")
        if history_txg == 0:
            raise self._error("internal history record has no valid transaction group")
        if name == b"spa checkpoint":
            match = re.fullmatch(rb"checkpointed uberblock txg=([0-9]+)", message)
            if match is None:
                raise self._error("malformed authoritative checkpoint creation record")
            txg = int(match[1])
            if not 0 < txg < 2 ** 64 or history_txg != txg + 1:
                raise self._error("checkpoint creation transaction groups are inconsistent")
            if self._observed:
                raise self._error("source checkpoint was replaced after observation")
            self._txg = txg
        elif name == b"spa discard checkpoint":
            if self._observed:
                raise self._error("source checkpoint was discarded after observation")
            self._txg = None

    def checkpoint_txg(self) -> int:
        """Return the active creation TXG, rejecting incomplete or replaced proof."""
        if self._failure is not None:
            raise self._error("a previous observation failed: " + self._failure)
        if not self._pool_handle:
            raise self._error("native observer is closed")
        try:
            self._verify_guid()
            while True:
                start = self._offset
                offset = ctypes.c_uint64(start)
                eof = ctypes.c_int()
                history = ctypes.c_void_p()
                try:
                    if self._libzfs.zpool_get_history(self._pool_handle, ctypes.byref(history),
                                                    ctypes.byref(offset), ctypes.byref(eof)) != 0:
                        raise self._native_error("cannot read committed kernel history")
                    if not history:
                        raise self._error("native history returned no record container")
                    records = ctypes.POINTER(ctypes.c_void_p)()
                    count = ctypes.c_uint()
                    if self._nvpair.nvlist_lookup_nvlist_array(
                            history, b"history record", ctypes.byref(records), ctypes.byref(count)) != 0:
                        raise self._error("native history record array is missing or malformed")
                    if count.value and not records:
                        raise self._error("native history record array has no storage")
                    framed_bytes = 0
                    for index in range(count.value):
                        record = records[index]
                        length = ctypes.c_size_t()
                        if not record or self._nvpair.nvlist_size(record, ctypes.byref(length), 0) != 0:
                            raise self._error("cannot size original native history record")
                        if length.value == 0:
                            raise self._error("native history record has zero encoded length")
                        framed_bytes += length.value + 8
                    advance = offset.value - start
                    if advance < 0 or advance < framed_bytes:
                        raise self._error("native history cursor is nonmonotonic or shorter than its records")
                    if advance != framed_bytes:
                        if self._observed:
                            raise self._error("incremental history cursor lost records")
                        self._txg = None
                        if not count.value:
                            raise self._error("initial history cursor lost records at EOF without checkpoint proof")
                        # libzfs combines reads, so the gap may occur anywhere
                        # inside this aggregate. None of its records can prove
                        # a checkpoint survived the loss. Advance to the native
                        # committed end boundary and trust only later batches.
                        # In particular, do not chase the moving ring-buffer
                        # beginning by replaying records from this batch.
                        self._offset = offset.value
                        continue
                    if eof.value not in (0, 1):
                        raise self._error("native history returned an invalid EOF flag")
                    if not eof.value and advance == 0:
                        raise self._error("native history cursor made no progress before EOF")
                    for index in range(count.value):
                        self._consume(records[index])
                    self._offset = offset.value
                    if eof.value:
                        break
                finally:
                    if history:
                        self._nvpair.nvlist_free(history)
            self._verify_guid()
            if self._txg is None:
                raise self._error("no current authoritative checkpoint creation remains in history")
            self._observed = True
            return self._txg
        except Exception as error:
            self._failure = str(error)
            raise self._error("native checkpoint observation failed: " + str(error)) from error

    def close(self) -> None:
        """Release only this observer's userspace native handles."""
        if self._pool_handle:
            self._libzfs.zpool_close(self._pool_handle)
            self._pool_handle = None
        if self._handle:
            self._libzfs.libzfs_fini(self._handle)
            self._handle = None
