"""Owned disposable-pool fixtures for fixed offline consumer proofs.

Keep exact device identity, recovery fencing, kernel history/byte verification
and encryption/ZVOL consumers here; workloads belong to the fixed proof suite.
"""

import fcntl
import hashlib
import os
from pathlib import Path
import re
import stat
import struct
import time

from integration import Pool, require


MIB = 1024 * 1024
BLKGETSIZE64 = 0x80081272
STABLE_PROPERTIES = (
    "guid", "createtxg", "creation", "origin", "mountpoint", "canmount",
    "recordsize", "volsize", "volblocksize", "copies", "compression",
    "checksum", "dedup", "encryption", "encryptionroot", "keyformat",
    "keylocation", "readonly", "quota", "reservation", "refquota",
    "refreservation", "defer_destroy", "userquota@0", "userobjquota@0",
    "org.convert-ddt:fixture",
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def image_hash(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(4 * MIB), b""):
            value.update(chunk)
    return value.hexdigest()


def payload(seed, token, size, compressible=False):
    material = (str(seed) + ":" + str(token)).encode()
    if compressible:
        unit = hashlib.shake_256(material).digest(1024)
        return (unit * ((size + 1023) // 1024))[:size]
    return hashlib.shake_256(material).digest(size)


class DisposablePool(Pool):
    def __init__(self, harness, label, seed):
        super().__init__(harness, label)
        self.files = {}
        self.views = {}
        self.volume_bytes = {}
        self.volume_views = {}
        self.file_identities = {}
        self.snapshot_mounts = {}
        self.recovery_required = False
        self.log = []
        self.info.update(seed=seed, operations=self.log, manifests=[])

    def create(self):
        super().create()
        for path in sorted(self.devices.iterdir()):
            value = path.stat()
            require(stat.S_ISREG(value.st_mode), "Fixture vdev is not a regular file")
            self.file_identities[str(path)] = [value.st_dev, value.st_ino, value.st_size]
        self.info["file_identities"] = self.file_identities
        self.cache = self.directory / "empty.cache"
        with self.cache.open("xb") as stream:
            stream.flush()
            os.fsync(stream.fileno())
        self.assert_owned()
        self.h.flush()

    def assert_files(self):
        require(self.file_identities, "Missing owned file identities")
        for filename, expected in self.file_identities.items():
            value = Path(filename).lstat()
            require(stat.S_ISREG(value.st_mode) and
                    [value.st_dev, value.st_ino, value.st_size] == expected,
                    "Refusing operation: owned vdev identity changed: " + filename)

    def assert_owned(self):
        super().assert_owned()
        if not self.file_identities:
            return
        self.assert_files()
        output = self.h.command("zpool", "status", "-P", self.name).stdout
        actual = set()
        for line in output.splitlines():
            parts = line.split()
            if parts and parts[0].startswith("/"):
                path = Path(parts[0])
                value = path.stat()
                actual.add((value.st_dev, value.st_ino, value.st_size))
        require(actual == {tuple(value) for value in self.file_identities.values()},
                "Pool leaf files no longer match exact owned inodes")

    def exported(self):
        self.assert_files()
        result = self.h.command("zpool", "list", "-Hp", "-o", "guid").stdout
        require(self.guid not in result.split(), "Owned pool is still imported")
        for filename in self.file_identities:
            labels = self.h.command("zdb", "-l", filename).stdout
            values = set(re.findall(r"^\s*pool_guid:\s*(\d+)\s*$", labels, re.MULTILINE))
            require(values == {self.guid}, "Exported label GUID no longer proves ownership")

    def import_pool(self, mount=True):
        require(not self.recovery_required,
                "Unrecovered offline stage: stock import is forbidden")
        self.exported()
        self.h.command("zpool", "import", "-N", "-d", self.devices,
                       "-o", "cachefile=none", self.guid)
        self.assert_owned()
        if not mount:
            return
        for dataset in self.keys:
            state = self.zfs("get", "-H", "-o", "value", "keystatus", dataset).stdout.strip()
            if state != "available":
                self.zfs("load-key", dataset)
        self.zfs("mount", self.name)
        for dataset in self.datasets:
            self.zfs("mount", dataset)
        for dataset in self.volume_bytes:
            self.zfs("set", "volmode=dev", "snapdev=visible", dataset)
            self.volume_path(dataset)
        self.mount_views()

    def export(self):
        require(not self.recovery_required,
                "Unrecovered offline stage: stock export is forbidden")
        self.unmount_views()
        super().export()
        self.exported()

    def destroy(self):
        require(not self.recovery_required,
                "Unrecovered offline stage retained; refusing stock import/destruction of raw allocations")
        self.unmount_views()
        if self.created and self.file_identities:
            self.assert_files()
        super().destroy()

    def action(self, operation, **fields):
        self.log.append({"operation": operation, **fields})
        self.h.flush()

    def path(self, dataset, relative):
        return self.mount / dataset.split("/", 1)[1] / relative

    def put(self, dataset, name, data):
        self.assert_owned()
        target = self.path(dataset, name)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        self.files[dataset][name] = data
        self.action("write", dataset=dataset, file=name, size=len(data), sha256=digest(data))

    def snapshot(self, dataset, name):
        self.zfs("snapshot", dataset + "@" + name)
        if dataset in self.files:
            self.views[dataset + "@" + name] = dict(self.files[dataset])
        else:
            self.volume_views[dataset + "@" + name] = self.volume_bytes[dataset]
        self.action("snapshot", dataset=dataset, name=name)

    def clone(self, source, target):
        dataset = self.name + "/" + target
        mount = self.mount / target
        self.zfs("clone", "-o", "mountpoint=" + str(mount), source, dataset)
        self.datasets.append(dataset)
        self.files[dataset] = dict(self.views[source])
        self.action("clone", source=source, dataset=dataset)
        return dataset

    def mount_views(self):
        for snapshot in sorted(self.views):
            if snapshot in self.snapshot_mounts:
                continue
            target = self.directory / "views" / snapshot.replace("/", "_").replace("@", "_")
            target.mkdir(parents=True, exist_ok=True)
            self.assert_owned()
            self.h.command("mount", "-t", "zfs", "-o", "ro", snapshot, target)
            self.snapshot_mounts[snapshot] = target

    def unmount_views(self):
        for snapshot, target in reversed(list(self.snapshot_mounts.items())):
            mounts = []
            for line in Path("/proc/self/mountinfo").read_text().splitlines():
                before, after = line.split(" - ", 1)
                if before.split()[4] == str(target):
                    mounts.append(after.split()[:2])
            require(mounts == [["zfs", snapshot]], "Snapshot mount ownership changed")
            self.assert_owned()
            self.h.command("umount", target)
            del self.snapshot_mounts[snapshot]

    def volume_path(self, dataset):
        path = Path("/dev/zvol") / dataset
        deadline = time.monotonic() + 30
        while not path.exists() and time.monotonic() < deadline:
            time.sleep(0.1)
        require(path.exists() and stat.S_ISBLK(path.stat().st_mode),
                "Required real ZVOL block device is absent: " + str(path))
        # The kernel dataset-to-device mapping must match, not merely a filename.
        link = path.resolve(strict=True)
        st = path.stat()
        sysdev = Path("/sys/dev/block") / (str(os.major(st.st_rdev)) + ":" + str(os.minor(st.st_rdev)))
        uevent = (sysdev / "uevent").read_text()
        require("DEVNAME=" + link.name in uevent.splitlines(), "ZVOL device mapping is ambiguous")
        return path

    def read_volume(self, dataset, expected):
        self.assert_owned()
        path = self.volume_path(dataset)
        with path.open("rb", buffering=0) as stream:
            value = os.fstat(stream.fileno())
            require(stat.S_ISBLK(value.st_mode) and value.st_rdev == path.stat().st_rdev,
                    "ZVOL identity changed while opening")
            size = struct.unpack("Q", fcntl.ioctl(stream.fileno(), BLKGETSIZE64, b"\0" * 8))[0]
            require(size == len(expected), "ZVOL size changed")
            chunks = []
            remaining = size
            while remaining:
                chunk = stream.read(min(MIB, remaining))
                require(chunk, "Short ZVOL read")
                chunks.append(chunk)
                remaining -= len(chunk)
        actual = b"".join(chunks)
        require(actual == expected, "ZVOL payload mismatch: " + dataset)
        return digest(actual)

    def put_volume(self, dataset, data):
        self.assert_owned()
        path = self.volume_path(dataset)
        with path.open("r+b", buffering=0) as stream:
            value = os.fstat(stream.fileno())
            require(stat.S_ISBLK(value.st_mode) and value.st_rdev == path.stat().st_rdev,
                    "Refusing write: ZVOL device identity changed")
            require(struct.unpack("Q", fcntl.ioctl(stream.fileno(), BLKGETSIZE64, b"\0" * 8))[0] == len(data),
                    "Refusing write: ZVOL size differs from owned fixture")
            offset = 0
            while offset < len(data):
                written = stream.write(data[offset:offset + MIB])
                require(written > 0, "Short ZVOL write")
                offset += written
            os.fsync(stream.fileno())
        self.volume_bytes[dataset] = data
        self.action("write-volume", dataset=dataset, size=len(data), sha256=digest(data))

    def stable_metadata(self):
        output = self.zfs("get", "-Hpr", "-t", "filesystem,volume,snapshot,bookmark",
                          "-o", "name,property,value,source", ",".join(STABLE_PROPERTIES), self.name).stdout
        # Sources and native GUIDs are part of the preservation oracle.
        properties = sorted(output.splitlines())
        snapshots = self.zfs("list", "-Hpr", "-t", "snapshot,bookmark", "-o", "name,guid,createtxg", self.name).stdout
        holds = []
        for snapshot in sorted({**self.views, **self.volume_views}):
            holds.extend(self.zfs("holds", "-Hp", snapshot).stdout.splitlines())
        return {"properties": properties, "history": sorted(snapshots.splitlines()),
                "holds": sorted(holds)}

    def verify_files(self, directory, expected):
        actual = set()
        for path in directory.rglob("*"):
            require(not path.is_symlink(), "Unexpected symlink in generated fixture")
            if path.is_file():
                actual.add(str(path.relative_to(directory)))
        require(actual == set(expected), "Namespace mismatch at " + str(directory))
        result = {}
        for name, data in sorted(expected.items()):
            path = directory / name
            require(path.stat().st_size == len(data), "File length mismatch: " + str(path))
            value = image_hash(path)
            require(value == digest(data), "File payload mismatch: " + str(path))
            result[name] = {"bytes": len(data), "sha256": value}
        return result

    def verify_manifest(self, stage):
        self.assert_owned()
        self.mount_views()
        result = {"stage": stage, "files": {}, "volumes": {}}
        for dataset, files in sorted(self.files.items()):
            result["files"][dataset] = self.verify_files(self.path(dataset, "."), files)
        for snapshot, files in sorted(self.views.items()):
            result["files"][snapshot] = self.verify_files(self.snapshot_mounts[snapshot], files)
        for dataset, data in sorted({**self.volume_bytes, **self.volume_views}.items()):
            result["volumes"][dataset] = {"bytes": len(data), "sha256": self.read_volume(dataset, data)}
        result["metadata"] = self.stable_metadata()
        self.info["manifests"].append(result)
        self.h.flush()
        return result

    def key_args(self):
        result = []
        for dataset in self.keys:
            key = self.directory / "encryption.key"
            require(key.is_file() and key.stat().st_size == 32, "Fixture encryption key is missing")
            result.extend(["--key-file", dataset + "=" + str(key)])
        return result
