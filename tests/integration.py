#!/usr/bin/env python3
"""Exercise DDT conversion and recovery on temporary file-backed pools.

Requires root. Saves command output and integrity checks in a JSON report
beside the temporary pool directory.
"""

import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import traceback
import uuid


class Failure(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise Failure(message)


class Harness:
    def __init__(self, converter, parent):
        self.converter = str(converter)
        self.root = Path(tempfile.mkdtemp(prefix="convert-ddt-integration-", dir=parent))
        self.evidence_path = self.root.with_suffix(".json")
        self.evidence = {
            "converter": self.converter,
            "work_directory": str(self.root),
            "started": time.time(),
            "status": "running",
            "cases": [{"name": name, "status": "not_run"} for name in (
                "disabled-fast-dedup-rejected-without-data-mutation",
                "full-layout-sha256-sha512-copies-encryption-snapshots-clone",
                "mixed-physical-slots-reject-full-preserve-journal-only",
                "committed-batch-sigterm-legacy-readable-restart",
                "committed-batch-sigkill-normal-import-recovery")],
            "commands": [],
            "pools": [],
            "coverage": {"zvol": "Required real block device: legacy writes, conversion reads, overwrite/addref/free."},
        }
        self.pools = []
        self.current_case = None
        self.flush()

    def flush(self):
        temporary = self.evidence_path.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(self.evidence, indent=2) + "\n")
        temporary.replace(self.evidence_path)

    def command(self, *args, expect=0, timeout=300):
        argv = [str(arg) for arg in args]
        item = {"case": self.current_case, "argv": argv, "started": time.time()}
        self.evidence["commands"].append(item)
        self.flush()
        try:
            result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True, errors="replace", timeout=timeout,
                                    env={**os.environ, "LC_ALL": "C"})
            item.update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
        except subprocess.TimeoutExpired as error:
            item.update(timeout=timeout, stdout=str(error.stdout), stderr=str(error.stderr))
            self.flush()
            raise Failure("Command timed out: " + " ".join(argv)) from error
        item["finished"] = time.time()
        self.flush()
        if expect is not None:
            require(result.returncode == expect,
                    "Command returned %d, expected %d: %s\n%s" %
                    (result.returncode, expect, " ".join(argv), result.stderr))
        return result

    @contextlib.contextmanager
    def case(self, name):
        self.current_case = name
        item = next(case for case in self.evidence["cases"] if case["name"] == name)
        item.update(status="running", started=time.time())
        self.flush()
        print("CASE " + name, flush=True)
        try:
            yield item
        except BaseException as error:
            item.update(status="failed", error=str(error), traceback=traceback.format_exc())
            raise
        else:
            item["status"] = "passed"
        finally:
            item["finished"] = time.time()
            self.flush()
            self.current_case = None

    def pool(self, label):
        pool = Pool(self, label)
        self.pools.append(pool)
        pool.create()
        return pool

    def cleanup(self):
        errors = []
        for pool in reversed(self.pools):
            try:
                pool.destroy()
            except BaseException as error:
                errors.append(str(error))
        self.evidence["cleanup_errors"] = errors
        self.flush()
        if not errors:
            shutil.rmtree(self.root)
        else:
            self.evidence["retained_work_directory"] = str(self.root)
            self.flush()
        return errors


class Pool:
    def __init__(self, harness, label):
        self.h = harness
        self.name = "ddt_it_" + uuid.uuid4().hex[:16]
        self.directory = self.h.root / label
        self.devices = self.directory / "devices"
        self.mount = self.directory / "mnt"
        self.guid = None
        self.created = False
        self.destroyed = False
        self.datasets = []
        self.keys = []
        self.volumes = []
        self.manifest = {}
        self.info = {"label": label, "name": self.name, "directory": str(self.directory)}
        self.h.evidence["pools"].append(self.info)

    def create(self):
        self.devices.mkdir(parents=True)
        vdevs = [self.devices / "mirror-0.img", self.devices / "mirror-1.img"]
        for path in vdevs:
            with path.open("xb") as stream:
                stream.truncate(2 * 1024**3)
        common = ["-o", "cachefile=none", "-o", "ashift=12", "-O", "compression=off",
                  "-O", "atime=off", "-m", str(self.mount)]
        self.info["ownership_uncertain"] = True
        result = self.h.command("zpool", "create", *common,
                                "-o", "feature@fast_dedup=disabled", self.name,
                                "mirror", *vdevs, expect=None)
        if result.returncode:
            existing = self.h.command("zpool", "get", "-H", "-o", "value", "guid",
                                      self.name, expect=None)
            require(existing.returncode != 0,
                    "Failed create left a pool; refusing fallback without established ownership")
            self.info["ownership_uncertain"] = False
            # Build the legacy fixture from the CLI's supported feature set.
            listing = self.h.command("zpool", "upgrade", "-v").stdout
            features = re.findall(r"^([a-z][a-z0-9_]*)[ \t]{2,}", listing, re.MULTILINE)
            require("fast_dedup" in features and "encryption" in features and
                    "sha512" in features, "Cannot discover complete default feature set")
            options = []
            for feature in dict.fromkeys(features):
                if feature != "fast_dedup":
                    options.extend(["-o", "feature@" + feature + "=enabled"])
            self.info["ownership_uncertain"] = True
            self.h.command("zpool", "create", "-d", *common, *options,
                           self.name, "mirror", *vdevs)
            self.info["feature_creation"] = "-d with all advertised features except fast_dedup"
        else:
            self.info["feature_creation"] = "defaults with fast_dedup disabled"
        self.created = True
        self.guid = self.h.command("zpool", "get", "-H", "-o", "value", "guid",
                                   self.name).stdout.strip()
        require(self.guid.isdecimal(), "Invalid newly created pool GUID")
        self.info["guid"] = self.guid
        self.info["ownership_uncertain"] = False
        self.h.flush()
        require(self.property("feature@fast_dedup") == "disabled", "Pool did not start with legacy dedup")

    def assert_owned(self):
        require(self.created and self.guid and not self.destroyed, "Pool ownership is not established")
        actual = self.h.command("zpool", "get", "-H", "-o", "value", "guid",
                                self.name).stdout.strip()
        require(actual == self.guid, "Refusing mutation: pool name no longer has owned GUID")

    def zp(self, operation, *args, timeout=300):
        self.assert_owned()
        return self.h.command("zpool", operation, *args, self.name, timeout=timeout)

    def zfs(self, *args):
        self.assert_owned()
        return self.h.command("zfs", *args)

    def property(self, name):
        return self.h.command("zpool", "get", "-Hp", "-o", "value", name, self.name).stdout.strip()

    def sync(self):
        self.zp("sync")

    def enable(self):
        self.zp("set", "feature@fast_dedup=enabled")
        require(self.property("feature@fast_dedup") in ("enabled", "active"), "fast_dedup not enabled")

    def export(self):
        self.sync()
        self.zp("export")

    def import_pool(self, mount=True):
        require(self.guid and not self.destroyed, "Cannot import unowned pool")
        self.h.command("zpool", "import", "-N", "-d", self.devices,
                       "-o", "cachefile=none", self.guid)
        self.assert_owned()
        if mount:
            for dataset in self.keys:
                self.zfs("load-key", dataset)
            self.zfs("mount", self.name)
            for dataset in self.datasets:
                self.zfs("mount", dataset)
            for volume in self.volumes:
                self.zfs("set", "volmode=dev", volume["dataset"])
                self.wait_volume(volume)

    def converter_args(self, mode, *options):
        return [self.h.converter, mode, "--pool-guid", self.guid,
                "--search-dir", str(self.devices), *options]

    def convert(self, mode="--convert", *options, accepted=True):
        args = self.converter_args(mode, *options)
        result = self.h.command(*args, expect=None, timeout=1800)
        if accepted:
            require(result.returncode == 0, "Converter failed: " + result.stderr)
        else:
            require(result.returncode != 0, "Converter accepted a forbidden operation")
        return result

    def dataset(self, name, checksum="sha256", copies=1, encrypted=False, recordsize="128K"):
        dataset = self.name + "/" + name
        options = ["-o", "dedup=" + checksum, "-o", "compression=off",
                   "-o", "recordsize=" + recordsize, "-o", "copies=" + str(copies),
                   "-o", "mountpoint=" + str(self.mount / name)]
        if encrypted:
            key = self.directory / "encryption.key"
            key.write_bytes(hashlib.sha256((self.name + " encryption key").encode()).digest())
            key.chmod(0o600)
            options += ["-o", "encryption=aes-256-gcm", "-o", "keyformat=raw",
                        "-o", "keylocation=" + key.as_uri()]
        self.zfs("create", *options, dataset)
        self.datasets.append(dataset)
        if encrypted:
            self.keys.append(dataset)
        return self.mount / name

    def wait_volume(self, volume):
        path = Path(volume["path"])
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                status = path.stat()
                if stat.S_ISBLK(status.st_mode):
                    volume["device"] = {"resolved_path": str(path.resolve()),
                                        "major": os.major(status.st_rdev),
                                        "minor": os.minor(status.st_rdev)}
                    self.h.flush()
                    return path
                raise Failure("Owned ZVOL path is not a block device: " + str(path))
            except FileNotFoundError:
                time.sleep(0.2)
        raise Failure("Required real ZVOL node unavailable after 30 seconds: " + str(path))

    def volume(self):
        dataset = self.name + "/dedup-volume"
        self.zfs("create", "-s", "-V", "16M", "-b", "128K",
                 "-o", "dedup=sha256", "-o", "compression=off",
                 "-o", "volmode=dev", dataset)
        volume = {"dataset": dataset, "path": "/dev/zvol/" + dataset,
                  "size": 16 * 1024 * 1024, "half_seeds": [None, None]}
        self.volumes.append(volume)
        self.info["volumes"] = self.volumes
        if shutil.which("udevadm"):
            self.h.command("udevadm", "settle", "--timeout=15", expect=None, timeout=20)
        self.wait_volume(volume)
        self.write_volume(volume, "zvol-original")
        return volume

    def write_volume(self, volume, seed, half=None):
        self.assert_owned()
        path = self.wait_volume(volume)
        halves = (0, 1) if half is None else (half,)
        require(all(index in (0, 1) for index in halves), "Invalid volume test range")
        with path.open("r+b", buffering=0) as stream:
            require(stat.S_ISBLK(os.fstat(stream.fileno()).st_mode),
                    "Refusing ZVOL writes to a non-block device")
            for index in halves:
                stream.seek(index * volume["size"] // 2)
                for block_index in range(64):
                    block = hashlib.shake_256((seed + ":" + str(block_index)).encode()).digest(128 * 1024)
                    require(stream.write(block) == len(block), "Short write to owned ZVOL")
                volume["half_seeds"][index] = seed
            os.fsync(stream.fileno())
        digest = hashlib.sha256()
        for half_seed in volume["half_seeds"]:
            require(half_seed is not None, "ZVOL fixture has unwritten ranges")
            for block_index in range(64):
                digest.update(hashlib.shake_256((half_seed + ":" + str(block_index)).encode()).digest(128 * 1024))
        self.manifest[str(path)] = digest.hexdigest()
        volume.setdefault("write_history", []).append({"halves": list(halves), "seed": seed,
                                                      "expected_sha256": digest.hexdigest()})
        self.sync()

    def overwrite_volume(self, volume):
        before = self.dedup_ratio()
        self.write_volume(volume, "zvol-replacement", half=0)
        self.verify()
        split = self.dedup_ratio()
        require(split < before, "Overwriting half the ZVOL did not release duplicate references")
        self.scrub()
        self.write_volume(volume, "zvol-replacement", half=1)
        self.verify()
        replaced = self.dedup_ratio()
        require(replaced > split, "Repeated ZVOL overwrite did not add references and free old keys")
        self.scrub()
        volume["overwrite_ratios"] = {"before": before, "split_halves": split, "both_replaced": replaced}
        self.h.flush()

    def write(self, path, seed, blocks=64, block_size=128 * 1024):
        digest = hashlib.sha256()
        with path.open("xb") as stream:
            for index in range(blocks):
                block = hashlib.shake_256((seed + ":" + str(index)).encode()).digest(block_size)
                stream.write(block)
                digest.update(block)
            stream.flush()
            os.fsync(stream.fileno())
        self.manifest[str(path)] = digest.hexdigest()
        return path

    def duplicate(self, source, target):
        digest = hashlib.sha256()
        with source.open("rb") as incoming, target.open("xb") as outgoing:
            while True:
                block = incoming.read(1024 * 1024)
                if not block:
                    break
                outgoing.write(block)
                digest.update(block)
            outgoing.flush()
            os.fsync(outgoing.fileno())
        self.manifest[str(target)] = digest.hexdigest()
        return target

    def verify(self):
        require(self.manifest, "No data was registered for verification")
        for filename, expected in self.manifest.items():
            digest = hashlib.sha256()
            with open(filename, "rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(block)
            require(digest.hexdigest() == expected, "Data mismatch: " + filename)
        self.info["verified_files"] = dict(self.manifest)
        self.info["last_verified"] = time.time()
        self.h.flush()

    def zdb(self, option, *objects):
        self.sync()
        return self.h.command("zdb", "-e", "-p", self.devices, option,
                              self.name, *objects, timeout=600).stdout

    def layout(self, version, flags, checksums=("sha256",)):
        output = self.zdb("-D")
        found = {}
        for checksum, ver, flag in re.findall(
                r"DDT-([\w-]+):\s*version=(\d+)[^\n]*flags=(0x[0-9a-fA-F]+|\d+)", output):
            found[checksum.lower()] = (int(ver), int(flag, 0))
        missing = [checksum for checksum in checksums if checksum not in found]
        if missing:
            directory = self.zdb("-dddd", "1")
            for checksum in missing:
                match = re.search(r"^\s*DDT-" + re.escape(checksum) +
                                  r"\s*=\s*(\d+)\s*$", directory, re.MULTILINE | re.IGNORECASE)
                if match:
                    details = self.zdb("-dddd", match.group(1))
                    values = dict(re.findall(r"^\s*(version|flags)\s*=\s*(0x[0-9a-fA-F]+|\d+)\s*$",
                                             details, re.MULTILINE))
                    require("version" in values and "flags" in values,
                            "zdb cannot expose DDT version and flags for " + checksum)
                    found[checksum] = (int(values["version"], 0), int(values["flags"], 0))
                elif version == 0 and re.search(r"DDT-" + re.escape(checksum) +
                                               r"-zap-(?:unique|duplicate)\s*=", directory,
                                               re.IGNORECASE):
                    found[checksum] = (0, 0)
        for checksum in checksums:
            require(found.get(checksum) == (version, flags),
                    "Wrong actual DDT layout for %s: %r; expected %r" %
                    (checksum, found.get(checksum), (version, flags)))
        self.info.setdefault("layouts", []).append({"version": version, "flags": flags,
                                                    "observed": found})
        self.h.flush()

    def dedup_ratio(self):
        value = self.property("dedupratio")
        return float(value.removesuffix("x"))

    def addref_free(self, pairs):
        self.sync()
        before = self.dedup_ratio()
        added = []
        for source, target in pairs:
            self.duplicate(source, target)
            added.append(target)
        self.sync()
        after = self.dedup_ratio()
        require(after > before, "New duplicate writes did not increase the actual pool dedup ratio")
        self.verify()
        for path in added:
            path.unlink()
            del self.manifest[str(path)]
        self.sync()
        self.scrub()
        self.verify()
        released = self.dedup_ratio()
        require(released < after, "Freeing duplicate files did not release DDT references")
        self.info.setdefault("addref_free", []).append({"before": before, "after_add": after,
                                                       "after_free": released})
        self.h.flush()

    def scrub(self):
        self.zp("scrub", "-w", timeout=1800)
        health = self.property("health")
        output = self.zp("status", "-p").stdout
        require(health == "ONLINE", "Pool is not healthy after scrub: " + health)
        require("errors: No known data errors" in output, "Scrub reported data errors")
        require(re.search(r"scrub repaired 0(?:B)?\b[^\n]*with 0 errors", output),
                "A completed zero-error scrub was not observed")
        for read, write, checksum in re.findall(
                r"^\s*\S+\s+(?:ONLINE|DEGRADED|FAULTED)\s+(\d+)\s+(\d+)\s+(\d+)\s*$",
                output, re.MULTILINE):
            require((int(read), int(write), int(checksum)) == (0, 0, 0),
                    "Nonzero vdev error counters after scrub")

    def destroy(self):
        require(not self.info.get("ownership_uncertain"),
                "Failed create left a pool with uncertain ownership; refusing deletion")
        if not self.created or self.destroyed:
            return
        require(self.guid, "No tracked GUID; retaining work directory rather than guessing ownership")
        result = self.h.command("zpool", "get", "-H", "-o", "value", "guid", self.name, expect=None)
        if result.returncode:
            self.import_pool(mount=False)
        self.assert_owned()
        self.zp("destroy", "-f")
        self.destroyed = True
        self.info["destroyed"] = True
        self.h.flush()


def full_conversion(h):
    with h.case("full-layout-sha256-sha512-copies-encryption-snapshots-clone"):
        pool = h.pool("full")
        one = pool.dataset("sha256")
        two = pool.dataset("copies2", copies=2)
        three = pool.dataset("copies3", copies=3)
        sha512 = pool.dataset("sha512", checksum="sha512")
        encrypted = pool.dataset("encrypted", encrypted=True)
        volume = pool.volume()
        for path, seed, blocks in [(one, "sha256-data", 64), (two, "copies-two", 32),
                                   (three, "copies-three", 32), (sha512, "sha512-data", 64),
                                   (encrypted, "encrypted-data", 32)]:
            source = pool.write(path / "original", seed, blocks)
            pool.duplicate(source, path / "duplicate")
            pool.write(path / "unique", seed + "-unique", 8)
        snapshot = pool.name + "/sha256@before"
        pool.zfs("snapshot", snapshot)
        clone = pool.name + "/clone"
        pool.zfs("clone", "-o", "mountpoint=" + str(pool.mount / "clone"), snapshot, clone)
        pool.datasets.append(clone)
        for name in ("original", "duplicate", "unique"):
            expected = pool.manifest[str(one / name)]
            pool.manifest[str(one / ".zfs/snapshot/before" / name)] = expected
            pool.manifest[str(pool.mount / "clone" / name)] = expected
        pool.sync()
        pool.layout(0, 0, ("sha256", "sha512"))
        entries = pool.zdb("-DDDDD")
        variants = set(int(value) for value in re.findall(r"\brefcnt \d+ phys (\d+)\b", entries))
        require({1, 2, 3}.issubset(variants), "Fixture did not materialize all three legacy copies variants")
        pool.verify()
        pool.enable()
        pool.convert("--check", accepted=False)  # Check imported-pool exclusion.
        pool.export()
        pool.convert("--check")
        pool.convert("--convert", accepted=False)
        pool.convert("--convert", "--fenced")
        pool.import_pool()
        pool.layout(1, 3, ("sha256", "sha512"))
        pool.verify()
        pool.scrub()
        pool.addref_free([(one / "original", one / "new-duplicate"),
                          (two / "original", two / "new-duplicate"),
                          (three / "original", three / "new-duplicate"),
                          (sha512 / "original", sha512 / "new-duplicate"),
                          (encrypted / "original", encrypted / "new-duplicate"),
                          (Path(volume["path"]), one / "new-volume-duplicate")])
        pool.overwrite_volume(volume)
        pool.zfs("destroy", clone)
        pool.datasets.remove(clone)
        pool.zfs("destroy", snapshot)
        for filename in list(pool.manifest):
            if filename.startswith(str(pool.mount / "clone") + "/") or "/.zfs/snapshot/" in filename:
                del pool.manifest[filename]
        for path in (one, two, three, sha512, encrypted):
            for name in ("original", "duplicate"):
                (path / name).unlink()
                del pool.manifest[str(path / name)]
        pool.sync()
        pool.scrub()
        pool.verify()
        pool.export()
        pool.import_pool()
        pool.layout(1, 3, ("sha256", "sha512"))
        pool.verify()
        pool.destroy()


def mixed_slots(h):
    with h.case("mixed-physical-slots-reject-full-preserve-journal-only"):
        pool = h.pool("mixed")
        one = pool.dataset("copies1")
        two = pool.dataset("copies2", copies=2)
        original = pool.write(one / "original", "same-key-mixed-copies", 128)
        pool.duplicate(original, one / "duplicate")
        pool.sync()  # Persist copies=1 before allocating copies=2 for the same keys.
        pool.duplicate(original, two / "original")
        pool.duplicate(original, two / "duplicate")
        pool.sync()
        pool.layout(0, 0)
        entries = pool.zdb("-DDDDD")
        variants = set(int(value) for value in re.findall(r"\brefcnt \d+ phys (\d+)\b", entries))
        require({1, 2}.issubset(variants), "Fixture did not create both legacy copies=1 and copies=2 slots")
        pool.verify()
        pool.enable()
        pool.export()
        pool.convert("--check", accepted=False)
        pool.convert("--convert", "--fenced", accepted=False)
        pool.import_pool()
        pool.layout(0, 0)
        pool.verify()
        pool.scrub()
        pool.export()
        pool.convert("--check", "--journal-only")
        pool.convert("--convert", "--fenced", "--journal-only")
        pool.import_pool()
        pool.layout(1, 2)
        preserved = pool.zdb("-DDDDD")
        variants = set(int(value) for value in re.findall(r"\brefcnt \d+ phys (\d+)\b", preserved))
        require({1, 2}.issubset(variants), "Journal-only lost an original physical variant")
        pool.verify()
        pool.scrub()
        pool.addref_free([(one / "original", one / "after"), (two / "original", two / "after")])
        for path in (one / "original", two / "original"):
            path.unlink()
            del pool.manifest[str(path)]
        pool.sync()
        pool.scrub()
        pool.verify()
        pool.export()
        pool.import_pool()
        pool.layout(1, 2)
        pool.verify()
        pool.destroy()


def interrupt_converter(pool, signum=signal.SIGTERM):
    h = pool.h
    argv = pool.converter_args("--convert", "--fenced", "--batch-size", "1")
    item = {"case": h.current_case, "argv": argv, "started": time.time(),
            "signal": signal.Signals(signum).name + " after copied batch"}
    h.evidence["commands"].append(item)
    h.flush()
    stdout = bytearray()
    stderr = bytearray()
    sent = False
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env={**os.environ, "LC_ALL": "C"})
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, stdout)
    selector.register(process.stderr, selectors.EVENT_READ, stderr)
    deadline = time.monotonic() + 300
    try:
        while selector.get_map():
            require(time.monotonic() < deadline, "No timely batch/clean termination during interrupt test")
            for key, _ in selector.select(timeout=1):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                key.data.extend(chunk)
                if not sent and b"copied batch" in stdout:
                    process.send_signal(signum)
                    sent = True
                    deadline = time.monotonic() + 120
        result = process.wait(timeout=10)
    finally:
        selector.close()
        if process.poll() is None:
            process.kill()
            process.wait()
        process.stdout.close()
        process.stderr.close()
        item.update(returncode=process.returncode, stdout=stdout.decode(errors="replace"),
                    stderr=stderr.decode(errors="replace"), signal_sent=sent, finished=time.time())
        h.flush()
    require(sent, "Converter completed or failed without a committed staging batch")
    expected = 130 if signum == signal.SIGTERM else -int(signum)
    require(result == expected, "%s returned %r instead of %r" %
            (signal.Signals(signum).name, result, expected))


def interruption(h):
    with h.case("committed-batch-sigterm-legacy-readable-restart"):
        pool = h.pool("interruption")
        data = pool.dataset("blocks", recordsize="4K")
        original = pool.write(data / "original", "interruption-unique-blocks", 8192, 4096)
        pool.duplicate(original, data / "duplicate")
        pool.sync()
        pool.layout(0, 0)
        pool.verify()
        pool.enable()
        pool.export()
        interrupt_converter(pool)
        pool.import_pool()
        pool.layout(0, 0)
        directory = pool.zdb("-dddd", "1")
        require(re.search(r"^\s*org\.convert-ddt:staging\s*=", directory, re.MULTILINE),
                "SIGTERM did not leave a committed staging root")
        pool.verify()
        pool.scrub()
        # Change source entries to exercise stale-stage reclamation on retry.
        pool.write(data / "between-runs", "intervening-write", 32, 4096)
        pool.duplicate(data / "between-runs", data / "between-runs-copy")
        pool.sync()
        pool.export()
        pool.convert("--check")
        pool.convert("--convert", "--fenced", "--batch-size", "256")
        pool.import_pool()
        pool.layout(1, 3)
        directory = pool.zdb("-dddd", "1")
        require(not re.search(r"^\s*org\.convert-ddt:staging\s*=", directory, re.MULTILINE),
                "Successful retry did not reclaim stale staging metadata")
        pool.verify()
        pool.scrub()
        pool.addref_free([(original, data / "post-restart-duplicate")])
        pool.destroy()


def disabled_feature(h):
    with h.case("disabled-fast-dedup-rejected-without-data-mutation"):
        pool = h.pool("disabled")
        data = pool.dataset("data")
        original = pool.write(data / "original", "feature-disabled", 16)
        pool.duplicate(original, data / "duplicate")
        pool.sync()
        pool.layout(0, 0)
        pool.verify()
        pool.export()
        pool.convert("--check", accepted=False)
        pool.convert("--convert", "--fenced", accepted=False)
        pool.convert("--convert", "--fenced", "--journal-only", accepted=False)
        pool.import_pool()
        require(pool.property("feature@fast_dedup") == "disabled", "Rejection enabled fast_dedup")
        pool.layout(0, 0)
        pool.verify()
        pool.scrub()
        pool.destroy()


def crash_recovery(h):
    with h.case("committed-batch-sigkill-normal-import-recovery"):
        pool = h.pool("crash-recovery")
        data = pool.dataset("blocks", recordsize="4K")
        original = pool.write(data / "original", "crash-recovery-unique-blocks", 8192, 4096)
        pool.duplicate(original, data / "duplicate")
        pool.sync()
        pool.layout(0, 0)
        pool.verify()
        pool.enable()
        pool.export()
        interrupt_converter(pool, signal.SIGKILL)
        labels = h.command("zdb", "-l", pool.devices / "mirror-0.img").stdout
        states = re.findall(r"^\s*state:\s*(\d+)\s*$", labels, re.MULTILINE)
        guids = re.findall(r"^\s*pool_guid:\s*(\d+)\s*$", labels, re.MULTILINE)
        require(states and set(states) == {"0"}, "SIGKILL fixture is not marked active on disk")
        require(guids and set(guids) == {pool.guid}, "Crash labels do not belong to the tracked test GUID")
        # Recover active labels through a normal same-host kernel import.
        pool.convert("--check", accepted=False)
        pool.convert("--convert", "--fenced", accepted=False)
        pool.import_pool()
        pool.layout(0, 0)
        directory = pool.zdb("-dddd", "1")
        require(re.search(r"^\s*org\.convert-ddt:staging\s*=", directory, re.MULTILINE),
                "SIGKILL did not retain the committed staging root")
        pool.verify()
        pool.scrub()
        pool.export()
        pool.convert("--check")
        pool.convert("--convert", "--fenced", "--batch-size", "256")
        pool.import_pool()
        pool.layout(1, 3)
        directory = pool.zdb("-dddd", "1")
        require(not re.search(r"^\s*org\.convert-ddt:staging\s*=", directory, re.MULTILINE),
                "Post-crash conversion did not reclaim staged objects")
        pool.verify()
        pool.scrub()
        pool.addref_free([(original, data / "post-crash-duplicate")])
        pool.destroy()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--converter", required=True, type=Path, help="Absolute built converter path")
    parser.add_argument("--work-dir", required=True, type=Path, help="Existing parent for disposable file pools")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("root is required to create disposable ZFS pools")
    if not args.converter.is_absolute() or not args.converter.is_file() or not os.access(args.converter, os.X_OK):
        parser.error("--converter must be an absolute executable file path")
    if not args.work_dir.is_dir():
        parser.error("--work-dir must name an existing directory")
    for executable in ("zpool", "zfs", "zdb"):
        if shutil.which(executable) is None:
            parser.error("required system executable not found: " + executable)
    h = Harness(args.converter.resolve(), args.work_dir.resolve())
    print("Evidence: " + str(h.evidence_path), flush=True)
    outcome = 1
    previous_handlers = {}

    def interrupted(signum, frame):
        raise KeyboardInterrupt("Harness received signal %d" % signum)

    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous_handlers[signum] = signal.signal(signum, interrupted)
        h.command("zfs", "version")
        disabled_feature(h)
        full_conversion(h)
        mixed_slots(h)
        interruption(h)
        crash_recovery(h)
        h.evidence["status"] = "passed"
        outcome = 0
    except BaseException as error:
        h.evidence.update(status="failed", error=str(error), traceback=traceback.format_exc())
        print("FAIL: " + str(error), file=sys.stderr, flush=True)
    finally:
        # Keep ownership-checked cleanup atomic with respect to further signals.
        for signum in previous_handlers:
            signal.signal(signum, signal.SIG_IGN)
        errors = h.cleanup()
        if errors:
            h.evidence["status"] = "failed"
            outcome = 1
            print("Cleanup failed; preserving owned pool files: " + "; ".join(errors), file=sys.stderr)
        h.evidence["finished"] = time.time()
        h.flush()
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
    print("%s; evidence: %s" % ("PASS" if outcome == 0 else "FAIL", h.evidence_path), flush=True)
    return outcome


if __name__ == "__main__":
    sys.exit(main())
