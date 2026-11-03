#!/usr/bin/env python3
"""Validate only an already exported, fenced, durably owned pool copy.

WORK_DIR/ownership.json is required unless --ownership-journal contains a
parallel_validation attestation. No pool, checkpoint, device or image is created
or retired here. Failed/interrupted runs preserve everything for the owner.
"""

import argparse
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import struct
import subprocess
import sys
import time
import traceback

GIB = 1024 ** 3
WORK_KEYS = ("entries", "bytes", "preload_plan_blocks", "preload_bytes", "tasks_completed",
             "samples_completed", "objects_examined", "bps_examined")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def atomic_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def private_json(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        value = os.fstat(descriptor)
        require(stat.S_ISREG(value.st_mode) and value.st_uid == 0 and
                value.st_nlink == 1 and not value.st_mode & 0o022,
                "Ownership evidence must be a root-owned non-writable regular file: " + str(path))
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read()
        return json.loads(raw), hashlib.sha256(raw).hexdigest()
    finally:
        os.close(descriptor)

def private_text(path):
    """Read retained native logs with the same ownership rules as JSON proof."""
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        value = os.fstat(descriptor)
        require(stat.S_ISREG(value.st_mode) and value.st_uid == 0 and
                value.st_nlink == 1 and not value.st_mode & 0o022,
                "Native evidence must be a root-owned non-writable regular file: " + str(path))
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read()
        return raw.decode("utf-8"), hashlib.sha256(raw).hexdigest()
    finally:
        os.close(descriptor)


def legacy_store_identity(data, *, baseline=False):
    """Compare only registered native metadata; this is not an entry census."""
    tables = data.get("tables")
    require(isinstance(tables, list) and tables, "Preflight resume requires registered legacy DDT tables")
    result, checksums, objects, total = [], set(), set(), 0
    for table in tables:
        require(isinstance(table, dict), "Invalid DDT table metadata")
        checksum = table.get("checksum")
        require(type(checksum) is int and checksum >= 0 and checksum not in checksums and
                type(table.get("version")) is int and table["version"] == 0 and
                type(table.get("flags")) is int and table["flags"] == 0,
                "Preflight resume refuses duplicate, nonlegacy or flagged DDT tables")
        checksums.add(checksum)
        stores = table.get("stores")
        require(isinstance(stores, list), "Missing registered DDT stores")
        classes, identities = set(), []
        for store in stores:
            require(isinstance(store, dict), "Invalid DDT store metadata")
            kind, class_ = store.get("type"), store.get("class")
            obj = store.get("object")
            count = store.get("native_zap_count" if baseline else "count")
            require(type(kind) is int and kind >= 0 and type(class_) is int and class_ >= 0 and
                    (kind, class_) not in classes and
                    isinstance(obj, str) and obj.isascii() and obj.isdecimal() and 0 < int(obj) < 2 ** 64 and
                    isinstance(count, str) and count.isascii() and count.isdecimal() and 0 <= int(count) < 2 ** 64,
                    "Invalid or duplicate registered DDT store identity/count")
            require(int(obj) not in objects, "Duplicate registered DDT object")
            classes.add((kind, class_))
            objects.add(int(obj))
            identities.append((kind, class_, int(obj), int(count)))
            total += int(count)
        result.append((checksum, tuple(sorted(identities))))
    require(total > 0, "Preflight resume refuses an empty legacy DDT")
    if baseline:
        require(data.get("full_flat_eligible") is True and str(total) == data.get("total_keys"),
                "Passed baseline lacks a complete full-flat-eligible native store census")
    return sorted(result)


def admit_preflight_metadata(description, baseline, pool_guid):
    require(description.get("format") == "convert-ddt-state-v1" and
            description.get("pool_guid") == pool_guid and description.get("exported") is True and
            description.get("staging_present") is False,
            "Current native metadata does not prove an exported unstaged pool")
    require(legacy_store_identity(description) == legacy_store_identity(baseline, baseline=True),
            "Current registered legacy DDT object identities/counts differ from passed baseline")


def admit_published_metadata(description, baseline, pool_guid):
    """Prove registered publication/counts without scanning DDT entries again."""
    expected = legacy_store_identity(baseline, baseline=True)
    require(isinstance(description, dict) and
            description.get("format") == "convert-ddt-state-v1" and
            description.get("pool_guid") == pool_guid and description.get("exported") is True and
            description.get("staging_present") is False,
            "Published metadata does not prove an exported unstaged pool")
    tables = description.get("tables")
    require(isinstance(tables, list) and tables, "Missing published DDT tables")
    registered, checksums, objects, stores = [], set(), set(), []
    old_objects = {store[2] for _, table in expected for store in table}
    for table in tables:
        require(isinstance(table, dict), "Invalid published DDT table")
        checksum = table.get("checksum")
        require(type(checksum) is int and checksum >= 0 and checksum not in checksums and
                type(table.get("version")) is int and table["version"] == 1 and
                type(table.get("flags")) is int and table["flags"] == 3,
                "Published DDT is not uniquely registered version-1 FLAT|LOG")
        checksums.add(checksum)
        require(isinstance(table.get("stores"), list), "Missing published DDT stores")
        classes, identities = set(), []
        for store in table["stores"]:
            require(isinstance(store, dict), "Invalid published DDT store")
            kind, class_, obj, count = (store.get(key) for key in ("type", "class", "object", "count"))
            require(type(kind) is int and kind >= 0 and type(class_) is int and class_ >= 0 and
                    (kind, class_) not in classes and
                    isinstance(obj, str) and obj.isascii() and obj.isdecimal() and 0 < int(obj) < 2 ** 64 and
                    isinstance(count, str) and count.isascii() and count.isdecimal() and 0 <= int(count) < 2 ** 64,
                    "Invalid or duplicate published DDT store identity/count")
            require(int(obj) not in objects and int(obj) not in old_objects,
                    "Published DDT object is duplicate or still a legacy object")
            objects.add(int(obj))
            classes.add((kind, class_))
            identities.append((kind, class_, int(count)))
            stores.append({"checksum": checksum, "type": kind, "class": class_,
                           "object": obj, "count": count})
        registered.append((checksum, tuple(sorted(identities))))
    expected_counts = [(checksum, tuple((kind, class_, count) for kind, class_, _, count in table))
                       for checksum, table in expected]
    require(sorted(registered) == expected_counts,
            "Published DDT checksum/type/class store counts differ from the original baseline")
    return {"status": "published_native_layout_counts_passed", "version": 1, "flags": 3,
            "total_entries": baseline["total_keys"], "stores": stores,
            "entry_census": False, "staging_present": False, "exported": True}


def admit_conversion_proof(progress, baseline):
    """Require native completion evidence for every nonempty original store."""
    legacy_store_identity(baseline, baseline=True)
    require(isinstance(progress, list) and all(isinstance(item, dict) for item in progress),
            "Missing native converter progress evidence")
    completed, expected = [], {}
    for table in baseline["tables"]:
        checksum_name = table.get("checksum_name")
        require(isinstance(checksum_name, str) and checksum_name,
                "Baseline lacks native checksum names for converter progress identity")
        for store in table["stores"]:
            count = int(store["native_zap_count"])
            key = (checksum_name, store["class"])
            require(key not in expected, "Ambiguous converter store identity")
            expected[key] = count
    for item in progress:
        phase = item.get("phase")
        require(phase in ("flat-preflight", "flat-copy", "flat-readback"),
                "Unknown converter native progress phase")
        key = (item.get("checksum"), item.get("class"))
        require(type(item.get("class")) is int and key in expected and
                type(item.get("entries")) is int and type(item.get("total_entries")) is int and
                0 <= item["entries"] <= item["total_entries"] == expected[key] and
                item.get("read_order") == "physical" and
                type(item.get("physical_blocks")) is int and
                type(item.get("total_physical_blocks")) is int and
                0 <= item["physical_blocks"] <= item["total_physical_blocks"] and
                (expected[key] == 0 or item["total_physical_blocks"] > 0),
                "Converter native progress store/count/physical identity differs")
    for (checksum, class_), count in expected.items():
        if not count:
            continue
        phases = {}
        for phase in ("flat-preflight", "flat-copy", "flat-readback"):
            matches = [item for item in progress if item["phase"] == phase and
                       item["checksum"] == checksum and item["class"] == class_]
            require(matches and matches[-1]["entries"] == count and
                    matches[-1]["physical_blocks"] == matches[-1]["total_physical_blocks"],
                    "Converter lacks complete " + phase + " evidence for " + checksum + "/" + str(class_))
            phases[phase] = matches[-1]
        completed.append({"checksum": checksum, "class": class_, "entries": count, "phases": phases})
    return {"total_entries": baseline["total_keys"], "stores": completed,
            "proof": "converter_full_preflight_copy_and_independent_staged_native_readback"}


def conversion_logs(command, directory, baseline):
    logs, hashes = {}, {}
    for stream in ("stdout", "stderr"):
        path = directory / ("converter-convert." + stream)
        require(command.get(stream) == str(path), "Converter native log path differs")
        logs[stream], hashes[stream + "_sha256"] = private_text(path)
    require("pool cleanly exported" in logs["stdout"].splitlines(),
            "Converter did not acknowledge a clean exported copy")
    progress = []
    for line in logs["stderr"].splitlines():
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict) and "phase" in item:
            require(item["phase"] in ("flat-preflight", "flat-copy", "flat-readback",
                                     "stage-reclaim"), "Unknown converter native progress phase")
            if item["phase"] != "stage-reclaim":
                progress.append(item)
    proof = admit_conversion_proof(progress, baseline)
    copied = {}
    for checksum, class_, entries, total in re.findall(
            r"copied batch (\S+) class=(\d+) entries=(\d+)/(\d+)", logs["stdout"]):
        key = (checksum, int(class_))
        copied[key] = (int(entries), int(total))
    for store in proof["stores"]:
        key = (store["checksum"], store["class"])
        if key in copied:
            require(copied[key] == (store["entries"], store["entries"]),
                    "Converter copied-batch evidence disagrees with native store counts")
    proof.update(hashes, copied_counts=[{"checksum": key[0], "class": key[1],
                                       "entries": value[0], "total_entries": value[1]}
                                      for key, value in sorted(copied.items())])
    return proof


def device_identity(path):
    value = path.stat()
    if stat.S_ISBLK(value.st_mode):
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            require(os.fstat(descriptor).st_rdev == value.st_rdev, "Device changed while opening")
            size = struct.unpack("Q", fcntl.ioctl(descriptor, 0x80081272, bytes(8)))[0]
        finally:
            os.close(descriptor)
    else:
        require(stat.S_ISREG(value.st_mode), "Owned device is not a block device or regular file")
        size = value.st_size
    return [value.st_dev, value.st_ino, value.st_rdev, size]


def process_sample(pid):
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        if fields[0] in ("Z", "X") or int(fields[6]) & 0x4:  # Linux PF_EXITING.
            return None
        io = {}
        for line in Path(f"/proc/{pid}/io").read_text().splitlines():
            key, value = line.split(":", 1)
            io[key] = int(value)
        return {"starttime": fields[19], "state": fields[0],
                "cpu_seconds": (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK"),
                "read_bytes": io.get("read_bytes", 0), "write_bytes": io.get("write_bytes", 0),
                "read_chars": io.get("rchar", 0), "read_calls": io.get("syscr", 0),
                "wchan": Path(f"/proc/{pid}/wchan").read_text().strip()}
    except (FileNotFoundError, ProcessLookupError):
        return None
    except PermissionError:
        # Denied statistics may race exit; never hide access loss to a live PID.
        try:
            fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        except (FileNotFoundError, ProcessLookupError):
            return None
        if fields[0] in ("Z", "X") or int(fields[6]) & 0x4:
            return None
        raise


class Child:
    def __init__(self, runner, name, argv, persistent=False):
        self.runner = runner
        self.name = name
        self.started = time.monotonic()
        self.last_work = self.started
        self.made_work = False
        self.previous_sample = None
        self.work = {}
        self.native_work = {}
        self.parts = [b"", b""]
        self.offsets = [0, 0]
        self.persistent = persistent
        self.paths = [runner.root / (name + suffix) for suffix in (".stdout", ".stderr")]
        self.record = {"name": name, "argv": [str(arg) for arg in argv],
                       "started": time.time(), "status": "starting",
                       "stdout": str(self.paths[0]), "stderr": str(self.paths[1])}
        runner.report["commands"].append(self.record)
        runner.save()
        self.process = None
        try:
            with self.paths[0].open("xb", buffering=0) as out, self.paths[1].open("xb", buffering=0) as err:
                self.process = subprocess.Popen(self.record["argv"], stdin=subprocess.PIPE if persistent else subprocess.DEVNULL,
                                                stdout=out, stderr=err, start_new_session=True,
                                                env={**os.environ, "LC_ALL": "C"})
            runner.children.append(self)
            sample = process_sample(self.process.pid)
            self.identity = sample["starttime"] if sample else None
            self.record.update(pid=self.process.pid, starttime=self.identity, status="running")
        except BaseException as error:
            self.record.update(status="startup_failed", error=str(error))
            raise
        finally:
            runner.save()

    def consume(self):
        changed = False
        for index, path in enumerate(self.paths):
            with path.open("rb") as stream:
                stream.seek(self.offsets[index])
                raw = stream.read(1024 * 1024)
            self.offsets[index] += len(raw)
            lines = re.split(b"[\r\n]", self.parts[index] + raw)
            self.parts[index] = lines.pop()[-65536:]
            for raw_line in lines:
                line = raw_line.decode("utf-8", errors="replace").strip()
                try:
                    item = json.loads(line)
                except (ValueError, TypeError):
                    item = None
                if isinstance(item, dict):
                    if "phase" in item:
                        self.record["native_progress"] = item
                    if item.get("phase") == "ddt-preload-plan":
                        # Preserve verified metadata work after the warm/census phases begin.
                        self.record["native_preload_plan_progress"] = item
                    if item.get("phase") == "ddt-preload":
                        # Retain completion even if preload ends between heartbeats.
                        self.record["native_preload_progress"] = item
                    context = tuple(value if isinstance(value, (str, int)) and not isinstance(value, bool) else None
                                    for value in (item.get("phase"), item.get("checksum"),
                                                  item.get("class"), item.get("object")))
                    for key in WORK_KEYS:
                        value = item.get(key)
                        if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value):
                            counter = (context, key)
                            changed |= value > self.native_work.get(counter, 0)
                            self.native_work[counter] = max(value, self.native_work.get(counter, 0))
                            self.work[key] = max(value, self.work.get(key, 0))
                    if "observer_txg" in item:
                        self.record["observer_txg"] = item["observer_txg"]
                        self.record["observer_sequence"] = item.get("sequence")
                match = re.search(r"copied batch (\S+) class=(\d+) entries=(\d+)/(\d+)", line)
                if match:
                    key = "copied_" + match[1] + "_" + match[2]
                    value = int(match[3])
                    changed |= value > self.work.get(key, 0)
                    self.work[key] = value
        return changed

    def tick(self, enforce=True):
        changed = self.consume()
        sample = process_sample(self.process.pid)
        now = time.monotonic()
        if sample:
            require(self.identity is None or sample["starttime"] == self.identity,
                    f"Child PID identity changed: {self.process.pid}")
            self.identity = sample["starttime"]
            previous = self.previous_sample
            if previous:
                # Diagnostic log writes and CPU/heartbeats are not data work.
                changed |= any(sample[key] > previous[key] for key in
                               ("read_bytes", "read_chars"))
                interval = max(0.001, now - self.sampled_at)
                self.record["cpu_cores"] = (sample["cpu_seconds"] - previous["cpu_seconds"]) / interval
                self.record["read_bytes_per_second"] = (sample["read_bytes"] - previous["read_bytes"]) / interval
                self.record["write_bytes_per_second"] = (sample["write_bytes"] - previous["write_bytes"]) / interval
            self.previous_sample = sample
            self.sampled_at = now
            self.record["proc"] = sample
        if changed:
            self.last_work = now
            self.made_work = True
        self.record.update(work=self.work, elapsed_seconds=now - self.started,
                           no_work_seconds=now - self.last_work)
        code = self.process.poll()
        if code is not None:
            self.record.update(returncode=code, status="passed" if code == 0 else "failed", finished=time.time())
            if enforce:
                require(code == 0, f"{self.name} exited {code}; see {self.paths[1]}")
            return True
        if enforce:
            require(self.made_work or now - self.started < self.runner.args.startup_timeout,
                    f"{self.name} produced no measured startup work; PID {self.process.pid}")
            require(now - self.started < self.runner.args.stage_timeout,
                    f"{self.name} exceeded stage deadline; PID {self.process.pid}")
            require(now - self.last_work < self.runner.args.stall_timeout,
                    f"{self.name} made no measured work for {now - self.last_work:.0f}s; PID {self.process.pid}")
        return False

    def stop(self):
        if self.process.poll() is not None:
            return
        for signum, grace in ((signal.SIGTERM, 5), (signal.SIGKILL, 5)):
            sample = process_sample(self.process.pid)
            if sample is not None:
                require(sample["starttime"] == self.identity, "Refusing signal to reused child PID")
            try:
                os.killpg(self.process.pid, signum)
            except ProcessLookupError:
                self.tick(enforce=False)
                return
            self.record["termination"] = signal.Signals(signum).name
            deadline = time.monotonic() + grace
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    self.tick(enforce=False)
                    return
                time.sleep(0.1)
        sample = process_sample(self.process.pid)
        self.record.update(status="blocked_preserve", blocking_pid=self.process.pid, proc=sample)
        self.runner.report["blocking_pids"].append({"pid": self.process.pid, "starttime": self.identity,
                                                     "name": self.name, "proc": sample})
        # Never call wait() without a deadline, including for unkillable D-state tasks.


class Runner:
    def __init__(self, args):
        self.args = args
        self.children = []
        self.locks = []
        self.observer = None
        self.observer_sequence = 0
        self.started = time.monotonic()
        self.work_dir = args.work_dir.resolve(strict=True)
        self.search_dir = args.search_dir.resolve(strict=True)
        self.journal_path = args.ownership_journal.resolve(strict=True) if args.ownership_journal else None
        self.journal = None
        self.journal_hash = None
        if self.journal_path:
            self.journal, self.journal_hash = private_json(self.journal_path)
        manifest = self.work_dir / "ownership.json"
        if manifest.exists():
            self.manifest_path = manifest
            self.ownership, self.ownership_hash = private_json(manifest)
            require(self.ownership.get("format") == "parallel-actual-ownership-v1", "Unsupported ownership manifest")
        else:
            require(self.journal is not None, "WORK_DIR/ownership.json or an attested ownership journal is required")
            self.manifest_path = self.journal_path
            self.ownership = self.journal.get("parallel_validation", {})
            self.ownership_hash = self.journal_hash
        self.pool_name = self.ownership.get("name")
        require(isinstance(self.pool_name, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:-]*", self.pool_name),
                "Manifest must identify the copy pool name")
        require(self.ownership.get("pool_guid") == args.pool_guid and
                self.ownership.get("exported") is True and self.ownership.get("fenced") is True,
                "Durable ownership does not attest the requested exported, fenced copy")
        source_guid = self.ownership.get("source_guid")
        require(isinstance(source_guid, str) and source_guid.isdecimal() and
                0 < int(source_guid) < 2 ** 64 and source_guid != args.pool_guid,
                "Owned copy must have a nonzero GUID distinct from its source")
        require(Path(self.ownership.get("search_dir", "")).resolve() == self.search_dir,
                "Search directory differs from durable ownership")
        self.root = Path(__import__("tempfile").mkdtemp(prefix="parallel-actual-", dir=self.work_dir))
        os.chmod(self.root, 0o700)
        self.report_path = self.root / "report.json"
        self.progress_path = self.root / "progress.jsonl"
        self.progress_stream = self.progress_path.open("x", buffering=1)
        self.report = {"format": "parallel-actual-validation-v1", "complete": False,
                       "status": "running", "pool_guid": args.pool_guid, "source_guid": source_guid,
                       "pool_name": self.pool_name, "started": time.time(),
                       "sample_target": args.sample_count,
                       "ownership": str(self.manifest_path), "ownership_sha256": self.ownership_hash,
                       "ownership_journal": str(self.journal_path) if self.journal_path else None,
                       "ownership_journal_sha256": self.journal_hash,
                       "resources_preserved": True, "blocking_pids": [], "commands": [], "phases": [],
                       "coverage": {"full_ddt": "not_run", "content": "not_run",
                                    "metadata": "not_requested_conversion_scope",
                                    "published_layout": "not_run",
                                    "whole_userdata_checksum_scan": False,
                                    "source_observer": "required" if self.journal else "not_requested"}}
        self.report["progress_log"] = str(self.progress_path)
        self.save()
        print("Evidence: " + str(self.report_path), flush=True)

    def save(self):
        atomic_json(self.report_path, self.report)

    def lock(self, path, shared=False, create=True):
        flags = os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW
        descriptor = os.open(path, flags | (os.O_CREAT if create else 0), 0o600)
        value = os.fstat(descriptor)
        require(stat.S_ISREG(value.st_mode) and value.st_uid == 0 and value.st_nlink == 1 and
                not value.st_mode & 0o022, "Unsafe ownership lock: " + str(path))
        try:
            fcntl.flock(descriptor, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
        except BaseException:
            os.close(descriptor)
            raise
        self.locks.append(descriptor)
        return descriptor

    def assert_devices(self):
        _, digest = private_json(self.manifest_path)
        require(digest == self.ownership_hash, "Durable ownership changed during validation")
        devices = self.ownership.get("devices")
        require(isinstance(devices, list) and devices, "No owned device identities supplied")
        expected = {}
        for item in devices:
            path = Path(item["path"])
            require(path.is_absolute() and path.resolve(strict=True) == path,
                    "Owned device paths must be absolute canonical paths")
            identity = device_identity(path)
            require(identity == item.get("identity"), "Owned device identity changed: " + str(path))
            require(str(path) not in expected, "Repeated owned device")
            expected[str(path)] = identity
            if stat.S_ISBLK(path.stat().st_mode):
                holders = Path("/sys/dev/block") / f"{os.major(identity[2])}:{os.minor(identity[2])}" / "holders"
                require(holders.is_dir() and not list(holders.iterdir()), "Owned device has unexpected holders")
        entries = list(self.search_dir.iterdir())
        require(entries and all(path.is_symlink() or path.is_file() or path.is_block_device() for path in entries),
                "Search directory must contain only the exclusive owned leaf set")
        found = [str(path.resolve(strict=True)) for path in entries]
        require(len(found) == len(expected) and set(found) == set(expected),
                "Search directory contains missing, duplicate or unowned devices")
        require(not (Path("/proc/spl/kstat/zfs") / self.pool_name).exists(),
                "Copy is still kernel-imported; parent must recover/export it first")
        require(not any(self.pool_name in line and " - zfs " in line
                        for line in Path("/proc/self/mountinfo").read_text().splitlines()),
                "Copy has kernel mounts; refusing validation")
        for directory in Path("/proc").iterdir():
            if not directory.name.isdecimal():
                continue
            try:
                fields = (directory / "stat").read_text().rsplit(")", 1)[1].split()
                if fields[0] != "D":
                    continue
                command = (directory / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                continue
            if "zpool" in command or self.pool_name in command or self.args.pool_guid in command:
                self.report["blocking_pids"].append({"pid": int(directory.name), "owned": False,
                                                     "command": command, "state": "D"})
                raise RuntimeError("Blocked pool administrator/reader already exists: PID " + directory.name + " " + command)
        if self.journal:
            self.assert_journal()

    def assert_journal(self):
        _, digest = private_json(self.journal_path)
        require(digest == self.journal_hash, "Original ownership journal changed")
        source = self.journal["source"]
        require(source["guid"] == self.ownership["source_guid"] and source["name"] != self.pool_name,
                "Actual journal source differs from ownership")
        copies = [item for item in self.journal["pools"] if item.get("guid") == self.args.pool_guid]
        require(len(copies) == 1 and copies[0].get("name") == self.pool_name and copies[0].get("imported") is False,
                "Actual journal does not establish an exported owned copy")
        preparation = self.journal.get("clone_preparation", {})
        require(preparation.get("clone_guid") == self.args.pool_guid and preparation.get("ownership_uncertain") is False,
                "Actual copy ownership is uncertain")
        require({str(Path(overlay["device"]).resolve()) for overlay in self.journal["overlays"]} ==
                {item["path"] for item in self.ownership["devices"]},
                "Actual journal NBDs differ from the exclusive owned device set")
        for overlay in self.journal["overlays"]:
            image = Path(overlay["image"])
            value = image.lstat()
            require(stat.S_ISREG(value.st_mode) and value.st_uid == 0 and value.st_nlink == 1 and
                    [value.st_dev, value.st_ino] == overlay.get("image_identity"), "Overlay image identity changed")
            backing = Path(overlay["backing"]).resolve(strict=True)
            require(device_identity(backing) == overlay["backing_identity"], "Source backing identity changed")
            device = Path(overlay["device"])
            require(overlay.get("attached") and device.stat().st_rdev == overlay["device_number"],
                    "Owned NBD attachment changed")
            pid = overlay["qemu_pid"]
            sample = process_sample(pid)
            require(sample and sample["starttime"] == overlay["qemu_starttime"] and sample["state"] != "Z",
                    "Owned qemu reader is no longer live")
            nbd = Path("/sys/class/block") / device.name
            thread = int((nbd / "pid").read_text().strip())
            status = Path(f"/proc/{thread}/status").read_text()
            require(re.search(r"^Tgid:\s*" + str(pid) + r"\s*$", status, re.MULTILINE),
                    "NBD is no longer connected to its owned qemu process")
            require(int((nbd / "size").read_text()) * 512 == overlay["virtual_bytes"], "NBD capacity changed")
            found_backing = found_image = False
            for descriptor in Path(f"/proc/{pid}/fd").iterdir():
                try:
                    target = descriptor.resolve(strict=True)
                    if target not in (backing, image):
                        continue
                    flags = Path(f"/proc/{pid}/fdinfo/{descriptor.name}").read_text()
                except FileNotFoundError:
                    continue
                match = re.search(r"^flags:\s*([0-7]+)$", flags, re.MULTILINE)
                require(match is not None, "Cannot verify qemu descriptor access")
                if target == backing:
                    require(int(match[1], 8) & os.O_ACCMODE == os.O_RDONLY, "Qemu source backing is writable")
                    found_backing = True
                if target == image:
                    found_image = True
            require(found_backing and found_image, "Qemu does not hold both exact owned image and read-only backing")

    def initialize_locks(self):
        self.lock(Path("/run/lock") / ("parallel-actual-" + self.args.pool_guid + ".lock"))
        if self.journal:
            lease_path = Path(self.journal["resources"]["source_lease"])
            require(lease_path == Path("/run/lock") / ("convert-ddt-actual-" + self.ownership["source_guid"] + ".lock"),
                    "Unexpected source ownership lease")
            descriptor = self.lock(lease_path, create=False)
            raw = os.pread(descriptor, 65536, 0)
            lease = json.loads(raw)
            require(lease.get("source_guid") == self.ownership["source_guid"] and
                    Path(lease.get("journal", "")).resolve() == self.journal_path,
                    "Source lease points to another journal")
            for overlay in self.journal["overlays"]:
                self.lock(Path("/run/lock") / ("convert-ddt-" + Path(overlay["device"]).name + ".lock"), create=False)
        self.assert_devices()

    def heartbeat(self, phase, children):
        rows = []
        for child in children:
            record = child.record
            native = record.get("native_progress", {})
            copied = sum(value for key, value in child.work.items() if key.startswith("copied_"))
            copied_total = self.report.get("ddt_reports", {}).get("before", {}).get("total_keys")
            if isinstance(copied_total, str) and copied_total.isdecimal():
                copied_total = int(copied_total)
            copy_rate = copied / max(0.001, record.get("elapsed_seconds", 0))
            eta = native.get("eta_seconds")
            if eta is None and copied and isinstance(copied_total, int):
                eta = max(0, copied_total - copied) / copy_rate
            rows.append({"name": child.name, "pid": child.process.pid, "status": record["status"],
                         "cpu_cores": round(record.get("cpu_cores", 0), 2),
                         "read_MiB_s": round(record.get("read_bytes_per_second", 0) / 1024 ** 2, 2),
                         "write_MiB_s": round(record.get("write_bytes_per_second", 0) / 1024 ** 2, 2),
                         "work": child.work, "native": native,
                         "native_preload_plan": record.get("native_preload_plan_progress", {}),
                         "native_preload": record.get("native_preload_progress", {}),
                         "entry_eta_seconds": eta,
                         "no_work_seconds": round(record.get("no_work_seconds", 0), 1),
                         "state": record.get("proc", {}).get("state"),
                         "average_work_per_second": {
                             key: round(value / max(0.001, record.get("elapsed_seconds", 0)), 2)
                             for key, value in child.work.items()}})
        event = {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                 "phase": phase, "elapsed_seconds": round(time.monotonic() - self.started, 1),
                 "children": rows}
        line = json.dumps(event, allow_nan=False)
        self.progress_stream.write(line + "\n")
        self.progress_stream.flush()
        print(line, file=sys.stderr, flush=True)
        self.save()

    def supervise(self, phase, children, predicate=None, timeout=None):
        deadline = time.monotonic() + (timeout or self.args.stage_timeout)
        last_print = 0
        while True:
            completed = [child.tick() for child in children]
            if predicate is not None:
                if predicate():
                    return
                require(not any(completed), phase + " child exited before acknowledgment")
            elif all(completed):
                self.heartbeat(phase, children)
                return
            require(time.monotonic() < deadline, phase + " deadline exceeded")
            if time.monotonic() - last_print >= 1:
                self.heartbeat(phase, children)
                last_print = time.monotonic()
            time.sleep(0.2)

    def run(self, phase, commands):
        record = {"phase": phase, "started": time.time(), "complete": False}
        self.report["phases"].append(record)
        self.save()
        children = []
        for name, argv in commands:
            children.append(Child(self, name, argv))
        self.supervise(phase, children)
        record.update(complete=True, finished=time.time())
        self.save()
        return children

    def boundary(self, phase):
        self.assert_devices()
        if not self.journal:
            return
        source = self.journal["source"]
        checkpoint_record = self.journal["checkpoint"]
        checkpoint = checkpoint_record.get("identity", checkpoint_record)
        require(isinstance(checkpoint.get("txg"), int) and isinstance(checkpoint.get("start_time"), int),
                "Durable checkpoint TXG/start_time are required")
        if self.observer is None:
            self.observer = Child(self, "checkpoint-observer", [sys.executable, str(Path(__file__).resolve()),
                                  "--checkpoint-observer", source["name"], source["guid"]], persistent=True)
        self.observer_sequence += 1
        self.observer.started = self.observer.last_work = time.monotonic()
        self.observer.process.stdin.write((str(self.observer_sequence) + "\n").encode())
        self.observer.process.stdin.flush()
        self.supervise("checkpoint-" + phase, [self.observer],
                       predicate=lambda: self.observer.record.get("observer_sequence") == self.observer_sequence,
                       timeout=self.args.startup_timeout)
        require(self.observer.record.get("observer_txg") == checkpoint["txg"], "Owned source checkpoint TXG changed")
        child = self.run("source-status-" + phase, [("source-status-" + phase,
                         ["zpool", "status", "-P", "-p", "-i", "-t", "-j", "--json-int", source["name"]])])[0]
        data = json.loads(child.paths[0].read_text())
        pools = data.get("pools", {})
        require(len(pools) == 1 and source["name"] in pools, "Cannot identify exact source pool")
        pool = pools[source["name"]]
        current = pool.get("checkpoint_stats", {})
        require(str(pool.get("pool_guid")) == source["guid"] and current.get("state") == "EXISTS" and
                current.get("start_time") == checkpoint["start_time"] and
                (not current.get("txg") or current["txg"] == checkpoint["txg"]),
                "Source GUID/checkpoint ownership changed")
        self.assert_devices()
        self.report["coverage"]["source_observer"] = "checkpoint_guid_start_time_and_contiguous_kernel_history_verified"

    def native_command(self, executable, workers, output, expect=None, *, ddt=False):
        arc_max = self.args.arc_max_bytes // 2
        if self.args.ddt_arc_max_bytes is not None:
            arc_max = self.args.ddt_arc_max_bytes if ddt else self.args.arc_max_bytes - self.args.ddt_arc_max_bytes
        argv = [executable, "--pool-guid", self.args.pool_guid, "--search-dir", self.search_dir,
                "--workers", str(workers), "--arc-max-bytes", str(arc_max),
                "--output", self.root / output]
        if ddt and self.args.ddt_preload:
            argv.append("--preload")
        if not ddt:
            argv.extend(["--sample-count", str(self.args.sample_count)])
        if expect:
            argv.extend(["--expect", self.root / expect])
        return argv

    def native_report(self, path, format_name):
        data = json.loads((self.root / path).read_text())
        require(data.get("format") == format_name and data.get("complete") is True and
                data.get("pool_guid") == self.args.pool_guid, "Native report is missing, incomplete or wrong-pool: " + path)
        if format_name == "validate-content-v2":
            self.admit_content(data)
        return data

    def admit_content(self, data):
        target = str(self.args.sample_count)
        require(data.get("format") == "validate-content-v2" and
                data.get("complete") is True and data.get("pool_guid") == self.args.pool_guid and
                data.get("sample_target") == data.get("sample_count") == target,
                "Content evidence requires complete v2 with the exact requested sample target/count")
        views = data.get("views")
        require(isinstance(views, list) and all(isinstance(view, dict) and
                isinstance(view.get("samples"), list) for view in views),
                "Content evidence lacks native per-view samples")
        samples = [sample for view in views for sample in view["samples"]]
        require(len(samples) == self.args.sample_count and
                all(isinstance(sample, dict) and isinstance(sample.get("bp"), dict) and
                    sample["bp"].get("dedup") is True and
                    isinstance(sample["bp"].get("words"), list) and len(sample["bp"]["words"]) == 16
                    for sample in samples),
                "Content evidence lacks the exact number of actual dedup-backed ranges")

    def admit_sample_target(self, previous):
        require(type(previous.get("sample_target")) is int and
                previous["sample_target"] == self.args.sample_count,
                "Resume sample target differs or predates the v2 content contract")

    def resume_images(self, baseline_started_ns):
        require(self.journal is not None,
                "--resume-baseline requires --ownership-journal and its actual COW/backing attestations")
        overlays = self.journal.get("overlays")
        require(isinstance(overlays, list) and overlays, "Resume requires attested actual COW images")
        images = []
        for overlay in overlays:
            image = Path(overlay["image"])
            require(image.is_absolute() and image.resolve(strict=True) == image,
                    "Resume image path is not canonical: " + str(image))
            value = image.lstat()
            require(stat.S_ISREG(value.st_mode) and value.st_uid == 0 and value.st_nlink == 1 and
                    not value.st_mode & 0o022 and
                    [value.st_dev, value.st_ino] == overlay.get("image_identity"),
                    "Resume image lacks its original private inode attestation: " + str(image))
            require(value.st_mtime_ns <= baseline_started_ns and value.st_ctime_ns <= baseline_started_ns,
                    "Cannot reuse baseline: image mtime_ns/ctime_ns postdates before-DDT start: " + str(image))
            images.append({"path": str(image), "identity": [value.st_dev, value.st_ino],
                           "mtime_ns": value.st_mtime_ns, "ctime_ns": value.st_ctime_ns,
                           "backing": overlay["backing"], "backing_identity": overlay["backing_identity"]})
        return images

    def resume_baseline(self):
        require(self.journal is not None,
                "--resume-baseline requires --ownership-journal; file-only ownership cannot prove an unchanged copy")
        path = self.args.resume_baseline.absolute()
        require(path.resolve(strict=True) == path, "Resume report path must not traverse symlinks")
        directory = path.parent.lstat()
        require(stat.S_ISDIR(directory.st_mode) and directory.st_uid == 0 and not directory.st_mode & 0o077,
                "Resume evidence directory must be private and root-owned")
        previous, digest = private_json(path)
        require(previous.get("format") == "parallel-actual-validation-v1" and
                previous.get("complete") is False and previous.get("status") == "failed" and
                previous.get("resources_preserved") is True,
                "Resume requires a failed, resource-preserving read-only qualification report")
        require(previous.get("pool_guid") == self.args.pool_guid and
                previous.get("source_guid") == self.ownership["source_guid"] and
                previous.get("pool_name") == self.pool_name and
                previous.get("ownership_sha256") == self.ownership_hash,
                "Resume copy/source GUID or durable ownership manifest hash differs")
        require(previous.get("ownership_journal") == str(self.journal_path),
                "Resume requires the same attested source ownership journal")
        require(previous.get("ownership_journal_sha256") in (None, self.journal_hash),
                "Resume source ownership journal hash differs")
        self.admit_sample_target(previous)
        phases = previous.get("phases")
        require(isinstance(phases, list), "Resume report has no phase evidence")
        allowed_phases = {"before-parallel", "converter-check", "source-status-before",
                          "source-status-before-converter-check", "source-status-before-converter-convert"}
        require(all(isinstance(phase, dict) and phase.get("phase") in allowed_phases for phase in phases),
                "Resume refused: previous report contains conversion, after, writer or unknown phases")
        before_phases = [phase for phase in phases if phase["phase"] == "before-parallel"]
        require(len(before_phases) == 1 and before_phases[0].get("complete") is True,
                "Resume requires one fully completed before-parallel phase")
        commands = previous.get("commands")
        require(isinstance(commands, list) and commands, "Resume report has no command evidence")
        allowed_commands = allowed_phases - {"before-parallel"} | {"before-ddt", "before-content", "checkpoint-observer"}
        for command in commands:
            require(isinstance(command, dict) and command.get("name") in allowed_commands,
                    "Resume refused: previous report contains conversion, after, writer or unknown commands")
            argv = command.get("argv")
            require(isinstance(argv, list) and argv and all(isinstance(arg, str) for arg in argv) and
                    not any(arg in ("--convert", "--rebuild", "--fenced", "--expect") or
                            arg.startswith(("--convert=", "--rebuild=", "--fenced=", "--expect=")) for arg in argv),
                    "Resume refused: previous command is not a baseline read-only command")
            name = command["name"]
            if name == "converter-check":
                require(len(argv) > 1 and argv[1] == "--check",
                        "Resume converter command was not an explicit read-only --check")
            elif name.startswith("source-status-"):
                require(argv == ["zpool", "status", "-P", "-p", "-i", "-t", "-j", "--json-int",
                                 self.journal["source"]["name"]],
                        "Resume source command was not an exact read-only status query")
            elif name == "checkpoint-observer":
                require(len(argv) == 5 and argv[2:] == ["--checkpoint-observer",
                        self.journal["source"]["name"], self.ownership["source_guid"]],
                        "Resume source observer identity differs")
            pid, starttime = command.get("pid"), command.get("starttime")
            require(isinstance(pid, int) and pid > 0 and isinstance(starttime, str) and starttime.isdecimal(),
                    "Resume cannot prove previous command PID/starttime identity: " + name)
            sample = process_sample(pid)
            require(sample is None or sample["starttime"] != starttime,
                    "Resume refused: previous command PID is still present: " + str(pid) + " " + name)
        baseline_commands = {}
        for name in ("before-ddt", "before-content"):
            matches = [command for command in commands if command["name"] == name]
            require(len(matches) == 1 and matches[0].get("status") == "passed" and
                    matches[0].get("returncode") == 0,
                    "Resume requires a passed native baseline command: " + name)
            command = matches[0]
            expected = {"--pool-guid": self.args.pool_guid, "--search-dir": str(self.search_dir),
                        "--output": str(path.parent / (name + ".json"))}
            if name == "before-content":
                expected["--sample-count"] = str(self.args.sample_count)
            for flag, value in expected.items():
                require(command["argv"].count(flag) == 1 and
                        command["argv"].index(flag) + 1 < len(command["argv"]) and
                        command["argv"][command["argv"].index(flag) + 1] == value,
                        "Resume baseline command identity/output differs: " + name + " " + flag)
            baseline_commands[name] = command
        started = baseline_commands["before-ddt"].get("started")
        require(isinstance(started, (int, float)) and not isinstance(started, bool) and
                math.isfinite(started) and started > 0,
                "Resume before-DDT command has no trustworthy start timestamp")
        started_ns = int(started * 1_000_000_000)
        images = self.resume_images(started_ns)
        files = {}
        for name, format_name in (("before-ddt", "validate-ddt-v1"), ("before-content", "validate-content-v2")):
            source = path.parent / (name + ".json")
            data, file_digest = private_json(source)
            require(data.get("format") == format_name and data.get("complete") is True and
                    data.get("pool_guid") == self.args.pool_guid,
                    "Resume native report is incomplete or wrong-pool: " + str(source))
            if name == "before-content":
                self.admit_content(data)
            if name == "before-ddt":
                require(data.get("full_flat_eligible") is True and
                        any(table.get("version") == 0 and table.get("flags") == 0
                            for table in data.get("tables", [])),
                        "Resume requires a complete, full-flat-eligible legacy DDT census")
            atomic_json(self.root / source.name, data)
            files[name] = {"source": str(source), "sha256": file_digest, "copy": source.name}
        atomic_json(self.root / "baseline-source-report.json", previous)
        self.report["baseline_resume"] = {
            "previous_report": str(path), "previous_report_sha256": digest,
            "previous_report_copy": "baseline-source-report.json", "files": files,
            "before_phase": before_phases[0], "before_commands": baseline_commands,
            "before_ddt_started_ns": started_ns, "unchanged_images": images,
            "journal_sha256_at_resume": self.journal_hash,
            "previous_journal_sha256_recorded": previous.get("ownership_journal_sha256") is not None,
            "proof": "original_image_inode_and_mtime_ctime_not_later_than_before_ddt_start"}
        self.report["phases"].append({"phase": "before-parallel", "complete": True, "reused": True,
                                     "started": before_phases[0].get("started"),
                                     "finished": before_phases[0].get("finished")})
        self.save()

    def preflight_report(self, path, *, interrupted):
        require(path.is_absolute() and path.resolve(strict=True) == path,
                "Preflight resume evidence path must be canonical")
        directory = path.parent.lstat()
        require(stat.S_ISDIR(directory.st_mode) and directory.st_uid == 0 and not directory.st_mode & 0o077,
                "Preflight resume evidence directory must be private and root-owned")
        previous, digest = private_json(path)
        require(previous.get("format") == "parallel-actual-validation-v1" and
                previous.get("complete") is False and previous.get("status") == "failed" and
                previous.get("resources_preserved") is True and not previous.get("blocking_pids"),
                "Preflight resume requires a failed resource-preserving report without blocked children")
        require(previous.get("pool_guid") == self.args.pool_guid and
                previous.get("source_guid") == self.ownership["source_guid"] and
                previous.get("pool_name") == self.pool_name and
                previous.get("ownership_sha256") == self.ownership_hash and
                previous.get("ownership_journal") == str(self.journal_path) and
                previous.get("ownership_journal_sha256") in (None, self.journal_hash),
                "Preflight resume copy/source ownership or journal identity differs")
        self.admit_sample_target(previous)
        allowed = {"before-parallel", "converter-check", "source-status-before",
                   "source-status-before-converter-check", "source-status-before-converter-convert"}
        if interrupted:
            allowed |= {"converter-convert", "preflight-describe",
                        "source-status-before-preflight-describe", "source-status-after-preflight-describe"}
        phases = previous.get("phases")
        require(isinstance(phases, list) and all(
            isinstance(item, dict) and item.get("phase") in allowed for item in phases),
            "Preflight resume refuses copy, after-validation, writer or unknown runner phases")
        before = [item for item in phases if item["phase"] == "before-parallel"]
        require(len(before) == 1 and before[0].get("complete") is True,
                "Preflight resume needs exactly one completed before phase")
        convert_phases = [item for item in phases if item["phase"] == "converter-convert"]
        require((len(convert_phases) == 1 and convert_phases[0].get("complete") is False) if interrupted
                else not convert_phases, "Preflight resume requires one interrupted converter phase")
        commands = previous.get("commands")
        require(isinstance(commands, list) and commands, "Missing preflight resume command provenance")
        allowed_commands = allowed - {"before-parallel"} | {"before-ddt", "before-content", "checkpoint-observer"}
        converters = []
        log_proof = None
        for command in commands:
            require(isinstance(command, dict) and command.get("name") in allowed_commands,
                    "Preflight resume refuses writer or unknown commands")
            name, argv = command["name"], command.get("argv")
            require(isinstance(argv, list) and argv and all(isinstance(arg, str) for arg in argv),
                    "Malformed preflight resume command")
            pid, starttime = command.get("pid"), command.get("starttime")
            require(type(pid) is int and pid > 0 and isinstance(starttime, str) and starttime.isdecimal(),
                    "Preflight resume cannot identify a previous child PID")
            sample = process_sample(pid)
            require(sample is None or sample["starttime"] != starttime,
                    "Preflight resume previous child is still live: " + name)
            if name.startswith("source-status-"):
                require(argv == ["zpool", "status", "-P", "-p", "-i", "-t", "-j", "--json-int",
                                 self.journal["source"]["name"]], "Unknown source status command")
            elif name == "checkpoint-observer":
                require(len(argv) == 5 and argv[2:] == ["--checkpoint-observer",
                        self.journal["source"]["name"], self.ownership["source_guid"]],
                        "Preflight resume checkpoint observer identity differs")
            else:
                expected = {"--pool-guid": self.args.pool_guid, "--search-dir": str(self.search_dir)}
                if name in ("before-ddt", "before-content"):
                    expected["--output"] = str(path.parent / (name + ".json"))
                    if name == "before-content":
                        expected["--sample-count"] = str(self.args.sample_count)
                    require(command.get("status") == "passed" and command.get("returncode") == 0,
                            "Preflight resume native baseline command did not pass")
                for flag, value in expected.items():
                    require(argv.count(flag) == 1 and argv.index(flag) + 1 < len(argv) and
                            argv[argv.index(flag) + 1] == value,
                            "Preflight resume command identity differs: " + name + " " + flag)
                if name == "converter-convert":
                    require(interrupted and len(argv) >= 3 and argv[1:3] == ["--convert", "--fenced"] and
                            command.get("status") == "failed" and command.get("returncode") == 130 and
                            command.get("termination") in (None, "SIGTERM"),
                            "Preflight resume converter did not stop cleanly with exit 130")
                    options = argv[3:]
                    require(len(options) % 2 == 0 and
                            all(flag in {"--pool-guid", "--search-dir", "--workers", "--batch-size",
                                         "--read-batch-entries"} for flag in options[::2]) and
                            len(set(options[::2])) == len(options[::2]),
                            "Preflight resume refuses unknown converter options or modes")
                    converters.append(command)
                    logs = {}
                    for stream in ("stdout", "stderr"):
                        log = path.parent / (name + "." + stream)
                        require(command.get(stream) == str(log), "Preflight resume native log path differs")
                        logs[stream], logs[stream + "_sha256"] = private_text(log)
                    require(logs["stdout"].rstrip().endswith("pool cleanly exported") and not re.search(
                        r"copied batch|published|reclaiming staging", logs["stdout"], re.IGNORECASE),
                        "Preflight resume lacks clean export or contains converter writes")
                    native = []
                    for line in logs["stderr"].splitlines():
                        try:
                            item = json.loads(line)
                        except ValueError:
                            continue
                        if isinstance(item, dict) and "phase" in item:
                            require(item["phase"] == "flat-preflight",
                                    "Preflight resume refuses a copy/readback or unknown native phase")
                            native.append(item)
                    require(native and native[-1].get("phase") == "flat-preflight" and
                            command.get("native_progress", {}).get("phase") == "flat-preflight" and
                            not re.search(r"flat-copy|flat-readback|publish|staging", logs["stderr"], re.IGNORECASE),
                            "Preflight resume requires real interrupted flat-preflight, never staging/publication")
                    log_proof = {"stdout_sha256": logs["stdout_sha256"],
                                 "stderr_sha256": logs["stderr_sha256"],
                                 "last_native_progress": native[-1], "command": command}
                elif name == "preflight-describe":
                    require(len(argv) == 6 and argv[1] == "--describe" and "--fenced" not in argv and
                            command.get("status") == "passed" and command.get("returncode") == 0,
                            "Previous describe was not a completed read-only metadata query")
                else:
                    require(not any(arg in ("--convert", "--rebuild", "--fenced", "--expect") or
                            arg.startswith(("--convert=", "--rebuild=", "--fenced=", "--expect=")) for arg in argv),
                            "Preflight resume baseline provenance contains writer flags")
                    if name == "converter-check":
                        require(len(argv) > 1 and argv[1] == "--check", "Unknown baseline converter command")
        require(len(converters) == (1 if interrupted else 0), "Ambiguous interrupted converter provenance")
        return previous, digest, log_proof

    def resume_preflight(self):
        require(self.journal is not None,
                "--resume-preflight requires --ownership-journal and actual COW/backing attestations")
        overlays = self.journal.get("overlays")
        require(isinstance(overlays, list) and overlays, "Preflight resume requires attested actual COW images")
        images = []
        for overlay in overlays:
            image = Path(overlay["image"])
            require(image.is_absolute() and image.resolve(strict=True) == image,
                    "Preflight resume image path is not canonical")
            value = image.lstat()
            require(stat.S_ISREG(value.st_mode) and value.st_uid == 0 and value.st_nlink == 1 and
                    not value.st_mode & 0o022 and
                    [value.st_dev, value.st_ino] == overlay.get("image_identity"),
                    "Preflight resume image lacks its original private inode attestation")
            images.append({"path": str(image), "identity": [value.st_dev, value.st_ino],
                           "mtime_ns": value.st_mtime_ns, "ctime_ns": value.st_ctime_ns})
        path = self.args.resume_preflight.absolute()
        chain, seen, reports = [], set(), []
        expected_digest, interrupted = None, True
        originals = None
        while True:
            require(path not in seen and len(seen) < 64, "Cyclic or excessive baseline provenance chain")
            seen.add(path)
            previous, digest, logs = self.preflight_report(path, interrupted=interrupted)
            require(expected_digest is None or digest == expected_digest, "Baseline provenance report SHA256 differs")
            files, data = {}, {}
            for name, format_name in (("before-ddt", "validate-ddt-v1"), ("before-content", "validate-content-v2")):
                source = path.parent / (name + ".json")
                data[name], file_digest = private_json(source)
                require(data[name].get("format") == format_name and data[name].get("complete") is True and
                        data[name].get("pool_guid") == self.args.pool_guid, "Invalid passed native baseline: " + name)
                if name == "before-content":
                    self.admit_content(data[name])
                files[name] = {"source": str(source), "sha256": file_digest, "copy": source.name}
            legacy_store_identity(data["before-ddt"], baseline=True)
            if originals is None:
                originals = data
            require(data == originals, "Baseline census/content changed along provenance chain")
            chain.append({"report": str(path), "sha256": digest, "files": files, "interrupted_preflight": logs})
            reports.append(previous)
            link = previous.get("preflight_resume") or previous.get("baseline_resume")
            if link is None:
                for name in ("before-ddt", "before-content"):
                    matches = [item for item in previous["commands"] if item["name"] == name]
                    require(len(matches) == 1, "Original passed native baseline command is missing or ambiguous")
                require(not next(item for item in previous["phases"] if item["phase"] == "before-parallel").get("reused"),
                        "Reused baseline lacks its provenance chain")
                break
            require(isinstance(link, dict), "Malformed baseline provenance")
            predecessor = Path(link.get("previous_report", ""))
            expected_digest = link.get("previous_report_sha256")
            require(isinstance(expected_digest, str) and re.fullmatch(r"[0-9a-f]{64}", expected_digest),
                    "Missing baseline provenance SHA256")
            copied = path.parent / link.get("previous_report_copy", "")
            require(copied.parent == path.parent and copied.resolve(strict=True) == copied,
                    "Baseline provenance copy path is not local and canonical")
            saved, _ = private_json(copied)
            original, original_digest = private_json(predecessor)
            require(saved == original and original_digest == expected_digest,
                    "Retained provenance copy differs from its original report")
            recorded_files = link.get("files")
            require(isinstance(recorded_files, dict), "Baseline provenance has no native file hashes")
            for name in ("before-ddt", "before-content"):
                _, original_digest = private_json(predecessor.parent / (name + ".json"))
                require(isinstance(recorded_files.get(name), dict) and
                        recorded_files[name].get("sha256") == original_digest,
                        "Baseline provenance native report SHA256 differs")
            interrupted = previous.get("preflight_resume") is not None
            path = predecessor
        self.boundary("before-preflight-describe")
        child = self.run("preflight-describe", [("preflight-describe", [self.args.converter, "--describe",
                         "--pool-guid", self.args.pool_guid, "--search-dir", self.search_dir])])[0]
        description, description_digest = private_json(child.paths[0])
        admit_preflight_metadata(description, originals["before-ddt"], self.args.pool_guid)
        self.boundary("after-preflight-describe")
        for name, data in originals.items():
            atomic_json(self.root / (name + ".json"), data)
        atomic_json(self.root / "preflight-source-report.json", reports[0])
        before_phase = next(item for item in reports[0]["phases"] if item["phase"] == "before-parallel")
        self.report["preflight_resume"] = {
            "previous_report": chain[0]["report"], "previous_report_sha256": chain[0]["sha256"],
            "previous_report_copy": "preflight-source-report.json", "files": chain[0]["files"],
            "provenance_chain": chain, "native_description": description,
            "native_description_sha256": description_digest,
            "native_description_file": child.paths[0].name,
            "journal_sha256_at_resume": self.journal_hash,
            "current_images": images,
            "proof": "clean_interrupted_preflight_and_current_registered_legacy_objects_counts",
            "baseline_reread": False, "eligibility_revalidated_by_describe": False}
        self.report["phases"].append({"phase": "before-parallel", "complete": True, "reused": True,
                                     "started": before_phase.get("started"), "finished": before_phase.get("finished")})
        self.save()

    def converter_argv(self):
        return [str(self.args.converter), "--convert", "--fenced",
                "--pool-guid", self.args.pool_guid, "--search-dir", str(self.search_dir),
                "--batch-size", str(self.args.batch_size), "--workers", str(self.args.workers),
                "--read-batch-entries", str(self.args.read_batch_entries)]

    def resume_conversion(self):
        """Admit one completed conversion, retaining the original baseline chain."""
        require(self.journal is not None,
                "--resume-conversion requires --ownership-journal and actual COW/backing attestations")
        path = self.args.resume_conversion.absolute()
        require(path.resolve(strict=True) == path, "Conversion resume report path must be canonical")
        directory = path.parent.lstat()
        require(stat.S_ISDIR(directory.st_mode) and directory.st_uid == 0 and not directory.st_mode & 0o077,
                "Conversion resume evidence directory must be private and root-owned")
        previous, digest = private_json(path)
        require(previous.get("format") == "parallel-actual-validation-v1" and
                previous.get("complete") is False and previous.get("status") == "failed" and
                previous.get("resources_preserved") is True and not previous.get("blocking_pids") and
                not previous.get("supervision_errors"),
                "Conversion resume requires a failed resource-preserving handoff without blocked children")
        require(previous.get("pool_guid") == self.args.pool_guid and
                previous.get("source_guid") == self.ownership["source_guid"] and
                previous.get("pool_name") == self.pool_name and
                previous.get("ownership") == str(self.manifest_path) and
                previous.get("ownership_sha256") == self.ownership_hash and
                previous.get("ownership_journal") == str(self.journal_path) and
                previous.get("ownership_journal_sha256") == self.journal_hash,
                "Conversion resume copy/source/manifest/journal identity differs")
        self.admit_sample_target(previous)
        require(previous.get("coverage", {}).get("source_observer") ==
                "checkpoint_guid_start_time_and_contiguous_kernel_history_verified",
                "Conversion resume lacks the original source checkpoint/history proof")
        require(not previous.get("conversion_resume"), "Conversion resume refuses a previously continued report")
        allowed = {"before-parallel", "converter-check", "converter-convert", "preflight-describe",
                   "source-status-before", "source-status-before-converter-check",
                   "source-status-before-converter-convert", "source-status-before-preflight-describe",
                   "source-status-after-preflight-describe", "source-status-after-converter", "published-describe"}
        phases = previous.get("phases")
        require(isinstance(phases, list) and all(isinstance(item, dict) and
                item.get("phase") in allowed for item in phases),
                "Conversion resume refuses unknown or post-validation phases")
        before = [item for item in phases if item["phase"] == "before-parallel"]
        converted = [item for item in phases if item["phase"] == "converter-convert"]
        after = [item for item in phases if item["phase"] == "published-describe"]
        require(len(before) == len(converted) == 1 and before[0].get("complete") is True and
                converted[0].get("complete") is True and len(after) == 1 and
                after[0].get("complete") is False and
                phases.index(before[0]) < phases.index(converted[0]) < phases.index(after[0]),
                "Conversion resume needs completed baseline/converter and an unstarted post-validation handoff")
        require(len({item["phase"] for item in phases}) == len(phases) and
                all(item.get("complete") is True for item in phases if item["phase"] != "published-describe"),
                "Conversion resume refuses duplicate or incomplete pre-handoff phases")
        commands = previous.get("commands")
        require(isinstance(commands, list) and commands, "Missing conversion handoff command provenance")
        require(all(isinstance(command, dict) for command in commands) and
                len({command.get("name") for command in commands}) == len(commands),
                "Conversion resume refuses duplicate or malformed command identities")
        for name in ("source-status-before", "source-status-before-converter-convert",
                     "source-status-after-converter", "checkpoint-observer"):
            require(any(command.get("name") == name for command in commands),
                    "Conversion resume lacks source checkpoint/readonly boundary: " + name)
        allowed_commands = allowed - {"before-parallel"} | {
            "before-ddt", "before-content", "checkpoint-observer"}
        converters, not_started = [], []
        for command in commands:
            require(isinstance(command, dict) and command.get("name") in allowed_commands,
                    "Conversion resume refuses after-content, writer or unknown commands")
            name, argv = command["name"], command.get("argv")
            require(isinstance(argv, list) and argv and all(isinstance(arg, str) for arg in argv),
                    "Malformed conversion handoff command")
            if name == "published-describe":
                expected = [str(self.args.converter), "--describe", "--pool-guid",
                            self.args.pool_guid, "--search-dir", str(self.search_dir)]
                require(argv == expected and command.get("status") == "startup_failed" and
                        "Permission denied" in command.get("error", "") and
                        not any(key in command for key in ("pid", "starttime", "returncode")),
                        "Conversion resume admits only an exact permission-denied unstarted published-description command")
                for stream in ("stdout", "stderr"):
                    log = path.parent / ("published-describe." + stream)
                    require(command.get(stream) == str(log) and private_text(log)[0] == "",
                            "Published-description admission contains output or changed log paths")
                not_started.append(command)
                continue
            pid, starttime = command.get("pid"), command.get("starttime")
            require(type(pid) is int and pid > 0 and isinstance(starttime, str) and starttime.isdecimal(),
                    "Conversion resume cannot identify previous child: " + name)
            sample = process_sample(pid)
            require(sample is None or sample["starttime"] != starttime,
                    "Conversion resume previous child remains live: " + name)
            if name.startswith("source-status-"):
                require(argv == ["zpool", "status", "-P", "-p", "-i", "-t", "-j", "--json-int",
                                 self.journal["source"]["name"]] and
                        command.get("status") == "passed" and command.get("returncode") == 0,
                        "Conversion resume source boundary was not a passed exact status query")
            elif name == "checkpoint-observer":
                checkpoint = self.journal["checkpoint"]
                checkpoint = checkpoint.get("identity", checkpoint)
                require(len(argv) == 5 and argv[2:] == ["--checkpoint-observer",
                        self.journal["source"]["name"], self.ownership["source_guid"]] and
                        command.get("status") == "passed" and command.get("returncode") == 0 and
                        command.get("observer_txg") == checkpoint["txg"] and
                        type(command.get("observer_sequence")) is int and command["observer_sequence"] > 0,
                        "Conversion resume checkpoint observer identity/completion differs")
            elif name == "converter-convert":
                require(argv == self.converter_argv() and command.get("status") == "passed" and
                        command.get("returncode") == 0 and not command.get("termination"),
                        "Conversion resume converter arguments or completed exit differ")
                converters.append(command)
            else:
                expected = {"--pool-guid": self.args.pool_guid, "--search-dir": str(self.search_dir)}
                require(command.get("status") == "passed" and command.get("returncode") == 0 and
                        not any(arg in ("--convert", "--rebuild", "--fenced", "--expect") or
                                arg.startswith(("--convert=", "--rebuild=", "--fenced=", "--expect="))
                                for arg in argv),
                        "Conversion resume baseline provenance contains failed commands or writer flags")
                if name in ("before-ddt", "before-content"):
                    expected["--output"] = str(path.parent / (name + ".json"))
                    if name == "before-content":
                        expected["--sample-count"] = str(self.args.sample_count)
                    require(argv[0] == str(self.args.ddt_validator if name == "before-ddt" else
                                           self.args.content_validator), "Baseline validator executable differs")
                else:
                    require(argv[0] == str(self.args.converter) and argv[1] ==
                            ("--check" if name == "converter-check" else "--describe"),
                            "Conversion resume baseline converter mode differs")
                for flag, value in expected.items():
                    require(argv.count(flag) == 1 and argv.index(flag) + 1 < len(argv) and
                            argv[argv.index(flag) + 1] == value,
                            "Conversion resume command identity differs: " + name + " " + flag)
        require(len(converters) == len(not_started) == 1,
                "Conversion resume requires exactly one passed converter and one unstarted published-description admission")
        converter_index = commands.index(converters[0])
        require(commands[-1] is not_started[0] and all(
                    item["name"] in ("source-status-after-converter", "published-describe")
                    for item in commands[converter_index + 1:]) and
                any(item["name"] == "source-status-after-converter"
                    for item in commands[converter_index + 1:]),
                "Conversion resume command order does not establish the clean post-converter handoff")
        files, originals = {}, {}
        for name, format_name in (("before-ddt", "validate-ddt-v1"), ("before-content", "validate-content-v2")):
            source = path.parent / (name + ".json")
            originals[name], file_digest = private_json(source)
            require(originals[name].get("format") == format_name and originals[name].get("complete") is True and
                    originals[name].get("pool_guid") == self.args.pool_guid,
                    "Conversion resume native baseline is incomplete or wrong-pool: " + name)
            if name == "before-content":
                self.admit_content(originals[name])
            files[name] = {"source": str(source), "sha256": file_digest, "copy": source.name}
        native_proof = conversion_logs(converters[0], path.parent, originals["before-ddt"])
        chain, current, current_path, seen = [], previous, path, {path}
        while True:
            links = [current[key] for key in ("preflight_resume", "baseline_resume") if current.get(key)]
            require(len(links) <= 1, "Ambiguous baseline provenance chain")
            if not links:
                original_before = [item for item in current["phases"] if item["phase"] == "before-parallel"]
                require(len(original_before) == 1 and not original_before[0].get("reused"),
                        "Reused baseline lacks original provenance")
                for name in ("before-ddt", "before-content"):
                    matches = [item for item in current["commands"] if item["name"] == name]
                    require(len(matches) == 1 and matches[0].get("status") == "passed" and
                            matches[0].get("returncode") == 0, "Missing original passed native baseline command")
                break
            link = links[0]
            require(isinstance(link, dict), "Malformed baseline provenance link")
            predecessor = Path(link.get("previous_report", ""))
            require(predecessor.is_absolute() and predecessor not in seen and len(seen) < 64,
                    "Cyclic, relative or excessive baseline provenance chain")
            seen.add(predecessor)
            expected_digest = link.get("previous_report_sha256")
            require(isinstance(expected_digest, str) and re.fullmatch(r"[0-9a-f]{64}", expected_digest),
                    "Missing original baseline report SHA256")
            copied = current_path.parent / link.get("previous_report_copy", "")
            require(copied.parent == current_path.parent and copied.resolve(strict=True) == copied,
                    "Baseline provenance copy must be local and canonical")
            saved, _ = private_json(copied)
            original, original_digest, logs = self.preflight_report(
                predecessor, interrupted=current.get("preflight_resume") is not None)
            require(saved == original and original_digest == expected_digest,
                    "Baseline provenance original/report copy SHA256 differs")
            recorded_files = link.get("files")
            require(isinstance(recorded_files, dict), "Baseline provenance lacks native report hashes")
            for name, data in originals.items():
                old_data, old_digest = private_json(predecessor.parent / (name + ".json"))
                require(old_data == data and isinstance(recorded_files.get(name), dict) and
                        recorded_files[name].get("sha256") == old_digest,
                        "Original baseline bytes/hash changed along provenance chain")
            chain.append({"report": str(predecessor), "sha256": original_digest,
                          "files": recorded_files, "interrupted_preflight": logs})
            current, current_path = original, predecessor
        images = []
        finishes = [converters[0].get("finished"), converted[0].get("finished")]
        require(all(type(value) in (int, float) and math.isfinite(value) and value > 0
                    for value in finishes),
                "Completed converter lacks trustworthy command/phase finish timestamps")
        # Child.tick() can refresh command.finished during runner teardown;
        # the completed phase timestamp cannot drift past the conversion.
        finished = min(finishes)
        for overlay in self.journal["overlays"]:
            image = Path(overlay["image"])
            value = image.lstat()
            require(image.is_absolute() and image.resolve(strict=True) == image and
                    stat.S_ISREG(value.st_mode) and value.st_uid == 0 and value.st_nlink == 1 and
                    not value.st_mode & 0o022 and
                    [value.st_dev, value.st_ino] == overlay.get("image_identity") and
                    value.st_mtime_ns <= int(finished * 1_000_000_000) and
                    value.st_ctime_ns <= int(finished * 1_000_000_000),
                    "Conversion resume image identity changed or was modified after converter completion")
            images.append({"path": str(image), "identity": [value.st_dev, value.st_ino],
                           "mtime_ns": value.st_mtime_ns, "ctime_ns": value.st_ctime_ns})
        self.assert_devices()
        for name, data in originals.items():
            atomic_json(self.root / (name + ".json"), data)
        atomic_json(self.root / "conversion-source-report.json", previous)
        self.report["conversion_resume"] = {
            "previous_report": str(path), "previous_report_sha256": digest,
            "previous_report_copy": "conversion-source-report.json", "files": files,
            "provenance_chain": chain, "converter_command": converters[0],
            "not_started_published_describe": not_started[0], "native_proof": native_proof,
            "current_images": images, "journal_sha256_at_resume": self.journal_hash,
            "baseline_reread": False, "converter_rerun": False,
            "proof": "passed_full_converter_clean_export_and_original_native_baseline_provenance"}
        for phase in (before[0], converted[0]):
            self.report["phases"].append({**phase, "reused": True})
        self.save()

    def validate(self):
        self.initialize_locks()
        self.boundary("before")
        if self.args.resume_conversion:
            self.resume_conversion()
        elif self.args.resume_preflight:
            self.resume_preflight()
        elif self.args.resume_baseline:
            self.resume_baseline()
        else:
            self.run("before-parallel", [
                ("before-ddt", self.native_command(self.args.ddt_validator, self.args.workers, "before-ddt.json", ddt=True)),
                ("before-content", self.native_command(self.args.content_validator, self.args.content_workers, "before-content.json"))])
        before_ddt = self.native_report("before-ddt.json", "validate-ddt-v1")
        self.report["ddt_reports"] = {"before": before_ddt}
        require(before_ddt.get("full_flat_eligible") is True and
                any(table.get("version") == 0 and table.get("flags") == 0
                    for table in before_ddt.get("tables", [])),
                "Baseline has no actual flat-eligible legacy DDT; refusing no-op validation")
        before_content = self.native_report("before-content.json", "validate-content-v2")
        if self.args.resume_conversion:
            native_proof = self.report["conversion_resume"]["native_proof"]
        else:
            self.boundary("before-converter-convert")
            if self.args.resume_baseline:
                self.resume_images(self.report["baseline_resume"]["before_ddt_started_ns"])
            child = self.run("converter-convert", [("converter-convert", self.converter_argv())])[0]
            native_proof = conversion_logs(child.record, self.root, before_ddt)
        self.report["coverage"]["full_ddt"] = {
            "status": "converter_full_staged_readback_passed", "before": "before-ddt.json",
            "independent_after_fingerprint": False, "native_proof": native_proof,
            "limits": "Full independent staged native readback by converter; no redundant after-DDT fingerprint"}
        self.boundary("after-converter")
        child = self.run("published-describe", [("published-describe", [self.args.converter, "--describe",
                         "--pool-guid", self.args.pool_guid, "--search-dir", self.search_dir])])[0]
        description, description_digest = private_json(child.paths[0])
        self.report["coverage"]["published_layout"] = admit_published_metadata(
            description, before_ddt, self.args.pool_guid)
        self.report["published_description"] = description
        self.report["published_description_sha256"] = description_digest
        self.report["published_description_file"] = child.paths[0].name
        self.boundary("before-content-replay")
        self.run("after-content-replay", [
            ("after-content", self.native_command(self.args.content_validator, self.args.content_workers,
                                                 "after-content.json", "before-content.json"))])
        after_content = self.native_report("after-content.json", "validate-content-v2")
        require(before_content == after_content, "Content inventory, locked coverage or exact sample identity/bytes changed")
        views = after_content.get("views", [])
        self.report["coverage"]["content"] = {"status": "exact_inventory_and_recorded_ranges_passed",
            "inventory_entries": len(after_content.get("inventory", [])), "selected_views": len(views),
            "locked_unavailable_views": [view for view in views if view.get("status") == "locked"],
            "sample_target": self.args.sample_count,
            "actual_dedup_backed_ranges": True,
            "sample_count": sum(len(view.get("samples", [])) for view in views),
            "sample_bytes": sum(int(sample["length"]) for view in views for sample in view.get("samples", [])),
            "limits": "Exact distinct logical dedup-backed ranges, not unique physical blocks; locked plaintext unavailable; not a full userdata scrub"}
        self.boundary("finished")
        self.report.update(complete=True, status="passed")

    def finish(self):
        for child in reversed(self.children):
            try:
                if child is self.observer and child.process.poll() is None:
                    child.process.stdin.close()
                    deadline = time.monotonic() + 2
                    while child.process.poll() is None and time.monotonic() < deadline:
                        time.sleep(0.1)
                child.stop()
                if child.process.poll() is not None:
                    child.tick(enforce=False)
                    if child.process.returncode != 0:
                        self.report.update(complete=False, status="failed")
                        self.report.setdefault("supervision_errors", []).append(
                            child.name + " exited " + str(child.process.returncode))
            except BaseException as error:
                self.report.setdefault("supervision_errors", []).append(str(error))
                self.report.update(complete=False, status="failed")
        if self.report["blocking_pids"]:
            self.report.update(complete=False, status="blocked_preserve")
        self.report.update(finished=time.time(), elapsed_seconds=time.monotonic() - self.started)
        self.save()
        self.heartbeat(self.report["status"], self.children)
        self.progress_stream.close()
        for descriptor in reversed(self.locks):
            os.close(descriptor)


def checkpoint_observer(pool, guid):
    from checkpoint_history import CheckpointHistory
    observer = CheckpointHistory(pool, guid)
    try:
        for line in sys.stdin:
            sequence = int(line.strip())
            print(json.dumps({"observer_txg": observer.checkpoint_txg(), "sequence": sequence}), flush=True)
    finally:
        observer.close()


def positive(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "--checkpoint-observer":
        checkpoint_observer(sys.argv[2], sys.argv[3])
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pool-guid", required=True)
    parser.add_argument("--search-dir", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--converter", type=Path, required=True)
    parser.add_argument("--ddt-validator", type=Path, required=True)
    parser.add_argument("--content-validator", type=Path, required=True)
    cpus = len(os.sched_getaffinity(0))
    parser.add_argument("--workers", type=positive, default=min(64, cpus))
    parser.add_argument("--content-workers", type=positive, default=min(16, cpus))
    parser.add_argument("--sample-count", type=positive, default=25000,
                        help="Exact dedup-backed logical ranges before/after conversion, at most 50000 (default 25000)")
    parser.add_argument("--batch-size", type=positive, default=65536,
                        help="Converter entries per transaction, at most 65536")
    parser.add_argument("--ownership-journal", "--journal", type=Path)
    parser.add_argument("--read-batch-entries", type=positive, default=1_000_000,
                        help="Converter entries per physical-read/hash-sort batch, at most 1000000")
    resume = parser.add_mutually_exclusive_group()
    resume.add_argument("--resume-baseline", type=Path, metavar="PREVIOUS_REPORT",
                        help="Reuse passed native before reports only from a failed read-only actual attempt with provably unchanged attested COW images")
    resume.add_argument("--resume-preflight", type=Path, metavar="PREVIOUS_REPORT",
                        help="Restart only cleanly interrupted converter preflight after native legacy object/count admission")
    resume.add_argument("--resume-conversion", type=Path, metavar="PREVIOUS_REPORT",
                        help="Admit one completed converter handoff and original baseline, then run only distinct publication/content checks")
    parser.add_argument("--arc-max-bytes", type=positive, default=min(8 * GIB, max(512 * 1024 ** 2,
                        os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE") // 8)),
                        help="Total native validator ARC budget, split equally unless --ddt-arc-max-bytes is set")
    parser.add_argument("--ddt-arc-max-bytes", type=positive,
                        help="DDT validator ARC budget; content receives the remaining total (at least 64MiB each)")
    parser.add_argument("--ddt-preload", action="store_true",
                        help="Warm DDT objects in physical-address order before the full census; requires their logical size to fit 75%% of DDT ARC")
    parser.add_argument("--stall-timeout", type=positive, default=60, help="Seconds without measured work, not heartbeat")
    parser.add_argument("--startup-timeout", type=positive, default=60, help="Seconds before first measured child work or observer acknowledgment")
    parser.add_argument("--stage-timeout", type=positive, default=21600, help="Absolute per-stage seconds, even while progressing")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("root is required")
    if not args.pool_guid.isdecimal() or not 0 < int(args.pool_guid) < 2 ** 64:
        parser.error("--pool-guid must be a nonzero uint64 decimal string")
    if args.workers > 64:
        parser.error("--workers must be at most 64 (shared DDT validator/converter worker limit)")
    if args.sample_count > 50000:
        parser.error("--sample-count must be at most 50000")
    if args.batch_size > 65536:
        parser.error("--batch-size must be at most 65536")
    if args.read_batch_entries > 1_000_000:
        parser.error("--read-batch-entries must be at most 1000000")
    for name in ("converter", "ddt_validator", "content_validator"):
        path = getattr(args, name)
        needs_execute = name != "ddt_validator" or not args.resume_conversion
        if not path.is_absolute() or not path.is_file() or (needs_execute and not os.access(path, os.X_OK)):
            parser.error("--" + name.replace("_", "-") + " must be an absolute " +
                         ("executable " if needs_execute else "") + "file")
        setattr(args, name, path.resolve())
    if not args.work_dir.is_dir() or not args.search_dir.is_dir():
        parser.error("--work-dir and --search-dir must be existing directories")
    if args.arc_max_bytes < 128 * 1024 ** 2:
        parser.error("--arc-max-bytes must permit at least 64MiB per validator")
    if args.ddt_arc_max_bytes is not None and not 64 * 1024 ** 2 <= args.ddt_arc_max_bytes <= args.arc_max_bytes - 64 * 1024 ** 2:
        parser.error("--ddt-arc-max-bytes must be at least 64MiB and leave at least 64MiB for content")
    if "ZFS_HOSTID" in os.environ:
        parser.error("ZFS_HOSTID override is forbidden")
    runner = None
    handlers = {}

    def interrupted(signum, frame):
        raise KeyboardInterrupt("Received signal " + str(signum))

    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            handlers[signum] = signal.signal(signum, interrupted)
        runner = Runner(args)
        runner.validate()
    except BaseException as error:
        if runner:
            runner.report.update(complete=False, status="failed", error=str(error), traceback=traceback.format_exc())
        print("FAIL: " + str(error), file=sys.stderr, flush=True)
    finally:
        for signum in handlers:
            signal.signal(signum, signal.SIG_IGN)
        if runner:
            runner.finish()
        for signum, handler in handlers.items():
            signal.signal(signum, handler)
    if runner:
        print(json.dumps({"status": runner.report["status"], "complete": runner.report["complete"],
                          "elapsed_seconds": runner.report["elapsed_seconds"],
                          "report": str(runner.report_path),
                          "throughput": [
                              {"name": child.name, "elapsed_seconds": child.record.get("elapsed_seconds", 0),
                               "average_work_per_second": {
                                   key: round(value / max(0.001, child.record.get("elapsed_seconds", 0)), 2)
                                   for key, value in child.work.items()}}
                              for child in runner.children if child.work],
                          "blocking_pids": runner.report["blocking_pids"]}), flush=True)
        return 0 if runner.report["complete"] else 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
