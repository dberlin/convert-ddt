#!/usr/bin/env python3
"""Validate full DDT conversion on sparse COW views of a live pool checkpoint.

The source stays imported. Its only mutations are explicitly authorized checkpoint
creation and discard of that exact checkpoint after every owned reader has stopped.
Full command logs and a durable ownership journal remain after dependent images
are retired. A nonempty source lease requires operator recovery before validation.
"""

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import struct
import subprocess
import sys
import time
import traceback
import uuid

from checkpoint_history import CheckpointHistory
from cow_validation import CowHarness, CopyPool, Overlay, process_identity
from integration import Failure, require

GIB = 1024 ** 3
BLKGETSIZE64 = 0x80081272


def capacity(path):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        require(stat.S_ISBLK(os.fstat(fd).st_mode), "Raw backing is not a block device")
        return struct.unpack("Q", fcntl.ioctl(fd, BLKGETSIZE64, bytes(8)))[0]
    finally:
        os.close(fd)


def nodes(tree):
    require(isinstance(tree, dict), "Malformed JSON vdev tree")
    for value in tree.values():
        require(isinstance(value, dict), "Malformed JSON vdev node")
        yield value
        if value.get("vdevs"):
            yield from nodes(value["vdevs"])


class RawOverlay(Overlay):
    """Block-device backing identity includes device number and ioctl capacity."""

    @staticmethod
    def identity(path):
        value = path.stat()
        require(stat.S_ISBLK(value.st_mode), "Source leaf is not a block device")
        return [value.st_dev, value.st_ino, value.st_rdev, capacity(path)]

    def create(self):
        require(not self.image.exists(), "Overlay image already exists")
        require(self.identity(self.backing) == self.backing_identity, "Backing identity changed")
        self.info.update(create_intent=True, virtual_bytes=self.backing_identity[-1])
        self.h.flush()
        self.h.command("qemu-img", "create", "-f", "qcow2", "-F", "raw",
                       "-b", self.backing, self.image)
        value = self.image.lstat()
        require(stat.S_ISREG(value.st_mode) and value.st_uid == 0 and value.st_nlink == 1,
                "Created overlay image has unexpected ownership or type")
        self.info["image_identity"] = [value.st_dev, value.st_ino]
        self.info["created"] = True
        self.h.flush()

    def retire(self):
        require(not self.info.get("attached") and
                (self.process is None or self.process.poll() is not None),
                "Overlay readers must stop before image retirement")
        try:
            value = self.image.lstat()
        except FileNotFoundError:
            value = None
        if value is not None:
            require(self.info.get("created") and stat.S_ISREG(value.st_mode) and
                    value.st_uid == 0 and value.st_nlink == 1 and
                    [value.st_dev, value.st_ino] == self.info.get("image_identity"),
                    "Overlay image ownership changed; preserve its checkpoint")
            self.info["retire_intent"] = True
            self.h.flush()
            self.image.unlink()
            fd = os.open(self.image.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        self.info["image_retired"] = True
        self.h.flush()


class ActualClone(CopyPool):
    def __init__(self, harness):
        super().__init__(harness, "checkpoint-clone")
        self.views = []
        self.samples = []

    def destroy(self):
        raise Failure("Clone destruction is unnecessary; only export and detach are permitted")

    def assert_owned(self):
        require(self.guid and self.guid != self.h.source_guid, "Clone GUID is not distinct")
        super().assert_owned()

    def export(self):
        self.unmount_views()
        self.assert_owned()
        self.h.command("zpool", "export", self.name)

    def unmount_views(self):
        for view in reversed(self.views):
            if not view.get("mounted"):
                continue
            self.assert_owned()
            mounts = {}
            for line in Path("/proc/self/mountinfo").read_text().splitlines():
                before, after = line.split(" - ", 1)
                mounts[before.split()[4]] = after.split()[:2]
            target = view["target"]
            if target in mounts:
                require(mounts[target] == ["zfs", view["dataset"]],
                        "Controlled mount identity changed: " + target)
                self.h.command("umount", target)
            view["mounted"] = False
            self.h.flush()

    def mount_view(self, view):
        self.assert_owned()
        target = Path(view["target"])
        target.mkdir(parents=True, exist_ok=True)
        view["mount_intent"] = True
        self.h.flush()
        options = "ro" if "@" in view["dataset"] or view["original_mountpoint"] == "legacy" else "ro,zfsutil"
        try:
            self.h.command("mount", "-t", "zfs", "-o", options, view["dataset"], target)
        finally:
            # A failed or interrupted mount can still have reached the kernel.
            for line in Path("/proc/self/mountinfo").read_text().splitlines():
                before, after = line.split(" - ", 1)
                if before.split()[4] == str(target):
                    require(after.split()[:2] == ["zfs", view["dataset"]],
                            "Unexpected mount at owned view target")
                    view["mounted"] = True
            self.h.flush()
        require(view.get("mounted"), "Controlled mount was not observed")

    def inventory(self, kinds="filesystem,volume,snapshot"):
        self.assert_owned()
        output = self.h.command("zfs", "list", "-Hp", "-r", "-t", kinds,
                                "-o", "name,type,mountpoint,keystatus,volmode", self.name,
                                timeout=None).stdout
        rows = []
        for line in output.splitlines():
            fields = line.split("\t")
            require(len(fields) == 5, "Unexpected dataset inventory row")
            name, kind, mountpoint, keys, volmode = fields
            require(name == self.name or name.startswith(self.name + "/") or
                    name.startswith(self.name + "@"), "Inventory escaped owned clone")
            rows.append(dict(name=name, type=kind, mountpoint=mountpoint,
                             keystatus=keys, volmode=volmode))
        require(rows or kinds == "volume", "Owned clone inventory is empty")
        self.info["volume_inventory" if kinds == "volume" else "inventory"] = rows
        self.h.flush()
        return rows

    def hidden_volumes(self, rows=None):
        rows = self.inventory("volume") if rows is None else rows
        for row in rows:
            if row["type"] != "volume":
                continue
            require(row["volmode"] == "none", "Clone volume is not volmode=none: " + row["name"])
            require(not os.path.lexists("/dev/zvol/" + row["name"]),
                    "Clone volume node is exposed: " + row["name"])
        root = Path("/dev/zvol") / self.name
        require(not root.exists() or not any(path.is_symlink() or path.is_file() or
                                            stat.S_ISBLK(path.lstat().st_mode)
                                            for path in root.rglob("*")),
                "A clone zvol or snapshot device node is exposed")
        self.info["volumes_hidden"] = True
        self.h.flush()

    def baseline(self):
        rows = self.inventory()
        self.hidden_volumes(rows)
        filesystems = {row["name"]: row for row in rows if row["type"] == "filesystem"}
        snapshots = {}
        for row in rows:
            if row["type"] == "snapshot" and row["name"].split("@", 1)[0] in filesystems:
                snapshots.setdefault(row["name"].split("@", 1)[0], row)
        self.info.update(views=self.views, samples=self.samples,
                         sample_policy={"files_per_view": 2, "max_file_bytes": 64 * 1024 ** 2,
                                        "max_directory_entries_per_view": 10000,
                                        "snapshots": "One existing snapshot per filesystem"})
        for row in filesystems.values():
            chosen = [row]
            if row["name"] in snapshots:
                chosen.append(snapshots[row["name"]])
            for selected in chosen:
                view = {"dataset": selected["name"], "original_mountpoint": row["mountpoint"],
                        "target": str(self.directory / "views" / str(len(self.views))),
                        "mounted": False}
                self.views.append(view)
                if row["keystatus"] == "unavailable":
                    view["coverage"] = "locked: no decryption key available"
                    self.h.flush()
                    continue
                self.mount_view(view)
                view["coverage"] = "readable; no representative file found within sampling bounds"
                examined = 0
                count = 0
                stack = [Path(view["target"])]
                device = stack[0].stat().st_dev
                while stack and examined < 10000 and count < 2:
                    directory = stack.pop()
                    try:
                        entries = os.scandir(directory)
                    except PermissionError:
                        continue
                    with entries:
                        for entry in entries:
                            examined += 1
                            if examined > 10000:
                                break
                            if entry.name == ".zfs" or entry.is_symlink():
                                continue
                            value = entry.stat(follow_symlinks=False)
                            if value.st_dev != device:
                                continue
                            if stat.S_ISDIR(value.st_mode):
                                stack.append(Path(entry.path))
                            elif stat.S_ISREG(value.st_mode) and 0 < value.st_size <= 64 * 1024 ** 2:
                                try:
                                    digest = self.hash_sample(Path(entry.path))
                                except PermissionError:
                                    continue
                                self.samples.append({"view": len(self.views) - 1,
                                                     "relative": str(Path(entry.path).relative_to(view["target"])),
                                                     "bytes": value.st_size, "sha256": digest})
                                count += 1
                                if count == 2:
                                    break
                view.update(examined_entries=examined, sampled_files=count)
                if count:
                    view["coverage"] = "representative existing files hashed"
                self.h.flush()
                self.unmount_views()
        require(self.samples, "No readable representative existing file could be hashed")
        self.unmount_views()

    def hash_sample(self, path):
        digest = hashlib.sha256()
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "Sample is no longer regular")
            while block := stream.read(1024 * 1024):
                self.h.guard()
                digest.update(block)
        return digest.hexdigest()

    def verify_samples(self):
        for index in sorted({sample["view"] for sample in self.samples}):
            view = self.views[index]
            self.mount_view(view)
            for sample in self.samples:
                if sample["view"] != index:
                    continue
                require(self.hash_sample(Path(view["target"]) / sample["relative"]) == sample["sha256"],
                        "Post-conversion file hash mismatch: " + view["dataset"] + "/" + sample["relative"])
            self.unmount_views()
        self.info["hashes_match"] = True
        self.h.flush()


class ActualHarness(CowHarness):
    def __init__(self, args):
        self.args = args
        self.source_guid = None
        self.source_leaves = []
        self.source_lease = None
        self.lease_owned = False
        self.checkpoint = None
        self.checkpoint_history = None
        self.checkpoint_intent = None
        self.preserve = False
        self.cleaning = False
        self.checking_identity = False
        self.command_children = {}
        self.last_guard = 0
        super().__init__(args.converter, args.clone_helper, args.work_dir)
        self.evidence.update(cases=[{"name": "actual-checkpoint-cow-conversion", "status": "not_run"}],
                             source={"name": args.pool}, resources={"work_directory": str(self.root)},
                             coverage={"source": "Live imported pool; checkpoint blocks read through read-only raw backing",
                                       "data": "Representative existing filesystem and explicit snapshot file hashes",
                                       "metadata": "Exported clone zdb -bc: metadata checksums, block-pointer traversal, "
                                                   "encountered DDT reference counts, and spacemap allocation/leak checks",
                                       "zvol": "Hidden volmode=none; block-pointer/allocation checks only, not payload checksums",
                                       "limits": "No whole-pool userdata checksum scan; DDT entries never encountered by "
                                                 "traversal are not directly refcount-checked",
                                       "locked": "Recorded without claiming decrypted reads"})
        self.flush()

    def flush(self):
        if not hasattr(self, "evidence_path"):
            return
        temporary = self.evidence_path.with_suffix(".json.tmp")
        with temporary.open("w") as stream:
            json.dump(self.evidence, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(self.evidence_path)
        fd = os.open(self.evidence_path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def command(self, *args, expect=0, timeout=300):
        argv = [str(arg) for arg in args]
        item = {"argv": argv, "started": time.time()}
        index = len(self.evidence["commands"])
        logdir = self.root / "commands"
        logdir.mkdir(exist_ok=True)
        stdout_path = logdir / ("%05d.stdout" % index)
        stderr_path = logdir / ("%05d.stderr" % index)
        item.update(stdout_path=str(stdout_path), stderr_path=str(stderr_path), intent=True)
        self.evidence["commands"].append(item)
        self.flush()
        child = None
        identity = None
        started = time.monotonic()
        try:
            with stdout_path.open("xb") as out, stderr_path.open("xb") as err:
                deferred = []
                handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)
                            if signal.getsignal(sig) != signal.SIG_IGN}

                def defer(signum, frame):
                    deferred.append(signum)

                for sig in handlers:
                    signal.signal(sig, defer)
                try:
                    # Journal ownership before cancellation can interrupt process creation.
                    child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=out, stderr=err,
                                             env={**os.environ, "LC_ALL": "C"})
                    self.command_children[child] = None
                    child.stdin.close()
                    identity = process_identity(child.pid)
                    self.command_children[child] = identity
                    item.update(pid=child.pid, starttime=identity)
                    self.flush()
                finally:
                    blocked = signal.pthread_sigmask(signal.SIG_BLOCK, set(handlers))
                    try:
                        for sig, handler in handlers.items():
                            signal.signal(sig, handler)
                    finally:
                        signal.pthread_sigmask(signal.SIG_SETMASK, blocked)
                for sig in deferred:
                    handler = handlers[sig]
                    if callable(handler):
                        handler(sig, None)
                    else:
                        raise KeyboardInterrupt("Validator command cancelled")
                while child.poll() is None:
                    if timeout is not None and time.monotonic() - started > timeout:
                        raise Failure("Command timed out: " + " ".join(argv))
                    if not self.cleaning:
                        self.guard()
                    time.sleep(0.25)
                item["returncode"] = child.returncode
        except BaseException:
            if child is not None and child.poll() is None:
                if process_identity(child.pid) != identity or identity is None:
                    self.preserve = True
                    raise Failure("Child identity ambiguous; retaining its checkpoint lease")
                child.terminate()
                item["termination"] = "SIGTERM"
                try:
                    child.wait(timeout=60)
                except subprocess.TimeoutExpired:
                    self.preserve = True
                    require(process_identity(child.pid) == identity, "Child identity changed")
                    child.kill()
                    child.wait()
                    item["termination"] = "SIGTERM then SIGKILL; resources retained"
                item["returncode"] = child.returncode
            raise
        finally:
            if child is not None:
                if child.poll() is None:
                    self.command_children[child] = identity
                    self.preserve = True
                    item["reader_still_running"] = True
                else:
                    self.command_children.pop(child, None)
            item["finished"] = time.time()
            if stdout_path.exists():
                # Full bytes remain in files even when a command emits a large table.
                item["stdout_bytes"] = stdout_path.stat().st_size
                item["stderr_bytes"] = stderr_path.stat().st_size
            self.flush()
        result = subprocess.CompletedProcess(argv, child.returncode,
                                              stdout_path.read_text(errors="replace"),
                                              stderr_path.read_text(errors="replace"))
        if expect is not None:
            require(result.returncode == expect,
                    "Command returned %d: %s; see %s" % (result.returncode, " ".join(argv), stderr_path))
        return result

    def status(self, name):
        data = json.loads(self.command("zpool", "status", "-P", "-p", "-i", "-t",
                                       "-j", "--json-int", name).stdout)
        pools = data.get("pools", {})
        require(len(pools) == 1 and name in pools, "JSON status did not identify exactly the requested pool")
        return pools[name]

    def source_property(self, prop):
        return self.command("zpool", "get", "-Hp", "-o", "value", prop, self.args.pool).stdout.strip()

    def assert_source(self):
        require(self.source_property("guid") == self.source_guid, "Source pool GUID changed")

    @staticmethod
    def checkpoint_identity(status):
        checkpoint = status.get("checkpoint_stats", {})
        if checkpoint.get("state", "NONE") == "NONE":
            return None
        require(checkpoint.get("state") == "EXISTS", "Checkpoint is being discarded or has unknown state")
        start = checkpoint.get("start_time")
        require(isinstance(start, int) and start > 0, "Checkpoint start_time is unavailable")
        identity = {"start_time": start}
        if checkpoint.get("txg"):
            identity["txg"] = int(checkpoint["txg"])
        return identity

    def assert_checkpoint(self):
        previous = self.checking_identity
        self.checking_identity = True
        try:
            self.assert_source()
            current = self.checkpoint_identity(self.status(self.args.pool))
            require(self.checkpoint is not None and current is not None and
                    all(current.get(key) == value for key, value in self.checkpoint.items()
                        if key in current),
                    "Source checkpoint identity changed; preserve resources and lease")
            if "txg" in self.checkpoint:
                require(self.checkpoint_txg() == self.checkpoint["txg"],
                        "Source checkpoint TXG changed or cannot be reconfirmed")
        finally:
            self.checking_identity = previous

    def assert_overlays(self):
        for overlay in self.overlays:
            if overlay.info.get("attached"):
                overlay.assert_readonly_backing()

    def checkpoint_txg(self):
        require(len(self.source_leaves) == 12, "Checkpoint probe requires validated source partitions")
        previous = self.checking_identity
        self.checking_identity = True
        try:
            self.assert_source()
            before = self.checkpoint_identity(self.status(self.args.pool))
            require(before is not None and self.checkpoint is not None and
                    before["start_time"] == self.checkpoint["start_time"],
                    "Owned checkpoint is unavailable before kernel history observation")
            for path, identity in self.source_leaves:
                require(RawOverlay.identity(path) == identity, "Source partition identity changed")
            # Kernel history contains the committed checkpoint creation TXG.
            # Keep its cursor so discards, replacements, and lost records cannot
            # be hidden by re-reading only the newest surviving creation record.
            # Full MOS verification remains on the exported converted copy.
            if getattr(self, "checkpoint_history", None) is None:
                self.checkpoint_history = CheckpointHistory(self.args.pool, self.source_guid)
            txg = self.checkpoint_history.checkpoint_txg()
            require("txg" not in self.checkpoint or self.checkpoint["txg"] == txg,
                    "Kernel history checkpoint TXG differs from the durable owned identity")
            require("txg" not in before or before["txg"] == txg,
                    "Kernel checkpoint status and history transaction groups disagree")
            for path, identity in self.source_leaves:
                require(RawOverlay.identity(path) == identity, "Source partition identity changed")
            self.assert_source()
            require(self.checkpoint_identity(self.status(self.args.pool)) == before,
                    "Source checkpoint identity changed during kernel history observation")
            return txg
        except BaseException:
            self.preserve = True
            raise
        finally:
            self.checking_identity = previous

    def preflight(self):
        self.source_guid = self.source_property("guid")
        require(self.source_guid.isdecimal() and int(self.source_guid), "Source GUID is invalid")
        path = Path("/run/lock") / ("convert-ddt-actual-" + self.source_guid + ".lock")
        self.source_lease = os.open(path, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        value = os.fstat(self.source_lease)
        require(stat.S_ISREG(value.st_mode) and value.st_uid == 0 and value.st_nlink == 1 and
                value.st_mode & 0o022 == 0,
                "Source lease is not a private root-owned regular file")
        fcntl.flock(self.source_lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        value = os.fstat(self.source_lease)
        require(value.st_size == 0, "Source has an existing durable lease; manual recovery is required: " + str(path))
        lease = json.dumps({"source_guid": self.source_guid, "journal": str(self.evidence_path),
                            "pid": os.getpid(), "starttime": process_identity(os.getpid())}).encode()
        os.write(self.source_lease, lease)
        os.fsync(self.source_lease)
        self.lease_owned = True
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        self.evidence["resources"]["source_lease"] = str(path)
        self.evidence["source"]["guid"] = self.source_guid
        self.flush()
        self.assert_source()
        status = self.status(self.args.pool)
        self.evidence["source"]["preflight_status"] = status
        require(status.get("state") == "ONLINE", "Source is not ONLINE")
        require(str(status.get("pool_guid", "")) == self.source_guid,
                "Source JSON topology GUID does not match the source lease")
        require(int(status.get("error_count", 0)) == 0, "Source has known data errors")
        require(self.checkpoint_identity(status) is None, "Source already has a checkpoint")
        require(self.source_property("checkpoint") in ("-", "0"), "Source checkpoint already exists")
        require(self.source_property("multihost") == "off", "multihost pools are unsupported")
        require(self.source_property("feature@fast_dedup") in ("enabled", "active"),
                "Source fast_dedup feature is unavailable")
        for key in ("logs", "l2cache", "spares", "special", "dedup"):
            require(not status.get(key), "Auxiliary vdev class unsupported: " + key)
        for key in ("scan_stats", "removal_stats", "raidz_expand_stats"):
            section = status.get(key, {})
            require(section.get("state", "NONE") in ("NONE", "FINISHED", "CANCELED", "COMPLETE"),
                    "Source has an active operation: " + key)
            require(section.get("err_scrub_state", "NONE") in ("NONE", "FINISHED", "CANCELED"),
                    "Source has an active error scrub")
            for rebuild in section.get("rebuild_stats", {}).values():
                require(rebuild.get("state") in ("NONE", "COMPLETE", "CANCELED"),
                        "Source has an active sequential resilver")
        all_nodes = list(nodes(status.get("vdevs", {})))
        require(all_nodes and all_nodes[0].get("vdev_type") == "root", "Complete root topology unavailable")
        leaves = []
        topology = []
        for node in all_nodes:
            require(node.get("state") == "ONLINE", "Source vdev is not ONLINE")
            require(node.get("class", "normal") == "normal", "Unsupported auxiliary allocation class")
            require(node.get("vdev_type") in ("root", "raidz", "mirror", "disk"),
                    "Unsupported source vdev topology")
            for key in ("read_errors", "write_errors", "checksum_errors"):
                require(int(node.get(key, 0)) == 0, "Source has vdev error counters")
            for key in ("init_state", "trim_state"):
                require(str(node.get(key, "NONE")).upper() not in
                        ("ACTIVE", "SCANNING", "SUSPENDED", "IN_PROGRESS"),
                        "Source has active vdev initialization or trimming")
            guid = str(node.get("guid", ""))
            require(guid.isdecimal() and int(guid), "Missing source vdev GUID")
            topology.append((guid, node.get("vdev_type"), node.get("path")))
            if not node.get("vdevs"):
                require(node.get("vdev_type") == "disk" and node.get("path"), "Unsupported non-disk leaf")
                path = Path(node["path"]).resolve(strict=True)
                identity = RawOverlay.identity(path)
                require((Path("/sys/dev/block") / ("%d:%d" % (os.major(identity[2]), os.minor(identity[2]))) /
                         "partition").exists(), "Source leaf must be an explicit partition, not a whole disk")
                leaves.append(path)
        require(len(leaves) == 12 and len({path.stat().st_rdev for path in leaves}) == 12,
                "Expected exactly twelve distinct source partition leaves")
        roots = list(status["vdevs"].values())
        require(len(roots) == 1, "Expected one pool root")
        tops = list(roots[0].get("vdevs", {}).values())
        require(len(tops) == 2 and all(top.get("vdev_type") == "raidz" and
                                      len(top.get("vdevs", {})) == 6 and
                                      top.get("name", "").startswith("raidz2-") for top in tops),
                "Expected exactly two six-disk RAIDZ2 top-level vdevs")
        self.evidence["source"].update(topology=topology, leaves=[str(path) for path in leaves])
        self.source_leaves = [(path, RawOverlay.identity(path)) for path in leaves]
        self.flush()
        self.allocation("source-preflight")
        return leaves

    def allocation(self, stage):
        images = [{"path": str(overlay.image), "allocated_bytes": overlay.image.stat().st_blocks * 512,
                   "virtual_bytes": overlay.info["virtual_bytes"]}
                  for overlay in self.overlays if overlay.image.exists()]
        allocated = sum(item["allocated_bytes"] for item in images)
        fs = os.statvfs(self.root)
        free = fs.f_bavail * fs.f_frsize
        self.evidence["allocation"].append({"stage": stage, "time": time.time(), "images": images,
                                             "allocated_bytes": allocated, "available_bytes": free})
        self.flush()
        if allocated >= self.args.max_overlay_bytes or free < self.args.reserve_free_bytes:
            self.preserve = bool(self.checkpoint_intent)
            raise Failure("Capacity guard reached; owned child terminated and resources retained")

    def guard(self):
        if self.cleaning or time.monotonic() - self.last_guard < 5:
            return
        self.last_guard = time.monotonic()
        self.allocation("running")
        if self.checkpoint is not None and not self.checking_identity:
            self.checking_identity = True
            try:
                self.assert_checkpoint()
                self.assert_overlays()
            except BaseException:
                self.preserve = True
                raise
            finally:
                self.checking_identity = False

    def create_checkpoint(self):
        require(self.args.create_checkpoint, "Checkpoint creation requires --create-checkpoint")
        self.assert_source()
        require(self.checkpoint_identity(self.status(self.args.pool)) is None,
                "Checkpoint appeared before creation; refusing adoption")
        self.checkpoint_intent = {"source_guid": self.source_guid, "intent_time": time.time(),
                                  "state": "creation-intent", "ownership_uncertain": True}
        self.evidence["checkpoint"] = self.checkpoint_intent
        self.flush()
        succeeded = False
        try:
            self.command("zpool", "checkpoint", self.args.pool)
            succeeded = True
        finally:
            self.checkpoint_intent["command_finished"] = time.time()
            # Reconcile even a timeout: the ioctl may have committed before CLI termination.
            try:
                self.assert_source()
                observed = self.checkpoint_identity(self.status(self.args.pool))
                self.checkpoint_intent["reconciled_identity"] = observed
                if observed is not None and succeeded and (
                        int(self.checkpoint_intent["intent_time"]) <= observed["start_time"] <=
                        int(self.checkpoint_intent["command_finished"])):
                    self.checkpoint = observed
                    self.checkpoint_intent.update(state="owned", identity=observed, ownership_uncertain=False)
                elif observed is None and not succeeded:
                    self.checkpoint_intent.update(state="creation-failed-no-checkpoint", ownership_uncertain=False)
                else:
                    self.preserve = True
                    self.checkpoint_intent["state"] = "ambiguous-preserve"
            except BaseException as error:
                self.preserve = True
                self.checkpoint_intent["reconciliation_error"] = str(error)
            self.flush()
        require(self.checkpoint is not None, "Checkpoint ownership was not established; preserve lease")
        txg = self.checkpoint_txg()
        if txg is not None:
            self.checkpoint["txg"] = txg
        self.checkpoint_intent["txg_observation"] = txg
        self.flush()
        self.assert_checkpoint()

    def prepare(self, leaves):
        directory = self.root / "overlay-images"
        devices = self.root / "overlay-devices"
        directory.mkdir()
        devices.mkdir()
        self.evidence["resources"].update(images=str(directory), devices=str(devices))
        self.flush()
        if not any(Path("/sys/class/block").glob("nbd[0-9]*")):
            self.command("modprobe", "nbd", "nbds_max=16", "max_part=0")
        for index, backing in enumerate(leaves):
            self.assert_checkpoint()
            overlay = RawOverlay(self, backing, directory / ("leaf-%02d.qcow2" % index))
            self.overlays.append(overlay)
            overlay.create()
            overlay.attach()
            (devices / ("leaf-%02d" % index)).symlink_to(overlay.device)
        self.assert_overlays()
        self.assert_checkpoint()
        self.allocation("before-clone-helper")
        name = "ddt_actual_" + uuid.uuid4().hex[:16]
        self.clone_started = True
        self.evidence["clone_preparation"] = {"source_guid": self.source_guid, "name": name,
                                               "devices": str(devices), "ownership_uncertain": True,
                                               "hide_volumes": True}
        self.flush()
        result = self.command(self.clone_helper, "--source-guid", self.source_guid,
                              "--devices", devices, "--name", name, "--checkpoint", "--hide-volumes",
                              timeout=None)
        guids = re.findall(r"^clone_guid=(\d+)\s*$", result.stdout, re.MULTILINE)
        require(len(guids) == 1 and int(guids[0]) and guids[0] != self.source_guid,
                "Clone helper did not establish a distinct nonzero pool GUID")
        clone = ActualClone(self)
        clone.name, clone.guid, clone.devices = name, guids[0], devices
        clone.directory.mkdir(parents=True)
        altroot = clone.directory / "altroot"
        altroot.mkdir()
        clone.created = True
        clone.info.update(name=name, guid=clone.guid, altroot=str(altroot), devices=str(devices))
        self.clone = clone
        self.evidence["clone_preparation"].update(clone_guid=clone.guid, ownership_uncertain=False)
        self.flush()
        self.assert_checkpoint()

    def import_clone(self):
        clone = self.clone
        require(clone is not None and clone.guid != self.source_guid, "Cannot import source as clone")
        self.assert_checkpoint()
        self.assert_overlays()
        clone.info["import_intent"] = True
        self.flush()
        try:
            self.command("zpool", "import", "-N", "-R", clone.info["altroot"], "-d", clone.devices,
                         "-o", "cachefile=none", clone.guid)
        finally:
            # Probe before cleanup even when import timed out or was interrupted.
            result = self.command("zpool", "get", "-Hp", "-o", "value", "guid", clone.name, expect=None)
            if result.returncode == 0:
                require(result.stdout.strip() == clone.guid, "Clone import name has another GUID")
                self.clone_exported = False
                clone.info["imported"] = True
                self.flush()
        clone.assert_owned()
        require(clone.property("checkpoint") in ("-", "0"), "Clone still has an unconsumed checkpoint")
        clone.hidden_volumes()

    def export_clone(self):
        self.clone.export()
        self.clone_exported = True
        self.clone.info["imported"] = False
        self.flush()

    def convert(self, mode):
        clone = self.clone
        require(self.clone_exported and clone.guid != self.source_guid, "Converter must target exported owned clone")
        self.assert_checkpoint()
        self.assert_overlays()
        args = [self.converter, mode, "--pool-guid", clone.guid, "--search-dir", str(clone.devices),
                "--batch-size", "65536"]
        if mode == "--convert":
            args.append("--fenced")
        self.command(*args, timeout=None)

    def inspect_layout(self, converted):
        clone = self.clone
        clone.assert_owned()
        directory = clone.zdb("-dddd", "1")
        checksums = set(re.findall(r"^\s*DDT-([\w-]+)-zap-(?:unique|duplicate)\s*=", directory, re.MULTILINE))
        checksums.update(name for name in re.findall(r"^\s*DDT-([\w-]+)\s*=", directory, re.MULTILINE)
                         if name != "statistics" and not name.startswith("log-") and
                         not name.endswith(("-zap-unique", "-zap-duplicate", "-zap-ditto")))
        require(checksums, "No actual DDT table was discovered")
        if not converted:
            self.evidence["baseline_ddt_checksums"] = sorted(checksums)
            self.flush()
            return
        require(checksums == set(self.evidence["baseline_ddt_checksums"]), "DDT checksum table set changed")
        require(not re.search(r"^\s*DDT-[\w-]+-zap-(?:unique|duplicate)\s*=", directory, re.MULTILINE),
                "Legacy DDT objects remain after full conversion")
        clone.layout(1, 3, tuple(sorted(checksums)))

    def verify_exported_clone(self):
        clone = self.clone
        require(self.clone_exported and clone.guid and clone.guid != self.source_guid,
                "zdb must target the exported owned clone")
        self.assert_checkpoint()
        self.assert_overlays()
        # An owned empty cache suppresses default/auto-selected pool caches.
        cache = self.root / "zdb-empty.cache"
        with cache.open("xb") as stream:
            stream.flush()
            os.fsync(stream.fileno())
        argv = ["zdb", "-U", str(cache), "-e", "-p", str(clone.devices), "-bc", clone.name]
        proof = {"argv": argv, "pool_guid": clone.guid, "exported": True,
                 "command_index": len(self.evidence["commands"]), "completed": False,
                 "metadata_checksums": False, "reference_allocation": False,
                 "userdata_checksums": "Representative file hashes only"}
        self.evidence["zdb_verification"] = proof
        self.flush()
        # One -c checks metadata only; omitting -L retains DDT refcount and
        # spacemap leak checks while all block pointers are traversed.
        result = self.command(*argv, expect=None, timeout=None)
        proof["returncode"] = result.returncode
        self.flush()
        require(result.returncode == 0, "Exported clone zdb verification failed; see command logs")
        require(re.search(r"^Traversing all blocks to verify metadata checksums "
                          r"and verify nothing leaked \.\.\.$", result.stdout, re.MULTILINE),
                "zdb did not establish metadata-checksum traversal with leak tracking")
        require(re.search(r"^\s*No leaks \(block sum matches space maps exactly\)\s*$",
                          result.stdout, re.MULTILINE),
                "zdb did not establish exact block-allocation agreement")
        counts = re.findall(r"^\s*bp count:\s+(\d+)\s*$", result.stdout, re.MULTILINE)
        require(len(counts) == 1 and int(counts[0]) > 0,
                "zdb did not report a nonempty completed block traversal")
        require(not re.search(r"^(?:block claim error|DDT leak:|BRT leak:|leaked space:|"
                              r"block traversal size |Error counts:)",
                              result.stdout + "\n" + result.stderr, re.MULTILINE),
                "zdb reported reference, allocation, or checksum errors")
        self.assert_checkpoint()
        self.assert_overlays()
        proof.update(completed=True, metadata_checksums=True, reference_allocation=True,
                     block_pointer_count=int(counts[0]),
                     allocation_result="No leaks (block sum matches space maps exactly)")
        self.flush()

    def validate(self):
        with self.case("actual-checkpoint-cow-conversion"):
            leaves = self.preflight()
            self.create_checkpoint()
            self.prepare(leaves)
            self.import_clone()
            self.inspect_layout(False)
            self.clone.baseline()
            self.export_clone()
            self.convert("--check")
            self.convert("--convert")
            self.allocation("after-full-conversion")
            self.import_clone()
            self.inspect_layout(True)
            self.clone.verify_samples()
            self.clone.hidden_volumes()
            self.export_clone()
            self.verify_exported_clone()
            self.import_clone()
            self.clone.verify_samples()
            self.clone.hidden_volumes()
            self.assert_checkpoint()
            self.export_clone()
            self.allocation("validated-exported-clone")

    def cleanup(self):
        self.cleaning = True
        errors = []
        if self.preserve:
            errors.append("Safety ambiguity or capacity limit: preserving resources and source checkpoint lease")
        for child in list(self.command_children):
            if child.poll() is None:
                errors.append("Owned command reader is still running")
            else:
                self.command_children.pop(child, None)
        if self.clone_started and self.clone is None:
            errors.append("Clone helper did not establish a new GUID; preserving all backing resources")
        if not errors and self.clone is not None and not self.clone_exported:
            try:
                self.export_clone()
            except BaseException as error:
                errors.append("Owned clone export: " + str(error))
        if not errors:
            for overlay in reversed(self.overlays):
                try:
                    # Includes qemu processes that failed before the NBD attach completed.
                    overlay.disconnect()
                    require(overlay.process is None or overlay.process.poll() is not None,
                            "qemu-nbd reader is still alive")
                except BaseException as error:
                    errors.append("Owned overlay detach: " + str(error))
        if not errors:
            devices = self.root / "overlay-devices"
            for index, overlay in enumerate(self.overlays):
                try:
                    link = devices / ("leaf-%02d" % index)
                    if link.is_symlink():
                        require(link.readlink() == overlay.device, "Overlay device link changed")
                        link.unlink()
                    else:
                        require(not link.exists(), "Unexpected overlay device link type")
                    overlay.retire()
                except BaseException as error:
                    errors.append("Owned overlay retirement: " + str(error))
            if not errors:
                if devices.exists():
                    fd = os.open(devices, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                self.evidence["resources"]["dependent_images_retired"] = True
                self.flush()
        if not errors and self.checkpoint is not None:
            try:
                self.assert_checkpoint()
                self.checkpoint_intent["state"] = "discard-intent"
                self.flush()
                self.command("zpool", "checkpoint", "-d", self.args.pool)
                self.assert_source()
                status = self.status(self.args.pool)
                state = status.get("checkpoint_stats", {}).get("state", "NONE")
                require(state in ("NONE", "DISCARDING"), "Checkpoint discard was not observed")
                self.checkpoint_intent.update(state="discard-requested", discard_state=state,
                                              readers_stopped=True)
                self.checkpoint = None
                self.flush()
            except BaseException as error:
                errors.append("Matching source checkpoint discard: " + str(error))
        if not errors and self.checkpoint_intent and self.checkpoint_intent.get("ownership_uncertain"):
            errors.append("Checkpoint creation ownership is ambiguous; preserving source lease")
        for overlay in self.overlays:
            overlay.capture_log()
        if self.source_lease is not None:
            if not errors and self.lease_owned:
                os.ftruncate(self.source_lease, 0)
                os.fsync(self.source_lease)
            os.close(self.source_lease)
            self.source_lease = None
        if getattr(self, "checkpoint_history", None) is not None:
            self.checkpoint_history.close()
            self.checkpoint_history = None
        self.evidence.update(cleanup_errors=errors, retained_work_directory=str(self.root),
                             resources_retained=bool(errors))
        self.flush()
        return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pool", required=True)
    parser.add_argument("--converter", type=Path, required=True)
    parser.add_argument("--clone-helper", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--create-checkpoint", action="store_true",
                        help="Explicitly authorize creation and matching discard of one source checkpoint")
    parser.add_argument("--max-overlay-bytes", type=int, default=512 * GIB)
    parser.add_argument("--reserve-free-bytes", type=int, default=64 * GIB)
    args = parser.parse_args()
    if not args.create_checkpoint:
        parser.error("--create-checkpoint is required; existing checkpoints are never adopted")
    if os.geteuid() != 0 or sys.version_info < (3, 12) or not hasattr(os, "unshare"):
        parser.error("root and Python 3.12+ with mount namespace support are required")
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:-]*", args.pool):
        parser.error("--pool must be a pool name, not a dataset or option")
    for label in ("converter", "clone_helper"):
        path = getattr(args, label)
        if not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK):
            parser.error("--" + label.replace("_", "-") + " must be an absolute executable file")
        setattr(args, label, path.resolve())
    if not args.work_dir.is_dir() or args.max_overlay_bytes <= 0 or args.reserve_free_bytes < 0:
        parser.error("An existing work directory and positive capacity limit are required")
    args.work_dir = args.work_dir.resolve()
    work_status = args.work_dir.stat()
    if work_status.st_uid != 0 or work_status.st_mode & 0o022:
        parser.error("--work-dir must be root-owned and not writable by group or others")
    if any(char.isspace() for char in str(args.work_dir)):
        parser.error("--work-dir must not contain whitespace, for unambiguous mount ownership checks")
    for executable in ("zpool", "zfs", "zdb", "qemu-img", "qemu-nbd", "mount", "umount"):
        if shutil.which(executable) is None:
            parser.error("Required executable not found: " + executable)
    os.umask(0o077)
    os.unshare(os.CLONE_NEWNS)
    subprocess.run(["mount", "--make-rprivate", "/"], input=b"", check=True)
    h = ActualHarness(args)
    print("Evidence: " + str(h.evidence_path), flush=True)
    handlers = {}
    outcome = 1

    def interrupted(signum, frame):
        raise KeyboardInterrupt("Validator received signal %d" % signum)

    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            handlers[signum] = signal.signal(signum, interrupted)
        h.command("zfs", "version")
        h.validate()
        h.evidence["status"] = "passed"
        outcome = 0
    except BaseException as error:
        h.evidence.update(status="failed", error=str(error), traceback=traceback.format_exc())
        print("FAIL: " + str(error), file=sys.stderr, flush=True)
    finally:
        for signum in handlers:
            signal.signal(signum, signal.SIG_IGN)
        try:
            errors = h.cleanup()
        except BaseException as error:
            errors = ["Cleanup ambiguity: " + str(error)]
            h.evidence.update(cleanup_errors=errors, retained_work_directory=str(h.root))
        if errors:
            outcome = 1
            h.evidence["status"] = "failed"
            print("Cleanup: " + "; ".join(errors), file=sys.stderr, flush=True)
        h.evidence["finished"] = time.time()
        h.flush()
        for signum, handler in handlers.items():
            signal.signal(signum, handler)
    print(("PASS" if outcome == 0 else "FAIL") + "; evidence: " + str(h.evidence_path), flush=True)
    return outcome


if __name__ == "__main__":
    sys.exit(main())
