#!/usr/bin/env python3
"""Validate conversion through sparse overlays of an owned, exported legacy pool.

Requires root, ZFS, qemu-img and qemu-nbd. Only newly created disposable pools
are accepted; the raw backing files remain exported until overlay validation
and whole-device hash comparison finish. Evidence survives beside the work dir.
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
import subprocess
import sys
import time
import traceback
import uuid

from integration import Failure, Harness, Pool, require


MIB = 1024 * 1024


def file_hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(MIB), b""):
            digest.update(chunk)
    return digest.hexdigest()


def process_identity(pid):
    try:
        # comm can contain spaces and parentheses; starttime is field 22.
        fields = Path("/proc/%d/stat" % pid).read_text().rsplit(")", 1)[1].split()
        return fields[19]
    except (FileNotFoundError, ProcessLookupError):
        return None


def process_group(pid):
    try:
        status = Path("/proc/%d/status" % pid).read_text()
    except (FileNotFoundError, ProcessLookupError):
        return None
    match = re.search(r"^Tgid:\s*(\d+)$", status, re.MULTILINE)
    return int(match.group(1)) if match else None


class Overlay:
    """One locked NBD attachment, with an owned foreground qemu-nbd process."""

    def __init__(self, harness, backing, image):
        self.h = harness
        self.backing = backing.resolve(strict=True)
        self.image = image.resolve()
        self.backing_identity = self.identity(self.backing)
        self.device = None
        self.lock = None
        self.process = None
        self.process_start = None
        self.log = None
        self.info = {"backing": str(self.backing), "image": str(self.image),
                     "backing_identity": self.backing_identity, "attached": False}
        self.h.evidence["overlays"].append(self.info)

    @staticmethod
    def identity(path):
        value = path.stat()
        return [value.st_dev, value.st_ino, value.st_size]

    @staticmethod
    def state(device):
        directory = Path("/sys/class/block") / device.name
        try:
            pid = (directory / "pid").read_text().strip()
        except FileNotFoundError:
            pid = ""
        return {"pid": int(pid) if pid else None,
                "sectors": int((directory / "size").read_text().strip()),
                "holders": sorted(path.name for path in (directory / "holders").iterdir())}

    def create(self):
        require(stat.S_ISREG(self.backing.stat().st_mode), "Backing must be an owned regular file")
        self.h.command("qemu-img", "create", "-f", "qcow2", "-F", "raw",
                       "-b", self.backing, self.image)
        self.info["virtual_bytes"] = self.backing.stat().st_size
        self.info["initial_backing_sha256"] = file_hash(self.backing)
        self.h.flush()

    def reserve(self):
        devices = (path for path in Path("/sys/class/block").glob("nbd[0-9]*")
                   if re.fullmatch(r"nbd\d+", path.name))
        for entry in sorted(devices, key=lambda path: int(path.name[3:])):
            device = Path("/dev") / entry.name
            if not device.exists() or not stat.S_ISBLK(device.stat().st_mode):
                continue
            fd = os.open("/run/lock/convert-ddt-" + entry.name + ".lock",
                         os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
            try:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    continue
                before = self.state(device)
                if before["pid"] is not None or before["sectors"] or before["holders"]:
                    continue
                self.device = device.resolve(strict=True)
                self.lock = fd
                fd = None
                self.info.update(device=str(self.device), free_state=before,
                                 device_number=device.stat().st_rdev)
                self.h.flush()
                return
            finally:
                if fd is not None:
                    os.close(fd)
        raise Failure("No free whole NBD device; existing attachments were left untouched")

    def attach(self):
        self.reserve()
        self.log = self.image.with_suffix(".qemu-nbd.log").open("xb")
        argv = ["qemu-nbd", "--verbose", "--persistent", "--format=qcow2",
                "--connect=" + str(self.device), str(self.image)]
        self.info["qemu_argv"] = argv
        self.process = subprocess.Popen(argv, stdout=self.log, stderr=subprocess.STDOUT,
                                        env={**os.environ, "LC_ALL": "C"})
        self.process_start = process_identity(self.process.pid)
        self.info.update(qemu_pid=self.process.pid, qemu_starttime=self.process_start)
        self.h.flush()
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            require(self.process.poll() is None,
                    "Owned qemu-nbd exited during attachment; see " + str(self.log.name))
            state = self.state(self.device)
            if state["pid"] is not None and state["sectors"]:
                self.assert_owned()
                require(state["sectors"] * 512 == self.info["virtual_bytes"],
                        "NBD capacity differs from owned backing file")
                self.info.update(attached=True, attached_state=state)
                self.assert_readonly_backing()
                self.h.flush()
                return
            time.sleep(0.1)
        raise Failure("Timed out attaching owned NBD device")

    def assert_process(self):
        require(self.process is not None and self.process.poll() is None and
                self.process_start is not None and
                process_identity(self.process.pid) == self.process_start,
                "Owned qemu-nbd process identity is no longer established")

    def assert_owned(self):
        self.assert_process()
        require(self.device.stat().st_rdev == self.info["device_number"] and
                stat.S_ISBLK(self.device.stat().st_mode), "NBD device identity changed")
        state = self.state(self.device)
        require(state["pid"] is not None and process_group(state["pid"]) == self.process.pid,
                "NBD connection is not owned by the tracked qemu-nbd process")
        require(self.identity(self.backing) == self.backing_identity,
                "Backing file identity or size changed")

    def assert_readonly_backing(self):
        self.assert_owned()
        found = False
        for descriptor in Path("/proc/%d/fd" % self.process.pid).iterdir():
            try:
                if descriptor.resolve(strict=True) != self.backing:
                    continue
                flags = Path("/proc/%d/fdinfo/%s" %
                             (self.process.pid, descriptor.name)).read_text()
            except FileNotFoundError:
                continue
            match = re.search(r"^flags:\s*([0-7]+)$", flags, re.MULTILINE)
            require(match is not None and int(match.group(1), 8) & os.O_ACCMODE == os.O_RDONLY,
                    "qemu-nbd opened the raw backing file writable")
            found = True
        require(found, "Cannot prove qemu-nbd holds the exact raw backing file read-only")
        self.info["backing_open_readonly"] = True

    def capture_log(self):
        path = self.image.with_suffix(".qemu-nbd.log")
        self.info["qemu_log_path"] = str(path)
        try:
            self.info["qemu_log"] = path.read_text(errors="replace")
        except FileNotFoundError:
            self.info["qemu_log"] = ""
        except OSError as error:
            self.info["qemu_log_error"] = str(error)

    def disconnect(self):
        if self.device is None or self.info.get("disconnected"):
            return
        state = self.state(self.device)
        if state["pid"] is not None or state["sectors"]:
            self.assert_owned()
            require(not state["holders"], "Owned NBD still has device-mapper holders")
            self.h.command("qemu-nbd", "--disconnect", self.device)
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                state = self.state(self.device)
                if state["pid"] is None and not state["sectors"]:
                    break
                time.sleep(0.1)
            require(state["pid"] is None and not state["sectors"], "Owned NBD did not disconnect")
        if self.process is not None and self.process.poll() is None:
            self.assert_process()
            self.process.terminate()
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.assert_process()
                self.process.kill()
                self.process.wait(timeout=15)
        self.capture_log()
        if self.log is not None:
            self.log.close()
        if self.lock is not None:
            os.close(self.lock)
            self.lock = None
        self.info.update(attached=False, disconnected=True)
        self.h.flush()


class CopyPool(Pool):
    def __init__(self, harness, label):
        super().__init__(harness, label)
        self.snapshot_views = {}

    def mount_snapshots(self):
        self.assert_owned()
        for snapshot, relative in self.snapshot_views.items():
            target = self.mount / relative
            target.mkdir(parents=True, exist_ok=True)
            self.h.command("mount", "-t", "zfs", "-o", "ro", snapshot, target)

    def unmount_snapshots(self):
        mounts = {}
        for line in Path("/proc/self/mountinfo").read_text().splitlines():
            before, after = line.split(" - ", 1)
            mounts[before.split()[4]] = after.split()[:2]
        for snapshot, relative in reversed(list(self.snapshot_views.items())):
            target = str(self.mount / relative)
            if target in mounts:
                self.assert_owned()
                require(mounts[target] == ["zfs", snapshot],
                        "Snapshot view ownership changed: " + target)
                self.h.command("umount", target)

    def export(self):
        self.unmount_snapshots()
        super().export()

    def import_pool(self, mount=True):
        super().import_pool(mount=mount)
        if mount:
            self.mount_snapshots()

    def destroy(self):
        self.unmount_snapshots()
        super().destroy()


class CowHarness(Harness):
    def __init__(self, converter, clone_helper, parent):
        super().__init__(converter, parent)
        self.clone_helper = str(clone_helper)
        self.source = None
        self.clone = None
        self.clone_started = False
        self.clone_exported = True
        self.overlays = []
        self.evidence.update(clone_helper=self.clone_helper,
                             cases=[{"name": "exported-checkpoint-cow-conversion", "status": "not_run"}],
                             overlays=[], allocation=[],
                             coverage={"stable_base": "Checkpointed, exported backing files",
                                       "consumers": "Filesystems, copies, encryption, snapshots, clones"})
        self.flush()

    def assert_overlays(self):
        for overlay in self.overlays:
            overlay.assert_readonly_backing()

    def allocation(self, stage):
        images = [{"path": str(overlay.image),
                   "allocated_bytes": overlay.image.stat().st_blocks * 512,
                   "file_bytes": overlay.image.stat().st_size,
                   "virtual_bytes": overlay.info["virtual_bytes"]}
                  for overlay in self.overlays]
        allocated = sum(item["allocated_bytes"] for item in images)
        virtual = sum(item["virtual_bytes"] for item in images)
        self.evidence["allocation"].append({"stage": stage, "images": images,
                                             "allocated_bytes": allocated, "virtual_bytes": virtual,
                                             "allocated_fraction": allocated / virtual})
        self.flush()
        require(allocated < virtual // 8,
                "Overlay allocation exceeded one eighth of virtual capacity; sparse-copy bound failed")

    def import_clone(self):
        clone = self.clone
        self.assert_overlays()
        self.command("zpool", "import", "-N", "-R", clone.info["altroot"],
                     "-d", clone.devices, "-o", "cachefile=none", clone.guid)
        self.clone_exported = False
        clone.assert_owned()
        require(clone.property("checkpoint") in ("-", "0"),
                "Clone helper did not consume the overlay checkpoint")
        clone.zfs("mount", clone.name)
        for dataset in clone.keys:
            clone.zfs("load-key", dataset)
        for dataset in clone.datasets:
            clone.zfs("mount", dataset)
        expected_mounts = {clone.name: str(clone.mount)}
        expected_mounts.update({dataset: str(clone.mount / dataset.split("/", 1)[1])
                                for dataset in clone.datasets})
        mounted = self.command("zfs", "mount").stdout
        for dataset, path in expected_mounts.items():
            require(any(line.split() == [dataset, path] for line in mounted.splitlines()),
                    "Clone dataset was not mounted inside private altroot: " + dataset)
        clone.mount_snapshots()

    def export_clone(self):
        try:
            self.clone.export()
        except Failure:
            self.evidence["export_failure"] = {
                "mounts": [line for line in Path("/proc/self/mountinfo").read_text().splitlines()
                           if self.clone.name in line],
                "devices": {str(overlay.device): overlay.state(overlay.device)
                            for overlay in self.overlays},
            }
            self.flush()
            raise
        self.clone_exported = True

    def cleanup(self):
        errors = []
        if self.clone_started and self.clone is None:
            errors.append("Clone preparation did not establish its new GUID; preserving overlays and backing files")
        if not errors and self.clone is not None:
            try:
                self.assert_overlays()
                if self.clone_exported:
                    self.import_clone()
                self.clone.destroy()
            except BaseException as error:
                errors.append("Clone cleanup: " + str(error))
        if not errors:
            for overlay in reversed(self.overlays):
                try:
                    overlay.disconnect()
                except BaseException as error:
                    errors.append("NBD cleanup: " + str(error))
        if not errors and self.source is not None:
            try:
                self.source.destroy()
            except BaseException as error:
                errors.append("Source cleanup: " + str(error))
        for overlay in self.overlays:
            overlay.capture_log()
        self.evidence["cleanup_errors"] = errors
        if errors:
            self.evidence["retained_work_directory"] = str(self.root)
        else:
            shutil.rmtree(self.root)
        self.flush()
        return errors


def populate(pool):
    pairs = []
    for name, checksum, copies, encrypted in (("sha256", "sha256", 1, False),
                                              ("sha512", "sha512", 1, False),
                                              ("copies2", "sha256", 2, False),
                                              ("copies3", "sha256", 3, False),
                                              ("encrypted", "sha256", 1, True)):
        directory = pool.dataset(name, checksum=checksum, copies=copies, encrypted=encrypted)
        original = pool.write(directory / "original", name + "-data", blocks=32)
        pool.duplicate(original, directory / "duplicate")
        pool.write(directory / "unique", name + "-unique", blocks=8)
        pairs.append((original, directory / "post-conversion-duplicate"))
    snapshot = pool.name + "/sha256@before"
    pool.zfs("snapshot", snapshot)
    clone = pool.name + "/clone"
    pool.zfs("clone", "-o", "mountpoint=" + str(pool.mount / "clone"), snapshot, clone)
    pool.datasets.append(clone)
    # Explicit snapshot mounts stay inside the test's private mount namespace.
    pool.snapshot_views[snapshot] = Path("snapshot-views/sha256-before")
    pool.mount_snapshots()
    for name in ("original", "duplicate", "unique"):
        expected = pool.manifest[str(pool.mount / "sha256" / name)]
        pool.manifest[str(pool.mount / pool.snapshot_views[snapshot] / name)] = expected
        pool.manifest[str(pool.mount / "clone" / name)] = expected
    pool.sync()
    pool.layout(0, 0, ("sha256", "sha512"))
    entries = pool.zdb("-DDDDD")
    variants = {int(value) for value in re.findall(r"\brefcnt \d+ phys (\d+)\b", entries)}
    require({1, 2, 3}.issubset(variants), "Fixture lacks eligible copies=1/2/3 legacy DDT entries")
    require(pool.dedup_ratio() > 1.0, "Fixture did not create actual deduplication")
    pool.verify()
    return pairs


def prepare_clone(h, source):
    directory = h.root / "overlay-images"
    directory.mkdir()
    devices = h.root / "overlay-devices"
    devices.mkdir()
    if not any(Path("/sys/class/block").glob("nbd[0-9]*")):
        require(shutil.which("modprobe") is not None, "NBD module is absent and modprobe is unavailable")
        h.command("modprobe", "nbd", "nbds_max=16", "max_part=0")
    for backing in sorted(source.devices.iterdir()):
        overlay = Overlay(h, backing, directory / (backing.stem + ".qcow2"))
        h.overlays.append(overlay)
        overlay.create()
        overlay.attach()
        (devices / backing.name).symlink_to(overlay.device)
    require(len(h.overlays) == 2, "Expected exactly the two owned mirror file vdevs")
    h.assert_overlays()
    h.allocation("before-clone-preparation")
    name = "ddt_cow_" + uuid.uuid4().hex[:16]
    h.clone_started = True
    h.evidence["clone_preparation"] = {"source_guid": source.guid, "new_name": name,
                                        "devices": str(devices), "checkpoint": True,
                                        "ownership_uncertain": True}
    h.flush()
    result = h.command(h.clone_helper, "--source-guid", source.guid, "--devices", devices,
                       "--name", name, "--checkpoint", timeout=1800)
    guids = re.findall(r"^clone_guid=(\d+)\s*$", result.stdout, re.MULTILINE)
    require(len(guids) == 1 and guids[0] != source.guid and int(guids[0]) != 0,
            "Clone helper did not report exactly one distinct nonzero GUID")
    clone = CopyPool(h, "converted-clone")
    clone.name = name
    clone.guid = guids[0]
    clone.devices = devices
    altroot = clone.directory / "altroot"
    altroot.mkdir(parents=True)
    clone.mount = altroot / source.mount.relative_to("/")
    clone.created = True
    clone.datasets = [name + dataset[len(source.name):] for dataset in source.datasets]
    clone.keys = [name + dataset[len(source.name):] for dataset in source.keys]
    clone.snapshot_views = {name + snapshot[len(source.name):]: relative
                            for snapshot, relative in source.snapshot_views.items()}
    clone.manifest = {str(clone.mount / Path(path).relative_to(source.mount)): digest
                      for path, digest in source.manifest.items()}
    clone.info.update(name=name, guid=clone.guid, altroot=str(altroot),
                      devices=str(devices), ownership_uncertain=False)
    h.clone = clone
    h.evidence["clone_preparation"].update(clone_guid=clone.guid, ownership_uncertain=False)
    h.flush()
    h.allocation("after-clone-preparation")
    return clone


def inspect_detached_overlays(h):
    for overlay in h.overlays:
        require(not overlay.info["attached"], "Image inspection requires disconnected owned NBD")
        chain = json.loads(h.command("qemu-img", "info", "--output=json", "--backing-chain",
                                     overlay.image).stdout)
        require(len(chain) == 2 and chain[0]["format"] == "qcow2" and chain[1]["format"] == "raw",
                "Unexpected qcow2 backing chain")
        require(Path(chain[0]["full-backing-filename"]).resolve() == overlay.backing and
                Path(chain[1]["filename"]).resolve() == overlay.backing,
                "Overlay no longer references its exact owned raw backing file")
        require(chain[0]["virtual-size"] == overlay.info["virtual_bytes"],
                "Overlay virtual size changed")
        extents = json.loads(h.command("qemu-img", "map", "--output=json", overlay.image).stdout)
        backing_bytes = sum(extent["length"] for extent in extents
                            if extent.get("depth", 0) > 0 and extent.get("data") and not extent.get("zero"))
        require(backing_bytes > 0, "Overlay map contains no readable data supplied by the backing image")
        overlay.info.update(backing_chain=chain, backing_data_bytes=backing_bytes,
                            final_backing_sha256=file_hash(overlay.backing))
        h.flush()
        require(overlay.info["final_backing_sha256"] == overlay.info["initial_backing_sha256"],
                "Exported original backing content changed during overlay conversion")
    h.allocation("final-detached-images")


def validate(h):
    with h.case("exported-checkpoint-cow-conversion"):
        source = CopyPool(h, "original")
        h.source = source
        source.create()
        pairs = populate(source)
        source.enable()
        source.sync()
        source.zp("checkpoint")
        source.export()
        h.evidence["original"] = {"guid": source.guid, "name": source.name,
                                   "baseline_files": dict(source.manifest),
                                   "exported_checkpoint": True}
        h.flush()
        clone = prepare_clone(h, source)
        # Check the clone's baseline contents before conversion.
        h.import_clone()
        clone.layout(0, 0, ("sha256", "sha512"))
        clone.verify()
        h.export_clone()
        h.assert_overlays()
        clone.convert("--check")
        clone.convert("--convert", "--fenced")
        h.allocation("after-conversion")
        h.import_clone()
        clone.layout(1, 3, ("sha256", "sha512"))
        clone.verify()
        clone.scrub()
        clone_pairs = [(clone.mount / original.relative_to(source.mount),
                        clone.mount / target.relative_to(source.mount)) for original, target in pairs]
        clone.addref_free(clone_pairs)
        snapshot = clone.name + "/sha256@before"
        clone_dataset = clone.name + "/clone"
        clone.zfs("destroy", clone_dataset)
        clone.datasets.remove(clone_dataset)
        clone.unmount_snapshots()
        clone.snapshot_views.clear()
        clone.zfs("destroy", snapshot)
        for path in list(clone.manifest):
            if (Path(path).is_relative_to(clone.mount / "clone") or
                    Path(path).is_relative_to(clone.mount / "snapshot-views")):
                del clone.manifest[path]
        for dataset in ("sha256", "sha512", "copies2", "copies3", "encrypted"):
            for filename in ("original", "duplicate"):
                path = clone.mount / dataset / filename
                path.unlink()
                del clone.manifest[str(path)]
        clone.sync()
        clone.scrub()
        clone.verify()
        h.export_clone()
        h.import_clone()
        clone.layout(1, 3, ("sha256", "sha512"))
        clone.verify()
        h.export_clone()
        h.allocation("after-reference-mutations")
        # Reclaim the clone before comparing its backing files.
        h.import_clone()
        clone.destroy()
        h.clone = None
        h.clone_started = False
        for overlay in reversed(h.overlays):
            overlay.disconnect()
        inspect_detached_overlays(h)
        source.import_pool()
        source.layout(0, 0, ("sha256", "sha512"))
        source.verify()
        source.scrub()
        h.evidence["original"].update(still_legacy=True, hashes_match=True,
                                      backing_files_unchanged=True)
        h.flush()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--converter", type=Path, required=True, help="Absolute built converter executable")
    parser.add_argument("--clone-helper", type=Path, required=True, help="Absolute test-only clone-pool executable")
    parser.add_argument("--work-dir", type=Path, required=True, help="Existing directory for owned disposable resources")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("root is required")
    for option, path in (("--converter", args.converter), ("--clone-helper", args.clone_helper)):
        if not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK):
            parser.error(option + " must name an absolute executable file")
    if not args.work_dir.is_dir():
        parser.error("--work-dir must name an existing directory")
    for executable in ("zpool", "zfs", "zdb", "qemu-img", "qemu-nbd", "mount"):
        if shutil.which(executable) is None:
            parser.error("required executable not found: " + executable)
    # Keep fixture mounts private to this test process and its children.
    if not hasattr(os, "unshare"):
        parser.error("Python 3.12 or newer is required for mount isolation")
    os.unshare(os.CLONE_NEWNS)
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    h = CowHarness(args.converter.resolve(), args.clone_helper.resolve(), args.work_dir.resolve())
    print("Evidence: " + str(h.evidence_path), flush=True)
    outcome = 1
    handlers = {}

    def interrupted(signum, frame):
        raise KeyboardInterrupt("Harness received signal %d" % signum)

    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            handlers[signum] = signal.signal(signum, interrupted)
        h.command("zfs", "version")
        validate(h)
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
            errors = ["Cleanup aborted; preserving uncertain resources: " + str(error)]
            h.evidence.update(cleanup_errors=errors, retained_work_directory=str(h.root))
        if errors:
            h.evidence["status"] = "failed"
            outcome = 1
            print("Cleanup: " + "; ".join(errors), file=sys.stderr, flush=True)
        h.evidence["finished"] = time.time()
        h.flush()
        for signum, handler in handlers.items():
            signal.signal(signum, handler)
    print("%s; evidence: %s" % ("PASS" if outcome == 0 else "FAIL", h.evidence_path), flush=True)
    return outcome


if __name__ == "__main__":
    sys.exit(main())
