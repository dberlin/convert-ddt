#!/usr/bin/env python3
"""Fixed, destructive consumer proof on freshly owned disposable FDT pools only.

Run as root with the pinned OpenZFS 2.4.4-1 kernel/userspace. This is not fuzzing.
No caller-supplied pool or vdev is accepted. Missing physical preconditions,
unsupported encryption/BRT/history, and unreached fault hooks fail, never skip.
Native stock zdb, not dedup-fdt's report, supplies the allocation/DDT oracle.
"""

import argparse
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import time
import traceback

from integration import Failure, Harness, require
from disposable_pool import DisposablePool, digest, image_hash, payload


MIB = 1024 * 1024
BLOCK = 128 * 1024
SEED = 20261102
PHASES = ("data-prepared", "flat-published")
ADMISSION_PHASE = "import-admitted"
# Full native BP text is requested with -bbbbbb; compact -dddddd alone hides D.
FULL_BP = re.compile(
    r"(?P<dvas>(?:DVA\[\d+\]=<\d+:[0-9a-f]+:[0-9a-f]+>\s+)+)"
    r"(?P<crypto>salt=[0-9a-f]+ iv=[0-9a-f]+:[0-9a-f]+\s+)?"
    r"\[L(?P<level>\d+) (?P<type>[^\]]+)\] (?P<flags>.*?) "
    r"size=(?P<logical>[0-9a-f]+)L/(?P<physical>[0-9a-f]+)P "
    r"birth=(?P<birth>\d+)L/(?P<physical_birth>\d+)P fill=(?P<fill>\d+) "
    r"cksum=(?P<checksum>[0-9a-f:]+)"
)


def parse_bp(text):
    match = FULL_BP.search(text)
    require(match is not None, "Stock zdb did not expose a full physical BP: " + text)
    fields = match.groupdict()
    return {
        "dvas": re.findall(r"DVA\[\d+\]=<(\d+:[0-9a-f]+:[0-9a-f]+)>", fields["dvas"]),
        "physical_birth": int(fields["physical_birth"]),
        "logical_birth": int(fields["birth"]),
        "level": int(fields["level"]),
        "type": fields["type"],
        "fill": int(fields["fill"]),
        "logical_bytes": int(fields["logical"], 16),
        "physical_bytes": int(fields["physical"], 16),
        "checksum": fields["checksum"],
        "crypto": (fields["crypto"] or "").strip(),
        "dedup": "dedup" in fields["flags"].split(),
        "flags": fields["flags"],
    }


def physical(bp):
    return (tuple(bp["dvas"]), bp["physical_birth"])


def canonical(bp):
    return (physical(bp), bp["crypto"], bp["checksum"], bp["logical_bytes"],
            bp["physical_bytes"])


def fdt_membership(bp):
    # Native DDT keys retain checksum/MAC, sizes, compression and crypt bit.
    # Their synthetic zdb BP lacks the occurrence's IV2 (upper fill bits).
    return (physical(bp), bp["checksum"], bp["logical_bytes"],
            bp["physical_bytes"], tuple(bp["flags"].split()[:2]), bool(bp["crypto"]))


def assert_retained_allocations(before, after, label):
    require(set(before) == set(after), "Unselected object offsets changed: " + label)
    for offset, old in before.items():
        new = after[offset]
        require({key: value for key, value in new.items() if key != "logical_birth"} ==
                {key: value for key, value in old.items() if key != "logical_birth"},
                "Unselected physical/semantic BP changed: " + label + ":" + offset)
        require(new["logical_birth"] >= old["logical_birth"] > 0,
                "Invalid unselected logical-birth promotion: " + label + ":" + offset)


def validate_read_trace(events, expected_sources, *, required_phases=None):
    """Prove actual native read overlap/order, not configured worker intent."""
    required_phases = required_phases or {"hashing", "verifying"}
    starts, ends, windows = {}, {}, {}
    for event in events:
        require(event.get("event") in ("submit", "complete"), "Unknown native read trace event")
        identity = (event.get("pass", 0), event["phase"], event["window"], event["seq"])
        target = starts if event["event"] == "submit" else ends
        require(identity not in target, "Duplicate native read trace identity")
        target[identity] = event
        if event["event"] == "submit":
            windows.setdefault(identity[:3], []).append(event)
    require(starts and set(starts) == set(ends), "Unfinished or absent native checked reads")
    phases = {key[1] for key in starts}
    require(required_phases <= phases, "Missing actual native read phase: " + str(required_phases - phases))
    observed, timeline = set(), []
    for identity, start in starts.items():
        end = ends[identity]
        address = tuple(start[key] for key in ("top_vdev", "offset", "birth"))
        require(all(end[key] == start[key] for key in ("top_vdev", "offset", "birth")),
                "Native completion address changed")
        require(end["error"] == 0 and end["time_ns"] > start["time_ns"],
                "Native checked read failed or has invalid timestamps")
        if identity[1] in ("hash", "hashing"):
            observed.add(address)
        timeline.extend(((start["time_ns"], 1), (end["time_ns"], -1)))
    require(expected_sources <= observed, "Selected source allocation absent from actual hash reads")
    largest_window = 0
    for identity, reads in windows.items():
        reads.sort(key=lambda event: (event["time_ns"], event["seq"]))
        addresses = [tuple(event[key] for key in ("top_vdev", "offset", "birth")) for event in reads]
        require(addresses == sorted(addresses), "Native payload reads dispatched in non-DVA order: " + str(identity))
        limits = {event["window_limit"] for event in reads}
        require(len(limits) == 1 and 0 < len(reads) <= next(iter(limits)) <= 64,
                "Native read window exceeded its explicit bounded capacity")
        largest_window = max(largest_window, len(reads))
    for pass_id in {key[0] for key in starts}:
        reads = sorted((event for key, event in starts.items()
                        if key[0] == pass_id and key[1] in ("hash", "hashing")),
                       key=lambda event: (event["time_ns"], event["seq"]))
        addresses = [tuple(event[key] for key in ("top_vdev", "offset", "birth"))
                     for event in reads]
        require(addresses == sorted(addresses), "Hash windows do not form a physical-order pass")
    active = maximum = 0
    # Completions sort first on ties: touching intervals are not overlap.
    for _, change in sorted(timeline):
        active += change
        maximum = max(maximum, active)
        require(active >= 0, "Invalid native read lifetime")
    require(maximum >= 2, "No overlapping actual native checked reads")
    return {"reads": len(starts), "windows": len(windows), "max_window": largest_window,
            "max_outstanding": maximum, "phases": sorted(phases),
            "independent_source_allocations": len(expected_sources)}


class DedupHarness(Harness):
    def __init__(self, args):
        super().__init__(args.tool, args.work_dir)
        self.args = args
        cases = ["ordinary-selected-consumer", "resource-pressure-ordered", "native-ddt-quota"]
        if args.faults == "all":
            cases.extend(phase + "-" + kind for phase in PHASES for kind in ("term", "kill"))
            cases.append(ADMISSION_PHASE + "-kill")
        if args.case:
            require(all(name in cases for name in args.case), "Selected case requires --faults all")
            cases = list(dict.fromkeys(args.case))
        self.evidence.update(
            cases=[{"name": name, "status": "not_run"} for name in cases],
            coverage={
                "physical": "Independent full BPs, effective native DDT ownership and exact spacemap accounting",
                "consumer": "Kernel file/snapshot/clone/ZVOL bytes and properties, future writes and frees",
                "scope": "Explicit dedup-off descendants; unselected same-byte/BRT/outside-clone allocations fixed",
                "keys": "Two roots using identical wrapping key material but distinct native data keys",
                "faults": "SIGTERM/SIGKILL at durable pre/postpublication boundaries; SIGKILL with ACTIVE labels before MOS staging",
            },
            reproducible_command=shlex.join([
                "python3", str(Path(__file__).resolve()), "--tool", str(args.tool),
                "--work-dir", str(args.work_dir), "--faults", args.faults] +
                [value for name in (args.case or []) for value in ("--case", name)]),
        )
        self.flush()

    @property
    def command_journal(self):
        return self.evidence_path.with_suffix(".commands.jsonl")

    def flush(self):
        # Command streams live only in the append-only journal. Checkpoint the
        # compact index at boundaries/intervals, never once per growing output.
        signature = (self.current_case, self.evidence.get("status"), self.evidence.get("finished"),
                     tuple((item["name"], item["status"]) for item in self.evidence["cases"]),
                     tuple(pool.get("recovery_required") for pool in self.evidence["pools"]),
                     "cleanup_errors" in self.evidence, tuple(self.evidence.get("cleanup_errors", [])),
                     self.evidence.get("retained_work_directory"))
        now = time.monotonic()
        count = len(self.evidence["commands"])
        if (signature == getattr(self, "_checkpoint_signature", None) and
                now - getattr(self, "_checkpoint_time", 0) < 10 and
                count - getattr(self, "_checkpoint_commands", 0) < 64):
            return
        self.evidence["command_journal"] = str(self.command_journal)
        self.evidence["command_count"] = count
        super().flush()
        self._checkpoint_signature = signature
        self._checkpoint_time = now
        self._checkpoint_commands = count

    def command(self, *args, expect=0, timeout=300, env=None):
        argv = [str(arg) for arg in args]
        seq = len(self.evidence["commands"])
        item = {"case": self.current_case, "argv": argv, "started": time.time(), "journal_seq": seq}
        self.evidence["commands"].append(item)
        with self.command_journal.open("a") as journal:
            journal.write(json.dumps({**item, "event": "start"}) + "\n")
            journal.flush()
            try:
                result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        text=True, errors="replace", timeout=timeout,
                                        env={**os.environ, "LC_ALL": "C", **(env or {})})
            except subprocess.TimeoutExpired as error:
                streams = {name: (value.decode(errors="replace") if isinstance(value, bytes) else value or "")
                           for name, value in (("stdout", error.stdout), ("stderr", error.stderr))}
                item.update(timeout=timeout, finished=time.time())
                journal.write(json.dumps({**item, **streams, "event": "complete"}) + "\n")
                journal.flush()
                self.flush()
                raise Failure("Command timed out: " + shlex.join(argv)) from error
            item.update(returncode=result.returncode, finished=time.time(),
                        stdout_bytes=len(result.stdout.encode()), stderr_bytes=len(result.stderr.encode()))
            journal.write(json.dumps({**item, "event": "complete",
                                      "stdout": result.stdout, "stderr": result.stderr}) + "\n")
            journal.flush()
        self.flush()
        if expect is not None:
            require(result.returncode == expect,
                    "Command returned %d, expected %d: %s\n%s" %
                    (result.returncode, expect, shlex.join(argv), result.stderr))
        return result

    def fixture(self, name):
        pool = DedupPool(self, name, SEED)
        self.pools.append(pool)
        pool.create()
        return pool


class DedupPool(DisposablePool):
    """Reuse existing owned-device, kernel-history and exact-byte consumers only."""

    def create(self):
        super().create()
        # No legacy writes: the very first dedup write must create an FDT.
        self.enable()
        self.zp("set", "feature@block_cloning=enabled")
        self.selected = self.name + "/selected"
        self.zfs("create", "-o", "dedup=off", "-o", "compression=off",
                 "-o", "mountpoint=" + str(self.mount / "selected"), self.selected)
        self.datasets.append(self.selected)
        self.scratch = self.directory / "dedup-work"
        self.scratch.mkdir(mode=0o700)
        self.objects = {}
        self.groups = {}
        self.unselected = []
        self.info.update(physical_proofs=[], independent_accounting=[], preflight=[])
        self.memory_max = 128 * MIB
        self.disk_max = 512 * MIB
        self.read_trace = None

    def fs_fixed(self, relative, *, compression="off", encrypted=False, dedup="off"):
        self.dataset(relative, checksum=dedup, encrypted=encrypted)
        dataset = self.name + "/" + relative
        self.zfs("set", "compression=" + compression, "checksum=blake3", dataset)
        self.files[dataset] = {}
        return dataset

    def remember(self, dataset, filename, *, unselected=False):
        path = self.path(dataset, filename)
        self.objects[dataset + ":" + filename] = (dataset, path.stat().st_ino)
        if unselected:
            self.unselected.append(dataset + ":" + filename)
        return dataset + ":" + filename

    def put_scrambled(self, dataset, filename, data):
        """Force logical runs into reverse allocation chronology on real ZFS."""
        self.assert_owned()
        path = self.path(dataset, filename)
        path.parent.mkdir(parents=True, exist_ok=True)
        window = 4 * BLOCK
        with path.open("xb", buffering=0) as stream:
            for offset in reversed(range(0, len(data), window)):
                stream.seek(offset)
                stream.write(data[offset:offset + window])
                os.fsync(stream.fileno())
        self.files[dataset][filename] = data
        self.action("scrambled-write", dataset=dataset, file=filename,
                    size=len(data), sha256=digest(data), allocation_window_bytes=window)

    def create_native_quota_fixture(self):
        self.encrypted_groups = []
        self.shared_metadata = ()
        anchor = self.fs_fixed("anchor", dedup="blake3")
        common = payload(SEED, "quota-anchor", 8 * MIB)
        self.put(anchor, "canonical", common)
        self.anchor = self.remember(anchor, "canonical", unselected=True)
        self.sync()
        self.zp("set", "dedup_table_quota=1")
        require(self.property("dedup_table_quota") == "1", "Literal native DDT quota was not installed")
        for token in ("new-first", "existing-fdt", "new-last"):
            dataset = self.fs_fixed("selected/" + token)
            data = common if token == "existing-fdt" else payload(SEED, token, 8 * MIB)
            self.groups[token] = []
            for filename in ("a", "b"):
                self.put(dataset, filename, data)
                self.groups[token].append(self.remember(dataset, filename))
            if token != "existing-fdt":
                self.snapshot(dataset, "quota-history")
                for filename in ("a", "b"):
                    self.objects[dataset + "@quota-history:" + filename] = (
                        dataset + "@quota-history", self.path(dataset, filename).stat().st_ino)
        self.sync()
        self.info["native_ddt_quota"] = 1

    def fixture(self):
        # Every offset differs. Equal-offset matching cannot be faked by merging
        # just one repeated block, and incompressible savings exceed COW overhead.
        common = payload(SEED, "ordinary", 16 * MIB)
        anchor = self.fs_fixed("anchor", dedup="blake3")
        self.put(anchor, "canonical", common)
        self.anchor = self.remember(anchor, "canonical", unselected=True)
        plain = self.fs_fixed("selected/plain")
        for filename in ("a", "b"):
            self.put(plain, filename, common)
        self.snapshot(plain, "original")
        outside = self.clone(plain + "@original", "outside-clone")
        # The outside clone shares both original data and inherited metadata.
        # Its allocations must remain ordinary and physically fixed.
        for filename in ("a", "b"):
            self.remember(outside, filename, unselected=True)
        self.groups["existing-fdt"] = [self.remember(plain, name) for name in ("a", "b")]
        for filename in ("a", "b"):
            self.objects[plain + "@original:" + filename] = (
                plain + "@original", self.path(plain, filename).stat().st_ino)
        self.shared_metadata = (plain + "@original", outside)

        freeable = self.fs_fixed("selected/freeable")
        self.groups["retire-ordinary"] = []
        for filename in ("a", "b", "c", "d"):
            data = payload(SEED, "freeable", 16 * MIB)
            if self.info["label"] == "resource-pressure-ordered" and filename == "a":
                self.put_scrambled(freeable, filename, data)
            else:
                self.put(freeable, filename, data)
            self.groups["retire-ordinary"].append(self.remember(freeable, filename))
        self.snapshot(freeable, "retained")
        self.clone(freeable + "@retained", "selected/inside-clone")
        for filename in ("a", "b", "c", "d"):
            self.objects[freeable + "@retained:" + filename] = (
                freeable + "@retained", self.path(freeable, filename).stat().st_ino)
            self.remember(self.selected + "/inside-clone", filename)

        compressed = self.fs_fixed("selected/compressed", compression="lz4")
        self.groups["compressed"] = []
        for filename in ("a", "b"):
            self.put(compressed, filename, payload(SEED, "compressed", 2 * MIB, compressible=True))
            self.groups["compressed"].append(self.remember(compressed, filename))

        weak = self.fs_fixed("selected/weak-checksum")
        self.zfs("set", "checksum=fletcher4", weak)
        self.groups["weak-checksum"] = []
        for filename in ("a", "b"):
            self.put(weak, filename, payload(SEED, "weak-checksum", 2 * MIB))
            self.groups["weak-checksum"].append(self.remember(weak, filename))

        outside = self.fs_fixed("unselected")
        self.put(outside, "same-bytes", common)
        self.remember(outside, "same-bytes", unselected=True)
        self.put(plain, "brt-source", payload(SEED, "brt", 2 * MIB))
        self.sync()
        source = self.path(plain, "brt-source")
        target = self.path(outside, "brt-kept")
        with source.open("rb") as incoming, target.open("xb") as outgoing:
            # Linux's FICLONE ioctl rejects different dataset superblocks before
            # ZFS can admit them. copy_file_range reaches ZFS's cross-dataset
            # native clone path; the BP preconditions below reject byte fallback.
            remaining = source.stat().st_size
            while remaining:
                copied = os.copy_file_range(incoming.fileno(), outgoing.fileno(), remaining)
                require(copied > 0, "Short native cross-dataset block clone")
                remaining -= copied
            os.fsync(outgoing.fileno())
        self.files[outside]["brt-kept"] = self.files[plain]["brt-source"]
        self.brt_source = self.remember(plain, "brt-source")
        self.brt_kept = self.remember(outside, "brt-kept", unselected=True)
        self.put(plain, "brt-duplicate", self.files[plain]["brt-source"])
        self.groups["brt"] = [self.brt_source, self.remember(plain, "brt-duplicate")]
        # Pin the second ordinary candidate outside selection as well. There is
        # no clean selected-only source and no FDT anchor for this payload.
        self.sync()
        source = self.path(plain, "brt-duplicate")
        target = self.path(outside, "brt-second-kept")
        with source.open("rb") as incoming, target.open("xb") as outgoing:
            remaining = source.stat().st_size
            while remaining:
                copied = os.copy_file_range(incoming.fileno(), outgoing.fileno(), remaining)
                require(copied > 0, "Short second native cross-dataset block clone")
                remaining -= copied
            os.fsync(outgoing.fileno())
        self.files[outside]["brt-second-kept"] = self.files[plain]["brt-duplicate"]
        self.brt_second_kept = self.remember(outside, "brt-second-kept", unselected=True)
        require(self.property("feature@block_cloning") == "active", "Fixture has no actual BRT sharing")

        self.encrypted_groups = []
        for number in (1, 2):
            dataset = self.fs_fixed("selected/crypt" + str(number), compression="lz4", encrypted=True)
            group = []
            for filename in ("a", "b"):
                self.put(dataset, filename, payload(SEED, "encrypted", 2 * MIB, compressible=True))
                group.append(self.remember(dataset, filename))
            self.groups["crypto" + str(number)] = group
            self.encrypted_groups.append(group)
            self.snapshot(dataset, "encrypted-history")
            for filename in ("a", "b"):
                self.objects[dataset + "@encrypted-history:" + filename] = (
                    dataset + "@encrypted-history", self.path(dataset, filename).stat().st_ino)

        volume = self.selected + "/volume"
        self.zfs("create", "-s", "-V", "2M", "-b", "128K", "-o", "dedup=off",
                 "-o", "checksum=blake3", "-o", "compression=lz4", "-o", "volmode=dev",
                 "-o", "snapdev=visible", volume)
        data = payload(SEED, "volume", BLOCK) * 16
        self.put_volume(volume, data)
        self.snapshot(volume, "original")
        self.put_volume(volume, payload(SEED, "volume-new", BLOCK) + data[BLOCK:])
        self.objects[volume + ":data"] = (volume, 1)
        self.objects[volume + "@original:data"] = (volume + "@original", 1)
        self.sync()
        self.info["selected_datasets"] = [self.selected]
        self.info["groups"] = self.groups
        self.info["unselected_objects"] = self.unselected
        self.h.flush()

    def stable_metadata(self):
        metadata = super().stable_metadata()
        domains = {}
        for group in self.encrypted_groups:
            dataset = group[0].split(":", 1)[0]
            value = self.zfs("get", "-Hp", "-o", "value", "keyguid", dataset).stdout.strip()
            require(value.isdecimal() and int(value) > 0, "No native encrypted data-key GUID: " + dataset)
            domains[dataset] = value
        require(len(set(domains.values())) == len(self.encrypted_groups),
                "Identical wrapping keys did not establish two distinct native data-key domains")
        metadata["data_key_guids"] = domains
        return metadata

    def argv(self, mode="--dedup", *, keys=True, guid=None, fenced=True,
             memory_max=None, disk_max=None):
        args = [self.h.converter, mode, "--pool-guid", guid or self.guid,
                "--search-dir", str(self.devices), "--work-dir", str(self.scratch),
                "--dataset", self.selected, "--batch-size", "8", "--workers", "4",
                "--memory-max-bytes", str(self.memory_max if memory_max is None else memory_max),
                "--disk-max-bytes", str(self.disk_max if disk_max is None else disk_max),
                "--arc-max-bytes", str(64 * MIB)]
        if mode == "--dedup" and fenced:
            args.append("--fenced")
        if keys:
            args.extend(self.key_args())
        return args

    def dedup(self):
        self.exported()
        self.recovery_required = True
        self.info["recovery_required"] = True
        self.h.flush()
        env = {"DEDUP_FDT_READ_TRACE": str(self.read_trace)} if self.read_trace else None
        result = self.h.command(*self.argv(), expect=None, timeout=1800, env=env)
        self.last_output = result.stdout
        require(result.returncode == 0, "Offline dedup/recovery failed: " + result.stderr)
        self.recovery_required = False
        self.info["recovery_required"] = False
        self.exported()
        self.h.flush()

    def zdb(self, *options, timeout=1800):
        require(not self.recovery_required, "Refusing stock zdb during unfinished dedup ownership")
        self.exported()
        return self.h.command("zdb", "-U", self.cache, "-e", "-p", self.devices,
                              *options, timeout=timeout)

    def bp_proof(self, stage):
        result = {}
        root_bps = {}
        for label, (dataset, obj) in self.objects.items():
            # -b >= 6 expands BPs in the object dump; it does not replace the
            # separate whole-pool ownership traversal below.
            key = ["-K", str(self.directory / "encryption.key")] if "/crypt" in dataset else []
            output = self.zdb(*key, "-dddddd", "-bbbbbb", dataset, str(obj)).stdout
            roots = [line.split(", rootbp ", 1)[1] for line in output.splitlines() if ", rootbp " in line]
            require(len(roots) == 1, "No unique native objset root BP: " + dataset)
            root_bps[dataset] = parse_bp(roots[0])
            leaves = {}
            for line in output.splitlines():
                match = re.match(r"^\s*([0-9a-f]+)\s+L0\s+(DVA\[.*)$", line)
                if match:
                    offset = int(match.group(1), 16)
                    require(str(offset) not in leaves, "Duplicate native object offset")
                    leaves[str(offset)] = parse_bp(match.group(2))
            require(leaves, "No independent data BPs for " + label)
            result[label] = leaves
        metadata = {}
        for dataset in self.shared_metadata:
            output = self.zdb("-dddddd", "-bbbbbb", dataset, "0").stdout
            leaves = {}
            for line in output.splitlines():
                match = re.match(r"^\s*([0-9a-f]+)\s+L0\s+(DVA\[.*)$", line)
                if match:
                    leaves[match.group(1)] = parse_bp(match.group(2))
            require(leaves, "No independent inherited dnode leaves: " + dataset)
            metadata[dataset] = leaves
        ddt = self.zdb("-DDDDD", self.name).stdout
        layouts = re.findall(r"^DDT-([\w-]+): version=(\d+).*flags=(0x[0-9a-fA-F]+|\d+)", ddt, re.MULTILINE)
        require(layouts and all(int(version) == 1 and int(flags, 0) & 1
                               for _, version, flags in layouts), "Pool was not already FDT")
        records = []
        for line in ddt.splitlines():
            match = re.match(r"index [0-9a-f]+ refcnt (\d+) phys \d+ (.*)", line)
            if match:
                records.append({"refs": int(match.group(1)), "bp": parse_bp(match.group(2))})
        proof = {"stage": stage, "objects": result, "ddt_records": records,
                 "root_bps": root_bps, "shared_metadata": metadata}
        self.info["physical_proofs"].append(proof)
        self.h.flush()
        return proof

    def accounting(self, stage):
        result = self.zdb("-bc", self.name)
        output = result.stdout + "\n" + result.stderr
        require(re.search(r"^\s*No leaks \(block sum matches space maps exactly\)\s*$", output, re.MULTILINE),
                "Independent native allocation/DDT/BRT accounting did not prove exact ownership")
        require(not re.search(r"^(?:block claim error|DDT leak:|BRT leak:|leaked space:|block traversal size |Error counts:)",
                              output, re.MULTILINE), "Native ownership/checksum error")
        count = re.findall(r"^\s*bp count:\s+(\d+)\s*$", output, re.MULTILINE)
        require(len(count) == 1 and int(count[0]) > 0, "Native accounting traversal did not finish")
        self.info["independent_accounting"].append({"stage": stage, "bp_count": int(count[0])})
        self.h.flush()

    def preconditions(self, proof):
        objects = proof["objects"]
        for group, labels in self.groups.items():
            offsets = set(objects[labels[0]])
            require(all(set(objects[label]) == offsets for label in labels), "Unequal offset sets: " + group)
            for offset in offsets:
                pointers = [objects[label][offset] for label in labels]
                require(all(not bp["dedup"] for bp in pointers), "Fixture source is not ordinary D0: " + group)
                require(len({physical(bp) for bp in pointers}) == len(pointers),
                        "Fixture duplicates were not independently allocated: " + group)
        require(all(bp["dedup"] for bp in objects[self.anchor].values()), "Existing FDT anchor is not dedup-backed")
        # Cloning legitimately promotes logical birth at the destination. Match
        # allocation, native checksum and crypto tuple, not that view-local birth.
        require({offset: canonical(bp) for offset, bp in objects[self.brt_source].items()} ==
                {offset: canonical(bp) for offset, bp in objects[self.brt_kept].items()},
                "Fixture did not prove selected/unselected BRT sharing")
        left, right = self.shared_metadata
        require(proof["shared_metadata"][left] == proof["shared_metadata"][right],
                "Selected snapshot and outside clone lack genuinely shared dnode metadata")
        for label in self.groups["weak-checksum"]:
            require(all(bp["flags"].split()[0] == "fletcher4" for bp in objects[label].values()),
                    "Weak-checksum ordinary fixture was not actually written with fletcher4")
        for group in self.encrypted_groups:
            require(all(bp["crypto"] for label in group for bp in objects[label].values()),
                    "Encrypted fixture has no native IV/salt tuple")
        for label in self.groups["compressed"]:
            require(any(bp["physical_bytes"] < bp["logical_bytes"] for bp in objects[label].values()),
                    "Compressed fixture is not physically compressed")
        self.assert_encryption_domains(proof)
        require({offset: canonical(bp) for offset, bp in objects[self.groups["brt"][1]].items()} ==
                {offset: canonical(bp) for offset, bp in objects[self.brt_second_kept].items()},
                "Second ordinary candidate has no actual unselected BRT owner")
        brt_allocations = {physical(bp) for label in self.groups["brt"] for bp in objects[label].values()}
        require(not any(physical(record["bp"]) in brt_allocations for record in proof["ddt_records"]),
                "Pinned BRT boundary unexpectedly already has an FDT canonical")

    def assert_encryption_domains(self, proof):
        left, right = self.encrypted_groups
        for offset, bp in proof["objects"][left[0]].items():
            require(physical(bp) != physical(proof["objects"][right[0]][offset]),
                    "Different native data-key domains share a canonical allocation")

    def postconditions(self, before, after):
        old, new = before["objects"], after["objects"]
        for label in self.unselected:
            assert_retained_allocations(old[label], new[label], label)
        for group, labels in self.groups.items():
            for offset in old[labels[0]]:
                pointers = [new[label][offset] for label in labels]
                require(all(bp["dedup"] for bp in pointers), "D0 false-positive; selected BP not DDT-backed: " + group)
                require(all(bp["flags"].split()[0] == "blake3" for bp in pointers),
                        "Canonical pointer lacks a native stored-representation BLAKE3 checksum")
                require(len({canonical(bp) for bp in pointers}) == 1, "Duplicate physical allocations remain: " + group)
                matches = [record for record in after["ddt_records"]
                           if fdt_membership(record["bp"]) == fdt_membership(pointers[0]) and record["refs"] >= 2]
                require(matches, "No native FDT canonical record with real duplicate references: " + group)
                if group == "brt":
                    require(physical(pointers[0]) not in
                            {physical(old[label][offset]) for label in labels},
                            "Canonical reuses a pinned ordinary/BRT allocation with dual native ownership")
        for label in self.groups["existing-fdt"]:
            for offset, bp in new[label].items():
                require(canonical(bp) == canonical(old[self.anchor][offset]),
                        "Eligible existing FDT canonical was not reused")
        # Historical views must receive the selected variant, outside clones not.
        for label, leaves in new.items():
            if label.startswith(self.selected + "/freeable@") or label.startswith(self.selected + "/inside-clone:"):
                for offset, bp in leaves.items():
                    require(canonical(bp) == canonical(new[self.groups["retire-ordinary"][0]][offset]) and bp["dedup"],
                            "Selected snapshot/clone was not remapped to canonical data")
            if label.startswith(self.selected + "/plain@original:"):
                for offset, bp in leaves.items():
                    require(canonical(bp) == canonical(old[self.anchor][offset]) and bp["dedup"],
                            "Selected historical pointer did not reuse existing FDT data")
        for group in self.encrypted_groups:
            dataset = group[0].split(":", 1)[0]
            for root in (dataset, dataset + "@encrypted-history"):
                require(after["root_bps"][root]["checksum"] != before["root_bps"][root]["checksum"],
                        "Encrypted changed descendants did not propagate authenticated objset child MACs")
            for filename in ("a", "b"):
                historical = new[dataset + "@encrypted-history:" + filename]
                for offset, bp in historical.items():
                    require(bp["dedup"] and canonical(bp) == canonical(new[group[0]][offset]),
                            "Encrypted snapshot ancestry/canonical tuple was not rewritten")
        self.assert_encryption_domains(after)
        for label, leaves in new.items():
            if "/volume" in label:
                shared = [bp for offset, bp in leaves.items() if int(offset) >= BLOCK]
                require(shared and all(bp["dedup"] for bp in shared) and
                        len({canonical(bp) for bp in shared}) == 1,
                        "ZVOL repeated offsets were not really consolidated")

    def readonly_checks(self):
        self.exported()
        baseline = {name: image_hash(Path(name)) for name in self.file_identities}
        checks = [("plan", self.argv("--plan"), True),
                  ("missing-key", self.argv("--plan", keys=False), False),
                  ("wrong-guid", self.argv("--plan", guid=str(int(self.guid) ^ 1)), False),
                  ("missing-fence", self.argv(fenced=False), False)]
        if self.info["label"] == "resource-pressure-ordered":
            checks.append(("insufficient-live-backing",
                           self.argv("--plan", memory_max=74 * MIB, disk_max=1), False))
        for label, argv, accepted in checks:
            result = self.h.command(*argv, expect=None, timeout=1800)
            actual = {name: image_hash(Path(name)) for name in self.file_identities}
            if actual != baseline:
                # A failed admission invariant cannot prove that any unexpected
                # allocations are safe for a stock import/destruction.
                self.recovery_required = True
                self.info["recovery_required"] = True
                self.h.flush()
            require(actual == baseline, "Read-only plan/refusal wrote an owned vdev: " + label)
            require((result.returncode == 0) == accepted, "Incorrect preflight admission: " + label)
            if label == "insufficient-live-backing":
                require(re.search(r"backing|quota|space|resource", result.stderr, re.IGNORECASE),
                        "Tiny-backing failure did not report an actual resource shortage")
            self.info["preflight"].append({"check": label, "accepted": accepted, "vdev_sha256": actual})
            self.h.flush()

    def future_consumer(self):
        freeable = self.selected + "/freeable"
        original = dict(self.files[freeable])
        self.put(freeable, "a", payload(SEED, "future-overwrite", 16 * MIB))
        self.zfs("set", "dedup=blake3", freeable)
        self.put(freeable, "future-ref", original["b"])
        self.verify_manifest("future-write-addref")
        self.sync()
        self.export()
        self.accounting("future-write-addref")
        self.import_pool()
        # A selected origin's rewritten references require an independent native
        # ownership/birth context in its outside clone, not a retained ghost edge.
        outside = self.shared_metadata[1]
        self.put(outside, "a", payload(SEED, "outside-clone-write", 16 * MIB))
        self.path(outside, "b").unlink()
        del self.files[outside]["b"]
        self.sync()
        self.verify_manifest("outside-clone-write-delete-origin-readable")
        self.export()
        self.accounting("outside-clone-write-delete")
        self.import_pool()
        self.verify_manifest("outside-clone-write-delete-reimport")
        self.unmount_views()
        self.zfs("destroy", "-r", outside)
        self.datasets.remove(outside)
        del self.files[outside]
        self.sync()
        self.zp("wait", "-t", "free")
        self.verify_manifest("outside-clone-destroy-origin-readable")
        self.export()
        self.accounting("outside-clone-destroy")
        self.import_pool()
        self.unmount_views()
        origin_snapshot = self.shared_metadata[0]
        origin = origin_snapshot.split("@", 1)[0]
        self.zfs("destroy", origin_snapshot)
        del self.views[origin_snapshot]
        self.zfs("destroy", origin)
        self.datasets.remove(origin)
        del self.files[origin]
        self.sync()
        self.zp("wait", "-t", "free")
        self.verify_manifest("outside-origin-teardown-brt-owners-readable")
        self.export()
        self.accounting("outside-origin-teardown")
        self.import_pool()
        self.unmount_views()
        self.zfs("destroy", "-r", self.selected + "/inside-clone")
        self.datasets.remove(self.selected + "/inside-clone")
        del self.files[self.selected + "/inside-clone"]
        self.zfs("destroy", freeable + "@retained")
        del self.views[freeable + "@retained"]
        for filename in list(self.files[freeable]):
            self.path(freeable, filename).unlink()
            del self.files[freeable][filename]
        # Free encrypted history and heads through real kernel paths too.
        for group in self.encrypted_groups:
            dataset = group[0].split(":", 1)[0]
            self.zfs("destroy", dataset + "@encrypted-history")
            del self.views[dataset + "@encrypted-history"]
            self.put(dataset, "a", payload(SEED, "crypto-future", 2 * MIB))
        volume = self.selected + "/volume"
        self.zfs("destroy", volume + "@original")
        del self.volume_views[volume + "@original"]
        self.put_volume(volume, payload(SEED, "volume-future", 2 * MIB))
        # The selected origin is gone; drop the last unselected ordinary/BRT
        # owners now so final accounting catches stale reference ownership.
        outside = self.name + "/unselected"
        for filename in ("brt-kept", "brt-second-kept"):
            self.path(outside, filename).unlink()
            del self.files[outside][filename]
        self.sync()
        self.zp("wait", "-t", "free")
        require(self.property("freeing") == "0", "Native deferred free did not drain")
        self.verify_manifest("future-kernel-free")
        self.export()
        self.accounting("future-kernel-free")
        self.import_pool()
        self.verify_manifest("future-free-reimport")
        self.export()


def interrupt(pool, phase, kind):
    pool.exported()
    pool.recovery_required = True
    pool.info["recovery_required"] = True
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
    env = {**os.environ, "LC_ALL": "C", "DEDUP_FDT_TESTING": "1",
           "DEDUP_FDT_TEST_PHASE_FD": str(write_fd), "DEDUP_FDT_TEST_PAUSE_PHASE": phase}
    event_log = {"phase": phase, "signal": kind, "events": [], "reached": False}
    pool.info["fault"] = event_log
    directory = pool.h.evidence_path.with_suffix(".logs")
    directory.mkdir(mode=0o700, exist_ok=True)
    stdout_path = directory / (pool.info["label"] + ".stdout")
    stderr_path = directory / (pool.info["label"] + ".stderr")
    command = {"case": pool.h.current_case, "argv": pool.argv(), "started": time.time(),
               "journal_seq": len(pool.h.evidence["commands"])}
    pool.h.evidence["commands"].append(command)
    with pool.h.command_journal.open("a") as journal:
        journal.write(json.dumps({**command, "event": "start"}) + "\n")
    process = None
    pending = b""
    selector = selectors.DefaultSelector()
    try:
        with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
            process = subprocess.Popen(pool.argv(), stdout=stdout, stderr=stderr, env=env,
                                       pass_fds=(write_fd,), start_new_session=True)
            os.close(write_fd)
            write_fd = None
            selector.register(read_fd, selectors.EVENT_READ)
            deadline = time.monotonic() + 1800
            while selector.get_map() and time.monotonic() < deadline:
                for key, _ in selector.select(0.2):
                    data = os.read(key.fd, 65536)
                    if not data:
                        selector.unregister(key.fd)
                        continue
                    pending += data
                    while b"\n" in pending:
                        line, pending = pending.split(b"\n", 1)
                        event = json.loads(line)
                        event_log["events"].append(event)
                        if event.get("phase") == phase and event.get("durable") is True and not event_log["reached"]:
                            if phase == ADMISSION_PHASE:
                                require(event.get("admission_proof") is True and
                                        event.get("active_labels") is True and event.get("mos_stage") is False,
                                        "Admission hook did not prove the ACTIVE, no-MOS-stage boundary")
                            event_log["reached"] = True
                            process.send_signal(signal.SIGTERM if kind == "term" else signal.SIGKILL)
                        pool.h.flush()
            require(time.monotonic() < deadline and not pending, "Durable phase channel timed out/truncated")
            code = process.wait(timeout=30)
            event_log["returncode"] = code
            require(event_log["reached"], "Requested durable boundary never reached: " + phase)
            require(code == (-signal.SIGKILL if kind == "kill" else 130), "Signal did not stop at the owned durable boundary")
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=30)
        selector.close()
        os.close(read_fd)
        if write_fd is not None:
            os.close(write_fd)
        event_log.update(stdout_log=str(stdout_path), stderr_log=str(stderr_path))
        command.update(finished=time.time(), returncode=process.returncode if process else None,
                       stdout_log=str(stdout_path), stderr_log=str(stderr_path))
        with pool.h.command_journal.open("a") as journal:
            journal.write(json.dumps({**command, "event": "complete",
                                      "stdout": stdout_path.read_text(errors="replace") if stdout_path.exists() else "",
                                      "stderr": stderr_path.read_text(errors="replace") if stderr_path.exists() else ""}) + "\n")
        pool.h.flush()
    if phase == ADMISSION_PHASE:
        # Read label nvlists directly; never open the ACTIVE pool with stock zdb.
        pool.assert_files()
        labels = {}
        for filename in pool.file_identities:
            output = pool.h.command("zdb", "-l", filename).stdout
            guids = set(re.findall(r"^\s*pool_guid:\s*(\d+)\s*$", output, re.MULTILINE))
            states = re.findall(r"^\s*state:\s*(\d+)\s*$", output, re.MULTILINE)
            require(guids == {pool.guid} and states and set(states) == {"0"},
                    "Admission SIGKILL did not leave exact owned vdev labels ACTIVE")
            labels[filename] = {"pool_guid": pool.guid, "states": [int(value) for value in states]}
        lease = pool.scratch / (".dedup-fdt-admission-" + pool.guid)
        identity = lease.lstat()
        require(stat.S_ISREG(identity.st_mode) and identity.st_uid == 0 and
                stat.S_IMODE(identity.st_mode) == 0o600,
                "Durable pre-stage admission proof is missing or not a private root-owned regular file")
        event_log["active_label_proof"] = labels
        event_log["admission_lease"] = str(lease)
        pool.h.flush()
    # No stock import/export or pool traversal between fault and recovery.
    pool.dedup()
    if phase == ADMISSION_PHASE:
        require(not lease.exists(), "Successful clean export retained the pre-stage admission lease")


def progress_records(output):
    records = []
    for line in output.splitlines():
        if line.startswith("{"):
            value = json.loads(line)
            if isinstance(value, dict):
                records.append(value)
    require(records, "Native tool emitted no structured progress evidence")
    return records


def resource_order_proof(pool, before):
    label = pool.groups["retire-ordinary"][0]
    leaves = before["objects"][label]
    addresses = []
    expected = set()
    for offset in sorted(leaves, key=int):
        bp = leaves[offset]
        vdev, dva, _ = bp["dvas"][0].split(":")
        address = (int(vdev), int(dva, 16), bp["physical_birth"])
        addresses.append(address)
        expected.add(address)
    inversions = sum(right < left for left, right in zip(addresses, addresses[1:]))
    require(inversions >= 8, "Scrambled logical fixture did not produce physical DVA inversions")
    require(pool.read_trace.is_file(), "Actual native ZIO trace was not produced")
    with pool.read_trace.open() as stream:
        trace = [json.loads(line) for line in stream]
    proof = validate_read_trace(trace, expected)
    proof.update(trace=str(pool.read_trace), logical_dva_inversions=inversions)
    records = progress_records(pool.last_output)
    snapshots = [record["resources"] for record in records if "resources" in record]
    require(snapshots, "No managed-resource evidence was emitted")
    latest = snapshots[-1]
    for field in ("cache_evictions", "disk_read_bytes", "disk_write_bytes"):
        require(latest[field] > 0, "Pressure case did not exercise " + field)
    require(latest["scratch_peak"] <= pool.disk_max, "Aggregate scratch quota exceeded")
    require(latest["cache_bytes"] + latest["workspace_bytes"] <= latest["work_limit"] and
            latest["cache_peak"] <= latest["work_limit"] and
            latest["workspace_peak"] <= latest["work_limit"],
            "Managed-memory allocation exceeded the shared budget")
    proof["resources"] = latest
    pool.info["actual_native_read_proof"] = proof
    pool.h.flush()


def run_quota_case(harness, name):
    with harness.case(name):
        pool = harness.fixture(name)
        pool.create_native_quota_fixture()
        manifest = pool.verify_manifest("before-native-quota")
        pool.export()
        before = pool.bp_proof("quota-full-before")
        require(before["ddt_records"], "Quota fixture has no existing native FDT keys")
        for group, labels in pool.groups.items():
            for offset in before["objects"][labels[0]]:
                pointers = [before["objects"][label][offset] for label in labels]
                require(all(not bp["dedup"] for bp in pointers) and
                        len({physical(bp) for bp in pointers}) == len(pointers),
                        "Quota fixture source groups are not independent ordinary allocations: " + group)
        pool.accounting("quota-before")
        pool.dedup()
        records = progress_records(pool.last_output)
        require(any(record.get("native_quota_skipped_groups", 0) > 0 and
                    record.get("native_quota_skipped_blocks", 0) > 0 for record in records),
                "Native DDT policy refusals were not distinctly reported")
        after = pool.bp_proof("quota-skips-and-existing-consolidation")
        old, new = before["objects"], after["objects"]
        for label in old:
            if "/new-" in label:
                require(new[label] == old[label], "Quota-rejected group BP/history changed: " + label)
        require(new[pool.anchor] == old[pool.anchor], "Native quota moved an existing canonical")
        old_records = {fdt_membership(record["bp"]): record["refs"] for record in before["ddt_records"]}
        new_records = {fdt_membership(record["bp"]): record["refs"] for record in after["ddt_records"]}
        require(set(new_records) == set(old_records), "Quota-full run introduced a new native FDT key")
        for offset, anchor in old[pool.anchor].items():
            for label in pool.groups["existing-fdt"]:
                require(new[label][offset]["dedup"] and canonical(new[label][offset]) == canonical(anchor),
                        "Quota-full policy prevented eligible existing-FDT consolidation")
            key = fdt_membership(anchor)
            require(new_records[key] == old_records[key] + 2, "Native canonical refcount is not exact")
        pool.accounting("quota-after")
        pool.import_pool()
        actual = pool.verify_manifest("after-native-quota")
        require({key: value for key, value in actual.items() if key != "stage"} ==
                {key: value for key, value in manifest.items() if key != "stage"},
                "Quota skip/consolidation changed kernel bytes or history/properties")
        # A finite, permissive quota exercises real committed admission
        # shadows and their final reuse, not the quota-disabled fast path.
        pool.zp("set", "dedup_table_quota=" + str(64 * MIB))
        pool.export()
        pool.dedup()
        accepted = pool.bp_proof("quota-finite-admitted-shadows")
        accepted_records = progress_records(pool.last_output)
        require(all(record.get("native_quota_skipped_groups", 0) == 0
                    for record in accepted_records),
                "Permissive native quota unexpectedly rejected a group")
        expected_keys = set(new_records)
        for group in ("new-first", "new-last"):
            labels = pool.groups[group]
            for offset in accepted["objects"][labels[0]]:
                bps = [accepted["objects"][label][offset] for label in labels]
                require(all(bp["dedup"] for bp in bps) and
                        all(canonical(bp) == canonical(bps[0]) for bp in bps),
                        "Admitted shadow did not consolidate its group: " + group)
                expected_keys.add(fdt_membership(bps[0]))
        require({fdt_membership(row["bp"]) for row in accepted["ddt_records"]} ==
                expected_keys, "Committed admission shadow published incorrect keys")
        pool.accounting("quota-finite-admitted")
        pool.import_pool()
        final = pool.verify_manifest("after-finite-native-quota")
        require({key: value for key, value in final.items() if key != "stage"} ==
                {key: value for key, value in manifest.items() if key != "stage"},
                "Committed quota shadow changed kernel bytes or historical placement")
        pool.export()
        pool.destroy()


def run_case(harness, name):
    with harness.case(name):
        pool = harness.fixture(name)
        if name in ("data-prepared-kill", "flat-published-kill"):
            pool.memory_max = 80 * MIB
        if name == "resource-pressure-ordered":
            pool.memory_max = 80 * MIB
            directory = harness.evidence_path.with_suffix(".logs")
            directory.mkdir(mode=0o700, exist_ok=True)
            pool.read_trace = directory / (name + ".reads.jsonl")
        pool.fixture()
        manifest = pool.verify_manifest("before-dedup")
        allocated = int(pool.property("allocated"))
        pool.export()
        before = pool.bp_proof("already-fdt-ordinary-before")
        pool.preconditions(before)
        pool.accounting("before")
        if name in ("ordinary-selected-consumer", "resource-pressure-ordered"):
            pool.readonly_checks()
            pool.dedup()
            if name == "resource-pressure-ordered":
                resource_order_proof(pool, before)
                pool.read_trace = None
        else:
            phase, kind = name.rsplit("-", 1)
            interrupt(pool, phase, kind)
        after = pool.bp_proof("dedup-published-retired")
        pool.postconditions(before, after)
        pool.accounting("after")
        pool.import_pool()
        actual = pool.verify_manifest("after-dedup")
        require({key: value for key, value in actual.items() if key != "stage"} ==
                {key: value for key, value in manifest.items() if key != "stage"},
                "Kernel data/object offsets, properties, identities or historical namespace changed")
        remaining = int(pool.property("allocated"))
        require(allocated - remaining >= 24 * MIB,
                "Ordinary duplicate retirement did not release real pool space (not a D-bit-only rewrite)")
        pool.info["space"] = {"allocated_before": allocated, "allocated_after": remaining,
                              "released": allocated - remaining, "minimum_required": 24 * MIB}
        pool.export()
        # Same command after success must not free predecessor data a second time.
        pool.dedup()
        retry = pool.bp_proof("completed-identical-retry")
        require(retry["objects"] == after["objects"], "Completed retry moved or freed canonical allocations")
        pool.accounting("completed-retry")
        pool.import_pool()
        pool.future_consumer()
        pool.destroy()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tool", type=Path, default=Path("build/dedup-fdt"))
    parser.add_argument("--work-dir", type=Path, default=Path("/var/tmp"))
    parser.add_argument("--faults", choices=("none", "all"), default="all")
    parser.add_argument("--case", action="append", choices=(
        "ordinary-selected-consumer", "resource-pressure-ordered", "native-ddt-quota",
        "data-prepared-term", "data-prepared-kill", "flat-published-term",
        "flat-published-kill", "import-admitted-kill"))
    args = parser.parse_args()
    require(os.geteuid() == 0, "Root is required for isolated disposable ZFS pools")
    args.tool = args.tool.resolve(strict=True)
    args.work_dir = args.work_dir.resolve(strict=True)
    require(args.tool.is_file() and os.access(args.tool, os.X_OK), "Tool must be executable")
    require(args.work_dir.is_dir() and not any(c.isspace() for c in str(args.work_dir)),
            "Work directory must exist and contain no whitespace")
    for executable in ("zpool", "zfs", "zdb", "mount", "umount"):
        require(shutil.which(executable), "Missing required executable: " + executable)
    os.umask(0o077)
    for name in list(os.environ):
        if name.startswith(("DEDUP_FDT_TEST", "REBUILD_DDT_TEST")) or name == "DEDUP_FDT_READ_TRACE":
            del os.environ[name]
    def interrupted(signum, _frame):
        raise Failure("Harness interrupted by signal %d" % signum)
    for signum in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, interrupted)
    harness = DedupHarness(args)
    code = 1
    try:
        version = harness.command("zfs", "version").stdout
        require(re.search(r"(?:^|\n)zfs-2\.4\.4-1(?:\n|$)", version) and
                re.search(r"(?:^|\n)zfs-kmod-2\.4\.4-1(?:\n|$)", version),
                "Exact OpenZFS 2.4.4-1 kernel and userspace required")
        if args.faults == "all":
            phases = json.loads(harness.command(args.tool, "--list-test-phases").stdout)["phases"]
            require(set(PHASES) | {ADMISSION_PHASE} <= set(phases),
                    "Missing admission/pre/postpublication durable test hooks")
            harness.evidence["durable_phases"] = phases
        for item in harness.evidence["cases"]:
            if item["name"] == "native-ddt-quota":
                run_quota_case(harness, item["name"])
            else:
                run_case(harness, item["name"])
        harness.evidence["status"] = "passed"
        code = 0
    except BaseException as error:
        harness.evidence.update(status="failed", error=str(error), traceback=traceback.format_exc())
        print(str(error), file=sys.stderr)
    finally:
        harness.evidence["finished"] = time.time()
        harness.flush()
        if harness.cleanup():
            harness.evidence["status"] = "failed"
            code = 1
            harness.flush()
        print("EVIDENCE " + str(harness.evidence_path), flush=True)
    return code


if __name__ == "__main__":
    sys.exit(main())
