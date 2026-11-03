#!/usr/bin/env python3
"""Exercise parallel DDT/content verification on one fixed, owned disposable pool."""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import sys
import time
import traceback

from integration import Harness, require
from parallel_actual_validation import (
    admit_conversion_proof,
    admit_preflight_metadata,
    admit_published_metadata,
    legacy_store_identity,
)


CASE = "parallel-blake3-ddt-files-snapshots-zvol"


def store(path, data):
    with path.open("wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def require_rejected(admit, message, *arguments):
    try:
        admit(*arguments)
    except RuntimeError:
        return
    raise RuntimeError(message)


def native_error(result, operation):
    for line in result.stderr.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if isinstance(event, dict) and event.get("phase") == "error" and event.get("operation") == operation:
            return True
    return False


def validate(h, args):
    with h.case(CASE):
        pool = h.pool("parallel-compression-features")
        ranges = pool.dataset("ranges", checksum="blake3", recordsize="4K")
        block = b"".join(hashlib.sha256(("fixed-range-" + str(i)).encode()).digest()
                         for i in range(128))
        store(ranges / "seed", block * 2)
        pool.export()
        insufficient = pool.directory / "insufficient-content.json"
        refused = h.command(args.content_validator, "--pool-guid", pool.guid,
                            "--search-dir", pool.devices, "--output", insufficient,
                            "--workers", "8", "--arc-max-bytes", str(128 * 1024 ** 2),
                            expect=None, timeout=120)
        require(refused.returncode != 0 and not insufficient.exists() and
                native_error(refused, "insufficient_dedup_samples"),
                "Native default target accepted fewer than 25000 dedup-backed ranges")
        pool.import_pool()
        payload = ranges / "payload"
        digest = hashlib.sha256()
        chunk = block * 256
        with payload.open("wb") as stream:
            for _ in range(100):
                stream.write(chunk)
                digest.update(chunk)
            stream.flush()
            os.fsync(stream.fileno())
        payload_object = payload.stat().st_ino
        pool.manifest[str(payload)] = digest.hexdigest()
        for compression in ("zstd", "lz4", "on"):
            mount = pool.dataset(compression, checksum="blake3")
            pool.zfs("set", "compression=" + compression, pool.name + "/" + compression)
            # Fixed compressible records exercise zstd, lz4 and default compression.
            data = b"".join(hashlib.sha256((compression + str(i)).encode()).digest() * 4096
                            for i in range(16))
            for name in ("first", "duplicate"):
                store(mount / name, data)
                pool.manifest[str(mount / name)] = hashlib.sha256(data).hexdigest()
            pool.sync()
            pool.zfs("snapshot", pool.name + "/" + compression + "@retained")
            for name in ("first", "duplicate"):
                pool.manifest[str(mount / ".zfs/snapshot/retained" / name)] = hashlib.sha256(data).hexdigest()
            changed = hashlib.sha256((compression + "changed").encode()).digest() * 4096 + data[128 * 1024:]
            store(mount / "first", changed)
            pool.manifest[str(mount / "first")] = hashlib.sha256(changed).hexdigest()
        volume_dataset = pool.name + "/volume"
        pool.zfs("create", "-s", "-V", "16M", "-b", "128K", "-o", "dedup=blake3",
                 "-o", "compression=zstd", "-o", "volmode=dev", volume_dataset)
        volume = {"dataset": volume_dataset, "path": "/dev/zvol/" + volume_dataset,
                  "size": 16 * 1024 * 1024, "half_seeds": [None, None]}
        pool.volumes.append(volume)
        pool.write_volume(volume, "fixed-parallel-volume")
        pool.zfs("snapshot", volume_dataset + "@retained")
        pool.write_volume(volume, "fixed-parallel-volume-replacement", half=0)
        locked = pool.dataset("locked", checksum="blake3", encrypted=True)
        locked_data = hashlib.sha256(b"fixed-encrypted-payload").digest() * 4096
        store(locked / "payload", locked_data)
        pool.manifest[str(locked / "payload")] = hashlib.sha256(locked_data).hexdigest()
        pool.sync()
        pool.zfs("unmount", pool.name + "/locked")
        pool.zfs("unload-key", pool.name + "/locked")
        pool.enable()
        pool.export()

        work = pool.directory / "parallel-validation"
        work.mkdir(mode=0o700)
        devices = []
        for path in sorted(pool.devices.iterdir()):
            target = path.resolve(strict=True)
            value = target.stat()
            require(stat.S_ISREG(value.st_mode), "Owned fixture vdev is not a regular file")
            devices.append({"path": str(target), "identity": [value.st_dev, value.st_ino,
                                                              value.st_rdev, value.st_size]})
        source_guid = str(int(pool.guid) % (2 ** 64 - 1) + 1)
        ownership = {"format": "parallel-actual-ownership-v1", "pool_guid": pool.guid,
                     "source_guid": source_guid, "name": pool.name, "exported": True,
                     "fenced": True, "search_dir": str(pool.devices), "devices": devices}
        owner_path = work / "ownership.json"
        owner_path.write_text(json.dumps(ownership, indent=2) + "\n")
        owner_path.chmod(0o600)
        described = json.loads(h.command(args.converter, "--describe", "--pool-guid", pool.guid,
                                         "--search-dir", pool.devices).stdout)
        require(described.get("format") == "convert-ddt-state-v1" and
                described.get("exported") is True and described.get("staging_present") is False,
                "Read-only describe did not prove exported unstaged metadata")
        initial_stores = legacy_store_identity(described)
        h.command(sys.executable, args.runner, "--pool-guid", pool.guid,
                  "--search-dir", pool.devices, "--work-dir", work,
                  "--converter", args.converter, "--ddt-validator", args.ddt_validator,
                  "--content-validator", args.content_validator, "--workers", "16",
                  "--content-workers", "8", "--ddt-preload", "--batch-size", "16",
                  "--read-batch-entries", "32",
                  "--arc-max-bytes", str(512 * 1024 ** 2),
                  "--ddt-arc-max-bytes", str(384 * 1024 ** 2), timeout=600)
        reports = list(work.glob("parallel-actual-*/report.json"))
        require(len(reports) == 1, "Expected one complete parallel report")
        report = json.loads(reports[0].read_text())
        require(report.get("complete") is True and report.get("status") == "passed" and
                report["coverage"]["full_ddt"]["status"] == "converter_full_staged_readback_passed" and
                report["coverage"]["full_ddt"]["independent_after_fingerprint"] is False and
                report["coverage"]["published_layout"]["status"] == "published_native_layout_counts_passed" and
                report["coverage"]["content"]["status"] == "exact_inventory_and_recorded_ranges_passed" and
                report["coverage"]["metadata"] == "not_requested_conversion_scope",
                "Preload run did not retain full converter readback, publication and recorded content proof")
        require([item["name"] for item in report["commands"]] ==
                ["before-ddt", "before-content", "converter-convert", "published-describe", "after-content"] and
                [item["phase"] for item in report["phases"]] ==
                ["before-parallel", "converter-convert", "published-describe", "after-content-replay"],
                "Conversion validation repeated completed checks or ran an unrelated whole-pool phase")
        before = json.loads(reports[0].with_name("before-ddt.json").read_text())
        published = json.loads(reports[0].with_name("published-describe.stdout").read_text())
        before_content = json.loads(reports[0].with_name("before-content.json").read_text())
        after_content = json.loads(reports[0].with_name("after-content.json").read_text())
        require(before_content.get("format") == "validate-content-v2" and
                before_content.get("sample_target") == before_content.get("sample_count") == "25000" and
                before_content == after_content,
                "Conversion changed the exact default-25000 content inventory, identities or sampled bytes")
        references = []
        for view in before_content["views"]:
            identity = next(item for item in before_content["inventory"]
                            if item["objset_id"] == view["objset_id"])
            for sample in view["samples"]:
                require(sample["bp"]["dedup"] is True and len(sample["bp"]["words"]) == 16 and
                        all(isinstance(word, str) and word.isdecimal() and
                            0 <= int(word) < 2 ** 64 for word in sample["bp"]["words"]),
                        "Native sample lacks an actual dedup-backed block pointer identity")
                # OpenZFS 2.4.4 blkptr_t word 6 is blk_prop; verify its native bits,
                # not merely the manifest's descriptive dedup boolean.
                prop = int(sample["bp"]["words"][6])
                require((prop >> 62) & 1 and not (prop >> 39) & 1 and
                        (prop >> 56) & 31 == 0 and any(int(word) for word in sample["bp"]["words"][:6]),
                        "Selected BP is embedded, indirect, a hole or not actually dedup-backed")
                references.append((identity["guid"], sample["object"], sample["offset"]))
        require(len(references) == len(set(references)) == 25000 and
                any(int(offset) > 0 for _, _, offset in references) and
                any(view.get("status") == "locked" for view in before_content["views"]) and
                report["coverage"]["content"]["sample_target"] == 25000 and
                report["coverage"]["content"]["sample_count"] == 25000,
                "Fixture lacks exact distinct logical ranges, nonzero offsets or locked-view preservation")
        require(legacy_store_identity(before, baseline=True) == initial_stores,
                "Describe disagrees with the independent complete native legacy census")
        admit_preflight_metadata(described, before, pool.guid)
        for field in ("object", "count", "staging_present", "flags"):
            changed = copy.deepcopy(described)
            table_store = next(item for table in changed["tables"] for item in table["stores"])
            if field in ("object", "count"):
                table_store[field] = str(int(table_store[field]) + 1)
            elif field == "staging_present":
                changed[field] = True
            else:
                changed["tables"][0]["flags"] = 3
            require_rejected(admit_preflight_metadata,
                             "Preflight continuation admitted changed native " + field,
                             changed, before, pool.guid)
        require_rejected(admit_preflight_metadata,
                         "Preflight continuation admitted the actual published DDT",
                         published, before, pool.guid)
        admit_published_metadata(published, before, pool.guid)
        require_rejected(admit_published_metadata,
                         "Published-layout admission accepted the actual legacy DDT",
                         described, before, pool.guid)
        for field in ("pool_guid", "exported", "staging_present", "version", "flags",
                      "checksum", "type", "class", "object", "legacy_object", "count", "missing_store"):
            changed = copy.deepcopy(published)
            table = next(item for item in changed["tables"]
                         if any(int(store["count"]) > 0 for store in item["stores"]))
            table_store = next(item for item in table["stores"] if int(item["count"]) > 0)
            if field == "pool_guid":
                changed[field] = source_guid
            elif field == "exported":
                changed[field] = False
            elif field == "staging_present":
                changed[field] = True
            elif field in ("version", "flags"):
                table[field] = 0
            elif field == "checksum":
                table[field] += 1
            elif field in ("type", "class"):
                table_store[field] += 1
            elif field == "object":
                table_store[field] = "0"
            elif field == "legacy_object":
                table_store["object"] = next(
                    store["object"] for baseline_table in before["tables"]
                    for store in baseline_table["stores"] if int(store["native_zap_count"]) > 0)
            elif field == "count":
                table_store[field] = str(int(table_store[field]) + 1)
            else:
                table["stores"].remove(table_store)
            require_rejected(admit_published_metadata,
                             "Published-layout admission accepted changed native " + field,
                             changed, before, pool.guid)
        total = int(before["total_keys"])
        native_progress = []
        reclaim_progress = {}
        for line in reports[0].with_name("converter-convert.stderr").read_text().splitlines():
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if isinstance(item, dict) and item.get("phase") in ("flat-preflight", "flat-copy", "flat-readback"):
                native_progress.append(item)
            elif isinstance(item, dict) and item.get("phase") == "stage-reclaim":
                reclaim_progress.setdefault(int(item["object"]), []).append(item)
        require(total > 32, "Fixed fixture does not cross physical-read batch boundaries")
        for table in before["tables"]:
            for source_store in table["stores"]:
                count = int(source_store["native_zap_count"])
                if not count:
                    continue
                for phase in ("flat-preflight", "flat-copy", "flat-readback"):
                    require(any(item.get("phase") == phase and
                                item.get("checksum") == table["checksum_name"] and
                                item.get("class") == source_store["class"] and
                                item.get("entries") == item.get("total_entries") == count and
                                item.get("read_order") == "physical" and
                                item.get("physical_blocks", 0) > 0 and
                                item["physical_blocks"] == item.get("total_physical_blocks")
                                for item in native_progress),
                            "Physical execution lacks complete store coverage for " + phase)
                for phase in ("flat-preflight", "flat-copy", "flat-readback"):
                    incomplete = [item for item in native_progress if not (
                        item.get("phase") == phase and item.get("checksum") == table["checksum_name"] and
                        item.get("class") == source_store["class"])]
                    require_rejected(admit_conversion_proof,
                                     "Conversion admission accepted missing store proof for " + phase,
                                     incomplete, before)
                for field in ("entries", "total_entries", "physical_blocks", "total_physical_blocks"):
                    incomplete = copy.deepcopy(native_progress)
                    for item in incomplete:
                        if (item.get("phase") == "flat-readback" and
                                item.get("checksum") == table["checksum_name"] and
                                item.get("class") == source_store["class"]):
                            item[field] = 0
                    require_rejected(admit_conversion_proof,
                                     "Conversion admission accepted incomplete readback " + field,
                                     incomplete, before)
        admit_conversion_proof(native_progress, before)
        for table in before["tables"]:
            for source_store in table["stores"]:
                object_id = int(source_store["object"])
                events = reclaim_progress.get(object_id, [])
                require(events and events[0]["bytes"] == 0 and
                        events[0]["state"] == "freeing-ranges" and
                        events[-1]["state"] == "complete" and
                        events[-1]["bytes"] == events[-1]["total_bytes"] and
                        all(0 <= item["bytes"] <= item["total_bytes"] for item in events) and
                        all(a["bytes"] <= b["bytes"] and
                            a["total_bytes"] == b["total_bytes"]
                            for a, b in zip(events, events[1:])),
                        "Old DDT reclamation lacks distinct monotonic committed-range progress")
        progress = [json.loads(line) for line in Path(report["progress_log"]).read_text().splitlines()]
        for name in ("before-content", "after-content"):
            require(any(any(child["name"] == name and
                            child.get("work", {}).get("samples_completed") == 25000
                            for child in event["children"]) for event in progress),
                    "Persistent progress lacks actual completed sample count for " + name)
        for name in ("before-ddt",):
            require(any(event.get("timestamp") and any(
                child["name"] == name and child.get("native", {}).get("entries") == total and
                child["native"].get("total_entries") == total and child.get("entry_eta_seconds") == 0
                for child in event["children"]) for event in progress),
                "Persistent progress did not record complete DDT work and ETA for " + name)
            require(any(event.get("timestamp") and any(
                child["name"] == name and
                child.get("native_preload_plan", {}).get("phase") == "ddt-preload-plan" and
                child["native_preload_plan"].get("preload_plan_blocks", 0) > 0 and
                child["native_preload_plan"]["preload_plan_blocks"] ==
                child["native_preload_plan"].get("total_preload_plan_blocks") and
                child["native_preload_plan"].get("eta_seconds") == 0 and
                child["work"].get("preload_plan_blocks") ==
                child["native_preload_plan"]["total_preload_plan_blocks"]
                for child in event["children"]) for event in progress),
                "Persistent progress did not retain completed physical preload planning work for " + name)
            require(any(event.get("timestamp") and any(
                child["name"] == name and
                child.get("native_preload", {}).get("phase") == "ddt-preload" and
                child["native_preload"].get("preload_bytes", 0) > 0 and
                child["native_preload"]["preload_bytes"] == child["native_preload"].get("total_preload_bytes") and
                child["native_preload"].get("preload_bytes_per_second", -1) >= 0 and
                child["native_preload"].get("eta_seconds") == 0 and
                child["work"].get("preload_bytes") == child["native_preload"]["total_preload_bytes"]
                for child in event["children"]) for event in progress),
                "Persistent progress did not retain complete preload counters, rate and ETA for " + name)
        require(progress[-1]["phase"] == "passed", "Progress log did not record successful completion")
        refused = h.command(
            sys.executable, args.runner, "--pool-guid", pool.guid,
            "--search-dir", pool.devices, "--work-dir", work,
            "--converter", args.converter, "--ddt-validator", args.ddt_validator,
            "--content-validator", args.content_validator,
            "--resume-conversion", reports[0], expect=None, timeout=60)
        require(refused.returncode != 0 and "--ownership-journal" in refused.stderr,
                "Conversion continuation admitted a file-only fixture without actual COW/backing proof")
        pool.import_pool()
        pool.layout(1, 3, ("blake3",))
        pool.verify()
        pool.info["independent_content_checks"] = len(pool.manifest)
        range_identity = next(item for item in before_content["inventory"]
                              if bytes.fromhex(item["name_hex"]).decode() == pool.name + "/ranges")
        range_view = next(view for view in before_content["views"]
                          if view["objset_id"] == range_identity["objset_id"])
        selected = next(sample for sample in range_view["samples"]
                        if int(sample["object"]) == payload_object)
        pool.zfs("set", "dedup=off", pool.name + "/ranges")
        # Same bytes, object, generation and size; only the real selected BP changes.
        with payload.open("r+b") as stream:
            stream.seek(int(selected["offset"]))
            original = stream.read(int(selected["length"]))
            require(hashlib.sha256(original).hexdigest() == selected["sha256"],
                    "Selected native range does not identify the fixture payload")
            stream.seek(int(selected["offset"]))
            stream.write(original)
            stream.flush()
            os.fsync(stream.fileno())
        pool.export()
        changed_output = reports[0].with_name("changed-bp-content.json")
        refused = h.command(args.content_validator, "--pool-guid", pool.guid,
                            "--search-dir", pool.devices, "--output", changed_output,
                            "--expect", reports[0].with_name("before-content.json"),
                            "--workers", "8", "--arc-max-bytes", str(128 * 1024 ** 2),
                            expect=None, timeout=120)
        require(refused.returncode != 0 and not changed_output.exists() and
                native_error(refused, "sample_bp_identity"),
                "Exact replay accepted an actually rewritten selected BP with identical bytes")
        pool.import_pool()
        with payload.open("r+b") as stream:
            stream.seek(int(selected["offset"]))
            changed = bytes([original[0] ^ 1]) + original[1:]
            stream.write(changed)
            stream.flush()
            os.fsync(stream.fileno())
        pool.export()
        changed_range_output = reports[0].with_name("changed-range-content.json")
        refused = h.command(args.content_validator, "--pool-guid", pool.guid,
                            "--search-dir", pool.devices, "--output", changed_range_output,
                            "--expect", reports[0].with_name("before-content.json"),
                            "--workers", "8", "--arc-max-bytes", str(128 * 1024 ** 2),
                            expect=None, timeout=120)
        require(refused.returncode != 0 and not changed_range_output.exists() and
                native_error(refused, "sample_bp_identity"),
                "Exact replay accepted an actually changed selected logical range")
        h.evidence["parallel_validation_directory"] = str(work)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--runner", type=Path, default=Path(__file__).with_name("parallel_actual_validation.py"))
    root = Path(__file__).resolve().parents[1]
    parser.add_argument("--converter", type=Path, default=root / "build/convert-ddt")
    parser.add_argument("--ddt-validator", type=Path, default=root / "build/validate-ddt")
    parser.add_argument("--content-validator", type=Path, default=root / "build/validate-content")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("root is required")
    if not args.work_dir.is_dir():
        parser.error("--work-dir must exist")
    h = Harness(args.converter.resolve(), args.work_dir.resolve())
    h.evidence.update(cases=[{"name": CASE, "status": "not_run"}],
                      coverage="Fixed BLAKE3 legacy DDT, zstd/lz4/default compression, snapshots, ZVOLs, locked roots, exact default-25000 dedup ranges, insufficient-target and changed-selected-BP/range rejection")
    h.flush()
    print("Evidence: " + str(h.evidence_path), flush=True)
    outcome = 1
    previous = {}

    def interrupt(signum, frame):
        raise KeyboardInterrupt("Fixed parallel validation proof cancelled")

    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            previous[sig] = signal.signal(sig, interrupt)
        validate(h, args)
        h.evidence["status"] = "passed"
        outcome = 0
    except BaseException as error:
        h.evidence.update(status="failed", error=str(error), traceback=traceback.format_exc())
        print("FAIL: " + str(error), file=sys.stderr, flush=True)
    finally:
        for sig in previous:
            signal.signal(sig, signal.SIG_IGN)
        # Keep native diagnostics after retiring the disposable pool files.
        evidence = {}
        for path in h.root.rglob("*"):
            if path.is_file() and path.suffix in (".stderr", ".stdout", ".json", ".jsonl"):
                if path.name in ("before-content.json", "after-content.json") or path.stat().st_size <= 2 * 1024 * 1024:
                    evidence[str(path.relative_to(h.root))] = path.read_text(errors="replace")
        h.evidence["native_evidence"] = evidence
        errors = h.cleanup()
        if errors:
            h.evidence["status"] = "failed"
            outcome = 1
        h.evidence["finished"] = time.time()
        h.flush()
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    print(("PASS" if outcome == 0 else "FAIL") + "; evidence: " + str(h.evidence_path), flush=True)
    return outcome


if __name__ == "__main__":
    raise SystemExit(main())
