#!/usr/bin/env python3
"""Check native checkpoint-history observations on one disposable file pool.

Requires root, system libzfs/libnvpair, zpool, and zfs. Only the exclusively
owned temporary pool is changed. Command output and native observer results
are retained in the integration Harness JSON report after cleanup.
"""

import argparse
import os
from pathlib import Path
import re
import shutil
import signal
import sys
import time
import traceback

from checkpoint_history import CheckpointHistory
from integration import Failure, Harness, require


CASE = "native-checkpoint-history-incremental-identity"


def create_checkpoint(h, pool):
    pool.zp("checkpoint")
    pool.info["checkpoint_state"] = "active"
    h.flush()
    pool.sync()


def discard_checkpoint(h, pool):
    if pool.info.get("checkpoint_state") == "active":
        pool.zp("checkpoint", "-d")
        pool.info["checkpoint_state"] = "discarding"
        h.flush()
    if pool.info.get("checkpoint_state") == "discarding":
        pool.zp("wait", "-t", "discard", timeout=120)
        pool.info["checkpoint_state"] = "none"
        h.flush()
        pool.sync()


def observe(h, observer, stage, expected=None):
    txg = observer.checkpoint_txg()
    h.evidence["observations"].append({"stage": stage, "checkpoint_txg": txg,
                                       "observed": time.time()})
    h.flush()
    require(isinstance(txg, int) and not isinstance(txg, bool) and txg > 0,
            "Native checkpoint observer did not return a positive TXG")
    if expected is not None:
        require(txg == expected, "Checkpoint TXG changed at " + stage)
    return txg


def record_history(h, pool, stage, expected_checkpoint):
    # zpool history obtains records through the live kernel, not an offline MOS.
    output = pool.zp("history", "-i").stdout
    checkpoint_txgs = [int(value) for value in re.findall(
        r"\[txg:\d+\] spa checkpoint checkpointed uberblock txg=(\d+)\s*$",
        output, re.MULTILINE)]
    logged_txgs = [int(value) for value in re.findall(r"\[txg:(\d+)\]", output)]
    require(checkpoint_txgs and logged_txgs,
            "Native CLI history did not contain checkpoint and transaction records")
    h.evidence["history_checks"].append({
        "stage": stage, "checkpoint_creation_txgs": checkpoint_txgs,
        "latest_logged_txg": max(logged_txgs)})
    h.flush()
    require(checkpoint_txgs[-1] == expected_checkpoint,
            "Observer TXG disagrees with the kernel's checkpoint creation record")
    return max(logged_txgs)


def validate(h, observers):
    with h.case(CASE):
        pool = h.pool("checkpoint-history")
        pool.zp("set", "feature@zpool_checkpoint=enabled")
        require(pool.property("feature@zpool_checkpoint") in ("enabled", "active"),
                "Disposable pool does not support checkpoints")
        dataset = pool.name + "/history-fixture"
        mount = pool.mount / "history-fixture"
        pool.zfs("create", "-o", "dedup=off", "-o", "mountpoint=" + str(mount), dataset)
        pool.sync()
        create_checkpoint(h, pool)

        observer = CheckpointHistory(pool.name, pool.guid)
        observers.append(observer)
        first_txg = observe(h, observer, "first-checkpoint")
        observe(h, observer, "first-checkpoint-unchanged-eof", first_txg)
        previous_logged_txg = record_history(h, pool, "first-checkpoint", first_txg)

        # Three fixed, synced metadata/data commits advance the live pool while
        # the checkpoint must retain its original identity. No random workload.
        fixture_file = mount / "fixed-metadata.txt"
        for stage in (1, 2, 3):
            pool.assert_owned()
            with fixture_file.open("wb") as stream:
                stream.write(("checkpoint-history stage %d\n" % stage).encode("ascii"))
                stream.flush()
                os.fsync(stream.fileno())
            fixture_file.chmod(0o600 if stage % 2 else 0o640)
            pool.zfs("set", "org.openzfs:checkpoint-history=stage-%d" % stage, dataset)
            pool.sync()
            label = "metadata-commit-%d" % stage
            logged_txg = record_history(h, pool, label, first_txg)
            require(logged_txg > previous_logged_txg,
                    "Fixed metadata operation did not advance the committed TXG")
            previous_logged_txg = logged_txg
            observe(h, observer, label, first_txg)
            observe(h, observer, label + "-unchanged-eof", first_txg)

        discard_checkpoint(h, pool)
        try:
            observer.checkpoint_txg()
        except RuntimeError as error:
            h.evidence["no_checkpoint_rejection"] = {
                "error": str(error), "observed": time.time()}
            h.flush()
        else:
            raise Failure("Observer accepted a discarded checkpoint")
        observer.close()

        create_checkpoint(h, pool)
        # A safety failure intentionally poisons the old observation stream.
        observer = CheckpointHistory(pool.name, pool.guid)
        observers.append(observer)
        second_txg = observe(h, observer, "replacement-checkpoint")
        require(second_txg > first_txg,
                "Replacement checkpoint did not acquire a newer TXG")
        record_history(h, pool, "replacement-checkpoint", second_txg)
        independent = CheckpointHistory(pool.name, pool.guid)
        observers.append(independent)
        observe(h, independent, "independent-full-history-scan", second_txg)
        observe(h, independent, "independent-unchanged-eof", second_txg)

        wrong_guid = str(int(pool.guid) % (2**64 - 1) + 1)
        wrong_observer = None
        try:
            wrong_observer = CheckpointHistory(pool.name, wrong_guid)
            wrong_observer.checkpoint_txg()
        except RuntimeError as error:
            h.evidence["wrong_guid_rejection"] = {
                "pool_guid": pool.guid, "supplied_guid": wrong_guid,
                "error": str(error), "observed": time.time()}
            h.flush()
        else:
            raise Failure("Observer accepted an incorrect pool GUID")
        finally:
            if wrong_observer is not None:
                wrong_observer.close()
        pool.assert_owned()
        observe(h, observer, "after-wrong-guid-rejection", second_txg)
        observe(h, independent, "independent-after-wrong-guid-rejection", second_txg)
        discard_checkpoint(h, pool)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", required=True, type=Path,
                        help="Existing parent for exclusively owned disposable file pools")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("root is required to create a disposable ZFS pool")
    if not args.work_dir.is_dir():
        parser.error("--work-dir must name an existing directory")
    for executable in ("zpool", "zfs"):
        if shutil.which(executable) is None:
            parser.error("required system executable not found: " + executable)

    h = Harness(Path(__file__).resolve(), args.work_dir.resolve())
    h.evidence.pop("converter")
    h.evidence.update(
        script=str(Path(__file__).resolve()),
        cases=[{"name": CASE, "status": "not_run"}],
        observations=[], history_checks=[],
        coverage={"checkpoint_history": "Native creation, incremental EOF, three fixed TXG commits, "
                  "discard rejection, replacement, independent scan, and GUID rejection"})
    h.flush()
    print("Evidence: " + str(h.evidence_path), flush=True)
    observers = []
    previous_handlers = {}
    outcome = 1

    def interrupted(signum, frame):
        raise KeyboardInterrupt("Checkpoint history fixture received signal %d" % signum)

    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous_handlers[signum] = signal.signal(signum, interrupted)
        h.command("zfs", "version")
        validate(h, observers)
        h.evidence["status"] = "passed"
        outcome = 0
    except BaseException as error:
        h.evidence.update(status="failed", error=str(error), traceback=traceback.format_exc())
        print("FAIL: " + str(error), file=sys.stderr, flush=True)
    finally:
        # As in integration.py, finish ownership-checked cleanup without a second
        # interrupt abandoning the owned pool and its sparse backing files.
        for signum in previous_handlers:
            signal.signal(signum, signal.SIG_IGN)
        errors = []
        for observer in reversed(observers):
            try:
                observer.close()
            except BaseException as error:
                errors.append("Closing checkpoint observer: " + str(error))
        for pool in reversed(h.pools):
            try:
                discard_checkpoint(h, pool)
            except BaseException as error:
                errors.append("Discarding owned checkpoint: " + str(error))
        errors.extend(h.cleanup())
        h.evidence["cleanup_errors"] = errors
        if errors:
            h.evidence["status"] = "failed"
            outcome = 1
            print("Cleanup failed: " + "; ".join(errors), file=sys.stderr, flush=True)
        h.evidence["finished"] = time.time()
        h.flush()
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
    print("%s; evidence: %s" % ("PASS" if outcome == 0 else "FAIL", h.evidence_path), flush=True)
    return outcome


if __name__ == "__main__":
    sys.exit(main())
