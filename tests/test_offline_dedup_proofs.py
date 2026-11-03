#!/usr/bin/env python3
"""Non-destructive regressions for the fixed offline FDT proof oracles."""

import argparse
import json
from pathlib import Path
import sys
import tempfile
import unittest

from integration import Failure
from offline_dedup_integration import DedupHarness, validate_read_trace


def event(kind, seq, offset, timestamp, thread=1, phase="hash", window=0):
    return {"event": kind, "seq": seq, "top_vdev": 0, "offset": offset,
            "birth": 4, "time_ns": timestamp, "thread": thread,
            "phase": phase, "window": window, "window_limit": 2, "error": 0}


class ReadTraceProofTests(unittest.TestCase):
    def trace(self):
        return [event("submit", 0, 4096, 10),
                event("submit", 1, 8192, 20, thread=2),
                event("complete", 1, 8192, 30, thread=2),
                event("complete", 0, 4096, 40)]

    def test_actual_overlapping_sorted_reads_match_independent_bps(self):
        proof = validate_read_trace(self.trace(), {(0, 4096, 4), (0, 8192, 4)},
                                    required_phases={"hash"})
        self.assertEqual(proof["max_outstanding"], 2)
        self.assertEqual(proof["reads"], 2)

    def test_workers_without_actual_overlap_are_not_evidence(self):
        trace = self.trace()
        trace[1]["time_ns"] = 50
        trace[2]["time_ns"] = 60
        with self.assertRaises(Failure):
            validate_read_trace(trace, set(), required_phases={"hash"})

    def test_hash_order_payload_dispatch_is_rejected(self):
        trace = self.trace()
        trace[0]["offset"] = trace[3]["offset"] = 12288
        with self.assertRaises(Failure):
            validate_read_trace(trace, set(), required_phases={"hash"})

    def test_sorted_sequence_labels_cannot_hide_reversed_actual_submissions(self):
        trace = self.trace()
        trace[0]["time_ns"], trace[1]["time_ns"] = 20, 10
        with self.assertRaises(Failure):
            validate_read_trace(trace, set(), required_phases={"hash"})

    def test_individually_sorted_hash_windows_must_form_one_physical_pass(self):
        trace = [event("submit", 0, 12288, 10), event("submit", 1, 16384, 20),
                 event("complete", 1, 16384, 30), event("complete", 0, 12288, 40),
                 event("submit", 2, 4096, 50, window=1),
                 event("submit", 3, 8192, 60, window=1),
                 event("complete", 3, 8192, 70, window=1),
                 event("complete", 2, 4096, 80, window=1)]
        with self.assertRaises(Failure):
            validate_read_trace(trace, set(), required_phases={"hash"})

    def test_distinct_discovery_passes_may_restart_at_low_physical_addresses(self):
        first = self.trace()
        second = self.trace()
        for item in second:
            item["pass"] = 1
            item["time_ns"] += 100
        proof = validate_read_trace(first + second, set(), required_phases={"hash"})
        self.assertEqual(proof["reads"], 4)

    def test_unobserved_source_and_missing_completion_are_rejected(self):
        with self.assertRaises(Failure):
            validate_read_trace(self.trace(), {(0, 16384, 4)}, required_phases={"hash"})
        with self.assertRaises(Failure):
            validate_read_trace(self.trace()[:-1], set(), required_phases={"hash"})

    def test_unbounded_window_and_native_read_error_are_rejected(self):
        trace = self.trace()
        trace[0]["window_limit"] = trace[1]["window_limit"] = 1
        with self.assertRaises(Failure):
            validate_read_trace(trace, set(), required_phases={"hash"})
        trace = self.trace()
        trace[2]["error"] = 5
        with self.assertRaises(Failure):
            validate_read_trace(trace, set(), required_phases={"hash"})


class CommandRecorderTests(unittest.TestCase):
    def test_full_outputs_are_append_only_and_snapshots_stay_compact(self):
        with tempfile.TemporaryDirectory() as directory:
            args = argparse.Namespace(tool=Path(sys.executable), work_dir=Path(directory),
                                      faults="none", case=None)
            harness = DedupHarness(args)
            try:
                expected = "full-output-" * 10000 + "\n"
                journal_prefix = None
                for _ in range(3):
                    result = harness.command(sys.executable, "-c",
                                             "import sys; print('full-output-' * 10000); print('diagnostic', file=sys.stderr)")
                    self.assertEqual(result.stdout, expected)
                    self.assertEqual(result.stderr, "diagnostic\n")
                    current = harness.command_journal.read_bytes()
                    if journal_prefix is not None:
                        self.assertTrue(current.startswith(journal_prefix))
                    journal_prefix = current
                harness.evidence["status"] = "passed"
                harness.flush()
                records = [json.loads(line) for line in harness.command_journal.read_text().splitlines()]
                completed = [item for item in records if item["event"] == "complete"]
                self.assertEqual([item["stdout"] for item in completed], [expected] * 3)
                self.assertEqual([item["stderr"] for item in completed], ["diagnostic\n"] * 3)
                snapshot = json.loads(harness.evidence_path.read_text())
                self.assertEqual(len(snapshot["commands"]), 3)
                self.assertLess(harness.evidence_path.stat().st_size, 16384)
                self.assertTrue(all("journal_seq" in item for item in snapshot["commands"]))
                self.assertTrue(all("stdout" not in item for item in snapshot["commands"]))
            finally:
                harness.cleanup()
                self.assertEqual(json.loads(harness.evidence_path.read_text())["cleanup_errors"], [])

    def test_timeout_preserves_partial_raw_streams_and_failure_record(self):
        with tempfile.TemporaryDirectory() as directory:
            args = argparse.Namespace(tool=Path(sys.executable), work_dir=Path(directory),
                                      faults="none", case=None)
            harness = DedupHarness(args)
            try:
                with self.assertRaises(Failure):
                    harness.command(sys.executable, "-c",
                                    "import time; print('before-timeout', flush=True); time.sleep(60)",
                                    timeout=1)
                records = [json.loads(line) for line in harness.command_journal.read_text().splitlines()]
                self.assertEqual(records[-1]["event"], "complete")
                self.assertEqual(records[-1]["timeout"], 1)
                self.assertEqual(records[-1]["stdout"], "before-timeout\n")
            finally:
                harness.cleanup()


if __name__ == "__main__":
    unittest.main()
