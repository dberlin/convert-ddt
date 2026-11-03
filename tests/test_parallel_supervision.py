"""Consumer-visible stall handling with a real diagnostic-only child process."""

from argparse import Namespace
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from parallel_actual_validation import Child, Runner, process_sample


class ParallelSupervisionTests(unittest.TestCase):
    def test_exiting_process_can_lose_io_access_before_becoming_zombie(self):
        fields = ["S"] + ["0"] * 21
        stat_reads = 0

        def proc_read(path, *args, **kwargs):
            nonlocal stat_reads
            if path.name == "stat":
                stat_reads += 1
                fields[6] = "0" if stat_reads == 1 else "4"  # Linux PF_EXITING.
                return "99 (child) " + " ".join(fields)
            raise PermissionError("Exiting process has dropped its mm")

        with patch.object(Path, "read_text", proc_read):
            self.assertIsNone(process_sample(99))

    def test_live_process_io_permission_loss_is_not_hidden(self):
        fields = ["S"] + ["0"] * 21

        def proc_read(path, *args, **kwargs):
            if path.name == "stat":
                return "99 (child) " + " ".join(fields)
            raise PermissionError("Live process access denied")

        with patch.object(Path, "read_text", proc_read):
            with self.assertRaises(PermissionError):
                process_sample(99)

    def test_diagnostic_writes_do_not_extend_stall_deadline(self):
        parent = Path(__file__).resolve().parents[1] / ".build"
        with tempfile.TemporaryDirectory(prefix="validator-idle-", dir=parent) as directory:
            runner = Runner.__new__(Runner)
            runner.root = Path(directory)
            runner.report_path = runner.root / "report.json"
            runner.report = {"commands": [], "blocking_pids": []}
            runner.children = []
            runner.args = Namespace(startup_timeout=30, stage_timeout=30, stall_timeout=0.6)
            program = (
                "import json,sys,time\n"
                "line=json.dumps({'phase':'blocked','entries':0,'bytes':0,'diagnostic':'x'*8192})+'\\n'\n"
                "while True:\n"
                " sys.stderr.write(line);sys.stderr.flush();time.sleep(0.05)\n"
            )
            child = Child(runner, "idle-diagnostics", [sys.executable, "-c", program])
            detected = False
            deadline = time.monotonic() + 4
            try:
                while time.monotonic() < deadline:
                    try:
                        child.tick()
                    except RuntimeError:
                        detected = True
                        break
                    time.sleep(0.05)
            finally:
                child.stop()
            self.assertTrue(detected, "Diagnostic-only output kept a stalled validator alive")
            self.assertIsNotNone(child.process.poll(), "Cancelled validator did not exit")
            self.assertEqual(runner.report["blocking_pids"], [])

    def test_counter_reset_between_phases_and_classes_is_measured_work(self):
        parent = Path(__file__).resolve().parents[1] / ".build"
        with tempfile.TemporaryDirectory(prefix="validator-phases-", dir=parent) as directory:
            runner = Runner.__new__(Runner)
            runner.root = Path(directory)
            runner.report_path = runner.root / "report.json"
            runner.report = {"commands": [], "blocking_pids": []}
            runner.children = []
            runner.args = Namespace(startup_timeout=10, stage_timeout=10, stall_timeout=0.6)
            program = (
                "import json,sys,time\n"
                "print(json.dumps({'phase':'flat-preflight','checksum':'blake3','class':1,'entries':100}),flush=True)\n"
                "for phase,cl in [('flat-readback',1),('flat-readback',2),('flat-copy',2)]:\n"
                " for count in range(1,9):\n"
                "  print(json.dumps({'phase':phase,'checksum':'blake3','class':cl,'entries':count}),flush=True)\n"
                "  time.sleep(0.1)\n"
            )
            child = Child(runner, "advancing-phases", [sys.executable, "-c", program])
            deadline = time.monotonic() + 8
            try:
                while not child.tick() and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertEqual(child.process.poll(), 0, "Advancing conversion was falsely cancelled")
                self.assertEqual(child.record["native_progress"]["phase"], "flat-copy")
                self.assertEqual(child.record["native_progress"]["class"], 2)
                self.assertEqual(child.record["native_progress"]["entries"], 8)
            finally:
                child.stop()


if __name__ == "__main__":
    unittest.main()
