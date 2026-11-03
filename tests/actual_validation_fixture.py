#!/usr/bin/env python3
"""Exercise actual-checkpoint validation on disposable RAIDZ2 block devices."""

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
import tempfile
import threading
import time
import traceback
import uuid
from unittest import mock

from validate_actual_ddt import ActualHarness, GIB
from integration import Failure

MIB = 1024 ** 2


def digest(path):
    value = hashlib.sha256()
    with path.open('rb', buffering=0) as stream:
        for block in iter(lambda: stream.read(MIB), b''):
            value.update(block)
    return value.hexdigest()


class Fixture:
    def __init__(self, args):
        self.args = args
        self.root = Path(tempfile.mkdtemp(prefix='ddt-actual-fixture-', dir=args.work_dir)).resolve()
        self.report_path = self.root.with_suffix('.json')
        self.pool = 'ddt_actual_fixture_' + uuid.uuid4().hex[:12]
        self.guid = None
        self.loops = []
        self.retained = False
        self.report = {'status': 'running', 'case': args.case, 'work_directory': str(self.root), 'pool': self.pool,
                       'commands': [], 'loops': self.loops, 'actual_runs': []}
        self.save()

    def save(self):
        temporary = self.report_path.with_suffix('.json.tmp')
        temporary.write_text(json.dumps(self.report, indent=2) + '\n')
        temporary.replace(self.report_path)

    def command(self, *args, timeout=180):
        result = subprocess.run([str(arg) for arg in args], input='', text=True,
                                capture_output=True, timeout=timeout)
        self.report['commands'].append({'argv': list(map(str, args)), 'returncode': result.returncode,
                                        'stdout': result.stdout, 'stderr': result.stderr})
        self.save()
        if result.returncode:
            raise RuntimeError((args, result.returncode, result.stderr))
        return result.stdout

    def assert_pool(self):
        assert self.guid and self.command('zpool', 'get', '-Hp', '-o', 'value', 'guid', self.pool).strip() == self.guid

    def assert_loop(self, entry):
        assert re.fullmatch(r'/dev/loop\d+', entry['device']), entry
        image = Path(entry['image']).lstat()
        assert stat.S_ISREG(image.st_mode) and image.st_uid == 0 and image.st_nlink == 1
        assert [image.st_dev, image.st_ino, image.st_size] == entry['image_identity']
        device = Path(entry['device'])
        node = device.stat()
        assert stat.S_ISBLK(node.st_mode)
        sysdir = Path('/sys/class/block') / device.name
        assert (sysdir / 'dev').read_text().strip() == '%d:%d' % (os.major(node.st_rdev), os.minor(node.st_rdev))
        status = json.loads(self.command('losetup', '--json', '--output',
                                         'NAME,BACK-INO,BACK-MAJ:MIN,OFFSET,SIZELIMIT',
                                         entry['device']))['loopdevices']
        assert len(status) == 1 and status[0]['name'] == entry['device']
        backing = status[0]
        assert backing['back-ino'] == image.st_ino
        assert backing['back-maj:min'] == '%d:%d' % (os.major(image.st_dev), os.minor(image.st_dev))
        assert backing['offset'] == 0 and backing['sizelimit'] == 0

    def create(self):
        parts = []
        for index in range(12):
            image = self.root / ('leaf-%02d.img' % index)
            size = 512 * MIB
            mbr = bytearray(512)
            mbr[446:462] = struct.pack('<B3sB3sII', 0, bytes(3), 0xbf, bytes(3),
                                       2048, size // 512 - 4096)
            mbr[510:512] = b'\x55\xaa'
            with image.open('xb') as stream:
                stream.truncate(size)
                stream.write(mbr)
            identity = image.stat()
            self.report['loop_attach_intent'] = {'image': str(image),
                                                 'image_identity': [identity.st_dev, identity.st_ino, identity.st_size]}
            # A failed or interrupted losetup can have attached an unreported loop.
            self.retained = True
            self.save()
            loop = self.command('losetup', '--find', '--show', '--partscan', image).strip()
            assert re.fullmatch(r'/dev/loop\d+', loop), loop
            self.loops.append({'device': loop, **self.report['loop_attach_intent']})
            del self.report['loop_attach_intent']
            self.save()
            self.retained = False
            partition = Path(loop + 'p1')
            deadline = time.monotonic() + 30
            while not partition.exists() and time.monotonic() < deadline:
                time.sleep(0.1)
            assert partition.exists() and stat.S_ISBLK(partition.stat().st_mode)
            parts.append(str(partition))
        if shutil.which('udevadm'):
            self.command('udevadm', 'settle', '--timeout=30')
        for entry, partition in zip(self.loops, parts):
            self.assert_loop(entry)
            sysdir = Path('/sys/class/block')
            value = Path(partition).stat()
            assert (sysdir / Path(partition).name / 'dev').read_text().strip() == '%d:%d' % (os.major(value.st_rdev), os.minor(value.st_rdev))
        mount = self.root / 'source'
        self.retained = True
        self.command('zpool', 'create', '-f', '-o', 'cachefile=none', '-o', 'ashift=12',
                     '-o', 'feature@fast_dedup=disabled', '-O', 'mountpoint=' + str(mount),
                     '-O', 'dedup=blake3', '-O', 'compression=off', '-O', 'atime=off',
                     self.pool, 'raidz2', *parts[:6], 'raidz2', *parts[6:])
        self.guid = self.command('zpool', 'get', '-Hp', '-o', 'value', 'guid', self.pool).strip()
        self.report['source_guid'] = self.guid
        self.save()
        self.retained = False
        payload = hashlib.shake_256(b'actual-ddt-fixture-data').digest(8 * MIB)
        for name in ('original', 'duplicate'):
            (mount / name).write_bytes(payload)
        self.command('zfs', 'create', '-o', 'mountpoint=legacy', self.pool + '/legacy')
        legacy = self.root / 'legacy-source'
        legacy.mkdir()
        self.command('mount', '-t', 'zfs', self.pool + '/legacy', legacy)
        for name in ('original', 'duplicate'):
            (legacy / name).write_bytes(payload)
        self.command('umount', legacy)
        self.command('zfs', 'create', '-s', '-V', '16M', '-b', '128K', '-o', 'dedup=blake3',
                     '-o', 'compression=off', '-o', 'volmode=dev', self.pool + '/volume')
        volume = Path('/dev/zvol') / self.pool / 'volume'
        deadline = time.monotonic() + 30
        while not volume.exists() and time.monotonic() < deadline:
            time.sleep(0.1)
        assert volume.exists() and stat.S_ISBLK(volume.stat().st_mode)
        with volume.open('r+b', buffering=0) as stream:
            assert stream.write(payload * 2) == len(payload) * 2
            os.fsync(stream.fileno())
        self.command('zpool', 'sync', self.pool)
        self.command('zfs', 'snapshot', '-r', self.pool + '@baseline')
        self.command('zpool', 'set', 'feature@fast_dedup=enabled', self.pool)
        self.expected_file = hashlib.sha256(payload).hexdigest()
        self.expected_volume = hashlib.sha256(payload * 2).hexdigest()
        self.mount = mount
        self.volume = volume

    def validate(self):
        runs = self.root / 'runs'
        runs.mkdir(mode=0o700)
        command = [sys.executable, str(Path(__file__).with_name('validate_actual_ddt.py')),
                   '--pool', self.pool, '--converter', str(self.args.converter),
                   '--clone-helper', str(self.args.clone_helper), '--work-dir', str(runs),
                   '--create-checkpoint']
        self.retained = True
        result = subprocess.run(command, input='', capture_output=True, text=True, timeout=1800)
        found = re.search(r'^Evidence: (.+)$', result.stdout, re.MULTILINE)
        assert found, (result.returncode, result.stdout, result.stderr)
        evidence_path = Path(found[1])
        assert evidence_path.parent == runs
        evidence = json.loads(evidence_path.read_text())
        self.report['actual_runs'].append(evidence)
        reported_retained = evidence.get('resources_retained', True)
        self.save()
        if result.returncode:
            raise RuntimeError(('Actual validator failed', evidence.get('error'), result.stdout, result.stderr))
        assert evidence['status'] == 'passed'
        assert not reported_retained
        assert len(evidence['overlays']) == 12
        remaining_images = [o['image'] for o in evidence['overlays'] if os.path.lexists(o['image'])]
        assert not remaining_images, ('COW images outlived their checkpoint protection', remaining_images)
        assert all(o.get('image_retired') for o in evidence['overlays'])
        assert evidence['resources']['dependent_images_retired']
        assert not list(Path(evidence['resources']['devices']).iterdir())
        verification = evidence['zdb_verification']
        assert verification['completed'] and verification['returncode'] == 0 and verification['exported']
        assert verification['metadata_checksums'] and verification['reference_allocation']
        assert verification['block_pointer_count'] > 0
        assert verification['pool_guid'] != self.guid
        self.assert_pool()
        self.command('zpool', 'wait', '-t', 'discard', self.pool)
        assert self.command('zpool', 'get', '-Hp', '-o', 'value', 'checkpoint', self.pool).strip() in ('-', '0')
        self.retained = False
        assert digest(self.mount / 'original') == self.expected_file
        assert digest(self.mount / 'duplicate') == self.expected_file
        assert digest(self.volume) == self.expected_volume
        layout = self.command('zdb', '-D', self.pool)
        assert re.search(r'version=0\b', layout), 'Source DDT format changed'
        self.report['verification'] = {'original_file_hashes_match': True,
                                       'original_volume_hash_matches': True,
                                       'source_still_legacy': True,
                                       'exported_zdb_metadata_reference_allocation_verified': True,
                                       'dependent_images_retired': True}
        self.save()

    def harness(self, harness_type=ActualHarness):
        runs = self.root / 'lifecycle-runs'
        runs.mkdir(mode=0o700)
        args = argparse.Namespace(pool=self.pool, converter=self.args.converter,
                                  clone_helper=self.args.clone_helper, work_dir=runs,
                                  create_checkpoint=True, max_overlay_bytes=512 * GIB,
                                  reserve_free_bytes=64 * GIB)
        return harness_type(args)

    def clear_fixture_lease(self, allowed):
        path = Path('/run/lock') / ('convert-ddt-actual-' + self.guid + '.lock')
        fd = os.open(path, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            content = os.read(fd, 65536)
            assert content in allowed
            os.ftruncate(fd, 0)
            os.fsync(fd)
        finally:
            os.close(fd)

    def claimed_zil(self):
        dataset = self.pool + '/claimed-zil'
        key = self.root / 'claimed-zil.key'
        key.write_bytes(hashlib.sha256(b'claimed-zil-fixture-key').digest())
        key.chmod(0o600)
        mount = self.root / 'claimed-zil-source'
        self.command('zfs', 'create', '-o', 'encryption=aes-256-gcm',
                     '-o', 'keyformat=raw', '-o', 'keylocation=' + key.as_uri(),
                     '-o', 'mountpoint=' + str(mount), '-o', 'sync=always', dataset)
        payload = hashlib.shake_256(b'claimed-zil-fixture-data').digest(2 * MIB)
        with (mount / 'sync-file').open('wb') as stream:
            assert stream.write(payload) == len(payload)
            stream.flush()
            os.fsync(stream.fileno())
        expected = hashlib.sha256(payload).hexdigest()
        self.command('zfs', 'snapshot', dataset + '@claimed')
        devices = self.root / 'source-devices'
        devices.mkdir()
        for index, entry in enumerate(self.loops):
            self.assert_loop(entry)
            (devices / ('leaf-%02d' % index)).symlink_to(entry['device'] + 'p1')
        self.retained = True
        self.command('zpool', 'export', self.pool)
        self.command('zpool', 'import', '-N', '-d', devices, '-o', 'cachefile=none', self.guid)
        self.assert_pool()
        self.command('zfs', 'mount', self.pool)
        cache = self.root / 'claimed-zil.cache'
        cache.touch()
        output = self.command('zdb', '-U', cache, '-e', '-p', devices, '-L', '-dd', dataset)
        headers = re.findall(r'ZIL header: claim_txg (\d+), claim_blk_seq (\d+)', output)
        assert len(headers) == 1 and all(int(value) > 0 for value in headers[0]), (
            'Encrypted dataset did not retain a nonempty claimed ZIL', output)
        assert self.command('zfs', 'get', '-H', '-o', 'value', 'keystatus', dataset).strip() == 'unavailable'
        fixture = self

        class ClaimedHarness(ActualHarness):
            def create_checkpoint(h):
                super().create_checkpoint()
                checkpoint_txg = h.checkpoint['txg']
                for number in range(4):
                    with (fixture.mount / 'live-progress').open('wb') as stream:
                        stream.write(bytes([number]) * MIB)
                        stream.flush()
                        os.fsync(stream.fileno())
                    fixture.command('zpool', 'sync', fixture.pool)
                text = fixture.command('zdb', '-U', cache, '-e', '-p', devices,
                                       '-L', '-u', fixture.guid)
                live = text.split('Checkpointed uberblock found:', 1)[0]
                values = re.findall(r'^\s*txg = (\d+)$', live, re.MULTILINE)
                assert len(values) == 1 and int(values[0]) > checkpoint_txg + 1
                fixture.report['claimed_zil'] = {
                    'claim_txg': int(headers[0][0]), 'claim_block_sequence': int(headers[0][1]),
                    'checkpoint_txg': checkpoint_txg, 'live_txg': int(values[0]),
                    'encrypted_file_sha256': expected}
                fixture.save()

            def import_clone(h):
                super().import_clone()
                h.command('zfs', 'load-key', '-L', key.as_uri(), h.clone.name + '/claimed-zil')

        h = self.harness(ClaimedHarness)
        try:
            h.validate()
            h.evidence['status'] = 'passed'
        finally:
            errors = h.cleanup()
            self.report['actual_runs'].append(h.evidence)
            self.save()
            assert not errors, errors
        self.command('zpool', 'wait', '-t', 'discard', self.pool)
        self.assert_pool()
        self.command('zfs', 'load-key', dataset)
        self.command('zfs', 'mount', dataset)
        assert digest(mount / 'sync-file') == expected
        assert digest(self.mount / 'original') == self.expected_file
        assert digest(self.mount / 'duplicate') == self.expected_file
        assert digest(self.volume) == self.expected_volume
        assert re.search(r'version=0\b', self.command('zdb', '-D', self.pool))
        self.report['claimed_zil']['source_data_and_legacy_ddt_preserved'] = True
        self.retained = False
        self.save()

    def checkpoint_probe(self):
        h = self.harness()
        parameters = ('spa_load_verify_metadata', 'spa_load_verify_data')
        proof = {}
        self.report['checkpoint_probe'] = proof

        def kernel_parameters():
            values = {}
            for name in parameters:
                try:
                    values[name] = (Path('/sys/module/zfs/parameters') / name).read_text().strip()
                except (FileNotFoundError, PermissionError):
                    pass
            return values

        def native_txg(checkpoint):
            # The independent oracle deliberately retains native import verification.
            options = ('-k', '-u') if checkpoint else ('-u',)
            output = self.command('zdb', *options, self.pool)
            if not checkpoint:
                # Native -u also dumps a second, older checkpoint uberblock.
                heading = re.search(r'^Uberblock:[ \t]*$', output, re.MULTILINE)
                assert heading is not None, 'Native zdb did not identify its live uberblock'
                output = output[heading.end():].split('\nCheckpointed uberblock found:', 1)[0]
            field = 'checkpoint_txg' if checkpoint else 'txg'
            values = {int(value) for value in re.findall(
                r'^\s*' + field + r'\s*=\s*(\d+)\s*$', output, re.MULTILINE)}
            assert len(values) == 1, ('Native zdb TXG is missing or ambiguous', field, values)
            value = values.pop()
            assert value > 0, ('Native zdb TXG is not positive', field, value)
            return value

        proof['kernel_parameters_before'] = kernel_parameters()
        proof['kernel_parameters_unreadable'] = [
            name for name in parameters if name not in proof['kernel_parameters_before']]
        self.retained = True
        try:
            h.preflight()
            h.create_checkpoint()
            original_checkpoint = dict(h.checkpoint)
            expected = native_txg(True)
            observed = h.checkpoint_txg()
            proof.update(checkpoint_before=original_checkpoint,
                         native_checkpoint_txg_before=expected,
                         harness_checkpoint_txg_before=observed)
            self.save()
            assert observed == expected and original_checkpoint.get('txg') == expected, (
                'Checkpoint probe disagrees with native checkpoint identity', proof)
            live_before = native_txg(False)
            # Force a new live transaction without modifying any checkpoint data.
            with (self.mount / 'checkpoint-probe-live-write').open('xb') as stream:
                payload = hashlib.shake_256(b'checkpoint-probe-live-write').digest(MIB)
                assert stream.write(payload) == len(payload)
                stream.flush()
                os.fsync(stream.fileno())
            self.command('zpool', 'sync', self.pool)
            live_after = native_txg(False)
            native_after = native_txg(True)
            observed_after = h.checkpoint_txg()
            proof.update(live_txg_before=live_before, live_txg_after=live_after,
                         native_checkpoint_txg_after=native_after,
                         harness_checkpoint_txg_after=observed_after)
            self.save()
            assert live_after > live_before and live_after > expected, (
                'Owned write did not establish a newer live TXG', proof)
            assert native_after == expected and observed_after == expected, (
                'Checkpoint probe followed the live TXG instead of the checkpoint', proof)
            h.assert_checkpoint()
            assert h.checkpoint == original_checkpoint, ('Owned checkpoint identity changed', proof)
            proof['original_checkpoint_accepted'] = True
        finally:
            try:
                errors = h.cleanup()
                proof['cleanup_errors'] = errors
                assert not errors, errors
                assert not h.command_children, 'Checkpoint probe left an owned command reader'
                self.assert_pool()
                self.command('zpool', 'wait', '-t', 'discard', self.pool)
                assert self.command('zpool', 'get', '-Hp', '-o', 'value',
                                    'checkpoint', self.pool).strip() in ('-', '0')
                self.clear_fixture_lease((b'',))
                self.retained = False
                proof['kernel_parameters_after'] = kernel_parameters()
                assert proof['kernel_parameters_after'] == proof['kernel_parameters_before'], (
                    'Read-only checkpoint probe changed kernel verification parameters', proof)
            finally:
                self.report['actual_runs'].append(h.evidence)
                self.save()

    def lease_handoff(self):
        h = self.harness()
        path = Path('/run/lock') / ('convert-ddt-actual-' + self.guid + '.lock')
        competing = json.dumps({'source_guid': self.guid, 'journal': 'fixture competing validator',
                                'operation': uuid.uuid4().hex}).encode()
        real_flock = fcntl.flock
        injected = False
        writer = 'import os,fcntl,sys; f=os.open(sys.argv[1],os.O_RDWR); fcntl.flock(f,fcntl.LOCK_EX); os.write(f,sys.argv[2].encode()); os.fsync(f); os.close(f)'

        def acquire(fd, operation):
            nonlocal injected
            if not injected and os.readlink('/proc/self/fd/' + str(fd)) == str(path):
                injected = True
                subprocess.run([sys.executable, '-c', writer, str(path), competing.decode()],
                               input='', capture_output=True, text=True, check=True)
            return real_flock(fd, operation)

        rejected = False
        self.retained = True
        try:
            try:
                with mock.patch('validate_actual_ddt.fcntl.flock', side_effect=acquire):
                    h.preflight()
            except Failure:
                rejected = True
        finally:
            h.cleanup()
            observed = path.read_bytes()
            self.report['lease_handoff'] = {'rejected': rejected, 'competing_record_preserved': observed == competing}
            self.report['actual_runs'].append(h.evidence)
            self.save()
            self.clear_fixture_lease((b'', competing))
            self.retained = False
        assert injected and rejected and observed == competing, 'Competing durable checkpoint lease was overwritten'

    def interrupted_command(self):
        h = self.harness()
        self.retained = True
        h.preflight()
        h.create_checkpoint()
        original_checkpoint = dict(h.checkpoint)
        ready = self.root / 'reader-ready'
        draining = self.root / 'reader-draining'
        release = self.root / 'reader-release'
        cancelled = threading.Event()
        driver_errors = []
        child_code = (
            'import os,signal,sys,time; from pathlib import Path\n'
            'ready,draining,release,backing=map(Path,sys.argv[1:])\n'
            'def stop(signum,frame):\n'
            ' draining.touch()\n'
            ' while not release.exists(): time.sleep(0.01)\n'
            ' sys.exit(0)\n'
            'signal.signal(signal.SIGTERM,stop)\n'
            'stream=backing.open("rb",buffering=0); stream.read(512)\n'
            'ready.write_text(str(os.getpid()))\n'
            'while True: stream.seek(0); stream.read(512); time.sleep(0.01)\n'
        )

        def interrupt(signum, frame):
            raise KeyboardInterrupt('Disposable checkpoint-reader interruption')

        def await_file(path):
            deadline = time.monotonic() + 30
            while not path.exists():
                if cancelled.wait(0.01):
                    return False
                if time.monotonic() > deadline:
                    raise TimeoutError(str(path))
            return True

        def driver():
            try:
                if await_file(ready):
                    os.kill(os.getpid(), signal.SIGTERM)
                if await_file(draining):
                    os.kill(os.getpid(), signal.SIGTERM)
            except BaseException as error:
                driver_errors.append(repr(error))
                release.touch()
                os.kill(os.getpid(), signal.SIGTERM)

        previous_handler = signal.signal(signal.SIGTERM, interrupt)
        thread = threading.Thread(target=driver)
        thread.start()
        observed = None
        retained = False
        pid = None
        try:
            try:
                h.last_guard = time.monotonic()
                h.command(sys.executable, '-c', child_code, ready, draining, release,
                          self.loops[0]['device'] + 'p1', timeout=60)
            except KeyboardInterrupt:
                pass
            pid = int(ready.read_text())
            os.kill(pid, 0)
            h.cleanup()
            status = json.loads(self.command('zpool', 'status', '-j', '--json-int', self.pool))['pools'][self.pool]
            observed = status.get('checkpoint_stats', {})
            retained = h.evidence.get('resources_retained', False)
            self.report['interrupted_command'] = {'checkpoint_before': original_checkpoint,
                                                   'checkpoint_after_cleanup': observed,
                                                   'resources_retained': retained}
            self.save()
        finally:
            cancelled.set()
            release.touch()
            thread.join(timeout=30)
            assert not thread.is_alive(), 'Interruption driver did not stop'
            signal.signal(signal.SIGTERM, previous_handler)
            if pid is None and ready.exists():
                pid = int(ready.read_text())
            if pid is not None:
                try:
                    os.waitpid(pid, 0)
                except ChildProcessError:
                    pass
            h.preserve = False
            errors = h.cleanup()
            assert not errors, errors
            lease = Path('/run/lock') / ('convert-ddt-actual-' + self.guid + '.lock')
            content = lease.read_bytes()
            if content:
                owner = json.loads(content)
                assert owner['source_guid'] == self.guid and owner['journal'] == str(h.evidence_path)
            self.clear_fixture_lease((b'', content))
            self.report['actual_runs'].append(h.evidence)
            self.save()
            self.retained = False
        assert not driver_errors, driver_errors
        assert retained and observed.get('state') == 'EXISTS' and observed.get('start_time') == original_checkpoint['start_time'], 'Live checkpoint reader lost its checkpoint protection after repeated interruption'

    def cleanup(self):
        if self.retained:
            self.report['cleanup_retained'] = True
            self.save()
            return
        try:
            if self.guid:
                self.assert_pool()
                self.command('zpool', 'wait', '-t', 'discard', self.pool)
                self.command('zpool', 'destroy', '-f', self.pool)
                self.guid = None
            for entry in reversed(self.loops):
                if entry.get('detached'):
                    continue
                self.assert_loop(entry)
                entry['detach_requested'] = True
                self.save()
                self.command('losetup', '--detach', entry['device'])
                # Detach may be deferred while an unexpected process holds the device.
                backing = Path('/sys/class/block') / Path(entry['device']).name / 'loop/backing_file'
                deadline = time.monotonic() + 30
                while backing.exists() and time.monotonic() < deadline:
                    time.sleep(0.1)
                assert not backing.exists(), ('Loop still has a live backing file', entry)
                entry['detached'] = True
                self.save()
            if shutil.which('udevadm'):
                self.command('udevadm', 'settle', '--timeout=30')
            self.report['cleanup_retained'] = False
            self.save()
            shutil.rmtree(self.root)
        except BaseException:
            self.retained = True
            self.report['cleanup_retained'] = True
            self.save()
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--converter', required=True, type=Path)
    parser.add_argument('--clone-helper', required=True, type=Path)
    parser.add_argument('--work-dir', type=Path, default=Path('/var/tmp'))
    parser.add_argument('--case', choices=('conversion', 'interrupted-command', 'lease-handoff',
                                          'checkpoint-probe', 'claimed-zil'), default='conversion')
    args = parser.parse_args()
    if os.geteuid() != 0 or not hasattr(os, 'unshare'):
        parser.error('root and Python 3.12+ are required')
    for name in ('converter', 'clone_helper'):
        path = getattr(args, name).resolve()
        if not path.is_file() or not os.access(path, os.X_OK):
            parser.error(name + ' must be an executable file')
        setattr(args, name, path)
    for executable in ('losetup', 'zpool', 'zfs', 'zdb', 'qemu-img', 'qemu-nbd', 'mount', 'umount'):
        if not shutil.which(executable):
            parser.error('required executable missing: ' + executable)
    os.umask(0o077)
    os.unshare(os.CLONE_NEWNS)
    subprocess.run(['mount', '--make-rprivate', '/'], input=b'', check=True)
    # Keep loop-device allocation and device-node retirement within one fixture.
    fixture_lock = os.open('/run/lock/convert-ddt-actual-fixture.lock',
                           os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    lock_stat = os.fstat(fixture_lock)
    assert stat.S_ISREG(lock_stat.st_mode) and lock_stat.st_uid == 0 and lock_stat.st_nlink == 1 and lock_stat.st_mode & 0o022 == 0
    fcntl.flock(fixture_lock, fcntl.LOCK_EX)
    fixture = Fixture(args)
    print('Evidence: ' + str(fixture.report_path), flush=True)
    outcome = 1
    try:
        fixture.create()
        if args.case == 'conversion':
            fixture.validate()
        elif args.case == 'interrupted-command':
            fixture.interrupted_command()
        elif args.case == 'checkpoint-probe':
            fixture.checkpoint_probe()
        elif args.case == 'claimed-zil':
            fixture.claimed_zil()
        else:
            fixture.lease_handoff()
        fixture.report['status'] = 'passed'
        outcome = 0
    except BaseException as error:
        fixture.report.update(status='failed', error=repr(error), traceback=traceback.format_exc())
        print(traceback.format_exc(), file=sys.stderr, flush=True)
    finally:
        try:
            fixture.cleanup()
        except BaseException as error:
            fixture.report.update(cleanup_error=repr(error), cleanup_traceback=traceback.format_exc())
            outcome = 1
        fixture.report['finished'] = time.time()
        fixture.save()
        os.close(fixture_lock)
    print(('PASS' if outcome == 0 else 'FAIL') + '; evidence: ' + str(fixture.report_path), flush=True)
    return outcome


if __name__ == '__main__':
    sys.exit(main())
