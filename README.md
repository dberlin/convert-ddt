# convert-ddt

Note: 
This tool is entirely AI written, but i have run and tested the conversion tool  on multiple pools of several hundred terabytes, totally approximately 6 billion dedup entries across all their tables (IE almost a terabyte worth of dedup tables).  All pools passed full scrubs after being converted.  However, you would still be a complete idiot to not have a backup, and you should still prefer to create new pools with fast dedup enabled rather than convert using these tools.    It was intended for the case where that is impractical.


Offline OpenZFS legacy deduplication table (DDT) conversion. `convert-ddt` migrates existing legacy tables to version 1 while preserving data block locations, reference counts, snapshots, clones and volume contents.

The converter is a native, version-pinned offline writer. A verified backup and exclusive maintenance access are prerequisites, not optional protections supplied by the program. It does not automatically run a scrub.

## Platform and build

Use a native **Linux** build and maintenance environment with **OpenZFS 2.4.4**. The tools link OpenZFS private userspace interfaces, not a stable public ABI; do not substitute another OpenZFS release or an arbitrary system `libzpool`. The converter accepts a loaded 2.4.4 kernel module. Use matching kernel and administrative userspace tools. No other platform/version is supported here.

Build dependencies include **CMake 3.24 or newer**, a C compiler, GNU make (also when using Ninja), pkg-config, patch, tar/gzip, and development headers/libraries for zlib, OpenSSL, UUID, blkid, udev, tirpc and Jansson. Ninja is optional; CMake also supports Unix Makefiles. Install the OpenZFS userspace build prerequisites for your distribution; package names vary. Python 3 is required for the default Python tests, and the installed ZFS administration commands are needed for root integration fixtures.

The namespace-isolated checkpoint/COW fixtures require Python 3.12 or newer (`os.unshare`); install that version when running the complete fixture set.

From the repository root:

```sh
cmake -S . -B build
cmake --build build --parallel 8
ctest --test-dir build --output-on-failure
```

The first build downloads and SHA256-verifies the pinned OpenZFS 2.4.4 release archive, applies the maintained native correction, and builds fresh userspace static libraries inside the CMake binary directory. It does not reuse an installed `libzpool` or generate OpenZFS files in the source checkout. Single-configuration builds produce:

| Artifact | Purpose |
| --- | --- |
| `build/convert-ddt` | Legacy DDT conversion and registered-layout inspection |
| `build/clone-pool` | Copy-validation helper |
| `build/validate-ddt` | Native read-only full DDT census/fingerprint validator |
| `build/validate-content` | Native read-only inventory and targeted content validator |
| `build/test_transform` | DDT layout transformation tests |

Choose a generator on the first configure: add `-G Ninja` for Ninja or `-G "Unix Makefiles"` for GNU make. Use a separate binary directory when changing generators. The same `cmake --build` and `ctest` commands work with either generator. `-DCMAKE_BUILD_TYPE=Release` is supported; native private-header ABI flags and test assertions remain enabled independently of build type.

### Dependency and offline configuration

The upstream OpenZFS build uses GNU make regardless of the CMake generator. `OPENZFS_BUILD_JOBS` is a positive integer controlling that build's parallelism; its default is the detected CPU count capped at 8. It is separate from `cmake --build --parallel`, which controls project compilation.

Use a binary directory and native dependency paths without whitespace, quotes or Make-special characters; the upstream Autoconf/Make build cannot safely represent those paths. The CMake configure step rejects unsupported paths before starting that build.

For an offline build, supply an existing OpenZFS 2.4.4 release archive with `OPENZFS_ARCHIVE`. The same pinned SHA256 is checked; a different release or a modified archive is refused. All other development dependencies must already be installed. For example:

```sh
cmake -S . -B build -G Ninja \
  -DOPENZFS_ARCHIVE=/absolute/path/to/zfs-2.4.4.tar.gz \
  -DOPENZFS_BUILD_JOBS=4 \
  -DCMAKE_PREFIX_PATH=/absolute/path/to/development-prefix
cmake --build build --parallel 8
```

Use ordinary CMake dependency discovery for non-system installations: `CMAKE_PREFIX_PATH`, `CMAKE_INCLUDE_PATH`, `CMAKE_LIBRARY_PATH`, and OpenSSL's `OPENSSL_ROOT_DIR`. `JANSSON_INCLUDE_DIR` and `JANSSON_LIBRARY` override Jansson discovery. The OpenZFS module also accepts `OPENZFS_UDEV_INCLUDE_DIR`/`OPENZFS_UDEV_LIBRARY`, `OPENZFS_BLKID_INCLUDE_DIR`/`OPENZFS_BLKID_LIBRARY`, `OPENZFS_UUID_INCLUDE_DIR`/`OPENZFS_UUID_LIBRARY`, and `OPENZFS_TIRPC_INCLUDE_DIR`/`OPENZFS_TIRPC_LIBRARY`. Select headers and libraries compatible with the build host; CMake does not synthesize a private dependency installation or replace host runtime libraries.

`OPENZFS_MAKE_EXECUTABLE` and `OPENZFS_PATCH_EXECUTABLE` select the upstream GNU make and patch programs when they are not found on `PATH`. The dependency build uses the release's generated configure script; it does not require regenerating it with Autoconf/Automake. OpenZFS administration programs (`zpool`, `zfs`, `zdb`) are not built or installed by default: install matching tools separately and make them available on `PATH` for integration fixtures and maintenance.

Set the compiler with `CC` on the initial configure or `-DCMAKE_C_COMPILER=...`; use the normal CMake compiler/linker cache settings rather than upstream Makefile fragments. Reconfiguration is managed by CMake. `-DBUILD_TESTING=OFF` disables test registration and the Python interpreter requirement, but keeps the native helper build targets available.

### Pinned native correction and attribution

The OpenZFS implementation and on-disk interfaces come from [OpenZFS](https://github.com/openzfs/zfs/tree/zfs-2.4.4); preserve its copyright and license notices when redistributing libraries or a maintenance bundle. Repository source files retain their SPDX notices.

Unless a file states otherwise, this repository uses the [CDDL 1.0 license](LICENSE). [NOTICE](NOTICE) preserves the upstream dependency notice without attributing independent contributions to the upstream organization.

The CMake dependency build applies `patches/zfs-2.4.4-claimed-zil-checkpoint.patch` only to the recognized upstream `zil.c`, and verifies the corrected file hash. During checkpoint rewind, already-claimed intent logs belong to the checkpoint, including their block and BRT references. The correction preserves their original replay limits instead of claiming them again with the new first-import TXG. This is a bundled userspace correction, not a kernel-module patch or permission to use an unrecognized source tree.

## Prepare an offline maintenance environment

Before writable conversion:

1. Verify a usable backup and the identity of the intended pool and all its leaf devices. Confirm the pool is healthy and resolve reported data errors before proceeding.
2. Finish or resolve active scans, rebuilds, device removal, RAIDZ expansion and other maintenance. **The converter refuses existing pool checkpoints**; do not discard a checkpoint without understanding the protection it provides.
3. Reserve pool free space. Full table conversion needs a second DDT plus copy-on-write metadata. There is no universal free-space percentage or zero-allocation guarantee.
4. Stop dependent services, shares, VMs and other writers. Fence automatic imports, cluster failover, other hosts and other administrators for the entire operation. The shared local maintenance lock does not fence another host or unrelated ZFS commands. `--fenced` acknowledges fencing you have established; it does not establish it.
5. Export the pool cleanly. Keep it exported and fenced until conversion and any required recovery finish with a clean export.

The executable, dynamic loader, shared libraries, shell, ZFS administration tools, working directory and logs must remain accessible **after export**. A source checkout or executable on the target pool is not sufficient. In particular, exporting a system/root pool requires a separate suitable maintenance environment; dependencies under `/usr`, `/var`, a home directory or a system dataset may also live on the target pool. Do not force an export to work around these dependencies.

If preparing a maintenance bundle, place the built executables and their required runtime dependencies on storage independent of the target pool. Inspect dependencies of your trusted local builds (for example with `ldd`), verify checksums after transfer, and confirm their resolved backing filesystems remain available offline. The build is not a self-contained static bundle. Keep persistent logs on independent storage with adequate free space. There is no host-specific wrapper or automatic service-quiescence script.

### Choose the target and paths

Run the following examples in a **root Bash session**. Replace every example value before use. Prepare an existing, dedicated device-search directory containing exactly one unique path or symlink per intended leaf, verified against `zpool status -P "$POOL"`. Stable device identifiers are preferable. Include no subdirectories, unrelated devices or duplicate aliases: the native validators inspect every entry and reject duplicate device identities. Do not point it at another pool's writable copy.

```bash
POOL='your-pool'
SEARCH_DIR='/absolute/path/to/your/device-search-directory'
TOOL_DIR='/absolute/path/to/your/maintenance/bin'
LOG_DIR='/absolute/path/on/independent-persistent-storage/operation-logs'

unset ZFS_HOSTID
umask 077
install -d -m 0700 -- "$LOG_DIR"

# Record while the intended pool is still imported; retain this GUID offline.
GUID=$(zpool get -Hp -o value guid "$POOL")
printf 'Target pool: %s; GUID: %s\n' "$POOL" "$GUID"
zpool status "$POOL"
zpool get feature@fast_dedup "$POOL"

# Only after backup, free-space, dependency and fencing preparation:
zpool export "$POOL"
```

For a local build, `TOOL_DIR` can be the absolute path to `build/` only if that filesystem and all runtime dependencies remain available after export. If the pool is already exported, set `GUID` from your previously verified decimal GUID record instead of importing it merely to run the assignment above. All native invocations identify the pool with `--pool-guid`, not a hard-coded pool name. The tools reject a `ZFS_HOSTID` override.

## Convert legacy tables

The pool must have `feature@fast_dedup` enabled. Enabling features is an operator-controlled compatibility decision; the converter does not replace that preparation.

| Mode | Published layout | Method |
| --- | --- | --- |
| Default | Version 1, `FLAT\|LOG`, flags 3 | Copies into compact shadow tables, verifies them, then publishes atomically |
| `--journal-only` | Version 1, `LOG`, flags 2 | Preserves traditional physical entries and enables journaling atomically |

Full flat conversion requires exactly one occupied physical allocation group per key. Copies 1, 2 and 3 are supported. Keys with independent allocations for multiple copies settings require journal-only mode. Journal-only conversion retains the traditional entry layout; it is not flat conversion.

The supported actions are:

* `--describe`: read-only registered-state JSON (`convert-ddt-state-v1`), including layout, objects, counts, export state and staging presence. It is not an entry scan or eligibility proof.
* `--check`: read-only full eligibility preflight for the selected conversion mode.
* `--convert --fenced`: full preflight followed by conversion, verification, publication and reclamation.

Use the same layout mode for checking and conversion. A separate `--check` is optional: `--convert` already performs full preflight, so repeating it immediately beforehand adds another traversal.

```bash
"$TOOL_DIR/convert-ddt" --describe \
  --pool-guid "$GUID" --search-dir "$SEARCH_DIR" \
  > "$LOG_DIR/before-layout.json"

"$TOOL_DIR/convert-ddt" --convert --fenced \
  --pool-guid "$GUID" --search-dir "$SEARCH_DIR" \
  > "$LOG_DIR/conversion.stdout" 2> "$LOG_DIR/conversion.stderr"

# Run only after successful conversion and clean export:
"$TOOL_DIR/convert-ddt" --describe \
  --pool-guid "$GUID" --search-dir "$SEARCH_DIR" \
  > "$LOG_DIR/after-layout.json"
```

For journal-only conversion, append `--journal-only` to the `--convert` command (and to any separate `--check`). Inspect command exit status and diagnostics; producing a log file alone is not success.

### Conversion resources, I/O and progress

`--batch-size 1..65536` controls entries per copy transaction (default 1024). `--read-batch-entries 1..1000000` independently bounds physical-read/hash-sort batches (default 1000000). `--workers 1..64` controls readers, defaulting to CPU affinity capped at 64.

Full-layout preflight, source copy and staged readback read **DDT metadata** in primary-DVA physical-address order using bounded parallel dispatch. This does not sort user-data DVAs or preload followed by a random hash-order scan. Native ARC/ZIO verifies the primary replica; an unreadable primary is an error. Copy batches are then hash-sorted for serial native syncing updates. Source cursors and native holds are released before writer transaction waits. More readers do not parallelize those serial metadata transactions.

Physical plans, sorting scratch, entry/index buffers and worker state share a **1 GiB working-memory cap**, separate from native ARC and whole-process RSS. Leave headroom for ARC and native overhead. Unsupported mappings, oversized batches/plans, count/histogram mismatches, checksum errors or staged verification failures stop the operation rather than reducing validation.

Timestamped `flat-preflight`, `flat-copy` and `flat-readback` JSON events on stderr report checksum/class, completed/total entries and physical blocks, rate, ETA and `read_order: "physical"`. An ETA of `null` means no rate is available. Copy transactions also report cumulative entries on stdout. `stage-reclaim` events track committed logical address ranges, including holes, not physical bytes freed or device throughput; destruction has no ETA and completes only after the object-destruction transaction commits.

### Converter interruption and recovery

Original tables remain authoritative during staging. One syncing transaction publishes tables and feature references; obsolete table metadata is then reclaimed in bounded transactions. SIGINT/SIGTERM stop between batches, attempt clean export and return 130. Retrying reclaims abandoned staging and rebuilds from authoritative tables; publication is not undone simply because later reclamation was interrupted.

After SIGKILL or a host crash, recover and cleanly export the pool using ordinary ZFS administration before retrying the converter. Keep fencing, investigate any final-export failure, and do not import elsewhere until it is resolved.

After successful conversion and clean export, an operator may import and start a normal asynchronous scrub:

```bash
zpool import -d "$SEARCH_DIR" "$GUID"
zdb -D "$POOL"
zpool scrub "$POOL"
zpool status -D "$POOL"
```

The scrub command does not wait for completion; normal workloads may resume while it runs. Check its eventual result separately. Conversion verification and the targeted validation below are not a completed scrub.

## Targeted conversion validation

The native validators are optional additional evidence on stable exported, fenced devices. They do not establish fencing or replace a backup, conversion preflight or a scrub. A typical targeted content baseline/replay uses **exactly 25,000 dedup-backed logical ranges**:

```bash
# Before conversion:
"$TOOL_DIR/validate-content" --pool-guid "$GUID" --search-dir "$SEARCH_DIR" \
  --sample-count 25000 --output "$LOG_DIR/content-before.json"

# After successful conversion, still exported and before ordinary writers:
"$TOOL_DIR/validate-content" --pool-guid "$GUID" --search-dir "$SEARCH_DIR" \
  --sample-count 25000 --expect "$LOG_DIR/content-before.json" \
  --output "$LOG_DIR/content-after.json"
```

These are distinct logical `(dataset GUID, object, offset)` references, not necessarily distinct allocations. Selected views include each head and the lowest-object-ID filesystem snapshot per head; ZVOL snapshots are inventoried but not sampled. Only level-zero dedup-backed data ranges qualify, not holes, embedded or ordinary non-dedup data. Ranges start at native logical block offsets and hash at most 1 MiB clipped to the block and EOF, using native checked reads. Each report records the full original 16-word BP, view/object identity, size, generation, offset, length and SHA-256. `--expect` replays the **same** references and compares inventory, BPs and hashes, rather than selecting fresh samples.

The target accepts 1–50,000 (default 25,000). Insufficient usable ranges fail with no complete report, not partial success. Sampling is targeted, not uniformly random and not a full content scan. Inventory is bounded at 262,144 objects and selection at 32,768 views; excess fails. The content validator has **no key-loading CLI**: encrypted views are recorded as locked without plaintext samples. Unchanged locked inventory is not encrypted-content validation.

Both native validators accept `--pool-guid DECIMAL --search-dir DIR --output PATH`, optional `--workers N`, `--arc-max-bytes N`, and `--expect BEFORE_REPORT`. Only content accepts `--sample-count`; only DDT accepts `--preload`. Complete reports are atomically published as `validate-content-v2` and `validate-ddt-v1`. DDT validation scans every configured checksum/type/class store, reconciles native ZAP counts and fingerprints keys/properties, DVAs, births and references. None of these checks is a whole-pool scrub or full user-data validation.

## Reproducible tests

The default CTest suite runs **without root**: the native DDT transformation helper plus Python unittest discovery of `tests/test_*.py` (four process-supervision tests). It does not create/import/export pools, access production devices, or invoke root integration fixtures. Run it after building:

```sh
ctest --test-dir build --output-on-failure
```

The following commands are separate, explicit opt-in tests for **disposable test pools**, not your target pool. They are never registered in default CTest. The fixed integration harnesses create their own mirrored/file-backed devices and retain evidence. Root, working ZFS administration tools, mount support and sufficient independent storage are required. Select an existing persistent test workspace:

```bash
TEST_WORK_DIR='/absolute/path/on/independent-persistent-storage/test-work'
install -d -m 0700 -- "$TEST_WORK_DIR"

sudo python3 tests/integration.py \
  --converter "$PWD/build/convert-ddt" --work-dir "$TEST_WORK_DIR"
```

Conversion integration covers modes, copies settings, encryption, snapshots, clones, ZVOLs, reference updates, interruption and recovery. Omitted cases are not passing cases. These invocations describe test coverage, not a claim that any particular checkout has passed it. Integration reports retain command results; preserve these as operator evidence, not as source artifacts.

### Checkpoint-backed copy fixtures

The block-device fixture additionally needs `qemu-img`, `qemu-nbd`, loop devices and mount-namespace support. It creates its own temporary twelve-partition RAIDZ2 pool and checkpoint-backed COW images:

```bash
sudo python3 tests/actual_validation_fixture.py \
  --converter "$PWD/build/convert-ddt" \
  --clone-helper "$PWD/build/clone-pool" --work-dir "$TEST_WORK_DIR"

sudo python3 tests/checkpoint_history_integration.py --work-dir "$TEST_WORK_DIR"
```

Fixture cases include `interrupted-command`, `lease-handoff`, `checkpoint-probe` and `claimed-zil`: cancellation protection, durable lease ownership, checkpoint identity while the live pool advances, and rewind of previously claimed encrypted intent logs. Checkpoint identity uses committed TXG, pool GUID, start time and contiguous kernel history; lost/replaced history fails admission without an offline walk of a changing live MOS. The fixture uses exported-copy `zdb -bc` for metadata checksums and reachable-block reference/allocation accounting, plus sampled file hashes. It retires dependent images before discarding their backing checkpoint. That accounting scope is separate from the conversion-only runner below.

## Advanced: validate an already owned copy

`tests/parallel_actual_validation.py` performs full flat conversion on an **already prepared, exported, exclusively fenced copy** with a nonzero GUID distinct from its source. It does not prepare or retire copies, checkpoints, images, attachments or devices. Preparation, recovery and eventual cleanup remain the resource owner's responsibility. **Never target the original pool or its writable devices.**

The runner does not kernel-import or mount the copy. Native before-DDT and content validators open separate read-only userspace SPAs with sealed empty caches, pinned device descriptors and an allowlist rejecting writable/unrelated opens. Only the converter phase opens writable through its offline userspace path. The tools share the maintenance lock. Detected kernel imports, mounts and blocked administrators/readers are refused; keep external fencing throughout.

### Ownership and invocation

Supply an existing work directory and a dedicated device-search directory containing **exactly** the copy's leaves (paths or symlinks), without missing, duplicate or unrelated devices. The owner must durably provide `WORK_DIR/ownership.json` with:

* `format`: `"parallel-actual-ownership-v1"`.
* `name`, `pool_guid`, `source_guid`: the copy name and decimal-string GUIDs; source and copy differ.
* `exported`: `true`; `fenced`: `true`; `search_dir`: the dedicated directory.
* `devices`: a nonempty array of canonical absolute `path` and `identity: [st_dev, st_ino, st_rdev, size_bytes]` entries. Size is `BLKGETSIZE64` for block devices and `st_size` for files.

The manifest must be a root-owned, single-link, non-symlink regular file without group/world write permission. The runner hashes it and rechecks identity and exact device membership at phase boundaries; block devices must have no unexpected holders. This is attestation of fencing already established, not a fencing mechanism.

An existing actual-copy journal can instead supply the same fields in `parallel_validation`, using `--ownership-journal PATH` (alias `--journal`) when the manifest is absent. Whenever supplied, the journal also subjects the run to source/copy, exported-state, clone-preparation, image/backing, live qemu/NBD attachment/capacity and read-only backing-descriptor checks. It acquires existing source-lease/NBD locks and checks the source checkpoint's committed TXG/start time and contiguous kernel history against the imported source. Do not fabricate a journal merely to enable reuse.

Set these separate copy variables from your ownership records:

```bash
COPY_GUID='your-verified-copy-decimal-guid'
COPY_SEARCH_DIR='/absolute/path/to/copy-only-device-directory'
OWNED_WORK_DIR='/absolute/path/to/existing-owned-copy-work-directory'

sudo python3 tests/parallel_actual_validation.py \
  --pool-guid "$COPY_GUID" --search-dir "$COPY_SEARCH_DIR" \
  --work-dir "$OWNED_WORK_DIR" \
  --converter "$TOOL_DIR/convert-ddt" \
  --ddt-validator "$TOOL_DIR/validate-ddt" \
  --content-validator "$TOOL_DIR/validate-content"
```

Replace the GUID placeholder with its recorded decimal value. Executable paths must be absolute. Run as root without `ZFS_HOSTID`; `--resume-conversion` still requires the unused DDT-validator path to exist, but it need not be executable. If using a journal, append `--ownership-journal "$OWNERSHIP_JOURNAL"` after setting `OWNERSHIP_JOURNAL` to its verified absolute path.

### Phases, resources and coverage

1. Concurrent **before-DDT** full census and **before-content** inventory/exact-N selection. A real legacy table and full flat eligibility are required; no-op and journal-only qualification are refused.
2. `convert-ddt --convert --fenced`, including its own preflight, copy and staged readback. Completed native per-store entry and physical-block totals must reconcile with the baseline; clean export is required. There is no redundant standalone `--check`.
3. Read-only `--describe` admits the same exported pool, no staging, only version-1/flags-3 tables, valid registration and unchanged checksum/type/class counts. It is not another full entry scan.
4. **After-content** replays the recorded ranges with `--expect`; inventory and complete sample reports must match. Final source/device guards still run.

Full DDT coverage here combines the independent before census, converter staged readback and independent published-layout/count admission. It does **not** include an independent after-DDT fingerprint scan. Reports mark `coverage.full_ddt.status: "converter_full_staged_readback_passed"` and `independent_after_fingerprint: false`. The runner does not perform whole-pool metadata traversal, allocation/reference accounting or a scrub; `coverage.metadata: "not_requested_conversion_scope"` and `whole_userdata_checksum_scan: false` explicitly record that limit. Content and encrypted-view limitations are those described above.

`--sample-count` is 1–50,000, default 25,000, and must match selection/replay exactly. `--workers` is 1–64 (CPU affinity capped at 64 by default); content workers default to at most 16 CPUs via `--content-workers`. Runner transaction batches default to 65536 (`--batch-size`), unlike the standalone converter's 1024; read batches default to 1000000 (`--read-batch-entries`). Native limits still apply.

`--arc-max-bytes` is the **total concurrent-validator ARC budget**, not whole-job memory. It defaults to one eighth of physical RAM bounded to 512 MiB–8 GiB and must be at least 128 MiB. It splits equally unless `--ddt-arc-max-bytes` assigns the DDT portion; each validator needs at least 64 MiB. The converter has an independent native ARC target and 1 GiB working-structure cap. Targets do not preallocate RAM or change kernel ARC; leave real system headroom.

Optional `--ddt-preload` warms only the before-DDT validator. It plans native-verified DDT level-1 indirect blocks/direct BPs, sorts non-hole primary-DVA blocks and uses at most 48 bounded readers before the complete census. Logical size must fit 75% of the DDT ARC budget; plan capacity is bounded by 1 GiB and one sixteenth of that allowance. Native checksums remain mandatory, and an unreadable primary fails rather than silently trying another access order. Preload is not a replacement census.

### Reusing retained evidence

The three options below are mutually exclusive and require the **same actual-copy ownership journal**, not just a standalone file fixture/manifest. All require verified provenance and current identity, fencing, source-lease, checkpoint/history, attachment and read-only-backing guards. Reports/native evidence must be complete, hash-linked, private, root-owned and protected against symlink or multi-link substitution. Previous recorded PID/starttime identities must no longer exist. Reuse never turns missing proof into success or silently falls back to another baseline scan.

* **`--resume-baseline PREVIOUS_REPORT`**: reuse passed before-DDT/content reports from a failed run that remained entirely read-only. Any conversion, after-validation, writer or unknown command/phase rejects reuse. Current COW images must retain attested inodes and have both `mtime_ns` and `ctime_ns` no later than the original before-DDT command start. Ownership hashes, source/copy GUIDs, name and journal path must match; a recorded journal hash must match. Missing image attestation cannot be waived. The runner copies the original evidence and then performs real conversion and all postchecks.
* **`--resume-preflight PREVIOUS_REPORT`**: restart only a cleanly interrupted converter **preflight**. The failed resource-preserving run must have one converter command ending with status 130 and clean-export acknowledgment, with native stderr containing only preflight phases. Copy/readback, staging/publication, unknown phases/options, blocked/live children or incomplete provenance reject admission. Read-only `--describe` must prove the same exported pool, no staging, only legacy version-0/flags-0 tables and the original census's object IDs/counts. The converter then restarts its full preflight; baselines are reused, not reread. Converter import/export timestamp changes do not relax read-only baseline reuse rules.
* **`--resume-conversion PREVIOUS_REPORT`**: reuse a completed converter handoff, not an incomplete conversion. Its converter must have exited zero with complete preflight/copy/readback entry and physical-block progress, a completed phase and final clean-export acknowledgment. The overall prior run may have failed later, but later writable/unknown operations, conflicting arguments or missing proof reject reuse. The runner copies original baselines, admits published layout/counts, replays exact content and runs final guards **without** rerunning conversion or before readers.

Reuse requires `validate-content-v2` evidence with the same exact target/count and command arguments throughout provenance; older evidence cannot be upgraded. Preflight provenance cycles or more than 64 linked reports are refused. Changed image timestamps permitted for phase-specific handoffs do not waive original image/backing identities. Rejected reuse preserves resources and reports the unmet prerequisite; it is not a recovery substitute for an unfinished writer.

### Reports, deadlines and retained resources

Each invocation creates a private `parallel-actual-*` evidence directory under the work directory and prints `report.json`. It retains native before/after reports, published description, command stdout/stderr and flushed once-per-second `progress.jsonl` heartbeats (also stderr). Progress includes phase, child PID/state, measured work, native counters, CPU/I/O rates and no-work duration; ETA may be unavailable. Heartbeats, diagnostic output and CPU activity alone do not count as work.

`--startup-timeout` and `--stall-timeout` default to 60 seconds; `--stage-timeout` defaults to 21600 seconds (six hours), even while progressing. Tune explicit bounds for the copy. On failure, interruption or timeout, the runner preserves devices, overlays, checkpoint ownership and evidence. It stops only its own child process groups with bounded SIGTERM/SIGKILL waits. An unkillable child is recorded as `blocked_preserve`; resolve it and any interrupted converter before reuse or cleanup. Exit zero requires a complete passing report. Resources are retained even on success, so owner-controlled cleanup remains necessary.

## Format references

* [DDT implementation](https://github.com/openzfs/zfs/blob/zfs-2.4.4/module/zfs/ddt.c)
* [Physical entry layouts](https://github.com/openzfs/zfs/blob/zfs-2.4.4/include/sys/ddt.h)
* [Deduplication log](https://github.com/openzfs/zfs/blob/zfs-2.4.4/module/zfs/ddt_log.c)
