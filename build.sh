#!/usr/bin/env bash
# Match libzpool's private-header ABI and link dependencies through upstream zhack.
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage: ./build.sh [-j JOBS] [--reconfigure]

Build build/convert-ddt, build/dedup-fdt, build/clone-pool, build/validate-ddt,
build/validate-content, build/test_transform, build/test_dedup_fdt_resources,
build/dedup_fdt_sort_test, build/dedup_fdt_workers_test, and build/rebuild_ddt_quota_test.
Native validators require Jansson.
Uses OpenZFS 2.4.4 from .build/zfs-2.4.4 or a SHA256-verified release download.
Detects private dependencies in .build/deps/usr and prefers host runtime libraries.

Environment: CC, CPPFLAGS, CFLAGS, LDFLAGS, LIBS, PKG_CONFIG, PKG_CONFIG_PATH,
             MAKE (one executable), JOBS (default: 2).
Supplying compiler/configuration variables or --reconfigure reruns configure.
Otherwise the existing configured tree, including its flags, is reused.
Use a native Linux build environment with the OpenZFS userspace dependencies.
USAGE
}
die() { printf 'build.sh: %s\n' "$*" >&2; exit 1; }

jobs=${JOBS:-2}
reconfigure=0
while (($#)); do
    case $1 in
        -j|--jobs)
            (($# >= 2)) || die "$1 needs a positive integer"
            jobs=$2
            shift 2
            ;;
        --reconfigure) reconfigure=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown argument: $1 (see --help)" ;;
    esac
done
[[ $jobs =~ ^[1-9][0-9]*$ ]] || die 'JOBS must be a positive integer'

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# Validate paths for use as GNU make target names.
unsafe_path='[[:space:]#$:\\]'
[[ ! $root =~ $unsafe_path ]] || die 'source path contains make-special characters'
cd -- "$root"
[[ -f convert_ddt.c ]] || die 'convert_ddt.c is missing'
[[ -f ddt_transform.h ]] || die 'ddt_transform.h is missing'
[[ -f ddt_physical.h ]] || die 'ddt_physical.h is missing'
dedup_sources=(dedup_fdt dedup_fdt_plan dedup_fdt_native dedup_fdt_index dedup_fdt_admission
    dedup_fdt_sort dedup_fdt_workers rebuild_keys rebuild_bridge rebuild_brt_native
    rebuild_ddt_native rebuild_history rebuild_history_native rebuild_quota
    rebuild_owners rebuild_zil rebuild_sync rebuild_io_fault dedup_fdt_traverse_native
    dedup_fdt_resources)
for name in "${dedup_sources[@]}"; do
    [[ -f $name.c ]] || die "$name.c is missing"
done

version=2.4.4
sha256=2a3c70d55a37cc71618a95a60e81ad66530201eb118d37741dc92efcf848c8b1
work=$root/.build
source=$work/zfs-$version
archive=$work/zfs-$version.tar.gz
make_bin=${MAKE:-make}
command -v "$make_bin" >/dev/null || die "missing make executable: $make_bin"
mkdir -p -- "$work" "$root/build"
fragment=
partial=
extract=
cleanup() {
    [[ -z $fragment ]] || rm -f -- "$fragment"
    [[ -z $partial ]] || rm -f -- "$partial"
    [[ -z $extract ]] || rm -rf -- "$extract"
    return 0
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ ! -d $source ]]; then
    command -v sha256sum >/dev/null || die 'sha256sum is required to verify OpenZFS'
    if [[ ! -f $archive ]]; then
        command -v curl >/dev/null || die 'curl is required to download OpenZFS'
        partial=$(mktemp "$work/zfs-download.XXXXXX")
        curl --fail --location --proto '=https' --tlsv1.2 \
            "https://github.com/openzfs/zfs/releases/download/zfs-$version/zfs-$version.tar.gz" \
            --output "$partial"
        printf '%s  %s\n' "$sha256" "$partial" | sha256sum --check --status ||
            die 'OpenZFS download checksum mismatch'
        mv -- "$partial" "$archive"
        partial=
    fi
    printf '%s  %s\n' "$sha256" "$archive" | sha256sum --check --status ||
        die 'cached OpenZFS archive checksum mismatch; remove it to download again'
    extract=$(mktemp -d "$work/zfs-extract.XXXXXX")
    tar --extract --gzip --file "$archive" --directory "$extract" \
        --no-same-owner --no-same-permissions
    [[ -f $extract/zfs-$version/configure ]] || die 'release archive lacks configure'
    mv -- "$extract/zfs-$version" "$source"
    rmdir -- "$extract"
    extract=
fi

# Validate the source version before configuring or building its libraries.
[[ -f $source/META ]] || die 'existing OpenZFS tree lacks META'
source_version=
while read -r key value rest; do
    [[ $key != Version: ]] || source_version=$value
done < "$source/META"
[[ $source_version == "$version" ]] || die "expected OpenZFS $version, found $source_version"

# Rewinding a checkpoint can expose an already-claimed ZIL from the live tree.
# Accept only the pinned upstream file or the exact maintained correction.
sha256_bin=$(command -v sha256sum) || die 'sha256sum is required to verify native sources'
patch_bin=$(command -v patch) || die 'patch is required for pinned native corrections'
zil_source=$source/module/zfs/zil.c
zil_patch=$root/patches/zfs-2.4.4-claimed-zil-checkpoint.patch
[[ -f $zil_patch ]] || die 'maintained claimed-ZIL checkpoint patch is missing'
read -r zil_hash _ < <("$sha256_bin" -- "$zil_source")
case $zil_hash in
    aff082bff393836fd3d415cf6441fee1c034e1f8378a94a4a1a573d21ce64ad6)
        "$patch_bin" --directory "$source" --batch --forward --fuzz=0 -p1 -i "$zil_patch"
        read -r zil_hash _ < <("$sha256_bin" -- "$zil_source")
        [[ $zil_hash == fee736dca22aed9ad55c8828835c715440c864bb77a2ef8943a074f758132912 ]] ||
            die 'claimed-ZIL native correction produced an unexpected source hash'
        ;;
    fee736dca22aed9ad55c8828835c715440c864bb77a2ef8943a074f758132912) ;;
    *) die 'unrecognized OpenZFS zil.c; refusing to patch or build it' ;;
esac

for name in CC CPPFLAGS CFLAGS LDFLAGS LIBS PKG_CONFIG PKG_CONFIG_PATH; do
    [[ ! -v $name ]] || reconfigure=1
done
private_cppflags=
private_ldflags=
private_pcpath=
deps=$work/deps/usr
if [[ -d $deps/include ]]; then
    private_cppflags="-I$deps/include"
    [[ ! -d $deps/include/tirpc ]] || private_cppflags+=" -I$deps/include/tirpc"
fi

# Prefer host runtime libraries to preserve compatibility with the host libc.
host_libs=$work/host-libs
mkdir -p -- "$host_libs"
multiarch=
read -r -a compiler_command <<< "${CC:-cc}"
if command -v "${compiler_command[0]}" >/dev/null; then
    multiarch=$("${compiler_command[@]}" -print-multiarch 2>/dev/null || true)
fi
# Use the native compiler's multiarch query as a fallback for compiler wrappers.
if [[ -z $multiarch ]] && command -v cc >/dev/null; then
    multiarch=$(cc -print-multiarch 2>/dev/null || true)
fi
for name in udev blkid uuid tirpc aio crypto; do
    case $name in
        udev) sonames=(libudev.so.1) ;;
        blkid) sonames=(libblkid.so.1) ;;
        uuid) sonames=(libuuid.so.1) ;;
        tirpc) sonames=(libtirpc.so.3) ;;
        aio) sonames=(libaio.so.1t64 libaio.so.1) ;;
        crypto) sonames=(libcrypto.so.3 libcrypto.so.1.1) ;;
    esac
    runtime=
    for soname in "${sonames[@]}"; do
        for directory in "/usr/lib/$multiarch" "/lib/$multiarch" /usr/lib64 /lib64 /usr/lib /lib; do
            if [[ -f $directory/$soname ]]; then
                runtime=$directory/$soname
                break 2
            fi
        done
    done
    if [[ -n $runtime ]]; then
        ln -sfn -- "$runtime" "$host_libs/lib$name.so"
    else
        rm -f -- "$host_libs/lib$name.so"
    fi
done
private_ldflags="-L$host_libs"
for directory in "$deps/lib/$multiarch" "$deps/lib64" "$deps/lib"; do
    [[ ! -d $directory ]] || private_ldflags+=" -L$directory"
    if [[ -d $directory/pkgconfig ]]; then
        private_pcpath+="${private_pcpath:+:}$directory/pkgconfig"
    fi
done

if [[ ! -f $source/Makefile || ! -f $source/zfs_config.h || $reconfigure == 1 ]]; then
    (
        cd -- "$source"
        export CPPFLAGS="${CPPFLAGS:+$CPPFLAGS }$private_cppflags"
        export LDFLAGS="${LDFLAGS:+$LDFLAGS }$private_ldflags"
        if [[ -n $private_pcpath ]]; then
            export PKG_CONFIG_PATH="${PKG_CONFIG_PATH:+$PKG_CONFIG_PATH:}$private_pcpath"
        fi
        ./configure --with-config=user --disable-pyzfs --disable-nls \
            --disable-shared --enable-static
    )
fi

fragment=$(mktemp "$work/convert-ddt.XXXXXX.mk")
cat > "$fragment" <<'MAKEFILE'
include Makefile

ifneq ($(ZFS_META_VERSION),2.4.4)
$(error Converter requires OpenZFS 2.4.4)
endif
ifneq ($(ZFS_CONFIG),user)
$(error Reconfigure OpenZFS with --with-config=user)
endif

# Match libzpool's DEBUG/ZFS_DEBUG structure layouts and upstream link dependencies.
override CPPFLAGS := $(CPPFLAGS) $(convert_ddt_cppflags)
override LDFLAGS := $(convert_ddt_ldflags) $(LDFLAGS)
convert_ddt_build = $(convert_ddt_root)/build
convert_ddt_compile = $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(zhack_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -I$(convert_ddt_root)
dedup_fdt_objects = $(addprefix $(convert_ddt_build)/,$(addsuffix .o,$(dedup_fdt_names)))

.PHONY: convert-ddt-local
convert-ddt-local: $(convert_ddt_build)/convert-ddt $(convert_ddt_build)/dedup-fdt $(convert_ddt_test) $(convert_ddt_build)/test_dedup_fdt_resources $(convert_ddt_build)/dedup_fdt_sort_test $(convert_ddt_build)/dedup_fdt_workers_test $(convert_ddt_build)/rebuild_ddt_quota_test $(convert_ddt_build)/clone-pool $(convert_ddt_build)/validate-ddt $(convert_ddt_build)/validate-content

$(convert_ddt_build)/convert_ddt.o: $(convert_ddt_root)/convert_ddt.c $(convert_ddt_root)/ddt_transform.h $(convert_ddt_root)/ddt_physical.h $(convert_ddt_root)/build.sh Makefile zfs_config.h
	$(convert_ddt_compile) -MMD -MP -MF $(convert_ddt_build)/convert_ddt.d -c -o $@ $<

$(convert_ddt_build)/convert-ddt: $(convert_ddt_build)/convert_ddt.o $(zhack_DEPENDENCIES)
	$(LINK) -static $(convert_ddt_build)/convert_ddt.o $(zhack_LDADD) $(LIBS)

$(dedup_fdt_objects): $(convert_ddt_build)/%.o: $(convert_ddt_root)/%.c $(convert_ddt_root)/build.sh Makefile zfs_config.h
	$(convert_ddt_compile) $(LIBCRYPTO_CFLAGS) -MMD -MP -MF $(@:.o=.d) -c -o $@ $<

# The replacement DDT/BRT translation units precede the static archive.
# Maintenance admission wrappers are confined to this separate executable.
$(convert_ddt_build)/dedup-fdt: $(dedup_fdt_objects) $(zhack_DEPENDENCIES)
	$(LINK) -static -Wl,--wrap=bpobj_iterate,--wrap=dsl_scan_sync,--wrap=zthr_create,--wrap=zfs_file_pwrite,--wrap=ddt_sync,--wrap=brt_sync,--wrap=brt_pending_apply,--wrap=zil_claim $(dedup_fdt_objects) $(zhack_LDADD) $(LIBCRYPTO_LIBS) $(LIBS)

$(convert_ddt_build)/test_transform.o: $(convert_ddt_root)/tests/test_transform.c $(convert_ddt_root)/ddt_transform.h $(convert_ddt_root)/build.sh Makefile zfs_config.h
	$(convert_ddt_compile) -MMD -MP -MF $(convert_ddt_build)/test_transform.d -c -o $@ $<

$(convert_ddt_build)/test_transform: $(convert_ddt_build)/test_transform.o $(zhack_DEPENDENCIES)
	$(LINK) -static $(convert_ddt_build)/test_transform.o $(zhack_LDADD) $(LIBS)

$(convert_ddt_build)/test_dedup_fdt_resources.o: $(convert_ddt_root)/tests/test_dedup_fdt_resources.c $(convert_ddt_root)/dedup_fdt_resources.h $(convert_ddt_root)/dedup_fdt_index.h $(convert_ddt_root)/build.sh Makefile zfs_config.h
	$(CC) $(CFLAGS) -UNDEBUG -D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE -I$(convert_ddt_root) -MMD -MP -MF $(convert_ddt_build)/test_dedup_fdt_resources.d -c -o $@ $<

$(convert_ddt_build)/test_dedup_fdt_resources: $(convert_ddt_build)/test_dedup_fdt_resources.o $(convert_ddt_build)/dedup_fdt_resources.o $(convert_ddt_build)/dedup_fdt_index.o
	$(LINK) -static -Wl,--wrap=pwrite,--wrap=pwrite64 $^ -lpthread

$(convert_ddt_build)/rebuild_ddt_quota_test: $(convert_ddt_root)/tests/rebuild_ddt_quota_test.c $(convert_ddt_root)/rebuild_ddt_quota.h $(convert_ddt_root)/build.sh
	$(CC) $(CFLAGS) -UNDEBUG -I$(convert_ddt_root) -o $@ $<

$(convert_ddt_build)/dedup_fdt_sort_test: $(convert_ddt_root)/tests/dedup_fdt_sort_test.c $(convert_ddt_build)/dedup_fdt_sort.o $(convert_ddt_build)/dedup_fdt_resources.o
	$(CC) $(CFLAGS) -UNDEBUG -I$(convert_ddt_root) -o $@ $^ -lpthread

$(convert_ddt_build)/dedup_fdt_workers_test: $(convert_ddt_root)/tests/dedup_fdt_workers_test.c $(convert_ddt_build)/dedup_fdt_workers.o $(convert_ddt_build)/dedup_fdt_resources.o
	$(CC) $(CFLAGS) -UNDEBUG -I$(convert_ddt_root) -o $@ $^ -lpthread

$(convert_ddt_build)/clone_pool.o: $(convert_ddt_root)/tests/clone_pool.c $(convert_ddt_root)/build.sh Makefile zfs_config.h
	$(convert_ddt_compile) -MMD -MP -MF $(convert_ddt_build)/clone_pool.d -c -o $@ $<

$(convert_ddt_build)/clone-pool: $(convert_ddt_build)/clone_pool.o $(zhack_DEPENDENCIES)
	$(LINK) -static -Wl,--wrap=zfs_file_open $(convert_ddt_build)/clone_pool.o $(zhack_LDADD) $(LIBS)

$(convert_ddt_build)/validate_ddt.o: $(convert_ddt_root)/tests/validate_ddt.c $(convert_ddt_root)/tests/validate_pool.h $(convert_ddt_root)/ddt_physical.h $(convert_ddt_root)/build.sh Makefile zfs_config.h
	$(convert_ddt_compile) $(LIBCRYPTO_CFLAGS) -MMD -MP -MF $(convert_ddt_build)/validate_ddt.d -c -o $@ $<

$(convert_ddt_build)/validate_content.o: $(convert_ddt_root)/tests/validate_content.c $(convert_ddt_root)/tests/validate_pool.h $(convert_ddt_root)/build.sh Makefile zfs_config.h
	$(convert_ddt_compile) $(LIBCRYPTO_CFLAGS) -MMD -MP -MF $(convert_ddt_build)/validate_content.d -c -o $@ $<

$(convert_ddt_build)/validate-ddt: $(convert_ddt_build)/validate_ddt.o $(zhack_DEPENDENCIES)
	$(LINK) -static -Wl,--wrap=zfs_file_open $(convert_ddt_build)/validate_ddt.o $(zhack_LDADD) $(LIBCRYPTO_LIBS) -ljansson $(LIBS)

$(convert_ddt_build)/validate-content: $(convert_ddt_build)/validate_content.o $(zhack_DEPENDENCIES)
	$(LINK) -static -Wl,--wrap=zfs_file_open $(convert_ddt_build)/validate_content.o $(zhack_LDADD) $(LIBCRYPTO_LIBS) -ljansson $(LIBS)

-include $(convert_ddt_build)/convert_ddt.d $(convert_ddt_build)/test_transform.d $(convert_ddt_build)/test_dedup_fdt_resources.d $(convert_ddt_build)/clone_pool.d $(convert_ddt_build)/validate_ddt.d $(convert_ddt_build)/validate_content.d $(dedup_fdt_objects:.o=.d)
MAKEFILE

make_args=("-j$jobs" -C "$source" -f "$fragment"
    "convert_ddt_root=$root"
    "dedup_fdt_names=${dedup_sources[*]}"
    "convert_ddt_cppflags=$private_cppflags" "convert_ddt_ldflags=$private_ldflags")
if [[ -f $root/tests/test_transform.c ]]; then
    make_args+=("convert_ddt_test=$root/build/test_transform")
fi
"$make_bin" "${make_args[@]}" convert-ddt-local
printf 'Built %s\n' "$root/build/convert-ddt"
printf 'Built %s\n' "$root/build/dedup-fdt"
printf 'Built %s\n' "$root/build/test_dedup_fdt_resources"
printf 'Built %s\n' "$root/build/rebuild_ddt_quota_test"
printf 'Built %s\n' "$root/build/dedup_fdt_sort_test"
printf 'Built %s\n' "$root/build/dedup_fdt_workers_test"
if [[ -f $root/tests/test_transform.c ]]; then
    printf 'Built %s\n' "$root/build/test_transform"
fi
printf 'Built %s\n' "$root/build/clone-pool"
printf 'Built %s\n' "$root/build/validate-ddt"
printf 'Built %s\n' "$root/build/validate-content"
