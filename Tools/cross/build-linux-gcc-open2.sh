#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "$0")/../.." && pwd)
source_dir="$project_root/Source"
stove=${OPENAMIGA_GCC_STOVE:-/home/da1ek/AmigaChrome/stoves/os32-gcc16}
build_dir=${AMIGAPYTHON_BUILD_DIR:-$project_root/build-ac4-gcc}
jobs=${JOBS:-4}
build_triplet=${AMIGAPYTHON_BUILD_TRIPLET:-x86_64-pc-linux-gnu}

if ! grep -Eq '^#define AC_BUILD[[:space:]]+4[[:space:]]*$' \
        "$source_dir/Include/patchlevel.h"; then
    echo "the GCC 16.2-open2 builder is reserved for OpenAmigaPython ac4" >&2
    exit 2
fi

python3 "$project_root/Tools/cross/check_gcc_open2.py" --stove "$stove"

cc="$stove/prefix/bin/m68k-amigaos-gcc"
cxx="$stove/prefix/bin/m68k-amigaos-g++"
ar="$stove/prefix/bin/m68k-amigaos-ar"
ranlib="$stove/prefix/bin/m68k-amigaos-ranlib"
for required in "$cc" "$cxx" "$ar" "$ranlib" "$source_dir/configure"; do
    if [[ ! -x "$required" ]]; then
        echo "missing build prerequisite: $required" >&2
        exit 1
    fi
done

case "$build_dir" in
    "$source_dir"|"$project_root")
        echo "refusing an in-source ac4 build: $build_dir" >&2
        exit 2
        ;;
esac

common_flags="-mcrt=nix20 -m68040 -m68881 -D_AMIGA -DOPENAMIGA_GCC_OPEN2=1 -fno-delete-null-pointer-checks"
if [[ ${AMIGAPYTHON_STARTUP_TRACE:-0} == 1 ]]; then
    common_flags+=" -DOPENAMIGAPYTHON_STARTUP_TRACE=1"
fi
cflags="-O3 -std=gnu99 -fwrapv"
configure_args=(
    "--build=$build_triplet"
    --host=m68k-amigaos
    --disable-shared
    --without-threads
    --disable-ipv6
)
support_objects=(
    Amiga/libcheck.o
    Amiga/dosio_init.o
    Amiga/wbconsole.o
    Amiga/wbargs.o
    Amiga/pyamiga_host.o
    Amiga/open2_runtime.o
    Modules/posix_helpers.o
    Modules/timemodule.o
)

mkdir -p "$build_dir/Amiga" "$build_dir/Modules"
(
    cd "$build_dir"
    ac_cv_file__dev_ptmx=no \
    ac_cv_file__dev_ptc=no \
    ac_cv_func_getgroups=no \
    ac_cv_func_getlogin=no \
    ac_cv_func_getpwent=no \
    ac_cv_func_initgroups=no \
    ac_cv_func_setegid=no \
    ac_cv_func_seteuid=no \
    ac_cv_func_setgid=no \
    ac_cv_func_setgroups=no \
    ac_cv_func_setpgid=no \
    ac_cv_func_setregid=no \
    ac_cv_func_setreuid=no \
    ac_cv_func_setuid=no \
    CC="$cc $common_flags" \
    CXX="$cxx $common_flags" \
    AR="$ar" \
    RANLIB="$ranlib" \
    CFLAGS="$cflags" \
        "$source_dir/configure" "${configure_args[@]}"
)

# Setup.dist assumes a Unix account database and makes pwd a mandatory
# builtin.  ac4 uses its own target profile so libsocket's __inituser is not
# dragged into the pre-main constructor list.  Regenerate config.c/Makefile
# after installing the target profile in the out-of-tree build directory.
install -m 644 "$source_dir/Modules/Setup.ac4" "$build_dir/Modules/Setup"
make -C "$build_dir" Makefile Modules/config.c

make -C "$build_dir" -j "$jobs" "${support_objects[@]}"
make -C "$build_dir" -j "$jobs" python \
    "LDFLAGS=${support_objects[*]}"

provenance_args=()
for option in "${configure_args[@]}"; do
    provenance_args+=("--configure-option=$option")
done
for object in "${support_objects[@]}"; do
    provenance_args+=(--support-object "$object")
done

python3 "$project_root/Tools/cross/write_build_provenance.py" \
    --binary "$build_dir/python" \
    --output "$build_dir/openamigapython-ac4-build.json" \
    --source-root "$project_root" \
    --version-header "$source_dir/Include/patchlevel.h" \
    --manifest "$project_root/Tools/cross/gcc-16.2-open2.json" \
    --compiler "$cc" \
    --cflags "$common_flags $cflags" \
    "${provenance_args[@]}"

echo "OPENAMIGAPYTHON-AC4-BUILD-OK $build_dir/python"
