#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "$0")/../.." && pwd)
build_target=${1:-standard}

case "$build_target" in
    standard|debug)
        ;;
    *)
        echo "usage: $0 [standard|debug]" >&2
        exit 2
        ;;
esac

source_dir="$project_root/Source"
toolchain=${AMIGAPYTHON_TOOLCHAIN:-/home/da1ek/ACNet-compat-lab/toolchain/amiga}
posix_dir=${AMIGAPYTHON_POSIXLIB:-$project_root/PosixLib}
ndk_include=${AMIGAPYTHON_NDK_INCLUDE:-/home/da1ek/AmigaChrome/stoves/os32/ndk/Include_H}
net_include=${AMIGAPYTHON_NET_INCLUDE:-/home/da1ek/AmigaChrome/stoves/os32/ndk/SANA+RoadshowTCP-IP/netinclude}
support_dir="$project_root/build-support/vbcc"
config_dir="$support_dir/config"
config_file="$config_dir/aos68k_posix"

for required in \
    "$toolchain/bin/vc" \
    "$toolchain/bin/vbccm68k" \
    "$toolchain/bin/vasmm68k_mot" \
    "$toolchain/bin/vlink" \
    "$toolchain/m68k-amigaos/vbcc/lib/startup.o" \
    "$posix_dir/AmigaOS3/posix.lib" \
    "$ndk_include/proto/exec.h" \
    "$net_include/proto/bsdsocket.h"; do
    if [[ ! -e "$required" ]]; then
        echo "missing build prerequisite: $required" >&2
        exit 1
    fi
done

mkdir -p "$config_dir"
sed \
    -e "s|@TOOLCHAIN@|$toolchain|g" \
    -e "s|@POSIX_LIB@|$posix_dir/AmigaOS3|g" \
    "$project_root/Tools/cross/aos68k_posix.in" > "$config_file"

make_assign() {
    local link_path=$1
    local target_path=$2

    if [[ -L "$link_path" ]]; then
        if [[ "$(readlink "$link_path")" == "$target_path" ]]; then
            return
        fi
        echo "refusing to replace existing assign link: $link_path" >&2
        exit 1
    fi
    if [[ -e "$link_path" ]]; then
        echo "refusing to replace existing path: $link_path" >&2
        exit 1
    fi
    ln -s "$target_path" "$link_path"
}

make_assign "$source_dir/vbcc:PosixLib" "$posix_dir"
make_assign "$source_dir/vincludeos3:" "$toolchain/m68k-amigaos/vbcc/include"
make_assign "$source_dir/include:" "$ndk_include"
make_assign "$source_dir/netinclude:" "$net_include"

export VBCC="$support_dir"

make_args=(
    -f vmakefile
    "CC=$toolchain/bin/vc"
    "VASM=$toolchain/bin/vasmm68k_mot"
    "VLINK=$toolchain/bin/vlink"
    "MKDIR=mkdir -p"
    "POSIX_INCLUDE=$posix_dir/include"
    "VBCC_INCLUDE=$toolchain/m68k-amigaos/vbcc/include"
    "NDK_INCLUDE=$ndk_include"
    "ZLIB_ODIR=$source_dir/build-vbcc/Modules/zlib"
)

cd "$source_dir"
make "${make_args[@]}" "$build_target"

if [[ "$build_target" == debug ]]; then
    echo "built: $source_dir/Python27_Debug"
else
    echo "built: $source_dir/Python27"
fi
