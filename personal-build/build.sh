#!/usr/bin/env bash
set -euo pipefail
recipe_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
sources_dir="$(realpath "$1")"
mkdir -p "$2" "$3"
build_dir="$(realpath "$2")"
output_dir="$(realpath "$3")"
prefix_dir="$build_dir/deps"
mkdir -p "$prefix_dir"
# No prebuilt xmrig-deps. libuv and OpenSSL are compiled from pinned sources.
cmake -S "$sources_dir/libuv" -B "$build_dir/uv" -DCMAKE_TOOLCHAIN_FILE="$recipe_dir/mingw.cmake" \
    -DCMAKE_INSTALL_PREFIX="$prefix_dir" -DLIBUV_BUILD_SHARED=OFF -DLIBUV_BUILD_TESTS=OFF -DCMAKE_BUILD_TYPE=Release
cmake --build "$build_dir/uv" --parallel 2
cmake --install "$build_dir/uv"
(
    cd "$sources_dir/openssl"
    perl Configure mingw64 --cross-compile-prefix=x86_64-w64-mingw32- \
        no-shared no-tests no-module --prefix="$prefix_dir" --libdir=lib
    make -j2 build_libs
    make install_dev
)
# Windows headers are case-insensitive on Windows; MinGW cross builds run on Linux.
# These forwarding headers adapt Windows header names for the Linux compiler.
mkdir -p "$prefix_dir/include"
for header in Windows Shobjidl Objbase; do
    printf '#include <%s.h>\n' "${header,,}" > "$prefix_dir/include/$header.h"
done
python3 "$recipe_dir/apply_hardening.py" "$sources_dir/xmrig"
cmake -S "$sources_dir/xmrig" -B "$build_dir/xmrig" -DCMAKE_TOOLCHAIN_FILE="$recipe_dir/mingw.cmake" \
    -DXMRIG_DEPS="$prefix_dir" -DUV_LIBRARY="$prefix_dir/lib/libuv.a" -DCMAKE_PROJECT_xmrig_INCLUDE="$recipe_dir/windows-libs.cmake" \
    -DWITH_OPENCL=ON -DWITH_KAWPOW=ON -DWITH_TLS=ON -DWITH_ADL=ON \
    -DWITH_HWLOC=OFF -DWITH_MSR=OFF -DWITH_DMI=OFF -DWITH_ASM=OFF -DWITH_CUDA=OFF \
    -DWITH_RANDOMX=ON -DWITH_BENCHMARK=OFF -DWITH_GHOSTRIDER=OFF -DWITH_ARGON2=OFF \
    -DWITH_CN_LITE=OFF -DWITH_CN_HEAVY=OFF -DWITH_CN_PICO=OFF -DWITH_CN_FEMTO=OFF \
    -DWITH_HTTP=OFF -DCMAKE_BUILD_TYPE=Release
cmake --build "$build_dir/xmrig" --parallel 2
cp "$build_dir/xmrig/xmrig.exe" "$output_dir/xmrig.exe"
cp "$sources_dir/xmrig/LICENSE" "$output_dir/LICENSE-xmrig.txt"
cp "$sources_dir/libuv/LICENSE" "$output_dir/LICENSE-libuv.txt"
cp "$sources_dir/openssl/LICENSE.txt" "$output_dir/LICENSE-openssl.txt"
cp "$recipe_dir/sources.json" "$output_dir/sources.json"
python3 "$recipe_dir/provenance.py" "$output_dir"
x86_64-w64-mingw32-objdump -p "$output_dir/xmrig.exe" > "$output_dir/pe-imports.txt"
