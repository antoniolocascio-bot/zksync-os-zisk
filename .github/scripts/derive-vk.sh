#!/usr/bin/env bash
set -euo pipefail

# Compute the program VK for one ELF. The stable output copy has the ZiSK
# binary format: four little-endian u64 limbs.

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <elf> <output-directory>" >&2
    exit 2
fi

elf=$1
output_dir=$2

test -f "$elf"
mkdir -p "$output_dir"

cargo-zisk program-setup \
    --elf "$elf" \
    --proving-key "$HOME/.zisk/provingKey" \
    -o "$output_dir" \
    2>&1 | tee "$output_dir/program-setup.log"

shopt -s nullglob
verkeys=("$output_dir"/*.verkey.bin)
if [[ ${#verkeys[@]} -ne 1 ]]; then
    echo "ERROR: expected one program VK, found ${#verkeys[@]}" >&2
    exit 1
fi

test "$(stat --format=%s "${verkeys[0]}")" -eq 32
cp "${verkeys[0]}" "$output_dir/program.verkey.bin"
