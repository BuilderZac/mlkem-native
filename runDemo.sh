#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
output="$project_dir/demoUse"

cc="${CC:-gcc}"

"$cc" \
    -std=c99 \
    -O2 \
    -Wall \
    -Wextra \
    -Wpedantic \
    -DMLK_CONFIG_PARAMETER_SET=768 \
    -I"$project_dir/mlkem" \
    "$project_dir/demoUse.c" \
    "$project_dir/mlkem/mlkem_native.c" \
    "$project_dir/mlkem/mlkem_native_asm.S" \
    -o "$output"

exec "$output" "$@"
