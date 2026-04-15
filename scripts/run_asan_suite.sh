#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

HARDENING_TOOLCHAIN="${HARDENING_TOOLCHAIN:-nightly-2025-07-14}"
SANITIZER_TARGET="${SANITIZER_TARGET:-$(rustc +"${HARDENING_TOOLCHAIN}" -vV | awk '/^host: / { print $2 }')}"

source "$ROOT_DIR/scripts/hardening_test_names.sh"

if ((${#hardening_base_test_filters[@]} == 0 && ${#hardening_stwo_test_filters[@]} == 0)); then
  echo "hardening test filter lists are empty; refusing to run an empty hardening suite" >&2
  exit 1
fi

export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=1:leak_check_at_exit=0}"
export RUSTFLAGS="${RUSTFLAGS:-} -Zsanitizer=address"
export RUSTDOCFLAGS="${RUSTDOCFLAGS:-} -Zsanitizer=address"

for test_filter in "${hardening_base_test_filters[@]}"; do
  cargo +"${HARDENING_TOOLCHAIN}" test \
    -Zbuild-std \
    --target "${SANITIZER_TARGET}" \
    --lib "${test_filter}" \
    -- \
    --exact
done

for test_filter in "${hardening_stwo_test_filters[@]}"; do
  cargo +"${HARDENING_TOOLCHAIN}" test \
    -Zbuild-std \
    --target "${SANITIZER_TARGET}" \
    --features stwo-backend \
    --lib "${test_filter}" \
    -- \
    --exact
done
