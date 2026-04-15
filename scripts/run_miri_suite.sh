#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

HARDENING_TOOLCHAIN="${HARDENING_TOOLCHAIN:-nightly-2025-07-14}"
export MIRIFLAGS="${MIRIFLAGS:-"-Zmiri-strict-provenance -Zmiri-symbolic-alignment-check -Zmiri-disable-isolation"}"

source "$ROOT_DIR/scripts/hardening_test_names.sh"

if ((${#hardening_base_test_filters[@]} == 0)); then
  echo "hardening_base_test_filters is empty; refusing to run an empty Miri suite" >&2
  exit 1
fi

cargo +"${HARDENING_TOOLCHAIN}" miri setup

for test_filter in "${hardening_base_test_filters[@]}"; do
  cargo +"${HARDENING_TOOLCHAIN}" miri test --lib "${test_filter}" -- --exact
done
