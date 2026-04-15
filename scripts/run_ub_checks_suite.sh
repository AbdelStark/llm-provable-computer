#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

HARDENING_TOOLCHAIN="${HARDENING_TOOLCHAIN:-nightly-2025-07-14}"

source "$ROOT_DIR/scripts/hardening_test_names.sh"

if ((${#hardening_base_test_filters[@]} == 0 && ${#hardening_onnx_test_filters[@]} == 0 && ${#hardening_tvm_bin_test_filters[@]} == 0 && ${#hardening_research_v3_test_filters[@]} == 0 && ${#hardening_stwo_test_filters[@]} == 0)); then
  echo "hardening test filter lists are empty; refusing to run an empty UB-checks suite" >&2
  exit 1
fi

export RUSTFLAGS="${RUSTFLAGS:-} -Zub-checks=yes"
export RUSTDOCFLAGS="${RUSTDOCFLAGS:-} -Zub-checks=yes"

for test_filter in "${hardening_base_test_filters[@]}"; do
  cargo +"${HARDENING_TOOLCHAIN}" test --lib "${test_filter}" -- --exact
done

for test_filter in "${hardening_onnx_test_filters[@]}"; do
  cargo +"${HARDENING_TOOLCHAIN}" test \
    --features onnx-export \
    --lib "${test_filter}" \
    -- \
    --exact
done

for test_filter in "${hardening_tvm_bin_test_filters[@]}"; do
  cargo +"${HARDENING_TOOLCHAIN}" test \
    "${hardening_tvm_bin_cargo_args[@]}" "${test_filter}" \
    -- \
    --exact
done

for test_filter in "${hardening_research_v3_test_filters[@]}"; do
  cargo +"${HARDENING_TOOLCHAIN}" test \
    --features burn-model,onnx-export \
    --bin tvm "${test_filter}" \
    -- \
    --exact
done

for test_filter in "${hardening_stwo_test_filters[@]}"; do
  cargo +"${HARDENING_TOOLCHAIN}" test \
    --features stwo-backend \
    --lib "${test_filter}" \
    -- \
    --exact
done
