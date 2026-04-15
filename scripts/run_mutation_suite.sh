#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

MUTATION_TOOLCHAIN="${MUTATION_TOOLCHAIN:-nightly-2025-07-14}"
MUTATION_TARGETS=(
  src/stwo_backend/decoding.rs
  src/stwo_backend/shared_lookup_artifact.rs
  src/stwo_backend/arithmetic_subset_prover.rs
)

if (($# > 0)) && [[ "$1" == "--print-targets" ]]; then
  printf '%s\n' "${MUTATION_TARGETS[@]}"
  exit 0
fi

missing_targets=()
for target in "${MUTATION_TARGETS[@]}"; do
  if [[ ! -f "$target" ]]; then
    missing_targets+=("$target")
  fi
done

if (( ${#missing_targets[@]} > 0 )); then
  printf 'missing mutation targets:\n' >&2
  printf '  %s\n' "${missing_targets[@]}" >&2
  exit 1
fi

if [[ -n "${MUTATION_DIFF_FILE:-}" ]]; then
  if [[ ! -f "${MUTATION_DIFF_FILE}" ]]; then
    echo "MUTATION_DIFF_FILE points to a missing file: ${MUTATION_DIFF_FILE}" >&2
    exit 1
  fi
  if [[ ! -s "${MUTATION_DIFF_FILE}" ]]; then
    echo "MUTATION_DIFF_FILE is empty; refusing to run a zero-diff mutation slice" >&2
    exit 1
  fi
fi

args=(
  cargo
  +"${MUTATION_TOOLCHAIN}"
  mutants
  --features stwo-backend
  --test-tool cargo
  --cap-lints=true
  --copy-target=true
  --baseline "${MUTATION_BASELINE:-skip}"
  --minimum-test-timeout "${MUTATION_MIN_TEST_TIMEOUT:-60}"
  --timeout "${MUTATION_TIMEOUT:-600}"
  --jobs "${MUTATION_JOBS:-2}"
  --no-shuffle
)

for target in "${MUTATION_TARGETS[@]}"; do
  args+=(--file "$target")
done

if [[ -n "${MUTATION_SHARD:-}" ]]; then
  args+=(--shard "$MUTATION_SHARD")
fi

if [[ -n "${MUTATION_DIFF_FILE:-}" ]]; then
  args+=(--in-diff "${MUTATION_DIFF_FILE}")
fi

"${args[@]}" "$@"
