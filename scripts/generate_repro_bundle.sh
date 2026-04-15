#!/usr/bin/env bash
# Generate a publication-grade reproducibility bundle with commands, timings,
# proofs, semantic artifacts, and artifact hashes.
#
# Usage:
#   ./scripts/generate_repro_bundle.sh
#   ./scripts/generate_repro_bundle.sh /custom/output/dir

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/compiled/repro-bundle}"
mkdir -p "$OUT"

STARK_PROFILE="${STARK_PROFILE:-default}"
PROOF_MAX_STEPS="${PROOF_MAX_STEPS:-256}"
INCLUDE_FIBONACCI_PROOF="${INCLUDE_FIBONACCI_PROOF:-0}"

COMMANDS_LOG="$OUT/commands.log"
BENCHMARKS="$OUT/benchmarks.tsv"
MANIFEST="$OUT/manifest.txt"
HASHES="$OUT/sha256sums.txt"

: >"$COMMANDS_LOG"
printf "label\tseconds\n" >"$BENCHMARKS"

run_and_capture() {
  local label="$1"
  shift
  local stdout_path="$OUT/${label}.out"
  local stderr_path="$OUT/${label}.err"

  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $label :: $*" | tee -a "$COMMANDS_LOG"
  local start
  start="$(date +%s)"
  "$@" >"$stdout_path" 2>"$stderr_path"
  local end
  end="$(date +%s)"
  local seconds=$((end - start))
  printf "%s\t%d\n" "$label" "$seconds" >>"$BENCHMARKS"
}

cat >"$MANIFEST" <<EOF
generated_at_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)
repo_root: $ROOT
git_commit: $(git -C "$ROOT" rev-parse HEAD)
git_commit_short: $(git -C "$ROOT" rev-parse --short HEAD)
git_branch: $(git -C "$ROOT" rev-parse --abbrev-ref HEAD)
rustc: $(rustc --version)
cargo: $(cargo --version)
host_uname: $(uname -a)
stark_profile_for_proofs: ${STARK_PROFILE}
proof_max_steps: ${PROOF_MAX_STEPS}
include_fibonacci_proof: ${INCLUDE_FIBONACCI_PROOF}
EOF

PROGRAMS=(
  "addition"
  "counter"
  "fibonacci"
  "factorial_recursive"
  "multiply"
  "soft_attention_memory"
  "dot_product"
  "matmul_2x2"
  "single_neuron"
)

for name in "${PROGRAMS[@]}"; do
  run_and_capture "run_${name}" \
    cargo run --bin tvm -- run "programs/${name}.tvm" --verify-native --max-steps 256
done

PROOF_PROGRAMS=("addition" "dot_product" "single_neuron")
if [[ "$INCLUDE_FIBONACCI_PROOF" == "1" ]]; then
  PROOF_PROGRAMS+=("fibonacci")
fi

for name in "${PROOF_PROGRAMS[@]}"; do
  run_and_capture "prove_${name}" \
    cargo run --bin tvm -- prove-stark "programs/${name}.tvm" \
      -o "$OUT/${name}.proof.json" --stark-profile "$STARK_PROFILE" --max-steps "$PROOF_MAX_STEPS"
  run_and_capture "verify_${name}" \
    cargo run --bin tvm -- verify-stark "$OUT/${name}.proof.json" \
      --verification-profile "$STARK_PROFILE" --reexecute
done

run_and_capture "research_v2_step_dot_product" \
  cargo run --features onnx-export --bin tvm -- research-v2-step \
    programs/dot_product.tvm -o "$OUT/research-v2-dot-product-step.json" --max-steps 1

run_and_capture "research_v2_trace_dot_product" \
  cargo run --features onnx-export --bin tvm -- research-v2-trace \
    programs/dot_product.tvm -o "$OUT/research-v2-dot-product-trace.json" --max-steps 16

run_and_capture "research_v2_matrix_default_suite" \
  cargo run --features onnx-export --bin tvm -- research-v2-matrix \
    -o "$OUT/research-v2-matrix-default-suite.json" --include-default-suite --max-steps 64

run_and_capture "research_v3_equivalence_addition" \
  cargo run --features full --bin tvm -- research-v3-equivalence \
    programs/addition.tvm -o "$OUT/research-v3-addition-equivalence.json" --max-steps 8

(
  cd "$OUT"
  LC_ALL=C LANG=C shasum -a 256 \
    ./*.json \
    ./*.out \
    ./*.err \
    ./benchmarks.tsv \
    ./manifest.txt \
    ./commands.log >"$HASHES"
)

echo "Reproducibility bundle generated at: $OUT"
echo "Manifest: $MANIFEST"
echo "Benchmarks: $BENCHMARKS"
echo "Hashes: $HASHES"
