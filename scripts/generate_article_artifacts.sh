#!/usr/bin/env bash
# Generate all article demo artifacts.
# Usage: ./scripts/generate_article_artifacts.sh
# Output: docs/artifacts/

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/docs/artifacts"
mkdir -p "$OUT"
GENERATED_ARTIFACTS=()

record_artifact() {
  GENERATED_ARTIFACTS+=("$1")
}

echo "=== Generating article artifacts ==="
echo "Output directory: $OUT"
echo ""

# --- 1. Micro-demo: addition ---

echo "--- addition: execution trace ---"
cargo run --bin tvm -- run programs/addition.tvm --trace 2>/dev/null \
  > "$OUT/addition_execution.txt"
record_artifact "$OUT/addition_execution.txt"
cat "$OUT/addition_execution.txt"
echo ""

echo "--- addition: prove-stark ---"
cargo run --bin tvm -- prove-stark programs/addition.tvm \
  -o "$OUT/addition.proof.json" 2>/dev/null \
  > "$OUT/addition_prove_summary.txt"
record_artifact "$OUT/addition.proof.json"
record_artifact "$OUT/addition_prove_summary.txt"
cat "$OUT/addition_prove_summary.txt"
echo ""

echo "--- addition: verify-stark ---"
cargo run --bin tvm -- verify-stark "$OUT/addition.proof.json" 2>/dev/null \
  > "$OUT/addition_verify_summary.txt"
record_artifact "$OUT/addition_verify_summary.txt"
cat "$OUT/addition_verify_summary.txt"
echo ""

# --- 2. Hero demo: fibonacci ---

echo "--- fibonacci: execution trace ---"
cargo run --bin tvm -- run programs/fibonacci.tvm --trace 2>/dev/null \
  > "$OUT/fibonacci_execution.txt"
record_artifact "$OUT/fibonacci_execution.txt"
# Print only the summary (first lines before trace)
head -20 "$OUT/fibonacci_execution.txt"
echo ""

echo "--- fibonacci: verify-all (4 engines) ---"
cargo run --features full --bin tvm -- run programs/fibonacci.tvm --verify-all 2>/dev/null \
  > "$OUT/fibonacci_verify_all.txt"
record_artifact "$OUT/fibonacci_verify_all.txt"
cat "$OUT/fibonacci_verify_all.txt"
echo ""

echo "--- fibonacci: prove-stark ---"
cargo run --bin tvm -- prove-stark programs/fibonacci.tvm \
  -o "$OUT/fibonacci.proof.json" 2>/dev/null \
  > "$OUT/fibonacci_prove_summary.txt"
record_artifact "$OUT/fibonacci.proof.json"
record_artifact "$OUT/fibonacci_prove_summary.txt"
cat "$OUT/fibonacci_prove_summary.txt"
echo ""

echo "--- fibonacci: verify-stark ---"
cargo run --bin tvm -- verify-stark "$OUT/fibonacci.proof.json" 2>/dev/null \
  > "$OUT/fibonacci_verify_summary.txt"
record_artifact "$OUT/fibonacci_verify_summary.txt"
cat "$OUT/fibonacci_verify_summary.txt"
echo ""

# --- 3. Recursion demo: factorial ---

echo "--- factorial_recursive: execution trace ---"
cargo run --bin tvm -- run programs/factorial_recursive.tvm --trace 2>/dev/null \
  > "$OUT/factorial_execution.txt"
record_artifact "$OUT/factorial_execution.txt"
head -20 "$OUT/factorial_execution.txt"
echo ""

echo "--- factorial_recursive: prove-stark ---"
cargo run --bin tvm -- prove-stark programs/factorial_recursive.tvm \
  -o "$OUT/factorial.proof.json" 2>/dev/null \
  > "$OUT/factorial_prove_summary.txt"
record_artifact "$OUT/factorial.proof.json"
record_artifact "$OUT/factorial_prove_summary.txt"
cat "$OUT/factorial_prove_summary.txt"
echo ""

echo "--- factorial_recursive: verify-stark ---"
cargo run --bin tvm -- verify-stark "$OUT/factorial.proof.json" 2>/dev/null \
  > "$OUT/factorial_verify_summary.txt"
record_artifact "$OUT/factorial_verify_summary.txt"
cat "$OUT/factorial_verify_summary.txt"
echo ""

# --- 4. Optional: multiply ---

echo "--- multiply: execution ---"
cargo run --bin tvm -- run programs/multiply.tvm --trace 2>/dev/null \
  > "$OUT/multiply_execution.txt"
record_artifact "$OUT/multiply_execution.txt"
cat "$OUT/multiply_execution.txt"
echo ""

# --- Summary ---

echo "=== All artifacts generated ==="
echo ""
for f in "${GENERATED_ARTIFACTS[@]}"; do
  [[ -e "$f" ]] || {
    echo "Missing generated artifact: $f" >&2
    exit 1
  }
  bytes=$(wc -c < "$f" | tr -d ' ')
  echo "$bytes $f"
done
echo ""
echo "Proof file sizes:"
for f in "$OUT"/*.proof.json; do
  [[ -e "$f" ]] || continue
  bytes=$(wc -c < "$f" | tr -d ' ')
  name=$(basename "$f")
  echo "  $name: $bytes bytes"
done
