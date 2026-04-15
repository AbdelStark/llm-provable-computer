#!/usr/bin/env bash
set -euo pipefail

export LANG=C
export LC_ALL=C

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

BUNDLE_DIR="${BUNDLE_DIR:-$REPO_ROOT/docs/paper/artifacts/stwo-experimental-v1-2026-04-06}"
NIGHTLY_TOOLCHAIN="${NIGHTLY_TOOLCHAIN:-+nightly-2025-07-14}"
CARGO_STWO=(cargo "$NIGHTLY_TOOLCHAIN" run --features stwo-backend --bin tvm --)

EXPECTED_PREFIX="$REPO_ROOT/docs/paper/artifacts"
CANON_EXPECTED_PREFIX="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$EXPECTED_PREFIX")"
CANON_BUNDLE_DIR="$(python3 -c 'import os,sys; print(os.path.realpath(os.path.abspath(sys.argv[1])))' "$BUNDLE_DIR")"
case "$CANON_BUNDLE_DIR/" in
  "$CANON_EXPECTED_PREFIX"/*) ;;
  *)
    echo "Refusing to use BUNDLE_DIR outside $EXPECTED_PREFIX: $BUNDLE_DIR" >&2
    exit 1
    ;;
esac
[ -n "$CANON_BUNDLE_DIR" ] || { echo "Refusing to use empty BUNDLE_DIR" >&2; exit 1; }
[ "$CANON_BUNDLE_DIR" != "$CANON_EXPECTED_PREFIX" ] || {
  echo "Refusing to delete artifacts root: $CANON_BUNDLE_DIR" >&2
  exit 1
}
[ "$CANON_BUNDLE_DIR" != "/" ] || { echo "Refusing to delete /" >&2; exit 1; }
[ "$CANON_BUNDLE_DIR" != "$REPO_ROOT" ] || { echo "Refusing to delete repo root" >&2; exit 1; }

BUNDLE_DIR="$CANON_BUNDLE_DIR"
rm -rf -- "$BUNDLE_DIR"
mkdir -p "$BUNDLE_DIR"

MANIFEST="$BUNDLE_DIR/manifest.txt"
BENCHMARKS="$BUNDLE_DIR/benchmarks.tsv"
COMMANDS_LOG="$BUNDLE_DIR/commands.log"
SHA256S="$BUNDLE_DIR/sha256sums.txt"
INDEX_MD="$BUNDLE_DIR/APPENDIX_ARTIFACT_INDEX.md"
README_MD="$BUNDLE_DIR/README.md"

: > "$COMMANDS_LOG"
printf 'label\tseconds\n' > "$BENCHMARKS"

run_timed() {
  local label="$1"
  shift
  local started_iso started_epoch ended_epoch elapsed
  started_iso="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  started_epoch="$(date +%s)"
  printf '[%s] %s\n' "$started_iso" "$*" | tee -a "$COMMANDS_LOG"
  "$@"
  ended_epoch="$(date +%s)"
  elapsed="$((ended_epoch - started_epoch))"
  printf '%s\t%s\n' "$label" "$elapsed" >> "$BENCHMARKS"
}

cat > "$MANIFEST" <<MANIFEST
generated_at_utc: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
repo_root: .
git_commit: $(git rev-parse HEAD)
git_commit_short: $(git rev-parse --short HEAD)
git_branch: $(git rev-parse --abbrev-ref HEAD)
rustc: $(rustup run "${NIGHTLY_TOOLCHAIN#+}" rustc --version)
cargo: $(cargo "$NIGHTLY_TOOLCHAIN" --version)
host_platform: $(uname -srm)
nightly_toolchain: $NIGHTLY_TOOLCHAIN
bundle_dir: docs/paper/artifacts/$(basename "$BUNDLE_DIR")
fixtures: addition, shared-normalization-demo, gemma_block_v4, decoding_demo
MANIFEST

run_timed prove_addition_stwo \
  "${CARGO_STWO[@]}" \
  prove-stark programs/addition.tvm \
  --backend stwo \
  -o "$BUNDLE_DIR/addition.stwo.proof.json"

run_timed verify_addition_stwo \
  "${CARGO_STWO[@]}" \
  verify-stark "$BUNDLE_DIR/addition.stwo.proof.json"

run_timed prove_shared_normalization_stwo \
  "${CARGO_STWO[@]}" \
  prove-stwo-shared-normalization-demo \
  -o "$BUNDLE_DIR/shared-normalization.stwo.proof.json"

run_timed verify_shared_normalization_stwo \
  "${CARGO_STWO[@]}" \
  verify-stwo-shared-normalization-demo "$BUNDLE_DIR/shared-normalization.stwo.proof.json"

run_timed prove_gemma_block_v4_stwo \
  "${CARGO_STWO[@]}" \
  prove-stark programs/gemma_block_v4.tvm \
  --backend stwo \
  --max-steps 256 \
  -o "$BUNDLE_DIR/gemma_block_v4.stwo.proof.json"

run_timed verify_gemma_block_v4_stwo \
  "${CARGO_STWO[@]}" \
  verify-stark "$BUNDLE_DIR/gemma_block_v4.stwo.proof.json"

run_timed prove_decoding_demo_stwo \
  "${CARGO_STWO[@]}" \
  prove-stwo-decoding-demo \
  -o "$BUNDLE_DIR/decoding.stwo.chain.json"

run_timed verify_decoding_demo_stwo \
  "${CARGO_STWO[@]}" \
  verify-stwo-decoding-demo "$BUNDLE_DIR/decoding.stwo.chain.json"

python3 - "$BUNDLE_DIR" "$INDEX_MD" "$README_MD" <<'PY'
import hashlib
import os
import sys
from pathlib import Path

bundle = Path(sys.argv[1])
index_md = Path(sys.argv[2])
readme_md = Path(sys.argv[3])

artifacts = [
    ("addition.stwo.proof.json", "Experimental S-two arithmetic execution proof", "arithmetic"),
    ("shared-normalization.stwo.proof.json", "Shared-table normalization lookup proof envelope", "lookup-backed component"),
    ("gemma_block_v4.stwo.proof.json", "Gemma-inspired fixed-shape execution proof with shared lookup bindings", "transformer-shaped checksum fixture"),
    ("decoding.stwo.chain.json", "Three-step proof-carrying decoding chain", "proof-carrying decoding"),
    ("manifest.txt", "Environment and commit metadata", "metadata"),
    ("benchmarks.tsv", "Wall-clock timings by command label", "metadata"),
    ("commands.log", "Exact command log with UTC timestamps", "metadata"),
]

def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()

benchmarks = {}
bench_path = bundle / "benchmarks.tsv"
with bench_path.open() as f:
    next(f)
    for line in f:
        label, seconds = line.rstrip("\n").split("\t")
        benchmarks[label] = seconds

rows = []
for name, purpose, scope in artifacts:
    path = bundle / name
    size = path.stat().st_size
    digest = sha256(path)
    rows.append((name, purpose, scope, size, digest))

index_lines = [
    "# Appendix Artifact Index (S-two Experimental V1)",
    "",
    "## Run Metadata",
]
manifest_lines = (bundle / "manifest.txt").read_text().splitlines()
for line in manifest_lines:
    if ": " in line:
        key, value = line.split(": ", 1)
        index_lines.append(f"- {key.replace('_', ' ').capitalize()}: {value}")
index_lines.extend([
    "",
    "## Primary Artifacts",
    "",
    "| Artifact | Purpose | Semantic scope | Size (bytes) | SHA-256 |",
    "|---|---|---|---:|---|",
])
for name, purpose, scope, size, digest in rows:
    index_lines.append(f"| {name} | {purpose} | {scope} | {size} | {digest} |")
index_lines.extend([
    "",
    "## Timing Summary (seconds)",
    "",
    "| Label | Seconds |",
    "|---|---:|",
])
for label, seconds in benchmarks.items():
    index_lines.append(f"| {label} | {seconds} |")
index_lines.extend([
    "",
    "## Notes",
    "- This bundle freezes the current publication-facing experimental `stwo` evidence tier.",
    "- The included artifacts deliberately span one arithmetic proof, one lookup-backed proof envelope, one transformer-shaped execution proof, and one proof-carrying decoding chain.",
    "- Timing rows are local wall-clock bundle runs under an existing cargo build cache; they are artifact facts, not a normalized backend-performance study.",
    "- Recompute integrity with `shasum -a 256 *.json benchmarks.tsv manifest.txt commands.log APPENDIX_ARTIFACT_INDEX.md README.md` inside the bundle directory.",
])
index_md.write_text("\n".join(index_lines) + "\n")

readme_lines = [
    "# S-two Experimental Artifact Bundle V1",
    "",
    "This directory freezes the publication-facing exploratory `stwo` evidence tier referenced by the paper. It deliberately complements the vanilla-backend `production-v1` reproducibility bundle with four narrower experimental artifacts:",
    "",
    "- `addition.stwo.proof.json`: one arithmetic `statement-v1` execution proof,",
    "- `shared-normalization.stwo.proof.json`: one shared-table lookup-backed normalization proof envelope,",
    "- `gemma_block_v4.stwo.proof.json`: one transformer-shaped fixed-shape `statement-v1` execution proof with shared lookup bindings, and",
    "- `decoding.stwo.chain.json`: one three-step proof-carrying decoding chain over explicit carried-state commitments.",
    "",
    "These artifacts remain intentionally narrow. They do **not** prove full standard-softmax transformer inference, recursive aggregation, or production-scale decoding. Their role is to provide a frozen second evidence tier for the paper's experimental `stwo` path.",
    "Timing rows in the accompanying index are local wall-clock bundle runs under an existing cargo build cache and should be read as artifact metadata rather than a normalized backend benchmark.",
    "",
    "See `APPENDIX_ARTIFACT_INDEX.md` for exact hashes, timings, and metadata.",
]
readme_md.write_text("\n".join(readme_lines) + "\n")
PY

(
  cd "$BUNDLE_DIR"
  shasum -a 256 -- *.json benchmarks.tsv manifest.txt commands.log APPENDIX_ARTIFACT_INDEX.md README.md > "$SHA256S"
)

chmod 644 "$MANIFEST" "$BENCHMARKS" "$COMMANDS_LOG" "$SHA256S" "$INDEX_MD" "$README_MD"

echo "Generated $BUNDLE_DIR"
