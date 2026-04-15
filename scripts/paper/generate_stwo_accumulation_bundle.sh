#!/usr/bin/env bash
set -euo pipefail

export LANG=C
export LC_ALL=C

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

BUNDLE_DIR="${BUNDLE_DIR:-$REPO_ROOT/docs/paper/artifacts/stwo-accumulation-v1-2026-04-09}"
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
if [ -d "$BUNDLE_DIR" ] && [ "${ALLOW_OVERWRITE_FROZEN:-0}" != "1" ]; then
  if [ -f "$BUNDLE_DIR/sha256sums.txt" ] || [ -f "$BUNDLE_DIR/manifest.txt" ] || [ -f "$BUNDLE_DIR/APPENDIX_ARTIFACT_INDEX.md" ]; then
    echo "Refusing to overwrite existing frozen-looking bundle: $BUNDLE_DIR" >&2
    echo "Set BUNDLE_DIR to a fresh scratch directory under $EXPECTED_PREFIX or set ALLOW_OVERWRITE_FROZEN=1 to override." >&2
    exit 1
  fi
fi
rm -rf -- "$BUNDLE_DIR"
mkdir -p "$BUNDLE_DIR"

MANIFEST="$BUNDLE_DIR/manifest.txt"
BENCHMARKS="$BUNDLE_DIR/benchmarks.tsv"
COMMANDS_LOG="$BUNDLE_DIR/commands.log"
SUMMARY_TSV="$BUNDLE_DIR/artifact_summary.tsv"
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
fixtures: decoding_chain_phase12, decoding_rollup_matrix_phase17, decoding_matrix_accumulator_phase21, decoding_lookup_accumulator_phase22, decoding_cross_step_lookup_accumulator_phase23
MANIFEST

run_timed prove_decoding_chain_phase12_stwo \
  "${CARGO_STWO[@]}" \
  prove-stwo-decoding-demo \
  -o "$BUNDLE_DIR/decoding-phase12.chain.json"

run_timed verify_decoding_chain_phase12_stwo \
  "${CARGO_STWO[@]}" \
  verify-stwo-decoding-demo "$BUNDLE_DIR/decoding-phase12.chain.json"

run_timed prove_decoding_rollup_matrix_phase17_stwo \
  "${CARGO_STWO[@]}" \
  prove-stwo-decoding-history-rollup-matrix-demo \
  -o "$BUNDLE_DIR/decoding-phase17.rollup-matrix.json"

run_timed verify_decoding_rollup_matrix_phase17_stwo \
  "${CARGO_STWO[@]}" \
  verify-stwo-decoding-history-rollup-matrix-demo "$BUNDLE_DIR/decoding-phase17.rollup-matrix.json"

run_timed prove_decoding_matrix_accumulator_phase21_stwo \
  "${CARGO_STWO[@]}" \
  prove-stwo-decoding-matrix-accumulator-demo \
  -o "$BUNDLE_DIR/decoding-phase21.matrix-accumulator.json"

run_timed verify_decoding_matrix_accumulator_phase21_stwo \
  "${CARGO_STWO[@]}" \
  verify-stwo-decoding-matrix-accumulator-demo "$BUNDLE_DIR/decoding-phase21.matrix-accumulator.json"

run_timed prove_decoding_lookup_accumulator_phase22_stwo \
  "${CARGO_STWO[@]}" \
  prove-stwo-decoding-lookup-accumulator-demo \
  -o "$BUNDLE_DIR/decoding-phase22.lookup-accumulator.json"

run_timed verify_decoding_lookup_accumulator_phase22_stwo \
  "${CARGO_STWO[@]}" \
  verify-stwo-decoding-lookup-accumulator-demo "$BUNDLE_DIR/decoding-phase22.lookup-accumulator.json"

run_timed prove_decoding_cross_step_lookup_accumulator_phase23_stwo \
  "${CARGO_STWO[@]}" \
  prove-stwo-decoding-cross-step-lookup-accumulator-demo \
  -o "$BUNDLE_DIR/decoding-phase23.cross-step-lookup-accumulator.json"

run_timed verify_decoding_cross_step_lookup_accumulator_phase23_stwo \
  "${CARGO_STWO[@]}" \
  verify-stwo-decoding-cross-step-lookup-accumulator-demo \
  "$BUNDLE_DIR/decoding-phase23.cross-step-lookup-accumulator.json"

python3 - "$BUNDLE_DIR" "$INDEX_MD" "$README_MD" "$SUMMARY_TSV" <<'PY'
import csv
import hashlib
import json
import sys
from pathlib import Path

bundle = Path(sys.argv[1])
index_md = Path(sys.argv[2])
readme_md = Path(sys.argv[3])
summary_tsv = Path(sys.argv[4])

artifacts = [
    (
        "decoding-phase12.chain.json",
        "Phase 12",
        "Base proof-carrying decoding chain",
        "proof-carrying decoding baseline",
        "prove_decoding_chain_phase12_stwo",
        "verify_decoding_chain_phase12_stwo",
    ),
    (
        "decoding-phase17.rollup-matrix.json",
        "Phase 17",
        "Multi-layout rollup matrix over carried-state segments",
        "carried-state matrix packaging",
        "prove_decoding_rollup_matrix_phase17_stwo",
        "verify_decoding_rollup_matrix_phase17_stwo",
    ),
    (
        "decoding-phase21.matrix-accumulator.json",
        "Phase 21",
        "Template-bound accumulator over Phase 17 matrices",
        "pre-recursive template-bound accumulation",
        "prove_decoding_matrix_accumulator_phase21_stwo",
        "verify_decoding_matrix_accumulator_phase21_stwo",
    ),
    (
        "decoding-phase22.lookup-accumulator.json",
        "Phase 22",
        "Lookup-side accumulator over a Phase 21 matrix accumulator",
        "pre-recursive lookup accumulation",
        "prove_decoding_lookup_accumulator_phase22_stwo",
        "verify_decoding_lookup_accumulator_phase22_stwo",
    ),
    (
        "decoding-phase23.cross-step-lookup-accumulator.json",
        "Phase 23",
        "Cross-step lookup accumulator over cumulative Phase 22 prefixes",
        "cross-step pre-recursive lookup accumulation",
        "prove_decoding_cross_step_lookup_accumulator_phase23_stwo",
        "verify_decoding_cross_step_lookup_accumulator_phase23_stwo",
    ),
]

def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def load_json(path: Path):
    with path.open() as f:
        return json.load(f)

def extract_stats(data):
    return {
        "proof_count": len(data["proofs"]) if isinstance(data.get("proofs"), list) else "",
        "member_count": len(data["members"]) if isinstance(data.get("members"), list) else "",
        "matrix_count": len(data["matrices"]) if isinstance(data.get("matrices"), list) else "",
        "total_steps": data.get("total_steps", ""),
        "total_layouts": data.get("total_layouts", ""),
        "total_rollups": data.get("total_rollups", ""),
        "total_segments": data.get("total_segments", ""),
        "total_members": data.get("total_members", ""),
        "total_matrices": data.get("total_matrices", ""),
        "lookup_delta_entries": data.get("lookup_delta_entries", ""),
        "max_lookup_frontier_entries": data.get("max_lookup_frontier_entries", ""),
    }

benchmarks = {}
with (bundle / "benchmarks.tsv").open() as f:
    next(f)
    for line in f:
        label, seconds = line.rstrip("\n").split("\t")
        benchmarks[label] = seconds

summary_rows = []
for name, phase, purpose, scope, prove_label, verify_label in artifacts:
    path = bundle / name
    data = load_json(path)
    stats = extract_stats(data)
    summary_rows.append({
        "artifact": name,
        "phase": phase,
        "purpose": purpose,
        "scope": scope,
        "size_bytes": path.stat().st_size,
        "prove_seconds": benchmarks.get(prove_label, ""),
        "verify_seconds": benchmarks.get(verify_label, ""),
        "proof_count": stats["proof_count"],
        "member_count": stats["member_count"],
        "matrix_count": stats["matrix_count"],
        "total_steps": stats["total_steps"],
        "total_layouts": stats["total_layouts"],
        "total_rollups": stats["total_rollups"],
        "total_segments": stats["total_segments"],
        "total_members": stats["total_members"],
        "total_matrices": stats["total_matrices"],
        "lookup_delta_entries": stats["lookup_delta_entries"],
        "max_lookup_frontier_entries": stats["max_lookup_frontier_entries"],
        "sha256": sha256(path),
    })

fieldnames = [
    "artifact",
    "phase",
    "purpose",
    "scope",
    "size_bytes",
    "prove_seconds",
    "verify_seconds",
    "proof_count",
    "member_count",
    "matrix_count",
    "total_steps",
    "total_layouts",
    "total_rollups",
    "total_segments",
    "total_members",
    "total_matrices",
    "lookup_delta_entries",
    "max_lookup_frontier_entries",
    "sha256",
]
with summary_tsv.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter="\t")
    writer.writeheader()
    writer.writerows(summary_rows)

index_lines = [
    "# Appendix Artifact Index (S-two Accumulation V1)",
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
    "## Artifact Summary",
    "",
    "| Artifact | Phase | Scope | Size (bytes) | Prove (s) | Verify (s) | Total steps | Total rollups | Total segments | Total members | Lookup delta entries | SHA-256 |",
    "|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|",
])
for row in summary_rows:
    index_lines.append(
        f"| {row['artifact']} | {row['phase']} | {row['scope']} | {row['size_bytes']} | "
        f"{row['prove_seconds']} | {row['verify_seconds']} | {row['total_steps']} | "
        f"{row['total_rollups']} | {row['total_segments']} | {row['total_members']} | "
        f"{row['lookup_delta_entries']} | {row['sha256']} |"
    )
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
    "- This bundle is a controlled carried/accumulated decode-artifact snapshot for the next-paper track, not a normalized backend benchmark study.",
    "- The artifact family keeps the same underlying decoding relation while moving from a base chain to matrix packaging and then to progressively stronger pre-recursive accumulation layers.",
    "- Timing rows are local wall-clock runs under an existing cargo build cache and should be read as artifact facts, not cross-system benchmark claims.",
    "- `artifact_summary.tsv` provides the machine-readable comparison surface for later paper tables and plots.",
    "- Recompute integrity with `shasum -a 256 *.json benchmarks.tsv artifact_summary.tsv manifest.txt commands.log APPENDIX_ARTIFACT_INDEX.md README.md` inside the bundle directory.",
])
index_md.write_text("\n".join(index_lines) + "\n")

readme_lines = [
    "# S-two Accumulation Artifact Bundle V1",
    "",
    "This directory freezes a controlled decode-artifact family for the carried/accumulated `stwo` path. It is intended for the next-paper track rather than for the current publication snapshot.",
    "",
    "Artifacts included:",
    "",
    "- `decoding-phase12.chain.json`: base proof-carrying decoding chain,",
    "- `decoding-phase17.rollup-matrix.json`: multi-layout rollup-matrix packaging over the same decode relation,",
    "- `decoding-phase21.matrix-accumulator.json`: template-bound accumulator over Phase 17 matrices,",
    "- `decoding-phase22.lookup-accumulator.json`: lookup-side accumulator over a Phase 21 matrix accumulator,",
    "- `decoding-phase23.cross-step-lookup-accumulator.json`: cross-step lookup accumulator over cumulative Phase 22 prefixes.",
    "",
    "The bundle records exact command logs, wall-clock timings, integrity hashes, and a machine-readable `artifact_summary.tsv` so later paper drafts can compare base, carried, and accumulated paths on one committed artifact family.",
    "",
    "These artifacts are still pre-recursive. They do **not** claim recursive cryptographic accumulation/compression or full standard-softmax transformer inference.",
    "",
    "See `APPENDIX_ARTIFACT_INDEX.md` for exact hashes, timings, and structural summary fields.",
]
readme_md.write_text("\n".join(readme_lines) + "\n")
PY

(
  cd "$BUNDLE_DIR"
  shasum -a 256 -- *.json benchmarks.tsv artifact_summary.tsv manifest.txt commands.log APPENDIX_ARTIFACT_INDEX.md README.md > "$SHA256S"
)

chmod 644 "$MANIFEST" "$BENCHMARKS" "$COMMANDS_LOG" "$SUMMARY_TSV" "$SHA256S" "$INDEX_MD" "$README_MD"

echo "Generated $BUNDLE_DIR"
