#!/usr/bin/env bash
set -euo pipefail

export LANG=C
export LC_ALL=C
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

BUNDLE_DIR="${BUNDLE_DIR:-$REPO_ROOT/docs/paper/artifacts/stwo-folded-interval-v1-2026-04-10}"
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
SUMMARY_TSV="$BUNDLE_DIR/artifact_summary.tsv"
SHA256S="$BUNDLE_DIR/sha256sums.txt"
PROVENANCE_SHA256S="$BUNDLE_DIR/provenance_sha256sums.txt"
INDEX_MD="$BUNDLE_DIR/APPENDIX_ARTIFACT_INDEX.md"
README_MD="$BUNDLE_DIR/README.md"
CANONICAL_CHECKSUM_FILES=(
  README.md
  decoding-phase24.state-relation-accumulator.json.gz
  decoding-phase25.intervalized-state-relation.json.gz
  decoding-phase26.folded-intervalized-state-relation.json.gz
)
PROVENANCE_CHECKSUM_FILES=(
  manifest.txt
  benchmarks.tsv
  commands.log
  artifact_summary.tsv
  APPENDIX_ARTIFACT_INDEX.md
  README.md
  decoding-phase24.state-relation-accumulator.json.gz
  decoding-phase25.intervalized-state-relation.json.gz
  decoding-phase26.folded-intervalized-state-relation.json.gz
)

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
fixtures: decoding_state_relation_accumulator_phase24, intervalized_decoding_state_relation_phase25, folded_intervalized_decoding_state_relation_phase26
MANIFEST

run_timed prove_decoding_state_relation_accumulator_phase24_stwo \
  "${CARGO_STWO[@]}" \
  prove-stwo-decoding-state-relation-accumulator-demo \
  -o "$BUNDLE_DIR/decoding-phase24.state-relation-accumulator.json"

run_timed verify_decoding_state_relation_accumulator_phase24_stwo \
  "${CARGO_STWO[@]}" \
  verify-stwo-decoding-state-relation-accumulator-demo \
  "$BUNDLE_DIR/decoding-phase24.state-relation-accumulator.json"

run_timed prove_intervalized_decoding_state_relation_phase25_stwo \
  "${CARGO_STWO[@]}" \
  prove-stwo-intervalized-decoding-state-relation-demo \
  -o "$BUNDLE_DIR/decoding-phase25.intervalized-state-relation.json"

run_timed verify_intervalized_decoding_state_relation_phase25_stwo \
  "${CARGO_STWO[@]}" \
  verify-stwo-intervalized-decoding-state-relation-demo \
  "$BUNDLE_DIR/decoding-phase25.intervalized-state-relation.json"

run_timed prove_folded_intervalized_decoding_state_relation_phase26_stwo \
  "${CARGO_STWO[@]}" \
  prove-stwo-folded-intervalized-decoding-state-relation-demo \
  -o "$BUNDLE_DIR/decoding-phase26.folded-intervalized-state-relation.json"

run_timed verify_folded_intervalized_decoding_state_relation_phase26_stwo \
  "${CARGO_STWO[@]}" \
  verify-stwo-folded-intervalized-decoding-state-relation-demo \
  "$BUNDLE_DIR/decoding-phase26.folded-intervalized-state-relation.json"

for artifact in \
  "$BUNDLE_DIR/decoding-phase24.state-relation-accumulator.json" \
  "$BUNDLE_DIR/decoding-phase25.intervalized-state-relation.json" \
  "$BUNDLE_DIR/decoding-phase26.folded-intervalized-state-relation.json"
do
  gzip -n -9 -c "$artifact" > "$artifact.gz"
  rm -f "$artifact"
done

python3 - "$BUNDLE_DIR" "$INDEX_MD" "$README_MD" "$SUMMARY_TSV" <<'PY'
import csv
import gzip
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
        "decoding-phase24.state-relation-accumulator.json.gz",
        "Phase 24",
        "Carried-state relation accumulator over cumulative Phase 23 prefixes",
        "pre-recursive carried-state relation boundary accumulator",
        "prove_decoding_state_relation_accumulator_phase24_stwo",
        "verify_decoding_state_relation_accumulator_phase24_stwo",
    ),
    (
        "decoding-phase25.intervalized-state-relation.json.gz",
        "Phase 25",
        "Intervalized carried-state relation artifact over rebased cumulative prefixes",
        "honest intervalization over real carried-state intervals",
        "prove_intervalized_decoding_state_relation_phase25_stwo",
        "verify_intervalized_decoding_state_relation_phase25_stwo",
    ),
    (
        "decoding-phase26.folded-intervalized-state-relation.json.gz",
        "Phase 26",
        "Folded accumulator over Phase 25 interval artifacts",
        "bounded pre-recursive folding over carried-state intervals",
        "prove_folded_intervalized_decoding_state_relation_phase26_stwo",
        "verify_folded_intervalized_decoding_state_relation_phase26_stwo",
    ),
]

def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def load_json(path: Path):
    opener = gzip.open if path.suffix == ".gz" else path.open
    with opener(path, "rt") as f:
        return json.load(f)

def extract_stats(data):
    return {
        "member_count": len(data["members"]) if isinstance(data.get("members"), list) else "",
        "total_steps": data.get("total_steps", ""),
        "total_layouts": data.get("total_layouts", ""),
        "total_rollups": data.get("total_rollups", ""),
        "total_segments": data.get("total_segments", ""),
        "total_matrices": data.get("total_matrices", ""),
        "lookup_delta_entries": data.get("lookup_delta_entries", ""),
        "max_lookup_frontier_entries": data.get("max_lookup_frontier_entries", ""),
        "bounded_fold_arity": data.get("bounded_fold_arity", ""),
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
        "member_count": stats["member_count"],
        "total_steps": stats["total_steps"],
        "total_layouts": stats["total_layouts"],
        "total_rollups": stats["total_rollups"],
        "total_segments": stats["total_segments"],
        "total_matrices": stats["total_matrices"],
        "lookup_delta_entries": stats["lookup_delta_entries"],
        "max_lookup_frontier_entries": stats["max_lookup_frontier_entries"],
        "bounded_fold_arity": stats["bounded_fold_arity"],
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
    "member_count",
    "total_steps",
    "total_layouts",
    "total_rollups",
    "total_segments",
    "total_matrices",
    "lookup_delta_entries",
    "max_lookup_frontier_entries",
    "bounded_fold_arity",
    "sha256",
]
with summary_tsv.open("w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter="\t")
    writer.writeheader()
    writer.writerows(summary_rows)

lines = [
    "# Phase 24-26 STWO Folded-Interval Artifact Bundle",
    "",
    "This bundle freezes the carried-state relation progression from cumulative Phase 24 relation accumulation to honest Phase 25 intervalization and Phase 26 folded interval accumulation.",
    "",
    "| Phase | Artifact | Purpose | Prove (s) | Verify (s) | Size (bytes) | Total steps | Members | Fold arity |",
    "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
]
for row in summary_rows:
    lines.append(
        f"| {row['phase']} | `{row['artifact']}` | {row['purpose']} | {row['prove_seconds']} | {row['verify_seconds']} | {row['size_bytes']} | {row['total_steps']} | {row['member_count']} | {row['bounded_fold_arity']} |"
    )
lines.extend(
    [
        "",
        "The Phase 25 artifact is the first honest intervalized carried-state artifact in this sequence.",
        "The Phase 26 artifact folds real Phase 25 intervals rather than reusing the obsolete cumulative-prefix interpretation.",
        "",
        "See `artifact_summary.tsv` for the full machine-readable summary, `sha256sums.txt` for deterministic canonical artifact checksums, and `provenance_sha256sums.txt` for the full emitted bundle checksum set.",
        "",
    ]
)
index_md.write_text("\n".join(lines))
readme_md.write_text(
    "\n".join(
        [
            "# STWO Folded Interval Bundle",
            "",
            "Generated by `scripts/paper/generate_stwo_folded_interval_bundle.sh`.",
            "",
            "Files:",
            "- `manifest.txt`: bundle metadata and toolchain snapshot",
            "- `benchmarks.tsv`: prove/verify timings",
            "- `artifact_summary.tsv`: machine-readable artifact summary",
            "- `APPENDIX_ARTIFACT_INDEX.md`: paper-facing artifact index",
            "- `decoding-phase24.state-relation-accumulator.json.gz`: compressed Phase 24 artifact",
            "- `decoding-phase25.intervalized-state-relation.json.gz`: compressed Phase 25 artifact",
            "- `decoding-phase26.folded-intervalized-state-relation.json.gz`: compressed Phase 26 artifact",
            "- `sha256sums.txt`: deterministic canonical artifact checksums",
            "- `provenance_sha256sums.txt`: checksums for the full emitted bundle, including volatile provenance and timing files",
            "",
        ]
    )
)
PY

(cd "$BUNDLE_DIR" && shasum -a 256 "${CANONICAL_CHECKSUM_FILES[@]}" > "$SHA256S")
(cd "$BUNDLE_DIR" && shasum -a 256 "${PROVENANCE_CHECKSUM_FILES[@]}" > "$PROVENANCE_SHA256S")

echo "Generated folded interval artifact bundle at $BUNDLE_DIR"
