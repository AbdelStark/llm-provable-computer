#!/usr/bin/env bash
set -euo pipefail

export LANG=C
export LC_ALL=C
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

BUNDLE_DIR="${BUNDLE_DIR:-$REPO_ROOT/docs/paper/artifacts/stwo-proof-carrying-aggregation-v1-2026-04-11}"
NIGHTLY_TOOLCHAIN="${NIGHTLY_TOOLCHAIN:-+nightly-2025-07-14}"
BUILD_PROFILE="${BUILD_PROFILE:-debug}"
CARGO_BUILD_STWO=(cargo "$NIGHTLY_TOOLCHAIN" build --features stwo-backend --bin tvm)
if [ "$BUILD_PROFILE" = "release" ]; then
  CARGO_BUILD_STWO=(cargo "$NIGHTLY_TOOLCHAIN" build --release --features stwo-backend --bin tvm)
fi
TVM_BIN="$(
  BUILD_PROFILE="$BUILD_PROFILE" python3 - "$REPO_ROOT" <<'PY'
import os
import sys

repo_root = sys.argv[1]
target_dir = os.environ.get("CARGO_TARGET_DIR", os.path.join(repo_root, "target"))
if not os.path.isabs(target_dir):
    target_dir = os.path.join(repo_root, target_dir)
target = os.environ.get("CARGO_BUILD_TARGET") or os.environ.get("TARGET")
profile = os.environ.get("BUILD_PROFILE", "debug")
binary = "tvm.exe" if os.name == "nt" else "tvm"
parts = [target_dir]
if target:
    parts.append(target)
parts.extend([profile, binary])
print(os.path.realpath(os.path.join(*parts)))
PY
)"

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

relpath_from() {
  python3 - "$1" "$2" <<'PY'
import os
import sys

target = os.path.realpath(sys.argv[1])
base = os.path.realpath(sys.argv[2])
print(os.path.relpath(target, base))
PY
}

BUNDLE_DIR="$CANON_BUNDLE_DIR"
REL_BUNDLE_DIR="$(relpath_from "$BUNDLE_DIR" "$REPO_ROOT")"
REL_TVM_BIN="$(relpath_from "$TVM_BIN" "$REPO_ROOT")"
if [ -n "$(git status --porcelain --untracked-files=normal -- . ":(exclude)$REL_BUNDLE_DIR")" ]; then
  echo "Refusing to generate frozen bundle from a dirty worktree; commit or stash local changes first" >&2
  exit 1
fi
START_HEAD="$(git rev-parse HEAD)"
START_HEAD_SHORT="$(git rev-parse --short HEAD)"
START_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
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
  decoding-phase27.chained-folded-intervalized-state-relation.json.gz
  decoding-phase28.aggregated-chained-folded-intervalized-state-relation.json.gz
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
  decoding-phase27.chained-folded-intervalized-state-relation.json.gz
  decoding-phase28.aggregated-chained-folded-intervalized-state-relation.json.gz
)

: > "$COMMANDS_LOG"
printf 'label\tseconds\n' > "$BENCHMARKS"

run_logged() {
  local started_iso
  started_iso="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  {
    printf '[%s]' "$started_iso"
    printf ' %q' "$@"
    printf '\n'
  } | tee -a "$COMMANDS_LOG"
}

assert_generation_checkout_unchanged() {
  local current_head current_branch dirty_status
  current_head="$(git rev-parse HEAD)"
  current_branch="$(git rev-parse --abbrev-ref HEAD)"
  if [ "$current_head" != "$START_HEAD" ] || [ "$current_branch" != "$START_BRANCH" ]; then
    echo "Refusing to continue; checkout changed after manifest provenance was recorded" >&2
    echo "start:   $START_BRANCH $START_HEAD" >&2
    echo "current: $current_branch $current_head" >&2
    exit 1
  fi
  dirty_status="$(git status --porcelain --untracked-files=normal -- . ":(exclude)$REL_BUNDLE_DIR")"
  if [ -n "$dirty_status" ]; then
    echo "Refusing to continue from a dirty worktree; provenance may drift" >&2
    printf '%s\n' "$dirty_status" >&2
    exit 1
  fi
}

ensure_tvm_binary() {
  if [ ! -x "$TVM_BIN" ]; then
    assert_generation_checkout_unchanged
    echo "Expected tvm binary at $TVM_BIN was missing; rebuilding" >&2
    run_logged "${CARGO_BUILD_STWO[@]}"
    "${CARGO_BUILD_STWO[@]}"
  fi
  [ -x "$TVM_BIN" ] || {
    echo "Expected tvm binary at $TVM_BIN after build, but it was not found or is not executable" >&2
    exit 1
  }
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    echo "sha256sum or shasum is required" >&2
    exit 1
  fi
}

monotonic_ns() {
  python3 - <<'PY'
import time
print(time.monotonic_ns())
PY
}

elapsed_seconds() {
  python3 - "$1" "$2" <<'PY'
import sys

start = int(sys.argv[1])
end = int(sys.argv[2])
print(f"{(end - start) / 1_000_000_000:.6f}")
PY
}

run_timed() {
  local label="$1"
  shift
  local started_ns ended_ns elapsed
  assert_generation_checkout_unchanged
  if [ "${1:-}" = "$TVM_BIN" ]; then
    ensure_tvm_binary
  fi
  started_ns="$(monotonic_ns)"
  run_logged "$@"
  "$@"
  ended_ns="$(monotonic_ns)"
  elapsed="$(elapsed_seconds "$started_ns" "$ended_ns")"
  printf '%s\t%s\n' "$label" "$elapsed" >> "$BENCHMARKS"
}

cat > "$MANIFEST" <<MANIFEST
generated_at_utc: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
repo_root: .
git_commit: $START_HEAD
git_commit_short: $START_HEAD_SHORT
git_branch: $START_BRANCH
rustc: $(rustup run "${NIGHTLY_TOOLCHAIN#+}" rustc --version)
cargo: $(cargo "$NIGHTLY_TOOLCHAIN" --version)
host_platform: $(uname -srm)
nightly_toolchain: $NIGHTLY_TOOLCHAIN
bundle_dir: $REL_BUNDLE_DIR
fixtures: decoding_state_relation_accumulator_phase24, intervalized_decoding_state_relation_phase25, folded_intervalized_decoding_state_relation_phase26, chained_folded_intervalized_decoding_state_relation_phase27, aggregated_chained_folded_intervalized_decoding_state_relation_phase28
benchmark_binary: $REL_TVM_BIN
MANIFEST

assert_generation_checkout_unchanged
run_logged "${CARGO_BUILD_STWO[@]}"
"${CARGO_BUILD_STWO[@]}"
ensure_tvm_binary

run_timed prove_decoding_state_relation_accumulator_phase24_stwo \
  "$TVM_BIN" \
  prove-stwo-decoding-state-relation-accumulator-demo \
  -o "$BUNDLE_DIR/decoding-phase24.state-relation-accumulator.json"

run_timed verify_decoding_state_relation_accumulator_phase24_stwo \
  "$TVM_BIN" \
  verify-stwo-decoding-state-relation-accumulator-demo \
  "$BUNDLE_DIR/decoding-phase24.state-relation-accumulator.json"

run_timed prove_intervalized_decoding_state_relation_phase25_stwo \
  "$TVM_BIN" \
  prove-stwo-intervalized-decoding-state-relation-demo \
  -o "$BUNDLE_DIR/decoding-phase25.intervalized-state-relation.json"

run_timed verify_intervalized_decoding_state_relation_phase25_stwo \
  "$TVM_BIN" \
  verify-stwo-intervalized-decoding-state-relation-demo \
  "$BUNDLE_DIR/decoding-phase25.intervalized-state-relation.json"

run_timed prove_folded_intervalized_decoding_state_relation_phase26_stwo \
  "$TVM_BIN" \
  prove-stwo-folded-intervalized-decoding-state-relation-demo \
  -o "$BUNDLE_DIR/decoding-phase26.folded-intervalized-state-relation.json"

run_timed verify_folded_intervalized_decoding_state_relation_phase26_stwo \
  "$TVM_BIN" \
  verify-stwo-folded-intervalized-decoding-state-relation-demo \
  "$BUNDLE_DIR/decoding-phase26.folded-intervalized-state-relation.json"

run_timed prove_chained_folded_intervalized_decoding_state_relation_phase27_stwo \
  "$TVM_BIN" \
  prove-stwo-chained-folded-intervalized-decoding-state-relation-demo \
  -o "$BUNDLE_DIR/decoding-phase27.chained-folded-intervalized-state-relation.json"

run_timed verify_chained_folded_intervalized_decoding_state_relation_phase27_stwo \
  "$TVM_BIN" \
  verify-stwo-chained-folded-intervalized-decoding-state-relation-demo \
  "$BUNDLE_DIR/decoding-phase27.chained-folded-intervalized-state-relation.json"

run_timed prove_aggregated_chained_folded_intervalized_decoding_state_relation_phase28_stwo \
  "$TVM_BIN" \
  prove-stwo-aggregated-chained-folded-intervalized-decoding-state-relation-demo \
  -o "$BUNDLE_DIR/decoding-phase28.aggregated-chained-folded-intervalized-state-relation.json"

run_timed verify_aggregated_chained_folded_intervalized_decoding_state_relation_phase28_stwo \
  "$TVM_BIN" \
  verify-stwo-aggregated-chained-folded-intervalized-decoding-state-relation-demo \
  "$BUNDLE_DIR/decoding-phase28.aggregated-chained-folded-intervalized-state-relation.json"

for artifact in \
  "$BUNDLE_DIR/decoding-phase24.state-relation-accumulator.json" \
  "$BUNDLE_DIR/decoding-phase25.intervalized-state-relation.json" \
  "$BUNDLE_DIR/decoding-phase26.folded-intervalized-state-relation.json" \
  "$BUNDLE_DIR/decoding-phase27.chained-folded-intervalized-state-relation.json" \
  "$BUNDLE_DIR/decoding-phase28.aggregated-chained-folded-intervalized-state-relation.json"
do
  gzip -n -9 -c "$artifact" > "$artifact.gz"
  rm -f "$artifact"
done

run_timed verify_decoding_state_relation_accumulator_phase24_stwo_gzip \
  "$TVM_BIN" \
  verify-stwo-decoding-state-relation-accumulator-demo \
  "$BUNDLE_DIR/decoding-phase24.state-relation-accumulator.json.gz"

run_timed verify_intervalized_decoding_state_relation_phase25_stwo_gzip \
  "$TVM_BIN" \
  verify-stwo-intervalized-decoding-state-relation-demo \
  "$BUNDLE_DIR/decoding-phase25.intervalized-state-relation.json.gz"

run_timed verify_folded_intervalized_decoding_state_relation_phase26_stwo_gzip \
  "$TVM_BIN" \
  verify-stwo-folded-intervalized-decoding-state-relation-demo \
  "$BUNDLE_DIR/decoding-phase26.folded-intervalized-state-relation.json.gz"

run_timed verify_chained_folded_intervalized_decoding_state_relation_phase27_stwo_gzip \
  "$TVM_BIN" \
  verify-stwo-chained-folded-intervalized-decoding-state-relation-demo \
  "$BUNDLE_DIR/decoding-phase27.chained-folded-intervalized-state-relation.json.gz"

run_timed verify_aggregated_chained_folded_intervalized_decoding_state_relation_phase28_stwo_gzip \
  "$TVM_BIN" \
  verify-stwo-aggregated-chained-folded-intervalized-decoding-state-relation-demo \
  "$BUNDLE_DIR/decoding-phase28.aggregated-chained-folded-intervalized-state-relation.json.gz"

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
        "verify_decoding_state_relation_accumulator_phase24_stwo_gzip",
        "accumulator_version",
        "stwo-phase24-decoding-state-relation-accumulator-v1",
        "stwo_execution_parameterized_proof_carrying_decoding_state_relation_accumulator",
    ),
    (
        "decoding-phase25.intervalized-state-relation.json.gz",
        "Phase 25",
        "Intervalized carried-state relation artifact over rebased cumulative prefixes",
        "honest intervalization over real carried-state intervals",
        "prove_intervalized_decoding_state_relation_phase25_stwo",
        "verify_intervalized_decoding_state_relation_phase25_stwo_gzip",
        "artifact_version",
        "stwo-phase25-intervalized-decoding-state-relation-v1",
        "stwo_execution_parameterized_intervalized_proof_carrying_decoding_state_relation",
    ),
    (
        "decoding-phase26.folded-intervalized-state-relation.json.gz",
        "Phase 26",
        "Folded accumulator over Phase 25 interval artifacts",
        "bounded pre-recursive folding over carried-state intervals",
        "prove_folded_intervalized_decoding_state_relation_phase26_stwo",
        "verify_folded_intervalized_decoding_state_relation_phase26_stwo_gzip",
        "artifact_version",
        "stwo-phase26-folded-intervalized-decoding-state-relation-v1",
        "stwo_execution_parameterized_folded_intervalized_proof_carrying_decoding_state_relation",
    ),
    (
        "decoding-phase27.chained-folded-intervalized-state-relation.json.gz",
        "Phase 27",
        "Chained fold-of-folds accumulator over Phase 26 artifacts",
        "bounded pre-recursive chained folding over real carried-state intervals",
        "prove_chained_folded_intervalized_decoding_state_relation_phase27_stwo",
        "verify_chained_folded_intervalized_decoding_state_relation_phase27_stwo_gzip",
        "artifact_version",
        "stwo-phase27-chained-folded-intervalized-decoding-state-relation-v1",
        "stwo_execution_parameterized_chained_folded_intervalized_proof_carrying_decoding_state_relation",
    ),
    (
        "decoding-phase28.aggregated-chained-folded-intervalized-state-relation.json.gz",
        "Phase 28",
        "Proof-carrying outer aggregation over Phase 27 chained artifacts",
        "bounded pre-recursive cross-bundle aggregation over real carried-state intervals",
        "prove_aggregated_chained_folded_intervalized_decoding_state_relation_phase28_stwo",
        "verify_aggregated_chained_folded_intervalized_decoding_state_relation_phase28_stwo_gzip",
        "artifact_version",
        "stwo-phase28-aggregated-chained-folded-intervalized-decoding-state-relation-v1",
        "stwo_execution_parameterized_aggregated_chained_folded_intervalized_proof_carrying_decoding_state_relation",
    ),
]

def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def load_json(path: Path):
    with gzip.open(path, "rt") as f:
        return json.load(f)

def validate_contract(name, data, version_field, expected_version, expected_scope):
    if data.get("proof_backend") != "stwo":
        raise SystemExit(
            f"{name}: expected proof_backend=stwo, got {data.get('proof_backend')!r}"
        )
    if data.get(version_field) != expected_version:
        raise SystemExit(
            f"{name}: expected {version_field}={expected_version!r}, got {data.get(version_field)!r}"
        )
    if data.get("semantic_scope") != expected_scope:
        raise SystemExit(
            f"{name}: expected semantic_scope={expected_scope!r}, got {data.get('semantic_scope')!r}"
        )
    if data.get("statement_version") != "statement-v1":
        raise SystemExit(
            f"{name}: expected statement_version='statement-v1', got {data.get('statement_version')!r}"
        )

def extract_stats(data):
    return {
        "member_count": len(data["members"]) if isinstance(data.get("members"), list) else "",
        "total_phase26_members": data.get("total_phase26_members", ""),
        "total_phase25_members": data.get("total_phase25_members", ""),
        "max_nested_chain_arity": data.get("max_nested_chain_arity", ""),
        "max_nested_fold_arity": data.get("max_nested_fold_arity", ""),
        "bounded_fold_arity": data.get("bounded_fold_arity", ""),
        "bounded_chain_arity": data.get("bounded_chain_arity", ""),
        "bounded_aggregation_arity": data.get("bounded_aggregation_arity", ""),
        "total_steps": data.get("total_steps", ""),
        "total_layouts": data.get("total_layouts", ""),
        "total_rollups": data.get("total_rollups", ""),
        "total_segments": data.get("total_segments", ""),
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

def require_benchmark(label: str) -> str:
    try:
        return benchmarks[label]
    except KeyError as exc:
        raise SystemExit(f"missing benchmark label `{label}` in benchmarks.tsv") from exc

summary_rows = []
for (
    name,
    phase,
    purpose,
    scope,
    prove_label,
    verify_label,
    version_field,
    expected_version,
    expected_scope,
) in artifacts:
    path = bundle / name
    data = load_json(path)
    validate_contract(name, data, version_field, expected_version, expected_scope)
    stats = extract_stats(data)
    summary_rows.append({
        "artifact": name,
        "phase": phase,
        "purpose": purpose,
        "scope": scope,
        "size_bytes": path.stat().st_size,
        "prove_seconds": require_benchmark(prove_label),
        "verify_seconds": require_benchmark(verify_label),
        **stats,
        "sha256": sha256(path),
    })

with summary_tsv.open("w", newline="") as f:
    fieldnames = list(summary_rows[0].keys())
    writer = csv.DictWriter(f, fieldnames=fieldnames, delimiter="\t", lineterminator="\n")
    writer.writeheader()
    writer.writerows(summary_rows)

index_lines = [
    "# Appendix Artifact Index",
    "",
    "| Artifact | Phase | Purpose | Size (bytes) | SHA-256 |",
    "| --- | --- | --- | ---: | --- |",
]
for row in summary_rows:
    index_lines.append(
        f"| `{row['artifact']}` | {row['phase']} | {row['purpose']} | {row['size_bytes']} | `{row['sha256']}` |"
    )
index_md.write_text("\n".join(index_lines) + "\n")

readme_lines = [
    "# STWO Proof-Carrying Aggregation Bundle",
    "",
    "This bundle freezes the Phase 24 -> Phase 28 carried-state artifact ladder, including the first cross-bundle proof-carrying aggregation layer.",
    "",
    "Included artifacts:",
]
for row in summary_rows:
    readme_lines.append(
        f"- `{row['artifact']}`: {row['purpose']} ({row['scope']})"
    )
readme_lines.append("")
readme_lines.append("See `APPENDIX_ARTIFACT_INDEX.md` and `artifact_summary.tsv` for details.")
readme_md.write_text("\n".join(readme_lines) + "\n")
PY

(
  cd "$BUNDLE_DIR"
  for checksum_file in "${CANONICAL_CHECKSUM_FILES[@]}"; do
    printf '%s  %s\n' "$(sha256_file "$checksum_file")" "$checksum_file"
  done > "$SHA256S"
  for checksum_file in "${PROVENANCE_CHECKSUM_FILES[@]}"; do
    printf '%s  %s\n' "$(sha256_file "$checksum_file")" "$checksum_file"
  done > "$PROVENANCE_SHA256S"
)

echo "Bundle written to $BUNDLE_DIR"
