#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SCRIPT_PATH="$SCRIPT_DIR/$(basename "${BASH_SOURCE[0]}")"
cd "$ROOT_DIR"

REPO="${MERGE_GATE_REPO:-$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null || true)}"
PR_NUMBER="${MERGE_GATE_PR:-}"
QUIET_SECONDS="${MERGE_GATE_QUIET_SECONDS:-300}"
MAX_WAIT_SECONDS="${MERGE_GATE_MAX_WAIT_SECONDS:-1800}"
WAIT_STARTED_AT="${MERGE_GATE_WAIT_STARTED_AT:-}"
EVIDENCE_DIR="${MERGE_GATE_EVIDENCE_DIR:-target/local-hardening}"
LOG_DIR=""
MERGE=0
WAIT=0
RUN_LOCAL=1
RUN_MODE="${MERGE_GATE_RUN_MODE:-smoke}"
MERGE_METHOD="${MERGE_GATE_METHOD:-merge}"
DELETE_BRANCH=1

usage() {
  cat <<'EOF'
Usage: scripts/local_merge_gate.sh [options] [PR_NUMBER]

Local-first merge gate for trusted-core PRs.

Options:
  --repo OWNER/REPO       GitHub repository. Defaults to gh repo view.
  --pr NUMBER            Pull request number. Can also be positional.
  --mode smoke|full|hardening|none
                          Local command tier. Default: smoke.
  --quiet-seconds N      AI-review quiet window. Default: 300.
  --max-wait-seconds N   Maximum total --wait wall time. Default: 1800; 0 disables.
  --evidence-dir DIR     Evidence output directory. Default: target/local-hardening.
  --wait                 Wait until the quiet window is satisfied.
  --merge                Merge after all gates pass.
  --method merge|squash|rebase
                          Merge method to pass to gh pr merge. Default: merge.
  --keep-branch          Do not delete the remote PR branch after merge.
  --skip-local           Do not run local commands; only verify existing gate state.
  -h, --help             Show this help.

Environment:
  MERGE_GATE_REPO, MERGE_GATE_PR, MERGE_GATE_QUIET_SECONDS,
  MERGE_GATE_MAX_WAIT_SECONDS, MERGE_GATE_WAIT_STARTED_AT,
  MERGE_GATE_EVIDENCE_DIR, MERGE_GATE_RUN_MODE, MERGE_GATE_METHOD.
EOF
}

log() {
  printf '[merge-gate] %s\n' "$*" >&2
}

fail() {
  printf '[merge-gate] ERROR: %s\n' "$*" >&2
  exit 1
}

# shellcheck source=scripts/hardening_test_names.sh
source "$ROOT_DIR/scripts/hardening_test_names.sh"
declare -p hardening_tvm_bin_test_filters >/dev/null 2>&1 ||
  fail "scripts/hardening_test_names.sh must define hardening_tvm_bin_test_filters"
declare -p hardening_tvm_bin_cargo_args >/dev/null 2>&1 ||
  fail "scripts/hardening_test_names.sh must define hardening_tvm_bin_cargo_args"

sleep_with_wait_budget() {
  local duration="$1"
  local reason="$2"
  local now elapsed budget

  [[ -n "$WAIT_STARTED_AT" ]] || fail "WAIT_STARTED_AT is not initialized"
  now="$(date -u +%s)"
  elapsed=$((now - WAIT_STARTED_AT))
  budget="$MAX_WAIT_SECONDS"

  if (( budget > 0 && elapsed + duration > budget )); then
    fail "${reason}; wait budget would be exceeded (${elapsed}s elapsed, ${budget}s max)"
  fi

  if (( budget > 0 )); then
    log "${reason}; sleeping ${duration}s (${elapsed}/${budget}s wait budget elapsed)"
  else
    log "${reason}; sleeping ${duration}s (unbounded wait budget)"
  fi
  sleep "$duration"
}

retry_gate_mode_none() {
  retry_args=("$SCRIPT_PATH" --repo "$REPO" --pr "$PR_NUMBER" --mode none --quiet-seconds "$QUIET_SECONDS" --max-wait-seconds "$MAX_WAIT_SECONDS" --evidence-dir "$EVIDENCE_DIR" --wait --method "$MERGE_METHOD")
  if (( MERGE )); then
    retry_args+=(--merge)
  fi
  if (( DELETE_BRANCH == 0 )); then
    retry_args+=(--keep-branch)
  fi
  export MERGE_GATE_WAIT_STARTED_AT="$WAIT_STARTED_AT"
  rm -f "${tmp_pr_json:-}"
  exec "${retry_args[@]}"
}

check_graphql_response() {
  local response_file="$1"
  if ! jq -e . "$response_file" >/dev/null 2>&1; then
    cat "$response_file" >&2 || true
    fail "GitHub GraphQL returned invalid JSON"
  fi
  if jq -e '(.errors // []) | length > 0' "$response_file" >/dev/null; then
    jq -r '.errors[]?.message' "$response_file" >&2
    fail "GitHub GraphQL query failed"
  fi
  if ! jq -e '.data.repository.pullRequest' "$response_file" >/dev/null; then
    cat "$response_file" >&2 || true
    fail "GitHub GraphQL response did not include pullRequest data"
  fi
}

fetch_paginated_connection() {
  local connection="$1"
  local query_text="$2"
  local jq_nodes_filter="$3"
  local output_file="$4"
  local cursor=""
  local page response_file nodes_file merged_file

  printf '[]\n' >"$output_file"
  page=0
  while :; do
    page=$((page + 1))
    response_file="$run_evidence_dir/${connection}-page-${page}.json"
    nodes_file="$run_evidence_dir/${connection}-nodes-${page}.json"
    merged_file="$run_evidence_dir/${connection}-merged-${page}.json"

    graph_args=(gh api graphql -f query="$query_text" -F owner="$owner" -F name="$name" -F number="$PR_NUMBER")
    if [[ -n "$cursor" ]]; then
      graph_args+=(-F cursor="$cursor")
    fi
    "${graph_args[@]}" >"$response_file"
    check_graphql_response "$response_file"

    jq "$jq_nodes_filter" "$response_file" >"$nodes_file"
    jq -s '.[0] + .[1]' "$output_file" "$nodes_file" >"$merged_file"
    mv "$merged_file" "$output_file"

    if [[ "$(jq -r ".data.repository.pullRequest.${connection}.pageInfo.hasNextPage" "$response_file")" != "true" ]]; then
      break
    fi
    cursor="$(jq -r ".data.repository.pullRequest.${connection}.pageInfo.endCursor // empty" "$response_file")"
    [[ -n "$cursor" ]] || fail "GitHub GraphQL ${connection} pageInfo omitted endCursor"
  done
}

run_logged() {
  local name="$1"
  shift
  [[ -n "$LOG_DIR" ]] || fail "LOG_DIR is not initialized"
  local log_file="$LOG_DIR/${name}.log"
  local start end status
  start="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  log "running ${name}: $*"
  set +e
  "$@" >"$log_file" 2>&1
  status=$?
  set -e
  end="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local hash
  if command -v shasum >/dev/null 2>&1; then
    hash="$(shasum -a 256 "$log_file" | awk '{print $1}')"
  elif command -v sha256sum >/dev/null 2>&1; then
    hash="$(sha256sum "$log_file" | awk '{print $1}')"
  else
    fail "shasum or sha256sum is required"
  fi
  jq -n \
    --arg name "$name" \
    --arg start "$start" \
    --arg end "$end" \
    --arg command "$*" \
    --arg log_file "$log_file" \
    --arg log_sha256 "$hash" \
    --argjson exit_code "$status" \
    '{name:$name,start:$start,end:$end,command:$command,exit_code:$exit_code,log_file:$log_file,log_sha256:$log_sha256}' \
    >"$LOG_DIR/${name}.json"
  if (( status != 0 )); then
    tail -n 80 "$log_file" >&2 || true
    fail "local command failed: ${name} (exit ${status}); see ${log_file}"
  fi
}

resolve_tvm_test_binary_path() {
  local manifest_dir target_dir binary_name target_triple resolved_path
  manifest_dir="$ROOT_DIR"
  target_dir="${CARGO_TARGET_DIR:-$manifest_dir/target}"
  if [[ "$target_dir" != /* ]]; then
    target_dir="$manifest_dir/$target_dir"
  fi
  binary_name="tvm"
  if [[ "${OS:-}" == "Windows_NT" ]]; then
    binary_name="${binary_name}.exe"
  fi
  target_triple="${CARGO_BUILD_TARGET:-}"
  if [[ -n "$target_triple" ]]; then
    resolved_path="$target_dir/$target_triple/debug/$binary_name"
  else
    resolved_path="$target_dir/debug/$binary_name"
  fi
  [[ -f "$resolved_path" ]] || fail "expected built tvm binary at $resolved_path after cargo build (CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-}, CARGO_BUILD_TARGET=${CARGO_BUILD_TARGET:-})"
  printf '%s\n' "$resolved_path"
}

while (($#)); do
  case "$1" in
    --repo)
      REPO="${2:-}"
      shift 2
      ;;
    --repo=*)
      REPO="${1#*=}"
      shift
      ;;
    --pr)
      PR_NUMBER="${2:-}"
      shift 2
      ;;
    --pr=*)
      PR_NUMBER="${1#*=}"
      shift
      ;;
    --mode)
      RUN_MODE="${2:-}"
      shift 2
      ;;
    --mode=*)
      RUN_MODE="${1#*=}"
      shift
      ;;
    --quiet-seconds)
      QUIET_SECONDS="${2:-}"
      shift 2
      ;;
    --quiet-seconds=*)
      QUIET_SECONDS="${1#*=}"
      shift
      ;;
    --max-wait-seconds)
      MAX_WAIT_SECONDS="${2:-}"
      shift 2
      ;;
    --max-wait-seconds=*)
      MAX_WAIT_SECONDS="${1#*=}"
      shift
      ;;
    --evidence-dir)
      EVIDENCE_DIR="${2:-}"
      shift 2
      ;;
    --evidence-dir=*)
      EVIDENCE_DIR="${1#*=}"
      shift
      ;;
    --wait)
      WAIT=1
      shift
      ;;
    --merge)
      MERGE=1
      shift
      ;;
    --method)
      MERGE_METHOD="${2:-}"
      shift 2
      ;;
    --method=*)
      MERGE_METHOD="${1#*=}"
      shift
      ;;
    --keep-branch)
      DELETE_BRANCH=0
      shift
      ;;
    --skip-local)
      RUN_LOCAL=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --*)
      fail "unknown option: $1"
      ;;
    *)
      if [[ -n "$PR_NUMBER" ]]; then
        fail "unexpected positional argument: $1"
      fi
      PR_NUMBER="$1"
      shift
      ;;
  esac
done

[[ -n "$REPO" ]] || fail "repository is required; pass --repo OWNER/REPO or run inside a gh-known checkout"
[[ "$PR_NUMBER" =~ ^[0-9]+$ ]] || fail "PR number is required"
[[ "$QUIET_SECONDS" =~ ^[0-9]+$ ]] || fail "quiet seconds must be a non-negative integer"
[[ "$MAX_WAIT_SECONDS" =~ ^[0-9]+$ ]] || fail "max wait seconds must be a non-negative integer"
if (( WAIT )); then
  if [[ -z "$WAIT_STARTED_AT" ]]; then
    WAIT_STARTED_AT="$(date -u +%s)"
  fi
  [[ "$WAIT_STARTED_AT" =~ ^[0-9]+$ ]] || fail "wait started timestamp must be a Unix epoch"
  export MERGE_GATE_WAIT_STARTED_AT
fi
case "$RUN_MODE" in
  smoke|full|hardening|none) ;;
  *) fail "unsupported --mode: $RUN_MODE" ;;
esac
case "$MERGE_METHOD" in
  merge|squash|rebase) ;;
  *) fail "unsupported --method: $MERGE_METHOD" ;;
esac

if ! command -v gh >/dev/null 2>&1; then
  fail "gh is required"
fi
if ! command -v jq >/dev/null 2>&1; then
  fail "jq is required"
fi

tmp_pr_json="$(mktemp)"
trap 'rm -f "$tmp_pr_json"' EXIT
gh pr view "$PR_NUMBER" --repo "$REPO" \
  --json url,state,isDraft,mergeable,reviewDecision,headRefOid,baseRefOid,headRefName,baseRefName,createdAt \
  >"$tmp_pr_json"

state="$(jq -r '.state' "$tmp_pr_json")"
is_draft="$(jq -r '.isDraft' "$tmp_pr_json")"
mergeable="$(jq -r '.mergeable' "$tmp_pr_json")"
head_sha="$(jq -r '.headRefOid' "$tmp_pr_json")"
base_sha="$(jq -r '.baseRefOid' "$tmp_pr_json")"
base_ref_name="$(jq -r '.baseRefName' "$tmp_pr_json")"
pr_url="$(jq -r '.url' "$tmp_pr_json")"

[[ "$state" == "OPEN" ]] || fail "PR is not open: $state"
[[ "$is_draft" == "false" ]] || fail "PR is draft"
[[ "$mergeable" == "MERGEABLE" ]] || fail "PR is not mergeable: $mergeable"

current_head="$(git rev-parse HEAD)"
if [[ "$current_head" != "$head_sha" ]]; then
  fail "local HEAD $current_head does not match PR head $head_sha; checkout the PR head before running local evidence"
fi

dirty_status="$(git status --porcelain)"
if [[ -n "$dirty_status" ]]; then
  printf '%s\n' "$dirty_status" >&2
  fail "worktree has uncommitted changes; local evidence must be tied to the exact PR head"
fi

if ! git cat-file -e "${base_sha}^{commit}" 2>/dev/null; then
  log "base commit ${base_sha} is missing locally; fetching origin/${base_ref_name}"
  if [[ "$(git rev-parse --is-shallow-repository)" == "true" ]]; then
    git fetch --unshallow origin "$base_ref_name" || git fetch origin "$base_ref_name"
  else
    git fetch origin "$base_ref_name"
  fi
fi
git cat-file -e "${base_sha}^{commit}" 2>/dev/null || fail "base commit ${base_sha} is unavailable locally"

run_evidence_dir="$EVIDENCE_DIR/pr-${PR_NUMBER}-${head_sha}"
LOG_DIR="$run_evidence_dir/logs"
mkdir -p "$LOG_DIR"
pr_json="$run_evidence_dir/pr.json"
cp "$tmp_pr_json" "$pr_json"
diff_range="${base_sha}...${head_sha}"
mapfile -t changed_paths < <(git diff --name-only "$diff_range")
local_evidence_marker="$run_evidence_dir/local-evidence.json"
completed_local_mode=""
stwo_smoke_targets=(
  "stwo_backend::decoding::tests::phase28_aggregated_chained_folded_intervalized_state_relation_rejects_header_mismatch_before_nested_checks"
  "stwo_backend::decoding::tests::load_phase30_decoding_step_proof_envelope_manifest_reports_malformed_json_as_invalid_config"
  "stwo_backend::decoding::tests::phase30_step_envelope_manifest_rejects_tampered_start_boundary"
  "stwo_backend::decoding::tests::phase30_step_envelope_manifest_rejects_tampered_end_boundary"
  "stwo_backend::decoding::tests::phase30_step_envelope_manifest_rejects_step_envelope_list_commitment_drift"
  "stwo_backend::decoding::tests::phase30_step_envelope_manifest_rejects_step_index_drift"
  "stwo_backend::recursion::tests::phase29_recursive_compression_input_contract_rejects_tampered_commitment"
)
onnx_smoke_targets=(
  "onnx_export::tests::load_onnx_program_metadata_rejects_wrong_format_version"
  "onnx_export::tests::load_onnx_program_metadata_rejects_input_contract_drift"
  "onnx_export::tests::load_onnx_program_metadata_rejects_output_contract_drift"
  "onnx_export::tests::load_onnx_program_metadata_rejects_instruction_table_instruction_drift"
  "onnx_export::tests::load_onnx_program_metadata_rejects_model_path_escape"
  "onnx_export::tests::load_onnx_program_metadata_rejects_unknown_top_level_field"
  "onnx_export::tests::load_onnx_program_metadata_rejects_unknown_nested_config_field"
  "onnx_export::tests::load_onnx_program_metadata_rejects_unknown_nested_program_field"
  "onnx_export::tests::load_onnx_program_metadata_rejects_unknown_nested_memory_read_field"
  "onnx_export::tests::load_onnx_program_metadata_rejects_unknown_direct_memory_read_field"
  "onnx_export::tests::load_onnx_program_metadata_rejects_missing_direct_memory_read_address"
  "onnx_export::tests::load_onnx_program_metadata_maps_runtime_conversion_failures_to_serialization"
)
tvm_bin_smoke_targets=("${hardening_tvm_bin_test_filters[@]}")
research_v3_smoke_targets=(
  "tests::research_v3_rule_witnesses_rejects_event_length_mismatch"
  "tests::load_research_v3_equivalence_artifact_rejects_unknown_top_level_field"
  "tests::load_research_v3_equivalence_artifact_rejects_unknown_nested_rule_witness_field"
  "tests::load_research_v3_equivalence_artifact_rejects_oversized_file"
  "tests::load_research_v3_equivalence_artifact_reports_malformed_json_as_serialization"
  "tests::load_research_v3_equivalence_artifact_rejects_non_regular_file"
  "tests::verify_research_v3_equivalence_artifact_rejects_unknown_engine_binding"
  "tests::verify_research_v3_equivalence_artifact_rejects_missing_pinned_engine"
  "tests::verify_research_v3_equivalence_artifact_rejects_extra_engine_events_beyond_checked_steps"
)
stwo_cli_smoke_targets=(
  "cli_can_verify_stwo_recursive_compression_input_contract"
  "cli_verify_stwo_recursive_compression_input_contract_rejects_tampered_commitment"
  "cli_verify_stwo_recursive_compression_input_contract_rejects_recomputed_header_drift"
  "cli_prepare_stwo_recursive_compression_input_contract_rejects_synthetic_phase28_shell"
  "cli_prepare_stwo_recursive_compression_input_contract_rejects_gzip_output_path"
)
mapfile -t mutation_targets < <(bash scripts/run_mutation_suite.sh --print-targets)

changed_path_has_prefix() {
  local prefix="$1"
  local path
  for path in "${changed_paths[@]}"; do
    if [[ "$path" == "$prefix"* ]]; then
      return 0
    fi
  done
  return 1
}

changed_path_is_shell_script() {
  local path
  for path in "${changed_paths[@]}"; do
    if [[ "$path" =~ ^scripts/.+\.sh$ ]]; then
      return 0
    fi
  done
  return 1
}

changed_path_is_onnx_surface() {
  changed_path_has_prefix "src/onnx_" ||
    changed_path_has_prefix "src/config.rs" ||
    changed_path_has_prefix "src/instruction.rs" ||
    changed_path_has_prefix "src/model.rs" ||
    changed_path_has_prefix "tests/onnx_export.rs" ||
    changed_path_has_prefix "spec/onnx"
}

changed_path_is_research_v3_surface() {
  changed_path_has_prefix "src/bin/tvm.rs" ||
    changed_path_has_prefix "tests/cli.rs" ||
    changed_path_has_prefix "spec/statement-v3-equivalence-kernel" ||
    changed_path_has_prefix "spec/frontend-runtime-semantics-registry-v1.json" ||
    changed_path_has_prefix "spec/fixed-point-semantics-v2.json" ||
    changed_path_has_prefix "spec/onnx-op-subset-v2.json" ||
    changed_path_has_prefix "scripts/local_merge_gate.sh" ||
    changed_path_has_prefix "scripts/hardening_test_names.sh" ||
    changed_path_has_prefix "scripts/run_ub_checks_suite.sh"
}

changed_path_is_dependency_audit_input() {
  local path

  if changed_path_has_prefix "vendor/onnx-protobuf/"; then
    return 0
  fi

  for path in "${changed_paths[@]}"; do
    case "$path" in
      Cargo.toml|Cargo.lock|deny.toml|fuzz/Cargo.toml|fuzz/Cargo.lock|scripts/run_dependency_audit_suite.sh)
        return 0
        ;;
    esac
  done

  return 1
}

changed_path_is_mutation_target() {
  local path target
  for path in "${changed_paths[@]}"; do
    for target in "${mutation_targets[@]}"; do
      if [[ "$path" == "$target" ]]; then
        return 0
      fi
    done
  done
  return 1
}

run_stwo_smoke_targets() {
  local stwo_smoke label
  for stwo_smoke in "${stwo_smoke_targets[@]}"; do
    label="${stwo_smoke##*::}"
    run_logged "stwo-backend-smoke-${label}" cargo +nightly-2025-07-14 test -q \
      --features stwo-backend \
      --lib "$stwo_smoke" \
      -- \
      --exact
  done
}

run_onnx_smoke_targets() {
  local onnx_smoke label
  for onnx_smoke in "${onnx_smoke_targets[@]}"; do
    label="${onnx_smoke##*::}"
    run_logged "onnx-smoke-${label}" cargo test -q \
      --features onnx-export \
      --lib "$onnx_smoke" \
      -- \
      --exact
  done
}

run_tvm_bin_smoke_targets() {
  local tvm_bin_smoke label
  for tvm_bin_smoke in "${tvm_bin_smoke_targets[@]}"; do
    label="${tvm_bin_smoke##*::}"
    run_logged "tvm-bin-smoke-${label}" cargo test -q \
      "${hardening_tvm_bin_cargo_args[@]}" "$tvm_bin_smoke" \
      -- \
      --exact
  done
}

run_stwo_cli_smoke_targets() {
  local stwo_cli_smoke
  local tvm_test_binary
  run_logged stwo-backend-cli-build cargo +nightly-2025-07-14 build -q \
    --features stwo-backend \
    --bin tvm
  tvm_test_binary="$(resolve_tvm_test_binary_path)"
  for stwo_cli_smoke in "${stwo_cli_smoke_targets[@]}"; do
    run_logged "stwo-backend-cli-smoke-${stwo_cli_smoke}" env TVM_TEST_BINARY="$tvm_test_binary" cargo +nightly-2025-07-14 test -q \
      --features stwo-backend \
      --test cli "$stwo_cli_smoke" \
      -- \
      --exact
  done
}

run_research_v3_smoke_targets() {
  local research_v3_smoke label
  for research_v3_smoke in "${research_v3_smoke_targets[@]}"; do
    label="${research_v3_smoke##*::}"
    run_logged "research-v3-smoke-${label}" cargo test -q \
      --features burn-model,onnx-export \
      --bin tvm "$research_v3_smoke" \
      -- \
      --exact
  done

}

run_research_v3_cli_smoke_target() {
  local tvm_test_binary
  run_logged research-v3-equivalence-cli-build cargo build -q \
    --features full \
    --bin tvm
  tvm_test_binary="$(resolve_tvm_test_binary_path)"
  run_logged research-v3-equivalence-cli env TVM_TEST_BINARY="$tvm_test_binary" cargo test -q \
    --features full \
    --test cli cli_supports_research_v3_equivalence_command \
    -- \
    --exact
}

run_conditional_quick_audits() {
  if changed_path_has_prefix ".github/workflows/" || changed_path_has_prefix "zizmor.yml"; then
    run_logged workflow-audit bash scripts/run_workflow_audit_suite.sh
  fi

  if changed_path_is_shell_script; then
    run_logged shellcheck bash scripts/run_shellcheck_suite.sh
  fi

  if changed_path_is_dependency_audit_input; then
    run_logged dependency-audit bash scripts/run_dependency_audit_suite.sh
  fi
}

run_conditional_mutation_check() {
  local mutation_diff_file
  local git_diff_status

  if ! changed_path_is_mutation_target; then
    return 0
  fi

  mutation_diff_file="$run_evidence_dir/mutation.diff"
  set +e
  git diff --no-ext-diff --unified=0 "$diff_range" -- "${mutation_targets[@]}" >"$mutation_diff_file"
  git_diff_status=$?
  set -e

  if (( git_diff_status > 1 )); then
    fail "git diff failed while building ${mutation_diff_file}"
  fi

  if [[ -s "$mutation_diff_file" ]]; then
    run_logged mutation env MUTATION_DIFF_FILE="$mutation_diff_file" scripts/run_mutation_suite.sh
  else
    fail "mutation target changed but ${mutation_diff_file} is empty"
  fi
}

if (( RUN_LOCAL )) && [[ "$RUN_MODE" == "smoke" ]]; then
  run_logged git-diff-check git diff --check "$diff_range"
  run_logged cargo-fmt-check cargo fmt --check
  run_conditional_quick_audits
  run_logged lib-contract cargo test -q --lib statement_spec_contract_is_synced_with_constants
  smoke_targets=(assembly e2e interpreter runtime vanillastark_smoke)
  for test_target in "${smoke_targets[@]}"; do
    run_logged "integration-${test_target}" cargo test -q --test "$test_target"
  done
  if changed_path_is_onnx_surface; then
    run_onnx_smoke_targets
  fi
  if changed_path_is_research_v3_surface; then
    run_tvm_bin_smoke_targets
    run_research_v3_smoke_targets
    run_research_v3_cli_smoke_target
  fi
  run_stwo_smoke_targets
  run_stwo_cli_smoke_targets
  completed_local_mode="$RUN_MODE"
elif (( RUN_LOCAL )) && [[ "$RUN_MODE" == "full" ]]; then
  run_logged git-diff-check git diff --check "$diff_range"
  run_logged cargo-fmt-check cargo fmt --check
  run_conditional_quick_audits
  run_logged cargo-lib-tests env RUST_TEST_THREADS=1 cargo test -q --lib
  run_logged cargo-build-tvm cargo build -q --bin tvm
  tvm_test_binary="$(resolve_tvm_test_binary_path)"
  run_logged cargo-lib-and-integration-tests env RUST_TEST_THREADS=1 TVM_TEST_BINARY="$tvm_test_binary" cargo test -q --lib --tests
  run_logged cargo-doc-tests cargo test -q --workspace --doc
  if changed_path_is_onnx_surface; then
    run_onnx_smoke_targets
  fi
  if changed_path_is_research_v3_surface; then
    run_tvm_bin_smoke_targets
    run_research_v3_smoke_targets
    run_research_v3_cli_smoke_target
  fi
  run_stwo_smoke_targets
  run_stwo_cli_smoke_targets
  completed_local_mode="$RUN_MODE"
elif (( RUN_LOCAL )) && [[ "$RUN_MODE" == "hardening" ]]; then
  run_logged git-diff-check git diff --check "$diff_range"
  run_logged cargo-fmt-check cargo fmt --check
  run_conditional_quick_audits
  run_logged cargo-lib-tests env RUST_TEST_THREADS=1 cargo test -q --lib
  run_logged cargo-build-tvm cargo build -q --bin tvm
  tvm_test_binary="$(resolve_tvm_test_binary_path)"
  run_logged cargo-lib-and-integration-tests env RUST_TEST_THREADS=1 TVM_TEST_BINARY="$tvm_test_binary" cargo test -q --lib --tests
  run_logged cargo-doc-tests cargo test -q --workspace --doc
  if changed_path_is_onnx_surface; then
    run_onnx_smoke_targets
  fi
  if changed_path_is_research_v3_surface; then
    run_tvm_bin_smoke_targets
    run_research_v3_smoke_targets
    run_research_v3_cli_smoke_target
  fi
  run_stwo_smoke_targets
  run_stwo_cli_smoke_targets
  run_conditional_mutation_check
  run_logged fuzz-smoke env FUZZ_TIME_PER_TARGET=20 scripts/run_fuzz_smoke_suite.sh
  run_logged ub-checks env HARDENING_TOOLCHAIN=nightly-2025-07-14 scripts/run_ub_checks_suite.sh
  run_logged asan env HARDENING_TOOLCHAIN=nightly-2025-07-14 scripts/run_asan_suite.sh
  run_logged miri env HARDENING_TOOLCHAIN=nightly-2025-07-14 scripts/run_miri_suite.sh
  run_logged formal-contracts scripts/run_formal_contract_suite.sh
  completed_local_mode="$RUN_MODE"
elif (( RUN_LOCAL )) && [[ "$RUN_MODE" == "none" ]]; then
  log "local commands disabled by --mode none"
elif (( ! RUN_LOCAL )); then
  log "local commands skipped by --skip-local"
fi

if [[ -n "$completed_local_mode" ]]; then
  jq -n \
    --arg mode "$completed_local_mode" \
    --arg head_sha "$head_sha" \
    --arg completed_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{mode:$mode,head_sha:$head_sha,completed_at:$completed_at}' \
    >"$local_evidence_marker"
fi

if (( MERGE )) && [[ ! -f "$local_evidence_marker" ]]; then
  fail "merge requires completed local evidence for this PR head; rerun with --mode smoke, --mode full, or --mode hardening first"
fi

# Refresh PR state after local commands in case review bots posted while tests ran.
gh pr view "$PR_NUMBER" --repo "$REPO" \
  --json url,state,isDraft,mergeable,reviewDecision,headRefOid,baseRefOid,headRefName,baseRefName,createdAt \
  >"$pr_json"
head_sha_after="$(jq -r '.headRefOid' "$pr_json")"
[[ "$head_sha_after" == "$head_sha" ]] || fail "PR head changed while gate was running: $head_sha -> $head_sha_after"

checks_json="$run_evidence_dir/checks.json"
check_runs_json="$run_evidence_dir/check-runs.json"
statuses_json="$run_evidence_dir/statuses.json"
gh api --paginate "repos/${REPO}/commits/${head_sha}/check-runs?per_page=100" \
  --jq '.check_runs[] | {name, id, created_at, started_at, completed_at, status: (.status | ascii_upcase), conclusion: ((.conclusion // "") | ascii_upcase)}' \
  | jq -s '
      sort_by((.created_at // .started_at // .completed_at // ""), (.id // 0))
      | reduce .[] as $check ({}; .[$check.name] = $check)
      | to_entries
      | sort_by(.key)
      | map(.value)
    ' >"$check_runs_json"
gh api --paginate "repos/${REPO}/commits/${head_sha}/statuses?per_page=100" \
  --jq '.[] | {name: .context, created_at: .created_at, status: (if .state == "pending" then "IN_PROGRESS" else "COMPLETED" end), conclusion: (if .state == "success" then "SUCCESS" elif .state == "pending" then "" elif .state == "error" then "FAILURE" else (.state | ascii_upcase) end)}' \
  | jq -s '
      sort_by(.created_at)
      | reduce .[] as $status ({}; .[$status.name] = $status)
      | to_entries
      | sort_by(.key)
      | map(.value)
    ' >"$statuses_json"
jq -s '.[0] + .[1]' "$check_runs_json" "$statuses_json" >"$checks_json"

failed_checks="$(jq -r '
  [.[]
   | select(.status == "COMPLETED")
   | select(.conclusion | IN("SUCCESS", "SKIPPED", "NEUTRAL") | not)
   | select(.name != null)]
  | length
' "$checks_json")"
if (( failed_checks > 0 )); then
  jq -r '
    .[]
    | select(.status == "COMPLETED")
    | select(.conclusion | IN("SUCCESS", "SKIPPED", "NEUTRAL") | not)
    | select(.name != null)
    | "failed check: \(.name) status=\(.status) conclusion=\(.conclusion)"
  ' "$checks_json" >&2
  fail "GitHub check rollup is not clean"
fi
pending_checks="$(jq -r '[.[] | select(.name != null) | select(.status != "COMPLETED")] | length' "$checks_json")"
if (( pending_checks > 0 )); then
  jq -r '
    .[]
    | select(.name != null)
    | select(.status != "COMPLETED")
    | "pending check: \(.name) status=\(.status) conclusion=\(.conclusion)"
  ' "$checks_json" >&2
  if (( WAIT )); then
    sleep_with_wait_budget 30 "GitHub checks are still pending"
    retry_gate_mode_none
  fi
  fail "GitHub checks are still pending"
fi

owner="${REPO%/*}"
name="${REPO#*/}"
comments_query=$(cat <<'GRAPHQL'
query($owner:String!,$name:String!,$number:Int!,$cursor:String){
  repository(owner:$owner,name:$name){
    pullRequest(number:$number){
      comments(first:100, after:$cursor){
        pageInfo{ hasNextPage endCursor }
        nodes{ author{login} createdAt }
      }
    }
  }
}
GRAPHQL
)
reviews_query=$(cat <<'GRAPHQL'
query($owner:String!,$name:String!,$number:Int!,$cursor:String){
  repository(owner:$owner,name:$name){
    pullRequest(number:$number){
      reviews(first:100, after:$cursor){
        pageInfo{ hasNextPage endCursor }
        nodes{ author{login} submittedAt }
      }
    }
  }
}
GRAPHQL
)
threads_query=$(cat <<'GRAPHQL'
query($owner:String!,$name:String!,$number:Int!,$cursor:String){
  repository(owner:$owner,name:$name){
    pullRequest(number:$number){
      reviewThreads(first:100, after:$cursor){
        pageInfo{ hasNextPage endCursor }
        nodes{
          isResolved
          isOutdated
          comments(first:100){
            pageInfo{ hasNextPage endCursor }
            nodes{ author{login} createdAt }
          }
        }
      }
    }
  }
}
GRAPHQL
)

now_epoch="$(date -u +%s)"
threads_json="$run_evidence_dir/review-gate.json"
comments_json="$run_evidence_dir/review-comments.json"
reviews_json="$run_evidence_dir/reviews.json"
review_threads_json="$run_evidence_dir/review-threads.json"
review_source_json="$run_evidence_dir/review-source.json"

fetch_paginated_connection comments "$comments_query" '.data.repository.pullRequest.comments.nodes' "$comments_json"
fetch_paginated_connection reviews "$reviews_query" '[.data.repository.pullRequest.reviews.nodes[] | {author, createdAt:.submittedAt}]' "$reviews_json"
fetch_paginated_connection reviewThreads "$threads_query" '.data.repository.pullRequest.reviewThreads.nodes' "$review_threads_json"

if jq -e '[.[].comments.pageInfo.hasNextPage // false] | any' "$review_threads_json" >/dev/null; then
  fail "a review thread has more than 100 comments; refusing to merge without complete review data"
fi

jq -n \
  --slurpfile comments "$comments_json" \
  --slurpfile reviews "$reviews_json" \
  --slurpfile reviewThreads "$review_threads_json" \
  '{data:{repository:{pullRequest:{comments:{nodes:$comments[0]},reviews:{nodes:$reviews[0]},reviewThreads:{nodes:$reviewThreads[0]}}}}}' \
  >"$review_source_json"

jq --argjson now "$now_epoch" '
    .data.repository.pullRequest as $pull
    | ["coderabbitai", "greptile-apps", "qodo-code-review"] as $ai_reviewers
    | [ $pull.reviewThreads.nodes[]? | select((.isResolved // false) == false and (.isOutdated // false) == false) ] as $active
    | ([
        ($pull.comments.nodes[]? | select(.author.login as $login | $ai_reviewers | index($login)) | {author:.author.login, createdAt}),
        ($pull.reviews.nodes[]? | select(.author.login as $login | $ai_reviewers | index($login)) | {author:.author.login, createdAt}),
        ($pull.reviewThreads.nodes[].comments.nodes[]? | select(.author.login as $login | $ai_reviewers | index($login)) | {author:.author.login, createdAt})
      ]
      | map(
          select(.createdAt | type == "string" and length > 0)
          | . + {epoch: (try (.createdAt | fromdateiso8601) catch null)}
          | select(.epoch != null)
        )
      | sort_by(.epoch)
      | last) as $latest
    | {
        active_threads: ($active | length),
        latest_ai_event: (if $latest then {author:$latest.author, createdAt:$latest.createdAt} else null end),
        latest_ai_event_epoch: (if $latest then $latest.epoch else null end),
        quiet_window_source: (if $latest then "latest_ai_event" else "no_ai_event" end),
        seconds_since_latest_ai_event: (if $latest then ($now - $latest.epoch) else null end)
      }
  ' "$review_source_json" >"$threads_json"

active_threads="$(jq -r '.active_threads' "$threads_json")"
seconds_since_ai="$(jq -r '.seconds_since_latest_ai_event // "none"' "$threads_json")"
latest_ai="$(jq -r '.latest_ai_event.createdAt // "none"' "$threads_json")"
latest_ai_author="$(jq -r '.latest_ai_event.author // "none"' "$threads_json")"

if (( active_threads > 0 )); then
  fail "active review threads remain: $active_threads"
fi

if [[ "$seconds_since_ai" == "none" ]]; then
  fail "no AI reviewer review/comment event observed yet"
fi

if (( seconds_since_ai < QUIET_SECONDS )); then
  remaining=$((QUIET_SECONDS - seconds_since_ai))
  if (( WAIT )); then
    sleep_with_wait_budget "$remaining" "AI quiet window not satisfied; latest ${latest_ai_author} event at ${latest_ai}"
    retry_gate_mode_none
  fi
  fail "AI quiet window not satisfied; latest ${latest_ai_author} event at ${latest_ai}"
fi

commands_json="$run_evidence_dir/commands.json"
if compgen -G "$LOG_DIR/*.json" >/dev/null; then
  jq -s '.' "$LOG_DIR"/*.json >"$commands_json"
else
  printf '[]\n' >"$commands_json"
fi

evidence_file="$run_evidence_dir/evidence.json"
jq -n \
  --arg repo "$REPO" \
  --arg pr_number "$PR_NUMBER" \
  --arg pr_url "$pr_url" \
  --arg head_sha "$head_sha" \
  --arg base_sha "$base_sha" \
  --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg run_mode "$RUN_MODE" \
  --argjson quiet_seconds "$QUIET_SECONDS" \
  --slurpfile pr "$pr_json" \
  --slurpfile checks "$checks_json" \
  --slurpfile threads "$threads_json" \
  --slurpfile commands "$commands_json" \
  '{
    repo:$repo,
    pr_number:($pr_number|tonumber),
    pr_url:$pr_url,
    base_sha:$base_sha,
    head_sha:$head_sha,
    generated_at:$generated_at,
    run_mode:$run_mode,
    quiet_seconds:$quiet_seconds,
    pr:$pr[0],
    checks:$checks[0],
    review_gate:$threads[0],
    local_commands:$commands[0]
  }' >"$evidence_file"

log "gate passed for ${pr_url}"
log "evidence: ${evidence_file}"

if (( MERGE )); then
  merge_args=(gh pr merge "$PR_NUMBER" --repo "$REPO" --match-head-commit "$head_sha")
  case "$MERGE_METHOD" in
    merge) merge_args+=(--merge) ;;
    squash) merge_args+=(--squash) ;;
    rebase) merge_args+=(--rebase) ;;
  esac
  if (( DELETE_BRANCH )); then
    merge_args+=(--delete-branch)
  fi
  "${merge_args[@]}"
  log "merged PR ${PR_NUMBER}"
else
  log "not merging; pass --merge to merge after the gate"
fi
