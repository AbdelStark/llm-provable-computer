#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

CARGO_AUDIT_VERSION="${CARGO_AUDIT_VERSION:-0.22.1}"
CARGO_DENY_VERSION="${CARGO_DENY_VERSION:-0.19.0}"
# Keep this list aligned with docs/engineering/dependency-audit-exceptions.md.
ROOT_IGNORED_AUDIT_ADVISORIES=(
  "RUSTSEC-2025-0141"
  "RUSTSEC-2024-0388"
  "RUSTSEC-2024-0436"
  "RUSTSEC-2026-0002"
  "RUSTSEC-2026-0097"
)
FUZZ_IGNORED_AUDIT_ADVISORIES=(
  "RUSTSEC-2024-0388"
  "RUSTSEC-2024-0436"
  "RUSTSEC-2026-0002"
  "RUSTSEC-2026-0097"
)
ROOT_IGNORED_YANKED_PACKAGES=(
  "core2@0.4.0"
)
FUZZ_IGNORED_YANKED_PACKAGES=()

require_command() {
  local command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "missing required command: $command_name" >&2
    exit 1
  fi
}

require_exact_version() {
  local label="$1"
  local actual="$2"
  local expected="$3"
  if [[ "$actual" != "$expected" ]]; then
    echo "$label version mismatch: expected ${expected}, found ${actual}" >&2
    exit 1
  fi
}

require_command cargo-audit
require_command cargo-deny
require_command python3

cargo_audit_version="$(cargo-audit --version | awk '{print $2}')"
require_exact_version cargo-audit "$cargo_audit_version" "$CARGO_AUDIT_VERSION"

cargo_deny_version="$(cargo-deny --version | awk '{print $2}')"
require_exact_version cargo-deny "$cargo_deny_version" "$CARGO_DENY_VERSION"

cargo_audit_args=(
  "--json"
)

run_cargo_audit() {
  local label="$1"
  local lockfile="$2"
  local report_path
  local -a allowed_advisories=()
  local -a allowed_yanked_packages=()
  local check_args=(
    "--report"
  )

  case "$label" in
    root)
      allowed_advisories=("${ROOT_IGNORED_AUDIT_ADVISORIES[@]}")
      allowed_yanked_packages=("${ROOT_IGNORED_YANKED_PACKAGES[@]}")
      ;;
    fuzz)
      allowed_advisories=("${FUZZ_IGNORED_AUDIT_ADVISORIES[@]}")
      allowed_yanked_packages=("${FUZZ_IGNORED_YANKED_PACKAGES[@]}")
      ;;
    *)
      echo "unknown dependency-audit label: $label" >&2
      return 1
      ;;
  esac

  echo "[dependency-audit] cargo audit: ${label} (${lockfile})"
  if ! report_path="$(mktemp "${TMPDIR:-/tmp}/cargo-audit-report.XXXXXX")"; then
    echo "failed to allocate cargo-audit temp file for ${label} (${lockfile})" >&2
    return 1
  fi
  if ! cargo audit "${cargo_audit_args[@]}" --file "$lockfile" >"$report_path"; then
    rm -f "$report_path"
    return 1
  fi
  check_args+=("$report_path")

  for advisory_id in "${allowed_advisories[@]}"; do
    check_args+=("--allow-advisory" "$advisory_id")
  done

  for package_spec in "${allowed_yanked_packages[@]}"; do
    check_args+=("--allow-yanked" "$package_spec")
  done

  if ! python3 "$ROOT_DIR/scripts/check_cargo_audit_report.py" "${check_args[@]}"; then
    rm -f "$report_path"
    return 1
  fi
  rm -f "$report_path"
}

run_cargo_deny() {
  local label="$1"
  local manifest_path="$2"
  echo "[dependency-audit] cargo deny: ${label} (${manifest_path})"
  cargo deny --manifest-path "$manifest_path" check -c "$ROOT_DIR/deny.toml" advisories bans licenses sources
}

run_cargo_audit root Cargo.lock
run_cargo_deny root Cargo.toml
run_cargo_audit fuzz fuzz/Cargo.lock
run_cargo_deny fuzz fuzz/Cargo.toml
