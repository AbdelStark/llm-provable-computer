# Local CI and Hardening Policy

Trusted-core work must preserve the hardening discipline without defaulting to
expensive GitHub Actions compute.

The operational strategy behind this policy is formalized in
[`docs/engineering/hardening-strategy.md`](hardening-strategy.md).
Use that document to decide which tier, attack style, and evidence bundle a
change requires.

## Rule

- Do not use automatic `push`, `pull_request`, or `schedule` triggers for
  heavyweight GitHub Actions compute such as full CI matrix, mutation testing,
  Miri, sanitizers, or formal contracts.
- Keep any automatic PR GitHub Actions compute lightweight and path-scoped; the
  CI workflow only runs a core library contract plus integration-test smoke for
  Rust, Cargo, program fixture, or CI workflow changes, plus one exact
  pinned-nightly `stwo-backend` smoke with the pinned nightly toolchain cached.
- Keep dependency-advisory drift under continuous watch with a lightweight
  scheduled and `main`-branch dependency-audit job instead of widening the full
  PR matrix.
- Keep heavyweight GitHub Actions workflows available through
  `workflow_dispatch` for intentional release, baseline, or emergency
  GitHub-hosted validation.
- Before opening or merging trusted-core PRs, run the matching tests and
  hardening suite locally, preferably inside a Lima Ubuntu 22.04 environment for
  Linux parity.
- Keep CodeRabbit, Greptile, and Qodo as GitHub PR review signals, and keep the
  PR hardening contract workflow (`.github/workflows/pr-hardening-contract.yml`)
  as the enforced PR-body checklist gate.
- `main` does not get automatic post-merge runs for heavyweight GitHub Actions
  workflows; dispatch those workflows manually when release or baseline
  validation needs a GitHub-hosted run on the merge commit.
- If a PR cannot run a local hardening command, document the blocker in the PR
  validation notes and use `workflow_dispatch` intentionally.
- Merge trusted-core PRs through `scripts/local_merge_gate.sh` so the final
  merge decision is tied to the exact PR head SHA, local evidence logs, a clean
  GitHub check rollup, zero unresolved review threads, and a five-minute quiet
  window after the last CodeRabbit, Greptile, or Qodo event.

## Local Commands

Run the relevant subset from the repository root:

```bash
cargo test -q --lib
cargo nextest run \
  --workspace --all-targets --profile ci --no-fail-fast
cargo test --workspace --doc
RUSTUP_TOOLCHAIN=nightly-2025-07-14 cargo nextest run \
  --workspace --all-targets --features stwo-backend \
  --profile ci-stwo --no-fail-fast
cargo fmt --check
git diff --check
scripts/run_shellcheck_suite.sh
scripts/run_workflow_audit_suite.sh
scripts/run_dependency_audit_suite.sh
python3 scripts/fuzz/generate_decoding_fuzz_corpus.py
FUZZ_TIME_PER_TARGET=20 scripts/run_fuzz_smoke_suite.sh
HARDENING_TOOLCHAIN=nightly-2025-07-14 scripts/run_miri_suite.sh
HARDENING_TOOLCHAIN=nightly-2025-07-14 scripts/run_ub_checks_suite.sh
HARDENING_TOOLCHAIN=nightly-2025-07-14 scripts/run_asan_suite.sh
scripts/run_formal_contract_suite.sh
```

`scripts/fuzz/generate_decoding_fuzz_corpus.py` refreshes the tracked curated
corpus. `scripts/run_fuzz_smoke_suite.sh` generates its own temporary corpus
under `target/fuzz-smoke/generated-corpus` so the hardening gate does not
rewrite tracked fuzz seeds as a side effect.

The sanitizer and UB hardening scripts use the curated exact test lists in
`scripts/hardening_test_names.sh`; update that file when adding new trusted-core
phase gates.
Install the `cargo-nextest` version pinned in `.config/nextest.toml` if it is
missing. Run the relevant feature rows from `.github/workflows/ci.yml` when the
change touches broader runtime, export, or backend behavior.

## Lima Baseline

For sanitizer parity with GitHub's Ubuntu runners, prefer running the hardening
suite inside Lima:

```bash
limactl start template://ubuntu-22.04 --name ptv-ci
limactl shell ptv-ci
```

Inside the VM:

```bash
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libssl-dev git curl jq shellcheck python3-pip
curl https://sh.rustup.rs -sSf | sh -s -- -y
source "$HOME/.cargo/env"
rustup toolchain install nightly-2025-07-14 --component miri,rust-src
python3 -m pip install --user uv
export PATH="$HOME/.local/bin:$PATH"
cargo install --locked cargo-audit --version 0.22.1
cargo install --locked cargo-deny --version 0.19.0
```

The dependency audit suite carries the current upstream exception policy in
`deny.toml` and `docs/engineering/dependency-audit-exceptions.md`, and it audits
both the repository root graph and the separate `fuzz/` workspace lockfile.
Review those files before adding new ignores or widening the vendored
`onnx-protobuf` patch surface.

Then run the local commands above from the repository checkout mounted or cloned
inside the VM. The merge gate also requires GitHub CLI (`gh`) authenticated
against the target repository; install it from GitHub CLI's package repository
or your host package manager before running `scripts/local_merge_gate.sh`.

## Local Merge Gate

Use the merge gate from a clean checkout of the PR head after the PR has been
opened and the review bots have reported:

```bash
scripts/local_merge_gate.sh --repo omarespejel/provable-transformer-vm --pr <PR> --mode smoke --wait --merge
```

The script refuses to continue if the local `HEAD` differs from the PR head SHA
or if the worktree is dirty. It writes per-PR evidence under
`target/local-hardening/pr-<PR>-<HEAD>/evidence.json`, including command exit
codes, UTC timestamps, log paths, and log SHA-256 digests.

Available local command tiers:

- `--mode smoke`: default minimum gate for ordinary PRs. Runs PR-range
  whitespace hygiene as `git diff --check "$base_sha...$head_sha"`, `cargo fmt
  --check`, conditional workflow auditing and shellcheck when the PR touches
  those surfaces, the statement-spec contract, allowlisted integration smoke
  targets, and exact pinned-nightly `stwo-backend` smokes for the Phase 28
  aggregation verifier, Phase 29 recursive-compression input contract, and
  non-heavy Phase 29 CLI artifact verification paths.
- `--mode full`: runs the same PR-range whitespace and formatting hygiene, full
  library tests, integration tests, doctests, the same conditional workflow
  auditing, dependency auditing, and shellcheck, and the exact pinned-nightly
  `stwo-backend` smokes.
- `--mode hardening`: runs the `full` tier, including the same conditional
  workflow auditing for `.github/workflows/**` and `zizmor.yml`, the same
  conditional dependency auditing for `Cargo.toml`, `Cargo.lock`,
  `fuzz/Cargo.toml`, `fuzz/Cargo.lock`, `deny.toml`,
  `scripts/run_dependency_audit_suite.sh`, and `vendor/onnx-protobuf/**`, and
  the same conditional shellcheck for `scripts/*.sh` and `scripts/**/*.sh`,
  plus diff-scoped mutation testing when the trusted-core prover files change,
  curated fuzz smoke, UB checks, ASAN, Miri, and the formal contract suite. The
  inherited whitespace gate is still scoped to the committed PR delta, not the
  whole worktree. Prefer running this tier inside Lima for Linux parity.
- `--mode none`: only checks GitHub status, review-thread state, and the
  five-minute AI-review quiet window. Use this only after a prior evidence run
  for the same PR head SHA.

The GitHub side of the merge gate is intentionally narrow:

- Every non-null GitHub check in the PR rollup must be completed with
  `SUCCESS`, `SKIPPED`, or `NEUTRAL`. The gate reads check runs and commit
  statuses through paginated GitHub API calls instead of relying on the capped
  `statusCheckRollup` view. Legacy commit statuses are append-only, so the gate
  evaluates only the newest status per context while still enforcing every
  check-run row. Passing `--wait` polls pending checks and fails immediately for
  completed failure conclusions.
- All review threads must be resolved, regardless of reviewer.
- The review gate paginates PR comments, PR reviews, and review threads. It
  fails closed if any individual review thread has more than 100 comments,
  because the gate cannot safely inspect that nested comment stream.
- No CodeRabbit, Greptile, or Qodo review/comment event may have occurred in the
  previous 300 seconds. If no AI review/comment event exists yet, the gate
  refuses to merge. Passing `--wait` sleeps through the remaining quiet window
  and then rechecks without rerunning local tests; any PR head change causes the
  recheck to fail.
- Passing `--merge` is required for the script to merge. Without `--merge`, it
  only writes evidence and reports the gate result.
- `--wait` is bounded by `--max-wait-seconds` (default 1800 seconds) so stuck
  third-party checks do not spin indefinitely.

Do not treat AI reviewer approval as proof. Treat the AI tools as review input;
the proof for trusted-core work is the local evidence artifact plus the frozen
phase artifacts produced by the relevant implementation work.
