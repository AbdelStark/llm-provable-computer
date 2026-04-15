# Hardening and Test Strategy

This document formalizes how the repository proves to itself that a change is
safe enough to merge.

It is not a publication document. It is an engineering contract for trusted-core
work.

## Goals

- Catch semantic regressions before proof generation.
- Catch verifier drift before a malformed artifact can be accepted.
- Catch parser/decoder failures before malformed or adversarial input can panic,
  trigger UB, or silently decode to the wrong value.
- Catch supply-chain and workflow drift before new advisories or CI regressions
  land unnoticed.
- Tie every merge decision to reproducible local evidence rather than reviewer
  opinion.

## Threat Classes

The repository treats the following as primary failure modes:

| Threat class | What can go wrong | Preferred defenses |
| --- | --- | --- |
| Runtime semantics drift | Transformer/native/Burn/ONNX paths disagree on the same program | lockstep integration tests, bounded equivalence artifacts, regression smoke |
| Verifier acceptance bug | malformed proof/artifact/manifest is accepted | tamper-path unit tests, CLI rejection tests, schema/statement checks |
| Parser/decoder unsoundness | malformed input panics, misdecodes, or triggers UB | unit tests, fuzzing, Miri, UB checks, ASAN, no-panic fallbacks |
| Statement drift | code and documented public statement stop matching | statement-spec contract tests, manifest schema checks, proof claim round-trips |
| Workflow drift | CI or merge policy stops enforcing the intended guarantees | workflow audit, shellcheck, local merge gate evidence |
| Dependency drift | new RustSec/license/source risk lands without code changes | dependency audit on PR deltas plus scheduled and `main`-branch audit |
| Overclaiming from AI review | bots approve while the artifact is still weak | zero unresolved threads plus local evidence and merge gate |

## Assurance Tiers

Use these tiers intentionally. Do not treat every PR as a release ceremony, but
do not let trusted-core changes merge on smoke alone.

| Tier | Purpose | Typical commands |
| --- | --- | --- |
| `smoke` | Fast confidence on ordinary PRs | `git diff --check`, `cargo fmt --check`, shellcheck/workflow audit when touched, statement-spec contract, allowlisted smoke targets, exact pinned-nightly `stwo` smokes |
| `full` | Merge proof for most code changes | `smoke` plus `cargo test -q --lib`, `cargo test -q --lib --tests`, `cargo test -q --workspace --doc`, dependency audit, exact pinned-nightly `stwo` smokes |
| `hardening` | Adversarial confidence for parser/verifier/trusted-core changes | `full` plus mutation, fuzz smoke, UB checks, ASAN, Miri, formal contracts |
| scheduled baseline | Detect drift that diff-scoped PR checks cannot see | scheduled or `main`-branch dependency audit, manually dispatched heavy CI baselines when needed |

The merge gate in `scripts/local_merge_gate.sh` enforces the first three tiers.

## Required Test Types

Every trusted-core change should be classified into one or more of these test
families.

### 1. Deterministic unit and integration tests

Use for:

- pure logic,
- proof claim serialization,
- manifest/schema validation,
- backend routing,
- lockstep runtime semantics.

Minimum rule:

- add a happy-path test for the new behavior,
- add at least one rejection or mismatch test if the code verifies, parses, or
  decodes anything.

### 2. Tamper and rejection tests

Use for:

- proof verifiers,
- manifest loaders,
- artifact registries,
- carried-state boundaries,
- recursive-compression input contracts,
- any CLI command that verifies an artifact.

Minimum rule:

- test at least one structurally valid but semantically wrong input,
- test at least one malformed input,
- assert deterministic rejection without panic.

### 3. Property and mutation-style tests

Use for:

- statement-preserving transforms,
- manifest rebasing,
- accumulator/aggregation recomputation,
- claim hashing and commitment recomputation.

Minimum rule:

- when a transform is supposed to preserve a public statement, test both:
  - round-trip preservation on valid input,
  - mismatch detection when one committed field drifts.

### 4. Fuzzing

Use for:

- decoders,
- manifest loaders,
- artifact parsers,
- public verifier entrypoints,
- carried-state artifact boundaries.

Minimum rule:

- every public binary format or structured JSON manifest should have either:
  - a dedicated fuzz target, or
  - an explicit reason why fuzzing is not yet applicable.

Use:

- `python3 scripts/fuzz/generate_decoding_fuzz_corpus.py`
- `FUZZ_TIME_PER_TARGET=20 scripts/run_fuzz_smoke_suite.sh`

### 5. UB and sanitizer checks

Use for:

- `unsafe`,
- pointer/slice reinterpretation,
- vendored decoding code,
- custom alloc/layout assumptions,
- parser logic that handles raw buffers.

Minimum rule:

- any new `unsafe` or vendored low-level decoding patch must be backed by:
  - targeted unit coverage,
  - no-panic fallback behavior on malformed input,
  - `scripts/run_ub_checks_suite.sh`,
  - `scripts/run_asan_suite.sh`,
  - `scripts/run_miri_suite.sh` when the surface is Rust-defined memory logic.

### 6. Workflow and dependency audit

Use for:

- CI/workflow edits,
- merge-gate edits,
- dependency changes,
- vendored third-party code,
- audit policy changes.

Minimum rule:

- workflow edits run `scripts/run_workflow_audit_suite.sh`,
- shell scripts run `scripts/run_shellcheck_suite.sh`,
- dependency and vendor edits run `scripts/run_dependency_audit_suite.sh`,
- accepted dependency risk must be documented in
  `docs/engineering/dependency-audit-exceptions.md`.

## Change-Class Matrix

This is the minimum expected evidence for each change class.

| Change class | Required tier | Required extra evidence |
| --- | --- | --- |
| docs-only publication edits | `smoke` | format and policy/doc consistency |
| ordinary runtime logic | `full` | unit/integration coverage for changed behavior |
| workflow or merge-gate logic | `full` | workflow audit, shellcheck, clean GitHub check rollup |
| dependency or vendored third-party patch | `full` | dependency audit, targeted regression tests, documented exception policy if any |
| parser/decoder/verifier path | `hardening` preferred | tamper tests, fuzz coverage, no-panic behavior, UB/ASAN/Miri when applicable |
| public statement/schema/manifest change | `full` minimum | round-trip tests, mismatch detection, CLI/load/verify rejection tests |
| carried-state / aggregation / recursive-compression surfaces | `hardening` preferred | recomputation/tamper tests, fuzz target coverage, exact pinned-nightly `stwo` smokes |
| release or baseline confidence run | `hardening` plus manual baseline | archived evidence bundle under `target/local-hardening/...` |

If a trusted-core PR chooses less than the preferred tier, the PR notes must say
why.

## Surface-Specific Rules

### Verifiers

- Never rely on happy-path coverage alone.
- Every verifier change must include at least one structurally valid tampered
  artifact and one malformed artifact.
- Rejections must be deterministic and non-panicking.

### Decoders and parsers

- Unsupported inputs must degrade to explicit rejection or `Unknown`, not
  `todo!()` or `unreachable!()`.
- Avoid `unsafe` reinterpretation unless the layout assumption is proven and
  covered.
- If logical elements are stored in widened protobuf/runtime containers, convert
  by checked logical-element conversion instead of raw byte reinterpretation.

### Proof and statement surfaces

- Public statement semantics are part of the contract.
- If the code changes a statement, claim hash, schema field, or commitment
  recomputation rule, update:
  - the implementation,
  - the contract tests,
  - the relevant engineering spec,
  - the publication-facing wording if that surface is public.

### Dependency policy

- New exceptions are not free.
- Any allowlist addition must include:
  - advisory/license/source identifier,
  - owning surface,
  - reason the risk remains,
  - exit condition.

## Evidence Requirements

A merge is not justified by “tests passed” in chat. It is justified by a local
evidence artifact tied to the exact PR head SHA.

Required properties:

- clean worktree,
- local `HEAD` equals PR head,
- evidence written under
  `target/local-hardening/pr-<PR>-<HEAD>/`,
- zero unresolved review threads,
- clean GitHub status/check rollup,
- quiet window after the last AI review event,
- merge performed through the local merge gate.

The canonical artifact is:

- `target/local-hardening/pr-<PR>-<HEAD>/evidence.json`

## Operating Procedure

1. Classify the change.
2. Choose the minimum required tier from the matrix above.
3. Add or update happy-path and rejection-path tests first.
4. Run the matching local commands.
5. Open the PR with explicit validation and hardening notes.
6. Address every actionable review thread with code or a documented reason.
7. Re-run the merge gate on the final PR head.
8. Merge only through the gate.

## Anti-Patterns

Do not do these:

- treat AI approval as proof,
- merge parser/verifier changes without tamper-path tests,
- add `unsafe` or vendor patches without targeted coverage,
- widen dependency exceptions without an owner and exit condition,
- rely only on diff-scoped PR audits for advisory drift,
- claim a hardening tier ran when it did not.

## Current Default

For this repository today:

- `smoke` is the minimum ordinary PR gate,
- `full` is the normal merge gate for code changes,
- `hardening` is the preferred gate for parser/verifier/trusted-core boundary
  work,
- scheduled and `main`-branch dependency audit covers advisory drift that PR
  diff-gating cannot catch.

When in doubt, choose the stricter tier and record the evidence.
