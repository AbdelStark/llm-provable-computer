# Review Rules

Review this repository as a proof-system codebase, not as a generic app repository.

## Highest priorities

1. Proof soundness and verification correctness.
2. AIR, trace, and carried-state consistency.
3. Statement, backend, manifest, and artifact version drift.
4. Bounds and denial-of-service safety in verification and manifest parsing.
5. Missing negative, tamper, or compatibility tests after semantic changes.
6. Documentation or README claims that overstate supported backends or phases.

## High-signal targets

- `src/stwo_backend/**`
- `src/proof.rs`
- `src/verification.rs`
- `src/bin/tvm.rs`
- `tests/**`
- `.github/workflows/**`
- `scripts/**`
- `README.md`
- `docs/design/**`
- `docs/paper/*.md`

## Low-value targets to ignore

Do not spend review budget on vendored or generated content unless it creates an integrity or reproducibility risk:

- `scripts/node_modules/**`
- `docs/artifacts/**`
- `docs/paper/artifacts/**`
- `docs/paper/evidence/**`
- `docs/paper/figures/**`
- `compiled/**`

## Review style

- Prefer one precise bug over five generic suggestions.
- Treat removed checks, weaker commitment comparisons, and skipped nested-proof verification as high severity.
- When a PR changes proof semantics, decoding-chain structure, or manifest schemas, expect at least one failing-path or tamper-path test.
- Ignore style-only issues unless they hide a correctness, maintenance, or security risk.
