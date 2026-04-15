# Formal Contract Pilot

This pilot formalizes the narrowest trust-critical decoding bindings we currently rely on in the `stwo` proof-carrying path.

Scope:
- Phase 12 claim bindings:
  - `statement_version` must match the manifest
  - `semantic_scope` must remain `CLAIM_SEMANTIC_SCOPE_V1`
  - the manifest artifact commitment must match the proof-payload artifact commitment
- Phase 12 state progress:
  - history length must advance by exactly one
  - position must advance by exactly one
- Phase 14 claim bindings:
  - `statement_version` must match the manifest
  - `semantic_scope` must remain `CLAIM_SEMANTIC_SCOPE_V1`
  - the manifest artifact commitment must match the proof-payload artifact commitment
- Phase 14 state progress:
  - history length must advance by exactly one
  - lookup transcript entries must advance by exactly one
  - position must advance by exactly one

Mechanization:
- Kani harnesses live in `src/stwo_backend/decoding.rs`
- the Kani model deliberately reduces string/commitment equality into scalar match predicates so the solver checks the binding logic rather than spending proof budget on `memcmp`
- the dedicated runner is `scripts/run_formal_contract_suite.sh`
- CI entrypoint is `.github/workflows/formal-contracts.yml`

Non-goals:
- this does not prove the full decoding verifier
- this does not prove the `stwo` backend itself
- this does not replace fuzzing, mutation testing, or oracle checks

Why this exists:
- the decoding validator is now stable enough that its scalar binding kernel is worth machine-checking
- these contracts cover the highest-value “do not silently drift” invariants before larger proof-carrying decoding work continues
