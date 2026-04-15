# S-two Phase 0 Checklist

This checklist breaks `docs/engineering/design/stwo-backend-design.md` into issue-sized implementation steps for the backend-abstraction phase.

## Phase 0 objective

Create a backend boundary around proving and verification while preserving current `statement-v1` semantics and keeping `vanilla` as the only fully functional backend.

## Issue 1: Introduce backend identifiers

- [x] Add a backend enum shared by proof code and CLI.
- [x] Reserve identifiers for `vanilla` and `stwo`.
- [x] Make legacy proof JSON deserialize as `vanilla` by default.

## Issue 2: Add backend metadata to proof envelopes

- [x] Add `proof_backend` to serialized proof output.
- [x] Add `proof_backend_version` to serialized proof output.
- [x] Validate backend metadata during verification.
- [ ] Decide whether future backend fingerprints belong in the proof envelope or claim commitments.

## Issue 3: Separate witness preparation from backend proving

- [x] Extract common witness/claim preparation away from the current vanilla proving path.
- [x] Keep semantic checks shared before backend dispatch.
- [ ] Decide whether AIR construction should remain shared or become backend-specific in Phase 1.

## Issue 4: Introduce backend driver abstraction

- [x] Add an internal backend trait for prove/verify operations.
- [x] Implement `VanillaBackend` using the current `Stark::new(...)` path.
- [x] Add an explicit `StwoBackend` placeholder that fails cleanly.
- [ ] Decide whether Phase 1 should keep a trait-object interface or move to enum dispatch for performance/simplicity.

## Issue 5: Wire CLI backend selection

- [x] Add `--backend vanilla|stwo` to `prove-stark`.
- [x] Add optional `--backend` override to `verify-stark`.
- [x] Print backend metadata in CLI output.
- [ ] Add README examples once the branch stabilizes.

## Issue 6: Add regression tests for Phase 0

- [x] Serialization round-trip still works.
- [x] Legacy proof JSON without backend fields defaults to `vanilla`.
- [x] CLI reports backend metadata.
- [x] CLI rejects `--backend stwo` with a clear message.
- [x] CLI rejects backend-override mismatch during verification.

## Issue 7: Prepare for Phase 1

- [x] Define the minimum arithmetic-subset fixture matrix for `stwo` parity (`addition`, `multiply`, `counter`, `dot_product`).
- [x] Decide where S-two-specific dependencies and feature gates will live in `Cargo.toml`.
- [x] Decide whether proof bytes stay as opaque `Vec<u8>` or need a backend-tagged envelope type.
- [x] Define what must remain identical between `vanilla` and `stwo` for `statement-v1` compatibility.

Phase 1 status:

- `stwo-backend` is now an explicit Cargo feature gate.
- The first S-two seam is subset-aware rather than generic: `addition`, `multiply`, `counter`, and `dot_product` define the minimum accepted fixture matrix.
- Proof bytes remain `Vec<u8>` at the statement-v1 envelope layer; backend selection/versioning stays in proof metadata until a real S-two serialization format exists.
- Statement-v1 compatibility remains defined by identical claim semantics (`statement_version`, `semantic_scope`, public program/final-state meaning), not by identical proof-byte encoding.

## Exit criteria for Phase 0

- [ ] `prove-stark` and `verify-stark` route through a backend abstraction without changing `statement-v1` semantics.
- [ ] `vanilla` remains the default and continues to pass current proving tests.
- [ ] `stwo` is visible as a future backend but fails explicitly rather than implicitly.
- [ ] Proof artifacts now carry enough backend metadata to support a later multi-backend migration.
