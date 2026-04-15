## Proof And Verification Standards

- Do not weaken proof, manifest, or artifact verification checks in the name of convenience.
- If a change adds a new proof field, version constant, carried-state field, or artifact reference, require explicit verification of that field on the read path.
- Treat nested proof envelopes and derived commitments as first-class integrity boundaries. If an artifact embeds a proof envelope, verify the embedded envelope itself, not only a copied commitment.

## Regression Test Expectations

- When proof semantics, decoding-chain structure, manifest schema, or version constants change, add at least one failing-path, tamper-path, or compatibility regression test.
- Happy-path-only tests are insufficient for changes to `src/stwo_backend/**`, `src/proof.rs`, `src/verification.rs`, or `src/bin/tvm.rs`.
- If a change is motivated by a denial-of-service or untrusted-input concern, add a regression test that exercises the rejected input shape.
- For trusted-core pull requests, include a `Validation` section and a `Hardening` section in the PR body. The PR should not merge without those sections.

## Trusted-Core Default Harness

- For changes to decoding, manifest verification, carried-state commitments, proof binding, or CLI verification paths, run the relevant subset of:
  - targeted regression and tamper-path tests,
  - oracle or differential checks,
  - resource-bound verification tests,
  - Kani / formal-kernel checks when the invariant is bounded,
  - Miri / ASAN / UB-check coverage when parser or validator glue changes.
- If a layer is not applicable, explain that explicitly in the PR body instead of silently skipping it.

## Documentation And Claim Discipline

- README and technical docs are part of the product surface. Flag command drift, unsupported backend claims, and stale phase descriptions.
- Do not describe an experimental backend as production-ready unless the code and tests already support that claim.

## Low-Value Noise To Avoid

- Ignore formatting-only suggestions unless they hide a correctness or maintainability problem.
- Ignore vendored or generated content unless it creates reproducibility, integrity, or supply-chain risk.
