# Summary

- describe the change

## Validation

- [ ] `cargo +nightly-2025-07-14 check --quiet --features stwo-backend`
- [ ] targeted tests listed below

Commands run:

```text
# paste exact commands here
```

## Hardening

Complete this section for changes touching trusted-core paths such as `src/stwo_backend/**`,
`src/proof.rs`, `src/verification.rs`, `src/bin/tvm.rs`, `tests/**`, or `.github/workflows/**`.

- [ ] targeted regression and tamper-path coverage added or updated
- [ ] oracle or differential checks added/updated, or marked not applicable below
- [ ] resource-bound / untrusted-input impact reviewed, or marked not applicable below
- [ ] Kani / formal-kernel impact reviewed, or marked not applicable below

Not applicable notes:

```text
# explain any unchecked item here
```
