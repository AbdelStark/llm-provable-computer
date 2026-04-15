# Dependency Audit Exceptions

The dependency audit gate is intentionally strict:

- `scripts/run_dependency_audit_suite.sh` runs `cargo audit --json` plus a
  repository-owned checker that still fails on every vulnerability,
  unmaintained dependency, unsound dependency, and yanked crate unless the
  exact advisory ID or yanked `crate@version` is documented here.
- The checker also fails on stale allowlist entries, so each exception must
  remain scoped to the lockfile that still exhibits it (`root` versus `fuzz`).
- `cargo deny check advisories bans licenses sources` enforces the graph,
  licensing, and source policy from `deny.toml` against both manifests.
- Yanked-package exceptions must stay duplicated in `deny.toml` because
  `cargo-audit` only ignores advisory IDs, not individual yanked packages.

Any new advisory must fail the gate unless it is added here with a specific
reason, an owning surface, and an exit condition.

## Current accepted exceptions

| Advisory | Tooling surface | Current owner | Why it is still present | Exit condition |
| --- | --- | --- | --- | --- |
| `core2@0.4.0` (yanked) | `cargo-audit root`, `cargo-deny` | optional Burn image/export chain | `burn-dataset 0.20.1` still reaches `core2 0.4.0` through `image 0.25.10 -> ravif 0.13.0 -> rav1e 0.8.1 -> bitstream-io 4.9.0`; no semver-compatible non-yanked replacement is available in the current graph | Upgrade or patch the Burn/image/ravif chain so the root lockfile no longer resolves `core2 0.4.0`, or fence that optional surface into a separate package/workspace |
| `RUSTSEC-2025-0141` (`bincode 2.0.1`) | `cargo-audit root`, `cargo-deny` | optional Burn model/runtime surface | `burn 0.20.1` still depends on `bincode 2.0.1`; no compatible patch release is available in the current graph | Upgrade Burn to a release that removes `bincode 2.0.1`, or fence the optional Burn surface behind a separate workspace/package |
| `RUSTSEC-2024-0388` (`derivative 2.2.0`) | `cargo-audit`, `cargo-deny` | `stwo` / Starknet finite-field chain | `stwo 2.2.0` transitively depends on `derivative 2.2.0` via `starknet-ff 0.3.7`; no compatible patch release is available | Upgrade the `stwo` / `starknet-ff` chain once a compatible maintained replacement lands |
| `RUSTSEC-2024-0436` (`paste 1.0.15`) | `cargo-audit`, `cargo-deny` | `ark-ff 0.5.0`, `ratatui 0.29.0`, MLIR/Burn support chain | Several transitive chains still pull `paste 1.0.15`; no compatible patch release is available without broader dependency churn | Upgrade the affected upstream chains or remove the optional surfaces that require them |
| `RUSTSEC-2026-0002` (`lru 0.12.5`) | `cargo-audit` | TUI surface via `ratatui 0.29.0` | `ratatui 0.29.0` still depends on `lru 0.12.5`; `cargo-deny` does not currently surface this advisory on this graph, so `cargo-audit` is the enforcement point | Migrate the TUI surface to a `ratatui` release that removes `lru 0.12.5` |
| `RUSTSEC-2026-0097` (`rand 0.8.5`) | `cargo-audit` | `stwo`, `tract-onnx`, `tch`, and `ark-*` transitive chains | The current graph still requires `rand 0.8.5` through multiple upstream stacks; `cargo-deny` does not currently surface this advisory on this graph, so `cargo-audit` is the enforcement point | Upgrade or patch the upstream stacks away from `rand 0.8.5` |

## Review rule

Before adding a new exception:

1. Try to remove the vulnerable crate with a compatible patch or manifest
   change.
2. If the advisory only affects an optional surface, prefer isolating or
   deleting that surface over widening the exception set.
3. If an exception is unavoidable, update this file, `deny.toml`, and
   `scripts/run_dependency_audit_suite.sh` together in the same PR.
