# Appendix A. Claim Boundary

This appendix makes the positive and negative claim surfaces explicit.

## A1. Positive claim surface

The paper claims only the following:

| Surface | Honest claim |
| --- | --- |
| Step and chain artifacts | Verified step-bearing artifacts expose a fixed public statement surface and compose into ordered decode chains. |
| Carried-state boundaries | Public carried-state tuples bind execution, KV, and lookup continuity across ordered members. |
| Packaging layers | Chain, segment, interval, rollup, matrix, and pre-recursive aggregation layers preserve the same decode semantics when their validity conditions hold. |
| Semantic-agreement artifacts | Bounded multi-runtime relation evidence reduces the risk of silently assuming frontend/runtime semantic identity. |
| Provenance manifests | Release manifests bind local file identities and pinned release coordinates for reproducibility. |

## A2. Negative claim surface

The paper does not claim:

| Surface | Explicit non-claim |
| --- | --- |
| Recursive proof systems | No recursive proof-carrying data, no verifier-closed recursion, no folding theorem. |
| IVC/PCD semantics | No formal IVC or PCD construction in the sense of the recursive literature. |
| Shared-table recursion | No recursive shared-table accumulation as a compressed proof object. |
| General equivalence proving | No general SMT/e-graph/compiler equivalence theorem. |
| Supply-chain theorems | No complete provenance-attestation theorem for exporter or build systems. |
| Full `stwo` transformer proving | No claim of full standard-softmax transformer inference proving on the current `stwo` path. |

## A3. Why this boundary is sufficient

The paper is worthwhile because the repository already stabilizes the public
statement that later recursive work would need to preserve. That is a meaningful
intermediate result even though the recursive layer is not yet implemented.
