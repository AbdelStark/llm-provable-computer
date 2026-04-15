# Phase 28 Proof-Carrying Aggregation over Chained Folded Interval Artifacts

## Goal

Phase 28 lifts the carried-state artifact ladder above Phase 27 by aggregating multiple fully materialized Phase 27 chained folded interval artifacts into one proof-carrying outer statement.

The object proved here is:

- a bounded ordered list of **Phase 27 chained folded intervalized artifacts**,
- where each Phase 27 member already preserves carried-state continuity across its own nested Phase 26 folds,
- and the Phase 28 outer aggregation preserves the same carried-state continuity across the boundaries between those Phase 27 members.

This is still **not recursive verification** and **not cryptographic compression**.
It is a proof-carrying outer aggregation layer that is honest about replaying verification of nested members.

The manifest makes that posture explicit:

- `recursion_posture` defaults to `pre-recursive-proof-carrying-aggregation`,
- `recursive_verification_claimed` defaults to `false`,
- `cryptographic_compression_claimed` defaults to `false`.

The public verifier rejects any Phase 28 manifest where the effective
`recursion_posture` after deserialization is not
`pre-recursive-proof-carrying-aggregation`, or where either claim bit is set to
`true`. Older Phase 28 artifacts that omit these fields still deserialize to the
same pre-recursive posture.
When a `recursion_posture` field is present, deserialization also rejects values
larger than `128` bytes before the verifier compares the posture value or claim
bits; this keeps oversized untrusted posture strings out of verifier error
paths.

## Inputs

Each Phase 28 member is a fully materialized:

- `Phase27ChainedFoldedIntervalizedDecodingStateRelationManifest`

Every nested Phase 27 member must already satisfy:

- valid `stwo` backend / statement headers,
- valid chain template commitment,
- valid chained accumulator commitment,
- contiguous step range semantics,
- carried-state continuity across its nested Phase 26 members.

## Public Statement

The Phase 28 manifest asserts:

- all nested Phase 27 members share one `source_template_commitment`,
- the first Phase 27 member begins at global step `0`,
- later Phase 27 members begin exactly where the previous member ends,
- later Phase 27 members reuse the previous member's `global_end_state_commitment` as their `global_start_state_commitment`,
- aggregate totals are the exact sums/maxima derived from the nested members,
- the outer `aggregation_template_commitment` is recomputed from the ordered public summaries,
- the outer `aggregated_chained_folded_interval_accumulator_commitment` is recomputed from the entire derived public statement.

## Honest Semantics

Phase 28 does **not** claim recursion.
It aggregates only:

1. honest Phase 25 intervals,
2. Phase 26 folds built from those intervals,
3. Phase 27 chains built from those folds,
4. one Phase 28 outer aggregation built from those already-verified Phase 27 chains.

So the carried-state boundary exposed at the Phase 28 level is still anchored in real contiguous interval evidence, just across multiple chained bundles instead of one bundle.

The guard implementing these anti-overclaiming rejection criteria is
intentionally shallow: it runs before nested Phase 27 proof walks and before the
expensive proof-checking mode. This keeps a bad artifact from spending verifier
resources after it has already claimed a recursive or compressed proof posture
that Phase 28 does not implement.

## Demo Construction

The current demo path is intentionally simple and bounded:

1. generate `16` proving-safe decoding proofs for one layout,
2. derive cumulative Phase 23 members from prefixes `1..=16`,
3. accumulate them into one Phase 24 carried-state relation source,
4. partition that Phase 24 source into `8` contiguous Phase 25 interval members using chunk size `2`,
5. partition those into `4` Phase 26 folded members using fold arity `2`,
6. partition those into `2` Phase 27 chained members using chain arity `2`,
7. aggregate those `2` Phase 27 members into one Phase 28 manifest.

This gives a real cross-bundle proof-carrying aggregation over honest carried-state intervals, not a relabeled single-chain demo.

## Hardening Expectations

Phase 28 should ship only with:

- proof-bearing verification of every nested Phase 27 member,
- shallow header fast-fail before nested walks,
- tamper regressions for:
  - outer aggregation template commitment,
  - outer aggregated accumulator commitment,
  - aggregate counters,
  - member ordering / carried-state continuity,
- load/save round-trips, including gzip input,
- fuzz coverage on the outer deserializer/verifier path,
- Kani scalar harnesses for aggregation-shape invariants,
- frozen evaluation bundle generation.

The default unit hardening path uses synthetic Phase 27 member summaries to test
the Phase 28 aggregation contract directly. The full CLI path remains an
explicit ignored end-to-end gate because it generates and verifies the live
16-proof Phase 24 -> Phase 28 demo and is too expensive for the fast default
test cycle.

## Non-Goals

Phase 28 does not claim:

- recursive verification,
- recursive proof aggregation,
- cryptographic accumulation compression,
- on-chain verification of the aggregated object.

Those remain future steps after the proof-carrying outer aggregation layer.
