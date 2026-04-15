# Phase 27 Chained Folded Intervalized Decoding State Relation

## Goal

Phase 27 lifts the carried-state artifact ladder one step higher than Phase 26 without pretending that recursion or cryptographic compression already exist.

The object proved here is:

- a **bounded chain of Phase 26 folded interval artifacts**,
- where each Phase 26 member already summarizes a contiguous set of honest Phase 25 intervals,
- and the Phase 27 chain preserves the same carried-state continuity at the boundaries between Phase 26 members.

This is still a **pre-recursive** artifact.
It is not recursive verification, recursive accumulation, or proof compression.

## Inputs

Each Phase 27 member is a fully materialized:

- `Phase26FoldedIntervalizedDecodingStateRelationManifest`

Every nested Phase 26 member must already satisfy:

- valid `stwo` backend / statement headers,
- valid fold template commitment,
- valid folded interval accumulator commitment,
- contiguous step range semantics,
- carried-state continuity inside the Phase 26 fold.

## Public Statement

The Phase 27 manifest asserts:

- all nested Phase 26 members share one `source_template_commitment`,
- the first Phase 26 member begins at global step `0`,
- later Phase 26 members begin exactly where the previous member ends,
- later Phase 26 members reuse the previous member's `global_end_state_commitment` as their `global_start_state_commitment`,
- aggregate totals are the exact sums/maxima derived from the nested members,
- the outer `chain_template_commitment` is recomputed from the ordered public summaries,
- the outer `chained_folded_interval_accumulator_commitment` is recomputed from the entire derived public statement.

## Honest Semantics

Phase 27 does **not** fold arbitrary prefixes.
It chains only:

1. Phase 25 intervalized members derived from rebased cumulative prefixes,
2. Phase 26 folds built from those honest intervals,
3. Phase 27 chained members built from those honest Phase 26 folds.

So the carried-state boundary exposed at the Phase 27 level is still anchored in real contiguous interval evidence.

## Demo Construction

The current demo path is intentionally simple and bounded:

1. generate `8` proving-safe decoding proofs for one layout,
2. derive cumulative Phase 23 members from prefixes `1..=8`,
3. partition them into `4` contiguous Phase 25 interval members using chunk size `2`,
4. partition those into `2` Phase 26 folded members using fold arity `2`,
5. chain those `2` Phase 26 members into one Phase 27 manifest.

This gives a true fold-of-folds artifact over real carried-state intervals, not a synthetic wrapper.

## Hardening Expectations

Phase 27 should ship only with:

- proof-bearing verification of every nested Phase 26 member,
- shallow header fast-fail before nested walks,
- tamper regressions for:
  - outer chain template commitment,
  - outer chained accumulator commitment,
  - aggregate counters,
  - member ordering / carried-state continuity,
- load/save round-trips, including gzip input,
- fuzz coverage on the outer deserializer/verifier path,
- Kani scalar harnesses for chain-shape invariants,
- frozen evaluation bundle generation.

## Non-Goals

Phase 27 does not claim:

- recursive verification,
- recursive proof aggregation,
- cryptographic accumulation compression,
- on-chain verification of the chained object.

Those remain future steps after the pre-recursive chained artifact layer.
