# Phase 25: Intervalized Carried-State Relation Spec

## Purpose

Phase 24 proves a full carried-state relation over an ordered list of cumulative
Phase 23 members, but the public artifact is still shaped around the cumulative
source relation object.

That is acceptable for verification.
It is not yet the clean folding input.

The folding layer should consume one explicit intervalized artifact whose public
surface is the ordered list of local interval relations, not the cumulative
Phase 23 prefix machinery that was only needed to derive them.

Phase 25 therefore introduces one explicit intervalization step.

## Core Goal

Given one verified Phase 24 decoding state-relation accumulator, derive and bind
one new artifact whose primary committed object is the ordered interval sequence
already implicit inside the nested cumulative Phase 23 members of that Phase 24
source artifact.

This phase is still pre-recursive.
It does not claim folded accumulation, recursive verification, proof compression,
or generic rebasing beyond the carried-state decoding relation already proven in
Phase 24.

## Claim Boundary

Let `R` be one verified Phase 24 decoding state-relation accumulator over
ordered cumulative Phase 23 members.
Let

```math
I_0, I_1, ..., I_{k-1}
```

be the interval summaries derived from those cumulative members by checked
subtraction and rebased boundaries.

Phase 25 should support this narrow claim:

1. the Phase 25 artifact preserves the same global start-state to end-state
   relation already proven by `R`,
2. its committed public surface is the ordered interval sequence
   `I_0, ..., I_{k-1}`,
3. each interval summary exposes one local `Sigma_from -> Sigma_to` relation with
   exact interval totals,
4. all interval totals are exact checked differences of the cumulative Phase 23
   source members embedded in the verified Phase 24 source artifact,
5. and any mismatch between the Phase 24 source relation and the derived
   intervalized view invalidates the artifact.

## Non-Claims

- not folded accumulation yet
- not recursive verification
- not proof compression
- not generic AIR/CCS rebasing
- not shared-table accumulation across unrelated templates
- not a benchmark claim against other zkML systems

## Why This Step Is Necessary

The failed folded-relation attempt exposed the exact problem:

- the repository already knew how to derive local interval summaries,
- but the proof-bearing artifact boundary still centered the cumulative source
  relation object,
- and the folding layer was at risk of consuming the wrong surface.

Without one explicit intervalized artifact, a later folded result could look
"green" while still binding the wrong intermediate object.

Phase 25 exists to make the interval view canonical before any folding claim is
reintroduced.

## Input Requirements

The Phase 25 constructor takes one verified Phase 24 relation accumulator with:

- `statement_version = statement-v1`,
- `proof_backend = stwo`,
- a non-empty `source_template_commitment`,
- a non-empty Phase 24 `relation_template_commitment`,
- a non-empty Phase 24 `relation_accumulator_commitment`,
- at least two ordered Phase 23 source members,
- and exact carried-state boundary continuity across the derived intervals.

## Output Artifact

The Phase 25 intervalized artifact contains:

- `artifact_version = stwo-phase25-intervalized-decoding-state-relation-v1`,
- `semantic_scope = stwo_execution_parameterized_intervalized_proof_carrying_decoding_state_relation`,
- `proof_backend = stwo`,
- `proof_backend_version`,
- `statement_version = statement-v1`,
- `member_count`,
- `source_template_commitment`,
- `source_relation_template_commitment`,
- `source_relation_accumulator_commitment`,
- `global_start_state_commitment`,
- `global_end_state_commitment`,
- `interval_template_commitment`,
- `interval_accumulator_commitment`,
- and one bounded ordered list of interval summaries derived from the verified
  Phase 24 source relation.

Each interval summary exposes:

- local interval `[t_i, u_i)`,
- local start-state commitment,
- local end-state commitment,
- exact interval step count,
- exact interval lookup-delta count,
- exact interval matrix/layout/rollup/segment counts,
- the shared source template commitment,
- and the cumulative Phase 23 lookup accumulator commitment from which that
  interval was derived.

## Derivation Rule

For ordered cumulative Phase 23 members `A_0, ..., A_{k-1}` inside one verified
Phase 24 source relation, derive interval summary `I_i` by:

```math
steps(I_i) = steps(A_i) - steps(A_{i-1})
counts(I_i) = counts(A_i) - counts(A_{i-1})
start(I_i) = boundary(A_i, steps(A_{i-1}))
end(I_i) = boundary(A_i, steps(A_i))
```

with `I_0` anchored at the Phase 24 global start boundary.

No interval may be accepted if any checked difference underflows, any interval
width is zero, or any rebased boundary fails to match the previous interval end.

The Phase 25 interval template is a new commitment.
It is derived from:

- the verified Phase 24 `source_relation_template_commitment`, and
- the exact ordered interval summaries derived from the nested cumulative Phase
  23 members.

Phase 25 does not claim that distinct top-level Phase 24 cumulative artifacts
share one literal relation-template commitment.
That stronger statement would be false for the current implementation because
the Phase 24 relation-template commitment already binds aggregate metadata such
as member counts and totals.

## Verifier Invariants

The Phase 25 verifier must reject unless all of the following hold:

- the embedded Phase 23 source members still re-derive a valid Phase 24 source
  relation,
- the derived interval summaries match the serialized Phase 25 member summaries
  exactly,
- the first interval start equals the global start commitment,
- the last interval end equals the global end commitment,
- interval totals reconstruct the Phase 24 source totals exactly,
- the serialized Phase 24 source relation commitments match the re-derived
  commitments,
- the interval template commitment matches the re-derived interval template,
- and the interval accumulator commitment matches the re-derived interval
  accumulator.

## MVP Theorem Target

The theorem-facing statement should be:

> Let `R` be a verified Phase 24 decoding state-relation accumulator. If the
> interval summaries derived from the cumulative Phase 23 members nested inside
> `R` are contiguous, positive-width, and boundary-consistent, then the Phase 25
> intervalized artifact preserves the same global decode relation as `R` while
> exposing an explicit ordered sequence of local interval relations suitable for
> later folding.

This is the theorem the later folding layer actually needs.

## Implementation Plan

1. Add a Phase 25 intervalized manifest type in
   `src/stwo_backend/decoding.rs`.
2. Reuse the checked Phase 24 interval-summary derivation as the Phase 25 source
   of truth.
3. Add `phase25_prepare_intervalized_decoding_state_relation(...)` over one
   verified Phase 24 source relation.
4. Add `verify_phase25_intervalized_decoding_state_relation(...)`.
5. Add save/load helpers and a CLI demo.
6. Keep folded-relation work paused until it consumes Phase 25 artifacts rather
   than the raw cumulative source object.

## Hardening Requirements

Required before merge:

- regressions for tampered source relation commitments,
- regressions for tampered interval commitments,
- regressions for mirrored interval-summary drift,
- fuzz coverage for load/verify on intervalized manifests,
- bounded Kani harnesses for checked-difference and adjacency invariants,
- explicit caps on member count and JSON size,
- and oracle checks for interval template and interval accumulator commitments.

## Exit Criteria

- one intervalized artifact verifies over at least two carried-state intervals,
- oracle and production commitments match,
- tamper tests cover both source-relation drift and interval-view drift,
- the artifact survives fuzz/load/verify and formal-kernel slices,
- and the later folded-relation work can consume the Phase 25 artifact instead
  of the raw cumulative Phase 24 source relation.
