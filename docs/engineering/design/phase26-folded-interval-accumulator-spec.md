# Phase 26: Folded Intervalized Decoding State-Relation Accumulator Spec

## Goal

Lift the honest Phase 25 intervalized carried-state relation into the first true folded accumulator over real carried-state intervals.

## Scope

This phase is still pre-recursive. It does not introduce recursive verification or cryptographic compression. It folds verified Phase 25 interval artifacts into one carried-state boundary claim and one bounded fold transcript.

## Claim Boundary

Given an ordered sequence of contiguous Phase 25 intervalized decoding state-relation artifacts that:
- share the same source decoding template commitment
- preserve carried-state boundary continuity
- verify individually under the shipped Phase 25 verifier

Phase 26 produces a folded intervalized accumulator whose verifier preserves:
- identical global start-state commitment
- identical global end-state commitment
- identical total step count
- identical lookup-delta count
- identical source template commitment
- explicit member interval-template commitments and interval-accumulator commitments

## Non-Claims

- not recursive verification
- not proof compression
- not generic AIR/CCS folding
- not cross-family accumulation across different source decoding templates
- not full transformer proving beyond the shipped fixed-shape carried-state path

## Required Inputs

- ordered Phase 25 intervalized decoding state-relation artifacts
- shared source template commitment
- shared statement/proof-backend version
- bounded fold arity metadata

## Verifier Invariants

- fold members are contiguous in public step intervals
- fold members are contiguous in carried-state boundaries
- every member shares the same source template commitment
- every member interval template commitment is bound into the fold template
- folded totals equal the checked sum of member totals
- folded start equals the first member start
- folded end equals the last member end
- tampering any member interval accumulator, boundary, interval template, or total invalidates the fold

## Deliverables

- manifest schema and Phase 26 version constant
- prepare/save/load/verify helpers in `src/stwo_backend/decoding.rs`
- CLI prove/verify demo over multiple real Phase 25 interval members
- oracle commitment helpers
- tamper tests, CLI tests, fuzz target, and bounded Kani harnesses
- one frozen evaluation bundle comparing Phase 24, Phase 25, and Phase 26 carried-state artifacts

## Exit Criteria

- one folded artifact verifies over at least two contiguous Phase 25 interval members
- oracle and production commitments match
- differential tamper tests cover fold-template, accumulator, boundary, and total-count drift
- fuzz smoke and Kani harnesses pass
- one frozen artifact bundle is generated from the merged Phase 25 interval model, not the obsolete cumulative-prefix model
