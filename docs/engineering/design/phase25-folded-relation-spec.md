# Phase 25: Folded Decoding State-Relation Accumulator Spec

## Goal
Lift the Phase 24 state-relation accumulator from a verifiable interval summary into a folded relation object that preserves one public `Sigma_start -> Sigma_end` claim while amortizing repeated interval structure.

## Scope
This phase is still pre-recursive. It does not introduce recursive proof verification or cryptographic compression. It introduces a foldable relation transcript and verifier semantics that can later be consumed by a recursive backend.

## Claim Boundary
Given a sequence of contiguous Phase 24 state-relation accumulators sharing a fixed relation template and fixed carried-state discipline, Phase 25 produces a folded relation accumulator whose verifier preserves:
- identical global start-state commitment
- identical global end-state commitment
- identical total step count
- identical lookup-delta count
- identical template commitment

## Non-Claims
- not recursive verification
- not proof compression
- not generic AIR/CCS folding
- not cross-template accumulation
- not full standard-softmax transformer proving

## Required Inputs
- ordered Phase 24 relation accumulators
- shared relation template commitment
- shared carried-state statement version
- bounded fold arity metadata

## Verifier Invariants
- fold members are contiguous in carried-state boundaries
- every member binds the same relation template commitment
- folded totals equal the checked sum of member totals
- folded start equals first member start
- folded end equals last member end
- tampering any member commitment, interval total, or boundary invalidates the fold

## Deliverables
- manifest schema and version constant
- prepare/save/load/verify helpers in `src/stwo_backend/decoding.rs`
- CLI prove/verify demo
- oracle commitment helpers
- tamper tests, CLI tests, fuzz target, and bounded Kani harnesses
- one evaluation bundle comparing Phase 24 interval accumulation vs Phase 25 folded accumulation metadata

## Exit Criteria
- one folded artifact verifies over at least two contiguous Phase 24 members
- oracle and production commitments match
- differential tamper tests cover member-commitment, boundary, and total-count drift
- fuzz smoke and Kani harnesses pass
