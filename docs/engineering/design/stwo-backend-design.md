# S-two Backend Design

## Goal

Harden and widen the existing experimental S-two / STWO proving backend in
`provable-transformer-vm` without breaking the current `statement-v1` claim contract or the
existing vanilla STARK path.

The design target remains conservative:

- preserve current semantics and claim scope,
- isolate proving-backend concerns behind an explicit abstraction,
- widen the proved S-two surface only when the claim boundary stays honest, and
- treat recursion as a later compression layer, not a substitute for backend correctness.

## Why this document exists

The paper at `docs/paper/stark-transformer-alignment-2026.md` argues that S-two recursion and
M31-native proving strengthen the architectural case for STARK-native verifiable AI. The repo no
longer treats S-two as purely prospective: it already exposes a narrow experimental backend,
shared-table lookup demos, fixed-shape Gemma-inspired fixtures, and a proof-carrying decoding
demo. The remaining problem is therefore not “backend yes or no,” but how to widen that proved
surface without drifting the statement semantics.

This document records the design boundary for that widening work.

## Current state

Today the repository has the following `stwo` properties:

- proof generation is still orchestrated from `src/proof.rs`,
- the default reproducibility bundle and primary transformer proof relation remain on the local
  vanilla backend,
- `--features stwo-backend` enables an experimental S-two path under the same `statement-v1`
  semantic claim,
- the experimental S-two path publicly proves a shipped fixture set including arithmetic programs,
  `gemma_block_v1` through `gemma_block_v4`, the fixed-shape `decoding_step_v1` family, and the
  parameterized `decoding_step_v2` family used by the proof-carrying decoding demos,
- dedicated lookup and normalization demos exist both in single-row and shared-table multi-claim
  forms,
- proof-carrying decoding now includes both a fixed-shape `decoding_step_v1` chain and a
  parameterized `decoding_step_v2` chain with layout-bound carried-state commitments, cumulative
  KV-history commitments, rolling KV-cache windows, and explicit position metadata,
- a Phase 13 layout-matrix demo now proves and verifies several `decoding_step_v2` layouts under
  one matrix manifest, and
- recursion work currently stops at canonical batch manifests and compatibility checks rather than
  recursive proving.

This means the migration problem is no longer “swap one prover crate for another.” The repo now
already couples:

- witness generation,
- AIR shape,
- proof serialization,
- verifier claim logic,
- backend-version compatibility checks,
- embedded lookup proof envelopes,
- and carried-state decoding metadata.

## Non-goals for the current widening milestone

The next S-two milestone should not try to solve all of the following at once:

- full standard-softmax proving,
- recursive aggregation,
- onchain verification,
- learned or trained weights,
- zero-knowledge hiding,
- or complete ISA proof coverage.

Trying to do all of those together would turn the backend into an unbounded rewrite and make the
claim boundary impossible to defend.

## Design principles

### 1. Preserve statement semantics first

`statement-v1` is still the user-visible proof contract. The S-two path must preserve:

- claim fields,
- semantic scope,
- lockstep verification behavior,
- and output digest structure where possible.

If proof bytes or backend metadata differ, that is acceptable. If the semantic statement changes,
that is a `statement-v2` problem and should be treated separately.

### 2. Separate backend from witness extraction

Trace construction and semantic checks should happen once, while proof generation varies by
backend. The original backend-abstraction shape is still the right mental model:

```rust
pub trait ProofBackend {
    type Proof;
    type VerifyParams;

    fn backend_name(&self) -> &'static str;
    fn prove(&self, witness: &ProofWitness, params: &ProofParams) -> Result<Self::Proof>;
    fn verify(
        &self,
        proof: &Self::Proof,
        claim: &ProofClaim,
        params: &Self::VerifyParams,
    ) -> Result<()>;
}
```

The widening work should continue to keep:

- semantic execution and witness extraction,
- claim assembly,
- backend-specific proving,
- and backend-specific verification

as separate concerns.

### 3. Keep vanilla STARK as a reference backend

Do not remove or degrade the current vanilla backend while hardening S-two. It still serves as:

- the correctness oracle for migration,
- the fallback local backend,
- the bundle used by the primary frozen reproducibility tier, and
- the easiest place to spot statement drift.

## Statused roadmap

### Phase 0: Backend abstraction refactor `[implemented]`

Delivered:

- backend selection on the CLI,
- backend-tagged proof metadata,
- default backend remains `vanilla`,
- no semantic fork away from `statement-v1`.

### Phase 1: S-two arithmetic-subset proving `[implemented narrowly]`

Delivered:

- experimental `stwo` feature flag,
- proof generation and verification for the shipped arithmetic fixture set,
- explicit backend fingerprints and backend-version metadata,
- deterministic rejection outside the public proved family.

Current limitation:

- broader arithmetic-subset AIR coverage exists in code, but public end-to-end proving remains
  intentionally narrower than that internal coverage.

### Phase 2: AIR parity and unsupported-op inventory `[implemented partially]`

Delivered:

- backend-specific shape validation,
- internal constraint coverage for the broader arithmetic subset,
- explicit public rejection for unsupported execution-proof shapes.

Still missing:

- a publication-facing opcode coverage matrix that cleanly separates
  “internal AIR coverage” from “publicly frozen proving coverage.”

### Phase 3: Lookup-backed nonlinearity path `[implemented narrowly]`

Delivered:

- bounded activation demo proofs,
- normalization demo proofs,
- shared-table lookup demos,
- embedded lookup proof envelopes inside `gemma_block_v2` through `gemma_block_v4`.

Current limitation:

- lookup-backed nonlinearities are still fixed-shape or demo-scoped rather than a general
  transformer relation with standard softmax.

### Phase 4: Transformer-shaped fixed fixtures and decoding `[implemented narrowly]`

Delivered:

- `gemma_block_v1` through `gemma_block_v4`,
- embedded normalization and bounded activation proofs in the top-level S-two payload,
- proof-carrying decoding over a fixed three-step `decoding_step_v1` chain with carried-state
  commitments,
- proof-carrying decoding over a parameterized `decoding_step_v2` family with layout-bound
  carried-state commitments and cumulative KV-history commitments,
- a chunked-history carried-state variant over the same `decoding_step_v2` proofs, separating
  sealed history chunks from the open chunk to make later accumulation boundaries explicit,
- a segment-bundle layer over those Phase 14 chunked-history chains, carrying explicit global
  boundary states so later accumulation work can consume mergeable decoding segments without
  pretending recursion already exists,
- a Phase 16 rollup layer over Phase 15 segment bundles, carrying larger global boundary units so
  later accumulation work can consume mergeable groups of segments instead of one flat bundle,
- a Phase 17 layout-matrix layer over those Phase 16 rollups, proving that the higher-level
  carried-state packaging survives multiple public `decoding_step_v2` layouts as well,
- a Phase 18 frontier-boundary refinement over the same chunked-history/segment/rollup stack,
  tying the carried history suffix explicitly to the live rolling KV-cache commitment seen by
  each decoding step,
- a Phase 19 lookup-transcript layer over that same stack, preserving a committed non-arithmetic
  trace across chunked-history chains, segment bundles, rollups, and rollup matrices,
- a Phase 20 lookup-frontier layer over that same stack, preserving a recent non-arithmetic
  window alongside the cumulative lookup transcript so later accumulation work has a cleaner
  lookup boundary to consume, and binding that lookup state back to the embedded shared
  normalization / activation claims already carried inside each `decoding_step_v2` proof payload,
  with the current transition now reading both shared normalization scale rows and both shared
  activation output rows inside the executed `decoding_step_v2` program instead of treating those
  lookup rows as write-only metadata, feeding bounded lookup-backed values into the latest carried
  KV-cache pair on the public demo layouts, with three carried lanes now bound to the combined
  output cell and one to the lookup-backed primary output on the wider layouts, with that
  combined-output cell now also absorbing two additional bounded shared lookup rows before it is
  carried forward, with both final output lanes absorbing that combined-output cell, and with a
  shared-lookup registry boundary at Phase 12+ where each manifest deduplicates shared lookup
  artifacts into a registry and decoding steps reference those artifacts by commitment rather than
  inlining them, so the extra bounded shared lookup rows consumed by the combined-output cell and
  lookup-backed primary output are represented once at the manifest layer and then rebound to each
  proof payload during verification, with exact tests plus real-backend proving coverage over all
  default demo steps and the default layout matrix, and
- a Phase 21 matrix-accumulator layer over Phase 17 rollup matrices, requiring a shared template
  commitment and carrying an explicit accumulator commitment so repeated-layout matrix batches can
  be verified as one bounded merge artifact before recursion.

Current limitation:

- the decoding path is still a bounded research family with fixed demo layouts rather than a
  broader transformer decode relation.

### Phase 5: Broaden the proved S-two relation `[next]`

This is now the highest-leverage next milestone.

Targets:

- broaden the parameterized decode-step family beyond the current demo layouts,
- move from the current frontier-aware KV-cache/history boundary plus lookup-transcript/lookup-frontier layer to a
  more reusable merge interface,
- move one transformer-relevant non-arithmetic path from transcript-level carried state deeper
  into the main proved relation,
- keep the same `statement-v1` claim boundary until a real semantic change forces `statement-v2`.

The new Phase 13 layout-matrix demo, now covered by real-backend proving regressions across the
default layout matrix, plus the Phase 14 chunked-history chain, Phase 15 segmented-history
bundle, Phase 16 rollup layer, Phase 17 rollup-matrix layer, and Phase 18 frontier-boundary
refinement, Phase 19 lookup-transcript layer, Phase 20 lookup-frontier layer, and the new
Phase 21 matrix-accumulator layer are the first steps on that path: they prove that the
parameterized relation survives multiple public layouts and progressively more mergeable
carried-state boundaries without changing the semantic contract.

### Phase 6: Recursive compression and aggregation `[later]`

Recursion only becomes the right next step once there is more than one meaningful S-two proof
family worth aggregating.

Targets:

- aggregate frozen S-two artifacts rather than ad hoc local proofs,
- compress proof bundles for appendix-ready or onchain-friendlier outputs,
- prepare for a future Starknet-facing verification story without overstating current repo status.

## Serialization and claim compatibility

Proof outputs should continue to add backend metadata while preserving semantic claim fields.

Required metadata:

- `proof_backend: vanilla | stwo`
- `proof_backend_version`
- `backend_fingerprint`

These fields belong in `ExecutionClaimCommitments`, not as new semantic fields on
`VanillaStarkExecutionClaim`. They are proof-artifact metadata, not new statement semantics.

Because these additions do not change the meaning of the claimed computation, they are
backward-compatible commitment metadata only. They should continue to use `#[serde(default)]`
compatibility where needed and do **not** require forking to `statement-v2`.

Reserve `statement-v2` for material semantic changes such as:

- changing the meaning of `VanillaStarkExecutionClaim`,
- altering required semantic fields,
- widening the proved relation beyond the current `statement-v1` scope,
- or making carried-state decoding fields first-class semantic statement components.

## Testing strategy

### Golden-path parity tests

For each frozen S-two artifact family:

- run transformer/native lockstep where applicable,
- prove with `vanilla` when a vanilla analogue exists,
- prove with `stwo`,
- verify both,
- compare final semantic outputs and claim digests where the statements are comparable.

### Negative tests

For unsupported or mismatched shapes:

- softmax path,
- unsupported instructions,
- backend-version/program-family mismatches,
- tampered lookup rows,
- tampered carried-state commitments,

assert that backend rejection is explicit and stable.

### Artifact tests

Generate backend-tagged reproducibility metadata:

- benchmark TSVs,
- artifact hashes,
- backend fingerprints,
- command logs,
- bundle manifests.

The publication-facing `stwo` tier should stay reproducible the same way the vanilla
`production-v1` tier is reproducible.

## Risks

### Risk 1: AIR mismatch

The current vanilla AIR and an S-two-compatible AIR do not need to line up internally. Preserve
claim semantics and accept backend-specific trace shape where necessary.

### Risk 2: Statement drift

The easiest mistake is letting an experimental S-two path silently widen or alter the semantic
statement. Guard against this with explicit statement-version and backend-version checks.

### Risk 3: Premature recursion work

Recursion is attractive because StarkWare’s public recursion story is now much stronger, but
adding it before the proved S-two relation is broad enough would still produce architecture
theater rather than real progress.

## Recommended implementation order

1. keep the current frozen S-two bundle reproducible,
2. widen the decode-step family without changing the semantic claim,
3. improve KV-cache and non-arithmetic commitment discipline beyond the current cumulative-history, chunked-history, segmented-boundary, frontier-boundary, lookup-transcript, and lookup-frontier layout,
4. move a more faithful non-arithmetic attention path into the main proved relation,
5. only then bind to recursive aggregation work.

## Definition of success

The next meaningful success condition is not “recursive proof on Starknet.”

It is this:

> The same `statement-v1` claim family can be proved on the current narrow experimental S-two path
> for a transformer-shaped fixed fixture and a proof-carrying decoding transition, while preserving
> verifier-side lockstep semantics and explicit carried-state integrity.

Once that exists for a broader family than the current fixed fixtures, the recursion and
aggregation roadmap becomes technically serious rather than aspirational.
