# Phase 23: Cross-Step Lookup Accumulation Spec

## Purpose

Phase 23 is the first bridge from the current pre-recursive carried-state stack to a
real cross-step accumulation artifact.

The Phase 21 matrix accumulator proves that multiple Phase 17 rollup matrices can be
bound under one template-level merge artifact. Phase 22 lifts that boundary to the
lookup side by binding a verified lookup accumulator over one Phase 21 source object.

Phase 23 extends that line one step further:

- consume multiple verified Phase 22 manifests,
- require a shared decode template and shared lookup-template commitment,
- enforce adjacency across step intervals,
- emit one verifier-consumable artifact summarizing the full start-to-end lookup-side
  transition.

This phase is still pre-recursive. It does not claim cryptographic folding,
recursive compression, or generic accumulation for arbitrary AIR/CCS relations.

## Claim Boundary

Phase 23 is intended to support the following narrow claim:

> A sequence of contiguous `decoding_step_v2` windows that already verify under the
> current `statement-v1` relation can be accumulated into one explicit lookup-side
> boundary artifact without changing the underlying decode semantics.

This is a systems-and-relation claim, not a new proof-system claim.

Phase 23 does not claim:

- recursive aggregation,
- proof compression,
- generic AIR folding,
- generic CCS folding,
- shared-table accumulation across unrelated decode templates,
- full standard-softmax proving on S-two,
- or production benchmark superiority.

## Input Objects

Each Phase 23 input item is a Phase 22 decoding lookup-accumulator manifest `M_i`
that already satisfies:

- `verify_phase22_decoding_lookup_accumulator_with_proof_checks(M_i) = ok`,
- one `statement-v1` decode relation underneath the nested proof objects,
- a declared `source_template_commitment`,
- a declared `lookup_template_commitment`,
- a declared `lookup_accumulator_commitment`,
- carried lookup transcript/frontier commitments and counts,
- and a bounded nested Phase 21 source accumulator.

Phase 23 only accepts lists `[M_0, ..., M_{k-1}]` with `k >= 2`.

## Public Relation

We reuse the public decoding state from the proof-carrying decoding draft:

```math
\Sigma_t^{(\ell)} =
(\ell, p_t, C_t^{state}, C_t^{kv}, C_t^{kv,front}, n_t^{kv}, n_t^{kv,front},
 C_t^{look}, C_t^{look,front}, n_t^{look}, n_t^{look,front},
 C_t^{in}, C_t^{qry}, C_t^{out}, C_t^{row}).
```

Each Phase 22 manifest covers one contiguous window `[t_i, t_{i+1})` of the same
base decode relation

```math
\mathcal{R}_{decode}^{(\ell)}(\Sigma_t^{(\ell)}, w_t) \to \Sigma_{t+1}^{(\ell)}.
```

Phase 23 defines an accumulation relation

```math
\mathcal{A}_{23}(M_0, ..., M_{k-1}) \to B,
```

where `B` is valid only if:

1. every `M_i` verifies under Phase 22 proof checks,
2. all `M_i` share the same `source_template_commitment`,
3. all `M_i` share the same `lookup_template_commitment`,
4. consecutive manifests are contiguous at the carried-state boundary,
5. the accumulated counts equal the exact sum/max derived from the members,
6. and the accumulated boundary object exposes the first start-state and last
   end-state commitments needed for later recursive consumption.

## Contiguity Rules

Two consecutive manifests `M_i`, `M_{i+1}` are admissible only if the end boundary of
`M_i` matches the start boundary of `M_{i+1}` on the fields Phase 23 treats as
publicly bound carry-state.

The MVP should bind at least:

- decode template commitment,
- lookup template commitment,
- carried lookup transcript commitment,
- carried lookup transcript entry count,
- carried lookup frontier commitment,
- carried lookup frontier entry count,
- and the nested source-accumulator commitment chain needed to prove the windows
  were derived from a consistent Phase 21 family.

If the existing Phase 22 manifest does not yet expose every start/end boundary field
cleanly enough, the Phase 23 implementation should add explicit boundary summaries
rather than inferring them opaquely from nested structures at verification time.

## Output Artifact

The Phase 23 accumulator artifact `B` should contain:

- `version = stwo-phase23-decoding-cross-step-lookup-accumulator-v1`,
- `semantic_scope = stwo_execution_parameterized_proof_carrying_decoding_cross_step_lookup_accumulator`,
- `proof_backend = stwo`,
- `proof_backend_version`,
- `statement_version = statement-v1`,
- `member_count`,
- `total_steps`,
- `total_lookup_delta_entries`,
- `max_lookup_frontier_entries`,
- `source_template_commitment`,
- `lookup_template_commitment`,
- `start_boundary_commitment`,
- `end_boundary_commitment`,
- `accumulator_commitment`,
- and a bounded list of member descriptors or their commitments.

The output should be designed so a later recursive or folded layer can consume it
without re-parsing the full nested Phase 22 payloads.

## MVP Theorem Target

The MVP theorem statement for the later paper should be modest:

> If each member Phase 22 manifest preserves the same `statement-v1` decode relation
> over its covered window, and if adjacent member boundaries match on all publicly
> bound carried-state fields, then the Phase 23 accumulator preserves the same
> start-state to end-state relation as the concatenation of those member windows.

This is not a new cryptographic soundness theorem. It is a relation-preservation
lemma for the repository's carried-state packaging discipline.

## Non-Claims To Preserve In Code And Paper

The implementation and later paper draft should continue to say explicitly:

- current shared-table support is binding inside and across packaged objects, not
  yet cryptographic shared-table accumulation in the recursive sense,
- current Phase 21/22/23 merge boundaries are pre-recursive boundaries, not a
  finished recursion layer,
- the default frozen reproducibility tier remains separate from the experimental
  `stwo` carried-state path,
- and Phase 23 is transformer-shaped because it preserves decode-state and lookup
  boundaries, not because it proves full production transformer inference.

## Implementation Plan

1. Add a new manifest type and commitment helper in `src/stwo_backend/decoding.rs`.
2. Implement `phase23_prepare_cross_step_lookup_accumulator(...)` over a slice of
   verified Phase 22 manifests.
3. Implement `verify_phase23_cross_step_lookup_accumulator(...)`.
4. Implement `verify_phase23_cross_step_lookup_accumulator_with_proof_checks(...)`.
5. Add CLI commands for demo prove/verify paths.
6. Add a demo generator that packages at least two Phase 22 windows from the same
   decode family.

## Hardening Requirements

Phase 23 should not land without the same hardening stack now used on the trusted
validator core.

Required before merge:

- exact regression tests,
- tamper-path tests for every derived field,
- oracle/differential checks against a slow replay implementation,
- property tests for determinism and count preservation,
- fuzz targets for manifest load/verify,
- Kani harnesses for small bounded aggregation invariants,
- and explicit byte/member-count limits on untrusted inputs.

## Evaluation Plan

The evaluation should remain internal and controlled.

Compare three paths on the same demo family:

1. flat Phase 22 members,
2. chained Phase 22 verification,
3. one Phase 23 cross-step accumulator.

Report:

- prover time,
- verifier time,
- JSON artifact size,
- total bound steps,
- lookup-delta entries,
- max frontier size,
- and marginal cost per additional member.

The first benchmark family should stay narrow:

- `decoding_step_v2`,
- `gemma_block_v4`-compatible lookup/state shape where relevant,
- and one fixed-shape carried-state family with at least two windows.

## Stop Condition

Phase 23 is complete when the repository can generate and verify one commit-pinned,
reviewed artifact over multiple contiguous Phase 22 windows and the artifact can be
summarized in one appendix-ready table without overclaiming recursion or folding.
