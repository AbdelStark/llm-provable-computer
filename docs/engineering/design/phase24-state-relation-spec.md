# Phase 24: Carried-State Relation Accumulator Spec

## Purpose

Phase 24 is the first post-Phase-23 step that should carry theorem weight.

Phase 23 already proves something useful: multiple contiguous Phase 22 windows can
be accumulated into one pre-recursive lookup-side artifact with exact boundary and
count preservation. That was the right systems milestone.

But Phase 23 still leaves the central theorem-facing gap open:

- it accumulates lookup-side structure,
- it checks carried-state boundary compatibility,
- but it does not yet expose one explicit relation object stating that the full
  decode state moved from `Sigma_t` to `Sigma_u` under the unchanged
  `statement-v1` semantics.

Phase 24 should close that gap.

## Core Goal

Define one accumulator artifact that consumes verified contiguous Phase 23 members
and emits a single relation-level object

```math
R_{24}(Sigma_t, Sigma_u)
```

with enough public structure to support the following later claims:

1. concatenation of valid Phase 23 windows preserves the same decode relation as
   flat execution over the covered interval,
2. the carried KV / lookup / public-state commitments remain consistent across the
   whole interval,
3. and a later recursive or folded layer can consume one compact relation summary
   rather than re-opening every nested Phase 23 member.

This is still pre-recursive. It is not yet folding, recursive compression, or a
new proof system.

## Claim Boundary

Phase 24 should support this narrow claim:

> If a sequence of contiguous Phase 23 accumulators all preserve the same
> `statement-v1` decode relation over adjacent intervals, then Phase 24 preserves
> the same start-state to end-state decode relation over the concatenated interval
> while exposing one explicit carried-state relation certificate.

Phase 24 does **not** claim:

- recursive aggregation,
- proof compression,
- generic AIR or CCS folding,
- full transformer-block accumulation,
- shared-table recursive reuse,
- or production proving superiority.

## Why This Is The Right Next Step

The current repository now has:

- Phase 21 matrix accumulation,
- Phase 22 lookup accumulation,
- Phase 23 cross-step lookup accumulation,
- parameterized carried-state decoding,
- and hardening around the trusted validator surface.

The next missing piece is therefore not another packaging layer. It is the first
artifact whose meaning is directly theorem-shaped:

- one explicit state relation,
- one interval,
- one preserved semantic claim.

That is the bridge from "accumulation artifact" to "relation-preservation lemma".

## Input Objects

Each Phase 24 input member is a verified Phase 23 manifest `A_i` such that:

- `verify_phase23_decoding_cross_step_lookup_accumulator_with_proof_checks(A_i) = ok`,
- all members use the same `statement_version = statement-v1`,
- all members share the same decode template family,
- all members are ordered by strictly increasing covered step interval,
- and adjacent members are contiguous at the full carried-state boundary.

Phase 24 should require at least `k >= 2` members.

## Public Decode Relation

Reuse the proof-carrying decoding public state notation:

```math
Sigma_t = (
  p_t,
  C_t^{state},
  C_t^{kv}, C_t^{kv,front}, n_t^{kv}, n_t^{kv,front},
  C_t^{look}, C_t^{look,front}, n_t^{look}, n_t^{look,front},
  C_t^{cache},
  C_t^{in}, C_t^{qry}, C_t^{out}, C_t^{row},
  C^{layout}
).
```

Phase 24 should treat the following as explicitly bound public relation fields:

- layout/template commitment,
- persistent/public state commitment,
- KV history commitment and counters,
- KV frontier commitment and counters,
- lookup transcript commitment and counters,
- lookup frontier commitment and counters,
- KV cache commitment,
- decode position / step index,
- and the input/query/output/lookup-row commitments already used in the carried
  decoding relation.

This is intentionally broader than Phase 23's lookup-side accumulation surface.

## Contiguity Rule

Two adjacent members `A_i`, `A_{i+1}` are admissible only if:

```math
end(A_i) = start(A_{i+1})
```

on **all** publicly bound Phase 24 relation fields, not just the lookup-side
subset.

In other words, Phase 24 must bind the full carried decode-state boundary, not a
projection that could allow silent drift in KV/cache/public-state fields.

## Output Artifact

The Phase 24 artifact `R` should contain at minimum:

- `version = stwo-phase24-decoding-state-relation-accumulator-v1`,
- `semantic_scope = stwo_execution_parameterized_proof_carrying_decoding_state_relation_accumulator`,
- `proof_backend = stwo`,
- `proof_backend_version`,
- `statement_version = statement-v1`,
- `member_count`,
- `total_steps`,
- `source_template_commitment`,
- `start_state_commitment`,
- `end_state_commitment`,
- `relation_template_commitment`,
- `relation_accumulator_commitment`,
- and a bounded list of member summaries or commitments.

The output should be small enough that later recursive consumption can treat it as
one relation node instead of one unpacked artifact tree.

## Proposed Internal Structure

Each member summary should expose:

- covered step interval `[t_i, u_i)`,
- start-state commitment,
- end-state commitment,
- lookup-side accumulator commitment,
- full carried-state boundary commitment,
- and exact derived counts used in the accumulator commitment.

The relation accumulator commitment should hash:

- version + semantic scope,
- template commitment,
- ordered member interval summaries,
- exact total step count,
- first start-state commitment,
- last end-state commitment,
- and exact preserved max/sum counters.

## MVP Theorem Target

The Phase 24 paper-facing lemma should be stated roughly as:

> Let `A_0, ..., A_{k-1}` be verified contiguous Phase 23 accumulators over one
> fixed decode template and one unchanged `statement-v1` relation. If the end
> boundary of `A_i` equals the start boundary of `A_{i+1}` on all publicly bound
> carried-state fields, then the Phase 24 accumulator preserves the same decode
> relation from the start state of `A_0` to the end state of `A_{k-1}` as the flat
> concatenation of the underlying decoding windows.

This is the first theorem-ready statement that matters for the breakthrough path.

## Implementation Plan

1. Add a Phase 24 manifest type in `src/stwo_backend/decoding.rs`.
2. Define one full-state commitment helper for the public carried decode state.
3. Add `phase24_prepare_decoding_state_relation_accumulator(...)` over verified
   Phase 23 inputs.
4. Add `verify_phase24_decoding_state_relation_accumulator(...)`.
5. Add `verify_phase24_decoding_state_relation_accumulator_with_proof_checks(...)`.
6. Add a small demo generator consuming at least two contiguous Phase 23 members.
7. Expose prove/verify CLI commands.

## Hardening Requirements

Phase 24 should inherit the same validator discipline now required on the trusted
core.

Required before merge:

- exact regression tests for interval concatenation,
- negative tests for every derived boundary and count field,
- oracle/differential checks against a slow concatenation replay,
- property tests for determinism and interval preservation,
- fuzz coverage for manifest load/verify,
- bounded Kani harnesses for adjacency and count invariants,
- and explicit byte/member-count caps for untrusted inputs.

## Evaluation Plan

Keep the first evaluation controlled and internal.

Compare:

1. flat carried decoding windows,
2. Phase 23 lookup accumulation,
3. Phase 24 full-state relation accumulation.

Report:

- verifier time,
- JSON artifact size,
- total steps covered,
- exact boundary fields bound,
- marginal size/cost per additional member,
- and whether the relation artifact can replace unpacked nested verification in
  downstream consumers.

## Paper Impact

If implemented cleanly, Phase 24 becomes the first real theorem-bearing systems
bridge in the line of work.

The narrative progression becomes:

1. architecture thesis,
2. carried-state decoding,
3. lookup-side accumulation,
4. full-state relation accumulation,
5. only then recursive compression / folding.

That is a much stronger breakthrough trajectory than adding more bundle or appendix
material.

## Stop Condition

Phase 24 is complete when the repository can generate and verify one commit-pinned
artifact that explicitly binds a full carried decode-state relation across multiple
Phase 23 members and the repository can state one narrow, defensible
relation-preservation lemma over that artifact without claiming recursion or
folding.
