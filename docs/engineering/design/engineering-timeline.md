# Engineering Timeline

This note preserves the detailed internal phase chronology that was removed from the
top-level README during the publication-facing cleanup pass.

It is engineering provenance, not publication-facing claim language.

## Experimental `stwo` Execution And Decoding Line

The public README now summarizes current proof surfaces and explicit non-goals. This
note keeps the more detailed sequencing for maintainers who need the implementation
history behind the experimental `stwo` line.

### Phase 6-28 Highlights

- Phase 6: canonical pre-aggregation batch manifests for future recursion work
- Phase 8: `gemma_block_v2` binds canonical normalization inside the top-level execution
  proof instead of only through `stwo_auxiliary`
- Phase 9: `gemma_block_v3` binds normalization plus canonical binary-step activation
  inside the same top-level execution proof
- Phase 10: `gemma_block_v4` binds shared-table normalization and activation rows inside
  the same top-level execution proof
- Phase 11: fixed-shape proof-carrying decoding over `decoding_step_v1`
- Phase 12: parameterized `decoding_step_v2` family with richer carried state,
  proof-bound shared-lookup rows, and executed reads of both shared normalization scale
  rows plus both shared activation output rows inside the decoding transition itself,
  with the latest carried KV-cache pair now updated from lookup-backed values rather
  than only forwarded incoming values, with three carried lanes now driven by the
  bounded combined-output cell and one by the lookup-backed primary output on the wider
  public layouts, with that combined-output cell now also absorbing two additional
  bounded shared lookup rows before it is carried forward, and with the primary and
  secondary outputs both absorbing that combined-output cell so both shared activation
  rows influence the carried output frontier and output commitment, plus exact semantic
  tests and real-backend proving coverage over all default demo steps
- Phase 13: validated layout matrix for `decoding_step_v2`, now with real-backend
  proving coverage across the default layout matrix
- Phase 14: chunked cumulative KV-history with sealed/open segment boundaries
- Phase 15: mergeable history segments with explicit global carried-state boundaries
- Phase 16: rollups over verified Phase 15 segment bundles
- Phase 17: multi-layout rollup matrices over the same carried-state family
- Phase 18: explicit KV-history frontier commitments tied to the live rolling cache
- Phase 19: carried lookup transcripts over the same Phase 14-17 stack
- Phase 20: explicit lookup frontier commitments over that same stack
- Phase 21: template-bound accumulation over Phase 17 matrices with explicit template
  and accumulator commitments
- Phase 22: lookup-side accumulation over a verified Phase 21 source accumulator with
  explicit source/template binding and derived frontier/count checks before recursion
- Phase 23: pre-recursive cross-step lookup accumulation over cumulative Phase 22
  prefixes with carried-state boundary commitments and derived counter checks
- Phase 24: full carried-state relation accumulation over verified Phase 23 members with
  explicit relation-template and relation-accumulator commitments before recursive
  compression
- Phase 25: honest intervalization of the Phase 24 carried-state relation into explicit
  contiguous carried-state intervals with derived interval-template and
  interval-accumulator commitments
- Phase 26: folded accumulation over verified Phase 25 intervals with explicit
  fold-template binding and folded interval accumulator commitments over real
  carried-state intervals
- Phase 27: chained fold-of-folds accumulation over verified Phase 26 members with
  explicit chain-template binding and chained accumulator commitments over honest
  carried-state intervals
- Phase 28: proof-carrying aggregation over verified Phase 27 chained artifacts with
  explicit aggregation-template binding, length-framed aggregation transcripts, and
  aggregate carried-state boundary checks

These phases define pre-recursive merge boundaries and carried-state bindings; they do
not yet implement recursive cryptographic accumulation or compressed cross-member
shared-table reuse.

## Carried-State Aggregation Line

The broader carried-state aggregation line overlaps with the experimental `stwo`
decoding path but also has its own internal sequencing milestones. The README now keeps
only the publication-facing surface summary; this note keeps the chronology.

### Detailed Transition Note

The current Phase 12 transition now uses both shared normalization scale rows and both
shared activation output rows in executed decoding semantics, not only as carried proof
metadata, and feeds lookup-backed values into the latest carried KV-cache pair on the
public demo layouts, with the current wider layout frontier now mostly
output-derived rather than forwarded-input-derived, while the bounded combined-output
cell itself now absorbs two additional shared lookup rows before both final output lanes
carry it forward.

### Phase 3-28 Highlights

- Phase 3: narrow arithmetic pilot and bounded lookup-backed activation pilot
- Phase 5: real arithmetic proof lifecycles plus normalization lookup demo
- Phase 7-10: `gemma_block_v1` through `gemma_block_v4`, ending with shared-table lookup
  binding inside the top-level execution proof
- Phase 11-14: fixed-shape decoding, parameterized decoding family, layout matrix, and
  chunked cumulative KV-history
- Phase 15-17: mergeable history segments, rollups over segments, and multi-layout
  rollup matrices
- Phase 18-20: explicit KV frontiers, carried lookup transcripts, and lookup frontier
  commitments
- Phase 21: template-bound accumulation over Phase 17 matrices for a reusable
  pre-recursive merge boundary
- Phase 22: lookup-side accumulation over a verified Phase 21 source accumulator with
  explicit source/template binding and derived frontier/count checks before recursion
- Phase 23: pre-recursive cross-step lookup accumulation over cumulative Phase 22
  prefixes with carried-state boundary commitments and derived counter checks
- Phase 24: full carried-state relation accumulation over verified Phase 23 members with
  explicit relation-template and relation-accumulator commitments before recursive
  compression
- Phase 25: honest intervalization of the Phase 24 carried-state relation into explicit
  contiguous carried-state intervals with derived interval-template and
  interval-accumulator commitments
- Phase 26: folded accumulation over verified Phase 25 intervals with explicit
  fold-template binding and folded interval accumulator commitments over real
  carried-state intervals
- Phase 27: chained fold-of-folds accumulation over verified Phase 26 members with
  explicit chain-template binding and chained accumulator commitments over honest
  carried-state intervals
- Phase 28: proof-carrying aggregation over verified Phase 27 chained artifacts with
  explicit aggregation-template binding, length-framed aggregation transcripts, and
  aggregate carried-state boundary checks

These phases define pre-recursive merge boundaries and carried-state bindings; they do
not yet implement recursive cryptographic accumulation or compressed cross-member
shared-table reuse.
