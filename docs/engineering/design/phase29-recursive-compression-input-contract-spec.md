# Phase 29 Recursive-Compression Input Contract

Phase 29 does not implement recursion. It defines the input contract that a later
recursive-compression prover may consume from a Phase 28 proof-carrying
aggregation artifact.

The contract exists to avoid an easy false positive: a compact summary of an
aggregation is not a recursive proof. Phase 29 is only valid when it is derived
from a Phase 28 manifest that passes the Phase 28 verifier with nested proof
checks enabled.

## Accepted Input

The preparer accepts a
`Phase28AggregatedChainedFoldedIntervalizedDecodingStateRelationManifest` only
after calling
`verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_proof_checks`.
That check rejects synthetic member shells and requires the nested Phase 27
proof-bearing evidence.

The derived contract binds the following fields:

- Phase 28 artifact version and semantic scope.
- S-two proof backend and the supported Phase 28 backend version.
- The supported statement version.
- Recursion posture.
- Explicit recursive-verification and cryptographic-compression claim bits.
- Aggregation arity, member count, member-summary count, and nested-member count.
- Phase 26 and Phase 25 aggregate member totals.
- Matrix, layout, rollup, segment, step, and lookup-frontier totals.
- Source-template, global-start-state, global-end-state, aggregation-template,
  and aggregate-accumulator commitments.
- A BLAKE2b-256 input-contract commitment computed by the algorithm below,
  then stored in `input_contract_commitment` for recomputation.

## Commitment Recompute

`input_contract_commitment` is the lowercase hexadecimal BLAKE2b-256 digest of
the following byte stream. It does not hash `input_contract_commitment` itself.

Strings are UTF-8 bytes with no BOM and are encoded as a 16-byte little-endian
unsigned byte length followed by the string bytes. The domain tag is encoded the
same way as a string. Counters and length prefixes are 16-byte little-endian
unsigned integers. Booleans are one byte: `0` for false and `1` for true.

The exact hash input order is:

- Domain tag: `phase29-contract`.
- `proof_backend` as its string value.
- `contract_version`.
- `semantic_scope`.
- `phase28_artifact_version`.
- `phase28_semantic_scope`.
- `phase28_proof_backend_version`.
- `statement_version`.
- `required_recursion_posture`.
- `recursive_verification_claimed`.
- `cryptographic_compression_claimed`.
- `phase28_bounded_aggregation_arity`.
- `phase28_member_count`.
- `phase28_member_summaries`.
- `phase28_nested_members`.
- `total_phase26_members`.
- `total_phase25_members`.
- `max_nested_chain_arity`.
- `max_nested_fold_arity`.
- `total_matrices`.
- `total_layouts`.
- `total_rollups`.
- `total_segments`.
- `total_steps`.
- `lookup_delta_entries`.
- `max_lookup_frontier_entries`.
- `source_template_commitment`.
- `global_start_state_commitment`.
- `global_end_state_commitment`.
- `aggregation_template_commitment`.
- `aggregated_chained_folded_interval_accumulator_commitment`.

## Rejected Input

Phase 29 rejects:

- Any Phase 28 artifact that claims recursive verification.
- Any Phase 28 artifact that claims cryptographic compression.
- Any Phase 28 artifact whose recursion posture is not
  `pre-recursive-proof-carrying-aggregation`.
- Any contract whose Phase 28 backend version or statement version does not
  match the supported repository dialect.
- Any contract with an empty source-template, global-start-state,
  global-end-state, aggregation-template, aggregate-accumulator, or
  input-contract commitment.
- Any contract whose `phase28_member_count < 2`.
- Any contract whose `phase28_member_summaries != phase28_member_count` or
  whose `phase28_nested_members != phase28_member_count`.
- Any contract whose `phase28_bounded_aggregation_arity` is smaller than
  `phase28_member_count`; the arity may be larger than the realized member
  count, but not smaller.
- Any contract whose stored `input_contract_commitment` does not recompute from
  the other contract fields.

Deserialization of `Phase29RecursiveCompressionInputContract` is a validating
operation. The read helpers
`parse_phase29_recursive_compression_input_contract_json` and
`load_phase29_recursive_compression_input_contract` return a contract only after
the same Phase 29 verifier accepts the parsed fields. Validation failures are
reported as invalid contract configuration, not as generic JSON serialization
failures. The file loader uses the repository's bounded JSON read path: it only
accepts regular files and rejects compressed or uncompressed inputs above the
Phase 29 JSON byte budget before parsing. The string parser applies the same
byte budget to in-memory JSON, and deserialization rejects unknown fields. The
commitment encodes length and counter fields with fixed-width unsigned bytes
rather than platform-width `usize` bytes.

## CLI Surface

The `tvm` CLI exposes Phase 29 as an artifact boundary:

```bash
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  prepare-stwo-recursive-compression-input-contract \
  --phase28 phase28-aggregate.json.gz \
  -o phase29-recursive-compression-input-contract.json

cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  verify-stwo-recursive-compression-input-contract \
  --input phase29-recursive-compression-input-contract.json
```

`prepare-stwo-recursive-compression-input-contract` first loads the Phase 28
artifact with nested proof checks enabled, then derives and writes the Phase 29
contract. `verify-stwo-recursive-compression-input-contract` validates a stored
contract by recomputing the input-contract commitment. Both commands preserve
the same non-goal: they do not claim recursive verification or cryptographic
compression.

## Non-Goals

Phase 29 does not verify a Phase 28 aggregate inside another proof. It also does
not compress Phase 28 proof bytes into a smaller cryptographic proof. Those are
Phase 30+ tasks. The only Phase 29 claim is that future recursion/compression
must start from a proof-checked Phase 28 aggregation boundary with explicit
commitments and non-recursive claim bits.
