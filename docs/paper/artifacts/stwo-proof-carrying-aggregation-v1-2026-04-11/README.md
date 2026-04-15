# S-two Proof-Carrying Aggregation Bundle

This bundle freezes the carried-state packaging ladder from state-relation accumulation through a pre-recursive aggregation boundary.

The artifact filenames retain legacy phase-numbered names for checksum stability and provenance. In publication-facing prose, the corresponding ladder is described as chain, segment, interval bundle, rollup, matrix, and pre-recursive aggregation boundary.

Included artifacts:
- `decoding-phase24.state-relation-accumulator.json.gz`: carried-state relation accumulator over cumulative prefix boundaries.
- `decoding-phase25.intervalized-state-relation.json.gz`: interval bundle over rebased carried-state prefixes.
- `decoding-phase26.folded-intervalized-state-relation.json.gz`: rollup package over interval bundle members.
- `decoding-phase27.chained-folded-intervalized-state-relation.json.gz`: matrix-compatible chained rollup package.
- `decoding-phase28.aggregated-chained-folded-intervalized-state-relation.json.gz`: proof-carrying pre-recursive aggregation boundary over chained rollup members.

See `APPENDIX_ARTIFACT_INDEX.md` and `artifact_summary.tsv` for details.

## Provenance note

The raw proof artifacts were generated from commit `e428171fdca22188c773a55bacf7284757bc7f54`. During the first outer-aggregation verification step, `target/debug/tvm` was unexpectedly missing, so verification/compression resumed after rebuilding the same `tvm` binary path. The outer aggregation proof was not re-proven during that resume; the existing generated JSON was verified, compressed with deterministic gzip flags, and then each compressed artifact was verified again. The `verify_aggregated_chained_folded_intervalized_decoding_state_relation_phase28_stwo` benchmark row (`482.162583` seconds) is from the resumed successful verification at `2026-04-11T12:01:22Z`; the failed `2026-04-11T11:58:58Z` attempt wrote no benchmark row. The branch later added generator hardening so a missing `tvm` binary is rebuilt before timed verification commands.
