# S-two Accumulation Artifact Bundle V1

This directory freezes a controlled decode-artifact family for the carried/accumulated `stwo` path. It is intended for the next-paper track rather than for the current publication snapshot.

Artifacts included:

- `decoding-phase12.chain.json`: base proof-carrying decoding chain,
- `decoding-phase17.rollup-matrix.json`: multi-layout rollup-matrix packaging over the same decode relation,
- `decoding-phase21.matrix-accumulator.json`: template-bound accumulator over Phase 17 matrices,
- `decoding-phase22.lookup-accumulator.json`: lookup-side accumulator over a Phase 21 matrix accumulator,
- `decoding-phase23.cross-step-lookup-accumulator.json`: cross-step lookup accumulator over cumulative Phase 22 prefixes.

The bundle records exact command logs, wall-clock timings, integrity hashes, and a machine-readable `artifact_summary.tsv` so later paper drafts can compare base, carried, and accumulated paths on one committed artifact family.

These artifacts are still pre-recursive. They do **not** claim recursive cryptographic accumulation/compression or full standard-softmax transformer inference.

See `APPENDIX_ARTIFACT_INDEX.md` for exact hashes, timings, and structural summary fields.
