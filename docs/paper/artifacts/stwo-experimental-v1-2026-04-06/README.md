# S-two Experimental Artifact Bundle V1

This directory freezes the publication-facing exploratory `stwo` evidence tier referenced by the paper. It deliberately complements the vanilla-backend `production-v1` reproducibility bundle with four narrower experimental artifacts:

- `addition.stwo.proof.json`: one arithmetic `statement-v1` execution proof,
- `shared-normalization.stwo.proof.json`: one shared-table lookup-backed normalization proof envelope,
- `gemma_block_v4.stwo.proof.json`: one transformer-shaped fixed-shape `statement-v1` execution proof with shared lookup bindings, and
- `decoding.stwo.chain.json`: one three-step proof-carrying decoding chain over explicit carried-state commitments.

These artifacts remain intentionally narrow. They do **not** prove full standard-softmax transformer inference, recursive aggregation, or production-scale decoding. Their role is to provide a frozen second evidence tier for the paper's experimental `stwo` path.
Timing rows in the accompanying index are local wall-clock bundle runs under an existing cargo build cache and should be read as artifact metadata rather than a normalized backend benchmark.

See `APPENDIX_ARTIFACT_INDEX.md` for exact hashes, timings, and metadata.
