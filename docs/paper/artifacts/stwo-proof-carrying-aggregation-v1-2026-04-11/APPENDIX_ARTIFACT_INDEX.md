# Appendix Artifact Index

The artifact filenames retain legacy phase-numbered names for checksum stability and provenance. Publication-facing prose describes this ladder as chain, segment, interval bundle, rollup, matrix, and pre-recursive aggregation boundary.

| Artifact | Legacy label | Publication-facing role | Size (bytes) | SHA-256 |
| --- | --- | --- | ---: | --- |
| `decoding-phase24.state-relation-accumulator.json.gz` | phase24 | Carried-state relation accumulator over cumulative prefix boundaries | 431512 | `e2d96e64343792653b9f15a5fa3a96d8269e33f97ae585d532f8e7c699dfc020` |
| `decoding-phase25.intervalized-state-relation.json.gz` | phase25 | Interval bundle over rebased carried-state prefixes | 431575 | `76fd688b45a9eb16005346312df5ef0beec18c981b5c9c565b4ff55605a97950` |
| `decoding-phase26.folded-intervalized-state-relation.json.gz` | phase26 | Rollup package over interval bundle members | 1712918 | `67a0eecae5d3d9ca9c53d3d1c9ac79afbf49c6f7f5539ec87ac251ac10aa3138` |
| `decoding-phase27.chained-folded-intervalized-state-relation.json.gz` | phase27 | Matrix-compatible chained rollup package | 4694996 | `3c376f1acc5081b5921795528026b44ffece3278d0d93af27289b536d0f81976` |
| `decoding-phase28.aggregated-chained-folded-intervalized-state-relation.json.gz` | phase28 | Proof-carrying pre-recursive aggregation boundary over chained rollup members | 32069039 | `a17176ce84214111c858ba5af3e8404c63b18cddaa86eba4ea460f776234f21e` |
