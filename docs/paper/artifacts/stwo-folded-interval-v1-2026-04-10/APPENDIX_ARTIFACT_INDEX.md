# Phase 24-26 STWO Folded-Interval Artifact Bundle

This bundle freezes the carried-state relation progression from cumulative Phase 24 relation accumulation to honest Phase 25 intervalization and Phase 26 folded interval accumulation.

| Phase | Artifact | Purpose | Prove (s) | Verify (s) | Size (bytes) | Total steps | Members | Fold arity |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Phase 24 | `decoding-phase24.state-relation-accumulator.json.gz` | Carried-state relation accumulator over cumulative Phase 23 prefixes | 7 | 2 | 431512 | 3 | 2 |  |
| Phase 25 | `decoding-phase25.intervalized-state-relation.json.gz` | Intervalized carried-state relation artifact over rebased cumulative prefixes | 9 | 6 | 431575 | 3 | 2 |  |
| Phase 26 | `decoding-phase26.folded-intervalized-state-relation.json.gz` | Folded accumulator over Phase 25 interval artifacts | 39 | 25 | 1712918 | 4 | 2 | 2 |

The Phase 25 artifact is the first honest intervalized carried-state artifact in this sequence.
The Phase 26 artifact folds real Phase 25 intervals rather than reusing the obsolete cumulative-prefix interpretation.

See `artifact_summary.tsv` for the full machine-readable summary, `sha256sums.txt` for deterministic canonical artifact checksums, and `provenance_sha256sums.txt` for the full emitted bundle checksum set.
