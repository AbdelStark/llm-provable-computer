# Appendix: Frozen Backend Artifact Comparison

Evidence snapshot: **April 6, 2026** bundle, with index material finalized April 7, 2026
UTC.

This appendix complements Appendix A and the main paper’s Section 5 by placing the two
frozen artifact tiers side by side:

- the vanilla-backend `production-v1` reproducibility bundle, and
- the narrow experimental `stwo-experimental-v1` bundle.

These rows are **not** matched end-to-end benchmarks on identical workloads. They are
frozen artifact facts drawn from the committed bundle indices under
`docs/paper/artifacts/production-v1-2026-04-04/` and
`docs/paper/artifacts/stwo-experimental-v1-2026-04-06/`.

The repository also contains
`docs/paper/artifacts/stwo-proof-carrying-aggregation-v1-2026-04-11/`, a proof-carrying
aggregation bundle. It is systems evidence for pre-recursive carried-state aggregation,
not a normalized backend-performance row in Table C1.

## Table C1. Frozen artifact comparison by backend and scope

| Artifact                    | Backend | Bundle                 |  Prove | Verify |         Proof size | Semantic scope                                                              |
| --------------------------- | ------- | ---------------------- | -----: | -----: | -----------------: | --------------------------------------------------------------------------- |
| `addition`                  | vanilla | `production-v1`        |  `71s` |   `2s` |  `7,644,769` bytes | arithmetic `statement-v1` execution proof                                   |
| `addition`                  | `stwo`  | `stwo-experimental-v1` |   `2s` |   `1s` |     `54,563` bytes | arithmetic `statement-v1` execution proof                                   |
| `dot_product`               | vanilla | `production-v1`        | `430s` |   `5s` | `12,835,175` bytes | neural-style arithmetic `statement-v1` execution proof                      |
| `single_neuron`             | vanilla | `production-v1`        | `390s` |   `4s` | `11,767,989` bytes | neural-style arithmetic `statement-v1` execution proof                      |
| `shared-normalization-demo` | `stwo`  | `stwo-experimental-v1` |   `1s` |   `1s` |     `74,074` bytes | shared-table normalization lookup proof envelope                            |
| `gemma_block_v4`            | `stwo`  | `stwo-experimental-v1` |   `1s` |   `1s` |    `751,737` bytes | fixed-shape Gemma-inspired `statement-v1` proof with shared lookup bindings |
| `decoding_demo`             | `stwo`  | `stwo-experimental-v1` |   `1s` |   `1s` |  `4,032,182` bytes | three-step proof-carrying decoding chain                                    |

## How to read this appendix

- `production-v1` remains the stronger vanilla reproducibility tier and the basis of the
  main artifact discussion.
- `stwo-experimental-v1` is intentionally narrower, but it freezes one arithmetic proof,
  one lookup-backed proof envelope, one transformer-shaped fixed-shape proof, and one
  proof-carrying decoding chain on the experimental S-two path.
- The table is useful as artifact evidence, not as a normalized backend-performance
  study. In particular, the `stwo-experimental-v1` timing rows come from warmed local
  bundle runs rather than a cold-build or matched-hardware benchmark harness.
