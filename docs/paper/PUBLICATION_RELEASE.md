# Publication Release Package

Snapshot date: **April 11, 2026**

Planned publication tag after repository transfer: `paper-publication-v4-2026-04-11`

Canonical publication snapshot after transfer: The canonical v4 publication snapshot is
the release tag `paper-publication-v4-2026-04-11` once cut in the final publication
repository. Until that transfer and tag cut happen, the paper keeps Reference `[30]`
pointed at the staging commit-pinned snapshot below. The final publication tag
intentionally need not match the pinned carried-state evidence commit used by the
aggregation bundle. Before upload, that tag still needs to be cut in the final
publication repository and Reference `[30]` needs to be retargeted to it.

Pinned carried-state aggregation provenance checkpoint:
`6ff972ddda4051d73dc65c92a88c0d00683ec8c7`

Dedicated proof-carrying aggregation bundle index cited by Reference `[46]`:
`6bb8cab99092203217d64951c3af61488aa2c58e`

Current staging repository: `https://github.com/omarespejel/provable-transformer-vm`
(earlier iterations of this research line used the `llm-provable-computer` project
name). The final publication repository may move before the canonical tag is cut.

Formal paper author line in the draft:

- Abdelhamid Bakhta - StarkWare
- Omar Espejel - Starknet Foundation

This repository state is the publication-facing package for the paper and its supporting
artifacts. The package is intentionally split into evidence tiers rather than treated as
one monolithic benchmark claim.

## Included materials

- Main paper:
  - `docs/paper/stark-transformer-alignment-2026.md`
  - Title: `On the Structural Fit of Transformer Workloads and STARK Proof Systems`
- Supporting appendices:
  - `docs/paper/appendix-system-comparison.md`
  - `docs/paper/appendix-scaling-companion.md`
  - `docs/paper/appendix-backend-artifact-comparison.md`
  - `docs/paper/appendix-influence-realization.md`
- Frozen artifact bundles:
  - `docs/paper/artifacts/production-v1-2026-04-04/`
  - `docs/paper/artifacts/stwo-experimental-v1-2026-04-06/`
  - `docs/paper/artifacts/stwo-proof-carrying-aggregation-v1-2026-04-11/`
- Figure sources:
  - `docs/paper/figures/section4-ratio-vs-context.tsv`
  - `docs/paper/figures/section4-decomposition-vs-context.tsv`
  - `docs/paper/figures/section5-carried-state-ladder.svg`
  - `scripts/paper/generate_section4_ratio_figure.py`
  - `scripts/paper/generate_section4_decomposition_figure.py`
- External evidence snapshots:
  - `docs/paper/evidence/web-2026-04-06/`
  - `docs/paper/evidence/gemma-config-snapshots/`

## Claim posture

- `production-v1` is the primary frozen reproducibility bundle for the vanilla backend.
- `stwo-experimental-v1` is the frozen narrow evidence tier for the experimental S-two
  path.
- Post-freeze commit-pinned evidence now includes the merged pre-recursive carried-state
  aggregation bundle, including proof-carrying outer aggregation over chained artifacts.
- Older carried-state artifact bundles are retained as archival provenance; see
  `docs/paper/artifacts/README.md`. The proof-carrying aggregation bundle is the
  publication-facing artifact bundle for the carried-state aggregation line.
- The repo still does **not** claim full standard-softmax transformer inference on
  S-two, recursive cross-step shared-table accumulation beyond the public
  lookup-accumulator artifact, recursive cryptographic compression/verification closure,
  or production-scale zkML deployment.

## Regeneration

- Vanilla bundle:
  - `./scripts/generate_repro_bundle.sh`
- Experimental `stwo` bundle:
  - `./scripts/paper/generate_stwo_publication_bundle.sh`
- Proof-carrying aggregation bundle:
  - `./scripts/paper/generate_stwo_proof_carrying_aggregation_bundle.sh`
- Archived web evidence:
  - `python3 scripts/paper/archive_supporting_web_evidence.py`
- Gemma config extracts:
  - `python3 scripts/paper/extract_gemma_config_snapshots.py`
- Paper preflight checks:
  - `python3 scripts/paper/paper_preflight.py --repo-root .`

## Publication check

Before cutting a release tag, verify:

1. the frozen bundle directories exist and their `sha256sums.txt` files validate, and
   the aggregation bundle's `provenance_sha256sums.txt` also validates,
2. the main paper and appendices refer to the same repo state and evidence tiers,
3. the design note matches the current experimental `stwo` status,
4. no stale top-level README language still describes S-two as merely prospective,
5. Reference `[30]` remains commit-pinned until the repository transfer and v4
   publication tag exist; after that tag is cut in the final publication repository,
   update `[30]` to the v4 publication tag while keeping the aggregation bundle directly
   pinned by Reference `[46]`,
6. the formal author line and affiliation text are confirmed before public release,
7. `paper preflight` passes (citation integrity, immutable local repo links, figure/link
   paths, appendix source note, and unresolved publication snapshot placeholder
   detection).
