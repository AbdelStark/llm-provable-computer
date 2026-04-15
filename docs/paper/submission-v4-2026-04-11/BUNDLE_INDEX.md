# Submission Bundle Index (v4, 2026-04-11)

Planned publication tag after repository transfer:

- `paper-publication-v4-2026-04-11`

Canonical repository snapshot after transfer:

- `paper-publication-v4-2026-04-11` once cut in the final publication repository. Until
  that happens, the paper cites the staging commit-pinned snapshot for Reference `[30]`.

Carried-state aggregation provenance checkpoint:

- `6ff972ddda4051d73dc65c92a88c0d00683ec8c7` (publication-facing proof-carrying
  aggregation provenance)

Draft author line:

- Abdelhamid Bakhta - StarkWare
- Omar Espejel - Starknet Foundation

Paper title:

- `On the Structural Fit of Transformer Workloads and STARK Proof Systems`

## Core Paper Files

- Main paper:
  - `docs/paper/stark-transformer-alignment-2026.md`

## Appendices

- `docs/paper/appendix-system-comparison.md`
- `docs/paper/appendix-scaling-companion.md`
- `docs/paper/appendix-backend-artifact-comparison.md`
- `docs/paper/appendix-influence-realization.md`

## Artifact Index Pointers

- Production frozen bundle index:
  - `docs/paper/artifacts/production-v1-2026-04-04/APPENDIX_ARTIFACT_INDEX.md`
- Experimental `stwo` frozen bundle index:
  - `docs/paper/artifacts/stwo-experimental-v1-2026-04-06/APPENDIX_ARTIFACT_INDEX.md`
- Proof-carrying aggregation bundle index:
  - `docs/paper/artifacts/stwo-proof-carrying-aggregation-v1-2026-04-11/APPENDIX_ARTIFACT_INDEX.md`
  - Citation commit: `6bb8cab99092203217d64951c3af61488aa2c58e`

Older carried-state artifact directories remain archival provenance; see
`docs/paper/artifacts/README.md`. The bundle above is the publication-facing artifact
bundle for the carried-state aggregation line.

## Evidence Pointer

- Web evidence manifest:
  - `docs/paper/evidence/web-2026-04-06/manifest.tsv`
  - `docs/paper/evidence/web-2026-04-06/manifest.json`

## Reproducibility Note

- One-page note:
  - `docs/paper/submission-v4-2026-04-11/REPRODUCIBILITY_NOTE.md`

## Verification Commands

- Paper preflight:
  - `python3 scripts/paper/paper_preflight.py --repo-root .`
- Regenerate Section 4 figures and TSVs:
  - `python3 scripts/paper/generate_section4_ratio_figure.py`
  - `python3 scripts/paper/generate_section4_decomposition_figure.py`
- Static Section 5 systems figure:
  - `docs/paper/figures/section5-carried-state-ladder.svg`
