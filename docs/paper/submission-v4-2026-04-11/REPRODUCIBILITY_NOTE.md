# Reproducibility Note (One Page)

This note describes how to reproduce the publication-facing paper artifacts for **On the
Structural Fit of Transformer Workloads and STARK Proof Systems** under the rolling base
tag `paper-publication-v4-2026-04-11` once cut. The tag should resolve to a commit that
contains this v4 paper metadata. The carried-state aggregation evidence remains pinned
to the proof-carrying aggregation checkpoint commit
`6ff972ddda4051d73dc65c92a88c0d00683ec8c7`, with the dedicated bundle index cited at
commit `6bb8cab99092203217d64951c3af61488aa2c58e`.

## 1) Scope and Intended Reproduction Target

The target is reproducibility of:

- paper text and references,
- appendix artifacts and evidence pointers,
- figure-generating scripts and TSV outputs,
- frozen artifact index manifests for the evidence tiers, including the proof-carrying
  aggregation bundle.

This package is intentionally a **research artifact snapshot**, not a claim of
production-scale zkML deployment.

## 2) Environment

Minimum practical setup:

- Python 3.9+,
- Rust toolchain used by the repository CI,
- dependencies from `scripts/requirements.txt`.

Install Python dependencies:

```bash
python3 -m pip install -r scripts/requirements.txt
```

## 3) Paper Integrity / Preflight Check

Run:

```bash
python3 scripts/paper/paper_preflight.py --repo-root .
```

This verifies:

- local citation integrity for files with local references sections,
- immutable-link policy for this repository's GitHub links (commit-pinned),
- local figure/link path existence,
- standalone source note presence for system-comparison appendix.

Warnings about unused references are informational; errors fail the check.

## 4) Figure and Data Regeneration

Regenerate Section 4 artifacts:

```bash
python3 scripts/paper/generate_section4_ratio_figure.py
python3 scripts/paper/generate_section4_decomposition_figure.py
```

Expected outputs live under:

- `docs/paper/figures/section4-ratio-vs-context.*`
- `docs/paper/figures/section4-decomposition-vs-context.*`

Use git status to detect reproducibility drift quickly:

```bash
git status --short docs/paper/figures
```

Then inspect exact renderer-level drift with:

```bash
git diff -- docs/paper/figures
```

Numeric TSV outputs should be stable for a fixed code path; renderer-specific
binary/metadata drift (PDF/SVG/PNG) can occur across local plotting stacks.

## 5) Frozen Evidence Tiers

Primary frozen bundle index:

- `docs/paper/artifacts/production-v1-2026-04-04/APPENDIX_ARTIFACT_INDEX.md`

Frozen experimental `stwo` bundle index:

- `docs/paper/artifacts/stwo-experimental-v1-2026-04-06/APPENDIX_ARTIFACT_INDEX.md`

Proof-carrying aggregation bundle index:

- `docs/paper/artifacts/stwo-proof-carrying-aggregation-v1-2026-04-11/APPENDIX_ARTIFACT_INDEX.md`

These indexes contain commit anchors, command logs, hashes, and artifact paths.

## 6) External Evidence Snapshot

Primary evidence manifest:

- `docs/paper/evidence/web-2026-04-06/manifest.tsv`
- `docs/paper/evidence/web-2026-04-06/manifest.json`

This records the source set used for infrastructure/system-state claims at the time of
packaging.

## 7) Consistency Sweep Before Sharing

Before sharing a draft externally, verify:

1. author names and affiliations are confirmed,
2. title and claim posture are aligned between:
   - `docs/paper/stark-transformer-alignment-2026.md`
   - `docs/paper/PUBLICATION_RELEASE.md`
3. paper preflight passes,
4. the aggregation bundle checksum files validate locally or in a clean reproduction
   environment,
5. release tag and commit references are consistent with the single main paper.

If additional reviewer feedback lands, patch on top and cut a follow-up publication tag
rather than mutating existing evidence claims.
