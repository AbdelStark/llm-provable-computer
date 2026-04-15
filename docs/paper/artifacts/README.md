# Paper Artifact Bundles

This directory contains two kinds of frozen artifact bundles.

## Publication-facing cited bundles

These are the bundles directly used by the current paper package:

- `production-v1-2026-04-04/`
- `stwo-experimental-v1-2026-04-06/`
- `stwo-proof-carrying-aggregation-v1-2026-04-11/`

These are the bundles that should be treated as the paper's primary reproducibility and systems-evidence surfaces.

## Archival provenance bundles

These older carried-state bundles are retained as provenance for the development of the aggregation line:

- `stwo-accumulation-v1-2026-04-09/`
- `stwo-folded-interval-v1-2026-04-10/`
- `stwo-chained-folded-interval-v1-2026-04-10/`

They remain useful supporting evidence, but they are not the main cited artifact tiers for the current paper package.

## Frozen-bundle handling

Do not rewrite or relocate frozen bundle contents casually.

In particular, avoid editing:

- `commands.log`
- `manifest.txt`
- `sha256sums.txt`
- artifact JSON / gzip files

Those files are provenance objects. Their recorded paths, command lines, and hashes are part of the evidence trail.

Host-specific absolute paths inside frozen command logs and manifests are expected historical provenance, not documentation drift.

When regenerating related engineering bundles, prefer a fresh scratch output
directory under `docs/paper/artifacts/`. The accumulation-bundle generator
refuses to overwrite frozen-looking bundle directories unless
`ALLOW_OVERWRITE_FROZEN=1` is set explicitly.
