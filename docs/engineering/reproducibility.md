# Engineering Reproducibility Guide

This guide covers the broader engineering reproducibility flows in the repository.

For the publication-facing paper package, start with:

- `docs/paper/README.md`
- `docs/paper/PUBLICATION_RELEASE.md`
- `docs/paper/submission-v4-2026-04-11/REPRODUCIBILITY_NOTE.md`

## Tooling notes

- The default vanilla STARK path builds on stable Rust.
- The experimental `stwo` path is different: compiling or running anything with
  `--features stwo-backend` currently requires the pinned nightly toolchain
  `cargo +nightly-2025-07-14`, because the upstream `stwo` stack is still
  nightly-only.
- Python helper scripts should be run from a local virtual environment. On
  PEP-668-managed Python installations, bare `pip install` may fail against the
  system interpreter.

Recommended Python setup:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r scripts/requirements.txt
```

## Command

```bash
./scripts/generate_repro_bundle.sh
```

For the carried/accumulated experimental `stwo` decode path, write each run to a
fresh scratch directory:

```bash
BUNDLE_DIR="docs/paper/artifacts/stwo-accumulation-scratch-$(date -u +%Y%m%dT%H%M%SZ)" ./scripts/paper/generate_stwo_accumulation_bundle.sh
```

Optional output directory:

```bash
./scripts/generate_repro_bundle.sh /tmp/provable-transformer-vm-repro
```

Optional knobs:

```bash
STARK_PROFILE=production-v1 INCLUDE_FIBONACCI_PROOF=1 ./scripts/generate_repro_bundle.sh
```

- `STARK_PROFILE`: `default` (fast) or `production-v1` (stronger proving profile)
- `PROOF_MAX_STEPS`: max steps for `prove-stark` runs (default `256`)
- `INCLUDE_FIBONACCI_PROOF`: `1` to include a fibonacci proof in the bundle

## Bundle Contents

The script writes to `compiled/repro-bundle/` by default and produces:

- `manifest.txt`: commit/toolchain/environment metadata
- `commands.log`: exact executed commands with UTC timestamps
- `benchmarks.tsv`: wall-clock timing per command
- `sha256sums.txt`: hashes for artifacts and command outputs
- `*.proof.json`: STARK proofs for representative programs
- `research-v2-*.json`: semantic equivalence certificates (step/trace/matrix)
- `research-v3-*.json`: multi-engine equivalence-kernel artifacts with transition
  relation hashes, explicit non-e-graph/non-SMT limits, and a frontend/runtime
  semantics registry for implemented versus research-watch lanes
- `*.out` / `*.err`: full stdout/stderr capture for each command

The accumulation bundle script defaults to the archival provenance bundle path
`docs/paper/artifacts/stwo-accumulation-v1-2026-04-09/`, but frozen bundle
paths should be treated as read-only evidence. Use `BUNDLE_DIR` to point at a
fresh scratch directory under `docs/paper/artifacts/` for each run. If you
intend to rerun against an existing scratch directory, delete it first or set
`ALLOW_OVERWRITE_FROZEN=1`. The script refuses to overwrite an existing
bundle-looking directory unless that override is set. Its outputs are:

- `manifest.txt`: commit/toolchain/environment metadata
- `commands.log`: exact executed commands with UTC timestamps
- `benchmarks.tsv`: wall-clock timing per prove/verify command
- `artifact_summary.tsv`: machine-readable size/count summary for the Phase 12,
  Phase 17, Phase 21, Phase 22, and Phase 23 decode artifacts
- `sha256sums.txt`: hashes for the bundle outputs
- `decoding-*.json`: carried/accumulated `stwo` decode artifacts

## Intended Use

- Use the generated manifests, benchmarks, and hashes as engineering evidence
  inputs; the publication-facing paper package cites the frozen bundles under
  `docs/paper/artifacts/`.
- Link generated `research-v2` / `research-v3` artifacts as evidence for semantic-equivalence
  claims.
- Link generated `*.proof.json` files for statement-v1 proof demonstrations.
- Use `artifact_summary.tsv` from the accumulation bundle when comparing base,
  carried, and accumulated decode paths inside the same artifact family.
- Use `prepare-hf-provenance-manifest` for HF-backed release bundles that need
  pinned Hub revisions, tokenizer identity, safetensors metadata/file hashes,
  optional ONNX export hashes, and model-card/DOI/dataset release metadata.

## Claim Scope Reminder

- `statement-v1` proof files are cryptographic claims enforced by verifier code.
- `research-v2` artifacts are structured semantic certificates with commitments,
  used as evidence and regression checks, but are not yet part of the STARK
  claim relation.
- `research-v3` artifacts extend that evidence to transformer/native/Burn/ONNX
  lockstep plus rule witnesses and per-engine transition relation hashes. Their
  verifier recomputes artifact commitments, bounded trace hashes, semantic
  canonical event-relation hashes, cross-engine state-boundary consistency,
  final-state links, and transition relation hashes as an integrity check. Their
  frontend/runtime semantics registry keeps PyTorch
  `torch.export`, ExecuTorch, StableHLO, IREE, ONNX-MLIR, TVM, vLLM, SGLang,
  and egg/Emerge-style paths as explicit research-watch lanes; these artifacts
  are not e-graph saturation results, SMT rewrite proofs, randomized
  opaque-kernel tests, or cryptographic implementation-equivalence proofs.
- HF provenance manifests are release/provenance artifacts only. They bind
  pinned Hub and tokenizer identifiers plus local tokenizer, safetensors, ONNX,
  model-card, DOI, and dataset metadata where supplied, but they do not prove
  tokenizer algorithm correctness, model-weight semantics, Optimum export
  equivalence, live Hub availability, or DOI validity.

## Paper figure regeneration

The Section 4 paper figures can be regenerated from the same local venv:

```bash
python3 scripts/paper/generate_section4_ratio_figure.py
python3 scripts/paper/generate_section4_decomposition_figure.py
```

These scripts rewrite the committed TSV/SVG/PDF figure assets under
`docs/paper/figures/`.
