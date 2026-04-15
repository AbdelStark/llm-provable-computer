# Appendix Artifact Index (S-two Experimental V1)

## Run Metadata
- Generated at utc: 2026-04-07T09:42:11Z
- Repo root: .
- Git commit: 3cb6d55e9fdc39ab729f7cff910976163e2814f0
- Git commit short: 3cb6d55
- Git branch: codex/publication-ready-stwo-bundle
- Rustc: rustc 1.90.0-nightly (e9182f195 2025-07-13)
- Cargo: cargo 1.90.0-nightly (eabb4cd92 2025-07-09)
- Host platform: Darwin 23.6.0 arm64
- Nightly toolchain: +nightly-2025-07-14
- Bundle dir: docs/paper/artifacts/stwo-experimental-v1-2026-04-06
- Fixtures: addition, shared-normalization-demo, gemma_block_v4, decoding_demo

## Primary Artifacts

| Artifact | Purpose | Semantic scope | Size (bytes) | SHA-256 |
|---|---|---|---:|---|
| addition.stwo.proof.json | Experimental S-two arithmetic execution proof | arithmetic | 54563 | 179858a42f6e220086369400c52ab255a76e93b06141cf786f2a3d927d8c324a |
| shared-normalization.stwo.proof.json | Shared-table normalization lookup proof envelope | lookup-backed component | 74074 | 9eb8e12ed8063e95d409268d69043f73d3aed89164bfb33f680d3655a7d74691 |
| gemma_block_v4.stwo.proof.json | Gemma-inspired fixed-shape execution proof with shared lookup bindings | transformer-shaped checksum fixture | 751737 | 89f3634f8f7a3dbbcef3992fda612915b78bf50924a6860438f800de68521c1e |
| decoding.stwo.chain.json | Three-step proof-carrying decoding chain | proof-carrying decoding | 4032182 | b7ab5a7238d52fc69250a25713a6650dfa12384d9c9f4f564d559e57b3655a5f |
| manifest.txt | Environment and commit metadata | metadata | 497 | 268cbe060c6962bdfa6014fee3cc52e73f758c44a3627e89154740fc4014f9f1 |
| benchmarks.tsv | Wall-clock timings by command label | metadata | 240 | 7719611ebb378ef1e36b6b00ed494a0c10c036b878650a13c57f8abd055be024 |
| commands.log | Exact command log with UTC timestamps | metadata | 2160 | f6a8027a207ff8c6457eb1e432bb6093b7703065c5192621a5ed6fbc9e63605b |

## Timing Summary (seconds)

| Label | Seconds |
|---|---:|
| prove_addition_stwo | 2 |
| verify_addition_stwo | 1 |
| prove_shared_normalization_stwo | 1 |
| verify_shared_normalization_stwo | 1 |
| prove_gemma_block_v4_stwo | 1 |
| verify_gemma_block_v4_stwo | 1 |
| prove_decoding_demo_stwo | 1 |
| verify_decoding_demo_stwo | 1 |

## Notes
- This bundle freezes the current publication-facing experimental `stwo` evidence tier.
- The included artifacts deliberately span one arithmetic proof, one lookup-backed proof envelope, one transformer-shaped execution proof, and one proof-carrying decoding chain.
- Timing rows are local wall-clock bundle runs under an existing cargo build cache; they are artifact facts, not a normalized backend-performance study.
- Recompute integrity with `shasum -a 256 *.json benchmarks.tsv manifest.txt commands.log APPENDIX_ARTIFACT_INDEX.md README.md` inside the bundle directory.
