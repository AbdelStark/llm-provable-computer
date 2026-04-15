# Appendix Artifact Index (S-two Accumulation V1)

## Run Metadata
- Generated at utc: 2026-04-09T19:47:18Z
- Repo root: .
- Git commit: afa856237c53b5507a0335ce4bf0f802099504fc
- Git commit short: afa8562
- Git branch: codex/phase23-eval-bundle-v1
- Rustc: rustc 1.90.0-nightly (e9182f195 2025-07-13)
- Cargo: cargo 1.90.0-nightly (eabb4cd92 2025-07-09)
- Host platform: Darwin 23.6.0 arm64
- Nightly toolchain: +nightly-2025-07-14
- Bundle dir: docs/paper/artifacts/stwo-accumulation-v1-2026-04-09
- Fixtures: decoding_chain_phase12, decoding_rollup_matrix_phase17, decoding_matrix_accumulator_phase21, decoding_lookup_accumulator_phase22, decoding_cross_step_lookup_accumulator_phase23

## Artifact Summary

| Artifact | Phase | Scope | Size (bytes) | Prove (s) | Verify (s) | Total steps | Total rollups | Total segments | Total members | Lookup delta entries | SHA-256 |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| decoding-phase12.chain.json | Phase 12 | proof-carrying decoding baseline | 4070570 | 9 | 1 | 3 |  |  |  |  | 8e38d56e8f4557476051cfa8462ccc2953a411a92fe5d3d10ca8cef49f5dc3fd |
| decoding-phase17.rollup-matrix.json | Phase 17 | carried-state matrix packaging | 34889921 | 9 | 3 | 9 | 6 | 9 |  |  | f0870d6f7389d8432d859a32861dee7be65fd0c8daf5662e83d4fcfadae923d9 |
| decoding-phase21.matrix-accumulator.json | Phase 21 | pre-recursive template-bound accumulation | 79589673 | 22 | 5 | 18 | 12 | 18 |  |  | fa7398c56b388d6e2a10db159ece314b1419fc5e8bb4050d536df821bb800ff6 |
| decoding-phase22.lookup-accumulator.json | Phase 22 | pre-recursive lookup accumulation | 84495208 | 46 | 9 | 18 | 12 | 18 |  | 18 | 966c0a588130e86fef22566dfd318ac93032063d079c2b957e0783d98a64c285 |
| decoding-phase23.cross-step-lookup-accumulator.json | Phase 23 | cross-step pre-recursive lookup accumulation | 27519142 | 9 | 4 | 3 | 2 | 3 |  | 3 | e5bc07726fa47f920c576b18cbf24c86133c262dbec9d60b82a8e73e82497fa2 |

## Timing Summary (seconds)

| Label | Seconds |
|---|---:|
| prove_decoding_chain_phase12_stwo | 9 |
| verify_decoding_chain_phase12_stwo | 1 |
| prove_decoding_rollup_matrix_phase17_stwo | 9 |
| verify_decoding_rollup_matrix_phase17_stwo | 3 |
| prove_decoding_matrix_accumulator_phase21_stwo | 22 |
| verify_decoding_matrix_accumulator_phase21_stwo | 5 |
| prove_decoding_lookup_accumulator_phase22_stwo | 46 |
| verify_decoding_lookup_accumulator_phase22_stwo | 9 |
| prove_decoding_cross_step_lookup_accumulator_phase23_stwo | 9 |
| verify_decoding_cross_step_lookup_accumulator_phase23_stwo | 4 |

## Notes
- This bundle is a controlled carried/accumulated decode-artifact snapshot for the next-paper track, not a normalized backend benchmark study.
- The artifact family keeps the same underlying decode relation while moving from a base chain to matrix packaging and then to progressively stronger pre-recursive accumulation layers.
- Timing rows are local wall-clock runs under an existing cargo build cache and should be read as artifact facts, not cross-system benchmark claims.
- `artifact_summary.tsv` provides the machine-readable comparison surface for later paper tables and plots.
- Recompute integrity with `shasum -a 256 *.json benchmarks.tsv artifact_summary.tsv manifest.txt commands.log APPENDIX_ARTIFACT_INDEX.md README.md` inside the bundle directory.
