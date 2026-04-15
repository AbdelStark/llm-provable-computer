# Gemma Block V3 Artifact

This directory freezes a `statement-v1` S-two execution proof for `programs/gemma_block_v3.tvm` together with `research-v2` semantic agreement artifacts for the same fixed-shape block fixture. The fixture is still not a full Gemma block and does not claim standard-softmax proving. The difference from `gemma_block_v2` is that the top-level serialized execution proof now binds two canonical lookup-backed facts inside the same payload:

- the normalization row `norm_sq = 16`, `inv_sqrt_q8 = 64`, and
- the bounded binary-step activation row `input = 1`, `output = 1`.

This package therefore keeps four layers of evidence together:

- a real `stwo` execution proof for the shipped fixed-shape block fixture,
- an embedded normalization lookup proof for the claimed canonical row,
- an embedded binary-step activation lookup proof for the claimed canonical row, and
- transformer/ONNX semantic agreement artifacts for one-step and prefix-trace execution under the fixed `research-v2` profile.

The fixture models a tiny local/global score mix, a grouped-value accumulation, a residual projection, a canonical normalization row selection, and a canonical bounded activation row selection. The execution proof remains a `statement-v1` claim over native ISA execution with transformer/native equivalence checks. The `research-v2` files remain semantic agreement artifacts rather than cryptographic execution proofs.

Reproduce:

```bash
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  prove-stark programs/gemma_block_v3.tvm \
  --backend stwo \
  --max-steps 256 \
  -o docs/paper/artifacts/gemma-block-v3/stwo-execution-proof.json

cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  verify-stark docs/paper/artifacts/gemma-block-v3/stwo-execution-proof.json \
  --reexecute

cargo run --features onnx-export --bin tvm -- \
  research-v2-step programs/gemma_block_v3.tvm \
  -o docs/paper/artifacts/gemma-block-v3/gemma_block_v3-step.json \
  --max-steps 256

cargo run --features onnx-export --bin tvm -- \
  research-v2-trace programs/gemma_block_v3.tvm \
  -o docs/paper/artifacts/gemma-block-v3/gemma_block_v3-trace.json \
  --max-steps 256
```

Expected final-state row bindings:

- `MEM[13] = 16` (`norm_sq`)
- `MEM[14] = 64` (`inv_sqrt_q8`)
- `MEM[15] = 1` (`activation_input`)
- `MEM[16] = 1` (`activation_output`)

Artifact hashes:

- `stwo-execution-proof.json`: `d236a6e49f6c1b19eae47ea9bb943fe7fdfefc379d908af5e49a0aacbfada7c7`
- `gemma_block_v3-step.json`: `0881088fd15449ebabc568d61b38c3d8dc3b1a762133282a7a5dbf29c03078d0`
- `gemma_block_v3-trace.json`: `165da427a668e28eb87f7ace1c3c11345a7050f723390d640e8687c1090b80f6`
