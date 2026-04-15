# Gemma Block V1 Artifact

This directory freezes a `statement-v1` S-two execution proof for `programs/gemma_block_v1.tvm` together with `research-v2` semantic agreement artifacts for the same fixed-shape block fixture. The fixture is not a full Gemma block and does not claim standard-softmax proving. It is a fixed-shape, Gemma-inspired block checksum artifact that keeps three layers of evidence together:

- a real `stwo` execution proof for the shipped arithmetic-subset program,
- the claimed final-state cells `norm_sq = 16` and `inv_sqrt_q8 = 64`, carried by a normalization lookup companion inside the outer proof file, and
- transformer/ONNX semantic agreement artifacts for one-step and prefix-trace execution under the fixed `research-v2` profile.

The fixture models a tiny local/global score mix, a grouped-value accumulation, a residual projection, and a canonical normalization row selection. The execution proof remains a `statement-v1` claim over native ISA execution with transformer/native equivalence checks. The `research-v2` files remain semantic agreement artifacts rather than cryptographic execution proofs.

Reproduce:

```bash
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  prove-stark programs/gemma_block_v1.tvm \
  --backend stwo \
  --max-steps 256 \
  -o docs/paper/artifacts/gemma-block-v1/stwo-execution-proof.json

cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  verify-stark docs/paper/artifacts/gemma-block-v1/stwo-execution-proof.json \
  --reexecute

cargo run --features onnx-export --bin tvm -- \
  research-v2-step programs/gemma_block_v1.tvm \
  -o docs/paper/artifacts/gemma-block-v1/gemma_block_v1-step.json \
  --max-steps 1

cargo run --features onnx-export --bin tvm -- \
  research-v2-trace programs/gemma_block_v1.tvm \
  -o docs/paper/artifacts/gemma-block-v1/gemma_block_v1-trace.json \
  --max-steps 64
```

Expected final-state row bindings:

- `MEM[13] = 16` (`norm_sq`)
- `MEM[14] = 64` (`inv_sqrt_q8`)

Artifact hashes:

- `stwo-execution-proof.json`: `4225c86af3f458a7c8f6c92af6831d925b3d9763a8e3562302e02d928e82b43b`
- `gemma_block_v1-step.json`: `6e1c864a4d2fa9b7edd9f4d73fd1391ee5bf480613f0b8a12971ec03eafa89d1`
- `gemma_block_v1-trace.json`: `1c3f4bf1fc7afc79d9aa3688480702fc6a47c61d6f8e681ef54aa5e90fb3a13a`
