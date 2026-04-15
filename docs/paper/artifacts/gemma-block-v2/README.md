# Gemma Block V2 Artifact

This directory freezes a `statement-v1` S-two execution proof for `programs/gemma_block_v2.tvm` together with `research-v2` semantic agreement artifacts for the same fixed-shape block fixture. The fixture is still not a full Gemma block and does not claim standard-softmax proving. The difference from `gemma_block_v1` is narrower and more important: the canonical normalization row is no longer attached through `stwo_auxiliary` sidecar metadata. It is bound inside the main serialized `prove-stark --backend stwo` proof payload consumed by `verify-stark`.

This package therefore keeps three layers of evidence together:

- a real `stwo` execution proof for the shipped fixed-shape block fixture,
- an embedded normalization lookup proof for the claimed `norm_sq = 16` and `inv_sqrt_q8 = 64` row, verified from the same top-level proof payload, and
- transformer/ONNX semantic agreement artifacts for one-step and prefix-trace execution under the fixed `research-v2` profile.

The fixture models a tiny local/global score mix, a grouped-value accumulation, a residual projection, and a canonical normalization row selection. The execution proof remains a `statement-v1` claim over native ISA execution with transformer/native equivalence checks. The `research-v2` files remain semantic agreement artifacts rather than cryptographic execution proofs.

Reproduce:

```bash
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  prove-stark programs/gemma_block_v2.tvm \
  --backend stwo \
  --max-steps 256 \
  -o docs/paper/artifacts/gemma-block-v2/stwo-execution-proof.json

cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  verify-stark docs/paper/artifacts/gemma-block-v2/stwo-execution-proof.json \
  --reexecute

cargo run --features onnx-export --bin tvm -- \
  research-v2-step programs/gemma_block_v2.tvm \
  -o docs/paper/artifacts/gemma-block-v2/gemma_block_v2-step.json \
  --max-steps 256

cargo run --features onnx-export --bin tvm -- \
  research-v2-trace programs/gemma_block_v2.tvm \
  -o docs/paper/artifacts/gemma-block-v2/gemma_block_v2-trace.json \
  --max-steps 256
```

Expected final-state row bindings:

- `MEM[13] = 16` (`norm_sq`)
- `MEM[14] = 64` (`inv_sqrt_q8`)

Artifact hashes:

- `stwo-execution-proof.json`: `3a2d5818c821c2fd00a0993fe163588c2038dc970f9eb7bc259cc57484014435`
- `gemma_block_v2-step.json`: `5aa849df53f56b69a6a3eeb24ea4d383ad66ac769b8bc7da5009e80667a1c3e1`
- `gemma_block_v2-trace.json`: `c6f6ca62e908dbbc8a2a8cbe348b3724f9052a51bd0285233644a30c536766e2`
