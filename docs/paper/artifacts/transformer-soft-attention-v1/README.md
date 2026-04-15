# Transformer Soft-Attention Artifact (V1)

This directory commits a transformer-shaped semantic artifact for `programs/soft_attention_memory.tvm`.
It complements the production-v1 appendix bundle by adding hash-anchored `research-v2` evidence for a
transformer-relevant fixture rather than only arithmetic microprograms.

## Generation

Generated on 2026-04-06 Europe/Istanbul from `main` after the `paper-v1-2026-04-06` freeze, using:

```bash
cargo run --features onnx-export --bin tvm -- \
  research-v2-step programs/soft_attention_memory.tvm \
  -o docs/paper/artifacts/transformer-soft-attention-v1/soft_attention_memory-step.json \
  --max-steps 1

cargo run --features onnx-export --bin tvm -- \
  research-v2-trace programs/soft_attention_memory.tvm \
  -o docs/paper/artifacts/transformer-soft-attention-v1/soft_attention_memory-trace.json \
  --max-steps 8
```

## Hashes

- `soft_attention_memory-step.json`: `ea475a661173faa919bf6d6888a33ee15dc25f764a5a3d5b66da0049fb16758f`
- `soft_attention_memory-trace.json`: `02268849e688ff8ab3be295c02819f3421677474ab4f8bf59b82812491eab3a1`

## Notes

- The step artifact proves one-step transformer/ONNX semantic agreement under the research-v2 fixed-point profile.
- The trace artifact proves prefix-trace agreement for the same fixture through six checked steps under an eight-step budget.
- These are semantic agreement artifacts, not `statement-v1` STARK proofs.
