# Appendix Artifact Index (Production V1)

## Run Metadata
- Generated (UTC): 2026-04-04T17:28:47Z
- Bundle path: /tmp/llm-provable-computer-repro-production-v1-20260404
- Git commit: 58bb05fdd57ee9816e5935eb004396fea6a9fac3
- Branch: codex/neural-programs-repro-bundle
- STARK proof profile: production-v1
- Proof max steps: 256
- Included fibonacci proof: 1
- Toolchain: rustc 1.92.0 (ded5c06cf 2025-12-08) ; cargo 1.92.0 (344c4567c 2025-10-21)

## Primary Artifacts

| Artifact | Purpose | Size (bytes) | SHA-256 |
|---|---|---:|---|
| addition.proof.json | STARK proof for addition | 7644769 | 456933f9a76ded15a095db0bbcab84dba19bd40b82b03cbdbc50f59e53c20054 |
| dot_product.proof.json | STARK proof for neural-style dot product | 12835175 | 53cf110df7a176e6af5c69f340fb6aab7fb0cb63939ff91d6d2c240ab435c231 |
| single_neuron.proof.json | STARK proof for single-neuron forward pass | 11767989 | 3916f1954c47721cad06618c2c7c4057e96ea707e531a149473e062d6ff35ceb |
| fibonacci.proof.json | STARK proof for fibonacci benchmark | 11137502 | 3a8235044a4bbb620ef64bcaa433dab2eb0acf2115ec8ec1db22e4a77c393fc1 |
| research-v2-dot-product-step.json | One-step transformer/ONNX semantic certificate | 2186 | f2f81faf029dfc60a4c6de6dad70bf6440629de00eafaebdd7e4b8f2778cc929 |
| research-v2-dot-product-trace.json | Prefix-trace transformer/ONNX semantic certificate | 2089 | 020aa96fc591d05a59940feb488f03855bd42f1cf1a84c272929e7238b98b43b |
| research-v2-matrix-default-suite.json | Matrix semantic certificate over default suite | 16578 | 8c5992b995d6e156199ea5eeff084e87c445a5c114be57b36e9e0f93d01943c6 |
| manifest.txt | Environment and commit metadata | 569 | 86e251a74d8e57269793c3b790526cf7548bb138e599c2d0c045ba67e00adcbb |
| benchmarks.tsv | Wall-clock timings by command label | 446 | 74cad79eafc40b632a8504f5ae96fe33e0657d2c715913ce40e941daba5a8461 |
| commands.log | Exact command log with UTC timestamps | 3661 | 9291f17bef7f65fc56c9dacd363acea67850b5923193c32fe579daaa475ae3cd |
| sha256sums.txt | Full hash inventory for all outputs | 4567 | n/a (self-reference) |

## Timing Summary (seconds)

| Label | Seconds |
|---|---:|
| run_addition | 1 |
| run_counter | 1 |
| run_fibonacci | 1 |
| run_factorial_recursive | 1 |
| run_multiply | 0 |
| run_soft_attention_memory | 1 |
| run_dot_product | 1 |
| run_matmul_2x2 | 0 |
| run_single_neuron | 1 |
| prove_addition | 71 |
| verify_addition | 2 |
| prove_dot_product | 430 |
| verify_dot_product | 5 |
| prove_single_neuron | 390 |
| verify_single_neuron | 4 |
| prove_fibonacci | 856 |
| verify_fibonacci | 4 |
| research_v2_step_dot_product | 3 |
| research_v2_trace_dot_product | 1 |
| research_v2_matrix_default_suite | 4 |

## Notes
- This index is derived directly from manifest.txt, benchmarks.tsv, and sha256sums.txt in the same bundle.
- Recompute integrity with:
  cd "/tmp/llm-provable-computer-repro-production-v1-20260404"
  shasum -a 256 *.json *.out *.err benchmarks.tsv manifest.txt commands.log
