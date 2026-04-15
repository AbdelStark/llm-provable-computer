# Appendix: External Influences and Current Repository Realization

This supplementary appendix records how the current paper and repository draw on
external work without overstating equivalence of scope. The table is meant to separate
three questions that can otherwise blur together in review:

- which external line influenced the design,
- where that influence is visible in the current paper and repository, and
- which part remains future work rather than a present claim.

| Work / line                           | What we took from it                                                                         | Where it appears in the paper           | Where it appears in the repo                                        | What remains future work                                  |
| ------------------------------------- | -------------------------------------------------------------------------------------------- | --------------------------------------- | ------------------------------------------------------------------- | --------------------------------------------------------- |
| Percepta transformer-computer line    | Conceptual framing for transformer-shaped execution as a meaningful computational object     | Introduction and conceptual framing     | Transformer-shaped VM and execution-trace framing                   | This repository is not a learned-transformer proof system |
| DeepProve / reusable lookup direction | Motivation for stateful decoding and reusable/shared lookup structure                        | Related work and near-term roadmap      | Shared lookup-table identity binding and carried lookup state       | Not yet recursive cross-step shared-table accumulation    |
| Emerge                                | Motivation for bounded multi-runtime semantic-agreement artifacts                            | Section 5.6 semantic-agreement boundary | `research-v3` bounded equivalence-kernel artifacts                  | Not a general e-graph / SMT equivalence prover            |
| Jolt Atlas                            | Motivation for lookup-centric operator-level proving and streaming-friendly proving surfaces | Related work and near-term roadmap      | Lookup-heavy artifact direction and operator-surface roadmap        | Not yet ONNX-operator proving in this repository          |
| NANOZK                                | Legibility of block/layer proof envelopes                                                    | Related work and near-term roadmap      | Reusable block-shaped execution proofs and step-level proof objects | Not a constant-size layer-proof system                    |
| HyperNova / NeutronNova / ProtoStar   | Novelty boundary for what this paper is not claiming                                         | Section 5 artifact-layer disclaimer     | Pre-recursive artifact-layer packaging language                     | Recursive cryptographic accumulation remains future work  |
