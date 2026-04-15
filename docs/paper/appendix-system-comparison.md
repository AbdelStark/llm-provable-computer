# Appendix: Public System Comparison Snapshot

Snapshot date: **April 11, 2026**

This appendix is a compact comparison table for the three systems most relevant to the
argument in the main paper. It inherits its source posture from Sections 6 and 7:
archival papers, official engineering/product materials, and commit-pinned repository
artifacts are used for different claim types and should not be read as a single matched
benchmark class.

Sources: rows inherit the main paper’s source set from Sections 6 and 7, especially
References 24-31 and 35-40.

It should be read with one rule in mind: these are **not** matched end-to-end benchmarks
on identical workloads. They are a structured comparison of public claims, committed
artifacts, and implementation scope.

## Table A1. DeepProve vs. BitSage obelyzk.rs (formerly stwo-ml) vs. `provable-transformer-vm`

| Dimension                 | Lagrange DeepProve                                                                               | BitSage obelyzk.rs (formerly stwo-ml)                                                                                                                                               | `provable-transformer-vm`                                                                                                                                                      |
| ------------------------- | ------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Primary role              | Production-oriented zkML system                                                                  | Public STARK-native zkML stack                                                                                                                                                      | Semantics-and-proof research artifact                                                                                                                                          |
| Proof family              | SNARK / SNARK-hybrid                                                                             | STARK-native on S-two / STWO                                                                                                                                                        | Vanilla STARK by default; frozen narrow `stwo` artifact tier plus a pre-recursive carried-state aggregation line                                                               |
| Public transformer scope  | Public claims of full GPT-2 inference and later Gemma-class progress                             | Public repo/verifier claims transformer-block support, recursive verifier milestones, and aggressive single-block benchmarks                                                        | Deterministic transformer-shaped VM, not full learned transformer inference                                                                                                    |
| Strongest public evidence | Official Lagrange product/blog materials                                                         | Public repo, verifier docs, audit notes, Starknet verification path                                                                                                                 | Two frozen artifact bundles plus a proof-carrying aggregation bundle and statement-versioned repo outputs                                                                      |
| Non-arithmetic handling   | Custom circuits and lookup-oriented techniques                                                   | LogUp-style lookup machinery on STWO                                                                                                                                                | `average-hard` proof path only; `softmax` not yet in proved relation                                                                                                           |
| Backend maturity          | Strongest public deployment maturity of the three                                                | Strongest public STARK-native zkML signal                                                                                                                                           | Strongest semantics-portability story among the three                                                                                                                          |
| Public onchain posture    | Production/prover maturity emphasized more than public Starknet verification demos               | Starknet verification path and public demos emphasized                                                                                                                              | No onchain verifier integration yet                                                                                                                                            |
| Public onchain evidence   | Public materials emphasize production deployment more than named Starknet proof-demo identifiers | Public verifier docs name `D8`, `D9`, `D10`, and `D11` as accepted on Starknet Sepolia, and later describe single-transaction recursive verification plus a six-step streaming path | No public onchain proof-verification artifact set                                                                                                                              |
| Recursion posture         | Present in system architecture, but details vary by release                                      | Publicly aligned with S-two / STWO recursion path                                                                                                                                   | Recursive cryptographic compression not implemented; repo stops at frozen narrow S-two execution proofs, proof-carrying decoding demos, and a pre-recursive aggregation ladder |
| Paper relevance           | Main counterexample to categorical anti-SNARK claims                                             | Closest STARK-native comparator to the paper thesis                                                                                                                                 | Concrete artifact that the paper can describe precisely                                                                                                                        |
| Main caveat               | Strong public claims, but not directly comparable to STARK systems on identical workloads        | Public materials mix benchmark claims, verification demos, and roadmap claims; verifier docs still show uneven component maturity (`Attention` remains `Prover only`)               | Narrow scope: vanilla backend remains primary, `average-hard` only in the main proved relation, no full learned-model proving                                                  |

## How to use this appendix

Use this appendix when the main paper needs one concise comparison object, but keep the
stronger qualifications in the main text:

- DeepProve is the strongest counterexample to categorical anti-SNARK claims.
- BitSage is the strongest public STARK-native comparator, but public evidence should be
  separated into benchmark claims, onchain demos, and broader roadmap scope.
- `provable-transformer-vm` is not a frontier zkML prover; it is a trace-semantics and
  proof-architecture artifact with reproducible evidence and an explicit pre-recursive
  aggregation boundary.
