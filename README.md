# Transformer VM

**A deterministic transformer runtime with a repository-backed proof stack.**

This repository compiles a compact assembly language into a transformer-shaped runtime,
executes it deterministically, records the execution trace, and proves the claimed
computation with a transparent STARK. The same program can also run through independent
native, Burn, and ONNX paths so semantic drift is caught before proof generation.

The execution model builds on Percepta's
[*Can LLMs Be Computers?*](https://www.percepta.ai/blog/can-llms-be-computers), then
pushes it into a maintained Rust implementation with proof artifacts and frozen
publication bundles.

```text
         .tvm program
              │
              │ compile
              ▼
    +------------------------+
    |  transformer runtime   |
    |  hull memory + FFN VM  |
    +-----------+------------+
                │
                │ execute in lockstep
                ▼
    +------------------------+      +----------------------+
    |   execution trace      | ───▶ |   STARK / stwo      |
    |   (AIR witness)        |      |   proof surfaces    |
    +------------------------+      +----------+-----------+
                                               │
                                               ▼
                                          verify claim
```

No sampling. No stochastic output. Same input, same output, every time.

## At A Glance

- Compile `.tvm` assembly into a deterministic transformer-style runtime.
- Run the same program through up to four engines and optionally fail on the first
  semantic divergence when verification paths are enabled.
- Prove `statement-v1` native ISA execution with the in-repo vanilla STARK.
- Exercise an experimental `stwo` backend for shipped arithmetic fixtures, shared-table
  lookup demos, transformer-shaped fixtures, and bounded proof-carrying decoding
  artifacts.
- Regenerate frozen paper bundles, artifact manifests, and figure inputs from committed
  scripts.

## Proof Surfaces

| Surface        | Status        | What it actually covers                                                                                                       |
| -------------- | ------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `statement-v1` | Stable        | Vanilla STARK proof of native ISA execution, plus enforced transformer/native semantic agreement checks                       |
| `stwo-backend` | Experimental  | Narrow `statement-v1` proving surface for shipped fixtures, lookup demos, transformer-shaped fixtures, and decoding artifacts |
| `research-v2`  | Artifact-only | Semantic agreement artifacts for transformer vs ONNX, not yet a full STARK claim                                              |
| `research-v3`  | Artifact-only | Bounded multi-engine transformer/native/Burn/ONNX equivalence-kernel artifacts with transition relation hashes                |

The important boundary is explicit: this repo does **not** yet prove full
standard-softmax transformer inference on `stwo`. The current proving boundary is native
ISA execution with semantic agreement checks layered around the transformer runtime.

Hardening and merge discipline for trusted-core work is formalized in:

- [`docs/engineering/hardening-policy.md`](docs/engineering/hardening-policy.md)
- [`docs/engineering/hardening-strategy.md`](docs/engineering/hardening-strategy.md)

Current public proof surfaces:

- native-ISA `statement-v1` arithmetic proofs
- shared-table lookup proofs
- reusable block-shaped execution proofs
- step-level proof-carrying decode artifacts
- bounded multi-runtime semantic-agreement artifacts
- pre-recursive aggregation bundles

## Start Here

| Goal                             | Command                                                                                                                                 | Notes                                            |
| -------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------ |
| Run a program                    | `cargo run --bin tvm -- programs/fibonacci.tvm`                                                                                         | Fastest way to see the VM work                   |
| Inspect a full trace             | `cargo run --bin tvm -- run programs/fibonacci.tvm --trace`                                                                             | Emits the full machine-state trace               |
| Prove with the vanilla STARK     | `cargo run --bin tvm -- prove-stark programs/fibonacci.tvm -o fib.proof.json`                                                           | Stable proof path                                |
| Verify a proof                   | `cargo run --bin tvm -- verify-stark fib.proof.json`                                                                                    | `statement-v1` includes lockstep semantic checks |
| Try the experimental `stwo` path | `cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- prove-stark programs/addition.tvm -o add.proof.json --backend stwo` | Pinned nightly required                          |
| Regenerate paper artifacts       | `./scripts/generate_repro_bundle.sh`                                                                                                    | Publication-facing bundle                        |

## Toolchains

| Task                                            | Requirement                                             |
| ----------------------------------------------- | ------------------------------------------------------- |
| Core runtime, vanilla STARK, default tests      | Stable Rust                                             |
| `--features stwo-backend` compile and CLI paths | `cargo +nightly-2025-07-14`                             |
| ONNX validation and paper figure scripts        | Python venv + `pip install -r scripts/requirements.txt` |

If you want the shortest successful path, start on stable Rust with the default runtime
and vanilla STARK commands. Move to `stwo` only when you need the experimental backend
surface.

______________________________________________________________________

## Why This Works

Three ideas, stacked.

### 1. Attention Is Memory Access

Each memory address maintains a write history as 2D points `(step, value)`. To read the
latest write, query with direction `[1, 0]`:

```
score(q, k) = 1 * step + 0 * value = step
```

The argmax selects the most recent write. In 2D, the maximizer of any linear objective
lies on the **convex hull** of the key set. So the runtime maintains a hull-backed KV
cache and answers memory queries via binary search in **O(log n)** instead of scanning
the full history.

At step 1,000,000, each memory read still costs O(log n).

### 2. Feed-Forward Layers Are Instructions

Each compiled instruction becomes a deterministic gate-and-transform operation in the
FFN:

```
output = gate(state) * transition(state)
```

The gate activates only for the correct opcode. The transition encodes the instruction
semantics. Together they form a compiled, non-learned feed-forward layer that maps one
machine state to the next.

### 3. The Trace Is Already a STARK Witness

A STARK proves that a sequence of states satisfies a set of polynomial constraints (an
AIR). An execution trace --- a table of `(PC, ACC, SP, flags, memory)` rows where each
row follows deterministically from the previous --- is exactly that object.

The transition constraints **are** the instruction semantics. The boundary constraints
**are** the initial and final states. You do not bolt provability onto the architecture
after the fact; the execution trace is already the AIR object you need.

The proof is **transparent** (no trusted setup) and **post-quantum** (hash-based, no
elliptic curves). STARK verification itself is **O(log^2 n)**, while the current
`statement-v1` verifier also performs transformer/native lockstep re-execution to
enforce semantic equivalence.

Scope note: the current proof claim is a `statement-v1` claim over native ISA execution,
with semantic agreement checks layered around it. This repository now exposes an
experimental `stwo` backend and a frozen `stwo` artifact bundle, but it still does not
provide a full standard-softmax transformer path on S-two.

______________________________________________________________________

## Common Commands

```bash
git clone https://github.com/omarespejel/provable-transformer-vm && cd provable-transformer-vm

# Run a program
cargo run --bin tvm -- programs/fibonacci.tvm

# Full execution trace
cargo run --bin tvm -- run programs/fibonacci.tvm --trace

# Prove execution with a vanilla STARK
cargo run --bin tvm -- prove-stark programs/fibonacci.tvm -o fib.proof.json

# Verify (statement-v1 includes lockstep re-execution)
cargo run --bin tvm -- verify-stark fib.proof.json

# Exercise the experimental S-two backend (nightly-only upstream toolchain)
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  prove-stark programs/addition.tvm -o add.proof.json --backend stwo

# The experimental `stwo` path requires the pinned nightly toolchain both to
# compile `--features stwo-backend` and to run its CLI commands.

# Verify transformer matches native interpreter (lockstep)
cargo run --bin tvm -- run programs/fibonacci.tvm --verify-native

# Interactive TUI
cargo run --bin tvm -- tui programs/fibonacci.tvm

# Tests
cargo test

# Reproducibility bundle for paper/post artifacts
./scripts/generate_repro_bundle.sh
```

For stronger proving settings in the bundle:

```bash
STARK_PROFILE=production-v1 INCLUDE_FIBONACCI_PROOF=1 ./scripts/generate_repro_bundle.sh
```

### Example Output

```
program: programs/fibonacci.tvm
engine: transformer
steps: 103
halted: true
acc: 21
zero_flag: false
memory: [13, 21, 21, 7, 7]
elapsed_ms: 9.760
throughput_steps_per_sec: 10553.55
```

______________________________________________________________________

## The Assembly Language

Programs are `.tvm` files with a compact assembly syntax.

**Fibonacci(8) = 21:**

```asm
.memory 5
.init 0 0
.init 1 1
.init 3 0
.init 4 7

loop:
  LOAD 3
  SUBM 4
  JZ done
  LOAD 0
  ADDM 1
  STORE 2
  LOAD 1
  STORE 0
  LOAD 2
  STORE 1
  LOAD 3
  ADD 1
  STORE 3
  JMP loop

done:
  LOAD 1
  HALT
```

**Recursive factorial (5! = 120):**

```asm
.memory 11

LOADI 5
CALL fact
HALT

fact:
  JZ fact_base
  PUSH
  SUB 1
  CALL fact
  STORE 0
  POP
  MULM 0
  RET

fact_base:
  LOADI 1
  RET
```

<details>
<summary><strong>Full instruction set</strong></summary>

| Instruction  | Effect                                                |
| ------------ | ----------------------------------------------------- |
| `NOP`        | No operation                                          |
| `LOADI imm`  | `ACC = imm`                                           |
| `LOAD addr`  | `ACC = MEM[addr]`                                     |
| `STORE addr` | `MEM[addr] = ACC`                                     |
| `PUSH`       | `SP -= 1; MEM[SP] = ACC`                              |
| `POP`        | `ACC = MEM[SP]; SP += 1`                              |
| `ADD imm`    | `ACC += imm`                                          |
| `ADDM addr`  | `ACC += MEM[addr]`                                    |
| `SUB imm`    | `ACC -= imm`                                          |
| `SUBM addr`  | `ACC -= MEM[addr]`                                    |
| `MUL imm`    | `ACC *= imm`                                          |
| `MULM addr`  | `ACC *= MEM[addr]`                                    |
| `AND imm`    | `ACC &= imm`                                          |
| `ANDM addr`  | `ACC &= MEM[addr]`                                    |
| `OR imm`     | `ACC \|= imm`                                         |
| `ORM addr`   | `ACC \|= MEM[addr]`                                   |
| `XOR imm`    | `ACC ^= imm`                                          |
| `XORM addr`  | `ACC ^= MEM[addr]`                                    |
| `CMP imm`    | `ACC = ACC - imm; carry_flag = ACC < imm`             |
| `CMPM addr`  | `ACC = ACC - MEM[addr]; carry_flag = ACC < MEM[addr]` |
| `CALL label` | Push return address, jump                             |
| `RET`        | Pop return address, jump                              |
| `JMP label`  | Unconditional jump                                    |
| `JZ label`   | Jump if `zero_flag`                                   |
| `JNZ label`  | Jump if not `zero_flag`                               |
| `HALT`       | Stop execution                                        |

</details>

______________________________________________________________________

## Execution Engines

The same compiled program runs through four independent backends. The verifier executes
them in lockstep and fails on the first divergence.

| Engine                | What it is                                                           | Purpose                  |
| --------------------- | -------------------------------------------------------------------- | ------------------------ |
| **TransformerVm**     | Encode-attend-FFN loop with hull-backed memory                       | The transformer runtime  |
| **NativeInterpreter** | Direct ISA semantics, no transformer structure                       | Semantic oracle          |
| **BurnRuntime**       | Same compiled weights through [Burn](https://burn.dev) tensors       | Tensor-level cross-check |
| **OnnxRuntime**       | Exported ONNX models through [Tract](https://github.com/sonos/tract) | Portable format proof    |

```bash
# Pick an engine
cargo run --bin tvm -- run programs/fibonacci.tvm --engine native
cargo run --bin tvm -- run programs/fibonacci.tvm --engine transformer
cargo run --features burn-model --bin tvm -- run programs/fibonacci.tvm --engine burn
cargo run --features onnx-export --bin tvm -- run programs/fibonacci.tvm --engine onnx

# Differential verification
cargo run --bin tvm -- run programs/fibonacci.tvm --verify-native
cargo run --features full --bin tvm -- run programs/fibonacci.tvm --verify-all
```

If `--verify-all` passes and `scripts/validate_onnx.py` reproduces the result from
exported ONNX files, the computation is not trapped inside custom Rust structs. It is a
real, portable transformer computation with independent cross-checks.

### ONNX Export + Python Validation

```bash
# Export ONNX models
cargo run --features onnx-export --bin tvm -- export-onnx programs/fibonacci.tvm -o compiled/fibonacci

# Reproduce in Python with onnxruntime
python3 -m venv .venv
source .venv/bin/activate
pip install -r scripts/requirements.txt
python3 scripts/validate_onnx.py compiled/fibonacci \
  --program-name fibonacci --expected-acc 21 --expected-halted true
```

On PEP-668-managed Python installations, use the local venv above rather than system
`pip`.

______________________________________________________________________

## Proof Stack

The vanilla STARK prover operates over **F_p** where p = 1 + 407 · 2^119 (a 128-bit
prime with a large power-of-two subgroup for NTT). The in-repo implementation includes:

| Component         | What it does                                                        |
| ----------------- | ------------------------------------------------------------------- |
| `field.rs`        | Montgomery-form arithmetic via `ark-ff`                             |
| `polynomial.rs`   | Univariate polynomial ops, Lagrange interpolation                   |
| `ntt.rs`          | Number-theoretic transform for O(n log n) polynomial multiplication |
| `multivariate.rs` | Multivariate polynomial representation for AIR constraints          |
| `merkle.rs`       | Blake2b Merkle trees for commitment                                 |
| `fri.rs`          | FRI protocol for low-degree testing                                 |
| `stark.rs`        | STARK prover and verifier                                           |
| `proof.rs`        | VM-specific AIR: transition constraints from instruction semantics  |

The AIR encodes each supported instruction as polynomial transition constraints over the
trace columns `(PC, ACC, SP, zero_flag, carry_flag, halted, MEM[0..n])`. The boundary
constraints pin the initial and final machine states.

```bash
# Prove
cargo run --bin tvm -- prove-stark programs/factorial_recursive.tvm -o fact.proof.json

# Prove with the named production profile (v1)
cargo run --bin tvm -- prove-stark programs/factorial_recursive.tvm -o fact.proof.json \
  --stark-profile production-v1

# Prove with explicit STARK options (overrides any selected profile)
cargo run --bin tvm -- prove-stark programs/factorial_recursive.tvm -o fact.proof.json \
  --stark-profile production-v1 \
  --stark-expansion-factor 8 --stark-num-colinearity-checks 16 --stark-security-level 32

# Exercise the experimental S-two backend on the shipped arithmetic fixtures
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  prove-stark programs/addition.tvm -o addition.stwo.proof.json --backend stwo
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  prove-stark programs/dot_product.tvm -o dot.stwo.proof.json --backend stwo --max-steps 256
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  prove-stark programs/fibonacci.tvm -o fibonacci.stwo.proof.json --backend stwo --max-steps 256

# Produce and verify the binary-step lookup and normalization demos on the same CLI surface
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  prove-stwo-lookup-demo -o lookup.stwo.proof.json
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  verify-stwo-lookup-demo lookup.stwo.proof.json
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  prove-stwo-normalization-demo -o normalization.stwo.proof.json
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  verify-stwo-normalization-demo normalization.stwo.proof.json

# Produce and verify the shared-table lookup demos
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  prove-stwo-shared-lookup-demo -o shared-lookup.stwo.proof.json
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  verify-stwo-shared-lookup-demo shared-lookup.stwo.proof.json
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  prove-stwo-shared-normalization-demo -o shared-normalization.stwo.proof.json
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  verify-stwo-shared-normalization-demo shared-normalization.stwo.proof.json

# Produce and verify the fixed-shape proof-carrying decoding demo chain
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  prove-stwo-decoding-demo -o decoding.stwo.chain.json
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  verify-stwo-decoding-demo decoding.stwo.chain.json

# Produce and verify the parameterized decoding-family demo chain
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  prove-stwo-decoding-family-demo -o decoding-family.stwo.chain.json
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  verify-stwo-decoding-family-demo decoding-family.stwo.chain.json

# Extract and verify a standalone shared lookup artifact from a verified Phase 12 chain
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  prepare-stwo-shared-lookup-artifact --proof decoding-family.stwo.chain.json \
  --artifact-commitment <artifact_commitment> -o shared-lookup-artifact.stwo.json
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  verify-stwo-shared-lookup-artifact --artifact shared-lookup-artifact.stwo.json \
  --proof decoding-family.stwo.chain.json

# Derive and verify a standalone Phase 30 decoding-step proof-envelope manifest
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  prepare-stwo-decoding-step-envelope-manifest --proof decoding-family.stwo.chain.json \
  -o decoding-step-envelope-manifest.stwo.json
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  verify-stwo-decoding-step-envelope-manifest --manifest decoding-step-envelope-manifest.stwo.json \
  --proof decoding-family.stwo.chain.json

# Produce and verify the parameterized decoding layout-matrix demo
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  prove-stwo-decoding-layout-matrix-demo -o decoding-layout-matrix.stwo.json
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  verify-stwo-decoding-layout-matrix-demo decoding-layout-matrix.stwo.json

# Produce and verify the chunked-history decoding demo
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  prove-stwo-decoding-chunked-history-demo -o decoding-chunked-history.stwo.json
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  verify-stwo-decoding-chunked-history-demo decoding-chunked-history.stwo.json

# Produce and verify the segmented-history decoding demo
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  prove-stwo-decoding-history-segments-demo -o decoding-history-segments.stwo.json
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  verify-stwo-decoding-history-segments-demo decoding-history-segments.stwo.json

# Produce and verify the rollup-over-segments decoding demo
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  prove-stwo-decoding-history-rollup-demo -o decoding-history-rollup.stwo.json
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  verify-stwo-decoding-history-rollup-demo decoding-history-rollup.stwo.json

# Produce and verify the layout-matrix over Phase 16 rollups
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  prove-stwo-decoding-history-rollup-matrix-demo -o decoding-history-rollup-matrix.stwo.json
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  verify-stwo-decoding-history-rollup-matrix-demo decoding-history-rollup-matrix.stwo.json

# Produce and verify the Phase 21 matrix accumulator over Phase 17 rollup matrices
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  prove-stwo-decoding-matrix-accumulator-demo -o decoding-matrix-accumulator.stwo.json
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  verify-stwo-decoding-matrix-accumulator-demo decoding-matrix-accumulator.stwo.json

# Produce and verify the Phase 22 lookup accumulator over a Phase 21 matrix accumulator
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  prove-stwo-decoding-lookup-accumulator-demo -o decoding-lookup-accumulator.stwo.json
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  verify-stwo-decoding-lookup-accumulator-demo decoding-lookup-accumulator.stwo.json

# Produce and verify the Phase 23 cross-step lookup accumulator over cumulative Phase 22 prefixes
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  prove-stwo-decoding-cross-step-lookup-accumulator-demo \
  -o decoding-cross-step-lookup-accumulator.stwo.json
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  verify-stwo-decoding-cross-step-lookup-accumulator-demo \
  decoding-cross-step-lookup-accumulator.stwo.json

# Produce and verify the Phase 24 full carried-state relation accumulator over Phase 23 members
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  prove-stwo-decoding-state-relation-accumulator-demo \
  -o decoding-state-relation-accumulator.stwo.json
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  verify-stwo-decoding-state-relation-accumulator-demo \
  decoding-state-relation-accumulator.stwo.json

# Produce and verify the Phase 25 honest intervalized carried-state relation over Phase 24 members
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  prove-stwo-intervalized-decoding-state-relation-demo \
  -o decoding-intervalized-state-relation.stwo.json
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  verify-stwo-intervalized-decoding-state-relation-demo \
  decoding-intervalized-state-relation.stwo.json

# Produce and verify the Phase 26 folded carried-state accumulator over Phase 25 intervals
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  prove-stwo-folded-intervalized-decoding-state-relation-demo \
  -o decoding-folded-intervalized-state-relation.stwo.json
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  verify-stwo-folded-intervalized-decoding-state-relation-demo \
  decoding-folded-intervalized-state-relation.stwo.json

# Produce and verify the Phase 27 chained fold-of-folds carried-state accumulator over Phase 26 members
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  prove-stwo-chained-folded-intervalized-decoding-state-relation-demo \
  -o decoding-chained-folded-intervalized-state-relation.stwo.json
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  verify-stwo-chained-folded-intervalized-decoding-state-relation-demo \
  decoding-chained-folded-intervalized-state-relation.stwo.json

# Produce and verify the Phase 28 proof-carrying aggregate over Phase 27 chained artifacts
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  prove-stwo-aggregated-chained-folded-intervalized-decoding-state-relation-demo \
  -o decoding-aggregated-chained-folded-intervalized-state-relation.stwo.json
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  verify-stwo-aggregated-chained-folded-intervalized-decoding-state-relation-demo \
  decoding-aggregated-chained-folded-intervalized-state-relation.stwo.json

# Derive and verify the Phase 29 input contract that future recursion/compression must consume
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  prepare-stwo-recursive-compression-input-contract \
  --phase28 decoding-aggregated-chained-folded-intervalized-state-relation.stwo.json \
  -o recursive-compression-input-contract.stwo.json
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  verify-stwo-recursive-compression-input-contract \
  --input recursive-compression-input-contract.stwo.json

# Freeze a canonical pre-aggregation batch manifest for future recursion work
cargo +nightly-2025-07-14 run --features stwo-backend --bin tvm -- \
  prepare-stwo-recursion-batch \
  --proof addition.stwo.proof.json \
  --proof dot.stwo.proof.json \
  -o recursion-batch.json

# Verify (statement-v1 includes lockstep re-execution)
cargo run --bin tvm -- verify-stark fact.proof.json

# Verify and re-execute transformer/native runtimes from claim data
cargo run --bin tvm -- verify-stark fact.proof.json --reexecute

# Verify with the production verification profile (reexec + minimum 32 bits)
cargo run --bin tvm -- verify-stark fact.proof.json --verification-profile production-v1

# Verify with a custom minimum conjectured-security policy and strict mode
cargo run --bin tvm -- verify-stark fact.proof.json --min-conjectured-security 64
cargo run --bin tvm -- verify-stark fact.proof.json --strict
```

`prove-stark` first runs transformer/native lockstep verification and aborts on any
divergence before emitting a proof. The STARK witness trace is then built from the
transformer execution trace. Proof claims now include explicit statement metadata:

- `statement_version = statement-v1`
- `semantic_scope = native_isa_execution_with_transformer_native_equivalence_check`

Verifier checks enforce both fields exactly, so claim wording cannot drift from what is
actually being verified. Proof claims also include transformer config, equivalence
metadata (`equivalence_checked_steps`, transformer fingerprint, native fingerprint), and
artifact commitments (program hash, config hash, deterministic-model hash, STARK-options
hash, prover-build info/hash) in CLI output. Verifier policy checks are available via
`--min-conjectured-security`; `--strict` enforces an 80-bit floor and turns on
re-execution checks.

### Experimental `stwo` Surface

- Backend flag: `--features stwo-backend`
- Toolchain: `cargo +nightly-2025-07-14`
- Upstream crates: `stwo` and `stwo-constraint-framework` at `2.2.0`
- Claim boundary: still `statement-v1`

#### Current Fixture Set

The public `stwo` proving path currently proves and verifies these shipped fixtures
under `statement-v1`:

- arithmetic fixtures: `programs/addition.tvm`, `programs/counter.tvm`,
  `programs/memory_roundtrip.tvm`, `programs/multiply.tvm`, `programs/dot_product.tvm`,
  `programs/fibonacci.tvm`, `programs/matmul_2x2.tvm`, `programs/single_neuron.tvm`
- transformer-shaped fixtures: `programs/gemma_block_v1.tvm`,
  `programs/gemma_block_v2.tvm`, `programs/gemma_block_v3.tvm`,
  `programs/gemma_block_v4.tvm`

Broader arithmetic-subset AIR coverage exists beyond those fixtures, but that surface is
not yet exposed as a public end-to-end proving path.

#### Lookup Demos

The repo exposes dedicated serialized proof artifacts and CLI commands for:

- single-row binary-step lookup and normalization demos
- shared-table multi-claim lookup and normalization demos

That means the lookup-backed components are part of the public proof workflow, not just
internal metadata or library-only helpers.

#### Decoding Families

The public decoding artifacts currently cover:

- fixed-shape `decoding_step_v1`
- parameterized `decoding_step_v2`

Those power the proof-carrying decoding demos, including layout-bound carried state,
rolling KV-cache windows, cumulative KV-history commitments, and the pre-recursive
packaging objects discussed in the paper. The detailed phase chronology for this line
now lives in
[`docs/engineering/design/engineering-timeline.md`](docs/engineering/design/engineering-timeline.md),
so the public README can stay focused on current proof surfaces rather than internal
implementation sequencing.

#### Explicit Non-Goals

- not a full `stwo` zkML backend for standard-softmax transformers
- not full public end-to-end proving for every arithmetic-subset program
- not recursive proving yet

Programs outside the current proven fixture set still fail cleanly on the
execution-proof `stwo` path, which keeps the claim boundary honest.

The canonical machine-readable statement contract is checked into
`spec/statement-v1.json`. CI enforces sync between this file and verifier constants via:

```bash
cargo test --quiet statement_spec_contract_is_synced_with_constants
```

### Claim Boundaries

`statement-v1` (cryptographically proven):

- STARK proof attests to native ISA execution trace validity.
- Verifier enforces `statement_version = statement-v1` and
  `semantic_scope = native_isa_execution_with_transformer_native_equivalence_check`.
- Verification can re-execute transformer/native runtimes from claim data, and the
  strict/default production verification path enforces agreement with claimed outputs
  and equivalence fingerprints.

`research-v2` (research artifacts, not yet a full STARK claim about transformer/ONNX
semantics):

- `research-v2-step`, `research-v2-trace`, and `research-v2-matrix` generate semantic
  equivalence certificates with cryptographic commitments.
- These artifacts are publication evidence and regression guards, but they are not
  currently embedded into the `statement-v1` STARK proof relation.

`research-v3` (research artifacts, not yet a full implementation-equivalence proof):

- `research-v3-equivalence` checks transformer, native, Burn, and ONNX/Tract runtimes in
  lockstep and emits an equivalence-kernel artifact with rule witnesses, bounded trace
  rows, semantic canonical event rows, per-engine transition relation hashes, and
  commitment hashes.
- `verify-research-v3-equivalence` verifies the artifact boundary by recomputing
  internal commitments, bounded trace hashes, semantic canonical event-relation hashes,
  cross-engine state-boundary consistency, final-state links, and per-engine transition
  relation hashes.
- The artifact is deliberately bounded: it is not an e-graph saturation result,
  SMT-backed rewrite proof, randomized opaque-kernel test suite, or cryptographic proof
  of implementation equivalence.

### Production Profile (v1)

`production-v1` is a practical local proving profile intended for routine CI/integration
checks:

- `expansion_factor = 4`
- `num_colinearity_checks = 16`
- `security_level = 32`
- `conjectured_security_bits = 32`
- target proving budget: `<= 45s` (release build, `programs/fibonacci.tvm`, 103 steps)

Measured reference (local release build):

| Profile       | Settings `(expansion, q, security)` | Conjectured bits | Prove time (`fibonacci`, 103 steps) |
| ------------- | ----------------------------------- | ---------------- | ----------------------------------- |
| default       | `(4, 2, 2)`                         | 4                | ~7-12s                              |
| production-v1 | `(4, 16, 32)`                       | 32               | ~29s                                |
| heavier       | `(8, 16, 32)`                       | 48               | ~61s                                |

Verification checks STARK validity and (for the current `statement-v1` semantic scope)
re-executes transformer/native lockstep to enforce equivalence against claim outputs.

The proof is transparent and public. The claim includes statement metadata
(`statement_version`, `semantic_scope`), the program, attention mode/configuration, step
count, final state, equivalence metadata, and claim commitments. Zero-knowledge hiding
is out of scope.

### Research V2 One-Step Semantic Artifact

For research toward `statement-v2`, the CLI can generate a one-step transformer-vs-ONNX
semantic equivalence artifact for a toy/target program:

```bash
cargo run --features onnx-export --bin tvm -- research-v2-step programs/addition.tvm \
  -o compiled/research-v2-addition-step.json --max-steps 1
```

This checks a single step across transformer and ONNX runtimes and emits a JSON artifact
with:

- statement metadata (`statement-v2-research-draft`)
- fixed-point profile and ONNX op subset version
- pre/post machine states
- commitment hashes for specs, program/config, and runtime outputs

Canonical research-v2 spec files:

- `spec/statement-v2-research.json`
- `spec/fixed-point-semantics-v2.json`
- `spec/onnx-op-subset-v2.json`
- `spec/statement-v2-one-step-certificate.schema.json`

### Research V2 Prefix-Trace Semantic Artifact

For deeper research evidence, generate a prefix trace certificate across up to `N`
steps:

```bash
cargo run --features onnx-export --bin tvm -- research-v2-trace programs/addition.tvm \
  -o compiled/research-v2-addition-trace.json --max-steps 8
```

This checks transformer and ONNX step-by-step, emits mismatch localization
(`first_mismatch_step`, `mismatch_reason`), and includes trace/final-state commitments.
By default, the command still writes the artifact but exits non-zero when a mismatch is
found. Use `--allow-mismatch` to keep the artifact and exit success for CI/reporting
workflows.

Additional trace spec files:

- `spec/statement-v2-trace-research.json`
- `spec/statement-v2-trace-certificate.schema.json`

### Research V2 Multi-Program Matrix Artifact

For a broader benchmark view, generate a matrix artifact across multiple programs:

```bash
cargo run --features onnx-export --bin tvm -- research-v2-matrix \
  -o compiled/research-v2-matrix.json \
  --program programs/addition.tvm \
  --program programs/counter.tvm \
  --max-steps 8
```

Or include the built-in suite (`addition`, `counter`, `fibonacci`, `multiply`,
`factorial_recursive`, `dot_product`, `matmul_2x2`, `single_neuron`):

```bash
cargo run --features onnx-export --bin tvm -- research-v2-matrix \
  -o compiled/research-v2-matrix-default-suite.json \
  --include-default-suite \
  --max-steps 32
```

The matrix artifact reports per-program match status, mismatch localization, aggregate
counts (`total_programs`, `matched_programs`, `mismatched_programs`), and a top-level
`matrix_entries_hash` commitment. By default, the command still writes the artifact but
exits non-zero when `mismatched_programs > 0`; pass `--allow-mismatch` to keep success
exits.

Additional matrix spec files:

- `spec/statement-v2-matrix-research.json`
- `spec/statement-v2-matrix-certificate.schema.json`

### Research V3 Multi-Engine Equivalence Kernel

For the first Emerge-style hardening step, generate a bounded multi-engine
equivalence-kernel artifact:

```bash
cargo run --features full --bin tvm -- research-v3-equivalence programs/addition.tvm \
  -o compiled/research-v3-addition-equivalence.json --max-steps 8
cargo run --features full --bin tvm -- verify-research-v3-equivalence \
  compiled/research-v3-addition-equivalence.json
```

This checks transformer, native, Burn, and ONNX/Tract runtimes in lockstep, then emits a
JSON artifact with engine summaries, deterministic rule witnesses, bounded trace rows,
semantic canonical event rows, per-engine transition relation hashes, and commitment
hashes. The transition hashes are the first narrow Emerge-style relation-kernel
hardening step: they make each same-instruction state transition explicit without
claiming equality saturation or synthesized rewrite validation. The verifier command
recomputes the artifact's internal commitments, bounded trace hashes, semantic canonical
event-relation hashes, engine final-state hashes, cross-engine state-boundary
consistency, and transition relation hashes; it is an artifact-integrity check, not a
proof that independent model implementations are equivalent in general. The artifact
also carries a frontend/runtime semantics registry that separates currently checked
lanes from these research-watch lanes: `torch-export`, `executorch`, `stablehlo`,
`iree`, `onnx-mlir`, `tvm-unity`, `vllm`, `sglang`, and `egg-emerge`. It intentionally
does not claim support for those watch lanes, e-graph saturation, SMT-backed rewrite
synthesis, randomized opaque-kernel testing, or a cryptographic
implementation-equivalence proof.

Canonical research-v3 spec files:

- `spec/statement-v3-equivalence-kernel-research.json`
- `spec/statement-v3-equivalence-kernel.schema.json`
- `spec/frontend-runtime-semantics-registry-v1.json`

### Hugging Face Provenance Manifest

For HF-backed model or artifact releases, prepare a bounded provenance manifest:

```bash
cargo run --bin tvm -- prepare-hf-provenance-manifest \
  -o compiled/hf-provenance.json \
  --hub-repo org/model \
  --hub-revision <pinned-commit-or-release-tag> \
  --tokenizer-id org/model \
  --tokenizer-json path/to/tokenizer.json \
  --safetensors path/to/model.safetensors \
  --onnx-model path/to/model.onnx \
  --onnx-metadata path/to/metadata.json \
  --onnx-external-data path/to/model.onnx_data \
  --model-card path/to/README.md
cargo run --bin tvm -- verify-hf-provenance-manifest compiled/hf-provenance.json
```

This manifest is deliberately a provenance artifact, not a proving claim. It pins the
Hub repo/revision, tokenizer identity/revision, optional tokenizer files and
tokenization transcripts, local `safetensors` file hashes plus parsed metadata-header
hashes/tensor counts, optional ONNX graph/metadata/external-data file hashes, and
optional model-card/DOI/dataset release metadata. The verifier rejects floating Hub
revisions such as `main`, recomputes local file hashes, recomputes the manifest
commitments, and rejects safetensors metadata drift. It does not prove tokenizer
algorithm correctness, safetensors architectural semantics, ONNX exporter semantic
equivalence, ONNX metadata semantic correctness, live Hub availability, DOI
validity, or GitHub/Sigstore/in-toto/SLSA attestation validity. The current wire
format also carries `sha256` digests for bound files so release assets can be
matched against attestation subject digests without turning the manifest into an
attestation verifier.

The current manifest wire format is `hf-provenance-manifest-v4`. Older
`hf-provenance-manifest-v1`, `hf-provenance-manifest-v2`, and
`hf-provenance-manifest-v3` files must be regenerated before verification
because the ONNX sidecar surface, hub-binding commitment, and
attestation-digest inventory now have explicit versioned format boundaries.

Canonical HF provenance spec file:

- `spec/hf-provenance-manifest.schema.json`

### Reproducibility Bundle

For publication-ready artifacts (benchmarks, proofs, semantic agreement artifacts,
hashes), run:

```bash
./scripts/generate_repro_bundle.sh
```

Outputs are written to `compiled/repro-bundle/`:

- `manifest.txt` (commit + toolchain + environment)
- `benchmarks.tsv` (timings by command)
- `sha256sums.txt` (hashes for generated artifacts)
- STARK proof files and `research-v2` / `research-v3` certificates used for evidence
  sections

Additional committed transformer-shaped semantic artifacts live under:

- `docs/paper/artifacts/transformer-soft-attention-v1/`
- `docs/paper/artifacts/transformer-soft-attention-v1/soft_attention_memory-step.json`
- `docs/paper/artifacts/transformer-soft-attention-v1/soft_attention_memory-trace.json`

______________________________________________________________________

## Attention Modes

| Mode             | Behavior                              | Flag                               |
| ---------------- | ------------------------------------- | ---------------------------------- |
| `average-hard`   | Deterministic argmax via convex hull  | Default                            |
| `softmax`        | Weighted read over full write history | `--attention-mode softmax`         |
| `hard-softmax:T` | Temperature-interpolated              | `--attention-mode hard-softmax:10` |

The `average-hard` mode is the only one supported by the STARK proof path. `softmax` and
`hard-softmax` are available for experimentation and comparison.

______________________________________________________________________

## Feature Flags

| Flag           | Enables                                                                                          |
| -------------- | ------------------------------------------------------------------------------------------------ |
| *(default)*    | Transformer runtime, native interpreter, TUI, STARK prover                                       |
| `burn-model`   | Burn tensor execution engine, `--verify-burn`                                                    |
| `onnx-export`  | ONNX export, Tract execution engine, `--verify-onnx`                                             |
| `stwo-backend` | Experimental S-two backend seam for `prove-stark --backend stwo` / `verify-stark --backend stwo` |
| `full`         | `burn-model` + `onnx-export`, plus `--verify-all` convenience workflows                          |

```bash
cargo test                    # Core suite
cargo test --features full    # Everything
cargo bench                   # Hull + STARK benchmarks
```

`cargo test` is not a fast smoke check here: several suites generate and verify real
STARK proofs, so full runs can take 10-30+ minutes depending on machine and enabled
features.

## Development Checks

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

The CLI is self-documenting:

```bash
cargo run --bin tvm -- --help
cargo run --bin tvm -- run --help
```

______________________________________________________________________

## Repository Structure

```
src/
  assembly.rs           # .tvm parser, directives, labels
  compiler.rs           # Program → transformer weights
  config.rs             # VM configuration, attention modes
  engine.rs             # Execution traits, trace events
  geometry.rs           # Point2D, HullKvCache (convex hull memory)
  model.rs              # 2D attention + compiled FFN blocks
  runtime.rs            # Transformer execution loop
  interpreter.rs        # Native reference interpreter
  state.rs              # MachineState encoding (d_model = 36)
  memory.rs             # Addressed memory with write histories
  proof.rs              # VM AIR construction, STARK integration
  stwo_backend/         # Experimental S-two adapter + layout seam
  verification.rs       # Lockstep multi-engine differential verification
  tui.rs                # Interactive terminal viewer
  bin/tvm.rs            # CLI (clap)
  vanillastark/         # Field, polynomial, NTT, Merkle, FRI, STARK
  burn_model.rs         # Burn Module definitions (optional)
  burn_runtime.rs       # Burn execution loop (optional)
  onnx_export.rs        # ONNX graph generation (optional)
  onnx_runtime.rs       # Tract execution runtime (optional)
tests/                  # Unit, integration, property, differential, CLI tests
programs/               # Example .tvm programs
benches/                # Criterion benchmarks
scripts/                # Python ONNX validator
```

~10k lines of Rust. ~3k lines of tests. ~3k lines of STARK internals.

______________________________________________________________________

## Scope and Status

This repository is intentionally narrow. It is trying to make a difficult claim
correctly, not to look broad.

| Area                                                | Status              | Notes                                                                                   |
| --------------------------------------------------- | ------------------- | --------------------------------------------------------------------------------------- |
| Compact ISA + deterministic transformer runtime     | Implemented         | Arithmetic, memory, stack, and control flow                                             |
| Lockstep multi-engine execution                     | Implemented         | Transformer, native, Burn, and ONNX surfaces                                            |
| Vanilla STARK proving                               | Implemented         | Stable `statement-v1` path                                                              |
| Experimental `stwo` proving                         | Implemented, narrow | Shipped fixtures, lookup demos, transformer-shaped fixtures, bounded decoding artifacts |
| Full standard-softmax transformer proving on `stwo` | Not implemented     | Still outside the current claim boundary                                                |
| Zero-knowledge hiding                               | Not implemented     | Current proofs are transparent, not hiding                                              |
| Full-ISA STARK AIR for bitwise/compare              | Not implemented     | Broader subset exists, but not full public proof coverage                               |

### Experimental `stwo` Backend

- Backend flag: `--features stwo-backend`
- Toolchain: `cargo +nightly-2025-07-14`
- Upstream crates: `stwo` and `stwo-constraint-framework` at `2.2.0`
- Claim boundary: still `statement-v1`

#### Current Fixture Set

The public `stwo` proving path currently proves and verifies these shipped fixtures
under `statement-v1`:

- arithmetic fixtures: `programs/addition.tvm`, `programs/counter.tvm`,
  `programs/memory_roundtrip.tvm`, `programs/multiply.tvm`, `programs/dot_product.tvm`,
  `programs/fibonacci.tvm`, `programs/matmul_2x2.tvm`, `programs/single_neuron.tvm`
- transformer-shaped fixtures: `programs/gemma_block_v1.tvm`,
  `programs/gemma_block_v2.tvm`, `programs/gemma_block_v3.tvm`,
  `programs/gemma_block_v4.tvm`
- decoding families: fixed-shape `decoding_step_v1` and parameterized `decoding_step_v2`

The broader Phase 2 arithmetic subset (`NOP`, `LOADI`, `LOAD`, `STORE`, `ADD`, `ADDM`,
`SUBM`, `MULM`, `JMP`, `JZ`, `HALT`) is implemented at the AIR/trace level and covered
by internal constraint tests, but end-to-end `stwo` proving is only validated publicly
for the shipped fixture set and decoding families.

#### Lookup Demos

The repo exposes dedicated serialized proof artifacts and CLI commands for:

- single-row binary-step lookup and normalization demos
- shared-table multi-claim lookup and normalization demos

That means the lookup-backed components are part of the public proof workflow, not just
internal metadata or library-only helpers.

#### Decoding Families

The public decoding artifacts currently cover:

- fixed-shape `decoding_step_v1`
- parameterized `decoding_step_v2`

Those power the proof-carrying decoding demos, including layout-bound carried state,
rolling KV-cache windows, cumulative KV-history commitments, mergeable history segments,
rollups, rollup matrices, and pre-recursive aggregation bundles. The detailed internal
phase chronology and transition notes now live in
[`docs/engineering/design/engineering-timeline.md`](docs/engineering/design/engineering-timeline.md),
so the public README stays publication-facing.

#### Explicit Non-Goals

- not a full `stwo` zkML backend for standard-softmax transformers
- not full public end-to-end proving for every arithmetic-subset program
- not recursive proving yet

This is still not a full `stwo` zkML backend for standard-softmax transformers, but it
is well past the old “dependency seam only” stage.

### Frozen Publication Artifacts

- Vanilla reproducibility bundle: generated by `./scripts/generate_repro_bundle.sh`
- Frozen narrow experimental `stwo` bundle:
  `docs/paper/artifacts/stwo-experimental-v1-2026-04-06/`
- Frozen proof-carrying aggregation bundle:
  `docs/paper/artifacts/stwo-proof-carrying-aggregation-v1-2026-04-11/`
- Publication-facing artifact index: `docs/paper/artifacts/README.md`
- Proof-carrying aggregation `stwo` bundle regeneration script:
  `scripts/paper/generate_stwo_proof_carrying_aggregation_bundle.sh`
- `stwo` publication bundle regeneration script:
  `scripts/paper/generate_stwo_publication_bundle.sh`

Older carried-state bundle generators remain available for archival provenance and
engineering comparison, but the current paper package cites the frozen experimental
`stwo` bundle and the frozen proof-carrying aggregation bundle.

Archival provenance generators:

- `scripts/paper/generate_stwo_accumulation_bundle.sh`
- `scripts/paper/generate_stwo_folded_interval_bundle.sh`
- `scripts/paper/generate_stwo_chained_folded_interval_bundle.sh`

### Project Lineage

The canonical launch repository is `omarespejel/provable-transformer-vm` (this
repository). Earlier phases of the same research line were developed under the
`llm-provable-computer` naming before consolidation here. This repository carries the
maintained artifact bundles, research-oriented semantic agreement artifacts,
transformer-shaped fixtures, shared-table lookup proofs, and proof-carrying decoding
artifacts.

______________________________________________________________________

## References

- [Can LLMs Be Computers?](https://www.percepta.ai/blog/can-llms-be-computers) ---
  Percepta. The original idea.
- [Scalable, Transparent, and Post-Quantum Secure Computational Integrity](https://eprint.iacr.org/2018/046)
  --- Ben-Sasson et al., 2018. The STARK protocol.
- [Circle STARKs](https://eprint.iacr.org/2024/278) --- Haböck, Levit, Papini, 2024.
  STARKs over Mersenne prime fields.
- [STWO Prover](https://github.com/starkware-libs/stwo) --- StarkWare's production
  Circle STARK prover.
- [Anatomy of a STARK](https://aszepieniec.github.io/stark-anatomy/) --- Aszepieniec.
  The reference implementation this STARK is ported from.

## License

MIT
