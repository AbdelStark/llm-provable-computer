use std::fs;
use std::path::Path;

use blake2::digest::{Update, VariableOutput};
use blake2::{Blake2b512, Blake2bVar, Digest};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::Attention2DMode;
use crate::config::TransformerVmConfig;
use crate::engine::ExecutionResult;
use crate::error::{Result, VmError};
use crate::instruction::{Instruction, Program};
use crate::model::TransformerVm;
use crate::runtime::ExecutionRuntime;
use crate::state::MachineState;
use crate::stwo_backend;
use crate::vanillastark::{FieldElement, MPolynomial, Stark};
use crate::verification::verify_model_against_native;

const PC: usize = 0;
const ACC: usize = 1;
const SP: usize = 2;
const ZERO: usize = 3;
const CARRY: usize = 4;
const HALTED: usize = 5;
const MACHINE_STATE_PREFIX: usize = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum StarkProofBackend {
    #[default]
    Vanilla,
    Stwo,
}

impl std::fmt::Display for StarkProofBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Vanilla => f.write_str("vanilla"),
            Self::Stwo => f.write_str("stwo"),
        }
    }
}

const VANILLA_STARK_BACKEND_VERSION_V1: &str = "vanilla-v1";
fn default_stark_proof_backend() -> StarkProofBackend {
    StarkProofBackend::Vanilla
}

fn default_stark_proof_backend_version() -> String {
    VANILLA_STARK_BACKEND_VERSION_V1.to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VanillaStarkProofOptions {
    pub expansion_factor: usize,
    pub num_colinearity_checks: usize,
    pub security_level: usize,
}

impl Default for VanillaStarkProofOptions {
    fn default() -> Self {
        Self {
            expansion_factor: 4,
            num_colinearity_checks: 2,
            security_level: 2,
        }
    }
}

/// Production STARK profile (v1) tuned for local proving throughput in release builds.
///
/// This profile targets ~32 conjectured security bits while keeping proving time under
/// roughly 45 seconds for the 103-step `programs/fibonacci.tvm` benchmark on a modern laptop.
pub fn production_v1_stark_options() -> VanillaStarkProofOptions {
    VanillaStarkProofOptions {
        expansion_factor: 4,
        num_colinearity_checks: 16,
        security_level: 32,
    }
}

/// Minimum conjectured security floor expected when verifying production-v1 proofs.
pub const PRODUCTION_V1_MIN_CONJECTURED_SECURITY_BITS: u32 = 32;

/// Target proving-time budget for production-v1 on local release builds.
pub const PRODUCTION_V1_TARGET_MAX_PROVING_SECONDS: u64 = 45;

const VANILLA_STARK_FIELD_SECURITY_BITS: u32 = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StarkVerificationPolicy {
    pub min_conjectured_security_bits: u32,
}

impl StarkVerificationPolicy {
    pub fn strict() -> Self {
        Self {
            min_conjectured_security_bits: 80,
        }
    }
}

impl Default for StarkVerificationPolicy {
    fn default() -> Self {
        Self {
            min_conjectured_security_bits: 0,
        }
    }
}

pub fn production_v1_verification_policy() -> StarkVerificationPolicy {
    StarkVerificationPolicy {
        min_conjectured_security_bits: PRODUCTION_V1_MIN_CONJECTURED_SECURITY_BITS,
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VanillaStarkExecutionClaim {
    #[serde(default)]
    pub statement_version: String,
    #[serde(default)]
    pub semantic_scope: String,
    pub program: Program,
    pub attention_mode: Attention2DMode,
    #[serde(default)]
    pub transformer_config: Option<TransformerVmConfig>,
    pub steps: usize,
    pub final_state: MachineState,
    pub options: VanillaStarkProofOptions,
    #[serde(default)]
    pub equivalence: Option<ExecutionEquivalenceMetadata>,
    #[serde(default)]
    pub commitments: Option<ExecutionClaimCommitments>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VanillaStarkExecutionProof {
    #[serde(default = "default_stark_proof_backend")]
    pub proof_backend: StarkProofBackend,
    #[serde(default = "default_stark_proof_backend_version")]
    pub proof_backend_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stwo_auxiliary: Option<StwoAuxiliaryProofs>,
    pub claim: VanillaStarkExecutionClaim,
    pub proof: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StwoAuxiliaryProofs {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub normalization_companion: Option<StwoNormalizationCompanion>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StwoNormalizationCompanion {
    pub statement_version: String,
    pub semantic_scope: String,
    pub norm_sq_memory_index: u8,
    pub inv_sqrt_q8_memory_index: u8,
    pub expected_norm_sq: i16,
    pub expected_inv_sqrt_q8: i16,
    pub proof_envelope: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionEquivalenceMetadata {
    pub checked_steps: usize,
    pub transformer_fingerprint: String,
    pub native_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionClaimCommitments {
    pub scheme_version: String,
    pub hash_function: String,
    pub program_hash: String,
    pub transformer_config_hash: String,
    pub deterministic_model_hash: String,
    pub stark_options_hash: String,
    pub prover_build_info: String,
    pub prover_build_hash: String,
}

pub const CLAIM_COMMITMENT_SCHEME_VERSION_V1: &str = "v1";
pub const CLAIM_COMMITMENT_HASH_FUNCTION_V1: &str = "blake2b-256";
pub const CLAIM_STATEMENT_VERSION_V1: &str = "statement-v1";
pub const CLAIM_SEMANTIC_SCOPE_V1: &str =
    "native_isa_execution_with_transformer_native_equivalence_check";
const COMMITMENT_PAYLOAD_VERSION_V1: &str = "v1";

#[derive(Debug, Clone, Copy)]
struct ColumnLayout {
    memory_size: usize,
}

impl ColumnLayout {
    fn new(memory_size: usize) -> Self {
        Self { memory_size }
    }

    fn mem(&self, index: usize) -> usize {
        MACHINE_STATE_PREFIX + index
    }

    fn acc_inv(&self) -> usize {
        MACHINE_STATE_PREFIX + self.memory_size
    }

    fn sp_nonzero_inv(&self) -> usize {
        self.acc_inv() + 1
    }

    fn sp_not_top_inv(&self) -> usize {
        self.acc_inv() + 2
    }

    fn machine_state_register_count(&self) -> usize {
        MACHINE_STATE_PREFIX + self.memory_size
    }

    fn register_count(&self) -> usize {
        self.machine_state_register_count() + 3
    }
}

#[derive(Debug, Clone)]
struct VmAir {
    program: Program,
    layout: ColumnLayout,
}

impl VmAir {
    fn new(program: Program) -> Self {
        let layout = ColumnLayout::new(program.memory_size());
        Self { program, layout }
    }

    fn register_count(&self) -> usize {
        self.layout.register_count()
    }

    fn transition_degree_bound(&self) -> usize {
        self.transition_constraints()
            .iter()
            .flat_map(|constraint| constraint.dictionary.keys())
            .map(|powers| powers.iter().sum())
            .max()
            .unwrap_or(1)
            .max(2)
    }

    fn boundary_constraints(
        &self,
        steps: usize,
        final_state: &MachineState,
    ) -> Vec<(usize, usize, FieldElement)> {
        let mut boundary = Vec::new();
        let initial = MachineState::with_memory(self.program.initial_memory().to_vec());

        for (register, value) in state_public_registers(&self.layout, &initial)
            .into_iter()
            .enumerate()
        {
            boundary.push((0, register, value));
        }

        for (register, value) in state_public_registers(&self.layout, final_state)
            .into_iter()
            .enumerate()
        {
            boundary.push((steps, register, value));
        }

        boundary
    }

    fn transition_constraints(&self) -> Vec<MPolynomial> {
        let register_count = self.layout.register_count();
        let variables = MPolynomial::variables(1 + 2 * register_count);
        let current = variables[1..1 + register_count].to_vec();
        let next = variables[1 + register_count..].to_vec();

        let current_pc = current[PC].clone();
        let current_acc = current[ACC].clone();
        let current_sp = current[SP].clone();
        let current_zero = current[ZERO].clone();
        let current_memory: Vec<MPolynomial> = (0..self.layout.memory_size)
            .map(|index| current[self.layout.mem(index)].clone())
            .collect();

        let next_pc = next[PC].clone();
        let next_acc = next[ACC].clone();
        let next_sp = next[SP].clone();
        let next_zero = next[ZERO].clone();
        let next_carry = next[CARRY].clone();
        let next_halted = next[HALTED].clone();
        let next_memory: Vec<MPolynomial> = (0..self.layout.memory_size)
            .map(|index| next[self.layout.mem(index)].clone())
            .collect();
        let next_acc_inv = next[self.layout.acc_inv()].clone();
        let current_sp_nonzero_inv = current[self.layout.sp_nonzero_inv()].clone();
        let current_sp_not_top_inv = current[self.layout.sp_not_top_inv()].clone();

        let one = mp_constant(1);
        let zero = MPolynomial::zero();
        let current_stack_read = self.stack_read_expression(&current_sp, &current_memory);
        let current_stack_write_selectors = self.stack_write_selectors(&current_sp);
        let valid_pc = self.domain_zerofier(&current_pc, self.program.len());
        let valid_sp = self.domain_zerofier(&current_sp, self.layout.memory_size + 1);
        let mut expected_next_pc = MPolynomial::zero();
        let mut expected_next_acc = MPolynomial::zero();
        let mut expected_next_sp = MPolynomial::zero();
        let mut expected_next_halted = MPolynomial::zero();
        let mut expected_next_memory = vec![MPolynomial::zero(); self.layout.memory_size];
        let mut push_or_call_selector = MPolynomial::zero();
        let mut pop_or_ret_selector = MPolynomial::zero();

        let pc_selectors = self.pc_selectors(&current_pc);

        for (pc, instruction) in self.program.instructions().iter().enumerate() {
            let selector = pc_selectors[pc].clone();
            let next_pc_constant = mp_constant(i128::from((pc as u8).wrapping_add(1)));

            match *instruction {
                Instruction::Nop => {
                    expected_next_pc = expected_next_pc + selector.clone() * next_pc_constant;
                    expected_next_acc = expected_next_acc + selector.clone() * current_acc.clone();
                    expected_next_sp = expected_next_sp + selector.clone() * current_sp.clone();
                    expected_next_halted = expected_next_halted + selector * zero.clone();
                    for (index, expected) in expected_next_memory.iter_mut().enumerate() {
                        *expected = expected.clone()
                            + pc_selectors[pc].clone() * current_memory[index].clone();
                    }
                }
                Instruction::LoadImmediate(value) => {
                    expected_next_pc = expected_next_pc + selector.clone() * next_pc_constant;
                    expected_next_acc =
                        expected_next_acc + selector.clone() * mp_constant(i128::from(value));
                    expected_next_sp = expected_next_sp + selector.clone() * current_sp.clone();
                    expected_next_halted = expected_next_halted + selector * zero.clone();
                    for (index, expected) in expected_next_memory.iter_mut().enumerate() {
                        *expected = expected.clone()
                            + pc_selectors[pc].clone() * current_memory[index].clone();
                    }
                }
                Instruction::Load(address) => {
                    let loaded = current_memory[address as usize].clone();
                    expected_next_pc = expected_next_pc + selector.clone() * next_pc_constant;
                    expected_next_acc = expected_next_acc + selector.clone() * loaded;
                    expected_next_sp = expected_next_sp + selector.clone() * current_sp.clone();
                    expected_next_halted = expected_next_halted + selector * zero.clone();
                    for (index, expected) in expected_next_memory.iter_mut().enumerate() {
                        *expected = expected.clone()
                            + pc_selectors[pc].clone() * current_memory[index].clone();
                    }
                }
                Instruction::Store(address) => {
                    expected_next_pc = expected_next_pc + selector.clone() * next_pc_constant;
                    expected_next_acc = expected_next_acc + selector.clone() * current_acc.clone();
                    expected_next_sp = expected_next_sp + selector.clone() * current_sp.clone();
                    expected_next_halted = expected_next_halted + selector * zero.clone();
                    for (index, expected) in expected_next_memory.iter_mut().enumerate() {
                        let value = if index == address as usize {
                            current_acc.clone()
                        } else {
                            current_memory[index].clone()
                        };
                        *expected = expected.clone() + pc_selectors[pc].clone() * value;
                    }
                }
                Instruction::Push => {
                    push_or_call_selector = push_or_call_selector + selector.clone();
                    expected_next_pc = expected_next_pc + selector.clone() * next_pc_constant;
                    expected_next_acc = expected_next_acc + selector.clone() * current_acc.clone();
                    expected_next_sp =
                        expected_next_sp + selector.clone() * (current_sp.clone() - one.clone());
                    expected_next_halted = expected_next_halted + selector * zero.clone();
                    for (index, expected) in expected_next_memory.iter_mut().enumerate() {
                        let write_selector = current_stack_write_selectors[index].clone();
                        let value = write_selector.clone() * current_acc.clone()
                            + (one.clone() - write_selector) * current_memory[index].clone();
                        *expected = expected.clone() + pc_selectors[pc].clone() * value;
                    }
                }
                Instruction::Pop => {
                    pop_or_ret_selector = pop_or_ret_selector + selector.clone();
                    expected_next_pc = expected_next_pc + selector.clone() * next_pc_constant;
                    expected_next_acc =
                        expected_next_acc + selector.clone() * current_stack_read.clone();
                    expected_next_sp =
                        expected_next_sp + selector.clone() * (current_sp.clone() + one.clone());
                    expected_next_halted = expected_next_halted + selector * zero.clone();
                    for (index, expected) in expected_next_memory.iter_mut().enumerate() {
                        *expected = expected.clone()
                            + pc_selectors[pc].clone() * current_memory[index].clone();
                    }
                }
                Instruction::AddImmediate(value) => {
                    expected_next_pc = expected_next_pc + selector.clone() * next_pc_constant;
                    expected_next_acc = expected_next_acc
                        + selector.clone() * (current_acc.clone() + mp_constant(i128::from(value)));
                    expected_next_sp = expected_next_sp + selector.clone() * current_sp.clone();
                    expected_next_halted = expected_next_halted + selector * zero.clone();
                    for (index, expected) in expected_next_memory.iter_mut().enumerate() {
                        *expected = expected.clone()
                            + pc_selectors[pc].clone() * current_memory[index].clone();
                    }
                }
                Instruction::AddMemory(address) => {
                    let rhs = current_memory[address as usize].clone();
                    expected_next_pc = expected_next_pc + selector.clone() * next_pc_constant;
                    expected_next_acc =
                        expected_next_acc + selector.clone() * (current_acc.clone() + rhs);
                    expected_next_sp = expected_next_sp + selector.clone() * current_sp.clone();
                    expected_next_halted = expected_next_halted + selector * zero.clone();
                    for (index, expected) in expected_next_memory.iter_mut().enumerate() {
                        *expected = expected.clone()
                            + pc_selectors[pc].clone() * current_memory[index].clone();
                    }
                }
                Instruction::SubImmediate(value) => {
                    expected_next_pc = expected_next_pc + selector.clone() * next_pc_constant;
                    expected_next_acc = expected_next_acc
                        + selector.clone() * (current_acc.clone() - mp_constant(i128::from(value)));
                    expected_next_sp = expected_next_sp + selector.clone() * current_sp.clone();
                    expected_next_halted = expected_next_halted + selector * zero.clone();
                    for (index, expected) in expected_next_memory.iter_mut().enumerate() {
                        *expected = expected.clone()
                            + pc_selectors[pc].clone() * current_memory[index].clone();
                    }
                }
                Instruction::SubMemory(address) => {
                    let rhs = current_memory[address as usize].clone();
                    expected_next_pc = expected_next_pc + selector.clone() * next_pc_constant;
                    expected_next_acc =
                        expected_next_acc + selector.clone() * (current_acc.clone() - rhs);
                    expected_next_sp = expected_next_sp + selector.clone() * current_sp.clone();
                    expected_next_halted = expected_next_halted + selector * zero.clone();
                    for (index, expected) in expected_next_memory.iter_mut().enumerate() {
                        *expected = expected.clone()
                            + pc_selectors[pc].clone() * current_memory[index].clone();
                    }
                }
                Instruction::MulImmediate(value) => {
                    expected_next_pc = expected_next_pc + selector.clone() * next_pc_constant;
                    expected_next_acc = expected_next_acc
                        + selector.clone() * (current_acc.clone() * mp_constant(i128::from(value)));
                    expected_next_sp = expected_next_sp + selector.clone() * current_sp.clone();
                    expected_next_halted = expected_next_halted + selector * zero.clone();
                    for (index, expected) in expected_next_memory.iter_mut().enumerate() {
                        *expected = expected.clone()
                            + pc_selectors[pc].clone() * current_memory[index].clone();
                    }
                }
                Instruction::MulMemory(address) => {
                    let rhs = current_memory[address as usize].clone();
                    expected_next_pc = expected_next_pc + selector.clone() * next_pc_constant;
                    expected_next_acc =
                        expected_next_acc + selector.clone() * (current_acc.clone() * rhs);
                    expected_next_sp = expected_next_sp + selector.clone() * current_sp.clone();
                    expected_next_halted = expected_next_halted + selector * zero.clone();
                    for (index, expected) in expected_next_memory.iter_mut().enumerate() {
                        *expected = expected.clone()
                            + pc_selectors[pc].clone() * current_memory[index].clone();
                    }
                }
                Instruction::Call(target) => {
                    push_or_call_selector = push_or_call_selector + selector.clone();
                    expected_next_pc =
                        expected_next_pc + selector.clone() * mp_constant(i128::from(target));
                    expected_next_acc = expected_next_acc + selector.clone() * current_acc.clone();
                    expected_next_sp =
                        expected_next_sp + selector.clone() * (current_sp.clone() - one.clone());
                    expected_next_halted = expected_next_halted + selector * zero.clone();
                    for (index, expected) in expected_next_memory.iter_mut().enumerate() {
                        let write_selector = current_stack_write_selectors[index].clone();
                        let return_address = mp_constant(i128::from((pc as u8).wrapping_add(1)));
                        let value = write_selector.clone() * return_address
                            + (one.clone() - write_selector) * current_memory[index].clone();
                        *expected = expected.clone() + pc_selectors[pc].clone() * value;
                    }
                }
                Instruction::Ret => {
                    pop_or_ret_selector = pop_or_ret_selector + selector.clone();
                    expected_next_pc =
                        expected_next_pc + selector.clone() * current_stack_read.clone();
                    expected_next_acc = expected_next_acc + selector.clone() * current_acc.clone();
                    expected_next_sp =
                        expected_next_sp + selector.clone() * (current_sp.clone() + one.clone());
                    expected_next_halted = expected_next_halted + selector * zero.clone();
                    for (index, expected) in expected_next_memory.iter_mut().enumerate() {
                        *expected = expected.clone()
                            + pc_selectors[pc].clone() * current_memory[index].clone();
                    }
                }
                Instruction::Jump(target) => {
                    expected_next_pc =
                        expected_next_pc + selector.clone() * mp_constant(i128::from(target));
                    expected_next_acc = expected_next_acc + selector.clone() * current_acc.clone();
                    expected_next_sp = expected_next_sp + selector.clone() * current_sp.clone();
                    expected_next_halted = expected_next_halted + selector * zero.clone();
                    for (index, expected) in expected_next_memory.iter_mut().enumerate() {
                        *expected = expected.clone()
                            + pc_selectors[pc].clone() * current_memory[index].clone();
                    }
                }
                Instruction::JumpIfZero(target) => {
                    let target_expr = current_zero.clone() * mp_constant(i128::from(target))
                        + (one.clone() - current_zero.clone()) * next_pc_constant;
                    expected_next_pc = expected_next_pc + selector.clone() * target_expr;
                    expected_next_acc = expected_next_acc + selector.clone() * current_acc.clone();
                    expected_next_sp = expected_next_sp + selector.clone() * current_sp.clone();
                    expected_next_halted = expected_next_halted + selector * zero.clone();
                    for (index, expected) in expected_next_memory.iter_mut().enumerate() {
                        *expected = expected.clone()
                            + pc_selectors[pc].clone() * current_memory[index].clone();
                    }
                }
                Instruction::JumpIfNotZero(target) => {
                    let target_expr = current_zero.clone() * next_pc_constant
                        + (one.clone() - current_zero.clone()) * mp_constant(i128::from(target));
                    expected_next_pc = expected_next_pc + selector.clone() * target_expr;
                    expected_next_acc = expected_next_acc + selector.clone() * current_acc.clone();
                    expected_next_sp = expected_next_sp + selector.clone() * current_sp.clone();
                    expected_next_halted = expected_next_halted + selector * zero.clone();
                    for (index, expected) in expected_next_memory.iter_mut().enumerate() {
                        *expected = expected.clone()
                            + pc_selectors[pc].clone() * current_memory[index].clone();
                    }
                }
                Instruction::Halt => {
                    expected_next_pc =
                        expected_next_pc + selector.clone() * mp_constant(i128::from(pc as i16));
                    expected_next_acc = expected_next_acc + selector.clone() * current_acc.clone();
                    expected_next_sp = expected_next_sp + selector.clone() * current_sp.clone();
                    expected_next_halted = expected_next_halted + selector * one.clone();
                    for (index, expected) in expected_next_memory.iter_mut().enumerate() {
                        *expected = expected.clone()
                            + pc_selectors[pc].clone() * current_memory[index].clone();
                    }
                }
                Instruction::AndImmediate(_)
                | Instruction::AndMemory(_)
                | Instruction::OrImmediate(_)
                | Instruction::OrMemory(_)
                | Instruction::XorImmediate(_)
                | Instruction::XorMemory(_)
                | Instruction::CmpImmediate(_)
                | Instruction::CmpMemory(_) => {
                    unreachable!("unsupported instructions are filtered before AIR construction")
                }
            }
        }

        let mut constraints = vec![
            valid_pc,
            valid_sp,
            current_zero.clone() * (current_zero.clone() - one.clone()),
            current[HALTED].clone(),
            current[CARRY].clone(),
            next_pc - expected_next_pc,
            next_acc.clone() - expected_next_acc,
            next_sp - expected_next_sp,
            next_halted - expected_next_halted,
            next_carry,
            next_acc.clone() * next_acc_inv - (one.clone() - next_zero.clone()),
            next_zero * next_acc,
        ];

        if !self.layout.memory_size.is_zero() {
            constraints.push(
                push_or_call_selector * (current_sp.clone() * current_sp_nonzero_inv - one.clone()),
            );
            constraints.push(
                pop_or_ret_selector
                    * ((current_sp - mp_constant(self.layout.memory_size as i128))
                        * current_sp_not_top_inv
                        - one.clone()),
            );
        }

        for (index, expected) in expected_next_memory.into_iter().enumerate() {
            constraints.push(next_memory[index].clone() - expected);
        }

        constraints
    }

    fn pc_selectors(&self, pc: &MPolynomial) -> Vec<MPolynomial> {
        let domain: Vec<i128> = (0..self.program.len()).map(|value| value as i128).collect();
        domain
            .iter()
            .map(|&point| lagrange_selector(pc, &domain, point))
            .collect()
    }

    fn stack_write_selectors(&self, sp: &MPolynomial) -> Vec<MPolynomial> {
        let domain: Vec<i128> = (0..=self.layout.memory_size)
            .map(|value| value as i128)
            .collect();
        (0..self.layout.memory_size)
            .map(|index| lagrange_selector(sp, &domain, index as i128 + 1))
            .collect()
    }

    fn stack_read_expression(&self, sp: &MPolynomial, memory: &[MPolynomial]) -> MPolynomial {
        let domain: Vec<i128> = (0..=self.layout.memory_size)
            .map(|value| value as i128)
            .collect();
        let mut expression = MPolynomial::zero();
        for (index, cell) in memory.iter().enumerate() {
            expression = expression + lagrange_selector(sp, &domain, index as i128) * cell.clone();
        }
        expression
    }

    fn domain_zerofier(&self, variable: &MPolynomial, size: usize) -> MPolynomial {
        let mut polynomial = mp_constant(1);
        for point in 0..size {
            polynomial = polynomial * (variable.clone() - mp_constant(point as i128));
        }
        polynomial
    }
}

pub(crate) struct PreparedExecutionWitness {
    air: VmAir,
    trace: Vec<Vec<FieldElement>>,
    #[cfg(feature = "stwo-backend")]
    pub(crate) state_trace: Vec<MachineState>,
    pub(crate) claim: VanillaStarkExecutionClaim,
}

trait ProofBackendDriver {
    fn backend_kind(&self) -> StarkProofBackend;
    fn backend_version(&self) -> &'static str;
    fn prove(&self, witness: PreparedExecutionWitness) -> Result<VanillaStarkExecutionProof>;
    fn verify(&self, proof: &VanillaStarkExecutionProof, air: &VmAir) -> Result<bool>;
}

struct VanillaBackend;

impl ProofBackendDriver for VanillaBackend {
    fn backend_kind(&self) -> StarkProofBackend {
        StarkProofBackend::Vanilla
    }

    fn backend_version(&self) -> &'static str {
        VANILLA_STARK_BACKEND_VERSION_V1
    }

    fn prove(&self, witness: PreparedExecutionWitness) -> Result<VanillaStarkExecutionProof> {
        let stark = Stark::new(
            witness.claim.options.expansion_factor,
            witness.claim.options.num_colinearity_checks,
            witness.claim.options.security_level,
            witness.air.register_count(),
            witness.claim.steps + 1,
            witness.air.transition_degree_bound(),
        );
        let proof = stark.prove(
            &witness.trace,
            &witness.air.transition_constraints(),
            &witness
                .air
                .boundary_constraints(witness.claim.steps, &witness.claim.final_state),
        );

        Ok(VanillaStarkExecutionProof {
            proof_backend: self.backend_kind(),
            proof_backend_version: self.backend_version().to_string(),
            stwo_auxiliary: None,
            claim: witness.claim,
            proof,
        })
    }

    fn verify(&self, proof: &VanillaStarkExecutionProof, air: &VmAir) -> Result<bool> {
        let trace_length = proof
            .claim
            .steps
            .checked_add(1)
            .ok_or_else(|| VmError::InvalidConfig("proof steps overflow".to_string()))?;

        let stark = Stark::new(
            proof.claim.options.expansion_factor,
            proof.claim.options.num_colinearity_checks,
            proof.claim.options.security_level,
            air.register_count(),
            trace_length,
            air.transition_degree_bound(),
        );

        Ok(stark.verify(
            &proof.proof,
            &air.transition_constraints(),
            &air.boundary_constraints(proof.claim.steps, &proof.claim.final_state),
        ))
    }
}

struct StwoBackend;

impl ProofBackendDriver for StwoBackend {
    fn backend_kind(&self) -> StarkProofBackend {
        StarkProofBackend::Stwo
    }

    fn backend_version(&self) -> &'static str {
        #[cfg(feature = "stwo-backend")]
        {
            stwo_backend::STWO_BACKEND_VERSION_PHASE5
        }
        #[cfg(not(feature = "stwo-backend"))]
        {
            stwo_backend::STWO_BACKEND_VERSION_PHASE2
        }
    }

    fn prove(&self, witness: PreparedExecutionWitness) -> Result<VanillaStarkExecutionProof> {
        #[cfg(feature = "stwo-backend")]
        {
            return stwo_backend::prove_phase5_arithmetic_subset(witness);
        }
        #[cfg(not(feature = "stwo-backend"))]
        {
            let _ = witness;
            Err(stwo_backend::phase2_placeholder_prove_error())
        }
    }

    fn verify(&self, proof: &VanillaStarkExecutionProof, _air: &VmAir) -> Result<bool> {
        #[cfg(feature = "stwo-backend")]
        {
            return stwo_backend::verify_phase5_arithmetic_subset(proof);
        }
        #[cfg(not(feature = "stwo-backend"))]
        {
            let _ = proof;
            Err(stwo_backend::phase2_placeholder_verify_error())
        }
    }
}

fn backend_driver(backend: StarkProofBackend) -> &'static dyn ProofBackendDriver {
    match backend {
        StarkProofBackend::Vanilla => &VanillaBackend,
        StarkProofBackend::Stwo => &StwoBackend,
    }
}

pub fn prove_execution_stark(
    model: &TransformerVm,
    max_steps: usize,
) -> Result<VanillaStarkExecutionProof> {
    prove_execution_stark_with_backend_and_options(
        model,
        max_steps,
        StarkProofBackend::Vanilla,
        production_v1_stark_options(),
    )
}

pub fn prove_execution_stark_with_options(
    model: &TransformerVm,
    max_steps: usize,
    options: VanillaStarkProofOptions,
) -> Result<VanillaStarkExecutionProof> {
    prove_execution_stark_with_backend_and_options(
        model,
        max_steps,
        StarkProofBackend::Vanilla,
        options,
    )
}

pub fn prove_execution_stark_with_backend_and_options(
    model: &TransformerVm,
    max_steps: usize,
    backend: StarkProofBackend,
    options: VanillaStarkProofOptions,
) -> Result<VanillaStarkExecutionProof> {
    validate_proof_inputs(model.program(), &model.config().attention_mode, backend)?;
    validate_stark_options(&options)?;
    let witness = prepare_execution_witness(model, max_steps, options)?;
    backend_driver(backend).prove(witness)
}

pub fn verify_execution_stark(proof: &VanillaStarkExecutionProof) -> Result<bool> {
    verify_execution_stark_with_policy(proof, production_v1_verification_policy())
}

pub fn verify_execution_stark_with_policy(
    proof: &VanillaStarkExecutionProof,
    policy: StarkVerificationPolicy,
) -> Result<bool> {
    verify_execution_stark_with_backend_and_policy(proof, proof.proof_backend, policy)
}

pub fn verify_execution_stark_with_backend_and_policy(
    proof: &VanillaStarkExecutionProof,
    backend: StarkProofBackend,
    policy: StarkVerificationPolicy,
) -> Result<bool> {
    validate_backend_metadata(proof, backend)?;
    validate_statement_metadata(&proof.claim)?;
    validate_proof_inputs(&proof.claim.program, &proof.claim.attention_mode, backend)?;
    validate_stark_options(&proof.claim.options)?;
    validate_verification_policy(&proof.claim.options, &policy)?;
    validate_public_state(&proof.claim.program, &proof.claim.final_state)?;
    validate_transformer_config(&proof.claim)?;
    validate_equivalence_metadata(&proof.claim)?;
    validate_claim_commitments(&proof.claim)?;

    if !proof.claim.final_state.halted {
        return Err(VmError::UnsupportedProof(
            "the public claim must end in a halted state".to_string(),
        ));
    }
    if proof.claim.final_state.carry_flag {
        return Err(VmError::UnsupportedProof(
            "carry-flag claims are not supported by the vanilla STARK AIR".to_string(),
        ));
    }

    let air = VmAir::new(proof.claim.program.clone());
    let is_valid = backend_driver(backend).verify(proof, &air)?;
    if !is_valid {
        return Ok(false);
    }

    enforce_equivalence_scope(&proof.claim)?;
    Ok(true)
}

pub fn verify_execution_stark_with_reexecution(proof: &VanillaStarkExecutionProof) -> Result<bool> {
    verify_execution_stark_with_reexecution_and_policy(proof, production_v1_verification_policy())
}

pub fn verify_execution_stark_with_reexecution_and_policy(
    proof: &VanillaStarkExecutionProof,
    policy: StarkVerificationPolicy,
) -> Result<bool> {
    verify_execution_stark_with_policy(proof, policy)
}

pub(crate) fn validate_execution_stark_support(
    program: &Program,
    attention_mode: &Attention2DMode,
) -> Result<()> {
    validate_proof_inputs(program, attention_mode, StarkProofBackend::Vanilla)
}

pub fn save_execution_stark_proof(proof: &VanillaStarkExecutionProof, path: &Path) -> Result<()> {
    let bytes =
        serde_json::to_vec_pretty(proof).map_err(|err| VmError::Serialization(err.to_string()))?;
    fs::write(path, bytes)?;
    Ok(())
}

pub fn load_execution_stark_proof(path: &Path) -> Result<VanillaStarkExecutionProof> {
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(|err| VmError::Serialization(err.to_string()))
}

pub fn conjectured_security_bits(options: &VanillaStarkProofOptions) -> u32 {
    if options.expansion_factor == 0 || options.num_colinearity_checks == 0 {
        return 0;
    }
    let query_bits = (options.expansion_factor.trailing_zeros() as u64)
        .checked_mul(options.num_colinearity_checks as u64)
        .unwrap_or(u64::MAX);
    query_bits.min(VANILLA_STARK_FIELD_SECURITY_BITS as u64) as u32
}

fn validate_stark_options(options: &VanillaStarkProofOptions) -> Result<()> {
    if !options.expansion_factor.is_power_of_two() {
        return Err(VmError::InvalidConfig(format!(
            "stark expansion_factor must be a power of two, got {}",
            options.expansion_factor
        )));
    }
    if options.expansion_factor < 4 {
        return Err(VmError::InvalidConfig(format!(
            "stark expansion_factor must be at least 4, got {}",
            options.expansion_factor
        )));
    }
    if options.num_colinearity_checks == 0 {
        return Err(VmError::InvalidConfig(
            "stark num_colinearity_checks must be greater than zero".to_string(),
        ));
    }
    if options.security_level == 0 {
        return Err(VmError::InvalidConfig(
            "stark security_level must be greater than zero".to_string(),
        ));
    }
    let lhs = options
        .num_colinearity_checks
        .checked_mul(2)
        .ok_or_else(|| {
            VmError::InvalidConfig("stark option multiplication overflow".to_string())
        })?;
    if lhs < options.security_level {
        return Err(VmError::InvalidConfig(format!(
            "stark num_colinearity_checks={} does not satisfy 2*q >= security_level={}",
            options.num_colinearity_checks, options.security_level
        )));
    }
    if options.security_level > VANILLA_STARK_FIELD_SECURITY_BITS as usize {
        return Err(VmError::InvalidConfig(format!(
            "stark security_level {} exceeds field bound {}",
            options.security_level, VANILLA_STARK_FIELD_SECURITY_BITS
        )));
    }
    Ok(())
}

fn validate_verification_policy(
    options: &VanillaStarkProofOptions,
    policy: &StarkVerificationPolicy,
) -> Result<()> {
    let bits = conjectured_security_bits(options);
    if bits < policy.min_conjectured_security_bits {
        return Err(VmError::InvalidConfig(format!(
            "conjectured security {} bits is below required {} bits",
            bits, policy.min_conjectured_security_bits
        )));
    }
    Ok(())
}

fn prepare_execution_witness(
    model: &TransformerVm,
    max_steps: usize,
    options: VanillaStarkProofOptions,
) -> Result<PreparedExecutionWitness> {
    let comparison = verify_model_against_native(model.clone(), max_steps)?;
    let equivalence = ExecutionEquivalenceMetadata {
        checked_steps: comparison.checked_steps,
        transformer_fingerprint: execution_fingerprint_from_result(
            "transformer",
            comparison.checked_steps,
            &comparison.transformer,
        ),
        native_fingerprint: execution_fingerprint_from_result(
            "native",
            comparison.checked_steps,
            &comparison.native,
        ),
    };

    let mut runtime = ExecutionRuntime::new(model.clone(), max_steps);
    let result = runtime.run()?;
    if !result.halted {
        return Err(VmError::UnsupportedProof(format!(
            "execution must halt before proving; stopped after {} steps without HALT",
            result.steps
        )));
    }
    if runtime.trace().iter().any(|state| state.carry_flag) {
        return Err(VmError::UnsupportedProof(
            "overflowing arithmetic is not supported by the vanilla STARK AIR".to_string(),
        ));
    }

    let air = VmAir::new(model.program().clone());
    let trace = execution_trace_rows(&air.layout, runtime.trace());
    let commitments = build_claim_commitments(model.program(), model.config(), &options)?;
    let claim = VanillaStarkExecutionClaim {
        statement_version: CLAIM_STATEMENT_VERSION_V1.to_string(),
        semantic_scope: CLAIM_SEMANTIC_SCOPE_V1.to_string(),
        program: model.program().clone(),
        attention_mode: model.config().attention_mode.clone(),
        transformer_config: Some(model.config().clone()),
        steps: result.steps,
        final_state: result.final_state.clone(),
        options,
        equivalence: Some(equivalence),
        commitments: Some(commitments),
    };

    Ok(PreparedExecutionWitness {
        air,
        trace,
        #[cfg(feature = "stwo-backend")]
        state_trace: runtime.trace().to_vec(),
        claim,
    })
}

fn validate_backend_metadata(
    proof: &VanillaStarkExecutionProof,
    requested_backend: StarkProofBackend,
) -> Result<()> {
    if proof.proof_backend != requested_backend {
        return Err(VmError::InvalidConfig(format!(
            "proof backend `{}` does not match requested backend `{}`",
            proof.proof_backend, requested_backend
        )));
    }

    let expected_version = backend_driver(requested_backend).backend_version();
    let backend_version_matches = match requested_backend {
        StarkProofBackend::Vanilla => proof.proof_backend_version == expected_version,
        StarkProofBackend::Stwo => {
            proof.proof_backend_version == stwo_backend::STWO_BACKEND_VERSION_PHASE2
                || proof.proof_backend_version == stwo_backend::STWO_BACKEND_VERSION_PHASE5
                || proof.proof_backend_version == stwo_backend::STWO_BACKEND_VERSION_PHASE11
                || proof.proof_backend_version == stwo_backend::STWO_BACKEND_VERSION_PHASE12
        }
    };
    if !backend_version_matches {
        let expected_versions = match requested_backend {
            StarkProofBackend::Vanilla => expected_version.to_string(),
            StarkProofBackend::Stwo => format!(
                "{}/{}/{}/{}",
                stwo_backend::STWO_BACKEND_VERSION_PHASE2,
                stwo_backend::STWO_BACKEND_VERSION_PHASE5,
                stwo_backend::STWO_BACKEND_VERSION_PHASE11,
                stwo_backend::STWO_BACKEND_VERSION_PHASE12
            ),
        };
        return Err(VmError::InvalidConfig(format!(
            "proof backend version `{}` does not match expected `{}` for backend `{}`",
            proof.proof_backend_version, expected_versions, requested_backend
        )));
    }

    Ok(())
}

fn validate_proof_inputs(
    program: &Program,
    attention_mode: &Attention2DMode,
    backend: StarkProofBackend,
) -> Result<()> {
    if program.is_empty() {
        return Err(VmError::UnsupportedProof(
            "cannot prove an empty program".to_string(),
        ));
    }

    match backend {
        StarkProofBackend::Vanilla => {
            if !matches!(attention_mode, Attention2DMode::AverageHard) {
                return Err(VmError::UnsupportedProof(format!(
                    "vanilla STARK proofs currently support only `average-hard` attention, got `{attention_mode}`"
                )));
            }

            for instruction in program.instructions() {
                match instruction {
                    Instruction::AndImmediate(_)
                    | Instruction::AndMemory(_)
                    | Instruction::OrImmediate(_)
                    | Instruction::OrMemory(_)
                    | Instruction::XorImmediate(_)
                    | Instruction::XorMemory(_)
                    | Instruction::CmpImmediate(_)
                    | Instruction::CmpMemory(_) => {
                        return Err(VmError::UnsupportedProof(format!(
                            "instruction `{instruction}` is not yet supported by the vanilla STARK AIR"
                        )));
                    }
                    _ => {}
                }
            }
        }
        StarkProofBackend::Stwo => {
            stwo_backend::validate_phase2_proof_shape(program, attention_mode)?;
        }
    }

    Ok(())
}

fn validate_public_state(program: &Program, final_state: &MachineState) -> Result<()> {
    if final_state.memory.len() != program.memory_size() {
        return Err(VmError::InvalidConfig(format!(
            "proof final-state memory length {} does not match program memory size {}",
            final_state.memory.len(),
            program.memory_size()
        )));
    }
    Ok(())
}

fn validate_statement_metadata(claim: &VanillaStarkExecutionClaim) -> Result<()> {
    if claim.statement_version != CLAIM_STATEMENT_VERSION_V1 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported statement_version `{}` (expected `{}`)",
            claim.statement_version, CLAIM_STATEMENT_VERSION_V1
        )));
    }
    if claim.semantic_scope != CLAIM_SEMANTIC_SCOPE_V1 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported semantic_scope `{}` (expected `{}`)",
            claim.semantic_scope, CLAIM_SEMANTIC_SCOPE_V1
        )));
    }
    let commitments = claim.commitments.as_ref().ok_or_else(|| {
        VmError::UnsupportedProof("proof claim is missing artifact commitments".to_string())
    })?;
    if commitments.scheme_version != CLAIM_COMMITMENT_SCHEME_VERSION_V1 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported commitment_scheme_version `{}` (expected `{}`)",
            commitments.scheme_version, CLAIM_COMMITMENT_SCHEME_VERSION_V1
        )));
    }
    if commitments.hash_function != CLAIM_COMMITMENT_HASH_FUNCTION_V1 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported commitment_hash_function `{}` (expected `{}`)",
            commitments.hash_function, CLAIM_COMMITMENT_HASH_FUNCTION_V1
        )));
    }
    Ok(())
}

fn enforce_equivalence_scope(claim: &VanillaStarkExecutionClaim) -> Result<()> {
    if claim.semantic_scope != CLAIM_SEMANTIC_SCOPE_V1 {
        return Ok(());
    }

    let config = claim.transformer_config.clone().ok_or_else(|| {
        VmError::UnsupportedProof(
            "proof claim is missing transformer configuration for equivalence re-execution"
                .to_string(),
        )
    })?;
    let model = TransformerVm::new(config, claim.program.clone())?;
    let comparison = verify_model_against_native(model, claim.steps)?;
    validate_reexecution_matches_claim(claim, &comparison)?;
    Ok(())
}

fn validate_transformer_config(claim: &VanillaStarkExecutionClaim) -> Result<()> {
    let Some(config) = &claim.transformer_config else {
        return Ok(());
    };

    config.validate()?;
    if config.attention_mode != claim.attention_mode {
        return Err(VmError::InvalidConfig(format!(
            "proof transformer config attention mode `{}` does not match claim attention mode `{}`",
            config.attention_mode, claim.attention_mode
        )));
    }
    Ok(())
}

fn validate_reexecution_matches_claim(
    claim: &VanillaStarkExecutionClaim,
    comparison: &crate::verification::ExecutionComparison,
) -> Result<()> {
    if comparison.checked_steps != claim.steps {
        return Err(VmError::InvalidConfig(format!(
            "re-execution checked_steps {} does not match claim steps {}",
            comparison.checked_steps, claim.steps
        )));
    }

    for (engine, result) in [
        ("transformer", &comparison.transformer),
        ("native", &comparison.native),
    ] {
        if result.steps != claim.steps {
            return Err(VmError::InvalidConfig(format!(
                "re-executed {engine} steps {} does not match claim steps {}",
                result.steps, claim.steps
            )));
        }
        if result.halted != claim.final_state.halted {
            return Err(VmError::InvalidConfig(format!(
                "re-executed {engine} halted={} does not match claim halted={}",
                result.halted, claim.final_state.halted
            )));
        }
        if result.final_state != claim.final_state {
            return Err(VmError::InvalidConfig(format!(
                "re-executed {engine} final state does not match claim final state"
            )));
        }
    }

    if let Some(metadata) = &claim.equivalence {
        if metadata.checked_steps != comparison.checked_steps {
            return Err(VmError::InvalidConfig(format!(
                "equivalence checked_steps {} does not match re-execution checked_steps {}",
                metadata.checked_steps, comparison.checked_steps
            )));
        }

        let transformer_fingerprint = execution_fingerprint_from_result(
            "transformer",
            comparison.checked_steps,
            &comparison.transformer,
        );
        if metadata.transformer_fingerprint != transformer_fingerprint {
            return Err(VmError::InvalidConfig(
                "transformer fingerprint does not match re-execution".to_string(),
            ));
        }

        let native_fingerprint = execution_fingerprint_from_result(
            "native",
            comparison.checked_steps,
            &comparison.native,
        );
        if metadata.native_fingerprint != native_fingerprint {
            return Err(VmError::InvalidConfig(
                "native fingerprint does not match re-execution".to_string(),
            ));
        }
    }

    Ok(())
}

fn validate_equivalence_metadata(claim: &VanillaStarkExecutionClaim) -> Result<()> {
    let Some(metadata) = &claim.equivalence else {
        return Ok(());
    };

    if metadata.checked_steps != claim.steps {
        return Err(VmError::InvalidConfig(format!(
            "equivalence checked_steps {} does not match claim steps {}",
            metadata.checked_steps, claim.steps
        )));
    }

    let expected_transformer = execution_fingerprint(
        "transformer",
        metadata.checked_steps,
        claim.steps,
        claim.final_state.halted,
        &claim.final_state,
    );
    if metadata.transformer_fingerprint != expected_transformer {
        return Err(VmError::InvalidConfig(
            "invalid transformer equivalence fingerprint".to_string(),
        ));
    }

    let expected_native = execution_fingerprint(
        "native",
        metadata.checked_steps,
        claim.steps,
        claim.final_state.halted,
        &claim.final_state,
    );
    if metadata.native_fingerprint != expected_native {
        return Err(VmError::InvalidConfig(
            "invalid native equivalence fingerprint".to_string(),
        ));
    }

    Ok(())
}

fn validate_claim_commitments(claim: &VanillaStarkExecutionClaim) -> Result<()> {
    let commitments = claim.commitments.as_ref().ok_or_else(|| {
        VmError::UnsupportedProof("proof claim is missing artifact commitments".to_string())
    })?;
    let config = claim.transformer_config.as_ref().ok_or_else(|| {
        VmError::UnsupportedProof(
            "proof claim is missing transformer configuration required for commitment checks"
                .to_string(),
        )
    })?;

    if commitments.scheme_version != CLAIM_COMMITMENT_SCHEME_VERSION_V1 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported commitment scheme version `{}` (expected `{}`)",
            commitments.scheme_version, CLAIM_COMMITMENT_SCHEME_VERSION_V1
        )));
    }
    if commitments.hash_function != CLAIM_COMMITMENT_HASH_FUNCTION_V1 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported commitment hash function `{}` (expected `{}`)",
            commitments.hash_function, CLAIM_COMMITMENT_HASH_FUNCTION_V1
        )));
    }
    if commitments.prover_build_info.trim().is_empty() {
        return Err(VmError::InvalidConfig(
            "invalid prover_build_info commitment: value is empty".to_string(),
        ));
    }

    let expected_program_hash = hash_serialized_payload_hex(
        "program",
        &ProgramCommitmentPayloadV1 {
            version: COMMITMENT_PAYLOAD_VERSION_V1,
            program: &claim.program,
        },
    )?;
    let expected_config_hash = hash_serialized_payload_hex(
        "transformer config",
        &TransformerConfigCommitmentPayloadV1 {
            version: COMMITMENT_PAYLOAD_VERSION_V1,
            transformer_config: config,
        },
    )?;
    let expected_model_hash = hash_serialized_payload_hex(
        "deterministic model",
        &DeterministicModelCommitmentPayloadV1 {
            version: COMMITMENT_PAYLOAD_VERSION_V1,
            program: &claim.program,
            transformer_config: config,
        },
    )?;
    let expected_options_hash = hash_serialized_payload_hex(
        "stark options",
        &StarkOptionsCommitmentPayloadV1 {
            version: COMMITMENT_PAYLOAD_VERSION_V1,
            stark_options: &claim.options,
        },
    )?;
    let expected_build_hash = hash_bytes_hex(commitments.prover_build_info.as_bytes());

    validate_commitment_field(
        "program_hash",
        &commitments.program_hash,
        &expected_program_hash,
    )?;
    validate_commitment_field(
        "transformer_config_hash",
        &commitments.transformer_config_hash,
        &expected_config_hash,
    )?;
    validate_commitment_field(
        "deterministic_model_hash",
        &commitments.deterministic_model_hash,
        &expected_model_hash,
    )?;
    validate_commitment_field(
        "stark_options_hash",
        &commitments.stark_options_hash,
        &expected_options_hash,
    )?;
    validate_commitment_field(
        "prover_build_hash",
        &commitments.prover_build_hash,
        &expected_build_hash,
    )?;

    Ok(())
}

fn validate_commitment_field(name: &str, actual: &str, expected: &str) -> Result<()> {
    if actual != expected {
        return Err(VmError::InvalidConfig(format!(
            "invalid {name} commitment: expected {expected}, got {actual}"
        )));
    }
    Ok(())
}

fn build_claim_commitments(
    program: &Program,
    config: &TransformerVmConfig,
    options: &VanillaStarkProofOptions,
) -> Result<ExecutionClaimCommitments> {
    let prover_build_info = prover_build_info();
    let prover_build_hash = hash_bytes_hex(prover_build_info.as_bytes());

    let program_hash = hash_serialized_payload_hex(
        "program",
        &ProgramCommitmentPayloadV1 {
            version: COMMITMENT_PAYLOAD_VERSION_V1,
            program,
        },
    )?;
    let transformer_config_hash = hash_serialized_payload_hex(
        "transformer config",
        &TransformerConfigCommitmentPayloadV1 {
            version: COMMITMENT_PAYLOAD_VERSION_V1,
            transformer_config: config,
        },
    )?;
    let deterministic_model_hash = hash_serialized_payload_hex(
        "deterministic model",
        &DeterministicModelCommitmentPayloadV1 {
            version: COMMITMENT_PAYLOAD_VERSION_V1,
            program,
            transformer_config: config,
        },
    )?;
    let stark_options_hash = hash_serialized_payload_hex(
        "stark options",
        &StarkOptionsCommitmentPayloadV1 {
            version: COMMITMENT_PAYLOAD_VERSION_V1,
            stark_options: options,
        },
    )?;

    Ok(ExecutionClaimCommitments {
        scheme_version: CLAIM_COMMITMENT_SCHEME_VERSION_V1.to_string(),
        hash_function: CLAIM_COMMITMENT_HASH_FUNCTION_V1.to_string(),
        program_hash,
        transformer_config_hash,
        deterministic_model_hash,
        stark_options_hash,
        prover_build_info,
        prover_build_hash,
    })
}

fn prover_build_info() -> String {
    let version = env!("CARGO_PKG_VERSION");
    let git_commit = option_env!("LLM_PC_GIT_COMMIT").unwrap_or("unknown");
    format!("llm-provable-computer/{version}+{git_commit}")
}

fn hash_serialized_payload_hex<T: Serialize>(label: &str, value: &T) -> Result<String> {
    let payload = canonical_json_bytes(label, value)?;
    Ok(hash_bytes_hex(&payload))
}

fn canonical_json_bytes<T: Serialize>(label: &str, value: &T) -> Result<Vec<u8>> {
    let json = serde_json::to_value(value)
        .map_err(|err| VmError::Serialization(format!("{label}: {err}")))?;
    let mut out = Vec::new();
    write_canonical_json_value(&json, &mut out)
        .map_err(|err| VmError::Serialization(format!("{label}: {err}")))?;
    Ok(out)
}

fn write_canonical_json_value(
    value: &Value,
    out: &mut Vec<u8>,
) -> std::result::Result<(), serde_json::Error> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(v) => out.extend_from_slice(if *v { b"true" } else { b"false" }),
        Value::Number(v) => out.extend_from_slice(v.to_string().as_bytes()),
        Value::String(v) => out.extend_from_slice(serde_json::to_string(v)?.as_bytes()),
        Value::Array(values) => {
            out.push(b'[');
            for (index, item) in values.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_canonical_json_value(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            out.push(b'{');
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));
            for (index, (key, item)) in entries.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                out.extend_from_slice(serde_json::to_string(key)?.as_bytes());
                out.push(b':');
                write_canonical_json_value(item, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn hash_bytes_hex(bytes: &[u8]) -> String {
    let mut output = [0u8; 32];
    let mut hasher = Blake2bVar::new(output.len()).expect("blake2b-256 hasher");
    hasher.update(bytes);
    hasher
        .finalize_variable(&mut output)
        .expect("blake2b-256 finalization");
    output.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Serialize)]
struct ProgramCommitmentPayloadV1<'a> {
    version: &'static str,
    program: &'a Program,
}

#[derive(Serialize)]
struct TransformerConfigCommitmentPayloadV1<'a> {
    version: &'static str,
    transformer_config: &'a TransformerVmConfig,
}

#[derive(Serialize)]
struct DeterministicModelCommitmentPayloadV1<'a> {
    version: &'static str,
    program: &'a Program,
    transformer_config: &'a TransformerVmConfig,
}

#[derive(Serialize)]
struct StarkOptionsCommitmentPayloadV1<'a> {
    version: &'static str,
    stark_options: &'a VanillaStarkProofOptions,
}

fn execution_trace_rows(layout: &ColumnLayout, trace: &[MachineState]) -> Vec<Vec<FieldElement>> {
    trace
        .iter()
        .map(|state| {
            let acc = field_from_i128(i128::from(state.acc));
            let sp = field_from_i128(i128::from(state.sp));
            let sp_minus_top = field_from_i128(i128::from(state.sp) - layout.memory_size as i128);
            let mut row = Vec::with_capacity(layout.register_count());
            row.push(field_from_i128(i128::from(state.pc)));
            row.push(acc);
            row.push(sp);
            row.push(field_from_bool(state.zero_flag));
            row.push(field_from_bool(state.carry_flag));
            row.push(field_from_bool(state.halted));
            row.extend(
                state
                    .memory
                    .iter()
                    .copied()
                    .map(|value| field_from_i128(i128::from(value))),
            );
            row.push(inverse_or_zero(acc));
            row.push(inverse_or_zero(sp));
            row.push(inverse_or_zero(sp_minus_top));
            row
        })
        .collect()
}

fn state_public_registers(layout: &ColumnLayout, state: &MachineState) -> Vec<FieldElement> {
    let mut registers = Vec::with_capacity(layout.machine_state_register_count());
    registers.push(field_from_i128(i128::from(state.pc)));
    registers.push(field_from_i128(i128::from(state.acc)));
    registers.push(field_from_i128(i128::from(state.sp)));
    registers.push(field_from_bool(state.zero_flag));
    registers.push(field_from_bool(state.carry_flag));
    registers.push(field_from_bool(state.halted));
    registers.extend(
        state
            .memory
            .iter()
            .copied()
            .map(|value| field_from_i128(i128::from(value))),
    );
    registers
}

fn lagrange_selector(variable: &MPolynomial, domain: &[i128], point: i128) -> MPolynomial {
    let mut selector = mp_constant(1);
    for &other in domain {
        if other == point {
            continue;
        }
        let denominator = field_from_i128(point - other).inverse();
        selector =
            selector * (variable.clone() - mp_constant(other)) * MPolynomial::constant(denominator);
    }
    selector
}

fn mp_constant(value: i128) -> MPolynomial {
    MPolynomial::constant(field_from_i128(value))
}

fn field_from_bool(value: bool) -> FieldElement {
    field_from_i128(if value { 1 } else { 0 })
}

fn field_from_i128(value: i128) -> FieldElement {
    if value >= 0 {
        FieldElement::new(value as u128)
    } else {
        -FieldElement::new(value.unsigned_abs())
    }
}

fn inverse_or_zero(value: FieldElement) -> FieldElement {
    if value.is_zero() {
        FieldElement::zero()
    } else {
        value.inverse()
    }
}

fn execution_fingerprint_from_result(
    engine: &str,
    checked_steps: usize,
    result: &ExecutionResult,
) -> String {
    execution_fingerprint(
        engine,
        checked_steps,
        result.steps,
        result.halted,
        &result.final_state,
    )
}

fn execution_fingerprint(
    engine: &str,
    checked_steps: usize,
    steps: usize,
    halted: bool,
    final_state: &MachineState,
) -> String {
    #[derive(Serialize)]
    struct FingerprintPayload<'a> {
        engine: &'a str,
        checked_steps: usize,
        steps: usize,
        halted: bool,
        final_state: &'a MachineState,
    }

    let payload = FingerprintPayload {
        engine,
        checked_steps,
        steps,
        halted,
        final_state,
    };
    let encoded = serde_json::to_vec(&payload).expect("fingerprint payload serialization");
    let digest = Blake2b512::digest(encoded);
    digest
        .as_slice()
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

trait IsZeroExt {
    fn is_zero(&self) -> bool;
}

impl IsZeroExt for usize {
    fn is_zero(&self) -> bool {
        *self == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProgramCompiler, TransformerVmConfig};
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct StatementSpecFile {
        statement_version: String,
        semantic_scope: String,
        commitment_scheme_version: String,
        commitment_hash_function: String,
    }

    fn prove_program(path: &str, max_steps: usize) -> VanillaStarkExecutionProof {
        let source = std::fs::read_to_string(path).expect("program source");
        let model = ProgramCompiler
            .compile_source(&source, TransformerVmConfig::default())
            .expect("compile");
        prove_execution_stark_with_options(&model, max_steps, production_v1_stark_options())
            .expect("prove")
    }

    #[test]
    fn addition_round_trips_through_stark_proof() {
        let proof = prove_program("programs/addition.tvm", 32);
        assert!(verify_execution_stark(&proof).expect("verify"));
        assert_eq!(proof.claim.final_state.acc, 8);
    }

    #[test]
    fn small_loop_round_trips_through_stark_proof() {
        let source = "\
.memory 2
.init 1 2

LOADI 0
STORE 0
loop:
LOAD 0
ADD 1
STORE 0
LOAD 0
SUBM 1
JZ done
JMP loop
done:
LOAD 0
HALT
";
        let model = ProgramCompiler
            .compile_source(source, TransformerVmConfig::default())
            .expect("compile");
        let proof = prove_execution_stark_with_options(&model, 128, production_v1_stark_options())
            .expect("prove");
        assert!(verify_execution_stark(&proof).expect("verify"));
        assert_eq!(proof.claim.final_state.acc, 2);
    }

    #[test]
    fn stack_and_subroutine_round_trip_through_stark_proof() {
        for (path, max_steps, expected_acc) in [
            ("programs/stack_roundtrip.tvm", 32, 42),
            ("programs/subroutine_addition.tvm", 64, 42),
        ] {
            let proof = prove_program(path, max_steps);
            assert!(verify_execution_stark(&proof).expect("verify"), "{path}");
            assert_eq!(proof.claim.final_state.acc, expected_acc, "{path}");
        }
    }

    #[test]
    fn proof_rejects_softmax_attention() {
        let source = std::fs::read_to_string("programs/addition.tvm").expect("program source");
        let model = ProgramCompiler
            .compile_source(
                &source,
                TransformerVmConfig {
                    attention_mode: Attention2DMode::Softmax,
                    ..TransformerVmConfig::default()
                },
            )
            .expect("compile");

        let err = prove_execution_stark(&model, 32).unwrap_err();
        assert!(matches!(err, VmError::UnsupportedProof(_)));
    }

    #[test]
    fn proof_rejects_unsupported_instruction_set() {
        let program = Program::new(vec![Instruction::CmpImmediate(1), Instruction::Halt], 1);
        let model = TransformerVm::new(TransformerVmConfig::default(), program).expect("model");
        let err = prove_execution_stark(&model, 16).unwrap_err();
        assert!(matches!(err, VmError::UnsupportedProof(_)));
    }

    #[test]
    fn proof_serialization_round_trip() {
        let proof = prove_program("programs/addition.tvm", 32);
        let path = std::env::temp_dir().join(format!(
            "llm-provable-computer-proof-{}.json",
            std::process::id()
        ));

        save_execution_stark_proof(&proof, &path).expect("save");
        let loaded = load_execution_stark_proof(&path).expect("load");
        let _ = std::fs::remove_file(&path);

        assert_eq!(loaded, proof);
        assert!(verify_execution_stark(&loaded).expect("verify"));
    }

    #[test]
    fn proof_serialization_backfills_vanilla_backend_for_legacy_json() {
        let proof = prove_program("programs/addition.tvm", 32);
        let mut json = serde_json::to_value(&proof).expect("proof json");
        let object = json.as_object_mut().expect("proof object");
        object.remove("proof_backend");
        object.remove("proof_backend_version");

        let loaded: VanillaStarkExecutionProof =
            serde_json::from_value(json).expect("deserialize legacy proof");
        assert_eq!(loaded.proof_backend, StarkProofBackend::Vanilla);
        assert_eq!(
            loaded.proof_backend_version,
            VANILLA_STARK_BACKEND_VERSION_V1
        );
    }

    #[test]
    fn proof_claim_includes_equivalence_metadata() {
        let proof = prove_program("programs/addition.tvm", 32);
        assert_eq!(proof.proof_backend, StarkProofBackend::Vanilla);
        assert_eq!(
            proof.proof_backend_version,
            VANILLA_STARK_BACKEND_VERSION_V1
        );
        let metadata = proof.claim.equivalence.expect("equivalence metadata");
        assert_eq!(proof.claim.statement_version, CLAIM_STATEMENT_VERSION_V1);
        assert_eq!(proof.claim.semantic_scope, CLAIM_SEMANTIC_SCOPE_V1);
        assert_eq!(metadata.checked_steps, proof.claim.steps);
        let config = proof
            .claim
            .transformer_config
            .as_ref()
            .expect("transformer config");
        assert_eq!(config.attention_mode, proof.claim.attention_mode);
        assert_eq!(
            metadata.transformer_fingerprint,
            execution_fingerprint(
                "transformer",
                metadata.checked_steps,
                proof.claim.steps,
                proof.claim.final_state.halted,
                &proof.claim.final_state,
            )
        );
        assert_eq!(
            metadata.native_fingerprint,
            execution_fingerprint(
                "native",
                metadata.checked_steps,
                proof.claim.steps,
                proof.claim.final_state.halted,
                &proof.claim.final_state,
            )
        );
    }

    #[test]
    fn proof_claim_includes_artifact_commitments() {
        let proof = prove_program("programs/addition.tvm", 32);
        let commitments = proof
            .claim
            .commitments
            .as_ref()
            .expect("artifact commitments");
        assert_eq!(
            commitments.scheme_version,
            CLAIM_COMMITMENT_SCHEME_VERSION_V1
        );
        assert_eq!(commitments.hash_function, CLAIM_COMMITMENT_HASH_FUNCTION_V1);
        assert!(!commitments.prover_build_info.trim().is_empty());
        assert_eq!(
            commitments.prover_build_hash,
            hash_bytes_hex(commitments.prover_build_info.as_bytes())
        );

        let config = proof
            .claim
            .transformer_config
            .as_ref()
            .expect("transformer config");
        let expected = build_claim_commitments(&proof.claim.program, config, &proof.claim.options)
            .expect("rebuild commitments");
        assert_eq!(commitments.program_hash, expected.program_hash);
        assert_eq!(
            commitments.transformer_config_hash,
            expected.transformer_config_hash
        );
        assert_eq!(
            commitments.deterministic_model_hash,
            expected.deterministic_model_hash
        );
        assert_eq!(commitments.stark_options_hash, expected.stark_options_hash);
    }

    #[test]
    fn reexecution_verification_round_trips() {
        let proof = prove_program("programs/addition.tvm", 32);
        assert!(verify_execution_stark_with_reexecution(&proof).expect("verify with reexecution"));
    }

    #[test]
    fn policy_rejects_low_security_proof_options() {
        let source = std::fs::read_to_string("programs/addition.tvm").expect("program source");
        let model = ProgramCompiler
            .compile_source(&source, TransformerVmConfig::default())
            .expect("compile");
        let proof = prove_execution_stark_with_options(
            &model,
            32,
            VanillaStarkProofOptions {
                expansion_factor: 4,
                num_colinearity_checks: 2,
                security_level: 2,
            },
        )
        .expect("prove");
        let err = verify_execution_stark_with_policy(
            &proof,
            StarkVerificationPolicy {
                min_conjectured_security_bits: 8,
            },
        )
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("conjectured security 4 bits is below required 8 bits"));
    }

    #[test]
    fn verify_rejects_invalid_stark_options_without_panic() {
        let mut proof = prove_program("programs/addition.tvm", 32);
        proof.claim.options.expansion_factor = 3;
        let err = verify_execution_stark(&proof).unwrap_err();
        assert!(err.to_string().contains("power of two"));
    }

    #[test]
    fn verify_rejects_step_overflow_without_panic() {
        let mut proof = prove_program("programs/addition.tvm", 32);
        proof.claim.equivalence = None;
        proof.claim.steps = usize::MAX;
        let err = verify_execution_stark(&proof).unwrap_err();
        assert!(err.to_string().contains("proof steps overflow"));
    }

    #[test]
    fn verify_rejects_commitment_mismatch() {
        let mut proof = prove_program("programs/addition.tvm", 32);
        let commitments = proof
            .claim
            .commitments
            .as_mut()
            .expect("artifact commitments");
        commitments.stark_options_hash = "00".repeat(32);
        let err = verify_execution_stark(&proof).unwrap_err();
        assert!(err
            .to_string()
            .contains("invalid stark_options_hash commitment"));
    }

    #[test]
    fn verify_rejects_statement_scope_mismatch() {
        let mut proof = prove_program("programs/addition.tvm", 32);
        proof.claim.semantic_scope = "native_isa_execution_only".to_string();
        let err = verify_execution_stark(&proof).unwrap_err();
        assert!(err.to_string().contains("unsupported semantic_scope"));
    }

    #[test]
    fn verify_rejects_commitment_scheme_version_mismatch() {
        let mut proof = prove_program("programs/addition.tvm", 32);
        proof
            .claim
            .commitments
            .as_mut()
            .expect("artifact commitments")
            .scheme_version = "v2".to_string();
        let err = verify_execution_stark(&proof).unwrap_err();
        assert!(err
            .to_string()
            .contains("unsupported commitment_scheme_version"));
    }

    #[test]
    fn verify_rejects_commitment_hash_function_mismatch() {
        let mut proof = prove_program("programs/addition.tvm", 32);
        proof
            .claim
            .commitments
            .as_mut()
            .expect("artifact commitments")
            .hash_function = "sha256".to_string();
        let err = verify_execution_stark(&proof).unwrap_err();
        assert!(err
            .to_string()
            .contains("unsupported commitment_hash_function"));
    }

    #[test]
    fn production_profile_v1_is_self_consistent() {
        let options = production_v1_stark_options();
        assert_eq!(
            conjectured_security_bits(&options),
            PRODUCTION_V1_MIN_CONJECTURED_SECURITY_BITS
        );
        assert!(options.num_colinearity_checks.saturating_mul(2) >= options.security_level);
        assert!(PRODUCTION_V1_TARGET_MAX_PROVING_SECONDS > 0);
    }

    #[test]
    fn statement_spec_contract_is_synced_with_constants() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("spec")
            .join("statement-v1.json");
        let bytes = std::fs::read(&path).expect("read statement spec");
        let spec: StatementSpecFile = serde_json::from_slice(&bytes).expect("parse statement spec");

        assert_eq!(spec.statement_version, CLAIM_STATEMENT_VERSION_V1);
        assert_eq!(spec.semantic_scope, CLAIM_SEMANTIC_SCOPE_V1);
        assert_eq!(
            spec.commitment_scheme_version,
            CLAIM_COMMITMENT_SCHEME_VERSION_V1
        );
        assert_eq!(
            spec.commitment_hash_function,
            CLAIM_COMMITMENT_HASH_FUNCTION_V1
        );
    }

    #[test]
    fn commitment_hash_matches_blake2b_256_test_vector() {
        assert_eq!(
            hash_bytes_hex(b""),
            "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
        );
    }

    #[test]
    fn conjectured_security_bits_handles_large_query_counts() {
        let options = VanillaStarkProofOptions {
            expansion_factor: 1 << 63,
            num_colinearity_checks: usize::MAX,
            security_level: 1,
        };
        assert_eq!(
            conjectured_security_bits(&options),
            VANILLA_STARK_FIELD_SECURITY_BITS
        );
    }

    #[test]
    fn canonical_json_hash_is_key_order_invariant() {
        let ordered = serde_json::json!({
            "a": 1,
            "b": {
                "x": true,
                "y": [2, 3]
            }
        });

        let mut inner = serde_json::Map::new();
        inner.insert("y".to_string(), serde_json::json!([2, 3]));
        inner.insert("x".to_string(), serde_json::json!(true));
        let mut outer = serde_json::Map::new();
        outer.insert("b".to_string(), Value::Object(inner));
        outer.insert("a".to_string(), serde_json::json!(1));
        let reordered = Value::Object(outer);

        let ordered_hash = hash_serialized_payload_hex("ordered", &ordered).expect("hash ordered");
        let reordered_hash =
            hash_serialized_payload_hex("reordered", &reordered).expect("hash reordered");
        assert_eq!(ordered_hash, reordered_hash);
    }
}
