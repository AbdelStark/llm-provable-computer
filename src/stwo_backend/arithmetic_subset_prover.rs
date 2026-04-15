use ark_ff::Zero;
use serde::{Deserialize, Serialize};
use serde_json;
use stwo::core::air::Component;
use stwo::core::channel::Blake2sM31Channel;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};
use stwo::core::verifier::verify;
use stwo::prover::backend::cpu::CpuBackend;
use stwo::prover::backend::{Col, Column};
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::poly::{BitReversedOrder, NaturalOrder};
use stwo::prover::{prove, CommitmentSchemeProver};
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator,
};

use super::decoding::{
    infer_phase12_decoding_layout, matches_decoding_step_v1_family,
    matches_decoding_step_v2_family, MAX_DECODING_PROOF_PAYLOAD_BYTES,
    MAX_SHARED_LOOKUP_ENVELOPE_PROOF_BYTES,
};
use super::normalization_component::phase5_normalization_table_rows;
use super::normalization_prover::{
    prove_phase10_shared_normalization_lookup_envelope,
    prove_phase5_normalization_lookup_demo_envelope,
    verify_phase10_shared_normalization_lookup_envelope,
    verify_phase5_normalization_lookup_demo_envelope, STWO_NORMALIZATION_STATEMENT_VERSION_PHASE5,
    STWO_SHARED_NORMALIZATION_STATEMENT_VERSION_PHASE10,
};
use super::shared_lookup_artifact::{
    build_phase12_shared_lookup_artifact, EmbeddedSharedActivationClaimRow,
    EmbeddedSharedActivationLookupProof, EmbeddedSharedNormalizationClaimRow,
    EmbeddedSharedNormalizationProof, Phase12SharedLookupArtifact,
    DECODING_STEP_V2_SHARED_ACTIVATION_SCOPE, DECODING_STEP_V2_SHARED_NORMALIZATION_SCOPE,
};
use super::{
    phase3_lookup_table_rows, prove_phase10_shared_binary_step_lookup_envelope,
    prove_phase3_binary_step_lookup_demo_envelope,
    verify_phase10_shared_binary_step_lookup_envelope,
    verify_phase3_binary_step_lookup_demo_envelope, Phase3LookupProofEnvelope,
    Phase3LookupTableRow, STWO_LOOKUP_STATEMENT_VERSION_PHASE3,
    STWO_SHARED_LOOKUP_STATEMENT_VERSION_PHASE10,
};
use crate::config::Attention2DMode;
use crate::error::{Result, VmError};
use crate::instruction::{Instruction, Program};
use crate::interpreter::NativeInterpreter;
use crate::proof::{
    PreparedExecutionWitness, StarkProofBackend, StwoAuxiliaryProofs, StwoNormalizationCompanion,
    VanillaStarkExecutionClaim, VanillaStarkExecutionProof,
};
use crate::state::MachineState;

pub const STWO_BACKEND_VERSION_PHASE5: &str = "stwo-phase10-gemma-block-v4";
pub const STWO_BACKEND_VERSION_PHASE11: &str = "stwo-phase11-decoding-step-v1";
const M31_MODULUS: u32 = (1u32 << 31) - 1;
const GEMMA_BLOCK_NORM_SQ_MEMORY_INDEX: usize = 13;
const GEMMA_BLOCK_INV_SQRT_MEMORY_INDEX: usize = 14;
const GEMMA_BLOCK_ACTIVATION_INPUT_MEMORY_INDEX: usize = 15;
const GEMMA_BLOCK_ACTIVATION_OUTPUT_MEMORY_INDEX: usize = 16;
const GEMMA_BLOCK_EXPECTED_NORM_SQ: i16 = 16;
const GEMMA_BLOCK_EXPECTED_INV_SQRT_Q8: i16 = 64;
const GEMMA_BLOCK_EXPECTED_ACTIVATION_INPUT: i16 = 1;
const GEMMA_BLOCK_EXPECTED_ACTIVATION_OUTPUT: i16 = 1;
const GEMMA_BLOCK_V4_SHARED_NORM_SQ_MEMORY_INDEX: usize = 17;
const GEMMA_BLOCK_V4_SHARED_INV_SQRT_Q8_MEMORY_INDEX: usize = 18;
const GEMMA_BLOCK_V4_SHARED_ACTIVATION_INPUT_MEMORY_INDEX: usize = 19;
const GEMMA_BLOCK_V4_SHARED_ACTIVATION_OUTPUT_MEMORY_INDEX: usize = 20;
const GEMMA_BLOCK_V4_SHARED_NORM_SQ: i16 = 4;
const GEMMA_BLOCK_V4_SHARED_INV_SQRT_Q8: i16 = 128;
const GEMMA_BLOCK_V4_SHARED_ACTIVATION_INPUT: i16 = 0;
const GEMMA_BLOCK_V4_SHARED_ACTIVATION_OUTPUT: i16 = 1;
const GEMMA_BLOCK_NORMALIZATION_SCOPE: &str =
    "stwo_gemma_block_v1_execution_plus_normalization_companion";
const GEMMA_BLOCK_V2_NORMALIZATION_SCOPE: &str =
    "stwo_gemma_block_v2_execution_with_embedded_normalization";
const GEMMA_BLOCK_V3_NORMALIZATION_SCOPE: &str =
    "stwo_gemma_block_v3_execution_with_embedded_normalization";
const GEMMA_BLOCK_V3_ACTIVATION_SCOPE: &str =
    "stwo_gemma_block_v3_execution_with_embedded_binary_step_lookup";
const GEMMA_BLOCK_V4_SHARED_NORMALIZATION_SCOPE: &str =
    "stwo_gemma_block_v4_execution_with_shared_normalization_lookup";
const GEMMA_BLOCK_V4_SHARED_ACTIVATION_SCOPE: &str =
    "stwo_gemma_block_v4_execution_with_shared_binary_step_lookup";
const DECODING_STEP_V1_SHARED_NORMALIZATION_SCOPE: &str =
    "stwo_decoding_step_v1_execution_with_shared_normalization_lookup";
const DECODING_STEP_V1_SHARED_ACTIVATION_SCOPE: &str =
    "stwo_decoding_step_v1_execution_with_shared_binary_step_lookup";
const OPCODE_COLUMN_NAMES: [&str; 11] = [
    "phase5/arithmetic/op/nop",
    "phase5/arithmetic/op/loadi",
    "phase5/arithmetic/op/load",
    "phase5/arithmetic/op/store",
    "phase5/arithmetic/op/addi",
    "phase5/arithmetic/op/addm",
    "phase5/arithmetic/op/subm",
    "phase5/arithmetic/op/mulm",
    "phase5/arithmetic/op/jmp",
    "phase5/arithmetic/op/jz",
    "phase5/arithmetic/op/halt",
];
const IMMEDIATE_COLUMN: &str = "phase5/arithmetic/immediate";
const JUMP_TARGET_COLUMN: &str = "phase5/arithmetic/jump_target";
const FIRST_ROW_COLUMN: &str = "phase5/arithmetic/first_row";
const LAST_ROW_COLUMN: &str = "phase5/arithmetic/last_row";

#[derive(Clone, Debug)]
struct Phase5ArithmeticSubsetEval {
    log_size: u32,
    memory_size: usize,
    initial_state: PublicState,
    final_state: PublicState,
}

#[derive(Clone, Debug)]
struct PublicState {
    pc: u8,
    acc: i16,
    sp: u8,
    zero_flag: bool,
    carry_flag: bool,
    halted: bool,
    memory: Vec<i16>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct PreprocessedRow {
    opcode_flags: [u32; 11],
    immediate: i16,
    jump_target: u8,
    address_flags: Vec<u32>,
    store_address_flags: Vec<u32>,
    is_first_row: bool,
    is_last_row: bool,
}

#[derive(Clone, Debug)]
struct AuxiliaryState {
    loaded_memory: i16,
    mul_result: i16,
    next_pc_active: u8,
    next_acc_active: i16,
    next_memory_active: Vec<i16>,
}

#[derive(Clone, Copy, Debug)]
struct TraceLayout {
    memory_size: usize,
}

impl TraceLayout {
    const STATE_PREFIX_WIDTH: usize = 7;
    const AUX_PREFIX_WIDTH: usize = 4;

    fn new(memory_size: usize) -> Self {
        Self { memory_size }
    }

    fn state_width(&self) -> usize {
        Self::STATE_PREFIX_WIDTH + self.memory_size
    }

    fn total_width(&self) -> usize {
        self.state_width() * 2 + Self::AUX_PREFIX_WIDTH + self.memory_size
    }

    fn next_prefix(&self) -> usize {
        self.state_width()
    }

    fn aux_prefix(&self) -> usize {
        self.state_width() * 2
    }

    fn loaded_memory(&self) -> usize {
        self.aux_prefix()
    }

    fn mul_result(&self) -> usize {
        self.aux_prefix() + 1
    }

    fn next_pc_active(&self) -> usize {
        self.aux_prefix() + 2
    }

    fn next_acc_active(&self) -> usize {
        self.aux_prefix() + 3
    }

    fn next_memory_active(&self, index: usize) -> usize {
        self.aux_prefix() + Self::AUX_PREFIX_WIDTH + index
    }
}

impl FrameworkEval for Phase5ArithmeticSubsetEval {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size.saturating_add(1)
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let layout = TraceLayout::new(self.memory_size);
        let one = E::F::from(BaseField::from(1u32));
        let zero = E::F::zero();

        let current_pc = eval.next_trace_mask();
        let current_acc = eval.next_trace_mask();
        let current_sp = eval.next_trace_mask();
        let current_zero = eval.next_trace_mask();
        let current_carry = eval.next_trace_mask();
        let current_halted = eval.next_trace_mask();
        let current_acc_inv = eval.next_trace_mask();
        let current_memory: Vec<_> = (0..self.memory_size)
            .map(|_| eval.next_trace_mask())
            .collect();

        let next_pc = eval.next_trace_mask();
        let next_acc = eval.next_trace_mask();
        let next_sp = eval.next_trace_mask();
        let next_zero = eval.next_trace_mask();
        let next_carry = eval.next_trace_mask();
        let next_halted = eval.next_trace_mask();
        let next_acc_inv = eval.next_trace_mask();
        let next_memory: Vec<_> = (0..self.memory_size)
            .map(|_| eval.next_trace_mask())
            .collect();
        let loaded_memory_aux = eval.next_trace_mask();
        let mul_result_aux = eval.next_trace_mask();
        let next_pc_active_aux = eval.next_trace_mask();
        let next_acc_active_aux = eval.next_trace_mask();
        let next_memory_active_aux: Vec<_> = (0..self.memory_size)
            .map(|_| eval.next_trace_mask())
            .collect();

        let opcode_flags: Vec<_> = OPCODE_COLUMN_NAMES
            .iter()
            .map(|name| eval.get_preprocessed_column(column_id(name)))
            .collect();
        let immediate = eval.get_preprocessed_column(column_id(IMMEDIATE_COLUMN));
        let jump_target = eval.get_preprocessed_column(column_id(JUMP_TARGET_COLUMN));
        let is_first_row = eval.get_preprocessed_column(column_id(FIRST_ROW_COLUMN));
        let is_last_row = eval.get_preprocessed_column(column_id(LAST_ROW_COLUMN));
        let address_flags: Vec<_> = (0..self.memory_size)
            .map(|index| eval.get_preprocessed_column(column_id(&address_column_name(index))))
            .collect();
        let store_address_flags: Vec<_> = (0..self.memory_size)
            .map(|index| eval.get_preprocessed_column(column_id(&store_address_column_name(index))))
            .collect();

        for bit in [
            current_zero.clone(),
            current_halted.clone(),
            next_zero.clone(),
            next_halted.clone(),
            is_first_row.clone(),
            is_last_row.clone(),
        ] {
            eval.add_constraint(bit.clone() * (bit - one.clone()));
        }

        for selector in opcode_flags
            .iter()
            .cloned()
            .chain(address_flags.iter().cloned())
            .chain(store_address_flags.iter().cloned())
        {
            eval.add_constraint(selector.clone() * (selector - one.clone()));
        }

        let opcode_sum = opcode_flags
            .iter()
            .cloned()
            .fold(zero.clone(), |acc, x| acc + x);
        eval.add_constraint(opcode_sum - one.clone());

        let memory_operand_selector = opcode_flags[2].clone()
            + opcode_flags[3].clone()
            + opcode_flags[5].clone()
            + opcode_flags[6].clone()
            + opcode_flags[7].clone();
        let address_sum = address_flags
            .iter()
            .cloned()
            .fold(zero.clone(), |acc, x| acc + x);
        eval.add_constraint(address_sum - memory_operand_selector);
        let store_address_sum = store_address_flags
            .iter()
            .cloned()
            .fold(zero.clone(), |acc, x| acc + x);
        eval.add_constraint(store_address_sum - opcode_flags[3].clone());

        eval.add_constraint(current_carry.clone());
        eval.add_constraint(next_carry.clone());

        eval.add_constraint(current_zero.clone() * current_acc.clone());
        eval.add_constraint(
            (one.clone() - current_zero.clone())
                * (current_acc.clone() * current_acc_inv - one.clone()),
        );
        eval.add_constraint(next_zero.clone() * next_acc.clone());
        eval.add_constraint(
            (one.clone() - next_zero.clone()) * (next_acc.clone() * next_acc_inv - one.clone()),
        );

        let pc_plus_one = current_pc.clone() + one.clone();
        let loaded_memory = address_flags
            .iter()
            .cloned()
            .zip(current_memory.iter().cloned())
            .fold(zero.clone(), |acc, (sel, value)| acc + sel * value);
        eval.add_constraint(loaded_memory_aux.clone() - loaded_memory.clone());
        eval.add_constraint(
            opcode_flags[7].clone()
                * (mul_result_aux.clone() - current_acc.clone() * loaded_memory_aux.clone()),
        );
        let jump_taken = current_zero.clone() * jump_target.clone()
            + (one.clone() - current_zero.clone()) * pc_plus_one.clone();

        let expected_pc_active = opcode_flags[0].clone() * pc_plus_one.clone()
            + opcode_flags[1].clone() * pc_plus_one.clone()
            + opcode_flags[2].clone() * pc_plus_one.clone()
            + opcode_flags[3].clone() * pc_plus_one.clone()
            + opcode_flags[4].clone() * pc_plus_one.clone()
            + opcode_flags[5].clone() * pc_plus_one.clone()
            + opcode_flags[6].clone() * pc_plus_one.clone()
            + opcode_flags[7].clone() * pc_plus_one.clone()
            + opcode_flags[8].clone() * jump_target.clone()
            + opcode_flags[9].clone() * jump_taken
            + opcode_flags[10].clone() * current_pc.clone();
        eval.add_constraint(next_pc_active_aux.clone() - expected_pc_active);

        let expected_acc_active = opcode_flags[1].clone() * immediate.clone()
            + opcode_flags[2].clone() * loaded_memory_aux.clone()
            + opcode_flags[4].clone() * (current_acc.clone() + immediate.clone())
            + opcode_flags[5].clone() * (current_acc.clone() + loaded_memory_aux.clone())
            + opcode_flags[6].clone() * (current_acc.clone() - loaded_memory_aux.clone())
            + opcode_flags[7].clone() * mul_result_aux.clone()
            + (opcode_flags[0].clone()
                + opcode_flags[3].clone()
                + opcode_flags[8].clone()
                + opcode_flags[9].clone()
                + opcode_flags[10].clone())
                * current_acc.clone();
        eval.add_constraint(next_acc_active_aux.clone() - expected_acc_active);

        let expected_halted_active = opcode_flags[10].clone();
        let expected_next_pc = current_halted.clone() * current_pc.clone()
            + (one.clone() - current_halted.clone()) * next_pc_active_aux;
        let expected_next_acc = current_halted.clone() * current_acc.clone()
            + (one.clone() - current_halted.clone()) * next_acc_active_aux;
        let expected_next_sp = current_sp.clone();
        let expected_next_halted = current_halted.clone()
            + (one.clone() - current_halted.clone()) * expected_halted_active;

        eval.add_constraint(next_pc - expected_next_pc);
        eval.add_constraint(next_acc - expected_next_acc);
        eval.add_constraint(next_sp - expected_next_sp);
        eval.add_constraint(next_halted - expected_next_halted);

        for (index, (current_mem, next_mem)) in current_memory
            .iter()
            .cloned()
            .zip(next_memory.iter().cloned())
            .enumerate()
        {
            let store_here = store_address_flags[index].clone();
            let expected_next_mem_active = store_here.clone() * current_acc.clone()
                + (one.clone() - store_here) * current_mem.clone();
            eval.add_constraint(next_memory_active_aux[index].clone() - expected_next_mem_active);
            let expected_next_mem = current_halted.clone() * current_mem.clone()
                + (one.clone() - current_halted.clone()) * next_memory_active_aux[index].clone();
            eval.add_constraint(next_mem - expected_next_mem);
        }

        constrain_public_state(
            &mut eval,
            &layout,
            true,
            is_first_row,
            &self.initial_state,
            &current_pc,
            &current_acc,
            &current_sp,
            &current_zero,
            &current_carry,
            &current_halted,
            &current_memory,
        );
        constrain_public_state(
            &mut eval,
            &layout,
            false,
            is_last_row,
            &self.final_state,
            &current_pc,
            &current_acc,
            &current_sp,
            &current_zero,
            &current_carry,
            &current_halted,
            &current_memory,
        );

        eval
    }
}

pub(crate) fn prove_phase5_arithmetic_subset(
    witness: PreparedExecutionWitness,
) -> Result<VanillaStarkExecutionProof> {
    validate_phase5_subset_witness(
        &witness.claim.program,
        &witness.state_trace,
        witness.claim.steps,
    )?;

    let trace_bundle = build_trace_bundle(&witness.claim.program, &witness.state_trace)?;
    let component = arithmetic_subset_component(
        trace_bundle.log_size,
        witness.claim.program.initial_memory(),
        witness.claim.final_state.clone(),
    );
    let config = PcsConfig::default();
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(
            component.max_constraint_log_degree_bound() + config.fri_config.log_blowup_factor + 1,
        )
        .circle_domain()
        .half_coset,
    );

    let prover_channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<CpuBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(trace_bundle.preprocessed_trace.clone());
    tree_builder.commit(prover_channel);

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(trace_bundle.base_trace.clone());
    tree_builder.commit(prover_channel);

    let stark_proof = prove::<CpuBackend, Blake2sM31MerkleChannel>(
        &[&component],
        prover_channel,
        commitment_scheme,
    )
    .map_err(|error| {
        VmError::UnsupportedProof(format!("S-two arithmetic-subset proving failed: {error}"))
    })?;

    let embedded_normalization = build_phase8_embedded_normalization(&witness.claim)?;
    let embedded_activation_lookup = build_phase9_embedded_activation_lookup(&witness.claim)?;
    let embedded_shared_normalization =
        build_phase10_embedded_shared_normalization(&witness.claim)?;
    let embedded_shared_activation_lookup =
        build_phase10_embedded_shared_activation_lookup(&witness.claim)?;
    let proof_bytes = serde_json::to_vec(&Phase5ArithmeticSubsetProofPayload {
        stark_proof,
        canonical_preprocessed_rows: trace_bundle.preprocessed_rows,
        embedded_normalization,
        embedded_activation_lookup,
        embedded_shared_normalization,
        embedded_shared_activation_lookup,
    })
    .map_err(|error| VmError::Serialization(error.to_string()))?;
    let stwo_auxiliary = build_phase7_auxiliary_proofs(&witness.claim)?;

    Ok(VanillaStarkExecutionProof {
        proof_backend: StarkProofBackend::Stwo,
        proof_backend_version: stwo_backend_version_for_program(&witness.claim.program).to_string(),
        stwo_auxiliary,
        claim: witness.claim,
        proof: proof_bytes,
    })
}

pub(crate) fn verify_phase5_arithmetic_subset(proof: &VanillaStarkExecutionProof) -> Result<bool> {
    let expected_backend_version = stwo_backend_version_for_program(&proof.claim.program);
    if proof.proof_backend_version != expected_backend_version {
        return Err(VmError::InvalidConfig(format!(
            "S-two proof backend version `{}` does not match expected `{}` for this program family",
            proof.proof_backend_version, expected_backend_version
        )));
    }
    validate_phase5_claim(&proof.claim)?;
    if matches_decoding_step_v2(&proof.claim.program)
        && proof.proof.len() > MAX_DECODING_PROOF_PAYLOAD_BYTES
    {
        return Err(VmError::InvalidConfig(format!(
            "decoding_step_v2 proof payload is {} bytes, exceeding the limit of {} bytes",
            proof.proof.len(),
            MAX_DECODING_PROOF_PAYLOAD_BYTES
        )));
    }
    let state_trace = reconstruct_state_trace_from_claim(&proof.claim)?;
    let trace_bundle = build_trace_bundle(&proof.claim.program, &state_trace)?;
    let component = arithmetic_subset_component(
        trace_bundle.log_size,
        proof.claim.program.initial_memory(),
        proof.claim.final_state.clone(),
    );
    let payload: Phase5ArithmeticSubsetProofPayload = serde_json::from_slice(&proof.proof)
        .map_err(|error| VmError::Serialization(error.to_string()))?;
    if payload.canonical_preprocessed_rows != trace_bundle.preprocessed_rows {
        return Err(VmError::UnsupportedProof(
            "S-two arithmetic subset verification rejected proof with non-canonical preprocessed rows"
                .to_string(),
        ));
    }

    let stark_proof = payload.stark_proof;
    let config = stark_proof.config;
    let verifier_channel = &mut Blake2sM31Channel::default();
    let commitment_scheme = &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(config);
    let sizes = component.trace_log_degree_bounds();
    commitment_scheme.commit(stark_proof.commitments[0], &sizes[0], verifier_channel);
    commitment_scheme.commit(stark_proof.commitments[1], &sizes[1], verifier_channel);

    let verified = verify(
        &[&component],
        verifier_channel,
        commitment_scheme,
        stark_proof,
    )
    .is_ok();
    if !verified {
        return Ok(false);
    }

    verify_phase7_auxiliary_proofs(proof)?;
    verify_phase8_embedded_normalization(proof, payload.embedded_normalization.as_ref())?;
    verify_phase9_embedded_activation_lookup(proof, payload.embedded_activation_lookup.as_ref())?;
    verify_phase10_embedded_shared_normalization(
        proof,
        payload.embedded_shared_normalization.as_ref(),
    )?;
    verify_phase10_embedded_shared_activation_lookup(
        proof,
        payload.embedded_shared_activation_lookup.as_ref(),
    )?;
    Ok(true)
}

fn build_phase7_auxiliary_proofs(
    claim: &VanillaStarkExecutionClaim,
) -> Result<Option<StwoAuxiliaryProofs>> {
    if !matches_gemma_block_v1(&claim.program) {
        return Ok(None);
    }

    let final_memory = &claim.final_state.memory;
    let norm_sq = *final_memory
        .get(GEMMA_BLOCK_NORM_SQ_MEMORY_INDEX)
        .ok_or_else(|| {
            VmError::InvalidConfig("gemma_block_v1 final state missing norm_sq cell".to_string())
        })?;
    let inv_sqrt_q8 = *final_memory
        .get(GEMMA_BLOCK_INV_SQRT_MEMORY_INDEX)
        .ok_or_else(|| {
            VmError::InvalidConfig(
                "gemma_block_v1 final state missing inv_sqrt_q8 cell".to_string(),
            )
        })?;
    if norm_sq != GEMMA_BLOCK_EXPECTED_NORM_SQ || inv_sqrt_q8 != GEMMA_BLOCK_EXPECTED_INV_SQRT_Q8 {
        return Err(VmError::UnsupportedProof(format!(
            "gemma_block_v1 normalization companion expects norm_sq={} and inv_sqrt_q8={}, got {} and {}",
            GEMMA_BLOCK_EXPECTED_NORM_SQ,
            GEMMA_BLOCK_EXPECTED_INV_SQRT_Q8,
            norm_sq,
            inv_sqrt_q8
        )));
    }

    let proof_envelope = serde_json::to_value(prove_phase5_normalization_lookup_demo_envelope()?)
        .map_err(|error| VmError::Serialization(error.to_string()))?;

    Ok(Some(StwoAuxiliaryProofs {
        normalization_companion: Some(StwoNormalizationCompanion {
            statement_version: STWO_NORMALIZATION_STATEMENT_VERSION_PHASE5.to_string(),
            semantic_scope: GEMMA_BLOCK_NORMALIZATION_SCOPE.to_string(),
            norm_sq_memory_index: GEMMA_BLOCK_NORM_SQ_MEMORY_INDEX as u8,
            inv_sqrt_q8_memory_index: GEMMA_BLOCK_INV_SQRT_MEMORY_INDEX as u8,
            expected_norm_sq: norm_sq,
            expected_inv_sqrt_q8: inv_sqrt_q8,
            proof_envelope,
        }),
    }))
}

fn build_phase8_embedded_normalization(
    claim: &VanillaStarkExecutionClaim,
) -> Result<Option<EmbeddedNormalizationProof>> {
    if !(matches_gemma_block_v2(&claim.program) || matches_gemma_block_v3(&claim.program)) {
        return Ok(None);
    }

    let (norm_sq, inv_sqrt_q8) = gemma_block_normalization_pair(&claim.final_state.memory)?;
    let proof_envelope = serde_json::to_value(prove_phase5_normalization_lookup_demo_envelope()?)
        .map_err(|error| VmError::Serialization(error.to_string()))?;
    Ok(Some(EmbeddedNormalizationProof {
        statement_version: STWO_NORMALIZATION_STATEMENT_VERSION_PHASE5.to_string(),
        semantic_scope: embedded_normalization_scope(&claim.program).to_string(),
        norm_sq_memory_index: GEMMA_BLOCK_NORM_SQ_MEMORY_INDEX as u8,
        inv_sqrt_q8_memory_index: GEMMA_BLOCK_INV_SQRT_MEMORY_INDEX as u8,
        expected_norm_sq: norm_sq,
        expected_inv_sqrt_q8: inv_sqrt_q8,
        proof_envelope,
    }))
}

fn build_phase9_embedded_activation_lookup(
    claim: &VanillaStarkExecutionClaim,
) -> Result<Option<EmbeddedActivationLookupProof>> {
    if !matches_gemma_block_v3(&claim.program) {
        return Ok(None);
    }

    let (activation_input, activation_output) =
        gemma_block_activation_pair(&claim.final_state.memory)?;
    let proof_envelope = serde_json::to_value(prove_phase3_binary_step_lookup_demo_envelope()?)
        .map_err(|error| VmError::Serialization(error.to_string()))?;
    Ok(Some(EmbeddedActivationLookupProof {
        statement_version: STWO_LOOKUP_STATEMENT_VERSION_PHASE3.to_string(),
        semantic_scope: GEMMA_BLOCK_V3_ACTIVATION_SCOPE.to_string(),
        input_memory_index: GEMMA_BLOCK_ACTIVATION_INPUT_MEMORY_INDEX as u8,
        output_memory_index: GEMMA_BLOCK_ACTIVATION_OUTPUT_MEMORY_INDEX as u8,
        expected_input: activation_input,
        expected_output: activation_output,
        proof_envelope,
    }))
}

fn build_phase10_embedded_shared_normalization(
    claim: &VanillaStarkExecutionClaim,
) -> Result<Option<EmbeddedSharedNormalizationProof>> {
    if !(matches_gemma_block_v4(&claim.program)
        || matches_decoding_step_v1(&claim.program)
        || matches_decoding_step_v2(&claim.program))
    {
        return Ok(None);
    }

    let claimed_rows = shared_normalization_claim_rows(&claim.program, &claim.final_state.memory)?;
    let proof_rows: Vec<(u16, u16)> = claimed_rows
        .iter()
        .map(|row| (row.expected_norm_sq as u16, row.expected_inv_sqrt_q8 as u16))
        .collect();
    let proof_envelope = prove_phase10_shared_normalization_lookup_envelope(&proof_rows)?;
    Ok(Some(EmbeddedSharedNormalizationProof {
        statement_version: STWO_SHARED_NORMALIZATION_STATEMENT_VERSION_PHASE10.to_string(),
        semantic_scope: shared_normalization_scope(&claim.program).to_string(),
        claimed_rows,
        proof_envelope,
    }))
}

fn build_phase10_embedded_shared_activation_lookup(
    claim: &VanillaStarkExecutionClaim,
) -> Result<Option<EmbeddedSharedActivationLookupProof>> {
    if !(matches_gemma_block_v4(&claim.program)
        || matches_decoding_step_v1(&claim.program)
        || matches_decoding_step_v2(&claim.program))
    {
        return Ok(None);
    }

    let claimed_rows = shared_activation_claim_rows(&claim.program, &claim.final_state.memory)?;
    let proof_rows: Vec<Phase3LookupTableRow> = claimed_rows
        .iter()
        .map(|row| Phase3LookupTableRow {
            input: row.expected_input,
            output: row.expected_output as u8,
        })
        .collect();
    let proof_envelope = prove_phase10_shared_binary_step_lookup_envelope(&proof_rows)?;
    Ok(Some(EmbeddedSharedActivationLookupProof {
        statement_version: STWO_SHARED_LOOKUP_STATEMENT_VERSION_PHASE10.to_string(),
        semantic_scope: shared_activation_scope(&claim.program).to_string(),
        claimed_rows,
        proof_envelope,
    }))
}

fn verify_phase7_auxiliary_proofs(proof: &VanillaStarkExecutionProof) -> Result<()> {
    if !matches_gemma_block_v1(&proof.claim.program) {
        return Ok(());
    }

    let auxiliary = proof.stwo_auxiliary.as_ref().ok_or_else(|| {
        VmError::InvalidConfig(
            "gemma_block_v1 S-two proof is missing its normalization companion".to_string(),
        )
    })?;
    let companion = auxiliary.normalization_companion.as_ref().ok_or_else(|| {
        VmError::InvalidConfig(
            "gemma_block_v1 S-two proof is missing normalization companion metadata".to_string(),
        )
    })?;
    if companion.statement_version != STWO_NORMALIZATION_STATEMENT_VERSION_PHASE5 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported gemma_block_v1 normalization companion statement version `{}`",
            companion.statement_version
        )));
    }
    if companion.semantic_scope != GEMMA_BLOCK_NORMALIZATION_SCOPE {
        return Err(VmError::InvalidConfig(format!(
            "unsupported gemma_block_v1 normalization companion scope `{}`",
            companion.semantic_scope
        )));
    }
    let final_memory = &proof.claim.final_state.memory;
    let norm_sq = *final_memory
        .get(companion.norm_sq_memory_index as usize)
        .ok_or_else(|| {
            VmError::InvalidConfig(
                "gemma_block_v1 normalization companion norm_sq index is out of bounds".to_string(),
            )
        })?;
    let inv_sqrt_q8 = *final_memory
        .get(companion.inv_sqrt_q8_memory_index as usize)
        .ok_or_else(|| {
            VmError::InvalidConfig(
                "gemma_block_v1 normalization companion inv_sqrt_q8 index is out of bounds"
                    .to_string(),
            )
        })?;
    if norm_sq != companion.expected_norm_sq || inv_sqrt_q8 != companion.expected_inv_sqrt_q8 {
        return Err(VmError::InvalidConfig(format!(
            "gemma_block_v1 normalization companion does not match claimed final state: expected ({}, {}), got ({}, {})",
            companion.expected_norm_sq, companion.expected_inv_sqrt_q8, norm_sq, inv_sqrt_q8
        )));
    }
    let canonical_pair_exists = phase5_normalization_table_rows()
        .into_iter()
        .any(|row| row.norm_sq as i16 == norm_sq && row.inv_sqrt_q8 as i16 == inv_sqrt_q8);
    if !canonical_pair_exists {
        return Err(VmError::InvalidConfig(format!(
            "gemma_block_v1 normalization companion row ({norm_sq}, {inv_sqrt_q8}) is not present in the canonical Phase 5 lookup table"
        )));
    }
    let proof_envelope = serde_json::from_value(companion.proof_envelope.clone())
        .map_err(|error| VmError::Serialization(error.to_string()))?;
    if !verify_phase5_normalization_lookup_demo_envelope(&proof_envelope)? {
        return Err(VmError::UnsupportedProof(
            "gemma_block_v1 normalization companion proof did not verify".to_string(),
        ));
    }
    Ok(())
}

fn verify_phase8_embedded_normalization(
    proof: &VanillaStarkExecutionProof,
    embedded: Option<&EmbeddedNormalizationProof>,
) -> Result<()> {
    if !(matches_gemma_block_v2(&proof.claim.program)
        || matches_gemma_block_v3(&proof.claim.program))
    {
        return Ok(());
    }

    let embedded = embedded.ok_or_else(|| {
        VmError::InvalidConfig(
            "gemma_block_v2/v3 S-two proof is missing embedded normalization proof".to_string(),
        )
    })?;
    if embedded.statement_version != STWO_NORMALIZATION_STATEMENT_VERSION_PHASE5 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported gemma_block_v2/v3 embedded normalization statement version `{}`",
            embedded.statement_version
        )));
    }
    let expected_scope = embedded_normalization_scope(&proof.claim.program);
    if embedded.semantic_scope != expected_scope {
        return Err(VmError::InvalidConfig(format!(
            "unsupported gemma_block_v2/v3 embedded normalization scope `{}`",
            embedded.semantic_scope
        )));
    }
    let (norm_sq, inv_sqrt_q8) = normalized_pair_from_indices(
        &proof.claim.final_state.memory,
        embedded.norm_sq_memory_index,
        embedded.inv_sqrt_q8_memory_index,
        "gemma_block_v2/v3 embedded normalization",
    )?;
    if norm_sq != embedded.expected_norm_sq || inv_sqrt_q8 != embedded.expected_inv_sqrt_q8 {
        return Err(VmError::InvalidConfig(format!(
            "gemma_block_v2/v3 embedded normalization does not match claimed final state: expected ({}, {}), got ({}, {})",
            embedded.expected_norm_sq, embedded.expected_inv_sqrt_q8, norm_sq, inv_sqrt_q8
        )));
    }
    let canonical_pair_exists = phase5_normalization_table_rows()
        .into_iter()
        .any(|row| row.norm_sq as i16 == norm_sq && row.inv_sqrt_q8 as i16 == inv_sqrt_q8);
    if !canonical_pair_exists {
        return Err(VmError::InvalidConfig(format!(
            "gemma_block_v2/v3 embedded normalization row ({norm_sq}, {inv_sqrt_q8}) is not present in the canonical Phase 5 lookup table"
        )));
    }
    let proof_envelope = serde_json::from_value(embedded.proof_envelope.clone())
        .map_err(|error| VmError::Serialization(error.to_string()))?;
    if !verify_phase5_normalization_lookup_demo_envelope(&proof_envelope)? {
        return Err(VmError::UnsupportedProof(
            "gemma_block_v2/v3 embedded normalization proof did not verify".to_string(),
        ));
    }
    Ok(())
}

fn verify_phase9_embedded_activation_lookup(
    proof: &VanillaStarkExecutionProof,
    embedded: Option<&EmbeddedActivationLookupProof>,
) -> Result<()> {
    if !matches_gemma_block_v3(&proof.claim.program) {
        return Ok(());
    }

    let embedded = embedded.ok_or_else(|| {
        VmError::InvalidConfig(
            "gemma_block_v3 S-two proof is missing embedded activation lookup proof".to_string(),
        )
    })?;
    if embedded.statement_version != STWO_LOOKUP_STATEMENT_VERSION_PHASE3 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported gemma_block_v3 embedded activation statement version `{}`",
            embedded.statement_version
        )));
    }
    if embedded.semantic_scope != GEMMA_BLOCK_V3_ACTIVATION_SCOPE {
        return Err(VmError::InvalidConfig(format!(
            "unsupported gemma_block_v3 embedded activation scope `{}`",
            embedded.semantic_scope
        )));
    }
    let (activation_input, activation_output) = activation_pair_from_indices(
        &proof.claim.final_state.memory,
        embedded.input_memory_index,
        embedded.output_memory_index,
        "gemma_block_v3 embedded activation",
    )?;
    if activation_input != embedded.expected_input || activation_output != embedded.expected_output
    {
        return Err(VmError::InvalidConfig(format!(
            "gemma_block_v3 embedded activation does not match claimed final state: expected ({}, {}), got ({}, {})",
            embedded.expected_input, embedded.expected_output, activation_input, activation_output
        )));
    }
    let canonical_pair_exists = phase3_lookup_table_rows()
        .into_iter()
        .any(|row| row.input == activation_input && row.output as i16 == activation_output);
    if !canonical_pair_exists {
        return Err(VmError::InvalidConfig(format!(
            "gemma_block_v3 embedded activation row ({activation_input}, {activation_output}) is not present in the canonical Phase 3 lookup table"
        )));
    }
    let proof_envelope: Phase3LookupProofEnvelope =
        serde_json::from_value(embedded.proof_envelope.clone())
            .map_err(|error| VmError::Serialization(error.to_string()))?;
    if !verify_phase3_binary_step_lookup_demo_envelope(&proof_envelope)? {
        return Err(VmError::UnsupportedProof(
            "gemma_block_v3 embedded activation proof did not verify".to_string(),
        ));
    }
    Ok(())
}

fn verify_phase10_embedded_shared_normalization(
    proof: &VanillaStarkExecutionProof,
    embedded: Option<&EmbeddedSharedNormalizationProof>,
) -> Result<()> {
    if !(matches_gemma_block_v4(&proof.claim.program)
        || matches_decoding_step_v1(&proof.claim.program)
        || matches_decoding_step_v2(&proof.claim.program))
    {
        return Ok(());
    }

    let embedded = embedded.ok_or_else(|| {
        VmError::InvalidConfig(format!(
            "{} S-two proof is missing embedded shared normalization proof",
            shared_program_label(&proof.claim.program)
        ))
    })?;
    if embedded.statement_version != STWO_SHARED_NORMALIZATION_STATEMENT_VERSION_PHASE10 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported gemma_block_v4 embedded shared normalization statement version `{}`",
            embedded.statement_version
        )));
    }
    let expected_scope = shared_normalization_scope(&proof.claim.program);
    if embedded.semantic_scope != expected_scope {
        return Err(VmError::InvalidConfig(format!(
            "unsupported {} embedded shared normalization scope `{}`",
            shared_program_label(&proof.claim.program),
            embedded.semantic_scope
        )));
    }
    let canonical_rows =
        shared_normalization_claim_rows(&proof.claim.program, &proof.claim.final_state.memory)?;
    if embedded.claimed_rows != canonical_rows {
        return Err(VmError::InvalidConfig(format!(
            "{} embedded claimed rows do not match the canonical final-state rows",
            shared_normalization_label(&proof.claim.program)
        )));
    }
    let proof_rows: Vec<(u16, u16)> = canonical_rows
        .iter()
        .map(|row| {
            Ok((
                u16::try_from(row.expected_norm_sq).map_err(|_| {
                    VmError::InvalidConfig(format!(
                        "{} normalization row is not a canonical u16",
                        shared_normalization_label(&proof.claim.program)
                    ))
                })?,
                u16::try_from(row.expected_inv_sqrt_q8).map_err(|_| {
                    VmError::InvalidConfig(format!(
                        "{} normalization inverse row is not a canonical u16",
                        shared_normalization_label(&proof.claim.program)
                    ))
                })?,
            ))
        })
        .collect::<Result<_>>()?;
    let proof_envelope = embedded.proof_envelope.clone();
    if proof_envelope.claimed_rows != proof_rows {
        return Err(VmError::InvalidConfig(format!(
            "{} proof envelope claimed rows do not match the embedded rows",
            shared_normalization_label(&proof.claim.program)
        )));
    }
    if !verify_phase10_shared_normalization_lookup_envelope(&proof_envelope)? {
        return Err(VmError::UnsupportedProof(format!(
            "{} proof did not verify",
            shared_normalization_label(&proof.claim.program)
        )));
    }
    Ok(())
}

fn verify_phase10_embedded_shared_activation_lookup(
    proof: &VanillaStarkExecutionProof,
    embedded: Option<&EmbeddedSharedActivationLookupProof>,
) -> Result<()> {
    if !(matches_gemma_block_v4(&proof.claim.program)
        || matches_decoding_step_v1(&proof.claim.program)
        || matches_decoding_step_v2(&proof.claim.program))
    {
        return Ok(());
    }

    let embedded = embedded.ok_or_else(|| {
        VmError::InvalidConfig(format!(
            "{} S-two proof is missing embedded shared activation proof",
            shared_program_label(&proof.claim.program)
        ))
    })?;
    if embedded.statement_version != STWO_SHARED_LOOKUP_STATEMENT_VERSION_PHASE10 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported gemma_block_v4 embedded shared activation statement version `{}`",
            embedded.statement_version
        )));
    }
    let expected_scope = shared_activation_scope(&proof.claim.program);
    if embedded.semantic_scope != expected_scope {
        return Err(VmError::InvalidConfig(format!(
            "unsupported {} embedded shared activation scope `{}`",
            shared_program_label(&proof.claim.program),
            embedded.semantic_scope
        )));
    }
    let canonical_rows =
        shared_activation_claim_rows(&proof.claim.program, &proof.claim.final_state.memory)?;
    if embedded.claimed_rows != canonical_rows {
        return Err(VmError::InvalidConfig(format!(
            "{} embedded claimed rows do not match the canonical final-state rows",
            shared_activation_label(&proof.claim.program)
        )));
    }
    let mut proof_rows = Vec::with_capacity(canonical_rows.len());
    for row in &canonical_rows {
        let (activation_input, activation_output) = activation_pair_from_indices(
            &proof.claim.final_state.memory,
            row.input_memory_index,
            row.output_memory_index,
            shared_activation_label(&proof.claim.program),
        )?;
        if activation_input != row.expected_input || activation_output != row.expected_output {
            return Err(VmError::InvalidConfig(format!(
                "gemma_block_v4 shared activation does not match claimed final state: expected ({}, {}), got ({}, {})",
                row.expected_input, row.expected_output, activation_input, activation_output
            )));
        }
        proof_rows.push(Phase3LookupTableRow {
            input: activation_input,
            output: u8::try_from(activation_output).map_err(|_| {
                VmError::InvalidConfig(format!(
                    "{} activation output is not a canonical u8",
                    shared_activation_label(&proof.claim.program)
                ))
            })?,
        });
    }
    let proof_envelope = embedded.proof_envelope.clone();
    if proof_envelope.claimed_rows != proof_rows {
        return Err(VmError::InvalidConfig(format!(
            "{} proof envelope claimed rows do not match the embedded rows",
            shared_activation_label(&proof.claim.program)
        )));
    }
    if !verify_phase10_shared_binary_step_lookup_envelope(&proof_envelope)? {
        return Err(VmError::UnsupportedProof(format!(
            "{} proof did not verify",
            shared_activation_label(&proof.claim.program)
        )));
    }
    Ok(())
}

pub(crate) fn phase12_shared_lookup_artifact_from_proof_payload(
    proof: &VanillaStarkExecutionProof,
    layout_commitment: &str,
) -> Result<Option<Phase12SharedLookupArtifact>> {
    if !matches_decoding_step_v2(&proof.claim.program) {
        return Ok(None);
    }
    if proof.proof.len() > MAX_DECODING_PROOF_PAYLOAD_BYTES {
        return Err(VmError::InvalidConfig(format!(
            "decoding_step_v2 proof payload is {} bytes, exceeding the limit of {} bytes",
            proof.proof.len(),
            MAX_DECODING_PROOF_PAYLOAD_BYTES
        )));
    }

    let payload: serde_json::Value = serde_json::from_slice(&proof.proof)
        .map_err(|error| VmError::Serialization(error.to_string()))?;
    let normalization_value = payload
        .get("embedded_shared_normalization")
        .cloned()
        .ok_or_else(|| {
            VmError::InvalidConfig(
                "decoding_step_v2 proof payload is missing embedded shared normalization rows"
                    .to_string(),
            )
        })?;
    let activation_value = payload
        .get("embedded_shared_activation_lookup")
        .cloned()
        .ok_or_else(|| {
            VmError::InvalidConfig(
                "decoding_step_v2 proof payload is missing embedded shared activation rows"
                    .to_string(),
            )
        })?;
    let normalization: EmbeddedSharedNormalizationProof =
        serde_json::from_value(normalization_value)
            .map_err(|error| VmError::Serialization(error.to_string()))?;
    let activation: EmbeddedSharedActivationLookupProof = serde_json::from_value(activation_value)
        .map_err(|error| VmError::Serialization(error.to_string()))?;
    if normalization.proof_envelope.proof.len() > MAX_SHARED_LOOKUP_ENVELOPE_PROOF_BYTES {
        return Err(VmError::InvalidConfig(format!(
            "decoding_step_v2 shared normalization proof is {} bytes, exceeding the limit of {} bytes",
            normalization.proof_envelope.proof.len(),
            MAX_SHARED_LOOKUP_ENVELOPE_PROOF_BYTES
        )));
    }
    if activation.proof_envelope.proof.len() > MAX_SHARED_LOOKUP_ENVELOPE_PROOF_BYTES {
        return Err(VmError::InvalidConfig(format!(
            "decoding_step_v2 shared activation proof is {} bytes, exceeding the limit of {} bytes",
            activation.proof_envelope.proof.len(),
            MAX_SHARED_LOOKUP_ENVELOPE_PROOF_BYTES
        )));
    }

    let expected_norm_rows =
        shared_normalization_claim_rows(&proof.claim.program, &proof.claim.final_state.memory)?;
    if normalization.statement_version != STWO_SHARED_NORMALIZATION_STATEMENT_VERSION_PHASE10 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding_step_v2 shared normalization statement version `{}`",
            normalization.statement_version
        )));
    }
    if normalization.semantic_scope != DECODING_STEP_V2_SHARED_NORMALIZATION_SCOPE {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding_step_v2 shared normalization scope `{}`",
            normalization.semantic_scope
        )));
    }
    if normalization.claimed_rows != expected_norm_rows {
        return Err(VmError::InvalidConfig(
            "decoding_step_v2 embedded shared normalization rows do not match the canonical final-state rows".to_string(),
        ));
    }
    let expected_norm_pairs: Vec<(u16, u16)> = expected_norm_rows
        .iter()
        .map(|row| (row.expected_norm_sq as u16, row.expected_inv_sqrt_q8 as u16))
        .collect();
    if normalization.proof_envelope.claimed_rows != expected_norm_pairs {
        return Err(VmError::InvalidConfig(
            "decoding_step_v2 shared normalization proof envelope rows do not match the canonical final-state rows".to_string(),
        ));
    }

    let expected_activation_rows =
        shared_activation_claim_rows(&proof.claim.program, &proof.claim.final_state.memory)?;
    if activation.statement_version != STWO_SHARED_LOOKUP_STATEMENT_VERSION_PHASE10 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding_step_v2 shared activation statement version `{}`",
            activation.statement_version
        )));
    }
    if activation.semantic_scope != DECODING_STEP_V2_SHARED_ACTIVATION_SCOPE {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding_step_v2 shared activation scope `{}`",
            activation.semantic_scope
        )));
    }
    if activation.claimed_rows != expected_activation_rows {
        return Err(VmError::InvalidConfig(
            "decoding_step_v2 embedded shared activation rows do not match the canonical final-state rows".to_string(),
        ));
    }
    let expected_activation_pairs: Vec<Phase3LookupTableRow> = expected_activation_rows
        .iter()
        .map(|row| Phase3LookupTableRow {
            input: row.expected_input,
            output: row.expected_output as u8,
        })
        .collect();
    if activation.proof_envelope.claimed_rows != expected_activation_pairs {
        return Err(VmError::InvalidConfig(
            "decoding_step_v2 shared activation proof envelope rows do not match the canonical final-state rows".to_string(),
        ));
    }
    if expected_norm_rows.len() != expected_activation_rows.len() {
        return Err(VmError::InvalidConfig(format!(
            "decoding_step_v2 embedded shared lookup row counts disagree: normalization={}, activation={}",
            expected_norm_rows.len(),
            expected_activation_rows.len()
        )));
    }

    let mut lookup_rows = Vec::with_capacity(expected_norm_rows.len() * 4);
    for (normalization_row, activation_row) in expected_norm_rows
        .iter()
        .zip(expected_activation_rows.iter())
    {
        lookup_rows.push(normalization_row.expected_norm_sq);
        lookup_rows.push(normalization_row.expected_inv_sqrt_q8);
        lookup_rows.push(activation_row.expected_input);
        lookup_rows.push(activation_row.expected_output);
    }
    Ok(Some(build_phase12_shared_lookup_artifact(
        layout_commitment,
        lookup_rows,
        normalization,
        activation,
    )?))
}

pub(crate) fn phase12_shared_lookup_rows_from_proof_payload(
    proof: &VanillaStarkExecutionProof,
    layout_commitment: &str,
) -> Result<Option<Vec<i16>>> {
    Ok(
        phase12_shared_lookup_artifact_from_proof_payload(proof, layout_commitment)?
            .map(|artifact| artifact.flattened_lookup_rows),
    )
}

fn gemma_block_normalization_pair(final_memory: &[i16]) -> Result<(i16, i16)> {
    let norm_sq = *final_memory
        .get(GEMMA_BLOCK_NORM_SQ_MEMORY_INDEX)
        .ok_or_else(|| {
            VmError::InvalidConfig("gemma_block final state missing norm_sq cell".to_string())
        })?;
    let inv_sqrt_q8 = *final_memory
        .get(GEMMA_BLOCK_INV_SQRT_MEMORY_INDEX)
        .ok_or_else(|| {
            VmError::InvalidConfig("gemma_block final state missing inv_sqrt_q8 cell".to_string())
        })?;
    if norm_sq != GEMMA_BLOCK_EXPECTED_NORM_SQ || inv_sqrt_q8 != GEMMA_BLOCK_EXPECTED_INV_SQRT_Q8 {
        return Err(VmError::UnsupportedProof(format!(
            "gemma_block normalization expects norm_sq={} and inv_sqrt_q8={}, got {} and {}",
            GEMMA_BLOCK_EXPECTED_NORM_SQ, GEMMA_BLOCK_EXPECTED_INV_SQRT_Q8, norm_sq, inv_sqrt_q8
        )));
    }
    Ok((norm_sq, inv_sqrt_q8))
}

fn gemma_block_activation_pair(final_memory: &[i16]) -> Result<(i16, i16)> {
    let activation_input = *final_memory
        .get(GEMMA_BLOCK_ACTIVATION_INPUT_MEMORY_INDEX)
        .ok_or_else(|| {
            VmError::InvalidConfig(
                "gemma_block final state missing activation input cell".to_string(),
            )
        })?;
    let activation_output = *final_memory
        .get(GEMMA_BLOCK_ACTIVATION_OUTPUT_MEMORY_INDEX)
        .ok_or_else(|| {
            VmError::InvalidConfig(
                "gemma_block final state missing activation output cell".to_string(),
            )
        })?;
    if activation_input != GEMMA_BLOCK_EXPECTED_ACTIVATION_INPUT
        || activation_output != GEMMA_BLOCK_EXPECTED_ACTIVATION_OUTPUT
    {
        return Err(VmError::UnsupportedProof(format!(
            "gemma_block activation expects input={} and output={}, got {} and {}",
            GEMMA_BLOCK_EXPECTED_ACTIVATION_INPUT,
            GEMMA_BLOCK_EXPECTED_ACTIVATION_OUTPUT,
            activation_input,
            activation_output
        )));
    }
    Ok((activation_input, activation_output))
}

fn shared_normalization_claim_rows(
    program: &Program,
    final_memory: &[i16],
) -> Result<Vec<EmbeddedSharedNormalizationClaimRow>> {
    if matches_decoding_step_v2(program) {
        let (primary_norm_idx, primary_inv_idx, secondary_norm_idx, secondary_inv_idx) =
            phase12_shared_normalization_indices(program)?;
        let primary = normalized_pair_from_indices(
            final_memory,
            primary_norm_idx,
            primary_inv_idx,
            "shared normalization primary row",
        )?;
        let secondary = normalized_pair_from_indices(
            final_memory,
            secondary_norm_idx,
            secondary_inv_idx,
            "shared normalization secondary row",
        )?;
        return validate_shared_normalization_pairs(
            primary,
            secondary,
            primary_norm_idx,
            primary_inv_idx,
            secondary_norm_idx,
            secondary_inv_idx,
        );
    }

    let primary = normalized_pair_from_indices(
        final_memory,
        GEMMA_BLOCK_NORM_SQ_MEMORY_INDEX as u8,
        GEMMA_BLOCK_INV_SQRT_MEMORY_INDEX as u8,
        "shared normalization primary row",
    )?;
    if primary
        != (
            GEMMA_BLOCK_EXPECTED_NORM_SQ,
            GEMMA_BLOCK_EXPECTED_INV_SQRT_Q8,
        )
    {
        return Err(VmError::UnsupportedProof(format!(
            "shared normalization expects primary row ({}, {}), got ({}, {})",
            GEMMA_BLOCK_EXPECTED_NORM_SQ, GEMMA_BLOCK_EXPECTED_INV_SQRT_Q8, primary.0, primary.1
        )));
    }
    let secondary = normalized_pair_from_indices(
        final_memory,
        GEMMA_BLOCK_V4_SHARED_NORM_SQ_MEMORY_INDEX as u8,
        GEMMA_BLOCK_V4_SHARED_INV_SQRT_Q8_MEMORY_INDEX as u8,
        "shared normalization secondary row",
    )?;
    if secondary
        != (
            GEMMA_BLOCK_V4_SHARED_NORM_SQ,
            GEMMA_BLOCK_V4_SHARED_INV_SQRT_Q8,
        )
    {
        return Err(VmError::UnsupportedProof(format!(
            "shared normalization expects secondary row ({}, {}), got ({}, {})",
            GEMMA_BLOCK_V4_SHARED_NORM_SQ,
            GEMMA_BLOCK_V4_SHARED_INV_SQRT_Q8,
            secondary.0,
            secondary.1
        )));
    }
    validate_shared_normalization_pairs(
        primary,
        secondary,
        GEMMA_BLOCK_NORM_SQ_MEMORY_INDEX as u8,
        GEMMA_BLOCK_INV_SQRT_MEMORY_INDEX as u8,
        GEMMA_BLOCK_V4_SHARED_NORM_SQ_MEMORY_INDEX as u8,
        GEMMA_BLOCK_V4_SHARED_INV_SQRT_Q8_MEMORY_INDEX as u8,
    )
}

fn shared_activation_claim_rows(
    program: &Program,
    final_memory: &[i16],
) -> Result<Vec<EmbeddedSharedActivationClaimRow>> {
    if matches_decoding_step_v2(program) {
        let (primary_input_idx, primary_output_idx, secondary_input_idx, secondary_output_idx) =
            phase12_shared_activation_indices(program)?;
        let primary = activation_pair_from_indices(
            final_memory,
            primary_input_idx,
            primary_output_idx,
            "shared activation primary row",
        )?;
        let secondary = activation_pair_from_indices(
            final_memory,
            secondary_input_idx,
            secondary_output_idx,
            "shared activation secondary row",
        )?;
        return validate_shared_activation_pairs(
            primary,
            secondary,
            primary_input_idx,
            primary_output_idx,
            secondary_input_idx,
            secondary_output_idx,
        );
    }

    let primary = activation_pair_from_indices(
        final_memory,
        GEMMA_BLOCK_ACTIVATION_INPUT_MEMORY_INDEX as u8,
        GEMMA_BLOCK_ACTIVATION_OUTPUT_MEMORY_INDEX as u8,
        "shared activation primary row",
    )?;
    if primary
        != (
            GEMMA_BLOCK_EXPECTED_ACTIVATION_INPUT,
            GEMMA_BLOCK_EXPECTED_ACTIVATION_OUTPUT,
        )
    {
        return Err(VmError::UnsupportedProof(format!(
            "shared activation expects primary row ({}, {}), got ({}, {})",
            GEMMA_BLOCK_EXPECTED_ACTIVATION_INPUT,
            GEMMA_BLOCK_EXPECTED_ACTIVATION_OUTPUT,
            primary.0,
            primary.1
        )));
    }
    let secondary = activation_pair_from_indices(
        final_memory,
        GEMMA_BLOCK_V4_SHARED_ACTIVATION_INPUT_MEMORY_INDEX as u8,
        GEMMA_BLOCK_V4_SHARED_ACTIVATION_OUTPUT_MEMORY_INDEX as u8,
        "shared activation secondary row",
    )?;
    if secondary
        != (
            GEMMA_BLOCK_V4_SHARED_ACTIVATION_INPUT,
            GEMMA_BLOCK_V4_SHARED_ACTIVATION_OUTPUT,
        )
    {
        return Err(VmError::UnsupportedProof(format!(
            "shared activation expects secondary row ({}, {}), got ({}, {})",
            GEMMA_BLOCK_V4_SHARED_ACTIVATION_INPUT,
            GEMMA_BLOCK_V4_SHARED_ACTIVATION_OUTPUT,
            secondary.0,
            secondary.1
        )));
    }
    validate_shared_activation_pairs(
        primary,
        secondary,
        GEMMA_BLOCK_ACTIVATION_INPUT_MEMORY_INDEX as u8,
        GEMMA_BLOCK_ACTIVATION_OUTPUT_MEMORY_INDEX as u8,
        GEMMA_BLOCK_V4_SHARED_ACTIVATION_INPUT_MEMORY_INDEX as u8,
        GEMMA_BLOCK_V4_SHARED_ACTIVATION_OUTPUT_MEMORY_INDEX as u8,
    )
}

fn validate_shared_normalization_pairs(
    primary: (i16, i16),
    secondary: (i16, i16),
    primary_norm_idx: u8,
    primary_inv_idx: u8,
    secondary_norm_idx: u8,
    secondary_inv_idx: u8,
) -> Result<Vec<EmbeddedSharedNormalizationClaimRow>> {
    if primary
        != (
            GEMMA_BLOCK_EXPECTED_NORM_SQ,
            GEMMA_BLOCK_EXPECTED_INV_SQRT_Q8,
        )
    {
        return Err(VmError::UnsupportedProof(format!(
            "shared normalization expects primary row ({}, {}), got ({}, {})",
            GEMMA_BLOCK_EXPECTED_NORM_SQ, GEMMA_BLOCK_EXPECTED_INV_SQRT_Q8, primary.0, primary.1
        )));
    }
    if secondary
        != (
            GEMMA_BLOCK_V4_SHARED_NORM_SQ,
            GEMMA_BLOCK_V4_SHARED_INV_SQRT_Q8,
        )
    {
        return Err(VmError::UnsupportedProof(format!(
            "shared normalization expects secondary row ({}, {}), got ({}, {})",
            GEMMA_BLOCK_V4_SHARED_NORM_SQ,
            GEMMA_BLOCK_V4_SHARED_INV_SQRT_Q8,
            secondary.0,
            secondary.1
        )));
    }
    Ok(vec![
        EmbeddedSharedNormalizationClaimRow {
            norm_sq_memory_index: primary_norm_idx,
            inv_sqrt_q8_memory_index: primary_inv_idx,
            expected_norm_sq: primary.0,
            expected_inv_sqrt_q8: primary.1,
        },
        EmbeddedSharedNormalizationClaimRow {
            norm_sq_memory_index: secondary_norm_idx,
            inv_sqrt_q8_memory_index: secondary_inv_idx,
            expected_norm_sq: secondary.0,
            expected_inv_sqrt_q8: secondary.1,
        },
    ])
}

fn validate_shared_activation_pairs(
    primary: (i16, i16),
    secondary: (i16, i16),
    primary_input_idx: u8,
    primary_output_idx: u8,
    secondary_input_idx: u8,
    secondary_output_idx: u8,
) -> Result<Vec<EmbeddedSharedActivationClaimRow>> {
    if primary
        != (
            GEMMA_BLOCK_EXPECTED_ACTIVATION_INPUT,
            GEMMA_BLOCK_EXPECTED_ACTIVATION_OUTPUT,
        )
    {
        return Err(VmError::UnsupportedProof(format!(
            "shared activation expects primary row ({}, {}), got ({}, {})",
            GEMMA_BLOCK_EXPECTED_ACTIVATION_INPUT,
            GEMMA_BLOCK_EXPECTED_ACTIVATION_OUTPUT,
            primary.0,
            primary.1
        )));
    }
    if secondary
        != (
            GEMMA_BLOCK_V4_SHARED_ACTIVATION_INPUT,
            GEMMA_BLOCK_V4_SHARED_ACTIVATION_OUTPUT,
        )
    {
        return Err(VmError::UnsupportedProof(format!(
            "shared activation expects secondary row ({}, {}), got ({}, {})",
            GEMMA_BLOCK_V4_SHARED_ACTIVATION_INPUT,
            GEMMA_BLOCK_V4_SHARED_ACTIVATION_OUTPUT,
            secondary.0,
            secondary.1
        )));
    }
    Ok(vec![
        EmbeddedSharedActivationClaimRow {
            input_memory_index: primary_input_idx,
            output_memory_index: primary_output_idx,
            expected_input: primary.0,
            expected_output: primary.1,
        },
        EmbeddedSharedActivationClaimRow {
            input_memory_index: secondary_input_idx,
            output_memory_index: secondary_output_idx,
            expected_input: secondary.0,
            expected_output: secondary.1,
        },
    ])
}

fn phase12_shared_normalization_indices(program: &Program) -> Result<(u8, u8, u8, u8)> {
    let layout = infer_phase12_decoding_layout(program).ok_or_else(|| {
        VmError::UnsupportedProof(
            "Phase 12 shared normalization requires a decoding_step_v2-family layout".to_string(),
        )
    })?;
    let lookup = layout.lookup_range()?;
    Ok((
        lookup.start as u8,
        (lookup.start + 1) as u8,
        (lookup.start + 4) as u8,
        (lookup.start + 5) as u8,
    ))
}

fn phase12_shared_activation_indices(program: &Program) -> Result<(u8, u8, u8, u8)> {
    let layout = infer_phase12_decoding_layout(program).ok_or_else(|| {
        VmError::UnsupportedProof(
            "Phase 12 shared activation requires a decoding_step_v2-family layout".to_string(),
        )
    })?;
    let lookup = layout.lookup_range()?;
    Ok((
        (lookup.start + 2) as u8,
        (lookup.start + 3) as u8,
        (lookup.start + 6) as u8,
        (lookup.start + 7) as u8,
    ))
}

fn normalized_pair_from_indices(
    final_memory: &[i16],
    norm_sq_index: u8,
    inv_sqrt_q8_index: u8,
    scope: &str,
) -> Result<(i16, i16)> {
    let norm_sq = *final_memory
        .get(norm_sq_index as usize)
        .ok_or_else(|| VmError::InvalidConfig(format!("{scope} norm_sq index is out of bounds")))?;
    let inv_sqrt_q8 = *final_memory
        .get(inv_sqrt_q8_index as usize)
        .ok_or_else(|| {
            VmError::InvalidConfig(format!("{scope} inv_sqrt_q8 index is out of bounds"))
        })?;
    Ok((norm_sq, inv_sqrt_q8))
}

fn activation_pair_from_indices(
    final_memory: &[i16],
    input_index: u8,
    output_index: u8,
    scope: &str,
) -> Result<(i16, i16)> {
    let activation_input = *final_memory
        .get(input_index as usize)
        .ok_or_else(|| VmError::InvalidConfig(format!("{scope} input index is out of bounds")))?;
    let activation_output = *final_memory
        .get(output_index as usize)
        .ok_or_else(|| VmError::InvalidConfig(format!("{scope} output index is out of bounds")))?;
    Ok((activation_input, activation_output))
}

fn embedded_normalization_scope(program: &Program) -> &'static str {
    if matches_gemma_block_v3(program) {
        GEMMA_BLOCK_V3_NORMALIZATION_SCOPE
    } else {
        GEMMA_BLOCK_V2_NORMALIZATION_SCOPE
    }
}

#[derive(Serialize, Deserialize)]
struct Phase5ArithmeticSubsetProofPayload {
    stark_proof: StarkProof<Blake2sM31MerkleHasher>,
    canonical_preprocessed_rows: Vec<PreprocessedRow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    embedded_normalization: Option<EmbeddedNormalizationProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    embedded_activation_lookup: Option<EmbeddedActivationLookupProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    embedded_shared_normalization: Option<EmbeddedSharedNormalizationProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    embedded_shared_activation_lookup: Option<EmbeddedSharedActivationLookupProof>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct EmbeddedNormalizationProof {
    statement_version: String,
    semantic_scope: String,
    norm_sq_memory_index: u8,
    inv_sqrt_q8_memory_index: u8,
    expected_norm_sq: i16,
    expected_inv_sqrt_q8: i16,
    proof_envelope: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct EmbeddedActivationLookupProof {
    statement_version: String,
    semantic_scope: String,
    input_memory_index: u8,
    output_memory_index: u8,
    expected_input: i16,
    expected_output: i16,
    proof_envelope: serde_json::Value,
}

fn arithmetic_subset_component(
    log_size: u32,
    initial_memory: &[i16],
    final_state: MachineState,
) -> FrameworkComponent<Phase5ArithmeticSubsetEval> {
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(
        &preprocessed_column_ids(initial_memory.len()),
    );
    FrameworkComponent::new(
        &mut allocator,
        Phase5ArithmeticSubsetEval {
            log_size,
            memory_size: initial_memory.len(),
            initial_state: PublicState::from_initial_memory(initial_memory),
            final_state: PublicState::from_machine_state(final_state),
        },
        SecureField::zero(),
    )
}

fn validate_phase5_claim(claim: &VanillaStarkExecutionClaim) -> Result<()> {
    if !matches!(claim.attention_mode, Attention2DMode::AverageHard) {
        return Err(VmError::UnsupportedProof(format!(
            "S-two backend Phase 5 supports only `average-hard` attention, got `{}`",
            claim.attention_mode
        )));
    }

    validate_phase5_subset_witness(
        &claim.program,
        std::slice::from_ref(&claim.final_state),
        claim.steps,
    )
    .or_else(|_| {
        let trace = reconstruct_state_trace_from_claim(claim)?;
        validate_phase5_subset_witness(&claim.program, &trace, claim.steps)
    })
}

fn validate_phase5_subset_witness(
    program: &Program,
    states: &[MachineState],
    steps: usize,
) -> Result<()> {
    validate_phase5_proven_fixture(program)?;
    super::validate_phase2_proof_shape(program, &Attention2DMode::AverageHard)?;

    if states.is_empty() {
        return Err(VmError::UnsupportedProof(
            "S-two arithmetic subset pilot requires a non-empty state trace".to_string(),
        ));
    }

    if steps + 1 != states.len() && states.len() != 1 {
        return Err(VmError::UnsupportedProof(format!(
            "S-two arithmetic subset pilot expected state trace length {} for {steps} steps, got {}",
            steps + 1,
            states.len()
        )));
    }

    let final_state = states.last().expect("non-empty");
    if !final_state.halted {
        return Err(VmError::UnsupportedProof(
            "S-two arithmetic subset pilot currently requires executions that halt".to_string(),
        ));
    }

    for (row, state) in states.iter().enumerate() {
        if state.memory.len() != program.memory_size() {
            return Err(VmError::UnsupportedProof(format!(
                "S-two arithmetic subset pilot expected memory size {} at row {row}, got {}",
                program.memory_size(),
                state.memory.len()
            )));
        }
        if state.carry_flag {
            return Err(VmError::UnsupportedProof(format!(
                "S-two arithmetic subset pilot does not support overflow/carry traces; carry set at row {row}"
            )));
        }
        if usize::from(state.sp) != program.memory_size() {
            return Err(VmError::UnsupportedProof(format!(
                "S-two arithmetic subset pilot does not yet support stack-pointer motion; expected sp={} at row {row}, got {}",
                program.memory_size(),
                state.sp
            )));
        }
    }

    Ok(())
}

fn validate_phase5_proven_fixture(program: &Program) -> Result<()> {
    let matches_addition = program.memory_size() == 4
        && program.initial_memory() == [0, 0, 0, 0]
        && program.instructions()
            == [
                Instruction::LoadImmediate(5),
                Instruction::AddImmediate(3),
                Instruction::Halt,
            ];
    let matches_counter = program.memory_size() == 4
        && program.initial_memory() == [0, 5, 0, 0]
        && program.instructions()
            == [
                Instruction::LoadImmediate(0),
                Instruction::Store(0),
                Instruction::Load(0),
                Instruction::AddImmediate(1),
                Instruction::Store(0),
                Instruction::Load(0),
                Instruction::SubMemory(1),
                Instruction::JumpIfZero(9),
                Instruction::Jump(2),
                Instruction::Load(0),
                Instruction::Halt,
            ];
    let matches_multiply = program.memory_size() == 4
        && program.initial_memory() == [7, 0, 0, 6]
        && program.instructions()
            == [
                Instruction::Load(2),
                Instruction::SubMemory(3),
                Instruction::JumpIfZero(10),
                Instruction::Load(1),
                Instruction::AddMemory(0),
                Instruction::Store(1),
                Instruction::Load(2),
                Instruction::AddImmediate(1),
                Instruction::Store(2),
                Instruction::Jump(0),
                Instruction::Load(1),
                Instruction::Halt,
            ];
    let matches_dot_product = program.memory_size() == 10
        && program.initial_memory() == [1, 2, 3, 4, 5, 6, 7, 8, 0, 0]
        && program.instructions()
            == [
                Instruction::Load(0),
                Instruction::MulMemory(4),
                Instruction::Store(9),
                Instruction::Load(1),
                Instruction::MulMemory(5),
                Instruction::AddMemory(9),
                Instruction::Store(9),
                Instruction::Load(2),
                Instruction::MulMemory(6),
                Instruction::AddMemory(9),
                Instruction::Store(9),
                Instruction::Load(3),
                Instruction::MulMemory(7),
                Instruction::AddMemory(9),
                Instruction::Store(9),
                Instruction::Load(9),
                Instruction::Halt,
            ];
    let matches_memory_roundtrip = program.memory_size() == 4
        && program.initial_memory() == [0, 0, 0, 0]
        && program.instructions()
            == [
                Instruction::LoadImmediate(41),
                Instruction::Store(2),
                Instruction::LoadImmediate(0),
                Instruction::Load(2),
                Instruction::AddImmediate(1),
                Instruction::Halt,
            ];
    let matches_fibonacci = program.memory_size() == 5
        && program.initial_memory() == [0, 1, 0, 0, 7]
        && program.instructions()
            == [
                Instruction::Load(3),
                Instruction::SubMemory(4),
                Instruction::JumpIfZero(14),
                Instruction::Load(0),
                Instruction::AddMemory(1),
                Instruction::Store(2),
                Instruction::Load(1),
                Instruction::Store(0),
                Instruction::Load(2),
                Instruction::Store(1),
                Instruction::Load(3),
                Instruction::AddImmediate(1),
                Instruction::Store(3),
                Instruction::Jump(0),
                Instruction::Load(1),
                Instruction::Halt,
            ];
    let matches_matmul_2x2 = program.memory_size() == 14
        && program.initial_memory() == [1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0]
        && program.instructions()
            == [
                Instruction::Load(0),
                Instruction::MulMemory(4),
                Instruction::Store(12),
                Instruction::Load(1),
                Instruction::MulMemory(6),
                Instruction::AddMemory(12),
                Instruction::Store(8),
                Instruction::Load(0),
                Instruction::MulMemory(5),
                Instruction::Store(12),
                Instruction::Load(1),
                Instruction::MulMemory(7),
                Instruction::AddMemory(12),
                Instruction::Store(9),
                Instruction::Load(2),
                Instruction::MulMemory(4),
                Instruction::Store(12),
                Instruction::Load(3),
                Instruction::MulMemory(6),
                Instruction::AddMemory(12),
                Instruction::Store(10),
                Instruction::Load(2),
                Instruction::MulMemory(5),
                Instruction::Store(12),
                Instruction::Load(3),
                Instruction::MulMemory(7),
                Instruction::AddMemory(12),
                Instruction::Store(11),
                Instruction::Load(8),
                Instruction::AddMemory(9),
                Instruction::AddMemory(10),
                Instruction::AddMemory(11),
                Instruction::Halt,
            ];
    let matches_single_neuron = program.memory_size() == 8
        && program.initial_memory() == [2, 3, 1, 4, 2, 6, 20, 0]
        && program.instructions()
            == [
                Instruction::Load(0),
                Instruction::MulMemory(3),
                Instruction::Store(7),
                Instruction::Load(1),
                Instruction::MulMemory(4),
                Instruction::AddMemory(7),
                Instruction::Store(7),
                Instruction::Load(2),
                Instruction::MulMemory(5),
                Instruction::AddMemory(7),
                Instruction::Store(7),
                Instruction::Load(7),
                Instruction::SubMemory(6),
                Instruction::JumpIfZero(16),
                Instruction::LoadImmediate(0),
                Instruction::Halt,
                Instruction::LoadImmediate(1),
                Instruction::Halt,
            ];
    let matches_gemma_block_v1 = matches_gemma_block_v1(program);
    let matches_gemma_block_v2 = matches_gemma_block_v2(program);
    let matches_gemma_block_v3 = matches_gemma_block_v3(program);
    let matches_gemma_block_v4 = matches_gemma_block_v4(program);
    let matches_decoding_step_v1 = matches_decoding_step_v1(program);
    let matches_decoding_step_v2 = matches_decoding_step_v2(program);

    if matches_addition
        || matches_counter
        || matches_multiply
        || matches_dot_product
        || matches_memory_roundtrip
        || matches_fibonacci
        || matches_matmul_2x2
        || matches_single_neuron
        || matches_gemma_block_v1
        || matches_gemma_block_v2
        || matches_gemma_block_v3
        || matches_gemma_block_v4
        || matches_decoding_step_v1
        || matches_decoding_step_v2
    {
        return Ok(());
    }

    Err(VmError::UnsupportedProof(
        "S-two Phase 5 currently proves only the shipped arithmetic fixtures `programs/addition.tvm`, `programs/counter.tvm`, `programs/memory_roundtrip.tvm`, `programs/multiply.tvm`, `programs/dot_product.tvm`, `programs/fibonacci.tvm`, `programs/matmul_2x2.tvm`, `programs/single_neuron.tvm`, `programs/gemma_block_v1.tvm`, `programs/gemma_block_v2.tvm`, `programs/gemma_block_v3.tvm`, `programs/gemma_block_v4.tvm`, the `decoding_step_v1` family, and the parameterized `decoding_step_v2` family; broader arithmetic-subset AIR coverage remains internal"
            .to_string(),
    ))
}

fn matches_gemma_block_v1(program: &Program) -> bool {
    program.memory_size() == 15
        && program.initial_memory() == [1, 1, 2, 0, 0, 2, 2, -4, 0, 2, 0, 0, 0, 0, 0]
        && program.instructions()
            == [
                Instruction::Load(0),
                Instruction::MulMemory(2),
                Instruction::Store(10),
                Instruction::Load(1),
                Instruction::MulMemory(3),
                Instruction::AddMemory(10),
                Instruction::Store(10),
                Instruction::Load(0),
                Instruction::MulMemory(4),
                Instruction::Store(11),
                Instruction::Load(1),
                Instruction::MulMemory(5),
                Instruction::AddMemory(11),
                Instruction::Store(11),
                Instruction::Load(10),
                Instruction::MulMemory(6),
                Instruction::Store(12),
                Instruction::Load(11),
                Instruction::MulMemory(9),
                Instruction::AddMemory(12),
                Instruction::Store(12),
                Instruction::Load(12),
                Instruction::AddMemory(7),
                Instruction::Store(8),
                Instruction::Load(8),
                Instruction::MulMemory(8),
                Instruction::Store(13),
                Instruction::LoadImmediate(64),
                Instruction::Store(14),
                Instruction::Load(13),
                Instruction::Halt,
            ]
}

fn matches_gemma_block_v2(program: &Program) -> bool {
    program.memory_size() == 15
        && program.initial_memory() == [1, 1, 2, 0, 0, 2, 2, -4, 0, 2, 0, 0, 0, 0, 0]
        && program.instructions()
            == [
                Instruction::Load(0),
                Instruction::MulMemory(2),
                Instruction::Store(10),
                Instruction::Load(1),
                Instruction::MulMemory(3),
                Instruction::AddMemory(10),
                Instruction::Store(10),
                Instruction::Load(0),
                Instruction::MulMemory(4),
                Instruction::Store(11),
                Instruction::Load(1),
                Instruction::MulMemory(5),
                Instruction::AddMemory(11),
                Instruction::Store(11),
                Instruction::Load(10),
                Instruction::MulMemory(6),
                Instruction::Store(12),
                Instruction::Load(11),
                Instruction::MulMemory(9),
                Instruction::AddMemory(12),
                Instruction::Store(12),
                Instruction::Load(12),
                Instruction::AddMemory(7),
                Instruction::Store(8),
                Instruction::Load(8),
                Instruction::MulMemory(8),
                Instruction::Store(13),
                Instruction::LoadImmediate(64),
                Instruction::Store(14),
                Instruction::Load(13),
                Instruction::Store(13),
                Instruction::Load(13),
                Instruction::Halt,
            ]
}

fn matches_gemma_block_v3(program: &Program) -> bool {
    program.memory_size() == 17
        && program.initial_memory() == [1, 1, 2, 0, 0, 2, 2, -4, 0, 2, 0, 0, 0, 0, 0, 0, 0]
        && program.instructions()
            == [
                Instruction::Load(0),
                Instruction::MulMemory(2),
                Instruction::Store(10),
                Instruction::Load(1),
                Instruction::MulMemory(3),
                Instruction::AddMemory(10),
                Instruction::Store(10),
                Instruction::Load(0),
                Instruction::MulMemory(4),
                Instruction::Store(11),
                Instruction::Load(1),
                Instruction::MulMemory(5),
                Instruction::AddMemory(11),
                Instruction::Store(11),
                Instruction::Load(10),
                Instruction::MulMemory(6),
                Instruction::Store(12),
                Instruction::Load(11),
                Instruction::MulMemory(9),
                Instruction::AddMemory(12),
                Instruction::Store(12),
                Instruction::Load(12),
                Instruction::AddMemory(7),
                Instruction::Store(8),
                Instruction::Load(8),
                Instruction::MulMemory(8),
                Instruction::Store(13),
                Instruction::LoadImmediate(64),
                Instruction::Store(14),
                Instruction::LoadImmediate(1),
                Instruction::Store(15),
                Instruction::LoadImmediate(1),
                Instruction::Store(16),
                Instruction::Load(13),
                Instruction::Store(13),
                Instruction::Load(13),
                Instruction::Halt,
            ]
}

fn stwo_backend_version_for_program(program: &Program) -> &str {
    if matches_decoding_step_v2(program) {
        super::STWO_BACKEND_VERSION_PHASE12
    } else if matches_decoding_step_v1(program) {
        STWO_BACKEND_VERSION_PHASE11
    } else {
        STWO_BACKEND_VERSION_PHASE5
    }
}

fn shared_program_label(program: &Program) -> &str {
    if matches_decoding_step_v2(program) {
        "decoding_step_v2"
    } else if matches_decoding_step_v1(program) {
        "decoding_step_v1"
    } else {
        "gemma_block_v4"
    }
}

fn shared_normalization_scope(program: &Program) -> &str {
    if matches_decoding_step_v2(program) {
        DECODING_STEP_V2_SHARED_NORMALIZATION_SCOPE
    } else if matches_decoding_step_v1(program) {
        DECODING_STEP_V1_SHARED_NORMALIZATION_SCOPE
    } else {
        GEMMA_BLOCK_V4_SHARED_NORMALIZATION_SCOPE
    }
}

fn shared_activation_scope(program: &Program) -> &str {
    if matches_decoding_step_v2(program) {
        DECODING_STEP_V2_SHARED_ACTIVATION_SCOPE
    } else if matches_decoding_step_v1(program) {
        DECODING_STEP_V1_SHARED_ACTIVATION_SCOPE
    } else {
        GEMMA_BLOCK_V4_SHARED_ACTIVATION_SCOPE
    }
}

fn shared_normalization_label(program: &Program) -> &str {
    if matches_decoding_step_v2(program) {
        "decoding_step_v2 shared normalization"
    } else if matches_decoding_step_v1(program) {
        "decoding_step_v1 shared normalization"
    } else {
        "gemma_block_v4 shared normalization"
    }
}

fn shared_activation_label(program: &Program) -> &str {
    if matches_decoding_step_v2(program) {
        "decoding_step_v2 shared activation"
    } else if matches_decoding_step_v1(program) {
        "decoding_step_v1 shared activation"
    } else {
        "gemma_block_v4 shared activation"
    }
}

fn matches_decoding_step_v1(program: &Program) -> bool {
    matches_decoding_step_v1_family(program)
}

fn matches_decoding_step_v2(program: &Program) -> bool {
    matches_decoding_step_v2_family(program)
}

fn matches_gemma_block_v4(program: &Program) -> bool {
    program.memory_size() == 21
        && program.initial_memory()
            == [
                1, 1, 2, 0, 0, 2, 2, -4, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]
        && program.instructions()
            == [
                Instruction::Load(0),
                Instruction::MulMemory(2),
                Instruction::Store(10),
                Instruction::Load(1),
                Instruction::MulMemory(3),
                Instruction::AddMemory(10),
                Instruction::Store(10),
                Instruction::Load(0),
                Instruction::MulMemory(4),
                Instruction::Store(11),
                Instruction::Load(1),
                Instruction::MulMemory(5),
                Instruction::AddMemory(11),
                Instruction::Store(11),
                Instruction::Load(10),
                Instruction::MulMemory(6),
                Instruction::Store(12),
                Instruction::Load(11),
                Instruction::MulMemory(9),
                Instruction::AddMemory(12),
                Instruction::Store(12),
                Instruction::Load(12),
                Instruction::AddMemory(7),
                Instruction::Store(8),
                Instruction::Load(8),
                Instruction::MulMemory(8),
                Instruction::Store(13),
                Instruction::LoadImmediate(64),
                Instruction::Store(14),
                Instruction::LoadImmediate(1),
                Instruction::Store(15),
                Instruction::LoadImmediate(1),
                Instruction::Store(16),
                Instruction::LoadImmediate(4),
                Instruction::Store(17),
                Instruction::LoadImmediate(128),
                Instruction::Store(18),
                Instruction::LoadImmediate(0),
                Instruction::Store(19),
                Instruction::LoadImmediate(1),
                Instruction::Store(20),
                Instruction::Load(13),
                Instruction::Halt,
            ]
}

fn reconstruct_state_trace_from_claim(
    claim: &VanillaStarkExecutionClaim,
) -> Result<Vec<MachineState>> {
    let mut runtime = NativeInterpreter::new(
        claim.program.clone(),
        claim.attention_mode.clone(),
        claim.steps,
    );
    let result = runtime.run()?;
    if !result.halted {
        return Err(VmError::UnsupportedProof(format!(
            "S-two arithmetic subset verification expected halted execution after {} steps",
            claim.steps
        )));
    }
    if result.steps != claim.steps {
        return Err(VmError::InvalidConfig(format!(
            "S-two arithmetic subset verification re-executed {} steps, expected {}",
            result.steps, claim.steps
        )));
    }
    if result.final_state != claim.final_state {
        return Err(VmError::InvalidConfig(
            "S-two arithmetic subset verification re-executed final state does not match claim"
                .to_string(),
        ));
    }
    Ok(runtime.trace().to_vec())
}

#[derive(Clone)]
struct TraceBundle {
    log_size: u32,
    preprocessed_rows: Vec<PreprocessedRow>,
    preprocessed_trace: Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>>,
    base_trace: Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>>,
}

fn build_trace_bundle(program: &Program, states: &[MachineState]) -> Result<TraceBundle> {
    let real_rows = states.len().max(1);
    let row_count = real_rows.next_power_of_two();
    let log_size = row_count.ilog2();
    let preprocessed_rows = build_preprocessed_rows(program, states, row_count)?;
    let preprocessed_trace =
        preprocessed_trace(&preprocessed_rows, log_size, program.memory_size());
    let base_trace = base_trace(program, states, log_size, program.memory_size())?;
    Ok(TraceBundle {
        log_size,
        preprocessed_rows,
        preprocessed_trace,
        base_trace,
    })
}

fn build_preprocessed_rows(
    program: &Program,
    states: &[MachineState],
    row_count: usize,
) -> Result<Vec<PreprocessedRow>> {
    let last_state = states.last().expect("non-empty state trace");
    let mut rows = Vec::with_capacity(row_count);
    for row_index in 0..row_count {
        let row = if row_index + 1 < states.len() {
            let state = &states[row_index];
            let instruction = program.instruction_at(state.pc)?;
            PreprocessedRow::from_instruction(
                instruction,
                program.memory_size(),
                row_index == 0,
                row_index + 1 == row_count,
            )
        } else {
            PreprocessedRow::synthetic_halt(
                program.memory_size(),
                row_index == 0,
                row_index + 1 == row_count,
            )
        };
        rows.push(row);
    }
    debug_assert!(last_state.halted);
    Ok(rows)
}

fn preprocessed_trace(
    rows: &[PreprocessedRow],
    log_size: u32,
    memory_size: usize,
) -> Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>> {
    let row_count = 1usize << log_size;
    let domain = CanonicCoset::new(log_size).circle_domain();
    let mut columns = (0..preprocessed_column_ids(memory_size).len())
        .map(|_| Col::<CpuBackend, BaseField>::zeros(row_count))
        .collect::<Vec<_>>();

    for (row_index, row) in rows.iter().enumerate() {
        let mut values = row.column_values();
        values.extend(row.address_flags.iter().map(|value| base_u32(*value)));
        values.extend(row.store_address_flags.iter().map(|value| base_u32(*value)));
        for (column_index, value) in values.into_iter().enumerate() {
            columns[column_index].set(row_index, value);
        }
    }

    columns
        .into_iter()
        .map(|column| {
            CircleEvaluation::<CpuBackend, BaseField, NaturalOrder>::new(domain, column)
                .bit_reverse()
        })
        .collect()
}

fn base_trace(
    program: &Program,
    states: &[MachineState],
    log_size: u32,
    memory_size: usize,
) -> Result<Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>>> {
    let row_count = 1usize << log_size;
    let layout = TraceLayout::new(memory_size);
    let domain = CanonicCoset::new(log_size).circle_domain();
    let mut columns = (0..layout.total_width())
        .map(|_| Col::<CpuBackend, BaseField>::zeros(row_count))
        .collect::<Vec<_>>();

    let last_state = states.last().expect("non-empty state trace");
    for row_index in 0..row_count {
        let current = if row_index + 1 < states.len() {
            &states[row_index]
        } else {
            last_state
        };
        let next = if row_index + 1 < states.len() {
            &states[row_index + 1]
        } else {
            last_state
        };
        let auxiliary = auxiliary_values(program, current)?;
        let current_row = state_values(current);
        let next_row = state_values(next);
        for (column_index, value) in current_row.into_iter().enumerate() {
            columns[column_index].set(row_index, value);
        }
        for (offset, value) in next_row.into_iter().enumerate() {
            columns[layout.next_prefix() + offset].set(row_index, value);
        }
        columns[layout.loaded_memory()].set(row_index, base_i16(auxiliary.loaded_memory));
        columns[layout.mul_result()].set(row_index, base_i16(auxiliary.mul_result));
        columns[layout.next_pc_active()]
            .set(row_index, base_u32(u32::from(auxiliary.next_pc_active)));
        columns[layout.next_acc_active()].set(row_index, base_i16(auxiliary.next_acc_active));
        for (index, value) in auxiliary.next_memory_active.into_iter().enumerate() {
            columns[layout.next_memory_active(index)].set(row_index, base_i16(value));
        }
    }

    Ok(columns
        .into_iter()
        .map(|column| {
            CircleEvaluation::<CpuBackend, BaseField, NaturalOrder>::new(domain, column)
                .bit_reverse()
        })
        .collect())
}

fn constrain_public_state<E: EvalAtRow>(
    eval: &mut E,
    layout: &TraceLayout,
    _is_initial: bool,
    selector: E::F,
    state: &PublicState,
    current_pc: &E::F,
    current_acc: &E::F,
    current_sp: &E::F,
    current_zero: &E::F,
    current_carry: &E::F,
    current_halted: &E::F,
    current_memory: &[E::F],
) {
    eval.add_constraint(selector.clone() * (current_pc.clone() - base_u8_field::<E>(state.pc)));
    eval.add_constraint(selector.clone() * (current_acc.clone() - base_i16_field::<E>(state.acc)));
    eval.add_constraint(selector.clone() * (current_sp.clone() - base_u8_field::<E>(state.sp)));
    eval.add_constraint(
        selector.clone() * (current_zero.clone() - bool_field::<E>(state.zero_flag)),
    );
    eval.add_constraint(
        selector.clone() * (current_carry.clone() - bool_field::<E>(state.carry_flag)),
    );
    eval.add_constraint(
        selector.clone() * (current_halted.clone() - bool_field::<E>(state.halted)),
    );
    for index in 0..layout.memory_size {
        eval.add_constraint(
            selector.clone()
                * (current_memory[index].clone() - base_i16_field::<E>(state.memory[index])),
        );
    }
}

fn state_values(state: &MachineState) -> Vec<BaseField> {
    let mut values = Vec::with_capacity(7 + state.memory.len());
    values.push(base_u32(u32::from(state.pc)));
    values.push(base_i16(state.acc));
    values.push(base_u32(u32::from(state.sp)));
    values.push(bool_base(state.zero_flag));
    values.push(bool_base(state.carry_flag));
    values.push(bool_base(state.halted));
    values.push(acc_inverse_base(state.acc));
    values.extend(state.memory.iter().copied().map(base_i16));
    values
}

fn preprocessed_column_ids(memory_size: usize) -> Vec<PreProcessedColumnId> {
    let mut ids: Vec<_> = OPCODE_COLUMN_NAMES
        .iter()
        .map(|name| column_id(name))
        .collect();
    ids.push(column_id(IMMEDIATE_COLUMN));
    ids.push(column_id(JUMP_TARGET_COLUMN));
    ids.push(column_id(FIRST_ROW_COLUMN));
    ids.push(column_id(LAST_ROW_COLUMN));
    ids.extend((0..memory_size).map(|index| column_id(&address_column_name(index))));
    ids.extend((0..memory_size).map(|index| column_id(&store_address_column_name(index))));
    ids
}

fn address_column_name(index: usize) -> String {
    format!("phase5/arithmetic/address/{index}")
}

fn store_address_column_name(index: usize) -> String {
    format!("phase5/arithmetic/store_address/{index}")
}

fn column_id(id: &str) -> PreProcessedColumnId {
    PreProcessedColumnId { id: id.to_string() }
}

impl PublicState {
    fn from_initial_memory(initial_memory: &[i16]) -> Self {
        let initial = MachineState::with_memory(initial_memory.to_vec());
        Self::from_machine_state(initial)
    }

    fn from_machine_state(state: MachineState) -> Self {
        Self {
            pc: state.pc,
            acc: state.acc,
            sp: state.sp,
            zero_flag: state.zero_flag,
            carry_flag: state.carry_flag,
            halted: state.halted,
            memory: state.memory,
        }
    }
}

impl PreprocessedRow {
    fn from_instruction(
        instruction: Instruction,
        memory_size: usize,
        is_first_row: bool,
        is_last_row: bool,
    ) -> Self {
        let mut row = Self::synthetic_halt(memory_size, is_first_row, is_last_row);
        row.opcode_flags = opcode_flags(instruction);
        row.immediate = match instruction {
            Instruction::LoadImmediate(value) | Instruction::AddImmediate(value) => value,
            _ => 0,
        };
        row.jump_target = match instruction {
            Instruction::Jump(target) | Instruction::JumpIfZero(target) => target,
            _ => 0,
        };
        let address = match instruction {
            Instruction::Load(address)
            | Instruction::Store(address)
            | Instruction::AddMemory(address)
            | Instruction::SubMemory(address)
            | Instruction::MulMemory(address) => Some(address),
            _ => None,
        };
        if let Some(address) = address {
            row.address_flags[address as usize] = 1;
        }
        if let Instruction::Store(address) = instruction {
            row.store_address_flags[address as usize] = 1;
        }
        row
    }

    fn synthetic_halt(memory_size: usize, is_first_row: bool, is_last_row: bool) -> Self {
        Self {
            opcode_flags: opcode_flags(Instruction::Halt),
            immediate: 0,
            jump_target: 0,
            address_flags: vec![0; memory_size],
            store_address_flags: vec![0; memory_size],
            is_first_row,
            is_last_row,
        }
    }

    fn column_values(&self) -> Vec<BaseField> {
        let mut values = self
            .opcode_flags
            .iter()
            .map(|value| base_u32(*value))
            .collect::<Vec<_>>();
        values.push(base_i16(self.immediate));
        values.push(base_u32(u32::from(self.jump_target)));
        values.push(bool_base(self.is_first_row));
        values.push(bool_base(self.is_last_row));
        values
    }
}

fn auxiliary_values(program: &Program, state: &MachineState) -> Result<AuxiliaryState> {
    let instruction = program.instruction_at(state.pc)?;
    let loaded_memory = match instruction {
        Instruction::Load(address)
        | Instruction::Store(address)
        | Instruction::AddMemory(address)
        | Instruction::SubMemory(address)
        | Instruction::MulMemory(address) => state.memory[address as usize],
        _ => 0,
    };
    let next_pc_active = match instruction {
        Instruction::Jump(target) => target,
        Instruction::JumpIfZero(target) => {
            if state.zero_flag {
                target
            } else {
                state.pc.saturating_add(1)
            }
        }
        Instruction::Halt => state.pc,
        _ => state.pc.saturating_add(1),
    };
    let mul_result = match instruction {
        Instruction::MulMemory(_) => state.acc.wrapping_mul(loaded_memory),
        _ => 0,
    };
    let next_acc_active = match instruction {
        Instruction::LoadImmediate(value) => value,
        Instruction::Load(_) => loaded_memory,
        Instruction::AddImmediate(value) => state.acc.wrapping_add(value),
        Instruction::AddMemory(_) => state.acc.wrapping_add(loaded_memory),
        Instruction::SubMemory(_) => state.acc.wrapping_sub(loaded_memory),
        Instruction::MulMemory(_) => mul_result,
        _ => state.acc,
    };
    let mut next_memory_active = state.memory.clone();
    if let Instruction::Store(address) = instruction {
        next_memory_active[address as usize] = state.acc;
    }
    Ok(AuxiliaryState {
        loaded_memory,
        mul_result,
        next_pc_active,
        next_acc_active,
        next_memory_active,
    })
}

fn opcode_flags(instruction: Instruction) -> [u32; 11] {
    let mut flags = [0u32; 11];
    let index = match instruction {
        Instruction::Nop => 0,
        Instruction::LoadImmediate(_) => 1,
        Instruction::Load(_) => 2,
        Instruction::Store(_) => 3,
        Instruction::AddImmediate(_) => 4,
        Instruction::AddMemory(_) => 5,
        Instruction::SubMemory(_) => 6,
        Instruction::MulMemory(_) => 7,
        Instruction::Jump(_) => 8,
        Instruction::JumpIfZero(_) => 9,
        Instruction::Halt => 10,
        other => panic!("instruction `{other}` is outside Phase 5 arithmetic subset"),
    };
    flags[index] = 1;
    flags
}

fn acc_inverse_base(value: i16) -> BaseField {
    if value == 0 {
        BaseField::zero()
    } else {
        base_i16(value).inverse()
    }
}

fn base_i16(value: i16) -> BaseField {
    if value >= 0 {
        BaseField::from_u32_unchecked(value as u32)
    } else {
        BaseField::from_u32_unchecked((M31_MODULUS as i64 + value as i64) as u32)
    }
}

fn base_u32(value: u32) -> BaseField {
    BaseField::from_u32_unchecked(value)
}

fn bool_base(value: bool) -> BaseField {
    base_u32(u32::from(value))
}

fn base_u8_field<E: EvalAtRow>(value: u8) -> E::F {
    E::F::from(base_u32(u32::from(value)))
}

fn base_i16_field<E: EvalAtRow>(value: i16) -> E::F {
    E::F::from(base_i16(value))
}

fn bool_field<E: EvalAtRow>(value: bool) -> E::F {
    E::F::from(bool_base(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stwo_backend::decoding::{
        decoding_step_v2_program_with_initial_memory, phase12_default_decoding_layout,
        phase12_demo_initial_memories,
    };
    use crate::{production_v1_stark_options, prove_execution_stark_with_backend_and_options};
    use crate::{ProgramCompiler, TransformerVmConfig};
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use stwo::core::pcs::utils::TreeVec;
    use stwo::prover::backend::Column;
    use stwo_constraint_framework::{assert_constraints_on_polys, assert_constraints_on_trace};

    fn compile_program(path: &str) -> Program {
        let source = std::fs::read_to_string(path).expect("program source");
        ProgramCompiler
            .compile_source(&source, TransformerVmConfig::default())
            .expect("compile")
            .program()
            .clone()
    }

    fn assert_trace_satisfies_constraints_for_program(program: Program) {
        let mut runtime =
            NativeInterpreter::new(program.clone(), Attention2DMode::AverageHard, 256);
        let result = runtime.run().expect("run program");
        assert!(result.halted);

        let states = runtime.trace().to_vec();
        let trace = build_trace_bundle(&program, &states).expect("trace bundle");
        let final_state = result.final_state.clone();
        let eval_state = Phase5ArithmeticSubsetEval {
            log_size: trace.log_size,
            memory_size: program.memory_size(),
            initial_state: PublicState::from_initial_memory(program.initial_memory()),
            final_state: PublicState::from_machine_state(final_state.clone()),
        };
        let preprocessed = trace
            .preprocessed_trace
            .iter()
            .map(|column| column.values.to_cpu())
            .collect::<Vec<_>>();
        let base = trace
            .base_trace
            .iter()
            .map(|column| column.values.to_cpu())
            .collect::<Vec<_>>();
        let tree = TreeVec(vec![
            preprocessed.iter().collect::<Vec<_>>(),
            base.iter().collect::<Vec<_>>(),
        ]);

        assert_constraints_on_trace(
            &tree,
            trace.log_size,
            |eval| {
                let _ = eval_state.evaluate(eval);
            },
            SecureField::zero(),
        );
    }

    fn assert_trace_polys_satisfy_constraints_for_program(program: Program) {
        let mut runtime =
            NativeInterpreter::new(program.clone(), Attention2DMode::AverageHard, 256);
        let result = runtime.run().expect("run program");
        assert!(result.halted);

        let states = runtime.trace().to_vec();
        let trace = build_trace_bundle(&program, &states).expect("trace bundle");
        let final_state = result.final_state.clone();
        let eval_state = Phase5ArithmeticSubsetEval {
            log_size: trace.log_size,
            memory_size: program.memory_size(),
            initial_state: PublicState::from_initial_memory(program.initial_memory()),
            final_state: PublicState::from_machine_state(final_state.clone()),
        };
        let trace_polys = TreeVec(vec![
            trace
                .preprocessed_trace
                .iter()
                .cloned()
                .map(|c| c.interpolate())
                .collect::<Vec<_>>(),
            trace
                .base_trace
                .iter()
                .cloned()
                .map(|c| c.interpolate())
                .collect::<Vec<_>>(),
        ]);

        assert_constraints_on_polys(
            &trace_polys,
            CanonicCoset::new(trace.log_size),
            |eval| {
                let _ = eval_state.evaluate(eval);
            },
            SecureField::zero(),
        );
    }

    #[test]
    fn phase5_subset_accepts_fixture_matrix_programs() {
        for path in [
            "programs/addition.tvm",
            "programs/counter.tvm",
            "programs/memory_roundtrip.tvm",
            "programs/multiply.tvm",
            "programs/dot_product.tvm",
            "programs/fibonacci.tvm",
            "programs/gemma_block_v1.tvm",
            "programs/gemma_block_v2.tvm",
            "programs/gemma_block_v3.tvm",
            "programs/gemma_block_v4.tvm",
            "programs/matmul_2x2.tvm",
            "programs/single_neuron.tvm",
        ] {
            let program = compile_program(path);
            validate_phase5_proven_fixture(&program).unwrap_or_else(|error| {
                panic!("{path} should be accepted by the Phase 5 fixture allow-list: {error}")
            });
        }
    }

    #[test]
    fn phase12_subset_accepts_parameterized_decoding_family() {
        let layout = phase12_default_decoding_layout();
        let memory = phase12_demo_initial_memories(&layout)
            .expect("memories")
            .remove(0);
        let program =
            decoding_step_v2_program_with_initial_memory(&layout, memory).expect("program");
        validate_phase5_proven_fixture(&program).expect("phase12 family allow-list");
    }

    #[test]
    fn phase5_opcode_flags_cover_subset() {
        assert_eq!(opcode_flags(Instruction::LoadImmediate(1))[1], 1);
        assert_eq!(opcode_flags(Instruction::JumpIfZero(3))[9], 1);
        assert_eq!(opcode_flags(Instruction::Halt)[10], 1);
    }

    #[test]
    fn phase5_trace_bundle_pads_to_power_of_two() {
        let states = vec![
            MachineState::with_memory(vec![0, 0, 0, 0]),
            MachineState {
                pc: 1,
                acc: 5,
                sp: 4,
                zero_flag: false,
                carry_flag: false,
                halted: false,
                memory: vec![0, 0, 0, 0],
            },
            MachineState {
                pc: 2,
                acc: 8,
                sp: 4,
                zero_flag: false,
                carry_flag: false,
                halted: true,
                memory: vec![0, 0, 0, 0],
            },
        ];
        let trace = build_trace_bundle(&compile_program("programs/addition.tvm"), &states).unwrap();
        assert_eq!(trace.log_size, 2);
        assert_eq!(trace.base_trace.len(), 30);
    }

    fn assert_program_trace_satisfies_constraints(path: &str) {
        assert_trace_satisfies_constraints_for_program(compile_program(path));
    }

    #[test]
    fn phase5_dot_product_trace_satisfies_constraints() {
        assert_program_trace_satisfies_constraints("programs/dot_product.tvm");
    }

    #[test]
    fn phase5_counter_trace_satisfies_constraints() {
        assert_program_trace_satisfies_constraints("programs/counter.tvm");
    }

    #[test]
    fn phase5_multiply_trace_satisfies_constraints() {
        assert_program_trace_satisfies_constraints("programs/multiply.tvm");
    }

    #[test]
    fn phase5_memory_roundtrip_trace_satisfies_constraints() {
        assert_program_trace_satisfies_constraints("programs/memory_roundtrip.tvm");
    }

    #[test]
    fn phase5_fibonacci_trace_satisfies_constraints() {
        assert_program_trace_satisfies_constraints("programs/fibonacci.tvm");
    }

    #[test]
    fn phase5_gemma_block_v1_trace_satisfies_constraints() {
        assert_program_trace_satisfies_constraints("programs/gemma_block_v1.tvm");
    }

    #[test]
    fn phase5_gemma_block_v2_trace_satisfies_constraints() {
        assert_program_trace_satisfies_constraints("programs/gemma_block_v2.tvm");
    }

    #[test]
    fn phase5_gemma_block_v3_trace_satisfies_constraints() {
        assert_program_trace_satisfies_constraints("programs/gemma_block_v3.tvm");
    }

    #[test]
    fn phase5_gemma_block_v4_trace_satisfies_constraints() {
        assert_program_trace_satisfies_constraints("programs/gemma_block_v4.tvm");
    }

    #[test]
    fn phase11_decoding_step_v1_trace_satisfies_constraints() {
        assert_program_trace_satisfies_constraints("programs/decoding_step_v1.tvm");
    }

    #[test]
    fn phase12_decoding_step_v2_trace_satisfies_constraints() {
        let layout = phase12_default_decoding_layout();
        for (step_index, memory) in phase12_demo_initial_memories(&layout)
            .expect("memories")
            .into_iter()
            .enumerate()
        {
            let debug_memory = memory.clone();
            let program =
                decoding_step_v2_program_with_initial_memory(&layout, memory).expect("program");
            catch_unwind(AssertUnwindSafe(|| {
                assert_trace_satisfies_constraints_for_program(program.clone())
            }))
            .unwrap_or_else(|payload| {
                panic!(
                    "step {step_index} failed trace constraints: {}; initial_memory={debug_memory:?}",
                    panic_payload_to_string(payload)
                )
            });
            assert!(
                matches_decoding_step_v2_family(&program),
                "step {step_index} is not recognized as decoding_step_v2-family"
            );
        }
    }

    #[test]
    fn phase5_matmul_2x2_trace_satisfies_constraints() {
        assert_program_trace_satisfies_constraints("programs/matmul_2x2.tvm");
    }

    #[test]
    fn phase5_single_neuron_trace_satisfies_constraints() {
        assert_program_trace_satisfies_constraints("programs/single_neuron.tvm");
    }

    fn assert_program_trace_polys_satisfy_constraints(path: &str) {
        assert_trace_polys_satisfy_constraints_for_program(compile_program(path));
    }

    fn panic_payload_to_string(payload: Box<dyn std::any::Any + Send>) -> String {
        if let Some(message) = payload.downcast_ref::<&str>() {
            (*message).to_string()
        } else if let Some(message) = payload.downcast_ref::<String>() {
            message.clone()
        } else {
            "non-string panic payload".to_string()
        }
    }

    #[test]
    fn phase5_dot_product_trace_polys_satisfy_constraints() {
        assert_program_trace_polys_satisfy_constraints("programs/dot_product.tvm");
    }

    #[test]
    fn phase5_counter_trace_polys_satisfy_constraints() {
        assert_program_trace_polys_satisfy_constraints("programs/counter.tvm");
    }

    #[test]
    fn phase5_multiply_trace_polys_satisfy_constraints() {
        assert_program_trace_polys_satisfy_constraints("programs/multiply.tvm");
    }

    #[test]
    fn phase5_memory_roundtrip_trace_polys_satisfy_constraints() {
        assert_program_trace_polys_satisfy_constraints("programs/memory_roundtrip.tvm");
    }

    #[test]
    fn phase5_fibonacci_trace_polys_satisfy_constraints() {
        assert_program_trace_polys_satisfy_constraints("programs/fibonacci.tvm");
    }

    #[test]
    fn phase5_gemma_block_v1_trace_polys_satisfy_constraints() {
        assert_program_trace_polys_satisfy_constraints("programs/gemma_block_v1.tvm");
    }

    #[test]
    fn phase5_gemma_block_v2_trace_polys_satisfy_constraints() {
        assert_program_trace_polys_satisfy_constraints("programs/gemma_block_v2.tvm");
    }

    #[test]
    fn phase5_gemma_block_v3_trace_polys_satisfy_constraints() {
        assert_program_trace_polys_satisfy_constraints("programs/gemma_block_v3.tvm");
    }

    #[test]
    fn phase5_gemma_block_v4_trace_polys_satisfy_constraints() {
        assert_program_trace_polys_satisfy_constraints("programs/gemma_block_v4.tvm");
    }

    #[test]
    fn phase11_decoding_step_v1_trace_polys_satisfy_constraints() {
        assert_program_trace_polys_satisfy_constraints("programs/decoding_step_v1.tvm");
    }

    #[test]
    fn phase12_decoding_step_v2_trace_polys_satisfy_constraints() {
        let layout = phase12_default_decoding_layout();
        for (step_index, memory) in phase12_demo_initial_memories(&layout)
            .expect("memories")
            .into_iter()
            .enumerate()
        {
            let debug_memory = memory.clone();
            let program =
                decoding_step_v2_program_with_initial_memory(&layout, memory).expect("program");
            catch_unwind(AssertUnwindSafe(|| {
                assert_trace_polys_satisfy_constraints_for_program(program.clone())
            }))
            .unwrap_or_else(|payload| {
                panic!(
                    "step {step_index} failed trace polynomial constraints: {}; initial_memory={debug_memory:?}",
                    panic_payload_to_string(payload)
                )
            });
            assert!(
                matches_decoding_step_v2_family(&program),
                "step {step_index} is not recognized as decoding_step_v2-family"
            );
        }
    }

    #[test]
    fn phase12_verify_phase5_rejects_oversized_decoding_payload_before_deserialization() {
        let layout = phase12_default_decoding_layout();
        let initial_memory = phase12_demo_initial_memories(&layout)
            .expect("memories")
            .into_iter()
            .next()
            .expect("seed memory");
        let program =
            decoding_step_v2_program_with_initial_memory(&layout, initial_memory).expect("program");
        let model = ProgramCompiler
            .compile_program(
                program,
                TransformerVmConfig {
                    num_layers: 1,
                    attention_mode: Attention2DMode::AverageHard,
                    ..TransformerVmConfig::default()
                },
            )
            .expect("compile");
        let mut proof = prove_execution_stark_with_backend_and_options(
            &model,
            128,
            StarkProofBackend::Stwo,
            production_v1_stark_options(),
        )
        .expect("real stwo proof");
        proof.proof = vec![0; MAX_DECODING_PROOF_PAYLOAD_BYTES + 1];

        let err = verify_phase5_arithmetic_subset(&proof).expect_err("oversized payload");
        assert!(err.to_string().contains("exceeding the limit"));
    }

    #[test]
    fn phase5_matmul_2x2_trace_polys_satisfy_constraints() {
        assert_program_trace_polys_satisfy_constraints("programs/matmul_2x2.tvm");
    }

    #[test]
    fn phase5_single_neuron_trace_polys_satisfy_constraints() {
        assert_program_trace_polys_satisfy_constraints("programs/single_neuron.tvm");
    }
}
