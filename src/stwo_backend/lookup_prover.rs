use ark_ff::Zero;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use stwo::core::air::Component;
use stwo::core::channel::{Blake2sM31Channel, Channel};
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sM31MerkleChannel, Blake2sM31MerkleHasher};
use stwo::core::verifier::verify;
use stwo::core::ColumnVec;
use stwo::prover::backend::simd::column::BaseColumn;
use stwo::prover::backend::simd::m31::LOG_N_LANES;
use stwo::prover::backend::simd::qm31::PackedSecureField;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::poly::{BitReversedOrder, NaturalOrder};
use stwo::prover::{prove, CommitmentSchemeProver};
use stwo_constraint_framework::{
    relation, EvalAtRow, FrameworkComponent, FrameworkEval, LogupTraceGenerator, Relation,
    RelationEntry, TraceLocationAllocator,
};

use super::lookup_component::{
    phase3_binary_step_lookup_component, phase3_lookup_table_rows, Phase3BinaryStepLookupElements,
    Phase3LookupTableRow,
};
use crate::error::{Result, VmError};
use crate::proof::StarkProofBackend;

pub const STWO_LOOKUP_PROOF_VERSION_PHASE3: &str = "stwo-phase3-binary-step-lookup-demo-v1";
pub const STWO_LOOKUP_STATEMENT_VERSION_PHASE3: &str = "stwo-binary-step-lookup-demo-v1";
pub const STWO_LOOKUP_SEMANTIC_SCOPE_PHASE3: &str =
    "stwo_binary_step_activation_lookup_demo_with_canonical_table";
pub const STWO_SHARED_LOOKUP_PROOF_VERSION_PHASE10: &str =
    "stwo-phase10-shared-binary-step-lookup-v1";
pub const STWO_SHARED_LOOKUP_STATEMENT_VERSION_PHASE10: &str = "stwo-shared-binary-step-lookup-v1";
pub const STWO_SHARED_LOOKUP_SEMANTIC_SCOPE_PHASE10: &str =
    "stwo_shared_binary_step_activation_lookup_with_canonical_table";

relation!(Phase10SharedBinaryStepLookupRelation, 2);
type Phase10SharedBinaryStepLookupElements = Phase10SharedBinaryStepLookupRelation;

#[derive(Debug, Clone)]
struct Phase10SharedBinaryStepLookupEval {
    log_size: u32,
    lookup_elements: Phase10SharedBinaryStepLookupElements,
}

impl FrameworkEval for Phase10SharedBinaryStepLookupEval {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size.saturating_add(1)
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let claimed_input = eval.next_trace_mask();
        let claimed_output = eval.next_trace_mask();
        let selector = eval.next_trace_mask();
        let table_input = eval.get_preprocessed_column(column_id("phase10/shared/table_input"));
        let table_output = eval.get_preprocessed_column(column_id("phase10/shared/table_output"));
        let one = E::F::from(BaseField::from(1u32));

        eval.add_constraint(selector.clone() * (selector.clone() - one));
        eval.add_constraint(selector.clone() * (claimed_input.clone() - table_input.clone()));
        eval.add_constraint(selector.clone() * (claimed_output.clone() - table_output.clone()));
        eval.add_to_relation(RelationEntry::new(
            &self.lookup_elements,
            selector.clone().into(),
            &[claimed_input, claimed_output],
        ));
        eval.add_to_relation(RelationEntry::new(
            &self.lookup_elements,
            (-selector).into(),
            &[table_input, table_output],
        ));
        eval.finalize_logup_in_pairs();
        eval
    }
}

#[derive(Serialize, Deserialize)]
struct Phase3LookupProofPayload {
    stark_proof: StarkProof<Blake2sM31MerkleHasher>,
    canonical_table_rows: Vec<Phase3LookupTableRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Phase3LookupProofEnvelope {
    pub proof_backend: StarkProofBackend,
    pub proof_backend_version: String,
    pub statement_version: String,
    pub semantic_scope: String,
    pub canonical_table_rows: Vec<Phase3LookupTableRow>,
    pub proof: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Phase10SharedLookupProofEnvelope {
    pub proof_backend: StarkProofBackend,
    pub proof_backend_version: String,
    pub statement_version: String,
    pub semantic_scope: String,
    pub canonical_table_rows: Vec<Phase3LookupTableRow>,
    pub claimed_rows: Vec<Phase3LookupTableRow>,
    pub proof: Vec<u8>,
}

pub fn prove_phase3_binary_step_lookup_demo_envelope() -> Result<Phase3LookupProofEnvelope> {
    let bundle = build_lookup_demo_bundle();
    Ok(Phase3LookupProofEnvelope {
        proof_backend: StarkProofBackend::Stwo,
        proof_backend_version: STWO_LOOKUP_PROOF_VERSION_PHASE3.to_string(),
        statement_version: STWO_LOOKUP_STATEMENT_VERSION_PHASE3.to_string(),
        semantic_scope: STWO_LOOKUP_SEMANTIC_SCOPE_PHASE3.to_string(),
        canonical_table_rows: bundle.table_rows.clone(),
        proof: prove_phase3_binary_step_lookup_demo()?,
    })
}

pub fn verify_phase3_binary_step_lookup_demo_envelope(
    envelope: &Phase3LookupProofEnvelope,
) -> Result<bool> {
    if envelope.proof_backend != StarkProofBackend::Stwo {
        return Err(VmError::InvalidConfig(format!(
            "binary-step lookup demo proof backend `{}` is not `stwo`",
            envelope.proof_backend
        )));
    }
    if envelope.proof_backend_version != STWO_LOOKUP_PROOF_VERSION_PHASE3 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported binary-step lookup demo proof backend version `{}` (expected `{}`)",
            envelope.proof_backend_version, STWO_LOOKUP_PROOF_VERSION_PHASE3
        )));
    }
    if envelope.statement_version != STWO_LOOKUP_STATEMENT_VERSION_PHASE3 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported binary-step lookup demo statement version `{}` (expected `{}`)",
            envelope.statement_version, STWO_LOOKUP_STATEMENT_VERSION_PHASE3
        )));
    }
    if envelope.semantic_scope != STWO_LOOKUP_SEMANTIC_SCOPE_PHASE3 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported binary-step lookup demo semantic scope `{}` (expected `{}`)",
            envelope.semantic_scope, STWO_LOOKUP_SEMANTIC_SCOPE_PHASE3
        )));
    }

    let bundle = build_lookup_demo_bundle();
    if envelope.canonical_table_rows != bundle.table_rows {
        return Err(VmError::UnsupportedProof(
            "binary-step lookup demo proof envelope does not match the canonical Phase 3 lookup table"
                .to_string(),
        ));
    }
    verify_phase3_binary_step_lookup_demo(&envelope.proof)
}

pub fn save_phase3_binary_step_lookup_proof(
    proof: &Phase3LookupProofEnvelope,
    path: &Path,
) -> Result<()> {
    let json = serde_json::to_string_pretty(proof)
        .map_err(|error| VmError::Serialization(error.to_string()))?;
    fs::write(path, json)?;
    Ok(())
}

pub fn load_phase3_binary_step_lookup_proof(path: &Path) -> Result<Phase3LookupProofEnvelope> {
    let json = fs::read_to_string(path)?;
    serde_json::from_str(&json).map_err(|error| VmError::Serialization(error.to_string()))
}

pub fn prove_phase10_shared_binary_step_lookup_envelope(
    claimed_rows: &[Phase3LookupTableRow],
) -> Result<Phase10SharedLookupProofEnvelope> {
    let bundle = build_shared_lookup_bundle(claimed_rows)?;
    Ok(Phase10SharedLookupProofEnvelope {
        proof_backend: StarkProofBackend::Stwo,
        proof_backend_version: STWO_SHARED_LOOKUP_PROOF_VERSION_PHASE10.to_string(),
        statement_version: STWO_SHARED_LOOKUP_STATEMENT_VERSION_PHASE10.to_string(),
        semantic_scope: STWO_SHARED_LOOKUP_SEMANTIC_SCOPE_PHASE10.to_string(),
        canonical_table_rows: bundle.canonical_table_rows.clone(),
        claimed_rows: bundle.claimed_rows.clone(),
        proof: prove_phase10_shared_binary_step_lookup(&bundle)?,
    })
}

pub fn verify_phase10_shared_binary_step_lookup_envelope(
    envelope: &Phase10SharedLookupProofEnvelope,
) -> Result<bool> {
    if envelope.proof_backend != StarkProofBackend::Stwo {
        return Err(VmError::InvalidConfig(format!(
            "shared binary-step lookup proof backend `{}` is not `stwo`",
            envelope.proof_backend
        )));
    }
    if envelope.proof_backend_version != STWO_SHARED_LOOKUP_PROOF_VERSION_PHASE10 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported shared binary-step lookup proof backend version `{}` (expected `{}`)",
            envelope.proof_backend_version, STWO_SHARED_LOOKUP_PROOF_VERSION_PHASE10
        )));
    }
    if envelope.statement_version != STWO_SHARED_LOOKUP_STATEMENT_VERSION_PHASE10 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported shared binary-step lookup statement version `{}` (expected `{}`)",
            envelope.statement_version, STWO_SHARED_LOOKUP_STATEMENT_VERSION_PHASE10
        )));
    }
    if envelope.semantic_scope != STWO_SHARED_LOOKUP_SEMANTIC_SCOPE_PHASE10 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported shared binary-step lookup semantic scope `{}` (expected `{}`)",
            envelope.semantic_scope, STWO_SHARED_LOOKUP_SEMANTIC_SCOPE_PHASE10
        )));
    }
    let bundle = build_shared_lookup_bundle(&envelope.claimed_rows)?;
    if envelope.canonical_table_rows != bundle.canonical_table_rows {
        return Err(VmError::UnsupportedProof(
            "shared binary-step lookup proof envelope does not match the canonical Phase 3 lookup table"
                .to_string(),
        ));
    }
    verify_phase10_shared_binary_step_lookup(&bundle, &envelope.proof)
}

pub fn save_phase10_shared_binary_step_lookup_proof(
    proof: &Phase10SharedLookupProofEnvelope,
    path: &Path,
) -> Result<()> {
    let json = serde_json::to_string_pretty(proof)
        .map_err(|error| VmError::Serialization(error.to_string()))?;
    fs::write(path, json)?;
    Ok(())
}

pub fn load_phase10_shared_binary_step_lookup_proof(
    path: &Path,
) -> Result<Phase10SharedLookupProofEnvelope> {
    let json = fs::read_to_string(path)?;
    serde_json::from_str(&json).map_err(|error| VmError::Serialization(error.to_string()))
}

pub fn prove_phase3_binary_step_lookup_demo() -> Result<Vec<u8>> {
    let bundle = build_lookup_demo_bundle();
    let config = PcsConfig::default();
    let component = phase3_binary_step_lookup_component(
        bundle.log_size,
        Phase3BinaryStepLookupElements::dummy(),
        SecureField::zero(),
    );
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(
            component.max_constraint_log_degree_bound() + config.fri_config.log_blowup_factor + 1,
        )
        .circle_domain()
        .half_coset,
    );

    let channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<SimdBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(bundle.preprocessed_trace.clone());
    tree_builder.commit(channel);

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(bundle.base_trace.clone());
    tree_builder.commit(channel);

    channel.mix_u64(bundle.log_size as u64);
    let lookup_elements = Phase3BinaryStepLookupElements::draw(channel);
    let (interaction_trace, claimed_sum) = lookup_interaction_trace(
        bundle.log_size,
        &bundle.base_trace,
        &bundle.preprocessed_trace,
        &lookup_elements,
    );
    if claimed_sum != SecureField::zero() {
        return Err(VmError::UnsupportedProof(
            "binary-step lookup demo expected zero claimed sum for identical witness/table multisets"
                .to_string(),
        ));
    }

    let component =
        phase3_binary_step_lookup_component(bundle.log_size, lookup_elements, claimed_sum);

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(interaction_trace);
    tree_builder.commit(channel);

    let stark_proof =
        prove::<SimdBackend, Blake2sM31MerkleChannel>(&[&component], channel, commitment_scheme)
            .map_err(|error| {
                VmError::UnsupportedProof(format!(
                    "S-two binary-step lookup proving failed: {error}"
                ))
            })?;

    serde_json::to_vec(&Phase3LookupProofPayload {
        stark_proof,
        canonical_table_rows: bundle.table_rows.clone(),
    })
    .map_err(|error| VmError::Serialization(error.to_string()))
}

pub fn verify_phase3_binary_step_lookup_demo(proof: &[u8]) -> Result<bool> {
    let bundle = build_lookup_demo_bundle();
    let payload: Phase3LookupProofPayload =
        serde_json::from_slice(proof).map_err(|error| VmError::Serialization(error.to_string()))?;
    if payload.canonical_table_rows != bundle.table_rows {
        return Err(VmError::UnsupportedProof(
            "S-two binary-step lookup verification rejected proof with non-canonical table rows"
                .to_string(),
        ));
    }
    let stark_proof = payload.stark_proof;

    let pcs_config = stark_proof.config;
    let channel = &mut Blake2sM31Channel::default();
    let commitment_scheme =
        &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(pcs_config);
    let placeholder_component = phase3_binary_step_lookup_component(
        bundle.log_size,
        Phase3BinaryStepLookupElements::dummy(),
        SecureField::zero(),
    );
    let sizes = placeholder_component.trace_log_degree_bounds();
    commitment_scheme.commit(stark_proof.commitments[0], &sizes[0], channel);
    commitment_scheme.commit(stark_proof.commitments[1], &sizes[1], channel);
    channel.mix_u64(bundle.log_size as u64);
    let lookup_elements = Phase3BinaryStepLookupElements::draw(channel);
    let component =
        phase3_binary_step_lookup_component(bundle.log_size, lookup_elements, SecureField::zero());
    commitment_scheme.commit(stark_proof.commitments[2], &sizes[2], channel);

    Ok(verify(&[&component], channel, commitment_scheme, stark_proof).is_ok())
}

#[derive(Clone)]
struct LookupDemoBundle {
    log_size: u32,
    table_rows: Vec<Phase3LookupTableRow>,
    preprocessed_trace: ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    base_trace: ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
}

#[derive(Clone)]
struct SharedLookupBundle {
    log_size: u32,
    canonical_table_rows: Vec<Phase3LookupTableRow>,
    claimed_rows: Vec<Phase3LookupTableRow>,
    preprocessed_trace: ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    base_trace: ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
}

fn build_lookup_demo_bundle() -> LookupDemoBundle {
    let log_size = LOG_N_LANES.max(4);
    let row_count = 1usize << log_size;
    let table_rows = padded_table_rows(row_count);
    let preprocessed_trace = lookup_preprocessed_trace(log_size, &table_rows);
    let base_trace = lookup_base_trace(log_size, &table_rows);
    LookupDemoBundle {
        log_size,
        table_rows,
        preprocessed_trace,
        base_trace,
    }
}

fn padded_table_rows(row_count: usize) -> Vec<Phase3LookupTableRow> {
    let mut rows = phase3_lookup_table_rows();
    let pad = rows.last().cloned().expect("lookup table rows");
    rows.resize(row_count, pad);
    rows
}

fn lookup_preprocessed_trace(
    log_size: u32,
    rows: &[Phase3LookupTableRow],
) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
    let domain = CanonicCoset::new(log_size).circle_domain();
    let table_input = BaseColumn::from_iter(
        rows.iter()
            .map(|row| BaseField::from((row.input as i32).rem_euclid(1 << 31) as u32)),
    );
    let table_output =
        BaseColumn::from_iter(rows.iter().map(|row| BaseField::from(row.output as u32)));
    vec![
        CircleEvaluation::<SimdBackend, BaseField, NaturalOrder>::new(domain, table_input)
            .bit_reverse(),
        CircleEvaluation::<SimdBackend, BaseField, NaturalOrder>::new(domain, table_output)
            .bit_reverse(),
    ]
}

fn lookup_base_trace(
    log_size: u32,
    rows: &[Phase3LookupTableRow],
) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
    lookup_preprocessed_trace(log_size, rows)
}

fn lookup_interaction_trace(
    log_size: u32,
    base_trace: &ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    preprocessed_trace: &ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    lookup_elements: &Phase3BinaryStepLookupElements,
) -> (
    ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    SecureField,
) {
    let mut logup_gen = LogupTraceGenerator::new(log_size);
    let mut col_gen = logup_gen.new_col();
    for vec_row in 0..(1 << (log_size - LOG_N_LANES)) {
        let witness_q: PackedSecureField =
            lookup_elements.combine(&[base_trace[0].data[vec_row], base_trace[1].data[vec_row]]);
        let table_q: PackedSecureField = lookup_elements.combine(&[
            preprocessed_trace[0].data[vec_row],
            preprocessed_trace[1].data[vec_row],
        ]);
        col_gen.write_frac(vec_row, table_q - witness_q, witness_q * table_q);
    }
    col_gen.finalize_col();
    logup_gen.finalize_last()
}

fn build_shared_lookup_bundle(claimed_rows: &[Phase3LookupTableRow]) -> Result<SharedLookupBundle> {
    if claimed_rows.is_empty() {
        return Err(VmError::InvalidConfig(
            "shared binary-step lookup requires at least one claimed row".to_string(),
        ));
    }
    let canonical_rows = phase3_lookup_table_rows();
    let mut selected_positions = Vec::with_capacity(claimed_rows.len());
    for row in claimed_rows {
        let Some(position) = canonical_rows.iter().position(|candidate| candidate == row) else {
            return Err(VmError::InvalidConfig(format!(
                "shared binary-step lookup received non-canonical claimed row ({}, {})",
                row.input, row.output
            )));
        };
        if selected_positions.contains(&position) {
            return Err(VmError::InvalidConfig(format!(
                "shared binary-step lookup received duplicate claimed row ({}, {})",
                row.input, row.output
            )));
        }
        selected_positions.push(position);
    }

    let log_size = LOG_N_LANES.max(4);
    let row_count = 1usize << log_size;
    let mut padded_canonical_rows = canonical_rows.clone();
    let pad = padded_canonical_rows
        .last()
        .cloned()
        .expect("phase3 lookup table rows");
    padded_canonical_rows.resize(row_count, pad);
    let preprocessed_trace = lookup_preprocessed_trace(log_size, &padded_canonical_rows);
    let base_trace =
        shared_lookup_base_trace(log_size, &padded_canonical_rows, &selected_positions);
    Ok(SharedLookupBundle {
        log_size,
        canonical_table_rows: canonical_rows,
        claimed_rows: claimed_rows.to_vec(),
        preprocessed_trace,
        base_trace,
    })
}

fn shared_lookup_base_trace(
    log_size: u32,
    canonical_rows: &[Phase3LookupTableRow],
    selected_positions: &[usize],
) -> ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>> {
    let domain = CanonicCoset::new(log_size).circle_domain();
    let claimed_input = BaseColumn::from_iter(
        canonical_rows
            .iter()
            .map(|row| BaseField::from((row.input as i32).rem_euclid(1 << 31) as u32)),
    );
    let claimed_output = BaseColumn::from_iter(
        canonical_rows
            .iter()
            .map(|row| BaseField::from(row.output as u32)),
    );
    let selector = BaseColumn::from_iter(
        canonical_rows
            .iter()
            .enumerate()
            .map(|(index, _)| BaseField::from(u32::from(selected_positions.contains(&index)))),
    );
    vec![
        CircleEvaluation::<SimdBackend, BaseField, NaturalOrder>::new(domain, claimed_input)
            .bit_reverse(),
        CircleEvaluation::<SimdBackend, BaseField, NaturalOrder>::new(domain, claimed_output)
            .bit_reverse(),
        CircleEvaluation::<SimdBackend, BaseField, NaturalOrder>::new(domain, selector)
            .bit_reverse(),
    ]
}

fn shared_lookup_component(
    log_size: u32,
    lookup_elements: Phase10SharedBinaryStepLookupElements,
    claimed_sum: SecureField,
) -> FrameworkComponent<Phase10SharedBinaryStepLookupEval> {
    FrameworkComponent::new(
        &mut TraceLocationAllocator::new_with_preprocessed_columns(&[
            column_id("phase10/shared/table_input"),
            column_id("phase10/shared/table_output"),
        ]),
        Phase10SharedBinaryStepLookupEval {
            log_size,
            lookup_elements,
        },
        claimed_sum,
    )
}

fn prove_phase10_shared_binary_step_lookup(bundle: &SharedLookupBundle) -> Result<Vec<u8>> {
    let config = PcsConfig::default();
    let component = shared_lookup_component(
        bundle.log_size,
        Phase10SharedBinaryStepLookupElements::dummy(),
        SecureField::zero(),
    );
    let twiddles = SimdBackend::precompute_twiddles(
        CanonicCoset::new(
            component.max_constraint_log_degree_bound() + config.fri_config.log_blowup_factor + 1,
        )
        .circle_domain()
        .half_coset,
    );

    let channel = &mut Blake2sM31Channel::default();
    let mut commitment_scheme =
        CommitmentSchemeProver::<SimdBackend, Blake2sM31MerkleChannel>::new(config, &twiddles);
    commitment_scheme.set_store_polynomials_coefficients();

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(bundle.preprocessed_trace.clone());
    tree_builder.commit(channel);

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(bundle.base_trace.clone());
    tree_builder.commit(channel);

    mix_shared_lookup_claim_rows(channel, &bundle.claimed_rows);
    let lookup_elements = Phase10SharedBinaryStepLookupElements::draw(channel);
    let (interaction_trace, claimed_sum) = shared_lookup_interaction_trace(
        bundle.log_size,
        &bundle.base_trace,
        &bundle.preprocessed_trace,
        &lookup_elements,
    );
    if claimed_sum != SecureField::zero() {
        return Err(VmError::UnsupportedProof(
            "shared binary-step lookup expected zero claimed sum for selected canonical rows"
                .to_string(),
        ));
    }
    let component = shared_lookup_component(bundle.log_size, lookup_elements, claimed_sum);

    let mut tree_builder = commitment_scheme.tree_builder();
    tree_builder.extend_evals(interaction_trace);
    tree_builder.commit(channel);

    let stark_proof =
        prove::<SimdBackend, Blake2sM31MerkleChannel>(&[&component], channel, commitment_scheme)
            .map_err(|error| {
                VmError::UnsupportedProof(format!(
                    "S-two shared binary-step lookup proving failed: {error}"
                ))
            })?;

    serde_json::to_vec(&Phase3LookupProofPayload {
        stark_proof,
        canonical_table_rows: bundle.canonical_table_rows.clone(),
    })
    .map_err(|error| VmError::Serialization(error.to_string()))
}

fn verify_phase10_shared_binary_step_lookup(
    bundle: &SharedLookupBundle,
    proof: &[u8],
) -> Result<bool> {
    let payload: Phase3LookupProofPayload =
        serde_json::from_slice(proof).map_err(|error| VmError::Serialization(error.to_string()))?;
    if payload.canonical_table_rows != bundle.canonical_table_rows {
        return Err(VmError::UnsupportedProof(
            "S-two shared binary-step lookup verification rejected proof with non-canonical table rows"
                .to_string(),
        ));
    }
    let stark_proof = payload.stark_proof;

    let pcs_config = stark_proof.config;
    let channel = &mut Blake2sM31Channel::default();
    let commitment_scheme =
        &mut CommitmentSchemeVerifier::<Blake2sM31MerkleChannel>::new(pcs_config);
    let placeholder_component = shared_lookup_component(
        bundle.log_size,
        Phase10SharedBinaryStepLookupElements::dummy(),
        SecureField::zero(),
    );
    let sizes = placeholder_component.trace_log_degree_bounds();
    commitment_scheme.commit(stark_proof.commitments[0], &sizes[0], channel);
    commitment_scheme.commit(stark_proof.commitments[1], &sizes[1], channel);
    mix_shared_lookup_claim_rows(channel, &bundle.claimed_rows);
    let lookup_elements = Phase10SharedBinaryStepLookupElements::draw(channel);
    let component = shared_lookup_component(bundle.log_size, lookup_elements, SecureField::zero());
    commitment_scheme.commit(stark_proof.commitments[2], &sizes[2], channel);

    Ok(verify(&[&component], channel, commitment_scheme, stark_proof).is_ok())
}

fn shared_lookup_interaction_trace(
    log_size: u32,
    base_trace: &ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    preprocessed_trace: &ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    lookup_elements: &Phase10SharedBinaryStepLookupElements,
) -> (
    ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    SecureField,
) {
    let mut logup_gen = LogupTraceGenerator::new(log_size);
    let mut col_gen = logup_gen.new_col();
    for vec_row in 0..(1 << (log_size - LOG_N_LANES)) {
        let selector = PackedSecureField::from(base_trace[2].data[vec_row]);
        let witness_q: PackedSecureField =
            lookup_elements.combine(&[base_trace[0].data[vec_row], base_trace[1].data[vec_row]]);
        let table_q: PackedSecureField = lookup_elements.combine(&[
            preprocessed_trace[0].data[vec_row],
            preprocessed_trace[1].data[vec_row],
        ]);
        col_gen.write_frac(
            vec_row,
            selector * (table_q - witness_q),
            witness_q * table_q,
        );
    }
    col_gen.finalize_col();
    logup_gen.finalize_last()
}

fn mix_shared_lookup_claim_rows(
    channel: &mut Blake2sM31Channel,
    claimed_rows: &[Phase3LookupTableRow],
) {
    channel.mix_u64(claimed_rows.len() as u64);
    for row in claimed_rows {
        channel.mix_u64((row.input as i32).rem_euclid(1 << 31) as u64);
        channel.mix_u64(row.output as u64);
    }
}

fn column_id(id: &str) -> stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId {
    stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId { id: id.to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase3_binary_step_lookup_demo_round_trips_real_proof() {
        let proof = prove_phase3_binary_step_lookup_demo().expect("prove lookup demo");
        assert!(!proof.is_empty());
        assert!(verify_phase3_binary_step_lookup_demo(&proof).expect("verify lookup demo"));
    }

    #[test]
    fn phase3_binary_step_lookup_demo_envelope_round_trips() {
        let envelope =
            prove_phase3_binary_step_lookup_demo_envelope().expect("prove lookup demo envelope");
        assert_eq!(envelope.proof_backend, StarkProofBackend::Stwo);
        assert_eq!(
            envelope.proof_backend_version,
            STWO_LOOKUP_PROOF_VERSION_PHASE3
        );
        assert_eq!(
            envelope.statement_version,
            STWO_LOOKUP_STATEMENT_VERSION_PHASE3
        );
        assert_eq!(envelope.semantic_scope, STWO_LOOKUP_SEMANTIC_SCOPE_PHASE3);
        assert!(verify_phase3_binary_step_lookup_demo_envelope(&envelope)
            .expect("verify lookup demo envelope"));
    }

    #[test]
    fn phase10_shared_lookup_envelope_round_trips_multiple_rows() {
        let claimed_rows = vec![
            Phase3LookupTableRow {
                input: 0,
                output: 1,
            },
            Phase3LookupTableRow {
                input: 1,
                output: 1,
            },
        ];
        let envelope = prove_phase10_shared_binary_step_lookup_envelope(&claimed_rows)
            .expect("prove shared lookup envelope");
        assert_eq!(envelope.proof_backend, StarkProofBackend::Stwo);
        assert_eq!(
            envelope.proof_backend_version,
            STWO_SHARED_LOOKUP_PROOF_VERSION_PHASE10
        );
        assert_eq!(
            envelope.statement_version,
            STWO_SHARED_LOOKUP_STATEMENT_VERSION_PHASE10
        );
        assert_eq!(
            envelope.semantic_scope,
            STWO_SHARED_LOOKUP_SEMANTIC_SCOPE_PHASE10
        );
        assert_eq!(envelope.claimed_rows, claimed_rows);
        assert!(verify_phase10_shared_binary_step_lookup_envelope(&envelope)
            .expect("verify shared lookup envelope"));
    }

    #[test]
    fn phase10_shared_lookup_rejects_noncanonical_row() {
        let claimed_rows = vec![Phase3LookupTableRow {
            input: 2,
            output: 1,
        }];
        let error = prove_phase10_shared_binary_step_lookup_envelope(&claimed_rows)
            .expect_err("noncanonical row should fail");
        assert!(error.to_string().contains("non-canonical"));
    }

    #[test]
    fn phase10_shared_lookup_rejects_duplicate_rows() {
        let claimed_rows = vec![
            Phase3LookupTableRow {
                input: 1,
                output: 1,
            },
            Phase3LookupTableRow {
                input: 1,
                output: 1,
            },
        ];
        let error = prove_phase10_shared_binary_step_lookup_envelope(&claimed_rows)
            .expect_err("duplicate rows should fail");
        assert!(error.to_string().contains("duplicate"));
    }

    #[test]
    fn phase10_shared_lookup_verification_detects_tampered_claimed_rows() {
        let claimed_rows = vec![
            Phase3LookupTableRow {
                input: 0,
                output: 1,
            },
            Phase3LookupTableRow {
                input: 1,
                output: 1,
            },
        ];
        let mut envelope = prove_phase10_shared_binary_step_lookup_envelope(&claimed_rows)
            .expect("prove shared lookup envelope");
        envelope.claimed_rows[1].output = 0;
        let error = verify_phase10_shared_binary_step_lookup_envelope(&envelope)
            .expect_err("tampered claimed rows should fail");
        assert!(error.to_string().contains("claimed row"));
    }
}
