use serde::{Deserialize, Serialize};
#[cfg(feature = "stwo-backend")]
use std::path::Path;

use crate::error::{Result, VmError};
use crate::proof::{ExecutionClaimCommitments, StarkProofBackend, VanillaStarkExecutionProof};

#[cfg(feature = "stwo-backend")]
use super::decoding::{
    read_json_bytes_with_limit,
    verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_proof_checks,
    Phase28AggregatedChainedFoldedIntervalizedDecodingStateRelationManifest,
    STWO_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_SCOPE_PHASE28,
    STWO_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE28,
    STWO_PHASE28_RECURSION_POSTURE_PRE_RECURSIVE,
};
#[cfg(feature = "stwo-backend")]
use super::STWO_BACKEND_VERSION_PHASE12;
#[cfg(feature = "stwo-backend")]
use crate::proof::CLAIM_STATEMENT_VERSION_V1;
#[cfg(feature = "stwo-backend")]
use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};

pub const STWO_RECURSION_BATCH_VERSION_PHASE6: &str = "stwo-phase6-recursion-batch-v1";
pub const STWO_RECURSION_BATCH_SCOPE_PHASE6: &str =
    "stwo_execution_proof_batch_preaggregation_manifest";
#[cfg(feature = "stwo-backend")]
pub const STWO_RECURSIVE_COMPRESSION_INPUT_CONTRACT_VERSION_PHASE29: &str =
    "stwo-phase29-recursive-compression-input-contract-v1";
#[cfg(feature = "stwo-backend")]
pub const STWO_RECURSIVE_COMPRESSION_INPUT_CONTRACT_SCOPE_PHASE29: &str =
    "stwo_phase29_recursive_compression_input_contract";
#[cfg(feature = "stwo-backend")]
const MAX_PHASE29_RECURSIVE_COMPRESSION_INPUT_CONTRACT_JSON_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Phase6RecursionBatchEntry {
    pub proof_backend_version: String,
    pub statement_version: String,
    pub semantic_scope: String,
    pub steps: usize,
    pub proof_bytes: usize,
    pub commitment_program_hash: String,
    pub commitment_stark_options_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Phase6RecursionBatchManifest {
    pub proof_backend: StarkProofBackend,
    pub batch_version: String,
    pub semantic_scope: String,
    pub proof_backend_version: String,
    pub statement_version: String,
    pub total_proofs: usize,
    pub total_steps: usize,
    pub total_proof_bytes: usize,
    pub entries: Vec<Phase6RecursionBatchEntry>,
}

#[cfg(feature = "stwo-backend")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Phase29RecursiveCompressionInputContractUnchecked")]
pub struct Phase29RecursiveCompressionInputContract {
    pub proof_backend: StarkProofBackend,
    pub contract_version: String,
    pub semantic_scope: String,
    pub phase28_artifact_version: String,
    pub phase28_semantic_scope: String,
    pub phase28_proof_backend_version: String,
    pub statement_version: String,
    pub required_recursion_posture: String,
    pub recursive_verification_claimed: bool,
    pub cryptographic_compression_claimed: bool,
    pub phase28_bounded_aggregation_arity: usize,
    pub phase28_member_count: usize,
    pub phase28_member_summaries: usize,
    pub phase28_nested_members: usize,
    pub total_phase26_members: usize,
    pub total_phase25_members: usize,
    pub max_nested_chain_arity: usize,
    pub max_nested_fold_arity: usize,
    pub total_matrices: usize,
    pub total_layouts: usize,
    pub total_rollups: usize,
    pub total_segments: usize,
    pub total_steps: usize,
    pub lookup_delta_entries: usize,
    pub max_lookup_frontier_entries: usize,
    pub source_template_commitment: String,
    pub global_start_state_commitment: String,
    pub global_end_state_commitment: String,
    pub aggregation_template_commitment: String,
    pub aggregated_chained_folded_interval_accumulator_commitment: String,
    pub input_contract_commitment: String,
}

#[cfg(feature = "stwo-backend")]
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Phase29RecursiveCompressionInputContractUnchecked {
    pub proof_backend: StarkProofBackend,
    pub contract_version: String,
    pub semantic_scope: String,
    pub phase28_artifact_version: String,
    pub phase28_semantic_scope: String,
    pub phase28_proof_backend_version: String,
    pub statement_version: String,
    pub required_recursion_posture: String,
    pub recursive_verification_claimed: bool,
    pub cryptographic_compression_claimed: bool,
    pub phase28_bounded_aggregation_arity: usize,
    pub phase28_member_count: usize,
    pub phase28_member_summaries: usize,
    pub phase28_nested_members: usize,
    pub total_phase26_members: usize,
    pub total_phase25_members: usize,
    pub max_nested_chain_arity: usize,
    pub max_nested_fold_arity: usize,
    pub total_matrices: usize,
    pub total_layouts: usize,
    pub total_rollups: usize,
    pub total_segments: usize,
    pub total_steps: usize,
    pub lookup_delta_entries: usize,
    pub max_lookup_frontier_entries: usize,
    pub source_template_commitment: String,
    pub global_start_state_commitment: String,
    pub global_end_state_commitment: String,
    pub aggregation_template_commitment: String,
    pub aggregated_chained_folded_interval_accumulator_commitment: String,
    pub input_contract_commitment: String,
}

#[cfg(feature = "stwo-backend")]
impl TryFrom<Phase29RecursiveCompressionInputContractUnchecked>
    for Phase29RecursiveCompressionInputContract
{
    type Error = VmError;

    fn try_from(
        unchecked: Phase29RecursiveCompressionInputContractUnchecked,
    ) -> std::result::Result<Self, Self::Error> {
        let contract = Self {
            proof_backend: unchecked.proof_backend,
            contract_version: unchecked.contract_version,
            semantic_scope: unchecked.semantic_scope,
            phase28_artifact_version: unchecked.phase28_artifact_version,
            phase28_semantic_scope: unchecked.phase28_semantic_scope,
            phase28_proof_backend_version: unchecked.phase28_proof_backend_version,
            statement_version: unchecked.statement_version,
            required_recursion_posture: unchecked.required_recursion_posture,
            recursive_verification_claimed: unchecked.recursive_verification_claimed,
            cryptographic_compression_claimed: unchecked.cryptographic_compression_claimed,
            phase28_bounded_aggregation_arity: unchecked.phase28_bounded_aggregation_arity,
            phase28_member_count: unchecked.phase28_member_count,
            phase28_member_summaries: unchecked.phase28_member_summaries,
            phase28_nested_members: unchecked.phase28_nested_members,
            total_phase26_members: unchecked.total_phase26_members,
            total_phase25_members: unchecked.total_phase25_members,
            max_nested_chain_arity: unchecked.max_nested_chain_arity,
            max_nested_fold_arity: unchecked.max_nested_fold_arity,
            total_matrices: unchecked.total_matrices,
            total_layouts: unchecked.total_layouts,
            total_rollups: unchecked.total_rollups,
            total_segments: unchecked.total_segments,
            total_steps: unchecked.total_steps,
            lookup_delta_entries: unchecked.lookup_delta_entries,
            max_lookup_frontier_entries: unchecked.max_lookup_frontier_entries,
            source_template_commitment: unchecked.source_template_commitment,
            global_start_state_commitment: unchecked.global_start_state_commitment,
            global_end_state_commitment: unchecked.global_end_state_commitment,
            aggregation_template_commitment: unchecked.aggregation_template_commitment,
            aggregated_chained_folded_interval_accumulator_commitment: unchecked
                .aggregated_chained_folded_interval_accumulator_commitment,
            input_contract_commitment: unchecked.input_contract_commitment,
        };
        verify_phase29_recursive_compression_input_contract(&contract)?;
        Ok(contract)
    }
}

pub fn phase6_prepare_recursion_batch(
    proofs: &[VanillaStarkExecutionProof],
) -> Result<Phase6RecursionBatchManifest> {
    let first = proofs.first().ok_or_else(|| {
        VmError::InvalidConfig(
            "recursion batch preparation requires at least one proof".to_string(),
        )
    })?;
    if first.proof_backend != StarkProofBackend::Stwo {
        return Err(VmError::InvalidConfig(format!(
            "recursion batch preparation requires `stwo` proofs, got `{}`",
            first.proof_backend
        )));
    }
    required_commitments(first)?;

    let mut entries = Vec::with_capacity(proofs.len());
    let mut total_steps = 0usize;
    let mut total_proof_bytes = 0usize;

    for (index, proof) in proofs.iter().enumerate() {
        if proof.proof_backend != StarkProofBackend::Stwo {
            return Err(VmError::InvalidConfig(format!(
                "proof {index} uses backend `{}`; expected `stwo` for recursion batching",
                proof.proof_backend
            )));
        }
        if proof.proof_backend_version != first.proof_backend_version {
            return Err(VmError::InvalidConfig(format!(
                "proof {index} uses backend version `{}`; expected `{}`",
                proof.proof_backend_version, first.proof_backend_version
            )));
        }
        if proof.claim.statement_version != first.claim.statement_version {
            return Err(VmError::InvalidConfig(format!(
                "proof {index} uses statement version `{}`; expected `{}`",
                proof.claim.statement_version, first.claim.statement_version
            )));
        }
        if proof.claim.semantic_scope != first.claim.semantic_scope {
            return Err(VmError::InvalidConfig(format!(
                "proof {index} uses semantic scope `{}`; expected `{}`",
                proof.claim.semantic_scope, first.claim.semantic_scope
            )));
        }
        let commitments = required_commitments(proof)?;
        if commitments.stark_options_hash != first_commitment_stark_options_hash(first)? {
            return Err(VmError::InvalidConfig(format!(
                "proof {index} uses stark options hash `{}`; expected `{}`",
                commitments.stark_options_hash,
                first_commitment_stark_options_hash(first)?
            )));
        }

        total_steps += proof.claim.steps;
        total_proof_bytes += proof.proof.len();
        entries.push(Phase6RecursionBatchEntry {
            proof_backend_version: proof.proof_backend_version.clone(),
            statement_version: proof.claim.statement_version.clone(),
            semantic_scope: proof.claim.semantic_scope.clone(),
            steps: proof.claim.steps,
            proof_bytes: proof.proof.len(),
            commitment_program_hash: commitments.program_hash.clone(),
            commitment_stark_options_hash: commitments.stark_options_hash.clone(),
        });
    }

    Ok(Phase6RecursionBatchManifest {
        proof_backend: StarkProofBackend::Stwo,
        batch_version: STWO_RECURSION_BATCH_VERSION_PHASE6.to_string(),
        semantic_scope: STWO_RECURSION_BATCH_SCOPE_PHASE6.to_string(),
        proof_backend_version: first.proof_backend_version.clone(),
        statement_version: first.claim.statement_version.clone(),
        total_proofs: entries.len(),
        total_steps,
        total_proof_bytes,
        entries,
    })
}

fn required_commitments(proof: &VanillaStarkExecutionProof) -> Result<&ExecutionClaimCommitments> {
    proof.claim.commitments.as_ref().ok_or_else(|| {
        VmError::InvalidConfig(
            "recursion batch preparation requires commitment metadata".to_string(),
        )
    })
}

fn first_commitment_stark_options_hash(proof: &VanillaStarkExecutionProof) -> Result<String> {
    Ok(required_commitments(proof)?.stark_options_hash.clone())
}

#[cfg(feature = "stwo-backend")]
pub fn phase29_prepare_recursive_compression_input_contract(
    phase28: &Phase28AggregatedChainedFoldedIntervalizedDecodingStateRelationManifest,
) -> Result<Phase29RecursiveCompressionInputContract> {
    verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_proof_checks(
        phase28,
    )?;

    phase29_prepare_recursive_compression_input_contract_from_proof_checked_phase28(phase28)
}

#[cfg(feature = "stwo-backend")]
pub fn phase29_prepare_recursive_compression_input_contract_from_proof_checked_phase28(
    phase28: &Phase28AggregatedChainedFoldedIntervalizedDecodingStateRelationManifest,
) -> Result<Phase29RecursiveCompressionInputContract> {
    let mut contract = Phase29RecursiveCompressionInputContract {
        proof_backend: StarkProofBackend::Stwo,
        contract_version: STWO_RECURSIVE_COMPRESSION_INPUT_CONTRACT_VERSION_PHASE29.to_string(),
        semantic_scope: STWO_RECURSIVE_COMPRESSION_INPUT_CONTRACT_SCOPE_PHASE29.to_string(),
        phase28_artifact_version: phase28.artifact_version.clone(),
        phase28_semantic_scope: phase28.semantic_scope.clone(),
        phase28_proof_backend_version: phase28.proof_backend_version.clone(),
        statement_version: phase28.statement_version.clone(),
        required_recursion_posture: phase28.recursion_posture.clone(),
        recursive_verification_claimed: phase28.recursive_verification_claimed,
        cryptographic_compression_claimed: phase28.cryptographic_compression_claimed,
        phase28_bounded_aggregation_arity: phase28.bounded_aggregation_arity,
        phase28_member_count: phase28.member_count,
        phase28_member_summaries: phase28.member_summaries.len(),
        phase28_nested_members: phase28.members.len(),
        total_phase26_members: phase28.total_phase26_members,
        total_phase25_members: phase28.total_phase25_members,
        max_nested_chain_arity: phase28.max_nested_chain_arity,
        max_nested_fold_arity: phase28.max_nested_fold_arity,
        total_matrices: phase28.total_matrices,
        total_layouts: phase28.total_layouts,
        total_rollups: phase28.total_rollups,
        total_segments: phase28.total_segments,
        total_steps: phase28.total_steps,
        lookup_delta_entries: phase28.lookup_delta_entries,
        max_lookup_frontier_entries: phase28.max_lookup_frontier_entries,
        source_template_commitment: phase28.source_template_commitment.clone(),
        global_start_state_commitment: phase28.global_start_state_commitment.clone(),
        global_end_state_commitment: phase28.global_end_state_commitment.clone(),
        aggregation_template_commitment: phase28.aggregation_template_commitment.clone(),
        aggregated_chained_folded_interval_accumulator_commitment: phase28
            .aggregated_chained_folded_interval_accumulator_commitment
            .clone(),
        input_contract_commitment: String::new(),
    };
    contract.input_contract_commitment =
        commit_phase29_recursive_compression_input_contract(&contract)?;
    verify_phase29_recursive_compression_input_contract(&contract)?;
    Ok(contract)
}

#[cfg(feature = "stwo-backend")]
pub fn parse_phase29_recursive_compression_input_contract_json(
    json: &str,
) -> Result<Phase29RecursiveCompressionInputContract> {
    if json.len() > MAX_PHASE29_RECURSIVE_COMPRESSION_INPUT_CONTRACT_JSON_BYTES {
        return Err(VmError::InvalidConfig(format!(
            "Phase 29 recursive-compression input contract JSON is {} bytes, exceeding the limit of {} bytes",
            json.len(),
            MAX_PHASE29_RECURSIVE_COMPRESSION_INPUT_CONTRACT_JSON_BYTES
        )));
    }
    serde_json::from_str(json).map_err(phase29_json_error)
}

#[cfg(feature = "stwo-backend")]
pub fn load_phase29_recursive_compression_input_contract(
    path: &Path,
) -> Result<Phase29RecursiveCompressionInputContract> {
    let bytes = read_json_bytes_with_limit(
        path,
        MAX_PHASE29_RECURSIVE_COMPRESSION_INPUT_CONTRACT_JSON_BYTES,
        "Phase 29 recursive-compression input contract",
    )?;
    serde_json::from_slice(&bytes).map_err(phase29_json_error)
}

#[cfg(feature = "stwo-backend")]
fn phase29_json_error(error: serde_json::Error) -> VmError {
    match error.classify() {
        serde_json::error::Category::Data
        | serde_json::error::Category::Syntax
        | serde_json::error::Category::Eof => VmError::InvalidConfig(error.to_string()),
        serde_json::error::Category::Io => VmError::Serialization(error.to_string()),
    }
}

#[cfg(feature = "stwo-backend")]
pub fn verify_phase29_recursive_compression_input_contract(
    contract: &Phase29RecursiveCompressionInputContract,
) -> Result<()> {
    if contract.proof_backend != StarkProofBackend::Stwo {
        return Err(VmError::InvalidConfig(format!(
            "Phase 29 recursive-compression input contract requires `stwo` backend, got `{}`",
            contract.proof_backend
        )));
    }
    if contract.contract_version != STWO_RECURSIVE_COMPRESSION_INPUT_CONTRACT_VERSION_PHASE29 {
        return Err(VmError::InvalidConfig(format!(
            "Phase 29 recursive-compression input contract version `{}` does not match expected `{}`",
            contract.contract_version, STWO_RECURSIVE_COMPRESSION_INPUT_CONTRACT_VERSION_PHASE29
        )));
    }
    if contract.semantic_scope != STWO_RECURSIVE_COMPRESSION_INPUT_CONTRACT_SCOPE_PHASE29 {
        return Err(VmError::InvalidConfig(format!(
            "Phase 29 recursive-compression input contract scope `{}` does not match expected `{}`",
            contract.semantic_scope, STWO_RECURSIVE_COMPRESSION_INPUT_CONTRACT_SCOPE_PHASE29
        )));
    }
    if contract.phase28_artifact_version
        != STWO_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE28
    {
        return Err(VmError::InvalidConfig(format!(
            "Phase 29 recursive-compression input contract requires Phase 28 artifact version `{}`, got `{}`",
            STWO_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE28,
            contract.phase28_artifact_version
        )));
    }
    if contract.phase28_semantic_scope
        != STWO_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_SCOPE_PHASE28
    {
        return Err(VmError::InvalidConfig(format!(
            "Phase 29 recursive-compression input contract requires Phase 28 scope `{}`, got `{}`",
            STWO_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_SCOPE_PHASE28,
            contract.phase28_semantic_scope
        )));
    }
    if contract.required_recursion_posture != STWO_PHASE28_RECURSION_POSTURE_PRE_RECURSIVE {
        return Err(VmError::InvalidConfig(format!(
            "Phase 29 recursive-compression input contract requires Phase 28 posture `{}`, got `{}`",
            STWO_PHASE28_RECURSION_POSTURE_PRE_RECURSIVE,
            contract.required_recursion_posture
        )));
    }
    if contract.recursive_verification_claimed {
        return Err(VmError::InvalidConfig(
            "Phase 29 recursive-compression input contract must not claim recursive verification"
                .to_string(),
        ));
    }
    if contract.cryptographic_compression_claimed {
        return Err(VmError::InvalidConfig(
            "Phase 29 recursive-compression input contract must not claim cryptographic compression"
                .to_string(),
        ));
    }
    if contract.phase28_member_count < 2 {
        return Err(VmError::InvalidConfig(format!(
            "Phase 29 recursive-compression input contract requires at least two Phase 28 members, got {}",
            contract.phase28_member_count
        )));
    }
    if contract.phase28_bounded_aggregation_arity < contract.phase28_member_count {
        return Err(VmError::InvalidConfig(format!(
            "Phase 29 recursive-compression input contract bounded arity {} is smaller than member count {}",
            contract.phase28_bounded_aggregation_arity, contract.phase28_member_count
        )));
    }
    if contract.phase28_member_summaries != contract.phase28_member_count {
        return Err(VmError::InvalidConfig(format!(
            "Phase 29 recursive-compression input contract summarizes {} members but declares {}",
            contract.phase28_member_summaries, contract.phase28_member_count
        )));
    }
    if contract.phase28_nested_members != contract.phase28_member_count {
        return Err(VmError::InvalidConfig(format!(
            "Phase 29 recursive-compression input contract carries {} nested members but declares {}",
            contract.phase28_nested_members, contract.phase28_member_count
        )));
    }
    for (label, value) in [
        (
            "phase28_proof_backend_version",
            contract.phase28_proof_backend_version.as_str(),
        ),
        ("statement_version", contract.statement_version.as_str()),
        (
            "source_template_commitment",
            contract.source_template_commitment.as_str(),
        ),
        (
            "global_start_state_commitment",
            contract.global_start_state_commitment.as_str(),
        ),
        (
            "global_end_state_commitment",
            contract.global_end_state_commitment.as_str(),
        ),
        (
            "aggregation_template_commitment",
            contract.aggregation_template_commitment.as_str(),
        ),
        (
            "aggregated_chained_folded_interval_accumulator_commitment",
            contract
                .aggregated_chained_folded_interval_accumulator_commitment
                .as_str(),
        ),
        (
            "input_contract_commitment",
            contract.input_contract_commitment.as_str(),
        ),
    ] {
        if value.is_empty() {
            return Err(VmError::InvalidConfig(format!(
                "Phase 29 recursive-compression input contract `{label}` must be non-empty"
            )));
        }
    }

    if contract.phase28_proof_backend_version != STWO_BACKEND_VERSION_PHASE12 {
        return Err(VmError::InvalidConfig(format!(
            "Phase 29 recursive-compression input contract requires Phase 28 proof backend version `{}`, got `{}`",
            STWO_BACKEND_VERSION_PHASE12, contract.phase28_proof_backend_version
        )));
    }
    if contract.statement_version != CLAIM_STATEMENT_VERSION_V1 {
        return Err(VmError::InvalidConfig(format!(
            "Phase 29 recursive-compression input contract requires statement version `{}`, got `{}`",
            CLAIM_STATEMENT_VERSION_V1, contract.statement_version
        )));
    }

    let expected = commit_phase29_recursive_compression_input_contract(contract)?;
    if contract.input_contract_commitment != expected {
        return Err(VmError::InvalidConfig(format!(
            "Phase 29 recursive-compression input contract commitment `{}` does not match recomputed `{}`",
            contract.input_contract_commitment, expected
        )));
    }

    Ok(())
}

#[cfg(feature = "stwo-backend")]
pub fn commit_phase29_recursive_compression_input_contract(
    contract: &Phase29RecursiveCompressionInputContract,
) -> Result<String> {
    let mut hasher = Blake2bVar::new(32).map_err(|err| {
        VmError::InvalidConfig(format!(
            "failed to initialize Phase 29 input contract commitment hash: {err}"
        ))
    })?;
    phase29_update_len_prefixed(&mut hasher, b"phase29-contract");
    phase29_update_len_prefixed(&mut hasher, contract.proof_backend.to_string().as_bytes());
    phase29_update_len_prefixed(&mut hasher, contract.contract_version.as_bytes());
    phase29_update_len_prefixed(&mut hasher, contract.semantic_scope.as_bytes());
    phase29_update_len_prefixed(&mut hasher, contract.phase28_artifact_version.as_bytes());
    phase29_update_len_prefixed(&mut hasher, contract.phase28_semantic_scope.as_bytes());
    phase29_update_len_prefixed(
        &mut hasher,
        contract.phase28_proof_backend_version.as_bytes(),
    );
    phase29_update_len_prefixed(&mut hasher, contract.statement_version.as_bytes());
    phase29_update_len_prefixed(&mut hasher, contract.required_recursion_posture.as_bytes());
    phase29_update_bool(&mut hasher, contract.recursive_verification_claimed);
    phase29_update_bool(&mut hasher, contract.cryptographic_compression_claimed);
    phase29_update_usize(&mut hasher, contract.phase28_bounded_aggregation_arity);
    phase29_update_usize(&mut hasher, contract.phase28_member_count);
    phase29_update_usize(&mut hasher, contract.phase28_member_summaries);
    phase29_update_usize(&mut hasher, contract.phase28_nested_members);
    phase29_update_usize(&mut hasher, contract.total_phase26_members);
    phase29_update_usize(&mut hasher, contract.total_phase25_members);
    phase29_update_usize(&mut hasher, contract.max_nested_chain_arity);
    phase29_update_usize(&mut hasher, contract.max_nested_fold_arity);
    phase29_update_usize(&mut hasher, contract.total_matrices);
    phase29_update_usize(&mut hasher, contract.total_layouts);
    phase29_update_usize(&mut hasher, contract.total_rollups);
    phase29_update_usize(&mut hasher, contract.total_segments);
    phase29_update_usize(&mut hasher, contract.total_steps);
    phase29_update_usize(&mut hasher, contract.lookup_delta_entries);
    phase29_update_usize(&mut hasher, contract.max_lookup_frontier_entries);
    phase29_update_len_prefixed(&mut hasher, contract.source_template_commitment.as_bytes());
    phase29_update_len_prefixed(
        &mut hasher,
        contract.global_start_state_commitment.as_bytes(),
    );
    phase29_update_len_prefixed(&mut hasher, contract.global_end_state_commitment.as_bytes());
    phase29_update_len_prefixed(
        &mut hasher,
        contract.aggregation_template_commitment.as_bytes(),
    );
    phase29_update_len_prefixed(
        &mut hasher,
        contract
            .aggregated_chained_folded_interval_accumulator_commitment
            .as_bytes(),
    );
    let mut out = [0u8; 32];
    hasher.finalize_variable(&mut out).map_err(|err| {
        VmError::InvalidConfig(format!(
            "failed to finalize Phase 29 input contract commitment hash: {err}"
        ))
    })?;
    Ok(phase29_lower_hex(&out))
}

#[cfg(feature = "stwo-backend")]
fn phase29_update_len_prefixed(hasher: &mut Blake2bVar, bytes: &[u8]) {
    phase29_update_usize(hasher, bytes.len());
    hasher.update(bytes);
}

#[cfg(feature = "stwo-backend")]
fn phase29_update_bool(hasher: &mut Blake2bVar, value: bool) {
    hasher.update(&[u8::from(value)]);
}

#[cfg(feature = "stwo-backend")]
fn phase29_update_usize(hasher: &mut Blake2bVar, value: usize) {
    hasher.update(&(value as u128).to_le_bytes());
}

#[cfg(feature = "stwo-backend")]
fn phase29_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembly::parse_program;
    use crate::proof::{
        production_v1_stark_options, CLAIM_SEMANTIC_SCOPE_V1, CLAIM_STATEMENT_VERSION_V1,
    };
    use crate::state::MachineState;
    use crate::Attention2DMode;

    fn sample_proof(program_source: &str, program_hash: &str) -> VanillaStarkExecutionProof {
        let program = parse_program(program_source).expect("parse");
        VanillaStarkExecutionProof {
            proof_backend: StarkProofBackend::Stwo,
            proof_backend_version: "stwo-phase7-gemma-block-v1".to_string(),
            stwo_auxiliary: None,
            claim: crate::proof::VanillaStarkExecutionClaim {
                statement_version: CLAIM_STATEMENT_VERSION_V1.to_string(),
                semantic_scope: CLAIM_SEMANTIC_SCOPE_V1.to_string(),
                program,
                attention_mode: Attention2DMode::AverageHard,
                transformer_config: None,
                steps: 3,
                final_state: MachineState::with_memory(vec![0, 0, 0, 0]),
                options: production_v1_stark_options(),
                equivalence: None,
                commitments: Some(ExecutionClaimCommitments {
                    scheme_version: "v1".to_string(),
                    hash_function: "blake2b-256".to_string(),
                    program_hash: program_hash.to_string(),
                    transformer_config_hash: "cfg".to_string(),
                    deterministic_model_hash: "model".to_string(),
                    stark_options_hash: "opts".to_string(),
                    prover_build_info: "build".to_string(),
                    prover_build_hash: "buildhash".to_string(),
                }),
            },
            proof: vec![1, 2, 3],
        }
    }

    #[test]
    fn phase6_recursion_batch_manifest_accepts_compatible_stwo_proofs() {
        let proofs = vec![
            sample_proof(".memory 4\nLOADI 1\nHALT\n", "hash-a"),
            sample_proof(".memory 4\nLOADI 2\nHALT\n", "hash-b"),
        ];
        let manifest = phase6_prepare_recursion_batch(&proofs).expect("prepare batch");
        assert_eq!(manifest.proof_backend, StarkProofBackend::Stwo);
        assert_eq!(manifest.total_proofs, 2);
        assert_eq!(manifest.total_steps, 6);
        assert_eq!(manifest.total_proof_bytes, 6);
        assert_eq!(manifest.entries[0].commitment_program_hash, "hash-a");
        assert_eq!(manifest.entries[1].commitment_program_hash, "hash-b");
    }

    #[cfg(feature = "stwo-backend")]
    fn sample_phase29_contract() -> Phase29RecursiveCompressionInputContract {
        let mut contract = Phase29RecursiveCompressionInputContract {
            proof_backend: StarkProofBackend::Stwo,
            contract_version: STWO_RECURSIVE_COMPRESSION_INPUT_CONTRACT_VERSION_PHASE29.to_string(),
            semantic_scope: STWO_RECURSIVE_COMPRESSION_INPUT_CONTRACT_SCOPE_PHASE29.to_string(),
            phase28_artifact_version:
                STWO_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE28
                    .to_string(),
            phase28_semantic_scope:
                STWO_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_SCOPE_PHASE28
                    .to_string(),
            phase28_proof_backend_version: crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12
                .to_string(),
            statement_version: CLAIM_STATEMENT_VERSION_V1.to_string(),
            required_recursion_posture: STWO_PHASE28_RECURSION_POSTURE_PRE_RECURSIVE.to_string(),
            recursive_verification_claimed: false,
            cryptographic_compression_claimed: false,
            phase28_bounded_aggregation_arity: 2,
            phase28_member_count: 2,
            phase28_member_summaries: 2,
            phase28_nested_members: 2,
            total_phase26_members: 4,
            total_phase25_members: 8,
            max_nested_chain_arity: 2,
            max_nested_fold_arity: 2,
            total_matrices: 16,
            total_layouts: 16,
            total_rollups: 8,
            total_segments: 8,
            total_steps: 32,
            lookup_delta_entries: 12,
            max_lookup_frontier_entries: 4,
            source_template_commitment: "phase28-source-template".to_string(),
            global_start_state_commitment: "phase28-start".to_string(),
            global_end_state_commitment: "phase28-end".to_string(),
            aggregation_template_commitment: "phase28-aggregation-template".to_string(),
            aggregated_chained_folded_interval_accumulator_commitment:
                "phase28-aggregate-accumulator".to_string(),
            input_contract_commitment: String::new(),
        };
        contract.input_contract_commitment =
            commit_phase29_recursive_compression_input_contract(&contract)
                .expect("commit Phase 29 contract");
        contract
    }

    #[cfg(feature = "stwo-backend")]
    fn empty_phase28_shell(
    ) -> Phase28AggregatedChainedFoldedIntervalizedDecodingStateRelationManifest {
        Phase28AggregatedChainedFoldedIntervalizedDecodingStateRelationManifest {
            proof_backend: StarkProofBackend::Stwo,
            artifact_version:
                STWO_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE28
                    .to_string(),
            semantic_scope:
                STWO_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_SCOPE_PHASE28
                    .to_string(),
            proof_backend_version: crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12.to_string(),
            statement_version: CLAIM_STATEMENT_VERSION_V1.to_string(),
            recursion_posture: STWO_PHASE28_RECURSION_POSTURE_PRE_RECURSIVE.to_string(),
            recursive_verification_claimed: false,
            cryptographic_compression_claimed: false,
            bounded_aggregation_arity: 2,
            member_count: 0,
            total_phase26_members: 0,
            total_phase25_members: 0,
            max_nested_chain_arity: 0,
            max_nested_fold_arity: 0,
            total_matrices: 0,
            total_layouts: 0,
            total_rollups: 0,
            total_segments: 0,
            total_steps: 0,
            lookup_delta_entries: 0,
            max_lookup_frontier_entries: 0,
            source_template_commitment: "phase28-source-template".to_string(),
            global_start_state_commitment: "phase28-start".to_string(),
            global_end_state_commitment: "phase28-end".to_string(),
            aggregation_template_commitment: "phase28-aggregation-template".to_string(),
            aggregated_chained_folded_interval_accumulator_commitment:
                "phase28-aggregate-accumulator".to_string(),
            member_summaries: Vec::new(),
            members: Vec::new(),
        }
    }

    #[cfg(feature = "stwo-backend")]
    #[test]
    fn phase29_recursive_compression_input_contract_accepts_committed_shape() {
        let contract = sample_phase29_contract();
        verify_phase29_recursive_compression_input_contract(&contract)
            .expect("verify Phase 29 contract");
    }

    #[cfg(feature = "stwo-backend")]
    #[test]
    fn phase29_recursive_compression_input_contract_rejects_recursive_claim() {
        let mut contract = sample_phase29_contract();
        contract.recursive_verification_claimed = true;
        let err = verify_phase29_recursive_compression_input_contract(&contract)
            .expect_err("recursive claim must be rejected");
        assert!(err
            .to_string()
            .contains("must not claim recursive verification"));
    }

    #[cfg(feature = "stwo-backend")]
    #[test]
    fn phase29_recursive_compression_input_contract_rejects_compression_claim() {
        let mut contract = sample_phase29_contract();
        contract.cryptographic_compression_claimed = true;
        let err = verify_phase29_recursive_compression_input_contract(&contract)
            .expect_err("compression claim must be rejected");
        assert!(err
            .to_string()
            .contains("must not claim cryptographic compression"));
    }

    #[cfg(feature = "stwo-backend")]
    #[test]
    fn phase29_recursive_compression_input_contract_rejects_empty_commitments() {
        let mut contract = sample_phase29_contract();
        contract.source_template_commitment.clear();
        let err = verify_phase29_recursive_compression_input_contract(&contract)
            .expect_err("empty source commitment must be rejected");
        assert!(err.to_string().contains("source_template_commitment"));
    }

    #[cfg(feature = "stwo-backend")]
    #[test]
    fn phase29_recursive_compression_input_contract_rejects_tampered_commitment() {
        let mut contract = sample_phase29_contract();
        contract.total_steps += 1;
        let err = verify_phase29_recursive_compression_input_contract(&contract)
            .expect_err("tampered contract must be rejected");
        assert!(err.to_string().contains("commitment"));
    }

    #[cfg(feature = "stwo-backend")]
    #[test]
    fn phase29_recursive_compression_input_contract_rejects_wrong_phase28_dialect() {
        let mut contract = sample_phase29_contract();
        contract.phase28_proof_backend_version = "unsupported-stwo-dialect".to_string();
        let err = verify_phase29_recursive_compression_input_contract(&contract)
            .expect_err("wrong Phase 28 dialect must be rejected");
        assert!(err
            .to_string()
            .contains("requires Phase 28 proof backend version"));
    }

    #[cfg(feature = "stwo-backend")]
    #[test]
    fn phase29_recursive_compression_input_contract_rejects_wrong_statement_version() {
        let mut contract = sample_phase29_contract();
        contract.statement_version = "unsupported-statement".to_string();
        let err = verify_phase29_recursive_compression_input_contract(&contract)
            .expect_err("wrong statement version must be rejected");
        assert!(err.to_string().contains("requires statement version"));
    }

    #[cfg(feature = "stwo-backend")]
    #[test]
    fn phase29_recursive_compression_input_contract_deserialization_verifies_contract() {
        let contract = sample_phase29_contract();
        let json = serde_json::to_string(&contract).expect("serialize contract");
        let parsed =
            parse_phase29_recursive_compression_input_contract_json(&json).expect("parse contract");
        assert_eq!(parsed, contract);

        let mut tampered = serde_json::to_value(&contract).expect("serialize value");
        tampered["total_steps"] = serde_json::json!(contract.total_steps + 1);
        let err = serde_json::from_value::<Phase29RecursiveCompressionInputContract>(tampered)
            .expect_err("tampered deserialized contract must be rejected");
        assert!(err.to_string().contains("commitment"));
    }

    #[cfg(feature = "stwo-backend")]
    #[test]
    fn phase29_recursive_compression_input_contract_parse_reports_validation_error_as_invalid_config(
    ) {
        let contract = sample_phase29_contract();
        let mut tampered = serde_json::to_value(&contract).expect("serialize value");
        tampered["total_steps"] = serde_json::json!(contract.total_steps + 1);
        let json = serde_json::to_string(&tampered).expect("tampered json");

        let err = parse_phase29_recursive_compression_input_contract_json(&json)
            .expect_err("validation failure must surface as invalid config");
        assert!(
            matches!(err, VmError::InvalidConfig(_)),
            "expected InvalidConfig, got {err:?}"
        );
        assert!(err.to_string().contains("commitment"));
    }

    #[cfg(feature = "stwo-backend")]
    #[test]
    fn phase29_recursive_compression_input_contract_parse_rejects_unknown_fields() {
        let contract = sample_phase29_contract();
        let mut value = serde_json::to_value(&contract).expect("serialize value");
        value["unexpected_phase29_field"] = serde_json::json!(true);
        let json = serde_json::to_string(&value).expect("json with unknown field");

        let err = parse_phase29_recursive_compression_input_contract_json(&json)
            .expect_err("unknown fields must be rejected");
        assert!(
            matches!(err, VmError::InvalidConfig(_)),
            "expected InvalidConfig, got {err:?}"
        );
        assert!(err.to_string().contains("unknown field"));
    }

    #[cfg(feature = "stwo-backend")]
    #[test]
    fn phase29_parse_recursive_compression_input_contract_reports_malformed_json_as_invalid_config()
    {
        let err = parse_phase29_recursive_compression_input_contract_json("{")
            .expect_err("malformed JSON must fail");
        assert!(
            matches!(err, VmError::InvalidConfig(_)),
            "expected InvalidConfig, got {err:?}"
        );
    }

    #[cfg(feature = "stwo-backend")]
    #[test]
    fn phase29_parse_recursive_compression_input_contract_rejects_oversized_json() {
        let json = " ".repeat(MAX_PHASE29_RECURSIVE_COMPRESSION_INPUT_CONTRACT_JSON_BYTES + 1);
        let err = parse_phase29_recursive_compression_input_contract_json(&json)
            .expect_err("oversized JSON must fail before serde parsing");
        assert!(
            matches!(err, VmError::InvalidConfig(_)),
            "expected InvalidConfig, got {err:?}"
        );
        assert!(err.to_string().contains("exceeding the limit"));
    }

    #[cfg(feature = "stwo-backend")]
    #[test]
    fn phase29_load_recursive_compression_input_contract_reports_malformed_json_as_invalid_config()
    {
        use std::io::Write;

        let mut temp = tempfile::NamedTempFile::new().expect("create temp file");
        temp.write_all(b"{").expect("write malformed JSON");

        let err = load_phase29_recursive_compression_input_contract(temp.path())
            .expect_err("malformed Phase 29 contract should fail");
        assert!(
            matches!(err, VmError::InvalidConfig(_)),
            "expected InvalidConfig, got {err:?}"
        );
    }

    #[cfg(feature = "stwo-backend")]
    #[test]
    fn phase29_load_recursive_compression_input_contract_rejects_oversized_file() {
        let path = std::env::temp_dir().join(format!(
            "phase29-recursive-compression-input-contract-oversized-{}.json",
            std::process::id()
        ));
        std::fs::write(
            &path,
            vec![b'x'; MAX_PHASE29_RECURSIVE_COMPRESSION_INPUT_CONTRACT_JSON_BYTES + 1],
        )
        .expect("write");

        let err = load_phase29_recursive_compression_input_contract(&path)
            .expect_err("oversized Phase 29 contract should fail");
        assert!(
            matches!(err, VmError::InvalidConfig(_)),
            "expected InvalidConfig, got {err:?}"
        );
        assert!(err.to_string().contains("exceeding the limit"));
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "stwo-backend")]
    #[test]
    fn phase29_load_recursive_compression_input_contract_rejects_oversized_gzip_file() {
        use flate2::{write::GzEncoder, Compression};
        use std::io::Write;

        let path = std::env::temp_dir().join(format!(
            "phase29-recursive-compression-input-contract-oversized-{}.json.gz",
            std::process::id()
        ));
        let mut encoder = GzEncoder::new(Vec::new(), Compression::none());
        let payload = vec![b'x'; MAX_PHASE29_RECURSIVE_COMPRESSION_INPUT_CONTRACT_JSON_BYTES];
        encoder.write_all(&payload).expect("write gzip payload");
        let bytes = encoder.finish().expect("finish gzip payload");
        assert!(
            bytes.len() > MAX_PHASE29_RECURSIVE_COMPRESSION_INPUT_CONTRACT_JSON_BYTES,
            "gzip fixture must exceed the compressed-byte budget"
        );
        std::fs::write(&path, bytes).expect("write");

        let err = load_phase29_recursive_compression_input_contract(&path)
            .expect_err("oversized compressed Phase 29 contract should fail");
        assert!(
            matches!(err, VmError::InvalidConfig(_)),
            "expected InvalidConfig, got {err:?}"
        );
        assert!(err.to_string().contains("exceeding the limit"));
        let _ = std::fs::remove_file(path);
    }

    #[cfg(feature = "stwo-backend")]
    #[test]
    fn phase29_load_recursive_compression_input_contract_rejects_non_regular_file() {
        let path = std::env::temp_dir().join(format!(
            "phase29-recursive-compression-input-contract-dir-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create dir");

        let err = load_phase29_recursive_compression_input_contract(&path)
            .expect_err("directory path should fail");
        assert!(
            matches!(err, VmError::InvalidConfig(_)),
            "expected InvalidConfig, got {err:?}"
        );
        assert!(err.to_string().contains("is not a regular file"));
        let _ = std::fs::remove_dir_all(path);
    }

    #[cfg(feature = "stwo-backend")]
    #[test]
    fn phase29_prepare_rejects_phase28_recursive_claim_before_contract_derivation() {
        let mut phase28 = empty_phase28_shell();
        phase28.recursive_verification_claimed = true;
        let err = phase29_prepare_recursive_compression_input_contract(&phase28)
            .expect_err("recursive Phase 28 claim must be rejected");
        assert!(err
            .to_string()
            .contains("must not claim recursive verification"));
    }

    #[cfg(feature = "stwo-backend")]
    #[test]
    fn phase29_prepare_rejects_phase28_synthetic_shell_without_nested_members() {
        let phase28 = empty_phase28_shell();
        let err = phase29_prepare_recursive_compression_input_contract(&phase28)
            .expect_err("empty Phase 28 shell must be rejected");
        assert!(err
            .to_string()
            .contains("must contain at least two members"));
    }
}
