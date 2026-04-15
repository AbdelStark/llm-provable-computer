mod adapter;
#[cfg(feature = "stwo-backend")]
mod arithmetic_component;
#[cfg(feature = "stwo-backend")]
mod arithmetic_subset_prover;
#[cfg(feature = "stwo-backend")]
mod decoding;
mod layout;
#[cfg(feature = "stwo-backend")]
mod lookup_component;
#[cfg(feature = "stwo-backend")]
mod lookup_prover;
#[cfg(feature = "stwo-backend")]
mod normalization_component;
#[cfg(feature = "stwo-backend")]
mod normalization_prover;
mod recursion;
#[cfg(feature = "stwo-backend")]
mod shared_lookup_artifact;

use crate::config::Attention2DMode;
use crate::error::{Result, VmError};
use crate::instruction::Program;

pub use adapter::{
    phase2_dependency_seam, StwoDependencySeam, STWO_CONSTRAINT_FRAMEWORK_VERSION_PHASE2,
    STWO_CRATE_VERSION_PHASE2,
};
#[cfg(feature = "stwo-backend")]
pub use arithmetic_component::{
    phase3_arithmetic_component_metadata, phase3_arithmetic_preprocessed_columns,
    Phase3ArithmeticComponentMetadata, Phase3TreeSubspan,
};
#[cfg(feature = "stwo-backend")]
pub(crate) use arithmetic_subset_prover::{
    prove_phase5_arithmetic_subset, verify_phase5_arithmetic_subset,
};
#[cfg(feature = "stwo-backend")]
pub use decoding::{
    decoding_step_v1_program_with_initial_memory, decoding_step_v1_template_program,
    decoding_step_v2_program_with_initial_memory, decoding_step_v2_template_program,
    derive_phase11_from_final_memory, derive_phase11_from_program_initial_state,
    derive_phase12_from_final_memory, derive_phase12_from_program_initial_state,
    infer_phase12_decoding_layout, load_phase11_decoding_chain, load_phase12_decoding_chain,
    load_phase13_decoding_layout_matrix, load_phase14_decoding_chain,
    load_phase15_decoding_segment_bundle, load_phase16_decoding_segment_rollup,
    load_phase17_decoding_rollup_matrix, load_phase21_decoding_matrix_accumulator,
    load_phase22_decoding_lookup_accumulator, load_phase23_decoding_cross_step_lookup_accumulator,
    load_phase24_decoding_state_relation_accumulator,
    load_phase25_intervalized_decoding_state_relation,
    load_phase26_folded_intervalized_decoding_state_relation,
    load_phase27_chained_folded_intervalized_decoding_state_relation,
    load_phase27_chained_folded_intervalized_decoding_state_relation_with_proof_checks,
    load_phase28_aggregated_chained_folded_intervalized_decoding_state_relation,
    load_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_proof_checks,
    load_phase30_decoding_step_proof_envelope_manifest, matches_decoding_step_v1_family,
    matches_decoding_step_v2_family, parse_phase30_decoding_step_proof_envelope_manifest_json,
    phase11_prepare_decoding_chain, phase12_default_decoding_layout,
    phase12_prepare_decoding_chain, phase13_default_decoding_layout_matrix,
    phase14_prepare_decoding_chain, phase15_default_segment_step_limit,
    phase15_prepare_segment_bundle, phase16_default_rollup_segment_limit,
    phase16_prepare_segment_rollup, phase21_prepare_decoding_matrix_accumulator,
    phase22_prepare_decoding_lookup_accumulator,
    phase23_prepare_decoding_cross_step_lookup_accumulator,
    phase24_prepare_decoding_state_relation_accumulator,
    phase25_prepare_intervalized_decoding_state_relation,
    phase26_prepare_folded_intervalized_decoding_state_relation,
    phase27_prepare_chained_folded_intervalized_decoding_state_relation,
    phase28_prepare_aggregated_chained_folded_intervalized_decoding_state_relation,
    phase30_prepare_decoding_step_proof_envelope_manifest, prove_phase11_decoding_demo,
    prove_phase12_decoding_demo, prove_phase12_decoding_demo_for_layout,
    prove_phase13_decoding_layout_matrix_demo, prove_phase14_decoding_demo,
    prove_phase14_decoding_demo_for_layout, prove_phase15_decoding_demo,
    prove_phase15_decoding_demo_for_layout, prove_phase16_decoding_demo,
    prove_phase16_decoding_demo_for_layout, prove_phase17_decoding_rollup_matrix_demo,
    prove_phase21_decoding_matrix_accumulator_demo, prove_phase22_decoding_lookup_accumulator_demo,
    prove_phase23_decoding_cross_step_lookup_accumulator_demo,
    prove_phase24_decoding_state_relation_accumulator_demo,
    prove_phase25_intervalized_decoding_state_relation_demo,
    prove_phase26_folded_intervalized_decoding_state_relation_demo,
    prove_phase27_chained_folded_intervalized_decoding_state_relation_demo,
    prove_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_demo,
    save_phase11_decoding_chain, save_phase12_decoding_chain, save_phase13_decoding_layout_matrix,
    save_phase14_decoding_chain, save_phase15_decoding_segment_bundle,
    save_phase16_decoding_segment_rollup, save_phase17_decoding_rollup_matrix,
    save_phase21_decoding_matrix_accumulator, save_phase22_decoding_lookup_accumulator,
    save_phase23_decoding_cross_step_lookup_accumulator,
    save_phase24_decoding_state_relation_accumulator,
    save_phase25_intervalized_decoding_state_relation,
    save_phase26_folded_intervalized_decoding_state_relation,
    save_phase27_chained_folded_intervalized_decoding_state_relation,
    save_phase28_aggregated_chained_folded_intervalized_decoding_state_relation,
    save_phase30_decoding_step_proof_envelope_manifest, verify_phase11_decoding_chain,
    verify_phase11_decoding_chain_with_proof_checks, verify_phase12_decoding_chain,
    verify_phase12_decoding_chain_with_proof_checks, verify_phase13_decoding_layout_matrix,
    verify_phase13_decoding_layout_matrix_with_proof_checks, verify_phase14_decoding_chain,
    verify_phase14_decoding_chain_with_proof_checks, verify_phase15_decoding_segment_bundle,
    verify_phase15_decoding_segment_bundle_with_proof_checks,
    verify_phase16_decoding_segment_rollup,
    verify_phase16_decoding_segment_rollup_with_proof_checks,
    verify_phase17_decoding_rollup_matrix, verify_phase17_decoding_rollup_matrix_with_proof_checks,
    verify_phase21_decoding_matrix_accumulator,
    verify_phase21_decoding_matrix_accumulator_with_proof_checks,
    verify_phase22_decoding_lookup_accumulator,
    verify_phase22_decoding_lookup_accumulator_with_proof_checks,
    verify_phase23_decoding_cross_step_lookup_accumulator,
    verify_phase23_decoding_cross_step_lookup_accumulator_with_proof_checks,
    verify_phase24_decoding_state_relation_accumulator,
    verify_phase24_decoding_state_relation_accumulator_with_proof_checks,
    verify_phase25_intervalized_decoding_state_relation,
    verify_phase25_intervalized_decoding_state_relation_with_proof_checks,
    verify_phase26_folded_intervalized_decoding_state_relation,
    verify_phase26_folded_intervalized_decoding_state_relation_with_proof_checks,
    verify_phase27_chained_folded_intervalized_decoding_state_relation,
    verify_phase27_chained_folded_intervalized_decoding_state_relation_with_proof_checks,
    verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation,
    verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_proof_checks,
    verify_phase30_decoding_step_proof_envelope_manifest,
    verify_phase30_decoding_step_proof_envelope_manifest_against_chain,
    Phase11DecodingChainManifest, Phase11DecodingState, Phase11DecodingStep,
    Phase12DecodingChainManifest, Phase12DecodingLayout, Phase12DecodingState, Phase12DecodingStep,
    Phase13DecodingLayoutMatrixManifest, Phase14DecodingChainManifest, Phase14DecodingState,
    Phase14DecodingStep, Phase15DecodingHistorySegment,
    Phase15DecodingHistorySegmentBundleManifest, Phase16DecodingHistoryRollup,
    Phase16DecodingHistoryRollupManifest, Phase17DecodingHistoryRollupMatrixManifest,
    Phase21DecodingMatrixAccumulatorManifest, Phase22DecodingLookupAccumulatorManifest,
    Phase23DecodingCrossStepLookupAccumulatorManifest,
    Phase24DecodingStateRelationAccumulatorManifest, Phase24DecodingStateRelationMemberSummary,
    Phase25IntervalizedDecodingStateRelationManifest,
    Phase25IntervalizedDecodingStateRelationMemberSummary,
    Phase26FoldedIntervalizedDecodingStateRelationManifest,
    Phase26FoldedIntervalizedDecodingStateRelationMemberSummary,
    Phase27ChainedFoldedIntervalizedDecodingStateRelationManifest,
    Phase27ChainedFoldedIntervalizedDecodingStateRelationMemberSummary,
    Phase28AggregatedChainedFoldedIntervalizedDecodingStateRelationManifest,
    Phase28AggregatedChainedFoldedIntervalizedDecodingStateRelationMemberSummary,
    Phase30DecodingStepProofEnvelope, Phase30DecodingStepProofEnvelopeManifest,
    STWO_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_SCOPE_PHASE28,
    STWO_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE28,
    STWO_CHAINED_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_SCOPE_PHASE27,
    STWO_CHAINED_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE27,
    STWO_DECODING_CHAIN_SCOPE_PHASE11, STWO_DECODING_CHAIN_SCOPE_PHASE12,
    STWO_DECODING_CHAIN_SCOPE_PHASE14, STWO_DECODING_CHAIN_VERSION_PHASE11,
    STWO_DECODING_CHAIN_VERSION_PHASE12, STWO_DECODING_CHAIN_VERSION_PHASE14,
    STWO_DECODING_CROSS_STEP_LOOKUP_ACCUMULATOR_SCOPE_PHASE23,
    STWO_DECODING_CROSS_STEP_LOOKUP_ACCUMULATOR_VERSION_PHASE23,
    STWO_DECODING_LAYOUT_MATRIX_SCOPE_PHASE13, STWO_DECODING_LAYOUT_MATRIX_VERSION_PHASE13,
    STWO_DECODING_LAYOUT_VERSION_PHASE12, STWO_DECODING_LOOKUP_ACCUMULATOR_SCOPE_PHASE22,
    STWO_DECODING_LOOKUP_ACCUMULATOR_VERSION_PHASE22,
    STWO_DECODING_MATRIX_ACCUMULATOR_SCOPE_PHASE21,
    STWO_DECODING_MATRIX_ACCUMULATOR_VERSION_PHASE21, STWO_DECODING_ROLLUP_MATRIX_SCOPE_PHASE17,
    STWO_DECODING_ROLLUP_MATRIX_VERSION_PHASE17, STWO_DECODING_SEGMENT_BUNDLE_SCOPE_PHASE15,
    STWO_DECODING_SEGMENT_BUNDLE_VERSION_PHASE15, STWO_DECODING_SEGMENT_ROLLUP_SCOPE_PHASE16,
    STWO_DECODING_SEGMENT_ROLLUP_VERSION_PHASE16,
    STWO_DECODING_STATE_RELATION_ACCUMULATOR_SCOPE_PHASE24,
    STWO_DECODING_STATE_RELATION_ACCUMULATOR_VERSION_PHASE24, STWO_DECODING_STATE_VERSION_PHASE11,
    STWO_DECODING_STATE_VERSION_PHASE12, STWO_DECODING_STATE_VERSION_PHASE14,
    STWO_DECODING_STEP_ENVELOPE_MANIFEST_SCOPE_PHASE30,
    STWO_DECODING_STEP_ENVELOPE_MANIFEST_VERSION_PHASE30,
    STWO_DECODING_STEP_ENVELOPE_RELATION_PHASE30, STWO_DECODING_STEP_ENVELOPE_SCOPE_PHASE30,
    STWO_DECODING_STEP_ENVELOPE_VERSION_PHASE30,
    STWO_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_SCOPE_PHASE26,
    STWO_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE26,
    STWO_INTERVALIZED_DECODING_STATE_RELATION_SCOPE_PHASE25,
    STWO_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE25,
    STWO_PHASE28_RECURSION_POSTURE_PRE_RECURSIVE,
};
pub use layout::{
    phase2_fixture_matrix, phase2_module_layout, phase2_supported_mnemonics,
    StwoBackendModuleLayout,
};
#[cfg(feature = "stwo-backend")]
pub use lookup_component::{
    phase3_binary_step_lookup_component_metadata, phase3_lookup_preprocessed_columns,
    phase3_lookup_table_rows, Phase3LookupComponentMetadata, Phase3LookupTableRow,
};
#[cfg(feature = "stwo-backend")]
pub use lookup_prover::{
    load_phase10_shared_binary_step_lookup_proof, load_phase3_binary_step_lookup_proof,
    prove_phase10_shared_binary_step_lookup_envelope, prove_phase3_binary_step_lookup_demo,
    prove_phase3_binary_step_lookup_demo_envelope, save_phase10_shared_binary_step_lookup_proof,
    save_phase3_binary_step_lookup_proof, verify_phase10_shared_binary_step_lookup_envelope,
    verify_phase3_binary_step_lookup_demo, verify_phase3_binary_step_lookup_demo_envelope,
    Phase10SharedLookupProofEnvelope, Phase3LookupProofEnvelope, STWO_LOOKUP_PROOF_VERSION_PHASE3,
    STWO_LOOKUP_SEMANTIC_SCOPE_PHASE3, STWO_LOOKUP_STATEMENT_VERSION_PHASE3,
    STWO_SHARED_LOOKUP_PROOF_VERSION_PHASE10, STWO_SHARED_LOOKUP_SEMANTIC_SCOPE_PHASE10,
    STWO_SHARED_LOOKUP_STATEMENT_VERSION_PHASE10,
};
#[cfg(feature = "stwo-backend")]
pub use normalization_component::{
    phase5_normalization_lookup_component_metadata, phase5_normalization_preprocessed_columns,
    phase5_normalization_table_rows, Phase5NormalizationComponentMetadata,
    Phase5NormalizationTableRow,
};
#[cfg(feature = "stwo-backend")]
pub use normalization_prover::{
    load_phase10_shared_normalization_lookup_proof, load_phase5_normalization_lookup_proof,
    prove_phase10_shared_normalization_lookup_envelope, prove_phase5_normalization_lookup_demo,
    prove_phase5_normalization_lookup_demo_envelope,
    save_phase10_shared_normalization_lookup_proof, save_phase5_normalization_lookup_proof,
    verify_phase10_shared_normalization_lookup_envelope, verify_phase5_normalization_lookup_demo,
    verify_phase5_normalization_lookup_demo_envelope,
    Phase10SharedNormalizationLookupProofEnvelope, Phase5NormalizationLookupProofEnvelope,
    STWO_NORMALIZATION_PROOF_VERSION_PHASE5, STWO_NORMALIZATION_SEMANTIC_SCOPE_PHASE5,
    STWO_NORMALIZATION_STATEMENT_VERSION_PHASE5, STWO_SHARED_NORMALIZATION_PROOF_VERSION_PHASE10,
    STWO_SHARED_NORMALIZATION_SEMANTIC_SCOPE_PHASE10,
    STWO_SHARED_NORMALIZATION_STATEMENT_VERSION_PHASE10,
};
#[cfg(feature = "stwo-backend")]
pub use recursion::{
    commit_phase29_recursive_compression_input_contract,
    load_phase29_recursive_compression_input_contract,
    parse_phase29_recursive_compression_input_contract_json,
    phase29_prepare_recursive_compression_input_contract,
    phase29_prepare_recursive_compression_input_contract_from_proof_checked_phase28,
    verify_phase29_recursive_compression_input_contract, Phase29RecursiveCompressionInputContract,
    STWO_RECURSIVE_COMPRESSION_INPUT_CONTRACT_SCOPE_PHASE29,
    STWO_RECURSIVE_COMPRESSION_INPUT_CONTRACT_VERSION_PHASE29,
};
pub use recursion::{
    phase6_prepare_recursion_batch, Phase6RecursionBatchEntry, Phase6RecursionBatchManifest,
    STWO_RECURSION_BATCH_SCOPE_PHASE6, STWO_RECURSION_BATCH_VERSION_PHASE6,
};
#[cfg(feature = "stwo-backend")]
pub use shared_lookup_artifact::{
    commit_phase12_shared_lookup_rows, load_phase12_shared_lookup_artifact,
    save_phase12_shared_lookup_artifact, verify_phase12_shared_lookup_artifact,
    Phase12SharedLookupArtifact, Phase12StaticLookupTableCommitment,
    STWO_SHARED_LOOKUP_ARTIFACT_SCOPE_PHASE12, STWO_SHARED_LOOKUP_ARTIFACT_VERSION_PHASE12,
    STWO_SHARED_STATIC_ACTIVATION_TABLE_ID_PHASE12,
    STWO_SHARED_STATIC_LOOKUP_TABLE_REGISTRY_SCOPE_PHASE12,
    STWO_SHARED_STATIC_LOOKUP_TABLE_REGISTRY_VERSION_PHASE12,
    STWO_SHARED_STATIC_NORMALIZATION_TABLE_ID_PHASE12,
};

/// Backend version label used by the experimental Phase 2 S-two seam.
pub const STWO_BACKEND_VERSION_PHASE2: &str = "stwo-phase2";
/// Backend version label used by the current shipped-fixture `stwo` execution-proof path.
pub const STWO_BACKEND_VERSION_PHASE5: &str = "stwo-phase10-gemma-block-v4";
/// Backend version label used by the fixed-shape proof-carrying decoding demo family.
pub const STWO_BACKEND_VERSION_PHASE11: &str = "stwo-phase11-decoding-step-v1";
/// Backend version label used by the parameterized proof-carrying decoding family.
pub const STWO_BACKEND_VERSION_PHASE12: &str = "stwo-phase12-decoding-family-v9";
/// Cargo feature that enables the experimental S-two backend seam.
pub const STWO_BACKEND_FEATURE_NAME: &str = "stwo-backend";

/// Returns whether the binary was built with the experimental S-two backend feature.
pub fn is_enabled() -> bool {
    cfg!(feature = "stwo-backend")
}

/// Validates that a program fits the current Phase 2 S-two proof shape.
pub fn validate_phase2_proof_shape(
    program: &Program,
    attention_mode: &Attention2DMode,
) -> Result<()> {
    ensure_feature_enabled()?;

    if program.instructions().is_empty() {
        return Err(VmError::UnsupportedProof(
            "S-two backend Phase 2 does not accept empty programs".to_string(),
        ));
    }

    if !matches!(attention_mode, Attention2DMode::AverageHard) {
        return Err(VmError::UnsupportedProof(format!(
            "S-two backend Phase 2 supports only `average-hard` attention, got `{attention_mode}`"
        )));
    }

    layout::validate_phase2_instruction_subset(program)
}

/// Returns the placeholder error emitted by `prove-stark --backend stwo` in Phase 2.
pub fn phase2_placeholder_prove_error() -> VmError {
    if !is_enabled() {
        return feature_gate_error();
    }

    let seam = phase2_dependency_seam();
    VmError::UnsupportedProof(format!(
        "S-two backend Phase 2 adapter seam is present (official crates: {} {}, {} {}; modules: {}, {}), but proving is not implemented yet in binaries built without the `stwo-backend` feature; the feature-gated implementation now covers real proof paths for the shipped arithmetic fixtures plus a separate normalization lookup demo",
        seam.stwo_crate,
        seam.stwo_crate_version,
        seam.constraint_framework_crate,
        seam.constraint_framework_version,
        seam.adapter_module,
        seam.layout_module
    ))
}

/// Returns the placeholder error emitted by `verify-stark --backend stwo` in Phase 2.
pub fn phase2_placeholder_verify_error() -> VmError {
    if !is_enabled() {
        return feature_gate_error();
    }

    let seam = phase2_dependency_seam();
    VmError::UnsupportedProof(format!(
        "S-two backend Phase 2 adapter seam is present (official crates: {} {}, {} {}; modules: {}, {}), but verification is not implemented yet in binaries built without the `stwo-backend` feature; the feature-gated implementation now covers real proof paths for the shipped arithmetic fixtures plus a separate normalization lookup demo",
        seam.stwo_crate,
        seam.stwo_crate_version,
        seam.constraint_framework_crate,
        seam.constraint_framework_version,
        seam.adapter_module,
        seam.layout_module
    ))
}

fn ensure_feature_enabled() -> Result<()> {
    if is_enabled() {
        return Ok(());
    }

    Err(feature_gate_error())
}

fn feature_gate_error() -> VmError {
    VmError::UnsupportedProof(format!(
        "S-two backend requires building with `--features {STWO_BACKEND_FEATURE_NAME}`"
    ))
}
