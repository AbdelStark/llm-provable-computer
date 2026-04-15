pub mod assembly;
#[cfg(feature = "burn-model")]
pub mod burn_model;
#[cfg(feature = "burn-model")]
pub mod burn_runtime;
pub mod compiler;
pub mod config;
pub mod engine;
pub mod error;
pub mod geometry;
pub mod instruction;
pub mod interpreter;
pub mod memory;
pub mod model;
#[cfg(feature = "onnx-export")]
pub mod onnx_export;
#[cfg(feature = "onnx-export")]
pub mod onnx_runtime;
pub mod proof;
pub mod runtime;
pub mod state;
pub mod stwo_backend;
pub mod tui;
pub mod vanillastark;
pub mod verification;

pub use assembly::parse_program;
#[cfg(feature = "burn-model")]
pub use burn_model::{
    load_burn_model, load_burn_model_on_device, save_burn_model, BurnTransformerVm,
};
#[cfg(feature = "burn-model")]
pub use burn_runtime::BurnExecutionRuntime;
pub use compiler::ProgramCompiler;
pub use config::{Attention2DMode, TransformerVmConfig};
pub use engine::{
    ExecutionEngine, ExecutionResult, ExecutionTraceEntry, VerificationResult, VerifiedEngine,
};
pub use error::{Result, VmError};
pub use geometry::{HullKvCache, Point2D};
pub use instruction::{Instruction, Program};
pub use interpreter::{NativeExecutionResult, NativeInterpreter, NativeTraceEntry};
pub use memory::AddressedMemory;
pub use model::{DispatchInfo, TransformerVm};
#[cfg(feature = "onnx-export")]
pub use onnx_export::{
    export_program_onnx, load_onnx_program_metadata, OnnxInputLayoutEntry, OnnxInstructionMetadata,
    OnnxInstructionRead, OnnxProgramMetadata, ONNX_OUTPUT_DIM,
};
#[cfg(feature = "onnx-export")]
pub use onnx_runtime::OnnxExecutionRuntime;
pub use proof::{
    conjectured_security_bits, load_execution_stark_proof, production_v1_stark_options,
    prove_execution_stark, prove_execution_stark_with_backend_and_options,
    prove_execution_stark_with_options, save_execution_stark_proof, verify_execution_stark,
    verify_execution_stark_with_backend_and_policy, verify_execution_stark_with_policy,
    verify_execution_stark_with_reexecution, verify_execution_stark_with_reexecution_and_policy,
    ExecutionClaimCommitments, ExecutionEquivalenceMetadata, StarkProofBackend,
    StarkVerificationPolicy, StwoAuxiliaryProofs, StwoNormalizationCompanion,
    VanillaStarkExecutionClaim, VanillaStarkExecutionProof, VanillaStarkProofOptions,
    CLAIM_COMMITMENT_HASH_FUNCTION_V1, CLAIM_COMMITMENT_SCHEME_VERSION_V1, CLAIM_SEMANTIC_SCOPE_V1,
    CLAIM_STATEMENT_VERSION_V1, PRODUCTION_V1_MIN_CONJECTURED_SECURITY_BITS,
    PRODUCTION_V1_TARGET_MAX_PROVING_SECONDS,
};
pub use runtime::ExecutionRuntime;
pub use state::{decode_state, encode_state, MachineState, MIN_D_MODEL};
#[cfg(feature = "stwo-backend")]
pub use stwo_backend::{
    commit_phase29_recursive_compression_input_contract,
    load_phase29_recursive_compression_input_contract,
    parse_phase29_recursive_compression_input_contract_json,
    phase29_prepare_recursive_compression_input_contract,
    phase29_prepare_recursive_compression_input_contract_from_proof_checked_phase28,
    verify_phase29_recursive_compression_input_contract, Phase29RecursiveCompressionInputContract,
    STWO_RECURSIVE_COMPRESSION_INPUT_CONTRACT_SCOPE_PHASE29,
    STWO_RECURSIVE_COMPRESSION_INPUT_CONTRACT_VERSION_PHASE29,
};
#[cfg(feature = "stwo-backend")]
pub use stwo_backend::{
    decoding_step_v1_program_with_initial_memory, decoding_step_v1_template_program,
    decoding_step_v2_program_with_initial_memory, decoding_step_v2_template_program,
    load_phase10_shared_binary_step_lookup_proof, load_phase10_shared_normalization_lookup_proof,
    load_phase11_decoding_chain, load_phase12_decoding_chain, load_phase12_shared_lookup_artifact,
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
    load_phase30_decoding_step_proof_envelope_manifest, load_phase3_binary_step_lookup_proof,
    load_phase5_normalization_lookup_proof, matches_decoding_step_v1_family,
    matches_decoding_step_v2_family, phase11_prepare_decoding_chain,
    phase12_default_decoding_layout, phase12_prepare_decoding_chain,
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
    phase30_prepare_decoding_step_proof_envelope_manifest, phase3_arithmetic_component_metadata,
    phase3_arithmetic_preprocessed_columns, phase3_binary_step_lookup_component_metadata,
    phase3_lookup_preprocessed_columns, phase3_lookup_table_rows,
    phase5_normalization_lookup_component_metadata,
    prove_phase10_shared_binary_step_lookup_envelope,
    prove_phase10_shared_normalization_lookup_envelope, prove_phase11_decoding_demo,
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
    prove_phase3_binary_step_lookup_demo, prove_phase3_binary_step_lookup_demo_envelope,
    prove_phase5_normalization_lookup_demo, prove_phase5_normalization_lookup_demo_envelope,
    save_phase10_shared_binary_step_lookup_proof, save_phase10_shared_normalization_lookup_proof,
    save_phase11_decoding_chain, save_phase12_decoding_chain, save_phase12_shared_lookup_artifact,
    save_phase13_decoding_layout_matrix, save_phase14_decoding_chain,
    save_phase15_decoding_segment_bundle, save_phase16_decoding_segment_rollup,
    save_phase17_decoding_rollup_matrix, save_phase21_decoding_matrix_accumulator,
    save_phase22_decoding_lookup_accumulator, save_phase23_decoding_cross_step_lookup_accumulator,
    save_phase24_decoding_state_relation_accumulator,
    save_phase25_intervalized_decoding_state_relation,
    save_phase26_folded_intervalized_decoding_state_relation,
    save_phase27_chained_folded_intervalized_decoding_state_relation,
    save_phase28_aggregated_chained_folded_intervalized_decoding_state_relation,
    save_phase30_decoding_step_proof_envelope_manifest, save_phase3_binary_step_lookup_proof,
    save_phase5_normalization_lookup_proof, verify_phase10_shared_binary_step_lookup_envelope,
    verify_phase10_shared_normalization_lookup_envelope, verify_phase11_decoding_chain,
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
    verify_phase3_binary_step_lookup_demo, verify_phase3_binary_step_lookup_demo_envelope,
    verify_phase5_normalization_lookup_demo, verify_phase5_normalization_lookup_demo_envelope,
    Phase10SharedLookupProofEnvelope, Phase10SharedNormalizationLookupProofEnvelope,
    Phase11DecodingChainManifest, Phase11DecodingState, Phase11DecodingStep,
    Phase12DecodingChainManifest, Phase12DecodingLayout, Phase12DecodingState, Phase12DecodingStep,
    Phase12SharedLookupArtifact, Phase12StaticLookupTableCommitment,
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
    Phase3ArithmeticComponentMetadata, Phase3LookupComponentMetadata, Phase3LookupProofEnvelope,
    Phase3LookupTableRow, Phase3TreeSubspan, Phase5NormalizationComponentMetadata,
    Phase5NormalizationLookupProofEnvelope,
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
    STWO_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_SCOPE_PHASE26,
    STWO_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE26,
    STWO_INTERVALIZED_DECODING_STATE_RELATION_SCOPE_PHASE25,
    STWO_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE25, STWO_LOOKUP_PROOF_VERSION_PHASE3,
    STWO_LOOKUP_SEMANTIC_SCOPE_PHASE3, STWO_LOOKUP_STATEMENT_VERSION_PHASE3,
    STWO_NORMALIZATION_PROOF_VERSION_PHASE5, STWO_NORMALIZATION_SEMANTIC_SCOPE_PHASE5,
    STWO_NORMALIZATION_STATEMENT_VERSION_PHASE5, STWO_PHASE28_RECURSION_POSTURE_PRE_RECURSIVE,
    STWO_SHARED_LOOKUP_ARTIFACT_SCOPE_PHASE12, STWO_SHARED_LOOKUP_ARTIFACT_VERSION_PHASE12,
    STWO_SHARED_LOOKUP_PROOF_VERSION_PHASE10, STWO_SHARED_LOOKUP_SEMANTIC_SCOPE_PHASE10,
    STWO_SHARED_LOOKUP_STATEMENT_VERSION_PHASE10, STWO_SHARED_NORMALIZATION_PROOF_VERSION_PHASE10,
    STWO_SHARED_NORMALIZATION_SEMANTIC_SCOPE_PHASE10,
    STWO_SHARED_NORMALIZATION_STATEMENT_VERSION_PHASE10,
    STWO_SHARED_STATIC_ACTIVATION_TABLE_ID_PHASE12,
    STWO_SHARED_STATIC_LOOKUP_TABLE_REGISTRY_SCOPE_PHASE12,
    STWO_SHARED_STATIC_LOOKUP_TABLE_REGISTRY_VERSION_PHASE12,
    STWO_SHARED_STATIC_NORMALIZATION_TABLE_ID_PHASE12,
};
pub use stwo_backend::{
    is_enabled as stwo_backend_enabled, phase2_dependency_seam, phase2_fixture_matrix,
    phase2_module_layout, phase2_supported_mnemonics, phase6_prepare_recursion_batch,
    Phase6RecursionBatchEntry, Phase6RecursionBatchManifest, StwoBackendModuleLayout,
    StwoDependencySeam, STWO_BACKEND_FEATURE_NAME, STWO_BACKEND_VERSION_PHASE12,
    STWO_BACKEND_VERSION_PHASE2, STWO_CONSTRAINT_FRAMEWORK_VERSION_PHASE2,
    STWO_CRATE_VERSION_PHASE2, STWO_RECURSION_BATCH_SCOPE_PHASE6,
    STWO_RECURSION_BATCH_VERSION_PHASE6,
};
pub use tui::run_execution_tui;
pub use verification::{verify_engines, verify_model_against_native, ExecutionComparison};
