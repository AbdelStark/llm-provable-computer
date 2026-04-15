use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;
#[cfg(feature = "onnx-export")]
use std::time::{SystemTime, UNIX_EPOCH};

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
#[cfg(feature = "burn-model")]
use burn::backend::NdArray;
use clap::{Parser, Subcommand, ValueEnum};
#[cfg(any(feature = "burn-model", feature = "onnx-export"))]
use llm_provable_computer::verify_engines;
use llm_provable_computer::{
    conjectured_security_bits, load_execution_stark_proof, phase6_prepare_recursion_batch,
    production_v1_stark_options, prove_execution_stark_with_backend_and_options, run_execution_tui,
    save_execution_stark_proof, verify_execution_stark_with_backend_and_policy,
    verify_execution_stark_with_reexecution_and_policy, verify_model_against_native,
    Attention2DMode, ExecutionResult, ExecutionRuntime, ExecutionTraceEntry, MachineState,
    NativeInterpreter, ProgramCompiler, StarkProofBackend, StarkVerificationPolicy, TransformerVm,
    TransformerVmConfig, VanillaStarkExecutionProof, VanillaStarkProofOptions, VmError,
    PRODUCTION_V1_MIN_CONJECTURED_SECURITY_BITS, PRODUCTION_V1_TARGET_MAX_PROVING_SECONDS,
    STWO_RECURSION_BATCH_SCOPE_PHASE6, STWO_RECURSION_BATCH_VERSION_PHASE6,
};
#[cfg(feature = "onnx-export")]
use llm_provable_computer::{export_program_onnx, OnnxExecutionRuntime};
#[cfg(feature = "stwo-backend")]
use llm_provable_computer::{
    load_phase10_shared_binary_step_lookup_proof, load_phase10_shared_normalization_lookup_proof,
    load_phase11_decoding_chain, load_phase12_decoding_chain, load_phase12_shared_lookup_artifact,
    load_phase13_decoding_layout_matrix, load_phase14_decoding_chain,
    load_phase15_decoding_segment_bundle, load_phase16_decoding_segment_rollup,
    load_phase17_decoding_rollup_matrix, load_phase21_decoding_matrix_accumulator,
    load_phase22_decoding_lookup_accumulator, load_phase23_decoding_cross_step_lookup_accumulator,
    load_phase24_decoding_state_relation_accumulator,
    load_phase25_intervalized_decoding_state_relation,
    load_phase26_folded_intervalized_decoding_state_relation,
    load_phase27_chained_folded_intervalized_decoding_state_relation_with_proof_checks,
    load_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_proof_checks,
    load_phase29_recursive_compression_input_contract,
    load_phase30_decoding_step_proof_envelope_manifest, load_phase3_binary_step_lookup_proof,
    load_phase5_normalization_lookup_proof,
    phase29_prepare_recursive_compression_input_contract_from_proof_checked_phase28,
    phase30_prepare_decoding_step_proof_envelope_manifest,
    prove_phase10_shared_binary_step_lookup_envelope,
    prove_phase10_shared_normalization_lookup_envelope, prove_phase11_decoding_demo,
    prove_phase12_decoding_demo, prove_phase13_decoding_layout_matrix_demo,
    prove_phase14_decoding_demo, prove_phase15_decoding_demo, prove_phase16_decoding_demo,
    prove_phase17_decoding_rollup_matrix_demo, prove_phase21_decoding_matrix_accumulator_demo,
    prove_phase22_decoding_lookup_accumulator_demo,
    prove_phase23_decoding_cross_step_lookup_accumulator_demo,
    prove_phase24_decoding_state_relation_accumulator_demo,
    prove_phase25_intervalized_decoding_state_relation_demo,
    prove_phase26_folded_intervalized_decoding_state_relation_demo,
    prove_phase27_chained_folded_intervalized_decoding_state_relation_demo,
    prove_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_demo,
    prove_phase3_binary_step_lookup_demo_envelope, prove_phase5_normalization_lookup_demo_envelope,
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
    save_phase5_normalization_lookup_proof, stwo_backend_enabled,
    verify_phase10_shared_binary_step_lookup_envelope,
    verify_phase10_shared_normalization_lookup_envelope,
    verify_phase11_decoding_chain_with_proof_checks,
    verify_phase12_decoding_chain_with_proof_checks,
    verify_phase13_decoding_layout_matrix_with_proof_checks,
    verify_phase14_decoding_chain_with_proof_checks,
    verify_phase15_decoding_segment_bundle_with_proof_checks,
    verify_phase16_decoding_segment_rollup_with_proof_checks,
    verify_phase17_decoding_rollup_matrix_with_proof_checks,
    verify_phase21_decoding_matrix_accumulator_with_proof_checks,
    verify_phase22_decoding_lookup_accumulator_with_proof_checks,
    verify_phase23_decoding_cross_step_lookup_accumulator_with_proof_checks,
    verify_phase24_decoding_state_relation_accumulator_with_proof_checks,
    verify_phase25_intervalized_decoding_state_relation_with_proof_checks,
    verify_phase26_folded_intervalized_decoding_state_relation_with_proof_checks,
    verify_phase30_decoding_step_proof_envelope_manifest_against_chain,
    verify_phase3_binary_step_lookup_demo_envelope,
    verify_phase5_normalization_lookup_demo_envelope, Phase29RecursiveCompressionInputContract,
    Phase30DecodingStepProofEnvelopeManifest,
    STWO_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE28,
    STWO_BACKEND_VERSION_PHASE12,
    STWO_CHAINED_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE27,
    STWO_DECODING_CHAIN_SCOPE_PHASE11, STWO_DECODING_CHAIN_SCOPE_PHASE12,
    STWO_DECODING_CHAIN_SCOPE_PHASE14, STWO_DECODING_CHAIN_VERSION_PHASE11,
    STWO_DECODING_CHAIN_VERSION_PHASE12, STWO_DECODING_CHAIN_VERSION_PHASE14,
    STWO_DECODING_CROSS_STEP_LOOKUP_ACCUMULATOR_SCOPE_PHASE23,
    STWO_DECODING_CROSS_STEP_LOOKUP_ACCUMULATOR_VERSION_PHASE23,
    STWO_DECODING_LAYOUT_MATRIX_SCOPE_PHASE13, STWO_DECODING_LAYOUT_MATRIX_VERSION_PHASE13,
    STWO_DECODING_LOOKUP_ACCUMULATOR_SCOPE_PHASE22,
    STWO_DECODING_LOOKUP_ACCUMULATOR_VERSION_PHASE22,
    STWO_DECODING_MATRIX_ACCUMULATOR_SCOPE_PHASE21,
    STWO_DECODING_MATRIX_ACCUMULATOR_VERSION_PHASE21, STWO_DECODING_ROLLUP_MATRIX_SCOPE_PHASE17,
    STWO_DECODING_ROLLUP_MATRIX_VERSION_PHASE17, STWO_DECODING_SEGMENT_BUNDLE_SCOPE_PHASE15,
    STWO_DECODING_SEGMENT_BUNDLE_VERSION_PHASE15, STWO_DECODING_SEGMENT_ROLLUP_SCOPE_PHASE16,
    STWO_DECODING_SEGMENT_ROLLUP_VERSION_PHASE16,
    STWO_DECODING_STATE_RELATION_ACCUMULATOR_SCOPE_PHASE24,
    STWO_DECODING_STATE_RELATION_ACCUMULATOR_VERSION_PHASE24,
    STWO_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE26,
    STWO_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE25, STWO_LOOKUP_PROOF_VERSION_PHASE3,
    STWO_LOOKUP_SEMANTIC_SCOPE_PHASE3, STWO_LOOKUP_STATEMENT_VERSION_PHASE3,
    STWO_NORMALIZATION_PROOF_VERSION_PHASE5, STWO_NORMALIZATION_SEMANTIC_SCOPE_PHASE5,
    STWO_NORMALIZATION_STATEMENT_VERSION_PHASE5,
    STWO_RECURSIVE_COMPRESSION_INPUT_CONTRACT_SCOPE_PHASE29,
    STWO_RECURSIVE_COMPRESSION_INPUT_CONTRACT_VERSION_PHASE29,
};
#[cfg(feature = "burn-model")]
use llm_provable_computer::{BurnExecutionRuntime, BurnTransformerVm};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[cfg(feature = "burn-model")]
type CliBurnBackend = NdArray<f64>;

#[derive(Debug, Parser)]
#[command(
    name = "tvm",
    about = "Run deterministic llm-provable-computer programs."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run a program and print the final machine state.
    Run {
        /// Path to the source `.tvm` program.
        program: PathBuf,
        /// Maximum number of execution steps before stopping.
        #[arg(long, default_value_t = 512)]
        max_steps: usize,
        /// Emit the full step-by-step execution trace.
        #[arg(long)]
        trace: bool,
        /// Number of transformer layers to distribute instructions across.
        #[arg(long, default_value_t = 1)]
        layers: usize,
        /// Execution backend to use for the run.
        #[arg(
            long,
            default_value = "transformer",
            value_parser = parse_execution_engine
        )]
        engine: CliExecutionEngine,
        /// Verify the transformer runtime against the native interpreter.
        #[arg(long)]
        verify_native: bool,
        /// Verify the transformer and native runtimes against Burn.
        #[arg(long)]
        verify_burn: bool,
        /// Verify the transformer and native runtimes against ONNX.
        #[arg(long)]
        verify_onnx: bool,
        /// Verify all available runtimes in lockstep.
        #[arg(long, conflicts_with_all = ["verify_native", "verify_burn", "verify_onnx"])]
        verify_all: bool,
        /// Attention mode to use for memory reads.
        #[arg(
            long,
            default_value = "average-hard",
            value_parser = parse_attention_mode
        )]
        attention_mode: Attention2DMode,
    },
    /// Run the interactive terminal viewer for a program.
    Tui {
        /// Path to the source `.tvm` program.
        program: PathBuf,
        /// Maximum number of execution steps before stopping.
        #[arg(long, default_value_t = 512)]
        max_steps: usize,
        /// Number of transformer layers to distribute instructions across.
        #[arg(long, default_value_t = 1)]
        layers: usize,
        /// UI refresh interval in milliseconds.
        #[arg(long, default_value_t = 60)]
        tick_ms: u64,
        /// Attention mode to use for memory reads.
        #[arg(
            long,
            default_value = "average-hard",
            value_parser = parse_attention_mode
        )]
        attention_mode: Attention2DMode,
    },
    /// Export the compiled program as per-instruction ONNX graphs.
    ExportOnnx {
        /// Path to the source `.tvm` program.
        program: PathBuf,
        /// Directory where ONNX models and metadata will be written.
        #[arg(short = 'o', long = "output-dir")]
        output_dir: PathBuf,
        /// Number of transformer layers to distribute instructions across.
        #[arg(long, default_value_t = 1)]
        layers: usize,
        /// Attention mode to use for memory reads.
        #[arg(
            long,
            default_value = "average-hard",
            value_parser = parse_attention_mode
        )]
        attention_mode: Attention2DMode,
    },
    /// Produce a STARK proof for a supported execution.
    ProveStark {
        /// Path to the source `.tvm` program.
        program: PathBuf,
        /// File where the serialized proof JSON will be written.
        #[arg(short = 'o', long = "output")]
        output: PathBuf,
        /// Maximum number of execution steps before stopping.
        #[arg(long, default_value_t = 512)]
        max_steps: usize,
        /// Number of transformer layers to distribute instructions across.
        #[arg(long, default_value_t = 1)]
        layers: usize,
        /// Attention mode to use for memory reads.
        #[arg(
            long,
            default_value = "average-hard",
            value_parser = parse_attention_mode
        )]
        attention_mode: Attention2DMode,
        /// Named STARK profile (recommended for repeatable proving policy).
        #[arg(long, value_enum, default_value_t = CliStarkProfile::ProductionV1)]
        stark_profile: CliStarkProfile,
        /// STARK blowup factor (must be power of two and >= 4).
        ///
        /// Overrides the selected profile.
        #[arg(long)]
        stark_expansion_factor: Option<usize>,
        /// Number of FRI colinearity checks.
        ///
        /// Overrides the selected profile.
        #[arg(long)]
        stark_num_colinearity_checks: Option<usize>,
        /// Requested STARK security level.
        ///
        /// Overrides the selected profile.
        #[arg(long)]
        stark_security_level: Option<usize>,
        /// Proof backend to use.
        #[arg(long, value_enum, default_value_t = CliProofBackend::Vanilla)]
        backend: CliProofBackend,
    },
    /// Verify a previously generated STARK proof.
    VerifyStark {
        /// Path to the serialized proof JSON file.
        proof: PathBuf,
        /// Verification policy profile.
        #[arg(long, value_enum, default_value_t = CliStarkProfile::ProductionV1)]
        verification_profile: CliStarkProfile,
        /// Re-execute transformer/native runtimes from claim data and check equivalence metadata.
        #[arg(long)]
        reexecute: bool,
        /// Minimum required conjectured security bits.
        #[arg(long, default_value_t = 0)]
        min_conjectured_security: u32,
        /// Apply strict verifier policy (enforces at least 80-bit conjectured security and reexecution).
        #[arg(long)]
        strict: bool,
        /// Optional backend override. When omitted, verification uses the backend encoded in the proof.
        #[arg(long, value_enum)]
        backend: Option<CliProofBackend>,
    },
    /// Produce a serialized S-two normalization lookup demo proof.
    ProveStwoLookupDemo {
        /// File where the serialized proof JSON will be written.
        #[arg(short = 'o', long = "output")]
        output: PathBuf,
    },
    /// Verify a serialized S-two binary-step lookup demo proof.
    VerifyStwoLookupDemo {
        /// Path to the serialized proof JSON file.
        proof: PathBuf,
    },
    /// Produce a serialized S-two normalization lookup demo proof.
    ProveStwoNormalizationDemo {
        /// File where the serialized proof JSON will be written.
        #[arg(short = 'o', long = "output")]
        output: PathBuf,
    },
    /// Verify a serialized S-two normalization lookup demo proof.
    VerifyStwoNormalizationDemo {
        /// Path to the serialized proof JSON file.
        proof: PathBuf,
    },
    /// Produce a serialized S-two shared binary-step lookup proof for two canonical rows.
    ProveStwoSharedLookupDemo {
        /// File where the serialized proof JSON will be written.
        #[arg(short = 'o', long = "output")]
        output: PathBuf,
    },
    /// Verify a serialized S-two shared binary-step lookup proof.
    VerifyStwoSharedLookupDemo {
        /// Path to the serialized proof JSON file.
        proof: PathBuf,
    },
    /// Produce a serialized S-two shared normalization lookup proof for two canonical rows.
    ProveStwoSharedNormalizationDemo {
        /// File where the serialized proof JSON will be written.
        #[arg(short = 'o', long = "output")]
        output: PathBuf,
    },
    /// Verify a serialized S-two shared normalization lookup proof.
    VerifyStwoSharedNormalizationDemo {
        /// Path to the serialized proof JSON file.
        proof: PathBuf,
    },
    /// Produce a serialized proof-carrying decoding chain over three fixed-shape S-two steps.
    ProveStwoDecodingDemo {
        /// File where the serialized chain JSON will be written.
        #[arg(short = 'o', long = "output")]
        output: PathBuf,
    },
    /// Verify a serialized proof-carrying decoding chain.
    VerifyStwoDecodingDemo {
        /// Path to the serialized chain JSON file.
        proof: PathBuf,
    },
    /// Produce a serialized proof-carrying decoding chain over a parameterized S-two step family.
    ProveStwoDecodingFamilyDemo {
        /// File where the serialized chain JSON will be written.
        #[arg(short = 'o', long = "output")]
        output: PathBuf,
    },
    /// Verify a serialized parameterized proof-carrying decoding chain.
    VerifyStwoDecodingFamilyDemo {
        /// Path to the serialized chain JSON file.
        proof: PathBuf,
    },
    #[cfg(feature = "stwo-backend")]
    /// Extract a standalone Phase 12 shared lookup artifact from a verified parameterized decoding chain.
    PrepareStwoSharedLookupArtifact {
        /// Path to the serialized Phase 12 chain JSON or JSON.gz file.
        #[arg(long = "proof")]
        proof: PathBuf,
        /// Optional shared lookup artifact commitment to extract when the chain contains more than one artifact.
        #[arg(long = "artifact-commitment")]
        artifact_commitment: Option<String>,
        /// File where the serialized Phase 12 shared lookup artifact JSON will be written.
        #[arg(short = 'o', long = "output")]
        output: PathBuf,
    },
    #[cfg(feature = "stwo-backend")]
    /// Verify a standalone Phase 12 shared lookup artifact against a verified parameterized decoding chain.
    VerifyStwoSharedLookupArtifact {
        /// Path to the serialized Phase 12 shared lookup artifact JSON or JSON.gz file.
        #[arg(long = "artifact")]
        artifact: PathBuf,
        /// Path to the serialized Phase 12 chain JSON or JSON.gz file.
        #[arg(long = "proof")]
        proof: PathBuf,
    },
    #[cfg(feature = "stwo-backend")]
    /// Derive a Phase 30 proof-envelope manifest from a verified parameterized proof-carrying decoding chain.
    PrepareStwoDecodingStepEnvelopeManifest {
        /// Path to the serialized Phase 12 chain JSON or JSON.gz file.
        #[arg(long = "proof")]
        proof: PathBuf,
        /// File where the serialized Phase 30 manifest JSON will be written.
        #[arg(short = 'o', long = "output")]
        output: PathBuf,
    },
    #[cfg(feature = "stwo-backend")]
    /// Verify a serialized Phase 30 decoding-step proof-envelope manifest.
    VerifyStwoDecodingStepEnvelopeManifest {
        /// Path to the serialized Phase 30 manifest JSON or JSON.gz file.
        #[arg(long = "manifest")]
        manifest: PathBuf,
        /// Optional Phase 12 source chain JSON or JSON.gz file for exact chain binding.
        #[arg(long = "proof")]
        proof: Option<PathBuf>,
    },
    /// Produce a serialized layout matrix over several parameterized proof-carrying decoding chains.
    ProveStwoDecodingLayoutMatrixDemo {
        /// File where the serialized matrix JSON will be written.
        #[arg(short = 'o', long = "output")]
        output: PathBuf,
    },
    /// Verify a serialized layout matrix over parameterized proof-carrying decoding chains.
    VerifyStwoDecodingLayoutMatrixDemo {
        /// Path to the serialized matrix JSON file.
        proof: PathBuf,
    },
    /// Produce a serialized chunked-history decoding chain over a parameterized S-two step family.
    ProveStwoDecodingChunkedHistoryDemo {
        /// File where the serialized chain JSON will be written.
        #[arg(short = 'o', long = "output")]
        output: PathBuf,
    },
    /// Verify a serialized chunked-history decoding chain.
    VerifyStwoDecodingChunkedHistoryDemo {
        /// Path to the serialized chain JSON file.
        proof: PathBuf,
    },
    /// Produce a serialized segment bundle over chunked-history decoding chains.
    ProveStwoDecodingHistorySegmentsDemo {
        /// File where the serialized bundle JSON will be written.
        #[arg(short = 'o', long = "output")]
        output: PathBuf,
    },
    /// Verify a serialized segment bundle over chunked-history decoding chains.
    VerifyStwoDecodingHistorySegmentsDemo {
        /// Path to the serialized bundle JSON file.
        proof: PathBuf,
    },
    /// Produce a serialized rollup over segmented chunked-history decoding bundles.
    ProveStwoDecodingHistoryRollupDemo {
        /// File where the serialized rollup JSON will be written.
        #[arg(short = 'o', long = "output")]
        output: PathBuf,
    },
    /// Verify a serialized rollup over segmented chunked-history decoding bundles.
    VerifyStwoDecodingHistoryRollupDemo {
        /// Path to the serialized rollup JSON file.
        proof: PathBuf,
    },
    /// Produce a serialized matrix over multiple Phase 16 decoding history rollups.
    ProveStwoDecodingHistoryRollupMatrixDemo {
        /// File where the serialized matrix JSON will be written.
        #[arg(short = 'o', long = "output")]
        output: PathBuf,
    },
    /// Verify a serialized matrix over multiple Phase 16 decoding history rollups.
    VerifyStwoDecodingHistoryRollupMatrixDemo {
        /// Path to the serialized matrix JSON file.
        proof: PathBuf,
    },
    /// Produce a serialized accumulator over multiple Phase 17 decoding history rollup matrices.
    ProveStwoDecodingMatrixAccumulatorDemo {
        /// File where the serialized accumulator JSON will be written.
        #[arg(short = 'o', long = "output")]
        output: PathBuf,
    },
    /// Verify a serialized accumulator over multiple Phase 17 decoding history rollup matrices.
    VerifyStwoDecodingMatrixAccumulatorDemo {
        /// Path to the serialized accumulator JSON file.
        proof: PathBuf,
    },
    /// Produce a serialized lookup-accumulator over a Phase 21 decoding matrix accumulator.
    ProveStwoDecodingLookupAccumulatorDemo {
        /// File where the serialized lookup-accumulator JSON will be written.
        #[arg(short = 'o', long = "output")]
        output: PathBuf,
    },
    /// Verify a serialized lookup-accumulator over a Phase 21 decoding matrix accumulator.
    VerifyStwoDecodingLookupAccumulatorDemo {
        /// Path to the serialized lookup-accumulator JSON file.
        proof: PathBuf,
    },
    /// Produce a serialized cross-step lookup accumulator over multiple Phase 22 decoding windows.
    ProveStwoDecodingCrossStepLookupAccumulatorDemo {
        /// File where the serialized cross-step lookup accumulator JSON will be written.
        #[arg(short = 'o', long = "output")]
        output: PathBuf,
    },
    /// Verify a serialized cross-step lookup accumulator over multiple Phase 22 decoding windows.
    VerifyStwoDecodingCrossStepLookupAccumulatorDemo {
        /// Path to the serialized cross-step lookup accumulator JSON file.
        proof: PathBuf,
    },
    /// Produce a serialized full carried-state relation accumulator over multiple Phase 23 members.
    ProveStwoDecodingStateRelationAccumulatorDemo {
        /// File where the serialized state relation accumulator JSON will be written.
        #[arg(short = 'o', long = "output")]
        output: PathBuf,
    },
    /// Verify a serialized full carried-state relation accumulator over multiple Phase 23 members.
    VerifyStwoDecodingStateRelationAccumulatorDemo {
        /// Path to the serialized state relation accumulator JSON file.
        proof: PathBuf,
    },
    /// Produce a serialized intervalized carried-state relation artifact over a Phase 24 source relation.
    ProveStwoIntervalizedDecodingStateRelationDemo {
        /// File where the serialized intervalized state relation JSON will be written.
        #[arg(short = 'o', long = "output")]
        output: PathBuf,
    },
    /// Verify a serialized intervalized carried-state relation artifact over a Phase 24 source relation.
    VerifyStwoIntervalizedDecodingStateRelationDemo {
        /// Path to the serialized intervalized state relation JSON file.
        proof: PathBuf,
    },
    /// Produce a serialized folded intervalized carried-state relation artifact over multiple Phase 25 intervals.
    ProveStwoFoldedIntervalizedDecodingStateRelationDemo {
        /// File where the serialized folded intervalized state relation JSON will be written.
        #[arg(short = 'o', long = "output")]
        output: PathBuf,
    },
    /// Verify a serialized folded intervalized carried-state relation artifact over multiple Phase 25 intervals.
    VerifyStwoFoldedIntervalizedDecodingStateRelationDemo {
        /// Path to the serialized folded intervalized state relation JSON file.
        proof: PathBuf,
    },
    /// Produce a serialized chained folded intervalized carried-state relation artifact over multiple Phase 26 folds.
    ProveStwoChainedFoldedIntervalizedDecodingStateRelationDemo {
        /// File where the serialized chained folded intervalized state relation JSON will be written.
        #[arg(short = 'o', long = "output")]
        output: PathBuf,
    },
    /// Verify a serialized chained folded intervalized carried-state relation artifact over multiple Phase 26 folds.
    VerifyStwoChainedFoldedIntervalizedDecodingStateRelationDemo {
        /// Path to the serialized chained folded intervalized state relation JSON file.
        proof: PathBuf,
    },
    /// Produce a serialized proof-carrying aggregate over multiple Phase 27 chained folded artifacts.
    #[cfg(feature = "stwo-backend")]
    ProveStwoAggregatedChainedFoldedIntervalizedDecodingStateRelationDemo {
        /// File where the serialized aggregated chained folded intervalized state relation JSON will be written.
        #[arg(short = 'o', long = "output")]
        output: PathBuf,
    },
    /// Verify a serialized proof-carrying aggregate over multiple Phase 27 chained folded artifacts.
    #[cfg(feature = "stwo-backend")]
    VerifyStwoAggregatedChainedFoldedIntervalizedDecodingStateRelationDemo {
        /// Path to the serialized aggregated chained folded intervalized state relation JSON file.
        proof: PathBuf,
    },
    /// Derive a Phase 29 recursive-compression input contract from a verified Phase 28 aggregate.
    #[cfg(feature = "stwo-backend")]
    PrepareStwoRecursiveCompressionInputContract {
        /// Path to the serialized Phase 28 aggregate JSON or JSON.gz file.
        #[arg(long = "phase28")]
        phase28: PathBuf,
        /// File where the serialized Phase 29 input contract JSON will be written.
        #[arg(short = 'o', long = "output")]
        output: PathBuf,
    },
    /// Verify a serialized Phase 29 recursive-compression input contract.
    #[cfg(feature = "stwo-backend")]
    VerifyStwoRecursiveCompressionInputContract {
        /// Path to the serialized Phase 29 input contract JSON or JSON.gz file.
        #[arg(long = "input")]
        input: PathBuf,
    },
    /// Prepare a canonical multi-proof batch manifest for future S-two recursion.
    PrepareStwoRecursionBatch {
        /// Proof JSON paths to include in the batch (repeatable).
        #[arg(long = "proof")]
        proofs: Vec<PathBuf>,
        /// File where the serialized batch manifest JSON will be written.
        #[arg(short = 'o', long = "output")]
        output: PathBuf,
    },
    /// Generate a research v2 one-step semantic equivalence artifact (transformer vs ONNX).
    ResearchV2Step {
        /// Path to the source `.tvm` program.
        program: PathBuf,
        /// File where the semantic artifact JSON will be written.
        #[arg(short = 'o', long = "output")]
        output: PathBuf,
        /// Maximum number of execution steps before stopping (must be >= 1).
        #[arg(long, default_value_t = 1)]
        max_steps: usize,
        /// Number of transformer layers to distribute instructions across.
        #[arg(long, default_value_t = 1)]
        layers: usize,
        /// Attention mode to use for memory reads.
        #[arg(
            long,
            default_value = "average-hard",
            value_parser = parse_attention_mode
        )]
        attention_mode: Attention2DMode,
    },
    /// Generate a research v2 prefix-trace semantic equivalence artifact (transformer vs ONNX).
    ResearchV2Trace {
        /// Path to the source `.tvm` program.
        program: PathBuf,
        /// File where the semantic artifact JSON will be written.
        #[arg(short = 'o', long = "output")]
        output: PathBuf,
        /// Maximum number of execution steps to check in the prefix.
        #[arg(long, default_value_t = 32)]
        max_steps: usize,
        /// Number of transformer layers to distribute instructions across.
        #[arg(long, default_value_t = 1)]
        layers: usize,
        /// Attention mode to use for memory reads.
        #[arg(
            long,
            default_value = "average-hard",
            value_parser = parse_attention_mode
        )]
        attention_mode: Attention2DMode,
        /// When set, write artifact and exit success even if a mismatch is found.
        #[arg(long)]
        allow_mismatch: bool,
    },
    /// Generate a research v2 multi-program prefix-trace matrix artifact.
    ResearchV2Matrix {
        /// File where the matrix artifact JSON will be written.
        #[arg(short = 'o', long = "output")]
        output: PathBuf,
        /// Program paths to include in the matrix (repeatable).
        #[arg(long = "program")]
        programs: Vec<PathBuf>,
        /// Include the built-in default suite (addition, counter, fibonacci, multiply,
        /// factorial_recursive, dot_product, matmul_2x2, single_neuron).
        #[arg(long)]
        include_default_suite: bool,
        /// Maximum number of execution steps to check per program.
        #[arg(long, default_value_t = 32)]
        max_steps: usize,
        /// Number of transformer layers to distribute instructions across.
        #[arg(long, default_value_t = 1)]
        layers: usize,
        /// Attention mode to use for memory reads.
        #[arg(
            long,
            default_value = "average-hard",
            value_parser = parse_attention_mode
        )]
        attention_mode: Attention2DMode,
        /// When set, write artifact and exit success even if mismatches are found.
        #[arg(long)]
        allow_mismatch: bool,
    },
    /// Generate a research v3 multi-engine equivalence-kernel artifact.
    ResearchV3Equivalence {
        /// Path to the source `.tvm` program.
        program: PathBuf,
        /// File where the equivalence-kernel artifact JSON will be written.
        #[arg(short = 'o', long = "output")]
        output: PathBuf,
        /// Maximum number of execution steps to check.
        #[arg(long, default_value_t = 32)]
        max_steps: usize,
        /// Number of transformer layers to distribute instructions across.
        #[arg(long, default_value_t = 1)]
        layers: usize,
        /// Attention mode to use for memory reads.
        #[arg(
            long,
            default_value = "average-hard",
            value_parser = parse_attention_mode
        )]
        attention_mode: Attention2DMode,
    },
    /// Verify a research v3 multi-engine equivalence-kernel artifact.
    VerifyResearchV3Equivalence {
        /// Path to the equivalence-kernel artifact JSON file.
        artifact: PathBuf,
    },
    /// Prepare a Hugging Face release/provenance manifest.
    PrepareHfProvenanceManifest {
        /// File where the HF provenance manifest JSON will be written.
        #[arg(short = 'o', long = "output")]
        output: PathBuf,
        /// Hugging Face Hub model or artifact repository, for example `org/model`.
        #[arg(long)]
        hub_repo: String,
        /// Pinned Hugging Face Hub revision, preferably a commit hash or immutable release tag.
        #[arg(long)]
        hub_revision: String,
        /// Tokenizer identifier used for prompt-to-token semantics.
        #[arg(long)]
        tokenizer_id: String,
        /// Tokenizer revision. Defaults to `--hub-revision`.
        #[arg(long)]
        tokenizer_revision: Option<String>,
        /// Optional local `tokenizer.json` file to hash into the manifest.
        #[arg(long)]
        tokenizer_json: Option<PathBuf>,
        /// Optional local tokenizer config file to hash into the manifest.
        #[arg(long)]
        tokenizer_config: Option<PathBuf>,
        /// Optional local prompt/token transcript file to hash into the manifest.
        #[arg(long)]
        tokenization_transcript: Option<PathBuf>,
        /// Local `.safetensors` files to hash and metadata-bind.
        #[arg(long = "safetensors")]
        safetensors_files: Vec<PathBuf>,
        /// Optional local ONNX graph exported from the HF/Optimum path.
        #[arg(long)]
        onnx_model: Option<PathBuf>,
        /// Optional local ONNX metadata companion file to hash into the manifest.
        #[arg(long)]
        onnx_metadata: Option<PathBuf>,
        /// Optional ONNX external-data side files to hash into the manifest.
        #[arg(long = "onnx-external-data")]
        onnx_external_data_files: Vec<PathBuf>,
        /// Name of the ONNX exporter used when `--onnx-model` is supplied.
        #[arg(long, default_value = "optimum-onnx")]
        onnx_exporter: String,
        /// Optional exporter version string.
        #[arg(long)]
        onnx_exporter_version: Option<String>,
        /// Optional local model/artifact card file to hash into the release metadata.
        #[arg(long)]
        model_card: Option<PathBuf>,
        /// Optional DOI or stable release identifier.
        #[arg(long)]
        doi: Option<String>,
        /// Dataset or benchmark corpus identifier used by the release (repeatable).
        #[arg(long = "dataset")]
        datasets: Vec<String>,
        /// Extra manifest note (repeatable).
        #[arg(long = "note")]
        notes: Vec<String>,
    },
    /// Verify a Hugging Face release/provenance manifest and local file bindings.
    VerifyHfProvenanceManifest {
        /// Path to the HF provenance manifest JSON file.
        manifest: PathBuf,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CliExecutionEngine {
    Native,
    Transformer,
    Burn,
    Onnx,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum CliStarkProfile {
    Default,
    ProductionV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum CliProofBackend {
    Vanilla,
    Stwo,
}

impl CliProofBackend {
    fn backend(self) -> StarkProofBackend {
        match self {
            Self::Vanilla => StarkProofBackend::Vanilla,
            Self::Stwo => StarkProofBackend::Stwo,
        }
    }
}

impl std::fmt::Display for CliProofBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Vanilla => f.write_str("vanilla"),
            Self::Stwo => f.write_str("stwo"),
        }
    }
}

impl CliStarkProfile {
    fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::ProductionV1 => "production-v1",
        }
    }

    fn proof_options(self) -> VanillaStarkProofOptions {
        match self {
            Self::Default => VanillaStarkProofOptions::default(),
            Self::ProductionV1 => production_v1_stark_options(),
        }
    }

    fn min_conjectured_security_bits(self) -> u32 {
        match self {
            Self::Default => 0,
            Self::ProductionV1 => PRODUCTION_V1_MIN_CONJECTURED_SECURITY_BITS,
        }
    }

    fn target_max_proving_seconds(self) -> Option<u64> {
        match self {
            Self::Default => None,
            Self::ProductionV1 => Some(PRODUCTION_V1_TARGET_MAX_PROVING_SECONDS),
        }
    }

    fn enforces_reexecution(self) -> bool {
        matches!(self, Self::ProductionV1)
    }
}

impl std::fmt::Display for CliExecutionEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Native => f.write_str("native"),
            Self::Transformer => f.write_str("transformer"),
            Self::Burn => f.write_str("burn"),
            Self::Onnx => f.write_str("onnx"),
        }
    }
}

impl std::fmt::Display for CliStarkProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone)]
struct EngineRunOutput {
    result: ExecutionResult,
    trace: Vec<MachineState>,
    events: Vec<ExecutionTraceEntry>,
}

#[derive(Debug, Clone)]
struct RunCommandOptions {
    program: PathBuf,
    max_steps: usize,
    trace: bool,
    layers: usize,
    engine: CliExecutionEngine,
    verify_native: bool,
    verify_burn: bool,
    verify_onnx: bool,
    verify_all: bool,
    attention_mode: Attention2DMode,
}

#[cfg(feature = "onnx-export")]
const STATEMENT_V2_STEP_SPEC_PATH: &str = "spec/statement-v2-research.json";
#[cfg(feature = "onnx-export")]
const STATEMENT_V2_TRACE_SPEC_PATH: &str = "spec/statement-v2-trace-research.json";
#[cfg(feature = "onnx-export")]
const STATEMENT_V2_MATRIX_SPEC_PATH: &str = "spec/statement-v2-matrix-research.json";
#[cfg(feature = "onnx-export")]
const STATEMENT_V3_EQUIVALENCE_SPEC_PATH: &str =
    "spec/statement-v3-equivalence-kernel-research.json";
#[cfg(feature = "onnx-export")]
const FRONTEND_RUNTIME_SEMANTICS_REGISTRY_PATH: &str =
    "spec/frontend-runtime-semantics-registry-v1.json";
#[cfg(feature = "onnx-export")]
const FRONTEND_RUNTIME_SEMANTICS_REGISTRY_VERSION: &str = "frontend-runtime-semantics-registry-v1";
#[cfg(feature = "onnx-export")]
const FRONTEND_RUNTIME_SEMANTICS_REGISTRY_SCOPE: &str =
    "research_v3_frontend_runtime_claim_boundary";
#[cfg(feature = "onnx-export")]
const FIXED_POINT_SPEC_PATH: &str = "spec/fixed-point-semantics-v2.json";
#[cfg(feature = "onnx-export")]
const ONNX_OP_SUBSET_SPEC_PATH: &str = "spec/onnx-op-subset-v2.json";
#[cfg(feature = "onnx-export")]
const STATEMENT_V2_STEP_ARTIFACT_SCHEMA_PATH: &str =
    "spec/statement-v2-one-step-certificate.schema.json";
#[cfg(feature = "onnx-export")]
const STATEMENT_V2_TRACE_ARTIFACT_SCHEMA_PATH: &str =
    "spec/statement-v2-trace-certificate.schema.json";
#[cfg(feature = "onnx-export")]
const STATEMENT_V2_MATRIX_ARTIFACT_SCHEMA_PATH: &str =
    "spec/statement-v2-matrix-certificate.schema.json";
#[cfg(feature = "onnx-export")]
const STATEMENT_V3_EQUIVALENCE_ARTIFACT_SCHEMA_PATH: &str =
    "spec/statement-v3-equivalence-kernel.schema.json";
#[cfg(feature = "onnx-export")]
const RESEARCH_V2_HASH_FUNCTION: &str = "blake2b-256";
#[cfg(all(feature = "burn-model", feature = "onnx-export"))]
const RESEARCH_V3_RELATION_FORMAT: &str = "multi-engine-trace-relation-v1-no-egraph-no-smt";
const MAX_HF_PROVENANCE_MANIFEST_JSON_BYTES: usize = 8 * 1024 * 1024;
const HF_PROVENANCE_FILE_READ_CHUNK_BYTES: usize = 1024 * 1024;
#[cfg(all(feature = "burn-model", feature = "onnx-export"))]
const MAX_RESEARCH_V3_EQUIVALENCE_ARTIFACT_JSON_BYTES: usize = 32 * 1024 * 1024;
#[cfg(feature = "onnx-export")]
const RESEARCH_V3_PINNED_ENGINE_LANE_BINDINGS: [(&str, &str); 4] = [
    ("transformer", "transformer-vm"),
    ("native", "native-isa"),
    ("burn", "burn"),
    ("onnx/tract", "onnx-tract"),
];
#[cfg(feature = "onnx-export")]
const FRONTEND_RUNTIME_RESEARCH_WATCH_LANES: [&str; 9] = [
    "torch-export",
    "executorch",
    "stablehlo",
    "iree",
    "onnx-mlir",
    "tvm-unity",
    "vllm",
    "sglang",
    "egg-emerge",
];
const HF_PROVENANCE_MANIFEST_VERSION_V1_LEGACY: &str = "hf-provenance-manifest-v1";
const HF_PROVENANCE_MANIFEST_VERSION_V2_LEGACY: &str = "hf-provenance-manifest-v2";
const HF_PROVENANCE_MANIFEST_VERSION_V3_LEGACY: &str = "hf-provenance-manifest-v3";
const HF_PROVENANCE_MANIFEST_VERSION: &str = "hf-provenance-manifest-v4";
const HF_PROVENANCE_SEMANTIC_SCOPE: &str = "hf-release-provenance-boundary-v1";
const HF_PROVENANCE_HASH_FUNCTION: &str = "blake2b-256";

struct HfProvenanceManifestCommand {
    output: PathBuf,
    hub_repo: String,
    hub_revision: String,
    tokenizer_id: String,
    tokenizer_revision: Option<String>,
    tokenizer_json: Option<PathBuf>,
    tokenizer_config: Option<PathBuf>,
    tokenization_transcript: Option<PathBuf>,
    safetensors_files: Vec<PathBuf>,
    onnx_model: Option<PathBuf>,
    onnx_metadata: Option<PathBuf>,
    onnx_external_data_files: Vec<PathBuf>,
    onnx_exporter: String,
    onnx_exporter_version: Option<String>,
    model_card: Option<PathBuf>,
    doi: Option<String>,
    datasets: Vec<String>,
    notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HfFileCommitment {
    path: String,
    size_bytes: u64,
    blake2b_256: String,
    sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HfSafetensorsFileCommitment {
    path: String,
    size_bytes: u64,
    blake2b_256: String,
    sha256: String,
    metadata_hash: String,
    tensor_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HfTokenizerProvenance {
    tokenizer_id: String,
    tokenizer_revision: String,
    tokenizer_json: Option<HfFileCommitment>,
    tokenizer_config: Option<HfFileCommitment>,
    tokenization_transcript: Option<HfFileCommitment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HfOnnxExportProvenance {
    exporter: String,
    exporter_version: Option<String>,
    graph: HfFileCommitment,
    metadata: Option<HfFileCommitment>,
    external_data_files: Vec<HfFileCommitment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HfReleaseMetadata {
    model_card: Option<HfFileCommitment>,
    doi: Option<String>,
    datasets: Vec<String>,
    notes: Vec<String>,
}

#[derive(Debug, Serialize)]
struct HfHubBinding<'a> {
    hub_repo: &'a str,
    hub_revision: &'a str,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HfProvenanceCommitments {
    hub_binding_hash: String,
    tokenizer_hash: String,
    safetensors_manifest_hash: String,
    onnx_export_hash: String,
    release_metadata_hash: String,
    limitations_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HfProvenanceManifest {
    manifest_version: String,
    semantic_scope: String,
    commitment_hash_function: String,
    hub_repo: String,
    hub_revision: String,
    tokenizer: HfTokenizerProvenance,
    safetensors: Vec<HfSafetensorsFileCommitment>,
    onnx_export: Option<HfOnnxExportProvenance>,
    release: HfReleaseMetadata,
    limitations: Vec<String>,
    commitments: HfProvenanceCommitments,
}

#[cfg(feature = "onnx-export")]
#[derive(Debug, Deserialize)]
struct StatementV2ResearchSpec {
    statement_version: String,
    semantic_scope: String,
    fixed_point_profile_ref: String,
    onnx_op_subset_ref: String,
    artifact_schema_ref: String,
}

#[cfg(feature = "onnx-export")]
#[derive(Debug, Deserialize)]
struct FixedPointSemanticsSpec {
    profile_id: String,
}

#[cfg(feature = "onnx-export")]
#[derive(Debug, Deserialize)]
struct OnnxOpSubsetSpec {
    version: String,
    operators: Vec<String>,
}

#[cfg(feature = "onnx-export")]
#[derive(Debug, Clone)]
struct ResearchV2SpecBundle {
    statement_version: String,
    semantic_scope: String,
    fixed_point_profile: String,
    onnx_op_subset_version: String,
    onnx_op_subset_size: usize,
    statement_spec_hash: String,
    fixed_point_spec_hash: String,
    onnx_op_subset_hash: String,
    artifact_schema_hash: String,
}

#[cfg(feature = "onnx-export")]
#[derive(Debug, Serialize)]
struct ResearchV2OneStepCommitments {
    hash_function: String,
    statement_spec_hash: String,
    fixed_point_spec_hash: String,
    onnx_op_subset_hash: String,
    artifact_schema_hash: String,
    program_hash: String,
    transformer_config_hash: String,
    onnx_metadata_hash: String,
    state_before_hash: String,
    transformer_state_after_hash: String,
    onnx_state_after_hash: String,
}

#[cfg(feature = "onnx-export")]
#[derive(Debug, Serialize)]
struct ResearchV2OneStepArtifact {
    statement_version: String,
    semantic_scope: String,
    fixed_point_profile: String,
    onnx_op_subset_version: String,
    onnx_op_subset_size: usize,
    program_path: String,
    checked_steps: usize,
    instruction: String,
    layer_idx: Option<usize>,
    matched: bool,
    state_before: MachineState,
    transformer_state_after: MachineState,
    onnx_state_after: MachineState,
    commitments: ResearchV2OneStepCommitments,
}

#[cfg(feature = "onnx-export")]
#[derive(Debug, Serialize)]
struct ResearchV2TraceCommitments {
    hash_function: String,
    statement_spec_hash: String,
    fixed_point_spec_hash: String,
    onnx_op_subset_hash: String,
    artifact_schema_hash: String,
    program_hash: String,
    transformer_config_hash: String,
    onnx_metadata_hash: String,
    transformer_trace_hash: String,
    onnx_trace_hash: String,
    transformer_final_state_hash: String,
    onnx_final_state_hash: String,
}

#[cfg(feature = "onnx-export")]
#[derive(Debug, Serialize)]
struct ResearchV2TraceArtifact {
    statement_version: String,
    semantic_scope: String,
    fixed_point_profile: String,
    onnx_op_subset_version: String,
    onnx_op_subset_size: usize,
    program_path: String,
    requested_max_steps: usize,
    checked_steps: usize,
    matched: bool,
    first_mismatch_step: Option<usize>,
    mismatch_reason: Option<String>,
    transformer_final_state: MachineState,
    onnx_final_state: MachineState,
    commitments: ResearchV2TraceCommitments,
}

#[cfg(feature = "onnx-export")]
#[derive(Debug, Serialize)]
struct ResearchV2MatrixEntry {
    program_path: String,
    checked_steps: usize,
    matched: bool,
    first_mismatch_step: Option<usize>,
    mismatch_reason: Option<String>,
    transformer_final_state: MachineState,
    onnx_final_state: MachineState,
    commitments: ResearchV2TraceCommitments,
}

#[cfg(feature = "onnx-export")]
#[derive(Debug, Serialize)]
struct ResearchV2MatrixCommitments {
    hash_function: String,
    statement_spec_hash: String,
    fixed_point_spec_hash: String,
    onnx_op_subset_hash: String,
    artifact_schema_hash: String,
    matrix_entries_hash: String,
}

#[cfg(feature = "onnx-export")]
#[derive(Debug, Serialize)]
struct ResearchV2MatrixArtifact {
    statement_version: String,
    semantic_scope: String,
    fixed_point_profile: String,
    onnx_op_subset_version: String,
    onnx_op_subset_size: usize,
    requested_max_steps: usize,
    total_programs: usize,
    matched_programs: usize,
    mismatched_programs: usize,
    entries: Vec<ResearchV2MatrixEntry>,
    commitments: ResearchV2MatrixCommitments,
}

#[cfg(all(feature = "burn-model", feature = "onnx-export"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResearchV3CanonicalEvent {
    step: usize,
    instruction: String,
    state_before_hash: String,
    state_after_hash: String,
}

#[cfg(all(feature = "burn-model", feature = "onnx-export"))]
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResearchV3TransitionRelationRow {
    relation_format: String,
    step: usize,
    instruction: String,
    state_before_hash: String,
    state_after_hash: String,
}

#[cfg(all(feature = "burn-model", feature = "onnx-export"))]
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResearchV3EngineSummary {
    name: String,
    steps: usize,
    halted: bool,
    trace_len: usize,
    events_len: usize,
    trace: Vec<MachineState>,
    canonical_events: Vec<ResearchV3CanonicalEvent>,
    final_state: MachineState,
    trace_hash: String,
    event_relation_hash: String,
    final_state_hash: String,
}

#[cfg(all(feature = "burn-model", feature = "onnx-export"))]
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResearchV3RuleValidation {
    differential_lockstep: bool,
    egraph_status: String,
    smt_status: String,
    randomized_testing_status: String,
}

#[cfg(all(feature = "burn-model", feature = "onnx-export"))]
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResearchV3RuleWitness {
    step: usize,
    rule_id: String,
    relation: String,
    instruction: String,
    participating_engines: Vec<String>,
    state_before_hashes: std::collections::BTreeMap<String, String>,
    state_after_hashes: std::collections::BTreeMap<String, String>,
    engine_transition_hashes: std::collections::BTreeMap<String, String>,
    canonical_transition_hash: String,
    validation: ResearchV3RuleValidation,
}

#[cfg(all(feature = "burn-model", feature = "onnx-export"))]
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResearchV3EquivalenceCommitments {
    hash_function: String,
    statement_spec_hash: String,
    fixed_point_spec_hash: String,
    onnx_op_subset_hash: String,
    artifact_schema_hash: String,
    frontend_runtime_semantics_registry_hash: String,
    relation_format_hash: String,
    limitations_hash: String,
    program_hash: String,
    transformer_config_hash: String,
    onnx_metadata_hash: String,
    engine_summaries_hash: String,
    rule_witnesses_hash: String,
}

#[cfg(all(feature = "burn-model", feature = "onnx-export"))]
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResearchV3EquivalenceArtifact {
    statement_version: String,
    semantic_scope: String,
    relation_format: String,
    fixed_point_profile: String,
    onnx_op_subset_version: String,
    onnx_op_subset_size: usize,
    program_path: String,
    requested_max_steps: usize,
    checked_steps: usize,
    engines: Vec<ResearchV3EngineSummary>,
    rule_witnesses: Vec<ResearchV3RuleWitness>,
    frontend_runtime_semantics_registry: serde_json::Value,
    limitations: Vec<String>,
    commitments: ResearchV3EquivalenceCommitments,
}

#[cfg(feature = "onnx-export")]
struct ScopedTempDir {
    path: PathBuf,
}

#[cfg(feature = "onnx-export")]
impl ScopedTempDir {
    fn new(prefix: &str) -> llm_provable_computer::Result<Self> {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| VmError::InvalidConfig(format!("system clock error: {err}")))?
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "llm-provable-computer-{prefix}-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(feature = "onnx-export")]
impl Drop for ScopedTempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> llm_provable_computer::Result<()> {
    let cli = Cli::parse_from(normalize_args(std::env::args_os()));
    match cli.command {
        Command::Run {
            program,
            max_steps,
            trace,
            layers,
            engine,
            verify_native,
            verify_burn,
            verify_onnx,
            verify_all,
            attention_mode,
        } => run_program_command(RunCommandOptions {
            program,
            max_steps,
            trace,
            layers,
            engine,
            verify_native,
            verify_burn,
            verify_onnx,
            verify_all,
            attention_mode,
        })?,
        Command::Tui {
            program,
            max_steps,
            layers,
            tick_ms,
            attention_mode,
        } => {
            let mut runtime = load_runtime(&program, max_steps, layers, attention_mode)?;
            run_execution_tui(&program, &mut runtime, Duration::from_millis(tick_ms))?;
        }
        Command::ExportOnnx {
            program,
            output_dir,
            layers,
            attention_mode,
        } => export_onnx_command(&program, &output_dir, layers, attention_mode)?,
        Command::ProveStark {
            program,
            output,
            max_steps,
            layers,
            attention_mode,
            stark_profile,
            stark_expansion_factor,
            stark_num_colinearity_checks,
            stark_security_level,
            backend,
        } => {
            let mut options = stark_profile.proof_options();
            if let Some(value) = stark_expansion_factor {
                options.expansion_factor = value;
            }
            if let Some(value) = stark_num_colinearity_checks {
                options.num_colinearity_checks = value;
            }
            if let Some(value) = stark_security_level {
                options.security_level = value;
            }
            prove_stark_command(
                &program,
                &output,
                max_steps,
                layers,
                attention_mode,
                stark_profile,
                backend,
                options,
            )?
        }
        Command::VerifyStark {
            proof,
            verification_profile,
            reexecute,
            min_conjectured_security,
            strict,
            backend,
        } => verify_stark_command(
            &proof,
            verification_profile,
            reexecute,
            min_conjectured_security,
            strict,
            backend,
        )?,
        Command::ProveStwoLookupDemo { output } => prove_stwo_lookup_demo_command(&output)?,
        Command::VerifyStwoLookupDemo { proof } => verify_stwo_lookup_demo_command(&proof)?,
        Command::ProveStwoNormalizationDemo { output } => {
            prove_stwo_normalization_demo_command(&output)?
        }
        Command::VerifyStwoNormalizationDemo { proof } => {
            verify_stwo_normalization_demo_command(&proof)?
        }
        Command::ProveStwoSharedLookupDemo { output } => {
            prove_stwo_shared_lookup_demo_command(&output)?
        }
        Command::VerifyStwoSharedLookupDemo { proof } => {
            verify_stwo_shared_lookup_demo_command(&proof)?
        }
        Command::ProveStwoSharedNormalizationDemo { output } => {
            prove_stwo_shared_normalization_demo_command(&output)?
        }
        Command::VerifyStwoSharedNormalizationDemo { proof } => {
            verify_stwo_shared_normalization_demo_command(&proof)?
        }
        Command::ProveStwoDecodingDemo { output } => prove_stwo_decoding_demo_command(&output)?,
        Command::VerifyStwoDecodingDemo { proof } => verify_stwo_decoding_demo_command(&proof)?,
        Command::ProveStwoDecodingFamilyDemo { output } => {
            prove_stwo_decoding_family_demo_command(&output)?
        }
        Command::VerifyStwoDecodingFamilyDemo { proof } => {
            verify_stwo_decoding_family_demo_command(&proof)?
        }
        #[cfg(feature = "stwo-backend")]
        Command::PrepareStwoSharedLookupArtifact {
            proof,
            artifact_commitment,
            output,
        } => prepare_stwo_shared_lookup_artifact_command(
            &proof,
            artifact_commitment.as_deref(),
            &output,
        )?,
        #[cfg(feature = "stwo-backend")]
        Command::VerifyStwoSharedLookupArtifact { artifact, proof } => {
            verify_stwo_shared_lookup_artifact_command(&artifact, &proof)?
        }
        #[cfg(feature = "stwo-backend")]
        Command::PrepareStwoDecodingStepEnvelopeManifest { proof, output } => {
            prepare_stwo_decoding_step_envelope_manifest_command(&proof, &output)?
        }
        #[cfg(feature = "stwo-backend")]
        Command::VerifyStwoDecodingStepEnvelopeManifest { manifest, proof } => {
            verify_stwo_decoding_step_envelope_manifest_command(&manifest, proof.as_deref())?
        }
        Command::ProveStwoDecodingLayoutMatrixDemo { output } => {
            prove_stwo_decoding_layout_matrix_demo_command(&output)?
        }
        Command::VerifyStwoDecodingLayoutMatrixDemo { proof } => {
            verify_stwo_decoding_layout_matrix_demo_command(&proof)?
        }
        Command::ProveStwoDecodingChunkedHistoryDemo { output } => {
            prove_stwo_decoding_chunked_history_demo_command(&output)?
        }
        Command::VerifyStwoDecodingChunkedHistoryDemo { proof } => {
            verify_stwo_decoding_chunked_history_demo_command(&proof)?
        }
        Command::ProveStwoDecodingHistorySegmentsDemo { output } => {
            prove_stwo_decoding_history_segments_demo_command(&output)?
        }
        Command::VerifyStwoDecodingHistorySegmentsDemo { proof } => {
            verify_stwo_decoding_history_segments_demo_command(&proof)?
        }
        Command::ProveStwoDecodingHistoryRollupDemo { output } => {
            prove_stwo_decoding_history_rollup_demo_command(&output)?
        }
        Command::VerifyStwoDecodingHistoryRollupDemo { proof } => {
            verify_stwo_decoding_history_rollup_demo_command(&proof)?
        }
        Command::ProveStwoDecodingHistoryRollupMatrixDemo { output } => {
            prove_stwo_decoding_history_rollup_matrix_demo_command(&output)?
        }
        Command::VerifyStwoDecodingHistoryRollupMatrixDemo { proof } => {
            verify_stwo_decoding_history_rollup_matrix_demo_command(&proof)?
        }
        Command::ProveStwoDecodingMatrixAccumulatorDemo { output } => {
            prove_stwo_decoding_matrix_accumulator_demo_command(&output)?
        }
        Command::VerifyStwoDecodingMatrixAccumulatorDemo { proof } => {
            verify_stwo_decoding_matrix_accumulator_demo_command(&proof)?
        }
        Command::ProveStwoDecodingLookupAccumulatorDemo { output } => {
            prove_stwo_decoding_lookup_accumulator_demo_command(&output)?
        }
        Command::VerifyStwoDecodingLookupAccumulatorDemo { proof } => {
            verify_stwo_decoding_lookup_accumulator_demo_command(&proof)?
        }
        Command::ProveStwoDecodingCrossStepLookupAccumulatorDemo { output } => {
            prove_stwo_decoding_cross_step_lookup_accumulator_demo_command(&output)?
        }
        Command::VerifyStwoDecodingCrossStepLookupAccumulatorDemo { proof } => {
            verify_stwo_decoding_cross_step_lookup_accumulator_demo_command(&proof)?
        }
        Command::ProveStwoDecodingStateRelationAccumulatorDemo { output } => {
            prove_stwo_decoding_state_relation_accumulator_demo_command(&output)?
        }
        Command::VerifyStwoDecodingStateRelationAccumulatorDemo { proof } => {
            verify_stwo_decoding_state_relation_accumulator_demo_command(&proof)?
        }
        Command::ProveStwoIntervalizedDecodingStateRelationDemo { output } => {
            prove_stwo_intervalized_decoding_state_relation_demo_command(&output)?
        }
        Command::VerifyStwoIntervalizedDecodingStateRelationDemo { proof } => {
            verify_stwo_intervalized_decoding_state_relation_demo_command(&proof)?
        }
        Command::ProveStwoFoldedIntervalizedDecodingStateRelationDemo { output } => {
            prove_stwo_folded_intervalized_decoding_state_relation_demo_command(&output)?
        }
        Command::VerifyStwoFoldedIntervalizedDecodingStateRelationDemo { proof } => {
            verify_stwo_folded_intervalized_decoding_state_relation_demo_command(&proof)?
        }
        Command::ProveStwoChainedFoldedIntervalizedDecodingStateRelationDemo { output } => {
            prove_stwo_chained_folded_intervalized_decoding_state_relation_demo_command(&output)?
        }
        Command::VerifyStwoChainedFoldedIntervalizedDecodingStateRelationDemo { proof } => {
            verify_stwo_chained_folded_intervalized_decoding_state_relation_demo_command(&proof)?
        }
        #[cfg(feature = "stwo-backend")]
        Command::ProveStwoAggregatedChainedFoldedIntervalizedDecodingStateRelationDemo {
            output,
        } => {
            prove_stwo_aggregated_chained_folded_intervalized_decoding_state_relation_demo_command(
                &output,
            )?
        }
        #[cfg(feature = "stwo-backend")]
        Command::VerifyStwoAggregatedChainedFoldedIntervalizedDecodingStateRelationDemo {
            proof,
        } => {
            verify_stwo_aggregated_chained_folded_intervalized_decoding_state_relation_demo_command(
                &proof,
            )?
        }
        #[cfg(feature = "stwo-backend")]
        Command::PrepareStwoRecursiveCompressionInputContract { phase28, output } => {
            prepare_stwo_recursive_compression_input_contract_command(&phase28, &output)?
        }
        #[cfg(feature = "stwo-backend")]
        Command::VerifyStwoRecursiveCompressionInputContract { input } => {
            verify_stwo_recursive_compression_input_contract_command(&input)?
        }
        Command::PrepareStwoRecursionBatch { proofs, output } => {
            prepare_stwo_recursion_batch_command(&proofs, &output)?
        }
        Command::ResearchV2Step {
            program,
            output,
            max_steps,
            layers,
            attention_mode,
        } => research_v2_step_command(&program, &output, max_steps, layers, attention_mode)?,
        Command::ResearchV2Trace {
            program,
            output,
            max_steps,
            layers,
            attention_mode,
            allow_mismatch,
        } => research_v2_trace_command(
            &program,
            &output,
            max_steps,
            layers,
            attention_mode,
            allow_mismatch,
        )?,
        Command::ResearchV2Matrix {
            output,
            programs,
            include_default_suite,
            max_steps,
            layers,
            attention_mode,
            allow_mismatch,
        } => research_v2_matrix_command(
            &output,
            &programs,
            include_default_suite,
            max_steps,
            layers,
            attention_mode,
            allow_mismatch,
        )?,
        Command::ResearchV3Equivalence {
            program,
            output,
            max_steps,
            layers,
            attention_mode,
        } => research_v3_equivalence_command(&program, &output, max_steps, layers, attention_mode)?,
        Command::VerifyResearchV3Equivalence { artifact } => {
            verify_research_v3_equivalence_command(&artifact)?
        }
        Command::PrepareHfProvenanceManifest {
            output,
            hub_repo,
            hub_revision,
            tokenizer_id,
            tokenizer_revision,
            tokenizer_json,
            tokenizer_config,
            tokenization_transcript,
            safetensors_files,
            onnx_model,
            onnx_metadata,
            onnx_external_data_files,
            onnx_exporter,
            onnx_exporter_version,
            model_card,
            doi,
            datasets,
            notes,
        } => prepare_hf_provenance_manifest_command(HfProvenanceManifestCommand {
            output,
            hub_repo,
            hub_revision,
            tokenizer_id,
            tokenizer_revision,
            tokenizer_json,
            tokenizer_config,
            tokenization_transcript,
            safetensors_files,
            onnx_model,
            onnx_metadata,
            onnx_external_data_files,
            onnx_exporter,
            onnx_exporter_version,
            model_card,
            doi,
            datasets,
            notes,
        })?,
        Command::VerifyHfProvenanceManifest { manifest } => {
            verify_hf_provenance_manifest_command(&manifest)?
        }
    }

    Ok(())
}

fn run_program_command(options: RunCommandOptions) -> llm_provable_computer::Result<()> {
    let model = compile_model(
        &options.program,
        options.layers,
        options.attention_mode.clone(),
    )?;
    let executed = execute_engine(&model, options.engine, options.max_steps)?;

    print_execution_summary(&options.program, options.engine, &model, &executed.result);

    if options.verify_native {
        let comparison = verify_model_against_native(model.clone(), options.max_steps)?;
        println!("verified_against_native: true");
        println!("verified_steps: {}", comparison.checked_steps);
        println!(
            "native_elapsed_ms: {:.3}",
            comparison.native.elapsed.as_secs_f64() * 1000.0
        );
        println!(
            "native_throughput_steps_per_sec: {:.2}",
            comparison.native.tokens_per_sec
        );
    }

    if options.verify_burn {
        let verification = verify_burn_engines(&model, options.max_steps)?;
        print_verification_summary(
            "verified_against_burn",
            "verified_burn",
            &verification.checked_steps.to_string(),
            &verification.engines,
        );
    }

    if options.verify_onnx {
        let verification = verify_onnx_engines(&model, options.max_steps)?;
        print_verification_summary(
            "verified_against_onnx",
            "verified_onnx",
            &verification.checked_steps.to_string(),
            &verification.engines,
        );
    }

    if options.verify_all {
        let verification = verify_all_engines(&model, options.max_steps)?;
        print_verification_summary(
            "verified_all",
            "verified_all",
            &verification.checked_steps.to_string(),
            &verification.engines,
        );
    }

    if options.trace {
        print_trace(&executed.trace, &executed.events);
    }

    Ok(())
}

fn export_onnx_command(
    program: &Path,
    output_dir: &Path,
    layers: usize,
    attention_mode: Attention2DMode,
) -> llm_provable_computer::Result<()> {
    let model = compile_model(program, layers, attention_mode)?;
    export_onnx_command_impl(program, output_dir, &model)
}

fn prove_stark_command(
    program: &Path,
    output: &Path,
    max_steps: usize,
    layers: usize,
    attention_mode: Attention2DMode,
    stark_profile: CliStarkProfile,
    backend: CliProofBackend,
    stark_options: VanillaStarkProofOptions,
) -> llm_provable_computer::Result<()> {
    let model = compile_model(program, layers, attention_mode)?;
    let profile_options = stark_profile.proof_options();
    let profile_overridden = stark_options != profile_options;
    let proof = prove_execution_stark_with_backend_and_options(
        &model,
        max_steps,
        backend.backend(),
        stark_options,
    )?;
    let equivalence = proof.claim.equivalence.as_ref().ok_or_else(|| {
        VmError::InvalidConfig(
            "prove-stark produced a claim without equivalence metadata".to_string(),
        )
    })?;
    save_execution_stark_proof(&proof, output)?;

    println!("program: {}", program.display());
    println!("proof: {}", output.display());
    println!("steps: {}", proof.claim.steps);
    println!("halted: {}", proof.claim.final_state.halted);
    println!("pc: {}", proof.claim.final_state.pc);
    println!("sp: {}", proof.claim.final_state.sp);
    println!("acc: {}", proof.claim.final_state.acc);
    println!("zero_flag: {}", proof.claim.final_state.zero_flag);
    println!("carry_flag: {}", proof.claim.final_state.carry_flag);
    println!("memory: {:?}", proof.claim.final_state.memory);
    println!("attention_mode: {}", proof.claim.attention_mode);
    println!("proof_backend: {}", proof.proof_backend);
    println!("proof_backend_version: {}", proof.proof_backend_version);
    println!("statement_version: {}", proof.claim.statement_version);
    println!("semantic_scope: {}", proof.claim.semantic_scope);
    print_stwo_normalization_companion(&proof);
    println!(
        "stark_expansion_factor: {}",
        proof.claim.options.expansion_factor
    );
    println!(
        "stark_num_colinearity_checks: {}",
        proof.claim.options.num_colinearity_checks
    );
    println!(
        "stark_security_level: {}",
        proof.claim.options.security_level
    );
    println!(
        "conjectured_security_bits: {}",
        conjectured_security_bits(&proof.claim.options)
    );
    if profile_overridden {
        println!("stark_profile: custom");
        println!("stark_profile_base: {stark_profile}");
    } else {
        println!("stark_profile: {stark_profile}");
        if let Some(target) = stark_profile.target_max_proving_seconds() {
            println!("profile_target_max_proving_seconds: {target}");
        }
        let profile_security_floor = stark_profile.min_conjectured_security_bits();
        if profile_security_floor > 0 {
            println!("profile_min_conjectured_security_bits: {profile_security_floor}");
        }
    }
    println!("equivalence_checked_steps: {}", equivalence.checked_steps);
    println!(
        "equivalence_transformer_fingerprint: {}",
        equivalence.transformer_fingerprint
    );
    println!(
        "equivalence_native_fingerprint: {}",
        equivalence.native_fingerprint
    );
    if let Some(commitments) = &proof.claim.commitments {
        println!("commitment_scheme_version: {}", commitments.scheme_version);
        println!("commitment_hash_function: {}", commitments.hash_function);
        println!("commitment_program_hash: {}", commitments.program_hash);
        println!(
            "commitment_transformer_config_hash: {}",
            commitments.transformer_config_hash
        );
        println!(
            "commitment_deterministic_model_hash: {}",
            commitments.deterministic_model_hash
        );
        println!(
            "commitment_stark_options_hash: {}",
            commitments.stark_options_hash
        );
        println!(
            "commitment_prover_build_info: {}",
            commitments.prover_build_info
        );
        println!(
            "commitment_prover_build_hash: {}",
            commitments.prover_build_hash
        );
    }
    println!("proof_bytes: {}", proof.proof.len());

    Ok(())
}

fn verify_stark_command(
    proof_path: &Path,
    verification_profile: CliStarkProfile,
    reexecute: bool,
    min_conjectured_security: u32,
    strict: bool,
    backend: Option<CliProofBackend>,
) -> llm_provable_computer::Result<()> {
    let proof = load_execution_stark_proof(proof_path)?;
    let policy = StarkVerificationPolicy {
        min_conjectured_security_bits: {
            let mut floor =
                min_conjectured_security.max(verification_profile.min_conjectured_security_bits());
            if strict {
                floor = floor.max(StarkVerificationPolicy::strict().min_conjectured_security_bits);
            }
            floor
        },
    };
    let effective_reexecute = reexecute || strict || verification_profile.enforces_reexecution();
    let backend = backend
        .map(CliProofBackend::backend)
        .unwrap_or(proof.proof_backend);
    let verified = if effective_reexecute {
        if backend != proof.proof_backend {
            return Err(VmError::InvalidConfig(format!(
                "proof backend override `{backend}` does not match encoded proof backend `{}`",
                proof.proof_backend
            )));
        }
        verify_execution_stark_with_reexecution_and_policy(&proof, policy)?
    } else {
        verify_execution_stark_with_backend_and_policy(&proof, backend, policy)?
    };
    if !verified {
        return Err(VmError::InvalidConfig(format!(
            "stark proof verification failed for {}",
            proof_path.display()
        )));
    }

    println!("proof: {}", proof_path.display());
    println!("verified_stark: true");
    println!("steps: {}", proof.claim.steps);
    println!("halted: {}", proof.claim.final_state.halted);
    println!("pc: {}", proof.claim.final_state.pc);
    println!("sp: {}", proof.claim.final_state.sp);
    println!("acc: {}", proof.claim.final_state.acc);
    println!("zero_flag: {}", proof.claim.final_state.zero_flag);
    println!("carry_flag: {}", proof.claim.final_state.carry_flag);
    println!("memory: {:?}", proof.claim.final_state.memory);
    println!("attention_mode: {}", proof.claim.attention_mode);
    println!("proof_backend: {}", proof.proof_backend);
    println!("proof_backend_version: {}", proof.proof_backend_version);
    println!("statement_version: {}", proof.claim.statement_version);
    println!("semantic_scope: {}", proof.claim.semantic_scope);
    print_stwo_normalization_companion(&proof);
    println!(
        "stark_expansion_factor: {}",
        proof.claim.options.expansion_factor
    );
    println!(
        "stark_num_colinearity_checks: {}",
        proof.claim.options.num_colinearity_checks
    );
    println!(
        "stark_security_level: {}",
        proof.claim.options.security_level
    );
    println!(
        "conjectured_security_bits: {}",
        conjectured_security_bits(&proof.claim.options)
    );
    println!(
        "required_conjectured_security_bits: {}",
        policy.min_conjectured_security_bits
    );
    println!("verification_profile: {verification_profile}");
    println!("strict_policy: {}", strict);
    println!("reexecuted_equivalence: {}", effective_reexecute);
    let equivalence = proof.claim.equivalence.as_ref().ok_or_else(|| {
        VmError::InvalidConfig("verified claim is missing equivalence metadata".to_string())
    })?;
    println!("equivalence_checked_steps: {}", equivalence.checked_steps);
    println!(
        "equivalence_transformer_fingerprint: {}",
        equivalence.transformer_fingerprint
    );
    println!(
        "equivalence_native_fingerprint: {}",
        equivalence.native_fingerprint
    );
    if let Some(commitments) = &proof.claim.commitments {
        println!("commitment_scheme_version: {}", commitments.scheme_version);
        println!("commitment_hash_function: {}", commitments.hash_function);
        println!("commitment_program_hash: {}", commitments.program_hash);
        println!(
            "commitment_transformer_config_hash: {}",
            commitments.transformer_config_hash
        );
        println!(
            "commitment_deterministic_model_hash: {}",
            commitments.deterministic_model_hash
        );
        println!(
            "commitment_stark_options_hash: {}",
            commitments.stark_options_hash
        );
        println!(
            "commitment_prover_build_info: {}",
            commitments.prover_build_info
        );
        println!(
            "commitment_prover_build_hash: {}",
            commitments.prover_build_hash
        );
    }
    println!("instructions: {}", proof.claim.program.instructions().len());
    println!("proof_bytes: {}", proof.proof.len());

    Ok(())
}

fn prove_stwo_normalization_demo_command(output: &Path) -> llm_provable_computer::Result<()> {
    #[cfg(not(feature = "stwo-backend"))]
    {
        let _ = output;
        return Err(VmError::UnsupportedProof(
            "S-two normalization demo requires building with `--features stwo-backend`".to_string(),
        ));
    }

    #[cfg(feature = "stwo-backend")]
    if !stwo_backend_enabled() {
        return Err(VmError::UnsupportedProof(
            "S-two normalization demo requires building with `--features stwo-backend`".to_string(),
        ));
    }

    #[cfg(feature = "stwo-backend")]
    {
        let proof = prove_phase5_normalization_lookup_demo_envelope()?;
        save_phase5_normalization_lookup_proof(&proof, output)?;

        println!("proof: {}", output.display());
        println!("proof_backend: {}", proof.proof_backend);
        println!("proof_backend_version: {}", proof.proof_backend_version);
        println!("statement_version: {}", proof.statement_version);
        println!("semantic_scope: {}", proof.semantic_scope);
        println!("canonical_table_rows: {}", proof.canonical_table_rows.len());
        println!("proof_bytes: {}", proof.proof.len());

        Ok(())
    }
}

fn require_stwo_backend(context: &str) -> llm_provable_computer::Result<()> {
    #[cfg(not(feature = "stwo-backend"))]
    {
        return Err(VmError::UnsupportedProof(format!(
            "{context} requires building with `--features stwo-backend`"
        )));
    }

    #[cfg(feature = "stwo-backend")]
    {
        if !stwo_backend_enabled() {
            return Err(VmError::UnsupportedProof(format!(
                "{context} requires building with `--features stwo-backend`"
            )));
        }
        Ok(())
    }
}

fn prove_stwo_lookup_demo_command(output: &Path) -> llm_provable_computer::Result<()> {
    #[cfg(not(feature = "stwo-backend"))]
    {
        let _ = output;
        return Err(VmError::UnsupportedProof(
            "S-two binary-step lookup demo requires building with `--features stwo-backend`"
                .to_string(),
        ));
    }

    #[cfg(feature = "stwo-backend")]
    if !stwo_backend_enabled() {
        return Err(VmError::UnsupportedProof(
            "S-two binary-step lookup demo requires building with `--features stwo-backend`"
                .to_string(),
        ));
    }

    #[cfg(feature = "stwo-backend")]
    {
        let proof = prove_phase3_binary_step_lookup_demo_envelope()?;
        save_phase3_binary_step_lookup_proof(&proof, output)?;

        println!("proof: {}", output.display());
        println!("proof_backend: {}", proof.proof_backend);
        println!("proof_backend_version: {}", proof.proof_backend_version);
        println!("statement_version: {}", proof.statement_version);
        println!("semantic_scope: {}", proof.semantic_scope);
        println!("canonical_table_rows: {}", proof.canonical_table_rows.len());
        println!("proof_bytes: {}", proof.proof.len());

        Ok(())
    }
}

fn prove_stwo_shared_lookup_demo_command(output: &Path) -> llm_provable_computer::Result<()> {
    #[cfg(not(feature = "stwo-backend"))]
    {
        let _ = output;
        return Err(VmError::UnsupportedProof(
            "S-two shared binary-step lookup demo requires building with `--features stwo-backend`"
                .to_string(),
        ));
    }

    #[cfg(feature = "stwo-backend")]
    if !stwo_backend_enabled() {
        return Err(VmError::UnsupportedProof(
            "S-two shared binary-step lookup demo requires building with `--features stwo-backend`"
                .to_string(),
        ));
    }

    #[cfg(feature = "stwo-backend")]
    {
        let proof = prove_phase10_shared_binary_step_lookup_envelope(&[
            llm_provable_computer::Phase3LookupTableRow {
                input: 0,
                output: 1,
            },
            llm_provable_computer::Phase3LookupTableRow {
                input: 1,
                output: 1,
            },
        ])?;
        save_phase10_shared_binary_step_lookup_proof(&proof, output)?;

        println!("proof: {}", output.display());
        println!("proof_backend: {}", proof.proof_backend);
        println!("proof_backend_version: {}", proof.proof_backend_version);
        println!("statement_version: {}", proof.statement_version);
        println!("semantic_scope: {}", proof.semantic_scope);
        println!("canonical_table_rows: {}", proof.canonical_table_rows.len());
        println!("claimed_rows: {}", proof.claimed_rows.len());
        println!("proof_bytes: {}", proof.proof.len());

        Ok(())
    }
}

fn prove_stwo_shared_normalization_demo_command(
    output: &Path,
) -> llm_provable_computer::Result<()> {
    #[cfg(not(feature = "stwo-backend"))]
    {
        let _ = output;
        return Err(VmError::UnsupportedProof(
            "S-two shared normalization demo requires building with `--features stwo-backend`"
                .to_string(),
        ));
    }

    #[cfg(feature = "stwo-backend")]
    if !stwo_backend_enabled() {
        return Err(VmError::UnsupportedProof(
            "S-two shared normalization demo requires building with `--features stwo-backend`"
                .to_string(),
        ));
    }

    #[cfg(feature = "stwo-backend")]
    {
        let proof = prove_phase10_shared_normalization_lookup_envelope(&[(4, 128), (16, 64)])?;
        save_phase10_shared_normalization_lookup_proof(&proof, output)?;

        println!("proof: {}", output.display());
        println!("proof_backend: {}", proof.proof_backend);
        println!("proof_backend_version: {}", proof.proof_backend_version);
        println!("statement_version: {}", proof.statement_version);
        println!("semantic_scope: {}", proof.semantic_scope);
        println!("canonical_table_rows: {}", proof.canonical_table_rows.len());
        println!("claimed_rows: {}", proof.claimed_rows.len());
        println!("proof_bytes: {}", proof.proof.len());

        Ok(())
    }
}

fn verify_stwo_lookup_demo_command(proof_path: &Path) -> llm_provable_computer::Result<()> {
    #[cfg(not(feature = "stwo-backend"))]
    {
        let _ = proof_path;
        return Err(VmError::UnsupportedProof(
            "S-two binary-step lookup demo requires building with `--features stwo-backend`"
                .to_string(),
        ));
    }

    #[cfg(feature = "stwo-backend")]
    if !stwo_backend_enabled() {
        return Err(VmError::UnsupportedProof(
            "S-two binary-step lookup demo requires building with `--features stwo-backend`"
                .to_string(),
        ));
    }

    #[cfg(feature = "stwo-backend")]
    {
        let proof = load_phase3_binary_step_lookup_proof(proof_path)?;
        let verified = verify_phase3_binary_step_lookup_demo_envelope(&proof)?;
        if !verified {
            return Err(VmError::InvalidConfig(format!(
                "binary-step lookup demo proof verification failed for {}",
                proof_path.display()
            )));
        }

        println!("proof: {}", proof_path.display());
        println!("verified_stark: true");
        println!("proof_backend: {}", proof.proof_backend);
        println!("proof_backend_version: {}", proof.proof_backend_version);
        println!("statement_version: {}", proof.statement_version);
        println!("semantic_scope: {}", proof.semantic_scope);
        println!("canonical_table_rows: {}", proof.canonical_table_rows.len());
        println!("expected_statement_version: {STWO_LOOKUP_STATEMENT_VERSION_PHASE3}");
        println!("expected_semantic_scope: {STWO_LOOKUP_SEMANTIC_SCOPE_PHASE3}");
        println!("expected_proof_backend_version: {STWO_LOOKUP_PROOF_VERSION_PHASE3}");
        println!("proof_bytes: {}", proof.proof.len());

        Ok(())
    }
}

fn verify_stwo_shared_lookup_demo_command(proof_path: &Path) -> llm_provable_computer::Result<()> {
    #[cfg(not(feature = "stwo-backend"))]
    {
        let _ = proof_path;
        return Err(VmError::UnsupportedProof(
            "S-two shared binary-step lookup demo requires building with `--features stwo-backend`"
                .to_string(),
        ));
    }

    #[cfg(feature = "stwo-backend")]
    if !stwo_backend_enabled() {
        return Err(VmError::UnsupportedProof(
            "S-two shared binary-step lookup demo requires building with `--features stwo-backend`"
                .to_string(),
        ));
    }

    #[cfg(feature = "stwo-backend")]
    {
        let proof = load_phase10_shared_binary_step_lookup_proof(proof_path)?;
        if !verify_phase10_shared_binary_step_lookup_envelope(&proof)? {
            return Err(VmError::InvalidConfig(format!(
                "S-two shared binary-step lookup proof verification failed for {}",
                proof_path.display()
            )));
        }

        println!("proof: {}", proof_path.display());
        println!("verified_stark: true");
        println!("proof_backend: {}", proof.proof_backend);
        println!("proof_backend_version: {}", proof.proof_backend_version);
        println!("statement_version: {}", proof.statement_version);
        println!("semantic_scope: {}", proof.semantic_scope);
        println!("canonical_table_rows: {}", proof.canonical_table_rows.len());
        println!("claimed_rows: {}", proof.claimed_rows.len());
        println!("proof_bytes: {}", proof.proof.len());

        Ok(())
    }
}

fn verify_stwo_shared_normalization_demo_command(
    proof_path: &Path,
) -> llm_provable_computer::Result<()> {
    #[cfg(not(feature = "stwo-backend"))]
    {
        let _ = proof_path;
        return Err(VmError::UnsupportedProof(
            "S-two shared normalization demo requires building with `--features stwo-backend`"
                .to_string(),
        ));
    }

    #[cfg(feature = "stwo-backend")]
    if !stwo_backend_enabled() {
        return Err(VmError::UnsupportedProof(
            "S-two shared normalization demo requires building with `--features stwo-backend`"
                .to_string(),
        ));
    }

    #[cfg(feature = "stwo-backend")]
    {
        let proof = load_phase10_shared_normalization_lookup_proof(proof_path)?;
        if !verify_phase10_shared_normalization_lookup_envelope(&proof)? {
            return Err(VmError::InvalidConfig(format!(
                "S-two shared normalization proof verification failed for {}",
                proof_path.display()
            )));
        }

        println!("proof: {}", proof_path.display());
        println!("verified_stark: true");
        println!("proof_backend: {}", proof.proof_backend);
        println!("proof_backend_version: {}", proof.proof_backend_version);
        println!("statement_version: {}", proof.statement_version);
        println!("semantic_scope: {}", proof.semantic_scope);
        println!("canonical_table_rows: {}", proof.canonical_table_rows.len());
        println!("claimed_rows: {}", proof.claimed_rows.len());
        println!("proof_bytes: {}", proof.proof.len());

        Ok(())
    }
}

fn prove_stwo_decoding_demo_command(output: &Path) -> llm_provable_computer::Result<()> {
    #[cfg(not(feature = "stwo-backend"))]
    {
        let _ = output;
        return Err(VmError::UnsupportedProof(
            "S-two proof-carrying decoding demo requires building with `--features stwo-backend`"
                .to_string(),
        ));
    }

    #[cfg(feature = "stwo-backend")]
    if !stwo_backend_enabled() {
        return Err(VmError::UnsupportedProof(
            "S-two proof-carrying decoding demo requires building with `--features stwo-backend`"
                .to_string(),
        ));
    }

    #[cfg(feature = "stwo-backend")]
    {
        let manifest = prove_phase11_decoding_demo()?;
        save_phase11_decoding_chain(&manifest, output)?;

        println!("proof: {}", output.display());
        println!("proof_backend: {}", manifest.proof_backend);
        println!("chain_version: {}", manifest.chain_version);
        println!("semantic_scope: {}", manifest.semantic_scope);
        println!("proof_backend_version: {}", manifest.proof_backend_version);
        println!("statement_version: {}", manifest.statement_version);
        println!("total_steps: {}", manifest.total_steps);
        if let Some(first) = manifest.steps.first() {
            println!("start_position: {}", first.from_state.position);
        }
        if let Some(last) = manifest.steps.last() {
            println!("final_position: {}", last.to_state.position);
        }

        Ok(())
    }
}

fn verify_stwo_decoding_demo_command(proof_path: &Path) -> llm_provable_computer::Result<()> {
    #[cfg(not(feature = "stwo-backend"))]
    {
        let _ = proof_path;
        return Err(VmError::UnsupportedProof(
            "S-two proof-carrying decoding demo requires building with `--features stwo-backend`"
                .to_string(),
        ));
    }

    #[cfg(feature = "stwo-backend")]
    if !stwo_backend_enabled() {
        return Err(VmError::UnsupportedProof(
            "S-two proof-carrying decoding demo requires building with `--features stwo-backend`"
                .to_string(),
        ));
    }

    #[cfg(feature = "stwo-backend")]
    {
        let manifest = load_phase11_decoding_chain(proof_path)?;
        verify_phase11_decoding_chain_with_proof_checks(&manifest)?;

        println!("proof: {}", proof_path.display());
        println!("verified_stark: true");
        println!("proof_backend: {}", manifest.proof_backend);
        println!("chain_version: {}", manifest.chain_version);
        println!("semantic_scope: {}", manifest.semantic_scope);
        println!("proof_backend_version: {}", manifest.proof_backend_version);
        println!("statement_version: {}", manifest.statement_version);
        println!("total_steps: {}", manifest.total_steps);
        println!("expected_chain_version: {STWO_DECODING_CHAIN_VERSION_PHASE11}");
        println!("expected_semantic_scope: {STWO_DECODING_CHAIN_SCOPE_PHASE11}");

        Ok(())
    }
}

fn prove_stwo_decoding_family_demo_command(output: &Path) -> llm_provable_computer::Result<()> {
    #[cfg(not(feature = "stwo-backend"))]
    {
        let _ = output;
        return Err(VmError::UnsupportedProof(
            "S-two parameterized proof-carrying decoding demo requires building with `--features stwo-backend`"
                .to_string(),
        ));
    }

    #[cfg(feature = "stwo-backend")]
    if !stwo_backend_enabled() {
        return Err(VmError::UnsupportedProof(
            "S-two parameterized proof-carrying decoding demo requires building with `--features stwo-backend`"
                .to_string(),
        ));
    }

    #[cfg(feature = "stwo-backend")]
    {
        let manifest = prove_phase12_decoding_demo()?;
        save_phase12_decoding_chain(&manifest, output)?;

        println!("proof: {}", output.display());
        println!("proof_backend: {}", manifest.proof_backend);
        println!("chain_version: {}", manifest.chain_version);
        println!("semantic_scope: {}", manifest.semantic_scope);
        println!("proof_backend_version: {}", manifest.proof_backend_version);
        println!("statement_version: {}", manifest.statement_version);
        println!("total_steps: {}", manifest.total_steps);
        println!("rolling_kv_pairs: {}", manifest.layout.rolling_kv_pairs);
        println!("pair_width: {}", manifest.layout.pair_width);
        if let Some(first) = manifest.steps.first() {
            println!("start_position: {}", first.from_state.position);
            println!(
                "start_history_length: {}",
                first.from_state.kv_history_length
            );
        }
        if let Some(last) = manifest.steps.last() {
            println!("final_position: {}", last.to_state.position);
            println!("final_history_length: {}", last.to_state.kv_history_length);
        }

        Ok(())
    }
}

fn verify_stwo_decoding_family_demo_command(
    proof_path: &Path,
) -> llm_provable_computer::Result<()> {
    #[cfg(not(feature = "stwo-backend"))]
    {
        let _ = proof_path;
        return Err(VmError::UnsupportedProof(
            "S-two parameterized proof-carrying decoding demo requires building with `--features stwo-backend`"
                .to_string(),
        ));
    }

    #[cfg(feature = "stwo-backend")]
    if !stwo_backend_enabled() {
        return Err(VmError::UnsupportedProof(
            "S-two parameterized proof-carrying decoding demo requires building with `--features stwo-backend`"
                .to_string(),
        ));
    }

    #[cfg(feature = "stwo-backend")]
    {
        let manifest = load_phase12_decoding_chain(proof_path)?;
        verify_phase12_decoding_chain_with_proof_checks(&manifest)?;

        println!("proof: {}", proof_path.display());
        println!("verified_stark: true");
        println!("proof_backend: {}", manifest.proof_backend);
        println!("chain_version: {}", manifest.chain_version);
        println!("semantic_scope: {}", manifest.semantic_scope);
        println!("proof_backend_version: {}", manifest.proof_backend_version);
        println!("statement_version: {}", manifest.statement_version);
        println!("total_steps: {}", manifest.total_steps);
        println!("rolling_kv_pairs: {}", manifest.layout.rolling_kv_pairs);
        println!("pair_width: {}", manifest.layout.pair_width);
        if let Some(first) = manifest.steps.first() {
            println!(
                "start_history_length: {}",
                first.from_state.kv_history_length
            );
        }
        if let Some(last) = manifest.steps.last() {
            println!("final_history_length: {}", last.to_state.kv_history_length);
        }
        println!("expected_chain_version: {STWO_DECODING_CHAIN_VERSION_PHASE12}");
        println!("expected_semantic_scope: {STWO_DECODING_CHAIN_SCOPE_PHASE12}");
        println!("expected_proof_backend_version: {STWO_BACKEND_VERSION_PHASE12}");

        Ok(())
    }
}

#[cfg(feature = "stwo-backend")]
fn selected_phase12_shared_lookup_artifact<'a>(
    chain: &'a llm_provable_computer::Phase12DecodingChainManifest,
    requested_commitment: Option<&str>,
) -> llm_provable_computer::Result<&'a llm_provable_computer::Phase12SharedLookupArtifact> {
    if let Some(requested_commitment) = requested_commitment {
        return chain
            .shared_lookup_artifacts
            .iter()
            .find(|artifact| artifact.artifact_commitment == requested_commitment)
            .ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "shared lookup artifact `{requested_commitment}` is not present in the verified Phase 12 chain"
                ))
            });
    }

    match chain.shared_lookup_artifacts.as_slice() {
        [artifact] => Ok(artifact),
        [] => Err(VmError::InvalidConfig(
            "verified Phase 12 chain does not contain any shared lookup artifacts".to_string(),
        )),
        artifacts => Err(VmError::InvalidConfig(format!(
            "verified Phase 12 chain contains {} shared lookup artifacts; pass --artifact-commitment to select one",
            artifacts.len()
        ))),
    }
}

#[cfg(feature = "stwo-backend")]
fn print_phase12_shared_lookup_artifact_report(
    artifact: &llm_provable_computer::Phase12SharedLookupArtifact,
) {
    println!("artifact_version: {}", artifact.artifact_version);
    println!("semantic_scope: {}", artifact.semantic_scope);
    println!("artifact_commitment: {}", artifact.artifact_commitment);
    println!("layout_commitment: {}", artifact.layout_commitment);
    println!(
        "static_table_registry_version: {}",
        artifact.static_table_registry_version
    );
    println!(
        "static_table_registry_scope: {}",
        artifact.static_table_registry_scope
    );
    println!(
        "static_table_registry_commitment: {}",
        artifact.static_table_registry_commitment
    );
    println!(
        "static_table_commitments: {}",
        artifact.static_table_commitments.len()
    );
}

fn prepare_stwo_shared_lookup_artifact_command(
    proof_path: &Path,
    artifact_commitment: Option<&str>,
    output: &Path,
) -> llm_provable_computer::Result<()> {
    #[cfg(not(feature = "stwo-backend"))]
    {
        let _ = (proof_path, artifact_commitment, output);
        return Err(VmError::UnsupportedProof(
            "S-two shared lookup artifacts require building with `--features stwo-backend`"
                .to_string(),
        ));
    }

    #[cfg(feature = "stwo-backend")]
    {
        require_stwo_backend("S-two shared lookup artifact")?;
        reject_phase12_shared_lookup_artifact_plain_json_gzip_output(output)?;

        let chain = load_phase12_decoding_chain(proof_path)?;
        verify_phase12_decoding_chain_with_proof_checks(&chain)?;
        let artifact = selected_phase12_shared_lookup_artifact(&chain, artifact_commitment)?;
        save_phase12_shared_lookup_artifact(artifact, output)?;

        println!("output: {}", output.display());
        println!("proof: {}", proof_path.display());
        println!("verified_stark: true");
        print_phase12_shared_lookup_artifact_report(artifact);

        Ok(())
    }
}

fn verify_stwo_shared_lookup_artifact_command(
    artifact_path: &Path,
    proof_path: &Path,
) -> llm_provable_computer::Result<()> {
    #[cfg(not(feature = "stwo-backend"))]
    {
        let _ = (artifact_path, proof_path);
        return Err(VmError::UnsupportedProof(
            "S-two shared lookup artifacts require building with `--features stwo-backend`"
                .to_string(),
        ));
    }

    #[cfg(feature = "stwo-backend")]
    {
        require_stwo_backend("S-two shared lookup artifact")?;

        let chain = load_phase12_decoding_chain(proof_path)?;
        verify_phase12_decoding_chain_with_proof_checks(&chain)?;
        let artifact = load_phase12_shared_lookup_artifact(artifact_path, &chain.layout)?;
        let expected =
            selected_phase12_shared_lookup_artifact(&chain, Some(&artifact.artifact_commitment))?;
        if &artifact != expected {
            return Err(VmError::InvalidConfig(format!(
                "shared lookup artifact `{}` does not match the verified Phase 12 chain payload",
                artifact.artifact_commitment
            )));
        }

        println!("artifact: {}", artifact_path.display());
        println!("proof: {}", proof_path.display());
        println!("verified_artifact: true");
        println!("verified_stark: true");
        println!("verified_against_chain: true");
        print_phase12_shared_lookup_artifact_report(&artifact);

        Ok(())
    }
}

fn prepare_stwo_decoding_step_envelope_manifest_command(
    proof_path: &Path,
    output: &Path,
) -> llm_provable_computer::Result<()> {
    #[cfg(not(feature = "stwo-backend"))]
    {
        let _ = (proof_path, output);
        return Err(VmError::UnsupportedProof(
            "S-two decoding step proof envelope manifests require building with `--features stwo-backend`"
                .to_string(),
        ));
    }

    #[cfg(feature = "stwo-backend")]
    {
        require_stwo_backend("S-two decoding step proof envelope manifest")?;
        reject_phase30_step_envelope_manifest_plain_json_gzip_output(output)?;

        let chain = load_phase12_decoding_chain(proof_path)?;
        verify_phase12_decoding_chain_with_proof_checks(&chain)?;
        let manifest = phase30_prepare_decoding_step_proof_envelope_manifest(&chain)?;
        save_phase30_decoding_step_proof_envelope_manifest(&manifest, output)?;

        println!("output: {}", output.display());
        println!("proof: {}", proof_path.display());
        println!("verified_stark: true");
        print_phase30_decoding_step_envelope_manifest_report(&manifest);

        Ok(())
    }
}

fn verify_stwo_decoding_step_envelope_manifest_command(
    manifest_path: &Path,
    proof_path: Option<&Path>,
) -> llm_provable_computer::Result<()> {
    #[cfg(not(feature = "stwo-backend"))]
    {
        let _ = (manifest_path, proof_path);
        return Err(VmError::UnsupportedProof(
            "S-two decoding step proof envelope manifests require building with `--features stwo-backend`"
                .to_string(),
        ));
    }

    #[cfg(feature = "stwo-backend")]
    {
        require_stwo_backend("S-two decoding step proof envelope manifest")?;

        let manifest = load_phase30_decoding_step_proof_envelope_manifest(manifest_path)?;

        println!("manifest: {}", manifest_path.display());
        if let Some(proof_path) = proof_path {
            let chain = load_phase12_decoding_chain(proof_path)?;
            verify_phase12_decoding_chain_with_proof_checks(&chain)?;
            verify_phase30_decoding_step_proof_envelope_manifest_against_chain(&manifest, &chain)?;
            println!("proof: {}", proof_path.display());
            println!("verified_stark: true");
            println!("verified_against_chain: true");
        }
        println!("verified_manifest: true");
        print_phase30_decoding_step_envelope_manifest_report(&manifest);

        Ok(())
    }
}

#[cfg(feature = "stwo-backend")]
fn reject_phase12_shared_lookup_artifact_plain_json_gzip_output(
    output: &Path,
) -> llm_provable_computer::Result<()> {
    if output.extension().and_then(|extension| extension.to_str()) == Some("gz") {
        return Err(VmError::InvalidConfig(
            "prepare-stwo-shared-lookup-artifact writes plain JSON; use a `.json` output path"
                .to_string(),
        ));
    }
    Ok(())
}

#[cfg(feature = "stwo-backend")]
fn reject_phase30_step_envelope_manifest_plain_json_gzip_output(
    output: &Path,
) -> llm_provable_computer::Result<()> {
    if output.extension().and_then(|extension| extension.to_str()) == Some("gz") {
        return Err(VmError::InvalidConfig(
            "prepare-stwo-decoding-step-envelope-manifest writes plain JSON; use a `.json` output path"
                .to_string(),
        ));
    }
    Ok(())
}

#[cfg(feature = "stwo-backend")]
fn print_phase30_decoding_step_envelope_manifest_report(
    manifest: &Phase30DecodingStepProofEnvelopeManifest,
) {
    println!("proof_backend: {}", manifest.proof_backend);
    println!("manifest_version: {}", manifest.manifest_version);
    println!("semantic_scope: {}", manifest.semantic_scope);
    println!("proof_backend_version: {}", manifest.proof_backend_version);
    println!("statement_version: {}", manifest.statement_version);
    println!("source_chain_version: {}", manifest.source_chain_version);
    println!(
        "source_chain_semantic_scope: {}",
        manifest.source_chain_semantic_scope
    );
    println!("total_steps: {}", manifest.total_steps);
    println!(
        "chain_start_boundary_commitment: {}",
        manifest.chain_start_boundary_commitment
    );
    println!(
        "chain_end_boundary_commitment: {}",
        manifest.chain_end_boundary_commitment
    );
    println!(
        "step_envelopes_commitment: {}",
        manifest.step_envelopes_commitment
    );
}

fn prove_stwo_decoding_layout_matrix_demo_command(
    output: &Path,
) -> llm_provable_computer::Result<()> {
    #[cfg(not(feature = "stwo-backend"))]
    {
        let _ = output;
        return Err(VmError::UnsupportedProof(
            "S-two decoding layout matrix demo requires building with `--features stwo-backend`"
                .to_string(),
        ));
    }

    #[cfg(feature = "stwo-backend")]
    if !stwo_backend_enabled() {
        return Err(VmError::UnsupportedProof(
            "S-two decoding layout matrix demo requires building with `--features stwo-backend`"
                .to_string(),
        ));
    }

    #[cfg(feature = "stwo-backend")]
    {
        let manifest = prove_phase13_decoding_layout_matrix_demo()?;
        save_phase13_decoding_layout_matrix(&manifest, output)?;

        println!("proof: {}", output.display());
        println!("proof_backend: {}", manifest.proof_backend);
        println!("matrix_version: {}", manifest.matrix_version);
        println!("semantic_scope: {}", manifest.semantic_scope);
        println!("proof_backend_version: {}", manifest.proof_backend_version);
        println!("statement_version: {}", manifest.statement_version);
        println!("total_layouts: {}", manifest.total_layouts);
        println!("total_steps: {}", manifest.total_steps);
        if let Some(first) = manifest.chains.first() {
            println!("first_layout_pairs: {}", first.layout.rolling_kv_pairs);
            println!("first_layout_width: {}", first.layout.pair_width);
        }
        if let Some(last) = manifest.chains.last() {
            println!("last_layout_pairs: {}", last.layout.rolling_kv_pairs);
            println!("last_layout_width: {}", last.layout.pair_width);
        }

        Ok(())
    }
}

fn verify_stwo_decoding_layout_matrix_demo_command(
    proof_path: &Path,
) -> llm_provable_computer::Result<()> {
    #[cfg(not(feature = "stwo-backend"))]
    {
        let _ = proof_path;
        return Err(VmError::UnsupportedProof(
            "S-two decoding layout matrix demo requires building with `--features stwo-backend`"
                .to_string(),
        ));
    }

    #[cfg(feature = "stwo-backend")]
    if !stwo_backend_enabled() {
        return Err(VmError::UnsupportedProof(
            "S-two decoding layout matrix demo requires building with `--features stwo-backend`"
                .to_string(),
        ));
    }

    #[cfg(feature = "stwo-backend")]
    {
        let manifest = load_phase13_decoding_layout_matrix(proof_path)?;
        verify_phase13_decoding_layout_matrix_with_proof_checks(&manifest)?;

        println!("proof: {}", proof_path.display());
        println!("verified_stark: true");
        println!("proof_backend: {}", manifest.proof_backend);
        println!("matrix_version: {}", manifest.matrix_version);
        println!("semantic_scope: {}", manifest.semantic_scope);
        println!("proof_backend_version: {}", manifest.proof_backend_version);
        println!("statement_version: {}", manifest.statement_version);
        println!("total_layouts: {}", manifest.total_layouts);
        println!("total_steps: {}", manifest.total_steps);
        println!("expected_matrix_version: {STWO_DECODING_LAYOUT_MATRIX_VERSION_PHASE13}");
        println!("expected_semantic_scope: {STWO_DECODING_LAYOUT_MATRIX_SCOPE_PHASE13}");
        println!("expected_proof_backend_version: {STWO_BACKEND_VERSION_PHASE12}");

        Ok(())
    }
}

fn prove_stwo_decoding_chunked_history_demo_command(
    output: &Path,
) -> llm_provable_computer::Result<()> {
    #[cfg(not(feature = "stwo-backend"))]
    {
        let _ = output;
        return Err(VmError::UnsupportedProof(
            "S-two chunked-history decoding demo requires building with `--features stwo-backend`"
                .to_string(),
        ));
    }

    #[cfg(feature = "stwo-backend")]
    if !stwo_backend_enabled() {
        return Err(VmError::UnsupportedProof(
            "S-two chunked-history decoding demo requires building with `--features stwo-backend`"
                .to_string(),
        ));
    }

    #[cfg(feature = "stwo-backend")]
    {
        let manifest = prove_phase14_decoding_demo()?;
        save_phase14_decoding_chain(&manifest, output)?;

        println!("proof: {}", output.display());
        println!("proof_backend: {}", manifest.proof_backend);
        println!("chain_version: {}", manifest.chain_version);
        println!("semantic_scope: {}", manifest.semantic_scope);
        println!("proof_backend_version: {}", manifest.proof_backend_version);
        println!("statement_version: {}", manifest.statement_version);
        println!("total_steps: {}", manifest.total_steps);
        println!("history_chunk_pairs: {}", manifest.history_chunk_pairs);
        println!("rolling_kv_pairs: {}", manifest.layout.rolling_kv_pairs);
        println!("pair_width: {}", manifest.layout.pair_width);
        if let Some(first) = manifest.steps.first() {
            println!(
                "start_history_length: {}",
                first.from_state.kv_history_length
            );
            println!(
                "start_sealed_chunks: {}",
                first.from_state.kv_history_sealed_chunks
            );
            println!(
                "start_open_chunk_pairs: {}",
                first.from_state.kv_history_open_chunk_pairs
            );
        }
        if let Some(last) = manifest.steps.last() {
            println!("final_history_length: {}", last.to_state.kv_history_length);
            println!(
                "final_sealed_chunks: {}",
                last.to_state.kv_history_sealed_chunks
            );
            println!(
                "final_open_chunk_pairs: {}",
                last.to_state.kv_history_open_chunk_pairs
            );
        }

        Ok(())
    }
}

fn verify_stwo_decoding_chunked_history_demo_command(
    proof_path: &Path,
) -> llm_provable_computer::Result<()> {
    #[cfg(not(feature = "stwo-backend"))]
    {
        let _ = proof_path;
        return Err(VmError::UnsupportedProof(
            "S-two chunked-history decoding demo requires building with `--features stwo-backend`"
                .to_string(),
        ));
    }

    #[cfg(feature = "stwo-backend")]
    if !stwo_backend_enabled() {
        return Err(VmError::UnsupportedProof(
            "S-two chunked-history decoding demo requires building with `--features stwo-backend`"
                .to_string(),
        ));
    }

    #[cfg(feature = "stwo-backend")]
    {
        let manifest = load_phase14_decoding_chain(proof_path)?;
        verify_phase14_decoding_chain_with_proof_checks(&manifest)?;

        println!("proof: {}", proof_path.display());
        println!("verified_stark: true");
        println!("proof_backend: {}", manifest.proof_backend);
        println!("chain_version: {}", manifest.chain_version);
        println!("semantic_scope: {}", manifest.semantic_scope);
        println!("proof_backend_version: {}", manifest.proof_backend_version);
        println!("statement_version: {}", manifest.statement_version);
        println!("total_steps: {}", manifest.total_steps);
        println!("history_chunk_pairs: {}", manifest.history_chunk_pairs);
        println!("rolling_kv_pairs: {}", manifest.layout.rolling_kv_pairs);
        println!("pair_width: {}", manifest.layout.pair_width);
        if let Some(first) = manifest.steps.first() {
            println!(
                "start_history_length: {}",
                first.from_state.kv_history_length
            );
            println!(
                "start_sealed_chunks: {}",
                first.from_state.kv_history_sealed_chunks
            );
            println!(
                "start_open_chunk_pairs: {}",
                first.from_state.kv_history_open_chunk_pairs
            );
        }
        if let Some(last) = manifest.steps.last() {
            println!("final_history_length: {}", last.to_state.kv_history_length);
            println!(
                "final_sealed_chunks: {}",
                last.to_state.kv_history_sealed_chunks
            );
            println!(
                "final_open_chunk_pairs: {}",
                last.to_state.kv_history_open_chunk_pairs
            );
        }
        println!("expected_chain_version: {STWO_DECODING_CHAIN_VERSION_PHASE14}");
        println!("expected_semantic_scope: {STWO_DECODING_CHAIN_SCOPE_PHASE14}");
        println!("expected_proof_backend_version: {STWO_BACKEND_VERSION_PHASE12}");

        Ok(())
    }
}

fn prove_stwo_decoding_history_segments_demo_command(
    output: &Path,
) -> llm_provable_computer::Result<()> {
    #[cfg(not(feature = "stwo-backend"))]
    {
        let _ = output;
        return Err(VmError::UnsupportedProof(
            "S-two decoding history-segment demo requires building with `--features stwo-backend`"
                .to_string(),
        ));
    }

    #[cfg(feature = "stwo-backend")]
    if !stwo_backend_enabled() {
        return Err(VmError::UnsupportedProof(
            "S-two decoding history-segment demo requires building with `--features stwo-backend`"
                .to_string(),
        ));
    }

    #[cfg(feature = "stwo-backend")]
    {
        let manifest = prove_phase15_decoding_demo()?;
        save_phase15_decoding_segment_bundle(&manifest, output)?;

        println!("proof: {}", output.display());
        println!("proof_backend: {}", manifest.proof_backend);
        println!("bundle_version: {}", manifest.bundle_version);
        println!("semantic_scope: {}", manifest.semantic_scope);
        println!("proof_backend_version: {}", manifest.proof_backend_version);
        println!("statement_version: {}", manifest.statement_version);
        println!("total_segments: {}", manifest.total_segments);
        println!("total_steps: {}", manifest.total_steps);
        println!("max_segment_steps: {}", manifest.max_segment_steps);
        println!("history_chunk_pairs: {}", manifest.history_chunk_pairs);
        println!("rolling_kv_pairs: {}", manifest.layout.rolling_kv_pairs);
        println!("pair_width: {}", manifest.layout.pair_width);
        if let Some(first) = manifest.segments.first() {
            println!(
                "first_segment_start_step: {}",
                first.global_start_step_index
            );
            println!("first_segment_steps: {}", first.total_steps);
        }
        if let Some(last) = manifest.segments.last() {
            println!("last_segment_start_step: {}", last.global_start_step_index);
            println!("last_segment_steps: {}", last.total_steps);
            println!(
                "final_history_length: {}",
                last.global_to_state.kv_history_length
            );
            println!(
                "final_sealed_chunks: {}",
                last.global_to_state.kv_history_sealed_chunks
            );
            println!(
                "final_open_chunk_pairs: {}",
                last.global_to_state.kv_history_open_chunk_pairs
            );
        }

        Ok(())
    }
}

fn verify_stwo_decoding_history_segments_demo_command(
    proof_path: &Path,
) -> llm_provable_computer::Result<()> {
    #[cfg(not(feature = "stwo-backend"))]
    {
        let _ = proof_path;
        return Err(VmError::UnsupportedProof(
            "S-two decoding history-segment demo requires building with `--features stwo-backend`"
                .to_string(),
        ));
    }

    #[cfg(feature = "stwo-backend")]
    if !stwo_backend_enabled() {
        return Err(VmError::UnsupportedProof(
            "S-two decoding history-segment demo requires building with `--features stwo-backend`"
                .to_string(),
        ));
    }

    #[cfg(feature = "stwo-backend")]
    {
        let manifest = load_phase15_decoding_segment_bundle(proof_path)?;
        verify_phase15_decoding_segment_bundle_with_proof_checks(&manifest)?;

        println!("proof: {}", proof_path.display());
        println!("verified_stark: true");
        println!("proof_backend: {}", manifest.proof_backend);
        println!("bundle_version: {}", manifest.bundle_version);
        println!("semantic_scope: {}", manifest.semantic_scope);
        println!("proof_backend_version: {}", manifest.proof_backend_version);
        println!("statement_version: {}", manifest.statement_version);
        println!("total_segments: {}", manifest.total_segments);
        println!("total_steps: {}", manifest.total_steps);
        println!("max_segment_steps: {}", manifest.max_segment_steps);
        println!("history_chunk_pairs: {}", manifest.history_chunk_pairs);
        println!("rolling_kv_pairs: {}", manifest.layout.rolling_kv_pairs);
        println!("pair_width: {}", manifest.layout.pair_width);
        if let Some(first) = manifest.segments.first() {
            println!(
                "first_segment_start_step: {}",
                first.global_start_step_index
            );
            println!("first_segment_steps: {}", first.total_steps);
        }
        if let Some(last) = manifest.segments.last() {
            println!("last_segment_start_step: {}", last.global_start_step_index);
            println!("last_segment_steps: {}", last.total_steps);
            println!(
                "final_history_length: {}",
                last.global_to_state.kv_history_length
            );
            println!(
                "final_sealed_chunks: {}",
                last.global_to_state.kv_history_sealed_chunks
            );
            println!(
                "final_open_chunk_pairs: {}",
                last.global_to_state.kv_history_open_chunk_pairs
            );
        }
        println!("expected_bundle_version: {STWO_DECODING_SEGMENT_BUNDLE_VERSION_PHASE15}");
        println!("expected_semantic_scope: {STWO_DECODING_SEGMENT_BUNDLE_SCOPE_PHASE15}");
        println!("expected_proof_backend_version: {STWO_BACKEND_VERSION_PHASE12}");

        Ok(())
    }
}

fn prove_stwo_decoding_history_rollup_demo_command(
    output: &Path,
) -> llm_provable_computer::Result<()> {
    require_stwo_backend("S-two decoding history-rollup demo")?;

    #[cfg(feature = "stwo-backend")]
    {
        let manifest = prove_phase16_decoding_demo()?;
        save_phase16_decoding_segment_rollup(&manifest, output)?;

        println!("proof: {}", output.display());
        println!("proof_backend: {}", manifest.proof_backend);
        println!("rollup_version: {}", manifest.rollup_version);
        println!("semantic_scope: {}", manifest.semantic_scope);
        println!("proof_backend_version: {}", manifest.proof_backend_version);
        println!("statement_version: {}", manifest.statement_version);
        println!("total_rollups: {}", manifest.total_rollups);
        println!("total_segments: {}", manifest.total_segments);
        println!("total_steps: {}", manifest.total_steps);
        println!("max_rollup_segments: {}", manifest.max_rollup_segments);
        println!("history_chunk_pairs: {}", manifest.history_chunk_pairs);
        println!("rolling_kv_pairs: {}", manifest.layout.rolling_kv_pairs);
        println!("pair_width: {}", manifest.layout.pair_width);
        if let Some(first) = manifest.rollups.first() {
            println!("first_rollup_start_step: {}", first.global_start_step_index);
            println!("first_rollup_segments: {}", first.total_segments);
        }
        if let Some(last) = manifest.rollups.last() {
            println!("last_rollup_start_step: {}", last.global_start_step_index);
            println!("last_rollup_segments: {}", last.total_segments);
            println!(
                "final_history_length: {}",
                last.global_to_state.kv_history_length
            );
            println!(
                "final_sealed_chunks: {}",
                last.global_to_state.kv_history_sealed_chunks
            );
            println!(
                "final_open_chunk_pairs: {}",
                last.global_to_state.kv_history_open_chunk_pairs
            );
        }

        Ok(())
    }

    #[cfg(not(feature = "stwo-backend"))]
    {
        let _ = output;
        unreachable!("require_stwo_backend must fail without `stwo-backend`");
    }
}

fn verify_stwo_decoding_history_rollup_demo_command(
    proof_path: &Path,
) -> llm_provable_computer::Result<()> {
    require_stwo_backend("S-two decoding history-rollup demo")?;

    #[cfg(feature = "stwo-backend")]
    {
        let manifest = load_phase16_decoding_segment_rollup(proof_path)?;
        verify_phase16_decoding_segment_rollup_with_proof_checks(&manifest)?;

        println!("proof: {}", proof_path.display());
        println!("verified_stark: true");
        println!("proof_backend: {}", manifest.proof_backend);
        println!("rollup_version: {}", manifest.rollup_version);
        println!("semantic_scope: {}", manifest.semantic_scope);
        println!("proof_backend_version: {}", manifest.proof_backend_version);
        println!("statement_version: {}", manifest.statement_version);
        println!("total_rollups: {}", manifest.total_rollups);
        println!("total_segments: {}", manifest.total_segments);
        println!("total_steps: {}", manifest.total_steps);
        println!("max_rollup_segments: {}", manifest.max_rollup_segments);
        println!("history_chunk_pairs: {}", manifest.history_chunk_pairs);
        println!("rolling_kv_pairs: {}", manifest.layout.rolling_kv_pairs);
        println!("pair_width: {}", manifest.layout.pair_width);
        println!(
            "expected_rollup_version: {}",
            STWO_DECODING_SEGMENT_ROLLUP_VERSION_PHASE16
        );
        println!(
            "expected_semantic_scope: {}",
            STWO_DECODING_SEGMENT_ROLLUP_SCOPE_PHASE16
        );
        println!(
            "expected_proof_backend_version: {}",
            STWO_BACKEND_VERSION_PHASE12
        );
        if let Some(first) = manifest.rollups.first() {
            println!("first_rollup_start_step: {}", first.global_start_step_index);
            println!("first_rollup_segments: {}", first.total_segments);
        }
        if let Some(last) = manifest.rollups.last() {
            println!("last_rollup_start_step: {}", last.global_start_step_index);
            println!("last_rollup_segments: {}", last.total_segments);
            println!(
                "final_history_length: {}",
                last.global_to_state.kv_history_length
            );
            println!(
                "final_sealed_chunks: {}",
                last.global_to_state.kv_history_sealed_chunks
            );
            println!(
                "final_open_chunk_pairs: {}",
                last.global_to_state.kv_history_open_chunk_pairs
            );
        }

        Ok(())
    }

    #[cfg(not(feature = "stwo-backend"))]
    {
        let _ = proof_path;
        unreachable!("require_stwo_backend must fail without `stwo-backend`");
    }
}

fn prove_stwo_decoding_history_rollup_matrix_demo_command(
    output: &Path,
) -> llm_provable_computer::Result<()> {
    require_stwo_backend("S-two decoding history-rollup matrix demo")?;

    #[cfg(feature = "stwo-backend")]
    {
        let manifest = prove_phase17_decoding_rollup_matrix_demo()?;
        save_phase17_decoding_rollup_matrix(&manifest, output)?;

        println!("proof: {}", output.display());
        println!("proof_backend: {}", manifest.proof_backend);
        println!("matrix_version: {}", manifest.matrix_version);
        println!("semantic_scope: {}", manifest.semantic_scope);
        println!("proof_backend_version: {}", manifest.proof_backend_version);
        println!("statement_version: {}", manifest.statement_version);
        println!("total_layouts: {}", manifest.total_layouts);
        println!("total_rollups: {}", manifest.total_rollups);
        println!("total_segments: {}", manifest.total_segments);
        println!("total_steps: {}", manifest.total_steps);
        if let Some(first) = manifest.rollups.first() {
            println!("first_layout_rollups: {}", first.total_rollups);
            println!("first_layout_segments: {}", first.total_segments);
        }
        if let Some(last) = manifest.rollups.last() {
            println!("last_layout_rollups: {}", last.total_rollups);
            println!("last_layout_segments: {}", last.total_segments);
            if let Some(last_rollup) = last.rollups.last() {
                println!(
                    "final_history_length: {}",
                    last_rollup.global_to_state.kv_history_length
                );
            }
        }
        Ok(())
    }

    #[cfg(not(feature = "stwo-backend"))]
    {
        let _ = output;
        unreachable!("require_stwo_backend must fail without `stwo-backend`");
    }
}

fn verify_stwo_decoding_history_rollup_matrix_demo_command(
    proof_path: &Path,
) -> llm_provable_computer::Result<()> {
    require_stwo_backend("S-two decoding history-rollup matrix demo")?;

    #[cfg(feature = "stwo-backend")]
    {
        let manifest = load_phase17_decoding_rollup_matrix(proof_path)?;
        verify_phase17_decoding_rollup_matrix_with_proof_checks(&manifest)?;

        println!("proof: {}", proof_path.display());
        println!("verified_stark: true");
        println!("proof_backend: {}", manifest.proof_backend);
        println!("matrix_version: {}", manifest.matrix_version);
        println!("semantic_scope: {}", manifest.semantic_scope);
        println!("proof_backend_version: {}", manifest.proof_backend_version);
        println!("statement_version: {}", manifest.statement_version);
        println!("total_layouts: {}", manifest.total_layouts);
        println!("total_rollups: {}", manifest.total_rollups);
        println!("total_segments: {}", manifest.total_segments);
        println!("total_steps: {}", manifest.total_steps);
        println!(
            "expected_matrix_version: {}",
            STWO_DECODING_ROLLUP_MATRIX_VERSION_PHASE17
        );
        println!(
            "expected_semantic_scope: {}",
            STWO_DECODING_ROLLUP_MATRIX_SCOPE_PHASE17
        );
        println!(
            "expected_proof_backend_version: {}",
            STWO_BACKEND_VERSION_PHASE12
        );
        if let Some(first) = manifest.rollups.first() {
            println!("first_layout_rollups: {}", first.total_rollups);
            println!("first_layout_segments: {}", first.total_segments);
        }
        if let Some(last) = manifest.rollups.last() {
            println!("last_layout_rollups: {}", last.total_rollups);
            println!("last_layout_segments: {}", last.total_segments);
            if let Some(last_rollup) = last.rollups.last() {
                println!(
                    "final_history_length: {}",
                    last_rollup.global_to_state.kv_history_length
                );
            }
        }
        Ok(())
    }

    #[cfg(not(feature = "stwo-backend"))]
    {
        let _ = proof_path;
        unreachable!("require_stwo_backend must fail without `stwo-backend`");
    }
}

fn prove_stwo_decoding_matrix_accumulator_demo_command(
    output: &Path,
) -> llm_provable_computer::Result<()> {
    require_stwo_backend("S-two decoding matrix-accumulator demo")?;

    #[cfg(feature = "stwo-backend")]
    {
        let manifest = prove_phase21_decoding_matrix_accumulator_demo()?;
        save_phase21_decoding_matrix_accumulator(&manifest, output)?;

        println!("proof: {}", output.display());
        println!("proof_backend: {}", manifest.proof_backend);
        println!("accumulator_version: {}", manifest.accumulator_version);
        println!("semantic_scope: {}", manifest.semantic_scope);
        println!("proof_backend_version: {}", manifest.proof_backend_version);
        println!("statement_version: {}", manifest.statement_version);
        println!("total_matrices: {}", manifest.total_matrices);
        println!("total_layouts: {}", manifest.total_layouts);
        println!("total_rollups: {}", manifest.total_rollups);
        println!("total_segments: {}", manifest.total_segments);
        println!("total_steps: {}", manifest.total_steps);
        if let Some(first) = manifest.matrices.first() {
            println!("first_matrix_layouts: {}", first.total_layouts);
            println!("first_matrix_rollups: {}", first.total_rollups);
        }
        if let Some(last) = manifest.matrices.last() {
            println!("last_matrix_layouts: {}", last.total_layouts);
            println!("last_matrix_rollups: {}", last.total_rollups);
        }
        Ok(())
    }

    #[cfg(not(feature = "stwo-backend"))]
    {
        let _ = output;
        unreachable!("require_stwo_backend must fail without `stwo-backend`");
    }
}

fn verify_stwo_decoding_matrix_accumulator_demo_command(
    proof_path: &Path,
) -> llm_provable_computer::Result<()> {
    require_stwo_backend("S-two decoding matrix-accumulator demo")?;

    #[cfg(feature = "stwo-backend")]
    {
        let manifest = load_phase21_decoding_matrix_accumulator(proof_path)?;
        verify_phase21_decoding_matrix_accumulator_with_proof_checks(&manifest)?;

        println!("proof: {}", proof_path.display());
        println!("verified_stark: true");
        println!("proof_backend: {}", manifest.proof_backend);
        println!("accumulator_version: {}", manifest.accumulator_version);
        println!("semantic_scope: {}", manifest.semantic_scope);
        println!("proof_backend_version: {}", manifest.proof_backend_version);
        println!("statement_version: {}", manifest.statement_version);
        println!("total_matrices: {}", manifest.total_matrices);
        println!("total_layouts: {}", manifest.total_layouts);
        println!("total_rollups: {}", manifest.total_rollups);
        println!("total_segments: {}", manifest.total_segments);
        println!("total_steps: {}", manifest.total_steps);
        println!(
            "expected_accumulator_version: {}",
            STWO_DECODING_MATRIX_ACCUMULATOR_VERSION_PHASE21
        );
        println!(
            "expected_semantic_scope: {}",
            STWO_DECODING_MATRIX_ACCUMULATOR_SCOPE_PHASE21
        );
        println!(
            "expected_proof_backend_version: {}",
            STWO_BACKEND_VERSION_PHASE12
        );
        if let Some(first) = manifest.matrices.first() {
            println!("first_matrix_layouts: {}", first.total_layouts);
            println!("first_matrix_rollups: {}", first.total_rollups);
        }
        if let Some(last) = manifest.matrices.last() {
            println!("last_matrix_layouts: {}", last.total_layouts);
            println!("last_matrix_rollups: {}", last.total_rollups);
        }
        Ok(())
    }

    #[cfg(not(feature = "stwo-backend"))]
    {
        let _ = proof_path;
        unreachable!("require_stwo_backend must fail without `stwo-backend`");
    }
}

fn prove_stwo_decoding_lookup_accumulator_demo_command(
    output: &Path,
) -> llm_provable_computer::Result<()> {
    require_stwo_backend("S-two decoding lookup-accumulator demo")?;

    #[cfg(feature = "stwo-backend")]
    {
        let manifest = prove_phase22_decoding_lookup_accumulator_demo()?;
        save_phase22_decoding_lookup_accumulator(&manifest, output)?;

        println!("proof: {}", output.display());
        println!("proof_backend: {}", manifest.proof_backend);
        println!("accumulator_version: {}", manifest.accumulator_version);
        println!("semantic_scope: {}", manifest.semantic_scope);
        println!("proof_backend_version: {}", manifest.proof_backend_version);
        println!("statement_version: {}", manifest.statement_version);
        println!("total_matrices: {}", manifest.total_matrices);
        println!("total_layouts: {}", manifest.total_layouts);
        println!("total_rollups: {}", manifest.total_rollups);
        println!("total_segments: {}", manifest.total_segments);
        println!("total_steps: {}", manifest.total_steps);
        println!("lookup_delta_entries: {}", manifest.lookup_delta_entries);
        println!(
            "max_lookup_frontier_entries: {}",
            manifest.max_lookup_frontier_entries
        );
        Ok(())
    }

    #[cfg(not(feature = "stwo-backend"))]
    {
        let _ = output;
        unreachable!("require_stwo_backend must fail without `stwo-backend`");
    }
}

fn verify_stwo_decoding_lookup_accumulator_demo_command(
    proof_path: &Path,
) -> llm_provable_computer::Result<()> {
    require_stwo_backend("S-two decoding lookup-accumulator demo")?;

    #[cfg(feature = "stwo-backend")]
    {
        let manifest = load_phase22_decoding_lookup_accumulator(proof_path)?;
        verify_phase22_decoding_lookup_accumulator_with_proof_checks(&manifest)?;

        println!("proof: {}", proof_path.display());
        println!("verified_stark: true");
        println!("proof_backend: {}", manifest.proof_backend);
        println!("accumulator_version: {}", manifest.accumulator_version);
        println!("semantic_scope: {}", manifest.semantic_scope);
        println!("proof_backend_version: {}", manifest.proof_backend_version);
        println!("statement_version: {}", manifest.statement_version);
        println!("total_matrices: {}", manifest.total_matrices);
        println!("total_layouts: {}", manifest.total_layouts);
        println!("total_rollups: {}", manifest.total_rollups);
        println!("total_segments: {}", manifest.total_segments);
        println!("total_steps: {}", manifest.total_steps);
        println!("lookup_delta_entries: {}", manifest.lookup_delta_entries);
        println!(
            "max_lookup_frontier_entries: {}",
            manifest.max_lookup_frontier_entries
        );
        println!(
            "expected_accumulator_version: {}",
            STWO_DECODING_LOOKUP_ACCUMULATOR_VERSION_PHASE22
        );
        println!(
            "expected_semantic_scope: {}",
            STWO_DECODING_LOOKUP_ACCUMULATOR_SCOPE_PHASE22
        );
        println!(
            "expected_proof_backend_version: {}",
            STWO_BACKEND_VERSION_PHASE12
        );
        Ok(())
    }

    #[cfg(not(feature = "stwo-backend"))]
    {
        let _ = proof_path;
        unreachable!("require_stwo_backend must fail without `stwo-backend`");
    }
}

fn prove_stwo_decoding_cross_step_lookup_accumulator_demo_command(
    output: &Path,
) -> llm_provable_computer::Result<()> {
    require_stwo_backend("S-two decoding cross-step lookup accumulator demo")?;

    #[cfg(feature = "stwo-backend")]
    {
        let manifest = prove_phase23_decoding_cross_step_lookup_accumulator_demo()?;
        save_phase23_decoding_cross_step_lookup_accumulator(&manifest, output)?;

        println!("proof: {}", output.display());
        println!("proof_backend: {}", manifest.proof_backend);
        println!("accumulator_version: {}", manifest.accumulator_version);
        println!("semantic_scope: {}", manifest.semantic_scope);
        println!("proof_backend_version: {}", manifest.proof_backend_version);
        println!("statement_version: {}", manifest.statement_version);
        println!("member_count: {}", manifest.member_count);
        println!("total_matrices: {}", manifest.total_matrices);
        println!("total_layouts: {}", manifest.total_layouts);
        println!("total_rollups: {}", manifest.total_rollups);
        println!("total_segments: {}", manifest.total_segments);
        println!("total_steps: {}", manifest.total_steps);
        println!("lookup_delta_entries: {}", manifest.lookup_delta_entries);
        println!(
            "max_lookup_frontier_entries: {}",
            manifest.max_lookup_frontier_entries
        );
        Ok(())
    }

    #[cfg(not(feature = "stwo-backend"))]
    {
        let _ = output;
        unreachable!("require_stwo_backend must fail without `stwo-backend`");
    }
}

fn verify_stwo_decoding_cross_step_lookup_accumulator_demo_command(
    proof_path: &Path,
) -> llm_provable_computer::Result<()> {
    require_stwo_backend("S-two decoding cross-step lookup accumulator demo")?;

    #[cfg(feature = "stwo-backend")]
    {
        let manifest = load_phase23_decoding_cross_step_lookup_accumulator(proof_path)?;
        verify_phase23_decoding_cross_step_lookup_accumulator_with_proof_checks(&manifest)?;

        println!("proof: {}", proof_path.display());
        println!("verified_stark: true");
        println!("proof_backend: {}", manifest.proof_backend);
        println!("accumulator_version: {}", manifest.accumulator_version);
        println!("semantic_scope: {}", manifest.semantic_scope);
        println!("proof_backend_version: {}", manifest.proof_backend_version);
        println!("statement_version: {}", manifest.statement_version);
        println!("member_count: {}", manifest.member_count);
        println!("total_matrices: {}", manifest.total_matrices);
        println!("total_layouts: {}", manifest.total_layouts);
        println!("total_rollups: {}", manifest.total_rollups);
        println!("total_segments: {}", manifest.total_segments);
        println!("total_steps: {}", manifest.total_steps);
        println!("lookup_delta_entries: {}", manifest.lookup_delta_entries);
        println!(
            "max_lookup_frontier_entries: {}",
            manifest.max_lookup_frontier_entries
        );
        println!(
            "expected_accumulator_version: {}",
            STWO_DECODING_CROSS_STEP_LOOKUP_ACCUMULATOR_VERSION_PHASE23
        );
        println!(
            "expected_semantic_scope: {}",
            STWO_DECODING_CROSS_STEP_LOOKUP_ACCUMULATOR_SCOPE_PHASE23
        );
        println!(
            "expected_proof_backend_version: {}",
            STWO_BACKEND_VERSION_PHASE12
        );
        Ok(())
    }

    #[cfg(not(feature = "stwo-backend"))]
    {
        let _ = proof_path;
        unreachable!("require_stwo_backend must fail without `stwo-backend`");
    }
}

fn prove_stwo_decoding_state_relation_accumulator_demo_command(
    output: &Path,
) -> llm_provable_computer::Result<()> {
    require_stwo_backend("S-two decoding state relation accumulator demo")?;

    #[cfg(feature = "stwo-backend")]
    {
        let manifest = prove_phase24_decoding_state_relation_accumulator_demo()?;
        save_phase24_decoding_state_relation_accumulator(&manifest, output)?;

        println!("proof: {}", output.display());
        println!("proof_backend: {}", manifest.proof_backend);
        println!("accumulator_version: {}", manifest.accumulator_version);
        println!("semantic_scope: {}", manifest.semantic_scope);
        println!("proof_backend_version: {}", manifest.proof_backend_version);
        println!("statement_version: {}", manifest.statement_version);
        println!("member_count: {}", manifest.member_count);
        println!("total_matrices: {}", manifest.total_matrices);
        println!("total_layouts: {}", manifest.total_layouts);
        println!("total_rollups: {}", manifest.total_rollups);
        println!("total_segments: {}", manifest.total_segments);
        println!("total_steps: {}", manifest.total_steps);
        println!("lookup_delta_entries: {}", manifest.lookup_delta_entries);
        println!(
            "max_lookup_frontier_entries: {}",
            manifest.max_lookup_frontier_entries
        );
        Ok(())
    }

    #[cfg(not(feature = "stwo-backend"))]
    {
        let _ = output;
        unreachable!("require_stwo_backend must fail without `stwo-backend`");
    }
}

fn verify_stwo_decoding_state_relation_accumulator_demo_command(
    proof_path: &Path,
) -> llm_provable_computer::Result<()> {
    require_stwo_backend("S-two decoding state relation accumulator demo")?;

    #[cfg(feature = "stwo-backend")]
    {
        let manifest = load_phase24_decoding_state_relation_accumulator(proof_path)?;
        verify_phase24_decoding_state_relation_accumulator_with_proof_checks(&manifest)?;

        println!("proof: {}", proof_path.display());
        println!("verified_stark: true");
        println!("proof_backend: {}", manifest.proof_backend);
        println!("accumulator_version: {}", manifest.accumulator_version);
        println!("semantic_scope: {}", manifest.semantic_scope);
        println!("proof_backend_version: {}", manifest.proof_backend_version);
        println!("statement_version: {}", manifest.statement_version);
        println!("member_count: {}", manifest.member_count);
        println!("total_matrices: {}", manifest.total_matrices);
        println!("total_layouts: {}", manifest.total_layouts);
        println!("total_rollups: {}", manifest.total_rollups);
        println!("total_segments: {}", manifest.total_segments);
        println!("total_steps: {}", manifest.total_steps);
        println!("lookup_delta_entries: {}", manifest.lookup_delta_entries);
        println!(
            "max_lookup_frontier_entries: {}",
            manifest.max_lookup_frontier_entries
        );
        println!(
            "expected_accumulator_version: {}",
            STWO_DECODING_STATE_RELATION_ACCUMULATOR_VERSION_PHASE24
        );
        println!(
            "expected_semantic_scope: {}",
            STWO_DECODING_STATE_RELATION_ACCUMULATOR_SCOPE_PHASE24
        );
        println!(
            "expected_proof_backend_version: {}",
            STWO_BACKEND_VERSION_PHASE12
        );
        Ok(())
    }

    #[cfg(not(feature = "stwo-backend"))]
    {
        let _ = proof_path;
        unreachable!("require_stwo_backend must fail without `stwo-backend`");
    }
}

fn prove_stwo_intervalized_decoding_state_relation_demo_command(
    output: &Path,
) -> llm_provable_computer::Result<()> {
    require_stwo_backend("S-two intervalized decoding state relation demo")?;

    #[cfg(feature = "stwo-backend")]
    {
        let manifest = prove_phase25_intervalized_decoding_state_relation_demo()?;
        save_phase25_intervalized_decoding_state_relation(&manifest, output)?;

        println!("proof: {}", output.display());
        println!("proof_backend: {}", manifest.proof_backend);
        println!("artifact_version: {}", manifest.artifact_version);
        println!("semantic_scope: {}", manifest.semantic_scope);
        println!("proof_backend_version: {}", manifest.proof_backend_version);
        println!("statement_version: {}", manifest.statement_version);
        println!("member_count: {}", manifest.member_count);
        println!("total_matrices: {}", manifest.total_matrices);
        println!("total_layouts: {}", manifest.total_layouts);
        println!("total_rollups: {}", manifest.total_rollups);
        println!("total_segments: {}", manifest.total_segments);
        println!("total_steps: {}", manifest.total_steps);
        println!("lookup_delta_entries: {}", manifest.lookup_delta_entries);
        println!(
            "max_lookup_frontier_entries: {}",
            manifest.max_lookup_frontier_entries
        );
        Ok(())
    }

    #[cfg(not(feature = "stwo-backend"))]
    {
        let _ = output;
        unreachable!("require_stwo_backend must fail without `stwo-backend`");
    }
}

fn verify_stwo_intervalized_decoding_state_relation_demo_command(
    proof_path: &Path,
) -> llm_provable_computer::Result<()> {
    require_stwo_backend("S-two intervalized decoding state relation demo")?;

    #[cfg(feature = "stwo-backend")]
    {
        let manifest = load_phase25_intervalized_decoding_state_relation(proof_path)?;
        verify_phase25_intervalized_decoding_state_relation_with_proof_checks(&manifest)?;

        println!("proof: {}", proof_path.display());
        println!("verified_stark: true");
        println!("proof_backend: {}", manifest.proof_backend);
        println!("artifact_version: {}", manifest.artifact_version);
        println!("semantic_scope: {}", manifest.semantic_scope);
        println!("proof_backend_version: {}", manifest.proof_backend_version);
        println!("statement_version: {}", manifest.statement_version);
        println!("member_count: {}", manifest.member_count);
        println!("total_matrices: {}", manifest.total_matrices);
        println!("total_layouts: {}", manifest.total_layouts);
        println!("total_rollups: {}", manifest.total_rollups);
        println!("total_segments: {}", manifest.total_segments);
        println!("total_steps: {}", manifest.total_steps);
        println!("lookup_delta_entries: {}", manifest.lookup_delta_entries);
        println!(
            "max_lookup_frontier_entries: {}",
            manifest.max_lookup_frontier_entries
        );
        println!(
            "expected_artifact_version: {}",
            STWO_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE25
        );
        println!(
            "expected_proof_backend_version: {}",
            STWO_BACKEND_VERSION_PHASE12
        );
        Ok(())
    }

    #[cfg(not(feature = "stwo-backend"))]
    {
        let _ = proof_path;
        unreachable!("require_stwo_backend must fail without `stwo-backend`");
    }
}

fn prove_stwo_folded_intervalized_decoding_state_relation_demo_command(
    output: &Path,
) -> llm_provable_computer::Result<()> {
    require_stwo_backend("S-two folded intervalized decoding state relation demo")?;

    #[cfg(feature = "stwo-backend")]
    {
        let manifest = prove_phase26_folded_intervalized_decoding_state_relation_demo()?;
        save_phase26_folded_intervalized_decoding_state_relation(&manifest, output)?;

        println!("proof: {}", output.display());
        println!("proof_backend: {}", manifest.proof_backend);
        println!("artifact_version: {}", manifest.artifact_version);
        println!("semantic_scope: {}", manifest.semantic_scope);
        println!("proof_backend_version: {}", manifest.proof_backend_version);
        println!("statement_version: {}", manifest.statement_version);
        println!("bounded_fold_arity: {}", manifest.bounded_fold_arity);
        println!("member_count: {}", manifest.member_count);
        println!("total_matrices: {}", manifest.total_matrices);
        println!("total_layouts: {}", manifest.total_layouts);
        println!("total_rollups: {}", manifest.total_rollups);
        println!("total_segments: {}", manifest.total_segments);
        println!("total_steps: {}", manifest.total_steps);
        println!("lookup_delta_entries: {}", manifest.lookup_delta_entries);
        println!(
            "max_lookup_frontier_entries: {}",
            manifest.max_lookup_frontier_entries
        );
        Ok(())
    }

    #[cfg(not(feature = "stwo-backend"))]
    {
        let _ = output;
        unreachable!("require_stwo_backend must fail without `stwo-backend`");
    }
}

fn verify_stwo_folded_intervalized_decoding_state_relation_demo_command(
    proof_path: &Path,
) -> llm_provable_computer::Result<()> {
    require_stwo_backend("S-two folded intervalized decoding state relation demo")?;

    #[cfg(feature = "stwo-backend")]
    {
        let manifest = load_phase26_folded_intervalized_decoding_state_relation(proof_path)?;
        verify_phase26_folded_intervalized_decoding_state_relation_with_proof_checks(&manifest)?;

        println!("proof: {}", proof_path.display());
        println!("verified_stark: true");
        println!("proof_backend: {}", manifest.proof_backend);
        println!("artifact_version: {}", manifest.artifact_version);
        println!("semantic_scope: {}", manifest.semantic_scope);
        println!("proof_backend_version: {}", manifest.proof_backend_version);
        println!("statement_version: {}", manifest.statement_version);
        println!("bounded_fold_arity: {}", manifest.bounded_fold_arity);
        println!("member_count: {}", manifest.member_count);
        println!("total_matrices: {}", manifest.total_matrices);
        println!("total_layouts: {}", manifest.total_layouts);
        println!("total_rollups: {}", manifest.total_rollups);
        println!("total_segments: {}", manifest.total_segments);
        println!("total_steps: {}", manifest.total_steps);
        println!("lookup_delta_entries: {}", manifest.lookup_delta_entries);
        println!(
            "max_lookup_frontier_entries: {}",
            manifest.max_lookup_frontier_entries
        );
        println!(
            "expected_artifact_version: {}",
            STWO_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE26
        );
        println!(
            "expected_proof_backend_version: {}",
            STWO_BACKEND_VERSION_PHASE12
        );
        Ok(())
    }

    #[cfg(not(feature = "stwo-backend"))]
    {
        let _ = proof_path;
        unreachable!("require_stwo_backend must fail without `stwo-backend`");
    }
}

fn prove_stwo_chained_folded_intervalized_decoding_state_relation_demo_command(
    output: &Path,
) -> llm_provable_computer::Result<()> {
    require_stwo_backend("S-two chained folded intervalized decoding state relation demo")?;

    #[cfg(feature = "stwo-backend")]
    {
        let manifest = prove_phase27_chained_folded_intervalized_decoding_state_relation_demo()?;
        save_phase27_chained_folded_intervalized_decoding_state_relation(&manifest, output)?;

        println!("proof: {}", output.display());
        println!("proof_backend: {}", manifest.proof_backend);
        println!("artifact_version: {}", manifest.artifact_version);
        println!("semantic_scope: {}", manifest.semantic_scope);
        println!("proof_backend_version: {}", manifest.proof_backend_version);
        println!("statement_version: {}", manifest.statement_version);
        println!("bounded_chain_arity: {}", manifest.bounded_chain_arity);
        println!("member_count: {}", manifest.member_count);
        println!("total_phase25_members: {}", manifest.total_phase25_members);
        println!("max_nested_fold_arity: {}", manifest.max_nested_fold_arity);
        println!("total_matrices: {}", manifest.total_matrices);
        println!("total_layouts: {}", manifest.total_layouts);
        println!("total_rollups: {}", manifest.total_rollups);
        println!("total_segments: {}", manifest.total_segments);
        println!("total_steps: {}", manifest.total_steps);
        println!("lookup_delta_entries: {}", manifest.lookup_delta_entries);
        println!(
            "max_lookup_frontier_entries: {}",
            manifest.max_lookup_frontier_entries
        );
        Ok(())
    }

    #[cfg(not(feature = "stwo-backend"))]
    {
        let _ = output;
        unreachable!("require_stwo_backend must fail without `stwo-backend`");
    }
}

fn verify_stwo_chained_folded_intervalized_decoding_state_relation_demo_command(
    proof_path: &Path,
) -> llm_provable_computer::Result<()> {
    require_stwo_backend("S-two chained folded intervalized decoding state relation demo")?;

    #[cfg(feature = "stwo-backend")]
    {
        let manifest =
            load_phase27_chained_folded_intervalized_decoding_state_relation_with_proof_checks(
                proof_path,
            )?;

        println!("proof: {}", proof_path.display());
        println!("verified_stark: true");
        println!("proof_backend: {}", manifest.proof_backend);
        println!("artifact_version: {}", manifest.artifact_version);
        println!("semantic_scope: {}", manifest.semantic_scope);
        println!("proof_backend_version: {}", manifest.proof_backend_version);
        println!("statement_version: {}", manifest.statement_version);
        println!("bounded_chain_arity: {}", manifest.bounded_chain_arity);
        println!("member_count: {}", manifest.member_count);
        println!("total_phase25_members: {}", manifest.total_phase25_members);
        println!("max_nested_fold_arity: {}", manifest.max_nested_fold_arity);
        println!("total_matrices: {}", manifest.total_matrices);
        println!("total_layouts: {}", manifest.total_layouts);
        println!("total_rollups: {}", manifest.total_rollups);
        println!("total_segments: {}", manifest.total_segments);
        println!("total_steps: {}", manifest.total_steps);
        println!("lookup_delta_entries: {}", manifest.lookup_delta_entries);
        println!(
            "max_lookup_frontier_entries: {}",
            manifest.max_lookup_frontier_entries
        );
        println!(
            "expected_artifact_version: {}",
            STWO_CHAINED_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE27
        );
        println!(
            "expected_proof_backend_version: {}",
            STWO_BACKEND_VERSION_PHASE12
        );
        Ok(())
    }

    #[cfg(not(feature = "stwo-backend"))]
    {
        let _ = proof_path;
        unreachable!("require_stwo_backend must fail without `stwo-backend`");
    }
}

#[cfg(feature = "stwo-backend")]
fn prove_stwo_aggregated_chained_folded_intervalized_decoding_state_relation_demo_command(
    output: &Path,
) -> llm_provable_computer::Result<()> {
    require_stwo_backend(
        "S-two aggregated chained folded intervalized decoding state relation demo",
    )?;

    #[cfg(feature = "stwo-backend")]
    {
        let manifest =
            prove_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_demo()?;
        save_phase28_aggregated_chained_folded_intervalized_decoding_state_relation(
            &manifest, output,
        )?;

        println!("proof: {}", output.display());
        println!("proof_backend: {}", manifest.proof_backend);
        println!("artifact_version: {}", manifest.artifact_version);
        println!("semantic_scope: {}", manifest.semantic_scope);
        println!("proof_backend_version: {}", manifest.proof_backend_version);
        println!("statement_version: {}", manifest.statement_version);
        println!(
            "bounded_aggregation_arity: {}",
            manifest.bounded_aggregation_arity
        );
        println!("member_count: {}", manifest.member_count);
        println!("total_phase26_members: {}", manifest.total_phase26_members);
        println!("total_phase25_members: {}", manifest.total_phase25_members);
        println!(
            "max_nested_chain_arity: {}",
            manifest.max_nested_chain_arity
        );
        println!("max_nested_fold_arity: {}", manifest.max_nested_fold_arity);
        println!("total_matrices: {}", manifest.total_matrices);
        println!("total_layouts: {}", manifest.total_layouts);
        println!("total_rollups: {}", manifest.total_rollups);
        println!("total_segments: {}", manifest.total_segments);
        println!("total_steps: {}", manifest.total_steps);
        println!("lookup_delta_entries: {}", manifest.lookup_delta_entries);
        println!(
            "max_lookup_frontier_entries: {}",
            manifest.max_lookup_frontier_entries
        );
        Ok(())
    }

    #[cfg(not(feature = "stwo-backend"))]
    {
        let _ = output;
        unreachable!("require_stwo_backend must fail without `stwo-backend`");
    }
}

#[cfg(feature = "stwo-backend")]
fn verify_stwo_aggregated_chained_folded_intervalized_decoding_state_relation_demo_command(
    proof_path: &Path,
) -> llm_provable_computer::Result<()> {
    require_stwo_backend(
        "S-two aggregated chained folded intervalized decoding state relation demo",
    )?;

    #[cfg(feature = "stwo-backend")]
    {
        let manifest =
            load_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_proof_checks(
                proof_path,
            )?;

        println!("proof: {}", proof_path.display());
        println!("verified_stark: true");
        println!("proof_backend: {}", manifest.proof_backend);
        println!("artifact_version: {}", manifest.artifact_version);
        println!("semantic_scope: {}", manifest.semantic_scope);
        println!("proof_backend_version: {}", manifest.proof_backend_version);
        println!("statement_version: {}", manifest.statement_version);
        println!(
            "bounded_aggregation_arity: {}",
            manifest.bounded_aggregation_arity
        );
        println!("member_count: {}", manifest.member_count);
        println!("total_phase26_members: {}", manifest.total_phase26_members);
        println!("total_phase25_members: {}", manifest.total_phase25_members);
        println!(
            "max_nested_chain_arity: {}",
            manifest.max_nested_chain_arity
        );
        println!("max_nested_fold_arity: {}", manifest.max_nested_fold_arity);
        println!("total_matrices: {}", manifest.total_matrices);
        println!("total_layouts: {}", manifest.total_layouts);
        println!("total_rollups: {}", manifest.total_rollups);
        println!("total_segments: {}", manifest.total_segments);
        println!("total_steps: {}", manifest.total_steps);
        println!("lookup_delta_entries: {}", manifest.lookup_delta_entries);
        println!(
            "max_lookup_frontier_entries: {}",
            manifest.max_lookup_frontier_entries
        );
        println!(
            "expected_artifact_version: {}",
            STWO_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE28
        );
        println!(
            "expected_proof_backend_version: {}",
            STWO_BACKEND_VERSION_PHASE12
        );
        Ok(())
    }

    #[cfg(not(feature = "stwo-backend"))]
    {
        let _ = proof_path;
        unreachable!("require_stwo_backend must fail without `stwo-backend`");
    }
}

#[cfg(feature = "stwo-backend")]
fn prepare_stwo_recursive_compression_input_contract_command(
    phase28_path: &Path,
    output: &Path,
) -> llm_provable_computer::Result<()> {
    require_stwo_backend("S-two Phase 29 recursive-compression input contract")?;

    reject_phase29_contract_plain_json_gzip_output(output)?;
    let phase28 =
        load_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_proof_checks(
            phase28_path,
        )?;
    let contract =
        phase29_prepare_recursive_compression_input_contract_from_proof_checked_phase28(&phase28)?;
    let json = serde_json::to_vec_pretty(&contract)
        .map_err(|error| VmError::Serialization(error.to_string()))?;
    fs::write(output, json)?;

    println!("output: {}", output.display());
    println!("phase28: {}", phase28_path.display());
    println!("verified_phase28: true");
    print_phase29_recursive_compression_input_contract_report(&contract);

    Ok(())
}

#[cfg(feature = "stwo-backend")]
fn verify_stwo_recursive_compression_input_contract_command(
    input_path: &Path,
) -> llm_provable_computer::Result<()> {
    require_stwo_backend("S-two Phase 29 recursive-compression input contract")?;

    let contract = load_phase29_recursive_compression_input_contract(input_path)?;

    println!("input: {}", input_path.display());
    println!("verified_contract: true");
    print_phase29_recursive_compression_input_contract_report(&contract);

    Ok(())
}

#[cfg(feature = "stwo-backend")]
fn reject_phase29_contract_plain_json_gzip_output(
    output: &Path,
) -> llm_provable_computer::Result<()> {
    if output.extension().and_then(|extension| extension.to_str()) == Some("gz") {
        return Err(VmError::InvalidConfig(
            "prepare-stwo-recursive-compression-input-contract writes plain JSON; use a `.json` output path"
                .to_string(),
        ));
    }
    Ok(())
}

#[cfg(feature = "stwo-backend")]
fn print_phase29_recursive_compression_input_contract_report(
    contract: &Phase29RecursiveCompressionInputContract,
) {
    println!("proof_backend: {}", contract.proof_backend);
    println!("contract_version: {}", contract.contract_version);
    println!("semantic_scope: {}", contract.semantic_scope);
    println!(
        "phase28_artifact_version: {}",
        contract.phase28_artifact_version
    );
    println!(
        "phase28_proof_backend_version: {}",
        contract.phase28_proof_backend_version
    );
    println!("statement_version: {}", contract.statement_version);
    println!(
        "required_recursion_posture: {}",
        contract.required_recursion_posture
    );
    println!(
        "recursive_verification_claimed: {}",
        contract.recursive_verification_claimed
    );
    println!(
        "cryptographic_compression_claimed: {}",
        contract.cryptographic_compression_claimed
    );
    println!("phase28_member_count: {}", contract.phase28_member_count);
    println!("total_phase26_members: {}", contract.total_phase26_members);
    println!("total_phase25_members: {}", contract.total_phase25_members);
    println!("total_matrices: {}", contract.total_matrices);
    println!("total_layouts: {}", contract.total_layouts);
    println!("total_rollups: {}", contract.total_rollups);
    println!("total_segments: {}", contract.total_segments);
    println!("total_steps: {}", contract.total_steps);
    println!("lookup_delta_entries: {}", contract.lookup_delta_entries);
    println!(
        "max_lookup_frontier_entries: {}",
        contract.max_lookup_frontier_entries
    );
    println!(
        "input_contract_commitment: {}",
        contract.input_contract_commitment
    );
    println!(
        "expected_contract_version: {}",
        STWO_RECURSIVE_COMPRESSION_INPUT_CONTRACT_VERSION_PHASE29
    );
    println!(
        "expected_semantic_scope: {}",
        STWO_RECURSIVE_COMPRESSION_INPUT_CONTRACT_SCOPE_PHASE29
    );
}

fn verify_stwo_normalization_demo_command(proof_path: &Path) -> llm_provable_computer::Result<()> {
    #[cfg(not(feature = "stwo-backend"))]
    {
        let _ = proof_path;
        return Err(VmError::UnsupportedProof(
            "S-two normalization demo requires building with `--features stwo-backend`".to_string(),
        ));
    }

    #[cfg(feature = "stwo-backend")]
    if !stwo_backend_enabled() {
        return Err(VmError::UnsupportedProof(
            "S-two normalization demo requires building with `--features stwo-backend`".to_string(),
        ));
    }

    #[cfg(feature = "stwo-backend")]
    {
        let proof = load_phase5_normalization_lookup_proof(proof_path)?;
        let verified = verify_phase5_normalization_lookup_demo_envelope(&proof)?;
        if !verified {
            return Err(VmError::InvalidConfig(format!(
                "normalization demo proof verification failed for {}",
                proof_path.display()
            )));
        }

        println!("proof: {}", proof_path.display());
        println!("verified_stark: true");
        println!("proof_backend: {}", proof.proof_backend);
        println!("proof_backend_version: {}", proof.proof_backend_version);
        println!("statement_version: {}", proof.statement_version);
        println!("semantic_scope: {}", proof.semantic_scope);
        println!("canonical_table_rows: {}", proof.canonical_table_rows.len());
        println!("expected_statement_version: {STWO_NORMALIZATION_STATEMENT_VERSION_PHASE5}");
        println!("expected_semantic_scope: {STWO_NORMALIZATION_SEMANTIC_SCOPE_PHASE5}");
        println!("expected_proof_backend_version: {STWO_NORMALIZATION_PROOF_VERSION_PHASE5}");
        println!("proof_bytes: {}", proof.proof.len());

        Ok(())
    }
}

fn prepare_stwo_recursion_batch_command(
    proofs: &[PathBuf],
    output: &Path,
) -> llm_provable_computer::Result<()> {
    if proofs.is_empty() {
        return Err(VmError::InvalidConfig(
            "prepare-stwo-recursion-batch requires at least one `--proof` path".to_string(),
        ));
    }

    let loaded = proofs
        .iter()
        .map(|path| load_execution_stark_proof(path))
        .collect::<Result<Vec<_>, _>>()?;
    let manifest = phase6_prepare_recursion_batch(&loaded)?;
    let json = serde_json::to_string_pretty(&manifest)
        .map_err(|error| VmError::Serialization(error.to_string()))?;
    fs::write(output, json)?;

    println!("output: {}", output.display());
    println!("proof_backend: {}", manifest.proof_backend);
    println!("batch_version: {}", manifest.batch_version);
    println!("semantic_scope: {}", manifest.semantic_scope);
    println!("proof_backend_version: {}", manifest.proof_backend_version);
    println!("statement_version: {}", manifest.statement_version);
    println!("total_proofs: {}", manifest.total_proofs);
    println!("total_steps: {}", manifest.total_steps);
    println!("total_proof_bytes: {}", manifest.total_proof_bytes);
    println!("expected_batch_version: {STWO_RECURSION_BATCH_VERSION_PHASE6}");
    println!("expected_semantic_scope: {STWO_RECURSION_BATCH_SCOPE_PHASE6}");

    Ok(())
}

fn research_v2_step_command(
    program: &Path,
    output: &Path,
    max_steps: usize,
    layers: usize,
    attention_mode: Attention2DMode,
) -> llm_provable_computer::Result<()> {
    research_v2_step_command_impl(program, output, max_steps, layers, attention_mode)
}

fn research_v2_trace_command(
    program: &Path,
    output: &Path,
    max_steps: usize,
    layers: usize,
    attention_mode: Attention2DMode,
    allow_mismatch: bool,
) -> llm_provable_computer::Result<()> {
    research_v2_trace_command_impl(
        program,
        output,
        max_steps,
        layers,
        attention_mode,
        allow_mismatch,
    )
}

fn research_v2_matrix_command(
    output: &Path,
    programs: &[PathBuf],
    include_default_suite: bool,
    max_steps: usize,
    layers: usize,
    attention_mode: Attention2DMode,
    allow_mismatch: bool,
) -> llm_provable_computer::Result<()> {
    research_v2_matrix_command_impl(
        output,
        programs,
        include_default_suite,
        max_steps,
        layers,
        attention_mode,
        allow_mismatch,
    )
}

fn research_v3_equivalence_command(
    program: &Path,
    output: &Path,
    max_steps: usize,
    layers: usize,
    attention_mode: Attention2DMode,
) -> llm_provable_computer::Result<()> {
    research_v3_equivalence_command_impl(program, output, max_steps, layers, attention_mode)
}

fn verify_research_v3_equivalence_command(artifact: &Path) -> llm_provable_computer::Result<()> {
    verify_research_v3_equivalence_command_impl(artifact)
}

fn prepare_hf_provenance_manifest_command(
    command: HfProvenanceManifestCommand,
) -> llm_provable_computer::Result<()> {
    validate_hf_identifier("hub_repo", &command.hub_repo)?;
    validate_hf_identifier("tokenizer_id", &command.tokenizer_id)?;
    validate_hf_pinned_revision("hub_revision", &command.hub_revision)?;
    let tokenizer_revision = command
        .tokenizer_revision
        .unwrap_or_else(|| command.hub_revision.clone());
    validate_hf_pinned_revision("tokenizer_revision", &tokenizer_revision)?;

    let tokenizer = HfTokenizerProvenance {
        tokenizer_id: command.tokenizer_id,
        tokenizer_revision,
        tokenizer_json: hf_optional_file_commitment(command.tokenizer_json.as_deref())?,
        tokenizer_config: hf_optional_file_commitment(command.tokenizer_config.as_deref())?,
        tokenization_transcript: hf_optional_file_commitment(
            command.tokenization_transcript.as_deref(),
        )?,
    };
    let safetensors = command
        .safetensors_files
        .iter()
        .map(|path| hf_safetensors_file_commitment(path))
        .collect::<llm_provable_computer::Result<Vec<_>>>()?;
    if command.onnx_model.is_none()
        && (command.onnx_metadata.is_some()
            || !command.onnx_external_data_files.is_empty()
            || command.onnx_exporter_version.is_some())
    {
        return Err(VmError::InvalidConfig(
            "HF provenance ONNX metadata, exporter version, or external-data files require --onnx-model".to_string(),
        ));
    }
    let onnx_export = command
        .onnx_model
        .as_deref()
        .map(|path| {
            let mut external_data_files = command
                .onnx_external_data_files
                .iter()
                .map(|path| hf_file_commitment(path))
                .collect::<llm_provable_computer::Result<Vec<_>>>()?;
            external_data_files.sort_by(|a, b| a.path.cmp(&b.path));
            Ok::<HfOnnxExportProvenance, VmError>(HfOnnxExportProvenance {
                exporter: command.onnx_exporter.clone(),
                exporter_version: command.onnx_exporter_version.clone(),
                graph: hf_file_commitment(path)?,
                metadata: hf_optional_file_commitment(command.onnx_metadata.as_deref())?,
                external_data_files,
            })
        })
        .transpose()?;
    let release = HfReleaseMetadata {
        model_card: hf_optional_file_commitment(command.model_card.as_deref())?,
        doi: command.doi,
        datasets: command.datasets,
        notes: command.notes,
    };
    let limitations = hf_provenance_limitations();
    let hub_binding_hash = hash_json_projection_hex(&HfHubBinding {
        hub_repo: &command.hub_repo,
        hub_revision: &command.hub_revision,
    })?;
    let manifest = HfProvenanceManifest {
        manifest_version: HF_PROVENANCE_MANIFEST_VERSION.to_string(),
        semantic_scope: HF_PROVENANCE_SEMANTIC_SCOPE.to_string(),
        commitment_hash_function: HF_PROVENANCE_HASH_FUNCTION.to_string(),
        hub_repo: command.hub_repo,
        hub_revision: command.hub_revision,
        commitments: HfProvenanceCommitments {
            hub_binding_hash,
            tokenizer_hash: hash_json_projection_hex(&tokenizer)?,
            safetensors_manifest_hash: hash_json_projection_hex(&safetensors)?,
            onnx_export_hash: hash_json_projection_hex(&onnx_export)?,
            release_metadata_hash: hash_json_projection_hex(&release)?,
            limitations_hash: hash_json_projection_hex(&limitations)?,
        },
        tokenizer,
        safetensors,
        onnx_export,
        release,
        limitations,
    };
    verify_hf_provenance_manifest(&manifest)?;
    let bytes = serialize_hf_provenance_manifest_bytes(&manifest, &command.output)?;
    write_bytes_atomically(&command.output, &bytes)?;

    println!("hf_provenance_manifest: {}", command.output.display());
    println!("manifest_version: {}", manifest.manifest_version);
    println!("semantic_scope: {}", manifest.semantic_scope);
    println!("hub_repo: {}", manifest.hub_repo);
    println!("hub_revision: {}", manifest.hub_revision);
    println!("tokenizer_id: {}", manifest.tokenizer.tokenizer_id);
    println!("safetensors_files: {}", manifest.safetensors.len());
    println!(
        "commitment_safetensors_manifest_hash: {}",
        manifest.commitments.safetensors_manifest_hash
    );

    Ok(())
}

struct BoundedManifestWriter {
    bytes: Vec<u8>,
    max_len: usize,
    attempted_len: usize,
}

impl BoundedManifestWriter {
    fn new(max_len: usize) -> Self {
        Self {
            bytes: Vec::new(),
            max_len,
            attempted_len: 0,
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for BoundedManifestWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let attempted_len = self
            .bytes
            .len()
            .checked_add(buf.len())
            .ok_or_else(|| std::io::Error::other("HF provenance manifest size overflow"))?;
        if attempted_len > self.max_len {
            self.attempted_len = attempted_len;
            return Err(std::io::Error::other(
                "HF provenance manifest exceeds byte limit",
            ));
        }
        self.attempted_len = attempted_len;
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn serialize_hf_provenance_manifest_bytes(
    manifest: &HfProvenanceManifest,
    output_path: &Path,
) -> llm_provable_computer::Result<Vec<u8>> {
    let mut writer = BoundedManifestWriter::new(MAX_HF_PROVENANCE_MANIFEST_JSON_BYTES);
    match serde_json::to_writer_pretty(&mut writer, manifest) {
        Ok(()) => Ok(writer.into_bytes()),
        Err(err) if writer.attempted_len > MAX_HF_PROVENANCE_MANIFEST_JSON_BYTES || err.is_io() => {
            let observed_len = writer
                .attempted_len
                .max(MAX_HF_PROVENANCE_MANIFEST_JSON_BYTES + 1);
            Err(VmError::InvalidConfig(format!(
                "HF provenance manifest {} would be at least {} bytes, exceeding the limit of {} bytes",
                output_path.display(),
                observed_len,
                MAX_HF_PROVENANCE_MANIFEST_JSON_BYTES
            )))
        }
        Err(err) => Err(VmError::Serialization(format!(
            "failed to serialize HF provenance manifest: {err}"
        ))),
    }
}

#[cfg_attr(not(windows), allow(dead_code))]
fn require_windows_regular_file_identity(
    path: &Path,
    label: &str,
    volume_serial_number: Option<u32>,
    file_index: Option<u64>,
    phase: &str,
) -> llm_provable_computer::Result<(u32, u64)> {
    let volume_serial_number = volume_serial_number.ok_or_else(|| {
        VmError::InvalidConfig(format!(
            "{label} {}: cannot read volume serial number {phase}",
            path.display()
        ))
    })?;
    let file_index = file_index.ok_or_else(|| {
        VmError::InvalidConfig(format!(
            "{label} {}: cannot read file index {phase}",
            path.display()
        ))
    })?;
    Ok((volume_serial_number, file_index))
}

fn open_checked_regular_file(
    path: &Path,
    label: &str,
    max_bytes: Option<u64>,
) -> llm_provable_computer::Result<(fs::File, u64)> {
    let metadata = fs::symlink_metadata(path).map_err(|err| {
        VmError::InvalidConfig(format!("failed to read {label} {}: {err}", path.display()))
    })?;
    if !metadata.file_type().is_file() {
        return Err(VmError::InvalidConfig(format!(
            "{label} {} is not a regular file",
            path.display()
        )));
    }
    if let Some(max_bytes) = max_bytes {
        if metadata.len() > max_bytes {
            return Err(VmError::InvalidConfig(format!(
                "{label} {} is {} bytes, exceeding the limit of {} bytes",
                path.display(),
                metadata.len(),
                max_bytes
            )));
        }
    }
    let file = fs::File::open(path).map_err(|err| {
        VmError::InvalidConfig(format!("failed to read {label} {}: {err}", path.display()))
    })?;
    let opened_metadata = file.metadata().map_err(|err| {
        VmError::InvalidConfig(format!("failed to read {label} {}: {err}", path.display()))
    })?;
    if !opened_metadata.is_file() {
        return Err(VmError::InvalidConfig(format!(
            "{label} {} is not a regular file after opening",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if metadata.dev() != opened_metadata.dev() || metadata.ino() != opened_metadata.ino() {
            return Err(VmError::InvalidConfig(format!(
                "{label} {} changed between metadata inspection and open",
                path.display()
            )));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;

        let (pre_volume_serial_number, pre_file_index) = require_windows_regular_file_identity(
            path,
            label,
            metadata.volume_serial_number(),
            metadata.file_index(),
            "before open",
        )?;
        let (post_volume_serial_number, post_file_index) = require_windows_regular_file_identity(
            path,
            label,
            opened_metadata.volume_serial_number(),
            opened_metadata.file_index(),
            "after open",
        )?;

        if pre_volume_serial_number != post_volume_serial_number
            || pre_file_index != post_file_index
        {
            return Err(VmError::InvalidConfig(format!(
                "{label} {} changed between metadata inspection and open",
                path.display()
            )));
        }
    }
    if let Some(max_bytes) = max_bytes {
        if opened_metadata.len() > max_bytes {
            return Err(VmError::InvalidConfig(format!(
                "{label} {} is {} bytes after opening, exceeding the limit of {} bytes",
                path.display(),
                opened_metadata.len(),
                max_bytes
            )));
        }
    }
    Ok((file, opened_metadata.len()))
}

fn verify_hf_provenance_manifest_command(
    manifest_path: &Path,
) -> llm_provable_computer::Result<()> {
    let manifest = load_hf_provenance_manifest(manifest_path)?;
    verify_hf_provenance_manifest(&manifest)?;

    println!("verified_hf_provenance_manifest: true");
    println!("manifest_version: {}", manifest.manifest_version);
    println!("semantic_scope: {}", manifest.semantic_scope);
    println!("hub_repo: {}", manifest.hub_repo);
    println!("hub_revision: {}", manifest.hub_revision);
    println!("tokenizer_id: {}", manifest.tokenizer.tokenizer_id);
    println!("safetensors_files: {}", manifest.safetensors.len());

    Ok(())
}

fn load_hf_provenance_manifest(
    manifest_path: &Path,
) -> llm_provable_computer::Result<HfProvenanceManifest> {
    let (file, _) = open_checked_regular_file(
        manifest_path,
        "HF provenance manifest",
        Some(MAX_HF_PROVENANCE_MANIFEST_JSON_BYTES as u64),
    )?;
    let mut manifest_bytes = Vec::new();
    let mut limited_reader = file.take(MAX_HF_PROVENANCE_MANIFEST_JSON_BYTES as u64 + 1);
    limited_reader
        .read_to_end(&mut manifest_bytes)
        .map_err(|err| {
            VmError::InvalidConfig(format!(
                "failed to read HF provenance manifest {}: {err}",
                manifest_path.display()
            ))
        })?;
    if manifest_bytes.len() > MAX_HF_PROVENANCE_MANIFEST_JSON_BYTES {
        return Err(VmError::InvalidConfig(format!(
            "HF provenance manifest {} is {} bytes after read, exceeding the limit of {} bytes",
            manifest_path.display(),
            manifest_bytes.len(),
            MAX_HF_PROVENANCE_MANIFEST_JSON_BYTES
        )));
    }

    let manifest_value: serde_json::Value =
        serde_json::from_slice(&manifest_bytes).map_err(|err| {
            VmError::Serialization(format!(
                "failed to parse HF provenance manifest {}: {err}",
                manifest_path.display()
            ))
        })?;
    let manifest_version = manifest_value
        .get("manifest_version")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            VmError::Serialization(format!(
                "failed to parse HF provenance manifest {}: missing or non-string field `manifest_version`",
                manifest_path.display()
            ))
        })?;
    match manifest_version {
        HF_PROVENANCE_MANIFEST_VERSION_V1_LEGACY => Err(VmError::Serialization(format!(
            "failed to parse HF provenance manifest {}: legacy manifest_version `{}` is no longer accepted after the ONNX sidecar format bump; regenerate the manifest as {}",
            manifest_path.display(),
            HF_PROVENANCE_MANIFEST_VERSION_V1_LEGACY,
            HF_PROVENANCE_MANIFEST_VERSION
        ))),
        HF_PROVENANCE_MANIFEST_VERSION_V2_LEGACY => Err(VmError::Serialization(format!(
            "failed to parse HF provenance manifest {}: legacy manifest_version `{}` is no longer accepted after the attestation-digest format bump; regenerate the manifest as {}",
            manifest_path.display(),
            HF_PROVENANCE_MANIFEST_VERSION_V2_LEGACY,
            HF_PROVENANCE_MANIFEST_VERSION
        ))),
        HF_PROVENANCE_MANIFEST_VERSION_V3_LEGACY => Err(VmError::Serialization(format!(
            "failed to parse HF provenance manifest {}: legacy manifest_version `{}` is no longer accepted after the hub-binding hardening update; regenerate the manifest as {}",
            manifest_path.display(),
            HF_PROVENANCE_MANIFEST_VERSION_V3_LEGACY,
            HF_PROVENANCE_MANIFEST_VERSION
        ))),
        HF_PROVENANCE_MANIFEST_VERSION => {
            ensure_hf_provenance_manifest_v4_required_fields(manifest_path, &manifest_value)?;
            serde_json::from_value(manifest_value).map_err(|err| {
                VmError::Serialization(format!(
                    "failed to parse HF provenance manifest {}: {err}",
                    manifest_path.display()
                ))
            })
        }
        other => Err(VmError::Serialization(format!(
            "failed to parse HF provenance manifest {}: unsupported manifest_version `{other}`",
            manifest_path.display()
        ))),
    }
}

fn ensure_hf_provenance_manifest_v4_required_fields(
    manifest_path: &Path,
    manifest_value: &serde_json::Value,
) -> llm_provable_computer::Result<()> {
    if let Some(commitments_obj) = manifest_value
        .get("commitments")
        .and_then(|v| v.as_object())
    {
        if !commitments_obj.contains_key("hub_binding_hash") {
            return Err(VmError::Serialization(format!(
                "failed to parse HF provenance manifest {}: missing field `hub_binding_hash` in `commitments` for {}",
                manifest_path.display(),
                HF_PROVENANCE_MANIFEST_VERSION
            )));
        }
    }
    let Some(onnx_export) = manifest_value.get("onnx_export") else {
        return Ok(());
    };
    let Some(onnx_export_obj) = onnx_export.as_object() else {
        return Ok(());
    };
    for field in ["exporter_version", "metadata", "external_data_files"] {
        if !onnx_export_obj.contains_key(field) {
            return Err(VmError::Serialization(format!(
                "failed to parse HF provenance manifest {}: missing field `{field}` in `onnx_export` for {}",
                manifest_path.display(),
                HF_PROVENANCE_MANIFEST_VERSION
            )));
        }
    }
    Ok(())
}

fn verify_hf_provenance_manifest(
    manifest: &HfProvenanceManifest,
) -> llm_provable_computer::Result<()> {
    expect_eq(
        "hf manifest_version",
        &manifest.manifest_version,
        HF_PROVENANCE_MANIFEST_VERSION,
    )?;
    expect_eq(
        "hf semantic_scope",
        &manifest.semantic_scope,
        HF_PROVENANCE_SEMANTIC_SCOPE,
    )?;
    expect_eq(
        "hf commitment_hash_function",
        &manifest.commitment_hash_function,
        HF_PROVENANCE_HASH_FUNCTION,
    )?;
    verify_hash_commitment(
        "hf hub_binding_hash",
        &manifest.commitments.hub_binding_hash,
        &hash_json_projection_hex(&HfHubBinding {
            hub_repo: &manifest.hub_repo,
            hub_revision: &manifest.hub_revision,
        })?,
    )?;
    validate_hf_identifier("hub_repo", &manifest.hub_repo)?;
    validate_hf_pinned_revision("hub_revision", &manifest.hub_revision)?;
    validate_hf_identifier("tokenizer_id", &manifest.tokenizer.tokenizer_id)?;
    validate_hf_pinned_revision("tokenizer_revision", &manifest.tokenizer.tokenizer_revision)?;
    if manifest.tokenizer.tokenizer_json.is_none()
        && manifest.tokenizer.tokenizer_config.is_none()
        && manifest.tokenizer.tokenization_transcript.is_none()
        && manifest.safetensors.is_empty()
        && manifest.onnx_export.is_none()
        && manifest.release.model_card.is_none()
    {
        return Err(VmError::InvalidConfig(
            "HF provenance manifest must bind at least one local tokenizer, safetensors, ONNX, transcript, or model-card file".to_string(),
        ));
    }
    let expected_limitations = hf_provenance_limitations();
    if manifest.limitations != expected_limitations {
        return Err(VmError::InvalidConfig(
            "HF provenance limitations do not match the pinned claim boundary".to_string(),
        ));
    }
    verify_hash_commitment(
        "hf tokenizer_hash",
        &manifest.commitments.tokenizer_hash,
        &hash_json_projection_hex(&manifest.tokenizer)?,
    )?;
    verify_hash_commitment(
        "hf safetensors_manifest_hash",
        &manifest.commitments.safetensors_manifest_hash,
        &hash_json_projection_hex(&manifest.safetensors)?,
    )?;
    verify_hash_commitment(
        "hf onnx_export_hash",
        &manifest.commitments.onnx_export_hash,
        &hash_json_projection_hex(&manifest.onnx_export)?,
    )?;
    verify_hash_commitment(
        "hf release_metadata_hash",
        &manifest.commitments.release_metadata_hash,
        &hash_json_projection_hex(&manifest.release)?,
    )?;
    verify_hash_commitment(
        "hf limitations_hash",
        &manifest.commitments.limitations_hash,
        &hash_json_projection_hex(&manifest.limitations)?,
    )?;
    let mut bound_paths = std::collections::BTreeSet::new();
    verify_hf_optional_file_commitment(
        "tokenizer_json",
        &manifest.tokenizer.tokenizer_json,
        &mut bound_paths,
    )?;
    verify_hf_optional_file_commitment(
        "tokenizer_config",
        &manifest.tokenizer.tokenizer_config,
        &mut bound_paths,
    )?;
    verify_hf_optional_file_commitment(
        "tokenization_transcript",
        &manifest.tokenizer.tokenization_transcript,
        &mut bound_paths,
    )?;
    for safetensors in &manifest.safetensors {
        let identity = verify_hf_safetensors_file_commitment(safetensors)?;
        ensure_unique_hf_identity(
            "HF provenance safetensors",
            &safetensors.path,
            identity,
            &mut bound_paths,
        )?;
    }
    if let Some(onnx_export) = &manifest.onnx_export {
        if onnx_export.exporter.trim().is_empty() {
            return Err(VmError::InvalidConfig(
                "HF provenance ONNX exporter must be non-empty".to_string(),
            ));
        }
        validate_hf_optional_identifier(
            "onnx_export.exporter_version",
            onnx_export.exporter_version.as_deref(),
        )?;
        let graph_identity = verify_hf_file_commitment("onnx_export.graph", &onnx_export.graph)?;
        ensure_unique_hf_identity(
            "HF provenance onnx_export.graph",
            &onnx_export.graph.path,
            graph_identity,
            &mut bound_paths,
        )?;
        verify_hf_optional_file_commitment(
            "onnx_export.metadata",
            &onnx_export.metadata,
            &mut bound_paths,
        )?;
        for commitment in &onnx_export.external_data_files {
            let identity =
                verify_hf_file_commitment("onnx_export.external_data_files[]", commitment)?;
            ensure_unique_hf_identity(
                "HF provenance onnx_export.external_data_files[]",
                &commitment.path,
                identity,
                &mut bound_paths,
            )?;
        }
    }
    verify_hf_optional_file_commitment(
        "model_card",
        &manifest.release.model_card,
        &mut bound_paths,
    )?;
    validate_hf_optional_identifier("release.doi", manifest.release.doi.as_deref())?;
    for (idx, dataset) in manifest.release.datasets.iter().enumerate() {
        validate_hf_identifier(&format!("release.datasets[{idx}]"), dataset)?;
    }
    for (idx, note) in manifest.release.notes.iter().enumerate() {
        if note.trim().is_empty() {
            return Err(VmError::InvalidConfig(format!(
                "HF provenance release.notes[{idx}] must be non-empty"
            )));
        }
    }

    Ok(())
}

fn hf_provenance_limitations() -> Vec<String> {
    [
        "HF provenance manifests pin artifact identity and local file hashes only",
        "attestation-friendly SHA-256 digests do not by themselves verify GitHub, Sigstore, in-toto, or SLSA attestations",
        "the manifest does not prove tokenizer algorithm correctness",
        "the manifest does not prove safetensors weights implement a model architecture",
        "the manifest does not prove Optimum or ONNX exporter semantic equivalence",
        "the manifest does not prove ONNX metadata or external-data semantic correctness",
        "the manifest does not perform live Hugging Face Hub downloads or DOI verification",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn validate_hf_identifier(label: &str, value: &str) -> llm_provable_computer::Result<()> {
    if value.trim().is_empty() {
        return Err(VmError::InvalidConfig(format!(
            "HF provenance {label} must be non-empty"
        )));
    }
    if value.contains(char::is_whitespace) {
        return Err(VmError::InvalidConfig(format!(
            "HF provenance {label} must not contain whitespace"
        )));
    }
    Ok(())
}

fn validate_hf_optional_identifier(
    label: &str,
    value: Option<&str>,
) -> llm_provable_computer::Result<()> {
    if let Some(value) = value {
        validate_hf_identifier(label, value)?;
    }
    Ok(())
}

fn validate_hf_pinned_revision(label: &str, value: &str) -> llm_provable_computer::Result<()> {
    validate_hf_identifier(label, value)?;
    let lower = value.to_ascii_lowercase();
    if matches!(lower.as_str(), "main" | "master" | "head") || lower.starts_with("refs/heads/") {
        return Err(VmError::InvalidConfig(format!(
            "HF provenance {label} must be pinned to an immutable commit or release tag, not `{value}`"
        )));
    }
    Ok(())
}

fn hf_optional_file_commitment(
    path: Option<&Path>,
) -> llm_provable_computer::Result<Option<HfFileCommitment>> {
    path.map(hf_file_commitment).transpose()
}

fn hf_file_commitment(path: &Path) -> llm_provable_computer::Result<HfFileCommitment> {
    let (_, size_bytes, blake2b_256, sha256) = hash_hf_commitment_file(path, "HF provenance file")?;
    Ok(HfFileCommitment {
        path: path.display().to_string(),
        size_bytes,
        blake2b_256,
        sha256,
    })
}

fn hf_safetensors_file_commitment(
    path: &Path,
) -> llm_provable_computer::Result<HfSafetensorsFileCommitment> {
    let (_, size_bytes, blake2b_256, sha256, metadata_hash, tensor_count) =
        inspect_hf_safetensors_file(path, "HF provenance file")?;
    Ok(HfSafetensorsFileCommitment {
        path: path.display().to_string(),
        size_bytes,
        blake2b_256,
        sha256,
        metadata_hash,
        tensor_count,
    })
}

fn verify_hf_optional_file_commitment(
    label: &str,
    commitment: &Option<HfFileCommitment>,
    seen_paths: &mut std::collections::BTreeSet<HfFileIdentity>,
) -> llm_provable_computer::Result<()> {
    if let Some(commitment) = commitment {
        let identity = verify_hf_file_commitment(label, commitment)?;
        ensure_unique_hf_identity(
            &format!("HF provenance {label}"),
            &commitment.path,
            identity,
            seen_paths,
        )?;
    }
    Ok(())
}

fn verify_hf_file_commitment(
    label: &str,
    commitment: &HfFileCommitment,
) -> llm_provable_computer::Result<HfFileIdentity> {
    let identity_label = format!("HF provenance {label}");
    let (identity, size_bytes, blake2b_256, sha256) =
        hash_hf_commitment_file(Path::new(&commitment.path), &identity_label)?;
    if commitment.size_bytes != size_bytes {
        return Err(VmError::InvalidConfig(format!(
            "HF provenance {label} size_bytes mismatch: expected {}, got {}",
            commitment.size_bytes, size_bytes
        )));
    }
    verify_hash_commitment(
        &format!("HF provenance {label} blake2b_256"),
        &commitment.blake2b_256,
        &blake2b_256,
    )?;
    verify_hash_commitment(
        &format!("HF provenance {label} sha256"),
        &commitment.sha256,
        &sha256,
    )?;
    Ok(identity)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum HfFileIdentity {
    #[cfg(unix)]
    Unix { dev: u64, ino: u64 },
    #[cfg(windows)]
    Windows {
        volume_serial_number: u32,
        file_index: u64,
    },
    #[cfg(not(any(unix, windows)))]
    CanonicalPath(PathBuf),
}

fn hf_file_identity_from_open_file(
    path: &Path,
    label: &str,
    file: &fs::File,
) -> llm_provable_computer::Result<HfFileIdentity> {
    let metadata = file.metadata().map_err(|err| {
        VmError::InvalidConfig(format!("failed to read {label} {}: {err}", path.display()))
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        return Ok(HfFileIdentity::Unix {
            dev: metadata.dev(),
            ino: metadata.ino(),
        });
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;

        let (volume_serial_number, file_index) = require_windows_regular_file_identity(
            path,
            label,
            metadata.volume_serial_number(),
            metadata.file_index(),
            "after open",
        )?;
        return Ok(HfFileIdentity::Windows {
            volume_serial_number,
            file_index,
        });
    }

    #[cfg(not(any(unix, windows)))]
    {
        let canonical = fs::canonicalize(path).map_err(|err| {
            VmError::InvalidConfig(format!(
                "failed to canonicalize {label} {}: {err}",
                path.display()
            ))
        })?;
        Ok(HfFileIdentity::CanonicalPath(canonical))
    }
}

fn ensure_unique_hf_identity(
    label: &str,
    path: &str,
    identity: HfFileIdentity,
    seen_paths: &mut std::collections::BTreeSet<HfFileIdentity>,
) -> llm_provable_computer::Result<()> {
    if !seen_paths.insert(identity) {
        return Err(VmError::InvalidConfig(format!(
            "{label} reuses the same underlying HF artifact as an earlier bound path via `{path}`",
        )));
    }
    Ok(())
}

fn verify_hf_safetensors_file_commitment(
    commitment: &HfSafetensorsFileCommitment,
) -> llm_provable_computer::Result<HfFileIdentity> {
    let (identity, size_bytes, blake2b_256, sha256, metadata_hash, tensor_count) =
        inspect_hf_safetensors_file(Path::new(&commitment.path), "HF provenance safetensors")?;
    if commitment.size_bytes != size_bytes {
        return Err(VmError::InvalidConfig(format!(
            "HF provenance safetensors {} size_bytes mismatch: expected {}, got {}",
            commitment.path, commitment.size_bytes, size_bytes
        )));
    }
    verify_hash_commitment(
        &format!("HF provenance safetensors {} blake2b_256", commitment.path),
        &commitment.blake2b_256,
        &blake2b_256,
    )?;
    verify_hash_commitment(
        &format!("HF provenance safetensors {} sha256", commitment.path),
        &commitment.sha256,
        &sha256,
    )?;
    verify_hash_commitment(
        &format!(
            "HF provenance safetensors {} metadata_hash",
            commitment.path
        ),
        &commitment.metadata_hash,
        &metadata_hash,
    )?;
    if commitment.tensor_count != tensor_count {
        return Err(VmError::InvalidConfig(format!(
            "HF provenance safetensors {} tensor_count mismatch: expected {}, got {}",
            commitment.path, commitment.tensor_count, tensor_count
        )));
    }
    Ok(identity)
}

fn hash_hf_commitment_file(
    path: &Path,
    label: &str,
) -> llm_provable_computer::Result<(HfFileIdentity, u64, String, String)> {
    let (mut file, size_bytes) = open_checked_regular_file(path, label, None)?;
    let identity = hf_file_identity_from_open_file(path, label, &file)?;
    let mut output = [0u8; 32];
    let mut hasher = Blake2bVar::new(output.len()).expect("blake2b-256 hasher");
    let mut sha256_hasher = Sha256::new();
    let mut observed_size = 0u64;
    let mut remaining = size_bytes;
    let mut buffer = vec![0u8; HF_PROVENANCE_FILE_READ_CHUNK_BYTES];
    while remaining > 0 {
        let chunk_len = remaining.min(buffer.len() as u64) as usize;
        let read_bytes = file.read(&mut buffer[..chunk_len]).map_err(|err| {
            VmError::InvalidConfig(format!("failed to read {label} {}: {err}", path.display()))
        })?;
        if read_bytes == 0 {
            return Err(VmError::InvalidConfig(format!(
                "{label} {} ended before the expected {} bytes were read",
                path.display(),
                size_bytes
            )));
        }
        observed_size = observed_size
            .checked_add(read_bytes as u64)
            .ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "{label} {} exceeded supported size accounting during read",
                    path.display()
                ))
            })?;
        remaining -= read_bytes as u64;
        hasher.update(&buffer[..read_bytes]);
        Digest::update(&mut sha256_hasher, &buffer[..read_bytes]);
    }
    let mut extra_byte = [0u8; 1];
    if file.read(&mut extra_byte).map_err(|err| {
        VmError::InvalidConfig(format!("failed to read {label} {}: {err}", path.display()))
    })? != 0
    {
        return Err(VmError::InvalidConfig(format!(
            "{label} {} grew while being hashed after {} bytes were expected",
            path.display(),
            size_bytes
        )));
    }
    hasher
        .finalize_variable(&mut output)
        .expect("blake2b-256 finalization");
    let sha256_output = sha256_hasher.finalize();
    Ok((
        identity,
        size_bytes,
        encode_hex(&output),
        encode_hex(sha256_output.as_slice()),
    ))
}

fn inspect_hf_safetensors_file(
    path: &Path,
    label: &str,
) -> llm_provable_computer::Result<(HfFileIdentity, u64, String, String, String, usize)> {
    const MAX_SAFETENSORS_HEADER_BYTES: u64 = 16 * 1024 * 1024;

    let (mut file, size_bytes) = open_checked_regular_file(path, label, None)?;
    let identity = hf_file_identity_from_open_file(path, label, &file)?;
    if size_bytes < 8 {
        return Err(VmError::InvalidConfig(format!(
            "HF provenance safetensors {} is shorter than the 8-byte metadata length header",
            path.display()
        )));
    }

    let mut output = [0u8; 32];
    let mut hasher = Blake2bVar::new(output.len()).expect("blake2b-256 hasher");
    let mut sha256_hasher = Sha256::new();

    let mut header_len_bytes = [0u8; 8];
    file.read_exact(&mut header_len_bytes).map_err(|err| {
        VmError::InvalidConfig(format!("failed to read {label} {}: {err}", path.display()))
    })?;
    hasher.update(&header_len_bytes);
    Digest::update(&mut sha256_hasher, &header_len_bytes);

    let header_len = u64::from_le_bytes(header_len_bytes);
    if header_len > MAX_SAFETENSORS_HEADER_BYTES {
        return Err(VmError::InvalidConfig(format!(
            "HF provenance safetensors {} metadata header is too large: {} bytes",
            path.display(),
            header_len
        )));
    }
    let header_end = 8u64.checked_add(header_len).ok_or_else(|| {
        VmError::InvalidConfig(format!(
            "HF provenance safetensors {} metadata header end overflows u64",
            path.display()
        ))
    })?;
    if size_bytes < header_end {
        return Err(VmError::InvalidConfig(format!(
            "HF provenance safetensors {} metadata header length exceeds file size",
            path.display()
        )));
    }

    let header_len = usize::try_from(header_len).map_err(|_| {
        VmError::InvalidConfig(format!(
            "HF provenance safetensors {} metadata header length overflows usize",
            path.display()
        ))
    })?;
    let mut header_bytes = vec![0u8; header_len];
    file.read_exact(&mut header_bytes).map_err(|err| {
        VmError::InvalidConfig(format!("failed to read {label} {}: {err}", path.display()))
    })?;
    hasher.update(&header_bytes);
    Digest::update(&mut sha256_hasher, &header_bytes);
    let (metadata_hash, tensor_count) =
        hf_safetensors_metadata_commitment_from_header(path, &header_bytes)?;

    let mut observed_size = header_end;
    let mut remaining = size_bytes - header_end;
    let mut buffer = vec![0u8; HF_PROVENANCE_FILE_READ_CHUNK_BYTES];
    while remaining > 0 {
        let chunk_len = remaining.min(buffer.len() as u64) as usize;
        let read_bytes = file.read(&mut buffer[..chunk_len]).map_err(|err| {
            VmError::InvalidConfig(format!("failed to read {label} {}: {err}", path.display()))
        })?;
        if read_bytes == 0 {
            return Err(VmError::InvalidConfig(format!(
                "{label} {} ended before the expected {} bytes were read",
                path.display(),
                size_bytes
            )));
        }
        observed_size = observed_size
            .checked_add(read_bytes as u64)
            .ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "{label} {} exceeded supported size accounting during read",
                    path.display()
                ))
            })?;
        remaining -= read_bytes as u64;
        hasher.update(&buffer[..read_bytes]);
        Digest::update(&mut sha256_hasher, &buffer[..read_bytes]);
    }
    let mut extra_byte = [0u8; 1];
    if file.read(&mut extra_byte).map_err(|err| {
        VmError::InvalidConfig(format!("failed to read {label} {}: {err}", path.display()))
    })? != 0
    {
        return Err(VmError::InvalidConfig(format!(
            "{label} {} grew while being hashed after {} bytes were expected",
            path.display(),
            size_bytes
        )));
    }

    hasher
        .finalize_variable(&mut output)
        .expect("blake2b-256 finalization");
    let sha256_output = sha256_hasher.finalize();
    Ok((
        identity,
        size_bytes,
        encode_hex(&output),
        encode_hex(sha256_output.as_slice()),
        metadata_hash,
        tensor_count,
    ))
}

fn hf_safetensors_metadata_commitment_from_header(
    path: &Path,
    header_bytes: &[u8],
) -> llm_provable_computer::Result<(String, usize)> {
    let header_json: serde_json::Value = serde_json::from_slice(header_bytes).map_err(|err| {
        VmError::Serialization(format!(
            "failed to parse HF provenance safetensors metadata {}: {err}",
            path.display()
        ))
    })?;
    let header_object = header_json.as_object().ok_or_else(|| {
        VmError::InvalidConfig(format!(
            "HF provenance safetensors {} metadata header must be a JSON object",
            path.display()
        ))
    })?;
    let tensor_count = header_object
        .keys()
        .filter(|key| key.as_str() != "__metadata__")
        .count();
    Ok((hash_bytes_hex(header_bytes), tensor_count))
}

fn verify_hash_commitment(
    label: &str,
    actual: &str,
    expected: &str,
) -> llm_provable_computer::Result<()> {
    expect_hash_hex(label, actual)?;
    expect_hash_hex(label, expected)?;
    if actual != expected {
        return Err(VmError::InvalidConfig(format!(
            "{label} commitment mismatch: expected {expected}, got {actual}"
        )));
    }
    Ok(())
}

fn expect_eq(label: &str, actual: &str, expected: &str) -> llm_provable_computer::Result<()> {
    if actual != expected {
        return Err(VmError::InvalidConfig(format!(
            "{label} mismatch: expected `{expected}`, got `{actual}`"
        )));
    }
    Ok(())
}

fn expect_hash_hex(label: &str, value: &str) -> llm_provable_computer::Result<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(VmError::InvalidConfig(format!(
            "{label} must be a 64-character hex hash"
        )));
    }
    Ok(())
}

#[cfg(feature = "onnx-export")]
fn research_v2_step_command_impl(
    program: &Path,
    output: &Path,
    max_steps: usize,
    layers: usize,
    attention_mode: Attention2DMode,
) -> llm_provable_computer::Result<()> {
    if max_steps < 1 {
        return Err(VmError::InvalidConfig(
            "research-v2-step requires max_steps >= 1".to_string(),
        ));
    }

    let statement_spec_bytes = read_repo_file(STATEMENT_V2_STEP_SPEC_PATH)?;
    let fixed_point_spec_bytes = read_repo_file(FIXED_POINT_SPEC_PATH)?;
    let onnx_op_subset_spec_bytes = read_repo_file(ONNX_OP_SUBSET_SPEC_PATH)?;
    let artifact_schema_bytes = read_repo_file(STATEMENT_V2_STEP_ARTIFACT_SCHEMA_PATH)?;

    let statement_spec: StatementV2ResearchSpec = serde_json::from_slice(&statement_spec_bytes)
        .map_err(|err| {
            VmError::Serialization(format!(
                "failed to parse {}: {err}",
                STATEMENT_V2_STEP_SPEC_PATH
            ))
        })?;
    let fixed_point_spec: FixedPointSemanticsSpec = serde_json::from_slice(&fixed_point_spec_bytes)
        .map_err(|err| {
            VmError::Serialization(format!("failed to parse {}: {err}", FIXED_POINT_SPEC_PATH))
        })?;
    let onnx_op_subset_spec: OnnxOpSubsetSpec = serde_json::from_slice(&onnx_op_subset_spec_bytes)
        .map_err(|err| {
            VmError::Serialization(format!(
                "failed to parse {}: {err}",
                ONNX_OP_SUBSET_SPEC_PATH
            ))
        })?;

    if statement_spec.fixed_point_profile_ref != FIXED_POINT_SPEC_PATH {
        return Err(VmError::InvalidConfig(format!(
            "{} references `{}` but expected `{}`",
            STATEMENT_V2_STEP_SPEC_PATH,
            statement_spec.fixed_point_profile_ref,
            FIXED_POINT_SPEC_PATH
        )));
    }
    if statement_spec.onnx_op_subset_ref != ONNX_OP_SUBSET_SPEC_PATH {
        return Err(VmError::InvalidConfig(format!(
            "{} references `{}` but expected `{}`",
            STATEMENT_V2_STEP_SPEC_PATH,
            statement_spec.onnx_op_subset_ref,
            ONNX_OP_SUBSET_SPEC_PATH
        )));
    }
    if statement_spec.artifact_schema_ref != STATEMENT_V2_STEP_ARTIFACT_SCHEMA_PATH {
        return Err(VmError::InvalidConfig(format!(
            "{} references `{}` but expected `{}`",
            STATEMENT_V2_STEP_SPEC_PATH,
            statement_spec.artifact_schema_ref,
            STATEMENT_V2_STEP_ARTIFACT_SCHEMA_PATH
        )));
    }

    let model = compile_model(program, layers, attention_mode)?;
    let export_dir = ScopedTempDir::new("research-v2-step")?;
    let onnx_metadata = export_program_onnx(&model, export_dir.path())?;

    let mut transformer = ExecutionRuntime::new(model.clone(), max_steps);
    let mut onnx = OnnxExecutionRuntime::from_export_dir(export_dir.path(), max_steps)?;

    let state_before = transformer.state().clone();
    if state_before != onnx.state().clone() {
        return Err(VmError::InvalidConfig(
            "research-v2-step initial state mismatch between transformer and ONNX runtimes"
                .to_string(),
        ));
    }
    if state_before.halted {
        return Err(VmError::InvalidConfig(
            "research-v2-step requires a non-halted initial state".to_string(),
        ));
    }

    transformer.step()?;
    onnx.step()?;

    let transformer_event = transformer
        .events()
        .last()
        .ok_or_else(|| {
            VmError::InvalidConfig(
                "research-v2-step transformer runtime produced no execution event".to_string(),
            )
        })?
        .clone();
    let onnx_event = onnx
        .events()
        .last()
        .ok_or_else(|| {
            VmError::InvalidConfig(
                "research-v2-step ONNX runtime produced no execution event".to_string(),
            )
        })?
        .clone();
    if transformer_event.instruction != onnx_event.instruction {
        return Err(VmError::InvalidConfig(format!(
            "research-v2-step instruction mismatch: transformer=`{}` onnx=`{}`",
            transformer_event.instruction, onnx_event.instruction
        )));
    }

    let transformer_state_after = transformer.state().clone();
    let onnx_state_after = onnx.state().clone();
    let matched = transformer_state_after == onnx_state_after;

    let commitments = ResearchV2OneStepCommitments {
        hash_function: RESEARCH_V2_HASH_FUNCTION.to_string(),
        statement_spec_hash: hash_bytes_hex(&statement_spec_bytes),
        fixed_point_spec_hash: hash_bytes_hex(&fixed_point_spec_bytes),
        onnx_op_subset_hash: hash_bytes_hex(&onnx_op_subset_spec_bytes),
        artifact_schema_hash: hash_bytes_hex(&artifact_schema_bytes),
        program_hash: hash_json_hex(model.program())?,
        transformer_config_hash: hash_json_hex(model.config())?,
        onnx_metadata_hash: hash_json_hex(&onnx_metadata)?,
        state_before_hash: hash_json_hex(&state_before)?,
        transformer_state_after_hash: hash_json_hex(&transformer_state_after)?,
        onnx_state_after_hash: hash_json_hex(&onnx_state_after)?,
    };

    let artifact = ResearchV2OneStepArtifact {
        statement_version: statement_spec.statement_version,
        semantic_scope: statement_spec.semantic_scope,
        fixed_point_profile: fixed_point_spec.profile_id,
        onnx_op_subset_version: onnx_op_subset_spec.version,
        onnx_op_subset_size: onnx_op_subset_spec.operators.len(),
        program_path: program.display().to_string(),
        checked_steps: transformer.step_count(),
        instruction: transformer_event.instruction.to_string(),
        layer_idx: transformer_event.layer_idx,
        matched,
        state_before,
        transformer_state_after,
        onnx_state_after,
        commitments,
    };

    if !matched {
        return Err(VmError::InvalidConfig(format!(
            "research-v2-step mismatch for instruction `{}`",
            artifact.instruction
        )));
    }

    let bytes = serde_json::to_vec_pretty(&artifact)
        .map_err(|err| VmError::Serialization(format!("failed to serialize artifact: {err}")))?;
    fs::write(output, bytes)?;

    println!("research_v2_artifact: {}", output.display());
    println!("statement_version: {}", artifact.statement_version);
    println!("semantic_scope: {}", artifact.semantic_scope);
    println!("fixed_point_profile: {}", artifact.fixed_point_profile);
    println!(
        "onnx_op_subset_version: {}",
        artifact.onnx_op_subset_version
    );
    println!("checked_steps: {}", artifact.checked_steps);
    println!("instruction: {}", artifact.instruction);
    println!("matched: {}", artifact.matched);
    println!(
        "commitment_program_hash: {}",
        artifact.commitments.program_hash
    );
    println!(
        "commitment_onnx_metadata_hash: {}",
        artifact.commitments.onnx_metadata_hash
    );

    Ok(())
}

#[cfg(feature = "onnx-export")]
fn research_v2_trace_command_impl(
    program: &Path,
    output: &Path,
    max_steps: usize,
    layers: usize,
    attention_mode: Attention2DMode,
    allow_mismatch: bool,
) -> llm_provable_computer::Result<()> {
    let bundle = load_research_v2_spec_bundle(
        STATEMENT_V2_TRACE_SPEC_PATH,
        STATEMENT_V2_TRACE_ARTIFACT_SCHEMA_PATH,
    )?;
    let artifact = compute_research_v2_trace_artifact_for_program(
        program,
        max_steps,
        layers,
        &attention_mode,
        &bundle,
    )?;

    enforce_research_v2_trace_mismatch_policy(
        artifact.matched,
        allow_mismatch,
        artifact.first_mismatch_step,
        artifact.mismatch_reason.as_deref(),
    )?;

    let bytes = serde_json::to_vec_pretty(&artifact)
        .map_err(|err| VmError::Serialization(format!("failed to serialize artifact: {err}")))?;
    fs::write(output, bytes)?;

    println!("research_v2_trace_artifact: {}", output.display());
    println!("statement_version: {}", artifact.statement_version);
    println!("semantic_scope: {}", artifact.semantic_scope);
    println!("fixed_point_profile: {}", artifact.fixed_point_profile);
    println!(
        "onnx_op_subset_version: {}",
        artifact.onnx_op_subset_version
    );
    println!("requested_max_steps: {}", artifact.requested_max_steps);
    println!("checked_steps: {}", artifact.checked_steps);
    println!("matched: {}", artifact.matched);
    if let Some(step) = artifact.first_mismatch_step {
        println!("first_mismatch_step: {step}");
    }
    if let Some(reason) = artifact.mismatch_reason.as_ref() {
        println!("mismatch_reason: {reason}");
    }
    println!(
        "commitment_program_hash: {}",
        artifact.commitments.program_hash
    );
    println!(
        "commitment_onnx_metadata_hash: {}",
        artifact.commitments.onnx_metadata_hash
    );

    Ok(())
}

#[cfg(feature = "onnx-export")]
fn research_v2_matrix_command_impl(
    output: &Path,
    programs: &[PathBuf],
    include_default_suite: bool,
    max_steps: usize,
    layers: usize,
    attention_mode: Attention2DMode,
    allow_mismatch: bool,
) -> llm_provable_computer::Result<()> {
    let bundle = load_research_v2_spec_bundle(
        STATEMENT_V2_MATRIX_SPEC_PATH,
        STATEMENT_V2_MATRIX_ARTIFACT_SCHEMA_PATH,
    )?;

    let mut selected = Vec::<PathBuf>::new();
    if include_default_suite {
        selected.extend(research_v2_default_program_suite());
    }
    selected.extend(programs.iter().cloned());

    if selected.is_empty() {
        return Err(VmError::InvalidConfig(
            "research-v2-matrix requires at least one --program or --include-default-suite"
                .to_string(),
        ));
    }

    let mut deduped = Vec::<PathBuf>::new();
    for path in selected {
        if !deduped.iter().any(|existing| existing == &path) {
            deduped.push(path);
        }
    }

    let mut entries = Vec::<ResearchV2MatrixEntry>::with_capacity(deduped.len());
    for program in deduped {
        let trace = compute_research_v2_trace_artifact_for_program(
            &program,
            max_steps,
            layers,
            &attention_mode,
            &bundle,
        )?;
        entries.push(ResearchV2MatrixEntry {
            program_path: trace.program_path,
            checked_steps: trace.checked_steps,
            matched: trace.matched,
            first_mismatch_step: trace.first_mismatch_step,
            mismatch_reason: trace.mismatch_reason,
            transformer_final_state: trace.transformer_final_state,
            onnx_final_state: trace.onnx_final_state,
            commitments: trace.commitments,
        });
    }

    let matched_programs = entries.iter().filter(|entry| entry.matched).count();
    let mismatched_programs = entries.len() - matched_programs;
    let matrix_entries_hash = hash_json_hex(&entries)?;

    let artifact = ResearchV2MatrixArtifact {
        statement_version: bundle.statement_version.clone(),
        semantic_scope: bundle.semantic_scope.clone(),
        fixed_point_profile: bundle.fixed_point_profile.clone(),
        onnx_op_subset_version: bundle.onnx_op_subset_version.clone(),
        onnx_op_subset_size: bundle.onnx_op_subset_size,
        requested_max_steps: max_steps,
        total_programs: entries.len(),
        matched_programs,
        mismatched_programs,
        entries,
        commitments: ResearchV2MatrixCommitments {
            hash_function: RESEARCH_V2_HASH_FUNCTION.to_string(),
            statement_spec_hash: bundle.statement_spec_hash.clone(),
            fixed_point_spec_hash: bundle.fixed_point_spec_hash.clone(),
            onnx_op_subset_hash: bundle.onnx_op_subset_hash.clone(),
            artifact_schema_hash: bundle.artifact_schema_hash.clone(),
            matrix_entries_hash,
        },
    };

    enforce_research_v2_matrix_mismatch_policy(artifact.mismatched_programs, allow_mismatch)?;

    let bytes = serde_json::to_vec_pretty(&artifact)
        .map_err(|err| VmError::Serialization(format!("failed to serialize artifact: {err}")))?;
    fs::write(output, bytes)?;

    println!("research_v2_matrix_artifact: {}", output.display());
    println!("statement_version: {}", artifact.statement_version);
    println!("semantic_scope: {}", artifact.semantic_scope);
    println!("requested_max_steps: {}", artifact.requested_max_steps);
    println!("total_programs: {}", artifact.total_programs);
    println!("matched_programs: {}", artifact.matched_programs);
    println!("mismatched_programs: {}", artifact.mismatched_programs);
    println!(
        "commitment_matrix_entries_hash: {}",
        artifact.commitments.matrix_entries_hash
    );

    Ok(())
}

#[cfg(all(feature = "burn-model", feature = "onnx-export"))]
fn research_v3_equivalence_command_impl(
    program: &Path,
    output: &Path,
    max_steps: usize,
    layers: usize,
    attention_mode: Attention2DMode,
) -> llm_provable_computer::Result<()> {
    if max_steps < 1 {
        return Err(VmError::InvalidConfig(
            "research-v3-equivalence requires max_steps >= 1".to_string(),
        ));
    }

    let bundle = load_research_v2_spec_bundle(
        STATEMENT_V3_EQUIVALENCE_SPEC_PATH,
        STATEMENT_V3_EQUIVALENCE_ARTIFACT_SCHEMA_PATH,
    )?;
    let frontend_runtime_semantics_registry =
        read_repo_json_value(FRONTEND_RUNTIME_SEMANTICS_REGISTRY_PATH)?;
    validate_frontend_runtime_semantics_registry(&frontend_runtime_semantics_registry)?;
    let frontend_runtime_semantics_registry_hash =
        hash_json_hex(&frontend_runtime_semantics_registry)?;
    let model = compile_model(program, layers, attention_mode)?;
    let export_dir = ScopedTempDir::new("research-v3-equivalence")?;
    let onnx_metadata = export_program_onnx(&model, export_dir.path())?;
    let device = Default::default();
    let burn_model = BurnTransformerVm::<CliBurnBackend>::from_compiled(&model, &device)?;

    let mut transformer = ExecutionRuntime::new(model.clone(), max_steps);
    let mut native = NativeInterpreter::new(
        model.program().clone(),
        model.config().attention_mode.clone(),
        max_steps,
    );
    let mut burn = BurnExecutionRuntime::new(burn_model, device, max_steps);
    let mut onnx = OnnxExecutionRuntime::from_export_dir(export_dir.path(), max_steps)?;

    let verification = verify_engines(&mut [&mut transformer, &mut native, &mut burn, &mut onnx])?;

    let engine_names = verification
        .engines
        .iter()
        .map(|engine| engine.name.clone())
        .collect::<Vec<_>>();
    let verified_transformer = verification.engines.first().ok_or_else(|| {
        VmError::InvalidConfig("research-v3-equivalence missing transformer result".to_string())
    })?;
    let verified_native = verification.engines.get(1).ok_or_else(|| {
        VmError::InvalidConfig("research-v3-equivalence missing native result".to_string())
    })?;
    let verified_burn = verification.engines.get(2).ok_or_else(|| {
        VmError::InvalidConfig("research-v3-equivalence missing burn result".to_string())
    })?;
    let verified_onnx = verification.engines.get(3).ok_or_else(|| {
        VmError::InvalidConfig("research-v3-equivalence missing ONNX result".to_string())
    })?;
    let engines = vec![
        research_v3_engine_summary(
            &verified_transformer.name,
            transformer.trace(),
            transformer.events(),
            &verified_transformer.result,
        )?,
        research_v3_engine_summary(
            &verified_native.name,
            native.trace(),
            native.events(),
            &verified_native.result,
        )?,
        research_v3_engine_summary(
            &verified_burn.name,
            burn.trace(),
            burn.events(),
            &verified_burn.result,
        )?,
        research_v3_engine_summary(
            &verified_onnx.name,
            onnx.trace(),
            onnx.events(),
            &verified_onnx.result,
        )?,
    ];
    let rule_witnesses = research_v3_rule_witnesses(&[
        (verified_transformer.name.as_str(), transformer.events()),
        (verified_native.name.as_str(), native.events()),
        (verified_burn.name.as_str(), burn.events()),
        (verified_onnx.name.as_str(), onnx.events()),
    ])?;
    let engine_summaries_hash = hash_json_projection_hex(&engines)?;
    let rule_witnesses_hash = hash_json_projection_hex(&rule_witnesses)?;
    let relation_format = RESEARCH_V3_RELATION_FORMAT.to_string();
    let limitations = research_v3_limitations();
    let relation_format_hash = hash_json_hex(&relation_format)?;
    let limitations_hash = hash_json_hex(&limitations)?;

    let artifact = ResearchV3EquivalenceArtifact {
        statement_version: bundle.statement_version.clone(),
        semantic_scope: bundle.semantic_scope.clone(),
        relation_format,
        fixed_point_profile: bundle.fixed_point_profile.clone(),
        onnx_op_subset_version: bundle.onnx_op_subset_version.clone(),
        onnx_op_subset_size: bundle.onnx_op_subset_size,
        program_path: program.display().to_string(),
        requested_max_steps: max_steps,
        checked_steps: verification.checked_steps,
        engines,
        rule_witnesses,
        frontend_runtime_semantics_registry,
        limitations,
        commitments: ResearchV3EquivalenceCommitments {
            hash_function: RESEARCH_V2_HASH_FUNCTION.to_string(),
            statement_spec_hash: bundle.statement_spec_hash,
            fixed_point_spec_hash: bundle.fixed_point_spec_hash,
            onnx_op_subset_hash: bundle.onnx_op_subset_hash,
            artifact_schema_hash: bundle.artifact_schema_hash,
            frontend_runtime_semantics_registry_hash,
            relation_format_hash,
            limitations_hash,
            program_hash: hash_json_hex(model.program())?,
            transformer_config_hash: hash_json_hex(model.config())?,
            onnx_metadata_hash: hash_json_hex(&onnx_metadata)?,
            engine_summaries_hash,
            rule_witnesses_hash,
        },
    };
    verify_research_v3_engine_lane_binding(&artifact)?;

    let bytes = serde_json::to_vec_pretty(&artifact)
        .map_err(|err| VmError::Serialization(format!("failed to serialize artifact: {err}")))?;
    write_bytes_atomically(output, &bytes)?;

    println!("research_v3_equivalence_artifact: {}", output.display());
    println!("statement_version: {}", artifact.statement_version);
    println!("semantic_scope: {}", artifact.semantic_scope);
    println!("relation_format: {}", artifact.relation_format);
    println!("checked_steps: {}", artifact.checked_steps);
    println!("engines: {}", engine_names.join(","));
    println!("rule_witnesses: {}", artifact.rule_witnesses.len());
    println!(
        "commitment_engine_summaries_hash: {}",
        artifact.commitments.engine_summaries_hash
    );
    println!(
        "commitment_frontend_runtime_semantics_registry_hash: {}",
        artifact
            .commitments
            .frontend_runtime_semantics_registry_hash
    );
    println!(
        "commitment_rule_witnesses_hash: {}",
        artifact.commitments.rule_witnesses_hash
    );

    Ok(())
}

#[cfg(all(feature = "burn-model", feature = "onnx-export"))]
fn research_v3_engine_summary(
    name: &str,
    trace: &[MachineState],
    events: &[ExecutionTraceEntry],
    result: &ExecutionResult,
) -> llm_provable_computer::Result<ResearchV3EngineSummary> {
    let canonical_events = research_v3_canonical_events(events)?;
    Ok(ResearchV3EngineSummary {
        name: name.to_string(),
        steps: result.steps,
        halted: result.halted,
        trace_len: trace.len(),
        events_len: events.len(),
        trace: trace.to_vec(),
        canonical_events: canonical_events.clone(),
        final_state: result.final_state.clone(),
        trace_hash: hash_json_hex(trace)?,
        event_relation_hash: hash_json_hex(&canonical_events)?,
        final_state_hash: hash_json_hex(&result.final_state)?,
    })
}

#[cfg(all(feature = "burn-model", feature = "onnx-export"))]
fn research_v3_canonical_events(
    events: &[ExecutionTraceEntry],
) -> llm_provable_computer::Result<Vec<ResearchV3CanonicalEvent>> {
    events
        .iter()
        .map(|event| {
            Ok(ResearchV3CanonicalEvent {
                step: event.step,
                instruction: event.instruction.to_string(),
                state_before_hash: hash_json_hex(&event.state_before)?,
                state_after_hash: hash_json_hex(&event.state_after)?,
            })
        })
        .collect()
}

#[cfg(all(feature = "burn-model", feature = "onnx-export"))]
fn research_v3_rule_witnesses(
    engine_events: &[(&str, &[ExecutionTraceEntry])],
) -> llm_provable_computer::Result<Vec<ResearchV3RuleWitness>> {
    let (reference_name, reference_events) = engine_events.first().ok_or_else(|| {
        VmError::InvalidConfig("research-v3-equivalence requires engine events".to_string())
    })?;
    let participating_engines = engine_events
        .iter()
        .map(|(engine_name, _)| (*engine_name).to_string())
        .collect::<Vec<_>>();
    let reference_event_len = reference_events.len();
    for (engine_name, events) in engine_events.iter().skip(1) {
        if events.len() != reference_event_len {
            return Err(VmError::InvalidConfig(format!(
                "research-v3-equivalence event length mismatch: {} has {}, {} has {}",
                reference_name,
                reference_event_len,
                engine_name,
                events.len()
            )));
        }
    }

    reference_events
        .iter()
        .enumerate()
        .map(|(event_idx, reference_event)| {
            let instruction = reference_event.instruction.to_string();
            let mut state_before_hashes = std::collections::BTreeMap::new();
            let mut state_after_hashes = std::collections::BTreeMap::new();
            let mut engine_transition_hashes = std::collections::BTreeMap::new();
            for (engine_name, events) in engine_events {
                let event = events.get(event_idx).ok_or_else(|| {
                    VmError::InvalidConfig(format!(
                        "research-v3-equivalence missing event {} for {}",
                        event_idx + 1,
                        engine_name
                    ))
                })?;
                if event.step != reference_event.step || event.instruction != reference_event.instruction {
                    return Err(VmError::InvalidConfig(format!(
                        "research-v3-equivalence event mismatch at index {}: {} step={} instruction=`{}` vs {} step={} instruction=`{}`",
                        event_idx,
                        reference_name,
                        reference_event.step,
                        reference_event.instruction,
                        engine_name,
                        event.step,
                        event.instruction
                    )));
                }
                let state_before_hash = hash_json_hex(&event.state_before)?;
                let state_after_hash = hash_json_hex(&event.state_after)?;
                let transition_hash = research_v3_transition_relation_hash(
                    event.step,
                    &instruction,
                    &state_before_hash,
                    &state_after_hash,
                )?;
                state_before_hashes.insert((*engine_name).to_string(), state_before_hash);
                state_after_hashes.insert((*engine_name).to_string(), state_after_hash);
                engine_transition_hashes.insert((*engine_name).to_string(), transition_hash);
            }
            let canonical_transition_hash =
                engine_transition_hashes
                    .get(*reference_name)
                    .cloned()
                    .ok_or_else(|| {
                        VmError::InvalidConfig(format!(
                            "research-v3-equivalence missing reference transition hash for {}",
                            reference_name
                        ))
                    })?;
            Ok(ResearchV3RuleWitness {
                step: reference_event.step,
                rule_id: research_v3_rule_id(&instruction),
                relation: "same-instruction-same-state-transition".to_string(),
                instruction,
                participating_engines: participating_engines.clone(),
                state_before_hashes,
                state_after_hashes,
                engine_transition_hashes,
                canonical_transition_hash,
                validation: ResearchV3RuleValidation {
                    differential_lockstep: true,
                    egraph_status: "not-attempted".to_string(),
                    smt_status: "not-attempted".to_string(),
                    randomized_testing_status: "not-attempted".to_string(),
                },
            })
        })
        .collect()
}

#[cfg(all(feature = "burn-model", feature = "onnx-export"))]
fn research_v3_transition_relation_hash(
    step: usize,
    instruction: &str,
    state_before_hash: &str,
    state_after_hash: &str,
) -> llm_provable_computer::Result<String> {
    let row = ResearchV3TransitionRelationRow {
        relation_format: RESEARCH_V3_RELATION_FORMAT.to_string(),
        step,
        instruction: instruction.to_string(),
        state_before_hash: state_before_hash.to_string(),
        state_after_hash: state_after_hash.to_string(),
    };
    hash_json_projection_hex(&row)
}

#[cfg(all(feature = "burn-model", feature = "onnx-export"))]
fn research_v3_limitations() -> Vec<String> {
    [
        "Emerge reproduction is not implemented in this artifact",
        "e-graph saturation is not implemented in this artifact",
        "SMT-backed rewrite synthesis is not implemented in this artifact",
        "randomized opaque-kernel testing is not implemented in this artifact",
        "recursive accumulation is not implemented in this artifact",
        "this artifact is not a cryptographic implementation-equivalence proof",
        "the current evidence is deterministic multi-engine lockstep over the shipped VM/ONNX/Burn/native surfaces",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

#[cfg(all(feature = "burn-model", feature = "onnx-export"))]
fn load_research_v3_equivalence_artifact(
    artifact_path: &Path,
) -> llm_provable_computer::Result<ResearchV3EquivalenceArtifact> {
    let metadata = fs::symlink_metadata(artifact_path).map_err(|err| {
        VmError::InvalidConfig(format!(
            "failed to read research-v3 artifact {}: {err}",
            artifact_path.display()
        ))
    })?;
    if !metadata.file_type().is_file() {
        return Err(VmError::InvalidConfig(format!(
            "research-v3 artifact {} is not a regular file",
            artifact_path.display()
        )));
    }
    if metadata.len() > MAX_RESEARCH_V3_EQUIVALENCE_ARTIFACT_JSON_BYTES as u64 {
        return Err(VmError::InvalidConfig(format!(
            "research-v3 artifact {} is {} bytes, exceeding the limit of {} bytes",
            artifact_path.display(),
            metadata.len(),
            MAX_RESEARCH_V3_EQUIVALENCE_ARTIFACT_JSON_BYTES
        )));
    }
    let file = fs::File::open(artifact_path).map_err(|err| {
        VmError::InvalidConfig(format!(
            "failed to read research-v3 artifact {}: {err}",
            artifact_path.display()
        ))
    })?;
    let opened_metadata = file.metadata().map_err(|err| {
        VmError::InvalidConfig(format!(
            "failed to read research-v3 artifact {}: {err}",
            artifact_path.display()
        ))
    })?;
    if !opened_metadata.is_file() {
        return Err(VmError::InvalidConfig(format!(
            "research-v3 artifact {} is not a regular file after opening",
            artifact_path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if metadata.dev() != opened_metadata.dev() || metadata.ino() != opened_metadata.ino() {
            return Err(VmError::InvalidConfig(format!(
                "research-v3 artifact {} changed between metadata inspection and open",
                artifact_path.display()
            )));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;

        if metadata.volume_serial_number() != opened_metadata.volume_serial_number()
            || metadata.file_index() != opened_metadata.file_index()
        {
            return Err(VmError::InvalidConfig(format!(
                "research-v3 artifact {} changed between metadata inspection and open",
                artifact_path.display()
            )));
        }
    }
    let mut artifact_bytes = Vec::new();
    let mut limited_reader = file.take(MAX_RESEARCH_V3_EQUIVALENCE_ARTIFACT_JSON_BYTES as u64 + 1);
    limited_reader
        .read_to_end(&mut artifact_bytes)
        .map_err(|err| {
            VmError::InvalidConfig(format!(
                "failed to read research-v3 artifact {}: {err}",
                artifact_path.display()
            ))
        })?;
    if artifact_bytes.len() > MAX_RESEARCH_V3_EQUIVALENCE_ARTIFACT_JSON_BYTES {
        return Err(VmError::InvalidConfig(format!(
            "research-v3 artifact {} is {} bytes after read, exceeding the limit of {} bytes",
            artifact_path.display(),
            artifact_bytes.len(),
            MAX_RESEARCH_V3_EQUIVALENCE_ARTIFACT_JSON_BYTES
        )));
    }

    serde_json::from_slice(&artifact_bytes).map_err(|err| {
        VmError::Serialization(format!(
            "failed to parse research-v3 artifact {}: {err}",
            artifact_path.display()
        ))
    })
}

#[cfg(all(feature = "burn-model", feature = "onnx-export"))]
fn verify_research_v3_equivalence_command_impl(
    artifact_path: &Path,
) -> llm_provable_computer::Result<()> {
    let artifact = load_research_v3_equivalence_artifact(artifact_path)?;

    verify_research_v3_equivalence_artifact(&artifact)?;

    println!("verified_research_v3_equivalence: true");
    println!("statement_version: {}", artifact.statement_version);
    println!("semantic_scope: {}", artifact.semantic_scope);
    println!("relation_format: {}", artifact.relation_format);
    println!("checked_steps: {}", artifact.checked_steps);
    println!(
        "engines: {}",
        artifact
            .engines
            .iter()
            .map(|engine| engine.name.as_str())
            .collect::<Vec<_>>()
            .join(",")
    );
    println!("rule_witnesses: {}", artifact.rule_witnesses.len());

    Ok(())
}

#[cfg(all(feature = "burn-model", feature = "onnx-export"))]
fn verify_research_v3_equivalence_artifact(
    artifact: &ResearchV3EquivalenceArtifact,
) -> llm_provable_computer::Result<()> {
    let bundle = load_research_v2_spec_bundle(
        STATEMENT_V3_EQUIVALENCE_SPEC_PATH,
        STATEMENT_V3_EQUIVALENCE_ARTIFACT_SCHEMA_PATH,
    )?;
    research_v3_expect_eq(
        "statement_version",
        &artifact.statement_version,
        &bundle.statement_version,
    )?;
    research_v3_expect_eq(
        "semantic_scope",
        &artifact.semantic_scope,
        &bundle.semantic_scope,
    )?;
    research_v3_expect_eq(
        "relation_format",
        &artifact.relation_format,
        RESEARCH_V3_RELATION_FORMAT,
    )?;
    research_v3_expect_eq(
        "fixed_point_profile",
        &artifact.fixed_point_profile,
        &bundle.fixed_point_profile,
    )?;
    research_v3_expect_eq(
        "onnx_op_subset_version",
        &artifact.onnx_op_subset_version,
        &bundle.onnx_op_subset_version,
    )?;
    if artifact.onnx_op_subset_size != bundle.onnx_op_subset_size {
        return Err(VmError::InvalidConfig(format!(
            "research-v3 onnx_op_subset_size mismatch: expected {}, got {}",
            bundle.onnx_op_subset_size, artifact.onnx_op_subset_size
        )));
    }
    if artifact.requested_max_steps == 0 {
        return Err(VmError::InvalidConfig(
            "research-v3 requested_max_steps must be nonzero".to_string(),
        ));
    }
    if artifact.checked_steps > artifact.requested_max_steps {
        return Err(VmError::InvalidConfig(format!(
            "research-v3 checked_steps {} exceeds requested_max_steps {}",
            artifact.checked_steps, artifact.requested_max_steps
        )));
    }
    if artifact.checked_steps != artifact.rule_witnesses.len() {
        return Err(VmError::InvalidConfig(format!(
            "research-v3 checked_steps {} does not match rule_witnesses length {}",
            artifact.checked_steps,
            artifact.rule_witnesses.len()
        )));
    }
    let expected_limitations = research_v3_limitations();
    if artifact.limitations != expected_limitations {
        return Err(VmError::InvalidConfig(
            "research-v3 limitations do not match the pinned research-v3 claim boundary"
                .to_string(),
        ));
    }

    validate_frontend_runtime_semantics_registry(&artifact.frontend_runtime_semantics_registry)?;
    verify_research_v3_engine_lane_binding(artifact)?;
    research_v3_verify_commitment(
        "statement_spec_hash",
        &artifact.commitments.statement_spec_hash,
        &bundle.statement_spec_hash,
    )?;
    research_v3_verify_commitment(
        "fixed_point_spec_hash",
        &artifact.commitments.fixed_point_spec_hash,
        &bundle.fixed_point_spec_hash,
    )?;
    research_v3_verify_commitment(
        "onnx_op_subset_hash",
        &artifact.commitments.onnx_op_subset_hash,
        &bundle.onnx_op_subset_hash,
    )?;
    research_v3_verify_commitment(
        "artifact_schema_hash",
        &artifact.commitments.artifact_schema_hash,
        &bundle.artifact_schema_hash,
    )?;
    research_v3_expect_eq(
        "commitments.hash_function",
        &artifact.commitments.hash_function,
        RESEARCH_V2_HASH_FUNCTION,
    )?;
    research_v3_verify_commitment(
        "frontend_runtime_semantics_registry_hash",
        &artifact
            .commitments
            .frontend_runtime_semantics_registry_hash,
        &hash_json_hex(&artifact.frontend_runtime_semantics_registry)?,
    )?;
    research_v3_verify_commitment(
        "relation_format_hash",
        &artifact.commitments.relation_format_hash,
        &hash_json_hex(&artifact.relation_format)?,
    )?;
    research_v3_verify_commitment(
        "limitations_hash",
        &artifact.commitments.limitations_hash,
        &hash_json_hex(&artifact.limitations)?,
    )?;
    research_v3_verify_commitment(
        "engine_summaries_hash",
        &artifact.commitments.engine_summaries_hash,
        &hash_json_projection_hex(&artifact.engines)?,
    )?;
    research_v3_verify_commitment(
        "rule_witnesses_hash",
        &artifact.commitments.rule_witnesses_hash,
        &hash_json_projection_hex(&artifact.rule_witnesses)?,
    )?;
    for (label, hash) in [
        ("program_hash", artifact.commitments.program_hash.as_str()),
        (
            "transformer_config_hash",
            artifact.commitments.transformer_config_hash.as_str(),
        ),
        (
            "onnx_metadata_hash",
            artifact.commitments.onnx_metadata_hash.as_str(),
        ),
    ] {
        research_v3_expect_hash_hex(label, hash)?;
    }

    verify_research_v3_engine_summaries(artifact)?;
    verify_research_v3_rule_witnesses(artifact)?;

    Ok(())
}

#[cfg(all(feature = "burn-model", feature = "onnx-export"))]
fn verify_research_v3_engine_lane_binding(
    artifact: &ResearchV3EquivalenceArtifact,
) -> llm_provable_computer::Result<()> {
    let expected_engine_bindings = RESEARCH_V3_PINNED_ENGINE_LANE_BINDINGS
        .iter()
        .copied()
        .collect::<std::collections::BTreeMap<_, _>>();
    let expected_engine_names = expected_engine_bindings
        .keys()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    let mut actual_engine_names = std::collections::BTreeSet::new();
    for engine in &artifact.engines {
        expected_engine_bindings
            .get(engine.name.as_str())
            .ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "research-v3 engine {} is not bound to a pinned implemented lane",
                    engine.name
                ))
            })?;
        actual_engine_names.insert(engine.name.as_str());
    }
    if actual_engine_names != expected_engine_names {
        return Err(VmError::InvalidConfig(format!(
            "research-v3 engine set does not match the pinned artifact boundary: expected [{}], got [{}]",
            expected_engine_names.iter().copied().collect::<Vec<_>>().join(", "),
            actual_engine_names.iter().copied().collect::<Vec<_>>().join(", ")
        )));
    }

    Ok(())
}

#[cfg(all(feature = "burn-model", feature = "onnx-export"))]
fn verify_research_v3_engine_summaries(
    artifact: &ResearchV3EquivalenceArtifact,
) -> llm_provable_computer::Result<()> {
    let expected_trace_len = artifact.checked_steps.checked_add(1).ok_or_else(|| {
        VmError::InvalidConfig("research-v3 checked_steps overflowed trace_len".to_string())
    })?;
    let mut seen = std::collections::BTreeSet::new();
    for engine in &artifact.engines {
        if !seen.insert(engine.name.as_str()) {
            return Err(VmError::InvalidConfig(format!(
                "research-v3 duplicate engine summary `{}`",
                engine.name
            )));
        }
        if engine.halted != engine.final_state.halted {
            return Err(VmError::InvalidConfig(format!(
                "research-v3 engine {} halted={} does not match final_state.halted={}",
                engine.name, engine.halted, engine.final_state.halted
            )));
        }
        if engine.steps != artifact.checked_steps {
            return Err(VmError::InvalidConfig(format!(
                "research-v3 engine {} steps {} does not match checked_steps {}",
                engine.name, engine.steps, artifact.checked_steps
            )));
        }
        if engine.events_len != artifact.checked_steps {
            return Err(VmError::InvalidConfig(format!(
                "research-v3 engine {} events_len {} does not match checked_steps {}",
                engine.name, engine.events_len, artifact.checked_steps
            )));
        }
        if engine.trace.len() != engine.trace_len {
            return Err(VmError::InvalidConfig(format!(
                "research-v3 engine {} trace array length {} does not match trace_len {}",
                engine.name,
                engine.trace.len(),
                engine.trace_len
            )));
        }
        if engine.canonical_events.len() != engine.events_len {
            return Err(VmError::InvalidConfig(format!(
                "research-v3 engine {} canonical_events length {} does not match events_len {}",
                engine.name,
                engine.canonical_events.len(),
                engine.events_len
            )));
        }
        if engine.trace_len != expected_trace_len {
            return Err(VmError::InvalidConfig(format!(
                "research-v3 engine {} trace_len {} does not match checked_steps+1 {}",
                engine.name, engine.trace_len, expected_trace_len
            )));
        }
        if engine.trace.last() != Some(&engine.final_state) {
            return Err(VmError::InvalidConfig(format!(
                "research-v3 engine {} final_state does not match final trace state",
                engine.name
            )));
        }
        verify_research_v3_engine_trace_events(engine)?;
        research_v3_verify_commitment(
            &format!("{}.final_state_hash", engine.name),
            &engine.final_state_hash,
            &hash_json_hex(&engine.final_state)?,
        )?;
        research_v3_verify_commitment(
            &format!("{}.trace_hash", engine.name),
            &engine.trace_hash,
            &hash_json_hex(&engine.trace)?,
        )?;
        research_v3_verify_commitment(
            &format!("{}.event_relation_hash", engine.name),
            &engine.event_relation_hash,
            &hash_json_hex(&engine.canonical_events)?,
        )?;
    }
    if let Some(reference) = artifact.engines.first() {
        for engine in &artifact.engines {
            research_v3_verify_commitment(
                &format!("engine {} cross-engine trace_hash", engine.name),
                &engine.trace_hash,
                &reference.trace_hash,
            )?;
            research_v3_verify_commitment(
                &format!("engine {} cross-engine event_relation_hash", engine.name),
                &engine.event_relation_hash,
                &reference.event_relation_hash,
            )?;
        }
    }
    Ok(())
}

#[cfg(all(feature = "burn-model", feature = "onnx-export"))]
fn verify_research_v3_engine_trace_events(
    engine: &ResearchV3EngineSummary,
) -> llm_provable_computer::Result<()> {
    for (index, event) in engine.canonical_events.iter().enumerate() {
        let expected_step = index + 1;
        if event.step != expected_step {
            return Err(VmError::InvalidConfig(format!(
                "research-v3 engine {} canonical event step mismatch at index {}: expected {}, got {}",
                engine.name, index, expected_step, event.step
            )));
        }
        let state_before = engine.trace.get(index).ok_or_else(|| {
            VmError::InvalidConfig(format!(
                "research-v3 engine {} missing trace state before canonical event {}",
                engine.name, event.step
            ))
        })?;
        let state_after = engine.trace.get(index + 1).ok_or_else(|| {
            VmError::InvalidConfig(format!(
                "research-v3 engine {} missing trace state after canonical event {}",
                engine.name, event.step
            ))
        })?;
        research_v3_verify_commitment(
            &format!(
                "engine {} canonical event {} state_before_hash",
                engine.name, event.step
            ),
            &event.state_before_hash,
            &hash_json_hex(state_before)?,
        )?;
        research_v3_verify_commitment(
            &format!(
                "engine {} canonical event {} state_after_hash",
                engine.name, event.step
            ),
            &event.state_after_hash,
            &hash_json_hex(state_after)?,
        )?;
    }
    Ok(())
}

#[cfg(all(feature = "burn-model", feature = "onnx-export"))]
fn verify_research_v3_rule_witnesses(
    artifact: &ResearchV3EquivalenceArtifact,
) -> llm_provable_computer::Result<()> {
    let engine_names = artifact
        .engines
        .iter()
        .map(|engine| engine.name.clone())
        .collect::<Vec<_>>();
    if engine_names.len() < 2 {
        return Err(VmError::InvalidConfig(
            "research-v3 artifact must include at least two engines".to_string(),
        ));
    }
    let reference_engine = engine_names.first().ok_or_else(|| {
        VmError::InvalidConfig("research-v3 artifact must include at least one engine".to_string())
    })?;

    for (index, witness) in artifact.rule_witnesses.iter().enumerate() {
        if witness.step != index + 1 {
            return Err(VmError::InvalidConfig(format!(
                "research-v3 witness step mismatch at index {}: expected {}, got {}",
                index,
                index + 1,
                witness.step
            )));
        }
        if witness.participating_engines != engine_names {
            return Err(VmError::InvalidConfig(format!(
                "research-v3 witness step {} participating_engines mismatch",
                witness.step
            )));
        }
        research_v3_expect_eq(
            &format!("witness {} relation", witness.step),
            &witness.relation,
            "same-instruction-same-state-transition",
        )?;
        research_v3_expect_eq(
            &format!("witness {} rule_id", witness.step),
            &witness.rule_id,
            &research_v3_rule_id(&witness.instruction),
        )?;
        if !witness.validation.differential_lockstep {
            return Err(VmError::InvalidConfig(format!(
                "research-v3 witness {} differential_lockstep must be true",
                witness.step
            )));
        }
        for (label, status) in [
            ("egraph_status", witness.validation.egraph_status.as_str()),
            ("smt_status", witness.validation.smt_status.as_str()),
            (
                "randomized_testing_status",
                witness.validation.randomized_testing_status.as_str(),
            ),
        ] {
            research_v3_expect_eq(
                &format!("witness {} {}", witness.step, label),
                status,
                "not-attempted",
            )?;
        }

        research_v3_expect_hash_map_keys(
            &witness.state_before_hashes,
            "state_before_hashes",
            witness.step,
            &engine_names,
        )?;
        research_v3_expect_hash_map_keys(
            &witness.state_after_hashes,
            "state_after_hashes",
            witness.step,
            &engine_names,
        )?;
        research_v3_expect_hash_map_keys(
            &witness.engine_transition_hashes,
            "engine_transition_hashes",
            witness.step,
            &engine_names,
        )?;
        let reference_state_before_hash = research_v3_map_hash(
            &witness.state_before_hashes,
            "state_before_hashes",
            witness.step,
            reference_engine,
        )?;
        let reference_state_after_hash = research_v3_map_hash(
            &witness.state_after_hashes,
            "state_after_hashes",
            witness.step,
            reference_engine,
        )?;
        let reference_transition_hash = research_v3_map_hash(
            &witness.engine_transition_hashes,
            "engine_transition_hashes",
            witness.step,
            reference_engine,
        )?;
        for engine_name in &engine_names {
            let engine = artifact
                .engines
                .iter()
                .find(|engine| &engine.name == engine_name)
                .ok_or_else(|| {
                    VmError::InvalidConfig(format!(
                        "research-v3 missing engine summary for {engine_name}"
                    ))
                })?;
            let canonical_event = engine.canonical_events.get(index).ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "research-v3 engine {} missing canonical event for witness {}",
                    engine.name, witness.step
                ))
            })?;
            research_v3_expect_eq(
                &format!(
                    "witness {} {} canonical_event.instruction",
                    witness.step, engine_name
                ),
                &canonical_event.instruction,
                &witness.instruction,
            )?;
            let state_before_hash = research_v3_map_hash(
                &witness.state_before_hashes,
                "state_before_hashes",
                witness.step,
                engine_name,
            )?;
            let state_after_hash = research_v3_map_hash(
                &witness.state_after_hashes,
                "state_after_hashes",
                witness.step,
                engine_name,
            )?;
            let transition_hash = research_v3_map_hash(
                &witness.engine_transition_hashes,
                "engine_transition_hashes",
                witness.step,
                engine_name,
            )?;
            research_v3_verify_commitment(
                &format!("witness {} {} state_before_hash", witness.step, engine_name),
                state_before_hash,
                reference_state_before_hash,
            )?;
            research_v3_verify_commitment(
                &format!("witness {} {} state_after_hash", witness.step, engine_name),
                state_after_hash,
                reference_state_after_hash,
            )?;
            research_v3_verify_commitment(
                &format!(
                    "witness {} {} canonical_event.state_before_hash",
                    witness.step, engine_name
                ),
                &canonical_event.state_before_hash,
                state_before_hash,
            )?;
            research_v3_verify_commitment(
                &format!(
                    "witness {} {} canonical_event.state_after_hash",
                    witness.step, engine_name
                ),
                &canonical_event.state_after_hash,
                state_after_hash,
            )?;
            let expected_transition_hash = research_v3_transition_relation_hash(
                witness.step,
                &witness.instruction,
                state_before_hash,
                state_after_hash,
            )?;
            research_v3_verify_commitment(
                &format!("witness {} {} transition_hash", witness.step, engine_name),
                transition_hash,
                &expected_transition_hash,
            )?;
            research_v3_verify_commitment(
                &format!(
                    "witness {} {} cross-engine transition_hash",
                    witness.step, engine_name
                ),
                transition_hash,
                reference_transition_hash,
            )?;
        }

        research_v3_verify_commitment(
            &format!("witness {} canonical_transition_hash", witness.step),
            &witness.canonical_transition_hash,
            reference_transition_hash,
        )?;
    }

    if let Some(final_witness) = artifact.rule_witnesses.last() {
        for engine in &artifact.engines {
            let final_witness_state_hash = research_v3_map_hash(
                &final_witness.state_after_hashes,
                "state_after_hashes",
                final_witness.step,
                &engine.name,
            )?;
            research_v3_verify_commitment(
                &format!(
                    "engine {} final_state_hash matches final witness boundary",
                    engine.name
                ),
                &engine.final_state_hash,
                final_witness_state_hash,
            )?;
        }
    }
    let reference_final_state_hash = &artifact
        .engines
        .first()
        .ok_or_else(|| {
            VmError::InvalidConfig(
                "research-v3 artifact must include at least one engine".to_string(),
            )
        })?
        .final_state_hash;
    for engine in &artifact.engines {
        research_v3_verify_commitment(
            &format!("engine {} cross-engine final_state_hash", engine.name),
            &engine.final_state_hash,
            reference_final_state_hash,
        )?;
    }

    Ok(())
}

#[cfg(all(feature = "burn-model", feature = "onnx-export"))]
fn research_v3_expect_hash_map_keys(
    map: &std::collections::BTreeMap<String, String>,
    map_name: &str,
    step: usize,
    engine_names: &[String],
) -> llm_provable_computer::Result<()> {
    let actual = map
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    let expected = engine_names
        .iter()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    if actual != expected {
        return Err(VmError::InvalidConfig(format!(
            "research-v3 witness {step} {map_name} engine-key set mismatch"
        )));
    }
    Ok(())
}

#[cfg(all(feature = "burn-model", feature = "onnx-export"))]
fn research_v3_map_hash<'a>(
    map: &'a std::collections::BTreeMap<String, String>,
    map_name: &str,
    step: usize,
    engine_name: &str,
) -> llm_provable_computer::Result<&'a str> {
    let hash = map.get(engine_name).ok_or_else(|| {
        VmError::InvalidConfig(format!(
            "research-v3 witness {} missing {} entry for {}",
            step, map_name, engine_name
        ))
    })?;
    research_v3_expect_hash_hex(
        &format!("witness {} {} {}", step, map_name, engine_name),
        hash,
    )?;
    Ok(hash)
}

#[cfg(all(feature = "burn-model", feature = "onnx-export"))]
fn research_v3_verify_commitment(
    label: &str,
    actual: &str,
    expected: &str,
) -> llm_provable_computer::Result<()> {
    research_v3_expect_hash_hex(label, actual)?;
    research_v3_expect_hash_hex(label, expected)?;
    if actual != expected {
        return Err(VmError::InvalidConfig(format!(
            "research-v3 {label} commitment mismatch: expected {expected}, got {actual}"
        )));
    }
    Ok(())
}

#[cfg(all(feature = "burn-model", feature = "onnx-export"))]
fn research_v3_expect_eq(
    label: &str,
    actual: &str,
    expected: &str,
) -> llm_provable_computer::Result<()> {
    if actual != expected {
        return Err(VmError::InvalidConfig(format!(
            "research-v3 {label} mismatch: expected `{expected}`, got `{actual}`"
        )));
    }
    Ok(())
}

#[cfg(all(feature = "burn-model", feature = "onnx-export"))]
fn research_v3_expect_hash_hex(label: &str, value: &str) -> llm_provable_computer::Result<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(VmError::InvalidConfig(format!(
            "research-v3 {label} must be a 64-character hex Blake2b-256 hash"
        )));
    }
    Ok(())
}

#[cfg(all(feature = "burn-model", feature = "onnx-export"))]
fn research_v3_rule_id(instruction: &str) -> String {
    let opcode = instruction
        .split_whitespace()
        .next()
        .unwrap_or("unknown")
        .to_ascii_lowercase();
    format!("lockstep-{opcode}-v1")
}

#[cfg(feature = "onnx-export")]
fn enforce_research_v2_trace_mismatch_policy(
    matched: bool,
    allow_mismatch: bool,
    first_mismatch_step: Option<usize>,
    mismatch_reason: Option<&str>,
) -> llm_provable_computer::Result<()> {
    if !matched && !allow_mismatch {
        return Err(VmError::InvalidConfig(format!(
            "research-v2-trace mismatch at step {:?}: {}",
            first_mismatch_step,
            mismatch_reason.unwrap_or("unspecified mismatch")
        )));
    }
    Ok(())
}

#[cfg(feature = "onnx-export")]
fn enforce_research_v2_matrix_mismatch_policy(
    mismatched_programs: usize,
    allow_mismatch: bool,
) -> llm_provable_computer::Result<()> {
    if mismatched_programs > 0 && !allow_mismatch {
        return Err(VmError::InvalidConfig(format!(
            "research-v2-matrix found {} mismatched program(s)",
            mismatched_programs
        )));
    }
    Ok(())
}

#[cfg(feature = "onnx-export")]
fn load_research_v2_spec_bundle(
    statement_spec_path: &str,
    artifact_schema_path: &str,
) -> llm_provable_computer::Result<ResearchV2SpecBundle> {
    let statement_spec_bytes = read_repo_file(statement_spec_path)?;
    let fixed_point_spec_bytes = read_repo_file(FIXED_POINT_SPEC_PATH)?;
    let onnx_op_subset_spec_bytes = read_repo_file(ONNX_OP_SUBSET_SPEC_PATH)?;
    let artifact_schema_bytes = read_repo_file(artifact_schema_path)?;

    let statement_spec: StatementV2ResearchSpec = serde_json::from_slice(&statement_spec_bytes)
        .map_err(|err| {
            VmError::Serialization(format!("failed to parse {}: {err}", statement_spec_path))
        })?;
    let fixed_point_spec: FixedPointSemanticsSpec = serde_json::from_slice(&fixed_point_spec_bytes)
        .map_err(|err| {
            VmError::Serialization(format!("failed to parse {}: {err}", FIXED_POINT_SPEC_PATH))
        })?;
    let onnx_op_subset_spec: OnnxOpSubsetSpec = serde_json::from_slice(&onnx_op_subset_spec_bytes)
        .map_err(|err| {
            VmError::Serialization(format!(
                "failed to parse {}: {err}",
                ONNX_OP_SUBSET_SPEC_PATH
            ))
        })?;

    if statement_spec.fixed_point_profile_ref != FIXED_POINT_SPEC_PATH {
        return Err(VmError::InvalidConfig(format!(
            "{} references `{}` but expected `{}`",
            statement_spec_path, statement_spec.fixed_point_profile_ref, FIXED_POINT_SPEC_PATH
        )));
    }
    if statement_spec.onnx_op_subset_ref != ONNX_OP_SUBSET_SPEC_PATH {
        return Err(VmError::InvalidConfig(format!(
            "{} references `{}` but expected `{}`",
            statement_spec_path, statement_spec.onnx_op_subset_ref, ONNX_OP_SUBSET_SPEC_PATH
        )));
    }
    if statement_spec.artifact_schema_ref != artifact_schema_path {
        return Err(VmError::InvalidConfig(format!(
            "{} references `{}` but expected `{}`",
            statement_spec_path, statement_spec.artifact_schema_ref, artifact_schema_path
        )));
    }

    Ok(ResearchV2SpecBundle {
        statement_version: statement_spec.statement_version,
        semantic_scope: statement_spec.semantic_scope,
        fixed_point_profile: fixed_point_spec.profile_id,
        onnx_op_subset_version: onnx_op_subset_spec.version,
        onnx_op_subset_size: onnx_op_subset_spec.operators.len(),
        statement_spec_hash: hash_bytes_hex(&statement_spec_bytes),
        fixed_point_spec_hash: hash_bytes_hex(&fixed_point_spec_bytes),
        onnx_op_subset_hash: hash_bytes_hex(&onnx_op_subset_spec_bytes),
        artifact_schema_hash: hash_bytes_hex(&artifact_schema_bytes),
    })
}

#[cfg(feature = "onnx-export")]
fn compute_research_v2_trace_artifact_for_program(
    program: &Path,
    max_steps: usize,
    layers: usize,
    attention_mode: &Attention2DMode,
    bundle: &ResearchV2SpecBundle,
) -> llm_provable_computer::Result<ResearchV2TraceArtifact> {
    if max_steps < 1 {
        return Err(VmError::InvalidConfig(
            "research-v2 trace computation requires max_steps >= 1".to_string(),
        ));
    }

    let model = compile_model(program, layers, attention_mode.clone())?;
    let export_dir = ScopedTempDir::new("research-v2-trace")?;
    let onnx_metadata = export_program_onnx(&model, export_dir.path())?;

    let mut transformer = ExecutionRuntime::new(model.clone(), max_steps);
    let mut onnx = OnnxExecutionRuntime::from_export_dir(export_dir.path(), max_steps)?;

    let mut matched = true;
    let mut first_mismatch_step: Option<usize> = None;
    let mut mismatch_reason: Option<String> = None;

    if transformer.state() != onnx.state() {
        matched = false;
        first_mismatch_step = Some(0);
        mismatch_reason =
            Some("initial state mismatch between transformer and ONNX runtimes".to_string());
    }

    while matched && transformer.step_count() < max_steps {
        let t_halted = transformer.state().halted;
        let o_halted = onnx.state().halted;
        if t_halted || o_halted {
            if t_halted != o_halted {
                matched = false;
                first_mismatch_step = Some(transformer.step_count());
                mismatch_reason = Some(format!(
                    "halted flag mismatch before step {}: transformer={}, onnx={}",
                    transformer.step_count() + 1,
                    t_halted,
                    o_halted
                ));
            }
            break;
        }

        transformer.step()?;
        onnx.step()?;
        let step = transformer.step_count();
        if step != onnx.step_count() {
            matched = false;
            first_mismatch_step = Some(step.min(onnx.step_count()));
            mismatch_reason = Some(format!(
                "step counter mismatch: transformer={}, onnx={}",
                step,
                onnx.step_count()
            ));
            break;
        }

        let transformer_event = transformer.events().last().ok_or_else(|| {
            VmError::InvalidConfig("transformer runtime produced no execution event".to_string())
        })?;
        let onnx_event = onnx.events().last().ok_or_else(|| {
            VmError::InvalidConfig("onnx runtime produced no execution event".to_string())
        })?;

        if transformer_event.instruction != onnx_event.instruction {
            matched = false;
            first_mismatch_step = Some(step);
            mismatch_reason = Some(format!(
                "instruction mismatch at step {}: transformer=`{}` onnx=`{}`",
                step, transformer_event.instruction, onnx_event.instruction
            ));
            break;
        }
        if transformer_event.state_before != onnx_event.state_before {
            matched = false;
            first_mismatch_step = Some(step);
            mismatch_reason = Some(format!("state_before mismatch at step {}", step));
            break;
        }
        if transformer_event.state_after != onnx_event.state_after {
            matched = false;
            first_mismatch_step = Some(step);
            mismatch_reason = Some(format!("state_after mismatch at step {}", step));
            break;
        }
    }

    let checked_steps = transformer.step_count().min(onnx.step_count());
    let transformer_final_state = transformer.state().clone();
    let onnx_final_state = onnx.state().clone();
    if matched && transformer_final_state != onnx_final_state {
        matched = false;
        first_mismatch_step = Some(checked_steps);
        mismatch_reason = Some("final state mismatch".to_string());
    }

    let commitments = ResearchV2TraceCommitments {
        hash_function: RESEARCH_V2_HASH_FUNCTION.to_string(),
        statement_spec_hash: bundle.statement_spec_hash.clone(),
        fixed_point_spec_hash: bundle.fixed_point_spec_hash.clone(),
        onnx_op_subset_hash: bundle.onnx_op_subset_hash.clone(),
        artifact_schema_hash: bundle.artifact_schema_hash.clone(),
        program_hash: hash_json_hex(model.program())?,
        transformer_config_hash: hash_json_hex(model.config())?,
        onnx_metadata_hash: hash_json_hex(&onnx_metadata)?,
        transformer_trace_hash: hash_json_hex(transformer.trace())?,
        onnx_trace_hash: hash_json_hex(onnx.trace())?,
        transformer_final_state_hash: hash_json_hex(&transformer_final_state)?,
        onnx_final_state_hash: hash_json_hex(&onnx_final_state)?,
    };

    Ok(ResearchV2TraceArtifact {
        statement_version: bundle.statement_version.clone(),
        semantic_scope: bundle.semantic_scope.clone(),
        fixed_point_profile: bundle.fixed_point_profile.clone(),
        onnx_op_subset_version: bundle.onnx_op_subset_version.clone(),
        onnx_op_subset_size: bundle.onnx_op_subset_size,
        program_path: program.display().to_string(),
        requested_max_steps: max_steps,
        checked_steps,
        matched,
        first_mismatch_step,
        mismatch_reason,
        transformer_final_state,
        onnx_final_state,
        commitments,
    })
}

#[cfg(feature = "onnx-export")]
fn research_v2_default_program_suite() -> Vec<PathBuf> {
    vec![
        PathBuf::from("programs/addition.tvm"),
        PathBuf::from("programs/counter.tvm"),
        PathBuf::from("programs/fibonacci.tvm"),
        PathBuf::from("programs/multiply.tvm"),
        PathBuf::from("programs/factorial_recursive.tvm"),
        PathBuf::from("programs/dot_product.tvm"),
        PathBuf::from("programs/matmul_2x2.tvm"),
        PathBuf::from("programs/single_neuron.tvm"),
    ]
}

#[cfg(not(feature = "onnx-export"))]
fn research_v2_step_command_impl(
    _program: &Path,
    _output: &Path,
    _max_steps: usize,
    _layers: usize,
    _attention_mode: Attention2DMode,
) -> llm_provable_computer::Result<()> {
    Err(feature_required_error(
        "`research-v2-step`",
        &["onnx-export"],
    ))
}

#[cfg(not(feature = "onnx-export"))]
fn research_v2_trace_command_impl(
    _program: &Path,
    _output: &Path,
    _max_steps: usize,
    _layers: usize,
    _attention_mode: Attention2DMode,
    _allow_mismatch: bool,
) -> llm_provable_computer::Result<()> {
    Err(feature_required_error(
        "`research-v2-trace`",
        &["onnx-export"],
    ))
}

#[cfg(not(feature = "onnx-export"))]
fn research_v2_matrix_command_impl(
    _output: &Path,
    _programs: &[PathBuf],
    _include_default_suite: bool,
    _max_steps: usize,
    _layers: usize,
    _attention_mode: Attention2DMode,
    _allow_mismatch: bool,
) -> llm_provable_computer::Result<()> {
    Err(feature_required_error(
        "`research-v2-matrix`",
        &["onnx-export"],
    ))
}

#[cfg(not(all(feature = "burn-model", feature = "onnx-export")))]
fn research_v3_equivalence_command_impl(
    _program: &Path,
    _output: &Path,
    _max_steps: usize,
    _layers: usize,
    _attention_mode: Attention2DMode,
) -> llm_provable_computer::Result<()> {
    Err(feature_required_error(
        "`research-v3-equivalence`",
        &["burn-model", "onnx-export"],
    ))
}

#[cfg(not(all(feature = "burn-model", feature = "onnx-export")))]
fn verify_research_v3_equivalence_command_impl(
    _artifact: &Path,
) -> llm_provable_computer::Result<()> {
    Err(feature_required_error(
        "`verify-research-v3-equivalence`",
        &["burn-model", "onnx-export"],
    ))
}

#[cfg(feature = "onnx-export")]
fn read_repo_file(relative_path: &str) -> llm_provable_computer::Result<Vec<u8>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative_path);
    fs::read(&path).map_err(|io_error| {
        VmError::InvalidConfig(format!("failed to read {}: {io_error}", path.display()))
    })
}

#[cfg(feature = "onnx-export")]
fn read_repo_json_value(relative_path: &str) -> llm_provable_computer::Result<serde_json::Value> {
    let bytes = read_repo_file(relative_path)?;
    serde_json::from_slice(&bytes)
        .map_err(|err| VmError::Serialization(format!("failed to parse {relative_path}: {err}")))
}

#[cfg(feature = "onnx-export")]
fn validate_frontend_runtime_semantics_registry(
    registry: &serde_json::Value,
) -> llm_provable_computer::Result<()> {
    let version = registry
        .get("registry_version")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            VmError::InvalidConfig(
                "frontend runtime semantics registry missing registry_version".to_string(),
            )
        })?;
    if version != FRONTEND_RUNTIME_SEMANTICS_REGISTRY_VERSION {
        return Err(VmError::InvalidConfig(format!(
            "frontend runtime semantics registry version mismatch: expected {}, got {}",
            FRONTEND_RUNTIME_SEMANTICS_REGISTRY_VERSION, version
        )));
    }

    let scope = registry
        .get("semantic_scope")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            VmError::InvalidConfig(
                "frontend runtime semantics registry missing semantic_scope".to_string(),
            )
        })?;
    if scope != FRONTEND_RUNTIME_SEMANTICS_REGISTRY_SCOPE {
        return Err(VmError::InvalidConfig(format!(
            "frontend runtime semantics registry scope mismatch: expected {}, got {}",
            FRONTEND_RUNTIME_SEMANTICS_REGISTRY_SCOPE, scope
        )));
    }

    let lanes = registry
        .get("lanes")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            VmError::InvalidConfig(
                "frontend runtime semantics registry missing lanes array".to_string(),
            )
        })?;

    let implemented_allowlist = RESEARCH_V3_PINNED_ENGINE_LANE_BINDINGS
        .iter()
        .map(|(_, lane_id)| *lane_id)
        .collect::<std::collections::BTreeSet<_>>();
    let mut lane_statuses = std::collections::BTreeMap::new();
    for lane in lanes {
        let lane_id = lane
            .get("lane_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                VmError::InvalidConfig(
                    "frontend runtime semantics registry lane missing lane_id".to_string(),
                )
            })?;
        let status = lane
            .get("status")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "frontend runtime semantics registry lane {lane_id} missing status"
                ))
            })?;
        if !matches!(status, "implemented" | "research_watch" | "not_implemented") {
            return Err(VmError::InvalidConfig(format!(
                "frontend runtime semantics registry lane {lane_id} has invalid status {status}"
            )));
        }
        if status == "implemented" && !implemented_allowlist.contains(lane_id) {
            return Err(VmError::InvalidConfig(format!(
                "frontend runtime semantics registry unexpected implemented lane {lane_id}"
            )));
        }
        if lane_statuses.insert(lane_id, status).is_some() {
            return Err(VmError::InvalidConfig(format!(
                "frontend runtime semantics registry duplicate lane_id {lane_id}"
            )));
        }
    }

    for (lane_id, expected_status) in RESEARCH_V3_PINNED_ENGINE_LANE_BINDINGS
        .iter()
        .map(|(_, lane_id)| (*lane_id, "implemented"))
        .chain(
            FRONTEND_RUNTIME_RESEARCH_WATCH_LANES
                .iter()
                .copied()
                .map(|lane_id| (lane_id, "research_watch")),
        )
    {
        let status = lane_statuses.get(lane_id).copied().ok_or_else(|| {
            VmError::InvalidConfig(format!(
                "frontend runtime semantics registry missing lane {lane_id}"
            ))
        })?;
        if status != expected_status {
            return Err(VmError::InvalidConfig(format!(
                "frontend runtime semantics registry lane {lane_id} status mismatch: expected {expected_status}, got {status}"
            )));
        }
    }

    Ok(())
}

fn hash_json_hex<T: Serialize + ?Sized>(value: &T) -> llm_provable_computer::Result<String> {
    let bytes = serde_json::to_vec(value).map_err(|err| {
        VmError::Serialization(format!("failed to serialize hash payload: {err}"))
    })?;
    Ok(hash_bytes_hex(&bytes))
}

fn hash_json_projection_hex<T: Serialize + ?Sized>(
    value: &T,
) -> llm_provable_computer::Result<String> {
    let projection = serde_json::to_value(value).map_err(|err| {
        VmError::Serialization(format!("failed to serialize hash projection: {err}"))
    })?;
    hash_json_hex(&projection)
}

fn hash_bytes_hex(bytes: &[u8]) -> String {
    let mut output = [0u8; 32];
    let mut hasher = Blake2bVar::new(output.len()).expect("blake2b-256 hasher");
    hasher.update(bytes);
    hasher
        .finalize_variable(&mut output)
        .expect("blake2b-256 finalization");
    encode_hex(&output)
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn write_bytes_atomically(path: &Path, bytes: &[u8]) -> llm_provable_computer::Result<()> {
    use std::io::Write;

    let parent = path.parent().filter(|dir| !dir.as_os_str().is_empty());
    let dir = parent.unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_else(|| "artifact".into());
    for attempt in 0..1024u16 {
        let temp_path = dir.join(format!(".{file_name}.tmp-{}-{attempt}", std::process::id()));
        let mut file = match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
        {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err.into()),
        };
        if let Err(err) = file.write_all(bytes).and_then(|()| file.sync_all()) {
            let _ = fs::remove_file(&temp_path);
            return Err(err.into());
        }
        drop(file);

        if let Err(err) = fs::rename(&temp_path, path) {
            let destination_exists = path.try_exists().unwrap_or(false);
            if destination_exists
                && matches!(
                    err.kind(),
                    std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::PermissionDenied
                )
            {
                // POSIX rename replaces atomically. Some platforms reject existing destinations.
                // Use a same-directory backup so a failed fallback publish can restore the old artifact.
                let backup_path =
                    dir.join(format!(".{file_name}.bak-{}-{attempt}", std::process::id()));
                if let Err(backup_err) = fs::rename(path, &backup_path) {
                    let _ = fs::remove_file(&temp_path);
                    if backup_err.kind() == std::io::ErrorKind::AlreadyExists {
                        continue;
                    }
                    return Err(backup_err.into());
                }
                if let Err(rename_err) = fs::rename(&temp_path, path) {
                    let restore_result = fs::rename(&backup_path, path);
                    let _ = fs::remove_file(&temp_path);
                    if let Err(restore_err) = restore_result {
                        return Err(VmError::InvalidConfig(format!(
                            "failed to publish {}; restore from {} failed after publish error: {restore_err}; publish error: {rename_err}",
                            path.display(),
                            backup_path.display()
                        )));
                    }
                    return Err(rename_err.into());
                }
                let _ = fs::remove_file(&backup_path);
            } else {
                let _ = fs::remove_file(&temp_path);
                return Err(err.into());
            }
        }

        return Ok(());
    }

    Err(VmError::InvalidConfig(format!(
        "failed to allocate atomic temp path for {}",
        path.display()
    )))
}

#[cfg(test)]
mod hf_provenance_manifest_tests {
    use super::*;

    fn hf_provenance_test_manifest_file(label: &str) -> tempfile::NamedTempFile {
        tempfile::Builder::new()
            .prefix(&format!("hf-provenance-{label}-"))
            .suffix(".json")
            .tempfile()
            .expect("create HF provenance manifest fixture")
    }

    fn sample_hf_provenance_manifest_value() -> serde_json::Value {
        serde_json::json!({
            "manifest_version": HF_PROVENANCE_MANIFEST_VERSION,
            "semantic_scope": HF_PROVENANCE_SEMANTIC_SCOPE,
            "commitment_hash_function": HF_PROVENANCE_HASH_FUNCTION,
            "hub_repo": "example/test-model",
            "hub_revision": "0123456789abcdef",
            "tokenizer": {
                "tokenizer_id": "example/test-model",
                "tokenizer_revision": "0123456789abcdef",
                "tokenizer_json": null,
                "tokenizer_config": null,
                "tokenization_transcript": null
            },
            "safetensors": [],
            "onnx_export": null,
            "release": {
                "model_card": null,
                "doi": null,
                "datasets": [],
                "notes": []
            },
            "limitations": hf_provenance_limitations(),
            "commitments": {
                "hub_binding_hash": "f".repeat(64),
                "tokenizer_hash": "0".repeat(64),
                "safetensors_manifest_hash": "1".repeat(64),
                "onnx_export_hash": "2".repeat(64),
                "release_metadata_hash": "3".repeat(64),
                "limitations_hash": "4".repeat(64)
            }
        })
    }

    fn write_hf_provenance_test_manifest(path: &Path, value: &serde_json::Value) {
        let bytes = serde_json::to_vec_pretty(value).expect("serialize HF provenance manifest");
        fs::write(path, bytes).expect("write HF provenance manifest");
    }

    fn sample_hf_provenance_manifest_with_onnx_export(
        onnx_export: Option<HfOnnxExportProvenance>,
    ) -> HfProvenanceManifest {
        let tokenizer = HfTokenizerProvenance {
            tokenizer_id: "example/test-model".to_string(),
            tokenizer_revision: "0123456789abcdef".to_string(),
            tokenizer_json: None,
            tokenizer_config: None,
            tokenization_transcript: None,
        };
        let safetensors = Vec::new();
        let release = HfReleaseMetadata {
            model_card: None,
            doi: None,
            datasets: Vec::new(),
            notes: vec!["release note".to_string()],
        };
        let limitations = hf_provenance_limitations();
        let hub_repo = "example/test-model".to_string();
        let hub_revision = "0123456789abcdef".to_string();
        HfProvenanceManifest {
            manifest_version: HF_PROVENANCE_MANIFEST_VERSION.to_string(),
            semantic_scope: HF_PROVENANCE_SEMANTIC_SCOPE.to_string(),
            commitment_hash_function: HF_PROVENANCE_HASH_FUNCTION.to_string(),
            hub_repo: hub_repo.clone(),
            hub_revision: hub_revision.clone(),
            tokenizer: tokenizer.clone(),
            safetensors,
            onnx_export: onnx_export.clone(),
            release: release.clone(),
            limitations: limitations.clone(),
            commitments: HfProvenanceCommitments {
                hub_binding_hash: hash_json_projection_hex(&HfHubBinding {
                    hub_repo: &hub_repo,
                    hub_revision: &hub_revision,
                })
                .expect("hub binding hash"),
                tokenizer_hash: hash_json_projection_hex(&tokenizer).expect("tokenizer hash"),
                safetensors_manifest_hash: hash_json_projection_hex(&Vec::<
                    HfSafetensorsFileCommitment,
                >::new())
                .expect("safetensors hash"),
                onnx_export_hash: hash_json_projection_hex(&onnx_export).expect("onnx hash"),
                release_metadata_hash: hash_json_projection_hex(&release).expect("release hash"),
                limitations_hash: hash_json_projection_hex(&limitations).expect("limitations hash"),
            },
        }
    }

    #[test]
    fn load_hf_provenance_manifest_rejects_unknown_top_level_field() {
        let file = hf_provenance_test_manifest_file("extra-top");
        let mut value = sample_hf_provenance_manifest_value();
        value
            .as_object_mut()
            .expect("manifest object")
            .insert("unexpected_field".to_string(), serde_json::json!(true));
        write_hf_provenance_test_manifest(file.path(), &value);

        let err = load_hf_provenance_manifest(file.path())
            .expect_err("unknown top-level field should fail");
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn load_hf_provenance_manifest_rejects_unknown_nested_onnx_export_field() {
        let file = hf_provenance_test_manifest_file("extra-onnx");
        let mut value = sample_hf_provenance_manifest_value();
        value["onnx_export"] = serde_json::json!({
            "exporter": "optimum",
            "exporter_version": "1.0.0",
            "graph": {
                "path": "model.onnx",
                "size_bytes": 16,
                "blake2b_256": "5".repeat(64),
                "sha256": "6".repeat(64)
            },
            "metadata": null,
            "external_data_files": [],
            "unexpected_field": 7
        });
        write_hf_provenance_test_manifest(file.path(), &value);

        let err = load_hf_provenance_manifest(file.path())
            .expect_err("unknown nested ONNX field should fail");
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn load_hf_provenance_manifest_rejects_v4_missing_onnx_metadata_field() {
        let file = hf_provenance_test_manifest_file("missing-onnx-metadata");
        let mut value = sample_hf_provenance_manifest_value();
        value["onnx_export"] = serde_json::json!({
            "exporter": "optimum",
            "exporter_version": null,
            "graph": {
                "path": "model.onnx",
                "size_bytes": 16,
                "blake2b_256": "5".repeat(64),
                "sha256": "6".repeat(64)
            },
            "external_data_files": []
        });
        write_hf_provenance_test_manifest(file.path(), &value);

        let err = load_hf_provenance_manifest(file.path())
            .expect_err("v3 manifest missing onnx metadata field should fail");
        assert!(err.to_string().contains("missing field `metadata`"));
    }

    #[test]
    fn load_hf_provenance_manifest_rejects_v4_missing_hub_binding_hash_field() {
        let file = hf_provenance_test_manifest_file("missing-hub-binding-hash");
        let mut value = sample_hf_provenance_manifest_value();
        value["commitments"]
            .as_object_mut()
            .expect("commitments object")
            .remove("hub_binding_hash");
        write_hf_provenance_test_manifest(file.path(), &value);

        let err = load_hf_provenance_manifest(file.path())
            .expect_err("v4 manifest missing hub_binding_hash should fail");
        let err_text = err.to_string();
        assert!(err_text.contains(HF_PROVENANCE_MANIFEST_VERSION));
        assert!(err_text.contains("hub_binding_hash"));
    }

    #[test]
    fn load_hf_provenance_manifest_rejects_legacy_v1_onnx_export_with_upgrade_message() {
        let file = hf_provenance_test_manifest_file("legacy-v1-onnx");
        let mut value = sample_hf_provenance_manifest_value();
        value["manifest_version"] = serde_json::json!(HF_PROVENANCE_MANIFEST_VERSION_V1_LEGACY);
        value["onnx_export"] = serde_json::json!({
            "exporter": "optimum",
            "exporter_version": null,
            "graph": {
                "path": "model.onnx",
                "size_bytes": 16,
                "blake2b_256": "5".repeat(64)
            }
        });
        write_hf_provenance_test_manifest(file.path(), &value);

        let err = load_hf_provenance_manifest(file.path())
            .expect_err("legacy v1 manifest should require regeneration");
        assert!(err
            .to_string()
            .contains("legacy manifest_version `hf-provenance-manifest-v1` is no longer accepted"));
    }

    #[test]
    fn load_hf_provenance_manifest_rejects_legacy_v2_with_upgrade_message() {
        let file = hf_provenance_test_manifest_file("legacy-v2");
        let mut value = sample_hf_provenance_manifest_value();
        value["manifest_version"] = serde_json::json!(HF_PROVENANCE_MANIFEST_VERSION_V2_LEGACY);
        write_hf_provenance_test_manifest(file.path(), &value);

        let err = load_hf_provenance_manifest(file.path())
            .expect_err("legacy v2 manifest should require regeneration");
        assert!(err
            .to_string()
            .contains("legacy manifest_version `hf-provenance-manifest-v2` is no longer accepted"));
    }

    #[test]
    fn load_hf_provenance_manifest_rejects_legacy_v3_with_upgrade_message() {
        let file = hf_provenance_test_manifest_file("legacy-v3");
        let mut value = sample_hf_provenance_manifest_value();
        value["manifest_version"] = serde_json::json!(HF_PROVENANCE_MANIFEST_VERSION_V3_LEGACY);
        write_hf_provenance_test_manifest(file.path(), &value);

        let err = load_hf_provenance_manifest(file.path())
            .expect_err("legacy v3 manifest should require regeneration");
        assert!(err
            .to_string()
            .contains("legacy manifest_version `hf-provenance-manifest-v3` is no longer accepted"));
    }

    #[test]
    fn load_hf_provenance_manifest_reports_malformed_json_as_serialization() {
        let file = hf_provenance_test_manifest_file("malformed");
        fs::write(file.path(), b"{").expect("write malformed manifest");

        let err =
            load_hf_provenance_manifest(file.path()).expect_err("malformed manifest should fail");
        assert!(matches!(err, VmError::Serialization(_)));
        assert!(err
            .to_string()
            .contains("failed to parse HF provenance manifest"));
    }

    #[test]
    fn load_hf_provenance_manifest_rejects_oversized_file() {
        let file = hf_provenance_test_manifest_file("oversized");
        fs::write(
            file.path(),
            vec![b'x'; MAX_HF_PROVENANCE_MANIFEST_JSON_BYTES + 1],
        )
        .expect("write oversized HF provenance manifest");

        let err =
            load_hf_provenance_manifest(file.path()).expect_err("oversized manifest should fail");
        assert!(err.to_string().contains("exceeding the limit"));
    }

    #[test]
    fn load_hf_provenance_manifest_rejects_non_regular_file() {
        let dir = tempfile::tempdir().expect("create temp dir");

        let err = load_hf_provenance_manifest(dir.path())
            .expect_err("directory manifest path should fail");
        assert!(err.to_string().contains("not a regular file"));
    }

    #[test]
    fn prepare_hf_provenance_manifest_rejects_oversized_output() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let output = dir.path().join("manifest.json");
        let model_card = dir.path().join("README.md");
        fs::write(&model_card, b"model card").expect("write model card");

        let err = prepare_hf_provenance_manifest_command(HfProvenanceManifestCommand {
            output: output.clone(),
            hub_repo: "example/test-model".to_string(),
            hub_revision: "0123456789abcdef".to_string(),
            tokenizer_id: "example/test-model".to_string(),
            tokenizer_revision: None,
            tokenizer_json: None,
            tokenizer_config: None,
            tokenization_transcript: None,
            safetensors_files: Vec::new(),
            onnx_model: None,
            onnx_metadata: None,
            onnx_external_data_files: Vec::new(),
            onnx_exporter: "optimum-onnx".to_string(),
            onnx_exporter_version: None,
            model_card: Some(model_card),
            doi: None,
            datasets: Vec::new(),
            notes: vec!["x".repeat(MAX_HF_PROVENANCE_MANIFEST_JSON_BYTES)],
        })
        .expect_err("oversized manifest output should fail");

        assert!(err.to_string().contains("exceeding the limit"));
        assert!(!output.exists());
    }

    #[test]
    fn windows_manifest_identity_requires_volume_serial_number() {
        let err = require_windows_regular_file_identity(
            Path::new("manifest.json"),
            "HF provenance manifest",
            None,
            Some(7),
            "before open",
        )
        .expect_err("missing volume serial number should fail");

        assert!(err
            .to_string()
            .contains("cannot read volume serial number before open"));
    }

    #[test]
    fn windows_manifest_identity_requires_file_index() {
        let err = require_windows_regular_file_identity(
            Path::new("manifest.json"),
            "HF provenance manifest",
            Some(11),
            None,
            "after open",
        )
        .expect_err("missing file index should fail");

        assert!(err
            .to_string()
            .contains("cannot read file index after open"));
    }

    #[test]
    fn verify_hf_provenance_manifest_rejects_non_regular_bound_file() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let bound_dir = dir.path().join("bound-dir");
        fs::create_dir(&bound_dir).expect("create bound dir");

        let tokenizer = HfTokenizerProvenance {
            tokenizer_id: "example/test-model".to_string(),
            tokenizer_revision: "0123456789abcdef".to_string(),
            tokenizer_json: None,
            tokenizer_config: None,
            tokenization_transcript: None,
        };
        let safetensors = Vec::new();
        let onnx_export = None;
        let release = HfReleaseMetadata {
            model_card: Some(HfFileCommitment {
                path: bound_dir.display().to_string(),
                size_bytes: 0,
                blake2b_256: "0".repeat(64),
                sha256: "1".repeat(64),
            }),
            doi: None,
            datasets: Vec::new(),
            notes: Vec::new(),
        };
        let limitations = hf_provenance_limitations();
        let manifest = HfProvenanceManifest {
            manifest_version: HF_PROVENANCE_MANIFEST_VERSION.to_string(),
            semantic_scope: HF_PROVENANCE_SEMANTIC_SCOPE.to_string(),
            commitment_hash_function: HF_PROVENANCE_HASH_FUNCTION.to_string(),
            hub_repo: "example/test-model".to_string(),
            hub_revision: "0123456789abcdef".to_string(),
            tokenizer,
            safetensors,
            onnx_export,
            release,
            limitations,
            commitments: HfProvenanceCommitments {
                hub_binding_hash: hash_json_projection_hex(&HfHubBinding {
                    hub_repo: "example/test-model",
                    hub_revision: "0123456789abcdef",
                })
                .expect("hub binding hash"),
                tokenizer_hash: hash_json_projection_hex(&HfTokenizerProvenance {
                    tokenizer_id: "example/test-model".to_string(),
                    tokenizer_revision: "0123456789abcdef".to_string(),
                    tokenizer_json: None,
                    tokenizer_config: None,
                    tokenization_transcript: None,
                })
                .expect("tokenizer hash"),
                safetensors_manifest_hash: hash_json_projection_hex(&Vec::<
                    HfSafetensorsFileCommitment,
                >::new())
                .expect("safetensors hash"),
                onnx_export_hash: hash_json_projection_hex(&Option::<HfOnnxExportProvenance>::None)
                    .expect("onnx hash"),
                release_metadata_hash: hash_json_projection_hex(&HfReleaseMetadata {
                    model_card: Some(HfFileCommitment {
                        path: bound_dir.display().to_string(),
                        size_bytes: 0,
                        blake2b_256: "0".repeat(64),
                        sha256: "1".repeat(64),
                    }),
                    doi: None,
                    datasets: Vec::new(),
                    notes: Vec::new(),
                })
                .expect("release hash"),
                limitations_hash: hash_json_projection_hex(&hf_provenance_limitations())
                    .expect("limitations hash"),
            },
        };

        let err = verify_hf_provenance_manifest(&manifest)
            .expect_err("non-regular bound file should fail verification");
        assert!(err.to_string().contains("not a regular file"));
    }

    #[test]
    fn prepare_hf_provenance_manifest_rejects_onnx_sidecars_without_graph() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let output = dir.path().join("manifest.json");
        let metadata = dir.path().join("metadata.json");
        fs::write(&metadata, b"{}").expect("write metadata");

        let err = prepare_hf_provenance_manifest_command(HfProvenanceManifestCommand {
            output,
            hub_repo: "example/test-model".to_string(),
            hub_revision: "0123456789abcdef".to_string(),
            tokenizer_id: "example/test-model".to_string(),
            tokenizer_revision: None,
            tokenizer_json: None,
            tokenizer_config: None,
            tokenization_transcript: None,
            safetensors_files: Vec::new(),
            onnx_model: None,
            onnx_metadata: Some(metadata),
            onnx_external_data_files: Vec::new(),
            onnx_exporter: "optimum-onnx".to_string(),
            onnx_exporter_version: Some("1.17.0".to_string()),
            model_card: None,
            doi: None,
            datasets: Vec::new(),
            notes: vec!["release note".to_string()],
        })
        .expect_err("ONNX sidecars without graph should fail");

        assert!(err.to_string().contains(
            "ONNX metadata, exporter version, or external-data files require --onnx-model"
        ));
    }

    #[test]
    fn verify_hf_provenance_manifest_rejects_duplicate_onnx_external_data_paths() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let graph = dir.path().join("model.onnx");
        let sidecar = dir.path().join("weights.bin");
        fs::write(&graph, b"onnx").expect("write graph");
        fs::write(&sidecar, b"weights").expect("write sidecar");

        let onnx_export = Some(HfOnnxExportProvenance {
            exporter: "optimum-onnx".to_string(),
            exporter_version: None,
            graph: hf_file_commitment(&graph).expect("graph commitment"),
            metadata: None,
            external_data_files: vec![
                hf_file_commitment(&sidecar).expect("sidecar commitment"),
                hf_file_commitment(&sidecar).expect("sidecar commitment"),
            ],
        });
        let manifest = sample_hf_provenance_manifest_with_onnx_export(onnx_export);

        let err = verify_hf_provenance_manifest(&manifest)
            .expect_err("duplicate ONNX sidecar paths should fail");
        assert!(err
            .to_string()
            .contains("onnx_export.external_data_files[] reuses the same underlying HF artifact"));
    }

    #[test]
    fn verify_hf_provenance_manifest_rejects_duplicate_onnx_external_data_hard_links() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let graph = dir.path().join("model.onnx");
        let sidecar = dir.path().join("weights.bin");
        let aliased_sidecar = dir.path().join("weights-alias.bin");
        fs::write(&graph, b"onnx").expect("write graph");
        fs::write(&sidecar, b"weights").expect("write sidecar");
        fs::hard_link(&sidecar, &aliased_sidecar).expect("hard link sidecar alias");

        let onnx_export = Some(HfOnnxExportProvenance {
            exporter: "optimum-onnx".to_string(),
            exporter_version: None,
            graph: hf_file_commitment(&graph).expect("graph commitment"),
            metadata: None,
            external_data_files: vec![
                hf_file_commitment(&sidecar).expect("sidecar commitment"),
                hf_file_commitment(&aliased_sidecar).expect("aliased sidecar commitment"),
            ],
        });
        let manifest = sample_hf_provenance_manifest_with_onnx_export(onnx_export);

        let err = verify_hf_provenance_manifest(&manifest)
            .expect_err("hard-linked ONNX sidecar paths should fail");
        assert!(err
            .to_string()
            .contains("onnx_export.external_data_files[] reuses the same underlying HF artifact"));
    }

    #[test]
    fn verify_hf_provenance_manifest_rejects_onnx_metadata_path_reusing_graph() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let graph = dir.path().join("model.onnx");
        fs::write(&graph, b"onnx").expect("write graph");

        let graph_commitment = hf_file_commitment(&graph).expect("graph commitment");
        let manifest =
            sample_hf_provenance_manifest_with_onnx_export(Some(HfOnnxExportProvenance {
                exporter: "optimum-onnx".to_string(),
                exporter_version: None,
                graph: graph_commitment.clone(),
                metadata: Some(graph_commitment),
                external_data_files: Vec::new(),
            }));

        let err = verify_hf_provenance_manifest(&manifest)
            .expect_err("duplicate ONNX graph/metadata path should fail");
        assert!(err
            .to_string()
            .contains("onnx_export.metadata reuses the same underlying HF artifact"));
    }

    #[test]
    fn verify_hf_provenance_manifest_rejects_onnx_external_data_path_reusing_graph() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let graph = dir.path().join("model.onnx");
        fs::write(&graph, b"onnx").expect("write graph");

        let graph_commitment = hf_file_commitment(&graph).expect("graph commitment");
        let manifest =
            sample_hf_provenance_manifest_with_onnx_export(Some(HfOnnxExportProvenance {
                exporter: "optimum-onnx".to_string(),
                exporter_version: None,
                graph: graph_commitment.clone(),
                metadata: None,
                external_data_files: vec![graph_commitment],
            }));

        let err = verify_hf_provenance_manifest(&manifest)
            .expect_err("duplicate ONNX graph/external-data path should fail");
        assert!(err
            .to_string()
            .contains("onnx_export.external_data_files[] reuses the same underlying HF artifact"));
    }

    #[test]
    fn verify_hf_provenance_manifest_rejects_cross_role_duplicate_bound_paths() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let shared = dir.path().join("shared.json");
        fs::write(&shared, b"{\"shared\":true}").expect("write shared file");

        let tokenizer_json = hf_file_commitment(&shared).expect("tokenizer commitment");
        let mut manifest = sample_hf_provenance_manifest_with_onnx_export(None);
        manifest.tokenizer = HfTokenizerProvenance {
            tokenizer_id: "example/test-model".to_string(),
            tokenizer_revision: "0123456789abcdef".to_string(),
            tokenizer_json: Some(tokenizer_json.clone()),
            tokenizer_config: None,
            tokenization_transcript: None,
        };
        manifest.release = HfReleaseMetadata {
            model_card: Some(tokenizer_json),
            doi: None,
            datasets: Vec::new(),
            notes: vec!["release note".to_string()],
        };
        manifest.commitments.tokenizer_hash =
            hash_json_projection_hex(&manifest.tokenizer).expect("tokenizer hash");
        manifest.commitments.release_metadata_hash =
            hash_json_projection_hex(&manifest.release).expect("release hash");

        let err = verify_hf_provenance_manifest(&manifest)
            .expect_err("reused bound file across roles should fail");
        assert!(err
            .to_string()
            .contains("reuses the same underlying HF artifact"));
    }

    #[test]
    fn verify_hf_provenance_manifest_rejects_hub_binding_hash_drift() {
        let mut manifest = sample_hf_provenance_manifest_with_onnx_export(None);
        manifest.hub_revision = "fedcba9876543210".to_string();

        let err =
            verify_hf_provenance_manifest(&manifest).expect_err("hub binding drift should fail");
        assert!(err
            .to_string()
            .contains("hf hub_binding_hash commitment mismatch"));
    }

    #[test]
    fn verify_hf_provenance_manifest_rejects_empty_onnx_exporter_version() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let graph = dir.path().join("model.onnx");
        fs::write(&graph, b"onnx").expect("write graph");

        let manifest =
            sample_hf_provenance_manifest_with_onnx_export(Some(HfOnnxExportProvenance {
                exporter: "optimum-onnx".to_string(),
                exporter_version: Some(String::new()),
                graph: hf_file_commitment(&graph).expect("graph commitment"),
                metadata: None,
                external_data_files: Vec::new(),
            }));

        let err = verify_hf_provenance_manifest(&manifest)
            .expect_err("empty ONNX exporter version should fail");
        assert!(err
            .to_string()
            .contains("HF provenance onnx_export.exporter_version must be non-empty"));
    }

    #[test]
    fn verify_hf_provenance_manifest_rejects_sha256_drift() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let graph = dir.path().join("model.onnx");
        fs::write(&graph, b"onnx").expect("write graph");

        let mut commitment = hf_file_commitment(&graph).expect("graph commitment");
        commitment.sha256 = "0".repeat(64);
        let manifest =
            sample_hf_provenance_manifest_with_onnx_export(Some(HfOnnxExportProvenance {
                exporter: "optimum-onnx".to_string(),
                exporter_version: None,
                graph: commitment,
                metadata: None,
                external_data_files: Vec::new(),
            }));

        let err = verify_hf_provenance_manifest(&manifest)
            .expect_err("sha256 drift should fail verification");
        assert!(err
            .to_string()
            .contains("HF provenance onnx_export.graph sha256 commitment mismatch"));
    }
}

#[cfg(all(test, feature = "onnx-export"))]
mod tests {
    use super::*;

    #[test]
    fn trace_mismatch_policy_rejects_without_allow_flag() {
        let err = enforce_research_v2_trace_mismatch_policy(
            false,
            false,
            Some(7),
            Some("state_after mismatch at step 7"),
        )
        .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("research-v2-trace mismatch"));
        assert!(message.contains("Some(7)"));
        assert!(message.contains("state_after mismatch at step 7"));
    }

    #[test]
    fn trace_mismatch_policy_allows_with_allow_flag() {
        enforce_research_v2_trace_mismatch_policy(false, true, Some(3), Some("mismatch"))
            .expect("allow mismatch");
    }

    #[test]
    fn matrix_mismatch_policy_rejects_without_allow_flag() {
        let err = enforce_research_v2_matrix_mismatch_policy(2, false).unwrap_err();
        assert!(err
            .to_string()
            .contains("research-v2-matrix found 2 mismatched program(s)"));
    }

    #[test]
    fn matrix_mismatch_policy_allows_with_allow_flag() {
        enforce_research_v2_matrix_mismatch_policy(1, true).expect("allow mismatch");
    }

    #[test]
    fn default_matrix_suite_contains_neural_style_programs() {
        let suite = research_v2_default_program_suite();
        assert!(suite.contains(&PathBuf::from("programs/dot_product.tvm")));
        assert!(suite.contains(&PathBuf::from("programs/matmul_2x2.tvm")));
        assert!(suite.contains(&PathBuf::from("programs/single_neuron.tvm")));
    }

    #[test]
    fn frontend_runtime_registry_validation_rejects_missing_version() {
        let mut registry =
            read_repo_json_value(FRONTEND_RUNTIME_SEMANTICS_REGISTRY_PATH).expect("registry json");
        registry
            .as_object_mut()
            .expect("registry object")
            .remove("registry_version");
        let err = validate_frontend_runtime_semantics_registry(&registry).unwrap_err();
        assert!(err.to_string().contains("missing registry_version"));
    }

    #[test]
    fn frontend_runtime_registry_validation_rejects_lane_status_drift() {
        let mut registry =
            read_repo_json_value(FRONTEND_RUNTIME_SEMANTICS_REGISTRY_PATH).expect("registry json");
        let lanes = registry
            .get_mut("lanes")
            .and_then(serde_json::Value::as_array_mut)
            .expect("registry lanes");
        let torch_export = lanes
            .iter_mut()
            .find(|lane| {
                lane.get("lane_id").and_then(serde_json::Value::as_str) == Some("torch-export")
            })
            .expect("torch-export lane");
        torch_export["status"] = serde_json::Value::String("not_implemented".to_string());
        let err = validate_frontend_runtime_semantics_registry(&registry).unwrap_err();
        assert!(err.to_string().contains("torch-export status mismatch"));
    }

    #[test]
    fn frontend_runtime_registry_validation_rejects_watch_lane_promoted_to_implemented() {
        let mut registry =
            read_repo_json_value(FRONTEND_RUNTIME_SEMANTICS_REGISTRY_PATH).expect("registry json");
        let lanes = registry
            .get_mut("lanes")
            .and_then(serde_json::Value::as_array_mut)
            .expect("registry lanes");
        let torch_export = lanes
            .iter_mut()
            .find(|lane| {
                lane.get("lane_id").and_then(serde_json::Value::as_str) == Some("torch-export")
            })
            .expect("torch-export lane");
        torch_export["status"] = serde_json::Value::String("implemented".to_string());
        let err = validate_frontend_runtime_semantics_registry(&registry).unwrap_err();
        assert!(err
            .to_string()
            .contains("unexpected implemented lane torch-export"));
    }

    #[test]
    fn frontend_runtime_registry_validation_rejects_missing_required_lane() {
        let mut registry =
            read_repo_json_value(FRONTEND_RUNTIME_SEMANTICS_REGISTRY_PATH).expect("registry json");
        let lanes = registry
            .get_mut("lanes")
            .and_then(serde_json::Value::as_array_mut)
            .expect("registry lanes");
        let before_len = lanes.len();
        lanes
            .retain(|lane| lane.get("lane_id").and_then(serde_json::Value::as_str) != Some("vllm"));
        assert_eq!(lanes.len(), before_len - 1, "expected to remove vllm lane");
        let err = validate_frontend_runtime_semantics_registry(&registry).unwrap_err();
        assert!(err
            .to_string()
            .contains("frontend runtime semantics registry missing lane vllm"));
    }

    #[test]
    fn frontend_runtime_registry_validation_rejects_unknown_implemented_lane() {
        let mut registry =
            read_repo_json_value(FRONTEND_RUNTIME_SEMANTICS_REGISTRY_PATH).expect("registry json");
        registry
            .get_mut("lanes")
            .and_then(serde_json::Value::as_array_mut)
            .expect("registry lanes")
            .push(serde_json::json!({
                "lane_id": "surprise-runtime",
                "ecosystem": "surprise",
                "role": "unexpected implementation claim",
                "status": "implemented",
                "artifact_binding": "No artifact binding in research-v3-equivalence.",
                "claim_boundary": "This lane must not be claimed without an allowlist update."
            }));
        let err = validate_frontend_runtime_semantics_registry(&registry).unwrap_err();
        assert!(err
            .to_string()
            .contains("unexpected implemented lane surprise-runtime"));
    }

    #[test]
    fn frontend_runtime_registry_validation_rejects_duplicate_lane_id() {
        let mut registry =
            read_repo_json_value(FRONTEND_RUNTIME_SEMANTICS_REGISTRY_PATH).expect("registry json");
        let lanes = registry
            .get_mut("lanes")
            .and_then(serde_json::Value::as_array_mut)
            .expect("registry lanes");
        let duplicate_lane_id = "transformer-vm";
        let duplicate = lanes
            .iter()
            .find(|lane| {
                lane.get("lane_id").and_then(serde_json::Value::as_str) == Some(duplicate_lane_id)
            })
            .unwrap_or_else(|| panic!("missing {duplicate_lane_id} lane"))
            .clone();
        lanes.push(duplicate);
        let err = validate_frontend_runtime_semantics_registry(&registry).unwrap_err();
        assert!(err
            .to_string()
            .contains(&format!("duplicate lane_id {duplicate_lane_id}")));
    }

    #[test]
    #[cfg(feature = "burn-model")]
    fn research_v3_rule_witnesses_rejects_event_length_mismatch() {
        let state_before = MachineState::new(4);
        let mut state_after = state_before.clone();
        state_after.pc = 1;
        let reference_event = ExecutionTraceEntry {
            step: 1,
            layer_idx: None,
            instruction: llm_provable_computer::Instruction::Nop,
            state_before,
            state_after,
        };
        let peer_events = Vec::new();

        let err = research_v3_rule_witnesses(&[
            ("transformer", std::slice::from_ref(&reference_event)),
            ("native", peer_events.as_slice()),
        ])
        .unwrap_err();

        assert!(err
            .to_string()
            .contains("research-v3-equivalence event length mismatch"));
    }

    #[cfg(all(feature = "burn-model", feature = "onnx-export"))]
    fn research_v3_test_artifact_file(label: &str) -> tempfile::NamedTempFile {
        tempfile::Builder::new()
            .prefix(&format!("llm-provable-computer-{label}-"))
            .suffix(".json")
            .tempfile()
            .expect("create temp file")
    }

    #[cfg(all(feature = "burn-model", feature = "onnx-export"))]
    fn research_v3_test_hash() -> String {
        "0".repeat(64)
    }

    #[cfg(all(feature = "burn-model", feature = "onnx-export"))]
    fn sample_research_v3_equivalence_artifact() -> ResearchV3EquivalenceArtifact {
        let state_before = MachineState::with_memory(vec![0, 1, 2]);
        let mut state_after = state_before.clone();
        state_after.pc = 1;
        state_after.acc = 7;
        let state_before_hash = hash_json_hex(&state_before).expect("state before hash");
        let state_after_hash = hash_json_hex(&state_after).expect("state after hash");
        let instruction = "NOP".to_string();
        let canonical_transition_hash = research_v3_transition_relation_hash(
            1,
            &instruction,
            &state_before_hash,
            &state_after_hash,
        )
        .expect("transition hash");

        let registry =
            read_repo_json_value(FRONTEND_RUNTIME_SEMANTICS_REGISTRY_PATH).expect("registry json");
        validate_frontend_runtime_semantics_registry(&registry).expect("valid registry");
        let engine_names = ["transformer", "native", "burn", "onnx/tract"];
        let engines = engine_names
            .iter()
            .map(|engine_name| ResearchV3EngineSummary {
                name: (*engine_name).to_string(),
                steps: 1,
                halted: false,
                trace_len: 2,
                events_len: 1,
                trace: vec![state_before.clone(), state_after.clone()],
                canonical_events: vec![ResearchV3CanonicalEvent {
                    step: 1,
                    instruction: instruction.clone(),
                    state_before_hash: state_before_hash.clone(),
                    state_after_hash: state_after_hash.clone(),
                }],
                final_state: state_after.clone(),
                trace_hash: hash_json_hex(&vec![state_before.clone(), state_after.clone()])
                    .expect("trace hash"),
                event_relation_hash: hash_json_hex(&vec![ResearchV3CanonicalEvent {
                    step: 1,
                    instruction: instruction.clone(),
                    state_before_hash: state_before_hash.clone(),
                    state_after_hash: state_after_hash.clone(),
                }])
                .expect("event relation hash"),
                final_state_hash: hash_json_hex(&state_after).expect("final state hash"),
            })
            .collect::<Vec<_>>();
        let mut artifact = ResearchV3EquivalenceArtifact {
            statement_version: String::new(),
            semantic_scope: String::new(),
            relation_format: RESEARCH_V3_RELATION_FORMAT.to_string(),
            fixed_point_profile: String::new(),
            onnx_op_subset_version: String::new(),
            onnx_op_subset_size: 0,
            program_path: "programs/addition.tvm".to_string(),
            requested_max_steps: 1,
            checked_steps: 1,
            engines,
            rule_witnesses: vec![ResearchV3RuleWitness {
                step: 1,
                rule_id: research_v3_rule_id(&instruction),
                relation: "same-instruction-same-state-transition".to_string(),
                instruction,
                participating_engines: engine_names
                    .iter()
                    .map(|name| (*name).to_string())
                    .collect(),
                state_before_hashes: engine_names
                    .iter()
                    .map(|engine_name| ((*engine_name).to_string(), state_before_hash.clone()))
                    .collect(),
                state_after_hashes: engine_names
                    .iter()
                    .map(|engine_name| ((*engine_name).to_string(), state_after_hash.clone()))
                    .collect(),
                engine_transition_hashes: engine_names
                    .iter()
                    .map(|engine_name| {
                        (
                            (*engine_name).to_string(),
                            canonical_transition_hash.clone(),
                        )
                    })
                    .collect(),
                canonical_transition_hash,
                validation: ResearchV3RuleValidation {
                    differential_lockstep: true,
                    egraph_status: "not-attempted".to_string(),
                    smt_status: "not-attempted".to_string(),
                    randomized_testing_status: "not-attempted".to_string(),
                },
            }],
            frontend_runtime_semantics_registry: registry,
            limitations: research_v3_limitations(),
            commitments: ResearchV3EquivalenceCommitments {
                hash_function: String::new(),
                statement_spec_hash: String::new(),
                fixed_point_spec_hash: String::new(),
                onnx_op_subset_hash: String::new(),
                artifact_schema_hash: String::new(),
                frontend_runtime_semantics_registry_hash: String::new(),
                relation_format_hash: String::new(),
                limitations_hash: String::new(),
                program_hash: research_v3_test_hash(),
                transformer_config_hash: research_v3_test_hash(),
                onnx_metadata_hash: research_v3_test_hash(),
                engine_summaries_hash: String::new(),
                rule_witnesses_hash: String::new(),
            },
        };
        refresh_research_v3_test_artifact_commitments(&mut artifact);
        artifact
    }

    #[cfg(all(feature = "burn-model", feature = "onnx-export"))]
    fn refresh_research_v3_test_engine_summary(engine: &mut ResearchV3EngineSummary) {
        engine.trace_len = engine.trace.len();
        engine.events_len = engine.canonical_events.len();
        engine.final_state = engine
            .trace
            .last()
            .cloned()
            .expect("research-v3 engine trace must be non-empty");
        engine.trace_hash = hash_json_hex(&engine.trace).expect("trace hash");
        engine.event_relation_hash =
            hash_json_hex(&engine.canonical_events).expect("event relation hash");
        engine.final_state_hash = hash_json_hex(&engine.final_state).expect("final state hash");
    }

    #[cfg(all(feature = "burn-model", feature = "onnx-export"))]
    fn refresh_research_v3_test_artifact_commitments(artifact: &mut ResearchV3EquivalenceArtifact) {
        let bundle = load_research_v2_spec_bundle(
            STATEMENT_V3_EQUIVALENCE_SPEC_PATH,
            STATEMENT_V3_EQUIVALENCE_ARTIFACT_SCHEMA_PATH,
        )
        .expect("statement-v3 bundle");
        for engine in &mut artifact.engines {
            refresh_research_v3_test_engine_summary(engine);
        }
        artifact.statement_version = bundle.statement_version.clone();
        artifact.semantic_scope = bundle.semantic_scope.clone();
        artifact.fixed_point_profile = bundle.fixed_point_profile.clone();
        artifact.onnx_op_subset_version = bundle.onnx_op_subset_version.clone();
        artifact.onnx_op_subset_size = bundle.onnx_op_subset_size;
        artifact.commitments.hash_function = RESEARCH_V2_HASH_FUNCTION.to_string();
        artifact.commitments.statement_spec_hash = bundle.statement_spec_hash;
        artifact.commitments.fixed_point_spec_hash = bundle.fixed_point_spec_hash;
        artifact.commitments.onnx_op_subset_hash = bundle.onnx_op_subset_hash;
        artifact.commitments.artifact_schema_hash = bundle.artifact_schema_hash;
        artifact
            .commitments
            .frontend_runtime_semantics_registry_hash =
            hash_json_hex(&artifact.frontend_runtime_semantics_registry)
                .expect("registry commitment");
        artifact.commitments.relation_format_hash =
            hash_json_hex(&artifact.relation_format).expect("relation format commitment");
        artifact.commitments.limitations_hash =
            hash_json_hex(&artifact.limitations).expect("limitations commitment");
        artifact.commitments.engine_summaries_hash =
            hash_json_projection_hex(&artifact.engines).expect("engine summaries commitment");
        artifact.commitments.rule_witnesses_hash =
            hash_json_projection_hex(&artifact.rule_witnesses).expect("rule witnesses commitment");
    }

    #[cfg(all(feature = "burn-model", feature = "onnx-export"))]
    fn rename_research_v3_test_engine(
        artifact: &mut ResearchV3EquivalenceArtifact,
        from: &str,
        to: &str,
    ) {
        for engine in &mut artifact.engines {
            if engine.name == from {
                engine.name = to.to_string();
            }
        }
        for witness in &mut artifact.rule_witnesses {
            for engine_name in &mut witness.participating_engines {
                if engine_name == from {
                    *engine_name = to.to_string();
                }
            }
            for hashes in [
                &mut witness.state_before_hashes,
                &mut witness.state_after_hashes,
                &mut witness.engine_transition_hashes,
            ] {
                if let Some(value) = hashes.remove(from) {
                    hashes.insert(to.to_string(), value);
                }
            }
        }
    }

    #[cfg(all(feature = "burn-model", feature = "onnx-export"))]
    fn append_research_v3_test_terminal_noop_event(artifact: &mut ResearchV3EquivalenceArtifact) {
        for engine in &mut artifact.engines {
            let next_step = engine.canonical_events.len() + 1;
            let final_state_hash = hash_json_hex(&engine.final_state).expect("final state hash");
            let instruction = "NOP".to_string();
            engine.trace.push(engine.final_state.clone());
            engine.canonical_events.push(ResearchV3CanonicalEvent {
                step: next_step,
                instruction,
                state_before_hash: final_state_hash.clone(),
                state_after_hash: final_state_hash,
            });
        }
    }

    #[cfg(all(feature = "burn-model", feature = "onnx-export"))]
    fn write_research_v3_test_artifact(path: &Path, value: &serde_json::Value) {
        let bytes = serde_json::to_vec_pretty(value).expect("serialize artifact");
        fs::write(path, bytes).expect("write artifact");
    }

    #[test]
    #[cfg(all(feature = "burn-model", feature = "onnx-export"))]
    fn load_research_v3_equivalence_artifact_rejects_unknown_top_level_field() {
        let file = research_v3_test_artifact_file("research-v3-extra-top");
        let mut value =
            serde_json::to_value(sample_research_v3_equivalence_artifact()).expect("artifact json");
        value
            .as_object_mut()
            .expect("artifact object")
            .insert("unexpected_field".to_string(), serde_json::json!(true));
        write_research_v3_test_artifact(file.path(), &value);

        let err = load_research_v3_equivalence_artifact(file.path())
            .expect_err("unknown field should fail");
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    #[cfg(all(feature = "burn-model", feature = "onnx-export"))]
    fn load_research_v3_equivalence_artifact_rejects_unknown_nested_rule_witness_field() {
        let file = research_v3_test_artifact_file("research-v3-extra-witness");
        let mut value =
            serde_json::to_value(sample_research_v3_equivalence_artifact()).expect("artifact json");
        value["rule_witnesses"][0]["unexpected_field"] = serde_json::json!(7);
        write_research_v3_test_artifact(file.path(), &value);

        let err = load_research_v3_equivalence_artifact(file.path())
            .expect_err("unknown nested rule witness field should fail");
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    #[cfg(all(feature = "burn-model", feature = "onnx-export"))]
    fn load_research_v3_equivalence_artifact_rejects_oversized_file() {
        let file = research_v3_test_artifact_file("research-v3-oversized");
        fs::write(
            file.path(),
            vec![b'x'; MAX_RESEARCH_V3_EQUIVALENCE_ARTIFACT_JSON_BYTES + 1],
        )
        .expect("write oversized artifact");

        let err = load_research_v3_equivalence_artifact(file.path())
            .expect_err("oversized artifact should fail");
        assert!(err.to_string().contains("exceeding the limit"));
    }

    #[test]
    #[cfg(all(feature = "burn-model", feature = "onnx-export"))]
    fn load_research_v3_equivalence_artifact_reports_malformed_json_as_serialization() {
        let file = research_v3_test_artifact_file("research-v3-malformed");
        fs::write(file.path(), b"{").expect("write malformed artifact");

        let err = load_research_v3_equivalence_artifact(file.path())
            .expect_err("malformed artifact should fail");
        assert!(matches!(err, VmError::Serialization(_)));
        assert!(err
            .to_string()
            .contains("failed to parse research-v3 artifact"));
    }

    #[test]
    #[cfg(all(feature = "burn-model", feature = "onnx-export"))]
    fn load_research_v3_equivalence_artifact_rejects_non_regular_file() {
        let dir = tempfile::tempdir().expect("create temp dir");

        let err = load_research_v3_equivalence_artifact(dir.path())
            .expect_err("directory artifact path should fail");
        assert!(err.to_string().contains("not a regular file"));
    }

    #[test]
    #[cfg(all(feature = "burn-model", feature = "onnx-export"))]
    fn verify_research_v3_equivalence_artifact_rejects_unknown_engine_binding() {
        let mut artifact = sample_research_v3_equivalence_artifact();
        rename_research_v3_test_engine(&mut artifact, "onnx/tract", "experimental-onnx");
        refresh_research_v3_test_artifact_commitments(&mut artifact);

        let err = verify_research_v3_equivalence_artifact(&artifact)
            .expect_err("unknown engine binding should fail");
        assert!(err
            .to_string()
            .contains("is not bound to a pinned implemented lane"));
    }

    #[test]
    #[cfg(all(feature = "burn-model", feature = "onnx-export"))]
    fn verify_research_v3_equivalence_artifact_rejects_missing_pinned_engine() {
        let mut artifact = sample_research_v3_equivalence_artifact();
        artifact
            .engines
            .retain(|engine| engine.name != "onnx/tract");
        for witness in &mut artifact.rule_witnesses {
            witness
                .participating_engines
                .retain(|engine_name| engine_name != "onnx/tract");
            witness.state_before_hashes.remove("onnx/tract");
            witness.state_after_hashes.remove("onnx/tract");
            witness.engine_transition_hashes.remove("onnx/tract");
        }
        refresh_research_v3_test_artifact_commitments(&mut artifact);

        let err = verify_research_v3_equivalence_artifact(&artifact)
            .expect_err("missing pinned engine should fail");
        assert!(err
            .to_string()
            .contains("engine set does not match the pinned artifact boundary"));
    }

    #[test]
    #[cfg(all(feature = "burn-model", feature = "onnx-export"))]
    fn verify_research_v3_equivalence_artifact_rejects_extra_engine_events_beyond_checked_steps() {
        let mut artifact = sample_research_v3_equivalence_artifact();
        let expected_steps = artifact.checked_steps;
        append_research_v3_test_terminal_noop_event(&mut artifact);
        refresh_research_v3_test_artifact_commitments(&mut artifact);

        let err = verify_research_v3_equivalence_artifact(&artifact)
            .expect_err("extra engine events beyond checked_steps should fail");
        assert!(err.to_string().contains(&format!(
            "events_len {} does not match checked_steps {}",
            expected_steps + 1,
            expected_steps
        )));
    }

    #[test]
    fn atomic_write_replaces_existing_output() {
        let path = std::env::temp_dir().join(format!(
            "llm-provable-computer-atomic-write-replace-{}.json",
            std::process::id()
        ));
        fs::write(&path, b"old").expect("seed output");
        write_bytes_atomically(&path, b"new").expect("replace output");
        assert_eq!(fs::read(&path).expect("read replaced output"), b"new");
        let _ = fs::remove_file(path);
    }
}

#[cfg(test)]
mod cli_dispatch_tests {
    use super::needs_run_subcommand;

    #[test]
    fn intervalized_phase25_commands_do_not_fall_back_to_run_shorthand() {
        assert!(!needs_run_subcommand(
            "prove-stwo-intervalized-decoding-state-relation-demo"
        ));
        assert!(!needs_run_subcommand(
            "verify-stwo-intervalized-decoding-state-relation-demo"
        ));
        assert!(!needs_run_subcommand(
            "prove-stwo-folded-intervalized-decoding-state-relation-demo"
        ));
        assert!(!needs_run_subcommand(
            "verify-stwo-folded-intervalized-decoding-state-relation-demo"
        ));
        assert!(!needs_run_subcommand(
            "prove-stwo-chained-folded-intervalized-decoding-state-relation-demo"
        ));
        assert!(!needs_run_subcommand(
            "verify-stwo-chained-folded-intervalized-decoding-state-relation-demo"
        ));
        assert!(!needs_run_subcommand(
            "prove-stwo-aggregated-chained-folded-intervalized-decoding-state-relation-demo"
        ));
        assert!(!needs_run_subcommand(
            "verify-stwo-aggregated-chained-folded-intervalized-decoding-state-relation-demo"
        ));
        assert!(!needs_run_subcommand(
            "prepare-stwo-recursive-compression-input-contract"
        ));
        assert!(!needs_run_subcommand(
            "verify-stwo-recursive-compression-input-contract"
        ));
    }
}

fn compile_model(
    program: &Path,
    layers: usize,
    attention_mode: Attention2DMode,
) -> llm_provable_computer::Result<TransformerVm> {
    let source = fs::read_to_string(program).map_err(|io_error| {
        VmError::InvalidConfig(format!(
            "failed to read program {}: {io_error}",
            program.display()
        ))
    })?;

    let config = TransformerVmConfig {
        num_layers: layers,
        attention_mode,
        ..TransformerVmConfig::default()
    };
    ProgramCompiler.compile_source(&source, config)
}

fn load_runtime(
    program: &Path,
    max_steps: usize,
    layers: usize,
    attention_mode: Attention2DMode,
) -> llm_provable_computer::Result<ExecutionRuntime> {
    Ok(ExecutionRuntime::new(
        compile_model(program, layers, attention_mode)?,
        max_steps,
    ))
}

fn execute_engine(
    model: &TransformerVm,
    engine: CliExecutionEngine,
    max_steps: usize,
) -> llm_provable_computer::Result<EngineRunOutput> {
    match engine {
        CliExecutionEngine::Transformer => {
            let mut runtime = ExecutionRuntime::new(model.clone(), max_steps);
            let result = runtime.run()?;
            Ok(EngineRunOutput {
                result,
                trace: runtime.trace().to_vec(),
                events: runtime.events().to_vec(),
            })
        }
        CliExecutionEngine::Native => {
            let mut runtime = NativeInterpreter::new(
                model.program().clone(),
                model.config().attention_mode.clone(),
                max_steps,
            );
            let result = runtime.run()?;
            Ok(EngineRunOutput {
                result,
                trace: runtime.trace().to_vec(),
                events: runtime.events().to_vec(),
            })
        }
        CliExecutionEngine::Burn => execute_burn_engine(model, max_steps),
        CliExecutionEngine::Onnx => execute_onnx_engine(model, max_steps),
    }
}

#[cfg(feature = "burn-model")]
fn execute_burn_engine(
    model: &TransformerVm,
    max_steps: usize,
) -> llm_provable_computer::Result<EngineRunOutput> {
    let device = Default::default();
    let burn_model = BurnTransformerVm::<CliBurnBackend>::from_compiled(model, &device)?;
    let mut runtime = BurnExecutionRuntime::new(burn_model, device, max_steps);
    let result = runtime.run()?;
    Ok(EngineRunOutput {
        result,
        trace: runtime.trace().to_vec(),
        events: runtime.events().to_vec(),
    })
}

#[cfg(not(feature = "burn-model"))]
fn execute_burn_engine(
    _model: &TransformerVm,
    _max_steps: usize,
) -> llm_provable_computer::Result<EngineRunOutput> {
    Err(feature_required_error("engine `burn`", &["burn-model"]))
}

#[cfg(feature = "onnx-export")]
fn execute_onnx_engine(
    model: &TransformerVm,
    max_steps: usize,
) -> llm_provable_computer::Result<EngineRunOutput> {
    let export_dir = ScopedTempDir::new("run-onnx")?;
    export_program_onnx(model, export_dir.path())?;
    let mut runtime = OnnxExecutionRuntime::from_export_dir(export_dir.path(), max_steps)?;
    let result = runtime.run()?;
    Ok(EngineRunOutput {
        result,
        trace: runtime.trace().to_vec(),
        events: runtime.events().to_vec(),
    })
}

#[cfg(not(feature = "onnx-export"))]
fn execute_onnx_engine(
    _model: &TransformerVm,
    _max_steps: usize,
) -> llm_provable_computer::Result<EngineRunOutput> {
    Err(feature_required_error("engine `onnx`", &["onnx-export"]))
}

fn verify_burn_engines(
    model: &TransformerVm,
    max_steps: usize,
) -> llm_provable_computer::Result<llm_provable_computer::VerificationResult> {
    verify_burn_engines_impl(model, max_steps)
}

#[cfg(feature = "burn-model")]
fn verify_burn_engines_impl(
    model: &TransformerVm,
    max_steps: usize,
) -> llm_provable_computer::Result<llm_provable_computer::VerificationResult> {
    let device = Default::default();
    let burn_model = BurnTransformerVm::<CliBurnBackend>::from_compiled(model, &device)?;
    let mut transformer = ExecutionRuntime::new(model.clone(), max_steps);
    let mut native = NativeInterpreter::new(
        model.program().clone(),
        model.config().attention_mode.clone(),
        max_steps,
    );
    let mut burn = BurnExecutionRuntime::new(burn_model, device, max_steps);
    verify_engines(&mut [&mut transformer, &mut native, &mut burn])
}

#[cfg(not(feature = "burn-model"))]
fn verify_burn_engines_impl(
    _model: &TransformerVm,
    _max_steps: usize,
) -> llm_provable_computer::Result<llm_provable_computer::VerificationResult> {
    Err(feature_required_error("`--verify-burn`", &["burn-model"]))
}

fn verify_onnx_engines(
    model: &TransformerVm,
    max_steps: usize,
) -> llm_provable_computer::Result<llm_provable_computer::VerificationResult> {
    verify_onnx_engines_impl(model, max_steps)
}

#[cfg(feature = "onnx-export")]
fn verify_onnx_engines_impl(
    model: &TransformerVm,
    max_steps: usize,
) -> llm_provable_computer::Result<llm_provable_computer::VerificationResult> {
    let export_dir = ScopedTempDir::new("verify-onnx")?;
    export_program_onnx(model, export_dir.path())?;
    let mut transformer = ExecutionRuntime::new(model.clone(), max_steps);
    let mut native = NativeInterpreter::new(
        model.program().clone(),
        model.config().attention_mode.clone(),
        max_steps,
    );
    let mut onnx = OnnxExecutionRuntime::from_export_dir(export_dir.path(), max_steps)?;
    verify_engines(&mut [&mut transformer, &mut native, &mut onnx])
}

#[cfg(not(feature = "onnx-export"))]
fn verify_onnx_engines_impl(
    _model: &TransformerVm,
    _max_steps: usize,
) -> llm_provable_computer::Result<llm_provable_computer::VerificationResult> {
    Err(feature_required_error("`--verify-onnx`", &["onnx-export"]))
}

fn verify_all_engines(
    model: &TransformerVm,
    max_steps: usize,
) -> llm_provable_computer::Result<llm_provable_computer::VerificationResult> {
    verify_all_engines_impl(model, max_steps)
}

#[cfg(all(feature = "burn-model", feature = "onnx-export"))]
fn verify_all_engines_impl(
    model: &TransformerVm,
    max_steps: usize,
) -> llm_provable_computer::Result<llm_provable_computer::VerificationResult> {
    let device = Default::default();
    let export_dir = ScopedTempDir::new("verify-all")?;
    export_program_onnx(model, export_dir.path())?;
    let burn_model = BurnTransformerVm::<CliBurnBackend>::from_compiled(model, &device)?;

    let mut transformer = ExecutionRuntime::new(model.clone(), max_steps);
    let mut native = NativeInterpreter::new(
        model.program().clone(),
        model.config().attention_mode.clone(),
        max_steps,
    );
    let mut burn = BurnExecutionRuntime::new(burn_model, device, max_steps);
    let mut onnx = OnnxExecutionRuntime::from_export_dir(export_dir.path(), max_steps)?;
    verify_engines(&mut [&mut transformer, &mut native, &mut burn, &mut onnx])
}

#[cfg(not(all(feature = "burn-model", feature = "onnx-export")))]
fn verify_all_engines_impl(
    _model: &TransformerVm,
    _max_steps: usize,
) -> llm_provable_computer::Result<llm_provable_computer::VerificationResult> {
    Err(feature_required_error(
        "`--verify-all`",
        &["burn-model", "onnx-export"],
    ))
}

#[cfg(feature = "onnx-export")]
fn export_onnx_command_impl(
    program: &Path,
    output_dir: &Path,
    model: &TransformerVm,
) -> llm_provable_computer::Result<()> {
    let metadata = export_program_onnx(model, output_dir)?;

    println!("program: {}", program.display());
    println!("output_dir: {}", output_dir.display());
    println!("instructions: {}", metadata.instructions.len());
    println!("layers: {}", metadata.config.num_layers);
    println!("attention_mode: {}", metadata.config.attention_mode);
    println!("onnx_ir_version: {}", metadata.ir_version);
    println!("onnx_opset_version: {}", metadata.opset_version);
    println!("metadata: {}", output_dir.join("metadata.json").display());

    Ok(())
}

#[cfg(not(feature = "onnx-export"))]
fn export_onnx_command_impl(
    _program: &Path,
    _output_dir: &Path,
    _model: &TransformerVm,
) -> llm_provable_computer::Result<()> {
    Err(feature_required_error("`export-onnx`", &["onnx-export"]))
}

fn print_execution_summary(
    program: &Path,
    engine: CliExecutionEngine,
    model: &TransformerVm,
    result: &ExecutionResult,
) {
    println!("program: {}", program.display());
    println!("engine: {engine}");
    println!("steps: {}", result.steps);
    println!("halted: {}", result.halted);
    println!("pc: {}", result.final_state.pc);
    println!("sp: {}", result.final_state.sp);
    println!("acc: {}", result.final_state.acc);
    println!("zero_flag: {}", result.final_state.zero_flag);
    println!("carry_flag: {}", result.final_state.carry_flag);
    println!("memory: {:?}", result.final_state.memory);
    println!("layers: {}", model.config().num_layers);
    println!("attention_mode: {}", model.config().attention_mode);
    println!("elapsed_ms: {:.3}", result.elapsed.as_secs_f64() * 1000.0);
    println!("throughput_steps_per_sec: {:.2}", result.tokens_per_sec);
}

fn print_verification_summary(
    status_key: &str,
    prefix: &str,
    checked_steps: &str,
    engines: &[llm_provable_computer::VerifiedEngine],
) {
    println!("{status_key}: true");
    println!("{prefix}_steps: {checked_steps}");
    println!(
        "{prefix}_engines: {}",
        engines
            .iter()
            .map(|engine| normalize_engine_name(&engine.name))
            .collect::<Vec<_>>()
            .join(",")
    );
}

fn print_trace(trace: &[MachineState], events: &[ExecutionTraceEntry]) {
    if let Some(initial) = trace.first() {
        println!(
            "trace[000] init pc={} sp={} acc={} zero={} carry={} halted={} memory={:?}",
            initial.pc,
            initial.sp,
            initial.acc,
            initial.zero_flag,
            initial.carry_flag,
            initial.halted,
            initial.memory
        );
    }

    for event in events {
        println!(
            "trace[{step:03}] layer={layer} instr=\"{instr}\" pc={pc} sp={sp} acc={acc} zero={zero} carry={carry} halted={halted} memory={memory:?}",
            step = event.step,
            layer = event.layer_idx.unwrap_or(0),
            instr = event.instruction,
            pc = event.state_after.pc,
            sp = event.state_after.sp,
            acc = event.state_after.acc,
            zero = event.state_after.zero_flag,
            carry = event.state_after.carry_flag,
            halted = event.state_after.halted,
            memory = event.state_after.memory
        );
    }
}

fn normalize_args<I>(args: I) -> Vec<OsString>
where
    I: IntoIterator<Item = OsString>,
{
    let mut args = args.into_iter().collect::<Vec<_>>();
    let should_insert_run = args
        .get(1)
        .and_then(|arg| arg.to_str())
        .map(needs_run_subcommand)
        .unwrap_or(false);

    if should_insert_run {
        args.insert(1, OsString::from("run"));
    }

    args
}

fn needs_run_subcommand(first_arg: &str) -> bool {
    !first_arg.starts_with('-')
        && !matches!(
            first_arg,
            "run"
                | "tui"
                | "export-onnx"
                | "prove-stark"
                | "verify-stark"
                | "prove-stwo-lookup-demo"
                | "verify-stwo-lookup-demo"
                | "prove-stwo-normalization-demo"
                | "verify-stwo-normalization-demo"
                | "prove-stwo-shared-lookup-demo"
                | "verify-stwo-shared-lookup-demo"
                | "prove-stwo-shared-normalization-demo"
                | "verify-stwo-shared-normalization-demo"
                | "prove-stwo-decoding-demo"
                | "verify-stwo-decoding-demo"
                | "prove-stwo-decoding-family-demo"
                | "verify-stwo-decoding-family-demo"
                | "prepare-stwo-shared-lookup-artifact"
                | "verify-stwo-shared-lookup-artifact"
                | "prepare-stwo-decoding-step-envelope-manifest"
                | "verify-stwo-decoding-step-envelope-manifest"
                | "prove-stwo-decoding-layout-matrix-demo"
                | "verify-stwo-decoding-layout-matrix-demo"
                | "prove-stwo-decoding-chunked-history-demo"
                | "verify-stwo-decoding-chunked-history-demo"
                | "prove-stwo-decoding-history-segments-demo"
                | "verify-stwo-decoding-history-segments-demo"
                | "prove-stwo-decoding-history-rollup-demo"
                | "verify-stwo-decoding-history-rollup-demo"
                | "prove-stwo-decoding-history-rollup-matrix-demo"
                | "verify-stwo-decoding-history-rollup-matrix-demo"
                | "prove-stwo-decoding-matrix-accumulator-demo"
                | "verify-stwo-decoding-matrix-accumulator-demo"
                | "prove-stwo-decoding-lookup-accumulator-demo"
                | "verify-stwo-decoding-lookup-accumulator-demo"
                | "prove-stwo-decoding-cross-step-lookup-accumulator-demo"
                | "verify-stwo-decoding-cross-step-lookup-accumulator-demo"
                | "prove-stwo-decoding-state-relation-accumulator-demo"
                | "verify-stwo-decoding-state-relation-accumulator-demo"
                | "prove-stwo-intervalized-decoding-state-relation-demo"
                | "verify-stwo-intervalized-decoding-state-relation-demo"
                | "prove-stwo-folded-intervalized-decoding-state-relation-demo"
                | "verify-stwo-folded-intervalized-decoding-state-relation-demo"
                | "prove-stwo-chained-folded-intervalized-decoding-state-relation-demo"
                | "verify-stwo-chained-folded-intervalized-decoding-state-relation-demo"
                | "prove-stwo-aggregated-chained-folded-intervalized-decoding-state-relation-demo"
                | "verify-stwo-aggregated-chained-folded-intervalized-decoding-state-relation-demo"
                | "prepare-stwo-recursive-compression-input-contract"
                | "verify-stwo-recursive-compression-input-contract"
                | "prepare-stwo-recursion-batch"
                | "research-v2-step"
                | "research-v2-trace"
                | "research-v2-matrix"
                | "research-v3-equivalence"
                | "verify-research-v3-equivalence"
                | "prepare-hf-provenance-manifest"
                | "verify-hf-provenance-manifest"
                | "help"
        )
}

fn print_stwo_normalization_companion(proof: &VanillaStarkExecutionProof) {
    if let Some(auxiliary) = &proof.stwo_auxiliary {
        if let Some(companion) = &auxiliary.normalization_companion {
            println!(
                "stwo_normalization_companion_scope: {}",
                companion.semantic_scope
            );
            println!(
                "stwo_normalization_companion_norm_sq_index: {}",
                companion.norm_sq_memory_index
            );
            println!(
                "stwo_normalization_companion_inv_sqrt_index: {}",
                companion.inv_sqrt_q8_memory_index
            );
            println!(
                "stwo_normalization_companion_expected_row: ({}, {})",
                companion.expected_norm_sq, companion.expected_inv_sqrt_q8
            );
        }
    }
}

fn parse_attention_mode(input: &str) -> Result<Attention2DMode, String> {
    Attention2DMode::from_str(input)
}

fn parse_execution_engine(input: &str) -> Result<CliExecutionEngine, String> {
    let normalized = input.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "native" => Ok(CliExecutionEngine::Native),
        "transformer" => Ok(CliExecutionEngine::Transformer),
        "burn" => Ok(CliExecutionEngine::Burn),
        "onnx" | "onnx-tract" | "onnx/tract" => Ok(CliExecutionEngine::Onnx),
        _ => Err(format!(
            "unknown execution engine `{input}`; expected native, transformer, burn, or onnx"
        )),
    }
}

fn normalize_engine_name(name: &str) -> String {
    match name {
        "onnx/tract" => "onnx".to_string(),
        other => other.to_string(),
    }
}

#[cfg(not(all(feature = "burn-model", feature = "onnx-export")))]
fn feature_required_error(subject: &str, features: &[&str]) -> VmError {
    VmError::InvalidConfig(format!(
        "{subject} requires {}",
        required_features_message(features)
    ))
}

#[cfg(not(all(feature = "burn-model", feature = "onnx-export")))]
fn required_features_message(features: &[&str]) -> String {
    if features.len() == 1 {
        format!("the `{}` feature", features[0])
    } else {
        let joined = features
            .iter()
            .map(|feature| format!("`{feature}`"))
            .collect::<Vec<_>>()
            .join(" and ");
        format!("the {joined} features")
    }
}
