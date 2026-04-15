use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fs;
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};

use crate::assembly::parse_program;
use crate::compiler::ProgramCompiler;
use crate::config::{Attention2DMode, TransformerVmConfig};
use crate::error::{Result, VmError};
use crate::instruction::{Instruction, Program};
use crate::interpreter::NativeInterpreter;
use crate::proof::{
    production_v1_stark_options, prove_execution_stark_with_backend_and_options,
    verify_execution_stark, StarkProofBackend, VanillaStarkExecutionProof, CLAIM_SEMANTIC_SCOPE_V1,
};
use crate::stwo_backend::{
    arithmetic_subset_prover::{
        phase12_shared_lookup_artifact_from_proof_payload,
        phase12_shared_lookup_rows_from_proof_payload,
    },
    commit_phase12_shared_lookup_rows, verify_phase12_shared_lookup_artifact,
    Phase12SharedLookupArtifact, STWO_BACKEND_VERSION_PHASE11,
};

pub const STWO_DECODING_CHAIN_VERSION_PHASE11: &str = "stwo-phase11-decoding-chain-v1";
pub const STWO_DECODING_CHAIN_SCOPE_PHASE11: &str = "stwo_execution_proof_carrying_decoding_chain";
pub const STWO_DECODING_STATE_VERSION_PHASE11: &str = "stwo-decoding-state-v1";
pub const STWO_DECODING_CHAIN_VERSION_PHASE12: &str = "stwo-phase12-decoding-chain-v9";
pub const STWO_DECODING_CHAIN_SCOPE_PHASE12: &str =
    "stwo_execution_parameterized_proof_carrying_decoding_chain";
pub const STWO_DECODING_STATE_VERSION_PHASE12: &str = "stwo-decoding-state-v11";
pub const STWO_DECODING_LAYOUT_VERSION_PHASE12: &str = "stwo-decoding-layout-v1";
pub const STWO_DECODING_LAYOUT_MATRIX_VERSION_PHASE13: &str =
    "stwo-phase13-decoding-layout-matrix-v9";
pub const STWO_DECODING_LAYOUT_MATRIX_SCOPE_PHASE13: &str =
    "stwo_execution_parameterized_proof_carrying_decoding_layout_matrix";
pub const STWO_DECODING_CHAIN_VERSION_PHASE14: &str =
    "stwo-phase14-decoding-chunked-history-chain-v9";
pub const STWO_DECODING_CHAIN_SCOPE_PHASE14: &str =
    "stwo_execution_parameterized_proof_carrying_decoding_chunked_history_chain";
pub const STWO_DECODING_STATE_VERSION_PHASE14: &str = "stwo-decoding-state-v6";
pub const STWO_DECODING_SEGMENT_BUNDLE_VERSION_PHASE15: &str =
    "stwo-phase15-decoding-history-segment-bundle-v9";
pub const STWO_DECODING_SEGMENT_BUNDLE_SCOPE_PHASE15: &str =
    "stwo_execution_parameterized_proof_carrying_decoding_history_segment_bundle";
pub const STWO_DECODING_SEGMENT_ROLLUP_VERSION_PHASE16: &str =
    "stwo-phase16-decoding-history-segment-rollup-v9";
pub const STWO_DECODING_SEGMENT_ROLLUP_SCOPE_PHASE16: &str =
    "stwo_execution_parameterized_proof_carrying_decoding_history_segment_rollup";
pub const STWO_DECODING_ROLLUP_MATRIX_VERSION_PHASE17: &str =
    "stwo-phase17-decoding-history-rollup-matrix-v9";
pub const STWO_DECODING_ROLLUP_MATRIX_SCOPE_PHASE17: &str =
    "stwo_execution_parameterized_proof_carrying_decoding_history_rollup_matrix";
pub const STWO_DECODING_MATRIX_ACCUMULATOR_VERSION_PHASE21: &str =
    "stwo-phase21-decoding-matrix-accumulator-v1";
pub const STWO_DECODING_MATRIX_ACCUMULATOR_SCOPE_PHASE21: &str =
    "stwo_execution_parameterized_proof_carrying_decoding_matrix_accumulator";
pub const STWO_DECODING_LOOKUP_ACCUMULATOR_VERSION_PHASE22: &str =
    "stwo-phase22-decoding-lookup-accumulator-v1";
pub const STWO_DECODING_LOOKUP_ACCUMULATOR_SCOPE_PHASE22: &str =
    "stwo_execution_parameterized_proof_carrying_decoding_lookup_accumulator";
pub const STWO_DECODING_CROSS_STEP_LOOKUP_ACCUMULATOR_VERSION_PHASE23: &str =
    "stwo-phase23-decoding-cross-step-lookup-accumulator-v1";
pub const STWO_DECODING_CROSS_STEP_LOOKUP_ACCUMULATOR_SCOPE_PHASE23: &str =
    "stwo_execution_parameterized_proof_carrying_decoding_cross_step_lookup_accumulator";
pub const STWO_DECODING_STATE_RELATION_ACCUMULATOR_VERSION_PHASE24: &str =
    "stwo-phase24-decoding-state-relation-accumulator-v1";
pub const STWO_DECODING_STATE_RELATION_ACCUMULATOR_SCOPE_PHASE24: &str =
    "stwo_execution_parameterized_proof_carrying_decoding_state_relation_accumulator";
pub const STWO_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE25: &str =
    "stwo-phase25-intervalized-decoding-state-relation-v1";
pub const STWO_INTERVALIZED_DECODING_STATE_RELATION_SCOPE_PHASE25: &str =
    "stwo_execution_parameterized_intervalized_proof_carrying_decoding_state_relation";
pub const STWO_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE26: &str =
    "stwo-phase26-folded-intervalized-decoding-state-relation-v1";
pub const STWO_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_SCOPE_PHASE26: &str =
    "stwo_execution_parameterized_folded_intervalized_proof_carrying_decoding_state_relation";
pub const STWO_CHAINED_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE27: &str =
    "stwo-phase27-chained-folded-intervalized-decoding-state-relation-v1";
pub const STWO_CHAINED_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_SCOPE_PHASE27: &str =
    "stwo_execution_parameterized_chained_folded_intervalized_proof_carrying_decoding_state_relation";
pub const STWO_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE28:
    &str = "stwo-phase28-aggregated-chained-folded-intervalized-decoding-state-relation-v1";
pub const STWO_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_SCOPE_PHASE28:
    &str = "stwo_execution_parameterized_aggregated_chained_folded_intervalized_proof_carrying_decoding_state_relation";
pub const STWO_PHASE28_RECURSION_POSTURE_PRE_RECURSIVE: &str =
    "pre-recursive-proof-carrying-aggregation";
pub const STWO_DECODING_STEP_ENVELOPE_VERSION_PHASE30: &str =
    "stwo-phase30-decoding-step-proof-envelope-v1";
pub const STWO_DECODING_STEP_ENVELOPE_SCOPE_PHASE30: &str =
    "stwo_execution_parameterized_decoding_step_proof_envelope";
pub const STWO_DECODING_STEP_ENVELOPE_MANIFEST_VERSION_PHASE30: &str =
    "stwo-phase30-decoding-step-proof-envelope-manifest-v1";
pub const STWO_DECODING_STEP_ENVELOPE_MANIFEST_SCOPE_PHASE30: &str =
    "stwo_execution_parameterized_decoding_step_proof_envelope_manifest";
pub const STWO_DECODING_STEP_ENVELOPE_RELATION_PHASE30: &str = "decoding_step_v2";
const DECODING_KV_CACHE_RANGE: std::ops::Range<usize> = 0..6;
const DECODING_OUTPUT_RANGE: std::ops::Range<usize> = 10..13;
const DECODING_POSITION_INDEX: usize = 21;
const PHASE12_OUTPUT_WIDTH: usize = 3;
const PHASE12_SHARED_LOOKUP_ROWS: usize = 8;
const PHASE12_LOOKUP_ROW_VALUES: [i16; PHASE12_SHARED_LOOKUP_ROWS] = [16, 64, 1, 1, 4, 128, 0, 1];
const PHASE14_HISTORY_CHUNK_PAIRS: usize = 2;
const PHASE15_SEGMENT_STEP_LIMIT: usize = 2;
const PHASE16_ROLLUP_SEGMENT_LIMIT: usize = 2;
const MAX_DECODING_CHAIN_STEPS: usize = 4096;
const MAX_DECODING_SHARED_LOOKUP_ARTIFACTS: usize = 4096;
pub(crate) const MAX_DECODING_PROOF_PAYLOAD_BYTES: usize = 2 * 1024 * 1024;
pub(crate) const MAX_SHARED_LOOKUP_ENVELOPE_PROOF_BYTES: usize = 512 * 1024;
// Sized from the shipped decoding demos plus bounded headroom; regression tests below lock this.
const MAX_PHASE11_DECODING_CHAIN_JSON_BYTES: usize = 6 * 1024 * 1024;
const MAX_PHASE12_DECODING_CHAIN_JSON_BYTES: usize = 12 * 1024 * 1024;
const MAX_PHASE14_DECODING_CHAIN_JSON_BYTES: usize = 16 * 1024 * 1024;
const MAX_PHASE15_SEGMENT_BUNDLE_JSON_BYTES: usize = 12 * 1024 * 1024;
const MAX_PHASE16_SEGMENT_ROLLUP_JSON_BYTES: usize = 12 * 1024 * 1024;
const MAX_PHASE17_ROLLUP_MATRIX_JSON_BYTES: usize = 40 * 1024 * 1024;
const MAX_PHASE21_MATRIX_ACCUMULATOR_JSON_BYTES: usize = 96 * 1024 * 1024;
const MAX_PHASE22_LOOKUP_ACCUMULATOR_JSON_BYTES: usize = 96 * 1024 * 1024;
const MAX_PHASE23_CROSS_STEP_LOOKUP_ACCUMULATOR_JSON_BYTES: usize = 128 * 1024 * 1024;
const MAX_PHASE24_STATE_RELATION_ACCUMULATOR_JSON_BYTES: usize = 160 * 1024 * 1024;
const MAX_PHASE25_INTERVALIZED_STATE_RELATION_JSON_BYTES: usize = 192 * 1024 * 1024;
const MAX_PHASE26_FOLDED_INTERVALIZED_STATE_RELATION_JSON_BYTES: usize = 224 * 1024 * 1024;
const MAX_PHASE27_CHAINED_FOLDED_INTERVALIZED_STATE_RELATION_JSON_BYTES: usize = 256 * 1024 * 1024;
const MAX_PHASE28_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_STATE_RELATION_JSON_BYTES: usize =
    512 * 1024 * 1024;
const MAX_PHASE30_DECODING_STEP_ENVELOPE_MANIFEST_JSON_BYTES: usize = 8 * 1024 * 1024;
const MAX_PHASE13_LAYOUT_MATRIX_JSON_BYTES: usize = 24 * 1024 * 1024;
const MAX_PHASE21_ACCUMULATOR_MATRICES: usize = 512;
const MAX_PHASE22_ACCUMULATOR_ROLLUPS: usize = 262_144;
const MAX_PHASE23_ACCUMULATOR_MEMBERS: usize = 512;
const MAX_PHASE23_ACCUMULATOR_ROLLUPS: usize = 1_048_576;
const MAX_PHASE24_ACCUMULATOR_MEMBERS: usize = 512;
const MAX_PHASE24_ACCUMULATOR_ROLLUPS: usize = 1_048_576;
const MAX_PHASE24_TOTAL_NESTED_PHASE23_MEMBERS: usize = 4_096;
const MAX_PHASE25_INTERVALIZED_MEMBERS: usize = 512;
const MAX_PHASE25_INTERVALIZED_ROLLUPS: usize = 1_048_576;
const MAX_PHASE26_FOLDED_INTERVALIZED_MEMBERS: usize = 512;
const MAX_PHASE26_FOLDED_INTERVALIZED_ROLLUPS: usize = 1_048_576;
const MAX_PHASE27_CHAINED_FOLDED_INTERVALIZED_MEMBERS: usize = 512;
const MAX_PHASE27_CHAINED_FOLDED_INTERVALIZED_ROLLUPS: usize = 4_194_304;
const MAX_PHASE27_TOTAL_NESTED_PHASE25_MEMBERS: usize = 4_096;
const MAX_PHASE28_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_MEMBERS: usize = 128;
const MAX_PHASE28_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_ROLLUPS: usize = 8_388_608;
const MAX_PHASE28_TOTAL_NESTED_PHASE26_MEMBERS: usize = 8_192;
const MAX_PHASE28_TOTAL_NESTED_PHASE25_MEMBERS: usize = 16_384;
const MAX_PHASE28_RECURSION_POSTURE_BYTES: usize = 128;

fn default_phase28_recursion_posture() -> String {
    STWO_PHASE28_RECURSION_POSTURE_PRE_RECURSIVE.to_string()
}

fn validate_phase28_recursion_posture_string<E>(value: &str) -> std::result::Result<(), E>
where
    E: serde::de::Error,
{
    if value.len() > MAX_PHASE28_RECURSION_POSTURE_BYTES {
        return Err(E::custom(format!(
            "aggregated chained folded intervalized decoding state relation recursion_posture_len={} exceeds the supported maximum {}",
            value.len(),
            MAX_PHASE28_RECURSION_POSTURE_BYTES
        )));
    }
    Ok(())
}

fn deserialize_phase28_recursion_posture<'de, D>(
    deserializer: D,
) -> std::result::Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Phase28RecursionPostureVisitor;

    impl<'de> serde::de::Visitor<'de> for Phase28RecursionPostureVisitor {
        type Value = String;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a bounded Phase 28 recursion posture string")
        }

        fn visit_borrowed_str<E>(self, value: &'de str) -> std::result::Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            validate_phase28_recursion_posture_string::<E>(value)?;
            Ok(value.to_string())
        }

        fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            validate_phase28_recursion_posture_string::<E>(value)?;
            Ok(value.to_string())
        }

        fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            validate_phase28_recursion_posture_string::<E>(&value)?;
            Ok(value)
        }
    }

    deserializer.deserialize_str(Phase28RecursionPostureVisitor)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Phase11DecodingState {
    pub state_version: String,
    pub step_index: usize,
    pub position: i16,
    pub kv_cache_commitment: String,
    pub output_commitment: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Phase11DecodingStep {
    pub from_state: Phase11DecodingState,
    pub to_state: Phase11DecodingState,
    pub proof: VanillaStarkExecutionProof,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Phase11DecodingChainManifest {
    pub proof_backend: StarkProofBackend,
    pub chain_version: String,
    pub semantic_scope: String,
    pub proof_backend_version: String,
    pub statement_version: String,
    pub total_steps: usize,
    pub steps: Vec<Phase11DecodingStep>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Phase12DecodingLayout {
    pub layout_version: String,
    pub rolling_kv_pairs: usize,
    pub pair_width: usize,
}

impl Phase12DecodingLayout {
    pub fn new(rolling_kv_pairs: usize, pair_width: usize) -> Result<Self> {
        let layout = Self {
            layout_version: STWO_DECODING_LAYOUT_VERSION_PHASE12.to_string(),
            rolling_kv_pairs,
            pair_width,
        };
        layout.validate()?;
        Ok(layout)
    }

    pub fn validate(&self) -> Result<()> {
        if self.layout_version != STWO_DECODING_LAYOUT_VERSION_PHASE12 {
            return Err(VmError::InvalidConfig(format!(
                "unsupported Phase 12 decoding layout version `{}`",
                self.layout_version
            )));
        }
        if self.rolling_kv_pairs == 0 {
            return Err(VmError::InvalidConfig(
                "Phase 12 decoding layout requires at least one rolling KV pair".to_string(),
            ));
        }
        if self.pair_width == 0 {
            return Err(VmError::InvalidConfig(
                "Phase 12 decoding layout requires pair_width > 0".to_string(),
            ));
        }
        let memory_size = self.memory_size()?;
        if memory_size > usize::from(u8::MAX) + 1 {
            return Err(VmError::InvalidConfig(format!(
                "Phase 12 decoding layout memory size {} exceeds the encoded address limit {}",
                memory_size,
                usize::from(u8::MAX) + 1
            )));
        }
        Ok(())
    }

    pub fn memory_size(&self) -> Result<usize> {
        self.position_increment_index()?
            .checked_add(1)
            .ok_or_else(|| {
                VmError::InvalidConfig(
                    "Phase 12 decoding layout memory size overflowed".to_string(),
                )
            })
    }

    pub fn kv_cache_range(&self) -> Result<std::ops::Range<usize>> {
        let end = self
            .rolling_kv_pairs
            .checked_mul(self.pair_width)
            .ok_or_else(|| {
                VmError::InvalidConfig(
                    "Phase 12 decoding layout KV-cache range overflowed".to_string(),
                )
            })?;
        Ok(0..end)
    }

    pub fn incoming_token_range(&self) -> Result<std::ops::Range<usize>> {
        let start = self.kv_cache_range()?.end;
        let end = start.checked_add(self.pair_width).ok_or_else(|| {
            VmError::InvalidConfig(
                "Phase 12 decoding layout incoming-token range overflowed".to_string(),
            )
        })?;
        Ok(start..end)
    }

    pub fn query_range(&self) -> Result<std::ops::Range<usize>> {
        let start = self.incoming_token_range()?.end;
        let end = start.checked_add(self.pair_width).ok_or_else(|| {
            VmError::InvalidConfig("Phase 12 decoding layout query range overflowed".to_string())
        })?;
        Ok(start..end)
    }

    pub fn output_range(&self) -> Result<std::ops::Range<usize>> {
        let start = self.query_range()?.end;
        let end = start.checked_add(PHASE12_OUTPUT_WIDTH).ok_or_else(|| {
            VmError::InvalidConfig("Phase 12 decoding layout output range overflowed".to_string())
        })?;
        Ok(start..end)
    }

    pub fn lookup_range(&self) -> Result<std::ops::Range<usize>> {
        let start = self.output_range()?.end;
        let end = start
            .checked_add(PHASE12_SHARED_LOOKUP_ROWS)
            .ok_or_else(|| {
                VmError::InvalidConfig(
                    "Phase 12 decoding layout lookup range overflowed".to_string(),
                )
            })?;
        Ok(start..end)
    }

    pub fn position_index(&self) -> Result<usize> {
        Ok(self.lookup_range()?.end)
    }

    pub fn position_increment_index(&self) -> Result<usize> {
        self.position_index()?.checked_add(1).ok_or_else(|| {
            VmError::InvalidConfig(
                "Phase 12 decoding layout position increment index overflowed".to_string(),
            )
        })
    }

    pub fn latest_cached_pair_range(&self) -> Result<std::ops::Range<usize>> {
        let end = self.kv_cache_range()?.end;
        let start = end.checked_sub(self.pair_width).ok_or_else(|| {
            VmError::InvalidConfig(
                "Phase 12 decoding layout latest cached pair range underflowed".to_string(),
            )
        })?;
        Ok(start..end)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Phase30DecodingLayoutUnchecked {
    pub layout_version: String,
    pub rolling_kv_pairs: usize,
    pub pair_width: usize,
}

impl TryFrom<Phase30DecodingLayoutUnchecked> for Phase12DecodingLayout {
    type Error = VmError;

    fn try_from(unchecked: Phase30DecodingLayoutUnchecked) -> Result<Self> {
        let layout = Self {
            layout_version: unchecked.layout_version,
            rolling_kv_pairs: unchecked.rolling_kv_pairs,
            pair_width: unchecked.pair_width,
        };
        layout.validate()?;
        Ok(layout)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Phase12DecodingState {
    pub state_version: String,
    pub step_index: usize,
    pub position: i16,
    pub layout_commitment: String,
    pub persistent_state_commitment: String,
    pub kv_history_commitment: String,
    pub kv_history_length: usize,
    pub kv_cache_commitment: String,
    pub incoming_token_commitment: String,
    pub query_commitment: String,
    pub output_commitment: String,
    pub lookup_rows_commitment: String,
    pub public_state_commitment: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Phase12DecodingStep {
    pub from_state: Phase12DecodingState,
    pub to_state: Phase12DecodingState,
    pub shared_lookup_artifact_commitment: String,
    pub proof: VanillaStarkExecutionProof,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Phase12DecodingChainManifest {
    pub proof_backend: StarkProofBackend,
    pub chain_version: String,
    pub semantic_scope: String,
    pub proof_backend_version: String,
    pub statement_version: String,
    pub layout: Phase12DecodingLayout,
    pub total_steps: usize,
    pub shared_lookup_artifacts: Vec<Phase12SharedLookupArtifact>,
    pub steps: Vec<Phase12DecodingStep>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Phase30DecodingStepProofEnvelope {
    pub envelope_version: String,
    pub semantic_scope: String,
    pub proof_backend: StarkProofBackend,
    pub proof_backend_version: String,
    pub statement_version: String,
    pub relation: String,
    pub layout_commitment: String,
    pub source_chain_commitment: String,
    pub step_index: usize,
    pub input_boundary_commitment: String,
    pub output_boundary_commitment: String,
    pub input_lookup_rows_commitment: String,
    pub output_lookup_rows_commitment: String,
    pub shared_lookup_artifact_commitment: String,
    pub static_lookup_registry_commitment: String,
    pub proof_commitment: String,
    pub envelope_commitment: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Phase30DecodingStepProofEnvelopeManifestUnchecked")]
pub struct Phase30DecodingStepProofEnvelopeManifest {
    pub proof_backend: StarkProofBackend,
    pub manifest_version: String,
    pub semantic_scope: String,
    pub proof_backend_version: String,
    pub statement_version: String,
    pub source_chain_version: String,
    pub source_chain_semantic_scope: String,
    pub source_chain_commitment: String,
    pub layout: Phase12DecodingLayout,
    pub total_steps: usize,
    pub chain_start_boundary_commitment: String,
    pub chain_end_boundary_commitment: String,
    pub step_envelopes_commitment: String,
    pub envelopes: Vec<Phase30DecodingStepProofEnvelope>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Phase30DecodingStepProofEnvelopeManifestUnchecked {
    pub proof_backend: StarkProofBackend,
    pub manifest_version: String,
    pub semantic_scope: String,
    pub proof_backend_version: String,
    pub statement_version: String,
    pub source_chain_version: String,
    pub source_chain_semantic_scope: String,
    pub source_chain_commitment: String,
    pub layout: Phase30DecodingLayoutUnchecked,
    pub total_steps: usize,
    pub chain_start_boundary_commitment: String,
    pub chain_end_boundary_commitment: String,
    pub step_envelopes_commitment: String,
    pub envelopes: Vec<Phase30DecodingStepProofEnvelope>,
}

impl TryFrom<Phase30DecodingStepProofEnvelopeManifestUnchecked>
    for Phase30DecodingStepProofEnvelopeManifest
{
    type Error = VmError;

    fn try_from(unchecked: Phase30DecodingStepProofEnvelopeManifestUnchecked) -> Result<Self> {
        let manifest = Self {
            proof_backend: unchecked.proof_backend,
            manifest_version: unchecked.manifest_version,
            semantic_scope: unchecked.semantic_scope,
            proof_backend_version: unchecked.proof_backend_version,
            statement_version: unchecked.statement_version,
            source_chain_version: unchecked.source_chain_version,
            source_chain_semantic_scope: unchecked.source_chain_semantic_scope,
            source_chain_commitment: unchecked.source_chain_commitment,
            layout: unchecked.layout.try_into()?,
            total_steps: unchecked.total_steps,
            chain_start_boundary_commitment: unchecked.chain_start_boundary_commitment,
            chain_end_boundary_commitment: unchecked.chain_end_boundary_commitment,
            step_envelopes_commitment: unchecked.step_envelopes_commitment,
            envelopes: unchecked.envelopes,
        };
        verify_phase30_decoding_step_proof_envelope_manifest(&manifest)?;
        Ok(manifest)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Phase13DecodingLayoutMatrixManifest {
    pub proof_backend: StarkProofBackend,
    pub matrix_version: String,
    pub semantic_scope: String,
    pub proof_backend_version: String,
    pub statement_version: String,
    pub total_layouts: usize,
    pub total_steps: usize,
    pub chains: Vec<Phase12DecodingChainManifest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Phase14DecodingState {
    pub state_version: String,
    pub step_index: usize,
    pub position: i16,
    pub layout_commitment: String,
    pub persistent_state_commitment: String,
    pub kv_history_commitment: String,
    pub kv_history_length: usize,
    pub kv_history_chunk_size: usize,
    pub kv_history_sealed_commitment: String,
    pub kv_history_sealed_chunks: usize,
    pub kv_history_open_chunk_commitment: String,
    pub kv_history_open_chunk_pairs: usize,
    pub kv_history_frontier_commitment: String,
    pub kv_history_frontier_pairs: usize,
    pub lookup_transcript_commitment: String,
    pub lookup_transcript_entries: usize,
    pub lookup_frontier_commitment: String,
    pub lookup_frontier_entries: usize,
    pub kv_cache_commitment: String,
    pub incoming_token_commitment: String,
    pub query_commitment: String,
    pub output_commitment: String,
    pub lookup_rows_commitment: String,
    pub public_state_commitment: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Phase14DecodingStep {
    pub from_state: Phase14DecodingState,
    pub to_state: Phase14DecodingState,
    pub shared_lookup_artifact_commitment: String,
    pub proof: VanillaStarkExecutionProof,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Phase14DecodingChainManifest {
    pub proof_backend: StarkProofBackend,
    pub chain_version: String,
    pub semantic_scope: String,
    pub proof_backend_version: String,
    pub statement_version: String,
    pub layout: Phase12DecodingLayout,
    pub total_steps: usize,
    pub history_chunk_pairs: usize,
    pub shared_lookup_artifacts: Vec<Phase12SharedLookupArtifact>,
    pub steps: Vec<Phase14DecodingStep>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Phase15DecodingHistorySegment {
    pub segment_index: usize,
    pub global_start_step_index: usize,
    pub total_steps: usize,
    pub global_from_state: Phase14DecodingState,
    pub global_to_state: Phase14DecodingState,
    pub public_state_boundary_commitment: String,
    pub chain: Phase14DecodingChainManifest,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Phase15DecodingHistorySegmentBundleManifest {
    pub proof_backend: StarkProofBackend,
    pub bundle_version: String,
    pub semantic_scope: String,
    pub proof_backend_version: String,
    pub statement_version: String,
    pub layout: Phase12DecodingLayout,
    pub history_chunk_pairs: usize,
    pub max_segment_steps: usize,
    pub total_segments: usize,
    pub total_steps: usize,
    pub segments: Vec<Phase15DecodingHistorySegment>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Phase16DecodingHistoryRollup {
    pub rollup_index: usize,
    pub global_start_step_index: usize,
    pub total_segments: usize,
    pub total_steps: usize,
    pub global_from_state: Phase14DecodingState,
    pub global_to_state: Phase14DecodingState,
    pub public_state_boundary_commitment: String,
    pub segments: Vec<Phase15DecodingHistorySegment>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Phase16DecodingHistoryRollupManifest {
    pub proof_backend: StarkProofBackend,
    pub rollup_version: String,
    pub semantic_scope: String,
    pub proof_backend_version: String,
    pub statement_version: String,
    pub layout: Phase12DecodingLayout,
    pub history_chunk_pairs: usize,
    pub max_rollup_segments: usize,
    pub total_rollups: usize,
    pub total_segments: usize,
    pub total_steps: usize,
    pub rollups: Vec<Phase16DecodingHistoryRollup>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Phase17DecodingHistoryRollupMatrixManifest {
    pub proof_backend: StarkProofBackend,
    pub matrix_version: String,
    pub semantic_scope: String,
    pub proof_backend_version: String,
    pub statement_version: String,
    pub total_layouts: usize,
    pub total_rollups: usize,
    pub total_segments: usize,
    pub total_steps: usize,
    pub public_state_boundary_commitment: String,
    pub rollups: Vec<Phase16DecodingHistoryRollupManifest>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Phase21DecodingMatrixAccumulatorManifest {
    pub proof_backend: StarkProofBackend,
    pub accumulator_version: String,
    pub semantic_scope: String,
    pub proof_backend_version: String,
    pub statement_version: String,
    pub total_matrices: usize,
    pub total_layouts: usize,
    pub total_rollups: usize,
    pub total_segments: usize,
    pub total_steps: usize,
    pub template_commitment: String,
    pub accumulator_commitment: String,
    pub matrices: Vec<Phase17DecodingHistoryRollupMatrixManifest>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Phase22DecodingLookupAccumulatorManifest {
    pub proof_backend: StarkProofBackend,
    pub accumulator_version: String,
    pub semantic_scope: String,
    pub proof_backend_version: String,
    pub statement_version: String,
    pub total_matrices: usize,
    pub total_layouts: usize,
    pub total_rollups: usize,
    pub total_segments: usize,
    pub total_steps: usize,
    pub lookup_delta_entries: usize,
    pub max_lookup_frontier_entries: usize,
    pub source_template_commitment: String,
    pub source_accumulator_commitment: String,
    pub lookup_template_commitment: String,
    pub lookup_accumulator_commitment: String,
    pub accumulator: Phase21DecodingMatrixAccumulatorManifest,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Phase23DecodingCrossStepLookupAccumulatorManifest {
    pub proof_backend: StarkProofBackend,
    pub accumulator_version: String,
    pub semantic_scope: String,
    pub proof_backend_version: String,
    pub statement_version: String,
    pub member_count: usize,
    pub total_matrices: usize,
    pub total_layouts: usize,
    pub total_rollups: usize,
    pub total_segments: usize,
    pub total_steps: usize,
    pub lookup_delta_entries: usize,
    pub max_lookup_frontier_entries: usize,
    pub source_template_commitment: String,
    pub lookup_template_commitment: String,
    pub start_boundary_commitment: String,
    pub end_boundary_commitment: String,
    pub accumulator_commitment: String,
    pub members: Vec<Phase22DecodingLookupAccumulatorManifest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Phase24DecodingStateRelationMemberSummary {
    pub start_step: usize,
    pub end_step: usize,
    pub total_matrices: usize,
    pub total_layouts: usize,
    pub total_rollups: usize,
    pub total_segments: usize,
    pub total_steps: usize,
    pub lookup_delta_entries: usize,
    pub max_lookup_frontier_entries: usize,
    pub source_template_commitment: String,
    pub lookup_template_commitment: String,
    pub lookup_accumulator_commitment: String,
    pub start_state_commitment: String,
    pub end_state_commitment: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Phase24DecodingStateRelationAccumulatorManifest {
    pub proof_backend: StarkProofBackend,
    pub accumulator_version: String,
    pub semantic_scope: String,
    pub proof_backend_version: String,
    pub statement_version: String,
    pub member_count: usize,
    pub total_matrices: usize,
    pub total_layouts: usize,
    pub total_rollups: usize,
    pub total_segments: usize,
    pub total_steps: usize,
    pub lookup_delta_entries: usize,
    pub max_lookup_frontier_entries: usize,
    pub source_template_commitment: String,
    pub start_state_commitment: String,
    pub end_state_commitment: String,
    pub relation_template_commitment: String,
    pub relation_accumulator_commitment: String,
    pub member_summaries: Vec<Phase24DecodingStateRelationMemberSummary>,
    pub members: Vec<Phase23DecodingCrossStepLookupAccumulatorManifest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Phase25IntervalizedDecodingStateRelationMemberSummary {
    pub start_step: usize,
    pub end_step: usize,
    pub total_matrices: usize,
    pub total_layouts: usize,
    pub total_rollups: usize,
    pub total_segments: usize,
    pub total_steps: usize,
    pub lookup_delta_entries: usize,
    pub max_lookup_frontier_entries: usize,
    pub source_template_commitment: String,
    pub lookup_template_commitment: String,
    pub lookup_accumulator_commitment: String,
    pub start_state_commitment: String,
    pub end_state_commitment: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Phase25IntervalizedDecodingStateRelationManifest {
    pub proof_backend: StarkProofBackend,
    pub artifact_version: String,
    pub semantic_scope: String,
    pub proof_backend_version: String,
    pub statement_version: String,
    pub member_count: usize,
    pub total_matrices: usize,
    pub total_layouts: usize,
    pub total_rollups: usize,
    pub total_segments: usize,
    pub total_steps: usize,
    pub lookup_delta_entries: usize,
    pub max_lookup_frontier_entries: usize,
    pub source_template_commitment: String,
    pub source_relation_template_commitment: String,
    pub source_relation_accumulator_commitment: String,
    pub global_start_state_commitment: String,
    pub global_end_state_commitment: String,
    pub interval_template_commitment: String,
    pub interval_accumulator_commitment: String,
    pub member_summaries: Vec<Phase25IntervalizedDecodingStateRelationMemberSummary>,
    pub members: Vec<Phase23DecodingCrossStepLookupAccumulatorManifest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Phase26FoldedIntervalizedDecodingStateRelationMemberSummary {
    pub start_step: usize,
    pub end_step: usize,
    pub total_matrices: usize,
    pub total_layouts: usize,
    pub total_rollups: usize,
    pub total_segments: usize,
    pub total_steps: usize,
    pub lookup_delta_entries: usize,
    pub max_lookup_frontier_entries: usize,
    pub source_template_commitment: String,
    pub interval_template_commitment: String,
    pub interval_accumulator_commitment: String,
    pub start_state_commitment: String,
    pub end_state_commitment: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Phase26FoldedIntervalizedDecodingStateRelationManifest {
    pub proof_backend: StarkProofBackend,
    pub artifact_version: String,
    pub semantic_scope: String,
    pub proof_backend_version: String,
    pub statement_version: String,
    pub bounded_fold_arity: usize,
    pub member_count: usize,
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
    pub fold_template_commitment: String,
    pub folded_interval_accumulator_commitment: String,
    pub member_summaries: Vec<Phase26FoldedIntervalizedDecodingStateRelationMemberSummary>,
    pub members: Vec<Phase25IntervalizedDecodingStateRelationManifest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Phase27ChainedFoldedIntervalizedDecodingStateRelationMemberSummary {
    pub start_step: usize,
    pub end_step: usize,
    pub bounded_fold_arity: usize,
    pub total_phase25_members: usize,
    pub total_matrices: usize,
    pub total_layouts: usize,
    pub total_rollups: usize,
    pub total_segments: usize,
    pub total_steps: usize,
    pub lookup_delta_entries: usize,
    pub max_lookup_frontier_entries: usize,
    pub source_template_commitment: String,
    pub fold_template_commitment: String,
    pub folded_interval_accumulator_commitment: String,
    pub start_state_commitment: String,
    pub end_state_commitment: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Phase27ChainedFoldedIntervalizedDecodingStateRelationManifest {
    pub proof_backend: StarkProofBackend,
    pub artifact_version: String,
    pub semantic_scope: String,
    pub proof_backend_version: String,
    pub statement_version: String,
    pub bounded_chain_arity: usize,
    pub member_count: usize,
    pub total_phase25_members: usize,
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
    pub chain_template_commitment: String,
    pub chained_folded_interval_accumulator_commitment: String,
    pub member_summaries: Vec<Phase27ChainedFoldedIntervalizedDecodingStateRelationMemberSummary>,
    pub members: Vec<Phase26FoldedIntervalizedDecodingStateRelationManifest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Phase28AggregatedChainedFoldedIntervalizedDecodingStateRelationMemberSummary {
    pub start_step: usize,
    pub end_step: usize,
    pub bounded_chain_arity: usize,
    pub total_phase26_members: usize,
    pub total_phase25_members: usize,
    pub max_nested_fold_arity: usize,
    pub total_matrices: usize,
    pub total_layouts: usize,
    pub total_rollups: usize,
    pub total_segments: usize,
    pub total_steps: usize,
    pub lookup_delta_entries: usize,
    pub max_lookup_frontier_entries: usize,
    pub source_template_commitment: String,
    pub chain_template_commitment: String,
    pub chained_folded_interval_accumulator_commitment: String,
    pub start_state_commitment: String,
    pub end_state_commitment: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Phase28AggregatedChainedFoldedIntervalizedDecodingStateRelationManifest {
    pub proof_backend: StarkProofBackend,
    pub artifact_version: String,
    pub semantic_scope: String,
    pub proof_backend_version: String,
    pub statement_version: String,
    // Defaulted posture metadata preserves legacy Phase 28 v1 commitments while
    // making any new recursive/compressed claim fail at verifier entry.
    #[serde(
        default = "default_phase28_recursion_posture",
        deserialize_with = "deserialize_phase28_recursion_posture"
    )]
    pub recursion_posture: String,
    #[serde(default)]
    pub recursive_verification_claimed: bool,
    #[serde(default)]
    pub cryptographic_compression_claimed: bool,
    pub bounded_aggregation_arity: usize,
    pub member_count: usize,
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
    pub member_summaries:
        Vec<Phase28AggregatedChainedFoldedIntervalizedDecodingStateRelationMemberSummary>,
    pub members: Vec<Phase27ChainedFoldedIntervalizedDecodingStateRelationManifest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Phase12StateView {
    position: i16,
    layout_commitment: String,
    persistent_state_commitment: String,
    kv_cache_commitment: String,
    incoming_token_commitment: String,
    query_commitment: String,
    output_commitment: String,
    lookup_rows_commitment: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Phase14HistoryAccumulator {
    history_commitment: String,
    history_length: usize,
    chunk_size: usize,
    sealed_commitment: String,
    sealed_chunks: usize,
    open_chunk_commitment: String,
    open_chunk_pairs: usize,
    frontier_commitment: String,
    frontier_pairs: usize,
    frontier_values: Vec<i16>,
    lookup_transcript_commitment: String,
    lookup_transcript_entries: usize,
    lookup_frontier_commitment: String,
    lookup_frontier_entries: usize,
    lookup_frontier_values: Vec<String>,
}

#[derive(Debug, Clone)]
struct Phase23MemberSummary {
    total_matrices: usize,
    total_layouts: usize,
    total_rollups: usize,
    total_segments: usize,
    total_steps: usize,
    lookup_delta_entries: usize,
    max_lookup_frontier_entries: usize,
    source_template_commitment: String,
    start_boundary_commitment: String,
    end_boundary_commitment: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Phase24MemberSummary {
    start_step: usize,
    end_step: usize,
    total_matrices: usize,
    total_layouts: usize,
    total_rollups: usize,
    total_segments: usize,
    total_steps: usize,
    lookup_delta_entries: usize,
    max_lookup_frontier_entries: usize,
    source_template_commitment: String,
    lookup_template_commitment: String,
    lookup_accumulator_commitment: String,
    start_state_commitment: String,
    end_state_commitment: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Phase24RebaseBaseline {
    total_matrices: usize,
    total_layouts: usize,
    total_rollups: usize,
    total_segments: usize,
    total_steps: usize,
    lookup_delta_entries: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Phase26MemberSummary {
    start_step: usize,
    end_step: usize,
    total_matrices: usize,
    total_layouts: usize,
    total_rollups: usize,
    total_segments: usize,
    total_steps: usize,
    lookup_delta_entries: usize,
    max_lookup_frontier_entries: usize,
    source_template_commitment: String,
    interval_template_commitment: String,
    interval_accumulator_commitment: String,
    start_state_commitment: String,
    end_state_commitment: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Phase26AggregateTotals {
    total_matrices: usize,
    total_layouts: usize,
    total_rollups: usize,
    total_segments: usize,
    total_steps: usize,
    lookup_delta_entries: usize,
    max_lookup_frontier_entries: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Phase27MemberSummary {
    start_step: usize,
    end_step: usize,
    bounded_fold_arity: usize,
    total_phase25_members: usize,
    total_matrices: usize,
    total_layouts: usize,
    total_rollups: usize,
    total_segments: usize,
    total_steps: usize,
    lookup_delta_entries: usize,
    max_lookup_frontier_entries: usize,
    source_template_commitment: String,
    fold_template_commitment: String,
    folded_interval_accumulator_commitment: String,
    start_state_commitment: String,
    end_state_commitment: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Phase27AggregateTotals {
    total_phase25_members: usize,
    max_nested_fold_arity: usize,
    total_matrices: usize,
    total_layouts: usize,
    total_rollups: usize,
    total_segments: usize,
    total_steps: usize,
    lookup_delta_entries: usize,
    max_lookup_frontier_entries: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Phase28MemberSummary {
    start_step: usize,
    end_step: usize,
    bounded_chain_arity: usize,
    total_phase26_members: usize,
    total_phase25_members: usize,
    max_nested_fold_arity: usize,
    total_matrices: usize,
    total_layouts: usize,
    total_rollups: usize,
    total_segments: usize,
    total_steps: usize,
    lookup_delta_entries: usize,
    max_lookup_frontier_entries: usize,
    source_template_commitment: String,
    chain_template_commitment: String,
    chained_folded_interval_accumulator_commitment: String,
    start_state_commitment: String,
    end_state_commitment: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Phase28AggregateTotals {
    total_phase26_members: usize,
    total_phase25_members: usize,
    max_nested_chain_arity: usize,
    max_nested_fold_arity: usize,
    total_matrices: usize,
    total_layouts: usize,
    total_rollups: usize,
    total_segments: usize,
    total_steps: usize,
    lookup_delta_entries: usize,
    max_lookup_frontier_entries: usize,
}

fn build_phase12_shared_lookup_artifact_registry(
    proofs: &[VanillaStarkExecutionProof],
    layout_commitment: &str,
) -> Result<(Vec<Phase12SharedLookupArtifact>, Vec<String>)> {
    let mut artifacts: Vec<Phase12SharedLookupArtifact> = Vec::new();
    let mut artifact_indexes: HashMap<String, usize> = HashMap::new();
    let mut artifact_refs = Vec::with_capacity(proofs.len());
    for (step_index, proof) in proofs.iter().enumerate() {
        let artifact = phase12_shared_lookup_artifact_from_proof_payload(proof, layout_commitment)?
            .ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "decoding step {step_index} is missing its Phase 12 shared lookup artifact payload"
                ))
            })?;
        if let Some(existing_index) = artifact_indexes.get(&artifact.artifact_commitment) {
            let existing = &artifacts[*existing_index];
            if existing != &artifact {
                return Err(VmError::InvalidConfig(format!(
                    "decoding step {step_index} reuses shared lookup artifact commitment `{}` but with different contents",
                    artifact.artifact_commitment
                )));
            }
        } else {
            artifact_indexes.insert(artifact.artifact_commitment.clone(), artifacts.len());
            artifacts.push(artifact.clone());
        }
        artifact_refs.push(artifact.artifact_commitment);
    }
    Ok((artifacts, artifact_refs))
}

fn build_phase12_shared_lookup_artifact_index<'a>(
    artifacts: &'a [Phase12SharedLookupArtifact],
    referenced_commitments: &HashSet<String>,
    layout: &Phase12DecodingLayout,
    expected_layout_commitment: &str,
    expected_flattened_lookup_rows_len: usize,
    registry_label: &str,
) -> Result<HashMap<String, &'a Phase12SharedLookupArtifact>> {
    let mut artifact_index = HashMap::with_capacity(artifacts.len());
    for artifact in artifacts {
        validate_phase12_shared_lookup_artifact_resource_bounds(artifact, registry_label)?;
        if artifact.flattened_lookup_rows.len() != expected_flattened_lookup_rows_len {
            return Err(VmError::InvalidConfig(format!(
                "{registry_label} artifact `{}` has {} flattened lookup rows; expected {}",
                artifact.artifact_commitment,
                artifact.flattened_lookup_rows.len(),
                expected_flattened_lookup_rows_len
            )));
        }
        if !referenced_commitments.contains(&artifact.artifact_commitment) {
            return Err(VmError::InvalidConfig(format!(
                "{registry_label} artifact `{}` is not referenced by any decoding step",
                artifact.artifact_commitment
            )));
        }
        if artifact_index
            .insert(artifact.artifact_commitment.clone(), artifact)
            .is_some()
        {
            return Err(VmError::InvalidConfig(format!(
                "{registry_label} artifact `{}` appears more than once in the manifest registry",
                artifact.artifact_commitment
            )));
        }
    }
    if artifact_index.len() != referenced_commitments.len() {
        let missing = referenced_commitments
            .iter()
            .find(|commitment| !artifact_index.contains_key(*commitment))
            .cloned()
            .unwrap_or_else(|| "<unknown>".to_string());
        return Err(VmError::InvalidConfig(format!(
            "{registry_label} artifact `{missing}` is not present in the manifest registry"
        )));
    }
    for artifact in artifact_index.values() {
        verify_phase12_shared_lookup_artifact(artifact, layout, expected_layout_commitment)?;
    }
    Ok(artifact_index)
}

fn shared_lookup_artifact_by_commitment<'a>(
    artifacts: &'a HashMap<String, &'a Phase12SharedLookupArtifact>,
    artifact_commitment: &str,
) -> Result<&'a Phase12SharedLookupArtifact> {
    artifacts.get(artifact_commitment).copied().ok_or_else(|| {
            VmError::InvalidConfig(format!(
                "shared lookup artifact `{artifact_commitment}` is not present in the manifest registry"
            ))
        })
}

fn validate_phase12_shared_lookup_artifact_resource_bounds(
    artifact: &Phase12SharedLookupArtifact,
    registry_label: &str,
) -> Result<()> {
    if artifact
        .normalization_proof_envelope
        .proof_envelope
        .proof
        .len()
        > MAX_SHARED_LOOKUP_ENVELOPE_PROOF_BYTES
    {
        return Err(VmError::InvalidConfig(format!(
            "{registry_label} artifact `{}` normalization proof is {} bytes, exceeding the limit of {} bytes",
            artifact.artifact_commitment,
            artifact.normalization_proof_envelope.proof_envelope.proof.len(),
            MAX_SHARED_LOOKUP_ENVELOPE_PROOF_BYTES
        )));
    }
    if artifact
        .activation_proof_envelope
        .proof_envelope
        .proof
        .len()
        > MAX_SHARED_LOOKUP_ENVELOPE_PROOF_BYTES
    {
        return Err(VmError::InvalidConfig(format!(
            "{registry_label} artifact `{}` activation proof is {} bytes, exceeding the limit of {} bytes",
            artifact.artifact_commitment,
            artifact.activation_proof_envelope.proof_envelope.proof.len(),
            MAX_SHARED_LOOKUP_ENVELOPE_PROOF_BYTES
        )));
    }
    Ok(())
}

pub(super) fn read_json_bytes_with_limit(
    path: &Path,
    max_bytes: usize,
    label: &str,
) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        VmError::InvalidConfig(format!(
            "{label} `{}` could not be inspected before reading: io_kind={:?}: {error}",
            path.display(),
            error.kind()
        ))
    })?;
    if !metadata.file_type().is_file() {
        return Err(VmError::InvalidConfig(format!(
            "{label} `{}` is not a regular file",
            path.display()
        )));
    }
    if metadata.len() > max_bytes as u64 {
        return Err(VmError::InvalidConfig(format!(
            "{label} `{}` is {} bytes, exceeding the limit of {} bytes",
            path.display(),
            metadata.len(),
            max_bytes
        )));
    }
    let file = open_json_file_for_read(path, label)?;
    let opened_metadata = file.metadata().map_err(|error| {
        VmError::InvalidConfig(format!(
            "{label} `{}` could not be inspected after opening: io_kind={:?}: {error}",
            path.display(),
            error.kind()
        ))
    })?;
    if !opened_metadata.file_type().is_file() {
        return Err(VmError::InvalidConfig(format!(
            "{label} `{}` is not a regular file after opening",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if metadata.dev() != opened_metadata.dev() || metadata.ino() != opened_metadata.ino() {
            return Err(VmError::InvalidConfig(format!(
                "{label} `{}` changed between metadata inspection and open",
                path.display()
            )));
        }
    }
    if opened_metadata.len() > max_bytes as u64 {
        return Err(VmError::InvalidConfig(format!(
            "{label} `{}` is {} bytes after opening, exceeding the limit of {} bytes",
            path.display(),
            opened_metadata.len(),
            max_bytes
        )));
    }
    let is_gzip = matches!(path.extension().and_then(|ext| ext.to_str()), Some("gz"));
    if is_gzip {
        let mut limited = GzDecoder::new(file).take((max_bytes as u64).saturating_add(1));
        let mut bytes = Vec::new();
        limited.read_to_end(&mut bytes).map_err(|error| {
            VmError::InvalidConfig(format!(
                "{label} `{}` could not be decompressed as gzip: {error}",
                path.display()
            ))
        })?;
        if bytes.len() > max_bytes {
            return Err(VmError::InvalidConfig(format!(
                "{label} `{}` decompresses to {} bytes, exceeding the limit of {} bytes",
                path.display(),
                bytes.len(),
                max_bytes
            )));
        }
        return Ok(bytes);
    }
    let mut limited = file.take((max_bytes as u64).saturating_add(1));
    let mut bytes = Vec::with_capacity(metadata.len().min(max_bytes as u64) as usize);
    limited.read_to_end(&mut bytes).map_err(|error| {
        VmError::InvalidConfig(format!(
            "{label} `{}` could not be read: io_kind={:?}: {error}",
            path.display(),
            error.kind()
        ))
    })?;
    if bytes.len() > max_bytes {
        return Err(VmError::InvalidConfig(format!(
            "{label} `{}` is {} bytes after reading, exceeding the limit of {} bytes",
            path.display(),
            bytes.len(),
            max_bytes
        )));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn open_json_file_for_read(path: &Path, label: &str) -> Result<fs::File> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| {
            VmError::InvalidConfig(format!(
                "{label} `{}` could not be opened for reading without following symlinks or blocking: io_kind={:?}: {error}",
                path.display(),
                error.kind()
            ))
        })
}

#[cfg(not(unix))]
fn open_json_file_for_read(path: &Path, label: &str) -> Result<fs::File> {
    fs::File::open(path).map_err(|error| {
        VmError::InvalidConfig(format!(
            "{label} `{}` could not be opened for reading: io_kind={:?}: {error}",
            path.display(),
            error.kind()
        ))
    })
}

pub(super) fn write_json_with_limit<T: Serialize>(
    value: &T,
    path: &Path,
    max_bytes: usize,
    label: &str,
) -> Result<()> {
    write_json_atomically_with_limit(value, path, max_bytes, label, true)
}

fn write_json_compact_with_limit<T: Serialize>(
    value: &T,
    path: &Path,
    max_bytes: usize,
    label: &str,
) -> Result<()> {
    write_json_atomically_with_limit(value, path, max_bytes, label, false)
}

struct CountingWriter<W> {
    inner: W,
    written: usize,
    max_bytes: usize,
    limit_exceeded: bool,
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let next = self.written.saturating_add(buf.len());
        if next > self.max_bytes {
            self.limit_exceeded = true;
            return Err(std::io::Error::other("json size limit exceeded"));
        }
        self.inner.write_all(buf)?;
        self.written = next;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl<W> CountingWriter<W> {
    fn into_inner(self) -> W {
        self.inner
    }
}

fn write_json_atomically_with_limit<T: Serialize>(
    value: &T,
    path: &Path,
    max_bytes: usize,
    label: &str,
    pretty: bool,
) -> Result<()> {
    let mut last_exists_error = None;

    for attempt in 0..16_u32 {
        let temp_path = temporary_json_output_path(path, attempt);
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
        {
            Ok(file) => {
                let writer = BufWriter::new(file);
                let mut counting_writer = CountingWriter {
                    inner: writer,
                    written: 0,
                    max_bytes,
                    limit_exceeded: false,
                };
                let write_result = if pretty {
                    serde_json::to_writer_pretty(&mut counting_writer, value)
                } else {
                    serde_json::to_writer(&mut counting_writer, value)
                };
                if let Err(err) = write_result {
                    let limit_exceeded = counting_writer.limit_exceeded;
                    drop(counting_writer);
                    let _ = fs::remove_file(&temp_path);
                    if limit_exceeded {
                        return Err(VmError::InvalidConfig(format!(
                            "{label} `{}` would serialize to JSON exceeding the limit of {} bytes",
                            path.display(),
                            max_bytes
                        )));
                    }
                    return Err(VmError::Serialization(err.to_string()));
                }
                let written = counting_writer.written;
                let file = counting_writer
                    .into_inner()
                    .into_inner()
                    .map_err(|err| VmError::Io(err.into_error()))?;
                if written > max_bytes {
                    let _ = fs::remove_file(&temp_path);
                    return Err(VmError::InvalidConfig(format!(
                        "{label} `{}` is {} bytes, exceeding the limit of {} bytes",
                        path.display(),
                        written,
                        max_bytes
                    )));
                }
                if let Err(err) = file.sync_all() {
                    let _ = fs::remove_file(&temp_path);
                    return Err(err.into());
                }
                if let Err(err) = persist_atomic_json_output(&temp_path, path) {
                    let _ = fs::remove_file(&temp_path);
                    return Err(err);
                }
                return Ok(());
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                last_exists_error = Some(err);
            }
            Err(err) => return Err(err.into()),
        }
    }

    let err = last_exists_error.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "{label} `{}` could not allocate a unique temporary output path",
                path.display()
            ),
        )
    });
    Err(err.into())
}

fn persist_atomic_json_output(temp_path: &Path, path: &Path) -> Result<()> {
    match fs::rename(temp_path, path) {
        Ok(()) => {
            sync_parent_directory(path)?;
            Ok(())
        }
        Err(err)
            if err.kind() == std::io::ErrorKind::AlreadyExists
                || err.kind() == std::io::ErrorKind::PermissionDenied =>
        {
            persist_atomic_json_output_with_backup(temp_path, path, err)
        }
        Err(err) => Err(err.into()),
    }
}

fn persist_atomic_json_output_with_backup(
    temp_path: &Path,
    path: &Path,
    rename_err: std::io::Error,
) -> Result<()> {
    if !path.exists() {
        return Err(rename_err.into());
    }

    let mut last_backup_collision = None;
    for attempt in 0..16 {
        let backup_path = temporary_backup_output_path(path, attempt);
        match fs::rename(path, &backup_path) {
            Ok(()) => {
                if let Err(err) = sync_parent_directory(path) {
                    let _ = fs::rename(&backup_path, path);
                    let _ = sync_parent_directory(path);
                    return Err(err.into());
                }
                if let Err(err) = fs::rename(temp_path, path) {
                    let restore_result = fs::rename(&backup_path, path);
                    let _ = sync_parent_directory(path);
                    return match restore_result {
                        Ok(()) => Err(err.into()),
                        Err(restore_err) => Err(VmError::Io(std::io::Error::new(
                            err.kind(),
                            format!(
                                "failed to replace `{}` from `{}` and could not restore backup `{}`: {}",
                                path.display(),
                                temp_path.display(),
                                backup_path.display(),
                                restore_err
                            ),
                        ))),
                    };
                }
                if let Err(err) = sync_parent_directory(path) {
                    let _ = fs::remove_file(path);
                    let restore_result = fs::rename(&backup_path, path);
                    let _ = sync_parent_directory(path);
                    return match restore_result {
                        Ok(()) => Err(err.into()),
                        Err(restore_err) => Err(VmError::Io(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!(
                                "persisted `{}` but could not durably finalize it and also failed to restore backup `{}`: {}",
                                path.display(),
                                backup_path.display(),
                                restore_err
                            ),
                        ))),
                    };
                }
                fs::remove_file(&backup_path)?;
                sync_parent_directory(path)?;
                return Ok(());
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                last_backup_collision = Some(err);
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Err(rename_err.into());
            }
            Err(err) => return Err(err.into()),
        }
    }

    Err(last_backup_collision.unwrap_or(rename_err).into())
}

fn sync_parent_directory(path: &Path) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let dir = fs::File::open(parent)?;
    dir.sync_all()?;
    Ok(())
}

fn temporary_json_output_path(path: &Path, attempt: u32) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut name = path
        .file_name()
        .map(|file_name| file_name.to_os_string())
        .unwrap_or_else(|| OsString::from("artifact.json"));
    let monotonic_tag = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    name.push(format!(
        ".tmp-{}-{monotonic_tag}-{attempt}",
        std::process::id()
    ));
    parent.join(name)
}

fn temporary_backup_output_path(path: &Path, attempt: u32) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut name = path
        .file_name()
        .map(|file_name| file_name.to_os_string())
        .unwrap_or_else(|| OsString::from("artifact.json"));
    let monotonic_tag = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    name.push(format!(
        ".bak-{}-{monotonic_tag}-{attempt}",
        std::process::id()
    ));
    parent.join(name)
}

pub fn decoding_step_v1_template_program() -> Result<Program> {
    parse_program(include_str!("../../programs/decoding_step_v1.tvm"))
}

pub fn decoding_step_v1_program_with_initial_memory(initial_memory: Vec<i16>) -> Result<Program> {
    decoding_step_v1_template_program()?.with_initial_memory(initial_memory)
}

pub fn phase12_default_decoding_layout() -> Phase12DecodingLayout {
    Phase12DecodingLayout {
        layout_version: STWO_DECODING_LAYOUT_VERSION_PHASE12.to_string(),
        rolling_kv_pairs: 4,
        pair_width: 4,
    }
}

pub fn decoding_step_v2_template_program(layout: &Phase12DecodingLayout) -> Result<Program> {
    layout.validate()?;

    let latest_cached = layout.latest_cached_pair_range()?;
    let incoming = layout.incoming_token_range()?;
    let query = layout.query_range()?;
    let output = layout.output_range()?;
    let lookup = layout.lookup_range()?;

    let mut instructions = Vec::new();

    for offset in 0..layout.pair_width {
        instructions.push(Instruction::Load((query.start + offset) as u8));
        instructions.push(Instruction::MulMemory((latest_cached.start + offset) as u8));
        if offset == 0 {
            instructions.push(Instruction::Store(output.start as u8));
        } else {
            instructions.push(Instruction::AddMemory(output.start as u8));
            instructions.push(Instruction::Store(output.start as u8));
        }
    }

    for offset in 0..layout.pair_width {
        instructions.push(Instruction::Load((incoming.start + offset) as u8));
        if offset == 0 {
            instructions.push(Instruction::AddMemory(output.start as u8));
        } else {
            instructions.push(Instruction::AddMemory((output.start + 1) as u8));
        }
        instructions.push(Instruction::Store((output.start + 1) as u8));
    }

    for (offset, value) in PHASE12_LOOKUP_ROW_VALUES.iter().enumerate() {
        instructions.push(Instruction::LoadImmediate(*value));
        instructions.push(Instruction::Store((lookup.start + offset) as u8));
    }

    instructions.push(Instruction::Load(output.start as u8));
    instructions.push(Instruction::MulMemory((lookup.start + 1) as u8));
    instructions.push(Instruction::Store(output.start as u8));
    instructions.push(Instruction::Load(output.start as u8));
    instructions.push(Instruction::AddMemory((lookup.start + 3) as u8));
    instructions.push(Instruction::Store(output.start as u8));
    instructions.push(Instruction::Load((output.start + 1) as u8));
    instructions.push(Instruction::MulMemory((lookup.start + 5) as u8));
    instructions.push(Instruction::Store((output.start + 1) as u8));
    instructions.push(Instruction::Load((output.start + 1) as u8));
    instructions.push(Instruction::AddMemory((lookup.start + 7) as u8));
    instructions.push(Instruction::Store((output.start + 1) as u8));
    instructions.push(Instruction::Load((lookup.start + 3) as u8));
    instructions.push(Instruction::AddMemory((lookup.start + 7) as u8));
    instructions.push(Instruction::AddMemory((lookup.start + 2) as u8));
    instructions.push(Instruction::AddMemory((lookup.start + 4) as u8));
    instructions.push(Instruction::Store((output.start + 2) as u8));
    instructions.push(Instruction::Load((output.start + 1) as u8));
    instructions.push(Instruction::AddMemory((output.start + 2) as u8));
    instructions.push(Instruction::Store((output.start + 1) as u8));
    instructions.push(Instruction::Load(output.start as u8));
    instructions.push(Instruction::AddMemory((output.start + 2) as u8));
    instructions.push(Instruction::Store(output.start as u8));

    let kv_cache = layout.kv_cache_range()?;
    for index in 0..(kv_cache.len().saturating_sub(layout.pair_width)) {
        instructions.push(Instruction::Load((index + layout.pair_width) as u8));
        instructions.push(Instruction::Store(index as u8));
    }
    for offset in 0..layout.pair_width {
        match offset {
            0 => {
                instructions.push(Instruction::Load((output.start + 2) as u8));
                instructions.push(Instruction::Store((latest_cached.start + offset) as u8));
            }
            1 => {
                instructions.push(Instruction::Load((output.start + 2) as u8));
                instructions.push(Instruction::Store((latest_cached.start + offset) as u8));
            }
            2 => {
                instructions.push(Instruction::Load((output.start + 2) as u8));
                instructions.push(Instruction::Store((latest_cached.start + offset) as u8));
            }
            3 => {
                instructions.push(Instruction::Load(output.start as u8));
                instructions.push(Instruction::Store((latest_cached.start + offset) as u8));
            }
            _ => {
                instructions.push(Instruction::Load((incoming.start + offset) as u8));
                instructions.push(Instruction::Store((latest_cached.start + offset) as u8));
            }
        }
    }

    instructions.push(Instruction::Load(layout.position_index()? as u8));
    instructions.push(Instruction::AddMemory(
        layout.position_increment_index()? as u8
    ));
    instructions.push(Instruction::Store(layout.position_index()? as u8));
    instructions.push(Instruction::Load((output.start + 2) as u8));
    instructions.push(Instruction::Halt);

    if instructions.len() > usize::from(u8::MAX) + 1 {
        return Err(VmError::InvalidConfig(format!(
            "Phase 12 decoding program instruction count {} exceeds the u8 pc horizon {}",
            instructions.len(),
            usize::from(u8::MAX) + 1
        )));
    }

    Ok(Program::new(instructions, layout.memory_size()?))
}

pub fn decoding_step_v2_program_with_initial_memory(
    layout: &Phase12DecodingLayout,
    initial_memory: Vec<i16>,
) -> Result<Program> {
    decoding_step_v2_template_program(layout)?.with_initial_memory(initial_memory)
}

pub fn derive_phase11_from_program_initial_state(
    program: &Program,
    step_index: usize,
) -> Result<Phase11DecodingState> {
    derive_phase11_state(program.initial_memory(), step_index)
}

pub fn derive_phase11_from_final_memory(
    final_memory: &[i16],
    step_index: usize,
) -> Result<Phase11DecodingState> {
    derive_phase11_state(final_memory, step_index)
}

pub fn derive_phase12_from_program_initial_state(
    program: &Program,
    step_index: usize,
) -> Result<Phase12DecodingState> {
    if step_index != 0 {
        return Err(VmError::InvalidConfig(format!(
            "Phase 12 standalone state derivation only supports the seed step, got step_index={step_index}"
        )));
    }
    let layout = infer_phase12_decoding_layout(program).ok_or_else(|| {
        VmError::InvalidConfig(
            "Phase 12 decoding state derivation requires a decoding_step_v2-family program"
                .to_string(),
        )
    })?;
    let view = derive_phase12_state_view(program.initial_memory(), &layout)?;
    let history_commitment = commit_phase12_history_seed(
        &view.layout_commitment,
        &program.initial_memory()[layout.kv_cache_range()?],
        layout.pair_width,
    );
    Ok(build_phase12_state(
        step_index,
        view,
        history_commitment,
        layout.rolling_kv_pairs,
    ))
}

pub fn derive_phase12_from_final_memory(
    final_memory: &[i16],
    step_index: usize,
    layout: &Phase12DecodingLayout,
) -> Result<Phase12DecodingState> {
    if step_index != 0 {
        return Err(VmError::InvalidConfig(format!(
            "Phase 12 standalone state derivation only supports the seed step, got step_index={step_index}"
        )));
    }
    let view = derive_phase12_state_view(final_memory, layout)?;
    let history_commitment = commit_phase12_history_seed(
        &view.layout_commitment,
        &final_memory[layout.kv_cache_range()?],
        layout.pair_width,
    );
    Ok(build_phase12_state(
        step_index,
        view,
        history_commitment,
        layout.rolling_kv_pairs,
    ))
}

pub fn phase11_prepare_decoding_chain(
    proofs: &[VanillaStarkExecutionProof],
) -> Result<Phase11DecodingChainManifest> {
    let first = proofs.first().ok_or_else(|| {
        VmError::InvalidConfig("proof-carrying decoding requires at least one proof".to_string())
    })?;
    if proofs.len() > MAX_DECODING_CHAIN_STEPS {
        return Err(VmError::InvalidConfig(format!(
            "decoding chain contains {} steps, exceeding the limit of {}",
            proofs.len(),
            MAX_DECODING_CHAIN_STEPS
        )));
    }
    if first.proof_backend != StarkProofBackend::Stwo {
        return Err(VmError::InvalidConfig(format!(
            "proof-carrying decoding requires `stwo` proofs, got `{}`",
            first.proof_backend
        )));
    }
    if !matches_decoding_step_v1_family(&first.claim.program) {
        return Err(VmError::InvalidConfig(
            "proof-carrying decoding requires decoding_step_v1-family programs".to_string(),
        ));
    }

    let mut steps = Vec::with_capacity(proofs.len());
    for (step_index, proof) in proofs.iter().cloned().enumerate() {
        if proof.proof_backend != StarkProofBackend::Stwo {
            return Err(VmError::InvalidConfig(format!(
                "decoding step {step_index} uses backend `{}`; expected `stwo`",
                proof.proof_backend
            )));
        }
        if proof.proof_backend_version != first.proof_backend_version {
            return Err(VmError::InvalidConfig(format!(
                "decoding step {step_index} uses backend version `{}`; expected `{}`",
                proof.proof_backend_version, first.proof_backend_version
            )));
        }
        if proof.claim.statement_version != first.claim.statement_version {
            return Err(VmError::InvalidConfig(format!(
                "decoding step {step_index} uses statement version `{}`; expected `{}`",
                proof.claim.statement_version, first.claim.statement_version
            )));
        }
        if proof.claim.semantic_scope != CLAIM_SEMANTIC_SCOPE_V1 {
            return Err(VmError::InvalidConfig(format!(
                "decoding step {step_index} uses semantic scope `{}`; expected `{}`",
                proof.claim.semantic_scope, CLAIM_SEMANTIC_SCOPE_V1
            )));
        }
        if !matches_decoding_step_v1_family(&proof.claim.program) {
            return Err(VmError::InvalidConfig(format!(
                "decoding step {step_index} is not a decoding_step_v1-family proof"
            )));
        }

        let from_state =
            derive_phase11_from_program_initial_state(&proof.claim.program, step_index)?;
        let to_state =
            derive_phase11_from_final_memory(&proof.claim.final_state.memory, step_index + 1)?;
        steps.push(Phase11DecodingStep {
            from_state,
            to_state,
            proof,
        });
    }

    validate_phase11_chain_steps(&steps)?;

    Ok(Phase11DecodingChainManifest {
        proof_backend: StarkProofBackend::Stwo,
        chain_version: STWO_DECODING_CHAIN_VERSION_PHASE11.to_string(),
        semantic_scope: STWO_DECODING_CHAIN_SCOPE_PHASE11.to_string(),
        proof_backend_version: first.proof_backend_version.clone(),
        statement_version: first.claim.statement_version.clone(),
        total_steps: steps.len(),
        steps,
    })
}

pub fn verify_phase11_decoding_chain(manifest: &Phase11DecodingChainManifest) -> Result<()> {
    if manifest.proof_backend != StarkProofBackend::Stwo {
        return Err(VmError::InvalidConfig(format!(
            "decoding chain backend `{}` is not `stwo`",
            manifest.proof_backend
        )));
    }
    if manifest.proof_backend_version != STWO_BACKEND_VERSION_PHASE11 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding proof backend version `{}`",
            manifest.proof_backend_version
        )));
    }
    if manifest.chain_version != STWO_DECODING_CHAIN_VERSION_PHASE11 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding chain version `{}`",
            manifest.chain_version
        )));
    }
    if manifest.semantic_scope != STWO_DECODING_CHAIN_SCOPE_PHASE11 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding chain semantic scope `{}`",
            manifest.semantic_scope
        )));
    }
    if manifest.steps.is_empty() {
        return Err(VmError::InvalidConfig(
            "decoding chain must contain at least one step".to_string(),
        ));
    }
    if manifest.steps.len() > MAX_DECODING_CHAIN_STEPS {
        return Err(VmError::InvalidConfig(format!(
            "decoding chain contains {} steps, exceeding the limit of {}",
            manifest.steps.len(),
            MAX_DECODING_CHAIN_STEPS
        )));
    }
    if manifest.total_steps != manifest.steps.len() {
        return Err(VmError::InvalidConfig(format!(
            "decoding chain total_steps={} does not match steps.len()={}",
            manifest.total_steps,
            manifest.steps.len()
        )));
    }
    for (step_index, step) in manifest.steps.iter().enumerate() {
        if !matches_decoding_step_v1_family(&step.proof.claim.program) {
            return Err(VmError::InvalidConfig(format!(
                "decoding step {step_index} is not a decoding_step_v1-family proof"
            )));
        }
        if step.proof.proof_backend != StarkProofBackend::Stwo {
            return Err(VmError::InvalidConfig(format!(
                "decoding step {step_index} proof backend `{}` is not `stwo`",
                step.proof.proof_backend
            )));
        }
        if step.proof.proof_backend_version != manifest.proof_backend_version {
            return Err(VmError::InvalidConfig(format!(
                "decoding step {step_index} proof backend version `{}` does not match manifest `{}`",
                step.proof.proof_backend_version, manifest.proof_backend_version
            )));
        }
        if step.proof.claim.statement_version != manifest.statement_version {
            return Err(VmError::InvalidConfig(format!(
                "decoding step {step_index} statement version `{}` does not match manifest `{}`",
                step.proof.claim.statement_version, manifest.statement_version
            )));
        }
        if step.proof.proof_backend_version != STWO_BACKEND_VERSION_PHASE11 {
            return Err(VmError::InvalidConfig(format!(
                "decoding step {step_index} proof backend version `{}` is not `{}`",
                step.proof.proof_backend_version, STWO_BACKEND_VERSION_PHASE11
            )));
        }

        let derived_from =
            derive_phase11_from_program_initial_state(&step.proof.claim.program, step_index)?;
        let derived_to =
            derive_phase11_from_final_memory(&step.proof.claim.final_state.memory, step_index + 1)?;
        if step.from_state != derived_from {
            return Err(VmError::InvalidConfig(format!(
                "decoding step {step_index} recorded from_state does not match the proof's initial state"
            )));
        }
        if step.to_state != derived_to {
            return Err(VmError::InvalidConfig(format!(
                "decoding step {step_index} recorded to_state does not match the proof's final state"
            )));
        }
    }

    validate_phase11_chain_steps(&manifest.steps)
}

pub fn verify_phase11_decoding_chain_with_proof_checks(
    manifest: &Phase11DecodingChainManifest,
) -> Result<()> {
    verify_phase11_decoding_chain(manifest)?;
    for (step_index, step) in manifest.steps.iter().enumerate() {
        if !verify_execution_stark(&step.proof)? {
            return Err(VmError::UnsupportedProof(format!(
                "decoding step {step_index} execution proof did not verify"
            )));
        }
    }
    Ok(())
}

pub fn phase12_prepare_decoding_chain(
    layout: &Phase12DecodingLayout,
    proofs: &[VanillaStarkExecutionProof],
) -> Result<Phase12DecodingChainManifest> {
    layout.validate()?;
    let latest_cached_range = layout.latest_cached_pair_range()?;
    let first = proofs.first().ok_or_else(|| {
        VmError::InvalidConfig("proof-carrying decoding requires at least one proof".to_string())
    })?;
    if proofs.len() > MAX_DECODING_CHAIN_STEPS {
        return Err(VmError::InvalidConfig(format!(
            "proof-carrying decoding contains {} steps, exceeding the limit of {}",
            proofs.len(),
            MAX_DECODING_CHAIN_STEPS
        )));
    }
    if first.proof_backend != StarkProofBackend::Stwo {
        return Err(VmError::InvalidConfig(format!(
            "proof-carrying decoding requires `stwo` proofs, got `{}`",
            first.proof_backend
        )));
    }
    if !matches_decoding_step_v2_family_with_layout(&first.claim.program, layout) {
        return Err(VmError::InvalidConfig(
            "proof-carrying decoding requires decoding_step_v2-family programs that match the manifest layout".to_string(),
        ));
    }

    let expected_layout_commitment = commit_phase12_layout(layout);
    let (shared_lookup_artifacts, artifact_refs) =
        build_phase12_shared_lookup_artifact_registry(proofs, &expected_layout_commitment)?;
    if shared_lookup_artifacts.len() > MAX_DECODING_SHARED_LOOKUP_ARTIFACTS {
        return Err(VmError::InvalidConfig(format!(
            "proof-carrying decoding contains {} shared lookup artifacts, exceeding the limit of {}",
            shared_lookup_artifacts.len(),
            MAX_DECODING_SHARED_LOOKUP_ARTIFACTS
        )));
    }
    let mut steps = Vec::with_capacity(proofs.len());
    let mut previous_history_commitment: Option<String> = None;
    let mut previous_history_length: Option<usize> = None;
    for (step_index, proof) in proofs.iter().cloned().enumerate() {
        if proof.proof_backend != StarkProofBackend::Stwo {
            return Err(VmError::InvalidConfig(format!(
                "decoding step {step_index} uses backend `{}`; expected `stwo`",
                proof.proof_backend
            )));
        }
        if proof.proof_backend_version != first.proof_backend_version {
            return Err(VmError::InvalidConfig(format!(
                "decoding step {step_index} uses backend version `{}`; expected `{}`",
                proof.proof_backend_version, first.proof_backend_version
            )));
        }
        if proof.claim.statement_version != first.claim.statement_version {
            return Err(VmError::InvalidConfig(format!(
                "decoding step {step_index} uses statement version `{}`; expected `{}`",
                proof.claim.statement_version, first.claim.statement_version
            )));
        }
        if proof.claim.semantic_scope != first.claim.semantic_scope {
            return Err(VmError::InvalidConfig(format!(
                "decoding step {step_index} uses semantic scope `{}`; expected `{}`",
                proof.claim.semantic_scope, first.claim.semantic_scope
            )));
        }
        if !matches_decoding_step_v2_family_with_layout(&proof.claim.program, layout) {
            return Err(VmError::InvalidConfig(format!(
                "decoding step {step_index} is not a decoding_step_v2-family proof for the manifest layout"
            )));
        }

        let from_view = derive_phase12_state_view(proof.claim.program.initial_memory(), layout)?;
        if from_view.layout_commitment != expected_layout_commitment {
            return Err(VmError::InvalidConfig(format!(
                "decoding step {step_index} initial state does not match the manifest layout commitment"
            )));
        }
        let (from_history_commitment, from_history_length) =
            match (previous_history_commitment.clone(), previous_history_length) {
                (Some(commitment), Some(length)) => (commitment, length),
                _ => (
                    commit_phase12_history_seed(
                        &expected_layout_commitment,
                        &proof.claim.program.initial_memory()[layout.kv_cache_range()?],
                        layout.pair_width,
                    ),
                    layout.rolling_kv_pairs,
                ),
            };
        let from_state = build_phase12_state(
            step_index,
            from_view,
            from_history_commitment.clone(),
            from_history_length,
        );

        let to_view = derive_phase12_final_state_view_from_proof(&proof, layout)?;
        if to_view.layout_commitment != expected_layout_commitment {
            return Err(VmError::InvalidConfig(format!(
                "decoding step {step_index} final state does not match the manifest layout commitment"
            )));
        }
        let to_history_length = from_history_length.checked_add(1).ok_or_else(|| {
            VmError::InvalidConfig(format!(
                "decoding step {step_index} history length {from_history_length} cannot be incremented"
            ))
        })?;
        let to_history_commitment = advance_phase12_history_commitment(
            &expected_layout_commitment,
            &from_history_commitment,
            &proof.claim.final_state.memory[latest_cached_range.clone()],
            to_history_length,
        );
        let to_state = build_phase12_state(
            step_index + 1,
            to_view,
            to_history_commitment.clone(),
            to_history_length,
        );

        previous_history_commitment = Some(to_history_commitment);
        previous_history_length = Some(to_history_length);
        steps.push(Phase12DecodingStep {
            from_state,
            to_state,
            shared_lookup_artifact_commitment: artifact_refs[step_index].clone(),
            proof,
        });
    }

    validate_phase12_chain_steps(layout, &steps)?;

    Ok(Phase12DecodingChainManifest {
        proof_backend: StarkProofBackend::Stwo,
        chain_version: STWO_DECODING_CHAIN_VERSION_PHASE12.to_string(),
        semantic_scope: STWO_DECODING_CHAIN_SCOPE_PHASE12.to_string(),
        proof_backend_version: first.proof_backend_version.clone(),
        statement_version: first.claim.statement_version.clone(),
        layout: layout.clone(),
        total_steps: steps.len(),
        shared_lookup_artifacts,
        steps,
    })
}

pub fn verify_phase12_decoding_chain(manifest: &Phase12DecodingChainManifest) -> Result<()> {
    manifest.layout.validate()?;
    let expected_layout_commitment = commit_phase12_layout(&manifest.layout);
    let latest_cached_range = manifest.layout.latest_cached_pair_range()?;
    if manifest.proof_backend != StarkProofBackend::Stwo {
        return Err(VmError::InvalidConfig(format!(
            "decoding chain backend `{}` is not `stwo`",
            manifest.proof_backend
        )));
    }
    if manifest.chain_version != STWO_DECODING_CHAIN_VERSION_PHASE12 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding chain version `{}`",
            manifest.chain_version
        )));
    }
    if manifest.semantic_scope != STWO_DECODING_CHAIN_SCOPE_PHASE12 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding chain semantic scope `{}`",
            manifest.semantic_scope
        )));
    }
    if manifest.proof_backend_version != crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding proof backend version `{}` (expected `{}`)",
            manifest.proof_backend_version,
            crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12
        )));
    }
    if manifest.steps.is_empty() {
        return Err(VmError::InvalidConfig(
            "decoding chain must contain at least one step".to_string(),
        ));
    }
    if manifest.steps.len() > MAX_DECODING_CHAIN_STEPS {
        return Err(VmError::InvalidConfig(format!(
            "decoding chain contains {} steps, exceeding the limit of {}",
            manifest.steps.len(),
            MAX_DECODING_CHAIN_STEPS
        )));
    }
    if manifest.total_steps != manifest.steps.len() {
        return Err(VmError::InvalidConfig(format!(
            "decoding chain total_steps={} does not match steps.len()={}",
            manifest.total_steps,
            manifest.steps.len()
        )));
    }
    if manifest.shared_lookup_artifacts.is_empty() {
        return Err(VmError::InvalidConfig(
            "decoding chain must contain at least one shared lookup artifact".to_string(),
        ));
    }
    if manifest.shared_lookup_artifacts.len() > MAX_DECODING_SHARED_LOOKUP_ARTIFACTS {
        return Err(VmError::InvalidConfig(format!(
            "decoding chain contains {} shared lookup artifacts, exceeding the limit of {}",
            manifest.shared_lookup_artifacts.len(),
            MAX_DECODING_SHARED_LOOKUP_ARTIFACTS
        )));
    }
    if manifest.shared_lookup_artifacts.len() > manifest.steps.len() {
        return Err(VmError::InvalidConfig(format!(
            "decoding chain contains {} shared lookup artifacts for only {} steps",
            manifest.shared_lookup_artifacts.len(),
            manifest.steps.len()
        )));
    }
    let referenced_artifacts: HashSet<String> = manifest
        .steps
        .iter()
        .map(|step| step.shared_lookup_artifact_commitment.clone())
        .collect();
    let shared_lookup_artifacts = build_phase12_shared_lookup_artifact_index(
        &manifest.shared_lookup_artifacts,
        &referenced_artifacts,
        &manifest.layout,
        &expected_layout_commitment,
        manifest.layout.lookup_range()?.len(),
        "decoding chain shared lookup",
    )?;
    let expected_step_semantic_scope = CLAIM_SEMANTIC_SCOPE_V1;

    for (step_index, step) in manifest.steps.iter().enumerate() {
        if !matches_decoding_step_v2_family_with_layout(&step.proof.claim.program, &manifest.layout)
        {
            return Err(VmError::InvalidConfig(format!(
                "decoding step {step_index} is not a decoding_step_v2-family proof for the manifest layout"
            )));
        }
        if step.proof.proof_backend != StarkProofBackend::Stwo {
            return Err(VmError::InvalidConfig(format!(
                "decoding step {step_index} proof backend `{}` is not `stwo`",
                step.proof.proof_backend
            )));
        }
        if step.proof.proof_backend_version != crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12 {
            return Err(VmError::InvalidConfig(format!(
                "decoding step {step_index} proof backend version `{}` does not match the supported Phase 12 version `{}`",
                step.proof.proof_backend_version,
                crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12
            )));
        }
        if step.proof.proof_backend_version != manifest.proof_backend_version {
            return Err(VmError::InvalidConfig(format!(
                "decoding step {step_index} proof backend version `{}` does not match manifest `{}`",
                step.proof.proof_backend_version, manifest.proof_backend_version
            )));
        }
        if step.proof.claim.statement_version != manifest.statement_version {
            return Err(VmError::InvalidConfig(format!(
                "decoding step {step_index} statement version `{}` does not match manifest `{}`",
                step.proof.claim.statement_version, manifest.statement_version
            )));
        }
        if step.proof.claim.semantic_scope != expected_step_semantic_scope {
            return Err(VmError::InvalidConfig(format!(
                "decoding step {step_index} semantic scope `{}` does not match expected `{}`",
                step.proof.claim.semantic_scope, expected_step_semantic_scope
            )));
        }
        let shared_lookup_artifact = shared_lookup_artifact_by_commitment(
            &shared_lookup_artifacts,
            &step.shared_lookup_artifact_commitment,
        )?;
        let proof_artifact = phase12_shared_lookup_artifact_from_proof_payload(
            &step.proof,
            &expected_layout_commitment,
        )?
        .ok_or_else(|| {
            VmError::InvalidConfig(format!(
                "decoding step {step_index} is missing its Phase 12 shared lookup artifact payload"
            ))
        })?;
        if &proof_artifact != shared_lookup_artifact {
            return Err(VmError::InvalidConfig(format!(
                "decoding step {step_index} shared lookup artifact `{}` does not match the proof payload",
                step.shared_lookup_artifact_commitment
            )));
        }

        let derived_from =
            derive_phase12_state_view(step.proof.claim.program.initial_memory(), &manifest.layout)?;
        let derived_to = derive_phase12_final_state_view_from_proof(&step.proof, &manifest.layout)?;
        if shared_lookup_artifact.lookup_rows_commitment != derived_to.lookup_rows_commitment {
            return Err(VmError::InvalidConfig(format!(
                "decoding step {step_index} shared lookup artifact `{}` does not match the proof's final-state lookup rows",
                step.shared_lookup_artifact_commitment
            )));
        }
        let (expected_history_commitment, expected_history_length) = if step_index == 0 {
            (
                commit_phase12_history_seed(
                    &expected_layout_commitment,
                    &step.proof.claim.program.initial_memory()[manifest.layout.kv_cache_range()?],
                    manifest.layout.pair_width,
                ),
                manifest.layout.rolling_kv_pairs,
            )
        } else {
            (
                manifest.steps[step_index - 1]
                    .to_state
                    .kv_history_commitment
                    .clone(),
                manifest.steps[step_index - 1].to_state.kv_history_length,
            )
        };
        let expected_from = build_phase12_state(
            step_index,
            derived_from,
            expected_history_commitment.clone(),
            expected_history_length,
        );
        let next_history_length = expected_history_length.checked_add(1).ok_or_else(|| {
            VmError::InvalidConfig(format!(
                "decoding step {step_index} history length {expected_history_length} cannot be incremented"
            ))
        })?;
        let next_history_commitment = advance_phase12_history_commitment(
            &expected_layout_commitment,
            &expected_history_commitment,
            &step.proof.claim.final_state.memory[latest_cached_range.clone()],
            next_history_length,
        );
        let expected_to = build_phase12_state(
            step_index + 1,
            derived_to,
            next_history_commitment,
            next_history_length,
        );
        if step.from_state != expected_from {
            return Err(VmError::InvalidConfig(format!(
                "decoding step {step_index} recorded from_state does not match the proof's initial state"
            )));
        }
        if step.to_state != expected_to {
            return Err(VmError::InvalidConfig(format!(
                "decoding step {step_index} recorded to_state does not match the proof's final state"
            )));
        }
    }

    validate_phase12_chain_steps(&manifest.layout, &manifest.steps)
}

pub fn verify_phase12_decoding_chain_with_proof_checks(
    manifest: &Phase12DecodingChainManifest,
) -> Result<()> {
    verify_phase12_decoding_chain(manifest)?;
    for (step_index, step) in manifest.steps.iter().enumerate() {
        if !verify_execution_stark(&step.proof)? {
            return Err(VmError::UnsupportedProof(format!(
                "decoding step {step_index} execution proof did not verify"
            )));
        }
    }
    Ok(())
}

pub fn phase30_prepare_decoding_step_proof_envelope_manifest(
    chain: &Phase12DecodingChainManifest,
) -> Result<Phase30DecodingStepProofEnvelopeManifest> {
    verify_phase12_decoding_chain(chain)?;
    let layout_commitment = commit_phase12_layout(&chain.layout);
    let source_chain_commitment = commit_phase12_decoding_chain_for_step_envelopes(chain)?;
    let artifact_index = chain
        .shared_lookup_artifacts
        .iter()
        .map(|artifact| (artifact.artifact_commitment.as_str(), artifact))
        .collect::<HashMap<_, _>>();
    let envelopes = chain
        .steps
        .iter()
        .enumerate()
        .map(|(step_index, step)| {
            let artifact = artifact_index
                .get(step.shared_lookup_artifact_commitment.as_str())
                .copied()
                .ok_or_else(|| {
                    VmError::InvalidConfig(format!(
                        "decoding step {step_index} shared lookup artifact `{}` is not present in the Phase 12 registry",
                        step.shared_lookup_artifact_commitment
                    ))
                })?;
            build_phase30_decoding_step_proof_envelope(
                step_index,
                step,
                &layout_commitment,
                &source_chain_commitment,
                artifact,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let step_envelopes_commitment = commit_phase30_step_envelope_list(&envelopes);
    let (chain_start_boundary_commitment, chain_end_boundary_commitment) =
        phase30_chain_boundary_pair(&envelopes)?;

    let manifest = Phase30DecodingStepProofEnvelopeManifest {
        proof_backend: StarkProofBackend::Stwo,
        manifest_version: STWO_DECODING_STEP_ENVELOPE_MANIFEST_VERSION_PHASE30.to_string(),
        semantic_scope: STWO_DECODING_STEP_ENVELOPE_MANIFEST_SCOPE_PHASE30.to_string(),
        proof_backend_version: chain.proof_backend_version.clone(),
        statement_version: chain.statement_version.clone(),
        source_chain_version: chain.chain_version.clone(),
        source_chain_semantic_scope: chain.semantic_scope.clone(),
        source_chain_commitment,
        layout: chain.layout.clone(),
        total_steps: envelopes.len(),
        chain_start_boundary_commitment,
        chain_end_boundary_commitment,
        step_envelopes_commitment,
        envelopes,
    };
    verify_phase30_decoding_step_proof_envelope_manifest(&manifest)?;
    Ok(manifest)
}

pub fn verify_phase30_decoding_step_proof_envelope_manifest(
    manifest: &Phase30DecodingStepProofEnvelopeManifest,
) -> Result<()> {
    manifest.layout.validate()?;
    let expected_layout_commitment = commit_phase12_layout(&manifest.layout);
    if manifest.proof_backend != StarkProofBackend::Stwo {
        return Err(VmError::InvalidConfig(format!(
            "decoding step envelope manifest backend `{}` is not `stwo`",
            manifest.proof_backend
        )));
    }
    if manifest.manifest_version != STWO_DECODING_STEP_ENVELOPE_MANIFEST_VERSION_PHASE30 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding step envelope manifest version `{}`",
            manifest.manifest_version
        )));
    }
    if manifest.semantic_scope != STWO_DECODING_STEP_ENVELOPE_MANIFEST_SCOPE_PHASE30 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding step envelope manifest scope `{}`",
            manifest.semantic_scope
        )));
    }
    if manifest.source_chain_version != STWO_DECODING_CHAIN_VERSION_PHASE12 {
        return Err(VmError::InvalidConfig(format!(
            "decoding step envelope manifest source chain version `{}` is not Phase 12",
            manifest.source_chain_version
        )));
    }
    if manifest.source_chain_semantic_scope != STWO_DECODING_CHAIN_SCOPE_PHASE12 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding step envelope manifest source chain scope `{}`",
            manifest.source_chain_semantic_scope
        )));
    }
    if manifest.proof_backend_version != crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12 {
        return Err(VmError::InvalidConfig(format!(
            "decoding step envelope manifest backend version `{}` is not `{}`",
            manifest.proof_backend_version,
            crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12
        )));
    }
    if manifest.statement_version != crate::proof::CLAIM_STATEMENT_VERSION_V1 {
        return Err(VmError::InvalidConfig(format!(
            "decoding step envelope manifest statement version `{}` is not `{}`",
            manifest.statement_version,
            crate::proof::CLAIM_STATEMENT_VERSION_V1
        )));
    }
    if manifest.source_chain_commitment.is_empty() {
        return Err(VmError::InvalidConfig(
            "decoding step envelope manifest source_chain_commitment must not be empty".to_string(),
        ));
    }
    ensure_phase30_manifest_cardinality_counts(manifest.envelopes.len(), manifest.total_steps)?;
    let expected_list_commitment = commit_phase30_step_envelope_list(&manifest.envelopes);
    if manifest.step_envelopes_commitment != expected_list_commitment {
        return Err(VmError::InvalidConfig(
            "decoding step envelope manifest step_envelopes_commitment does not match its envelopes"
                .to_string(),
        ));
    }
    let (expected_start, expected_end) = phase30_chain_boundary_pair(&manifest.envelopes)?;
    if !phase30_manifest_boundary_pair_matches(
        &manifest.chain_start_boundary_commitment,
        &expected_start,
        &manifest.chain_end_boundary_commitment,
        &expected_end,
    ) {
        if manifest.chain_start_boundary_commitment != expected_start {
            return Err(VmError::InvalidConfig(
                "decoding step envelope manifest start boundary does not match the first envelope"
                    .to_string(),
            ));
        }
        return Err(VmError::InvalidConfig(
            "decoding step envelope manifest end boundary does not match the final envelope"
                .to_string(),
        ));
    }

    for (index, envelope) in manifest.envelopes.iter().enumerate() {
        if envelope.envelope_version != STWO_DECODING_STEP_ENVELOPE_VERSION_PHASE30 {
            return Err(VmError::InvalidConfig(format!(
                "decoding step envelope {index} has unsupported version `{}`",
                envelope.envelope_version
            )));
        }
        if envelope.semantic_scope != STWO_DECODING_STEP_ENVELOPE_SCOPE_PHASE30 {
            return Err(VmError::InvalidConfig(format!(
                "decoding step envelope {index} has unsupported scope `{}`",
                envelope.semantic_scope
            )));
        }
        if envelope.relation != STWO_DECODING_STEP_ENVELOPE_RELATION_PHASE30 {
            return Err(VmError::InvalidConfig(format!(
                "decoding step envelope {index} has unsupported relation `{}`",
                envelope.relation
            )));
        }
        if envelope.proof_backend != StarkProofBackend::Stwo {
            return Err(VmError::InvalidConfig(format!(
                "decoding step envelope {index} backend `{}` is not `stwo`",
                envelope.proof_backend
            )));
        }
        if envelope.proof_backend_version != manifest.proof_backend_version {
            return Err(VmError::InvalidConfig(format!(
                "decoding step envelope {index} backend version `{}` does not match manifest `{}`",
                envelope.proof_backend_version, manifest.proof_backend_version
            )));
        }
        if envelope.statement_version != manifest.statement_version {
            return Err(VmError::InvalidConfig(format!(
                "decoding step envelope {index} statement version `{}` does not match manifest `{}`",
                envelope.statement_version, manifest.statement_version
            )));
        }
        if envelope.layout_commitment != expected_layout_commitment {
            return Err(VmError::InvalidConfig(format!(
                "decoding step envelope {index} layout commitment does not match the manifest layout"
            )));
        }
        if envelope.source_chain_commitment != manifest.source_chain_commitment {
            return Err(VmError::InvalidConfig(format!(
                "decoding step envelope {index} source_chain_commitment does not match the manifest"
            )));
        }
        if !phase30_step_envelope_index_matches(index, envelope.step_index) {
            return Err(VmError::InvalidConfig(format!(
                "decoding step envelope {index} records step_index={}",
                envelope.step_index
            )));
        }
        if envelope.input_boundary_commitment.is_empty()
            || envelope.output_boundary_commitment.is_empty()
            || envelope.input_lookup_rows_commitment.is_empty()
            || envelope.output_lookup_rows_commitment.is_empty()
            || envelope.source_chain_commitment.is_empty()
            || envelope.shared_lookup_artifact_commitment.is_empty()
            || envelope.static_lookup_registry_commitment.is_empty()
            || envelope.proof_commitment.is_empty()
        {
            return Err(VmError::InvalidConfig(format!(
                "decoding step envelope {index} contains an empty boundary or proof commitment"
            )));
        }
        let expected_envelope_commitment = commit_phase30_step_envelope(envelope);
        if envelope.envelope_commitment != expected_envelope_commitment {
            return Err(VmError::InvalidConfig(format!(
                "decoding step envelope {index} commitment does not match its serialized boundary metadata"
            )));
        }
        if index > 0 {
            let previous = &manifest.envelopes[index - 1];
            if !phase30_step_envelope_link_matches(
                &previous.output_boundary_commitment,
                &envelope.input_boundary_commitment,
            ) {
                return Err(VmError::InvalidConfig(format!(
                    "decoding step envelope link {} -> {} does not preserve the carried output/input boundary",
                    index - 1,
                    index
                )));
            }
        }
    }
    Ok(())
}

fn phase30_manifest_cardinality_counts_are_valid(
    envelope_count: usize,
    total_steps: usize,
) -> bool {
    envelope_count > 0
        && envelope_count <= MAX_DECODING_CHAIN_STEPS
        && total_steps == envelope_count
}

fn phase30_manifest_boundary_pair_matches(
    chain_start_boundary_commitment: &str,
    first_input_boundary_commitment: &str,
    chain_end_boundary_commitment: &str,
    last_output_boundary_commitment: &str,
) -> bool {
    chain_start_boundary_commitment == first_input_boundary_commitment
        && chain_end_boundary_commitment == last_output_boundary_commitment
}

fn phase30_step_envelope_index_matches(index: usize, recorded_step_index: usize) -> bool {
    index == recorded_step_index
}

fn phase30_step_envelope_link_matches(
    previous_output_boundary_commitment: &str,
    current_input_boundary_commitment: &str,
) -> bool {
    previous_output_boundary_commitment == current_input_boundary_commitment
}

fn ensure_phase30_manifest_cardinality_counts(
    envelope_count: usize,
    total_steps: usize,
) -> Result<()> {
    if phase30_manifest_cardinality_counts_are_valid(envelope_count, total_steps) {
        return Ok(());
    }
    if envelope_count == 0 {
        return Err(VmError::InvalidConfig(
            "decoding step envelope manifest must contain at least one envelope".to_string(),
        ));
    }
    if envelope_count > MAX_DECODING_CHAIN_STEPS {
        return Err(VmError::InvalidConfig(format!(
            "decoding step envelope manifest contains {} envelopes, exceeding the limit of {}",
            envelope_count, MAX_DECODING_CHAIN_STEPS
        )));
    }
    if total_steps != envelope_count {
        return Err(VmError::InvalidConfig(format!(
            "decoding step envelope manifest total_steps={} does not match envelopes.len()={}",
            total_steps, envelope_count
        )));
    }
    unreachable!("invalid Phase 30 cardinality must match one of the explicit error branches")
}

pub fn verify_phase30_decoding_step_proof_envelope_manifest_against_chain(
    manifest: &Phase30DecodingStepProofEnvelopeManifest,
    chain: &Phase12DecodingChainManifest,
) -> Result<()> {
    let expected = phase30_prepare_decoding_step_proof_envelope_manifest(chain)?;
    if manifest != &expected {
        return Err(VmError::InvalidConfig(
            "decoding step envelope manifest does not match the derived Phase 12 chain".to_string(),
        ));
    }
    Ok(())
}

pub fn verify_phase13_decoding_layout_matrix(
    manifest: &Phase13DecodingLayoutMatrixManifest,
) -> Result<()> {
    if manifest.proof_backend != StarkProofBackend::Stwo {
        return Err(VmError::InvalidConfig(format!(
            "decoding layout matrix backend `{}` is not `stwo`",
            manifest.proof_backend
        )));
    }
    if manifest.matrix_version != STWO_DECODING_LAYOUT_MATRIX_VERSION_PHASE13 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding layout matrix version `{}`",
            manifest.matrix_version
        )));
    }
    if manifest.semantic_scope != STWO_DECODING_LAYOUT_MATRIX_SCOPE_PHASE13 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding layout matrix semantic scope `{}`",
            manifest.semantic_scope
        )));
    }
    if manifest.proof_backend_version != crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding layout matrix proof backend version `{}` (expected `{}`)",
            manifest.proof_backend_version,
            crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12
        )));
    }
    if manifest.statement_version != crate::proof::CLAIM_STATEMENT_VERSION_V1 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding layout matrix statement version `{}`",
            manifest.statement_version
        )));
    }
    if manifest.chains.is_empty() {
        return Err(VmError::InvalidConfig(
            "decoding layout matrix must contain at least one chain".to_string(),
        ));
    }
    if manifest.total_layouts != manifest.chains.len() {
        return Err(VmError::InvalidConfig(format!(
            "decoding layout matrix total_layouts={} does not match chains.len()={}",
            manifest.total_layouts,
            manifest.chains.len()
        )));
    }
    let derived_total_steps: usize = manifest.chains.iter().map(|chain| chain.total_steps).sum();
    if manifest.total_steps != derived_total_steps {
        return Err(VmError::InvalidConfig(format!(
            "decoding layout matrix total_steps={} does not match derived total_steps={}",
            manifest.total_steps, derived_total_steps
        )));
    }
    for (layout_index, chain) in manifest.chains.iter().enumerate() {
        if chain.proof_backend_version != manifest.proof_backend_version {
            return Err(VmError::InvalidConfig(format!(
                "decoding layout matrix chain {layout_index} proof backend version `{}` does not match matrix `{}`",
                chain.proof_backend_version, manifest.proof_backend_version
            )));
        }
        if chain.statement_version != manifest.statement_version {
            return Err(VmError::InvalidConfig(format!(
                "decoding layout matrix chain {layout_index} statement version `{}` does not match matrix `{}`",
                chain.statement_version, manifest.statement_version
            )));
        }
        verify_phase12_decoding_chain(chain)?;
    }
    Ok(())
}

pub fn verify_phase13_decoding_layout_matrix_with_proof_checks(
    manifest: &Phase13DecodingLayoutMatrixManifest,
) -> Result<()> {
    verify_phase13_decoding_layout_matrix(manifest)?;
    for (layout_index, chain) in manifest.chains.iter().enumerate() {
        verify_phase12_decoding_chain_with_proof_checks(chain).map_err(|error| {
            VmError::UnsupportedProof(format!(
                "decoding layout matrix chain {layout_index} failed verification: {error}"
            ))
        })?;
    }
    Ok(())
}

pub fn phase14_prepare_decoding_chain(
    chain: &Phase12DecodingChainManifest,
) -> Result<Phase14DecodingChainManifest> {
    verify_phase12_decoding_chain(chain)?;
    if chain.statement_version != crate::proof::CLAIM_STATEMENT_VERSION_V1 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported chunked decoding statement version `{}`",
            chain.statement_version
        )));
    }

    let layout = &chain.layout;
    let expected_layout_commitment = commit_phase12_layout(layout);
    let kv_cache_range = layout.kv_cache_range()?;
    let latest_cached_range = layout.latest_cached_pair_range()?;
    let mut steps = Vec::with_capacity(chain.steps.len());
    let mut accumulator: Option<Phase14HistoryAccumulator> = None;

    for (step_index, step) in chain.steps.iter().enumerate() {
        let from_view =
            derive_phase12_state_view(step.proof.claim.program.initial_memory(), layout)?;
        if from_view.layout_commitment != expected_layout_commitment {
            return Err(VmError::InvalidConfig(format!(
                "Phase 14 decoding step {step_index} initial state does not match the manifest layout commitment"
            )));
        }
        let current = accumulator.clone().unwrap_or_else(|| {
            seed_phase14_history(
                &expected_layout_commitment,
                &step.proof.claim.program.initial_memory()[kv_cache_range.clone()],
                &from_view.lookup_rows_commitment,
                layout.pair_width,
            )
        });
        let from_state = build_phase14_state(step_index, from_view, &current);

        let to_view = derive_phase12_final_state_view_from_proof(&step.proof, layout)?;
        if to_view.layout_commitment != expected_layout_commitment {
            return Err(VmError::InvalidConfig(format!(
                "Phase 14 decoding step {step_index} final state does not match the manifest layout commitment"
            )));
        }
        let next = advance_phase14_history(
            &expected_layout_commitment,
            &current,
            &step.proof.claim.final_state.memory[latest_cached_range.clone()],
            &to_view.lookup_rows_commitment,
            layout.pair_width,
        )?;
        let to_state = build_phase14_state(step_index + 1, to_view, &next);
        steps.push(Phase14DecodingStep {
            from_state,
            to_state,
            shared_lookup_artifact_commitment: chain.steps[step_index]
                .shared_lookup_artifact_commitment
                .clone(),
            proof: step.proof.clone(),
        });
        accumulator = Some(next);
    }

    validate_phase14_chain_steps(&chain.layout, PHASE14_HISTORY_CHUNK_PAIRS, &steps)?;

    Ok(Phase14DecodingChainManifest {
        proof_backend: StarkProofBackend::Stwo,
        chain_version: STWO_DECODING_CHAIN_VERSION_PHASE14.to_string(),
        semantic_scope: STWO_DECODING_CHAIN_SCOPE_PHASE14.to_string(),
        proof_backend_version: crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12.to_string(),
        statement_version: chain.statement_version.clone(),
        layout: chain.layout.clone(),
        total_steps: steps.len(),
        history_chunk_pairs: PHASE14_HISTORY_CHUNK_PAIRS,
        shared_lookup_artifacts: chain.shared_lookup_artifacts.clone(),
        steps,
    })
}

pub fn verify_phase14_decoding_chain(manifest: &Phase14DecodingChainManifest) -> Result<()> {
    manifest.layout.validate()?;
    let expected_layout_commitment = commit_phase12_layout(&manifest.layout);
    let kv_cache_range = manifest.layout.kv_cache_range()?;
    let latest_cached_range = manifest.layout.latest_cached_pair_range()?;
    if manifest.proof_backend != StarkProofBackend::Stwo {
        return Err(VmError::InvalidConfig(format!(
            "chunked decoding chain backend `{}` is not `stwo`",
            manifest.proof_backend
        )));
    }
    if manifest.chain_version != STWO_DECODING_CHAIN_VERSION_PHASE14 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported chunked decoding chain version `{}`",
            manifest.chain_version
        )));
    }
    if manifest.semantic_scope != STWO_DECODING_CHAIN_SCOPE_PHASE14 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported chunked decoding semantic scope `{}`",
            manifest.semantic_scope
        )));
    }
    if manifest.proof_backend_version != crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported chunked decoding proof backend version `{}` (expected `{}`)",
            manifest.proof_backend_version,
            crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12
        )));
    }
    if manifest.statement_version != crate::proof::CLAIM_STATEMENT_VERSION_V1 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported chunked decoding statement version `{}`",
            manifest.statement_version
        )));
    }
    if manifest.history_chunk_pairs != PHASE14_HISTORY_CHUNK_PAIRS {
        return Err(VmError::InvalidConfig(format!(
            "unsupported chunked decoding history_chunk_pairs={} (expected {})",
            manifest.history_chunk_pairs, PHASE14_HISTORY_CHUNK_PAIRS
        )));
    }
    if manifest.steps.is_empty() {
        return Err(VmError::InvalidConfig(
            "chunked decoding chain must contain at least one step".to_string(),
        ));
    }
    if manifest.steps.len() > MAX_DECODING_CHAIN_STEPS {
        return Err(VmError::InvalidConfig(format!(
            "chunked decoding chain contains {} steps, exceeding the limit of {}",
            manifest.steps.len(),
            MAX_DECODING_CHAIN_STEPS
        )));
    }
    if manifest.total_steps != manifest.steps.len() {
        return Err(VmError::InvalidConfig(format!(
            "chunked decoding chain total_steps={} does not match steps.len()={}",
            manifest.total_steps,
            manifest.steps.len()
        )));
    }
    if manifest.shared_lookup_artifacts.is_empty() {
        return Err(VmError::InvalidConfig(
            "chunked decoding chain must contain at least one shared lookup artifact".to_string(),
        ));
    }
    if manifest.shared_lookup_artifacts.len() > MAX_DECODING_SHARED_LOOKUP_ARTIFACTS {
        return Err(VmError::InvalidConfig(format!(
            "chunked decoding chain contains {} shared lookup artifacts, exceeding the limit of {}",
            manifest.shared_lookup_artifacts.len(),
            MAX_DECODING_SHARED_LOOKUP_ARTIFACTS
        )));
    }
    if manifest.shared_lookup_artifacts.len() > manifest.steps.len() {
        return Err(VmError::InvalidConfig(format!(
            "chunked decoding chain contains {} shared lookup artifacts for only {} steps",
            manifest.shared_lookup_artifacts.len(),
            manifest.steps.len()
        )));
    }
    let referenced_artifacts: HashSet<String> = manifest
        .steps
        .iter()
        .map(|step| step.shared_lookup_artifact_commitment.clone())
        .collect();
    let shared_lookup_artifacts = build_phase12_shared_lookup_artifact_index(
        &manifest.shared_lookup_artifacts,
        &referenced_artifacts,
        &manifest.layout,
        &expected_layout_commitment,
        manifest.layout.lookup_range()?.len(),
        "chunked decoding shared lookup",
    )?;
    let expected_step_semantic_scope = CLAIM_SEMANTIC_SCOPE_V1;

    let mut accumulator: Option<Phase14HistoryAccumulator> = None;
    for (step_index, step) in manifest.steps.iter().enumerate() {
        if !matches_decoding_step_v2_family_with_layout(&step.proof.claim.program, &manifest.layout)
        {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding step {step_index} is not a decoding_step_v2-family proof for the manifest layout"
            )));
        }
        if step.proof.proof_backend != StarkProofBackend::Stwo {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding step {step_index} proof backend `{}` is not `stwo`",
                step.proof.proof_backend
            )));
        }
        if step.proof.proof_backend_version != crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12 {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding step {step_index} proof backend version `{}` is not `{}`",
                step.proof.proof_backend_version,
                crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12
            )));
        }
        if step.proof.claim.statement_version != manifest.statement_version {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding step {step_index} statement version `{}` does not match manifest `{}`",
                step.proof.claim.statement_version, manifest.statement_version
            )));
        }
        if step.proof.claim.semantic_scope != expected_step_semantic_scope {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding step {step_index} semantic scope `{}` does not match expected `{}`",
                step.proof.claim.semantic_scope, expected_step_semantic_scope
            )));
        }
        let shared_lookup_artifact = shared_lookup_artifact_by_commitment(
            &shared_lookup_artifacts,
            &step.shared_lookup_artifact_commitment,
        )?;
        let proof_artifact =
            phase12_shared_lookup_artifact_from_proof_payload(&step.proof, &expected_layout_commitment)?
                .ok_or_else(|| {
                    VmError::InvalidConfig(format!(
                        "chunked decoding step {step_index} is missing its Phase 12 shared lookup artifact payload"
                    ))
                })?;
        if &proof_artifact != shared_lookup_artifact {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding step {step_index} shared lookup artifact `{}` does not match the proof payload",
                step.shared_lookup_artifact_commitment
            )));
        }

        let from_view =
            derive_phase12_state_view(step.proof.claim.program.initial_memory(), &manifest.layout)?;
        if from_view.layout_commitment != expected_layout_commitment {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding step {step_index} initial state does not match the manifest layout commitment"
            )));
        }
        let current = accumulator.clone().unwrap_or_else(|| {
            seed_phase14_history(
                &expected_layout_commitment,
                &step.proof.claim.program.initial_memory()[kv_cache_range.clone()],
                &from_view.lookup_rows_commitment,
                manifest.layout.pair_width,
            )
        });
        let expected_from = build_phase14_state(step_index, from_view, &current);
        if step.from_state != expected_from {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding step {step_index} recorded from_state does not match the proof's initial state"
            )));
        }

        let to_view = derive_phase12_final_state_view_from_proof(&step.proof, &manifest.layout)?;
        if shared_lookup_artifact.lookup_rows_commitment != to_view.lookup_rows_commitment {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding step {step_index} shared lookup artifact `{}` does not match the proof's final-state lookup rows",
                step.shared_lookup_artifact_commitment
            )));
        }
        if to_view.layout_commitment != expected_layout_commitment {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding step {step_index} final state does not match the manifest layout commitment"
            )));
        }
        let next = advance_phase14_history(
            &expected_layout_commitment,
            &current,
            &step.proof.claim.final_state.memory[latest_cached_range.clone()],
            &to_view.lookup_rows_commitment,
            manifest.layout.pair_width,
        )?;
        let expected_to = build_phase14_state(step_index + 1, to_view, &next);
        if step.to_state != expected_to {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding step {step_index} recorded to_state does not match the proof's final state"
            )));
        }
        accumulator = Some(next);
    }

    validate_phase14_chain_steps(
        &manifest.layout,
        manifest.history_chunk_pairs,
        &manifest.steps,
    )
}

pub fn verify_phase14_decoding_chain_with_proof_checks(
    manifest: &Phase14DecodingChainManifest,
) -> Result<()> {
    verify_phase14_decoding_chain(manifest)?;
    for (step_index, step) in manifest.steps.iter().enumerate() {
        if !verify_execution_stark(&step.proof)? {
            return Err(VmError::UnsupportedProof(format!(
                "chunked decoding step {step_index} execution proof did not verify"
            )));
        }
    }
    Ok(())
}

pub fn phase15_default_segment_step_limit() -> usize {
    PHASE15_SEGMENT_STEP_LIMIT
}

pub fn phase16_default_rollup_segment_limit() -> usize {
    PHASE16_ROLLUP_SEGMENT_LIMIT
}

pub fn phase15_prepare_segment_bundle(
    chain: &Phase14DecodingChainManifest,
    max_segment_steps: usize,
) -> Result<Phase15DecodingHistorySegmentBundleManifest> {
    verify_phase14_decoding_chain(chain)?;
    if max_segment_steps == 0 {
        return Err(VmError::InvalidConfig(
            "Phase 15 segment bundle requires max_segment_steps > 0".to_string(),
        ));
    }

    let mut segments = Vec::new();
    let mut global_start_step_index = 0usize;
    for (segment_index, chunk) in chain.steps.chunks(max_segment_steps).enumerate() {
        let proofs = chunk
            .iter()
            .map(|step| step.proof.clone())
            .collect::<Vec<_>>();
        let phase12_chain = phase12_prepare_decoding_chain(&chain.layout, &proofs)?;
        let segment_chain = phase14_prepare_decoding_chain(&phase12_chain)?;
        let global_from_state = chunk
            .first()
            .ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "Phase 15 segment {segment_index} must contain at least one step"
                ))
            })?
            .from_state
            .clone();
        let global_to_state = chunk
            .last()
            .ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "Phase 15 segment {segment_index} must contain at least one step"
                ))
            })?
            .to_state
            .clone();
        let mut segment = Phase15DecodingHistorySegment {
            segment_index,
            global_start_step_index,
            total_steps: segment_chain.total_steps,
            global_from_state,
            global_to_state,
            public_state_boundary_commitment: String::new(),
            chain: segment_chain,
        };
        segment.public_state_boundary_commitment =
            commit_phase15_segment_public_state_boundary(&segment);
        segments.push(segment);
        global_start_step_index = global_start_step_index
            .checked_add(chunk.len())
            .ok_or_else(|| {
                VmError::InvalidConfig(
                    "Phase 15 segment bundle global step count overflowed".to_string(),
                )
            })?;
    }

    let manifest = Phase15DecodingHistorySegmentBundleManifest {
        proof_backend: StarkProofBackend::Stwo,
        bundle_version: STWO_DECODING_SEGMENT_BUNDLE_VERSION_PHASE15.to_string(),
        semantic_scope: STWO_DECODING_SEGMENT_BUNDLE_SCOPE_PHASE15.to_string(),
        proof_backend_version: crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12.to_string(),
        statement_version: crate::proof::CLAIM_STATEMENT_VERSION_V1.to_string(),
        layout: chain.layout.clone(),
        history_chunk_pairs: chain.history_chunk_pairs,
        max_segment_steps,
        total_segments: segments.len(),
        total_steps: chain.total_steps,
        segments,
    };
    verify_phase15_decoding_segment_bundle(&manifest)?;
    Ok(manifest)
}

pub fn verify_phase15_decoding_segment_bundle(
    manifest: &Phase15DecodingHistorySegmentBundleManifest,
) -> Result<()> {
    manifest.layout.validate()?;
    if manifest.proof_backend != StarkProofBackend::Stwo {
        return Err(VmError::InvalidConfig(format!(
            "decoding history segment bundle backend `{}` is not `stwo`",
            manifest.proof_backend
        )));
    }
    if manifest.bundle_version != STWO_DECODING_SEGMENT_BUNDLE_VERSION_PHASE15 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding history segment bundle version `{}`",
            manifest.bundle_version
        )));
    }
    if manifest.semantic_scope != STWO_DECODING_SEGMENT_BUNDLE_SCOPE_PHASE15 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding history segment bundle semantic scope `{}`",
            manifest.semantic_scope
        )));
    }
    if manifest.proof_backend_version != crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding history segment bundle proof backend version `{}` (expected `{}`)",
            manifest.proof_backend_version,
            crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12
        )));
    }
    if manifest.statement_version != crate::proof::CLAIM_STATEMENT_VERSION_V1 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding history segment bundle statement version `{}`",
            manifest.statement_version
        )));
    }
    if manifest.history_chunk_pairs != PHASE14_HISTORY_CHUNK_PAIRS {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding history segment bundle history_chunk_pairs={} (expected {})",
            manifest.history_chunk_pairs, PHASE14_HISTORY_CHUNK_PAIRS
        )));
    }
    if manifest.max_segment_steps == 0 {
        return Err(VmError::InvalidConfig(
            "decoding history segment bundle requires max_segment_steps > 0".to_string(),
        ));
    }
    if manifest.segments.is_empty() {
        return Err(VmError::InvalidConfig(
            "decoding history segment bundle must contain at least one segment".to_string(),
        ));
    }
    if manifest.total_segments != manifest.segments.len() {
        return Err(VmError::InvalidConfig(format!(
            "decoding history segment bundle total_segments={} does not match segments.len()={}",
            manifest.total_segments,
            manifest.segments.len()
        )));
    }
    let derived_total_steps = manifest
        .segments
        .iter()
        .try_fold(0usize, |acc, segment| acc.checked_add(segment.total_steps))
        .ok_or_else(|| {
            VmError::InvalidConfig(
                "decoding history segment bundle total_steps overflowed while summing segments"
                    .to_string(),
            )
        })?;
    if manifest.total_steps != derived_total_steps {
        return Err(VmError::InvalidConfig(format!(
            "decoding history segment bundle total_steps={} does not match derived total_steps={}",
            manifest.total_steps, derived_total_steps
        )));
    }

    let mut accumulator: Option<Phase14HistoryAccumulator> = None;
    let mut expected_global_start_step_index = 0usize;
    for (segment_index, segment) in manifest.segments.iter().enumerate() {
        if segment.segment_index != segment_index {
            return Err(VmError::InvalidConfig(format!(
                "decoding history segment {segment_index} stores segment_index={} instead of {}",
                segment.segment_index, segment_index
            )));
        }
        if segment.global_start_step_index != expected_global_start_step_index {
            return Err(VmError::InvalidConfig(format!(
                "decoding history segment {segment_index} starts at global step {} instead of {}",
                segment.global_start_step_index, expected_global_start_step_index
            )));
        }
        if segment.total_steps == 0 {
            return Err(VmError::InvalidConfig(format!(
                "decoding history segment {segment_index} must contain at least one step"
            )));
        }
        if segment.total_steps > manifest.max_segment_steps {
            return Err(VmError::InvalidConfig(format!(
                "decoding history segment {segment_index} total_steps={} exceeds max_segment_steps={}",
                segment.total_steps, manifest.max_segment_steps
            )));
        }
        if segment.chain.total_steps != segment.total_steps {
            return Err(VmError::InvalidConfig(format!(
                "decoding history segment {segment_index} total_steps={} does not match chain.total_steps={}",
                segment.total_steps, segment.chain.total_steps
            )));
        }
        if segment.public_state_boundary_commitment
            != commit_phase15_segment_public_state_boundary(segment)
        {
            return Err(VmError::InvalidConfig(format!(
                "decoding history segment {segment_index} public_state_boundary_commitment does not match the computed boundary commitment"
            )));
        }
        expected_global_start_step_index = expected_global_start_step_index
            .checked_add(segment.total_steps)
            .ok_or_else(|| {
                VmError::InvalidConfig(
                    "decoding history segment bundle global step count overflowed".to_string(),
                )
            })?;
    }
    let final_global_step_index = verify_phase15_segment_sequence(
        &manifest.layout,
        manifest.history_chunk_pairs,
        &manifest.proof_backend_version,
        &manifest.statement_version,
        &manifest.segments,
        0,
        &mut accumulator,
    )?;
    if final_global_step_index != manifest.total_steps {
        return Err(VmError::InvalidConfig(format!(
            "decoding history segment bundle replay ended at global step {} instead of total_steps={}",
            final_global_step_index, manifest.total_steps
        )));
    }

    Ok(())
}

pub fn verify_phase15_decoding_segment_bundle_with_proof_checks(
    manifest: &Phase15DecodingHistorySegmentBundleManifest,
) -> Result<()> {
    verify_phase15_decoding_segment_bundle(manifest)?;
    for (segment_index, segment) in manifest.segments.iter().enumerate() {
        verify_phase14_decoding_chain_with_proof_checks(&segment.chain).map_err(|error| {
            VmError::UnsupportedProof(format!(
                "decoding history segment {segment_index} failed verification: {error}"
            ))
        })?;
    }
    Ok(())
}

pub fn phase16_prepare_segment_rollup(
    bundle: &Phase15DecodingHistorySegmentBundleManifest,
    max_rollup_segments: usize,
) -> Result<Phase16DecodingHistoryRollupManifest> {
    verify_phase15_decoding_segment_bundle(bundle)?;
    if max_rollup_segments == 0 {
        return Err(VmError::InvalidConfig(
            "Phase 16 segment rollup requires max_rollup_segments > 0".to_string(),
        ));
    }

    let mut rollups = Vec::new();
    for (rollup_index, chunk) in bundle.segments.chunks(max_rollup_segments).enumerate() {
        let first = chunk.first().ok_or_else(|| {
            VmError::InvalidConfig(format!(
                "Phase 16 rollup {rollup_index} must contain at least one segment"
            ))
        })?;
        let last = chunk.last().ok_or_else(|| {
            VmError::InvalidConfig(format!(
                "Phase 16 rollup {rollup_index} must contain at least one segment"
            ))
        })?;
        let total_steps = chunk
            .iter()
            .try_fold(0usize, |acc, segment| acc.checked_add(segment.total_steps))
            .ok_or_else(|| {
                VmError::InvalidConfig(
                    "Phase 16 rollup total_steps overflowed while summing segments".to_string(),
                )
            })?;
        let mut rollup = Phase16DecodingHistoryRollup {
            rollup_index,
            global_start_step_index: first.global_start_step_index,
            total_segments: chunk.len(),
            total_steps,
            global_from_state: first.global_from_state.clone(),
            global_to_state: last.global_to_state.clone(),
            public_state_boundary_commitment: String::new(),
            segments: chunk.to_vec(),
        };
        rollup.public_state_boundary_commitment =
            commit_phase16_rollup_public_state_boundary(&rollup);
        rollups.push(rollup);
    }

    let manifest = Phase16DecodingHistoryRollupManifest {
        proof_backend: StarkProofBackend::Stwo,
        rollup_version: STWO_DECODING_SEGMENT_ROLLUP_VERSION_PHASE16.to_string(),
        semantic_scope: STWO_DECODING_SEGMENT_ROLLUP_SCOPE_PHASE16.to_string(),
        proof_backend_version: bundle.proof_backend_version.clone(),
        statement_version: bundle.statement_version.clone(),
        layout: bundle.layout.clone(),
        history_chunk_pairs: bundle.history_chunk_pairs,
        max_rollup_segments,
        total_rollups: rollups.len(),
        total_segments: bundle.total_segments,
        total_steps: bundle.total_steps,
        rollups,
    };
    verify_phase16_decoding_segment_rollup(&manifest)?;
    Ok(manifest)
}

pub fn verify_phase16_decoding_segment_rollup(
    manifest: &Phase16DecodingHistoryRollupManifest,
) -> Result<()> {
    manifest.layout.validate()?;
    if manifest.proof_backend != StarkProofBackend::Stwo {
        return Err(VmError::InvalidConfig(format!(
            "decoding history segment rollup backend `{}` is not `stwo`",
            manifest.proof_backend
        )));
    }
    if manifest.rollup_version != STWO_DECODING_SEGMENT_ROLLUP_VERSION_PHASE16 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding history segment rollup version `{}`",
            manifest.rollup_version
        )));
    }
    if manifest.semantic_scope != STWO_DECODING_SEGMENT_ROLLUP_SCOPE_PHASE16 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding history segment rollup semantic scope `{}`",
            manifest.semantic_scope
        )));
    }
    if manifest.proof_backend_version != crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding history segment rollup proof backend version `{}` (expected `{}`)",
            manifest.proof_backend_version,
            crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12
        )));
    }
    if manifest.statement_version != crate::proof::CLAIM_STATEMENT_VERSION_V1 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding history segment rollup statement version `{}`",
            manifest.statement_version
        )));
    }
    if manifest.history_chunk_pairs != PHASE14_HISTORY_CHUNK_PAIRS {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding history segment rollup history_chunk_pairs={} (expected {})",
            manifest.history_chunk_pairs, PHASE14_HISTORY_CHUNK_PAIRS
        )));
    }
    if manifest.max_rollup_segments == 0 {
        return Err(VmError::InvalidConfig(
            "decoding history segment rollup requires max_rollup_segments > 0".to_string(),
        ));
    }
    if manifest.rollups.is_empty() {
        return Err(VmError::InvalidConfig(
            "decoding history segment rollup must contain at least one rollup".to_string(),
        ));
    }
    if manifest.total_rollups != manifest.rollups.len() {
        return Err(VmError::InvalidConfig(format!(
            "decoding history segment rollup total_rollups={} does not match rollups.len()={}",
            manifest.total_rollups,
            manifest.rollups.len()
        )));
    }
    let derived_total_segments = manifest
        .rollups
        .iter()
        .try_fold(0usize, |acc, rollup| acc.checked_add(rollup.total_segments))
        .ok_or_else(|| {
            VmError::InvalidConfig(
                "decoding history segment rollup total_segments overflowed while summing rollups"
                    .to_string(),
            )
        })?;
    if manifest.total_segments != derived_total_segments {
        return Err(VmError::InvalidConfig(format!(
            "decoding history segment rollup total_segments={} does not match derived total_segments={}",
            manifest.total_segments, derived_total_segments
        )));
    }
    let derived_total_steps = manifest
        .rollups
        .iter()
        .try_fold(0usize, |acc, rollup| acc.checked_add(rollup.total_steps))
        .ok_or_else(|| {
            VmError::InvalidConfig(
                "decoding history segment rollup total_steps overflowed while summing rollups"
                    .to_string(),
            )
        })?;
    if manifest.total_steps != derived_total_steps {
        return Err(VmError::InvalidConfig(format!(
            "decoding history segment rollup total_steps={} does not match derived total_steps={}",
            manifest.total_steps, derived_total_steps
        )));
    }

    let mut accumulator: Option<Phase14HistoryAccumulator> = None;
    let mut expected_rollup_start_step_index = 0usize;
    let mut expected_segment_index = 0usize;
    for (rollup_index, rollup) in manifest.rollups.iter().enumerate() {
        if rollup.rollup_index != rollup_index {
            return Err(VmError::InvalidConfig(format!(
                "decoding history segment rollup {rollup_index} stores rollup_index={} instead of {}",
                rollup.rollup_index, rollup_index
            )));
        }
        if rollup.global_start_step_index != expected_rollup_start_step_index {
            return Err(VmError::InvalidConfig(format!(
                "decoding history segment rollup {rollup_index} starts at global step {} instead of {}",
                rollup.global_start_step_index, expected_rollup_start_step_index
            )));
        }
        if rollup.total_segments == 0 {
            return Err(VmError::InvalidConfig(format!(
                "decoding history segment rollup {rollup_index} must contain at least one segment"
            )));
        }
        if rollup.total_segments > manifest.max_rollup_segments {
            return Err(VmError::InvalidConfig(format!(
                "decoding history segment rollup {rollup_index} total_segments={} exceeds max_rollup_segments={}",
                rollup.total_segments, manifest.max_rollup_segments
            )));
        }
        if rollup.segments.len() != rollup.total_segments {
            return Err(VmError::InvalidConfig(format!(
                "decoding history segment rollup {rollup_index} total_segments={} does not match segments.len()={}",
                rollup.total_segments,
                rollup.segments.len()
            )));
        }
        if rollup.public_state_boundary_commitment
            != commit_phase16_rollup_public_state_boundary(rollup)
        {
            return Err(VmError::InvalidConfig(format!(
                "decoding history segment rollup {rollup_index} public_state_boundary_commitment does not match the computed boundary commitment"
            )));
        }
        let derived_rollup_total_steps = rollup
            .segments
            .iter()
            .try_fold(0usize, |acc, segment| acc.checked_add(segment.total_steps))
            .ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "decoding history segment rollup {rollup_index} total_steps overflowed while summing segments"
                ))
            })?;
        if rollup.total_steps != derived_rollup_total_steps {
            return Err(VmError::InvalidConfig(format!(
                "decoding history segment rollup {rollup_index} total_steps={} does not match derived total_steps={}",
                rollup.total_steps, derived_rollup_total_steps
            )));
        }
        let first_segment = rollup.segments.first().ok_or_else(|| {
            VmError::InvalidConfig(format!(
                "decoding history segment rollup {rollup_index} must contain at least one segment"
            ))
        })?;
        let last_segment = rollup.segments.last().ok_or_else(|| {
            VmError::InvalidConfig(format!(
                "decoding history segment rollup {rollup_index} must contain at least one segment"
            ))
        })?;
        if rollup.global_from_state != first_segment.global_from_state {
            return Err(VmError::InvalidConfig(format!(
                "decoding history segment rollup {rollup_index} global_from_state does not match the first segment boundary"
            )));
        }
        if rollup.global_to_state != last_segment.global_to_state {
            return Err(VmError::InvalidConfig(format!(
                "decoding history segment rollup {rollup_index} global_to_state does not match the last segment boundary"
            )));
        }
        for segment in &rollup.segments {
            if segment.segment_index != expected_segment_index {
                return Err(VmError::InvalidConfig(format!(
                    "decoding history segment rollup {rollup_index} segment stores segment_index={} instead of {}",
                    segment.segment_index, expected_segment_index
                )));
            }
            expected_segment_index = expected_segment_index.checked_add(1).ok_or_else(|| {
                VmError::InvalidConfig(
                    "decoding history segment rollup segment count overflowed".to_string(),
                )
            })?;
        }
        let next_global_start_step_index = verify_phase15_segment_sequence(
            &manifest.layout,
            manifest.history_chunk_pairs,
            &manifest.proof_backend_version,
            &manifest.statement_version,
            &rollup.segments,
            expected_rollup_start_step_index,
            &mut accumulator,
        )?;
        if rollup_index > 0 {
            validate_phase16_rollup_boundary(
                &manifest.rollups[rollup_index - 1].global_to_state,
                &rollup.global_from_state,
                rollup_index,
            )?;
        }
        expected_rollup_start_step_index = next_global_start_step_index;
    }
    if expected_rollup_start_step_index != manifest.total_steps {
        return Err(VmError::InvalidConfig(format!(
            "decoding history segment rollup replay ended at global step {} instead of total_steps={}",
            expected_rollup_start_step_index, manifest.total_steps
        )));
    }

    Ok(())
}

pub fn verify_phase16_decoding_segment_rollup_with_proof_checks(
    manifest: &Phase16DecodingHistoryRollupManifest,
) -> Result<()> {
    verify_phase16_decoding_segment_rollup(manifest)?;
    for (rollup_index, rollup) in manifest.rollups.iter().enumerate() {
        for segment in &rollup.segments {
            verify_phase14_decoding_chain_with_proof_checks(&segment.chain).map_err(|error| {
                VmError::UnsupportedProof(format!(
                    "decoding history segment rollup {rollup_index} segment {} failed verification: {error}",
                    segment.segment_index
                ))
            })?;
        }
    }
    Ok(())
}

pub fn verify_phase17_decoding_rollup_matrix(
    manifest: &Phase17DecodingHistoryRollupMatrixManifest,
) -> Result<()> {
    if manifest.proof_backend != StarkProofBackend::Stwo {
        return Err(VmError::InvalidConfig(format!(
            "decoding rollup matrix backend `{}` is not `stwo`",
            manifest.proof_backend
        )));
    }
    if manifest.matrix_version != STWO_DECODING_ROLLUP_MATRIX_VERSION_PHASE17 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding rollup matrix version `{}`",
            manifest.matrix_version
        )));
    }
    if manifest.semantic_scope != STWO_DECODING_ROLLUP_MATRIX_SCOPE_PHASE17 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding rollup matrix semantic scope `{}`",
            manifest.semantic_scope
        )));
    }
    if manifest.proof_backend_version != crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding rollup matrix proof backend version `{}` (expected `{}`)",
            manifest.proof_backend_version,
            crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12
        )));
    }
    if manifest.statement_version != crate::proof::CLAIM_STATEMENT_VERSION_V1 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding rollup matrix statement version `{}`",
            manifest.statement_version
        )));
    }
    if manifest.rollups.is_empty() {
        return Err(VmError::InvalidConfig(
            "decoding rollup matrix must contain at least one rollup manifest".to_string(),
        ));
    }
    if manifest.total_layouts != manifest.rollups.len() {
        return Err(VmError::InvalidConfig(format!(
            "decoding rollup matrix total_layouts={} does not match rollups.len()={}",
            manifest.total_layouts,
            manifest.rollups.len()
        )));
    }
    let derived_total_rollups = manifest
        .rollups
        .iter()
        .try_fold(0usize, |acc, rollup| acc.checked_add(rollup.total_rollups))
        .ok_or_else(|| {
            VmError::InvalidConfig(
                "decoding rollup matrix total_rollups overflowed while summing manifests"
                    .to_string(),
            )
        })?;
    if manifest.total_rollups != derived_total_rollups {
        return Err(VmError::InvalidConfig(format!(
            "decoding rollup matrix total_rollups={} does not match derived total_rollups={}",
            manifest.total_rollups, derived_total_rollups
        )));
    }
    let derived_total_segments = manifest
        .rollups
        .iter()
        .try_fold(0usize, |acc, rollup| acc.checked_add(rollup.total_segments))
        .ok_or_else(|| {
            VmError::InvalidConfig(
                "decoding rollup matrix total_segments overflowed while summing manifests"
                    .to_string(),
            )
        })?;
    if manifest.total_segments != derived_total_segments {
        return Err(VmError::InvalidConfig(format!(
            "decoding rollup matrix total_segments={} does not match derived total_segments={}",
            manifest.total_segments, derived_total_segments
        )));
    }
    let derived_total_steps = manifest
        .rollups
        .iter()
        .try_fold(0usize, |acc, rollup| acc.checked_add(rollup.total_steps))
        .ok_or_else(|| {
            VmError::InvalidConfig(
                "decoding rollup matrix total_steps overflowed while summing manifests".to_string(),
            )
        })?;
    if manifest.total_steps != derived_total_steps {
        return Err(VmError::InvalidConfig(format!(
            "decoding rollup matrix total_steps={} does not match derived total_steps={}",
            manifest.total_steps, derived_total_steps
        )));
    }
    if manifest.public_state_boundary_commitment
        != commit_phase17_matrix_public_state_boundary(manifest)?
    {
        return Err(VmError::InvalidConfig(
            "decoding rollup matrix public_state_boundary_commitment does not match the computed boundary commitment"
                .to_string(),
        ));
    }
    for (layout_index, rollup) in manifest.rollups.iter().enumerate() {
        if rollup.proof_backend_version != manifest.proof_backend_version {
            return Err(VmError::InvalidConfig(format!(
                "decoding rollup matrix manifest {layout_index} proof backend version `{}` does not match matrix `{}`",
                rollup.proof_backend_version, manifest.proof_backend_version
            )));
        }
        if rollup.statement_version != manifest.statement_version {
            return Err(VmError::InvalidConfig(format!(
                "decoding rollup matrix manifest {layout_index} statement version `{}` does not match matrix `{}`",
                rollup.statement_version, manifest.statement_version
            )));
        }
        verify_phase16_decoding_segment_rollup(rollup)?;
    }
    Ok(())
}

pub fn verify_phase17_decoding_rollup_matrix_with_proof_checks(
    manifest: &Phase17DecodingHistoryRollupMatrixManifest,
) -> Result<()> {
    verify_phase17_decoding_rollup_matrix(manifest)?;
    for (layout_index, rollup) in manifest.rollups.iter().enumerate() {
        verify_phase16_decoding_segment_rollup_with_proof_checks(rollup).map_err(|error| {
            VmError::UnsupportedProof(format!(
                "decoding rollup matrix manifest {layout_index} failed verification: {error}"
            ))
        })?;
    }
    Ok(())
}

pub fn phase21_prepare_decoding_matrix_accumulator(
    matrices: &[Phase17DecodingHistoryRollupMatrixManifest],
) -> Result<Phase21DecodingMatrixAccumulatorManifest> {
    if matrices.is_empty() {
        return Err(VmError::InvalidConfig(
            "Phase 21 decoding matrix accumulator requires at least one matrix".to_string(),
        ));
    }
    if matrices.len() > MAX_PHASE21_ACCUMULATOR_MATRICES {
        return Err(VmError::InvalidConfig(format!(
            "Phase 21 decoding matrix accumulator supports at most {MAX_PHASE21_ACCUMULATOR_MATRICES} matrices (got {})",
            matrices.len()
        )));
    }

    let first = &matrices[0];
    let mut total_layouts = 0usize;
    let mut total_rollups = 0usize;
    let mut total_segments = 0usize;
    let mut total_steps = 0usize;
    let expected_template = commit_phase21_matrix_template(first)?;

    for (matrix_index, matrix) in matrices.iter().enumerate() {
        verify_phase17_decoding_rollup_matrix(matrix).map_err(|error| {
            VmError::InvalidConfig(format!(
                "Phase 21 matrix {matrix_index} failed Phase 17 verification: {error}"
            ))
        })?;
        if matrix.proof_backend_version != first.proof_backend_version {
            return Err(VmError::InvalidConfig(format!(
                "Phase 21 matrix {matrix_index} proof backend version `{}` does not match the first matrix `{}`",
                matrix.proof_backend_version, first.proof_backend_version
            )));
        }
        if matrix.statement_version != first.statement_version {
            return Err(VmError::InvalidConfig(format!(
                "Phase 21 matrix {matrix_index} statement version `{}` does not match the first matrix `{}`",
                matrix.statement_version, first.statement_version
            )));
        }
        let matrix_template = commit_phase21_matrix_template(matrix)?;
        if matrix_template != expected_template {
            return Err(VmError::InvalidConfig(format!(
                "Phase 21 matrix {matrix_index} does not match the shared template commitment"
            )));
        }
        total_layouts = total_layouts
            .checked_add(matrix.total_layouts)
            .ok_or_else(|| {
                VmError::InvalidConfig(
                    "Phase 21 matrix accumulator total_layouts overflowed".to_string(),
                )
            })?;
        total_rollups = total_rollups
            .checked_add(matrix.total_rollups)
            .ok_or_else(|| {
                VmError::InvalidConfig(
                    "Phase 21 matrix accumulator total_rollups overflowed".to_string(),
                )
            })?;
        total_segments = total_segments
            .checked_add(matrix.total_segments)
            .ok_or_else(|| {
                VmError::InvalidConfig(
                    "Phase 21 matrix accumulator total_segments overflowed".to_string(),
                )
            })?;
        total_steps = total_steps.checked_add(matrix.total_steps).ok_or_else(|| {
            VmError::InvalidConfig("Phase 21 matrix accumulator total_steps overflowed".to_string())
        })?;
    }

    let mut manifest = Phase21DecodingMatrixAccumulatorManifest {
        proof_backend: StarkProofBackend::Stwo,
        accumulator_version: STWO_DECODING_MATRIX_ACCUMULATOR_VERSION_PHASE21.to_string(),
        semantic_scope: STWO_DECODING_MATRIX_ACCUMULATOR_SCOPE_PHASE21.to_string(),
        proof_backend_version: first.proof_backend_version.clone(),
        statement_version: first.statement_version.clone(),
        total_matrices: matrices.len(),
        total_layouts,
        total_rollups,
        total_segments,
        total_steps,
        template_commitment: expected_template,
        accumulator_commitment: String::new(),
        matrices: matrices.to_vec(),
    };
    manifest.accumulator_commitment = commit_phase21_matrix_accumulator(&manifest)?;
    verify_phase21_decoding_matrix_accumulator(&manifest)?;
    Ok(manifest)
}

pub fn verify_phase21_decoding_matrix_accumulator(
    manifest: &Phase21DecodingMatrixAccumulatorManifest,
) -> Result<()> {
    if manifest.proof_backend != StarkProofBackend::Stwo {
        return Err(VmError::InvalidConfig(format!(
            "decoding matrix accumulator backend `{}` is not `stwo`",
            manifest.proof_backend
        )));
    }
    if manifest.accumulator_version != STWO_DECODING_MATRIX_ACCUMULATOR_VERSION_PHASE21 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding matrix accumulator version `{}`",
            manifest.accumulator_version
        )));
    }
    if manifest.semantic_scope != STWO_DECODING_MATRIX_ACCUMULATOR_SCOPE_PHASE21 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding matrix accumulator semantic scope `{}`",
            manifest.semantic_scope
        )));
    }
    if manifest.proof_backend_version != crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding matrix accumulator proof backend version `{}` (expected `{}`)",
            manifest.proof_backend_version,
            crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12
        )));
    }
    if manifest.statement_version != crate::proof::CLAIM_STATEMENT_VERSION_V1 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding matrix accumulator statement version `{}`",
            manifest.statement_version
        )));
    }
    if manifest.matrices.is_empty() {
        return Err(VmError::InvalidConfig(
            "decoding matrix accumulator must contain at least one matrix".to_string(),
        ));
    }
    if manifest.matrices.len() > MAX_PHASE21_ACCUMULATOR_MATRICES {
        return Err(VmError::InvalidConfig(format!(
            "decoding matrix accumulator matrices.len()={} exceeds the supported maximum {}",
            manifest.matrices.len(),
            MAX_PHASE21_ACCUMULATOR_MATRICES
        )));
    }
    if manifest.total_matrices != manifest.matrices.len() {
        return Err(VmError::InvalidConfig(format!(
            "decoding matrix accumulator total_matrices={} does not match matrices.len()={}",
            manifest.total_matrices,
            manifest.matrices.len()
        )));
    }
    if manifest.template_commitment.is_empty() {
        return Err(VmError::InvalidConfig(
            "decoding matrix accumulator template_commitment must not be empty".to_string(),
        ));
    }
    if manifest.accumulator_commitment.is_empty() {
        return Err(VmError::InvalidConfig(
            "decoding matrix accumulator accumulator_commitment must not be empty".to_string(),
        ));
    }

    let mut total_layouts = 0usize;
    let mut total_rollups = 0usize;
    let mut total_segments = 0usize;
    let mut total_steps = 0usize;
    let mut derived_template_commitment: Option<String> = None;

    for (matrix_index, matrix) in manifest.matrices.iter().enumerate() {
        if matrix.proof_backend_version != manifest.proof_backend_version {
            return Err(VmError::InvalidConfig(format!(
                "decoding matrix accumulator matrix {matrix_index} proof backend version `{}` does not match accumulator `{}`",
                matrix.proof_backend_version, manifest.proof_backend_version
            )));
        }
        if matrix.statement_version != manifest.statement_version {
            return Err(VmError::InvalidConfig(format!(
                "decoding matrix accumulator matrix {matrix_index} statement version `{}` does not match accumulator `{}`",
                matrix.statement_version, manifest.statement_version
            )));
        }
        verify_phase17_decoding_rollup_matrix(matrix).map_err(|error| {
            VmError::InvalidConfig(format!(
                "decoding matrix accumulator matrix {matrix_index} failed verification: {error}"
            ))
        })?;

        let matrix_template = commit_phase21_matrix_template(matrix)?;
        if let Some(expected) = &derived_template_commitment {
            if expected != &matrix_template {
                return Err(VmError::InvalidConfig(format!(
                    "decoding matrix accumulator matrix {matrix_index} does not match the shared template commitment"
                )));
            }
        } else {
            derived_template_commitment = Some(matrix_template);
        }

        total_layouts = total_layouts
            .checked_add(matrix.total_layouts)
            .ok_or_else(|| {
                VmError::InvalidConfig(
                    "decoding matrix accumulator total_layouts overflowed while summing matrices"
                        .to_string(),
                )
            })?;
        total_rollups = total_rollups
            .checked_add(matrix.total_rollups)
            .ok_or_else(|| {
                VmError::InvalidConfig(
                    "decoding matrix accumulator total_rollups overflowed while summing matrices"
                        .to_string(),
                )
            })?;
        total_segments = total_segments
            .checked_add(matrix.total_segments)
            .ok_or_else(|| {
                VmError::InvalidConfig(
                    "decoding matrix accumulator total_segments overflowed while summing matrices"
                        .to_string(),
                )
            })?;
        total_steps = total_steps.checked_add(matrix.total_steps).ok_or_else(|| {
            VmError::InvalidConfig(
                "decoding matrix accumulator total_steps overflowed while summing matrices"
                    .to_string(),
            )
        })?;
    }

    if manifest.template_commitment
        != derived_template_commitment.ok_or_else(|| {
            VmError::InvalidConfig(
                "decoding matrix accumulator must contain at least one matrix".to_string(),
            )
        })?
    {
        return Err(VmError::InvalidConfig(
            "decoding matrix accumulator template_commitment does not match the computed template commitment"
                .to_string(),
        ));
    }
    if manifest.total_layouts != total_layouts {
        return Err(VmError::InvalidConfig(format!(
            "decoding matrix accumulator total_layouts={} does not match derived total_layouts={}",
            manifest.total_layouts, total_layouts
        )));
    }
    if manifest.total_rollups != total_rollups {
        return Err(VmError::InvalidConfig(format!(
            "decoding matrix accumulator total_rollups={} does not match derived total_rollups={}",
            manifest.total_rollups, total_rollups
        )));
    }
    if manifest.total_segments != total_segments {
        return Err(VmError::InvalidConfig(format!(
            "decoding matrix accumulator total_segments={} does not match derived total_segments={}",
            manifest.total_segments, total_segments
        )));
    }
    if manifest.total_steps != total_steps {
        return Err(VmError::InvalidConfig(format!(
            "decoding matrix accumulator total_steps={} does not match derived total_steps={}",
            manifest.total_steps, total_steps
        )));
    }
    let expected_accumulator_commitment = commit_phase21_matrix_accumulator(manifest)?;
    if manifest.accumulator_commitment != expected_accumulator_commitment {
        return Err(VmError::InvalidConfig(
            "decoding matrix accumulator accumulator_commitment does not match the computed accumulator commitment"
                .to_string(),
        ));
    }
    Ok(())
}

pub fn verify_phase21_decoding_matrix_accumulator_with_proof_checks(
    manifest: &Phase21DecodingMatrixAccumulatorManifest,
) -> Result<()> {
    verify_phase21_decoding_matrix_accumulator(manifest)?;
    for (matrix_index, matrix) in manifest.matrices.iter().enumerate() {
        verify_phase17_decoding_rollup_matrix_with_proof_checks(matrix).map_err(|error| {
            VmError::UnsupportedProof(format!(
                "decoding matrix accumulator matrix {matrix_index} failed verification: {error}"
            ))
        })?;
    }
    Ok(())
}

fn derive_phase22_lookup_stats(
    accumulator: &Phase21DecodingMatrixAccumulatorManifest,
) -> Result<(usize, usize, usize)> {
    let mut total_lookup_delta_entries = 0usize;
    let mut max_lookup_frontier_entries = 0usize;
    let mut total_rollup_boundaries = 0usize;

    for (matrix_index, matrix) in accumulator.matrices.iter().enumerate() {
        for (layout_index, rollup_manifest) in matrix.rollups.iter().enumerate() {
            for rollup in &rollup_manifest.rollups {
                if rollup
                    .global_from_state
                    .lookup_transcript_commitment
                    .is_empty()
                {
                    return Err(VmError::InvalidConfig(format!(
                        "decoding lookup accumulator matrix {matrix_index} layout {layout_index} rollup {} has an empty from-state lookup transcript commitment",
                        rollup.rollup_index
                    )));
                }
                if rollup
                    .global_to_state
                    .lookup_transcript_commitment
                    .is_empty()
                {
                    return Err(VmError::InvalidConfig(format!(
                        "decoding lookup accumulator matrix {matrix_index} layout {layout_index} rollup {} has an empty to-state lookup transcript commitment",
                        rollup.rollup_index
                    )));
                }
                if rollup
                    .global_from_state
                    .lookup_frontier_commitment
                    .is_empty()
                {
                    return Err(VmError::InvalidConfig(format!(
                        "decoding lookup accumulator matrix {matrix_index} layout {layout_index} rollup {} has an empty from-state lookup frontier commitment",
                        rollup.rollup_index
                    )));
                }
                if rollup.global_to_state.lookup_frontier_commitment.is_empty() {
                    return Err(VmError::InvalidConfig(format!(
                        "decoding lookup accumulator matrix {matrix_index} layout {layout_index} rollup {} has an empty to-state lookup frontier commitment",
                        rollup.rollup_index
                    )));
                }
                if rollup.global_to_state.lookup_transcript_entries
                    < rollup.global_from_state.lookup_transcript_entries
                {
                    return Err(VmError::InvalidConfig(format!(
                        "decoding lookup accumulator matrix {matrix_index} layout {layout_index} rollup {} decreases lookup transcript entries: from {} to {}",
                        rollup.rollup_index,
                        rollup.global_from_state.lookup_transcript_entries,
                        rollup.global_to_state.lookup_transcript_entries
                    )));
                }
                let rollup_lookup_delta = rollup.global_to_state.lookup_transcript_entries
                    - rollup.global_from_state.lookup_transcript_entries;
                if rollup_lookup_delta != rollup.total_steps {
                    return Err(VmError::InvalidConfig(format!(
                        "decoding lookup accumulator matrix {matrix_index} layout {layout_index} rollup {} lookup delta {} does not match total_steps {}",
                        rollup.rollup_index, rollup_lookup_delta, rollup.total_steps
                    )));
                }
                total_lookup_delta_entries = total_lookup_delta_entries
                    .checked_add(rollup_lookup_delta)
                    .ok_or_else(|| {
                        VmError::InvalidConfig(
                            "decoding lookup accumulator total_lookup_delta_entries overflowed"
                                .to_string(),
                        )
                    })?;
                if rollup.global_from_state.lookup_frontier_entries > PHASE14_HISTORY_CHUNK_PAIRS {
                    return Err(VmError::InvalidConfig(format!(
                        "decoding lookup accumulator matrix {matrix_index} layout {layout_index} rollup {} from-state frontier entries {} exceed supported {}",
                        rollup.rollup_index,
                        rollup.global_from_state.lookup_frontier_entries,
                        PHASE14_HISTORY_CHUNK_PAIRS
                    )));
                }
                if rollup.global_to_state.lookup_frontier_entries > PHASE14_HISTORY_CHUNK_PAIRS {
                    return Err(VmError::InvalidConfig(format!(
                        "decoding lookup accumulator matrix {matrix_index} layout {layout_index} rollup {} to-state frontier entries {} exceed supported {}",
                        rollup.rollup_index,
                        rollup.global_to_state.lookup_frontier_entries,
                        PHASE14_HISTORY_CHUNK_PAIRS
                    )));
                }
                max_lookup_frontier_entries = max_lookup_frontier_entries
                    .max(rollup.global_from_state.lookup_frontier_entries)
                    .max(rollup.global_to_state.lookup_frontier_entries);
                total_rollup_boundaries =
                    total_rollup_boundaries.checked_add(1).ok_or_else(|| {
                        VmError::InvalidConfig(
                            "decoding lookup accumulator total_rollup_boundaries overflowed"
                                .to_string(),
                        )
                    })?;
            }
        }
    }

    if total_rollup_boundaries > MAX_PHASE22_ACCUMULATOR_ROLLUPS {
        return Err(VmError::InvalidConfig(format!(
            "decoding lookup accumulator rollup boundary count {} exceeds the supported maximum {}",
            total_rollup_boundaries, MAX_PHASE22_ACCUMULATOR_ROLLUPS
        )));
    }

    Ok((
        total_lookup_delta_entries,
        max_lookup_frontier_entries,
        total_rollup_boundaries,
    ))
}

pub fn phase22_prepare_decoding_lookup_accumulator(
    accumulator: &Phase21DecodingMatrixAccumulatorManifest,
) -> Result<Phase22DecodingLookupAccumulatorManifest> {
    verify_phase21_decoding_matrix_accumulator(accumulator).map_err(|error| {
        VmError::InvalidConfig(format!(
            "Phase 22 source accumulator failed Phase 21 verification: {error}"
        ))
    })?;

    let (lookup_delta_entries, max_lookup_frontier_entries, total_rollup_boundaries) =
        derive_phase22_lookup_stats(accumulator)?;
    if total_rollup_boundaries != accumulator.total_rollups {
        return Err(VmError::InvalidConfig(format!(
            "Phase 22 source rollup boundary count {} does not match Phase 21 total_rollups {}",
            total_rollup_boundaries, accumulator.total_rollups
        )));
    }

    let mut manifest = Phase22DecodingLookupAccumulatorManifest {
        proof_backend: StarkProofBackend::Stwo,
        accumulator_version: STWO_DECODING_LOOKUP_ACCUMULATOR_VERSION_PHASE22.to_string(),
        semantic_scope: STWO_DECODING_LOOKUP_ACCUMULATOR_SCOPE_PHASE22.to_string(),
        proof_backend_version: accumulator.proof_backend_version.clone(),
        statement_version: accumulator.statement_version.clone(),
        total_matrices: accumulator.total_matrices,
        total_layouts: accumulator.total_layouts,
        total_rollups: accumulator.total_rollups,
        total_segments: accumulator.total_segments,
        total_steps: accumulator.total_steps,
        lookup_delta_entries,
        max_lookup_frontier_entries,
        source_template_commitment: accumulator.template_commitment.clone(),
        source_accumulator_commitment: accumulator.accumulator_commitment.clone(),
        lookup_template_commitment: commit_phase22_lookup_template(accumulator)?,
        lookup_accumulator_commitment: String::new(),
        accumulator: accumulator.clone(),
    };
    manifest.lookup_accumulator_commitment = commit_phase22_lookup_accumulator(&manifest)?;
    verify_phase22_decoding_lookup_accumulator(&manifest)?;
    Ok(manifest)
}

pub fn verify_phase22_decoding_lookup_accumulator(
    manifest: &Phase22DecodingLookupAccumulatorManifest,
) -> Result<()> {
    if manifest.proof_backend != StarkProofBackend::Stwo {
        return Err(VmError::InvalidConfig(format!(
            "decoding lookup accumulator backend `{}` is not `stwo`",
            manifest.proof_backend
        )));
    }
    if manifest.accumulator_version != STWO_DECODING_LOOKUP_ACCUMULATOR_VERSION_PHASE22 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding lookup accumulator version `{}`",
            manifest.accumulator_version
        )));
    }
    if manifest.semantic_scope != STWO_DECODING_LOOKUP_ACCUMULATOR_SCOPE_PHASE22 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding lookup accumulator semantic scope `{}`",
            manifest.semantic_scope
        )));
    }
    if manifest.proof_backend_version != crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding lookup accumulator proof backend version `{}` (expected `{}`)",
            manifest.proof_backend_version,
            crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12
        )));
    }
    if manifest.statement_version != crate::proof::CLAIM_STATEMENT_VERSION_V1 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding lookup accumulator statement version `{}`",
            manifest.statement_version
        )));
    }
    if manifest.total_rollups > MAX_PHASE22_ACCUMULATOR_ROLLUPS {
        return Err(VmError::InvalidConfig(format!(
            "decoding lookup accumulator total_rollups={} exceeds the supported maximum {}",
            manifest.total_rollups, MAX_PHASE22_ACCUMULATOR_ROLLUPS
        )));
    }
    if manifest.source_template_commitment.is_empty() {
        return Err(VmError::InvalidConfig(
            "decoding lookup accumulator source_template_commitment must not be empty".to_string(),
        ));
    }
    if manifest.source_accumulator_commitment.is_empty() {
        return Err(VmError::InvalidConfig(
            "decoding lookup accumulator source_accumulator_commitment must not be empty"
                .to_string(),
        ));
    }
    if manifest.lookup_template_commitment.is_empty() {
        return Err(VmError::InvalidConfig(
            "decoding lookup accumulator lookup_template_commitment must not be empty".to_string(),
        ));
    }
    if manifest.lookup_accumulator_commitment.is_empty() {
        return Err(VmError::InvalidConfig(
            "decoding lookup accumulator lookup_accumulator_commitment must not be empty"
                .to_string(),
        ));
    }

    verify_phase21_decoding_matrix_accumulator(&manifest.accumulator).map_err(|error| {
        VmError::InvalidConfig(format!(
            "decoding lookup accumulator source verification failed: {error}"
        ))
    })?;

    if manifest.source_template_commitment != manifest.accumulator.template_commitment {
        return Err(VmError::InvalidConfig(
            "decoding lookup accumulator source_template_commitment does not match the nested Phase 21 accumulator".to_string(),
        ));
    }
    if manifest.source_accumulator_commitment != manifest.accumulator.accumulator_commitment {
        return Err(VmError::InvalidConfig(
            "decoding lookup accumulator source_accumulator_commitment does not match the nested Phase 21 accumulator".to_string(),
        ));
    }
    if manifest.total_matrices != manifest.accumulator.total_matrices {
        return Err(VmError::InvalidConfig(format!(
            "decoding lookup accumulator total_matrices={} does not match nested Phase 21 total_matrices={}",
            manifest.total_matrices, manifest.accumulator.total_matrices
        )));
    }
    if manifest.total_layouts != manifest.accumulator.total_layouts {
        return Err(VmError::InvalidConfig(format!(
            "decoding lookup accumulator total_layouts={} does not match nested Phase 21 total_layouts={}",
            manifest.total_layouts, manifest.accumulator.total_layouts
        )));
    }
    if manifest.total_rollups != manifest.accumulator.total_rollups {
        return Err(VmError::InvalidConfig(format!(
            "decoding lookup accumulator total_rollups={} does not match nested Phase 21 total_rollups={}",
            manifest.total_rollups, manifest.accumulator.total_rollups
        )));
    }
    if manifest.total_segments != manifest.accumulator.total_segments {
        return Err(VmError::InvalidConfig(format!(
            "decoding lookup accumulator total_segments={} does not match nested Phase 21 total_segments={}",
            manifest.total_segments, manifest.accumulator.total_segments
        )));
    }
    if manifest.total_steps != manifest.accumulator.total_steps {
        return Err(VmError::InvalidConfig(format!(
            "decoding lookup accumulator total_steps={} does not match nested Phase 21 total_steps={}",
            manifest.total_steps, manifest.accumulator.total_steps
        )));
    }

    let (derived_lookup_delta, derived_max_frontier_entries, total_rollup_boundaries) =
        derive_phase22_lookup_stats(&manifest.accumulator)?;
    if total_rollup_boundaries != manifest.total_rollups {
        return Err(VmError::InvalidConfig(format!(
            "decoding lookup accumulator derived total_rollups={} does not match declared total_rollups={}",
            total_rollup_boundaries, manifest.total_rollups
        )));
    }
    if manifest.lookup_delta_entries != derived_lookup_delta {
        return Err(VmError::InvalidConfig(format!(
            "decoding lookup accumulator lookup_delta_entries={} does not match derived lookup_delta_entries={}",
            manifest.lookup_delta_entries, derived_lookup_delta
        )));
    }
    if manifest.max_lookup_frontier_entries != derived_max_frontier_entries {
        return Err(VmError::InvalidConfig(format!(
            "decoding lookup accumulator max_lookup_frontier_entries={} does not match derived max_lookup_frontier_entries={}",
            manifest.max_lookup_frontier_entries, derived_max_frontier_entries
        )));
    }

    let expected_lookup_template = commit_phase22_lookup_template(&manifest.accumulator)?;
    if manifest.lookup_template_commitment != expected_lookup_template {
        return Err(VmError::InvalidConfig(
            "decoding lookup accumulator lookup_template_commitment does not match the computed lookup template commitment".to_string(),
        ));
    }
    let expected_lookup_accumulator = commit_phase22_lookup_accumulator(manifest)?;
    if manifest.lookup_accumulator_commitment != expected_lookup_accumulator {
        return Err(VmError::InvalidConfig(
            "decoding lookup accumulator lookup_accumulator_commitment does not match the computed lookup accumulator commitment".to_string(),
        ));
    }
    Ok(())
}

pub fn verify_phase22_decoding_lookup_accumulator_with_proof_checks(
    manifest: &Phase22DecodingLookupAccumulatorManifest,
) -> Result<()> {
    verify_phase22_decoding_lookup_accumulator(manifest)?;
    verify_phase21_decoding_matrix_accumulator_with_proof_checks(&manifest.accumulator).map_err(
        |error| {
            VmError::UnsupportedProof(format!(
                "decoding lookup accumulator source proof verification failed: {error}"
            ))
        },
    )?;
    Ok(())
}

fn collect_phase23_member_rollups<'a>(
    member: &'a Phase22DecodingLookupAccumulatorManifest,
    member_index: usize,
) -> Result<Vec<&'a Phase16DecodingHistoryRollup>> {
    let mut rollups = Vec::with_capacity(member.total_rollups);
    for (matrix_index, matrix) in member.accumulator.matrices.iter().enumerate() {
        for (layout_index, rollup_manifest) in matrix.rollups.iter().enumerate() {
            if rollup_manifest.rollups.is_empty() {
                return Err(VmError::InvalidConfig(format!(
                    "Phase 23 member {member_index} matrix {matrix_index} layout {layout_index} must contain at least one rollup"
                )));
            }
            for rollup in &rollup_manifest.rollups {
                rollups.push(rollup);
            }
        }
    }
    if rollups.is_empty() {
        return Err(VmError::InvalidConfig(format!(
            "Phase 23 member {member_index} must contain at least one flattened rollup"
        )));
    }
    Ok(rollups)
}

fn commit_phase23_boundary_state(state: &Phase14DecodingState) -> String {
    let mut hasher = Blake2bVar::new(32).expect("blake2b-256");
    hasher.update(STWO_DECODING_CROSS_STEP_LOOKUP_ACCUMULATOR_VERSION_PHASE23.as_bytes());
    hasher.update(b"boundary-state");
    hasher.update(&state.position.to_le_bytes());
    hasher.update(state.layout_commitment.as_bytes());
    hasher.update(state.persistent_state_commitment.as_bytes());
    hasher.update(state.kv_history_commitment.as_bytes());
    hasher.update(&(state.kv_history_length as u64).to_le_bytes());
    hasher.update(&(state.kv_history_chunk_size as u64).to_le_bytes());
    hasher.update(state.kv_history_sealed_commitment.as_bytes());
    hasher.update(&(state.kv_history_sealed_chunks as u64).to_le_bytes());
    hasher.update(state.kv_history_open_chunk_commitment.as_bytes());
    hasher.update(&(state.kv_history_open_chunk_pairs as u64).to_le_bytes());
    hasher.update(state.kv_history_frontier_commitment.as_bytes());
    hasher.update(&(state.kv_history_frontier_pairs as u64).to_le_bytes());
    hasher.update(state.lookup_transcript_commitment.as_bytes());
    hasher.update(&(state.lookup_transcript_entries as u64).to_le_bytes());
    hasher.update(state.lookup_frontier_commitment.as_bytes());
    hasher.update(&(state.lookup_frontier_entries as u64).to_le_bytes());
    hasher.update(state.kv_cache_commitment.as_bytes());
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("blake2b finalize");
    lower_hex(&out)
}

fn collect_phase23_member_segments<'a>(
    member: &'a Phase22DecodingLookupAccumulatorManifest,
    member_index: usize,
) -> Result<Vec<&'a Phase15DecodingHistorySegment>> {
    let mut segments = Vec::new();
    for (matrix_index, matrix) in member.accumulator.matrices.iter().enumerate() {
        for (layout_index, rollup_manifest) in matrix.rollups.iter().enumerate() {
            if rollup_manifest.rollups.is_empty() {
                return Err(VmError::InvalidConfig(format!(
                    "Phase 23 member {member_index} matrix {matrix_index} layout {layout_index} must contain at least one rollup"
                )));
            }
            for (rollup_index, rollup) in rollup_manifest.rollups.iter().enumerate() {
                if rollup.segments.is_empty() {
                    return Err(VmError::InvalidConfig(format!(
                        "Phase 23 member {member_index} matrix {matrix_index} layout {layout_index} rollup {rollup_index} must contain at least one segment"
                    )));
                }
                for segment in &rollup.segments {
                    segments.push(segment);
                }
            }
        }
    }
    if segments.is_empty() {
        return Err(VmError::InvalidConfig(format!(
            "Phase 23 member {member_index} must contain at least one flattened segment"
        )));
    }
    Ok(segments)
}

fn derive_phase23_member_boundary_commitment_at_step(
    member: &Phase22DecodingLookupAccumulatorManifest,
    member_index: usize,
    step_count: usize,
) -> Result<String> {
    let flattened_segments = collect_phase23_member_segments(member, member_index)?;
    if flattened_segments.len() != member.total_segments {
        return Err(VmError::InvalidConfig(format!(
            "Phase 23 member {member_index} flattened segment count {} does not match declared total_segments {}",
            flattened_segments.len(),
            member.total_segments
        )));
    }
    if step_count > member.total_steps {
        return Err(VmError::InvalidConfig(format!(
            "Phase 23 member {member_index} cannot derive a boundary at step {} beyond total_steps {}",
            step_count, member.total_steps
        )));
    }
    let first_segment = flattened_segments.first().ok_or_else(|| {
        VmError::InvalidConfig(format!(
            "Phase 23 member {member_index} must contain at least one flattened segment"
        ))
    })?;
    if step_count == 0 {
        return Ok(commit_phase23_boundary_state(
            &first_segment.global_from_state,
        ));
    }

    let mut consumed_steps = 0usize;
    for (segment_index, segment) in flattened_segments.iter().enumerate() {
        if segment.total_steps == 0 {
            return Err(VmError::InvalidConfig(format!(
                "Phase 23 member {member_index} segment {segment_index} must contain at least one step"
            )));
        }
        let next_consumed_steps = consumed_steps
            .checked_add(segment.total_steps)
            .ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "Phase 23 member {member_index} step count overflowed while deriving boundary commitments"
                ))
            })?;
        if step_count < next_consumed_steps {
            let local_step_count = step_count - consumed_steps;
            debug_assert!(local_step_count < segment.total_steps);
            let boundary_state = derive_phase23_boundary_state_within_segment(
                segment,
                member_index,
                segment_index,
                local_step_count,
            )?;
            return Ok(commit_phase23_boundary_state(boundary_state));
        }
        consumed_steps = next_consumed_steps;
        if step_count == consumed_steps {
            return Ok(commit_phase23_boundary_state(&segment.global_to_state));
        }
    }

    Err(VmError::InvalidConfig(format!(
        "Phase 23 member {member_index} step-aligned boundary derivation ended at {} instead of total_steps {}",
        consumed_steps, member.total_steps
    )))
}

fn derive_phase23_boundary_state_within_segment<'a>(
    segment: &'a Phase15DecodingHistorySegment,
    member_index: usize,
    segment_index: usize,
    local_step_count: usize,
) -> Result<&'a Phase14DecodingState> {
    if segment.chain.steps.len() != segment.total_steps {
        return Err(VmError::InvalidConfig(format!(
            "Phase 23 member {member_index} segment {segment_index} chain step count {} does not match segment total_steps {}",
            segment.chain.steps.len(),
            segment.total_steps
        )));
    }
    if local_step_count > segment.total_steps {
        return Err(VmError::InvalidConfig(format!(
            "Phase 23 member {member_index} segment {segment_index} cannot derive local boundary {} beyond segment total_steps {}",
            local_step_count, segment.total_steps
        )));
    }
    if local_step_count == 0 {
        return Ok(&segment.global_from_state);
    }
    if local_step_count == segment.total_steps {
        return Ok(&segment.global_to_state);
    }
    Ok(&segment.chain.steps[local_step_count - 1].to_state)
}

fn derive_phase23_member_boundary_commitments(
    member: &Phase22DecodingLookupAccumulatorManifest,
    member_index: usize,
) -> Result<(String, String)> {
    Ok((
        derive_phase23_member_boundary_commitment_at_step(member, member_index, 0)?,
        derive_phase23_member_boundary_commitment_at_step(
            member,
            member_index,
            member.total_steps,
        )?,
    ))
}

fn summarize_phase23_member(
    member: &Phase22DecodingLookupAccumulatorManifest,
    member_index: usize,
) -> Result<Phase23MemberSummary> {
    verify_phase22_decoding_lookup_accumulator(member).map_err(|error| {
        VmError::InvalidConfig(format!(
            "Phase 23 member {member_index} failed Phase 22 verification: {error}"
        ))
    })?;

    let flattened_rollups = collect_phase23_member_rollups(member, member_index)?;
    if flattened_rollups.len() != member.total_rollups {
        return Err(VmError::InvalidConfig(format!(
            "Phase 23 member {member_index} flattened rollup count {} does not match declared total_rollups {}",
            flattened_rollups.len(),
            member.total_rollups
        )));
    }
    if member.total_rollups > MAX_PHASE23_ACCUMULATOR_ROLLUPS {
        return Err(VmError::InvalidConfig(format!(
            "Phase 23 member {member_index} total_rollups {} exceed the supported maximum {}",
            member.total_rollups, MAX_PHASE23_ACCUMULATOR_ROLLUPS
        )));
    }

    for (flattened_index, window) in flattened_rollups.windows(2).enumerate() {
        validate_phase16_rollup_boundary(
            &window[0].global_to_state,
            &window[1].global_from_state,
            flattened_index + 1,
        )
        .map_err(|error| match error {
            VmError::InvalidConfig(message) => VmError::InvalidConfig(format!(
                "Phase 23 member {member_index} flattened rollup boundary {} -> {} failed: {message}",
                flattened_index,
                flattened_index + 1
            )),
            other => other,
        })?;
    }

    let (start_boundary_commitment, end_boundary_commitment) =
        derive_phase23_member_boundary_commitments(member, member_index)?;

    Ok(Phase23MemberSummary {
        total_matrices: member.total_matrices,
        total_layouts: member.total_layouts,
        total_rollups: member.total_rollups,
        total_segments: member.total_segments,
        total_steps: member.total_steps,
        lookup_delta_entries: member.lookup_delta_entries,
        max_lookup_frontier_entries: member.max_lookup_frontier_entries,
        source_template_commitment: member.source_template_commitment.clone(),
        start_boundary_commitment,
        end_boundary_commitment,
    })
}

fn summarize_phase23_members(
    members: &[Phase22DecodingLookupAccumulatorManifest],
) -> Result<Vec<Phase23MemberSummary>> {
    let mut summaries = Vec::with_capacity(members.len());
    for (member_index, member) in members.iter().enumerate() {
        summaries.push(summarize_phase23_member(member, member_index)?);
    }
    Ok(summaries)
}

fn verify_phase23_member_prefix_sequence(
    members: &[Phase22DecodingLookupAccumulatorManifest],
    summaries: &[Phase23MemberSummary],
) -> Result<()> {
    if members.is_empty() || summaries.is_empty() {
        return Err(VmError::InvalidConfig(
            "Phase 23 cross-step lookup accumulator requires at least one member".to_string(),
        ));
    }
    let first = summaries.first().expect("phase23 summaries are non-empty");
    for (member_index, summary) in summaries.iter().enumerate() {
        if summary.source_template_commitment != first.source_template_commitment {
            return Err(VmError::InvalidConfig(format!(
                "Phase 23 member {member_index} does not share the source template commitment of member 0"
            )));
        }
        if summary.start_boundary_commitment != first.start_boundary_commitment {
            return Err(VmError::InvalidConfig(format!(
                "Phase 23 member {member_index} does not share the starting decode-state boundary commitment of member 0"
            )));
        }
        if member_index == 0 {
            continue;
        }
        let previous = &summaries[member_index - 1];
        if summary.total_steps <= previous.total_steps {
            return Err(VmError::InvalidConfig(format!(
                "Phase 23 member {member_index} total_steps {} must strictly increase beyond member {} total_steps {}",
                summary.total_steps,
                member_index - 1,
                previous.total_steps
            )));
        }
        if summary.total_matrices < previous.total_matrices
            || summary.total_layouts < previous.total_layouts
            || summary.total_rollups < previous.total_rollups
            || summary.total_segments < previous.total_segments
            || summary.lookup_delta_entries < previous.lookup_delta_entries
        {
            return Err(VmError::InvalidConfig(format!(
                "Phase 23 member {member_index} must extend, not shrink, the previous cumulative member counts"
            )));
        }
        let expected_prefix_boundary = derive_phase23_member_boundary_commitment_at_step(
            &members[member_index],
            member_index,
            previous.total_steps,
        )?;
        if previous.end_boundary_commitment != expected_prefix_boundary {
            return Err(VmError::InvalidConfig(format!(
                "Phase 23 member boundary {} -> {} does not preserve the decode-state boundary commitment",
                member_index - 1,
                member_index
            )));
        }
    }
    Ok(())
}

fn derive_phase24_member_boundary_commitment_at_step_with_summaries(
    member: &Phase23DecodingCrossStepLookupAccumulatorManifest,
    member_index: usize,
    step_count: usize,
    summaries: &[Phase23MemberSummary],
) -> Result<String> {
    if step_count > member.total_steps {
        return Err(VmError::InvalidConfig(format!(
            "Phase 24 member {member_index} cannot derive a boundary at step {} beyond total_steps {}",
            step_count, member.total_steps
        )));
    }
    if step_count == 0 {
        return Ok(member.start_boundary_commitment.clone());
    }
    if step_count == member.total_steps {
        return Ok(member.end_boundary_commitment.clone());
    }
    if summaries.len() != member.members.len() {
        return Err(VmError::InvalidConfig(format!(
            "Phase 24 member {member_index} summaries.len()={} does not match nested members.len()={}",
            summaries.len(),
            member.members.len()
        )));
    }

    for (nested_index, summary) in summaries.iter().enumerate() {
        if summary.total_steps >= step_count {
            return derive_phase23_member_boundary_commitment_at_step(
                &member.members[nested_index],
                nested_index,
                step_count,
            )
            .map_err(|error| {
                VmError::InvalidConfig(format!(
                    "Phase 24 member {member_index} nested Phase 23 member {nested_index} could not derive a boundary at step {step_count}: {error}"
                ))
            });
        }
    }

    Err(VmError::InvalidConfig(format!(
        "Phase 24 member {member_index} could not derive a nested boundary commitment at step {}",
        step_count
    )))
}

fn summarize_phase24_members(
    members: &[Phase23DecodingCrossStepLookupAccumulatorManifest],
) -> Result<Vec<Phase24MemberSummary>> {
    let mut summaries = Vec::with_capacity(members.len());
    let mut previous_total_matrices = 0usize;
    let mut previous_total_layouts = 0usize;
    let mut previous_total_rollups = 0usize;
    let mut previous_total_segments = 0usize;
    let mut previous_total_steps = 0usize;
    let mut previous_lookup_delta_entries = 0usize;

    for (member_index, member) in members.iter().enumerate() {
        validate_phase23_decoding_cross_step_lookup_accumulator_shallow(member).map_err(
            |error| {
                VmError::InvalidConfig(format!(
                    "Phase 24 member {member_index} failed shallow Phase 23 validation: {error}"
                ))
            },
        )?;
        let phase23_summaries = summarize_phase23_members(&member.members)?;
        verify_phase23_decoding_cross_step_lookup_accumulator_with_summaries(
            member,
            &phase23_summaries,
        )
        .map_err(|error| {
            VmError::InvalidConfig(format!(
                "Phase 24 member {member_index} failed Phase 23 verification: {error}"
            ))
        })?;
        if member.total_steps <= previous_total_steps {
            return Err(VmError::InvalidConfig(format!(
                "Phase 24 member {member_index} total_steps {} must strictly increase beyond the previous total_steps {}",
                member.total_steps, previous_total_steps
            )));
        }
        if member.total_matrices < previous_total_matrices
            || member.total_layouts < previous_total_layouts
            || member.total_rollups < previous_total_rollups
            || member.total_segments < previous_total_segments
            || member.lookup_delta_entries < previous_lookup_delta_entries
        {
            return Err(VmError::InvalidConfig(format!(
                "Phase 24 member {member_index} must extend, not shrink, the previous cumulative member counts"
            )));
        }

        let start_state_commitment =
            derive_phase24_member_boundary_commitment_at_step_with_summaries(
                member,
                member_index,
                previous_total_steps,
                &phase23_summaries,
            )?;
        let end_state_commitment =
            derive_phase24_member_boundary_commitment_at_step_with_summaries(
                member,
                member_index,
                member.total_steps,
                &phase23_summaries,
            )?;

        summaries.push(Phase24MemberSummary {
            start_step: previous_total_steps,
            end_step: member.total_steps,
            total_matrices: member
                .total_matrices
                .checked_sub(previous_total_matrices)
                .ok_or_else(|| {
                    VmError::InvalidConfig(format!(
                        "Phase 24 member {member_index} total_matrices underflowed while deriving interval counts"
                    ))
                })?,
            total_layouts: member
                .total_layouts
                .checked_sub(previous_total_layouts)
                .ok_or_else(|| {
                    VmError::InvalidConfig(format!(
                        "Phase 24 member {member_index} total_layouts underflowed while deriving interval counts"
                    ))
                })?,
            total_rollups: member
                .total_rollups
                .checked_sub(previous_total_rollups)
                .ok_or_else(|| {
                    VmError::InvalidConfig(format!(
                        "Phase 24 member {member_index} total_rollups underflowed while deriving interval counts"
                    ))
                })?,
            total_segments: member
                .total_segments
                .checked_sub(previous_total_segments)
                .ok_or_else(|| {
                    VmError::InvalidConfig(format!(
                        "Phase 24 member {member_index} total_segments underflowed while deriving interval counts"
                    ))
                })?,
            total_steps: member
                .total_steps
                .checked_sub(previous_total_steps)
                .ok_or_else(|| {
                    VmError::InvalidConfig(format!(
                        "Phase 24 member {member_index} total_steps underflowed while deriving interval counts"
                    ))
                })?,
            lookup_delta_entries: member
                .lookup_delta_entries
                .checked_sub(previous_lookup_delta_entries)
                .ok_or_else(|| {
                    VmError::InvalidConfig(format!(
                        "Phase 24 member {member_index} lookup_delta_entries underflowed while deriving interval counts"
                    ))
                })?,
            max_lookup_frontier_entries: member.max_lookup_frontier_entries,
            source_template_commitment: member.source_template_commitment.clone(),
            lookup_template_commitment: member.lookup_template_commitment.clone(),
            lookup_accumulator_commitment: member.accumulator_commitment.clone(),
            start_state_commitment,
            end_state_commitment,
        });

        previous_total_matrices = member.total_matrices;
        previous_total_layouts = member.total_layouts;
        previous_total_rollups = member.total_rollups;
        previous_total_segments = member.total_segments;
        previous_total_steps = member.total_steps;
        previous_lookup_delta_entries = member.lookup_delta_entries;
    }
    Ok(summaries)
}

fn phase24_zero_rebase_baseline() -> Phase24RebaseBaseline {
    Phase24RebaseBaseline {
        total_matrices: 0,
        total_layouts: 0,
        total_rollups: 0,
        total_segments: 0,
        total_steps: 0,
        lookup_delta_entries: 0,
    }
}

fn phase24_rebase_baseline_from_cumulative_member(
    member: &Phase23DecodingCrossStepLookupAccumulatorManifest,
) -> Phase24RebaseBaseline {
    Phase24RebaseBaseline {
        total_matrices: member.total_matrices,
        total_layouts: member.total_layouts,
        total_rollups: member.total_rollups,
        total_segments: member.total_segments,
        total_steps: member.total_steps,
        lookup_delta_entries: member.lookup_delta_entries,
    }
}

fn derive_phase24_rebased_member_summaries(
    members: &[Phase23DecodingCrossStepLookupAccumulatorManifest],
    baseline: Phase24RebaseBaseline,
) -> Result<Vec<Phase24MemberSummary>> {
    let mut summaries = Vec::with_capacity(members.len());
    let mut previous_total_matrices = baseline.total_matrices;
    let mut previous_total_layouts = baseline.total_layouts;
    let mut previous_total_rollups = baseline.total_rollups;
    let mut previous_total_segments = baseline.total_segments;
    let mut previous_total_steps = baseline.total_steps;
    let mut previous_lookup_delta_entries = baseline.lookup_delta_entries;

    for (member_index, member) in members.iter().enumerate() {
        validate_phase23_decoding_cross_step_lookup_accumulator_shallow(member).map_err(
            |error| {
                VmError::InvalidConfig(format!(
                    "rebased Phase 24 member {member_index} failed shallow Phase 23 validation: {error}"
                ))
            },
        )?;
        let phase23_summaries = summarize_phase23_members(&member.members)?;
        verify_phase23_decoding_cross_step_lookup_accumulator_with_summaries(
            member,
            &phase23_summaries,
        )
        .map_err(|error| {
            VmError::InvalidConfig(format!(
                "rebased Phase 24 member {member_index} failed Phase 23 verification: {error}"
            ))
        })?;
        if member.total_steps <= previous_total_steps {
            return Err(VmError::InvalidConfig(format!(
                "rebased Phase 24 member {member_index} total_steps {} must strictly increase beyond the previous total_steps {}",
                member.total_steps, previous_total_steps
            )));
        }
        if member.total_matrices < previous_total_matrices
            || member.total_layouts < previous_total_layouts
            || member.total_rollups < previous_total_rollups
            || member.total_segments < previous_total_segments
            || member.lookup_delta_entries < previous_lookup_delta_entries
        {
            return Err(VmError::InvalidConfig(format!(
                "rebased Phase 24 member {member_index} must extend, not shrink, the rebased cumulative counts"
            )));
        }

        let start_state_commitment =
            derive_phase24_member_boundary_commitment_at_step_with_summaries(
                member,
                member_index,
                previous_total_steps,
                &phase23_summaries,
            )?;
        let end_state_commitment =
            derive_phase24_member_boundary_commitment_at_step_with_summaries(
                member,
                member_index,
                member.total_steps,
                &phase23_summaries,
            )?;

        summaries.push(Phase24MemberSummary {
            start_step: previous_total_steps
                .checked_sub(baseline.total_steps)
                .ok_or_else(|| {
                    VmError::InvalidConfig(format!(
                        "rebased Phase 24 member {member_index} start_step underflowed"
                    ))
                })?,
            end_step: member
                .total_steps
                .checked_sub(baseline.total_steps)
                .ok_or_else(|| {
                    VmError::InvalidConfig(format!(
                        "rebased Phase 24 member {member_index} end_step underflowed"
                    ))
                })?,
            total_matrices: member
                .total_matrices
                .checked_sub(previous_total_matrices)
                .ok_or_else(|| {
                    VmError::InvalidConfig(format!(
                        "rebased Phase 24 member {member_index} total_matrices underflowed while deriving interval counts"
                    ))
                })?,
            total_layouts: member
                .total_layouts
                .checked_sub(previous_total_layouts)
                .ok_or_else(|| {
                    VmError::InvalidConfig(format!(
                        "rebased Phase 24 member {member_index} total_layouts underflowed while deriving interval counts"
                    ))
                })?,
            total_rollups: member
                .total_rollups
                .checked_sub(previous_total_rollups)
                .ok_or_else(|| {
                    VmError::InvalidConfig(format!(
                        "rebased Phase 24 member {member_index} total_rollups underflowed while deriving interval counts"
                    ))
                })?,
            total_segments: member
                .total_segments
                .checked_sub(previous_total_segments)
                .ok_or_else(|| {
                    VmError::InvalidConfig(format!(
                        "rebased Phase 24 member {member_index} total_segments underflowed while deriving interval counts"
                    ))
                })?,
            total_steps: member.total_steps.checked_sub(previous_total_steps).ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "rebased Phase 24 member {member_index} total_steps underflowed while deriving interval counts"
                ))
            })?,
            lookup_delta_entries: member
                .lookup_delta_entries
                .checked_sub(previous_lookup_delta_entries)
                .ok_or_else(|| {
                    VmError::InvalidConfig(format!(
                        "rebased Phase 24 member {member_index} lookup_delta_entries underflowed while deriving interval counts"
                    ))
                })?,
            max_lookup_frontier_entries: member.max_lookup_frontier_entries,
            source_template_commitment: member.source_template_commitment.clone(),
            lookup_template_commitment: member.lookup_template_commitment.clone(),
            lookup_accumulator_commitment: member.accumulator_commitment.clone(),
            start_state_commitment,
            end_state_commitment,
        });

        previous_total_matrices = member.total_matrices;
        previous_total_layouts = member.total_layouts;
        previous_total_rollups = member.total_rollups;
        previous_total_segments = member.total_segments;
        previous_total_steps = member.total_steps;
        previous_lookup_delta_entries = member.lookup_delta_entries;
    }

    Ok(summaries)
}

fn prepare_phase24_rebased_source_manifest(
    members: &[Phase23DecodingCrossStepLookupAccumulatorManifest],
    baseline: Phase24RebaseBaseline,
    proof_backend_version: &str,
    statement_version: &str,
) -> Result<(
    Phase24DecodingStateRelationAccumulatorManifest,
    Vec<Phase24MemberSummary>,
)> {
    if members.len() < 2 {
        return Err(VmError::InvalidConfig(
            "rebased Phase 24 source requires at least two cumulative members".to_string(),
        ));
    }
    if members.len() > MAX_PHASE24_ACCUMULATOR_MEMBERS {
        return Err(VmError::InvalidConfig(format!(
            "rebased Phase 24 source supports at most {MAX_PHASE24_ACCUMULATOR_MEMBERS} members (got {})",
            members.len()
        )));
    }

    let summaries = derive_phase24_rebased_member_summaries(members, baseline)?;
    verify_phase24_member_relation_sequence(&summaries)?;

    let mut total_matrices = 0usize;
    let mut total_layouts = 0usize;
    let mut total_rollups = 0usize;
    let mut total_segments = 0usize;
    let mut total_steps = 0usize;
    let mut lookup_delta_entries = 0usize;
    let mut max_lookup_frontier_entries = 0usize;
    for (member_index, summary) in summaries.iter().enumerate() {
        total_matrices = total_matrices
            .checked_add(summary.total_matrices)
            .ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "rebased Phase 24 total_matrices overflowed while adding member {member_index}"
                ))
            })?;
        total_layouts = total_layouts
            .checked_add(summary.total_layouts)
            .ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "rebased Phase 24 total_layouts overflowed while adding member {member_index}"
                ))
            })?;
        total_rollups = total_rollups
            .checked_add(summary.total_rollups)
            .ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "rebased Phase 24 total_rollups overflowed while adding member {member_index}"
                ))
            })?;
        total_segments = total_segments
            .checked_add(summary.total_segments)
            .ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "rebased Phase 24 total_segments overflowed while adding member {member_index}"
                ))
            })?;
        total_steps = total_steps
            .checked_add(summary.total_steps)
            .ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "rebased Phase 24 total_steps overflowed while adding member {member_index}"
                ))
            })?;
        lookup_delta_entries = lookup_delta_entries
            .checked_add(summary.lookup_delta_entries)
            .ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "rebased Phase 24 lookup_delta_entries overflowed while adding member {member_index}"
                ))
            })?;
        max_lookup_frontier_entries =
            max_lookup_frontier_entries.max(summary.max_lookup_frontier_entries);
    }
    if total_rollups > MAX_PHASE24_ACCUMULATOR_ROLLUPS {
        return Err(VmError::InvalidConfig(format!(
            "rebased Phase 24 total_rollups {} exceed the supported maximum {}",
            total_rollups, MAX_PHASE24_ACCUMULATOR_ROLLUPS
        )));
    }

    let first = summaries
        .first()
        .expect("rebased phase24 summaries are non-empty");
    let last = summaries
        .last()
        .expect("rebased phase24 summaries are non-empty");
    let relation_template_commitment = commit_phase24_relation_template(&summaries)?;
    let mut manifest = Phase24DecodingStateRelationAccumulatorManifest {
        proof_backend: StarkProofBackend::Stwo,
        accumulator_version: STWO_DECODING_STATE_RELATION_ACCUMULATOR_VERSION_PHASE24.to_string(),
        semantic_scope: STWO_DECODING_STATE_RELATION_ACCUMULATOR_SCOPE_PHASE24.to_string(),
        proof_backend_version: proof_backend_version.to_string(),
        statement_version: statement_version.to_string(),
        member_count: members.len(),
        total_matrices,
        total_layouts,
        total_rollups,
        total_segments,
        total_steps,
        lookup_delta_entries,
        max_lookup_frontier_entries,
        source_template_commitment: first.source_template_commitment.clone(),
        start_state_commitment: first.start_state_commitment.clone(),
        end_state_commitment: last.end_state_commitment.clone(),
        relation_template_commitment,
        relation_accumulator_commitment: String::new(),
        member_summaries: phase24_public_member_summaries(&summaries),
        members: members.to_vec(),
    };
    manifest.relation_accumulator_commitment =
        commit_phase24_state_relation_accumulator_with_summaries(&manifest, &summaries)?;
    verify_phase24_decoding_state_relation_accumulator_with_summaries(&manifest, &summaries)?;
    Ok((manifest, summaries))
}

fn validate_phase23_decoding_cross_step_lookup_accumulator_shallow(
    manifest: &Phase23DecodingCrossStepLookupAccumulatorManifest,
) -> Result<()> {
    if manifest.proof_backend != StarkProofBackend::Stwo {
        return Err(VmError::InvalidConfig(format!(
            "decoding cross-step lookup accumulator backend `{}` is not `stwo`",
            manifest.proof_backend
        )));
    }
    if manifest.accumulator_version != STWO_DECODING_CROSS_STEP_LOOKUP_ACCUMULATOR_VERSION_PHASE23 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding cross-step lookup accumulator version `{}`",
            manifest.accumulator_version
        )));
    }
    if manifest.semantic_scope != STWO_DECODING_CROSS_STEP_LOOKUP_ACCUMULATOR_SCOPE_PHASE23 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding cross-step lookup accumulator semantic scope `{}`",
            manifest.semantic_scope
        )));
    }
    if manifest.proof_backend_version != crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding cross-step lookup accumulator proof backend version `{}` (expected `{}`)",
            manifest.proof_backend_version,
            crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12
        )));
    }
    if manifest.statement_version != crate::proof::CLAIM_STATEMENT_VERSION_V1 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding cross-step lookup accumulator statement version `{}`",
            manifest.statement_version
        )));
    }
    if manifest.members.is_empty() {
        return Err(VmError::InvalidConfig(
            "decoding cross-step lookup accumulator must contain at least one member".to_string(),
        ));
    }
    if manifest.members.len() > MAX_PHASE23_ACCUMULATOR_MEMBERS {
        return Err(VmError::InvalidConfig(format!(
            "decoding cross-step lookup accumulator members.len()={} exceeds the supported maximum {}",
            manifest.members.len(),
            MAX_PHASE23_ACCUMULATOR_MEMBERS
        )));
    }
    if manifest.member_count != manifest.members.len() {
        return Err(VmError::InvalidConfig(format!(
            "decoding cross-step lookup accumulator member_count={} does not match members.len()={}",
            manifest.member_count,
            manifest.members.len()
        )));
    }
    if manifest.total_rollups > MAX_PHASE23_ACCUMULATOR_ROLLUPS {
        return Err(VmError::InvalidConfig(format!(
            "decoding cross-step lookup accumulator total_rollups={} exceeds the supported maximum {}",
            manifest.total_rollups,
            MAX_PHASE23_ACCUMULATOR_ROLLUPS
        )));
    }
    Ok(())
}

fn verify_phase24_member_relation_sequence(summaries: &[Phase24MemberSummary]) -> Result<()> {
    if summaries.len() < 2 {
        return Err(VmError::InvalidConfig(
            "Phase 24 state relation accumulator requires at least two members".to_string(),
        ));
    }
    let first = summaries.first().expect("phase24 summaries are non-empty");
    if first.total_steps == 0 {
        return Err(VmError::InvalidConfig(
            "Phase 24 member 0 must cover at least one step".to_string(),
        ));
    }
    for (member_index, summary) in summaries.iter().enumerate() {
        if summary.total_steps == 0 {
            return Err(VmError::InvalidConfig(format!(
                "Phase 24 member {member_index} must cover at least one step"
            )));
        }
        if summary.start_step >= summary.end_step {
            return Err(VmError::InvalidConfig(format!(
                "Phase 24 member {member_index} has invalid interval [{}..{})",
                summary.start_step, summary.end_step
            )));
        }
        if summary.end_step - summary.start_step != summary.total_steps {
            return Err(VmError::InvalidConfig(format!(
                "Phase 24 member {member_index} interval width {} does not match total_steps {}",
                summary.end_step - summary.start_step,
                summary.total_steps
            )));
        }
        if summary.source_template_commitment != first.source_template_commitment {
            return Err(VmError::InvalidConfig(format!(
                "Phase 24 member {member_index} does not share the source template commitment of member 0"
            )));
        }
        if summary.lookup_template_commitment.is_empty() {
            return Err(VmError::InvalidConfig(format!(
                "Phase 24 member {member_index} has an empty lookup_template_commitment"
            )));
        }
        if summary.lookup_accumulator_commitment.is_empty() {
            return Err(VmError::InvalidConfig(format!(
                "Phase 24 member {member_index} has an empty lookup_accumulator_commitment"
            )));
        }
        if summary.start_state_commitment.is_empty() || summary.end_state_commitment.is_empty() {
            return Err(VmError::InvalidConfig(format!(
                "Phase 24 member {member_index} has an empty state-boundary commitment"
            )));
        }
        if member_index == 0 {
            continue;
        }
        let previous = &summaries[member_index - 1];
        if summary.start_step != previous.end_step {
            return Err(VmError::InvalidConfig(format!(
                "Phase 24 member {} interval [{}..{}) is not contiguous with member {} interval [{}..{})",
                member_index,
                summary.start_step,
                summary.end_step,
                member_index - 1,
                previous.start_step,
                previous.end_step
            )));
        }
        if summary.start_state_commitment != previous.end_state_commitment {
            return Err(VmError::InvalidConfig(format!(
                "Phase 24 member boundary {} -> {} does not preserve the full carried-state commitment",
                member_index - 1,
                member_index
            )));
        }
    }
    Ok(())
}

fn validate_phase24_decoding_state_relation_accumulator_shallow(
    manifest: &Phase24DecodingStateRelationAccumulatorManifest,
) -> Result<()> {
    if manifest.proof_backend != StarkProofBackend::Stwo {
        return Err(VmError::InvalidConfig(format!(
            "decoding state relation accumulator backend `{}` is not `stwo`",
            manifest.proof_backend
        )));
    }
    if manifest.accumulator_version != STWO_DECODING_STATE_RELATION_ACCUMULATOR_VERSION_PHASE24 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding state relation accumulator version `{}`",
            manifest.accumulator_version
        )));
    }
    if manifest.semantic_scope != STWO_DECODING_STATE_RELATION_ACCUMULATOR_SCOPE_PHASE24 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding state relation accumulator semantic scope `{}`",
            manifest.semantic_scope
        )));
    }
    if manifest.proof_backend_version != crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding state relation accumulator proof backend version `{}` (expected `{}`)",
            manifest.proof_backend_version,
            crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12
        )));
    }
    if manifest.statement_version != crate::proof::CLAIM_STATEMENT_VERSION_V1 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding state relation accumulator statement version `{}`",
            manifest.statement_version
        )));
    }
    if manifest.members.len() < 2 {
        return Err(VmError::InvalidConfig(
            "decoding state relation accumulator must contain at least two members".to_string(),
        ));
    }
    if manifest.members.len() > MAX_PHASE24_ACCUMULATOR_MEMBERS {
        return Err(VmError::InvalidConfig(format!(
            "decoding state relation accumulator members.len()={} exceeds the supported maximum {}",
            manifest.members.len(),
            MAX_PHASE24_ACCUMULATOR_MEMBERS
        )));
    }
    if manifest.member_count != manifest.members.len() {
        return Err(VmError::InvalidConfig(format!(
            "decoding state relation accumulator member_count={} does not match members.len()={}",
            manifest.member_count,
            manifest.members.len()
        )));
    }
    if manifest.member_summaries.len() != manifest.members.len() {
        return Err(VmError::InvalidConfig(format!(
            "decoding state relation accumulator member_summaries.len()={} does not match members.len()={}",
            manifest.member_summaries.len(),
            manifest.members.len()
        )));
    }
    if manifest.total_rollups > MAX_PHASE24_ACCUMULATOR_ROLLUPS {
        return Err(VmError::InvalidConfig(format!(
            "decoding state relation accumulator total_rollups={} exceeds the supported maximum {}",
            manifest.total_rollups, MAX_PHASE24_ACCUMULATOR_ROLLUPS
        )));
    }
    let mut total_nested_phase23_members = 0usize;
    for (member_index, member) in manifest.members.iter().enumerate() {
        total_nested_phase23_members = total_nested_phase23_members
            .checked_add(member.members.len())
            .ok_or_else(|| {
                VmError::InvalidConfig(
                    "decoding state relation accumulator total nested Phase 23 members overflowed"
                        .to_string(),
                )
            })?;
        if total_nested_phase23_members > MAX_PHASE24_TOTAL_NESTED_PHASE23_MEMBERS {
            return Err(VmError::InvalidConfig(format!(
                "decoding state relation accumulator total nested Phase 23 members {} exceeds the supported maximum {} at member {}",
                total_nested_phase23_members,
                MAX_PHASE24_TOTAL_NESTED_PHASE23_MEMBERS,
                member_index
            )));
        }
    }
    if manifest.source_template_commitment.is_empty() {
        return Err(VmError::InvalidConfig(
            "decoding state relation accumulator source_template_commitment must not be empty"
                .to_string(),
        ));
    }
    if manifest.start_state_commitment.is_empty() || manifest.end_state_commitment.is_empty() {
        return Err(VmError::InvalidConfig(
            "decoding state relation accumulator state-boundary commitments must not be empty"
                .to_string(),
        ));
    }
    if manifest.relation_template_commitment.is_empty() {
        return Err(VmError::InvalidConfig(
            "decoding state relation accumulator relation_template_commitment must not be empty"
                .to_string(),
        ));
    }
    if manifest.relation_accumulator_commitment.is_empty() {
        return Err(VmError::InvalidConfig(
            "decoding state relation accumulator relation_accumulator_commitment must not be empty"
                .to_string(),
        ));
    }
    Ok(())
}

fn phase24_public_member_summaries(
    summaries: &[Phase24MemberSummary],
) -> Vec<Phase24DecodingStateRelationMemberSummary> {
    summaries
        .iter()
        .map(|summary| Phase24DecodingStateRelationMemberSummary {
            start_step: summary.start_step,
            end_step: summary.end_step,
            total_matrices: summary.total_matrices,
            total_layouts: summary.total_layouts,
            total_rollups: summary.total_rollups,
            total_segments: summary.total_segments,
            total_steps: summary.total_steps,
            lookup_delta_entries: summary.lookup_delta_entries,
            max_lookup_frontier_entries: summary.max_lookup_frontier_entries,
            source_template_commitment: summary.source_template_commitment.clone(),
            lookup_template_commitment: summary.lookup_template_commitment.clone(),
            lookup_accumulator_commitment: summary.lookup_accumulator_commitment.clone(),
            start_state_commitment: summary.start_state_commitment.clone(),
            end_state_commitment: summary.end_state_commitment.clone(),
        })
        .collect()
}

fn commit_phase24_relation_template(summaries: &[Phase24MemberSummary]) -> Result<String> {
    verify_phase24_member_relation_sequence(summaries)?;

    let mut hasher = Blake2bVar::new(32).expect("blake2b-256");
    hasher.update(STWO_DECODING_STATE_RELATION_ACCUMULATOR_VERSION_PHASE24.as_bytes());
    hasher.update(b"relation-template");
    hasher.update(&(summaries.len() as u64).to_le_bytes());
    hasher.update(summaries[0].source_template_commitment.as_bytes());
    for (member_index, summary) in summaries.iter().enumerate() {
        hasher.update(&(member_index as u64).to_le_bytes());
        hasher.update(summary.lookup_template_commitment.as_bytes());
        hasher.update(&(summary.total_matrices as u64).to_le_bytes());
        hasher.update(&(summary.total_layouts as u64).to_le_bytes());
        hasher.update(&(summary.total_rollups as u64).to_le_bytes());
        hasher.update(&(summary.total_segments as u64).to_le_bytes());
        hasher.update(&(summary.total_steps as u64).to_le_bytes());
    }

    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("blake2b finalize");
    Ok(lower_hex(&out))
}

fn commit_phase23_lookup_template(
    members: &[Phase22DecodingLookupAccumulatorManifest],
) -> Result<String> {
    if members.is_empty() {
        return Err(VmError::InvalidConfig(
            "Phase 23 lookup template requires at least one member".to_string(),
        ));
    }

    let mut hasher = Blake2bVar::new(32).expect("blake2b-256");
    hasher.update(STWO_DECODING_CROSS_STEP_LOOKUP_ACCUMULATOR_VERSION_PHASE23.as_bytes());
    hasher.update(b"lookup-template");
    hasher.update(&(members.len() as u64).to_le_bytes());
    for (member_index, member) in members.iter().enumerate() {
        if member.lookup_template_commitment.is_empty() {
            return Err(VmError::InvalidConfig(format!(
                "Phase 23 lookup template member {member_index} has an empty lookup_template_commitment"
            )));
        }
        hasher.update(&(member_index as u64).to_le_bytes());
        hasher.update(member.source_template_commitment.as_bytes());
        hasher.update(member.lookup_template_commitment.as_bytes());
        hasher.update(&(member.total_matrices as u64).to_le_bytes());
        hasher.update(&(member.total_layouts as u64).to_le_bytes());
        hasher.update(&(member.total_rollups as u64).to_le_bytes());
        hasher.update(&(member.total_segments as u64).to_le_bytes());
        hasher.update(&(member.total_steps as u64).to_le_bytes());
    }

    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("blake2b finalize");
    Ok(lower_hex(&out))
}

pub fn phase23_prepare_decoding_cross_step_lookup_accumulator(
    members: &[Phase22DecodingLookupAccumulatorManifest],
) -> Result<Phase23DecodingCrossStepLookupAccumulatorManifest> {
    if members.is_empty() {
        return Err(VmError::InvalidConfig(
            "Phase 23 cross-step lookup accumulator requires at least one Phase 22 member"
                .to_string(),
        ));
    }
    if members.len() > MAX_PHASE23_ACCUMULATOR_MEMBERS {
        return Err(VmError::InvalidConfig(format!(
            "Phase 23 cross-step lookup accumulator supports at most {MAX_PHASE23_ACCUMULATOR_MEMBERS} members (got {})",
            members.len()
        )));
    }

    let summaries = summarize_phase23_members(members)?;
    verify_phase23_member_prefix_sequence(members, &summaries)?;

    let first = summaries.first().expect("phase23 summaries are non-empty");
    let last = summaries.last().expect("phase23 summaries are non-empty");
    let total_matrices = last.total_matrices;
    let total_layouts = last.total_layouts;
    let total_rollups = last.total_rollups;
    let total_segments = last.total_segments;
    let total_steps = last.total_steps;
    let lookup_delta_entries = last.lookup_delta_entries;
    let max_lookup_frontier_entries = summaries
        .iter()
        .map(|summary| summary.max_lookup_frontier_entries)
        .max()
        .unwrap_or(0);

    if total_rollups > MAX_PHASE23_ACCUMULATOR_ROLLUPS {
        return Err(VmError::InvalidConfig(format!(
            "Phase 23 total_rollups {} exceed the supported maximum {}",
            total_rollups, MAX_PHASE23_ACCUMULATOR_ROLLUPS
        )));
    }

    let mut manifest = Phase23DecodingCrossStepLookupAccumulatorManifest {
        proof_backend: StarkProofBackend::Stwo,
        accumulator_version: STWO_DECODING_CROSS_STEP_LOOKUP_ACCUMULATOR_VERSION_PHASE23
            .to_string(),
        semantic_scope: STWO_DECODING_CROSS_STEP_LOOKUP_ACCUMULATOR_SCOPE_PHASE23.to_string(),
        proof_backend_version: members[0].proof_backend_version.clone(),
        statement_version: members[0].statement_version.clone(),
        member_count: members.len(),
        total_matrices,
        total_layouts,
        total_rollups,
        total_segments,
        total_steps,
        lookup_delta_entries,
        max_lookup_frontier_entries,
        source_template_commitment: first.source_template_commitment.clone(),
        lookup_template_commitment: commit_phase23_lookup_template(members)?,
        start_boundary_commitment: first.start_boundary_commitment.clone(),
        end_boundary_commitment: last.end_boundary_commitment.clone(),
        accumulator_commitment: String::new(),
        members: members.to_vec(),
    };
    manifest.accumulator_commitment =
        commit_phase23_lookup_accumulator_with_summaries(&manifest, &summaries)?;
    verify_phase23_decoding_cross_step_lookup_accumulator_with_summaries(&manifest, &summaries)?;
    Ok(manifest)
}

fn verify_phase23_decoding_cross_step_lookup_accumulator_with_summaries(
    manifest: &Phase23DecodingCrossStepLookupAccumulatorManifest,
    summaries: &[Phase23MemberSummary],
) -> Result<()> {
    if manifest.proof_backend != StarkProofBackend::Stwo {
        return Err(VmError::InvalidConfig(format!(
            "decoding cross-step lookup accumulator backend `{}` is not `stwo`",
            manifest.proof_backend
        )));
    }
    if manifest.accumulator_version != STWO_DECODING_CROSS_STEP_LOOKUP_ACCUMULATOR_VERSION_PHASE23 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding cross-step lookup accumulator version `{}`",
            manifest.accumulator_version
        )));
    }
    if manifest.semantic_scope != STWO_DECODING_CROSS_STEP_LOOKUP_ACCUMULATOR_SCOPE_PHASE23 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding cross-step lookup accumulator semantic scope `{}`",
            manifest.semantic_scope
        )));
    }
    if manifest.proof_backend_version != crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding cross-step lookup accumulator proof backend version `{}` (expected `{}`)",
            manifest.proof_backend_version,
            crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12
        )));
    }
    if manifest.statement_version != crate::proof::CLAIM_STATEMENT_VERSION_V1 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding cross-step lookup accumulator statement version `{}`",
            manifest.statement_version
        )));
    }
    if manifest.members.is_empty() {
        return Err(VmError::InvalidConfig(
            "decoding cross-step lookup accumulator must contain at least one member".to_string(),
        ));
    }
    if manifest.members.len() > MAX_PHASE23_ACCUMULATOR_MEMBERS {
        return Err(VmError::InvalidConfig(format!(
            "decoding cross-step lookup accumulator members.len()={} exceeds the supported maximum {}",
            manifest.members.len(),
            MAX_PHASE23_ACCUMULATOR_MEMBERS
        )));
    }
    if manifest.member_count != manifest.members.len() {
        return Err(VmError::InvalidConfig(format!(
            "decoding cross-step lookup accumulator member_count={} does not match members.len()={}",
            manifest.member_count,
            manifest.members.len()
        )));
    }
    if manifest.total_rollups > MAX_PHASE23_ACCUMULATOR_ROLLUPS {
        return Err(VmError::InvalidConfig(format!(
            "decoding cross-step lookup accumulator total_rollups={} exceeds the supported maximum {}",
            manifest.total_rollups, MAX_PHASE23_ACCUMULATOR_ROLLUPS
        )));
    }
    if manifest.source_template_commitment.is_empty() {
        return Err(VmError::InvalidConfig(
            "decoding cross-step lookup accumulator source_template_commitment must not be empty"
                .to_string(),
        ));
    }
    if manifest.lookup_template_commitment.is_empty() {
        return Err(VmError::InvalidConfig(
            "decoding cross-step lookup accumulator lookup_template_commitment must not be empty"
                .to_string(),
        ));
    }
    if manifest.start_boundary_commitment.is_empty() {
        return Err(VmError::InvalidConfig(
            "decoding cross-step lookup accumulator start_boundary_commitment must not be empty"
                .to_string(),
        ));
    }
    if manifest.end_boundary_commitment.is_empty() {
        return Err(VmError::InvalidConfig(
            "decoding cross-step lookup accumulator end_boundary_commitment must not be empty"
                .to_string(),
        ));
    }
    if manifest.accumulator_commitment.is_empty() {
        return Err(VmError::InvalidConfig(
            "decoding cross-step lookup accumulator accumulator_commitment must not be empty"
                .to_string(),
        ));
    }

    for (member_index, member) in manifest.members.iter().enumerate() {
        if member.proof_backend_version != manifest.proof_backend_version {
            return Err(VmError::InvalidConfig(format!(
                "decoding cross-step lookup accumulator member {member_index} proof backend version `{}` does not match manifest `{}`",
                member.proof_backend_version, manifest.proof_backend_version
            )));
        }
        if member.statement_version != manifest.statement_version {
            return Err(VmError::InvalidConfig(format!(
                "decoding cross-step lookup accumulator member {member_index} statement version `{}` does not match manifest `{}`",
                member.statement_version, manifest.statement_version
            )));
        }
    }
    if summaries.len() != manifest.members.len() {
        return Err(VmError::InvalidConfig(format!(
            "decoding cross-step lookup accumulator summaries.len()={} does not match members.len()={}",
            summaries.len(),
            manifest.members.len()
        )));
    }
    verify_phase23_member_prefix_sequence(&manifest.members, summaries)?;

    let first = summaries.first().expect("phase23 summaries are non-empty");
    let last = summaries.last().expect("phase23 summaries are non-empty");

    let derived_total_matrices: usize = last.total_matrices;
    if manifest.total_matrices != derived_total_matrices {
        return Err(VmError::InvalidConfig(format!(
            "decoding cross-step lookup accumulator total_matrices={} does not match derived total_matrices={}",
            manifest.total_matrices, derived_total_matrices
        )));
    }
    let derived_total_layouts: usize = last.total_layouts;
    if manifest.total_layouts != derived_total_layouts {
        return Err(VmError::InvalidConfig(format!(
            "decoding cross-step lookup accumulator total_layouts={} does not match derived total_layouts={}",
            manifest.total_layouts, derived_total_layouts
        )));
    }
    let derived_total_rollups: usize = last.total_rollups;
    if manifest.total_rollups != derived_total_rollups {
        return Err(VmError::InvalidConfig(format!(
            "decoding cross-step lookup accumulator total_rollups={} does not match derived total_rollups={}",
            manifest.total_rollups, derived_total_rollups
        )));
    }
    let derived_total_segments: usize = last.total_segments;
    if manifest.total_segments != derived_total_segments {
        return Err(VmError::InvalidConfig(format!(
            "decoding cross-step lookup accumulator total_segments={} does not match derived total_segments={}",
            manifest.total_segments, derived_total_segments
        )));
    }
    let derived_total_steps: usize = last.total_steps;
    if manifest.total_steps != derived_total_steps {
        return Err(VmError::InvalidConfig(format!(
            "decoding cross-step lookup accumulator total_steps={} does not match derived total_steps={}",
            manifest.total_steps, derived_total_steps
        )));
    }
    let derived_lookup_delta_entries: usize = last.lookup_delta_entries;
    if manifest.lookup_delta_entries != derived_lookup_delta_entries {
        return Err(VmError::InvalidConfig(format!(
            "decoding cross-step lookup accumulator lookup_delta_entries={} does not match derived lookup_delta_entries={}",
            manifest.lookup_delta_entries, derived_lookup_delta_entries
        )));
    }
    let derived_max_lookup_frontier_entries = summaries
        .iter()
        .map(|summary| summary.max_lookup_frontier_entries)
        .max()
        .unwrap_or(0);
    if manifest.max_lookup_frontier_entries != derived_max_lookup_frontier_entries {
        return Err(VmError::InvalidConfig(format!(
            "decoding cross-step lookup accumulator max_lookup_frontier_entries={} does not match derived max_lookup_frontier_entries={}",
            manifest.max_lookup_frontier_entries, derived_max_lookup_frontier_entries
        )));
    }
    if manifest.source_template_commitment != first.source_template_commitment {
        return Err(VmError::InvalidConfig(
            "decoding cross-step lookup accumulator source_template_commitment does not match the shared member template commitment".to_string(),
        ));
    }
    if summaries
        .iter()
        .any(|summary| summary.source_template_commitment != first.source_template_commitment)
    {
        return Err(VmError::InvalidConfig(
            "decoding cross-step lookup accumulator members do not share a common source template commitment".to_string(),
        ));
    }
    if manifest.start_boundary_commitment != first.start_boundary_commitment {
        return Err(VmError::InvalidConfig(
            "decoding cross-step lookup accumulator start_boundary_commitment does not match the first member boundary".to_string(),
        ));
    }
    if manifest.end_boundary_commitment != last.end_boundary_commitment {
        return Err(VmError::InvalidConfig(
            "decoding cross-step lookup accumulator end_boundary_commitment does not match the last member boundary".to_string(),
        ));
    }

    let expected_lookup_template_commitment = commit_phase23_lookup_template(&manifest.members)?;
    if manifest.lookup_template_commitment != expected_lookup_template_commitment {
        return Err(VmError::InvalidConfig(
            "decoding cross-step lookup accumulator lookup_template_commitment does not match the computed member lookup template commitment".to_string(),
        ));
    }

    let expected_accumulator_commitment =
        commit_phase23_lookup_accumulator_with_summaries(manifest, summaries)?;
    if manifest.accumulator_commitment != expected_accumulator_commitment {
        return Err(VmError::InvalidConfig(
            "decoding cross-step lookup accumulator accumulator_commitment does not match the computed accumulator commitment".to_string(),
        ));
    }
    Ok(())
}

pub fn verify_phase23_decoding_cross_step_lookup_accumulator(
    manifest: &Phase23DecodingCrossStepLookupAccumulatorManifest,
) -> Result<()> {
    validate_phase23_decoding_cross_step_lookup_accumulator_shallow(manifest)?;
    let summaries = summarize_phase23_members(&manifest.members)?;
    verify_phase23_decoding_cross_step_lookup_accumulator_with_summaries(manifest, &summaries)
}

fn verify_phase23_decoding_cross_step_lookup_accumulator_members_with_proof_checks(
    manifest: &Phase23DecodingCrossStepLookupAccumulatorManifest,
) -> Result<()> {
    for (member_index, member) in manifest.members.iter().enumerate() {
        verify_phase22_decoding_lookup_accumulator_with_proof_checks(member).map_err(|error| {
            VmError::UnsupportedProof(format!(
                "decoding cross-step lookup accumulator member {member_index} failed verification: {error}"
            ))
        })?;
    }
    Ok(())
}

pub fn verify_phase23_decoding_cross_step_lookup_accumulator_with_proof_checks(
    manifest: &Phase23DecodingCrossStepLookupAccumulatorManifest,
) -> Result<()> {
    verify_phase23_decoding_cross_step_lookup_accumulator(manifest)?;
    verify_phase23_decoding_cross_step_lookup_accumulator_members_with_proof_checks(manifest)
}

fn commit_phase24_state_relation_accumulator_with_summaries(
    manifest: &Phase24DecodingStateRelationAccumulatorManifest,
    summaries: &[Phase24MemberSummary],
) -> Result<String> {
    if manifest.members.len() < 2 {
        return Err(VmError::InvalidConfig(
            "decoding state relation accumulator must contain at least two members".to_string(),
        ));
    }
    if summaries.len() != manifest.members.len() {
        return Err(VmError::InvalidConfig(format!(
            "decoding state relation accumulator summaries.len()={} does not match members.len()={}",
            summaries.len(),
            manifest.members.len()
        )));
    }

    let mut hasher = Blake2bVar::new(32).expect("blake2b-256");
    hasher.update(STWO_DECODING_STATE_RELATION_ACCUMULATOR_VERSION_PHASE24.as_bytes());
    hasher.update(b"state-relation-accumulator");
    hasher.update(manifest.source_template_commitment.as_bytes());
    hasher.update(manifest.relation_template_commitment.as_bytes());
    hasher.update(manifest.start_state_commitment.as_bytes());
    hasher.update(manifest.end_state_commitment.as_bytes());
    hasher.update(&(manifest.member_count as u64).to_le_bytes());
    hasher.update(&(manifest.total_matrices as u64).to_le_bytes());
    hasher.update(&(manifest.total_layouts as u64).to_le_bytes());
    hasher.update(&(manifest.total_rollups as u64).to_le_bytes());
    hasher.update(&(manifest.total_segments as u64).to_le_bytes());
    hasher.update(&(manifest.total_steps as u64).to_le_bytes());
    hasher.update(&(manifest.lookup_delta_entries as u64).to_le_bytes());
    hasher.update(&(manifest.max_lookup_frontier_entries as u64).to_le_bytes());
    for (member_index, summary) in summaries.iter().enumerate() {
        hasher.update(&(member_index as u64).to_le_bytes());
        hasher.update(&(summary.start_step as u64).to_le_bytes());
        hasher.update(&(summary.end_step as u64).to_le_bytes());
        hasher.update(summary.lookup_accumulator_commitment.as_bytes());
        hasher.update(summary.start_state_commitment.as_bytes());
        hasher.update(summary.end_state_commitment.as_bytes());
        hasher.update(&(summary.total_matrices as u64).to_le_bytes());
        hasher.update(&(summary.total_layouts as u64).to_le_bytes());
        hasher.update(&(summary.total_rollups as u64).to_le_bytes());
        hasher.update(&(summary.total_segments as u64).to_le_bytes());
        hasher.update(&(summary.total_steps as u64).to_le_bytes());
        hasher.update(&(summary.lookup_delta_entries as u64).to_le_bytes());
        hasher.update(&(summary.max_lookup_frontier_entries as u64).to_le_bytes());
    }

    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("blake2b finalize");
    Ok(lower_hex(&out))
}

pub fn phase24_prepare_decoding_state_relation_accumulator(
    members: &[Phase23DecodingCrossStepLookupAccumulatorManifest],
) -> Result<Phase24DecodingStateRelationAccumulatorManifest> {
    if members.len() < 2 {
        return Err(VmError::InvalidConfig(
            "Phase 24 state relation accumulator requires at least two Phase 23 members"
                .to_string(),
        ));
    }
    if members.len() > MAX_PHASE24_ACCUMULATOR_MEMBERS {
        return Err(VmError::InvalidConfig(format!(
            "Phase 24 state relation accumulator supports at most {MAX_PHASE24_ACCUMULATOR_MEMBERS} members (got {})",
            members.len()
        )));
    }

    let summaries = summarize_phase24_members(members)?;
    verify_phase24_member_relation_sequence(&summaries)?;

    let mut total_matrices = 0usize;
    let mut total_layouts = 0usize;
    let mut total_rollups = 0usize;
    let mut total_segments = 0usize;
    let mut total_steps = 0usize;
    let mut lookup_delta_entries = 0usize;
    let mut max_lookup_frontier_entries = 0usize;
    for (member_index, summary) in summaries.iter().enumerate() {
        total_matrices = total_matrices
            .checked_add(summary.total_matrices)
            .ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "Phase 24 total_matrices overflowed while adding member {member_index}"
                ))
            })?;
        total_layouts = total_layouts
            .checked_add(summary.total_layouts)
            .ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "Phase 24 total_layouts overflowed while adding member {member_index}"
                ))
            })?;
        total_rollups = total_rollups
            .checked_add(summary.total_rollups)
            .ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "Phase 24 total_rollups overflowed while adding member {member_index}"
                ))
            })?;
        total_segments = total_segments
            .checked_add(summary.total_segments)
            .ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "Phase 24 total_segments overflowed while adding member {member_index}"
                ))
            })?;
        total_steps = total_steps
            .checked_add(summary.total_steps)
            .ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "Phase 24 total_steps overflowed while adding member {member_index}"
                ))
            })?;
        lookup_delta_entries = lookup_delta_entries
            .checked_add(summary.lookup_delta_entries)
            .ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "Phase 24 lookup_delta_entries overflowed while adding member {member_index}"
                ))
            })?;
        max_lookup_frontier_entries =
            max_lookup_frontier_entries.max(summary.max_lookup_frontier_entries);
    }
    if total_rollups > MAX_PHASE24_ACCUMULATOR_ROLLUPS {
        return Err(VmError::InvalidConfig(format!(
            "Phase 24 total_rollups {} exceed the supported maximum {}",
            total_rollups, MAX_PHASE24_ACCUMULATOR_ROLLUPS
        )));
    }

    let first = summaries.first().expect("phase24 summaries are non-empty");
    let last = summaries.last().expect("phase24 summaries are non-empty");
    let relation_template_commitment = commit_phase24_relation_template(&summaries)?;
    let mut manifest = Phase24DecodingStateRelationAccumulatorManifest {
        proof_backend: StarkProofBackend::Stwo,
        accumulator_version: STWO_DECODING_STATE_RELATION_ACCUMULATOR_VERSION_PHASE24.to_string(),
        semantic_scope: STWO_DECODING_STATE_RELATION_ACCUMULATOR_SCOPE_PHASE24.to_string(),
        proof_backend_version: members[0].proof_backend_version.clone(),
        statement_version: members[0].statement_version.clone(),
        member_count: members.len(),
        total_matrices,
        total_layouts,
        total_rollups,
        total_segments,
        total_steps,
        lookup_delta_entries,
        max_lookup_frontier_entries,
        source_template_commitment: first.source_template_commitment.clone(),
        start_state_commitment: first.start_state_commitment.clone(),
        end_state_commitment: last.end_state_commitment.clone(),
        relation_template_commitment,
        relation_accumulator_commitment: String::new(),
        member_summaries: phase24_public_member_summaries(&summaries),
        members: members.to_vec(),
    };
    manifest.relation_accumulator_commitment =
        commit_phase24_state_relation_accumulator_with_summaries(&manifest, &summaries)?;
    verify_phase24_decoding_state_relation_accumulator_with_summaries(&manifest, &summaries)?;
    Ok(manifest)
}

fn verify_phase24_decoding_state_relation_accumulator_with_summaries(
    manifest: &Phase24DecodingStateRelationAccumulatorManifest,
    summaries: &[Phase24MemberSummary],
) -> Result<()> {
    if manifest.proof_backend != StarkProofBackend::Stwo {
        return Err(VmError::InvalidConfig(format!(
            "decoding state relation accumulator backend `{}` is not `stwo`",
            manifest.proof_backend
        )));
    }
    if manifest.accumulator_version != STWO_DECODING_STATE_RELATION_ACCUMULATOR_VERSION_PHASE24 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding state relation accumulator version `{}`",
            manifest.accumulator_version
        )));
    }
    if manifest.semantic_scope != STWO_DECODING_STATE_RELATION_ACCUMULATOR_SCOPE_PHASE24 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding state relation accumulator semantic scope `{}`",
            manifest.semantic_scope
        )));
    }
    if manifest.proof_backend_version != crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding state relation accumulator proof backend version `{}` (expected `{}`)",
            manifest.proof_backend_version,
            crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12
        )));
    }
    if manifest.statement_version != crate::proof::CLAIM_STATEMENT_VERSION_V1 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported decoding state relation accumulator statement version `{}`",
            manifest.statement_version
        )));
    }
    if manifest.members.len() < 2 {
        return Err(VmError::InvalidConfig(
            "decoding state relation accumulator must contain at least two members".to_string(),
        ));
    }
    if manifest.members.len() > MAX_PHASE24_ACCUMULATOR_MEMBERS {
        return Err(VmError::InvalidConfig(format!(
            "decoding state relation accumulator members.len()={} exceeds the supported maximum {}",
            manifest.members.len(),
            MAX_PHASE24_ACCUMULATOR_MEMBERS
        )));
    }
    if manifest.member_count != manifest.members.len() {
        return Err(VmError::InvalidConfig(format!(
            "decoding state relation accumulator member_count={} does not match members.len()={}",
            manifest.member_count,
            manifest.members.len()
        )));
    }
    if manifest.member_summaries.len() != manifest.members.len() {
        return Err(VmError::InvalidConfig(format!(
            "decoding state relation accumulator member_summaries.len()={} does not match members.len()={}",
            manifest.member_summaries.len(),
            manifest.members.len()
        )));
    }
    if manifest.total_rollups > MAX_PHASE24_ACCUMULATOR_ROLLUPS {
        return Err(VmError::InvalidConfig(format!(
            "decoding state relation accumulator total_rollups={} exceeds the supported maximum {}",
            manifest.total_rollups, MAX_PHASE24_ACCUMULATOR_ROLLUPS
        )));
    }
    if manifest.source_template_commitment.is_empty() {
        return Err(VmError::InvalidConfig(
            "decoding state relation accumulator source_template_commitment must not be empty"
                .to_string(),
        ));
    }
    if manifest.start_state_commitment.is_empty() || manifest.end_state_commitment.is_empty() {
        return Err(VmError::InvalidConfig(
            "decoding state relation accumulator state-boundary commitments must not be empty"
                .to_string(),
        ));
    }
    if manifest.relation_template_commitment.is_empty() {
        return Err(VmError::InvalidConfig(
            "decoding state relation accumulator relation_template_commitment must not be empty"
                .to_string(),
        ));
    }
    if manifest.relation_accumulator_commitment.is_empty() {
        return Err(VmError::InvalidConfig(
            "decoding state relation accumulator relation_accumulator_commitment must not be empty"
                .to_string(),
        ));
    }
    for (member_index, member) in manifest.members.iter().enumerate() {
        if member.proof_backend_version != manifest.proof_backend_version {
            return Err(VmError::InvalidConfig(format!(
                "decoding state relation accumulator member {member_index} proof backend version `{}` does not match manifest `{}`",
                member.proof_backend_version, manifest.proof_backend_version
            )));
        }
        if member.statement_version != manifest.statement_version {
            return Err(VmError::InvalidConfig(format!(
                "decoding state relation accumulator member {member_index} statement version `{}` does not match manifest `{}`",
                member.statement_version, manifest.statement_version
            )));
        }
    }
    if summaries.len() != manifest.members.len() {
        return Err(VmError::InvalidConfig(format!(
            "decoding state relation accumulator summaries.len()={} does not match members.len()={}",
            summaries.len(),
            manifest.members.len()
        )));
    }
    verify_phase24_member_relation_sequence(summaries)?;

    let expected_public_summaries = phase24_public_member_summaries(summaries);
    if manifest.member_summaries != expected_public_summaries {
        return Err(VmError::InvalidConfig(
            "decoding state relation accumulator member_summaries do not match the derived member summaries".to_string(),
        ));
    }

    let mut derived_total_matrices = 0usize;
    let mut derived_total_layouts = 0usize;
    let mut derived_total_rollups = 0usize;
    let mut derived_total_segments = 0usize;
    let mut derived_total_steps = 0usize;
    let mut derived_lookup_delta_entries = 0usize;
    let mut derived_max_lookup_frontier_entries = 0usize;
    for (member_index, summary) in summaries.iter().enumerate() {
        derived_total_matrices =
            derived_total_matrices
                .checked_add(summary.total_matrices)
                .ok_or_else(|| {
                    VmError::InvalidConfig(format!(
                        "decoding state relation accumulator total_matrices overflowed while adding member {member_index}"
                    ))
                })?;
        derived_total_layouts = derived_total_layouts
            .checked_add(summary.total_layouts)
            .ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "decoding state relation accumulator total_layouts overflowed while adding member {member_index}"
                ))
            })?;
        derived_total_rollups = derived_total_rollups
            .checked_add(summary.total_rollups)
            .ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "decoding state relation accumulator total_rollups overflowed while adding member {member_index}"
                ))
            })?;
        derived_total_segments = derived_total_segments
            .checked_add(summary.total_segments)
            .ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "decoding state relation accumulator total_segments overflowed while adding member {member_index}"
                ))
            })?;
        derived_total_steps = derived_total_steps
            .checked_add(summary.total_steps)
            .ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "decoding state relation accumulator total_steps overflowed while adding member {member_index}"
                ))
            })?;
        derived_lookup_delta_entries = derived_lookup_delta_entries
            .checked_add(summary.lookup_delta_entries)
            .ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "decoding state relation accumulator lookup_delta_entries overflowed while adding member {member_index}"
                ))
            })?;
        derived_max_lookup_frontier_entries =
            derived_max_lookup_frontier_entries.max(summary.max_lookup_frontier_entries);
    }
    if manifest.total_matrices != derived_total_matrices {
        return Err(VmError::InvalidConfig(format!(
            "decoding state relation accumulator total_matrices={} does not match derived total_matrices={}",
            manifest.total_matrices, derived_total_matrices
        )));
    }
    if manifest.total_layouts != derived_total_layouts {
        return Err(VmError::InvalidConfig(format!(
            "decoding state relation accumulator total_layouts={} does not match derived total_layouts={}",
            manifest.total_layouts, derived_total_layouts
        )));
    }
    if manifest.total_rollups != derived_total_rollups {
        return Err(VmError::InvalidConfig(format!(
            "decoding state relation accumulator total_rollups={} does not match derived total_rollups={}",
            manifest.total_rollups, derived_total_rollups
        )));
    }
    if manifest.total_segments != derived_total_segments {
        return Err(VmError::InvalidConfig(format!(
            "decoding state relation accumulator total_segments={} does not match derived total_segments={}",
            manifest.total_segments, derived_total_segments
        )));
    }
    if manifest.total_steps != derived_total_steps {
        return Err(VmError::InvalidConfig(format!(
            "decoding state relation accumulator total_steps={} does not match derived total_steps={}",
            manifest.total_steps, derived_total_steps
        )));
    }
    if manifest.lookup_delta_entries != derived_lookup_delta_entries {
        return Err(VmError::InvalidConfig(format!(
            "decoding state relation accumulator lookup_delta_entries={} does not match derived lookup_delta_entries={}",
            manifest.lookup_delta_entries, derived_lookup_delta_entries
        )));
    }
    if manifest.max_lookup_frontier_entries != derived_max_lookup_frontier_entries {
        return Err(VmError::InvalidConfig(format!(
            "decoding state relation accumulator max_lookup_frontier_entries={} does not match derived max_lookup_frontier_entries={}",
            manifest.max_lookup_frontier_entries, derived_max_lookup_frontier_entries
        )));
    }

    let first = summaries.first().expect("phase24 summaries are non-empty");
    let last = summaries.last().expect("phase24 summaries are non-empty");
    if manifest.source_template_commitment != first.source_template_commitment {
        return Err(VmError::InvalidConfig(
            "decoding state relation accumulator source_template_commitment does not match the shared member template commitment".to_string(),
        ));
    }
    if manifest.start_state_commitment != first.start_state_commitment {
        return Err(VmError::InvalidConfig(
            "decoding state relation accumulator start_state_commitment does not match the first member boundary".to_string(),
        ));
    }
    if manifest.end_state_commitment != last.end_state_commitment {
        return Err(VmError::InvalidConfig(
            "decoding state relation accumulator end_state_commitment does not match the last member boundary".to_string(),
        ));
    }

    let expected_relation_template_commitment = commit_phase24_relation_template(summaries)?;
    if manifest.relation_template_commitment != expected_relation_template_commitment {
        return Err(VmError::InvalidConfig(
            "decoding state relation accumulator relation_template_commitment does not match the computed member relation template commitment".to_string(),
        ));
    }
    let expected_relation_accumulator_commitment =
        commit_phase24_state_relation_accumulator_with_summaries(manifest, summaries)?;
    if manifest.relation_accumulator_commitment != expected_relation_accumulator_commitment {
        return Err(VmError::InvalidConfig(
            "decoding state relation accumulator relation_accumulator_commitment does not match the computed accumulator commitment".to_string(),
        ));
    }
    Ok(())
}

pub fn verify_phase24_decoding_state_relation_accumulator(
    manifest: &Phase24DecodingStateRelationAccumulatorManifest,
) -> Result<()> {
    validate_phase24_decoding_state_relation_accumulator_shallow(manifest)?;
    let summaries = summarize_phase24_members(&manifest.members)?;
    verify_phase24_decoding_state_relation_accumulator_with_summaries(manifest, &summaries)
}

pub fn verify_phase24_decoding_state_relation_accumulator_with_proof_checks(
    manifest: &Phase24DecodingStateRelationAccumulatorManifest,
) -> Result<()> {
    verify_phase24_decoding_state_relation_accumulator(manifest)?;
    for (member_index, member) in manifest.members.iter().enumerate() {
        verify_phase23_decoding_cross_step_lookup_accumulator_members_with_proof_checks(member)
            .map_err(|error| {
                VmError::UnsupportedProof(format!(
                    "decoding state relation accumulator member {member_index} failed verification: {error}"
                ))
            })?;
    }
    Ok(())
}

fn phase25_intervalized_public_member_summaries(
    summaries: &[Phase24MemberSummary],
) -> Vec<Phase25IntervalizedDecodingStateRelationMemberSummary> {
    summaries
        .iter()
        .map(
            |summary| Phase25IntervalizedDecodingStateRelationMemberSummary {
                start_step: summary.start_step,
                end_step: summary.end_step,
                total_matrices: summary.total_matrices,
                total_layouts: summary.total_layouts,
                total_rollups: summary.total_rollups,
                total_segments: summary.total_segments,
                total_steps: summary.total_steps,
                lookup_delta_entries: summary.lookup_delta_entries,
                max_lookup_frontier_entries: summary.max_lookup_frontier_entries,
                source_template_commitment: summary.source_template_commitment.clone(),
                lookup_template_commitment: summary.lookup_template_commitment.clone(),
                lookup_accumulator_commitment: summary.lookup_accumulator_commitment.clone(),
                start_state_commitment: summary.start_state_commitment.clone(),
                end_state_commitment: summary.end_state_commitment.clone(),
            },
        )
        .collect()
}

fn validate_phase25_intervalized_decoding_state_relation_shallow(
    manifest: &Phase25IntervalizedDecodingStateRelationManifest,
) -> Result<()> {
    if manifest.proof_backend != StarkProofBackend::Stwo {
        return Err(VmError::InvalidConfig(format!(
            "intervalized decoding state relation backend `{}` is not `stwo`",
            manifest.proof_backend
        )));
    }
    if manifest.artifact_version != STWO_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE25 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported intervalized decoding state relation version `{}`",
            manifest.artifact_version
        )));
    }
    if manifest.semantic_scope != STWO_INTERVALIZED_DECODING_STATE_RELATION_SCOPE_PHASE25 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported intervalized decoding state relation semantic scope `{}`",
            manifest.semantic_scope
        )));
    }
    if manifest.proof_backend_version != crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported intervalized decoding state relation proof backend version `{}` (expected `{}`)",
            manifest.proof_backend_version,
            crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12
        )));
    }
    if manifest.statement_version != crate::proof::CLAIM_STATEMENT_VERSION_V1 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported intervalized decoding state relation statement version `{}`",
            manifest.statement_version
        )));
    }
    if manifest.members.len() < 2 {
        return Err(VmError::InvalidConfig(
            "intervalized decoding state relation must contain at least two members".to_string(),
        ));
    }
    if manifest.members.len() > MAX_PHASE25_INTERVALIZED_MEMBERS {
        return Err(VmError::InvalidConfig(format!(
            "intervalized decoding state relation members.len()={} exceeds the supported maximum {}",
            manifest.members.len(),
            MAX_PHASE25_INTERVALIZED_MEMBERS
        )));
    }
    if manifest.member_count != manifest.members.len() {
        return Err(VmError::InvalidConfig(format!(
            "intervalized decoding state relation member_count={} does not match members.len()={}",
            manifest.member_count,
            manifest.members.len()
        )));
    }
    if manifest.member_summaries.len() != manifest.members.len() {
        return Err(VmError::InvalidConfig(format!(
            "intervalized decoding state relation member_summaries.len()={} does not match members.len()={}",
            manifest.member_summaries.len(),
            manifest.members.len()
        )));
    }
    if manifest.total_rollups > MAX_PHASE25_INTERVALIZED_ROLLUPS {
        return Err(VmError::InvalidConfig(format!(
            "intervalized decoding state relation total_rollups={} exceeds the supported maximum {}",
            manifest.total_rollups,
            MAX_PHASE25_INTERVALIZED_ROLLUPS
        )));
    }
    if manifest.source_template_commitment.is_empty() {
        return Err(VmError::InvalidConfig(
            "intervalized decoding state relation source_template_commitment must not be empty"
                .to_string(),
        ));
    }
    if manifest.source_relation_template_commitment.is_empty() {
        return Err(VmError::InvalidConfig(
            "intervalized decoding state relation source_relation_template_commitment must not be empty"
                .to_string(),
        ));
    }
    if manifest.source_relation_accumulator_commitment.is_empty() {
        return Err(VmError::InvalidConfig(
            "intervalized decoding state relation source_relation_accumulator_commitment must not be empty"
                .to_string(),
        ));
    }
    if manifest.global_start_state_commitment.is_empty()
        || manifest.global_end_state_commitment.is_empty()
    {
        return Err(VmError::InvalidConfig(
            "intervalized decoding state relation global state-boundary commitments must not be empty"
                .to_string(),
        ));
    }
    if manifest.interval_template_commitment.is_empty() {
        return Err(VmError::InvalidConfig(
            "intervalized decoding state relation interval_template_commitment must not be empty"
                .to_string(),
        ));
    }
    if manifest.interval_accumulator_commitment.is_empty() {
        return Err(VmError::InvalidConfig(
            "intervalized decoding state relation interval_accumulator_commitment must not be empty"
                .to_string(),
        ));
    }
    Ok(())
}

fn commit_phase25_interval_template_from_summaries(
    source_relation_template_commitment: &str,
    summaries: &[Phase24MemberSummary],
) -> Result<String> {
    verify_phase24_member_relation_sequence(summaries)?;
    if source_relation_template_commitment.is_empty() {
        return Err(VmError::InvalidConfig(
            "Phase 25 interval template source_relation_template_commitment must not be empty"
                .to_string(),
        ));
    }

    let mut hasher = Blake2bVar::new(32).expect("blake2b-256");
    hasher.update(STWO_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE25.as_bytes());
    hasher.update(b"interval-template");
    hasher.update(source_relation_template_commitment.as_bytes());
    hasher.update(&(summaries.len() as u64).to_le_bytes());
    for (member_index, summary) in summaries.iter().enumerate() {
        hasher.update(&(member_index as u64).to_le_bytes());
        hasher.update(summary.lookup_template_commitment.as_bytes());
        hasher.update(summary.lookup_accumulator_commitment.as_bytes());
        hasher.update(summary.start_state_commitment.as_bytes());
        hasher.update(summary.end_state_commitment.as_bytes());
        hasher.update(&(summary.start_step as u64).to_le_bytes());
        hasher.update(&(summary.end_step as u64).to_le_bytes());
        hasher.update(&(summary.total_matrices as u64).to_le_bytes());
        hasher.update(&(summary.total_layouts as u64).to_le_bytes());
        hasher.update(&(summary.total_rollups as u64).to_le_bytes());
        hasher.update(&(summary.total_segments as u64).to_le_bytes());
        hasher.update(&(summary.total_steps as u64).to_le_bytes());
        hasher.update(&(summary.lookup_delta_entries as u64).to_le_bytes());
        hasher.update(&(summary.max_lookup_frontier_entries as u64).to_le_bytes());
    }

    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("blake2b finalize");
    Ok(lower_hex(&out))
}

fn commit_phase25_intervalized_state_relation_with_summaries(
    manifest: &Phase25IntervalizedDecodingStateRelationManifest,
    summaries: &[Phase24MemberSummary],
) -> Result<String> {
    if manifest.members.len() < 2 {
        return Err(VmError::InvalidConfig(
            "intervalized decoding state relation must contain at least two members".to_string(),
        ));
    }
    if summaries.len() != manifest.members.len() {
        return Err(VmError::InvalidConfig(format!(
            "intervalized decoding state relation summaries.len()={} does not match members.len()={}",
            summaries.len(),
            manifest.members.len()
        )));
    }

    let mut hasher = Blake2bVar::new(32).expect("blake2b-256");
    hasher.update(STWO_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE25.as_bytes());
    hasher.update(b"intervalized-state-relation");
    hasher.update(manifest.source_template_commitment.as_bytes());
    hasher.update(manifest.source_relation_template_commitment.as_bytes());
    hasher.update(manifest.source_relation_accumulator_commitment.as_bytes());
    hasher.update(manifest.global_start_state_commitment.as_bytes());
    hasher.update(manifest.global_end_state_commitment.as_bytes());
    hasher.update(manifest.interval_template_commitment.as_bytes());
    hasher.update(&(manifest.member_count as u64).to_le_bytes());
    hasher.update(&(manifest.total_matrices as u64).to_le_bytes());
    hasher.update(&(manifest.total_layouts as u64).to_le_bytes());
    hasher.update(&(manifest.total_rollups as u64).to_le_bytes());
    hasher.update(&(manifest.total_segments as u64).to_le_bytes());
    hasher.update(&(manifest.total_steps as u64).to_le_bytes());
    hasher.update(&(manifest.lookup_delta_entries as u64).to_le_bytes());
    hasher.update(&(manifest.max_lookup_frontier_entries as u64).to_le_bytes());
    for (member_index, summary) in summaries.iter().enumerate() {
        hasher.update(&(member_index as u64).to_le_bytes());
        hasher.update(&(summary.start_step as u64).to_le_bytes());
        hasher.update(&(summary.end_step as u64).to_le_bytes());
        hasher.update(summary.lookup_accumulator_commitment.as_bytes());
        hasher.update(summary.start_state_commitment.as_bytes());
        hasher.update(summary.end_state_commitment.as_bytes());
        hasher.update(&(summary.total_matrices as u64).to_le_bytes());
        hasher.update(&(summary.total_layouts as u64).to_le_bytes());
        hasher.update(&(summary.total_rollups as u64).to_le_bytes());
        hasher.update(&(summary.total_segments as u64).to_le_bytes());
        hasher.update(&(summary.total_steps as u64).to_le_bytes());
        hasher.update(&(summary.lookup_delta_entries as u64).to_le_bytes());
        hasher.update(&(summary.max_lookup_frontier_entries as u64).to_le_bytes());
    }

    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("blake2b finalize");
    Ok(lower_hex(&out))
}

fn prepare_phase25_intervalized_decoding_state_relation_from_phase24_source(
    source: &Phase24DecodingStateRelationAccumulatorManifest,
    summaries: &[Phase24MemberSummary],
) -> Result<Phase25IntervalizedDecodingStateRelationManifest> {
    let interval_template_commitment = commit_phase25_interval_template_from_summaries(
        &source.relation_template_commitment,
        &summaries,
    )?;
    let mut manifest = Phase25IntervalizedDecodingStateRelationManifest {
        proof_backend: StarkProofBackend::Stwo,
        artifact_version: STWO_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE25.to_string(),
        semantic_scope: STWO_INTERVALIZED_DECODING_STATE_RELATION_SCOPE_PHASE25.to_string(),
        proof_backend_version: source.proof_backend_version.clone(),
        statement_version: source.statement_version.clone(),
        member_count: source.member_count,
        total_matrices: source.total_matrices,
        total_layouts: source.total_layouts,
        total_rollups: source.total_rollups,
        total_segments: source.total_segments,
        total_steps: source.total_steps,
        lookup_delta_entries: source.lookup_delta_entries,
        max_lookup_frontier_entries: source.max_lookup_frontier_entries,
        source_template_commitment: source.source_template_commitment.clone(),
        source_relation_template_commitment: source.relation_template_commitment.clone(),
        source_relation_accumulator_commitment: source.relation_accumulator_commitment.clone(),
        global_start_state_commitment: source.start_state_commitment.clone(),
        global_end_state_commitment: source.end_state_commitment.clone(),
        interval_template_commitment,
        interval_accumulator_commitment: String::new(),
        member_summaries: phase25_intervalized_public_member_summaries(&summaries),
        members: source.members.clone(),
    };
    manifest.interval_accumulator_commitment =
        commit_phase25_intervalized_state_relation_with_summaries(&manifest, &summaries)?;
    verify_phase25_intervalized_decoding_state_relation_with_summaries(&manifest, &summaries)?;
    Ok(manifest)
}

fn phase25_prepare_intervalized_decoding_state_relation_from_phase23_members(
    members: &[Phase23DecodingCrossStepLookupAccumulatorManifest],
    baseline: Phase24RebaseBaseline,
    proof_backend_version: &str,
    statement_version: &str,
) -> Result<Phase25IntervalizedDecodingStateRelationManifest> {
    let (source_manifest, summaries) = prepare_phase24_rebased_source_manifest(
        members,
        baseline,
        proof_backend_version,
        statement_version,
    )?;
    prepare_phase25_intervalized_decoding_state_relation_from_phase24_source(
        &source_manifest,
        &summaries,
    )
}

pub fn phase25_prepare_intervalized_decoding_state_relation(
    source: &Phase24DecodingStateRelationAccumulatorManifest,
) -> Result<Phase25IntervalizedDecodingStateRelationManifest> {
    verify_phase24_decoding_state_relation_accumulator(source)?;
    if source.members.len() > MAX_PHASE25_INTERVALIZED_MEMBERS {
        return Err(VmError::InvalidConfig(format!(
            "Phase 25 intervalized decoding state relation supports at most {MAX_PHASE25_INTERVALIZED_MEMBERS} members (got {})",
            source.members.len()
        )));
    }

    let summaries = summarize_phase24_members(&source.members)?;
    verify_phase24_member_relation_sequence(&summaries)?;
    prepare_phase25_intervalized_decoding_state_relation_from_phase24_source(source, &summaries)
}

fn infer_phase24_rebase_baseline_from_phase25_manifest(
    manifest: &Phase25IntervalizedDecodingStateRelationManifest,
) -> Result<Phase24RebaseBaseline> {
    let last_member = manifest.members.last().ok_or_else(|| {
        VmError::InvalidConfig(
            "intervalized decoding state relation must contain at least one member".to_string(),
        )
    })?;
    Ok(Phase24RebaseBaseline {
        total_matrices: last_member
            .total_matrices
            .checked_sub(manifest.total_matrices)
            .ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "intervalized decoding state relation total_matrices={} exceed the final nested cumulative total {}",
                    manifest.total_matrices, last_member.total_matrices
                ))
            })?,
        total_layouts: last_member
            .total_layouts
            .checked_sub(manifest.total_layouts)
            .ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "intervalized decoding state relation total_layouts={} exceed the final nested cumulative total {}",
                    manifest.total_layouts, last_member.total_layouts
                ))
            })?,
        total_rollups: last_member
            .total_rollups
            .checked_sub(manifest.total_rollups)
            .ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "intervalized decoding state relation total_rollups={} exceed the final nested cumulative total {}",
                    manifest.total_rollups, last_member.total_rollups
                ))
            })?,
        total_segments: last_member
            .total_segments
            .checked_sub(manifest.total_segments)
            .ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "intervalized decoding state relation total_segments={} exceed the final nested cumulative total {}",
                    manifest.total_segments, last_member.total_segments
                ))
            })?,
        total_steps: last_member.total_steps.checked_sub(manifest.total_steps).ok_or_else(|| {
            VmError::InvalidConfig(format!(
                "intervalized decoding state relation total_steps={} exceed the final nested cumulative total {}",
                manifest.total_steps, last_member.total_steps
            ))
        })?,
        lookup_delta_entries: last_member
            .lookup_delta_entries
            .checked_sub(manifest.lookup_delta_entries)
            .ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "intervalized decoding state relation lookup_delta_entries={} exceed the final nested cumulative total {}",
                    manifest.lookup_delta_entries, last_member.lookup_delta_entries
                ))
            })?,
    })
}

fn verify_phase25_intervalized_decoding_state_relation_with_summaries(
    manifest: &Phase25IntervalizedDecodingStateRelationManifest,
    summaries: &[Phase24MemberSummary],
) -> Result<()> {
    validate_phase25_intervalized_decoding_state_relation_shallow(manifest)?;
    if summaries.len() != manifest.members.len() {
        return Err(VmError::InvalidConfig(format!(
            "intervalized decoding state relation summaries.len()={} does not match members.len()={}",
            summaries.len(),
            manifest.members.len()
        )));
    }
    let baseline = infer_phase24_rebase_baseline_from_phase25_manifest(manifest)?;
    let expected_summaries = derive_phase24_rebased_member_summaries(&manifest.members, baseline)?;
    if summaries != expected_summaries.as_slice() {
        return Err(VmError::InvalidConfig(
            "intervalized decoding state relation summaries do not match the rebased summaries derived from the nested cumulative members".to_string(),
        ));
    }
    verify_phase24_member_relation_sequence(summaries)?;

    let (source_manifest, _) = prepare_phase24_rebased_source_manifest(
        &manifest.members,
        baseline,
        &manifest.proof_backend_version,
        &manifest.statement_version,
    )?;
    if manifest.member_count != source_manifest.member_count {
        return Err(VmError::InvalidConfig(format!(
            "intervalized decoding state relation member_count={} does not match derived member_count {}",
            manifest.member_count, source_manifest.member_count
        )));
    }
    if manifest.total_matrices != source_manifest.total_matrices {
        return Err(VmError::InvalidConfig(format!(
            "intervalized decoding state relation total_matrices={} does not match derived total_matrices {}",
            manifest.total_matrices, source_manifest.total_matrices
        )));
    }
    if manifest.total_layouts != source_manifest.total_layouts {
        return Err(VmError::InvalidConfig(format!(
            "intervalized decoding state relation total_layouts={} does not match derived total_layouts {}",
            manifest.total_layouts, source_manifest.total_layouts
        )));
    }
    if manifest.total_rollups != source_manifest.total_rollups {
        return Err(VmError::InvalidConfig(format!(
            "intervalized decoding state relation total_rollups={} does not match derived total_rollups {}",
            manifest.total_rollups, source_manifest.total_rollups
        )));
    }
    if manifest.total_segments != source_manifest.total_segments {
        return Err(VmError::InvalidConfig(format!(
            "intervalized decoding state relation total_segments={} does not match derived total_segments {}",
            manifest.total_segments, source_manifest.total_segments
        )));
    }
    if manifest.total_steps != source_manifest.total_steps {
        return Err(VmError::InvalidConfig(format!(
            "intervalized decoding state relation total_steps={} does not match derived total_steps {}",
            manifest.total_steps, source_manifest.total_steps
        )));
    }
    if manifest.lookup_delta_entries != source_manifest.lookup_delta_entries {
        return Err(VmError::InvalidConfig(format!(
            "intervalized decoding state relation lookup_delta_entries={} does not match derived lookup_delta_entries {}",
            manifest.lookup_delta_entries, source_manifest.lookup_delta_entries
        )));
    }
    if manifest.max_lookup_frontier_entries != source_manifest.max_lookup_frontier_entries {
        return Err(VmError::InvalidConfig(format!(
            "intervalized decoding state relation max_lookup_frontier_entries={} does not match derived max_lookup_frontier_entries {}",
            manifest.max_lookup_frontier_entries, source_manifest.max_lookup_frontier_entries
        )));
    }
    if manifest.source_template_commitment != source_manifest.source_template_commitment {
        return Err(VmError::InvalidConfig(
            "intervalized decoding state relation source_template_commitment does not match the derived rebased Phase 24 source".to_string(),
        ));
    }
    if manifest.source_relation_template_commitment != source_manifest.relation_template_commitment
    {
        return Err(VmError::InvalidConfig(
            "intervalized decoding state relation source_relation_template_commitment does not match the derived rebased Phase 24 source".to_string(),
        ));
    }
    if manifest.source_relation_accumulator_commitment
        != source_manifest.relation_accumulator_commitment
    {
        return Err(VmError::InvalidConfig(
            "intervalized decoding state relation source_relation_accumulator_commitment does not match the derived rebased Phase 24 source".to_string(),
        ));
    }
    if manifest.global_start_state_commitment != source_manifest.start_state_commitment {
        return Err(VmError::InvalidConfig(
            "intervalized decoding state relation global_start_state_commitment does not match the derived rebased Phase 24 source".to_string(),
        ));
    }
    if manifest.global_end_state_commitment != source_manifest.end_state_commitment {
        return Err(VmError::InvalidConfig(
            "intervalized decoding state relation global_end_state_commitment does not match the derived rebased Phase 24 source".to_string(),
        ));
    }

    let expected_member_summaries = phase25_intervalized_public_member_summaries(summaries);
    if manifest.member_summaries != expected_member_summaries {
        return Err(VmError::InvalidConfig(
            "intervalized decoding state relation member_summaries do not match the derived interval summaries".to_string(),
        ));
    }

    let expected_interval_template_commitment = commit_phase25_interval_template_from_summaries(
        &manifest.source_relation_template_commitment,
        summaries,
    )?;
    if manifest.interval_template_commitment != expected_interval_template_commitment {
        return Err(VmError::InvalidConfig(
            "intervalized decoding state relation interval_template_commitment does not match the computed interval template commitment".to_string(),
        ));
    }

    let expected_interval_accumulator_commitment =
        commit_phase25_intervalized_state_relation_with_summaries(manifest, summaries)?;
    if manifest.interval_accumulator_commitment != expected_interval_accumulator_commitment {
        return Err(VmError::InvalidConfig(
            "intervalized decoding state relation interval_accumulator_commitment does not match the computed interval accumulator commitment".to_string(),
        ));
    }
    Ok(())
}

pub fn verify_phase25_intervalized_decoding_state_relation(
    manifest: &Phase25IntervalizedDecodingStateRelationManifest,
) -> Result<()> {
    validate_phase25_intervalized_decoding_state_relation_shallow(manifest)?;
    let baseline = infer_phase24_rebase_baseline_from_phase25_manifest(manifest)?;
    let summaries = derive_phase24_rebased_member_summaries(&manifest.members, baseline)?;
    verify_phase25_intervalized_decoding_state_relation_with_summaries(manifest, &summaries)
}

fn verify_phase25_intervalized_decoding_state_relation_members_with_proof_checks(
    manifest: &Phase25IntervalizedDecodingStateRelationManifest,
) -> Result<()> {
    for (member_index, member) in manifest.members.iter().enumerate() {
        verify_phase23_decoding_cross_step_lookup_accumulator_with_proof_checks(member).map_err(
            |error| {
                VmError::UnsupportedProof(format!(
                    "intervalized decoding state relation member {member_index} failed verification: {error}"
                ))
            },
        )?;
    }
    Ok(())
}

pub fn verify_phase25_intervalized_decoding_state_relation_with_proof_checks(
    manifest: &Phase25IntervalizedDecodingStateRelationManifest,
) -> Result<()> {
    verify_phase25_intervalized_decoding_state_relation(manifest)?;
    verify_phase25_intervalized_decoding_state_relation_members_with_proof_checks(manifest)
}

fn summarize_phase26_members(
    members: &[Phase25IntervalizedDecodingStateRelationManifest],
) -> Result<Vec<Phase26MemberSummary>> {
    let mut summaries = Vec::with_capacity(members.len());
    let mut cumulative_steps = 0usize;

    for (member_index, member) in members.iter().enumerate() {
        verify_phase25_intervalized_decoding_state_relation(member).map_err(|error| {
            VmError::InvalidConfig(format!(
                "Phase 26 member {member_index} failed Phase 25 verification: {error}"
            ))
        })?;
        if member.total_steps == 0 {
            return Err(VmError::InvalidConfig(format!(
                "Phase 26 member {member_index} must cover at least one step"
            )));
        }
        if member.source_template_commitment.is_empty() {
            return Err(VmError::InvalidConfig(format!(
                "Phase 26 member {member_index} has an empty source_template_commitment"
            )));
        }
        if member.interval_template_commitment.is_empty() {
            return Err(VmError::InvalidConfig(format!(
                "Phase 26 member {member_index} has an empty interval_template_commitment"
            )));
        }
        if member.interval_accumulator_commitment.is_empty() {
            return Err(VmError::InvalidConfig(format!(
                "Phase 26 member {member_index} has an empty interval_accumulator_commitment"
            )));
        }
        if member.global_start_state_commitment.is_empty()
            || member.global_end_state_commitment.is_empty()
        {
            return Err(VmError::InvalidConfig(format!(
                "Phase 26 member {member_index} has an empty state-boundary commitment"
            )));
        }

        let start_step = cumulative_steps;
        let end_step = cumulative_steps.checked_add(member.total_steps).ok_or_else(|| {
            VmError::InvalidConfig(format!(
                "Phase 26 member {member_index} total_steps overflowed while deriving folded intervals"
            ))
        })?;
        summaries.push(Phase26MemberSummary {
            start_step,
            end_step,
            total_matrices: member.total_matrices,
            total_layouts: member.total_layouts,
            total_rollups: member.total_rollups,
            total_segments: member.total_segments,
            total_steps: member.total_steps,
            lookup_delta_entries: member.lookup_delta_entries,
            max_lookup_frontier_entries: member.max_lookup_frontier_entries,
            source_template_commitment: member.source_template_commitment.clone(),
            interval_template_commitment: member.interval_template_commitment.clone(),
            interval_accumulator_commitment: member.interval_accumulator_commitment.clone(),
            start_state_commitment: member.global_start_state_commitment.clone(),
            end_state_commitment: member.global_end_state_commitment.clone(),
        });
        cumulative_steps = end_step;
    }

    Ok(summaries)
}

fn verify_phase26_fold_sequence(summaries: &[Phase26MemberSummary]) -> Result<()> {
    if summaries.len() < 2 {
        return Err(VmError::InvalidConfig(
            "folded intervalized decoding state relation must contain at least two members"
                .to_string(),
        ));
    }

    let shared_source_template_commitment = summaries[0].source_template_commitment.clone();
    if shared_source_template_commitment.is_empty() {
        return Err(VmError::InvalidConfig(
            "folded intervalized decoding state relation source_template_commitment must not be empty"
                .to_string(),
        ));
    }

    for (member_index, summary) in summaries.iter().enumerate() {
        if summary.total_steps == 0 {
            return Err(VmError::InvalidConfig(format!(
                "Phase 26 member {member_index} must cover at least one step"
            )));
        }
        if summary.start_step >= summary.end_step {
            return Err(VmError::InvalidConfig(format!(
                "Phase 26 member {member_index} has invalid interval [{}..{})",
                summary.start_step, summary.end_step
            )));
        }
        if summary.end_step - summary.start_step != summary.total_steps {
            return Err(VmError::InvalidConfig(format!(
                "Phase 26 member {member_index} interval width {} does not match total_steps {}",
                summary.end_step - summary.start_step,
                summary.total_steps
            )));
        }
        if summary.source_template_commitment != shared_source_template_commitment {
            return Err(VmError::InvalidConfig(format!(
                "Phase 26 member {member_index} does not share the source_template_commitment of member 0"
            )));
        }
        if summary.interval_template_commitment.is_empty() {
            return Err(VmError::InvalidConfig(format!(
                "Phase 26 member {member_index} has an empty interval_template_commitment"
            )));
        }
        if summary.interval_accumulator_commitment.is_empty() {
            return Err(VmError::InvalidConfig(format!(
                "Phase 26 member {member_index} has an empty interval_accumulator_commitment"
            )));
        }
        if summary.start_state_commitment.is_empty() || summary.end_state_commitment.is_empty() {
            return Err(VmError::InvalidConfig(format!(
                "Phase 26 member {member_index} has an empty state-boundary commitment"
            )));
        }
        if member_index == 0 {
            if summary.start_step != 0 {
                return Err(VmError::InvalidConfig(format!(
                    "Phase 26 member 0 must start at step 0, got {}",
                    summary.start_step
                )));
            }
            continue;
        }
        let previous = &summaries[member_index - 1];
        if summary.start_step != previous.end_step {
            return Err(VmError::InvalidConfig(format!(
                "Phase 26 member {} interval [{}..{}) is not contiguous with member {} interval [{}..{})",
                member_index,
                summary.start_step,
                summary.end_step,
                member_index - 1,
                previous.start_step,
                previous.end_step
            )));
        }
        if summary.start_state_commitment != previous.end_state_commitment {
            return Err(VmError::InvalidConfig(format!(
                "Phase 26 member boundary {} -> {} does not preserve the carried-state commitment",
                member_index - 1,
                member_index
            )));
        }
    }

    Ok(())
}

fn aggregate_phase26_summary_totals(
    summaries: &[Phase26MemberSummary],
) -> Result<Phase26AggregateTotals> {
    verify_phase26_fold_sequence(summaries)?;

    let mut totals = Phase26AggregateTotals {
        total_matrices: 0,
        total_layouts: 0,
        total_rollups: 0,
        total_segments: 0,
        total_steps: 0,
        lookup_delta_entries: 0,
        max_lookup_frontier_entries: 0,
    };

    for (member_index, summary) in summaries.iter().enumerate() {
        totals.total_matrices = totals
            .total_matrices
            .checked_add(summary.total_matrices)
            .ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "Phase 26 total_matrices overflowed while adding member {member_index}"
                ))
            })?;
        totals.total_layouts = totals
            .total_layouts
            .checked_add(summary.total_layouts)
            .ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "Phase 26 total_layouts overflowed while adding member {member_index}"
                ))
            })?;
        totals.total_rollups = totals
            .total_rollups
            .checked_add(summary.total_rollups)
            .ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "Phase 26 total_rollups overflowed while adding member {member_index}"
                ))
            })?;
        totals.total_segments = totals
            .total_segments
            .checked_add(summary.total_segments)
            .ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "Phase 26 total_segments overflowed while adding member {member_index}"
                ))
            })?;
        totals.total_steps = totals
            .total_steps
            .checked_add(summary.total_steps)
            .ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "Phase 26 total_steps overflowed while adding member {member_index}"
                ))
            })?;
        totals.lookup_delta_entries = totals
            .lookup_delta_entries
            .checked_add(summary.lookup_delta_entries)
            .ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "Phase 26 lookup_delta_entries overflowed while adding member {member_index}"
                ))
            })?;
        totals.max_lookup_frontier_entries = totals
            .max_lookup_frontier_entries
            .max(summary.max_lookup_frontier_entries);
    }

    Ok(totals)
}

fn phase26_public_member_summaries(
    summaries: &[Phase26MemberSummary],
) -> Vec<Phase26FoldedIntervalizedDecodingStateRelationMemberSummary> {
    summaries
        .iter()
        .map(
            |summary| Phase26FoldedIntervalizedDecodingStateRelationMemberSummary {
                start_step: summary.start_step,
                end_step: summary.end_step,
                total_matrices: summary.total_matrices,
                total_layouts: summary.total_layouts,
                total_rollups: summary.total_rollups,
                total_segments: summary.total_segments,
                total_steps: summary.total_steps,
                lookup_delta_entries: summary.lookup_delta_entries,
                max_lookup_frontier_entries: summary.max_lookup_frontier_entries,
                source_template_commitment: summary.source_template_commitment.clone(),
                interval_template_commitment: summary.interval_template_commitment.clone(),
                interval_accumulator_commitment: summary.interval_accumulator_commitment.clone(),
                start_state_commitment: summary.start_state_commitment.clone(),
                end_state_commitment: summary.end_state_commitment.clone(),
            },
        )
        .collect()
}

fn validate_phase26_folded_intervalized_decoding_state_relation_shallow(
    manifest: &Phase26FoldedIntervalizedDecodingStateRelationManifest,
) -> Result<()> {
    if manifest.proof_backend != StarkProofBackend::Stwo {
        return Err(VmError::InvalidConfig(format!(
            "folded intervalized decoding state relation backend `{}` is not `stwo`",
            manifest.proof_backend
        )));
    }
    if manifest.artifact_version != STWO_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE26
    {
        return Err(VmError::InvalidConfig(format!(
            "unsupported folded intervalized decoding state relation version `{}`",
            manifest.artifact_version
        )));
    }
    if manifest.semantic_scope != STWO_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_SCOPE_PHASE26 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported folded intervalized decoding state relation semantic scope `{}`",
            manifest.semantic_scope
        )));
    }
    if manifest.proof_backend_version != crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported folded intervalized decoding state relation proof backend version `{}` (expected `{}`)",
            manifest.proof_backend_version,
            crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12
        )));
    }
    if manifest.statement_version != crate::proof::CLAIM_STATEMENT_VERSION_V1 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported folded intervalized decoding state relation statement version `{}`",
            manifest.statement_version
        )));
    }
    if manifest.members.len() < 2 {
        return Err(VmError::InvalidConfig(
            "folded intervalized decoding state relation must contain at least two members"
                .to_string(),
        ));
    }
    if manifest.members.len() > MAX_PHASE26_FOLDED_INTERVALIZED_MEMBERS {
        return Err(VmError::InvalidConfig(format!(
            "folded intervalized decoding state relation members.len()={} exceeds the supported maximum {}",
            manifest.members.len(),
            MAX_PHASE26_FOLDED_INTERVALIZED_MEMBERS
        )));
    }
    if manifest.member_count != manifest.members.len() {
        return Err(VmError::InvalidConfig(format!(
            "folded intervalized decoding state relation member_count={} does not match members.len()={}",
            manifest.member_count,
            manifest.members.len()
        )));
    }
    if manifest.member_summaries.len() != manifest.members.len() {
        return Err(VmError::InvalidConfig(format!(
            "folded intervalized decoding state relation member_summaries.len()={} does not match members.len()={}",
            manifest.member_summaries.len(),
            manifest.members.len()
        )));
    }
    if manifest.bounded_fold_arity < manifest.member_count
        || manifest.bounded_fold_arity > MAX_PHASE26_FOLDED_INTERVALIZED_MEMBERS
    {
        return Err(VmError::InvalidConfig(format!(
            "folded intervalized decoding state relation bounded_fold_arity={} must be between member_count {} and supported maximum {}",
            manifest.bounded_fold_arity,
            manifest.member_count,
            MAX_PHASE26_FOLDED_INTERVALIZED_MEMBERS
        )));
    }
    if manifest.total_rollups > MAX_PHASE26_FOLDED_INTERVALIZED_ROLLUPS {
        return Err(VmError::InvalidConfig(format!(
            "folded intervalized decoding state relation total_rollups={} exceeds the supported maximum {}",
            manifest.total_rollups,
            MAX_PHASE26_FOLDED_INTERVALIZED_ROLLUPS
        )));
    }
    if manifest.source_template_commitment.is_empty() {
        return Err(VmError::InvalidConfig(
            "folded intervalized decoding state relation source_template_commitment must not be empty"
                .to_string(),
        ));
    }
    if manifest.global_start_state_commitment.is_empty()
        || manifest.global_end_state_commitment.is_empty()
    {
        return Err(VmError::InvalidConfig(
            "folded intervalized decoding state relation global state-boundary commitments must not be empty"
                .to_string(),
        ));
    }
    if manifest.fold_template_commitment.is_empty() {
        return Err(VmError::InvalidConfig(
            "folded intervalized decoding state relation fold_template_commitment must not be empty"
                .to_string(),
        ));
    }
    if manifest.folded_interval_accumulator_commitment.is_empty() {
        return Err(VmError::InvalidConfig(
            "folded intervalized decoding state relation folded_interval_accumulator_commitment must not be empty"
                .to_string(),
        ));
    }
    Ok(())
}

fn commit_phase26_fold_template(
    source_template_commitment: &str,
    bounded_fold_arity: usize,
    summaries: &[Phase26MemberSummary],
) -> Result<String> {
    verify_phase26_fold_sequence(summaries)?;
    if source_template_commitment.is_empty() {
        return Err(VmError::InvalidConfig(
            "Phase 26 fold template source_template_commitment must not be empty".to_string(),
        ));
    }
    if bounded_fold_arity < summaries.len()
        || bounded_fold_arity > MAX_PHASE26_FOLDED_INTERVALIZED_MEMBERS
    {
        return Err(VmError::InvalidConfig(format!(
            "Phase 26 bounded_fold_arity={} must be between member_count {} and supported maximum {}",
            bounded_fold_arity,
            summaries.len(),
            MAX_PHASE26_FOLDED_INTERVALIZED_MEMBERS
        )));
    }

    let mut hasher = Blake2bVar::new(32).expect("blake2b-256");
    hasher.update(STWO_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE26.as_bytes());
    hasher.update(b"fold-template");
    hasher.update(&(bounded_fold_arity as u64).to_le_bytes());
    hasher.update(&(summaries.len() as u64).to_le_bytes());
    hasher.update(source_template_commitment.as_bytes());
    for (member_index, summary) in summaries.iter().enumerate() {
        hasher.update(&(member_index as u64).to_le_bytes());
        hasher.update(summary.interval_template_commitment.as_bytes());
        hasher.update(&(summary.start_step as u64).to_le_bytes());
        hasher.update(&(summary.end_step as u64).to_le_bytes());
        hasher.update(&(summary.total_matrices as u64).to_le_bytes());
        hasher.update(&(summary.total_layouts as u64).to_le_bytes());
        hasher.update(&(summary.total_rollups as u64).to_le_bytes());
        hasher.update(&(summary.total_segments as u64).to_le_bytes());
        hasher.update(&(summary.total_steps as u64).to_le_bytes());
        hasher.update(&(summary.lookup_delta_entries as u64).to_le_bytes());
        hasher.update(&(summary.max_lookup_frontier_entries as u64).to_le_bytes());
    }

    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("blake2b finalize");
    Ok(lower_hex(&out))
}

fn commit_phase26_folded_intervalized_state_relation_with_summaries(
    manifest: &Phase26FoldedIntervalizedDecodingStateRelationManifest,
    summaries: &[Phase26MemberSummary],
) -> Result<String> {
    if summaries.len() != manifest.members.len() {
        return Err(VmError::InvalidConfig(format!(
            "folded intervalized decoding state relation summaries.len()={} does not match members.len()={}",
            summaries.len(),
            manifest.members.len()
        )));
    }
    verify_phase26_fold_sequence(summaries)?;

    let mut hasher = Blake2bVar::new(32).expect("blake2b-256");
    hasher.update(STWO_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE26.as_bytes());
    hasher.update(b"folded-intervalized-state-relation");
    hasher.update(&(manifest.bounded_fold_arity as u64).to_le_bytes());
    hasher.update(manifest.source_template_commitment.as_bytes());
    hasher.update(manifest.global_start_state_commitment.as_bytes());
    hasher.update(manifest.global_end_state_commitment.as_bytes());
    hasher.update(manifest.fold_template_commitment.as_bytes());
    hasher.update(&(manifest.member_count as u64).to_le_bytes());
    hasher.update(&(manifest.total_matrices as u64).to_le_bytes());
    hasher.update(&(manifest.total_layouts as u64).to_le_bytes());
    hasher.update(&(manifest.total_rollups as u64).to_le_bytes());
    hasher.update(&(manifest.total_segments as u64).to_le_bytes());
    hasher.update(&(manifest.total_steps as u64).to_le_bytes());
    hasher.update(&(manifest.lookup_delta_entries as u64).to_le_bytes());
    hasher.update(&(manifest.max_lookup_frontier_entries as u64).to_le_bytes());
    for (member_index, summary) in summaries.iter().enumerate() {
        hasher.update(&(member_index as u64).to_le_bytes());
        hasher.update(&(summary.start_step as u64).to_le_bytes());
        hasher.update(&(summary.end_step as u64).to_le_bytes());
        hasher.update(summary.interval_template_commitment.as_bytes());
        hasher.update(summary.interval_accumulator_commitment.as_bytes());
        hasher.update(summary.start_state_commitment.as_bytes());
        hasher.update(summary.end_state_commitment.as_bytes());
        hasher.update(&(summary.total_matrices as u64).to_le_bytes());
        hasher.update(&(summary.total_layouts as u64).to_le_bytes());
        hasher.update(&(summary.total_rollups as u64).to_le_bytes());
        hasher.update(&(summary.total_segments as u64).to_le_bytes());
        hasher.update(&(summary.total_steps as u64).to_le_bytes());
        hasher.update(&(summary.lookup_delta_entries as u64).to_le_bytes());
        hasher.update(&(summary.max_lookup_frontier_entries as u64).to_le_bytes());
    }

    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("blake2b finalize");
    Ok(lower_hex(&out))
}

pub fn phase26_prepare_folded_intervalized_decoding_state_relation(
    members: &[Phase25IntervalizedDecodingStateRelationManifest],
) -> Result<Phase26FoldedIntervalizedDecodingStateRelationManifest> {
    if members.len() < 2 {
        return Err(VmError::InvalidConfig(
            "Phase 26 folded intervalized decoding state relation requires at least two members"
                .to_string(),
        ));
    }
    if members.len() > MAX_PHASE26_FOLDED_INTERVALIZED_MEMBERS {
        return Err(VmError::InvalidConfig(format!(
            "Phase 26 folded intervalized decoding state relation supports at most {MAX_PHASE26_FOLDED_INTERVALIZED_MEMBERS} members (got {})",
            members.len()
        )));
    }

    let summaries = summarize_phase26_members(members)?;
    let totals = aggregate_phase26_summary_totals(&summaries)?;
    if totals.total_rollups > MAX_PHASE26_FOLDED_INTERVALIZED_ROLLUPS {
        return Err(VmError::InvalidConfig(format!(
            "Phase 26 folded intervalized decoding state relation total_rollups={} exceeds the supported maximum {}",
            totals.total_rollups, MAX_PHASE26_FOLDED_INTERVALIZED_ROLLUPS
        )));
    }

    let bounded_fold_arity = members.len();
    let fold_template_commitment = commit_phase26_fold_template(
        &summaries[0].source_template_commitment,
        bounded_fold_arity,
        &summaries,
    )?;
    let mut manifest = Phase26FoldedIntervalizedDecodingStateRelationManifest {
        proof_backend: StarkProofBackend::Stwo,
        artifact_version: STWO_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE26
            .to_string(),
        semantic_scope: STWO_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_SCOPE_PHASE26.to_string(),
        proof_backend_version: members[0].proof_backend_version.clone(),
        statement_version: members[0].statement_version.clone(),
        bounded_fold_arity,
        member_count: members.len(),
        total_matrices: totals.total_matrices,
        total_layouts: totals.total_layouts,
        total_rollups: totals.total_rollups,
        total_segments: totals.total_segments,
        total_steps: totals.total_steps,
        lookup_delta_entries: totals.lookup_delta_entries,
        max_lookup_frontier_entries: totals.max_lookup_frontier_entries,
        source_template_commitment: summaries[0].source_template_commitment.clone(),
        global_start_state_commitment: summaries[0].start_state_commitment.clone(),
        global_end_state_commitment: summaries
            .last()
            .expect("phase26 summaries are non-empty")
            .end_state_commitment
            .clone(),
        fold_template_commitment,
        folded_interval_accumulator_commitment: String::new(),
        member_summaries: phase26_public_member_summaries(&summaries),
        members: members.to_vec(),
    };
    manifest.folded_interval_accumulator_commitment =
        commit_phase26_folded_intervalized_state_relation_with_summaries(&manifest, &summaries)?;
    verify_phase26_folded_intervalized_decoding_state_relation_with_summaries(
        &manifest, &summaries,
    )?;
    Ok(manifest)
}

fn verify_phase26_folded_intervalized_decoding_state_relation_with_summaries(
    manifest: &Phase26FoldedIntervalizedDecodingStateRelationManifest,
    summaries: &[Phase26MemberSummary],
) -> Result<()> {
    validate_phase26_folded_intervalized_decoding_state_relation_shallow(manifest)?;
    if summaries.len() != manifest.members.len() {
        return Err(VmError::InvalidConfig(format!(
            "folded intervalized decoding state relation summaries.len()={} does not match members.len()={}",
            summaries.len(),
            manifest.members.len()
        )));
    }
    verify_phase26_fold_sequence(summaries)?;
    let totals = aggregate_phase26_summary_totals(summaries)?;
    if manifest.total_matrices != totals.total_matrices {
        return Err(VmError::InvalidConfig(format!(
            "folded intervalized decoding state relation total_matrices={} does not match derived total_matrices {}",
            manifest.total_matrices, totals.total_matrices
        )));
    }
    if manifest.total_layouts != totals.total_layouts {
        return Err(VmError::InvalidConfig(format!(
            "folded intervalized decoding state relation total_layouts={} does not match derived total_layouts {}",
            manifest.total_layouts, totals.total_layouts
        )));
    }
    if manifest.total_rollups != totals.total_rollups {
        return Err(VmError::InvalidConfig(format!(
            "folded intervalized decoding state relation total_rollups={} does not match derived total_rollups {}",
            manifest.total_rollups, totals.total_rollups
        )));
    }
    if manifest.total_segments != totals.total_segments {
        return Err(VmError::InvalidConfig(format!(
            "folded intervalized decoding state relation total_segments={} does not match derived total_segments {}",
            manifest.total_segments, totals.total_segments
        )));
    }
    if manifest.total_steps != totals.total_steps {
        return Err(VmError::InvalidConfig(format!(
            "folded intervalized decoding state relation total_steps={} does not match derived total_steps {}",
            manifest.total_steps, totals.total_steps
        )));
    }
    if manifest.lookup_delta_entries != totals.lookup_delta_entries {
        return Err(VmError::InvalidConfig(format!(
            "folded intervalized decoding state relation lookup_delta_entries={} does not match derived lookup_delta_entries {}",
            manifest.lookup_delta_entries, totals.lookup_delta_entries
        )));
    }
    if manifest.max_lookup_frontier_entries != totals.max_lookup_frontier_entries {
        return Err(VmError::InvalidConfig(format!(
            "folded intervalized decoding state relation max_lookup_frontier_entries={} does not match derived max_lookup_frontier_entries {}",
            manifest.max_lookup_frontier_entries, totals.max_lookup_frontier_entries
        )));
    }
    let expected_member_summaries = phase26_public_member_summaries(summaries);
    if manifest.member_summaries != expected_member_summaries {
        return Err(VmError::InvalidConfig(
            "folded intervalized decoding state relation member_summaries do not match the derived fold summaries".to_string(),
        ));
    }
    let first = summaries.first().expect("phase26 summaries are non-empty");
    let last = summaries.last().expect("phase26 summaries are non-empty");
    if manifest.source_template_commitment != first.source_template_commitment {
        return Err(VmError::InvalidConfig(
            "folded intervalized decoding state relation source_template_commitment does not match the first member source template".to_string(),
        ));
    }
    if manifest.global_start_state_commitment != first.start_state_commitment {
        return Err(VmError::InvalidConfig(
            "folded intervalized decoding state relation global_start_state_commitment does not match the first member boundary".to_string(),
        ));
    }
    if manifest.global_end_state_commitment != last.end_state_commitment {
        return Err(VmError::InvalidConfig(
            "folded intervalized decoding state relation global_end_state_commitment does not match the last member boundary".to_string(),
        ));
    }
    let expected_fold_template_commitment = commit_phase26_fold_template(
        &manifest.source_template_commitment,
        manifest.bounded_fold_arity,
        summaries,
    )?;
    if manifest.fold_template_commitment != expected_fold_template_commitment {
        return Err(VmError::InvalidConfig(
            "folded intervalized decoding state relation fold_template_commitment does not match the computed fold template commitment".to_string(),
        ));
    }
    let expected_folded_interval_accumulator_commitment =
        commit_phase26_folded_intervalized_state_relation_with_summaries(manifest, summaries)?;
    if manifest.folded_interval_accumulator_commitment
        != expected_folded_interval_accumulator_commitment
    {
        return Err(VmError::InvalidConfig(
            "folded intervalized decoding state relation folded_interval_accumulator_commitment does not match the computed folded interval accumulator commitment".to_string(),
        ));
    }
    Ok(())
}

pub fn verify_phase26_folded_intervalized_decoding_state_relation(
    manifest: &Phase26FoldedIntervalizedDecodingStateRelationManifest,
) -> Result<()> {
    validate_phase26_folded_intervalized_decoding_state_relation_shallow(manifest)?;
    let summaries = summarize_phase26_members(&manifest.members)?;
    verify_phase26_folded_intervalized_decoding_state_relation_with_summaries(manifest, &summaries)
}

fn verify_phase26_folded_intervalized_decoding_state_relation_members_with_proof_checks(
    manifest: &Phase26FoldedIntervalizedDecodingStateRelationManifest,
) -> Result<()> {
    for (member_index, member) in manifest.members.iter().enumerate() {
        verify_phase25_intervalized_decoding_state_relation_with_proof_checks(member).map_err(
            |error| {
                VmError::InvalidConfig(format!(
                    "Phase 26 member {member_index} failed proof-bearing Phase 25 verification: {error}"
                ))
            },
        )?;
    }
    Ok(())
}

pub fn verify_phase26_folded_intervalized_decoding_state_relation_with_proof_checks(
    manifest: &Phase26FoldedIntervalizedDecodingStateRelationManifest,
) -> Result<()> {
    verify_phase26_folded_intervalized_decoding_state_relation(manifest)?;
    verify_phase26_folded_intervalized_decoding_state_relation_members_with_proof_checks(manifest)
}

fn summarize_phase27_members(
    members: &[Phase26FoldedIntervalizedDecodingStateRelationManifest],
) -> Result<Vec<Phase27MemberSummary>> {
    let mut step_cursor = 0usize;
    let mut summaries = Vec::with_capacity(members.len());
    for (member_index, member) in members.iter().enumerate() {
        verify_phase26_folded_intervalized_decoding_state_relation(member).map_err(|error| {
            VmError::InvalidConfig(format!(
                "Phase 27 member {member_index} is not a valid folded intervalized decoding state relation: {error}"
            ))
        })?;
        let end_step = step_cursor.checked_add(member.total_steps).ok_or_else(|| {
            VmError::InvalidConfig(format!(
                "Phase 27 member {member_index} total_steps overflowed the chained step cursor"
            ))
        })?;
        summaries.push(Phase27MemberSummary {
            start_step: step_cursor,
            end_step,
            bounded_fold_arity: member.bounded_fold_arity,
            total_phase25_members: member.member_count,
            total_matrices: member.total_matrices,
            total_layouts: member.total_layouts,
            total_rollups: member.total_rollups,
            total_segments: member.total_segments,
            total_steps: member.total_steps,
            lookup_delta_entries: member.lookup_delta_entries,
            max_lookup_frontier_entries: member.max_lookup_frontier_entries,
            source_template_commitment: member.source_template_commitment.clone(),
            fold_template_commitment: member.fold_template_commitment.clone(),
            folded_interval_accumulator_commitment: member
                .folded_interval_accumulator_commitment
                .clone(),
            start_state_commitment: member.global_start_state_commitment.clone(),
            end_state_commitment: member.global_end_state_commitment.clone(),
        });
        step_cursor = end_step;
    }
    Ok(summaries)
}

fn verify_phase27_chain_sequence(summaries: &[Phase27MemberSummary]) -> Result<()> {
    if summaries.len() < 2 {
        return Err(VmError::InvalidConfig(
            "Phase 27 chained folded intervalized decoding state relation requires at least two members"
                .to_string(),
        ));
    }
    let first = summaries.first().expect("phase27 summaries are non-empty");
    if first.start_step != 0 {
        return Err(VmError::InvalidConfig(format!(
            "Phase 27 first member must start at step 0 (got {})",
            first.start_step
        )));
    }
    if first.source_template_commitment.is_empty() {
        return Err(VmError::InvalidConfig(
            "Phase 27 source_template_commitment must not be empty".to_string(),
        ));
    }
    for (member_index, summary) in summaries.iter().enumerate() {
        if summary.end_step <= summary.start_step {
            return Err(VmError::InvalidConfig(format!(
                "Phase 27 member {member_index} has non-positive width interval [{}..{})",
                summary.start_step, summary.end_step
            )));
        }
        let derived_total_steps = summary.end_step - summary.start_step;
        if summary.total_steps != derived_total_steps {
            return Err(VmError::InvalidConfig(format!(
                "Phase 27 member {member_index} total_steps={} does not match interval width {}",
                summary.total_steps, derived_total_steps
            )));
        }
        if summary.source_template_commitment != first.source_template_commitment {
            return Err(VmError::InvalidConfig(format!(
                "Phase 27 member {member_index} changed source_template_commitment"
            )));
        }
        if summary.bounded_fold_arity < summary.total_phase25_members {
            return Err(VmError::InvalidConfig(format!(
                "Phase 27 member {member_index} bounded_fold_arity={} is smaller than nested member_count={}",
                summary.bounded_fold_arity, summary.total_phase25_members
            )));
        }
        if summary.total_phase25_members < 2 {
            return Err(VmError::InvalidConfig(format!(
                "Phase 27 member {member_index} must summarize at least two Phase 25 members"
            )));
        }
        if member_index == 0 {
            continue;
        }
        let previous = &summaries[member_index - 1];
        if summary.start_step != previous.end_step {
            return Err(VmError::InvalidConfig(format!(
                "Phase 27 member {member_index} starts at step {} but previous member ended at step {}",
                summary.start_step, previous.end_step
            )));
        }
        if summary.start_state_commitment != previous.end_state_commitment {
            return Err(VmError::InvalidConfig(format!(
                "Phase 27 member {member_index} does not preserve the carried-state commitment from the previous folded interval member"
            )));
        }
    }
    Ok(())
}

fn aggregate_phase27_summary_totals(
    summaries: &[Phase27MemberSummary],
) -> Result<Phase27AggregateTotals> {
    verify_phase27_chain_sequence(summaries)?;
    let mut totals = Phase27AggregateTotals {
        total_phase25_members: 0,
        max_nested_fold_arity: 0,
        total_matrices: 0,
        total_layouts: 0,
        total_rollups: 0,
        total_segments: 0,
        total_steps: 0,
        lookup_delta_entries: 0,
        max_lookup_frontier_entries: 0,
    };
    for summary in summaries {
        totals.total_phase25_members = totals
            .total_phase25_members
            .checked_add(summary.total_phase25_members)
            .ok_or_else(|| {
                VmError::InvalidConfig(
                    "Phase 27 total_phase25_members overflowed usize".to_string(),
                )
            })?;
        totals.max_nested_fold_arity = totals.max_nested_fold_arity.max(summary.bounded_fold_arity);
        totals.total_matrices = totals
            .total_matrices
            .checked_add(summary.total_matrices)
            .ok_or_else(|| {
                VmError::InvalidConfig("Phase 27 total_matrices overflowed usize".to_string())
            })?;
        totals.total_layouts = totals
            .total_layouts
            .checked_add(summary.total_layouts)
            .ok_or_else(|| {
                VmError::InvalidConfig("Phase 27 total_layouts overflowed usize".to_string())
            })?;
        totals.total_rollups = totals
            .total_rollups
            .checked_add(summary.total_rollups)
            .ok_or_else(|| {
                VmError::InvalidConfig("Phase 27 total_rollups overflowed usize".to_string())
            })?;
        totals.total_segments = totals
            .total_segments
            .checked_add(summary.total_segments)
            .ok_or_else(|| {
                VmError::InvalidConfig("Phase 27 total_segments overflowed usize".to_string())
            })?;
        totals.total_steps = totals
            .total_steps
            .checked_add(summary.total_steps)
            .ok_or_else(|| {
                VmError::InvalidConfig("Phase 27 total_steps overflowed usize".to_string())
            })?;
        totals.lookup_delta_entries = totals
            .lookup_delta_entries
            .checked_add(summary.lookup_delta_entries)
            .ok_or_else(|| {
                VmError::InvalidConfig("Phase 27 lookup_delta_entries overflowed usize".to_string())
            })?;
        totals.max_lookup_frontier_entries = totals
            .max_lookup_frontier_entries
            .max(summary.max_lookup_frontier_entries);
    }
    Ok(totals)
}

fn phase27_public_member_summaries(
    summaries: &[Phase27MemberSummary],
) -> Vec<Phase27ChainedFoldedIntervalizedDecodingStateRelationMemberSummary> {
    summaries
        .iter()
        .map(
            |summary| Phase27ChainedFoldedIntervalizedDecodingStateRelationMemberSummary {
                start_step: summary.start_step,
                end_step: summary.end_step,
                bounded_fold_arity: summary.bounded_fold_arity,
                total_phase25_members: summary.total_phase25_members,
                total_matrices: summary.total_matrices,
                total_layouts: summary.total_layouts,
                total_rollups: summary.total_rollups,
                total_segments: summary.total_segments,
                total_steps: summary.total_steps,
                lookup_delta_entries: summary.lookup_delta_entries,
                max_lookup_frontier_entries: summary.max_lookup_frontier_entries,
                source_template_commitment: summary.source_template_commitment.clone(),
                fold_template_commitment: summary.fold_template_commitment.clone(),
                folded_interval_accumulator_commitment: summary
                    .folded_interval_accumulator_commitment
                    .clone(),
                start_state_commitment: summary.start_state_commitment.clone(),
                end_state_commitment: summary.end_state_commitment.clone(),
            },
        )
        .collect()
}

fn validate_phase27_chained_folded_intervalized_decoding_state_relation_shallow(
    manifest: &Phase27ChainedFoldedIntervalizedDecodingStateRelationManifest,
) -> Result<()> {
    if manifest.proof_backend != StarkProofBackend::Stwo {
        return Err(VmError::InvalidConfig(format!(
            "chained folded intervalized decoding state relation backend `{}` is not `stwo`",
            manifest.proof_backend
        )));
    }
    if manifest.artifact_version
        != STWO_CHAINED_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE27
    {
        return Err(VmError::InvalidConfig(format!(
            "unsupported chained folded intervalized decoding state relation version `{}`",
            manifest.artifact_version
        )));
    }
    if manifest.semantic_scope
        != STWO_CHAINED_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_SCOPE_PHASE27
    {
        return Err(VmError::InvalidConfig(format!(
            "unsupported chained folded intervalized decoding state relation semantic scope `{}`",
            manifest.semantic_scope
        )));
    }
    if manifest.proof_backend_version != crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported chained folded intervalized decoding state relation proof backend version `{}` (expected `{}`)",
            manifest.proof_backend_version,
            crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12
        )));
    }
    if manifest.statement_version != crate::proof::CLAIM_STATEMENT_VERSION_V1 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported chained folded intervalized decoding state relation statement version `{}`",
            manifest.statement_version
        )));
    }
    if manifest.members.len() < 2 {
        return Err(VmError::InvalidConfig(
            "chained folded intervalized decoding state relation must contain at least two members"
                .to_string(),
        ));
    }
    if manifest.members.len() > MAX_PHASE27_CHAINED_FOLDED_INTERVALIZED_MEMBERS {
        return Err(VmError::InvalidConfig(format!(
            "chained folded intervalized decoding state relation members.len()={} exceeds the supported maximum {}",
            manifest.members.len(),
            MAX_PHASE27_CHAINED_FOLDED_INTERVALIZED_MEMBERS
        )));
    }
    if manifest.member_count != manifest.members.len() {
        return Err(VmError::InvalidConfig(format!(
            "chained folded intervalized decoding state relation member_count={} does not match members.len()={}",
            manifest.member_count,
            manifest.members.len()
        )));
    }
    if manifest.member_summaries.len() != manifest.members.len() {
        return Err(VmError::InvalidConfig(format!(
            "chained folded intervalized decoding state relation member_summaries.len()={} does not match members.len()={}",
            manifest.member_summaries.len(),
            manifest.members.len()
        )));
    }
    if manifest.bounded_chain_arity < manifest.member_count
        || manifest.bounded_chain_arity > MAX_PHASE27_CHAINED_FOLDED_INTERVALIZED_MEMBERS
    {
        return Err(VmError::InvalidConfig(format!(
            "chained folded intervalized decoding state relation bounded_chain_arity={} must be between member_count {} and supported maximum {}",
            manifest.bounded_chain_arity,
            manifest.member_count,
            MAX_PHASE27_CHAINED_FOLDED_INTERVALIZED_MEMBERS
        )));
    }
    let min_total_phase25_members = manifest.member_count.checked_mul(2).ok_or_else(|| {
        VmError::InvalidConfig(
            "chained folded intervalized decoding state relation member_count overflowed while deriving the minimum nested Phase 25 member bound"
                .to_string(),
        )
    })?;
    if manifest.total_phase25_members < min_total_phase25_members
        || manifest.total_phase25_members > MAX_PHASE27_TOTAL_NESTED_PHASE25_MEMBERS
    {
        return Err(VmError::InvalidConfig(format!(
            "chained folded intervalized decoding state relation total_phase25_members={} must be between {} and supported maximum {}",
            manifest.total_phase25_members,
            min_total_phase25_members,
            MAX_PHASE27_TOTAL_NESTED_PHASE25_MEMBERS
        )));
    }
    if manifest.max_nested_fold_arity < 2
        || manifest.max_nested_fold_arity > MAX_PHASE26_FOLDED_INTERVALIZED_MEMBERS
    {
        return Err(VmError::InvalidConfig(format!(
            "chained folded intervalized decoding state relation max_nested_fold_arity={} must be between 2 and {}",
            manifest.max_nested_fold_arity,
            MAX_PHASE26_FOLDED_INTERVALIZED_MEMBERS
        )));
    }
    if manifest.total_rollups > MAX_PHASE27_CHAINED_FOLDED_INTERVALIZED_ROLLUPS {
        return Err(VmError::InvalidConfig(format!(
            "chained folded intervalized decoding state relation total_rollups={} exceeds the supported maximum {}",
            manifest.total_rollups,
            MAX_PHASE27_CHAINED_FOLDED_INTERVALIZED_ROLLUPS
        )));
    }
    if manifest.source_template_commitment.is_empty() {
        return Err(VmError::InvalidConfig(
            "chained folded intervalized decoding state relation source_template_commitment must not be empty".to_string(),
        ));
    }
    if manifest.global_start_state_commitment.is_empty() {
        return Err(VmError::InvalidConfig(
            "chained folded intervalized decoding state relation global_start_state_commitment must not be empty".to_string(),
        ));
    }
    if manifest.global_end_state_commitment.is_empty() {
        return Err(VmError::InvalidConfig(
            "chained folded intervalized decoding state relation global_end_state_commitment must not be empty".to_string(),
        ));
    }
    if manifest.chain_template_commitment.is_empty() {
        return Err(VmError::InvalidConfig(
            "chained folded intervalized decoding state relation chain_template_commitment must not be empty".to_string(),
        ));
    }
    if manifest
        .chained_folded_interval_accumulator_commitment
        .is_empty()
    {
        return Err(VmError::InvalidConfig(
            "chained folded intervalized decoding state relation chained_folded_interval_accumulator_commitment must not be empty".to_string(),
        ));
    }
    Ok(())
}

fn commit_phase27_chain_template(
    source_template_commitment: &str,
    bounded_chain_arity: usize,
    summaries: &[Phase27MemberSummary],
) -> Result<String> {
    verify_phase27_chain_sequence(summaries)?;
    if source_template_commitment.is_empty() {
        return Err(VmError::InvalidConfig(
            "Phase 27 chain template source_template_commitment must not be empty".to_string(),
        ));
    }
    if bounded_chain_arity < summaries.len()
        || bounded_chain_arity > MAX_PHASE27_CHAINED_FOLDED_INTERVALIZED_MEMBERS
    {
        return Err(VmError::InvalidConfig(format!(
            "Phase 27 bounded_chain_arity={} must be between member_count {} and supported maximum {}",
            bounded_chain_arity,
            summaries.len(),
            MAX_PHASE27_CHAINED_FOLDED_INTERVALIZED_MEMBERS
        )));
    }

    let mut hasher = Blake2bVar::new(32).expect("blake2b-256");
    hasher.update(
        STWO_CHAINED_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE27.as_bytes(),
    );
    hasher.update(b"chain-template");
    hasher.update(&(bounded_chain_arity as u64).to_le_bytes());
    hasher.update(&(summaries.len() as u64).to_le_bytes());
    hasher.update(source_template_commitment.as_bytes());
    for (member_index, summary) in summaries.iter().enumerate() {
        hasher.update(&(member_index as u64).to_le_bytes());
        hasher.update(&(summary.bounded_fold_arity as u64).to_le_bytes());
        hasher.update(&(summary.total_phase25_members as u64).to_le_bytes());
        hasher.update(summary.fold_template_commitment.as_bytes());
        hasher.update(&(summary.start_step as u64).to_le_bytes());
        hasher.update(&(summary.end_step as u64).to_le_bytes());
        hasher.update(&(summary.total_matrices as u64).to_le_bytes());
        hasher.update(&(summary.total_layouts as u64).to_le_bytes());
        hasher.update(&(summary.total_rollups as u64).to_le_bytes());
        hasher.update(&(summary.total_segments as u64).to_le_bytes());
        hasher.update(&(summary.total_steps as u64).to_le_bytes());
        hasher.update(&(summary.lookup_delta_entries as u64).to_le_bytes());
        hasher.update(&(summary.max_lookup_frontier_entries as u64).to_le_bytes());
    }

    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("blake2b finalize");
    Ok(lower_hex(&out))
}

fn commit_phase27_chained_folded_intervalized_state_relation_with_summaries(
    manifest: &Phase27ChainedFoldedIntervalizedDecodingStateRelationManifest,
    summaries: &[Phase27MemberSummary],
) -> Result<String> {
    if summaries.len() != manifest.members.len() {
        return Err(VmError::InvalidConfig(format!(
            "chained folded intervalized decoding state relation summaries.len()={} does not match members.len()={}",
            summaries.len(),
            manifest.members.len()
        )));
    }
    verify_phase27_chain_sequence(summaries)?;

    let mut hasher = Blake2bVar::new(32).expect("blake2b-256");
    hasher.update(
        STWO_CHAINED_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE27.as_bytes(),
    );
    hasher.update(b"chained-folded-intervalized-state-relation");
    hasher.update(&(manifest.bounded_chain_arity as u64).to_le_bytes());
    hasher.update(&(manifest.total_phase25_members as u64).to_le_bytes());
    hasher.update(&(manifest.max_nested_fold_arity as u64).to_le_bytes());
    hasher.update(manifest.source_template_commitment.as_bytes());
    hasher.update(manifest.global_start_state_commitment.as_bytes());
    hasher.update(manifest.global_end_state_commitment.as_bytes());
    hasher.update(manifest.chain_template_commitment.as_bytes());
    hasher.update(&(manifest.member_count as u64).to_le_bytes());
    hasher.update(&(manifest.total_matrices as u64).to_le_bytes());
    hasher.update(&(manifest.total_layouts as u64).to_le_bytes());
    hasher.update(&(manifest.total_rollups as u64).to_le_bytes());
    hasher.update(&(manifest.total_segments as u64).to_le_bytes());
    hasher.update(&(manifest.total_steps as u64).to_le_bytes());
    hasher.update(&(manifest.lookup_delta_entries as u64).to_le_bytes());
    hasher.update(&(manifest.max_lookup_frontier_entries as u64).to_le_bytes());
    for (member_index, summary) in summaries.iter().enumerate() {
        hasher.update(&(member_index as u64).to_le_bytes());
        hasher.update(&(summary.start_step as u64).to_le_bytes());
        hasher.update(&(summary.end_step as u64).to_le_bytes());
        hasher.update(&(summary.bounded_fold_arity as u64).to_le_bytes());
        hasher.update(&(summary.total_phase25_members as u64).to_le_bytes());
        hasher.update(summary.fold_template_commitment.as_bytes());
        hasher.update(summary.folded_interval_accumulator_commitment.as_bytes());
        hasher.update(summary.start_state_commitment.as_bytes());
        hasher.update(summary.end_state_commitment.as_bytes());
        hasher.update(&(summary.total_matrices as u64).to_le_bytes());
        hasher.update(&(summary.total_layouts as u64).to_le_bytes());
        hasher.update(&(summary.total_rollups as u64).to_le_bytes());
        hasher.update(&(summary.total_segments as u64).to_le_bytes());
        hasher.update(&(summary.total_steps as u64).to_le_bytes());
        hasher.update(&(summary.lookup_delta_entries as u64).to_le_bytes());
        hasher.update(&(summary.max_lookup_frontier_entries as u64).to_le_bytes());
    }

    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("blake2b finalize");
    Ok(lower_hex(&out))
}

pub fn phase27_prepare_chained_folded_intervalized_decoding_state_relation(
    members: &[Phase26FoldedIntervalizedDecodingStateRelationManifest],
) -> Result<Phase27ChainedFoldedIntervalizedDecodingStateRelationManifest> {
    if members.len() < 2 {
        return Err(VmError::InvalidConfig(
            "Phase 27 chained folded intervalized decoding state relation requires at least two members"
                .to_string(),
        ));
    }
    if members.len() > MAX_PHASE27_CHAINED_FOLDED_INTERVALIZED_MEMBERS {
        return Err(VmError::InvalidConfig(format!(
            "Phase 27 chained folded intervalized decoding state relation supports at most {MAX_PHASE27_CHAINED_FOLDED_INTERVALIZED_MEMBERS} members (got {})",
            members.len()
        )));
    }

    let summaries = summarize_phase27_members(members)?;
    let totals = aggregate_phase27_summary_totals(&summaries)?;
    if totals.total_phase25_members > MAX_PHASE27_TOTAL_NESTED_PHASE25_MEMBERS {
        return Err(VmError::InvalidConfig(format!(
            "Phase 27 chained folded intervalized decoding state relation total_phase25_members={} exceeds the supported maximum {}",
            totals.total_phase25_members, MAX_PHASE27_TOTAL_NESTED_PHASE25_MEMBERS
        )));
    }
    if totals.total_rollups > MAX_PHASE27_CHAINED_FOLDED_INTERVALIZED_ROLLUPS {
        return Err(VmError::InvalidConfig(format!(
            "Phase 27 chained folded intervalized decoding state relation total_rollups={} exceeds the supported maximum {}",
            totals.total_rollups, MAX_PHASE27_CHAINED_FOLDED_INTERVALIZED_ROLLUPS
        )));
    }

    let bounded_chain_arity = members.len();
    let chain_template_commitment = commit_phase27_chain_template(
        &summaries[0].source_template_commitment,
        bounded_chain_arity,
        &summaries,
    )?;
    let mut manifest = Phase27ChainedFoldedIntervalizedDecodingStateRelationManifest {
        proof_backend: StarkProofBackend::Stwo,
        artifact_version: STWO_CHAINED_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE27
            .to_string(),
        semantic_scope: STWO_CHAINED_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_SCOPE_PHASE27
            .to_string(),
        proof_backend_version: members[0].proof_backend_version.clone(),
        statement_version: members[0].statement_version.clone(),
        bounded_chain_arity,
        member_count: members.len(),
        total_phase25_members: totals.total_phase25_members,
        max_nested_fold_arity: totals.max_nested_fold_arity,
        total_matrices: totals.total_matrices,
        total_layouts: totals.total_layouts,
        total_rollups: totals.total_rollups,
        total_segments: totals.total_segments,
        total_steps: totals.total_steps,
        lookup_delta_entries: totals.lookup_delta_entries,
        max_lookup_frontier_entries: totals.max_lookup_frontier_entries,
        source_template_commitment: summaries[0].source_template_commitment.clone(),
        global_start_state_commitment: summaries[0].start_state_commitment.clone(),
        global_end_state_commitment: summaries
            .last()
            .expect("phase27 summaries are non-empty")
            .end_state_commitment
            .clone(),
        chain_template_commitment,
        chained_folded_interval_accumulator_commitment: String::new(),
        member_summaries: phase27_public_member_summaries(&summaries),
        members: members.to_vec(),
    };
    manifest.chained_folded_interval_accumulator_commitment =
        commit_phase27_chained_folded_intervalized_state_relation_with_summaries(
            &manifest, &summaries,
        )?;
    verify_phase27_chained_folded_intervalized_decoding_state_relation_with_summaries(
        &manifest, &summaries,
    )?;
    Ok(manifest)
}

fn verify_phase27_chained_folded_intervalized_decoding_state_relation_with_summaries(
    manifest: &Phase27ChainedFoldedIntervalizedDecodingStateRelationManifest,
    summaries: &[Phase27MemberSummary],
) -> Result<()> {
    validate_phase27_chained_folded_intervalized_decoding_state_relation_shallow(manifest)?;
    if summaries.len() != manifest.members.len() {
        return Err(VmError::InvalidConfig(format!(
            "chained folded intervalized decoding state relation summaries.len()={} does not match members.len()={}",
            summaries.len(),
            manifest.members.len()
        )));
    }
    verify_phase27_chain_sequence(summaries)?;
    let totals = aggregate_phase27_summary_totals(summaries)?;
    if manifest.total_phase25_members != totals.total_phase25_members {
        return Err(VmError::InvalidConfig(format!(
            "chained folded intervalized decoding state relation total_phase25_members={} does not match derived total_phase25_members {}",
            manifest.total_phase25_members, totals.total_phase25_members
        )));
    }
    if manifest.max_nested_fold_arity != totals.max_nested_fold_arity {
        return Err(VmError::InvalidConfig(format!(
            "chained folded intervalized decoding state relation max_nested_fold_arity={} does not match derived max_nested_fold_arity {}",
            manifest.max_nested_fold_arity, totals.max_nested_fold_arity
        )));
    }
    if manifest.total_matrices != totals.total_matrices {
        return Err(VmError::InvalidConfig(format!(
            "chained folded intervalized decoding state relation total_matrices={} does not match derived total_matrices {}",
            manifest.total_matrices, totals.total_matrices
        )));
    }
    if manifest.total_layouts != totals.total_layouts {
        return Err(VmError::InvalidConfig(format!(
            "chained folded intervalized decoding state relation total_layouts={} does not match derived total_layouts {}",
            manifest.total_layouts, totals.total_layouts
        )));
    }
    if manifest.total_rollups != totals.total_rollups {
        return Err(VmError::InvalidConfig(format!(
            "chained folded intervalized decoding state relation total_rollups={} does not match derived total_rollups {}",
            manifest.total_rollups, totals.total_rollups
        )));
    }
    if manifest.total_segments != totals.total_segments {
        return Err(VmError::InvalidConfig(format!(
            "chained folded intervalized decoding state relation total_segments={} does not match derived total_segments {}",
            manifest.total_segments, totals.total_segments
        )));
    }
    if manifest.total_steps != totals.total_steps {
        return Err(VmError::InvalidConfig(format!(
            "chained folded intervalized decoding state relation total_steps={} does not match derived total_steps {}",
            manifest.total_steps, totals.total_steps
        )));
    }
    if manifest.lookup_delta_entries != totals.lookup_delta_entries {
        return Err(VmError::InvalidConfig(format!(
            "chained folded intervalized decoding state relation lookup_delta_entries={} does not match derived lookup_delta_entries {}",
            manifest.lookup_delta_entries, totals.lookup_delta_entries
        )));
    }
    if manifest.max_lookup_frontier_entries != totals.max_lookup_frontier_entries {
        return Err(VmError::InvalidConfig(format!(
            "chained folded intervalized decoding state relation max_lookup_frontier_entries={} does not match derived max_lookup_frontier_entries {}",
            manifest.max_lookup_frontier_entries, totals.max_lookup_frontier_entries
        )));
    }
    let expected_member_summaries = phase27_public_member_summaries(summaries);
    if manifest.member_summaries != expected_member_summaries {
        return Err(VmError::InvalidConfig(
            "chained folded intervalized decoding state relation member_summaries do not match the derived chain summaries".to_string(),
        ));
    }
    let first = summaries.first().expect("phase27 summaries are non-empty");
    let last = summaries.last().expect("phase27 summaries are non-empty");
    if manifest.source_template_commitment != first.source_template_commitment {
        return Err(VmError::InvalidConfig(
            "chained folded intervalized decoding state relation source_template_commitment does not match the first member source template".to_string(),
        ));
    }
    if manifest.global_start_state_commitment != first.start_state_commitment {
        return Err(VmError::InvalidConfig(
            "chained folded intervalized decoding state relation global_start_state_commitment does not match the first member boundary".to_string(),
        ));
    }
    if manifest.global_end_state_commitment != last.end_state_commitment {
        return Err(VmError::InvalidConfig(
            "chained folded intervalized decoding state relation global_end_state_commitment does not match the last member boundary".to_string(),
        ));
    }
    let expected_chain_template_commitment = commit_phase27_chain_template(
        &manifest.source_template_commitment,
        manifest.bounded_chain_arity,
        summaries,
    )?;
    if manifest.chain_template_commitment != expected_chain_template_commitment {
        return Err(VmError::InvalidConfig(
            "chained folded intervalized decoding state relation chain_template_commitment does not match the computed chain template commitment".to_string(),
        ));
    }
    let expected_chained_folded_interval_accumulator_commitment =
        commit_phase27_chained_folded_intervalized_state_relation_with_summaries(
            manifest, summaries,
        )?;
    if manifest.chained_folded_interval_accumulator_commitment
        != expected_chained_folded_interval_accumulator_commitment
    {
        return Err(VmError::InvalidConfig(
            "chained folded intervalized decoding state relation chained_folded_interval_accumulator_commitment does not match the computed chained fold accumulator commitment".to_string(),
        ));
    }
    Ok(())
}

pub fn verify_phase27_chained_folded_intervalized_decoding_state_relation(
    manifest: &Phase27ChainedFoldedIntervalizedDecodingStateRelationManifest,
) -> Result<()> {
    validate_phase27_chained_folded_intervalized_decoding_state_relation_shallow(manifest)?;
    let summaries = summarize_phase27_members(&manifest.members)?;
    verify_phase27_chained_folded_intervalized_decoding_state_relation_with_summaries(
        manifest, &summaries,
    )
}

fn verify_phase27_chained_folded_intervalized_decoding_state_relation_members_with_proof_checks(
    manifest: &Phase27ChainedFoldedIntervalizedDecodingStateRelationManifest,
) -> Result<()> {
    for (member_index, member) in manifest.members.iter().enumerate() {
        verify_phase26_folded_intervalized_decoding_state_relation_with_proof_checks(member)
            .map_err(|error| {
                VmError::InvalidConfig(format!(
                    "Phase 27 member {member_index} failed proof-bearing Phase 26 verification: {error}"
                ))
            })?;
    }
    Ok(())
}

pub fn verify_phase27_chained_folded_intervalized_decoding_state_relation_with_proof_checks(
    manifest: &Phase27ChainedFoldedIntervalizedDecodingStateRelationManifest,
) -> Result<()> {
    verify_phase27_chained_folded_intervalized_decoding_state_relation(manifest)?;
    verify_phase27_chained_folded_intervalized_decoding_state_relation_members_with_proof_checks(
        manifest,
    )
}

fn summarize_phase28_members(
    members: &[Phase27ChainedFoldedIntervalizedDecodingStateRelationManifest],
) -> Result<Vec<Phase28MemberSummary>> {
    let mut step_cursor = 0usize;
    let mut summaries = Vec::with_capacity(members.len());
    for (member_index, member) in members.iter().enumerate() {
        verify_phase27_chained_folded_intervalized_decoding_state_relation(member).map_err(
            |error| {
                VmError::InvalidConfig(format!(
                    "Phase 28 member {member_index} is not a valid chained folded intervalized decoding state relation: {error}"
                ))
            },
        )?;
        let end_step = step_cursor.checked_add(member.total_steps).ok_or_else(|| {
            VmError::InvalidConfig(format!(
                "Phase 28 member {member_index} total_steps overflowed the aggregation step cursor"
            ))
        })?;
        summaries.push(Phase28MemberSummary {
            start_step: step_cursor,
            end_step,
            bounded_chain_arity: member.bounded_chain_arity,
            total_phase26_members: member.member_count,
            total_phase25_members: member.total_phase25_members,
            max_nested_fold_arity: member.max_nested_fold_arity,
            total_matrices: member.total_matrices,
            total_layouts: member.total_layouts,
            total_rollups: member.total_rollups,
            total_segments: member.total_segments,
            total_steps: member.total_steps,
            lookup_delta_entries: member.lookup_delta_entries,
            max_lookup_frontier_entries: member.max_lookup_frontier_entries,
            source_template_commitment: member.source_template_commitment.clone(),
            chain_template_commitment: member.chain_template_commitment.clone(),
            chained_folded_interval_accumulator_commitment: member
                .chained_folded_interval_accumulator_commitment
                .clone(),
            start_state_commitment: member.global_start_state_commitment.clone(),
            end_state_commitment: member.global_end_state_commitment.clone(),
        });
        step_cursor = end_step;
    }
    Ok(summaries)
}

fn verify_phase28_aggregation_sequence(summaries: &[Phase28MemberSummary]) -> Result<()> {
    if summaries.len() < 2 {
        return Err(VmError::InvalidConfig(
            "Phase 28 aggregated chained folded intervalized decoding state relation requires at least two members"
                .to_string(),
        ));
    }
    let first = summaries.first().expect("phase28 summaries are non-empty");
    if first.start_step != 0 {
        return Err(VmError::InvalidConfig(format!(
            "Phase 28 first member must start at step 0 (got {})",
            first.start_step
        )));
    }
    if first.source_template_commitment.is_empty() {
        return Err(VmError::InvalidConfig(
            "Phase 28 source_template_commitment must not be empty".to_string(),
        ));
    }
    for (member_index, summary) in summaries.iter().enumerate() {
        if summary.end_step <= summary.start_step {
            return Err(VmError::InvalidConfig(format!(
                "Phase 28 member {member_index} has non-positive width interval [{}..{})",
                summary.start_step, summary.end_step
            )));
        }
        let derived_total_steps = summary.end_step - summary.start_step;
        if summary.total_steps != derived_total_steps {
            return Err(VmError::InvalidConfig(format!(
                "Phase 28 member {member_index} total_steps={} does not match interval width {}",
                summary.total_steps, derived_total_steps
            )));
        }
        if summary.source_template_commitment != first.source_template_commitment {
            return Err(VmError::InvalidConfig(format!(
                "Phase 28 member {member_index} changed source_template_commitment"
            )));
        }
        if summary.bounded_chain_arity < summary.total_phase26_members {
            return Err(VmError::InvalidConfig(format!(
                "Phase 28 member {member_index} bounded_chain_arity={} is smaller than nested member_count={}",
                summary.bounded_chain_arity, summary.total_phase26_members
            )));
        }
        if summary.total_phase26_members < 2 {
            return Err(VmError::InvalidConfig(format!(
                "Phase 28 member {member_index} must summarize at least two Phase 26 members"
            )));
        }
        if summary.total_phase25_members < 4 {
            return Err(VmError::InvalidConfig(format!(
                "Phase 28 member {member_index} must summarize at least four Phase 25 members"
            )));
        }
        if member_index == 0 {
            continue;
        }
        let previous = &summaries[member_index - 1];
        if summary.start_step != previous.end_step {
            return Err(VmError::InvalidConfig(format!(
                "Phase 28 member {member_index} starts at step {} but previous member ended at step {}",
                summary.start_step, previous.end_step
            )));
        }
        if summary.start_state_commitment != previous.end_state_commitment {
            return Err(VmError::InvalidConfig(format!(
                "Phase 28 member {member_index} does not preserve the carried-state commitment from the previous chained folded interval member"
            )));
        }
    }
    Ok(())
}

fn aggregate_phase28_summary_totals(
    summaries: &[Phase28MemberSummary],
) -> Result<Phase28AggregateTotals> {
    verify_phase28_aggregation_sequence(summaries)?;
    let mut totals = Phase28AggregateTotals {
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
    };
    for summary in summaries {
        totals.total_phase26_members = totals
            .total_phase26_members
            .checked_add(summary.total_phase26_members)
            .ok_or_else(|| {
                VmError::InvalidConfig(
                    "Phase 28 total_phase26_members overflowed usize".to_string(),
                )
            })?;
        totals.total_phase25_members = totals
            .total_phase25_members
            .checked_add(summary.total_phase25_members)
            .ok_or_else(|| {
                VmError::InvalidConfig(
                    "Phase 28 total_phase25_members overflowed usize".to_string(),
                )
            })?;
        totals.max_nested_chain_arity = totals
            .max_nested_chain_arity
            .max(summary.bounded_chain_arity);
        totals.max_nested_fold_arity = totals
            .max_nested_fold_arity
            .max(summary.max_nested_fold_arity);
        totals.total_matrices = totals
            .total_matrices
            .checked_add(summary.total_matrices)
            .ok_or_else(|| {
                VmError::InvalidConfig("Phase 28 total_matrices overflowed usize".to_string())
            })?;
        totals.total_layouts = totals
            .total_layouts
            .checked_add(summary.total_layouts)
            .ok_or_else(|| {
                VmError::InvalidConfig("Phase 28 total_layouts overflowed usize".to_string())
            })?;
        totals.total_rollups = totals
            .total_rollups
            .checked_add(summary.total_rollups)
            .ok_or_else(|| {
                VmError::InvalidConfig("Phase 28 total_rollups overflowed usize".to_string())
            })?;
        totals.total_segments = totals
            .total_segments
            .checked_add(summary.total_segments)
            .ok_or_else(|| {
                VmError::InvalidConfig("Phase 28 total_segments overflowed usize".to_string())
            })?;
        totals.total_steps = totals
            .total_steps
            .checked_add(summary.total_steps)
            .ok_or_else(|| {
                VmError::InvalidConfig("Phase 28 total_steps overflowed usize".to_string())
            })?;
        totals.lookup_delta_entries = totals
            .lookup_delta_entries
            .checked_add(summary.lookup_delta_entries)
            .ok_or_else(|| {
                VmError::InvalidConfig("Phase 28 lookup_delta_entries overflowed usize".to_string())
            })?;
        totals.max_lookup_frontier_entries = totals
            .max_lookup_frontier_entries
            .max(summary.max_lookup_frontier_entries);
    }
    Ok(totals)
}

fn phase28_public_member_summaries(
    summaries: &[Phase28MemberSummary],
) -> Vec<Phase28AggregatedChainedFoldedIntervalizedDecodingStateRelationMemberSummary> {
    summaries
        .iter()
        .map(|summary| {
            Phase28AggregatedChainedFoldedIntervalizedDecodingStateRelationMemberSummary {
                start_step: summary.start_step,
                end_step: summary.end_step,
                bounded_chain_arity: summary.bounded_chain_arity,
                total_phase26_members: summary.total_phase26_members,
                total_phase25_members: summary.total_phase25_members,
                max_nested_fold_arity: summary.max_nested_fold_arity,
                total_matrices: summary.total_matrices,
                total_layouts: summary.total_layouts,
                total_rollups: summary.total_rollups,
                total_segments: summary.total_segments,
                total_steps: summary.total_steps,
                lookup_delta_entries: summary.lookup_delta_entries,
                max_lookup_frontier_entries: summary.max_lookup_frontier_entries,
                source_template_commitment: summary.source_template_commitment.clone(),
                chain_template_commitment: summary.chain_template_commitment.clone(),
                chained_folded_interval_accumulator_commitment: summary
                    .chained_folded_interval_accumulator_commitment
                    .clone(),
                start_state_commitment: summary.start_state_commitment.clone(),
                end_state_commitment: summary.end_state_commitment.clone(),
            }
        })
        .collect()
}

fn validate_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_shallow(
    manifest: &Phase28AggregatedChainedFoldedIntervalizedDecodingStateRelationManifest,
) -> Result<()> {
    if manifest.proof_backend != StarkProofBackend::Stwo {
        return Err(VmError::InvalidConfig(format!(
            "aggregated chained folded intervalized decoding state relation backend `{}` is not `stwo`",
            manifest.proof_backend
        )));
    }
    if manifest.artifact_version
        != STWO_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE28
    {
        return Err(VmError::InvalidConfig(format!(
            "unsupported aggregated chained folded intervalized decoding state relation version `{}`",
            manifest.artifact_version
        )));
    }
    if manifest.semantic_scope
        != STWO_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_SCOPE_PHASE28
    {
        return Err(VmError::InvalidConfig(format!(
            "unsupported aggregated chained folded intervalized decoding state relation semantic scope `{}`",
            manifest.semantic_scope
        )));
    }
    if manifest.proof_backend_version != crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported aggregated chained folded intervalized decoding state relation proof backend version `{}` (expected `{}`)",
            manifest.proof_backend_version,
            crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12
        )));
    }
    if manifest.statement_version != crate::proof::CLAIM_STATEMENT_VERSION_V1 {
        return Err(VmError::InvalidConfig(format!(
            "unsupported aggregated chained folded intervalized decoding state relation statement version `{}`",
            manifest.statement_version
        )));
    }
    if manifest.recursion_posture.len() > MAX_PHASE28_RECURSION_POSTURE_BYTES {
        return Err(VmError::InvalidConfig(format!(
            "aggregated chained folded intervalized decoding state relation recursion_posture_len={} exceeds the supported maximum {}",
            manifest.recursion_posture.len(),
            MAX_PHASE28_RECURSION_POSTURE_BYTES
        )));
    }
    if manifest.recursion_posture != STWO_PHASE28_RECURSION_POSTURE_PRE_RECURSIVE {
        return Err(VmError::InvalidConfig(format!(
            "aggregated chained folded intervalized decoding state relation recursion_posture mismatch (provided_len={}, expected `{}`)",
            manifest.recursion_posture.len(),
            STWO_PHASE28_RECURSION_POSTURE_PRE_RECURSIVE
        )));
    }
    if manifest.recursive_verification_claimed {
        return Err(VmError::InvalidConfig(
            "aggregated chained folded intervalized decoding state relation must not claim recursive verification".to_string(),
        ));
    }
    if manifest.cryptographic_compression_claimed {
        return Err(VmError::InvalidConfig(
            "aggregated chained folded intervalized decoding state relation must not claim cryptographic compression".to_string(),
        ));
    }
    if manifest.members.len() < 2 {
        return Err(VmError::InvalidConfig(
            "aggregated chained folded intervalized decoding state relation must contain at least two members"
                .to_string(),
        ));
    }
    if manifest.members.len() > MAX_PHASE28_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_MEMBERS {
        return Err(VmError::InvalidConfig(format!(
            "aggregated chained folded intervalized decoding state relation members.len()={} exceeds the supported maximum {}",
            manifest.members.len(),
            MAX_PHASE28_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_MEMBERS
        )));
    }
    if manifest.member_count != manifest.members.len() {
        return Err(VmError::InvalidConfig(format!(
            "aggregated chained folded intervalized decoding state relation member_count={} does not match members.len()={}",
            manifest.member_count,
            manifest.members.len()
        )));
    }
    if manifest.member_summaries.len() != manifest.members.len() {
        return Err(VmError::InvalidConfig(format!(
            "aggregated chained folded intervalized decoding state relation member_summaries.len()={} does not match members.len()={}",
            manifest.member_summaries.len(),
            manifest.members.len()
        )));
    }
    if manifest.bounded_aggregation_arity < manifest.member_count
        || manifest.bounded_aggregation_arity
            > MAX_PHASE28_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_MEMBERS
    {
        return Err(VmError::InvalidConfig(format!(
            "aggregated chained folded intervalized decoding state relation bounded_aggregation_arity={} must be between member_count {} and supported maximum {}",
            manifest.bounded_aggregation_arity,
            manifest.member_count,
            MAX_PHASE28_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_MEMBERS
        )));
    }
    let min_total_phase26_members = manifest.member_count.checked_mul(2).ok_or_else(|| {
        VmError::InvalidConfig(
            "aggregated chained folded intervalized decoding state relation member_count overflowed while deriving the minimum nested Phase 26 member bound"
                .to_string(),
        )
    })?;
    if manifest.total_phase26_members < min_total_phase26_members
        || manifest.total_phase26_members > MAX_PHASE28_TOTAL_NESTED_PHASE26_MEMBERS
    {
        return Err(VmError::InvalidConfig(format!(
            "aggregated chained folded intervalized decoding state relation total_phase26_members={} must be between {} and supported maximum {}",
            manifest.total_phase26_members,
            min_total_phase26_members,
            MAX_PHASE28_TOTAL_NESTED_PHASE26_MEMBERS
        )));
    }
    let min_total_phase25_members = manifest.member_count.checked_mul(4).ok_or_else(|| {
        VmError::InvalidConfig(
            "aggregated chained folded intervalized decoding state relation member_count overflowed while deriving the minimum nested Phase 25 member bound"
                .to_string(),
        )
    })?;
    if manifest.total_phase25_members < min_total_phase25_members
        || manifest.total_phase25_members > MAX_PHASE28_TOTAL_NESTED_PHASE25_MEMBERS
    {
        return Err(VmError::InvalidConfig(format!(
            "aggregated chained folded intervalized decoding state relation total_phase25_members={} must be between {} and supported maximum {}",
            manifest.total_phase25_members,
            min_total_phase25_members,
            MAX_PHASE28_TOTAL_NESTED_PHASE25_MEMBERS
        )));
    }
    if manifest.max_nested_chain_arity < 2
        || manifest.max_nested_chain_arity > MAX_PHASE27_CHAINED_FOLDED_INTERVALIZED_MEMBERS
    {
        return Err(VmError::InvalidConfig(format!(
            "aggregated chained folded intervalized decoding state relation max_nested_chain_arity={} must be between 2 and {}",
            manifest.max_nested_chain_arity,
            MAX_PHASE27_CHAINED_FOLDED_INTERVALIZED_MEMBERS
        )));
    }
    if manifest.max_nested_fold_arity < 2
        || manifest.max_nested_fold_arity > MAX_PHASE26_FOLDED_INTERVALIZED_MEMBERS
    {
        return Err(VmError::InvalidConfig(format!(
            "aggregated chained folded intervalized decoding state relation max_nested_fold_arity={} must be between 2 and {}",
            manifest.max_nested_fold_arity,
            MAX_PHASE26_FOLDED_INTERVALIZED_MEMBERS
        )));
    }
    if manifest.total_rollups > MAX_PHASE28_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_ROLLUPS {
        return Err(VmError::InvalidConfig(format!(
            "aggregated chained folded intervalized decoding state relation total_rollups={} exceeds the supported maximum {}",
            manifest.total_rollups,
            MAX_PHASE28_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_ROLLUPS
        )));
    }
    if manifest.source_template_commitment.is_empty() {
        return Err(VmError::InvalidConfig(
            "aggregated chained folded intervalized decoding state relation source_template_commitment must not be empty".to_string(),
        ));
    }
    if manifest.global_start_state_commitment.is_empty() {
        return Err(VmError::InvalidConfig(
            "aggregated chained folded intervalized decoding state relation global_start_state_commitment must not be empty".to_string(),
        ));
    }
    if manifest.global_end_state_commitment.is_empty() {
        return Err(VmError::InvalidConfig(
            "aggregated chained folded intervalized decoding state relation global_end_state_commitment must not be empty".to_string(),
        ));
    }
    if manifest.aggregation_template_commitment.is_empty() {
        return Err(VmError::InvalidConfig(
            "aggregated chained folded intervalized decoding state relation aggregation_template_commitment must not be empty".to_string(),
        ));
    }
    if manifest
        .aggregated_chained_folded_interval_accumulator_commitment
        .is_empty()
    {
        return Err(VmError::InvalidConfig(
            "aggregated chained folded intervalized decoding state relation aggregated_chained_folded_interval_accumulator_commitment must not be empty".to_string(),
        ));
    }
    Ok(())
}

fn update_phase28_len_prefixed_commitment_bytes(hasher: &mut Blake2bVar, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn commit_phase28_aggregation_template(
    source_template_commitment: &str,
    bounded_aggregation_arity: usize,
    summaries: &[Phase28MemberSummary],
) -> Result<String> {
    verify_phase28_aggregation_sequence(summaries)?;
    if source_template_commitment.is_empty() {
        return Err(VmError::InvalidConfig(
            "Phase 28 aggregation template source_template_commitment must not be empty"
                .to_string(),
        ));
    }
    if bounded_aggregation_arity < summaries.len()
        || bounded_aggregation_arity > MAX_PHASE28_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_MEMBERS
    {
        return Err(VmError::InvalidConfig(format!(
            "Phase 28 bounded_aggregation_arity={} must be between member_count {} and supported maximum {}",
            bounded_aggregation_arity,
            summaries.len(),
            MAX_PHASE28_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_MEMBERS
        )));
    }

    let mut hasher = Blake2bVar::new(32).expect("blake2b-256");
    update_phase28_len_prefixed_commitment_bytes(
        &mut hasher,
        STWO_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE28
            .as_bytes(),
    );
    update_phase28_len_prefixed_commitment_bytes(&mut hasher, b"aggregation-template");
    hasher.update(&(bounded_aggregation_arity as u64).to_le_bytes());
    hasher.update(&(summaries.len() as u64).to_le_bytes());
    update_phase28_len_prefixed_commitment_bytes(
        &mut hasher,
        source_template_commitment.as_bytes(),
    );
    for (member_index, summary) in summaries.iter().enumerate() {
        hasher.update(&(member_index as u64).to_le_bytes());
        hasher.update(&(summary.bounded_chain_arity as u64).to_le_bytes());
        hasher.update(&(summary.total_phase26_members as u64).to_le_bytes());
        hasher.update(&(summary.total_phase25_members as u64).to_le_bytes());
        hasher.update(&(summary.max_nested_fold_arity as u64).to_le_bytes());
        update_phase28_len_prefixed_commitment_bytes(
            &mut hasher,
            summary.chain_template_commitment.as_bytes(),
        );
        hasher.update(&(summary.start_step as u64).to_le_bytes());
        hasher.update(&(summary.end_step as u64).to_le_bytes());
        hasher.update(&(summary.total_matrices as u64).to_le_bytes());
        hasher.update(&(summary.total_layouts as u64).to_le_bytes());
        hasher.update(&(summary.total_rollups as u64).to_le_bytes());
        hasher.update(&(summary.total_segments as u64).to_le_bytes());
        hasher.update(&(summary.total_steps as u64).to_le_bytes());
        hasher.update(&(summary.lookup_delta_entries as u64).to_le_bytes());
        hasher.update(&(summary.max_lookup_frontier_entries as u64).to_le_bytes());
    }

    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("blake2b finalize");
    Ok(lower_hex(&out))
}

fn commit_phase28_aggregated_chained_folded_intervalized_state_relation_with_summaries(
    manifest: &Phase28AggregatedChainedFoldedIntervalizedDecodingStateRelationManifest,
    summaries: &[Phase28MemberSummary],
) -> Result<String> {
    if summaries.len() != manifest.members.len() {
        return Err(VmError::InvalidConfig(format!(
            "aggregated chained folded intervalized decoding state relation summaries.len()={} does not match members.len()={}",
            summaries.len(),
            manifest.members.len()
        )));
    }
    verify_phase28_aggregation_sequence(summaries)?;

    let mut hasher = Blake2bVar::new(32).expect("blake2b-256");
    update_phase28_len_prefixed_commitment_bytes(
        &mut hasher,
        STWO_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE28
            .as_bytes(),
    );
    update_phase28_len_prefixed_commitment_bytes(
        &mut hasher,
        b"aggregated-chained-folded-intervalized-state-relation",
    );
    hasher.update(&(manifest.bounded_aggregation_arity as u64).to_le_bytes());
    hasher.update(&(manifest.total_phase26_members as u64).to_le_bytes());
    hasher.update(&(manifest.total_phase25_members as u64).to_le_bytes());
    hasher.update(&(manifest.max_nested_chain_arity as u64).to_le_bytes());
    hasher.update(&(manifest.max_nested_fold_arity as u64).to_le_bytes());
    update_phase28_len_prefixed_commitment_bytes(
        &mut hasher,
        manifest.source_template_commitment.as_bytes(),
    );
    update_phase28_len_prefixed_commitment_bytes(
        &mut hasher,
        manifest.global_start_state_commitment.as_bytes(),
    );
    update_phase28_len_prefixed_commitment_bytes(
        &mut hasher,
        manifest.global_end_state_commitment.as_bytes(),
    );
    update_phase28_len_prefixed_commitment_bytes(
        &mut hasher,
        manifest.aggregation_template_commitment.as_bytes(),
    );
    hasher.update(&(manifest.member_count as u64).to_le_bytes());
    hasher.update(&(manifest.total_matrices as u64).to_le_bytes());
    hasher.update(&(manifest.total_layouts as u64).to_le_bytes());
    hasher.update(&(manifest.total_rollups as u64).to_le_bytes());
    hasher.update(&(manifest.total_segments as u64).to_le_bytes());
    hasher.update(&(manifest.total_steps as u64).to_le_bytes());
    hasher.update(&(manifest.lookup_delta_entries as u64).to_le_bytes());
    hasher.update(&(manifest.max_lookup_frontier_entries as u64).to_le_bytes());
    for (member_index, summary) in summaries.iter().enumerate() {
        hasher.update(&(member_index as u64).to_le_bytes());
        hasher.update(&(summary.start_step as u64).to_le_bytes());
        hasher.update(&(summary.end_step as u64).to_le_bytes());
        hasher.update(&(summary.bounded_chain_arity as u64).to_le_bytes());
        hasher.update(&(summary.total_phase26_members as u64).to_le_bytes());
        hasher.update(&(summary.total_phase25_members as u64).to_le_bytes());
        hasher.update(&(summary.max_nested_fold_arity as u64).to_le_bytes());
        update_phase28_len_prefixed_commitment_bytes(
            &mut hasher,
            summary.chain_template_commitment.as_bytes(),
        );
        update_phase28_len_prefixed_commitment_bytes(
            &mut hasher,
            summary
                .chained_folded_interval_accumulator_commitment
                .as_bytes(),
        );
        update_phase28_len_prefixed_commitment_bytes(
            &mut hasher,
            summary.start_state_commitment.as_bytes(),
        );
        update_phase28_len_prefixed_commitment_bytes(
            &mut hasher,
            summary.end_state_commitment.as_bytes(),
        );
        hasher.update(&(summary.total_matrices as u64).to_le_bytes());
        hasher.update(&(summary.total_layouts as u64).to_le_bytes());
        hasher.update(&(summary.total_rollups as u64).to_le_bytes());
        hasher.update(&(summary.total_segments as u64).to_le_bytes());
        hasher.update(&(summary.total_steps as u64).to_le_bytes());
        hasher.update(&(summary.lookup_delta_entries as u64).to_le_bytes());
        hasher.update(&(summary.max_lookup_frontier_entries as u64).to_le_bytes());
    }

    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("blake2b finalize");
    Ok(lower_hex(&out))
}

pub fn phase28_prepare_aggregated_chained_folded_intervalized_decoding_state_relation(
    members: &[Phase27ChainedFoldedIntervalizedDecodingStateRelationManifest],
) -> Result<Phase28AggregatedChainedFoldedIntervalizedDecodingStateRelationManifest> {
    if members.len() < 2 {
        return Err(VmError::InvalidConfig(
            "Phase 28 aggregated chained folded intervalized decoding state relation requires at least two members"
                .to_string(),
        ));
    }
    if members.len() > MAX_PHASE28_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_MEMBERS {
        return Err(VmError::InvalidConfig(format!(
            "Phase 28 aggregated chained folded intervalized decoding state relation supports at most {MAX_PHASE28_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_MEMBERS} members (got {})",
            members.len()
        )));
    }

    let summaries = summarize_phase28_members(members)?;
    let totals = aggregate_phase28_summary_totals(&summaries)?;
    if totals.total_phase26_members > MAX_PHASE28_TOTAL_NESTED_PHASE26_MEMBERS {
        return Err(VmError::InvalidConfig(format!(
            "Phase 28 aggregated chained folded intervalized decoding state relation total_phase26_members={} exceeds the supported maximum {}",
            totals.total_phase26_members, MAX_PHASE28_TOTAL_NESTED_PHASE26_MEMBERS
        )));
    }
    if totals.total_phase25_members > MAX_PHASE28_TOTAL_NESTED_PHASE25_MEMBERS {
        return Err(VmError::InvalidConfig(format!(
            "Phase 28 aggregated chained folded intervalized decoding state relation total_phase25_members={} exceeds the supported maximum {}",
            totals.total_phase25_members, MAX_PHASE28_TOTAL_NESTED_PHASE25_MEMBERS
        )));
    }
    if totals.total_rollups > MAX_PHASE28_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_ROLLUPS {
        return Err(VmError::InvalidConfig(format!(
            "Phase 28 aggregated chained folded intervalized decoding state relation total_rollups={} exceeds the supported maximum {}",
            totals.total_rollups, MAX_PHASE28_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_ROLLUPS
        )));
    }

    let bounded_aggregation_arity = members.len();
    let aggregation_template_commitment = commit_phase28_aggregation_template(
        &summaries[0].source_template_commitment,
        bounded_aggregation_arity,
        &summaries,
    )?;
    let mut manifest = Phase28AggregatedChainedFoldedIntervalizedDecodingStateRelationManifest {
        proof_backend: StarkProofBackend::Stwo,
        artifact_version:
            STWO_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE28
                .to_string(),
        semantic_scope:
            STWO_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_SCOPE_PHASE28
                .to_string(),
        proof_backend_version: members[0].proof_backend_version.clone(),
        statement_version: members[0].statement_version.clone(),
        recursion_posture: STWO_PHASE28_RECURSION_POSTURE_PRE_RECURSIVE.to_string(),
        recursive_verification_claimed: false,
        cryptographic_compression_claimed: false,
        bounded_aggregation_arity,
        member_count: members.len(),
        total_phase26_members: totals.total_phase26_members,
        total_phase25_members: totals.total_phase25_members,
        max_nested_chain_arity: totals.max_nested_chain_arity,
        max_nested_fold_arity: totals.max_nested_fold_arity,
        total_matrices: totals.total_matrices,
        total_layouts: totals.total_layouts,
        total_rollups: totals.total_rollups,
        total_segments: totals.total_segments,
        total_steps: totals.total_steps,
        lookup_delta_entries: totals.lookup_delta_entries,
        max_lookup_frontier_entries: totals.max_lookup_frontier_entries,
        source_template_commitment: summaries[0].source_template_commitment.clone(),
        global_start_state_commitment: summaries[0].start_state_commitment.clone(),
        global_end_state_commitment: summaries
            .last()
            .expect("phase28 summaries are non-empty")
            .end_state_commitment
            .clone(),
        aggregation_template_commitment,
        aggregated_chained_folded_interval_accumulator_commitment: String::new(),
        member_summaries: phase28_public_member_summaries(&summaries),
        members: members.to_vec(),
    };
    manifest.aggregated_chained_folded_interval_accumulator_commitment =
        commit_phase28_aggregated_chained_folded_intervalized_state_relation_with_summaries(
            &manifest, &summaries,
        )?;
    verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_summaries(
        &manifest, &summaries,
    )?;
    Ok(manifest)
}

fn verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_summaries(
    manifest: &Phase28AggregatedChainedFoldedIntervalizedDecodingStateRelationManifest,
    summaries: &[Phase28MemberSummary],
) -> Result<()> {
    validate_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_shallow(
        manifest,
    )?;
    if summaries.len() != manifest.members.len() {
        return Err(VmError::InvalidConfig(format!(
            "aggregated chained folded intervalized decoding state relation summaries.len()={} does not match members.len()={}",
            summaries.len(),
            manifest.members.len()
        )));
    }
    verify_phase28_aggregation_sequence(summaries)?;
    let totals = aggregate_phase28_summary_totals(summaries)?;
    if manifest.total_phase26_members != totals.total_phase26_members {
        return Err(VmError::InvalidConfig(format!(
            "aggregated chained folded intervalized decoding state relation total_phase26_members={} does not match derived total_phase26_members {}",
            manifest.total_phase26_members, totals.total_phase26_members
        )));
    }
    if manifest.total_phase25_members != totals.total_phase25_members {
        return Err(VmError::InvalidConfig(format!(
            "aggregated chained folded intervalized decoding state relation total_phase25_members={} does not match derived total_phase25_members {}",
            manifest.total_phase25_members, totals.total_phase25_members
        )));
    }
    if manifest.max_nested_chain_arity != totals.max_nested_chain_arity {
        return Err(VmError::InvalidConfig(format!(
            "aggregated chained folded intervalized decoding state relation max_nested_chain_arity={} does not match derived max_nested_chain_arity {}",
            manifest.max_nested_chain_arity, totals.max_nested_chain_arity
        )));
    }
    if manifest.max_nested_fold_arity != totals.max_nested_fold_arity {
        return Err(VmError::InvalidConfig(format!(
            "aggregated chained folded intervalized decoding state relation max_nested_fold_arity={} does not match derived max_nested_fold_arity {}",
            manifest.max_nested_fold_arity, totals.max_nested_fold_arity
        )));
    }
    if manifest.total_matrices != totals.total_matrices {
        return Err(VmError::InvalidConfig(format!(
            "aggregated chained folded intervalized decoding state relation total_matrices={} does not match derived total_matrices {}",
            manifest.total_matrices, totals.total_matrices
        )));
    }
    if manifest.total_layouts != totals.total_layouts {
        return Err(VmError::InvalidConfig(format!(
            "aggregated chained folded intervalized decoding state relation total_layouts={} does not match derived total_layouts {}",
            manifest.total_layouts, totals.total_layouts
        )));
    }
    if manifest.total_rollups != totals.total_rollups {
        return Err(VmError::InvalidConfig(format!(
            "aggregated chained folded intervalized decoding state relation total_rollups={} does not match derived total_rollups {}",
            manifest.total_rollups, totals.total_rollups
        )));
    }
    if manifest.total_segments != totals.total_segments {
        return Err(VmError::InvalidConfig(format!(
            "aggregated chained folded intervalized decoding state relation total_segments={} does not match derived total_segments {}",
            manifest.total_segments, totals.total_segments
        )));
    }
    if manifest.total_steps != totals.total_steps {
        return Err(VmError::InvalidConfig(format!(
            "aggregated chained folded intervalized decoding state relation total_steps={} does not match derived total_steps {}",
            manifest.total_steps, totals.total_steps
        )));
    }
    if manifest.lookup_delta_entries != totals.lookup_delta_entries {
        return Err(VmError::InvalidConfig(format!(
            "aggregated chained folded intervalized decoding state relation lookup_delta_entries={} does not match derived lookup_delta_entries {}",
            manifest.lookup_delta_entries, totals.lookup_delta_entries
        )));
    }
    if manifest.max_lookup_frontier_entries != totals.max_lookup_frontier_entries {
        return Err(VmError::InvalidConfig(format!(
            "aggregated chained folded intervalized decoding state relation max_lookup_frontier_entries={} does not match derived max_lookup_frontier_entries {}",
            manifest.max_lookup_frontier_entries, totals.max_lookup_frontier_entries
        )));
    }
    let expected_member_summaries = phase28_public_member_summaries(summaries);
    if manifest.member_summaries != expected_member_summaries {
        return Err(VmError::InvalidConfig(
            "aggregated chained folded intervalized decoding state relation member_summaries do not match the derived aggregation summaries".to_string(),
        ));
    }
    let first = summaries.first().expect("phase28 summaries are non-empty");
    let last = summaries.last().expect("phase28 summaries are non-empty");
    if manifest.source_template_commitment != first.source_template_commitment {
        return Err(VmError::InvalidConfig(
            "aggregated chained folded intervalized decoding state relation source_template_commitment does not match the first member source template".to_string(),
        ));
    }
    if manifest.global_start_state_commitment != first.start_state_commitment {
        return Err(VmError::InvalidConfig(
            "aggregated chained folded intervalized decoding state relation global_start_state_commitment does not match the first member boundary".to_string(),
        ));
    }
    if manifest.global_end_state_commitment != last.end_state_commitment {
        return Err(VmError::InvalidConfig(
            "aggregated chained folded intervalized decoding state relation global_end_state_commitment does not match the last member boundary".to_string(),
        ));
    }
    let expected_aggregation_template_commitment = commit_phase28_aggregation_template(
        &manifest.source_template_commitment,
        manifest.bounded_aggregation_arity,
        summaries,
    )?;
    if manifest.aggregation_template_commitment != expected_aggregation_template_commitment {
        return Err(VmError::InvalidConfig(
            "aggregated chained folded intervalized decoding state relation aggregation_template_commitment does not match the computed aggregation template commitment".to_string(),
        ));
    }
    let expected_aggregated_chained_folded_interval_accumulator_commitment =
        commit_phase28_aggregated_chained_folded_intervalized_state_relation_with_summaries(
            manifest, summaries,
        )?;
    if manifest.aggregated_chained_folded_interval_accumulator_commitment
        != expected_aggregated_chained_folded_interval_accumulator_commitment
    {
        return Err(VmError::InvalidConfig(
            "aggregated chained folded intervalized decoding state relation aggregated_chained_folded_interval_accumulator_commitment does not match the computed aggregated accumulator commitment".to_string(),
        ));
    }
    Ok(())
}

pub fn verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation(
    manifest: &Phase28AggregatedChainedFoldedIntervalizedDecodingStateRelationManifest,
) -> Result<()> {
    validate_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_shallow(
        manifest,
    )?;
    let summaries = summarize_phase28_members(&manifest.members)?;
    verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_summaries(
        manifest, &summaries,
    )
}

fn verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_members_with_proof_checks(
    manifest: &Phase28AggregatedChainedFoldedIntervalizedDecodingStateRelationManifest,
) -> Result<()> {
    for (member_index, member) in manifest.members.iter().enumerate() {
        validate_phase27_chained_folded_intervalized_decoding_state_relation_shallow(member)
            .map_err(|error| {
                VmError::InvalidConfig(format!(
                    "Phase 28 member {member_index} failed Phase 27 proof-bearing shell validation: {error}"
                ))
            })?;
        verify_phase27_chained_folded_intervalized_decoding_state_relation_members_with_proof_checks(
            member,
        ).map_err(|error| {
            VmError::InvalidConfig(format!(
                "Phase 28 member {member_index} failed proof-bearing Phase 27 verification: {error}"
            ))
        })?;
    }
    Ok(())
}

pub fn verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_proof_checks(
    manifest: &Phase28AggregatedChainedFoldedIntervalizedDecodingStateRelationManifest,
) -> Result<()> {
    validate_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_shallow(
        manifest,
    )?;
    let summaries = summarize_phase28_members(&manifest.members)?;
    verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_summaries(
        manifest, &summaries,
    )?;
    verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_members_with_proof_checks(
        manifest,
    )
}

pub fn save_phase11_decoding_chain(
    manifest: &Phase11DecodingChainManifest,
    path: &Path,
) -> Result<()> {
    write_json_with_limit(
        manifest,
        path,
        MAX_PHASE11_DECODING_CHAIN_JSON_BYTES,
        "Phase 11 decoding chain manifest",
    )
}

pub fn save_phase12_decoding_chain(
    manifest: &Phase12DecodingChainManifest,
    path: &Path,
) -> Result<()> {
    write_json_with_limit(
        manifest,
        path,
        MAX_PHASE12_DECODING_CHAIN_JSON_BYTES,
        "Phase 12 decoding chain manifest",
    )
}

pub fn load_phase11_decoding_chain(path: &Path) -> Result<Phase11DecodingChainManifest> {
    let bytes = read_json_bytes_with_limit(
        path,
        MAX_PHASE11_DECODING_CHAIN_JSON_BYTES,
        "Phase 11 decoding chain manifest",
    )?;
    serde_json::from_slice(&bytes).map_err(|err| VmError::Serialization(err.to_string()))
}

fn backfill_state_public_commitment_if_missing(
    state: &mut serde_json::Value,
    phase14: bool,
) -> Result<()> {
    let obj = state.as_object_mut().ok_or_else(|| {
        VmError::Serialization("decoding state must deserialize from a JSON object".to_string())
    })?;
    match obj.get("public_state_commitment") {
        Some(serde_json::Value::String(value)) if value.is_empty() => {
            return Err(VmError::Serialization(
                "public_state_commitment must not be empty when present".to_string(),
            ));
        }
        Some(_) => return Ok(()),
        None => {}
    }

    let mut candidate = serde_json::Value::Object(obj.clone());
    candidate["public_state_commitment"] = serde_json::Value::String(String::new());
    let commitment = if phase14 {
        let state: Phase14DecodingState = serde_json::from_value(candidate)
            .map_err(|err| VmError::Serialization(err.to_string()))?;
        commit_phase14_public_state(&state)
    } else {
        let state: Phase12DecodingState = serde_json::from_value(candidate)
            .map_err(|err| VmError::Serialization(err.to_string()))?;
        commit_phase12_public_state(&state)
    };
    obj.insert(
        "public_state_commitment".to_string(),
        serde_json::Value::String(commitment),
    );
    Ok(())
}

fn backfill_phase15_segment_boundary_commitment_if_missing(
    segment: &mut serde_json::Value,
) -> Result<()> {
    let obj = segment.as_object_mut().ok_or_else(|| {
        VmError::Serialization("Phase 15 segment must deserialize from a JSON object".to_string())
    })?;
    match obj.get("public_state_boundary_commitment") {
        Some(serde_json::Value::String(value)) if value.is_empty() => {
            return Err(VmError::Serialization(
                "public_state_boundary_commitment must not be empty when present".to_string(),
            ));
        }
        Some(_) => return Ok(()),
        None => {}
    }

    let mut candidate = serde_json::Value::Object(obj.clone());
    candidate["public_state_boundary_commitment"] = serde_json::Value::String(String::new());
    let segment: Phase15DecodingHistorySegment =
        serde_json::from_value(candidate).map_err(|err| VmError::Serialization(err.to_string()))?;
    obj.insert(
        "public_state_boundary_commitment".to_string(),
        serde_json::Value::String(commit_phase15_segment_public_state_boundary(&segment)),
    );
    Ok(())
}

fn backfill_phase16_rollup_boundary_commitment_if_missing(
    rollup: &mut serde_json::Value,
) -> Result<()> {
    let obj = rollup.as_object_mut().ok_or_else(|| {
        VmError::Serialization("Phase 16 rollup must deserialize from a JSON object".to_string())
    })?;
    match obj.get("public_state_boundary_commitment") {
        Some(serde_json::Value::String(value)) if value.is_empty() => {
            return Err(VmError::Serialization(
                "public_state_boundary_commitment must not be empty when present".to_string(),
            ));
        }
        Some(_) => return Ok(()),
        None => {}
    }

    let mut candidate = serde_json::Value::Object(obj.clone());
    candidate["public_state_boundary_commitment"] = serde_json::Value::String(String::new());
    let rollup: Phase16DecodingHistoryRollup =
        serde_json::from_value(candidate).map_err(|err| VmError::Serialization(err.to_string()))?;
    obj.insert(
        "public_state_boundary_commitment".to_string(),
        serde_json::Value::String(commit_phase16_rollup_public_state_boundary(&rollup)),
    );
    Ok(())
}

fn backfill_phase12_chain_manifest_public_commitments(value: &mut serde_json::Value) -> Result<()> {
    let steps = value
        .get_mut("steps")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or_else(|| {
            VmError::Serialization(
                "Phase 12 decoding chain manifest steps must be a JSON array".to_string(),
            )
        })?;
    for step in steps {
        let step_obj = step.as_object_mut().ok_or_else(|| {
            VmError::Serialization(
                "Phase 12 decoding step must deserialize from a JSON object".to_string(),
            )
        })?;
        for key in ["from_state", "to_state"] {
            let state = step_obj.get_mut(key).ok_or_else(|| {
                VmError::Serialization(format!("Phase 12 decoding step missing {key}"))
            })?;
            backfill_state_public_commitment_if_missing(state, false)?;
        }
    }
    Ok(())
}

fn backfill_phase14_chain_manifest_public_commitments(value: &mut serde_json::Value) -> Result<()> {
    let steps = value
        .get_mut("steps")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or_else(|| {
            VmError::Serialization(
                "Phase 14 decoding chain manifest steps must be a JSON array".to_string(),
            )
        })?;
    for step in steps {
        let step_obj = step.as_object_mut().ok_or_else(|| {
            VmError::Serialization(
                "Phase 14 decoding step must deserialize from a JSON object".to_string(),
            )
        })?;
        for key in ["from_state", "to_state"] {
            let state = step_obj.get_mut(key).ok_or_else(|| {
                VmError::Serialization(format!("Phase 14 decoding step missing {key}"))
            })?;
            backfill_state_public_commitment_if_missing(state, true)?;
        }
    }
    Ok(())
}

fn backfill_phase13_layout_matrix_public_commitments(value: &mut serde_json::Value) -> Result<()> {
    let chains = value
        .get_mut("chains")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or_else(|| {
            VmError::Serialization("Phase 13 layout matrix chains must be a JSON array".to_string())
        })?;
    for chain in chains {
        backfill_phase12_chain_manifest_public_commitments(chain)?;
    }
    Ok(())
}

fn backfill_phase15_segment_bundle_public_commitments(value: &mut serde_json::Value) -> Result<()> {
    let segments = value
        .get_mut("segments")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or_else(|| {
            VmError::Serialization(
                "Phase 15 segment bundle segments must be a JSON array".to_string(),
            )
        })?;
    for segment in segments {
        let segment_obj = segment.as_object_mut().ok_or_else(|| {
            VmError::Serialization(
                "Phase 15 segment must deserialize from a JSON object".to_string(),
            )
        })?;
        for key in ["global_from_state", "global_to_state"] {
            let state = segment_obj
                .get_mut(key)
                .ok_or_else(|| VmError::Serialization(format!("Phase 15 segment missing {key}")))?;
            backfill_state_public_commitment_if_missing(state, true)?;
        }
        let chain = segment_obj
            .get_mut("chain")
            .ok_or_else(|| VmError::Serialization("Phase 15 segment missing chain".to_string()))?;
        backfill_phase14_chain_manifest_public_commitments(chain)?;
        backfill_phase15_segment_boundary_commitment_if_missing(segment)?;
    }
    Ok(())
}

fn backfill_phase16_segment_rollup_public_commitments(value: &mut serde_json::Value) -> Result<()> {
    let rollups = value
        .get_mut("rollups")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or_else(|| {
            VmError::Serialization("Phase 16 segment rollups must be a JSON array".to_string())
        })?;
    for rollup in rollups {
        let rollup_obj = rollup.as_object_mut().ok_or_else(|| {
            VmError::Serialization(
                "Phase 16 rollup must deserialize from a JSON object".to_string(),
            )
        })?;
        for key in ["global_from_state", "global_to_state"] {
            let state = rollup_obj
                .get_mut(key)
                .ok_or_else(|| VmError::Serialization(format!("Phase 16 rollup missing {key}")))?;
            backfill_state_public_commitment_if_missing(state, true)?;
        }
        let segments = rollup_obj
            .get_mut("segments")
            .and_then(serde_json::Value::as_array_mut)
            .ok_or_else(|| {
                VmError::Serialization("Phase 16 rollup segments must be a JSON array".to_string())
            })?;
        for segment in segments {
            let segment_obj = segment.as_object_mut().ok_or_else(|| {
                VmError::Serialization(
                    "Phase 16 nested segment must deserialize from a JSON object".to_string(),
                )
            })?;
            for key in ["global_from_state", "global_to_state"] {
                let state = segment_obj.get_mut(key).ok_or_else(|| {
                    VmError::Serialization(format!("Phase 16 nested segment missing {key}"))
                })?;
                backfill_state_public_commitment_if_missing(state, true)?;
            }
            let chain = segment_obj.get_mut("chain").ok_or_else(|| {
                VmError::Serialization("Phase 16 nested segment missing chain".to_string())
            })?;
            backfill_phase14_chain_manifest_public_commitments(chain)?;
            backfill_phase15_segment_boundary_commitment_if_missing(segment)?;
        }
        backfill_phase16_rollup_boundary_commitment_if_missing(rollup)?;
    }
    Ok(())
}

fn backfill_phase17_rollup_matrix_public_commitments(value: &mut serde_json::Value) -> Result<()> {
    let rollups = value
        .get_mut("rollups")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or_else(|| {
            VmError::Serialization(
                "Phase 17 rollup matrix rollups must be a JSON array".to_string(),
            )
        })?;
    for rollup in rollups {
        backfill_phase16_segment_rollup_public_commitments(rollup)?;
    }
    backfill_phase17_matrix_boundary_commitment_if_missing(value)?;
    Ok(())
}

fn backfill_phase17_matrix_boundary_commitment_if_missing(
    value: &mut serde_json::Value,
) -> Result<()> {
    let obj = value.as_object().ok_or_else(|| {
        VmError::Serialization("Phase 17 rollup matrix manifest must be a JSON object".to_string())
    })?;
    match obj.get("public_state_boundary_commitment") {
        Some(serde_json::Value::String(current)) if current.is_empty() => {
            return Err(VmError::Serialization(
                "public_state_boundary_commitment must not be empty when present".to_string(),
            ));
        }
        Some(serde_json::Value::String(_)) => return Ok(()),
        Some(_) => {
            return Err(VmError::Serialization(
                "public_state_boundary_commitment must be a string".to_string(),
            ));
        }
        None => {}
    }

    let boundary = commit_phase17_matrix_public_state_boundary_from_json(value)?;
    let obj = value.as_object_mut().ok_or_else(|| {
        VmError::Serialization("Phase 17 rollup matrix manifest must be a JSON object".to_string())
    })?;
    obj.insert(
        "public_state_boundary_commitment".to_string(),
        serde_json::Value::String(boundary),
    );
    Ok(())
}

fn commit_phase17_matrix_public_state_boundary_from_json(
    value: &serde_json::Value,
) -> Result<String> {
    let obj = value.as_object().ok_or_else(|| {
        VmError::Serialization("Phase 17 rollup matrix manifest must be a JSON object".to_string())
    })?;
    let parse_u64 =
        |map: &serde_json::Map<String, serde_json::Value>, field: &str| -> Result<u64> {
            map.get(field)
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| {
                    VmError::Serialization(format!(
                        "Phase 17 rollup matrix field `{field}` must be a non-negative integer"
                    ))
                })
        };

    let total_layouts = parse_u64(obj, "total_layouts")?;
    let total_rollups = parse_u64(obj, "total_rollups")?;
    let total_segments = parse_u64(obj, "total_segments")?;
    let total_steps = parse_u64(obj, "total_steps")?;
    let rollups = obj
        .get("rollups")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            VmError::Serialization(
                "Phase 17 rollup matrix rollups must be a JSON array".to_string(),
            )
        })?;
    if rollups.is_empty() {
        return Err(VmError::Serialization(
            "Phase 17 rollup matrix must contain at least one rollup manifest".to_string(),
        ));
    }

    let mut hasher = Blake2bVar::new(32).expect("blake2b-256");
    hasher.update(STWO_DECODING_ROLLUP_MATRIX_VERSION_PHASE17.as_bytes());
    hasher.update(b"public-state-boundary");
    hasher.update(&total_layouts.to_le_bytes());
    hasher.update(&total_rollups.to_le_bytes());
    hasher.update(&total_segments.to_le_bytes());
    hasher.update(&total_steps.to_le_bytes());

    for (layout_index, rollup_manifest_value) in rollups.iter().enumerate() {
        let rollup_manifest_obj = rollup_manifest_value.as_object().ok_or_else(|| {
            VmError::Serialization(format!(
                "Phase 17 rollup manifest {layout_index} must be a JSON object"
            ))
        })?;
        let layout_value = rollup_manifest_obj.get("layout").ok_or_else(|| {
            VmError::Serialization(format!(
                "Phase 17 rollup manifest {layout_index} is missing `layout`"
            ))
        })?;
        let layout: Phase12DecodingLayout = serde_json::from_value(layout_value.clone())
            .map_err(|err| VmError::Serialization(err.to_string()))?;
        let layout_commitment = commit_phase12_layout(&layout);

        hasher.update(&(layout_index as u64).to_le_bytes());
        hasher.update(&parse_u64(rollup_manifest_obj, "total_rollups")?.to_le_bytes());
        hasher.update(&parse_u64(rollup_manifest_obj, "total_segments")?.to_le_bytes());
        hasher.update(&parse_u64(rollup_manifest_obj, "total_steps")?.to_le_bytes());
        hasher.update(layout_commitment.as_bytes());

        let nested_rollups = rollup_manifest_obj
            .get("rollups")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| {
                VmError::Serialization(format!(
                    "Phase 17 rollup manifest {layout_index} rollups must be a JSON array"
                ))
            })?;
        if nested_rollups.is_empty() {
            return Err(VmError::Serialization(format!(
                "Phase 17 rollup manifest {layout_index} must contain at least one rollup"
            )));
        }
        for (rollup_index, nested_rollup_value) in nested_rollups.iter().enumerate() {
            let nested_rollup_obj = nested_rollup_value.as_object().ok_or_else(|| {
                VmError::Serialization(format!(
                    "Phase 17 rollup manifest {layout_index} nested rollup {rollup_index} must be a JSON object"
                ))
            })?;
            hasher.update(&parse_u64(nested_rollup_obj, "rollup_index")?.to_le_bytes());
            hasher.update(&parse_u64(nested_rollup_obj, "global_start_step_index")?.to_le_bytes());
            hasher.update(&parse_u64(nested_rollup_obj, "total_segments")?.to_le_bytes());
            hasher.update(&parse_u64(nested_rollup_obj, "total_steps")?.to_le_bytes());
            let boundary = nested_rollup_obj
                .get("public_state_boundary_commitment")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    VmError::Serialization(format!(
                        "Phase 17 rollup manifest {layout_index} nested rollup {rollup_index} is missing `public_state_boundary_commitment`"
                    ))
                })?;
            if boundary.is_empty() {
                return Err(VmError::Serialization(format!(
                    "Phase 17 rollup manifest {layout_index} nested rollup {rollup_index} has an empty `public_state_boundary_commitment`"
                )));
            }
            hasher.update(boundary.as_bytes());
        }
    }

    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("blake2b finalize");
    Ok(lower_hex(&out))
}

pub fn load_phase12_decoding_chain(path: &Path) -> Result<Phase12DecodingChainManifest> {
    let bytes = read_json_bytes_with_limit(
        path,
        MAX_PHASE12_DECODING_CHAIN_JSON_BYTES,
        "Phase 12 decoding chain manifest",
    )?;
    let mut value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|err| VmError::Serialization(err.to_string()))?;
    backfill_phase12_chain_manifest_public_commitments(&mut value)?;
    serde_json::from_value(value).map_err(|err| VmError::Serialization(err.to_string()))
}

pub fn save_phase30_decoding_step_proof_envelope_manifest(
    manifest: &Phase30DecodingStepProofEnvelopeManifest,
    path: &Path,
) -> Result<()> {
    write_json_with_limit(
        manifest,
        path,
        MAX_PHASE30_DECODING_STEP_ENVELOPE_MANIFEST_JSON_BYTES,
        "Phase 30 decoding step proof envelope manifest",
    )
}

pub fn parse_phase30_decoding_step_proof_envelope_manifest_json(
    json: &str,
) -> Result<Phase30DecodingStepProofEnvelopeManifest> {
    if json.len() > MAX_PHASE30_DECODING_STEP_ENVELOPE_MANIFEST_JSON_BYTES {
        return Err(VmError::InvalidConfig(format!(
            "Phase 30 decoding step proof envelope manifest JSON is {} bytes, exceeding the limit of {} bytes",
            json.len(),
            MAX_PHASE30_DECODING_STEP_ENVELOPE_MANIFEST_JSON_BYTES
        )));
    }
    serde_json::from_str(json).map_err(phase30_json_error)
}

pub fn load_phase30_decoding_step_proof_envelope_manifest(
    path: &Path,
) -> Result<Phase30DecodingStepProofEnvelopeManifest> {
    let bytes = read_json_bytes_with_limit(
        path,
        MAX_PHASE30_DECODING_STEP_ENVELOPE_MANIFEST_JSON_BYTES,
        "Phase 30 decoding step proof envelope manifest",
    )?;
    serde_json::from_slice(&bytes).map_err(phase30_json_error)
}

fn phase30_json_error(error: serde_json::Error) -> VmError {
    match error.classify() {
        serde_json::error::Category::Data
        | serde_json::error::Category::Syntax
        | serde_json::error::Category::Eof => VmError::InvalidConfig(error.to_string()),
        serde_json::error::Category::Io => VmError::Serialization(error.to_string()),
    }
}

pub fn save_phase14_decoding_chain(
    manifest: &Phase14DecodingChainManifest,
    path: &Path,
) -> Result<()> {
    write_json_with_limit(
        manifest,
        path,
        MAX_PHASE14_DECODING_CHAIN_JSON_BYTES,
        "Phase 14 decoding chain manifest",
    )
}

pub fn load_phase14_decoding_chain(path: &Path) -> Result<Phase14DecodingChainManifest> {
    let bytes = read_json_bytes_with_limit(
        path,
        MAX_PHASE14_DECODING_CHAIN_JSON_BYTES,
        "Phase 14 decoding chain manifest",
    )?;
    let mut value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|err| VmError::Serialization(err.to_string()))?;
    backfill_phase14_chain_manifest_public_commitments(&mut value)?;
    serde_json::from_value(value).map_err(|err| VmError::Serialization(err.to_string()))
}

pub fn save_phase15_decoding_segment_bundle(
    manifest: &Phase15DecodingHistorySegmentBundleManifest,
    path: &Path,
) -> Result<()> {
    write_json_with_limit(
        manifest,
        path,
        MAX_PHASE15_SEGMENT_BUNDLE_JSON_BYTES,
        "Phase 15 decoding history segment bundle",
    )
}

pub fn load_phase15_decoding_segment_bundle(
    path: &Path,
) -> Result<Phase15DecodingHistorySegmentBundleManifest> {
    let bytes = read_json_bytes_with_limit(
        path,
        MAX_PHASE15_SEGMENT_BUNDLE_JSON_BYTES,
        "Phase 15 decoding history segment bundle",
    )?;
    let mut value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|err| VmError::Serialization(err.to_string()))?;
    backfill_phase15_segment_bundle_public_commitments(&mut value)?;
    serde_json::from_value(value).map_err(|err| VmError::Serialization(err.to_string()))
}

pub fn save_phase16_decoding_segment_rollup(
    manifest: &Phase16DecodingHistoryRollupManifest,
    path: &Path,
) -> Result<()> {
    write_json_with_limit(
        manifest,
        path,
        MAX_PHASE16_SEGMENT_ROLLUP_JSON_BYTES,
        "Phase 16 decoding history segment rollup",
    )
}

pub fn load_phase16_decoding_segment_rollup(
    path: &Path,
) -> Result<Phase16DecodingHistoryRollupManifest> {
    let bytes = read_json_bytes_with_limit(
        path,
        MAX_PHASE16_SEGMENT_ROLLUP_JSON_BYTES,
        "Phase 16 decoding history segment rollup",
    )?;
    let mut value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|err| VmError::Serialization(err.to_string()))?;
    backfill_phase16_segment_rollup_public_commitments(&mut value)?;
    serde_json::from_value(value).map_err(|err| VmError::Serialization(err.to_string()))
}

pub fn save_phase17_decoding_rollup_matrix(
    manifest: &Phase17DecodingHistoryRollupMatrixManifest,
    path: &Path,
) -> Result<()> {
    write_json_with_limit(
        manifest,
        path,
        MAX_PHASE17_ROLLUP_MATRIX_JSON_BYTES,
        "Phase 17 decoding history rollup matrix",
    )
}

pub fn load_phase17_decoding_rollup_matrix(
    path: &Path,
) -> Result<Phase17DecodingHistoryRollupMatrixManifest> {
    let bytes = read_json_bytes_with_limit(
        path,
        MAX_PHASE17_ROLLUP_MATRIX_JSON_BYTES,
        "Phase 17 decoding history rollup matrix",
    )?;
    let mut value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|err| VmError::Serialization(err.to_string()))?;
    backfill_phase17_rollup_matrix_public_commitments(&mut value)?;
    serde_json::from_value(value).map_err(|err| VmError::Serialization(err.to_string()))
}

pub fn save_phase21_decoding_matrix_accumulator(
    manifest: &Phase21DecodingMatrixAccumulatorManifest,
    path: &Path,
) -> Result<()> {
    write_json_with_limit(
        manifest,
        path,
        MAX_PHASE21_MATRIX_ACCUMULATOR_JSON_BYTES,
        "Phase 21 decoding matrix accumulator",
    )
}

pub fn load_phase21_decoding_matrix_accumulator(
    path: &Path,
) -> Result<Phase21DecodingMatrixAccumulatorManifest> {
    let bytes = read_json_bytes_with_limit(
        path,
        MAX_PHASE21_MATRIX_ACCUMULATOR_JSON_BYTES,
        "Phase 21 decoding matrix accumulator",
    )?;
    serde_json::from_slice(&bytes).map_err(|err| VmError::Serialization(err.to_string()))
}

pub fn save_phase22_decoding_lookup_accumulator(
    manifest: &Phase22DecodingLookupAccumulatorManifest,
    path: &Path,
) -> Result<()> {
    write_json_with_limit(
        manifest,
        path,
        MAX_PHASE22_LOOKUP_ACCUMULATOR_JSON_BYTES,
        "Phase 22 decoding lookup accumulator",
    )
}

pub fn load_phase22_decoding_lookup_accumulator(
    path: &Path,
) -> Result<Phase22DecodingLookupAccumulatorManifest> {
    let bytes = read_json_bytes_with_limit(
        path,
        MAX_PHASE22_LOOKUP_ACCUMULATOR_JSON_BYTES,
        "Phase 22 decoding lookup accumulator",
    )?;
    let manifest: Phase22DecodingLookupAccumulatorManifest =
        serde_json::from_slice(&bytes).map_err(|err| VmError::Serialization(err.to_string()))?;
    verify_phase22_decoding_lookup_accumulator(&manifest)?;
    Ok(manifest)
}

pub fn save_phase23_decoding_cross_step_lookup_accumulator(
    manifest: &Phase23DecodingCrossStepLookupAccumulatorManifest,
    path: &Path,
) -> Result<()> {
    write_json_with_limit(
        manifest,
        path,
        MAX_PHASE23_CROSS_STEP_LOOKUP_ACCUMULATOR_JSON_BYTES,
        "Phase 23 decoding cross-step lookup accumulator",
    )
}

pub fn load_phase23_decoding_cross_step_lookup_accumulator(
    path: &Path,
) -> Result<Phase23DecodingCrossStepLookupAccumulatorManifest> {
    let bytes = read_json_bytes_with_limit(
        path,
        MAX_PHASE23_CROSS_STEP_LOOKUP_ACCUMULATOR_JSON_BYTES,
        "Phase 23 decoding cross-step lookup accumulator",
    )?;
    let manifest: Phase23DecodingCrossStepLookupAccumulatorManifest =
        serde_json::from_slice(&bytes).map_err(|err| VmError::Serialization(err.to_string()))?;
    verify_phase23_decoding_cross_step_lookup_accumulator(&manifest)?;
    Ok(manifest)
}

pub fn save_phase24_decoding_state_relation_accumulator(
    manifest: &Phase24DecodingStateRelationAccumulatorManifest,
    path: &Path,
) -> Result<()> {
    write_json_with_limit(
        manifest,
        path,
        MAX_PHASE24_STATE_RELATION_ACCUMULATOR_JSON_BYTES,
        "Phase 24 decoding state relation accumulator",
    )
}

pub fn load_phase24_decoding_state_relation_accumulator(
    path: &Path,
) -> Result<Phase24DecodingStateRelationAccumulatorManifest> {
    let bytes = read_json_bytes_with_limit(
        path,
        MAX_PHASE24_STATE_RELATION_ACCUMULATOR_JSON_BYTES,
        "Phase 24 decoding state relation accumulator",
    )?;
    let manifest: Phase24DecodingStateRelationAccumulatorManifest =
        serde_json::from_slice(&bytes).map_err(|err| VmError::Serialization(err.to_string()))?;
    verify_phase24_decoding_state_relation_accumulator(&manifest)?;
    Ok(manifest)
}

pub fn save_phase25_intervalized_decoding_state_relation(
    manifest: &Phase25IntervalizedDecodingStateRelationManifest,
    path: &Path,
) -> Result<()> {
    write_json_with_limit(
        manifest,
        path,
        MAX_PHASE25_INTERVALIZED_STATE_RELATION_JSON_BYTES,
        "Phase 25 intervalized decoding state relation",
    )
}

pub fn load_phase25_intervalized_decoding_state_relation(
    path: &Path,
) -> Result<Phase25IntervalizedDecodingStateRelationManifest> {
    let bytes = read_json_bytes_with_limit(
        path,
        MAX_PHASE25_INTERVALIZED_STATE_RELATION_JSON_BYTES,
        "Phase 25 intervalized decoding state relation",
    )?;
    let manifest: Phase25IntervalizedDecodingStateRelationManifest =
        serde_json::from_slice(&bytes).map_err(|err| VmError::Serialization(err.to_string()))?;
    verify_phase25_intervalized_decoding_state_relation(&manifest)?;
    Ok(manifest)
}

pub fn save_phase26_folded_intervalized_decoding_state_relation(
    manifest: &Phase26FoldedIntervalizedDecodingStateRelationManifest,
    path: &Path,
) -> Result<()> {
    write_json_with_limit(
        manifest,
        path,
        MAX_PHASE26_FOLDED_INTERVALIZED_STATE_RELATION_JSON_BYTES,
        "Phase 26 folded intervalized decoding state relation",
    )
}

pub fn load_phase26_folded_intervalized_decoding_state_relation(
    path: &Path,
) -> Result<Phase26FoldedIntervalizedDecodingStateRelationManifest> {
    let bytes = read_json_bytes_with_limit(
        path,
        MAX_PHASE26_FOLDED_INTERVALIZED_STATE_RELATION_JSON_BYTES,
        "Phase 26 folded intervalized decoding state relation",
    )?;
    let manifest: Phase26FoldedIntervalizedDecodingStateRelationManifest =
        serde_json::from_slice(&bytes).map_err(|err| VmError::Serialization(err.to_string()))?;
    verify_phase26_folded_intervalized_decoding_state_relation(&manifest)?;
    Ok(manifest)
}

pub fn save_phase27_chained_folded_intervalized_decoding_state_relation(
    manifest: &Phase27ChainedFoldedIntervalizedDecodingStateRelationManifest,
    path: &Path,
) -> Result<()> {
    write_json_compact_with_limit(
        manifest,
        path,
        MAX_PHASE27_CHAINED_FOLDED_INTERVALIZED_STATE_RELATION_JSON_BYTES,
        "Phase 27 chained folded intervalized decoding state relation",
    )
}

fn load_phase27_chained_folded_intervalized_decoding_state_relation_unchecked(
    path: &Path,
) -> Result<Phase27ChainedFoldedIntervalizedDecodingStateRelationManifest> {
    let bytes = read_json_bytes_with_limit(
        path,
        MAX_PHASE27_CHAINED_FOLDED_INTERVALIZED_STATE_RELATION_JSON_BYTES,
        "Phase 27 chained folded intervalized decoding state relation",
    )?;
    serde_json::from_slice(&bytes).map_err(|err| VmError::Serialization(err.to_string()))
}

pub fn load_phase27_chained_folded_intervalized_decoding_state_relation(
    path: &Path,
) -> Result<Phase27ChainedFoldedIntervalizedDecodingStateRelationManifest> {
    let manifest =
        load_phase27_chained_folded_intervalized_decoding_state_relation_unchecked(path)?;
    verify_phase27_chained_folded_intervalized_decoding_state_relation(&manifest)?;
    Ok(manifest)
}

pub fn load_phase27_chained_folded_intervalized_decoding_state_relation_with_proof_checks(
    path: &Path,
) -> Result<Phase27ChainedFoldedIntervalizedDecodingStateRelationManifest> {
    let manifest =
        load_phase27_chained_folded_intervalized_decoding_state_relation_unchecked(path)?;
    verify_phase27_chained_folded_intervalized_decoding_state_relation_with_proof_checks(
        &manifest,
    )?;
    Ok(manifest)
}

pub fn save_phase28_aggregated_chained_folded_intervalized_decoding_state_relation(
    manifest: &Phase28AggregatedChainedFoldedIntervalizedDecodingStateRelationManifest,
    path: &Path,
) -> Result<()> {
    save_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_json_limit(
        manifest,
        path,
        MAX_PHASE28_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_STATE_RELATION_JSON_BYTES,
    )
}

fn save_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_json_limit(
    manifest: &Phase28AggregatedChainedFoldedIntervalizedDecodingStateRelationManifest,
    path: &Path,
    json_limit: usize,
) -> Result<()> {
    write_json_compact_with_limit(
        manifest,
        path,
        json_limit,
        "Phase 28 aggregated chained folded intervalized decoding state relation",
    )
}

fn load_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_unchecked(
    path: &Path,
) -> Result<Phase28AggregatedChainedFoldedIntervalizedDecodingStateRelationManifest> {
    let bytes = read_json_bytes_with_limit(
        path,
        MAX_PHASE28_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_STATE_RELATION_JSON_BYTES,
        "Phase 28 aggregated chained folded intervalized decoding state relation",
    )?;
    serde_json::from_slice(&bytes).map_err(|err| VmError::Serialization(err.to_string()))
}

pub fn load_phase28_aggregated_chained_folded_intervalized_decoding_state_relation(
    path: &Path,
) -> Result<Phase28AggregatedChainedFoldedIntervalizedDecodingStateRelationManifest> {
    let manifest =
        load_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_unchecked(
            path,
        )?;
    verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation(&manifest)?;
    Ok(manifest)
}

pub fn load_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_proof_checks(
    path: &Path,
) -> Result<Phase28AggregatedChainedFoldedIntervalizedDecodingStateRelationManifest> {
    let manifest =
        load_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_unchecked(
            path,
        )?;
    verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_proof_checks(
        &manifest,
    )?;
    Ok(manifest)
}

pub fn save_phase13_decoding_layout_matrix(
    manifest: &Phase13DecodingLayoutMatrixManifest,
    path: &Path,
) -> Result<()> {
    write_json_with_limit(
        manifest,
        path,
        MAX_PHASE13_LAYOUT_MATRIX_JSON_BYTES,
        "Phase 13 decoding layout matrix",
    )
}

pub fn load_phase13_decoding_layout_matrix(
    path: &Path,
) -> Result<Phase13DecodingLayoutMatrixManifest> {
    let bytes = read_json_bytes_with_limit(
        path,
        MAX_PHASE13_LAYOUT_MATRIX_JSON_BYTES,
        "Phase 13 decoding layout matrix",
    )?;
    let mut value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|err| VmError::Serialization(err.to_string()))?;
    backfill_phase13_layout_matrix_public_commitments(&mut value)?;
    serde_json::from_value(value).map_err(|err| VmError::Serialization(err.to_string()))
}

pub fn prove_phase11_decoding_demo() -> Result<Phase11DecodingChainManifest> {
    let config = TransformerVmConfig {
        num_layers: 1,
        attention_mode: Attention2DMode::AverageHard,
        ..TransformerVmConfig::default()
    };
    let mut proofs = Vec::new();
    for initial_memory in phase11_demo_initial_memories() {
        let program = decoding_step_v1_program_with_initial_memory(initial_memory)?;
        let model = ProgramCompiler.compile_program(program, config.clone())?;
        let proof = prove_execution_stark_with_backend_and_options(
            &model,
            128,
            StarkProofBackend::Stwo,
            production_v1_stark_options(),
        )?;
        proofs.push(proof);
    }
    let manifest = phase11_prepare_decoding_chain(&proofs)?;
    verify_phase11_decoding_chain_with_proof_checks(&manifest)?;
    Ok(manifest)
}

pub fn phase13_default_decoding_layout_matrix() -> Result<Vec<Phase12DecodingLayout>> {
    Ok(vec![
        Phase12DecodingLayout::new(2, 2)?,
        Phase12DecodingLayout::new(3, 3)?,
        phase12_default_decoding_layout(),
    ])
}

pub fn prove_phase12_decoding_demo_for_layout(
    layout: &Phase12DecodingLayout,
) -> Result<Phase12DecodingChainManifest> {
    let config = TransformerVmConfig {
        num_layers: 1,
        attention_mode: Attention2DMode::AverageHard,
        ..TransformerVmConfig::default()
    };
    let mut proofs = Vec::new();
    for initial_memory in phase12_demo_initial_memories(layout)? {
        let program = decoding_step_v2_program_with_initial_memory(layout, initial_memory)?;
        let model = ProgramCompiler.compile_program(program, config.clone())?;
        let proof = prove_execution_stark_with_backend_and_options(
            &model,
            128,
            StarkProofBackend::Stwo,
            production_v1_stark_options(),
        )?;
        proofs.push(proof);
    }
    let manifest = phase12_prepare_decoding_chain(layout, &proofs)?;
    verify_phase12_decoding_chain_with_proof_checks(&manifest)?;
    Ok(manifest)
}

pub fn prove_phase12_decoding_demo() -> Result<Phase12DecodingChainManifest> {
    let layout = phase12_default_decoding_layout();
    prove_phase12_decoding_demo_for_layout(&layout)
}

pub fn prove_phase13_decoding_layout_matrix_demo() -> Result<Phase13DecodingLayoutMatrixManifest> {
    let layouts = phase13_default_decoding_layout_matrix()?;
    let mut chains = Vec::with_capacity(layouts.len());
    for layout in &layouts {
        chains.push(prove_phase12_decoding_demo_for_layout(layout)?);
    }
    let manifest = Phase13DecodingLayoutMatrixManifest {
        proof_backend: StarkProofBackend::Stwo,
        matrix_version: STWO_DECODING_LAYOUT_MATRIX_VERSION_PHASE13.to_string(),
        semantic_scope: STWO_DECODING_LAYOUT_MATRIX_SCOPE_PHASE13.to_string(),
        proof_backend_version: crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12.to_string(),
        statement_version: crate::proof::CLAIM_STATEMENT_VERSION_V1.to_string(),
        total_layouts: chains.len(),
        total_steps: chains.iter().map(|chain| chain.total_steps).sum(),
        chains,
    };
    verify_phase13_decoding_layout_matrix_with_proof_checks(&manifest)?;
    Ok(manifest)
}

pub fn prove_phase14_decoding_demo_for_layout(
    layout: &Phase12DecodingLayout,
) -> Result<Phase14DecodingChainManifest> {
    let phase12_manifest = prove_phase12_decoding_demo_for_layout(layout)?;
    let manifest = phase14_prepare_decoding_chain(&phase12_manifest)?;
    verify_phase14_decoding_chain_with_proof_checks(&manifest)?;
    Ok(manifest)
}

pub fn prove_phase14_decoding_demo() -> Result<Phase14DecodingChainManifest> {
    let layout = phase12_default_decoding_layout();
    prove_phase14_decoding_demo_for_layout(&layout)
}

pub fn prove_phase15_decoding_demo_for_layout(
    layout: &Phase12DecodingLayout,
) -> Result<Phase15DecodingHistorySegmentBundleManifest> {
    let phase14_manifest = prove_phase14_decoding_demo_for_layout(layout)?;
    let manifest =
        phase15_prepare_segment_bundle(&phase14_manifest, phase15_default_segment_step_limit())?;
    verify_phase15_decoding_segment_bundle_with_proof_checks(&manifest)?;
    Ok(manifest)
}

pub fn prove_phase15_decoding_demo() -> Result<Phase15DecodingHistorySegmentBundleManifest> {
    let layout = phase12_default_decoding_layout();
    prove_phase15_decoding_demo_for_layout(&layout)
}

pub fn prove_phase16_decoding_demo_for_layout(
    layout: &Phase12DecodingLayout,
) -> Result<Phase16DecodingHistoryRollupManifest> {
    let phase14_manifest = prove_phase14_decoding_demo_for_layout(layout)?;
    let phase15_manifest = phase15_prepare_segment_bundle(&phase14_manifest, 1)?;
    let manifest =
        phase16_prepare_segment_rollup(&phase15_manifest, phase16_default_rollup_segment_limit())?;
    verify_phase16_decoding_segment_rollup_with_proof_checks(&manifest)?;
    Ok(manifest)
}

pub fn prove_phase16_decoding_demo() -> Result<Phase16DecodingHistoryRollupManifest> {
    let layout = phase12_default_decoding_layout();
    prove_phase16_decoding_demo_for_layout(&layout)
}

fn prepare_phase17_decoding_rollup_matrix(
    rollups: Vec<Phase16DecodingHistoryRollupManifest>,
) -> Result<Phase17DecodingHistoryRollupMatrixManifest> {
    if rollups.is_empty() {
        return Err(VmError::InvalidConfig(
            "Phase 17 decoding rollup matrix requires at least one rollup manifest".to_string(),
        ));
    }

    let mut manifest = Phase17DecodingHistoryRollupMatrixManifest {
        proof_backend: StarkProofBackend::Stwo,
        matrix_version: STWO_DECODING_ROLLUP_MATRIX_VERSION_PHASE17.to_string(),
        semantic_scope: STWO_DECODING_ROLLUP_MATRIX_SCOPE_PHASE17.to_string(),
        proof_backend_version: crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12.to_string(),
        statement_version: crate::proof::CLAIM_STATEMENT_VERSION_V1.to_string(),
        total_layouts: rollups.len(),
        total_rollups: rollups.iter().map(|rollup| rollup.total_rollups).sum(),
        total_segments: rollups.iter().map(|rollup| rollup.total_segments).sum(),
        total_steps: rollups.iter().map(|rollup| rollup.total_steps).sum(),
        public_state_boundary_commitment: String::new(),
        rollups,
    };
    manifest.public_state_boundary_commitment =
        commit_phase17_matrix_public_state_boundary(&manifest)?;
    verify_phase17_decoding_rollup_matrix_with_proof_checks(&manifest)?;
    Ok(manifest)
}

pub fn prove_phase17_decoding_rollup_matrix_demo(
) -> Result<Phase17DecodingHistoryRollupMatrixManifest> {
    let layouts = phase13_default_decoding_layout_matrix()?;
    let mut rollups = Vec::with_capacity(layouts.len());
    for layout in &layouts {
        rollups.push(prove_phase16_decoding_demo_for_layout(layout)?);
    }
    prepare_phase17_decoding_rollup_matrix(rollups)
}

pub fn prove_phase21_decoding_matrix_accumulator_demo(
) -> Result<Phase21DecodingMatrixAccumulatorManifest> {
    let first = prove_phase17_decoding_rollup_matrix_demo()?;
    let second = prove_phase17_decoding_rollup_matrix_demo()?;
    let manifest = phase21_prepare_decoding_matrix_accumulator(&[first, second])?;
    verify_phase21_decoding_matrix_accumulator_with_proof_checks(&manifest)?;
    Ok(manifest)
}

pub fn prove_phase22_decoding_lookup_accumulator_demo(
) -> Result<Phase22DecodingLookupAccumulatorManifest> {
    let phase21 = prove_phase21_decoding_matrix_accumulator_demo()?;
    let manifest = phase22_prepare_decoding_lookup_accumulator(&phase21)?;
    verify_phase22_decoding_lookup_accumulator_with_proof_checks(&manifest)?;
    Ok(manifest)
}

fn phase23_prepare_member_from_proof_window(
    layout: &Phase12DecodingLayout,
    proofs: &[VanillaStarkExecutionProof],
) -> Result<Phase22DecodingLookupAccumulatorManifest> {
    phase23_prepare_member_from_proof_window_with_segment_limit(layout, proofs, 1)
}

fn phase23_prepare_member_from_proof_window_with_segment_limit(
    layout: &Phase12DecodingLayout,
    proofs: &[VanillaStarkExecutionProof],
    max_segment_steps: usize,
) -> Result<Phase22DecodingLookupAccumulatorManifest> {
    let phase12 = phase12_prepare_decoding_chain(layout, proofs)?;
    let phase14 = phase14_prepare_decoding_chain(&phase12)?;
    let bundle = phase15_prepare_segment_bundle(&phase14, max_segment_steps)?;
    let rollup = phase16_prepare_segment_rollup(&bundle, phase16_default_rollup_segment_limit())?;
    let matrix = prepare_phase17_decoding_rollup_matrix(vec![rollup])?;
    let phase21 = phase21_prepare_decoding_matrix_accumulator(&[matrix])?;
    phase22_prepare_decoding_lookup_accumulator(&phase21)
}

pub fn prove_phase23_decoding_cross_step_lookup_accumulator_demo(
) -> Result<Phase23DecodingCrossStepLookupAccumulatorManifest> {
    let layout = phase12_default_decoding_layout();
    let phase12 = prove_phase12_decoding_demo_for_layout(&layout)?;
    let proofs = phase12
        .steps
        .iter()
        .map(|step| step.proof.clone())
        .collect::<Vec<_>>();
    if proofs.len() < 2 {
        return Err(VmError::InvalidConfig(format!(
            "Phase 23 demo requires at least two proof windows, got {}",
            proofs.len()
        )));
    }

    let split_index = proofs.len() - 1;
    let first_member = phase23_prepare_member_from_proof_window(&layout, &proofs[..split_index])?;
    let second_member = phase23_prepare_member_from_proof_window(&layout, &proofs)?;
    let manifest =
        phase23_prepare_decoding_cross_step_lookup_accumulator(&[first_member, second_member])?;
    verify_phase23_decoding_cross_step_lookup_accumulator_with_proof_checks(&manifest)?;
    Ok(manifest)
}

fn phase24_prepare_member_from_proof_window(
    layout: &Phase12DecodingLayout,
    proofs: &[VanillaStarkExecutionProof],
) -> Result<Phase24DecodingStateRelationAccumulatorManifest> {
    if proofs.len() < 2 {
        return Err(VmError::InvalidConfig(format!(
            "Phase 24 member window requires at least two proofs, got {}",
            proofs.len()
        )));
    }

    let first_phase22 = phase23_prepare_member_from_proof_window(layout, &proofs[..1])?;
    let second_phase22 = phase23_prepare_member_from_proof_window(layout, proofs)?;
    let first_member =
        phase23_prepare_decoding_cross_step_lookup_accumulator(&[first_phase22.clone()])?;
    let second_member =
        phase23_prepare_decoding_cross_step_lookup_accumulator(&[first_phase22, second_phase22])?;
    phase24_prepare_decoding_state_relation_accumulator(&[first_member, second_member])
}

fn phase25_demo_memory_from_seed(
    layout: &Phase12DecodingLayout,
    kv_cache: &[i16],
    position: usize,
    incoming_values: &[i16],
    query_values: &[i16],
) -> Result<Vec<i16>> {
    layout.validate()?;
    let kv_cache_range = layout.kv_cache_range()?;
    let incoming_token_range = layout.incoming_token_range()?;
    let query_range = layout.query_range()?;
    let lookup_range = layout.lookup_range()?;
    let position_index = layout.position_index()?;
    let position_increment_index = layout.position_increment_index()?;
    if kv_cache.len() != kv_cache_range.len() {
        return Err(VmError::InvalidConfig(format!(
            "Phase 25 demo expected {} KV-cache values, got {}",
            kv_cache_range.len(),
            kv_cache.len()
        )));
    }
    if incoming_values.len() != incoming_token_range.len() {
        return Err(VmError::InvalidConfig(format!(
            "Phase 25 demo expected {} incoming-token values, got {}",
            incoming_token_range.len(),
            incoming_values.len()
        )));
    }
    if query_values.len() != query_range.len() {
        return Err(VmError::InvalidConfig(format!(
            "Phase 25 demo expected {} query values, got {}",
            query_range.len(),
            query_values.len()
        )));
    }

    let mut memory = vec![0; layout.memory_size()?];
    memory[kv_cache_range].copy_from_slice(kv_cache);
    memory[incoming_token_range].copy_from_slice(incoming_values);
    memory[query_range].copy_from_slice(query_values);
    write_phase12_noncanonical_lookup_seed(&mut memory, lookup_range);
    memory[position_index] = position as i16;
    memory[position_increment_index] = 1;
    Ok(memory)
}

fn phase25_demo_seed_palette(pair_width: usize, position: usize) -> Vec<(Vec<i16>, Vec<i16>)> {
    let base_indices = [position % 3, 0, 1, 2];
    let mut unique_indices = Vec::with_capacity(base_indices.len());
    for index in base_indices {
        if !unique_indices.contains(&index) {
            unique_indices.push(index);
        }
    }

    let mut seeds = Vec::with_capacity(unique_indices.len() * unique_indices.len());
    for &incoming_index in &unique_indices {
        for &query_index in &unique_indices {
            seeds.push((
                phase12_demo_incoming_values(pair_width, incoming_index),
                phase12_demo_query_values(pair_width, query_index),
            ));
        }
    }
    seeds
}

fn phase25_demo_proofs_for_layout(
    layout: &Phase12DecodingLayout,
    positions: usize,
) -> Result<Vec<VanillaStarkExecutionProof>> {
    let config = TransformerVmConfig {
        num_layers: 1,
        attention_mode: Attention2DMode::AverageHard,
        ..TransformerVmConfig::default()
    };
    let kv_cache_range = layout.kv_cache_range()?;
    let mut kv_cache = vec![0; kv_cache_range.len()];
    let mut proofs = Vec::with_capacity(positions);
    for position in 0..positions {
        let mut accepted_proof = None;
        let mut last_overflow = None;
        for (incoming_values, query_values) in
            phase25_demo_seed_palette(layout.pair_width, position)
        {
            let initial_memory = phase25_demo_memory_from_seed(
                layout,
                &kv_cache,
                position,
                &incoming_values,
                &query_values,
            )?;
            let program = decoding_step_v2_program_with_initial_memory(layout, initial_memory)?;
            let model = ProgramCompiler.compile_program(program, config.clone())?;
            match prove_execution_stark_with_backend_and_options(
                &model,
                128,
                StarkProofBackend::Stwo,
                production_v1_stark_options(),
            ) {
                Ok(proof) => {
                    kv_cache
                        .copy_from_slice(&proof.claim.final_state.memory[kv_cache_range.clone()]);
                    accepted_proof = Some(proof);
                    break;
                }
                Err(VmError::UnsupportedProof(message))
                    if message.contains("overflowing arithmetic is not supported") =>
                {
                    last_overflow = Some(message);
                }
                Err(err) => return Err(err),
            }
        }
        let proof = accepted_proof.ok_or_else(|| {
            let overflow_suffix = last_overflow
                .as_deref()
                .map(|message| format!(" last rejection: {message}"))
                .unwrap_or_default();
            VmError::InvalidConfig(format!(
                "Phase 25 demo could not find a bounded proving-safe seed for position {position} after {} deterministic candidates.{overflow_suffix}",
                phase25_demo_seed_palette(layout.pair_width, position).len(),
            ))
        })?;
        proofs.push(proof);
    }
    Ok(proofs)
}

fn phase25_default_decoding_layouts() -> Result<Vec<Phase12DecodingLayout>> {
    Ok(vec![
        Phase12DecodingLayout::new(2, 2)?,
        Phase12DecodingLayout::new(3, 3)?,
        phase12_default_decoding_layout(),
    ])
}

fn phase25_prepare_cumulative_members_from_proof_prefixes(
    layout: &Phase12DecodingLayout,
    proofs: &[VanillaStarkExecutionProof],
) -> Result<Vec<Phase23DecodingCrossStepLookupAccumulatorManifest>> {
    if proofs.len() < 2 {
        return Err(VmError::InvalidConfig(format!(
            "Phase 25 interval extraction requires at least two proofs, got {}",
            proofs.len()
        )));
    }
    let mut phase22_prefixes = Vec::with_capacity(proofs.len());
    let mut members = Vec::with_capacity(proofs.len());
    for prefix_len in 1..=proofs.len() {
        phase22_prefixes.push(phase23_prepare_member_from_proof_window(
            layout,
            &proofs[..prefix_len],
        )?);
        members.push(phase23_prepare_decoding_cross_step_lookup_accumulator(
            &phase22_prefixes,
        )?);
    }
    Ok(members)
}

fn phase25_prepare_intervalized_member_from_cumulative_members(
    members: &[Phase23DecodingCrossStepLookupAccumulatorManifest],
    baseline_member: Option<&Phase23DecodingCrossStepLookupAccumulatorManifest>,
) -> Result<Phase25IntervalizedDecodingStateRelationManifest> {
    if members.len() < 2 {
        return Err(VmError::InvalidConfig(format!(
            "Phase 25 interval extraction requires at least two cumulative members, got {}",
            members.len()
        )));
    }
    let first_member = members.first().expect("phase25 members are non-empty");
    let baseline = baseline_member
        .map(phase24_rebase_baseline_from_cumulative_member)
        .unwrap_or_else(phase24_zero_rebase_baseline);
    phase25_prepare_intervalized_decoding_state_relation_from_phase23_members(
        members,
        baseline,
        &first_member.proof_backend_version,
        &first_member.statement_version,
    )
}

fn phase25_prepare_intervalized_members_from_cumulative_members(
    cumulative_members: &[Phase23DecodingCrossStepLookupAccumulatorManifest],
    cumulative_chunk_len: usize,
) -> Result<Vec<Phase25IntervalizedDecodingStateRelationManifest>> {
    if cumulative_chunk_len < 2 {
        return Err(VmError::InvalidConfig(format!(
            "Phase 25 interval chunk length must be at least 2 cumulative members (got {cumulative_chunk_len})"
        )));
    }
    if cumulative_members.len() < cumulative_chunk_len {
        return Err(VmError::InvalidConfig(format!(
            "Phase 25 interval chunking requires at least {cumulative_chunk_len} cumulative members, got {}",
            cumulative_members.len()
        )));
    }
    if cumulative_members.len() % cumulative_chunk_len != 0 {
        return Err(VmError::InvalidConfig(format!(
            "Phase 25 interval chunking requires cumulative_members.len()={} to be divisible by chunk length {}",
            cumulative_members.len(),
            cumulative_chunk_len
        )));
    }

    let mut interval_members = Vec::with_capacity(cumulative_members.len() / cumulative_chunk_len);
    for (chunk_index, chunk) in cumulative_members.chunks(cumulative_chunk_len).enumerate() {
        let start_index = chunk_index * cumulative_chunk_len;
        let baseline = if start_index == 0 {
            None
        } else {
            cumulative_members.get(start_index - 1)
        };
        interval_members.push(phase25_prepare_intervalized_member_from_cumulative_members(
            chunk, baseline,
        )?);
    }
    Ok(interval_members)
}

fn phase26_prepare_folded_members_from_interval_members(
    members: &[Phase25IntervalizedDecodingStateRelationManifest],
    fold_chunk_len: usize,
) -> Result<Vec<Phase26FoldedIntervalizedDecodingStateRelationManifest>> {
    if fold_chunk_len < 2 {
        return Err(VmError::InvalidConfig(format!(
            "Phase 26 fold chunk length must be at least 2 interval members (got {fold_chunk_len})"
        )));
    }
    if members.len() < fold_chunk_len {
        return Err(VmError::InvalidConfig(format!(
            "Phase 26 fold chunking requires at least {fold_chunk_len} interval members, got {}",
            members.len()
        )));
    }
    if members.len() % fold_chunk_len != 0 {
        return Err(VmError::InvalidConfig(format!(
            "Phase 26 fold chunking requires interval_members.len()={} to be divisible by chunk length {}",
            members.len(),
            fold_chunk_len
        )));
    }

    members
        .chunks(fold_chunk_len)
        .map(phase26_prepare_folded_intervalized_decoding_state_relation)
        .collect()
}

fn phase27_prepare_chained_members_from_folded_members(
    members: &[Phase26FoldedIntervalizedDecodingStateRelationManifest],
    chain_chunk_len: usize,
) -> Result<Vec<Phase27ChainedFoldedIntervalizedDecodingStateRelationManifest>> {
    if chain_chunk_len < 2 {
        return Err(VmError::InvalidConfig(format!(
            "Phase 27 chain chunk length must be at least 2 folded members (got {chain_chunk_len})"
        )));
    }
    if members.len() < chain_chunk_len {
        return Err(VmError::InvalidConfig(format!(
            "Phase 27 chain chunking requires at least {chain_chunk_len} folded members, got {}",
            members.len()
        )));
    }
    if !members.len().is_multiple_of(chain_chunk_len) {
        return Err(VmError::InvalidConfig(format!(
            "Phase 27 chain chunking requires folded_members.len()={} to be divisible by chunk length {}",
            members.len(),
            chain_chunk_len
        )));
    }

    members
        .chunks(chain_chunk_len)
        .map(phase27_prepare_chained_folded_intervalized_decoding_state_relation)
        .collect()
}

fn phase26_prepare_demo_manifest_for_layout(
    layout: &Phase12DecodingLayout,
) -> Result<Phase26FoldedIntervalizedDecodingStateRelationManifest> {
    let proofs = phase25_demo_proofs_for_layout(layout, 4)?;
    let cumulative_members =
        phase25_prepare_cumulative_members_from_proof_prefixes(layout, &proofs)?;
    let midpoint = cumulative_members.len() / 2;
    let first_member = phase25_prepare_intervalized_member_from_cumulative_members(
        &cumulative_members[..midpoint],
        None,
    )?;
    let second_member = phase25_prepare_intervalized_member_from_cumulative_members(
        &cumulative_members[midpoint..],
        cumulative_members.get(midpoint - 1),
    )?;
    phase26_prepare_folded_intervalized_decoding_state_relation(&[first_member, second_member])
}

fn phase27_prepare_demo_manifest_for_layout(
    layout: &Phase12DecodingLayout,
) -> Result<Phase27ChainedFoldedIntervalizedDecodingStateRelationManifest> {
    let proofs = phase25_demo_proofs_for_layout(layout, 8)?;
    let cumulative_members =
        phase25_prepare_cumulative_members_from_proof_prefixes(layout, &proofs)?;
    let interval_members =
        phase25_prepare_intervalized_members_from_cumulative_members(&cumulative_members, 2)?;
    let folded_members =
        phase26_prepare_folded_members_from_interval_members(&interval_members, 2)?;
    phase27_prepare_chained_folded_intervalized_decoding_state_relation(&folded_members)
}

fn phase28_prepare_demo_manifest_for_layout(
    layout: &Phase12DecodingLayout,
) -> Result<Phase28AggregatedChainedFoldedIntervalizedDecodingStateRelationManifest> {
    let proofs = phase25_demo_proofs_for_layout(layout, 16)?;
    let cumulative_members =
        phase25_prepare_cumulative_members_from_proof_prefixes(layout, &proofs)?;
    let interval_members =
        phase25_prepare_intervalized_members_from_cumulative_members(&cumulative_members, 2)?;
    let folded_members =
        phase26_prepare_folded_members_from_interval_members(&interval_members, 2)?;
    let chained_members = phase27_prepare_chained_members_from_folded_members(&folded_members, 2)?;
    phase28_prepare_aggregated_chained_folded_intervalized_decoding_state_relation(&chained_members)
}

pub fn prove_phase24_decoding_state_relation_accumulator_demo(
) -> Result<Phase24DecodingStateRelationAccumulatorManifest> {
    let layout = phase12_default_decoding_layout();
    let phase12 = prove_phase12_decoding_demo_for_layout(&layout)?;
    let proofs = phase12
        .steps
        .iter()
        .map(|step| step.proof.clone())
        .collect::<Vec<_>>();
    if proofs.len() < 2 {
        return Err(VmError::InvalidConfig(format!(
            "Phase 24 demo requires at least two proof windows, got {}",
            proofs.len()
        )));
    }

    let manifest = phase24_prepare_member_from_proof_window(&layout, &proofs)?;
    verify_phase24_decoding_state_relation_accumulator_with_proof_checks(&manifest)?;
    Ok(manifest)
}

pub fn prove_phase25_intervalized_decoding_state_relation_demo(
) -> Result<Phase25IntervalizedDecodingStateRelationManifest> {
    let source = prove_phase24_decoding_state_relation_accumulator_demo()?;
    let manifest = phase25_prepare_intervalized_decoding_state_relation(&source)?;
    verify_phase25_intervalized_decoding_state_relation_with_proof_checks(&manifest)?;
    Ok(manifest)
}

pub fn prove_phase26_folded_intervalized_decoding_state_relation_demo(
) -> Result<Phase26FoldedIntervalizedDecodingStateRelationManifest> {
    let mut last_error = None;
    for layout in phase25_default_decoding_layouts()? {
        match phase26_prepare_demo_manifest_for_layout(&layout) {
            Ok(manifest) => {
                verify_phase26_folded_intervalized_decoding_state_relation_with_proof_checks(
                    &manifest,
                )?;
                return Ok(manifest);
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        VmError::InvalidConfig(
            "Phase 26 folded intervalized demo did not have any candidate layouts to try"
                .to_string(),
        )
    }))
}

pub fn prove_phase27_chained_folded_intervalized_decoding_state_relation_demo(
) -> Result<Phase27ChainedFoldedIntervalizedDecodingStateRelationManifest> {
    let mut last_error = None;
    for layout in phase25_default_decoding_layouts()? {
        match phase27_prepare_demo_manifest_for_layout(&layout) {
            Ok(manifest) => {
                verify_phase27_chained_folded_intervalized_decoding_state_relation_with_proof_checks(
                    &manifest,
                )?;
                return Ok(manifest);
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        VmError::InvalidConfig(
            "Phase 27 chained folded intervalized demo did not have any candidate layouts to try"
                .to_string(),
        )
    }))
}

pub fn prove_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_demo(
) -> Result<Phase28AggregatedChainedFoldedIntervalizedDecodingStateRelationManifest> {
    let mut last_error = None;
    for layout in phase25_default_decoding_layouts()? {
        match phase28_prepare_demo_manifest_for_layout(&layout) {
            Ok(manifest) => {
                verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_proof_checks(
                    &manifest,
                )?;
                return Ok(manifest);
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        VmError::InvalidConfig(
            "Phase 28 aggregated chained folded intervalized demo did not have any candidate layouts to try"
                .to_string(),
        )
    }))
}

fn derive_phase11_state(memory: &[i16], step_index: usize) -> Result<Phase11DecodingState> {
    if memory.len() <= DECODING_POSITION_INDEX {
        return Err(VmError::InvalidConfig(format!(
            "decoding state requires at least {} memory cells, got {}",
            DECODING_POSITION_INDEX + 1,
            memory.len()
        )));
    }
    Ok(Phase11DecodingState {
        state_version: STWO_DECODING_STATE_VERSION_PHASE11.to_string(),
        step_index,
        position: memory[DECODING_POSITION_INDEX],
        kv_cache_commitment: commit_slice(&memory[DECODING_KV_CACHE_RANGE]),
        output_commitment: commit_slice(&memory[DECODING_OUTPUT_RANGE]),
    })
}

fn derive_phase12_state_view(
    memory: &[i16],
    layout: &Phase12DecodingLayout,
) -> Result<Phase12StateView> {
    layout.validate()?;
    let memory_size = layout.memory_size()?;
    let kv_cache_range = layout.kv_cache_range()?;
    let incoming_token_range = layout.incoming_token_range()?;
    let query_range = layout.query_range()?;
    let output_range = layout.output_range()?;
    let lookup_range = layout.lookup_range()?;
    let position_index = layout.position_index()?;
    if memory.len() != memory_size {
        return Err(VmError::InvalidConfig(format!(
            "Phase 12 decoding state requires exactly {} memory cells, got {}",
            memory_size,
            memory.len()
        )));
    }

    let layout_commitment = commit_phase12_layout(layout);
    let kv_cache_commitment = commit_phase12_named_slice(
        "kv-cache",
        &layout_commitment,
        &memory[kv_cache_range.clone()],
    );
    let incoming_token_commitment = commit_phase12_named_slice(
        "incoming-token",
        &layout_commitment,
        &memory[incoming_token_range.clone()],
    );
    let query_commitment =
        commit_phase12_named_slice("query", &layout_commitment, &memory[query_range]);
    let output_commitment =
        commit_phase12_named_slice("output", &layout_commitment, &memory[output_range]);
    let lookup_rows_commitment =
        commit_phase12_shared_lookup_rows(&layout_commitment, &memory[lookup_range]);
    let position = memory[position_index];
    let persistent_state_commitment =
        commit_phase12_persistent_state(&layout_commitment, position, &memory[kv_cache_range]);

    Ok(Phase12StateView {
        position,
        layout_commitment,
        persistent_state_commitment,
        kv_cache_commitment,
        incoming_token_commitment,
        query_commitment,
        output_commitment,
        lookup_rows_commitment,
    })
}

fn derive_phase12_final_state_view_from_proof(
    proof: &VanillaStarkExecutionProof,
    layout: &Phase12DecodingLayout,
) -> Result<Phase12StateView> {
    let mut view = derive_phase12_state_view(&proof.claim.final_state.memory, layout)?;
    if let Some(proof_lookup_rows) =
        phase12_shared_lookup_rows_from_proof_payload(proof, &view.layout_commitment)?
    {
        let lookup_range = layout.lookup_range()?;
        if proof_lookup_rows.len() != lookup_range.len() {
            return Err(VmError::InvalidConfig(format!(
                "decoding_step_v2 proof payload exposes {} shared lookup values, but layout expects {}",
                proof_lookup_rows.len(),
                lookup_range.len()
            )));
        }
        if &proof.claim.final_state.memory[lookup_range.clone()] != proof_lookup_rows.as_slice() {
            return Err(VmError::InvalidConfig(
                "decoding_step_v2 final-state lookup slice does not match the embedded shared lookup rows".to_string(),
            ));
        }
        view.lookup_rows_commitment =
            commit_phase12_shared_lookup_rows(&view.layout_commitment, &proof_lookup_rows);
    }
    Ok(view)
}

fn build_phase12_state(
    step_index: usize,
    view: Phase12StateView,
    kv_history_commitment: String,
    kv_history_length: usize,
) -> Phase12DecodingState {
    let mut state = Phase12DecodingState {
        state_version: STWO_DECODING_STATE_VERSION_PHASE12.to_string(),
        step_index,
        position: view.position,
        layout_commitment: view.layout_commitment,
        persistent_state_commitment: view.persistent_state_commitment,
        kv_history_commitment,
        kv_history_length,
        kv_cache_commitment: view.kv_cache_commitment,
        incoming_token_commitment: view.incoming_token_commitment,
        query_commitment: view.query_commitment,
        output_commitment: view.output_commitment,
        lookup_rows_commitment: view.lookup_rows_commitment,
        public_state_commitment: String::new(),
    };
    state.public_state_commitment = commit_phase12_public_state(&state);
    state
}

fn build_phase14_state(
    step_index: usize,
    view: Phase12StateView,
    history: &Phase14HistoryAccumulator,
) -> Phase14DecodingState {
    let mut state = Phase14DecodingState {
        state_version: STWO_DECODING_STATE_VERSION_PHASE14.to_string(),
        step_index,
        position: view.position,
        layout_commitment: view.layout_commitment,
        persistent_state_commitment: view.persistent_state_commitment,
        kv_history_commitment: history.history_commitment.clone(),
        kv_history_length: history.history_length,
        kv_history_chunk_size: history.chunk_size,
        kv_history_sealed_commitment: history.sealed_commitment.clone(),
        kv_history_sealed_chunks: history.sealed_chunks,
        kv_history_open_chunk_commitment: history.open_chunk_commitment.clone(),
        kv_history_open_chunk_pairs: history.open_chunk_pairs,
        kv_history_frontier_commitment: history.frontier_commitment.clone(),
        kv_history_frontier_pairs: history.frontier_pairs,
        lookup_transcript_commitment: history.lookup_transcript_commitment.clone(),
        lookup_transcript_entries: history.lookup_transcript_entries,
        lookup_frontier_commitment: history.lookup_frontier_commitment.clone(),
        lookup_frontier_entries: history.lookup_frontier_entries,
        kv_cache_commitment: view.kv_cache_commitment,
        incoming_token_commitment: view.incoming_token_commitment,
        query_commitment: view.query_commitment,
        output_commitment: view.output_commitment,
        lookup_rows_commitment: view.lookup_rows_commitment,
        public_state_commitment: String::new(),
    };
    state.public_state_commitment = commit_phase14_public_state(&state);
    state
}

fn validate_phase11_chain_steps(steps: &[Phase11DecodingStep]) -> Result<()> {
    for (index, step) in steps.iter().enumerate() {
        if step.from_state.state_version != STWO_DECODING_STATE_VERSION_PHASE11 {
            return Err(VmError::InvalidConfig(format!(
                "decoding step {index} uses unsupported from_state version `{}`",
                step.from_state.state_version
            )));
        }
        if step.to_state.state_version != STWO_DECODING_STATE_VERSION_PHASE11 {
            return Err(VmError::InvalidConfig(format!(
                "decoding step {index} uses unsupported to_state version `{}`",
                step.to_state.state_version
            )));
        }
        if step.from_state.step_index != index {
            return Err(VmError::InvalidConfig(format!(
                "decoding step {index} from_state step_index={} does not match its position",
                step.from_state.step_index
            )));
        }
        if step.to_state.step_index != index + 1 {
            return Err(VmError::InvalidConfig(format!(
                "decoding step {index} to_state step_index={} does not equal {}",
                step.to_state.step_index,
                index + 1
            )));
        }
        let expected_next_position = step.from_state.position.checked_add(1).ok_or_else(|| {
            VmError::InvalidConfig(format!(
                "decoding step {index} position {} cannot be incremented",
                step.from_state.position
            ))
        })?;
        if step.to_state.position != expected_next_position {
            return Err(VmError::InvalidConfig(format!(
                "decoding step {index} does not increment position: from {} to {}",
                step.from_state.position, step.to_state.position
            )));
        }
    }
    for index in 1..steps.len() {
        if steps[index - 1].to_state.kv_cache_commitment
            != steps[index].from_state.kv_cache_commitment
        {
            return Err(VmError::InvalidConfig(format!(
                "decoding chain link {} -> {} does not preserve the KV-cache commitment",
                index - 1,
                index
            )));
        }
        if steps[index - 1].to_state.position != steps[index].from_state.position {
            return Err(VmError::InvalidConfig(format!(
                "decoding chain link {} -> {} does not preserve the decoding position",
                index - 1,
                index
            )));
        }
    }
    Ok(())
}

fn validate_phase12_chain_steps(
    layout: &Phase12DecodingLayout,
    steps: &[Phase12DecodingStep],
) -> Result<()> {
    let expected_layout_commitment = commit_phase12_layout(layout);
    validate_phase12_chain_steps_against_layout_commitment(&expected_layout_commitment, steps)
}

fn validate_phase12_chain_steps_against_layout_commitment(
    expected_layout_commitment: &str,
    steps: &[Phase12DecodingStep],
) -> Result<()> {
    for (index, step) in steps.iter().enumerate() {
        if step.from_state.state_version != STWO_DECODING_STATE_VERSION_PHASE12 {
            return Err(VmError::InvalidConfig(format!(
                "decoding step {index} uses unsupported from_state version `{}`",
                step.from_state.state_version
            )));
        }
        if step.to_state.state_version != STWO_DECODING_STATE_VERSION_PHASE12 {
            return Err(VmError::InvalidConfig(format!(
                "decoding step {index} uses unsupported to_state version `{}`",
                step.to_state.state_version
            )));
        }
        if step.from_state.step_index != index {
            return Err(VmError::InvalidConfig(format!(
                "decoding step {index} from_state step_index={} does not match its position",
                step.from_state.step_index
            )));
        }
        if step.to_state.step_index != index + 1 {
            return Err(VmError::InvalidConfig(format!(
                "decoding step {index} to_state step_index={} does not equal {}",
                step.to_state.step_index,
                index + 1
            )));
        }
        if step.from_state.layout_commitment != expected_layout_commitment
            || step.to_state.layout_commitment != expected_layout_commitment
        {
            return Err(VmError::InvalidConfig(format!(
                "decoding step {index} does not match the manifest layout commitment"
            )));
        }
        let expected_next_position = step.from_state.position.checked_add(1).ok_or_else(|| {
            VmError::InvalidConfig(format!(
                "decoding step {index} position {} cannot be incremented",
                step.from_state.position
            ))
        })?;
        if step.to_state.position != expected_next_position {
            return Err(VmError::InvalidConfig(format!(
                "decoding step {index} does not increment position: from {} to {}",
                step.from_state.position, step.to_state.position
            )));
        }
        if step.from_state.public_state_commitment != commit_phase12_public_state(&step.from_state)
        {
            return Err(VmError::InvalidConfig(format!(
                "decoding step {index} from_state public_state_commitment does not match its serialized contents"
            )));
        }
        if step.to_state.public_state_commitment != commit_phase12_public_state(&step.to_state) {
            return Err(VmError::InvalidConfig(format!(
                "decoding step {index} to_state public_state_commitment does not match its serialized contents"
            )));
        }
    }
    for index in 1..steps.len() {
        if steps[index - 1].to_state.public_state_commitment
            != steps[index].from_state.public_state_commitment
        {
            return Err(VmError::InvalidConfig(format!(
                "decoding chain link {} -> {} does not preserve the carried public-state commitment",
                index - 1,
                index
            )));
        }
        if steps[index - 1].to_state.persistent_state_commitment
            != steps[index].from_state.persistent_state_commitment
        {
            return Err(VmError::InvalidConfig(format!(
                "decoding chain link {} -> {} does not preserve the persistent KV-cache state commitment",
                index - 1,
                index
            )));
        }
        if steps[index - 1].to_state.kv_cache_commitment
            != steps[index].from_state.kv_cache_commitment
        {
            return Err(VmError::InvalidConfig(format!(
                "decoding chain link {} -> {} does not preserve the KV-cache commitment",
                index - 1,
                index
            )));
        }
        if steps[index - 1].to_state.position != steps[index].from_state.position {
            return Err(VmError::InvalidConfig(format!(
                "decoding chain link {} -> {} does not preserve the decoding position",
                index - 1,
                index
            )));
        }
        if steps[index - 1].to_state.kv_history_commitment
            != steps[index].from_state.kv_history_commitment
        {
            return Err(VmError::InvalidConfig(format!(
                "decoding chain link {} -> {} does not preserve the cumulative KV-history commitment",
                index - 1,
                index
            )));
        }
        if steps[index - 1].to_state.kv_history_length != steps[index].from_state.kv_history_length
        {
            return Err(VmError::InvalidConfig(format!(
                "decoding chain link {} -> {} does not preserve the cumulative KV-history length",
                index - 1,
                index
            )));
        }
    }
    Ok(())
}

fn validate_phase14_chain_steps(
    layout: &Phase12DecodingLayout,
    history_chunk_pairs: usize,
    steps: &[Phase14DecodingStep],
) -> Result<()> {
    let expected_layout_commitment = commit_phase12_layout(layout);
    validate_phase14_chain_steps_against_layout_commitment(
        layout,
        &expected_layout_commitment,
        history_chunk_pairs,
        steps,
    )
}

fn validate_phase14_chain_steps_against_layout_commitment(
    layout: &Phase12DecodingLayout,
    expected_layout_commitment: &str,
    history_chunk_pairs: usize,
    steps: &[Phase14DecodingStep],
) -> Result<()> {
    for (index, step) in steps.iter().enumerate() {
        if step.from_state.state_version != STWO_DECODING_STATE_VERSION_PHASE14 {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding step {index} has unsupported from_state version `{}`",
                step.from_state.state_version
            )));
        }
        if step.to_state.state_version != STWO_DECODING_STATE_VERSION_PHASE14 {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding step {index} has unsupported to_state version `{}`",
                step.to_state.state_version
            )));
        }
        if step.from_state.step_index != index {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding step {index} from_state.step_index={} does not match index",
                step.from_state.step_index
            )));
        }
        if step.to_state.step_index != index + 1 {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding step {index} to_state.step_index={} does not match index + 1",
                step.to_state.step_index
            )));
        }
        if step.from_state.layout_commitment != step.to_state.layout_commitment {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding step {index} changes the layout commitment"
            )));
        }
        if step.from_state.layout_commitment != expected_layout_commitment {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding step {index} layout commitment `{}` does not match the canonical layout commitment",
                step.from_state.layout_commitment
            )));
        }
        if step.from_state.kv_history_chunk_size != history_chunk_pairs
            || step.to_state.kv_history_chunk_size != history_chunk_pairs
        {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding step {index} uses history_chunk_size {} -> {}, expected {}",
                step.from_state.kv_history_chunk_size,
                step.to_state.kv_history_chunk_size,
                history_chunk_pairs
            )));
        }
        if step.from_state.kv_history_frontier_pairs != layout.rolling_kv_pairs
            || step.to_state.kv_history_frontier_pairs != layout.rolling_kv_pairs
        {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding step {index} uses history frontier pair count {} -> {}, expected {}",
                step.from_state.kv_history_frontier_pairs,
                step.to_state.kv_history_frontier_pairs,
                layout.rolling_kv_pairs
            )));
        }
        if step.from_state.kv_history_frontier_commitment != step.from_state.kv_cache_commitment {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding step {index} does not tie the from_state history frontier commitment to the KV-cache commitment"
            )));
        }
        if step.to_state.kv_history_frontier_commitment != step.to_state.kv_cache_commitment {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding step {index} does not tie the to_state history frontier commitment to the KV-cache commitment"
            )));
        }
        if step.from_state.lookup_transcript_entries == 0 {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding step {index} must start from a non-empty lookup transcript"
            )));
        }
        if step.to_state.lookup_transcript_entries != step.from_state.lookup_transcript_entries + 1
        {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding step {index} does not advance the lookup transcript entry count: from {} to {}",
                step.from_state.lookup_transcript_entries,
                step.to_state.lookup_transcript_entries
            )));
        }
        if step.from_state.lookup_frontier_entries == 0
            || step.from_state.lookup_frontier_entries > history_chunk_pairs
            || step.to_state.lookup_frontier_entries == 0
            || step.to_state.lookup_frontier_entries > history_chunk_pairs
        {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding step {index} uses lookup frontier entry count {} -> {}, expected 1..={}",
                step.from_state.lookup_frontier_entries,
                step.to_state.lookup_frontier_entries,
                history_chunk_pairs
            )));
        }
        let expected_next_lookup_frontier_entries =
            (step.from_state.lookup_frontier_entries + 1).min(history_chunk_pairs);
        if step.to_state.lookup_frontier_entries != expected_next_lookup_frontier_entries {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding step {index} does not advance the lookup frontier entry count: from {} to {}, expected {}",
                step.from_state.lookup_frontier_entries,
                step.to_state.lookup_frontier_entries,
                expected_next_lookup_frontier_entries
            )));
        }
        let expected_next_position = step.from_state.position.checked_add(1).ok_or_else(|| {
            VmError::InvalidConfig(format!(
                "chunked decoding step {index} position {} cannot be incremented",
                step.from_state.position
            ))
        })?;
        if step.to_state.position != expected_next_position {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding step {index} does not increment position: from {} to {}",
                step.from_state.position, step.to_state.position
            )));
        }
        if step.from_state.public_state_commitment != commit_phase14_public_state(&step.from_state)
        {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding step {index} from_state public_state_commitment does not match its serialized contents"
            )));
        }
        if step.to_state.public_state_commitment != commit_phase14_public_state(&step.to_state) {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding step {index} to_state public_state_commitment does not match its serialized contents"
            )));
        }
    }
    for index in 1..steps.len() {
        if steps[index - 1].to_state.public_state_commitment
            != steps[index].from_state.public_state_commitment
        {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding chain link {} -> {} does not preserve the carried public-state commitment",
                index - 1,
                index
            )));
        }
        if steps[index - 1].to_state.persistent_state_commitment
            != steps[index].from_state.persistent_state_commitment
        {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding chain link {} -> {} does not preserve the persistent KV-cache state commitment",
                index - 1,
                index
            )));
        }
        if steps[index - 1].to_state.kv_cache_commitment
            != steps[index].from_state.kv_cache_commitment
        {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding chain link {} -> {} does not preserve the KV-cache commitment",
                index - 1,
                index
            )));
        }
        if steps[index - 1].to_state.position != steps[index].from_state.position {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding chain link {} -> {} does not preserve the decoding position",
                index - 1,
                index
            )));
        }
        if steps[index - 1].to_state.kv_history_commitment
            != steps[index].from_state.kv_history_commitment
        {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding chain link {} -> {} does not preserve the cumulative KV-history commitment",
                index - 1,
                index
            )));
        }
        if steps[index - 1].to_state.kv_history_length != steps[index].from_state.kv_history_length
        {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding chain link {} -> {} does not preserve the cumulative KV-history length",
                index - 1,
                index
            )));
        }
        if steps[index - 1].to_state.kv_history_sealed_commitment
            != steps[index].from_state.kv_history_sealed_commitment
        {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding chain link {} -> {} does not preserve the sealed KV-history commitment",
                index - 1,
                index
            )));
        }
        if steps[index - 1].to_state.kv_history_sealed_chunks
            != steps[index].from_state.kv_history_sealed_chunks
        {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding chain link {} -> {} does not preserve the sealed KV-history chunk count",
                index - 1,
                index
            )));
        }
        if steps[index - 1].to_state.kv_history_open_chunk_commitment
            != steps[index].from_state.kv_history_open_chunk_commitment
        {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding chain link {} -> {} does not preserve the open KV-history chunk commitment",
                index - 1,
                index
            )));
        }
        if steps[index - 1].to_state.kv_history_open_chunk_pairs
            != steps[index].from_state.kv_history_open_chunk_pairs
        {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding chain link {} -> {} does not preserve the open KV-history chunk length",
                index - 1,
                index
            )));
        }
        if steps[index - 1].to_state.kv_history_frontier_commitment
            != steps[index].from_state.kv_history_frontier_commitment
        {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding chain link {} -> {} does not preserve the KV-history frontier commitment",
                index - 1,
                index
            )));
        }
        if steps[index - 1].to_state.kv_history_frontier_pairs
            != steps[index].from_state.kv_history_frontier_pairs
        {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding chain link {} -> {} does not preserve the KV-history frontier pair count",
                index - 1,
                index
            )));
        }
        if steps[index - 1].to_state.lookup_transcript_commitment
            != steps[index].from_state.lookup_transcript_commitment
        {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding chain link {} -> {} does not preserve the lookup transcript commitment",
                index - 1,
                index
            )));
        }
        if steps[index - 1].to_state.lookup_transcript_entries
            != steps[index].from_state.lookup_transcript_entries
        {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding chain link {} -> {} does not preserve the lookup transcript entry count",
                index - 1,
                index
            )));
        }
        if steps[index - 1].to_state.lookup_frontier_commitment
            != steps[index].from_state.lookup_frontier_commitment
        {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding chain link {} -> {} does not preserve the lookup frontier commitment",
                index - 1,
                index
            )));
        }
        if steps[index - 1].to_state.lookup_frontier_entries
            != steps[index].from_state.lookup_frontier_entries
        {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding chain link {} -> {} does not preserve the lookup frontier entry count",
                index - 1,
                index
            )));
        }
    }
    Ok(())
}

fn validate_phase15_segment_boundary(
    previous_state: &Phase14DecodingState,
    current_state: &Phase14DecodingState,
    segment_index: usize,
) -> Result<()> {
    if previous_state.step_index != current_state.step_index {
        return Err(VmError::InvalidConfig(format!(
            "decoding history segment boundary {} -> {} does not preserve the global step index",
            segment_index - 1,
            segment_index
        )));
    }
    if previous_state.layout_commitment != current_state.layout_commitment {
        return Err(VmError::InvalidConfig(format!(
            "decoding history segment boundary {} -> {} does not preserve the layout commitment",
            segment_index - 1,
            segment_index
        )));
    }
    if previous_state.persistent_state_commitment != current_state.persistent_state_commitment {
        return Err(VmError::InvalidConfig(format!(
            "decoding history segment boundary {} -> {} does not preserve the persistent KV-cache state commitment",
            segment_index - 1,
            segment_index
        )));
    }
    if previous_state.kv_cache_commitment != current_state.kv_cache_commitment {
        return Err(VmError::InvalidConfig(format!(
            "decoding history segment boundary {} -> {} does not preserve the KV-cache commitment",
            segment_index - 1,
            segment_index
        )));
    }
    if previous_state.position != current_state.position {
        return Err(VmError::InvalidConfig(format!(
            "decoding history segment boundary {} -> {} does not preserve the decoding position",
            segment_index - 1,
            segment_index
        )));
    }
    if previous_state.kv_history_commitment != current_state.kv_history_commitment {
        return Err(VmError::InvalidConfig(format!(
            "decoding history segment boundary {} -> {} does not preserve the cumulative KV-history commitment",
            segment_index - 1,
            segment_index
        )));
    }
    if previous_state.kv_history_length != current_state.kv_history_length {
        return Err(VmError::InvalidConfig(format!(
            "decoding history segment boundary {} -> {} does not preserve the cumulative KV-history length",
            segment_index - 1,
            segment_index
        )));
    }
    if previous_state.kv_history_sealed_commitment != current_state.kv_history_sealed_commitment {
        return Err(VmError::InvalidConfig(format!(
            "decoding history segment boundary {} -> {} does not preserve the sealed KV-history commitment",
            segment_index - 1,
            segment_index
        )));
    }
    if previous_state.kv_history_sealed_chunks != current_state.kv_history_sealed_chunks {
        return Err(VmError::InvalidConfig(format!(
            "decoding history segment boundary {} -> {} does not preserve the sealed KV-history chunk count",
            segment_index - 1,
            segment_index
        )));
    }
    if previous_state.kv_history_open_chunk_commitment
        != current_state.kv_history_open_chunk_commitment
    {
        return Err(VmError::InvalidConfig(format!(
            "decoding history segment boundary {} -> {} does not preserve the open KV-history chunk commitment",
            segment_index - 1,
            segment_index
        )));
    }
    if previous_state.kv_history_open_chunk_pairs != current_state.kv_history_open_chunk_pairs {
        return Err(VmError::InvalidConfig(format!(
            "decoding history segment boundary {} -> {} does not preserve the open KV-history chunk length",
            segment_index - 1,
            segment_index
        )));
    }
    if previous_state.kv_history_frontier_commitment != current_state.kv_history_frontier_commitment
    {
        return Err(VmError::InvalidConfig(format!(
            "decoding history segment boundary {} -> {} does not preserve the KV-history frontier commitment",
            segment_index - 1,
            segment_index
        )));
    }
    if previous_state.kv_history_frontier_pairs != current_state.kv_history_frontier_pairs {
        return Err(VmError::InvalidConfig(format!(
            "decoding history segment boundary {} -> {} does not preserve the KV-history frontier pair count",
            segment_index - 1,
            segment_index
        )));
    }
    if previous_state.lookup_transcript_commitment != current_state.lookup_transcript_commitment {
        return Err(VmError::InvalidConfig(format!(
            "decoding history segment boundary {} -> {} does not preserve the lookup transcript commitment",
            segment_index - 1,
            segment_index
        )));
    }
    if previous_state.lookup_transcript_entries != current_state.lookup_transcript_entries {
        return Err(VmError::InvalidConfig(format!(
            "decoding history segment boundary {} -> {} does not preserve the lookup transcript entry count",
            segment_index - 1,
            segment_index
        )));
    }
    if previous_state.lookup_frontier_commitment != current_state.lookup_frontier_commitment {
        return Err(VmError::InvalidConfig(format!(
            "decoding history segment boundary {} -> {} does not preserve the lookup frontier commitment",
            segment_index - 1,
            segment_index
        )));
    }
    if previous_state.lookup_frontier_entries != current_state.lookup_frontier_entries {
        return Err(VmError::InvalidConfig(format!(
            "decoding history segment boundary {} -> {} does not preserve the lookup frontier entry count",
            segment_index - 1,
            segment_index
        )));
    }
    Ok(())
}

fn validate_phase16_rollup_boundary(
    previous_state: &Phase14DecodingState,
    current_state: &Phase14DecodingState,
    rollup_index: usize,
) -> Result<()> {
    validate_phase15_segment_boundary(previous_state, current_state, rollup_index).map_err(
        |error| match error {
            VmError::InvalidConfig(message) => VmError::InvalidConfig(message.replace(
                "decoding history segment boundary",
                "decoding history segment rollup boundary",
            )),
            other => other,
        },
    )
}

fn verify_phase15_segment_sequence(
    layout: &Phase12DecodingLayout,
    history_chunk_pairs: usize,
    proof_backend_version: &str,
    statement_version: &str,
    segments: &[Phase15DecodingHistorySegment],
    initial_global_start_step_index: usize,
    accumulator: &mut Option<Phase14HistoryAccumulator>,
) -> Result<usize> {
    let expected_layout_commitment = commit_phase12_layout(layout);
    let kv_cache_range = layout.kv_cache_range()?;
    let latest_cached_range = layout.latest_cached_pair_range()?;
    let mut expected_global_start_step_index = initial_global_start_step_index;

    for (local_segment_index, segment) in segments.iter().enumerate() {
        if segment.global_start_step_index != expected_global_start_step_index {
            return Err(VmError::InvalidConfig(format!(
                "decoding history segment {} starts at global step {} instead of {}",
                segment.segment_index,
                segment.global_start_step_index,
                expected_global_start_step_index
            )));
        }
        if segment.chain.total_steps != segment.total_steps {
            return Err(VmError::InvalidConfig(format!(
                "decoding history segment {} total_steps={} does not match chain.total_steps={}",
                segment.segment_index, segment.total_steps, segment.chain.total_steps
            )));
        }
        if segment.chain.layout != *layout {
            return Err(VmError::InvalidConfig(format!(
                "decoding history segment {} does not match the expected layout",
                segment.segment_index
            )));
        }
        if segment.chain.history_chunk_pairs != history_chunk_pairs {
            return Err(VmError::InvalidConfig(format!(
                "decoding history segment {} history_chunk_pairs={} does not match expected {}",
                segment.segment_index, segment.chain.history_chunk_pairs, history_chunk_pairs
            )));
        }
        if segment.chain.proof_backend_version != proof_backend_version {
            return Err(VmError::InvalidConfig(format!(
                "decoding history segment {} proof backend version `{}` does not match expected `{}`",
                segment.segment_index, segment.chain.proof_backend_version, proof_backend_version
            )));
        }
        if segment.chain.statement_version != statement_version {
            return Err(VmError::InvalidConfig(format!(
                "decoding history segment {} statement version `{}` does not match expected `{}`",
                segment.segment_index, segment.chain.statement_version, statement_version
            )));
        }
        verify_phase14_decoding_chain(&segment.chain)?;
        let first_local_step = segment.chain.steps.first().ok_or_else(|| {
            VmError::InvalidConfig(format!(
                "decoding history segment {} must contain at least one local step",
                segment.segment_index
            ))
        })?;
        let first_from_view = derive_phase12_state_view(
            first_local_step.proof.claim.program.initial_memory(),
            layout,
        )?;
        let mut current = accumulator.clone().unwrap_or_else(|| {
            seed_phase14_history(
                &expected_layout_commitment,
                &first_local_step.proof.claim.program.initial_memory()[kv_cache_range.clone()],
                &first_from_view.lookup_rows_commitment,
                layout.pair_width,
            )
        });
        let expected_global_from =
            build_phase14_state(expected_global_start_step_index, first_from_view, &current);
        if segment.global_from_state != expected_global_from {
            return Err(VmError::InvalidConfig(format!(
                "decoding history segment {} global_from_state does not match the carried-state replay",
                segment.segment_index
            )));
        }

        let mut expected_global_to = expected_global_from.clone();
        for (local_index, step) in segment.chain.steps.iter().enumerate() {
            let to_view = derive_phase12_final_state_view_from_proof(&step.proof, layout)?;
            current = advance_phase14_history(
                &expected_layout_commitment,
                &current,
                &step.proof.claim.final_state.memory[latest_cached_range.clone()],
                &to_view.lookup_rows_commitment,
                layout.pair_width,
            )?;
            let global_step_index = expected_global_start_step_index
                .checked_add(local_index + 1)
                .ok_or_else(|| {
                    VmError::InvalidConfig(
                        "decoding history segment replay global step index overflowed".to_string(),
                    )
                })?;
            expected_global_to = build_phase14_state(global_step_index, to_view, &current);
        }
        if segment.global_to_state != expected_global_to {
            return Err(VmError::InvalidConfig(format!(
                "decoding history segment {} global_to_state does not match the carried-state replay",
                segment.segment_index
            )));
        }
        if local_segment_index > 0 {
            validate_phase15_segment_boundary(
                &segments[local_segment_index - 1].global_to_state,
                &segment.global_from_state,
                segment.segment_index,
            )?;
        }
        *accumulator = Some(current);
        expected_global_start_step_index = expected_global_start_step_index
            .checked_add(segment.total_steps)
            .ok_or_else(|| {
                VmError::InvalidConfig(
                    "decoding history segment replay global step count overflowed".to_string(),
                )
            })?;
    }

    Ok(expected_global_start_step_index)
}

fn commit_slice(values: &[i16]) -> String {
    let mut hasher = Blake2bVar::new(32).expect("blake2b-256");
    hasher.update(STWO_DECODING_STATE_VERSION_PHASE11.as_bytes());
    for value in values {
        hasher.update(&value.to_le_bytes());
    }
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("blake2b finalize");
    lower_hex(&out)
}

pub(crate) fn commit_phase12_layout(layout: &Phase12DecodingLayout) -> String {
    let mut hasher = Blake2bVar::new(32).expect("blake2b-256");
    hasher.update(STWO_DECODING_LAYOUT_VERSION_PHASE12.as_bytes());
    hasher.update(&(layout.rolling_kv_pairs as u64).to_le_bytes());
    hasher.update(&(layout.pair_width as u64).to_le_bytes());
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("blake2b finalize");
    lower_hex(&out)
}

fn commit_phase12_named_slice(label: &str, layout_commitment: &str, values: &[i16]) -> String {
    let mut hasher = Blake2bVar::new(32).expect("blake2b-256");
    hasher.update(STWO_DECODING_STATE_VERSION_PHASE12.as_bytes());
    hasher.update(layout_commitment.as_bytes());
    hasher.update(label.as_bytes());
    for value in values {
        hasher.update(&value.to_le_bytes());
    }
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("blake2b finalize");
    lower_hex(&out)
}

fn commit_phase12_persistent_state(
    layout_commitment: &str,
    position: i16,
    kv_cache_values: &[i16],
) -> String {
    let mut hasher = Blake2bVar::new(32).expect("blake2b-256");
    hasher.update(STWO_DECODING_STATE_VERSION_PHASE12.as_bytes());
    hasher.update(layout_commitment.as_bytes());
    hasher.update(&position.to_le_bytes());
    for value in kv_cache_values {
        hasher.update(&value.to_le_bytes());
    }
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("blake2b finalize");
    lower_hex(&out)
}

/// Commits only the carried Phase 12 state that must remain stable across links.
/// Step-local I/O commitments are excluded because the execution proof already binds them.
fn commit_phase12_public_state(state: &Phase12DecodingState) -> String {
    let mut hasher = Blake2bVar::new(32).expect("blake2b-256");
    hasher.update(STWO_DECODING_STATE_VERSION_PHASE12.as_bytes());
    hasher.update(b"public-state");
    hasher.update(state.state_version.as_bytes());
    hasher.update(&(state.step_index as u64).to_le_bytes());
    hasher.update(&state.position.to_le_bytes());
    hasher.update(state.layout_commitment.as_bytes());
    hasher.update(state.persistent_state_commitment.as_bytes());
    hasher.update(state.kv_history_commitment.as_bytes());
    hasher.update(&(state.kv_history_length as u64).to_le_bytes());
    hasher.update(state.kv_cache_commitment.as_bytes());
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("blake2b finalize");
    lower_hex(&out)
}

fn build_phase30_decoding_step_proof_envelope(
    step_index: usize,
    step: &Phase12DecodingStep,
    layout_commitment: &str,
    source_chain_commitment: &str,
    shared_lookup_artifact: &Phase12SharedLookupArtifact,
) -> Result<Phase30DecodingStepProofEnvelope> {
    let proof_commitment = commit_phase30_step_proof(&step.proof)?;
    let mut envelope = Phase30DecodingStepProofEnvelope {
        envelope_version: STWO_DECODING_STEP_ENVELOPE_VERSION_PHASE30.to_string(),
        semantic_scope: STWO_DECODING_STEP_ENVELOPE_SCOPE_PHASE30.to_string(),
        proof_backend: step.proof.proof_backend,
        proof_backend_version: step.proof.proof_backend_version.clone(),
        statement_version: step.proof.claim.statement_version.clone(),
        relation: STWO_DECODING_STEP_ENVELOPE_RELATION_PHASE30.to_string(),
        layout_commitment: layout_commitment.to_string(),
        source_chain_commitment: source_chain_commitment.to_string(),
        step_index,
        input_boundary_commitment: step.from_state.public_state_commitment.clone(),
        output_boundary_commitment: step.to_state.public_state_commitment.clone(),
        input_lookup_rows_commitment: step.from_state.lookup_rows_commitment.clone(),
        output_lookup_rows_commitment: step.to_state.lookup_rows_commitment.clone(),
        shared_lookup_artifact_commitment: step.shared_lookup_artifact_commitment.clone(),
        static_lookup_registry_commitment: shared_lookup_artifact
            .static_table_registry_commitment
            .clone(),
        proof_commitment,
        envelope_commitment: String::new(),
    };
    envelope.envelope_commitment = commit_phase30_step_envelope(&envelope);
    Ok(envelope)
}

fn commit_phase12_decoding_chain_for_step_envelopes(
    chain: &Phase12DecodingChainManifest,
) -> Result<String> {
    let mut hasher = Blake2bVar::new(32).expect("blake2b-256");
    hasher.update(STWO_DECODING_STEP_ENVELOPE_MANIFEST_VERSION_PHASE30.as_bytes());
    hasher.update(b"source-phase12-chain");
    phase30_update_hasher_with_json(&mut hasher, chain)?;
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("blake2b finalize");
    Ok(lower_hex(&out))
}

fn commit_phase30_step_proof(proof: &VanillaStarkExecutionProof) -> Result<String> {
    let mut hasher = Blake2bVar::new(32).expect("blake2b-256");
    hasher.update(STWO_DECODING_STEP_ENVELOPE_VERSION_PHASE30.as_bytes());
    hasher.update(b"step-proof");
    phase30_update_hasher_with_json(&mut hasher, proof)?;
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("blake2b finalize");
    Ok(lower_hex(&out))
}

fn phase30_update_hasher_with_json<T: Serialize>(hasher: &mut Blake2bVar, value: &T) -> Result<()> {
    // Frame large JSON values without buffering full proof JSON or traversing it twice.
    let mut writer = Phase30JsonDigestWriter {
        byte_len: 0,
        hasher: Blake2bVar::new(32).expect("blake2b-256"),
    };
    serde_json::to_writer(&mut writer, value)
        .map_err(|error| VmError::Serialization(error.to_string()))?;
    let (byte_len, json_digest) = writer.finalize();
    hasher.update(&byte_len.to_le_bytes());
    hasher.update(&json_digest);
    Ok(())
}

struct Phase30JsonDigestWriter {
    byte_len: u64,
    hasher: Blake2bVar,
}

impl Phase30JsonDigestWriter {
    fn finalize(self) -> (u64, [u8; 32]) {
        let mut out = [0u8; 32];
        self.hasher
            .finalize_variable(&mut out)
            .expect("blake2b finalize");
        (self.byte_len, out)
    }
}

impl Write for Phase30JsonDigestWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = u64::try_from(buf.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "phase30 json chunk length exceeded u64",
            )
        })?;
        self.byte_len = self.byte_len.checked_add(written).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "phase30 json length overflowed u64",
            )
        })?;
        self.hasher.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn commit_phase30_step_envelope(envelope: &Phase30DecodingStepProofEnvelope) -> String {
    let mut hasher = Blake2bVar::new(32).expect("blake2b-256");
    hasher.update(STWO_DECODING_STEP_ENVELOPE_VERSION_PHASE30.as_bytes());
    hasher.update(b"step-envelope");
    let proof_backend = envelope.proof_backend.to_string();
    for part in [
        envelope.envelope_version.as_bytes(),
        envelope.semantic_scope.as_bytes(),
        proof_backend.as_bytes(),
        envelope.proof_backend_version.as_bytes(),
        envelope.statement_version.as_bytes(),
        envelope.relation.as_bytes(),
        envelope.layout_commitment.as_bytes(),
        envelope.source_chain_commitment.as_bytes(),
    ] {
        phase30_hash_part(&mut hasher, part);
    }
    hasher.update(&(envelope.step_index as u64).to_le_bytes());
    for part in [
        envelope.input_boundary_commitment.as_bytes(),
        envelope.output_boundary_commitment.as_bytes(),
        envelope.input_lookup_rows_commitment.as_bytes(),
        envelope.output_lookup_rows_commitment.as_bytes(),
        envelope.shared_lookup_artifact_commitment.as_bytes(),
        envelope.static_lookup_registry_commitment.as_bytes(),
        envelope.proof_commitment.as_bytes(),
    ] {
        phase30_hash_part(&mut hasher, part);
    }
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("blake2b finalize");
    lower_hex(&out)
}

fn phase30_hash_part(hasher: &mut Blake2bVar, bytes: &[u8]) {
    let byte_len = u64::try_from(bytes.len()).expect("phase30 hash part length fits in u64");
    hasher.update(&byte_len.to_le_bytes());
    hasher.update(bytes);
}

fn commit_phase30_step_envelope_list(envelopes: &[Phase30DecodingStepProofEnvelope]) -> String {
    let mut hasher = Blake2bVar::new(32).expect("blake2b-256");
    hasher.update(STWO_DECODING_STEP_ENVELOPE_MANIFEST_VERSION_PHASE30.as_bytes());
    hasher.update(b"step-envelope-list");
    hasher.update(&(envelopes.len() as u64).to_le_bytes());
    for envelope in envelopes {
        hasher.update(envelope.envelope_commitment.as_bytes());
    }
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("blake2b finalize");
    lower_hex(&out)
}

fn phase30_chain_boundary_pair(
    envelopes: &[Phase30DecodingStepProofEnvelope],
) -> Result<(String, String)> {
    let first = envelopes.first().ok_or_else(|| {
        VmError::InvalidConfig(
            "decoding step envelope manifest must contain at least one envelope".to_string(),
        )
    })?;
    let last = envelopes.last().expect("non-empty envelopes");
    Ok((
        first.input_boundary_commitment.clone(),
        last.output_boundary_commitment.clone(),
    ))
}

/// Commits only the carried Phase 14 state that must remain stable across links.
/// Step-local I/O commitments are excluded because the execution proof already binds them.
fn commit_phase14_public_state(state: &Phase14DecodingState) -> String {
    let mut hasher = Blake2bVar::new(32).expect("blake2b-256");
    hasher.update(STWO_DECODING_STATE_VERSION_PHASE14.as_bytes());
    hasher.update(b"public-state");
    hasher.update(state.state_version.as_bytes());
    hasher.update(&(state.step_index as u64).to_le_bytes());
    hasher.update(&state.position.to_le_bytes());
    hasher.update(state.layout_commitment.as_bytes());
    hasher.update(state.persistent_state_commitment.as_bytes());
    hasher.update(state.kv_history_commitment.as_bytes());
    hasher.update(&(state.kv_history_length as u64).to_le_bytes());
    hasher.update(&(state.kv_history_chunk_size as u64).to_le_bytes());
    hasher.update(state.kv_history_sealed_commitment.as_bytes());
    hasher.update(&(state.kv_history_sealed_chunks as u64).to_le_bytes());
    hasher.update(state.kv_history_open_chunk_commitment.as_bytes());
    hasher.update(&(state.kv_history_open_chunk_pairs as u64).to_le_bytes());
    hasher.update(state.kv_history_frontier_commitment.as_bytes());
    hasher.update(&(state.kv_history_frontier_pairs as u64).to_le_bytes());
    hasher.update(state.lookup_transcript_commitment.as_bytes());
    hasher.update(&(state.lookup_transcript_entries as u64).to_le_bytes());
    hasher.update(state.lookup_frontier_commitment.as_bytes());
    hasher.update(&(state.lookup_frontier_entries as u64).to_le_bytes());
    hasher.update(state.kv_cache_commitment.as_bytes());
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("blake2b finalize");
    lower_hex(&out)
}

fn commit_phase15_segment_public_state_boundary(segment: &Phase15DecodingHistorySegment) -> String {
    let mut hasher = Blake2bVar::new(32).expect("blake2b-256");
    hasher.update(STWO_DECODING_SEGMENT_BUNDLE_VERSION_PHASE15.as_bytes());
    hasher.update(b"public-state-boundary");
    hasher.update(&(segment.segment_index as u64).to_le_bytes());
    hasher.update(&(segment.global_start_step_index as u64).to_le_bytes());
    hasher.update(&(segment.total_steps as u64).to_le_bytes());
    hasher.update(segment.global_from_state.public_state_commitment.as_bytes());
    hasher.update(segment.global_to_state.public_state_commitment.as_bytes());
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("blake2b finalize");
    lower_hex(&out)
}

fn commit_phase16_rollup_public_state_boundary(rollup: &Phase16DecodingHistoryRollup) -> String {
    let mut hasher = Blake2bVar::new(32).expect("blake2b-256");
    hasher.update(STWO_DECODING_SEGMENT_ROLLUP_VERSION_PHASE16.as_bytes());
    hasher.update(b"public-state-boundary");
    hasher.update(&(rollup.rollup_index as u64).to_le_bytes());
    hasher.update(&(rollup.global_start_step_index as u64).to_le_bytes());
    hasher.update(&(rollup.total_segments as u64).to_le_bytes());
    hasher.update(&(rollup.total_steps as u64).to_le_bytes());
    hasher.update(rollup.global_from_state.public_state_commitment.as_bytes());
    hasher.update(rollup.global_to_state.public_state_commitment.as_bytes());
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("blake2b finalize");
    lower_hex(&out)
}

fn commit_phase17_matrix_public_state_boundary(
    manifest: &Phase17DecodingHistoryRollupMatrixManifest,
) -> Result<String> {
    if manifest.rollups.is_empty() {
        return Err(VmError::InvalidConfig(
            "decoding rollup matrix must contain at least one rollup manifest".to_string(),
        ));
    }

    let mut hasher = Blake2bVar::new(32).expect("blake2b-256");
    hasher.update(STWO_DECODING_ROLLUP_MATRIX_VERSION_PHASE17.as_bytes());
    hasher.update(b"public-state-boundary");
    hasher.update(&(manifest.total_layouts as u64).to_le_bytes());
    hasher.update(&(manifest.total_rollups as u64).to_le_bytes());
    hasher.update(&(manifest.total_segments as u64).to_le_bytes());
    hasher.update(&(manifest.total_steps as u64).to_le_bytes());

    for (layout_index, rollup_manifest) in manifest.rollups.iter().enumerate() {
        if rollup_manifest.rollups.is_empty() {
            return Err(VmError::InvalidConfig(format!(
                "decoding rollup matrix manifest {layout_index} must contain at least one rollup"
            )));
        }
        let layout_commitment = commit_phase12_layout(&rollup_manifest.layout);
        hasher.update(&(layout_index as u64).to_le_bytes());
        hasher.update(&(rollup_manifest.total_rollups as u64).to_le_bytes());
        hasher.update(&(rollup_manifest.total_segments as u64).to_le_bytes());
        hasher.update(&(rollup_manifest.total_steps as u64).to_le_bytes());
        hasher.update(layout_commitment.as_bytes());

        for rollup in &rollup_manifest.rollups {
            if rollup.public_state_boundary_commitment.is_empty() {
                return Err(VmError::InvalidConfig(format!(
                    "decoding rollup matrix manifest {layout_index} contains a rollup with an empty public_state_boundary_commitment"
                )));
            }
            hasher.update(&(rollup.rollup_index as u64).to_le_bytes());
            hasher.update(&(rollup.global_start_step_index as u64).to_le_bytes());
            hasher.update(&(rollup.total_segments as u64).to_le_bytes());
            hasher.update(&(rollup.total_steps as u64).to_le_bytes());
            hasher.update(rollup.public_state_boundary_commitment.as_bytes());
        }
    }

    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("blake2b finalize");
    Ok(lower_hex(&out))
}

fn commit_phase21_matrix_template(
    matrix: &Phase17DecodingHistoryRollupMatrixManifest,
) -> Result<String> {
    if matrix.rollups.is_empty() {
        return Err(VmError::InvalidConfig(
            "decoding matrix template source must contain at least one layout rollup".to_string(),
        ));
    }

    let mut hasher = Blake2bVar::new(32).expect("blake2b-256");
    hasher.update(STWO_DECODING_MATRIX_ACCUMULATOR_VERSION_PHASE21.as_bytes());
    hasher.update(b"template");
    hasher.update(matrix.statement_version.as_bytes());
    hasher.update(matrix.proof_backend_version.as_bytes());
    hasher.update(&(matrix.total_layouts as u64).to_le_bytes());

    for (layout_index, rollup_manifest) in matrix.rollups.iter().enumerate() {
        let layout_commitment = commit_phase12_layout(&rollup_manifest.layout);
        hasher.update(&(layout_index as u64).to_le_bytes());
        hasher.update(layout_commitment.as_bytes());
        hasher.update(&(rollup_manifest.history_chunk_pairs as u64).to_le_bytes());
        hasher.update(&(rollup_manifest.max_rollup_segments as u64).to_le_bytes());
    }

    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("blake2b finalize");
    Ok(lower_hex(&out))
}

fn commit_phase21_matrix_accumulator(
    manifest: &Phase21DecodingMatrixAccumulatorManifest,
) -> Result<String> {
    if manifest.matrices.is_empty() {
        return Err(VmError::InvalidConfig(
            "decoding matrix accumulator must contain at least one matrix".to_string(),
        ));
    }

    let mut hasher = Blake2bVar::new(32).expect("blake2b-256");
    hasher.update(STWO_DECODING_MATRIX_ACCUMULATOR_VERSION_PHASE21.as_bytes());
    hasher.update(b"accumulator");
    hasher.update(manifest.template_commitment.as_bytes());
    hasher.update(&(manifest.total_matrices as u64).to_le_bytes());
    hasher.update(&(manifest.total_layouts as u64).to_le_bytes());
    hasher.update(&(manifest.total_rollups as u64).to_le_bytes());
    hasher.update(&(manifest.total_segments as u64).to_le_bytes());
    hasher.update(&(manifest.total_steps as u64).to_le_bytes());

    for (matrix_index, matrix) in manifest.matrices.iter().enumerate() {
        if matrix.public_state_boundary_commitment.is_empty() {
            return Err(VmError::InvalidConfig(format!(
                "decoding matrix accumulator matrix {matrix_index} has an empty public_state_boundary_commitment"
            )));
        }
        hasher.update(&(matrix_index as u64).to_le_bytes());
        hasher.update(matrix.matrix_version.as_bytes());
        hasher.update(matrix.semantic_scope.as_bytes());
        hasher.update(matrix.proof_backend_version.as_bytes());
        hasher.update(matrix.statement_version.as_bytes());
        hasher.update(&(matrix.total_layouts as u64).to_le_bytes());
        hasher.update(&(matrix.total_rollups as u64).to_le_bytes());
        hasher.update(&(matrix.total_segments as u64).to_le_bytes());
        hasher.update(&(matrix.total_steps as u64).to_le_bytes());
        hasher.update(matrix.public_state_boundary_commitment.as_bytes());
    }

    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("blake2b finalize");
    Ok(lower_hex(&out))
}

fn commit_phase22_lookup_template(
    accumulator: &Phase21DecodingMatrixAccumulatorManifest,
) -> Result<String> {
    if accumulator.matrices.is_empty() {
        return Err(VmError::InvalidConfig(
            "decoding lookup template source must contain at least one matrix".to_string(),
        ));
    }

    let mut hasher = Blake2bVar::new(32).expect("blake2b-256");
    hasher.update(STWO_DECODING_LOOKUP_ACCUMULATOR_VERSION_PHASE22.as_bytes());
    hasher.update(b"lookup-template");
    hasher.update(accumulator.template_commitment.as_bytes());
    hasher.update(accumulator.proof_backend_version.as_bytes());
    hasher.update(accumulator.statement_version.as_bytes());
    hasher.update(&(accumulator.total_matrices as u64).to_le_bytes());
    hasher.update(&(accumulator.total_layouts as u64).to_le_bytes());

    for (matrix_index, matrix) in accumulator.matrices.iter().enumerate() {
        hasher.update(&(matrix_index as u64).to_le_bytes());
        hasher.update(&(matrix.total_layouts as u64).to_le_bytes());
        hasher.update(matrix.public_state_boundary_commitment.as_bytes());
        for (layout_index, rollup_manifest) in matrix.rollups.iter().enumerate() {
            hasher.update(&(layout_index as u64).to_le_bytes());
            hasher.update(commit_phase12_layout(&rollup_manifest.layout).as_bytes());
            hasher.update(&(rollup_manifest.history_chunk_pairs as u64).to_le_bytes());
            hasher.update(&(rollup_manifest.max_rollup_segments as u64).to_le_bytes());
        }
    }

    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("blake2b finalize");
    Ok(lower_hex(&out))
}

fn commit_phase22_lookup_accumulator(
    manifest: &Phase22DecodingLookupAccumulatorManifest,
) -> Result<String> {
    if manifest.accumulator.matrices.is_empty() {
        return Err(VmError::InvalidConfig(
            "decoding lookup accumulator must contain at least one matrix".to_string(),
        ));
    }

    let mut hasher = Blake2bVar::new(32).expect("blake2b-256");
    hasher.update(STWO_DECODING_LOOKUP_ACCUMULATOR_VERSION_PHASE22.as_bytes());
    hasher.update(b"lookup-accumulator");
    hasher.update(manifest.lookup_template_commitment.as_bytes());
    hasher.update(manifest.source_accumulator_commitment.as_bytes());
    hasher.update(&(manifest.total_matrices as u64).to_le_bytes());
    hasher.update(&(manifest.total_layouts as u64).to_le_bytes());
    hasher.update(&(manifest.total_rollups as u64).to_le_bytes());
    hasher.update(&(manifest.total_segments as u64).to_le_bytes());
    hasher.update(&(manifest.total_steps as u64).to_le_bytes());
    hasher.update(&(manifest.lookup_delta_entries as u64).to_le_bytes());
    hasher.update(&(manifest.max_lookup_frontier_entries as u64).to_le_bytes());

    for (matrix_index, matrix) in manifest.accumulator.matrices.iter().enumerate() {
        hasher.update(&(matrix_index as u64).to_le_bytes());
        hasher.update(matrix.public_state_boundary_commitment.as_bytes());
        for (layout_index, rollup_manifest) in matrix.rollups.iter().enumerate() {
            hasher.update(&(layout_index as u64).to_le_bytes());
            for rollup in &rollup_manifest.rollups {
                if rollup
                    .global_from_state
                    .lookup_transcript_commitment
                    .is_empty()
                {
                    return Err(VmError::InvalidConfig(format!(
                        "decoding lookup accumulator matrix {matrix_index} layout {layout_index} rollup {} has an empty from-state lookup transcript commitment",
                        rollup.rollup_index
                    )));
                }
                if rollup
                    .global_to_state
                    .lookup_transcript_commitment
                    .is_empty()
                {
                    return Err(VmError::InvalidConfig(format!(
                        "decoding lookup accumulator matrix {matrix_index} layout {layout_index} rollup {} has an empty to-state lookup transcript commitment",
                        rollup.rollup_index
                    )));
                }
                if rollup
                    .global_from_state
                    .lookup_frontier_commitment
                    .is_empty()
                {
                    return Err(VmError::InvalidConfig(format!(
                        "decoding lookup accumulator matrix {matrix_index} layout {layout_index} rollup {} has an empty from-state lookup frontier commitment",
                        rollup.rollup_index
                    )));
                }
                if rollup.global_to_state.lookup_frontier_commitment.is_empty() {
                    return Err(VmError::InvalidConfig(format!(
                        "decoding lookup accumulator matrix {matrix_index} layout {layout_index} rollup {} has an empty to-state lookup frontier commitment",
                        rollup.rollup_index
                    )));
                }
                hasher.update(&(rollup.rollup_index as u64).to_le_bytes());
                hasher.update(&(rollup.global_start_step_index as u64).to_le_bytes());
                hasher.update(&(rollup.total_steps as u64).to_le_bytes());
                hasher.update(rollup.public_state_boundary_commitment.as_bytes());
                hasher.update(
                    rollup
                        .global_from_state
                        .lookup_transcript_commitment
                        .as_bytes(),
                );
                hasher.update(
                    &(rollup.global_from_state.lookup_transcript_entries as u64).to_le_bytes(),
                );
                hasher.update(
                    rollup
                        .global_to_state
                        .lookup_transcript_commitment
                        .as_bytes(),
                );
                hasher.update(
                    &(rollup.global_to_state.lookup_transcript_entries as u64).to_le_bytes(),
                );
                hasher.update(
                    rollup
                        .global_from_state
                        .lookup_frontier_commitment
                        .as_bytes(),
                );
                hasher.update(
                    &(rollup.global_from_state.lookup_frontier_entries as u64).to_le_bytes(),
                );
                hasher.update(rollup.global_to_state.lookup_frontier_commitment.as_bytes());
                hasher
                    .update(&(rollup.global_to_state.lookup_frontier_entries as u64).to_le_bytes());
            }
        }
    }

    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("blake2b finalize");
    Ok(lower_hex(&out))
}

fn commit_phase23_lookup_accumulator_with_summaries(
    manifest: &Phase23DecodingCrossStepLookupAccumulatorManifest,
    summaries: &[Phase23MemberSummary],
) -> Result<String> {
    if manifest.members.is_empty() {
        return Err(VmError::InvalidConfig(
            "decoding cross-step lookup accumulator must contain at least one member".to_string(),
        ));
    }
    if summaries.len() != manifest.members.len() {
        return Err(VmError::InvalidConfig(format!(
            "decoding cross-step lookup accumulator summaries.len()={} does not match members.len()={}",
            summaries.len(),
            manifest.members.len()
        )));
    }

    let mut hasher = Blake2bVar::new(32).expect("blake2b-256");
    hasher.update(STWO_DECODING_CROSS_STEP_LOOKUP_ACCUMULATOR_VERSION_PHASE23.as_bytes());
    hasher.update(b"cross-step-lookup-accumulator");
    hasher.update(manifest.source_template_commitment.as_bytes());
    hasher.update(manifest.lookup_template_commitment.as_bytes());
    hasher.update(manifest.start_boundary_commitment.as_bytes());
    hasher.update(manifest.end_boundary_commitment.as_bytes());
    hasher.update(&(manifest.member_count as u64).to_le_bytes());
    hasher.update(&(manifest.total_matrices as u64).to_le_bytes());
    hasher.update(&(manifest.total_layouts as u64).to_le_bytes());
    hasher.update(&(manifest.total_rollups as u64).to_le_bytes());
    hasher.update(&(manifest.total_segments as u64).to_le_bytes());
    hasher.update(&(manifest.total_steps as u64).to_le_bytes());
    hasher.update(&(manifest.lookup_delta_entries as u64).to_le_bytes());
    hasher.update(&(manifest.max_lookup_frontier_entries as u64).to_le_bytes());

    for (member_index, (member, summary)) in
        manifest.members.iter().zip(summaries.iter()).enumerate()
    {
        if member.lookup_accumulator_commitment.is_empty() {
            return Err(VmError::InvalidConfig(format!(
                "decoding cross-step lookup accumulator member {member_index} has an empty lookup_accumulator_commitment"
            )));
        }
        hasher.update(&(member_index as u64).to_le_bytes());
        hasher.update(member.lookup_accumulator_commitment.as_bytes());
        hasher.update(summary.start_boundary_commitment.as_bytes());
        hasher.update(summary.end_boundary_commitment.as_bytes());
        hasher.update(&(summary.total_matrices as u64).to_le_bytes());
        hasher.update(&(summary.total_layouts as u64).to_le_bytes());
        hasher.update(&(summary.total_rollups as u64).to_le_bytes());
        hasher.update(&(summary.total_segments as u64).to_le_bytes());
        hasher.update(&(summary.total_steps as u64).to_le_bytes());
        hasher.update(&(summary.lookup_delta_entries as u64).to_le_bytes());
        hasher.update(&(summary.max_lookup_frontier_entries as u64).to_le_bytes());
    }

    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("blake2b finalize");
    Ok(lower_hex(&out))
}

fn decoding_program_step_limit(program: &Program) -> Result<usize> {
    let instruction_count = program.instructions().len();
    let max_reachable_instructions = usize::from(u8::MAX) + 1;
    if instruction_count > max_reachable_instructions {
        return Err(VmError::InvalidConfig(format!(
            "Phase 12 decoding program instruction count {} exceeds the u8 pc horizon {}",
            instruction_count, max_reachable_instructions
        )));
    }
    Ok(instruction_count + 1)
}

fn commit_phase12_history_seed(
    layout_commitment: &str,
    kv_cache_values: &[i16],
    pair_width: usize,
) -> String {
    let mut hasher = Blake2bVar::new(32).expect("blake2b-256");
    hasher.update(STWO_DECODING_STATE_VERSION_PHASE12.as_bytes());
    hasher.update(layout_commitment.as_bytes());
    hasher.update(b"history-seed");
    hasher.update(&(pair_width as u64).to_le_bytes());
    hasher.update(&((kv_cache_values.len() / pair_width) as u64).to_le_bytes());
    for value in kv_cache_values {
        hasher.update(&value.to_le_bytes());
    }
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("blake2b finalize");
    lower_hex(&out)
}

fn commit_phase14_history_empty_chunk(layout_commitment: &str, pair_width: usize) -> String {
    let mut hasher = Blake2bVar::new(32).expect("blake2b-256");
    hasher.update(STWO_DECODING_STATE_VERSION_PHASE14.as_bytes());
    hasher.update(layout_commitment.as_bytes());
    hasher.update(b"history-open-empty");
    hasher.update(&(pair_width as u64).to_le_bytes());
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("blake2b finalize");
    lower_hex(&out)
}

fn commit_phase14_history_chunk(
    layout_commitment: &str,
    pair_width: usize,
    chunk_values: &[i16],
) -> String {
    let mut hasher = Blake2bVar::new(32).expect("blake2b-256");
    hasher.update(STWO_DECODING_STATE_VERSION_PHASE14.as_bytes());
    hasher.update(layout_commitment.as_bytes());
    hasher.update(b"history-chunk");
    hasher.update(&(pair_width as u64).to_le_bytes());
    hasher.update(&((chunk_values.len() / pair_width) as u64).to_le_bytes());
    for value in chunk_values {
        hasher.update(&value.to_le_bytes());
    }
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("blake2b finalize");
    lower_hex(&out)
}

fn fold_phase14_history_chunk(
    layout_commitment: &str,
    previous_sealed_commitment: &str,
    previous_sealed_chunks: usize,
    chunk_commitment: &str,
) -> String {
    let mut hasher = Blake2bVar::new(32).expect("blake2b-256");
    hasher.update(STWO_DECODING_STATE_VERSION_PHASE14.as_bytes());
    hasher.update(layout_commitment.as_bytes());
    hasher.update(b"history-sealed-fold");
    hasher.update(previous_sealed_commitment.as_bytes());
    hasher.update(&(previous_sealed_chunks as u64).to_le_bytes());
    hasher.update(chunk_commitment.as_bytes());
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("blake2b finalize");
    lower_hex(&out)
}

fn commit_phase14_history_total(
    layout_commitment: &str,
    sealed_commitment: &str,
    sealed_chunks: usize,
    open_chunk_commitment: &str,
    open_chunk_pairs: usize,
    chunk_size: usize,
    history_length: usize,
) -> String {
    let mut hasher = Blake2bVar::new(32).expect("blake2b-256");
    hasher.update(STWO_DECODING_STATE_VERSION_PHASE14.as_bytes());
    hasher.update(layout_commitment.as_bytes());
    hasher.update(b"history-total");
    hasher.update(sealed_commitment.as_bytes());
    hasher.update(&(sealed_chunks as u64).to_le_bytes());
    hasher.update(open_chunk_commitment.as_bytes());
    hasher.update(&(open_chunk_pairs as u64).to_le_bytes());
    hasher.update(&(chunk_size as u64).to_le_bytes());
    hasher.update(&(history_length as u64).to_le_bytes());
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("blake2b finalize");
    lower_hex(&out)
}

fn commit_phase19_lookup_transcript_seed(
    layout_commitment: &str,
    lookup_rows_commitment: &str,
) -> String {
    let mut hasher = Blake2bVar::new(32).expect("blake2b-256");
    hasher.update(STWO_DECODING_STATE_VERSION_PHASE14.as_bytes());
    hasher.update(layout_commitment.as_bytes());
    hasher.update(b"lookup-transcript-seed");
    hasher.update(&(1u64).to_le_bytes());
    hasher.update(lookup_rows_commitment.as_bytes());
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("blake2b finalize");
    lower_hex(&out)
}

fn fold_phase19_lookup_transcript(
    layout_commitment: &str,
    previous_commitment: &str,
    previous_entries: usize,
    lookup_rows_commitment: &str,
) -> String {
    let mut hasher = Blake2bVar::new(32).expect("blake2b-256");
    hasher.update(STWO_DECODING_STATE_VERSION_PHASE14.as_bytes());
    hasher.update(layout_commitment.as_bytes());
    hasher.update(b"lookup-transcript-fold");
    hasher.update(previous_commitment.as_bytes());
    hasher.update(&(previous_entries as u64).to_le_bytes());
    hasher.update(lookup_rows_commitment.as_bytes());
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("blake2b finalize");
    lower_hex(&out)
}

fn commit_phase20_lookup_frontier(
    layout_commitment: &str,
    lookup_rows_commitments: &[String],
) -> String {
    let mut hasher = Blake2bVar::new(32).expect("blake2b-256");
    hasher.update(STWO_DECODING_STATE_VERSION_PHASE14.as_bytes());
    hasher.update(layout_commitment.as_bytes());
    hasher.update(b"lookup-frontier");
    hasher.update(&(lookup_rows_commitments.len() as u64).to_le_bytes());
    for commitment in lookup_rows_commitments {
        hasher.update(commitment.as_bytes());
    }
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("blake2b finalize");
    lower_hex(&out)
}

fn seed_phase14_history(
    layout_commitment: &str,
    kv_cache_values: &[i16],
    lookup_rows_commitment: &str,
    pair_width: usize,
) -> Phase14HistoryAccumulator {
    let mut sealed_commitment = commit_phase14_history_empty_chunk(layout_commitment, pair_width);
    let mut sealed_chunks = 0usize;
    let mut open_chunk_pairs = 0usize;
    let mut open_chunk_values = Vec::new();

    for pair in kv_cache_values.chunks(pair_width) {
        open_chunk_values.extend_from_slice(pair);
        open_chunk_pairs += 1;
        if open_chunk_pairs == PHASE14_HISTORY_CHUNK_PAIRS {
            let chunk_commitment =
                commit_phase14_history_chunk(layout_commitment, pair_width, &open_chunk_values);
            sealed_commitment = fold_phase14_history_chunk(
                layout_commitment,
                &sealed_commitment,
                sealed_chunks,
                &chunk_commitment,
            );
            sealed_chunks += 1;
            open_chunk_pairs = 0;
            open_chunk_values.clear();
        }
    }

    let open_chunk_commitment = if open_chunk_pairs == 0 {
        commit_phase14_history_empty_chunk(layout_commitment, pair_width)
    } else {
        commit_phase14_history_chunk(layout_commitment, pair_width, &open_chunk_values)
    };
    let history_length = kv_cache_values.len() / pair_width;
    let history_commitment = commit_phase14_history_total(
        layout_commitment,
        &sealed_commitment,
        sealed_chunks,
        &open_chunk_commitment,
        open_chunk_pairs,
        PHASE14_HISTORY_CHUNK_PAIRS,
        history_length,
    );
    let frontier_values = kv_cache_values.to_vec();
    Phase14HistoryAccumulator {
        history_commitment,
        history_length,
        chunk_size: PHASE14_HISTORY_CHUNK_PAIRS,
        sealed_commitment,
        sealed_chunks,
        open_chunk_commitment,
        open_chunk_pairs,
        frontier_commitment: commit_phase12_named_slice(
            "kv-cache",
            layout_commitment,
            &frontier_values,
        ),
        frontier_pairs: history_length,
        frontier_values,
        lookup_transcript_commitment: commit_phase19_lookup_transcript_seed(
            layout_commitment,
            lookup_rows_commitment,
        ),
        lookup_transcript_entries: 1,
        lookup_frontier_commitment: commit_phase20_lookup_frontier(
            layout_commitment,
            &[lookup_rows_commitment.to_string()],
        ),
        lookup_frontier_entries: 1,
        lookup_frontier_values: vec![lookup_rows_commitment.to_string()],
    }
}

fn advance_phase14_open_chunk(
    layout_commitment: &str,
    previous_open_chunk_commitment: &str,
    previous_open_chunk_pairs: usize,
    appended_pair: &[i16],
    pair_width: usize,
) -> String {
    let mut hasher = Blake2bVar::new(32).expect("blake2b-256");
    hasher.update(STWO_DECODING_STATE_VERSION_PHASE14.as_bytes());
    hasher.update(layout_commitment.as_bytes());
    hasher.update(b"history-open-advance");
    hasher.update(previous_open_chunk_commitment.as_bytes());
    hasher.update(&(previous_open_chunk_pairs as u64).to_le_bytes());
    hasher.update(&(pair_width as u64).to_le_bytes());
    for value in appended_pair {
        hasher.update(&value.to_le_bytes());
    }
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("blake2b finalize");
    lower_hex(&out)
}

fn advance_phase14_history(
    layout_commitment: &str,
    previous: &Phase14HistoryAccumulator,
    appended_pair: &[i16],
    lookup_rows_commitment: &str,
    pair_width: usize,
) -> Result<Phase14HistoryAccumulator> {
    if appended_pair.len() != pair_width {
        return Err(VmError::InvalidConfig(format!(
            "chunked decoding history append expects pair_width={} values, got {}",
            pair_width,
            appended_pair.len()
        )));
    }
    let next_history_length = previous.history_length.checked_add(1).ok_or_else(|| {
        VmError::InvalidConfig(format!(
            "chunked decoding history length {} cannot be incremented",
            previous.history_length
        ))
    })?;

    let advanced_open_commitment = advance_phase14_open_chunk(
        layout_commitment,
        &previous.open_chunk_commitment,
        previous.open_chunk_pairs,
        appended_pair,
        pair_width,
    );
    let next_open_chunk_pairs = previous.open_chunk_pairs + 1;

    let (sealed_commitment, sealed_chunks, open_chunk_commitment, open_chunk_pairs) =
        if next_open_chunk_pairs == previous.chunk_size {
            let next_sealed_commitment = fold_phase14_history_chunk(
                layout_commitment,
                &previous.sealed_commitment,
                previous.sealed_chunks,
                &advanced_open_commitment,
            );
            (
                next_sealed_commitment,
                previous.sealed_chunks + 1,
                commit_phase14_history_empty_chunk(layout_commitment, pair_width),
                0,
            )
        } else {
            (
                previous.sealed_commitment.clone(),
                previous.sealed_chunks,
                advanced_open_commitment,
                next_open_chunk_pairs,
            )
        };
    let history_commitment = commit_phase14_history_total(
        layout_commitment,
        &sealed_commitment,
        sealed_chunks,
        &open_chunk_commitment,
        open_chunk_pairs,
        previous.chunk_size,
        next_history_length,
    );
    let frontier_value_capacity =
        previous
            .frontier_pairs
            .checked_mul(pair_width)
            .ok_or_else(|| {
                VmError::InvalidConfig(
                    "chunked decoding frontier value capacity overflowed".to_string(),
                )
            })?;
    let mut frontier_values = previous.frontier_values.clone();
    frontier_values.extend_from_slice(appended_pair);
    if frontier_values.len() > frontier_value_capacity {
        let keep_from = frontier_values.len() - frontier_value_capacity;
        frontier_values = frontier_values[keep_from..].to_vec();
    }
    let lookup_transcript_entries = previous
        .lookup_transcript_entries
        .checked_add(1)
        .ok_or_else(|| {
            VmError::InvalidConfig(
                "chunked decoding lookup transcript length overflowed".to_string(),
            )
        })?;
    let mut lookup_frontier_values = previous.lookup_frontier_values.clone();
    lookup_frontier_values.push(lookup_rows_commitment.to_string());
    if lookup_frontier_values.len() > PHASE14_HISTORY_CHUNK_PAIRS {
        let keep_from = lookup_frontier_values.len() - PHASE14_HISTORY_CHUNK_PAIRS;
        lookup_frontier_values = lookup_frontier_values[keep_from..].to_vec();
    }
    Ok(Phase14HistoryAccumulator {
        history_commitment,
        history_length: next_history_length,
        chunk_size: previous.chunk_size,
        sealed_commitment,
        sealed_chunks,
        open_chunk_commitment,
        open_chunk_pairs,
        frontier_commitment: commit_phase12_named_slice(
            "kv-cache",
            layout_commitment,
            &frontier_values,
        ),
        frontier_pairs: previous.frontier_pairs,
        frontier_values,
        lookup_transcript_commitment: fold_phase19_lookup_transcript(
            layout_commitment,
            &previous.lookup_transcript_commitment,
            previous.lookup_transcript_entries,
            lookup_rows_commitment,
        ),
        lookup_transcript_entries,
        lookup_frontier_commitment: commit_phase20_lookup_frontier(
            layout_commitment,
            &lookup_frontier_values,
        ),
        lookup_frontier_entries: lookup_frontier_values.len(),
        lookup_frontier_values,
    })
}

fn advance_phase12_history_commitment(
    layout_commitment: &str,
    previous_commitment: &str,
    appended_pair: &[i16],
    next_length: usize,
) -> String {
    let mut hasher = Blake2bVar::new(32).expect("blake2b-256");
    hasher.update(STWO_DECODING_STATE_VERSION_PHASE12.as_bytes());
    hasher.update(layout_commitment.as_bytes());
    hasher.update(b"history-advance");
    hasher.update(previous_commitment.as_bytes());
    hasher.update(&(next_length as u64).to_le_bytes());
    hasher.update(&(appended_pair.len() as u64).to_le_bytes());
    for value in appended_pair {
        hasher.update(&value.to_le_bytes());
    }
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("blake2b finalize");
    lower_hex(&out)
}

fn phase11_demo_initial_memories() -> Vec<Vec<i16>> {
    vec![
        vec![
            0, 0, 0, 0, 0, 0, 2, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ],
        vec![
            0, 0, 0, 0, 2, 1, 3, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1,
        ],
        vec![
            0, 0, 2, 1, 3, 2, 4, 3, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 1,
        ],
    ]
}

fn write_phase12_noncanonical_lookup_seed(memory: &mut [i16], lookup: std::ops::Range<usize>) {
    let slice = &mut memory[lookup];
    assert_eq!(
        slice.len(),
        PHASE12_LOOKUP_ROW_VALUES.len(),
        "Phase 12 lookup seed length mismatch"
    );
    for (cell, &value) in slice.iter_mut().zip(PHASE12_LOOKUP_ROW_VALUES.iter()) {
        *cell = value.saturating_add(1);
    }
}

pub(crate) fn phase12_demo_initial_memories(
    layout: &Phase12DecodingLayout,
) -> Result<Vec<Vec<i16>>> {
    layout.validate()?;
    let kv_cache_range = layout.kv_cache_range()?;
    let incoming_token_range = layout.incoming_token_range()?;
    let query_range = layout.query_range()?;
    let lookup_range = layout.lookup_range()?;
    let position_index = layout.position_index()?;
    let position_increment_index = layout.position_increment_index()?;
    let mut kv_cache = vec![0; kv_cache_range.len()];

    let mut memories = Vec::with_capacity(3);
    for position in 0..3 {
        let incoming_values = phase12_demo_incoming_values(layout.pair_width, position);
        let query_values = phase12_demo_query_values(layout.pair_width, position);
        let mut memory = vec![0; layout.memory_size()?];
        memory[kv_cache_range.clone()].copy_from_slice(&kv_cache);
        memory[incoming_token_range.clone()].copy_from_slice(&incoming_values);
        memory[query_range.clone()].copy_from_slice(&query_values);
        write_phase12_noncanonical_lookup_seed(&mut memory, lookup_range.clone());
        memory[position_index] = position as i16;
        memory[position_increment_index] = 1;
        let program = decoding_step_v2_program_with_initial_memory(layout, memory.clone())?;
        let step_limit = decoding_program_step_limit(&program)?;
        let mut runtime = NativeInterpreter::new(program, Attention2DMode::AverageHard, step_limit);
        let result = runtime.run()?;
        if !result.halted {
            return Err(VmError::InvalidConfig(format!(
                "Phase 12 demo seed generation did not halt within {} steps",
                step_limit
            )));
        }
        kv_cache.copy_from_slice(&result.final_state.memory[kv_cache_range.clone()]);
        memories.push(memory);
    }
    Ok(memories)
}

fn phase12_demo_incoming_values(pair_width: usize, step_index: usize) -> Vec<i16> {
    (0..pair_width)
        .map(|offset| ((step_index + 1) as i16) * (offset as i16 + 1))
        .collect()
}

fn phase12_demo_query_values(pair_width: usize, step_index: usize) -> Vec<i16> {
    (0..pair_width)
        .map(|offset| ((step_index + offset + 1) % 3) as i16)
        .collect()
}

fn lower_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

pub fn matches_decoding_step_v1_family(program: &Program) -> bool {
    if program.memory_size() != 23 {
        return false;
    }
    let template = match decoding_step_v1_template_program() {
        Ok(program) => program,
        Err(_) => return false,
    };
    program.instructions() == template.instructions()
}

pub fn infer_phase12_decoding_layout(program: &Program) -> Option<Phase12DecodingLayout> {
    if program.memory_size() <= PHASE12_OUTPUT_WIDTH + PHASE12_SHARED_LOOKUP_ROWS + 2 {
        return None;
    }
    let payload_cells =
        program.memory_size() - (PHASE12_OUTPUT_WIDTH + PHASE12_SHARED_LOOKUP_ROWS + 2);
    for pair_width in 1..=payload_cells {
        if payload_cells % pair_width != 0 {
            continue;
        }
        let units = payload_cells / pair_width;
        if units < 3 {
            continue;
        }
        let rolling_kv_pairs = units - 2;
        let layout = Phase12DecodingLayout::new(rolling_kv_pairs, pair_width).ok()?;
        let template = decoding_step_v2_template_program(&layout).ok()?;
        if program.memory_size() == template.memory_size()
            && program.instructions() == template.instructions()
        {
            return Some(layout);
        }
    }
    None
}

pub fn matches_decoding_step_v2_family(program: &Program) -> bool {
    infer_phase12_decoding_layout(program).is_some()
}

pub fn matches_decoding_step_v2_family_with_layout(
    program: &Program,
    layout: &Phase12DecodingLayout,
) -> bool {
    let template = match decoding_step_v2_template_program(layout) {
        Ok(program) => program,
        Err(_) => return false,
    };
    program.memory_size() == template.memory_size()
        && program.instructions() == template.instructions()
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;
    use crate::instruction::Program;
    use crate::proof::{
        production_v1_stark_options, VanillaStarkExecutionClaim, VanillaStarkExecutionProof,
    };
    use crate::state::MachineState;

    fn phase12_step_header_is_valid(
        from_state_version: &str,
        to_state_version: &str,
        from_step_index: usize,
        to_step_index: usize,
        from_layout_commitment: &str,
        to_layout_commitment: &str,
        expected_layout_commitment: &str,
        from_position: i16,
        to_position: i16,
    ) -> bool {
        from_state_version == STWO_DECODING_STATE_VERSION_PHASE12
            && to_state_version == STWO_DECODING_STATE_VERSION_PHASE12
            && from_step_index + 1 == to_step_index
            && from_layout_commitment == expected_layout_commitment
            && to_layout_commitment == expected_layout_commitment
            && from_position.checked_add(1) == Some(to_position)
    }

    fn phase12_link_is_valid(
        public_state_matches: bool,
        persistent_state_matches: bool,
        kv_cache_matches: bool,
        position_matches: bool,
        kv_history_commitment_matches: bool,
        kv_history_length_matches: bool,
    ) -> bool {
        public_state_matches
            && persistent_state_matches
            && kv_cache_matches
            && position_matches
            && kv_history_commitment_matches
            && kv_history_length_matches
    }

    fn phase12_claim_bindings_are_valid(
        statement_version_matches: bool,
        semantic_scope_matches: bool,
        artifact_commitment_matches: bool,
    ) -> bool {
        statement_version_matches && semantic_scope_matches && artifact_commitment_matches
    }

    fn phase12_state_progress_is_valid(
        from_history_length: usize,
        to_history_length: usize,
        from_position: i16,
        to_position: i16,
    ) -> bool {
        from_history_length.checked_add(1) == Some(to_history_length)
            && from_position.checked_add(1) == Some(to_position)
    }

    fn phase14_step_header_is_valid(
        from_state_version: &str,
        to_state_version: &str,
        from_step_index: usize,
        to_step_index: usize,
        from_layout_commitment: &str,
        to_layout_commitment: &str,
        expected_layout_commitment: &str,
        from_chunk_size: usize,
        to_chunk_size: usize,
        history_chunk_pairs: usize,
        from_frontier_pairs: usize,
        to_frontier_pairs: usize,
        rolling_kv_pairs: usize,
        from_frontier_matches_cache: bool,
        to_frontier_matches_cache: bool,
        from_lookup_transcript_entries: usize,
        to_lookup_transcript_entries: usize,
        from_lookup_frontier_entries: usize,
        to_lookup_frontier_entries: usize,
        from_position: i16,
        to_position: i16,
    ) -> bool {
        let expected_next_lookup_frontier_entries =
            (from_lookup_frontier_entries + 1).min(history_chunk_pairs);
        from_state_version == STWO_DECODING_STATE_VERSION_PHASE14
            && to_state_version == STWO_DECODING_STATE_VERSION_PHASE14
            && from_step_index + 1 == to_step_index
            && from_layout_commitment == to_layout_commitment
            && from_layout_commitment == expected_layout_commitment
            && from_chunk_size == history_chunk_pairs
            && to_chunk_size == history_chunk_pairs
            && from_frontier_pairs == rolling_kv_pairs
            && to_frontier_pairs == rolling_kv_pairs
            && from_frontier_matches_cache
            && to_frontier_matches_cache
            && from_lookup_transcript_entries > 0
            && to_lookup_transcript_entries == from_lookup_transcript_entries + 1
            && from_lookup_frontier_entries > 0
            && from_lookup_frontier_entries <= history_chunk_pairs
            && to_lookup_frontier_entries > 0
            && to_lookup_frontier_entries <= history_chunk_pairs
            && to_lookup_frontier_entries == expected_next_lookup_frontier_entries
            && from_position.checked_add(1) == Some(to_position)
    }

    fn phase14_link_is_valid(
        public_state_matches: bool,
        persistent_state_matches: bool,
        kv_cache_matches: bool,
        position_matches: bool,
        kv_history_commitment_matches: bool,
        kv_history_length_matches: bool,
        kv_history_sealed_commitment_matches: bool,
        kv_history_sealed_chunks_matches: bool,
        kv_history_open_chunk_commitment_matches: bool,
        kv_history_open_chunk_pairs_matches: bool,
        kv_history_frontier_commitment_matches: bool,
        kv_history_frontier_pairs_matches: bool,
        lookup_transcript_commitment_matches: bool,
        lookup_transcript_entries_matches: bool,
        lookup_frontier_commitment_matches: bool,
        lookup_frontier_entries_matches: bool,
    ) -> bool {
        public_state_matches
            && persistent_state_matches
            && kv_cache_matches
            && position_matches
            && kv_history_commitment_matches
            && kv_history_length_matches
            && kv_history_sealed_commitment_matches
            && kv_history_sealed_chunks_matches
            && kv_history_open_chunk_commitment_matches
            && kv_history_open_chunk_pairs_matches
            && kv_history_frontier_commitment_matches
            && kv_history_frontier_pairs_matches
            && lookup_transcript_commitment_matches
            && lookup_transcript_entries_matches
            && lookup_frontier_commitment_matches
            && lookup_frontier_entries_matches
    }

    fn phase14_claim_bindings_are_valid(
        statement_version_matches: bool,
        semantic_scope_matches: bool,
        artifact_commitment_matches: bool,
    ) -> bool {
        statement_version_matches && semantic_scope_matches && artifact_commitment_matches
    }

    fn phase14_state_progress_is_valid(
        from_history_length: usize,
        to_history_length: usize,
        from_lookup_transcript_entries: usize,
        to_lookup_transcript_entries: usize,
        from_position: i16,
        to_position: i16,
    ) -> bool {
        from_history_length.checked_add(1) == Some(to_history_length)
            && from_lookup_transcript_entries.checked_add(1) == Some(to_lookup_transcript_entries)
            && from_position.checked_add(1) == Some(to_position)
    }

    fn kani_dummy_proof() -> VanillaStarkExecutionProof {
        VanillaStarkExecutionProof {
            proof_backend: StarkProofBackend::Stwo,
            proof_backend_version: "kani-stwo-test-proof".to_string(),
            stwo_auxiliary: None,
            claim: VanillaStarkExecutionClaim {
                statement_version: "statement-v1".to_string(),
                semantic_scope: "native_isa_execution_with_transformer_native_equivalence_check"
                    .to_string(),
                program: Program::new(vec![], 1),
                attention_mode: Attention2DMode::AverageHard,
                transformer_config: None,
                steps: 0,
                final_state: MachineState::with_memory(vec![0]),
                options: production_v1_stark_options(),
                equivalence: None,
                commitments: None,
            },
            proof: vec![],
        }
    }

    fn kani_phase12_step(
        layout_commitment: &str,
        from_step_index: usize,
        to_step_index: usize,
        from_position: i16,
        to_position: i16,
    ) -> Phase12DecodingStep {
        let from_state = Phase12DecodingState {
            state_version: STWO_DECODING_STATE_VERSION_PHASE12.to_string(),
            step_index: from_step_index,
            position: from_position,
            layout_commitment: layout_commitment.to_string(),
            persistent_state_commitment: "persistent".to_string(),
            kv_history_commitment: "history".to_string(),
            kv_history_length: 1,
            kv_cache_commitment: "cache".to_string(),
            incoming_token_commitment: "incoming".to_string(),
            query_commitment: "query".to_string(),
            output_commitment: "output".to_string(),
            lookup_rows_commitment: "lookup".to_string(),
            public_state_commitment: String::new(),
        };
        let from_state = Phase12DecodingState {
            public_state_commitment: commit_phase12_public_state(&from_state),
            ..from_state
        };
        let to_state = Phase12DecodingState {
            state_version: STWO_DECODING_STATE_VERSION_PHASE12.to_string(),
            step_index: to_step_index,
            position: to_position,
            layout_commitment: layout_commitment.to_string(),
            persistent_state_commitment: "persistent-next".to_string(),
            kv_history_commitment: "history-next".to_string(),
            kv_history_length: 2,
            kv_cache_commitment: "cache-next".to_string(),
            incoming_token_commitment: "incoming-next".to_string(),
            query_commitment: "query-next".to_string(),
            output_commitment: "output-next".to_string(),
            lookup_rows_commitment: "lookup-next".to_string(),
            public_state_commitment: String::new(),
        };
        let to_state = Phase12DecodingState {
            public_state_commitment: commit_phase12_public_state(&to_state),
            ..to_state
        };
        Phase12DecodingStep {
            from_state,
            to_state,
            shared_lookup_artifact_commitment: "artifact".to_string(),
            proof: kani_dummy_proof(),
        }
    }

    fn kani_phase14_step(
        layout_commitment: &str,
        history_chunk_pairs: usize,
        rolling_kv_pairs: usize,
        from_step_index: usize,
        to_step_index: usize,
        from_position: i16,
        to_position: i16,
    ) -> Phase14DecodingStep {
        let from_state = Phase14DecodingState {
            state_version: STWO_DECODING_STATE_VERSION_PHASE14.to_string(),
            step_index: from_step_index,
            position: from_position,
            layout_commitment: layout_commitment.to_string(),
            persistent_state_commitment: "persistent".to_string(),
            kv_history_commitment: "history".to_string(),
            kv_history_length: 1,
            kv_history_chunk_size: history_chunk_pairs,
            kv_history_sealed_commitment: "sealed".to_string(),
            kv_history_sealed_chunks: 0,
            kv_history_open_chunk_commitment: "open".to_string(),
            kv_history_open_chunk_pairs: 1,
            kv_history_frontier_commitment: "cache".to_string(),
            kv_history_frontier_pairs: rolling_kv_pairs,
            lookup_transcript_commitment: "lookup-transcript".to_string(),
            lookup_transcript_entries: 1,
            lookup_frontier_commitment: "lookup-frontier".to_string(),
            lookup_frontier_entries: 1,
            kv_cache_commitment: "cache".to_string(),
            incoming_token_commitment: "incoming".to_string(),
            query_commitment: "query".to_string(),
            output_commitment: "output".to_string(),
            lookup_rows_commitment: "lookup".to_string(),
            public_state_commitment: String::new(),
        };
        let from_state = Phase14DecodingState {
            public_state_commitment: commit_phase14_public_state(&from_state),
            ..from_state
        };
        let to_state = Phase14DecodingState {
            state_version: STWO_DECODING_STATE_VERSION_PHASE14.to_string(),
            step_index: to_step_index,
            position: to_position,
            layout_commitment: layout_commitment.to_string(),
            persistent_state_commitment: "persistent-next".to_string(),
            kv_history_commitment: "history-next".to_string(),
            kv_history_length: 2,
            kv_history_chunk_size: history_chunk_pairs,
            kv_history_sealed_commitment: "sealed-next".to_string(),
            kv_history_sealed_chunks: 1,
            kv_history_open_chunk_commitment: "open-next".to_string(),
            kv_history_open_chunk_pairs: 1,
            kv_history_frontier_commitment: "cache-next".to_string(),
            kv_history_frontier_pairs: rolling_kv_pairs,
            lookup_transcript_commitment: "lookup-transcript-next".to_string(),
            lookup_transcript_entries: 2,
            lookup_frontier_commitment: "lookup-frontier-next".to_string(),
            lookup_frontier_entries: 2,
            kv_cache_commitment: "cache-next".to_string(),
            incoming_token_commitment: "incoming-next".to_string(),
            query_commitment: "query-next".to_string(),
            output_commitment: "output-next".to_string(),
            lookup_rows_commitment: "lookup-next".to_string(),
            public_state_commitment: String::new(),
        };
        let to_state = Phase14DecodingState {
            public_state_commitment: commit_phase14_public_state(&to_state),
            ..to_state
        };
        Phase14DecodingStep {
            from_state,
            to_state,
            shared_lookup_artifact_commitment: "artifact".to_string(),
            proof: kani_dummy_proof(),
        }
    }

    #[kani::proof]
    fn kani_phase12_validate_accepts_canonical_single_step() {
        assert!(phase12_step_header_is_valid(
            STWO_DECODING_STATE_VERSION_PHASE12,
            STWO_DECODING_STATE_VERSION_PHASE12,
            0,
            1,
            "layout-commitment",
            "layout-commitment",
            "layout-commitment",
            0,
            1,
        ));
    }

    #[kani::proof]
    fn kani_phase12_validator_accepts_canonical_single_step() {
        let layout_commitment = "layout-commitment".to_string();
        let step = kani_phase12_step(&layout_commitment, 0, 1, 0, 1);
        assert!(validate_phase12_chain_steps_against_layout_commitment(
            &layout_commitment,
            &[step]
        )
        .is_ok());
    }

    #[kani::proof]
    fn kani_phase12_validate_rejects_step_index_drift() {
        let bad_index = kani::any::<usize>();
        kani::assume(bad_index != 1);
        assert!(!phase12_step_header_is_valid(
            STWO_DECODING_STATE_VERSION_PHASE12,
            STWO_DECODING_STATE_VERSION_PHASE12,
            0,
            bad_index,
            "layout-commitment",
            "layout-commitment",
            "layout-commitment",
            0,
            1,
        ));
    }

    #[kani::proof]
    fn kani_phase12_validator_rejects_step_index_drift() {
        let layout_commitment = "layout-commitment".to_string();
        let bad_index = kani::any::<usize>();
        kani::assume(bad_index != 1);
        let step = kani_phase12_step(&layout_commitment, 0, bad_index, 0, 1);
        assert!(validate_phase12_chain_steps_against_layout_commitment(
            &layout_commitment,
            &[step]
        )
        .is_err());
    }

    #[kani::proof]
    fn kani_phase12_validate_rejects_any_link_mismatch() {
        let which = kani::any::<u8>();
        kani::assume(which < 6);
        let mut public_state_matches = true;
        let mut persistent_state_matches = true;
        let mut kv_cache_matches = true;
        let mut position_matches = true;
        let mut kv_history_commitment_matches = true;
        let mut kv_history_length_matches = true;
        match which {
            0 => public_state_matches = false,
            1 => persistent_state_matches = false,
            2 => kv_cache_matches = false,
            3 => position_matches = false,
            4 => kv_history_commitment_matches = false,
            _ => kv_history_length_matches = false,
        }
        assert!(!phase12_link_is_valid(
            public_state_matches,
            persistent_state_matches,
            kv_cache_matches,
            position_matches,
            kv_history_commitment_matches,
            kv_history_length_matches,
        ));
    }

    #[kani::proof]
    fn kani_phase12_claim_bindings_accept_canonical_single_step() {
        assert!(phase12_claim_bindings_are_valid(true, true, true));
    }

    #[kani::proof]
    fn kani_phase12_claim_bindings_reject_any_binding_mismatch() {
        let which = kani::any::<u8>();
        kani::assume(which < 3);
        let mut statement_version_matches = true;
        let mut semantic_scope_matches = true;
        let mut artifact_commitment_matches = true;
        match which {
            0 => statement_version_matches = false,
            1 => semantic_scope_matches = false,
            _ => artifact_commitment_matches = false,
        }
        assert!(!phase12_claim_bindings_are_valid(
            statement_version_matches,
            semantic_scope_matches,
            artifact_commitment_matches,
        ));
    }

    #[kani::proof]
    fn kani_phase12_state_progress_accepts_canonical_single_step() {
        assert!(phase12_state_progress_is_valid(1, 2, 0, 1));
    }

    #[kani::proof]
    fn kani_phase12_state_progress_rejects_any_progress_mismatch() {
        let which = kani::any::<u8>();
        kani::assume(which < 2);
        let mut to_history_length = 2usize;
        let mut to_position = 1i16;
        match which {
            0 => to_history_length = 3,
            _ => to_position = 2,
        }
        assert!(!phase12_state_progress_is_valid(
            1,
            to_history_length,
            0,
            to_position
        ));
    }

    #[kani::proof]
    fn kani_phase14_validate_accepts_canonical_single_step() {
        assert!(phase14_step_header_is_valid(
            STWO_DECODING_STATE_VERSION_PHASE14,
            STWO_DECODING_STATE_VERSION_PHASE14,
            0,
            1,
            "layout-commitment",
            "layout-commitment",
            "layout-commitment",
            PHASE14_HISTORY_CHUNK_PAIRS,
            PHASE14_HISTORY_CHUNK_PAIRS,
            PHASE14_HISTORY_CHUNK_PAIRS,
            4,
            4,
            4,
            true,
            true,
            1,
            2,
            1,
            2,
            0,
            1,
        ));
    }

    #[kani::proof]
    fn kani_phase14_validator_accepts_canonical_single_step() {
        let layout = Phase12DecodingLayout::new(4, 4).expect("valid Phase 12 layout");
        let layout_commitment = "layout-commitment".to_string();
        let step = kani_phase14_step(
            &layout_commitment,
            PHASE14_HISTORY_CHUNK_PAIRS,
            layout.rolling_kv_pairs,
            0,
            1,
            0,
            1,
        );
        assert!(validate_phase14_chain_steps_against_layout_commitment(
            &layout,
            &layout_commitment,
            PHASE14_HISTORY_CHUNK_PAIRS,
            &[step],
        )
        .is_ok());
    }

    #[kani::proof]
    fn kani_phase14_validate_rejects_wrong_chunk_size() {
        assert!(!phase14_step_header_is_valid(
            STWO_DECODING_STATE_VERSION_PHASE14,
            STWO_DECODING_STATE_VERSION_PHASE14,
            0,
            1,
            "layout-commitment",
            "layout-commitment",
            "layout-commitment",
            PHASE14_HISTORY_CHUNK_PAIRS,
            PHASE14_HISTORY_CHUNK_PAIRS + 1,
            PHASE14_HISTORY_CHUNK_PAIRS,
            4,
            4,
            4,
            true,
            true,
            1,
            2,
            1,
            2,
            0,
            1,
        ));
    }

    #[kani::proof]
    fn kani_phase14_validator_rejects_wrong_chunk_size() {
        let layout = Phase12DecodingLayout::new(4, 4).expect("valid Phase 12 layout");
        let layout_commitment = "layout-commitment".to_string();
        let mut step = kani_phase14_step(
            &layout_commitment,
            PHASE14_HISTORY_CHUNK_PAIRS,
            layout.rolling_kv_pairs,
            0,
            1,
            0,
            1,
        );
        step.to_state.kv_history_chunk_size = PHASE14_HISTORY_CHUNK_PAIRS + 1;
        assert!(validate_phase14_chain_steps_against_layout_commitment(
            &layout,
            &layout_commitment,
            PHASE14_HISTORY_CHUNK_PAIRS,
            &[step],
        )
        .is_err());
    }

    #[kani::proof]
    fn kani_phase14_validate_rejects_frontier_commitment_drift() {
        assert!(!phase14_step_header_is_valid(
            STWO_DECODING_STATE_VERSION_PHASE14,
            STWO_DECODING_STATE_VERSION_PHASE14,
            0,
            1,
            "layout-commitment",
            "layout-commitment",
            "layout-commitment",
            PHASE14_HISTORY_CHUNK_PAIRS,
            PHASE14_HISTORY_CHUNK_PAIRS,
            PHASE14_HISTORY_CHUNK_PAIRS,
            4,
            4,
            4,
            false,
            true,
            1,
            2,
            1,
            2,
            0,
            1,
        ));
    }

    #[kani::proof]
    fn kani_phase14_validate_rejects_any_link_mismatch() {
        let which = kani::any::<u8>();
        kani::assume(which < 16);
        let mut flags = [true; 16];
        flags[which as usize] = false;
        assert!(!phase14_link_is_valid(
            flags[0], flags[1], flags[2], flags[3], flags[4], flags[5], flags[6], flags[7],
            flags[8], flags[9], flags[10], flags[11], flags[12], flags[13], flags[14], flags[15],
        ));
    }

    #[kani::proof]
    fn kani_phase14_claim_bindings_accept_canonical_single_step() {
        assert!(phase14_claim_bindings_are_valid(true, true, true));
    }

    #[kani::proof]
    fn kani_phase14_claim_bindings_reject_any_binding_mismatch() {
        let which = kani::any::<u8>();
        kani::assume(which < 3);
        let mut statement_version_matches = true;
        let mut semantic_scope_matches = true;
        let mut artifact_commitment_matches = true;
        match which {
            0 => statement_version_matches = false,
            1 => semantic_scope_matches = false,
            _ => artifact_commitment_matches = false,
        }
        assert!(!phase14_claim_bindings_are_valid(
            statement_version_matches,
            semantic_scope_matches,
            artifact_commitment_matches,
        ));
    }

    #[kani::proof]
    fn kani_phase14_state_progress_accepts_canonical_single_step() {
        assert!(phase14_state_progress_is_valid(1, 2, 1, 2, 0, 1));
    }

    #[kani::proof]
    fn kani_phase14_state_progress_rejects_any_progress_mismatch() {
        let which = kani::any::<u8>();
        kani::assume(which < 3);
        let mut to_history_length = 2usize;
        let mut to_lookup_transcript_entries = 2usize;
        let mut to_position = 1i16;
        match which {
            0 => to_history_length = 3,
            1 => to_lookup_transcript_entries = 3,
            _ => to_position = 2,
        }
        assert!(!phase14_state_progress_is_valid(
            1,
            to_history_length,
            1,
            to_lookup_transcript_entries,
            0,
            to_position,
        ));
    }
}

#[cfg(kani)]
mod kani_phase24_proofs {
    fn phase24_relation_sequence_is_valid(
        first_start_step: usize,
        first_end_step: usize,
        first_total_steps: usize,
        second_start_step: usize,
        second_end_step: usize,
        second_total_steps: usize,
        shared_source_template: bool,
        first_lookup_template_present: bool,
        first_lookup_accumulator_present: bool,
        first_state_present: bool,
        second_lookup_template_present: bool,
        second_lookup_accumulator_present: bool,
        second_state_present: bool,
        boundary_matches: bool,
    ) -> bool {
        first_total_steps > 0
            && second_total_steps > 0
            && first_start_step < first_end_step
            && second_start_step < second_end_step
            && first_end_step.checked_sub(first_start_step) == Some(first_total_steps)
            && second_end_step.checked_sub(second_start_step) == Some(second_total_steps)
            && shared_source_template
            && first_lookup_template_present
            && first_lookup_accumulator_present
            && first_state_present
            && second_lookup_template_present
            && second_lookup_accumulator_present
            && second_state_present
            && second_start_step == first_end_step
            && boundary_matches
    }

    #[kani::proof]
    fn kani_phase24_relation_sequence_accepts_contiguous_members() {
        let second_width = if kani::any::<bool>() { 1 } else { 2 };
        assert!(phase24_relation_sequence_is_valid(
            0,
            1,
            1,
            1,
            1 + second_width,
            second_width,
            true,
            true,
            true,
            true,
            true,
            true,
            true,
            true,
        ));
    }

    #[kani::proof]
    fn kani_phase24_relation_sequence_rejects_zero_width_member() {
        if kani::any::<bool>() {
            assert!(!phase24_relation_sequence_is_valid(
                0, 0, 0, 1, 3, 2, true, true, true, true, true, true, true, true,
            ));
        } else {
            assert!(!phase24_relation_sequence_is_valid(
                0, 1, 1, 1, 1, 0, true, true, true, true, true, true, true, true,
            ));
        }
    }

    #[kani::proof]
    fn kani_phase24_relation_sequence_rejects_non_contiguous_steps() {
        let gap = 1 + (kani::any::<u8>() % 2) as usize;
        assert!(!phase24_relation_sequence_is_valid(
            0,
            1,
            1,
            1 + gap,
            3 + gap,
            2,
            true,
            true,
            true,
            true,
            true,
            true,
            true,
            true,
        ));
    }

    #[kani::proof]
    fn kani_phase24_relation_sequence_rejects_boundary_mismatch() {
        assert!(!phase24_relation_sequence_is_valid(
            0, 1, 1, 1, 3, 2, true, true, true, true, true, true, true, false,
        ));
    }
}

#[cfg(kani)]
mod kani_phase25_proofs {
    fn phase25_interval_counts_are_valid(
        previous_total_steps: usize,
        current_total_steps: usize,
        interval_steps: usize,
        previous_lookup_delta_entries: usize,
        current_lookup_delta_entries: usize,
        interval_lookup_delta_entries: usize,
    ) -> bool {
        current_total_steps > previous_total_steps
            && current_total_steps.checked_sub(previous_total_steps) == Some(interval_steps)
            && interval_steps > 0
            && current_lookup_delta_entries >= previous_lookup_delta_entries
            && current_lookup_delta_entries.checked_sub(previous_lookup_delta_entries)
                == Some(interval_lookup_delta_entries)
    }

    fn phase25_interval_reconstruction_shape_is_valid(
        first_interval_steps: usize,
        second_interval_steps: usize,
        reconstructed_total_steps: usize,
        first_end_state_tag: u8,
        second_start_state_tag: u8,
    ) -> bool {
        first_interval_steps > 0
            && second_interval_steps > 0
            && first_interval_steps.checked_add(second_interval_steps)
                == Some(reconstructed_total_steps)
            && first_end_state_tag != 0
            && first_end_state_tag == second_start_state_tag
    }

    #[kani::proof]
    fn kani_phase25_interval_counts_accept_checked_differences() {
        assert!(phase25_interval_counts_are_valid(1, 3, 2, 2, 5, 3));
    }

    #[kani::proof]
    fn kani_phase25_interval_counts_cover_positive_nonzero_lookup_delta_case() {
        let previous_total_steps = kani::any::<u8>() as usize;
        let interval_steps = (kani::any::<u8>() % 4) as usize + 1;
        let previous_lookup_delta_entries = kani::any::<u8>() as usize;
        let interval_lookup_delta_entries = (kani::any::<u8>() % 4) as usize + 1;
        let current_total_steps = previous_total_steps + interval_steps;
        let current_lookup_delta_entries =
            previous_lookup_delta_entries + interval_lookup_delta_entries;

        kani::cover!(
            phase25_interval_counts_are_valid(
                previous_total_steps,
                current_total_steps,
                interval_steps,
                previous_lookup_delta_entries,
                current_lookup_delta_entries,
                interval_lookup_delta_entries,
            ) && interval_lookup_delta_entries > 0
        );
    }

    #[kani::proof]
    fn kani_phase25_interval_counts_reject_underflow() {
        let previous_total_steps = 2usize;
        let current_total_steps = if kani::any::<bool>() { 0 } else { 1 };
        assert!(!phase25_interval_counts_are_valid(
            previous_total_steps,
            current_total_steps,
            1,
            3,
            4,
            1,
        ));
    }

    #[kani::proof]
    fn kani_phase25_interval_counts_reject_zero_width_interval() {
        let current_lookup_delta_entries = 2usize + (kani::any::<u8>() % 2) as usize;
        assert!(!phase25_interval_counts_are_valid(
            2,
            2,
            0,
            1,
            current_lookup_delta_entries,
            current_lookup_delta_entries.saturating_sub(1),
        ));
    }

    #[kani::proof]
    fn kani_phase25_interval_reconstruction_rejects_boundary_mismatch() {
        let first_end_tag = 1u8 + (kani::any::<u8>() % 2);
        let second_start_tag = if first_end_tag == 1 { 2 } else { 1 };
        assert!(!phase25_interval_reconstruction_shape_is_valid(
            1,
            2,
            3,
            first_end_tag,
            second_start_tag,
        ));
    }

    #[kani::proof]
    fn kani_phase25_interval_reconstruction_covers_contiguous_pair() {
        let first_interval_steps = (kani::any::<u8>() % 4) as usize + 1;
        let second_interval_steps = (kani::any::<u8>() % 4) as usize + 1;
        let reconstructed_total_steps = first_interval_steps + second_interval_steps;
        let shared_boundary_tag = 1u8 + (kani::any::<u8>() % 2);

        kani::cover!(phase25_interval_reconstruction_shape_is_valid(
            first_interval_steps,
            second_interval_steps,
            reconstructed_total_steps,
            shared_boundary_tag,
            shared_boundary_tag,
        ));
    }
}

#[cfg(kani)]
mod kani_phase26_proofs {
    fn phase26_fold_shape_is_valid(
        first_interval_steps: usize,
        second_interval_steps: usize,
        reconstructed_total_steps: usize,
        first_end_state_tag: u8,
        second_start_state_tag: u8,
        bounded_fold_arity: usize,
        member_count: usize,
    ) -> bool {
        first_interval_steps > 0
            && second_interval_steps > 0
            && first_interval_steps.checked_add(second_interval_steps)
                == Some(reconstructed_total_steps)
            && first_end_state_tag != 0
            && first_end_state_tag == second_start_state_tag
            && member_count >= 2
            && bounded_fold_arity >= member_count
    }

    #[kani::proof]
    fn kani_phase26_fold_shape_accepts_contiguous_pair() {
        assert!(phase26_fold_shape_is_valid(2, 3, 5, 1, 1, 2, 2));
    }

    #[kani::proof]
    fn kani_phase26_fold_shape_covers_nonzero_lookup_delta_fold() {
        let first_interval_steps = (kani::any::<u8>() % 4) as usize + 1;
        let second_interval_steps = (kani::any::<u8>() % 4) as usize + 1;
        let reconstructed_total_steps = first_interval_steps + second_interval_steps;
        let shared_boundary_tag = 1u8 + (kani::any::<u8>() % 2);

        kani::cover!(phase26_fold_shape_is_valid(
            first_interval_steps,
            second_interval_steps,
            reconstructed_total_steps,
            shared_boundary_tag,
            shared_boundary_tag,
            2,
            2,
        ));
    }

    #[kani::proof]
    fn kani_phase26_fold_shape_rejects_boundary_mismatch() {
        let first_end_tag = 1u8 + (kani::any::<u8>() % 2);
        let second_start_tag = if first_end_tag == 1 { 2 } else { 1 };
        assert!(!phase26_fold_shape_is_valid(
            1,
            2,
            3,
            first_end_tag,
            second_start_tag,
            2,
            2,
        ));
    }

    #[kani::proof]
    fn kani_phase26_fold_shape_rejects_insufficient_bounded_arity() {
        assert!(!phase26_fold_shape_is_valid(1, 2, 3, 1, 1, 1, 2));
    }
}

#[cfg(kani)]
mod kani_phase27_proofs {
    fn phase27_chain_shape_is_valid(
        first_fold_steps: usize,
        second_fold_steps: usize,
        reconstructed_total_steps: usize,
        first_end_state_tag: u8,
        second_start_state_tag: u8,
        first_nested_member_count: usize,
        second_nested_member_count: usize,
        bounded_chain_arity: usize,
        member_count: usize,
    ) -> bool {
        first_fold_steps > 0
            && second_fold_steps > 0
            && first_fold_steps.checked_add(second_fold_steps) == Some(reconstructed_total_steps)
            && first_end_state_tag != 0
            && first_end_state_tag == second_start_state_tag
            && first_nested_member_count >= 2
            && second_nested_member_count >= 2
            && member_count >= 2
            && bounded_chain_arity >= member_count
    }

    #[kani::proof]
    fn kani_phase27_chain_shape_accepts_contiguous_pair() {
        assert!(phase27_chain_shape_is_valid(2, 3, 5, 1, 1, 2, 2, 2, 2));
    }

    #[kani::proof]
    fn kani_phase27_chain_shape_covers_nonzero_lookup_delta_chain() {
        let first_fold_steps = (kani::any::<u8>() % 4) as usize + 1;
        let second_fold_steps = (kani::any::<u8>() % 4) as usize + 1;
        let reconstructed_total_steps = first_fold_steps + second_fold_steps;
        let shared_boundary_tag = 1u8 + (kani::any::<u8>() % 2);

        kani::cover!(phase27_chain_shape_is_valid(
            first_fold_steps,
            second_fold_steps,
            reconstructed_total_steps,
            shared_boundary_tag,
            shared_boundary_tag,
            2,
            3,
            2,
            2,
        ));
    }

    #[kani::proof]
    fn kani_phase27_chain_shape_rejects_boundary_mismatch() {
        let first_end_tag = 1u8 + (kani::any::<u8>() % 2);
        let second_start_tag = if first_end_tag == 1 { 2 } else { 1 };
        assert!(!phase27_chain_shape_is_valid(
            1,
            2,
            3,
            first_end_tag,
            second_start_tag,
            2,
            2,
            2,
            2,
        ));
    }

    #[kani::proof]
    fn kani_phase27_chain_shape_rejects_insufficient_bounded_arity() {
        assert!(!phase27_chain_shape_is_valid(1, 2, 3, 1, 1, 2, 2, 1, 2));
    }
}

#[cfg(kani)]
mod kani_phase28_proofs {
    fn phase28_aggregation_shape_is_valid(
        first_chain_steps: usize,
        second_chain_steps: usize,
        reconstructed_total_steps: usize,
        first_end_state_tag: u8,
        second_start_state_tag: u8,
        first_nested_phase26_members: usize,
        second_nested_phase26_members: usize,
        first_nested_phase25_members: usize,
        second_nested_phase25_members: usize,
        bounded_aggregation_arity: usize,
        member_count: usize,
    ) -> bool {
        first_chain_steps > 0
            && second_chain_steps > 0
            && first_chain_steps.checked_add(second_chain_steps) == Some(reconstructed_total_steps)
            && first_end_state_tag != 0
            && first_end_state_tag == second_start_state_tag
            && first_nested_phase26_members >= 2
            && second_nested_phase26_members >= 2
            && first_nested_phase25_members >= 4
            && second_nested_phase25_members >= 4
            && member_count >= 2
            && bounded_aggregation_arity >= member_count
    }

    #[kani::proof]
    fn kani_phase28_aggregation_shape_accepts_contiguous_pair() {
        assert!(phase28_aggregation_shape_is_valid(
            4, 5, 9, 1, 1, 2, 2, 4, 4, 2, 2,
        ));
    }

    #[kani::proof]
    fn kani_phase28_aggregation_shape_covers_nonzero_lookup_delta_aggregate() {
        let first_chain_steps = (kani::any::<u8>() % 4) as usize + 1;
        let second_chain_steps = (kani::any::<u8>() % 4) as usize + 1;
        let reconstructed_total_steps = first_chain_steps + second_chain_steps;
        let shared_boundary_tag = 1u8 + (kani::any::<u8>() % 2);

        kani::cover!(phase28_aggregation_shape_is_valid(
            first_chain_steps,
            second_chain_steps,
            reconstructed_total_steps,
            shared_boundary_tag,
            shared_boundary_tag,
            2,
            3,
            4,
            6,
            2,
            2,
        ));
    }

    #[kani::proof]
    fn kani_phase28_aggregation_shape_rejects_boundary_mismatch() {
        let first_end_tag = 1u8 + (kani::any::<u8>() % 2);
        let second_start_tag = if first_end_tag == 1 { 2 } else { 1 };
        assert!(!phase28_aggregation_shape_is_valid(
            2,
            3,
            5,
            first_end_tag,
            second_start_tag,
            2,
            2,
            4,
            4,
            2,
            2,
        ));
    }

    #[kani::proof]
    fn kani_phase28_aggregation_shape_rejects_insufficient_bounded_arity() {
        assert!(!phase28_aggregation_shape_is_valid(
            2, 3, 5, 1, 1, 2, 2, 4, 4, 1, 2,
        ));
    }
}

#[cfg(kani)]
mod kani_phase30_proofs {
    use super::{
        phase30_manifest_boundary_pair_matches, phase30_manifest_cardinality_counts_are_valid,
        phase30_step_envelope_index_matches, phase30_step_envelope_link_matches,
    };

    #[kani::proof]
    fn kani_phase30_manifest_accepts_valid_single_step_surface() {
        assert!(phase30_manifest_cardinality_counts_are_valid(1, 1));
        assert!(phase30_manifest_boundary_pair_matches(
            "state-a", "state-a", "state-b", "state-b"
        ));
        assert!(phase30_step_envelope_index_matches(0, 0));
    }

    #[kani::proof]
    fn kani_phase30_manifest_accepts_contiguous_pair() {
        assert!(phase30_manifest_boundary_pair_matches(
            "state-a", "state-a", "state-c", "state-c"
        ));
        assert!(phase30_step_envelope_link_matches("state-b", "state-b"));
        assert!(phase30_step_envelope_index_matches(0, 0));
        assert!(phase30_step_envelope_index_matches(1, 1));
    }

    #[kani::proof]
    fn kani_phase30_manifest_shape_rejects_chain_boundary_mismatch() {
        assert!(!phase30_manifest_boundary_pair_matches(
            "state-a",
            "state-a",
            "wrong-end",
            "state-c"
        ));
    }

    #[kani::proof]
    fn kani_phase30_manifest_shape_rejects_step_index_drift() {
        assert!(!phase30_step_envelope_index_matches(1, 2));
    }

    #[kani::proof]
    fn kani_phase30_manifest_counts_accept_valid_bounded_counts() {
        assert!(phase30_manifest_cardinality_counts_are_valid(1, 1));
    }

    #[kani::proof]
    fn kani_phase30_manifest_counts_reject_zero_envelopes() {
        assert!(!phase30_manifest_cardinality_counts_are_valid(0, 0));
    }

    #[kani::proof]
    fn kani_phase30_manifest_counts_reject_mismatched_totals() {
        assert!(!phase30_manifest_cardinality_counts_are_valid(2, 1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Attention2DMode;
    use crate::interpreter::NativeInterpreter;
    use crate::proof::{
        production_v1_stark_options, prove_execution_stark_with_backend_and_options,
        ExecutionClaimCommitments, VanillaStarkExecutionClaim,
    };
    use crate::state::MachineState;
    use crate::stwo_backend::lookup_component::Phase3LookupTableRow;
    use crate::stwo_backend::shared_lookup_artifact::{
        build_phase12_shared_lookup_artifact, EmbeddedSharedActivationClaimRow,
        EmbeddedSharedActivationLookupProof, EmbeddedSharedNormalizationClaimRow,
        EmbeddedSharedNormalizationProof, Phase12SharedLookupArtifact,
    };
    use crate::stwo_backend::{
        prove_phase10_shared_binary_step_lookup_envelope,
        prove_phase10_shared_normalization_lookup_envelope,
    };
    use crate::{ProgramCompiler, TransformerVmConfig};
    use proptest::prelude::*;
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use std::sync::OnceLock;

    fn sample_commitments() -> ExecutionClaimCommitments {
        ExecutionClaimCommitments {
            scheme_version: "v1".to_string(),
            hash_function: "blake2b-256".to_string(),
            program_hash: "program".to_string(),
            transformer_config_hash: "config".to_string(),
            deterministic_model_hash: "model".to_string(),
            stark_options_hash: "options".to_string(),
            prover_build_info: "build".to_string(),
            prover_build_hash: "buildhash".to_string(),
        }
    }

    fn sample_step_proof(
        initial_memory: Vec<i16>,
        final_memory: Vec<i16>,
    ) -> VanillaStarkExecutionProof {
        let program =
            decoding_step_v1_program_with_initial_memory(initial_memory).expect("program");
        VanillaStarkExecutionProof {
            proof_backend: StarkProofBackend::Stwo,
            proof_backend_version: "stwo-phase11-decoding-step-v1".to_string(),
            stwo_auxiliary: None,
            claim: VanillaStarkExecutionClaim {
                statement_version: "statement-v1".to_string(),
                semantic_scope: "native_isa_execution_with_transformer_native_equivalence_check"
                    .to_string(),
                program,
                attention_mode: Attention2DMode::AverageHard,
                transformer_config: None,
                steps: 1,
                final_state: MachineState {
                    pc: 0,
                    acc: 1,
                    sp: 23,
                    zero_flag: false,
                    carry_flag: false,
                    halted: true,
                    memory: final_memory,
                },
                options: production_v1_stark_options(),
                equivalence: None,
                commitments: Some(sample_commitments()),
            },
            proof: vec![1, 2, 3],
        }
    }

    fn sample_phase12_step_proof(
        layout: &Phase12DecodingLayout,
        initial_memory: Vec<i16>,
    ) -> VanillaStarkExecutionProof {
        let program = decoding_step_v2_program_with_initial_memory(layout, initial_memory.clone())
            .expect("program");
        let mut runtime = NativeInterpreter::new(
            program.clone(),
            Attention2DMode::AverageHard,
            decoding_program_step_limit(&program).expect("step limit"),
        );
        let result = runtime.run().expect("run program");
        assert!(result.halted);
        let final_memory = result.final_state.memory.clone();
        VanillaStarkExecutionProof {
            proof_backend: StarkProofBackend::Stwo,
            proof_backend_version: crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12.to_string(),
            stwo_auxiliary: None,
            claim: VanillaStarkExecutionClaim {
                statement_version: "statement-v1".to_string(),
                semantic_scope: "native_isa_execution_with_transformer_native_equivalence_check"
                    .to_string(),
                program,
                attention_mode: Attention2DMode::AverageHard,
                transformer_config: None,
                steps: runtime.trace().len(),
                final_state: result.final_state,
                options: production_v1_stark_options(),
                equivalence: None,
                commitments: Some(sample_commitments()),
            },
            proof: sample_phase12_proof_payload(layout, &final_memory),
        }
    }

    fn sample_phase12_proof_payload(
        layout: &Phase12DecodingLayout,
        final_memory: &[i16],
    ) -> Vec<u8> {
        let lookup = layout.lookup_range().expect("lookup range");
        let normalization_envelope = prove_phase10_shared_normalization_lookup_envelope(&[
            (
                final_memory[lookup.start] as u16,
                final_memory[lookup.start + 1] as u16,
            ),
            (
                final_memory[lookup.start + 4] as u16,
                final_memory[lookup.start + 5] as u16,
            ),
        ])
        .expect("normalization envelope");
        let activation_envelope = prove_phase10_shared_binary_step_lookup_envelope(&[
            Phase3LookupTableRow {
                input: final_memory[lookup.start + 2],
                output: final_memory[lookup.start + 3] as u8,
            },
            Phase3LookupTableRow {
                input: final_memory[lookup.start + 6],
                output: final_memory[lookup.start + 7] as u8,
            },
        ])
        .expect("activation envelope");
        serde_json::to_vec(&serde_json::json!({
            "embedded_shared_normalization": {
                "statement_version": "stwo-shared-normalization-lookup-v1",
                "semantic_scope": "stwo_decoding_step_v2_execution_with_shared_normalization_lookup",
                "claimed_rows": [
                    {
                        "norm_sq_memory_index": lookup.start,
                        "inv_sqrt_q8_memory_index": lookup.start + 1,
                        "expected_norm_sq": final_memory[lookup.start],
                        "expected_inv_sqrt_q8": final_memory[lookup.start + 1]
                    },
                    {
                        "norm_sq_memory_index": lookup.start + 4,
                        "inv_sqrt_q8_memory_index": lookup.start + 5,
                        "expected_norm_sq": final_memory[lookup.start + 4],
                        "expected_inv_sqrt_q8": final_memory[lookup.start + 5]
                    }
                ],
                "proof_envelope": normalization_envelope
            },
            "embedded_shared_activation_lookup": {
                "statement_version": "stwo-shared-binary-step-lookup-v1",
                "semantic_scope": "stwo_decoding_step_v2_execution_with_shared_binary_step_lookup",
                "claimed_rows": [
                    {
                        "input_memory_index": lookup.start + 2,
                        "output_memory_index": lookup.start + 3,
                        "expected_input": final_memory[lookup.start + 2],
                        "expected_output": final_memory[lookup.start + 3]
                    },
                    {
                        "input_memory_index": lookup.start + 6,
                        "output_memory_index": lookup.start + 7,
                        "expected_input": final_memory[lookup.start + 6],
                        "expected_output": final_memory[lookup.start + 7]
                    }
                ],
                "proof_envelope": activation_envelope
            }
        }))
        .expect("sample proof payload")
    }

    fn sample_phase12_valid_but_wrong_shared_lookup_artifact(
        layout: &Phase12DecodingLayout,
    ) -> Phase12SharedLookupArtifact {
        let layout_commitment = commit_phase12_layout(layout);
        let lookup = layout.lookup_range().expect("lookup range");
        let normalization = EmbeddedSharedNormalizationProof {
            statement_version: "stwo-shared-normalization-lookup-v1".to_string(),
            semantic_scope: "stwo_decoding_step_v2_execution_with_shared_normalization_lookup"
                .to_string(),
            claimed_rows: vec![
                EmbeddedSharedNormalizationClaimRow {
                    norm_sq_memory_index: lookup.start as u8,
                    inv_sqrt_q8_memory_index: (lookup.start + 1) as u8,
                    expected_norm_sq: 4,
                    expected_inv_sqrt_q8: 128,
                },
                EmbeddedSharedNormalizationClaimRow {
                    norm_sq_memory_index: (lookup.start + 4) as u8,
                    inv_sqrt_q8_memory_index: (lookup.start + 5) as u8,
                    expected_norm_sq: 16,
                    expected_inv_sqrt_q8: 64,
                },
            ],
            proof_envelope: prove_phase10_shared_normalization_lookup_envelope(&[
                (4, 128),
                (16, 64),
            ])
            .expect("normalization envelope"),
        };
        let activation = EmbeddedSharedActivationLookupProof {
            statement_version: "stwo-shared-binary-step-lookup-v1".to_string(),
            semantic_scope: "stwo_decoding_step_v2_execution_with_shared_binary_step_lookup"
                .to_string(),
            claimed_rows: vec![
                EmbeddedSharedActivationClaimRow {
                    input_memory_index: (lookup.start + 2) as u8,
                    output_memory_index: (lookup.start + 3) as u8,
                    expected_input: 0,
                    expected_output: 1,
                },
                EmbeddedSharedActivationClaimRow {
                    input_memory_index: (lookup.start + 6) as u8,
                    output_memory_index: (lookup.start + 7) as u8,
                    expected_input: 1,
                    expected_output: 1,
                },
            ],
            proof_envelope: prove_phase10_shared_binary_step_lookup_envelope(&[
                Phase3LookupTableRow {
                    input: 0,
                    output: 1,
                },
                Phase3LookupTableRow {
                    input: 1,
                    output: 1,
                },
            ])
            .expect("activation envelope"),
        };
        build_phase12_shared_lookup_artifact(
            &layout_commitment,
            vec![4, 128, 0, 1, 16, 64, 1, 1],
            normalization,
            activation,
        )
        .expect("synthetic valid artifact")
    }

    const ORACLE_DECODING_STATE_VERSION_PHASE12: &str = "stwo-decoding-state-v11";
    const ORACLE_DECODING_STATE_VERSION_PHASE14: &str = "stwo-decoding-state-v6";

    fn oracle_lower_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for &byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }

    fn oracle_blake2b_256(parts: &[Vec<u8>]) -> String {
        oracle_lower_hex(&oracle_blake2b_256_bytes(parts))
    }

    fn oracle_blake2b_256_bytes(parts: &[Vec<u8>]) -> [u8; 32] {
        let mut hasher = Blake2bVar::new(32).expect("blake2b-256");
        for part in parts {
            hasher.update(part);
        }
        let mut out = [0u8; 32];
        hasher
            .finalize_variable(&mut out)
            .expect("blake2b finalize");
        out
    }

    fn oracle_phase30_len_prefixed_json_digest_commit<T: serde::Serialize>(
        version: &str,
        domain: &[u8],
        value: &T,
    ) -> String {
        let json = serde_json::to_vec(value).expect("json");
        let json_len = json.len();
        let json_digest = oracle_blake2b_256_bytes(&[json]);
        oracle_blake2b_256(&[
            version.as_bytes().to_vec(),
            domain.to_vec(),
            (json_len as u64).to_le_bytes().to_vec(),
            json_digest.to_vec(),
        ])
    }

    struct Phase30LargeStreamingPayload {
        entries: usize,
        row_width: usize,
    }

    impl serde::Serialize for Phase30LargeStreamingPayload {
        fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut seq = serializer.serialize_seq(Some(self.entries))?;
            let row = vec![7u8; self.row_width];
            for index in 0..self.entries {
                serde::ser::SerializeSeq::serialize_element(&mut seq, &(index, &row))?;
            }
            serde::ser::SerializeSeq::end(seq)
        }
    }

    fn oracle_push_len_prefixed_part(parts: &mut Vec<Vec<u8>>, bytes: &[u8]) {
        parts.push((bytes.len() as u64).to_le_bytes().to_vec());
        parts.push(bytes.to_vec());
    }

    fn oracle_commit_phase12_layout(layout: &Phase12DecodingLayout) -> String {
        oracle_blake2b_256(&[
            STWO_DECODING_LAYOUT_VERSION_PHASE12.as_bytes().to_vec(),
            (layout.rolling_kv_pairs as u64).to_le_bytes().to_vec(),
            (layout.pair_width as u64).to_le_bytes().to_vec(),
        ])
    }

    fn oracle_commit_phase12_named_slice(
        label: &str,
        layout_commitment: &str,
        values: &[i16],
    ) -> String {
        let mut parts = vec![
            ORACLE_DECODING_STATE_VERSION_PHASE12.as_bytes().to_vec(),
            layout_commitment.as_bytes().to_vec(),
            label.as_bytes().to_vec(),
        ];
        for value in values {
            parts.push(value.to_le_bytes().to_vec());
        }
        oracle_blake2b_256(&parts)
    }

    fn oracle_commit_phase12_persistent_state(
        layout_commitment: &str,
        position: i16,
        kv_cache_values: &[i16],
    ) -> String {
        let mut parts = vec![
            ORACLE_DECODING_STATE_VERSION_PHASE12.as_bytes().to_vec(),
            layout_commitment.as_bytes().to_vec(),
            position.to_le_bytes().to_vec(),
        ];
        for value in kv_cache_values {
            parts.push(value.to_le_bytes().to_vec());
        }
        oracle_blake2b_256(&parts)
    }

    fn oracle_commit_phase12_public_state(state: &Phase12DecodingState) -> String {
        oracle_blake2b_256(&[
            ORACLE_DECODING_STATE_VERSION_PHASE12.as_bytes().to_vec(),
            b"public-state".to_vec(),
            state.state_version.as_bytes().to_vec(),
            (state.step_index as u64).to_le_bytes().to_vec(),
            state.position.to_le_bytes().to_vec(),
            state.layout_commitment.as_bytes().to_vec(),
            state.persistent_state_commitment.as_bytes().to_vec(),
            state.kv_history_commitment.as_bytes().to_vec(),
            (state.kv_history_length as u64).to_le_bytes().to_vec(),
            state.kv_cache_commitment.as_bytes().to_vec(),
        ])
    }

    fn oracle_commit_phase12_shared_lookup_rows(layout_commitment: &str, values: &[i16]) -> String {
        let mut parts = vec![
            ORACLE_DECODING_STATE_VERSION_PHASE12.as_bytes().to_vec(),
            layout_commitment.as_bytes().to_vec(),
            b"lookup-rows".to_vec(),
        ];
        for value in values {
            parts.push(value.to_le_bytes().to_vec());
        }
        oracle_blake2b_256(&parts)
    }

    fn oracle_commit_phase12_history_seed(
        layout_commitment: &str,
        kv_cache_values: &[i16],
        pair_width: usize,
    ) -> String {
        oracle_blake2b_256(&[
            ORACLE_DECODING_STATE_VERSION_PHASE12.as_bytes().to_vec(),
            layout_commitment.as_bytes().to_vec(),
            b"history-seed".to_vec(),
            (pair_width as u64).to_le_bytes().to_vec(),
            ((kv_cache_values.len() / pair_width) as u64)
                .to_le_bytes()
                .to_vec(),
            kv_cache_values
                .iter()
                .flat_map(|value| value.to_le_bytes())
                .collect(),
        ])
    }

    fn oracle_advance_phase12_history_commitment(
        layout_commitment: &str,
        previous_commitment: &str,
        appended_pair: &[i16],
        next_length: usize,
    ) -> String {
        let mut parts = vec![
            ORACLE_DECODING_STATE_VERSION_PHASE12.as_bytes().to_vec(),
            layout_commitment.as_bytes().to_vec(),
            b"history-advance".to_vec(),
            previous_commitment.as_bytes().to_vec(),
            (next_length as u64).to_le_bytes().to_vec(),
            (appended_pair.len() as u64).to_le_bytes().to_vec(),
        ];
        for value in appended_pair {
            parts.push(value.to_le_bytes().to_vec());
        }
        oracle_blake2b_256(&parts)
    }

    fn oracle_phase12_state_view(
        memory: &[i16],
        layout: &Phase12DecodingLayout,
    ) -> Result<Phase12StateView> {
        layout.validate()?;
        let memory_size = layout.memory_size()?;
        if memory.len() != memory_size {
            return Err(VmError::InvalidConfig(format!(
                "Phase 12 decoding state requires exactly {} memory cells, got {}",
                memory_size,
                memory.len()
            )));
        }
        let kv_cache_range = layout.kv_cache_range()?;
        let incoming_token_range = layout.incoming_token_range()?;
        let query_range = layout.query_range()?;
        let output_range = layout.output_range()?;
        let lookup_range = layout.lookup_range()?;
        let position_index = layout.position_index()?;
        let layout_commitment = oracle_commit_phase12_layout(layout);
        let position = memory[position_index];

        Ok(Phase12StateView {
            position,
            layout_commitment: layout_commitment.clone(),
            persistent_state_commitment: oracle_commit_phase12_persistent_state(
                &layout_commitment,
                position,
                &memory[kv_cache_range.clone()],
            ),
            kv_cache_commitment: oracle_commit_phase12_named_slice(
                "kv-cache",
                &layout_commitment,
                &memory[kv_cache_range],
            ),
            incoming_token_commitment: oracle_commit_phase12_named_slice(
                "incoming-token",
                &layout_commitment,
                &memory[incoming_token_range],
            ),
            query_commitment: oracle_commit_phase12_named_slice(
                "query",
                &layout_commitment,
                &memory[query_range],
            ),
            output_commitment: oracle_commit_phase12_named_slice(
                "output",
                &layout_commitment,
                &memory[output_range],
            ),
            lookup_rows_commitment: oracle_commit_phase12_shared_lookup_rows(
                &layout_commitment,
                &memory[lookup_range],
            ),
        })
    }

    fn oracle_phase12_shared_lookup_artifact_from_proof_payload(
        proof: &VanillaStarkExecutionProof,
        layout: &Phase12DecodingLayout,
        layout_commitment: &str,
    ) -> Result<Option<Phase12SharedLookupArtifact>> {
        if !matches_decoding_step_v2_family(&proof.claim.program) {
            return Ok(None);
        }
        let payload: serde_json::Value = serde_json::from_slice(&proof.proof)
            .map_err(|error| VmError::Serialization(error.to_string()))?;
        let normalization_value = payload
            .get("embedded_shared_normalization")
            .ok_or_else(|| {
                VmError::Serialization(
                    "Phase 12 oracle payload is missing embedded_shared_normalization".to_string(),
                )
            })?
            .clone();
        let activation_value = payload
            .get("embedded_shared_activation_lookup")
            .ok_or_else(|| {
                VmError::Serialization(
                    "Phase 12 oracle payload is missing embedded_shared_activation_lookup"
                        .to_string(),
                )
            })?
            .clone();
        let normalization: EmbeddedSharedNormalizationProof =
            serde_json::from_value(normalization_value)
                .map_err(|error| VmError::Serialization(error.to_string()))?;
        let activation: EmbeddedSharedActivationLookupProof =
            serde_json::from_value(activation_value)
                .map_err(|error| VmError::Serialization(error.to_string()))?;
        if normalization.claimed_rows.len() != activation.claimed_rows.len() {
            return Err(VmError::InvalidConfig(format!(
                "Phase 12 oracle payload row count mismatch: normalization={}, activation={}",
                normalization.claimed_rows.len(),
                activation.claimed_rows.len()
            )));
        }
        let mut flattened_lookup_rows =
            Vec::with_capacity(normalization.claimed_rows.len().saturating_mul(4));
        for (normalization_row, activation_row) in normalization
            .claimed_rows
            .iter()
            .zip(activation.claimed_rows.iter())
        {
            flattened_lookup_rows.push(normalization_row.expected_norm_sq);
            flattened_lookup_rows.push(normalization_row.expected_inv_sqrt_q8);
            flattened_lookup_rows.push(activation_row.expected_input);
            flattened_lookup_rows.push(activation_row.expected_output);
        }
        let artifact = build_phase12_shared_lookup_artifact(
            layout_commitment,
            flattened_lookup_rows,
            normalization,
            activation,
        )?;
        verify_phase12_shared_lookup_artifact(&artifact, layout, layout_commitment)?;
        Ok(Some(artifact))
    }

    fn oracle_build_phase12_shared_lookup_artifact_index<'a>(
        artifacts: &'a [Phase12SharedLookupArtifact],
        referenced_commitments: &HashSet<String>,
        expected_flattened_lookup_rows_len: usize,
        registry_label: &str,
    ) -> Result<HashMap<String, &'a Phase12SharedLookupArtifact>> {
        let mut artifact_index = HashMap::with_capacity(artifacts.len());
        for artifact in artifacts {
            if artifact.flattened_lookup_rows.len() != expected_flattened_lookup_rows_len {
                return Err(VmError::InvalidConfig(format!(
                    "{registry_label} artifact `{}` has {} flattened lookup rows; expected {}",
                    artifact.artifact_commitment,
                    artifact.flattened_lookup_rows.len(),
                    expected_flattened_lookup_rows_len
                )));
            }
            if !referenced_commitments.contains(&artifact.artifact_commitment) {
                return Err(VmError::InvalidConfig(format!(
                    "{registry_label} artifact `{}` is not referenced by any decoding step",
                    artifact.artifact_commitment
                )));
            }
            if artifact_index
                .insert(artifact.artifact_commitment.clone(), artifact)
                .is_some()
            {
                return Err(VmError::InvalidConfig(format!(
                    "{registry_label} artifact `{}` appears more than once in the manifest registry",
                    artifact.artifact_commitment
                )));
            }
        }
        if artifact_index.len() != referenced_commitments.len() {
            let missing = referenced_commitments
                .iter()
                .find(|commitment| !artifact_index.contains_key(*commitment))
                .cloned()
                .unwrap_or_else(|| "<unknown>".to_string());
            return Err(VmError::InvalidConfig(format!(
                "{registry_label} artifact `{missing}` is not present in the manifest registry"
            )));
        }
        Ok(artifact_index)
    }

    fn oracle_shared_lookup_artifact_by_commitment<'a>(
        artifacts: &'a HashMap<String, &'a Phase12SharedLookupArtifact>,
        artifact_commitment: &str,
    ) -> Result<&'a Phase12SharedLookupArtifact> {
        artifacts.get(artifact_commitment).copied().ok_or_else(|| {
            VmError::InvalidConfig(format!(
                "shared lookup artifact `{artifact_commitment}` is not present in the manifest registry"
            ))
        })
    }

    fn oracle_commit_phase14_history_empty_chunk(
        layout_commitment: &str,
        pair_width: usize,
    ) -> String {
        oracle_blake2b_256(&[
            ORACLE_DECODING_STATE_VERSION_PHASE14.as_bytes().to_vec(),
            layout_commitment.as_bytes().to_vec(),
            b"history-open-empty".to_vec(),
            (pair_width as u64).to_le_bytes().to_vec(),
        ])
    }

    fn oracle_commit_phase14_history_chunk(
        layout_commitment: &str,
        pair_width: usize,
        chunk_values: &[i16],
    ) -> String {
        let mut parts = vec![
            ORACLE_DECODING_STATE_VERSION_PHASE14.as_bytes().to_vec(),
            layout_commitment.as_bytes().to_vec(),
            b"history-chunk".to_vec(),
            (pair_width as u64).to_le_bytes().to_vec(),
            ((chunk_values.len() / pair_width) as u64)
                .to_le_bytes()
                .to_vec(),
        ];
        for value in chunk_values {
            parts.push(value.to_le_bytes().to_vec());
        }
        oracle_blake2b_256(&parts)
    }

    fn oracle_fold_phase14_history_chunk(
        layout_commitment: &str,
        previous_sealed_commitment: &str,
        previous_sealed_chunks: usize,
        chunk_commitment: &str,
    ) -> String {
        oracle_blake2b_256(&[
            ORACLE_DECODING_STATE_VERSION_PHASE14.as_bytes().to_vec(),
            layout_commitment.as_bytes().to_vec(),
            b"history-sealed-fold".to_vec(),
            previous_sealed_commitment.as_bytes().to_vec(),
            (previous_sealed_chunks as u64).to_le_bytes().to_vec(),
            chunk_commitment.as_bytes().to_vec(),
        ])
    }

    fn oracle_commit_phase14_history_total(
        layout_commitment: &str,
        sealed_commitment: &str,
        sealed_chunks: usize,
        open_chunk_commitment: &str,
        open_chunk_pairs: usize,
        chunk_size: usize,
        history_length: usize,
    ) -> String {
        oracle_blake2b_256(&[
            ORACLE_DECODING_STATE_VERSION_PHASE14.as_bytes().to_vec(),
            layout_commitment.as_bytes().to_vec(),
            b"history-total".to_vec(),
            sealed_commitment.as_bytes().to_vec(),
            (sealed_chunks as u64).to_le_bytes().to_vec(),
            open_chunk_commitment.as_bytes().to_vec(),
            (open_chunk_pairs as u64).to_le_bytes().to_vec(),
            (chunk_size as u64).to_le_bytes().to_vec(),
            (history_length as u64).to_le_bytes().to_vec(),
        ])
    }

    fn oracle_commit_phase19_lookup_transcript_seed(
        layout_commitment: &str,
        lookup_rows_commitment: &str,
    ) -> String {
        oracle_blake2b_256(&[
            ORACLE_DECODING_STATE_VERSION_PHASE14.as_bytes().to_vec(),
            layout_commitment.as_bytes().to_vec(),
            b"lookup-transcript-seed".to_vec(),
            (1u64).to_le_bytes().to_vec(),
            lookup_rows_commitment.as_bytes().to_vec(),
        ])
    }

    fn oracle_fold_phase19_lookup_transcript(
        layout_commitment: &str,
        previous_commitment: &str,
        previous_entries: usize,
        lookup_rows_commitment: &str,
    ) -> String {
        oracle_blake2b_256(&[
            ORACLE_DECODING_STATE_VERSION_PHASE14.as_bytes().to_vec(),
            layout_commitment.as_bytes().to_vec(),
            b"lookup-transcript-fold".to_vec(),
            previous_commitment.as_bytes().to_vec(),
            (previous_entries as u64).to_le_bytes().to_vec(),
            lookup_rows_commitment.as_bytes().to_vec(),
        ])
    }

    fn oracle_commit_phase20_lookup_frontier(
        layout_commitment: &str,
        lookup_rows_commitments: &[String],
    ) -> String {
        let mut parts = vec![
            ORACLE_DECODING_STATE_VERSION_PHASE14.as_bytes().to_vec(),
            layout_commitment.as_bytes().to_vec(),
            b"lookup-frontier".to_vec(),
            (lookup_rows_commitments.len() as u64)
                .to_le_bytes()
                .to_vec(),
        ];
        for commitment in lookup_rows_commitments {
            parts.push(commitment.as_bytes().to_vec());
        }
        oracle_blake2b_256(&parts)
    }

    fn oracle_commit_phase14_public_state(state: &Phase14DecodingState) -> String {
        oracle_blake2b_256(&[
            ORACLE_DECODING_STATE_VERSION_PHASE14.as_bytes().to_vec(),
            b"public-state".to_vec(),
            state.state_version.as_bytes().to_vec(),
            (state.step_index as u64).to_le_bytes().to_vec(),
            state.position.to_le_bytes().to_vec(),
            state.layout_commitment.as_bytes().to_vec(),
            state.persistent_state_commitment.as_bytes().to_vec(),
            state.kv_history_commitment.as_bytes().to_vec(),
            (state.kv_history_length as u64).to_le_bytes().to_vec(),
            (state.kv_history_chunk_size as u64).to_le_bytes().to_vec(),
            state.kv_history_sealed_commitment.as_bytes().to_vec(),
            (state.kv_history_sealed_chunks as u64)
                .to_le_bytes()
                .to_vec(),
            state.kv_history_open_chunk_commitment.as_bytes().to_vec(),
            (state.kv_history_open_chunk_pairs as u64)
                .to_le_bytes()
                .to_vec(),
            state.kv_history_frontier_commitment.as_bytes().to_vec(),
            (state.kv_history_frontier_pairs as u64)
                .to_le_bytes()
                .to_vec(),
            state.lookup_transcript_commitment.as_bytes().to_vec(),
            (state.lookup_transcript_entries as u64)
                .to_le_bytes()
                .to_vec(),
            state.lookup_frontier_commitment.as_bytes().to_vec(),
            (state.lookup_frontier_entries as u64)
                .to_le_bytes()
                .to_vec(),
            state.kv_cache_commitment.as_bytes().to_vec(),
        ])
    }

    fn oracle_commit_phase17_matrix_public_state_boundary(
        manifest: &Phase17DecodingHistoryRollupMatrixManifest,
    ) -> Result<String> {
        if manifest.rollups.is_empty() {
            return Err(VmError::InvalidConfig(
                "decoding rollup matrix must contain at least one rollup manifest".to_string(),
            ));
        }

        let mut parts = vec![
            STWO_DECODING_ROLLUP_MATRIX_VERSION_PHASE17
                .as_bytes()
                .to_vec(),
            b"public-state-boundary".to_vec(),
            (manifest.total_layouts as u64).to_le_bytes().to_vec(),
            (manifest.total_rollups as u64).to_le_bytes().to_vec(),
            (manifest.total_segments as u64).to_le_bytes().to_vec(),
            (manifest.total_steps as u64).to_le_bytes().to_vec(),
        ];
        for (layout_index, rollup_manifest) in manifest.rollups.iter().enumerate() {
            if rollup_manifest.rollups.is_empty() {
                return Err(VmError::InvalidConfig(format!(
                    "decoding rollup matrix manifest {layout_index} must contain at least one rollup"
                )));
            }
            parts.push((layout_index as u64).to_le_bytes().to_vec());
            parts.push(
                (rollup_manifest.total_rollups as u64)
                    .to_le_bytes()
                    .to_vec(),
            );
            parts.push(
                (rollup_manifest.total_segments as u64)
                    .to_le_bytes()
                    .to_vec(),
            );
            parts.push((rollup_manifest.total_steps as u64).to_le_bytes().to_vec());
            parts.push(oracle_commit_phase12_layout(&rollup_manifest.layout).into_bytes());
            for rollup in &rollup_manifest.rollups {
                if rollup.public_state_boundary_commitment.is_empty() {
                    return Err(VmError::InvalidConfig(format!(
                        "decoding rollup matrix manifest {layout_index} contains a rollup with an empty public_state_boundary_commitment"
                    )));
                }
                parts.push((rollup.rollup_index as u64).to_le_bytes().to_vec());
                parts.push(
                    (rollup.global_start_step_index as u64)
                        .to_le_bytes()
                        .to_vec(),
                );
                parts.push((rollup.total_segments as u64).to_le_bytes().to_vec());
                parts.push((rollup.total_steps as u64).to_le_bytes().to_vec());
                parts.push(rollup.public_state_boundary_commitment.as_bytes().to_vec());
            }
        }
        Ok(oracle_blake2b_256(&parts))
    }

    fn oracle_commit_phase21_matrix_template(
        matrix: &Phase17DecodingHistoryRollupMatrixManifest,
    ) -> Result<String> {
        if matrix.rollups.is_empty() {
            return Err(VmError::InvalidConfig(
                "decoding matrix template source must contain at least one layout rollup"
                    .to_string(),
            ));
        }
        let mut parts = vec![
            STWO_DECODING_MATRIX_ACCUMULATOR_VERSION_PHASE21
                .as_bytes()
                .to_vec(),
            b"template".to_vec(),
            matrix.statement_version.as_bytes().to_vec(),
            matrix.proof_backend_version.as_bytes().to_vec(),
            (matrix.total_layouts as u64).to_le_bytes().to_vec(),
        ];
        for (layout_index, rollup_manifest) in matrix.rollups.iter().enumerate() {
            parts.push((layout_index as u64).to_le_bytes().to_vec());
            parts.push(oracle_commit_phase12_layout(&rollup_manifest.layout).into_bytes());
            parts.push(
                (rollup_manifest.history_chunk_pairs as u64)
                    .to_le_bytes()
                    .to_vec(),
            );
            parts.push(
                (rollup_manifest.max_rollup_segments as u64)
                    .to_le_bytes()
                    .to_vec(),
            );
        }
        Ok(oracle_blake2b_256(&parts))
    }

    fn oracle_commit_phase21_matrix_accumulator(
        manifest: &Phase21DecodingMatrixAccumulatorManifest,
    ) -> Result<String> {
        if manifest.matrices.is_empty() {
            return Err(VmError::InvalidConfig(
                "decoding matrix accumulator must contain at least one matrix".to_string(),
            ));
        }
        let mut parts = vec![
            STWO_DECODING_MATRIX_ACCUMULATOR_VERSION_PHASE21
                .as_bytes()
                .to_vec(),
            b"accumulator".to_vec(),
            manifest.template_commitment.as_bytes().to_vec(),
            (manifest.total_matrices as u64).to_le_bytes().to_vec(),
            (manifest.total_layouts as u64).to_le_bytes().to_vec(),
            (manifest.total_rollups as u64).to_le_bytes().to_vec(),
            (manifest.total_segments as u64).to_le_bytes().to_vec(),
            (manifest.total_steps as u64).to_le_bytes().to_vec(),
        ];
        for (matrix_index, matrix) in manifest.matrices.iter().enumerate() {
            if matrix.public_state_boundary_commitment.is_empty() {
                return Err(VmError::InvalidConfig(format!(
                    "decoding matrix accumulator matrix {matrix_index} has an empty public_state_boundary_commitment"
                )));
            }
            parts.push((matrix_index as u64).to_le_bytes().to_vec());
            parts.push(matrix.matrix_version.as_bytes().to_vec());
            parts.push(matrix.semantic_scope.as_bytes().to_vec());
            parts.push(matrix.proof_backend_version.as_bytes().to_vec());
            parts.push(matrix.statement_version.as_bytes().to_vec());
            parts.push((matrix.total_layouts as u64).to_le_bytes().to_vec());
            parts.push((matrix.total_rollups as u64).to_le_bytes().to_vec());
            parts.push((matrix.total_segments as u64).to_le_bytes().to_vec());
            parts.push((matrix.total_steps as u64).to_le_bytes().to_vec());
            parts.push(matrix.public_state_boundary_commitment.as_bytes().to_vec());
        }
        Ok(oracle_blake2b_256(&parts))
    }

    fn oracle_commit_phase22_lookup_template(
        accumulator: &Phase21DecodingMatrixAccumulatorManifest,
    ) -> Result<String> {
        if accumulator.matrices.is_empty() {
            return Err(VmError::InvalidConfig(
                "decoding lookup template source must contain at least one matrix".to_string(),
            ));
        }
        let mut parts = vec![
            STWO_DECODING_LOOKUP_ACCUMULATOR_VERSION_PHASE22
                .as_bytes()
                .to_vec(),
            b"lookup-template".to_vec(),
            accumulator.template_commitment.as_bytes().to_vec(),
            accumulator.proof_backend_version.as_bytes().to_vec(),
            accumulator.statement_version.as_bytes().to_vec(),
            (accumulator.total_matrices as u64).to_le_bytes().to_vec(),
            (accumulator.total_layouts as u64).to_le_bytes().to_vec(),
        ];
        for (matrix_index, matrix) in accumulator.matrices.iter().enumerate() {
            parts.push((matrix_index as u64).to_le_bytes().to_vec());
            parts.push((matrix.total_layouts as u64).to_le_bytes().to_vec());
            parts.push(matrix.public_state_boundary_commitment.as_bytes().to_vec());
            for (layout_index, rollup_manifest) in matrix.rollups.iter().enumerate() {
                parts.push((layout_index as u64).to_le_bytes().to_vec());
                parts.push(oracle_commit_phase12_layout(&rollup_manifest.layout).into_bytes());
                parts.push(
                    (rollup_manifest.history_chunk_pairs as u64)
                        .to_le_bytes()
                        .to_vec(),
                );
                parts.push(
                    (rollup_manifest.max_rollup_segments as u64)
                        .to_le_bytes()
                        .to_vec(),
                );
            }
        }
        Ok(oracle_blake2b_256(&parts))
    }

    fn oracle_commit_phase22_lookup_accumulator(
        manifest: &Phase22DecodingLookupAccumulatorManifest,
    ) -> Result<String> {
        if manifest.accumulator.matrices.is_empty() {
            return Err(VmError::InvalidConfig(
                "decoding lookup accumulator must contain at least one matrix".to_string(),
            ));
        }
        let mut parts = vec![
            STWO_DECODING_LOOKUP_ACCUMULATOR_VERSION_PHASE22
                .as_bytes()
                .to_vec(),
            b"lookup-accumulator".to_vec(),
            manifest.lookup_template_commitment.as_bytes().to_vec(),
            manifest.source_accumulator_commitment.as_bytes().to_vec(),
            (manifest.total_matrices as u64).to_le_bytes().to_vec(),
            (manifest.total_layouts as u64).to_le_bytes().to_vec(),
            (manifest.total_rollups as u64).to_le_bytes().to_vec(),
            (manifest.total_segments as u64).to_le_bytes().to_vec(),
            (manifest.total_steps as u64).to_le_bytes().to_vec(),
            (manifest.lookup_delta_entries as u64)
                .to_le_bytes()
                .to_vec(),
            (manifest.max_lookup_frontier_entries as u64)
                .to_le_bytes()
                .to_vec(),
        ];
        for (matrix_index, matrix) in manifest.accumulator.matrices.iter().enumerate() {
            parts.push((matrix_index as u64).to_le_bytes().to_vec());
            parts.push(matrix.public_state_boundary_commitment.as_bytes().to_vec());
            for (layout_index, rollup_manifest) in matrix.rollups.iter().enumerate() {
                parts.push((layout_index as u64).to_le_bytes().to_vec());
                for rollup in &rollup_manifest.rollups {
                    parts.push((rollup.rollup_index as u64).to_le_bytes().to_vec());
                    parts.push(
                        (rollup.global_start_step_index as u64)
                            .to_le_bytes()
                            .to_vec(),
                    );
                    parts.push((rollup.total_steps as u64).to_le_bytes().to_vec());
                    parts.push(rollup.public_state_boundary_commitment.as_bytes().to_vec());
                    parts.push(
                        rollup
                            .global_from_state
                            .lookup_transcript_commitment
                            .as_bytes()
                            .to_vec(),
                    );
                    parts.push(
                        (rollup.global_from_state.lookup_transcript_entries as u64)
                            .to_le_bytes()
                            .to_vec(),
                    );
                    parts.push(
                        rollup
                            .global_to_state
                            .lookup_transcript_commitment
                            .as_bytes()
                            .to_vec(),
                    );
                    parts.push(
                        (rollup.global_to_state.lookup_transcript_entries as u64)
                            .to_le_bytes()
                            .to_vec(),
                    );
                    parts.push(
                        rollup
                            .global_from_state
                            .lookup_frontier_commitment
                            .as_bytes()
                            .to_vec(),
                    );
                    parts.push(
                        (rollup.global_from_state.lookup_frontier_entries as u64)
                            .to_le_bytes()
                            .to_vec(),
                    );
                    parts.push(
                        rollup
                            .global_to_state
                            .lookup_frontier_commitment
                            .as_bytes()
                            .to_vec(),
                    );
                    parts.push(
                        (rollup.global_to_state.lookup_frontier_entries as u64)
                            .to_le_bytes()
                            .to_vec(),
                    );
                }
            }
        }
        Ok(oracle_blake2b_256(&parts))
    }

    fn oracle_commit_phase23_boundary_state(state: &Phase14DecodingState) -> String {
        oracle_blake2b_256(&[
            STWO_DECODING_CROSS_STEP_LOOKUP_ACCUMULATOR_VERSION_PHASE23
                .as_bytes()
                .to_vec(),
            b"boundary-state".to_vec(),
            state.position.to_le_bytes().to_vec(),
            state.layout_commitment.as_bytes().to_vec(),
            state.persistent_state_commitment.as_bytes().to_vec(),
            state.kv_history_commitment.as_bytes().to_vec(),
            (state.kv_history_length as u64).to_le_bytes().to_vec(),
            (state.kv_history_chunk_size as u64).to_le_bytes().to_vec(),
            state.kv_history_sealed_commitment.as_bytes().to_vec(),
            (state.kv_history_sealed_chunks as u64)
                .to_le_bytes()
                .to_vec(),
            state.kv_history_open_chunk_commitment.as_bytes().to_vec(),
            (state.kv_history_open_chunk_pairs as u64)
                .to_le_bytes()
                .to_vec(),
            state.kv_history_frontier_commitment.as_bytes().to_vec(),
            (state.kv_history_frontier_pairs as u64)
                .to_le_bytes()
                .to_vec(),
            state.lookup_transcript_commitment.as_bytes().to_vec(),
            (state.lookup_transcript_entries as u64)
                .to_le_bytes()
                .to_vec(),
            state.lookup_frontier_commitment.as_bytes().to_vec(),
            (state.lookup_frontier_entries as u64)
                .to_le_bytes()
                .to_vec(),
            state.kv_cache_commitment.as_bytes().to_vec(),
        ])
    }

    fn oracle_collect_phase23_member_segments<'a>(
        member: &'a Phase22DecodingLookupAccumulatorManifest,
    ) -> Result<Vec<&'a Phase15DecodingHistorySegment>> {
        let mut segments = Vec::new();
        for matrix in &member.accumulator.matrices {
            for rollup_manifest in &matrix.rollups {
                for rollup in &rollup_manifest.rollups {
                    for segment in &rollup.segments {
                        segments.push(segment);
                    }
                }
            }
        }
        if segments.is_empty() {
            return Err(VmError::InvalidConfig(
                "decoding cross-step lookup accumulator member must contain at least one segment"
                    .to_string(),
            ));
        }
        Ok(segments)
    }

    fn oracle_phase23_member_boundary_at_step(
        member: &Phase22DecodingLookupAccumulatorManifest,
        step_count: usize,
    ) -> Result<String> {
        let segments = oracle_collect_phase23_member_segments(member)?;
        if step_count > member.total_steps {
            return Err(VmError::InvalidConfig(format!(
                "decoding cross-step lookup accumulator oracle cannot derive step {} beyond total_steps {}",
                step_count, member.total_steps
            )));
        }
        let first_segment = segments.first().ok_or_else(|| {
            VmError::InvalidConfig(
                "decoding cross-step lookup accumulator member must contain at least one segment"
                    .to_string(),
            )
        })?;
        if step_count == 0 {
            return Ok(oracle_commit_phase23_boundary_state(
                &first_segment.global_from_state,
            ));
        }
        let mut consumed_steps = 0usize;
        for segment in segments {
            let next_consumed_steps =
                consumed_steps
                    .checked_add(segment.total_steps)
                    .ok_or_else(|| {
                        VmError::InvalidConfig(
                            "decoding cross-step lookup accumulator oracle step count overflowed"
                                .to_string(),
                        )
                    })?;
            if segment.chain.steps.len() != segment.total_steps {
                return Err(VmError::InvalidConfig(format!(
                    "decoding cross-step lookup accumulator oracle segment chain step count {} does not match total_steps {}",
                    segment.chain.steps.len(),
                    segment.total_steps
                )));
            }
            if step_count < next_consumed_steps {
                let local_step_count = step_count - consumed_steps;
                let boundary_state = if local_step_count == 0 {
                    &segment.global_from_state
                } else {
                    &segment.chain.steps[local_step_count - 1].to_state
                };
                return Ok(oracle_commit_phase23_boundary_state(boundary_state));
            }
            consumed_steps = next_consumed_steps;
            if step_count == consumed_steps {
                return Ok(oracle_commit_phase23_boundary_state(
                    &segment.global_to_state,
                ));
            }
        }
        Err(VmError::InvalidConfig(
            "decoding cross-step lookup accumulator oracle did not reach the requested boundary"
                .to_string(),
        ))
    }

    fn oracle_commit_phase23_lookup_accumulator(
        manifest: &Phase23DecodingCrossStepLookupAccumulatorManifest,
    ) -> Result<String> {
        if manifest.members.is_empty() {
            return Err(VmError::InvalidConfig(
                "decoding cross-step lookup accumulator must contain at least one member"
                    .to_string(),
            ));
        }
        let mut parts = vec![
            STWO_DECODING_CROSS_STEP_LOOKUP_ACCUMULATOR_VERSION_PHASE23
                .as_bytes()
                .to_vec(),
            b"cross-step-lookup-accumulator".to_vec(),
            manifest.source_template_commitment.as_bytes().to_vec(),
            manifest.lookup_template_commitment.as_bytes().to_vec(),
            manifest.start_boundary_commitment.as_bytes().to_vec(),
            manifest.end_boundary_commitment.as_bytes().to_vec(),
            (manifest.member_count as u64).to_le_bytes().to_vec(),
            (manifest.total_matrices as u64).to_le_bytes().to_vec(),
            (manifest.total_layouts as u64).to_le_bytes().to_vec(),
            (manifest.total_rollups as u64).to_le_bytes().to_vec(),
            (manifest.total_segments as u64).to_le_bytes().to_vec(),
            (manifest.total_steps as u64).to_le_bytes().to_vec(),
            (manifest.lookup_delta_entries as u64)
                .to_le_bytes()
                .to_vec(),
            (manifest.max_lookup_frontier_entries as u64)
                .to_le_bytes()
                .to_vec(),
        ];
        for (member_index, member) in manifest.members.iter().enumerate() {
            let start_boundary_commitment = oracle_phase23_member_boundary_at_step(member, 0)?;
            let end_boundary_commitment =
                oracle_phase23_member_boundary_at_step(member, member.total_steps)?;
            parts.push((member_index as u64).to_le_bytes().to_vec());
            parts.push(member.lookup_accumulator_commitment.as_bytes().to_vec());
            parts.push(start_boundary_commitment.into_bytes());
            parts.push(end_boundary_commitment.into_bytes());
            parts.push((member.total_matrices as u64).to_le_bytes().to_vec());
            parts.push((member.total_layouts as u64).to_le_bytes().to_vec());
            parts.push((member.total_rollups as u64).to_le_bytes().to_vec());
            parts.push((member.total_segments as u64).to_le_bytes().to_vec());
            parts.push((member.total_steps as u64).to_le_bytes().to_vec());
            parts.push((member.lookup_delta_entries as u64).to_le_bytes().to_vec());
            parts.push(
                (member.max_lookup_frontier_entries as u64)
                    .to_le_bytes()
                    .to_vec(),
            );
        }
        Ok(oracle_blake2b_256(&parts))
    }

    fn oracle_commit_phase24_relation_template_from_summaries(
        summaries: &[Phase24MemberSummary],
    ) -> Result<String> {
        if summaries.len() < 2 {
            return Err(VmError::InvalidConfig(
                "decoding state relation accumulator must contain at least two members".to_string(),
            ));
        }
        verify_phase24_member_relation_sequence(summaries)?;
        let mut parts = vec![
            STWO_DECODING_STATE_RELATION_ACCUMULATOR_VERSION_PHASE24
                .as_bytes()
                .to_vec(),
            b"relation-template".to_vec(),
            (summaries.len() as u64).to_le_bytes().to_vec(),
            summaries[0].source_template_commitment.as_bytes().to_vec(),
        ];
        for (member_index, member) in summaries.iter().enumerate() {
            parts.push((member_index as u64).to_le_bytes().to_vec());
            parts.push(member.lookup_template_commitment.as_bytes().to_vec());
            parts.push((member.total_matrices as u64).to_le_bytes().to_vec());
            parts.push((member.total_layouts as u64).to_le_bytes().to_vec());
            parts.push((member.total_rollups as u64).to_le_bytes().to_vec());
            parts.push((member.total_segments as u64).to_le_bytes().to_vec());
            parts.push((member.total_steps as u64).to_le_bytes().to_vec());
        }
        Ok(oracle_blake2b_256(&parts))
    }

    fn oracle_phase24_member_boundary_at_step(
        member: &Phase23DecodingCrossStepLookupAccumulatorManifest,
        step_count: usize,
    ) -> Result<String> {
        if member.members.is_empty() {
            return Err(VmError::InvalidConfig(
                "decoding state relation accumulator member must contain at least one nested member"
                    .to_string(),
            ));
        }
        if step_count > member.total_steps {
            return Err(VmError::InvalidConfig(format!(
                "decoding state relation accumulator oracle cannot derive step {} beyond total_steps {}",
                step_count, member.total_steps
            )));
        }
        if step_count == 0 {
            return oracle_phase23_member_boundary_at_step(&member.members[0], 0);
        }
        if step_count == member.total_steps {
            let last_member = member.members.last().ok_or_else(|| {
                VmError::InvalidConfig(
                    "decoding state relation accumulator member must contain at least one nested member"
                        .to_string(),
                )
            })?;
            return oracle_phase23_member_boundary_at_step(last_member, step_count);
        }
        for nested_member in &member.members {
            if nested_member.total_steps >= step_count {
                return oracle_phase23_member_boundary_at_step(nested_member, step_count);
            }
        }
        Err(VmError::InvalidConfig(
            "decoding state relation accumulator oracle did not reach the requested boundary"
                .to_string(),
        ))
    }

    fn oracle_summarize_phase24_members(
        members: &[Phase23DecodingCrossStepLookupAccumulatorManifest],
    ) -> Result<Vec<Phase24MemberSummary>> {
        let mut summaries = Vec::with_capacity(members.len());
        let mut previous_total_matrices = 0usize;
        let mut previous_total_layouts = 0usize;
        let mut previous_total_rollups = 0usize;
        let mut previous_total_segments = 0usize;
        let mut previous_total_steps = 0usize;
        let mut previous_lookup_delta_entries = 0usize;

        for (member_index, member) in members.iter().enumerate() {
            validate_phase23_decoding_cross_step_lookup_accumulator_shallow(member).map_err(
                |error| {
                    VmError::InvalidConfig(format!(
                        "Phase 24 oracle member {member_index} failed shallow Phase 23 validation: {error}"
                    ))
                },
            )?;
            let expected_lookup_accumulator = oracle_commit_phase23_lookup_accumulator(member)
                .map_err(|error| {
                    VmError::InvalidConfig(format!(
                        "Phase 24 oracle member {member_index} failed nested Phase 23 accumulation reconstruction: {error}"
                    ))
                })?;
            if member.accumulator_commitment != expected_lookup_accumulator {
                return Err(VmError::InvalidConfig(format!(
                    "Phase 24 oracle member {member_index} accumulator_commitment does not match the oracle-reconstructed Phase 23 lookup accumulator commitment"
                )));
            }
            if member.total_steps <= previous_total_steps {
                return Err(VmError::InvalidConfig(format!(
                    "Phase 24 oracle member {member_index} total_steps {} must strictly increase beyond the previous total_steps {}",
                    member.total_steps, previous_total_steps
                )));
            }
            if member.total_matrices < previous_total_matrices
                || member.total_layouts < previous_total_layouts
                || member.total_rollups < previous_total_rollups
                || member.total_segments < previous_total_segments
                || member.lookup_delta_entries < previous_lookup_delta_entries
            {
                return Err(VmError::InvalidConfig(format!(
                    "Phase 24 oracle member {member_index} must extend, not shrink, the previous cumulative member counts"
                )));
            }

            let start_state_commitment =
                oracle_phase24_member_boundary_at_step(member, previous_total_steps)?;
            let end_state_commitment =
                oracle_phase24_member_boundary_at_step(member, member.total_steps)?;

            summaries.push(Phase24MemberSummary {
                start_step: previous_total_steps,
                end_step: member.total_steps,
                total_matrices: member
                    .total_matrices
                    .checked_sub(previous_total_matrices)
                    .ok_or_else(|| {
                        VmError::InvalidConfig(format!(
                            "Phase 24 oracle member {member_index} total_matrices underflowed while deriving interval counts"
                        ))
                    })?,
                total_layouts: member
                    .total_layouts
                    .checked_sub(previous_total_layouts)
                    .ok_or_else(|| {
                        VmError::InvalidConfig(format!(
                            "Phase 24 oracle member {member_index} total_layouts underflowed while deriving interval counts"
                        ))
                    })?,
                total_rollups: member
                    .total_rollups
                    .checked_sub(previous_total_rollups)
                    .ok_or_else(|| {
                        VmError::InvalidConfig(format!(
                            "Phase 24 oracle member {member_index} total_rollups underflowed while deriving interval counts"
                        ))
                    })?,
                total_segments: member
                    .total_segments
                    .checked_sub(previous_total_segments)
                    .ok_or_else(|| {
                        VmError::InvalidConfig(format!(
                            "Phase 24 oracle member {member_index} total_segments underflowed while deriving interval counts"
                        ))
                    })?,
                total_steps: member
                    .total_steps
                    .checked_sub(previous_total_steps)
                    .ok_or_else(|| {
                        VmError::InvalidConfig(format!(
                            "Phase 24 oracle member {member_index} total_steps underflowed while deriving interval counts"
                        ))
                    })?,
                lookup_delta_entries: member
                    .lookup_delta_entries
                    .checked_sub(previous_lookup_delta_entries)
                    .ok_or_else(|| {
                        VmError::InvalidConfig(format!(
                            "Phase 24 oracle member {member_index} lookup_delta_entries underflowed while deriving interval counts"
                        ))
                    })?,
                max_lookup_frontier_entries: member.max_lookup_frontier_entries,
                source_template_commitment: member.source_template_commitment.clone(),
                lookup_template_commitment: member.lookup_template_commitment.clone(),
                lookup_accumulator_commitment: member.accumulator_commitment.clone(),
                start_state_commitment,
                end_state_commitment,
            });

            previous_total_matrices = member.total_matrices;
            previous_total_layouts = member.total_layouts;
            previous_total_rollups = member.total_rollups;
            previous_total_segments = member.total_segments;
            previous_total_steps = member.total_steps;
            previous_lookup_delta_entries = member.lookup_delta_entries;
        }

        Ok(summaries)
    }

    fn oracle_infer_phase24_rebase_baseline_from_phase25_manifest(
        manifest: &Phase25IntervalizedDecodingStateRelationManifest,
    ) -> Result<Phase24RebaseBaseline> {
        let last_member = manifest.members.last().ok_or_else(|| {
            VmError::InvalidConfig(
                "intervalized decoding state relation must contain at least one member".to_string(),
            )
        })?;
        Ok(Phase24RebaseBaseline {
            total_matrices: last_member
                .total_matrices
                .checked_sub(manifest.total_matrices)
                .ok_or_else(|| {
                    VmError::InvalidConfig(format!(
                        "intervalized decoding state relation total_matrices={} exceed the final nested cumulative total {}",
                        manifest.total_matrices, last_member.total_matrices
                    ))
                })?,
            total_layouts: last_member
                .total_layouts
                .checked_sub(manifest.total_layouts)
                .ok_or_else(|| {
                    VmError::InvalidConfig(format!(
                        "intervalized decoding state relation total_layouts={} exceed the final nested cumulative total {}",
                        manifest.total_layouts, last_member.total_layouts
                    ))
                })?,
            total_rollups: last_member
                .total_rollups
                .checked_sub(manifest.total_rollups)
                .ok_or_else(|| {
                    VmError::InvalidConfig(format!(
                        "intervalized decoding state relation total_rollups={} exceed the final nested cumulative total {}",
                        manifest.total_rollups, last_member.total_rollups
                    ))
                })?,
            total_segments: last_member
                .total_segments
                .checked_sub(manifest.total_segments)
                .ok_or_else(|| {
                    VmError::InvalidConfig(format!(
                        "intervalized decoding state relation total_segments={} exceed the final nested cumulative total {}",
                        manifest.total_segments, last_member.total_segments
                    ))
                })?,
            total_steps: last_member
                .total_steps
                .checked_sub(manifest.total_steps)
                .ok_or_else(|| {
                    VmError::InvalidConfig(format!(
                        "intervalized decoding state relation total_steps={} exceed the final nested cumulative total {}",
                        manifest.total_steps, last_member.total_steps
                    ))
                })?,
            lookup_delta_entries: last_member
                .lookup_delta_entries
                .checked_sub(manifest.lookup_delta_entries)
                .ok_or_else(|| {
                    VmError::InvalidConfig(format!(
                        "intervalized decoding state relation lookup_delta_entries={} exceed the final nested cumulative total {}",
                        manifest.lookup_delta_entries, last_member.lookup_delta_entries
                    ))
                })?,
        })
    }

    fn oracle_derive_phase24_rebased_member_summaries(
        members: &[Phase23DecodingCrossStepLookupAccumulatorManifest],
        baseline: Phase24RebaseBaseline,
    ) -> Result<Vec<Phase24MemberSummary>> {
        let mut summaries = Vec::with_capacity(members.len());
        let mut previous_total_matrices = baseline.total_matrices;
        let mut previous_total_layouts = baseline.total_layouts;
        let mut previous_total_rollups = baseline.total_rollups;
        let mut previous_total_segments = baseline.total_segments;
        let mut previous_total_steps = baseline.total_steps;
        let mut previous_lookup_delta_entries = baseline.lookup_delta_entries;

        for (member_index, member) in members.iter().enumerate() {
            validate_phase23_decoding_cross_step_lookup_accumulator_shallow(member).map_err(
                |error| {
                    VmError::InvalidConfig(format!(
                        "rebased Phase 24 oracle member {member_index} failed shallow Phase 23 validation: {error}"
                    ))
                },
            )?;
            let expected_lookup_accumulator =
                oracle_commit_phase23_lookup_accumulator(member).map_err(|error| {
                    VmError::InvalidConfig(format!(
                        "rebased Phase 24 oracle member {member_index} failed nested Phase 23 accumulation reconstruction: {error}"
                    ))
                })?;
            if member.accumulator_commitment != expected_lookup_accumulator {
                return Err(VmError::InvalidConfig(format!(
                    "rebased Phase 24 oracle member {member_index} accumulator_commitment does not match the oracle-reconstructed Phase 23 lookup accumulator commitment"
                )));
            }
            if member.total_steps <= previous_total_steps {
                return Err(VmError::InvalidConfig(format!(
                    "rebased Phase 24 oracle member {member_index} total_steps {} must strictly increase beyond the previous total_steps {}",
                    member.total_steps, previous_total_steps
                )));
            }
            if member.total_matrices < previous_total_matrices
                || member.total_layouts < previous_total_layouts
                || member.total_rollups < previous_total_rollups
                || member.total_segments < previous_total_segments
                || member.lookup_delta_entries < previous_lookup_delta_entries
            {
                return Err(VmError::InvalidConfig(format!(
                    "rebased Phase 24 oracle member {member_index} must extend, not shrink, the rebased cumulative member counts"
                )));
            }

            let start_state_commitment =
                oracle_phase24_member_boundary_at_step(member, previous_total_steps)?;
            let end_state_commitment =
                oracle_phase24_member_boundary_at_step(member, member.total_steps)?;

            summaries.push(Phase24MemberSummary {
                start_step: previous_total_steps
                    .checked_sub(baseline.total_steps)
                    .ok_or_else(|| {
                        VmError::InvalidConfig(format!(
                            "rebased Phase 24 oracle member {member_index} start_step underflowed"
                        ))
                    })?,
                end_step: member
                    .total_steps
                    .checked_sub(baseline.total_steps)
                    .ok_or_else(|| {
                        VmError::InvalidConfig(format!(
                            "rebased Phase 24 oracle member {member_index} end_step underflowed"
                        ))
                    })?,
                total_matrices: member
                    .total_matrices
                    .checked_sub(previous_total_matrices)
                    .ok_or_else(|| {
                        VmError::InvalidConfig(format!(
                            "rebased Phase 24 oracle member {member_index} total_matrices underflowed while deriving interval counts"
                        ))
                    })?,
                total_layouts: member
                    .total_layouts
                    .checked_sub(previous_total_layouts)
                    .ok_or_else(|| {
                        VmError::InvalidConfig(format!(
                            "rebased Phase 24 oracle member {member_index} total_layouts underflowed while deriving interval counts"
                        ))
                    })?,
                total_rollups: member
                    .total_rollups
                    .checked_sub(previous_total_rollups)
                    .ok_or_else(|| {
                        VmError::InvalidConfig(format!(
                            "rebased Phase 24 oracle member {member_index} total_rollups underflowed while deriving interval counts"
                        ))
                    })?,
                total_segments: member
                    .total_segments
                    .checked_sub(previous_total_segments)
                    .ok_or_else(|| {
                        VmError::InvalidConfig(format!(
                            "rebased Phase 24 oracle member {member_index} total_segments underflowed while deriving interval counts"
                        ))
                    })?,
                total_steps: member
                    .total_steps
                    .checked_sub(previous_total_steps)
                    .ok_or_else(|| {
                        VmError::InvalidConfig(format!(
                            "rebased Phase 24 oracle member {member_index} total_steps underflowed while deriving interval counts"
                        ))
                    })?,
                lookup_delta_entries: member
                    .lookup_delta_entries
                    .checked_sub(previous_lookup_delta_entries)
                    .ok_or_else(|| {
                        VmError::InvalidConfig(format!(
                            "rebased Phase 24 oracle member {member_index} lookup_delta_entries underflowed while deriving interval counts"
                        ))
                    })?,
                max_lookup_frontier_entries: member.max_lookup_frontier_entries,
                source_template_commitment: member.source_template_commitment.clone(),
                lookup_template_commitment: member.lookup_template_commitment.clone(),
                lookup_accumulator_commitment: member.accumulator_commitment.clone(),
                start_state_commitment,
                end_state_commitment,
            });

            previous_total_matrices = member.total_matrices;
            previous_total_layouts = member.total_layouts;
            previous_total_rollups = member.total_rollups;
            previous_total_segments = member.total_segments;
            previous_total_steps = member.total_steps;
            previous_lookup_delta_entries = member.lookup_delta_entries;
        }

        Ok(summaries)
    }

    fn oracle_commit_phase24_relation_template(
        manifest: &Phase24DecodingStateRelationAccumulatorManifest,
    ) -> Result<String> {
        let summaries = oracle_summarize_phase24_members(&manifest.members)?;
        oracle_commit_phase24_relation_template_from_summaries(&summaries)
    }

    fn oracle_commit_phase24_state_relation_accumulator(
        manifest: &Phase24DecodingStateRelationAccumulatorManifest,
    ) -> Result<String> {
        let summaries = oracle_summarize_phase24_members(&manifest.members)?;
        if summaries.len() < 2 {
            return Err(VmError::InvalidConfig(
                "decoding state relation accumulator must contain at least two members".to_string(),
            ));
        }
        verify_phase24_member_relation_sequence(&summaries)?;
        let first = summaries.first().expect("phase24 summaries are non-empty");
        let last = summaries.last().expect("phase24 summaries are non-empty");
        let relation_template_commitment =
            oracle_commit_phase24_relation_template_from_summaries(&summaries)?;
        let mut total_matrices = 0usize;
        let mut total_layouts = 0usize;
        let mut total_rollups = 0usize;
        let mut total_segments = 0usize;
        let mut total_steps = 0usize;
        let mut lookup_delta_entries = 0usize;
        let mut max_lookup_frontier_entries = 0usize;
        for (member_index, summary) in summaries.iter().enumerate() {
            total_matrices = total_matrices
                .checked_add(summary.total_matrices)
                .ok_or_else(|| {
                    VmError::InvalidConfig(format!(
                        "decoding state relation accumulator total_matrices overflowed while adding member {member_index}"
                    ))
                })?;
            total_layouts = total_layouts
                .checked_add(summary.total_layouts)
                .ok_or_else(|| {
                    VmError::InvalidConfig(format!(
                        "decoding state relation accumulator total_layouts overflowed while adding member {member_index}"
                    ))
                })?;
            total_rollups = total_rollups
                .checked_add(summary.total_rollups)
                .ok_or_else(|| {
                    VmError::InvalidConfig(format!(
                        "decoding state relation accumulator total_rollups overflowed while adding member {member_index}"
                    ))
                })?;
            total_segments = total_segments
                .checked_add(summary.total_segments)
                .ok_or_else(|| {
                    VmError::InvalidConfig(format!(
                        "decoding state relation accumulator total_segments overflowed while adding member {member_index}"
                    ))
                })?;
            total_steps = total_steps.checked_add(summary.total_steps).ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "decoding state relation accumulator total_steps overflowed while adding member {member_index}"
                ))
            })?;
            lookup_delta_entries = lookup_delta_entries
                .checked_add(summary.lookup_delta_entries)
                .ok_or_else(|| {
                    VmError::InvalidConfig(format!(
                        "decoding state relation accumulator lookup_delta_entries overflowed while adding member {member_index}"
                    ))
                })?;
            max_lookup_frontier_entries =
                max_lookup_frontier_entries.max(summary.max_lookup_frontier_entries);
        }
        let mut parts = vec![
            STWO_DECODING_STATE_RELATION_ACCUMULATOR_VERSION_PHASE24
                .as_bytes()
                .to_vec(),
            b"state-relation-accumulator".to_vec(),
            first.source_template_commitment.as_bytes().to_vec(),
            relation_template_commitment.as_bytes().to_vec(),
            first.start_state_commitment.as_bytes().to_vec(),
            last.end_state_commitment.as_bytes().to_vec(),
            (summaries.len() as u64).to_le_bytes().to_vec(),
            (total_matrices as u64).to_le_bytes().to_vec(),
            (total_layouts as u64).to_le_bytes().to_vec(),
            (total_rollups as u64).to_le_bytes().to_vec(),
            (total_segments as u64).to_le_bytes().to_vec(),
            (total_steps as u64).to_le_bytes().to_vec(),
            (lookup_delta_entries as u64).to_le_bytes().to_vec(),
            (max_lookup_frontier_entries as u64).to_le_bytes().to_vec(),
        ];
        for (member_index, member) in summaries.iter().enumerate() {
            parts.push((member_index as u64).to_le_bytes().to_vec());
            parts.push((member.start_step as u64).to_le_bytes().to_vec());
            parts.push((member.end_step as u64).to_le_bytes().to_vec());
            parts.push(member.lookup_accumulator_commitment.as_bytes().to_vec());
            parts.push(member.start_state_commitment.as_bytes().to_vec());
            parts.push(member.end_state_commitment.as_bytes().to_vec());
            parts.push((member.total_matrices as u64).to_le_bytes().to_vec());
            parts.push((member.total_layouts as u64).to_le_bytes().to_vec());
            parts.push((member.total_rollups as u64).to_le_bytes().to_vec());
            parts.push((member.total_segments as u64).to_le_bytes().to_vec());
            parts.push((member.total_steps as u64).to_le_bytes().to_vec());
            parts.push((member.lookup_delta_entries as u64).to_le_bytes().to_vec());
            parts.push(
                (member.max_lookup_frontier_entries as u64)
                    .to_le_bytes()
                    .to_vec(),
            );
        }
        Ok(oracle_blake2b_256(&parts))
    }

    fn oracle_commit_phase25_interval_template(
        manifest: &Phase25IntervalizedDecodingStateRelationManifest,
    ) -> Result<String> {
        let baseline = oracle_infer_phase24_rebase_baseline_from_phase25_manifest(manifest)?;
        let summaries =
            oracle_derive_phase24_rebased_member_summaries(&manifest.members, baseline)?;
        if summaries.len() < 2 {
            return Err(VmError::InvalidConfig(
                "intervalized decoding state relation must contain at least two members"
                    .to_string(),
            ));
        }
        verify_phase24_member_relation_sequence(&summaries)?;
        let mut parts = vec![
            STWO_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE25
                .as_bytes()
                .to_vec(),
            b"interval-template".to_vec(),
            manifest
                .source_relation_template_commitment
                .as_bytes()
                .to_vec(),
            (summaries.len() as u64).to_le_bytes().to_vec(),
        ];
        for (member_index, member) in summaries.iter().enumerate() {
            parts.push((member_index as u64).to_le_bytes().to_vec());
            parts.push(member.lookup_template_commitment.as_bytes().to_vec());
            parts.push(member.lookup_accumulator_commitment.as_bytes().to_vec());
            parts.push(member.start_state_commitment.as_bytes().to_vec());
            parts.push(member.end_state_commitment.as_bytes().to_vec());
            parts.push((member.start_step as u64).to_le_bytes().to_vec());
            parts.push((member.end_step as u64).to_le_bytes().to_vec());
            parts.push((member.total_matrices as u64).to_le_bytes().to_vec());
            parts.push((member.total_layouts as u64).to_le_bytes().to_vec());
            parts.push((member.total_rollups as u64).to_le_bytes().to_vec());
            parts.push((member.total_segments as u64).to_le_bytes().to_vec());
            parts.push((member.total_steps as u64).to_le_bytes().to_vec());
            parts.push((member.lookup_delta_entries as u64).to_le_bytes().to_vec());
            parts.push(
                (member.max_lookup_frontier_entries as u64)
                    .to_le_bytes()
                    .to_vec(),
            );
        }
        Ok(oracle_blake2b_256(&parts))
    }

    fn oracle_commit_phase25_intervalized_state_relation(
        manifest: &Phase25IntervalizedDecodingStateRelationManifest,
    ) -> Result<String> {
        validate_phase25_intervalized_decoding_state_relation_shallow(manifest)?;
        let baseline = oracle_infer_phase24_rebase_baseline_from_phase25_manifest(manifest)?;
        let summaries =
            oracle_derive_phase24_rebased_member_summaries(&manifest.members, baseline)?;
        if summaries.len() < 2 {
            return Err(VmError::InvalidConfig(
                "intervalized decoding state relation must contain at least two members"
                    .to_string(),
            ));
        }
        verify_phase24_member_relation_sequence(&summaries)?;
        let interval_template_commitment = oracle_commit_phase25_interval_template(manifest)?;
        let mut parts = vec![
            STWO_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE25
                .as_bytes()
                .to_vec(),
            b"intervalized-state-relation".to_vec(),
            manifest.source_template_commitment.as_bytes().to_vec(),
            manifest
                .source_relation_template_commitment
                .as_bytes()
                .to_vec(),
            manifest
                .source_relation_accumulator_commitment
                .as_bytes()
                .to_vec(),
            manifest.global_start_state_commitment.as_bytes().to_vec(),
            manifest.global_end_state_commitment.as_bytes().to_vec(),
            interval_template_commitment.as_bytes().to_vec(),
            (summaries.len() as u64).to_le_bytes().to_vec(),
            (manifest.total_matrices as u64).to_le_bytes().to_vec(),
            (manifest.total_layouts as u64).to_le_bytes().to_vec(),
            (manifest.total_rollups as u64).to_le_bytes().to_vec(),
            (manifest.total_segments as u64).to_le_bytes().to_vec(),
            (manifest.total_steps as u64).to_le_bytes().to_vec(),
            (manifest.lookup_delta_entries as u64)
                .to_le_bytes()
                .to_vec(),
            (manifest.max_lookup_frontier_entries as u64)
                .to_le_bytes()
                .to_vec(),
        ];
        for (member_index, member) in summaries.iter().enumerate() {
            parts.push((member_index as u64).to_le_bytes().to_vec());
            parts.push((member.start_step as u64).to_le_bytes().to_vec());
            parts.push((member.end_step as u64).to_le_bytes().to_vec());
            parts.push(member.lookup_accumulator_commitment.as_bytes().to_vec());
            parts.push(member.start_state_commitment.as_bytes().to_vec());
            parts.push(member.end_state_commitment.as_bytes().to_vec());
            parts.push((member.total_matrices as u64).to_le_bytes().to_vec());
            parts.push((member.total_layouts as u64).to_le_bytes().to_vec());
            parts.push((member.total_rollups as u64).to_le_bytes().to_vec());
            parts.push((member.total_segments as u64).to_le_bytes().to_vec());
            parts.push((member.total_steps as u64).to_le_bytes().to_vec());
            parts.push((member.lookup_delta_entries as u64).to_le_bytes().to_vec());
            parts.push(
                (member.max_lookup_frontier_entries as u64)
                    .to_le_bytes()
                    .to_vec(),
            );
        }
        Ok(oracle_blake2b_256(&parts))
    }

    fn oracle_summarize_phase26_members(
        members: &[Phase25IntervalizedDecodingStateRelationManifest],
    ) -> Result<Vec<Phase26MemberSummary>> {
        let mut summaries = Vec::with_capacity(members.len());
        let mut cumulative_steps = 0usize;

        for (member_index, member) in members.iter().enumerate() {
            validate_phase25_intervalized_decoding_state_relation_shallow(member).map_err(
                |error| {
                    VmError::InvalidConfig(format!(
                        "Phase 26 oracle member {member_index} failed shallow Phase 25 validation: {error}"
                    ))
                },
            )?;
            let expected_interval_template =
                oracle_commit_phase25_interval_template(member).map_err(|error| {
                    VmError::InvalidConfig(format!(
                        "Phase 26 oracle member {member_index} failed interval template reconstruction: {error}"
                    ))
                })?;
            if member.interval_template_commitment != expected_interval_template {
                return Err(VmError::InvalidConfig(format!(
                    "Phase 26 oracle member {member_index} interval_template_commitment does not match the oracle-reconstructed Phase 25 interval template commitment"
                )));
            }
            let expected_interval_accumulator =
                oracle_commit_phase25_intervalized_state_relation(member).map_err(|error| {
                    VmError::InvalidConfig(format!(
                        "Phase 26 oracle member {member_index} failed interval accumulator reconstruction: {error}"
                    ))
                })?;
            if member.interval_accumulator_commitment != expected_interval_accumulator {
                return Err(VmError::InvalidConfig(format!(
                    "Phase 26 oracle member {member_index} interval_accumulator_commitment does not match the oracle-reconstructed Phase 25 interval accumulator commitment"
                )));
            }
            if member.total_steps == 0 {
                return Err(VmError::InvalidConfig(format!(
                    "Phase 26 oracle member {member_index} must cover at least one step"
                )));
            }
            if member.source_template_commitment.is_empty() {
                return Err(VmError::InvalidConfig(format!(
                    "Phase 26 oracle member {member_index} has an empty source_template_commitment"
                )));
            }
            if member.global_start_state_commitment.is_empty()
                || member.global_end_state_commitment.is_empty()
            {
                return Err(VmError::InvalidConfig(format!(
                    "Phase 26 oracle member {member_index} has an empty state-boundary commitment"
                )));
            }

            let start_step = cumulative_steps;
            let end_step = cumulative_steps.checked_add(member.total_steps).ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "Phase 26 oracle member {member_index} total_steps overflowed while deriving folded intervals"
                ))
            })?;
            summaries.push(Phase26MemberSummary {
                start_step,
                end_step,
                total_matrices: member.total_matrices,
                total_layouts: member.total_layouts,
                total_rollups: member.total_rollups,
                total_segments: member.total_segments,
                total_steps: member.total_steps,
                lookup_delta_entries: member.lookup_delta_entries,
                max_lookup_frontier_entries: member.max_lookup_frontier_entries,
                source_template_commitment: member.source_template_commitment.clone(),
                interval_template_commitment: member.interval_template_commitment.clone(),
                interval_accumulator_commitment: member.interval_accumulator_commitment.clone(),
                start_state_commitment: member.global_start_state_commitment.clone(),
                end_state_commitment: member.global_end_state_commitment.clone(),
            });
            cumulative_steps = end_step;
        }

        verify_phase26_fold_sequence(&summaries)?;
        Ok(summaries)
    }

    fn oracle_commit_phase26_fold_template(
        manifest: &Phase26FoldedIntervalizedDecodingStateRelationManifest,
    ) -> Result<String> {
        validate_phase26_folded_intervalized_decoding_state_relation_shallow(manifest)?;
        let summaries = oracle_summarize_phase26_members(&manifest.members)?;
        let mut parts = vec![
            STWO_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE26
                .as_bytes()
                .to_vec(),
            b"fold-template".to_vec(),
            (manifest.bounded_fold_arity as u64).to_le_bytes().to_vec(),
            (summaries.len() as u64).to_le_bytes().to_vec(),
            manifest.source_template_commitment.as_bytes().to_vec(),
        ];
        for (member_index, member) in summaries.iter().enumerate() {
            parts.push((member_index as u64).to_le_bytes().to_vec());
            parts.push(member.interval_template_commitment.as_bytes().to_vec());
            parts.push((member.start_step as u64).to_le_bytes().to_vec());
            parts.push((member.end_step as u64).to_le_bytes().to_vec());
            parts.push((member.total_matrices as u64).to_le_bytes().to_vec());
            parts.push((member.total_layouts as u64).to_le_bytes().to_vec());
            parts.push((member.total_rollups as u64).to_le_bytes().to_vec());
            parts.push((member.total_segments as u64).to_le_bytes().to_vec());
            parts.push((member.total_steps as u64).to_le_bytes().to_vec());
            parts.push((member.lookup_delta_entries as u64).to_le_bytes().to_vec());
            parts.push(
                (member.max_lookup_frontier_entries as u64)
                    .to_le_bytes()
                    .to_vec(),
            );
        }
        Ok(oracle_blake2b_256(&parts))
    }

    fn oracle_commit_phase26_folded_intervalized_state_relation(
        manifest: &Phase26FoldedIntervalizedDecodingStateRelationManifest,
    ) -> Result<String> {
        validate_phase26_folded_intervalized_decoding_state_relation_shallow(manifest)?;
        let summaries = oracle_summarize_phase26_members(&manifest.members)?;
        let fold_template_commitment = oracle_commit_phase26_fold_template(manifest)?;
        let mut parts = vec![
            STWO_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE26
                .as_bytes()
                .to_vec(),
            b"folded-intervalized-state-relation".to_vec(),
            (manifest.bounded_fold_arity as u64).to_le_bytes().to_vec(),
            manifest.source_template_commitment.as_bytes().to_vec(),
            manifest.global_start_state_commitment.as_bytes().to_vec(),
            manifest.global_end_state_commitment.as_bytes().to_vec(),
            fold_template_commitment.as_bytes().to_vec(),
            (summaries.len() as u64).to_le_bytes().to_vec(),
            (manifest.total_matrices as u64).to_le_bytes().to_vec(),
            (manifest.total_layouts as u64).to_le_bytes().to_vec(),
            (manifest.total_rollups as u64).to_le_bytes().to_vec(),
            (manifest.total_segments as u64).to_le_bytes().to_vec(),
            (manifest.total_steps as u64).to_le_bytes().to_vec(),
            (manifest.lookup_delta_entries as u64)
                .to_le_bytes()
                .to_vec(),
            (manifest.max_lookup_frontier_entries as u64)
                .to_le_bytes()
                .to_vec(),
        ];
        for (member_index, member) in summaries.iter().enumerate() {
            parts.push((member_index as u64).to_le_bytes().to_vec());
            parts.push((member.start_step as u64).to_le_bytes().to_vec());
            parts.push((member.end_step as u64).to_le_bytes().to_vec());
            parts.push(member.interval_template_commitment.as_bytes().to_vec());
            parts.push(member.interval_accumulator_commitment.as_bytes().to_vec());
            parts.push(member.start_state_commitment.as_bytes().to_vec());
            parts.push(member.end_state_commitment.as_bytes().to_vec());
            parts.push((member.total_matrices as u64).to_le_bytes().to_vec());
            parts.push((member.total_layouts as u64).to_le_bytes().to_vec());
            parts.push((member.total_rollups as u64).to_le_bytes().to_vec());
            parts.push((member.total_segments as u64).to_le_bytes().to_vec());
            parts.push((member.total_steps as u64).to_le_bytes().to_vec());
            parts.push((member.lookup_delta_entries as u64).to_le_bytes().to_vec());
            parts.push(
                (member.max_lookup_frontier_entries as u64)
                    .to_le_bytes()
                    .to_vec(),
            );
        }
        Ok(oracle_blake2b_256(&parts))
    }

    fn oracle_summarize_phase27_members(
        members: &[Phase26FoldedIntervalizedDecodingStateRelationManifest],
    ) -> Result<Vec<Phase27MemberSummary>> {
        let mut summaries = Vec::with_capacity(members.len());
        let mut cumulative_steps = 0usize;

        for (member_index, member) in members.iter().enumerate() {
            validate_phase26_folded_intervalized_decoding_state_relation_shallow(member).map_err(
                |error| {
                    VmError::InvalidConfig(format!(
                        "Phase 27 oracle member {member_index} failed shallow Phase 26 validation: {error}"
                    ))
                },
            )?;
            let expected_fold_template =
                oracle_commit_phase26_fold_template(member).map_err(|error| {
                    VmError::InvalidConfig(format!(
                        "Phase 27 oracle member {member_index} failed fold template reconstruction: {error}"
                    ))
                })?;
            if member.fold_template_commitment != expected_fold_template {
                return Err(VmError::InvalidConfig(format!(
                    "Phase 27 oracle member {member_index} fold_template_commitment does not match the oracle-reconstructed Phase 26 fold template commitment"
                )));
            }
            let expected_folded_accumulator =
                oracle_commit_phase26_folded_intervalized_state_relation(member).map_err(
                    |error| {
                        VmError::InvalidConfig(format!(
                            "Phase 27 oracle member {member_index} failed folded interval accumulator reconstruction: {error}"
                        ))
                    },
                )?;
            if member.folded_interval_accumulator_commitment != expected_folded_accumulator {
                return Err(VmError::InvalidConfig(format!(
                    "Phase 27 oracle member {member_index} folded_interval_accumulator_commitment does not match the oracle-reconstructed Phase 26 folded interval accumulator commitment"
                )));
            }
            if member.total_steps == 0 {
                return Err(VmError::InvalidConfig(format!(
                    "Phase 27 oracle member {member_index} must cover at least one step"
                )));
            }
            if member.source_template_commitment.is_empty() {
                return Err(VmError::InvalidConfig(format!(
                    "Phase 27 oracle member {member_index} has an empty source_template_commitment"
                )));
            }
            if member.global_start_state_commitment.is_empty()
                || member.global_end_state_commitment.is_empty()
            {
                return Err(VmError::InvalidConfig(format!(
                    "Phase 27 oracle member {member_index} has an empty state-boundary commitment"
                )));
            }

            let start_step = cumulative_steps;
            let end_step = cumulative_steps.checked_add(member.total_steps).ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "Phase 27 oracle member {member_index} total_steps overflowed while deriving chained folds"
                ))
            })?;
            summaries.push(Phase27MemberSummary {
                start_step,
                end_step,
                bounded_fold_arity: member.bounded_fold_arity,
                total_phase25_members: member.member_count,
                total_matrices: member.total_matrices,
                total_layouts: member.total_layouts,
                total_rollups: member.total_rollups,
                total_segments: member.total_segments,
                total_steps: member.total_steps,
                lookup_delta_entries: member.lookup_delta_entries,
                max_lookup_frontier_entries: member.max_lookup_frontier_entries,
                source_template_commitment: member.source_template_commitment.clone(),
                fold_template_commitment: member.fold_template_commitment.clone(),
                folded_interval_accumulator_commitment: member
                    .folded_interval_accumulator_commitment
                    .clone(),
                start_state_commitment: member.global_start_state_commitment.clone(),
                end_state_commitment: member.global_end_state_commitment.clone(),
            });
            cumulative_steps = end_step;
        }

        verify_phase27_chain_sequence(&summaries)?;
        Ok(summaries)
    }

    fn oracle_commit_phase27_chain_template(
        manifest: &Phase27ChainedFoldedIntervalizedDecodingStateRelationManifest,
    ) -> Result<String> {
        validate_phase27_chained_folded_intervalized_decoding_state_relation_shallow(manifest)?;
        let summaries = oracle_summarize_phase27_members(&manifest.members)?;
        let mut parts = vec![
            STWO_CHAINED_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE27
                .as_bytes()
                .to_vec(),
            b"chain-template".to_vec(),
            (manifest.bounded_chain_arity as u64).to_le_bytes().to_vec(),
            (summaries.len() as u64).to_le_bytes().to_vec(),
            manifest.source_template_commitment.as_bytes().to_vec(),
        ];
        for (member_index, member) in summaries.iter().enumerate() {
            parts.push((member_index as u64).to_le_bytes().to_vec());
            parts.push((member.bounded_fold_arity as u64).to_le_bytes().to_vec());
            parts.push((member.total_phase25_members as u64).to_le_bytes().to_vec());
            parts.push(member.fold_template_commitment.as_bytes().to_vec());
            parts.push((member.start_step as u64).to_le_bytes().to_vec());
            parts.push((member.end_step as u64).to_le_bytes().to_vec());
            parts.push((member.total_matrices as u64).to_le_bytes().to_vec());
            parts.push((member.total_layouts as u64).to_le_bytes().to_vec());
            parts.push((member.total_rollups as u64).to_le_bytes().to_vec());
            parts.push((member.total_segments as u64).to_le_bytes().to_vec());
            parts.push((member.total_steps as u64).to_le_bytes().to_vec());
            parts.push((member.lookup_delta_entries as u64).to_le_bytes().to_vec());
            parts.push(
                (member.max_lookup_frontier_entries as u64)
                    .to_le_bytes()
                    .to_vec(),
            );
        }
        Ok(oracle_blake2b_256(&parts))
    }

    fn oracle_commit_phase27_chained_folded_intervalized_state_relation(
        manifest: &Phase27ChainedFoldedIntervalizedDecodingStateRelationManifest,
    ) -> Result<String> {
        validate_phase27_chained_folded_intervalized_decoding_state_relation_shallow(manifest)?;
        let summaries = oracle_summarize_phase27_members(&manifest.members)?;
        let chain_template_commitment = oracle_commit_phase27_chain_template(manifest)?;
        let mut parts = vec![
            STWO_CHAINED_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE27
                .as_bytes()
                .to_vec(),
            b"chained-folded-intervalized-state-relation".to_vec(),
            (manifest.bounded_chain_arity as u64).to_le_bytes().to_vec(),
            (manifest.total_phase25_members as u64)
                .to_le_bytes()
                .to_vec(),
            (manifest.max_nested_fold_arity as u64)
                .to_le_bytes()
                .to_vec(),
            manifest.source_template_commitment.as_bytes().to_vec(),
            manifest.global_start_state_commitment.as_bytes().to_vec(),
            manifest.global_end_state_commitment.as_bytes().to_vec(),
            chain_template_commitment.as_bytes().to_vec(),
            (summaries.len() as u64).to_le_bytes().to_vec(),
            (manifest.total_matrices as u64).to_le_bytes().to_vec(),
            (manifest.total_layouts as u64).to_le_bytes().to_vec(),
            (manifest.total_rollups as u64).to_le_bytes().to_vec(),
            (manifest.total_segments as u64).to_le_bytes().to_vec(),
            (manifest.total_steps as u64).to_le_bytes().to_vec(),
            (manifest.lookup_delta_entries as u64)
                .to_le_bytes()
                .to_vec(),
            (manifest.max_lookup_frontier_entries as u64)
                .to_le_bytes()
                .to_vec(),
        ];
        for (member_index, member) in summaries.iter().enumerate() {
            parts.push((member_index as u64).to_le_bytes().to_vec());
            parts.push((member.start_step as u64).to_le_bytes().to_vec());
            parts.push((member.end_step as u64).to_le_bytes().to_vec());
            parts.push((member.bounded_fold_arity as u64).to_le_bytes().to_vec());
            parts.push((member.total_phase25_members as u64).to_le_bytes().to_vec());
            parts.push(member.fold_template_commitment.as_bytes().to_vec());
            parts.push(
                member
                    .folded_interval_accumulator_commitment
                    .as_bytes()
                    .to_vec(),
            );
            parts.push(member.start_state_commitment.as_bytes().to_vec());
            parts.push(member.end_state_commitment.as_bytes().to_vec());
            parts.push((member.total_matrices as u64).to_le_bytes().to_vec());
            parts.push((member.total_layouts as u64).to_le_bytes().to_vec());
            parts.push((member.total_rollups as u64).to_le_bytes().to_vec());
            parts.push((member.total_segments as u64).to_le_bytes().to_vec());
            parts.push((member.total_steps as u64).to_le_bytes().to_vec());
            parts.push((member.lookup_delta_entries as u64).to_le_bytes().to_vec());
            parts.push(
                (member.max_lookup_frontier_entries as u64)
                    .to_le_bytes()
                    .to_vec(),
            );
        }
        Ok(oracle_blake2b_256(&parts))
    }

    fn oracle_commit_phase28_aggregation_template_from_summaries(
        manifest: &Phase28AggregatedChainedFoldedIntervalizedDecodingStateRelationManifest,
        summaries: &[Phase28MemberSummary],
    ) -> Result<String> {
        validate_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_shallow(
            manifest,
        )?;
        verify_phase28_aggregation_sequence(summaries)?;
        let mut parts = Vec::new();
        oracle_push_len_prefixed_part(
            &mut parts,
            STWO_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE28
                .as_bytes(),
        );
        oracle_push_len_prefixed_part(&mut parts, b"aggregation-template");
        parts.push(
            (manifest.bounded_aggregation_arity as u64)
                .to_le_bytes()
                .to_vec(),
        );
        parts.push((summaries.len() as u64).to_le_bytes().to_vec());
        oracle_push_len_prefixed_part(&mut parts, manifest.source_template_commitment.as_bytes());
        for (member_index, member) in summaries.iter().enumerate() {
            parts.push((member_index as u64).to_le_bytes().to_vec());
            parts.push((member.bounded_chain_arity as u64).to_le_bytes().to_vec());
            parts.push((member.total_phase26_members as u64).to_le_bytes().to_vec());
            parts.push((member.total_phase25_members as u64).to_le_bytes().to_vec());
            parts.push((member.max_nested_fold_arity as u64).to_le_bytes().to_vec());
            oracle_push_len_prefixed_part(&mut parts, member.chain_template_commitment.as_bytes());
            parts.push((member.start_step as u64).to_le_bytes().to_vec());
            parts.push((member.end_step as u64).to_le_bytes().to_vec());
            parts.push((member.total_matrices as u64).to_le_bytes().to_vec());
            parts.push((member.total_layouts as u64).to_le_bytes().to_vec());
            parts.push((member.total_rollups as u64).to_le_bytes().to_vec());
            parts.push((member.total_segments as u64).to_le_bytes().to_vec());
            parts.push((member.total_steps as u64).to_le_bytes().to_vec());
            parts.push((member.lookup_delta_entries as u64).to_le_bytes().to_vec());
            parts.push(
                (member.max_lookup_frontier_entries as u64)
                    .to_le_bytes()
                    .to_vec(),
            );
        }
        Ok(oracle_blake2b_256(&parts))
    }

    fn oracle_commit_phase28_aggregated_chained_folded_intervalized_state_relation_from_summaries(
        manifest: &Phase28AggregatedChainedFoldedIntervalizedDecodingStateRelationManifest,
        summaries: &[Phase28MemberSummary],
    ) -> Result<String> {
        validate_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_shallow(
            manifest,
        )?;
        verify_phase28_aggregation_sequence(summaries)?;
        let aggregation_template_commitment =
            oracle_commit_phase28_aggregation_template_from_summaries(manifest, summaries)?;
        let mut parts = Vec::new();
        oracle_push_len_prefixed_part(
            &mut parts,
            STWO_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE28
                .as_bytes(),
        );
        oracle_push_len_prefixed_part(
            &mut parts,
            b"aggregated-chained-folded-intervalized-state-relation",
        );
        parts.push(
            (manifest.bounded_aggregation_arity as u64)
                .to_le_bytes()
                .to_vec(),
        );
        parts.push(
            (manifest.total_phase26_members as u64)
                .to_le_bytes()
                .to_vec(),
        );
        parts.push(
            (manifest.total_phase25_members as u64)
                .to_le_bytes()
                .to_vec(),
        );
        parts.push(
            (manifest.max_nested_chain_arity as u64)
                .to_le_bytes()
                .to_vec(),
        );
        parts.push(
            (manifest.max_nested_fold_arity as u64)
                .to_le_bytes()
                .to_vec(),
        );
        oracle_push_len_prefixed_part(&mut parts, manifest.source_template_commitment.as_bytes());
        oracle_push_len_prefixed_part(
            &mut parts,
            manifest.global_start_state_commitment.as_bytes(),
        );
        oracle_push_len_prefixed_part(&mut parts, manifest.global_end_state_commitment.as_bytes());
        oracle_push_len_prefixed_part(&mut parts, aggregation_template_commitment.as_bytes());
        parts.push((summaries.len() as u64).to_le_bytes().to_vec());
        parts.push((manifest.total_matrices as u64).to_le_bytes().to_vec());
        parts.push((manifest.total_layouts as u64).to_le_bytes().to_vec());
        parts.push((manifest.total_rollups as u64).to_le_bytes().to_vec());
        parts.push((manifest.total_segments as u64).to_le_bytes().to_vec());
        parts.push((manifest.total_steps as u64).to_le_bytes().to_vec());
        parts.push(
            (manifest.lookup_delta_entries as u64)
                .to_le_bytes()
                .to_vec(),
        );
        parts.push(
            (manifest.max_lookup_frontier_entries as u64)
                .to_le_bytes()
                .to_vec(),
        );
        for (member_index, member) in summaries.iter().enumerate() {
            parts.push((member_index as u64).to_le_bytes().to_vec());
            parts.push((member.start_step as u64).to_le_bytes().to_vec());
            parts.push((member.end_step as u64).to_le_bytes().to_vec());
            parts.push((member.bounded_chain_arity as u64).to_le_bytes().to_vec());
            parts.push((member.total_phase26_members as u64).to_le_bytes().to_vec());
            parts.push((member.total_phase25_members as u64).to_le_bytes().to_vec());
            parts.push((member.max_nested_fold_arity as u64).to_le_bytes().to_vec());
            oracle_push_len_prefixed_part(&mut parts, member.chain_template_commitment.as_bytes());
            oracle_push_len_prefixed_part(
                &mut parts,
                member
                    .chained_folded_interval_accumulator_commitment
                    .as_bytes(),
            );
            oracle_push_len_prefixed_part(&mut parts, member.start_state_commitment.as_bytes());
            oracle_push_len_prefixed_part(&mut parts, member.end_state_commitment.as_bytes());
            parts.push((member.total_matrices as u64).to_le_bytes().to_vec());
            parts.push((member.total_layouts as u64).to_le_bytes().to_vec());
            parts.push((member.total_rollups as u64).to_le_bytes().to_vec());
            parts.push((member.total_segments as u64).to_le_bytes().to_vec());
            parts.push((member.total_steps as u64).to_le_bytes().to_vec());
            parts.push((member.lookup_delta_entries as u64).to_le_bytes().to_vec());
            parts.push(
                (member.max_lookup_frontier_entries as u64)
                    .to_le_bytes()
                    .to_vec(),
            );
        }
        Ok(oracle_blake2b_256(&parts))
    }

    fn oracle_advance_phase14_open_chunk(
        layout_commitment: &str,
        previous_open_chunk_commitment: &str,
        previous_open_chunk_pairs: usize,
        appended_pair: &[i16],
        pair_width: usize,
    ) -> String {
        let mut parts = vec![
            ORACLE_DECODING_STATE_VERSION_PHASE14.as_bytes().to_vec(),
            layout_commitment.as_bytes().to_vec(),
            b"history-open-advance".to_vec(),
            previous_open_chunk_commitment.as_bytes().to_vec(),
            (previous_open_chunk_pairs as u64).to_le_bytes().to_vec(),
            (pair_width as u64).to_le_bytes().to_vec(),
        ];
        for value in appended_pair {
            parts.push(value.to_le_bytes().to_vec());
        }
        oracle_blake2b_256(&parts)
    }

    fn oracle_seed_phase14_history(
        layout_commitment: &str,
        kv_cache_values: &[i16],
        lookup_rows_commitment: &str,
        pair_width: usize,
    ) -> Phase14HistoryAccumulator {
        let mut sealed_commitment =
            oracle_commit_phase14_history_empty_chunk(layout_commitment, pair_width);
        let mut sealed_chunks = 0usize;
        let mut open_chunk_pairs = 0usize;
        let mut open_chunk_values = Vec::new();

        for pair in kv_cache_values.chunks(pair_width) {
            open_chunk_values.extend_from_slice(pair);
            open_chunk_pairs += 1;
            if open_chunk_pairs == PHASE14_HISTORY_CHUNK_PAIRS {
                let chunk_commitment = oracle_commit_phase14_history_chunk(
                    layout_commitment,
                    pair_width,
                    &open_chunk_values,
                );
                sealed_commitment = oracle_fold_phase14_history_chunk(
                    layout_commitment,
                    &sealed_commitment,
                    sealed_chunks,
                    &chunk_commitment,
                );
                sealed_chunks += 1;
                open_chunk_pairs = 0;
                open_chunk_values.clear();
            }
        }

        let open_chunk_commitment = if open_chunk_pairs == 0 {
            oracle_commit_phase14_history_empty_chunk(layout_commitment, pair_width)
        } else {
            oracle_commit_phase14_history_chunk(layout_commitment, pair_width, &open_chunk_values)
        };
        let history_length = kv_cache_values.len() / pair_width;
        let frontier_values = kv_cache_values.to_vec();
        Phase14HistoryAccumulator {
            history_commitment: oracle_commit_phase14_history_total(
                layout_commitment,
                &sealed_commitment,
                sealed_chunks,
                &open_chunk_commitment,
                open_chunk_pairs,
                PHASE14_HISTORY_CHUNK_PAIRS,
                history_length,
            ),
            history_length,
            chunk_size: PHASE14_HISTORY_CHUNK_PAIRS,
            sealed_commitment,
            sealed_chunks,
            open_chunk_commitment,
            open_chunk_pairs,
            frontier_commitment: oracle_commit_phase12_named_slice(
                "kv-cache",
                layout_commitment,
                &frontier_values,
            ),
            frontier_pairs: history_length,
            frontier_values,
            lookup_transcript_commitment: oracle_commit_phase19_lookup_transcript_seed(
                layout_commitment,
                lookup_rows_commitment,
            ),
            lookup_transcript_entries: 1,
            lookup_frontier_commitment: oracle_commit_phase20_lookup_frontier(
                layout_commitment,
                &[lookup_rows_commitment.to_string()],
            ),
            lookup_frontier_entries: 1,
            lookup_frontier_values: vec![lookup_rows_commitment.to_string()],
        }
    }

    fn oracle_advance_phase14_history(
        layout_commitment: &str,
        previous: &Phase14HistoryAccumulator,
        appended_pair: &[i16],
        lookup_rows_commitment: &str,
        pair_width: usize,
    ) -> Result<Phase14HistoryAccumulator> {
        if appended_pair.len() != pair_width {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding history append expects pair_width={} values, got {}",
                pair_width,
                appended_pair.len()
            )));
        }
        let next_history_length = previous.history_length.checked_add(1).ok_or_else(|| {
            VmError::InvalidConfig(format!(
                "chunked decoding history length {} cannot be incremented",
                previous.history_length
            ))
        })?;
        let advanced_open_commitment = oracle_advance_phase14_open_chunk(
            layout_commitment,
            &previous.open_chunk_commitment,
            previous.open_chunk_pairs,
            appended_pair,
            pair_width,
        );
        let next_open_chunk_pairs = previous.open_chunk_pairs + 1;
        let (sealed_commitment, sealed_chunks, open_chunk_commitment, open_chunk_pairs) =
            if next_open_chunk_pairs == previous.chunk_size {
                let next_sealed_commitment = oracle_fold_phase14_history_chunk(
                    layout_commitment,
                    &previous.sealed_commitment,
                    previous.sealed_chunks,
                    &advanced_open_commitment,
                );
                (
                    next_sealed_commitment,
                    previous.sealed_chunks + 1,
                    oracle_commit_phase14_history_empty_chunk(layout_commitment, pair_width),
                    0,
                )
            } else {
                (
                    previous.sealed_commitment.clone(),
                    previous.sealed_chunks,
                    advanced_open_commitment,
                    next_open_chunk_pairs,
                )
            };

        let frontier_value_capacity =
            previous
                .frontier_pairs
                .checked_mul(pair_width)
                .ok_or_else(|| {
                    VmError::InvalidConfig(
                        "chunked decoding frontier value capacity overflowed".to_string(),
                    )
                })?;
        let mut frontier_values = previous.frontier_values.clone();
        frontier_values.extend_from_slice(appended_pair);
        if frontier_values.len() > frontier_value_capacity {
            let keep_from = frontier_values.len() - frontier_value_capacity;
            frontier_values = frontier_values[keep_from..].to_vec();
        }
        let lookup_transcript_entries = previous
            .lookup_transcript_entries
            .checked_add(1)
            .ok_or_else(|| {
                VmError::InvalidConfig(
                    "chunked decoding lookup transcript length overflowed".to_string(),
                )
            })?;
        let mut lookup_frontier_values = previous.lookup_frontier_values.clone();
        lookup_frontier_values.push(lookup_rows_commitment.to_string());
        if lookup_frontier_values.len() > PHASE14_HISTORY_CHUNK_PAIRS {
            let keep_from = lookup_frontier_values.len() - PHASE14_HISTORY_CHUNK_PAIRS;
            lookup_frontier_values = lookup_frontier_values[keep_from..].to_vec();
        }
        Ok(Phase14HistoryAccumulator {
            history_commitment: oracle_commit_phase14_history_total(
                layout_commitment,
                &sealed_commitment,
                sealed_chunks,
                &open_chunk_commitment,
                open_chunk_pairs,
                previous.chunk_size,
                next_history_length,
            ),
            history_length: next_history_length,
            chunk_size: previous.chunk_size,
            sealed_commitment,
            sealed_chunks,
            open_chunk_commitment,
            open_chunk_pairs,
            frontier_commitment: oracle_commit_phase12_named_slice(
                "kv-cache",
                layout_commitment,
                &frontier_values,
            ),
            frontier_pairs: previous.frontier_pairs,
            frontier_values,
            lookup_transcript_commitment: oracle_fold_phase19_lookup_transcript(
                layout_commitment,
                &previous.lookup_transcript_commitment,
                previous.lookup_transcript_entries,
                lookup_rows_commitment,
            ),
            lookup_transcript_entries,
            lookup_frontier_commitment: oracle_commit_phase20_lookup_frontier(
                layout_commitment,
                &lookup_frontier_values,
            ),
            lookup_frontier_entries: lookup_frontier_values.len(),
            lookup_frontier_values,
        })
    }

    fn oracle_verify_phase12_decoding_chain(manifest: &Phase12DecodingChainManifest) -> Result<()> {
        manifest.layout.validate()?;
        let expected_layout_commitment = oracle_commit_phase12_layout(&manifest.layout);
        let latest_cached_range = manifest.layout.latest_cached_pair_range()?;
        if manifest.proof_backend != StarkProofBackend::Stwo {
            return Err(VmError::InvalidConfig(format!(
                "decoding chain backend `{}` is not `stwo`",
                manifest.proof_backend
            )));
        }
        if manifest.chain_version != STWO_DECODING_CHAIN_VERSION_PHASE12 {
            return Err(VmError::InvalidConfig(format!(
                "unsupported decoding chain version `{}`",
                manifest.chain_version
            )));
        }
        if manifest.semantic_scope != STWO_DECODING_CHAIN_SCOPE_PHASE12 {
            return Err(VmError::InvalidConfig(format!(
                "unsupported decoding chain semantic scope `{}`",
                manifest.semantic_scope
            )));
        }
        if manifest.proof_backend_version != crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12 {
            return Err(VmError::InvalidConfig(format!(
                "unsupported decoding proof backend version `{}` (expected `{}`)",
                manifest.proof_backend_version,
                crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12
            )));
        }
        if manifest.steps.is_empty() || manifest.total_steps != manifest.steps.len() {
            return Err(VmError::InvalidConfig(
                "decoding chain step count metadata is inconsistent".to_string(),
            ));
        }
        if manifest.shared_lookup_artifacts.is_empty() {
            return Err(VmError::InvalidConfig(
                "decoding chain must contain at least one shared lookup artifact".to_string(),
            ));
        }
        if manifest.shared_lookup_artifacts.len() > manifest.steps.len() {
            return Err(VmError::InvalidConfig(format!(
                "decoding chain contains {} shared lookup artifacts for only {} steps",
                manifest.shared_lookup_artifacts.len(),
                manifest.steps.len()
            )));
        }

        let referenced_artifacts: HashSet<String> = manifest
            .steps
            .iter()
            .map(|step| step.shared_lookup_artifact_commitment.clone())
            .collect();
        let registry = oracle_build_phase12_shared_lookup_artifact_index(
            &manifest.shared_lookup_artifacts,
            &referenced_artifacts,
            manifest.layout.lookup_range()?.len(),
            "oracle decoding chain shared lookup",
        )?;
        let expected_step_semantic_scope = CLAIM_SEMANTIC_SCOPE_V1;

        let mut previous_history_commitment: Option<String> = None;
        let mut previous_history_length: Option<usize> = None;
        let mut previous_expected_to: Option<Phase12DecodingState> = None;
        for (step_index, step) in manifest.steps.iter().enumerate() {
            if step.proof.proof_backend != StarkProofBackend::Stwo {
                return Err(VmError::InvalidConfig(format!(
                    "decoding step {step_index} proof backend `{}` is not `stwo`",
                    step.proof.proof_backend
                )));
            }
            if step.proof.proof_backend_version != crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12
            {
                return Err(VmError::InvalidConfig(format!(
                    "decoding step {step_index} proof backend version `{}` does not match the supported Phase 12 version `{}`",
                    step.proof.proof_backend_version,
                    crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12
                )));
            }
            if step.proof.proof_backend_version != manifest.proof_backend_version
                || step.proof.claim.statement_version != manifest.statement_version
            {
                return Err(VmError::InvalidConfig(format!(
                    "decoding step {step_index} proof metadata does not match manifest"
                )));
            }
            if step.proof.claim.semantic_scope != expected_step_semantic_scope {
                return Err(VmError::InvalidConfig(format!(
                    "decoding step {step_index} semantic scope `{}` does not match expected `{}`",
                    step.proof.claim.semantic_scope, expected_step_semantic_scope
                )));
            }
            if !matches_decoding_step_v2_family_with_layout(
                &step.proof.claim.program,
                &manifest.layout,
            ) {
                return Err(VmError::InvalidConfig(format!(
                    "decoding step {step_index} is not a decoding_step_v2-family proof for the manifest layout"
                )));
            }
            let registry_artifact = oracle_shared_lookup_artifact_by_commitment(
                &registry,
                &step.shared_lookup_artifact_commitment,
            )?;
            let proof_artifact = oracle_phase12_shared_lookup_artifact_from_proof_payload(
                &step.proof,
                &manifest.layout,
                &expected_layout_commitment,
            )?
            .ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "decoding step {step_index} is missing its Phase 12 shared lookup artifact payload"
                ))
            })?;
            if *registry_artifact != proof_artifact {
                return Err(VmError::InvalidConfig(format!(
                    "decoding step {step_index} shared lookup artifact `{}` does not match the proof payload",
                    step.shared_lookup_artifact_commitment
                )));
            }

            let from_view = oracle_phase12_state_view(
                step.proof.claim.program.initial_memory(),
                &manifest.layout,
            )?;
            let from_history_commitment =
                previous_history_commitment.clone().unwrap_or_else(|| {
                    oracle_commit_phase12_history_seed(
                        &expected_layout_commitment,
                        &step.proof.claim.program.initial_memory()
                            [manifest.layout.kv_cache_range().expect("kv cache")],
                        manifest.layout.pair_width,
                    )
                });
            let from_history_length =
                previous_history_length.unwrap_or(manifest.layout.rolling_kv_pairs);
            let expected_from = Phase12DecodingState {
                state_version: STWO_DECODING_STATE_VERSION_PHASE12.to_string(),
                step_index,
                position: from_view.position,
                layout_commitment: from_view.layout_commitment.clone(),
                persistent_state_commitment: from_view.persistent_state_commitment.clone(),
                kv_history_commitment: from_history_commitment.clone(),
                kv_history_length: from_history_length,
                kv_cache_commitment: from_view.kv_cache_commitment.clone(),
                incoming_token_commitment: from_view.incoming_token_commitment.clone(),
                query_commitment: from_view.query_commitment.clone(),
                output_commitment: from_view.output_commitment.clone(),
                lookup_rows_commitment: from_view.lookup_rows_commitment.clone(),
                public_state_commitment: String::new(),
            };
            let expected_from = Phase12DecodingState {
                public_state_commitment: oracle_commit_phase12_public_state(&expected_from),
                ..expected_from
            };
            if step.from_state != expected_from {
                return Err(VmError::InvalidConfig(format!(
                    "decoding step {step_index} recorded from_state does not match the oracle replay"
                )));
            }
            if let Some(previous) = &previous_expected_to {
                if previous.public_state_commitment != expected_from.public_state_commitment {
                    return Err(VmError::InvalidConfig(format!(
                        "decoding chain link {} -> {} does not preserve the carried public-state commitment",
                        step_index - 1,
                        step_index
                    )));
                }
                if previous.persistent_state_commitment != expected_from.persistent_state_commitment
                {
                    return Err(VmError::InvalidConfig(format!(
                        "decoding chain link {} -> {} does not preserve the persistent KV-cache state commitment",
                        step_index - 1,
                        step_index
                    )));
                }
                if previous.kv_cache_commitment != expected_from.kv_cache_commitment {
                    return Err(VmError::InvalidConfig(format!(
                        "decoding chain link {} -> {} does not preserve the KV-cache commitment",
                        step_index - 1,
                        step_index
                    )));
                }
                if previous.position != expected_from.position {
                    return Err(VmError::InvalidConfig(format!(
                        "decoding chain link {} -> {} does not preserve the decoding position",
                        step_index - 1,
                        step_index
                    )));
                }
                if previous.kv_history_commitment != expected_from.kv_history_commitment {
                    return Err(VmError::InvalidConfig(format!(
                        "decoding chain link {} -> {} does not preserve the cumulative KV-history commitment",
                        step_index - 1,
                        step_index
                    )));
                }
                if previous.kv_history_length != expected_from.kv_history_length {
                    return Err(VmError::InvalidConfig(format!(
                        "decoding chain link {} -> {} does not preserve the cumulative KV-history length",
                        step_index - 1,
                        step_index
                    )));
                }
            }

            let to_view =
                oracle_phase12_state_view(&step.proof.claim.final_state.memory, &manifest.layout)?;
            if proof_artifact.lookup_rows_commitment != to_view.lookup_rows_commitment {
                return Err(VmError::InvalidConfig(format!(
                    "decoding step {step_index} shared lookup artifact `{}` does not match the proof's final-state lookup rows",
                    step.shared_lookup_artifact_commitment
                )));
            }
            let to_history_length = from_history_length.checked_add(1).ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "decoding step {step_index} history length {from_history_length} cannot be incremented"
                ))
            })?;
            let to_history_commitment = oracle_advance_phase12_history_commitment(
                &expected_layout_commitment,
                &from_history_commitment,
                &step.proof.claim.final_state.memory[latest_cached_range.clone()],
                to_history_length,
            );
            let expected_to = Phase12DecodingState {
                state_version: STWO_DECODING_STATE_VERSION_PHASE12.to_string(),
                step_index: step_index + 1,
                position: to_view.position,
                layout_commitment: to_view.layout_commitment.clone(),
                persistent_state_commitment: to_view.persistent_state_commitment.clone(),
                kv_history_commitment: to_history_commitment.clone(),
                kv_history_length: to_history_length,
                kv_cache_commitment: to_view.kv_cache_commitment.clone(),
                incoming_token_commitment: to_view.incoming_token_commitment.clone(),
                query_commitment: to_view.query_commitment.clone(),
                output_commitment: to_view.output_commitment.clone(),
                lookup_rows_commitment: to_view.lookup_rows_commitment.clone(),
                public_state_commitment: String::new(),
            };
            let expected_to = Phase12DecodingState {
                public_state_commitment: oracle_commit_phase12_public_state(&expected_to),
                ..expected_to
            };
            if step.to_state != expected_to {
                return Err(VmError::InvalidConfig(format!(
                    "decoding step {step_index} recorded to_state does not match the oracle replay"
                )));
            }
            if expected_to.position != expected_from.position + 1 {
                return Err(VmError::InvalidConfig(format!(
                    "decoding step {step_index} does not advance the decoding position by exactly one token"
                )));
            }
            previous_history_commitment = Some(to_history_commitment);
            previous_history_length = Some(to_history_length);
            previous_expected_to = Some(expected_to);
        }
        validate_phase12_chain_steps(&manifest.layout, &manifest.steps)
    }

    fn oracle_verify_phase14_decoding_chain(manifest: &Phase14DecodingChainManifest) -> Result<()> {
        manifest.layout.validate()?;
        let expected_layout_commitment = oracle_commit_phase12_layout(&manifest.layout);
        let kv_cache_range = manifest.layout.kv_cache_range()?;
        let latest_cached_range = manifest.layout.latest_cached_pair_range()?;
        if manifest.proof_backend != StarkProofBackend::Stwo {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding chain backend `{}` is not `stwo`",
                manifest.proof_backend
            )));
        }
        if manifest.chain_version != STWO_DECODING_CHAIN_VERSION_PHASE14 {
            return Err(VmError::InvalidConfig(format!(
                "unsupported chunked decoding chain version `{}`",
                manifest.chain_version
            )));
        }
        if manifest.semantic_scope != STWO_DECODING_CHAIN_SCOPE_PHASE14 {
            return Err(VmError::InvalidConfig(format!(
                "unsupported chunked decoding semantic scope `{}`",
                manifest.semantic_scope
            )));
        }
        if manifest.proof_backend_version != crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12 {
            return Err(VmError::InvalidConfig(format!(
                "unsupported chunked decoding proof backend version `{}` (expected `{}`)",
                manifest.proof_backend_version,
                crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12
            )));
        }
        if manifest.statement_version != crate::proof::CLAIM_STATEMENT_VERSION_V1 {
            return Err(VmError::InvalidConfig(format!(
                "unsupported chunked decoding statement version `{}`",
                manifest.statement_version
            )));
        }
        if manifest.history_chunk_pairs != PHASE14_HISTORY_CHUNK_PAIRS {
            return Err(VmError::InvalidConfig(format!(
                "unsupported chunked decoding history_chunk_pairs={} (expected {})",
                manifest.history_chunk_pairs, PHASE14_HISTORY_CHUNK_PAIRS
            )));
        }
        if manifest.steps.is_empty() || manifest.total_steps != manifest.steps.len() {
            return Err(VmError::InvalidConfig(
                "chunked decoding chain step count metadata is inconsistent".to_string(),
            ));
        }
        if manifest.shared_lookup_artifacts.is_empty() {
            return Err(VmError::InvalidConfig(
                "chunked decoding chain must contain at least one shared lookup artifact"
                    .to_string(),
            ));
        }
        if manifest.shared_lookup_artifacts.len() > manifest.steps.len() {
            return Err(VmError::InvalidConfig(format!(
                "chunked decoding chain contains {} shared lookup artifacts for only {} steps",
                manifest.shared_lookup_artifacts.len(),
                manifest.steps.len()
            )));
        }
        let referenced_artifacts: HashSet<String> = manifest
            .steps
            .iter()
            .map(|step| step.shared_lookup_artifact_commitment.clone())
            .collect();
        let registry = oracle_build_phase12_shared_lookup_artifact_index(
            &manifest.shared_lookup_artifacts,
            &referenced_artifacts,
            manifest.layout.lookup_range()?.len(),
            "oracle chunked decoding shared lookup",
        )?;
        let expected_step_semantic_scope = CLAIM_SEMANTIC_SCOPE_V1;
        let mut accumulator: Option<Phase14HistoryAccumulator> = None;
        let mut previous_expected_to: Option<Phase14DecodingState> = None;
        for (step_index, step) in manifest.steps.iter().enumerate() {
            if !matches_decoding_step_v2_family_with_layout(
                &step.proof.claim.program,
                &manifest.layout,
            ) {
                return Err(VmError::InvalidConfig(format!(
                    "chunked decoding step {step_index} is not a decoding_step_v2-family proof for the manifest layout"
                )));
            }
            if step.proof.proof_backend != StarkProofBackend::Stwo {
                return Err(VmError::InvalidConfig(format!(
                    "chunked decoding step {step_index} proof backend `{}` is not `stwo`",
                    step.proof.proof_backend
                )));
            }
            if step.proof.proof_backend_version != crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12
            {
                return Err(VmError::InvalidConfig(format!(
                    "chunked decoding step {step_index} proof backend version `{}` is not `{}`",
                    step.proof.proof_backend_version,
                    crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12
                )));
            }
            if step.proof.claim.statement_version != manifest.statement_version {
                return Err(VmError::InvalidConfig(format!(
                    "chunked decoding step {step_index} statement version `{}` does not match manifest `{}`",
                    step.proof.claim.statement_version, manifest.statement_version
                )));
            }
            if step.proof.claim.semantic_scope != expected_step_semantic_scope {
                return Err(VmError::InvalidConfig(format!(
                    "chunked decoding step {step_index} semantic scope `{}` does not match expected `{}`",
                    step.proof.claim.semantic_scope, expected_step_semantic_scope
                )));
            }
            let registry_artifact = oracle_shared_lookup_artifact_by_commitment(
                &registry,
                &step.shared_lookup_artifact_commitment,
            )?;
            let from_view = oracle_phase12_state_view(
                step.proof.claim.program.initial_memory(),
                &manifest.layout,
            )?;
            let current = accumulator.clone().unwrap_or_else(|| {
                oracle_seed_phase14_history(
                    &expected_layout_commitment,
                    &step.proof.claim.program.initial_memory()[kv_cache_range.clone()],
                    &from_view.lookup_rows_commitment,
                    manifest.layout.pair_width,
                )
            });
            let expected_from = Phase14DecodingState {
                state_version: STWO_DECODING_STATE_VERSION_PHASE14.to_string(),
                step_index,
                position: from_view.position,
                layout_commitment: from_view.layout_commitment.clone(),
                persistent_state_commitment: from_view.persistent_state_commitment.clone(),
                kv_history_commitment: current.history_commitment.clone(),
                kv_history_length: current.history_length,
                kv_history_chunk_size: current.chunk_size,
                kv_history_sealed_commitment: current.sealed_commitment.clone(),
                kv_history_sealed_chunks: current.sealed_chunks,
                kv_history_open_chunk_commitment: current.open_chunk_commitment.clone(),
                kv_history_open_chunk_pairs: current.open_chunk_pairs,
                kv_history_frontier_commitment: current.frontier_commitment.clone(),
                kv_history_frontier_pairs: current.frontier_pairs,
                lookup_transcript_commitment: current.lookup_transcript_commitment.clone(),
                lookup_transcript_entries: current.lookup_transcript_entries,
                lookup_frontier_commitment: current.lookup_frontier_commitment.clone(),
                lookup_frontier_entries: current.lookup_frontier_entries,
                kv_cache_commitment: from_view.kv_cache_commitment.clone(),
                incoming_token_commitment: from_view.incoming_token_commitment.clone(),
                query_commitment: from_view.query_commitment.clone(),
                output_commitment: from_view.output_commitment.clone(),
                lookup_rows_commitment: from_view.lookup_rows_commitment.clone(),
                public_state_commitment: String::new(),
            };
            let expected_from = Phase14DecodingState {
                public_state_commitment: oracle_commit_phase14_public_state(&expected_from),
                ..expected_from
            };
            if step.from_state != expected_from {
                return Err(VmError::InvalidConfig(format!(
                    "chunked decoding step {step_index} recorded from_state does not match the oracle replay"
                )));
            }
            if let Some(previous) = &previous_expected_to {
                if previous.public_state_commitment != expected_from.public_state_commitment {
                    return Err(VmError::InvalidConfig(format!(
                        "chunked decoding chain link {} -> {} does not preserve the carried public-state commitment",
                        step_index - 1,
                        step_index
                    )));
                }
                if previous.persistent_state_commitment != expected_from.persistent_state_commitment
                {
                    return Err(VmError::InvalidConfig(format!(
                        "chunked decoding chain link {} -> {} does not preserve the persistent KV-cache state commitment",
                        step_index - 1,
                        step_index
                    )));
                }
                if previous.kv_cache_commitment != expected_from.kv_cache_commitment {
                    return Err(VmError::InvalidConfig(format!(
                        "chunked decoding chain link {} -> {} does not preserve the KV-cache commitment",
                        step_index - 1,
                        step_index
                    )));
                }
                if previous.position != expected_from.position {
                    return Err(VmError::InvalidConfig(format!(
                        "chunked decoding chain link {} -> {} does not preserve the decoding position",
                        step_index - 1,
                        step_index
                    )));
                }
                if previous.kv_history_commitment != expected_from.kv_history_commitment {
                    return Err(VmError::InvalidConfig(format!(
                        "chunked decoding chain link {} -> {} does not preserve the cumulative KV-history commitment",
                        step_index - 1,
                        step_index
                    )));
                }
                if previous.kv_history_length != expected_from.kv_history_length {
                    return Err(VmError::InvalidConfig(format!(
                        "chunked decoding chain link {} -> {} does not preserve the cumulative KV-history length",
                        step_index - 1,
                        step_index
                    )));
                }
            }

            let to_view =
                oracle_phase12_state_view(&step.proof.claim.final_state.memory, &manifest.layout)?;
            let proof_artifact = oracle_phase12_shared_lookup_artifact_from_proof_payload(
                &step.proof,
                &manifest.layout,
                &expected_layout_commitment,
            )?
            .ok_or_else(|| {
                VmError::InvalidConfig(format!(
                    "chunked decoding step {step_index} is missing its Phase 12 shared lookup artifact payload"
                ))
            })?;
            if *registry_artifact != proof_artifact {
                return Err(VmError::InvalidConfig(format!(
                    "chunked decoding step {step_index} shared lookup artifact `{}` does not match the proof payload",
                    step.shared_lookup_artifact_commitment
                )));
            }
            if proof_artifact.lookup_rows_commitment != to_view.lookup_rows_commitment {
                return Err(VmError::InvalidConfig(format!(
                    "chunked decoding step {step_index} shared lookup artifact `{}` does not match the proof's final-state lookup rows",
                    step.shared_lookup_artifact_commitment
                )));
            }
            let next = oracle_advance_phase14_history(
                &expected_layout_commitment,
                &current,
                &step.proof.claim.final_state.memory[latest_cached_range.clone()],
                &proof_artifact.lookup_rows_commitment,
                manifest.layout.pair_width,
            )?;
            let expected_to = Phase14DecodingState {
                state_version: STWO_DECODING_STATE_VERSION_PHASE14.to_string(),
                step_index: step_index + 1,
                position: to_view.position,
                layout_commitment: to_view.layout_commitment.clone(),
                persistent_state_commitment: to_view.persistent_state_commitment.clone(),
                kv_history_commitment: next.history_commitment.clone(),
                kv_history_length: next.history_length,
                kv_history_chunk_size: next.chunk_size,
                kv_history_sealed_commitment: next.sealed_commitment.clone(),
                kv_history_sealed_chunks: next.sealed_chunks,
                kv_history_open_chunk_commitment: next.open_chunk_commitment.clone(),
                kv_history_open_chunk_pairs: next.open_chunk_pairs,
                kv_history_frontier_commitment: next.frontier_commitment.clone(),
                kv_history_frontier_pairs: next.frontier_pairs,
                lookup_transcript_commitment: next.lookup_transcript_commitment.clone(),
                lookup_transcript_entries: next.lookup_transcript_entries,
                lookup_frontier_commitment: next.lookup_frontier_commitment.clone(),
                lookup_frontier_entries: next.lookup_frontier_entries,
                kv_cache_commitment: to_view.kv_cache_commitment.clone(),
                incoming_token_commitment: to_view.incoming_token_commitment.clone(),
                query_commitment: to_view.query_commitment.clone(),
                output_commitment: to_view.output_commitment.clone(),
                lookup_rows_commitment: to_view.lookup_rows_commitment.clone(),
                public_state_commitment: String::new(),
            };
            let expected_to = Phase14DecodingState {
                public_state_commitment: oracle_commit_phase14_public_state(&expected_to),
                ..expected_to
            };
            if step.to_state != expected_to {
                return Err(VmError::InvalidConfig(format!(
                    "chunked decoding step {step_index} recorded to_state does not match the oracle replay"
                )));
            }
            if expected_to.position != expected_from.position + 1 {
                return Err(VmError::InvalidConfig(format!(
                    "chunked decoding step {step_index} does not advance the decoding position by exactly one token"
                )));
            }
            accumulator = Some(next);
            previous_expected_to = Some(expected_to);
        }
        validate_phase14_chain_steps(
            &manifest.layout,
            manifest.history_chunk_pairs,
            &manifest.steps,
        )
    }

    /// Requires `memory` to already contain `PHASE12_LOOKUP_ROW_VALUES` in the layout's lookup
    /// range. `phase12_expected_final_memory` satisfies that precondition before calling this
    /// helper.
    fn phase12_expected_output_cells(
        layout: &Phase12DecodingLayout,
        memory: &[i16],
    ) -> [i16; PHASE12_OUTPUT_WIDTH] {
        let latest_cached = layout.latest_cached_pair_range().expect("latest cached");
        let incoming = layout.incoming_token_range().expect("incoming");
        let query = layout.query_range().expect("query");
        let lookup = layout.lookup_range().expect("lookup");
        let raw_dot: i32 = (0..layout.pair_width)
            .map(|offset| {
                i32::from(memory[query.start + offset])
                    * i32::from(memory[latest_cached.start + offset])
            })
            .sum();
        let raw_accumulated = raw_dot
            + memory[incoming.clone()]
                .iter()
                .map(|&value| i32::from(value))
                .sum::<i32>();
        let combined_output = i32::from(memory[lookup.start + 3])
            + i32::from(memory[lookup.start + 7])
            + i32::from(memory[lookup.start + 2])
            + i32::from(memory[lookup.start + 4]);
        [
            raw_dot * i32::from(memory[lookup.start + 1])
                + i32::from(memory[lookup.start + 3])
                + combined_output,
            raw_accumulated * i32::from(memory[lookup.start + 5])
                + i32::from(memory[lookup.start + 7])
                + combined_output,
            combined_output,
        ]
        .map(|value| i16::try_from(value).expect("bounded Phase 12 oracle output"))
    }

    fn phase12_expected_final_memory(
        layout: &Phase12DecodingLayout,
        initial_memory: &[i16],
    ) -> Vec<i16> {
        let kv_cache = layout.kv_cache_range().expect("kv cache");
        let incoming = layout.incoming_token_range().expect("incoming");
        let output = layout.output_range().expect("output");
        let lookup = layout.lookup_range().expect("lookup");
        let latest_cached = layout.latest_cached_pair_range().expect("latest cached");
        let position_index = layout.position_index().expect("position");
        let position_increment_index = layout
            .position_increment_index()
            .expect("position increment");
        let mut expected = initial_memory.to_vec();

        expected[lookup.clone()].copy_from_slice(&PHASE12_LOOKUP_ROW_VALUES);
        let outputs = phase12_expected_output_cells(layout, &expected);
        expected[output.clone()].copy_from_slice(&outputs);

        for index in 0..kv_cache.len().saturating_sub(layout.pair_width) {
            expected[kv_cache.start + index] =
                initial_memory[kv_cache.start + index + layout.pair_width];
        }
        for offset in 0..layout.pair_width {
            expected[latest_cached.start + offset] = match offset {
                0 | 1 | 2 => outputs[2],
                3 => outputs[0],
                _ => initial_memory[incoming.start + offset],
            };
        }

        expected[position_index] =
            initial_memory[position_index] + initial_memory[position_increment_index];
        expected
    }

    fn phase12_random_bounded_memory(layout: &Phase12DecodingLayout, rng: &mut StdRng) -> Vec<i16> {
        let kv_cache = layout.kv_cache_range().expect("kv cache");
        let incoming = layout.incoming_token_range().expect("incoming");
        let query = layout.query_range().expect("query");
        let lookup = layout.lookup_range().expect("lookup");
        let position_index = layout.position_index().expect("position");
        let position_increment_index = layout
            .position_increment_index()
            .expect("position increment");
        let mut memory = vec![0; layout.memory_size().expect("memory size")];

        for index in kv_cache {
            memory[index] = rng.gen_range(-3..=3);
        }
        for index in incoming {
            memory[index] = rng.gen_range(-3..=3);
        }
        for index in query {
            memory[index] = rng.gen_range(-3..=3);
        }
        write_phase12_noncanonical_lookup_seed(&mut memory, lookup);
        memory[position_index] = rng.gen_range(0..=7);
        memory[position_increment_index] = 1;
        memory
    }

    fn phase12_bounded_memory_strategy() -> impl Strategy<Value = (Phase12DecodingLayout, Vec<i16>)>
    {
        let layouts = phase13_default_decoding_layout_matrix().expect("layout matrix");
        prop::sample::select(layouts).prop_flat_map(|layout| {
            let kv_cache_len = layout.kv_cache_range().expect("kv cache range").len();
            let incoming_len = layout.incoming_token_range().expect("incoming range").len();
            let query_len = layout.query_range().expect("query range").len();
            (
                Just(layout),
                prop::collection::vec(-3i16..=3, kv_cache_len),
                prop::collection::vec(-3i16..=3, incoming_len),
                prop::collection::vec(-3i16..=3, query_len),
                0i16..=7,
            )
                .prop_map(|(layout, kv_cache, incoming, query, position)| {
                    let kv_cache_range = layout.kv_cache_range().expect("kv cache range");
                    let incoming_range = layout.incoming_token_range().expect("incoming range");
                    let query_range = layout.query_range().expect("query range");
                    let lookup_range = layout.lookup_range().expect("lookup range");
                    let position_index = layout.position_index().expect("position index");
                    let position_increment_index = layout
                        .position_increment_index()
                        .expect("position increment index");
                    let mut memory = vec![0; layout.memory_size().expect("memory size")];
                    memory[kv_cache_range].copy_from_slice(&kv_cache);
                    memory[incoming_range].copy_from_slice(&incoming);
                    memory[query_range].copy_from_slice(&query);
                    write_phase12_noncanonical_lookup_seed(&mut memory, lookup_range);
                    memory[position_index] = position;
                    memory[position_increment_index] = 1;
                    (layout, memory)
                })
        })
    }

    fn sample_phase17_rollup_matrix_manifest() -> Phase17DecodingHistoryRollupMatrixManifest {
        let layouts = phase13_default_decoding_layout_matrix().expect("layout matrix");
        let mut rollups = Vec::with_capacity(layouts.len());
        for layout in &layouts {
            let proofs = phase12_demo_initial_memories(layout)
                .expect("memories")
                .into_iter()
                .map(|memory| sample_phase12_step_proof(layout, memory))
                .collect::<Vec<_>>();
            let phase12 = phase12_prepare_decoding_chain(layout, &proofs).expect("phase12 chain");
            let phase14 = phase14_prepare_decoding_chain(&phase12).expect("phase14 manifest");
            let phase15 = phase15_prepare_segment_bundle(&phase14, 1).expect("phase15 manifest");
            let phase16 =
                phase16_prepare_segment_rollup(&phase15, phase16_default_rollup_segment_limit())
                    .expect("phase16 manifest");
            rollups.push(phase16);
        }
        let mut manifest = Phase17DecodingHistoryRollupMatrixManifest {
            proof_backend: StarkProofBackend::Stwo,
            matrix_version: STWO_DECODING_ROLLUP_MATRIX_VERSION_PHASE17.to_string(),
            semantic_scope: STWO_DECODING_ROLLUP_MATRIX_SCOPE_PHASE17.to_string(),
            proof_backend_version: crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12.to_string(),
            statement_version: crate::proof::CLAIM_STATEMENT_VERSION_V1.to_string(),
            total_layouts: rollups.len(),
            total_rollups: rollups.iter().map(|rollup| rollup.total_rollups).sum(),
            total_segments: rollups.iter().map(|rollup| rollup.total_segments).sum(),
            total_steps: rollups.iter().map(|rollup| rollup.total_steps).sum(),
            public_state_boundary_commitment: String::new(),
            rollups,
        };
        manifest.public_state_boundary_commitment =
            commit_phase17_matrix_public_state_boundary(&manifest)
                .expect("phase17 boundary commitment");
        manifest
    }

    fn sample_phase21_matrix_accumulator_manifest() -> Phase21DecodingMatrixAccumulatorManifest {
        let first = sample_phase17_rollup_matrix_manifest();
        let second = sample_phase17_rollup_matrix_manifest();
        phase21_prepare_decoding_matrix_accumulator(&[first, second])
            .expect("phase21 accumulator manifest")
    }

    fn sample_phase22_lookup_accumulator_manifest() -> Phase22DecodingLookupAccumulatorManifest {
        let phase21 = sample_phase21_matrix_accumulator_manifest();
        phase22_prepare_decoding_lookup_accumulator(&phase21)
            .expect("phase22 lookup accumulator manifest")
    }

    fn sample_phase23_cross_step_lookup_accumulator_manifest(
    ) -> Phase23DecodingCrossStepLookupAccumulatorManifest {
        prove_phase23_decoding_cross_step_lookup_accumulator_demo()
            .expect("phase23 cross-step lookup accumulator manifest")
    }

    fn sample_phase24_decoding_state_relation_accumulator_manifest(
    ) -> Phase24DecodingStateRelationAccumulatorManifest {
        prove_phase24_decoding_state_relation_accumulator_demo()
            .expect("phase24 state relation accumulator manifest")
    }

    fn sample_phase25_intervalized_decoding_state_relation_manifest(
    ) -> Phase25IntervalizedDecodingStateRelationManifest {
        prove_phase25_intervalized_decoding_state_relation_demo()
            .expect("phase25 intervalized state relation manifest")
    }

    static PHASE26_SAMPLE_MANIFEST: OnceLock<
        Phase26FoldedIntervalizedDecodingStateRelationManifest,
    > = OnceLock::new();

    fn sample_phase26_folded_intervalized_decoding_state_relation_manifest(
    ) -> Phase26FoldedIntervalizedDecodingStateRelationManifest {
        PHASE26_SAMPLE_MANIFEST
            .get_or_init(|| {
                prove_phase26_folded_intervalized_decoding_state_relation_demo()
                    .expect("phase26 folded intervalized state relation manifest")
            })
            .clone()
    }

    static PHASE27_SAMPLE_MANIFEST: OnceLock<
        Phase27ChainedFoldedIntervalizedDecodingStateRelationManifest,
    > = OnceLock::new();

    fn sample_phase27_chained_folded_intervalized_decoding_state_relation_manifest(
    ) -> Phase27ChainedFoldedIntervalizedDecodingStateRelationManifest {
        PHASE27_SAMPLE_MANIFEST
            .get_or_init(|| {
                prove_phase27_chained_folded_intervalized_decoding_state_relation_demo()
                    .expect("phase27 chained folded intervalized state relation manifest")
            })
            .clone()
    }

    static PHASE28_SAMPLE_MANIFEST: OnceLock<
        Phase28AggregatedChainedFoldedIntervalizedDecodingStateRelationManifest,
    > = OnceLock::new();

    fn synthetic_phase28_member_summaries() -> Vec<Phase28MemberSummary> {
        vec![
            Phase28MemberSummary {
                start_step: 0,
                end_step: 8,
                bounded_chain_arity: 2,
                total_phase26_members: 2,
                total_phase25_members: 4,
                max_nested_fold_arity: 2,
                total_matrices: 1,
                total_layouts: 1,
                total_rollups: 2,
                total_segments: 4,
                total_steps: 8,
                lookup_delta_entries: 8,
                max_lookup_frontier_entries: 2,
                source_template_commitment: "phase28-source-template".to_string(),
                chain_template_commitment: "phase28-chain-template-0".to_string(),
                chained_folded_interval_accumulator_commitment: "phase28-chain-accumulator-0"
                    .to_string(),
                start_state_commitment: "phase28-state-0".to_string(),
                end_state_commitment: "phase28-state-1".to_string(),
            },
            Phase28MemberSummary {
                start_step: 8,
                end_step: 16,
                bounded_chain_arity: 2,
                total_phase26_members: 2,
                total_phase25_members: 4,
                max_nested_fold_arity: 2,
                total_matrices: 1,
                total_layouts: 1,
                total_rollups: 2,
                total_segments: 4,
                total_steps: 8,
                lookup_delta_entries: 8,
                max_lookup_frontier_entries: 2,
                source_template_commitment: "phase28-source-template".to_string(),
                chain_template_commitment: "phase28-chain-template-1".to_string(),
                chained_folded_interval_accumulator_commitment: "phase28-chain-accumulator-1"
                    .to_string(),
                start_state_commitment: "phase28-state-1".to_string(),
                end_state_commitment: "phase28-state-2".to_string(),
            },
        ]
    }

    fn synthetic_phase27_member_from_phase28_summary(
        summary: &Phase28MemberSummary,
    ) -> Phase27ChainedFoldedIntervalizedDecodingStateRelationManifest {
        Phase27ChainedFoldedIntervalizedDecodingStateRelationManifest {
            proof_backend: StarkProofBackend::Stwo,
            artifact_version:
                STWO_CHAINED_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE27.to_string(),
            semantic_scope: STWO_CHAINED_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_SCOPE_PHASE27
                .to_string(),
            proof_backend_version: crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12.to_string(),
            statement_version: crate::proof::CLAIM_STATEMENT_VERSION_V1.to_string(),
            bounded_chain_arity: summary.bounded_chain_arity,
            member_count: summary.total_phase26_members,
            total_phase25_members: summary.total_phase25_members,
            max_nested_fold_arity: summary.max_nested_fold_arity,
            total_matrices: summary.total_matrices,
            total_layouts: summary.total_layouts,
            total_rollups: summary.total_rollups,
            total_segments: summary.total_segments,
            total_steps: summary.total_steps,
            lookup_delta_entries: summary.lookup_delta_entries,
            max_lookup_frontier_entries: summary.max_lookup_frontier_entries,
            source_template_commitment: summary.source_template_commitment.clone(),
            global_start_state_commitment: summary.start_state_commitment.clone(),
            global_end_state_commitment: summary.end_state_commitment.clone(),
            chain_template_commitment: summary.chain_template_commitment.clone(),
            chained_folded_interval_accumulator_commitment: summary
                .chained_folded_interval_accumulator_commitment
                .clone(),
            member_summaries: Vec::new(),
            members: Vec::new(),
        }
    }

    fn phase28_manifest_from_valid_summaries(
        summaries: &[Phase28MemberSummary],
    ) -> Phase28AggregatedChainedFoldedIntervalizedDecodingStateRelationManifest {
        let totals = aggregate_phase28_summary_totals(summaries).expect("phase28 synthetic totals");
        let members = summaries
            .iter()
            .map(synthetic_phase27_member_from_phase28_summary)
            .collect::<Vec<_>>();
        let mut manifest = Phase28AggregatedChainedFoldedIntervalizedDecodingStateRelationManifest {
            proof_backend: StarkProofBackend::Stwo,
            artifact_version:
                STWO_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_VERSION_PHASE28
                    .to_string(),
            semantic_scope:
                STWO_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_DECODING_STATE_RELATION_SCOPE_PHASE28
                    .to_string(),
            proof_backend_version: crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12.to_string(),
            statement_version: crate::proof::CLAIM_STATEMENT_VERSION_V1.to_string(),
            recursion_posture: STWO_PHASE28_RECURSION_POSTURE_PRE_RECURSIVE.to_string(),
            recursive_verification_claimed: false,
            cryptographic_compression_claimed: false,
            bounded_aggregation_arity: summaries.len(),
            member_count: summaries.len(),
            total_phase26_members: totals.total_phase26_members,
            total_phase25_members: totals.total_phase25_members,
            max_nested_chain_arity: summaries
                .iter()
                .map(|summary| summary.bounded_chain_arity)
                .max()
                .expect("phase28 synthetic summaries are non-empty"),
            max_nested_fold_arity: totals.max_nested_fold_arity,
            total_matrices: totals.total_matrices,
            total_layouts: totals.total_layouts,
            total_rollups: totals.total_rollups,
            total_segments: totals.total_segments,
            total_steps: totals.total_steps,
            lookup_delta_entries: totals.lookup_delta_entries,
            max_lookup_frontier_entries: totals.max_lookup_frontier_entries,
            source_template_commitment: summaries[0].source_template_commitment.clone(),
            global_start_state_commitment: summaries[0].start_state_commitment.clone(),
            global_end_state_commitment: summaries
                .last()
                .expect("phase28 synthetic summaries are non-empty")
                .end_state_commitment
                .clone(),
            aggregation_template_commitment: String::new(),
            aggregated_chained_folded_interval_accumulator_commitment: String::new(),
            member_summaries: phase28_public_member_summaries(summaries),
            members,
        };
        manifest.aggregation_template_commitment = commit_phase28_aggregation_template(
            &manifest.source_template_commitment,
            manifest.bounded_aggregation_arity,
            summaries,
        )
        .expect("phase28 synthetic aggregation template");
        manifest.aggregated_chained_folded_interval_accumulator_commitment =
            commit_phase28_aggregated_chained_folded_intervalized_state_relation_with_summaries(
                &manifest, summaries,
            )
            .expect("phase28 synthetic accumulator");
        verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_summaries(
            &manifest,
            summaries,
        )
        .expect("phase28 synthetic manifest should verify against summaries");
        manifest
    }

    fn sample_phase28_aggregated_chained_folded_intervalized_decoding_state_relation() -> (
        Phase28AggregatedChainedFoldedIntervalizedDecodingStateRelationManifest,
        Vec<Phase28MemberSummary>,
    ) {
        let manifest = PHASE28_SAMPLE_MANIFEST
            .get_or_init(|| {
                let summaries = synthetic_phase28_member_summaries();
                phase28_manifest_from_valid_summaries(&summaries)
            })
            .clone();
        let summaries = synthetic_phase28_member_summaries();
        verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_summaries(
            &manifest,
            &summaries,
        )
        .expect("phase28 synthetic manifest should verify against summaries");
        (manifest, summaries)
    }

    #[test]
    fn decoding_step_family_ignores_initial_memory_but_requires_template() {
        let mut initial = vec![0; 23];
        initial[6] = 7;
        let program = decoding_step_v1_program_with_initial_memory(initial).expect("program");
        assert!(matches_decoding_step_v1_family(&program));
    }

    #[test]
    fn phase11_prepare_decoding_chain_accepts_linked_steps() {
        let step0 = sample_step_proof(
            vec![
                0, 0, 0, 0, 0, 0, 2, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ],
            vec![
                0, 0, 0, 0, 2, 1, 2, 1, 1, 1, 1, 4, 1, 16, 64, 1, 1, 4, 128, 0, 1, 1, 1,
            ],
        );
        let step1 = sample_step_proof(
            vec![
                0, 0, 0, 0, 2, 1, 3, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1,
            ],
            vec![
                0, 0, 2, 1, 3, 2, 3, 2, 1, 0, 2, 7, 1, 16, 64, 1, 1, 4, 128, 0, 1, 2, 1,
            ],
        );
        let manifest = phase11_prepare_decoding_chain(&[step0, step1]).expect("manifest");
        assert_eq!(manifest.total_steps, 2);
        assert_eq!(manifest.steps[0].from_state.position, 0);
        assert_eq!(manifest.steps[0].to_state.position, 1);
        assert_eq!(manifest.steps[1].from_state.position, 1);
        assert_eq!(manifest.steps[1].to_state.position, 2);
        assert_eq!(
            manifest.steps[0].to_state.kv_cache_commitment,
            manifest.steps[1].from_state.kv_cache_commitment
        );
    }

    #[test]
    fn phase11_prepare_decoding_chain_rejects_too_many_steps() {
        let step = sample_step_proof(
            vec![
                0, 0, 0, 0, 0, 0, 2, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ],
            vec![
                0, 0, 0, 0, 2, 1, 2, 1, 1, 1, 1, 4, 1, 16, 64, 1, 1, 4, 128, 0, 1, 1, 1,
            ],
        );
        let proofs = vec![step; MAX_DECODING_CHAIN_STEPS + 1];
        let err = phase11_prepare_decoding_chain(&proofs).expect_err("too many steps should fail");
        assert!(err.to_string().contains("exceeding the limit"));
    }

    #[test]
    fn phase11_verify_decoding_chain_rejects_broken_kv_link() {
        let step0 = sample_step_proof(
            vec![
                0, 0, 0, 0, 0, 0, 2, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ],
            vec![
                0, 0, 0, 0, 2, 1, 2, 1, 1, 1, 1, 4, 1, 16, 64, 1, 1, 4, 128, 0, 1, 1, 1,
            ],
        );
        let step1 = sample_step_proof(
            vec![
                9, 9, 9, 9, 9, 9, 3, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1,
            ],
            vec![
                9, 9, 9, 9, 3, 2, 3, 2, 1, 0, 2, 7, 1, 16, 64, 1, 1, 4, 128, 0, 1, 2, 1,
            ],
        );
        let err = phase11_prepare_decoding_chain(&[step0, step1]).unwrap_err();
        assert!(err.to_string().contains("KV-cache commitment"));
    }

    #[test]
    fn phase11_round_trips_manifest_json() {
        let step = sample_step_proof(
            vec![
                0, 0, 0, 0, 0, 0, 2, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ],
            vec![
                0, 0, 0, 0, 2, 1, 2, 1, 1, 1, 1, 4, 1, 16, 64, 1, 1, 4, 128, 0, 1, 1, 1,
            ],
        );
        let manifest = phase11_prepare_decoding_chain(&[step]).expect("manifest");
        let path = std::env::temp_dir().join(format!(
            "phase11-decoding-manifest-{}.json",
            std::process::id()
        ));
        save_phase11_decoding_chain(&manifest, &path).expect("save");
        let loaded = load_phase11_decoding_chain(&path).expect("load");
        verify_phase11_decoding_chain(&loaded).expect("verify");
        assert_eq!(loaded, manifest);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn load_phase12_decoding_chain_rejects_oversized_manifest_file() {
        let path = std::env::temp_dir().join(format!(
            "phase12-decoding-oversized-{}.json",
            std::process::id()
        ));
        fs::write(&path, vec![b'x'; MAX_PHASE12_DECODING_CHAIN_JSON_BYTES + 1]).expect("write");
        let err = load_phase12_decoding_chain(&path).expect_err("oversized manifest should fail");
        assert!(err.to_string().contains("exceeding the limit"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn load_phase12_decoding_chain_rejects_non_regular_file() {
        let path =
            std::env::temp_dir().join(format!("phase12-decoding-dir-{}", std::process::id()));
        fs::create_dir_all(&path).expect("create dir");
        let err = load_phase12_decoding_chain(&path).expect_err("directory should fail");
        assert!(err.to_string().contains("is not a regular file"));
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn load_phase12_decoding_chain_backfills_missing_public_state_commitment() {
        let layout = phase12_default_decoding_layout();
        let memories = phase12_demo_initial_memories(&layout).expect("memories");
        let proofs = memories
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let manifest = phase12_prepare_decoding_chain(&layout, &proofs).expect("manifest");
        let mut value = serde_json::to_value(&manifest).expect("manifest json");
        for step in value["steps"].as_array_mut().expect("steps") {
            step["from_state"]
                .as_object_mut()
                .expect("from_state")
                .remove("public_state_commitment");
            step["to_state"]
                .as_object_mut()
                .expect("to_state")
                .remove("public_state_commitment");
        }
        let path = std::env::temp_dir().join(format!(
            "phase12-decoding-legacy-{}.json",
            std::process::id()
        ));
        fs::write(&path, serde_json::to_vec(&value).expect("legacy json")).expect("write");
        let loaded = load_phase12_decoding_chain(&path).expect("load legacy manifest");
        verify_phase12_decoding_chain(&loaded).expect("verify normalized manifest");
        assert_eq!(loaded, manifest);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn load_phase12_decoding_chain_rejects_empty_public_state_commitment() {
        let layout = phase12_default_decoding_layout();
        let memories = phase12_demo_initial_memories(&layout).expect("memories");
        let proofs = memories
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let manifest = phase12_prepare_decoding_chain(&layout, &proofs).expect("manifest");
        let mut value = serde_json::to_value(&manifest).expect("manifest json");
        value["steps"][0]["from_state"]["public_state_commitment"] =
            serde_json::Value::String(String::new());
        let path = std::env::temp_dir().join(format!(
            "phase12-decoding-empty-public-state-{}.json",
            std::process::id()
        ));
        fs::write(&path, serde_json::to_vec(&value).expect("json")).expect("write");
        let err = load_phase12_decoding_chain(&path)
            .expect_err("empty public-state commitment should fail");
        assert!(err.to_string().contains("must not be empty"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn save_phase12_decoding_chain_rejects_manifest_exceeding_json_budget() {
        let layout = phase12_default_decoding_layout();
        let memories = phase12_demo_initial_memories(&layout).expect("memories");
        let proofs = memories
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let mut manifest = phase12_prepare_decoding_chain(&layout, &proofs).expect("manifest");
        manifest.steps[0].proof.proof = vec![0; MAX_PHASE12_DECODING_CHAIN_JSON_BYTES];
        let path = std::env::temp_dir().join(format!(
            "phase12-decoding-save-oversized-{}.json",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let err = save_phase12_decoding_chain(&manifest, &path)
            .expect_err("oversized manifest should be rejected on save");
        assert!(err.to_string().contains("exceeding the limit"));
        assert!(
            !path.exists(),
            "save should not write an unreadable manifest"
        );
    }

    #[test]
    fn save_phase14_decoding_chain_rejects_manifest_exceeding_json_budget() {
        let layout = phase12_default_decoding_layout();
        let memories = phase12_demo_initial_memories(&layout).expect("memories");
        let proofs = memories
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let phase12 = phase12_prepare_decoding_chain(&layout, &proofs).expect("phase12 manifest");
        let mut manifest = phase14_prepare_decoding_chain(&phase12).expect("phase14 manifest");
        manifest.steps[0].proof.proof = vec![0; MAX_PHASE14_DECODING_CHAIN_JSON_BYTES];
        let path = std::env::temp_dir().join(format!(
            "phase14-decoding-save-oversized-{}.json",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let err = save_phase14_decoding_chain(&manifest, &path)
            .expect_err("oversized phase14 manifest should be rejected on save");
        assert!(err.to_string().contains("exceeding the limit"));
        assert!(
            !path.exists(),
            "save should not write an unreadable manifest"
        );
    }

    #[test]
    fn load_phase14_decoding_chain_backfills_missing_public_state_commitment() {
        let layout = phase12_default_decoding_layout();
        let memories = phase12_demo_initial_memories(&layout).expect("memories");
        let proofs = memories
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let phase12 = phase12_prepare_decoding_chain(&layout, &proofs).expect("phase12");
        let manifest = phase14_prepare_decoding_chain(&phase12).expect("phase14");
        let mut value = serde_json::to_value(&manifest).expect("manifest json");
        for step in value["steps"].as_array_mut().expect("steps") {
            step["from_state"]
                .as_object_mut()
                .expect("from_state")
                .remove("public_state_commitment");
            step["to_state"]
                .as_object_mut()
                .expect("to_state")
                .remove("public_state_commitment");
        }
        let path = std::env::temp_dir().join(format!(
            "phase14-decoding-legacy-{}.json",
            std::process::id()
        ));
        fs::write(&path, serde_json::to_vec(&value).expect("legacy json")).expect("write");
        let loaded = load_phase14_decoding_chain(&path).expect("load legacy manifest");
        verify_phase14_decoding_chain(&loaded).expect("verify normalized manifest");
        assert_eq!(loaded, manifest);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn load_phase14_decoding_chain_rejects_empty_public_state_commitment() {
        let layout = phase12_default_decoding_layout();
        let memories = phase12_demo_initial_memories(&layout).expect("memories");
        let proofs = memories
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let phase12 = phase12_prepare_decoding_chain(&layout, &proofs).expect("phase12");
        let manifest = phase14_prepare_decoding_chain(&phase12).expect("phase14");
        let mut value = serde_json::to_value(&manifest).expect("manifest json");
        value["steps"][0]["from_state"]["public_state_commitment"] =
            serde_json::Value::String(String::new());
        let path = std::env::temp_dir().join(format!(
            "phase14-decoding-empty-public-state-{}.json",
            std::process::id()
        ));
        fs::write(&path, serde_json::to_vec(&value).expect("json")).expect("write");
        let err = load_phase14_decoding_chain(&path)
            .expect_err("empty public-state commitment should fail");
        assert!(err.to_string().contains("must not be empty"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn load_phase15_segment_bundle_backfills_nested_public_state_commitments() {
        let layout = phase12_default_decoding_layout();
        let memories = phase12_demo_initial_memories(&layout).expect("memories");
        let proofs = memories
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let phase12 = phase12_prepare_decoding_chain(&layout, &proofs).expect("phase12");
        let phase14 = phase14_prepare_decoding_chain(&phase12).expect("phase14");
        let manifest =
            phase15_prepare_segment_bundle(&phase14, phase15_default_segment_step_limit())
                .expect("phase15");
        let mut value = serde_json::to_value(&manifest).expect("manifest json");
        for segment in value["segments"].as_array_mut().expect("segments") {
            segment
                .as_object_mut()
                .expect("segment")
                .remove("public_state_boundary_commitment");
            segment["global_from_state"]
                .as_object_mut()
                .expect("global_from_state")
                .remove("public_state_commitment");
            segment["global_to_state"]
                .as_object_mut()
                .expect("global_to_state")
                .remove("public_state_commitment");
            for step in segment["chain"]["steps"]
                .as_array_mut()
                .expect("phase14 steps")
            {
                step["from_state"]
                    .as_object_mut()
                    .expect("from_state")
                    .remove("public_state_commitment");
                step["to_state"]
                    .as_object_mut()
                    .expect("to_state")
                    .remove("public_state_commitment");
            }
        }
        let path = std::env::temp_dir().join(format!(
            "phase15-decoding-legacy-public-state-{}.json",
            std::process::id()
        ));
        fs::write(&path, serde_json::to_vec(&value).expect("legacy json")).expect("write");
        let loaded = load_phase15_decoding_segment_bundle(&path).expect("load legacy manifest");
        verify_phase15_decoding_segment_bundle(&loaded).expect("verify normalized manifest");
        assert_eq!(loaded, manifest);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn load_phase16_rollup_backfills_nested_public_state_commitments() {
        let layout = phase12_default_decoding_layout();
        let memories = phase12_demo_initial_memories(&layout).expect("memories");
        let proofs = memories
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let phase12 = phase12_prepare_decoding_chain(&layout, &proofs).expect("phase12");
        let phase14 = phase14_prepare_decoding_chain(&phase12).expect("phase14");
        let phase15 = phase15_prepare_segment_bundle(&phase14, 1).expect("phase15");
        let manifest =
            phase16_prepare_segment_rollup(&phase15, phase16_default_rollup_segment_limit())
                .expect("phase16");
        let mut value = serde_json::to_value(&manifest).expect("manifest json");
        for rollup in value["rollups"].as_array_mut().expect("rollups") {
            rollup
                .as_object_mut()
                .expect("rollup")
                .remove("public_state_boundary_commitment");
            rollup["global_from_state"]
                .as_object_mut()
                .expect("global_from_state")
                .remove("public_state_commitment");
            rollup["global_to_state"]
                .as_object_mut()
                .expect("global_to_state")
                .remove("public_state_commitment");
            for segment in rollup["segments"].as_array_mut().expect("segments") {
                segment
                    .as_object_mut()
                    .expect("segment")
                    .remove("public_state_boundary_commitment");
                segment["global_from_state"]
                    .as_object_mut()
                    .expect("segment global_from_state")
                    .remove("public_state_commitment");
                segment["global_to_state"]
                    .as_object_mut()
                    .expect("segment global_to_state")
                    .remove("public_state_commitment");
                for step in segment["chain"]["steps"]
                    .as_array_mut()
                    .expect("phase14 steps")
                {
                    step["from_state"]
                        .as_object_mut()
                        .expect("from_state")
                        .remove("public_state_commitment");
                    step["to_state"]
                        .as_object_mut()
                        .expect("to_state")
                        .remove("public_state_commitment");
                }
            }
        }
        let path = std::env::temp_dir().join(format!(
            "phase16-decoding-legacy-public-state-{}.json",
            std::process::id()
        ));
        fs::write(&path, serde_json::to_vec(&value).expect("legacy json")).expect("write");
        let loaded = load_phase16_decoding_segment_rollup(&path).expect("load legacy manifest");
        verify_phase16_decoding_segment_rollup(&loaded).expect("verify normalized manifest");
        assert_eq!(loaded, manifest);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn load_phase17_rollup_matrix_backfills_missing_public_state_boundary_commitment() {
        let manifest = sample_phase17_rollup_matrix_manifest();
        let mut value = serde_json::to_value(&manifest).expect("manifest json");
        value
            .as_object_mut()
            .expect("matrix object")
            .remove("public_state_boundary_commitment");
        for rollup_manifest in value["rollups"].as_array_mut().expect("rollup manifests") {
            for rollup in rollup_manifest["rollups"]
                .as_array_mut()
                .expect("phase16 rollups")
            {
                rollup
                    .as_object_mut()
                    .expect("phase16 rollup")
                    .remove("public_state_boundary_commitment");
                rollup["global_from_state"]
                    .as_object_mut()
                    .expect("phase16 global_from_state")
                    .remove("public_state_commitment");
                rollup["global_to_state"]
                    .as_object_mut()
                    .expect("phase16 global_to_state")
                    .remove("public_state_commitment");
                for segment in rollup["segments"].as_array_mut().expect("phase15 segments") {
                    segment
                        .as_object_mut()
                        .expect("phase15 segment")
                        .remove("public_state_boundary_commitment");
                    segment["global_from_state"]
                        .as_object_mut()
                        .expect("phase15 global_from_state")
                        .remove("public_state_commitment");
                    segment["global_to_state"]
                        .as_object_mut()
                        .expect("phase15 global_to_state")
                        .remove("public_state_commitment");
                    for step in segment["chain"]["steps"]
                        .as_array_mut()
                        .expect("phase14 steps")
                    {
                        step["from_state"]
                            .as_object_mut()
                            .expect("from_state")
                            .remove("public_state_commitment");
                        step["to_state"]
                            .as_object_mut()
                            .expect("to_state")
                            .remove("public_state_commitment");
                    }
                }
            }
        }
        let path = std::env::temp_dir().join(format!(
            "phase17-decoding-legacy-public-state-boundary-{}.json",
            std::process::id()
        ));
        fs::write(&path, serde_json::to_vec(&value).expect("legacy json")).expect("write");
        let loaded = load_phase17_decoding_rollup_matrix(&path).expect("load legacy manifest");
        verify_phase17_decoding_rollup_matrix(&loaded).expect("verify normalized manifest");
        assert_eq!(loaded, manifest);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn load_phase17_rollup_matrix_rejects_empty_public_state_boundary_commitment() {
        let manifest = sample_phase17_rollup_matrix_manifest();
        let mut value = serde_json::to_value(&manifest).expect("manifest json");
        value["public_state_boundary_commitment"] = serde_json::Value::String(String::new());
        let path = std::env::temp_dir().join(format!(
            "phase17-decoding-empty-public-state-boundary-{}.json",
            std::process::id()
        ));
        fs::write(&path, serde_json::to_vec(&value).expect("json")).expect("write");
        let err = load_phase17_decoding_rollup_matrix(&path)
            .expect_err("empty public-state boundary commitment should fail");
        assert!(err.to_string().contains("must not be empty"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn phase21_save_and_load_round_trip() {
        let manifest = sample_phase21_matrix_accumulator_manifest();
        let path = std::env::temp_dir().join(format!(
            "phase21-decoding-matrix-accumulator-roundtrip-{}.json",
            std::process::id()
        ));
        save_phase21_decoding_matrix_accumulator(&manifest, &path).expect("save");
        let loaded = load_phase21_decoding_matrix_accumulator(&path).expect("load");
        verify_phase21_decoding_matrix_accumulator(&loaded).expect("verify");
        assert_eq!(loaded, manifest);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn phase22_save_and_load_round_trip() {
        let manifest = sample_phase22_lookup_accumulator_manifest();
        let path = std::env::temp_dir().join(format!(
            "phase22-decoding-lookup-accumulator-roundtrip-{}.json",
            std::process::id()
        ));
        save_phase22_decoding_lookup_accumulator(&manifest, &path).expect("save");
        let loaded = load_phase22_decoding_lookup_accumulator(&path).expect("load");
        verify_phase22_decoding_lookup_accumulator(&loaded).expect("verify");
        assert_eq!(loaded, manifest);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn phase23_save_and_load_round_trip() {
        let manifest = sample_phase23_cross_step_lookup_accumulator_manifest();
        let path = std::env::temp_dir().join(format!(
            "phase23-decoding-cross-step-lookup-accumulator-roundtrip-{}.json",
            std::process::id()
        ));
        save_phase23_decoding_cross_step_lookup_accumulator(&manifest, &path).expect("save");
        let loaded = load_phase23_decoding_cross_step_lookup_accumulator(&path).expect("load");
        verify_phase23_decoding_cross_step_lookup_accumulator(&loaded).expect("verify");
        assert_eq!(loaded, manifest);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn phase24_save_and_load_round_trip() {
        let manifest = sample_phase24_decoding_state_relation_accumulator_manifest();
        let path = std::env::temp_dir().join(format!(
            "phase24-decoding-state-relation-accumulator-roundtrip-{}.json",
            std::process::id()
        ));
        save_phase24_decoding_state_relation_accumulator(&manifest, &path).expect("save");
        let loaded = load_phase24_decoding_state_relation_accumulator(&path).expect("load");
        verify_phase24_decoding_state_relation_accumulator(&loaded).expect("verify");
        assert_eq!(loaded, manifest);
        let _ = fs::remove_file(path);
    }

    fn write_test_gzip_copy(source: &Path, target: &Path) {
        let bytes = fs::read(source).expect("read source json");
        let file = fs::File::create(target).expect("create gzip target");
        let mut encoder = flate2::GzBuilder::new()
            .mtime(0)
            .write(file, flate2::Compression::best());
        encoder.write_all(&bytes).expect("write gzip bytes");
        encoder.finish().expect("finish gzip copy");
    }

    #[test]
    fn phase24_load_accepts_gzip_round_trip() {
        let manifest = sample_phase24_decoding_state_relation_accumulator_manifest();
        let path = std::env::temp_dir().join(format!(
            "phase24-decoding-state-relation-accumulator-roundtrip-{}.json",
            std::process::id()
        ));
        let gzip_path = path.with_extension("json.gz");
        save_phase24_decoding_state_relation_accumulator(&manifest, &path).expect("save");
        write_test_gzip_copy(&path, &gzip_path);
        let loaded = load_phase24_decoding_state_relation_accumulator(&gzip_path).expect("load");
        verify_phase24_decoding_state_relation_accumulator(&loaded).expect("verify");
        assert_eq!(loaded, manifest);
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(gzip_path);
    }

    #[test]
    fn phase25_save_and_load_round_trip() {
        let manifest = sample_phase25_intervalized_decoding_state_relation_manifest();
        let path = std::env::temp_dir().join(format!(
            "phase25-intervalized-decoding-state-relation-roundtrip-{}.json",
            std::process::id()
        ));
        save_phase25_intervalized_decoding_state_relation(&manifest, &path).expect("save");
        let loaded = load_phase25_intervalized_decoding_state_relation(&path).expect("load");
        verify_phase25_intervalized_decoding_state_relation(&loaded).expect("verify");
        assert_eq!(loaded, manifest);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn phase25_load_accepts_gzip_round_trip() {
        let manifest = sample_phase25_intervalized_decoding_state_relation_manifest();
        let path = std::env::temp_dir().join(format!(
            "phase25-intervalized-decoding-state-relation-roundtrip-{}.json",
            std::process::id()
        ));
        let gzip_path = path.with_extension("json.gz");
        save_phase25_intervalized_decoding_state_relation(&manifest, &path).expect("save");
        write_test_gzip_copy(&path, &gzip_path);
        let loaded = load_phase25_intervalized_decoding_state_relation(&gzip_path).expect("load");
        verify_phase25_intervalized_decoding_state_relation(&loaded).expect("verify");
        assert_eq!(loaded, manifest);
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(gzip_path);
    }

    #[test]
    fn phase26_save_and_load_round_trip() {
        let manifest = sample_phase26_folded_intervalized_decoding_state_relation_manifest();
        let path = std::env::temp_dir().join(format!(
            "phase26-folded-intervalized-decoding-state-relation-roundtrip-{}.json",
            std::process::id()
        ));
        save_phase26_folded_intervalized_decoding_state_relation(&manifest, &path).expect("save");
        let loaded = load_phase26_folded_intervalized_decoding_state_relation(&path).expect("load");
        verify_phase26_folded_intervalized_decoding_state_relation(&loaded).expect("verify");
        assert_eq!(loaded, manifest);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn phase26_load_accepts_gzip_round_trip() {
        let manifest = sample_phase26_folded_intervalized_decoding_state_relation_manifest();
        let path = std::env::temp_dir().join(format!(
            "phase26-folded-intervalized-decoding-state-relation-roundtrip-{}.json",
            std::process::id()
        ));
        let gzip_path = path.with_extension("json.gz");
        save_phase26_folded_intervalized_decoding_state_relation(&manifest, &path).expect("save");
        write_test_gzip_copy(&path, &gzip_path);
        let loaded =
            load_phase26_folded_intervalized_decoding_state_relation(&gzip_path).expect("load");
        verify_phase26_folded_intervalized_decoding_state_relation(&loaded).expect("verify");
        assert_eq!(loaded, manifest);
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(gzip_path);
    }

    #[test]
    fn load_phase22_decoding_lookup_accumulator_rejects_tampered_manifest() {
        let mut manifest = sample_phase22_lookup_accumulator_manifest();
        manifest.source_accumulator_commitment = "tampered".to_string();
        let path = std::env::temp_dir().join(format!(
            "phase22-decoding-lookup-accumulator-invalid-{}.json",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        fs::write(
            &path,
            serde_json::to_vec_pretty(&manifest).expect("serialize invalid manifest"),
        )
        .expect("write invalid manifest");
        let err =
            load_phase22_decoding_lookup_accumulator(&path).expect_err("tampered load should fail");
        assert!(err.to_string().contains(
            "source_accumulator_commitment does not match the nested Phase 21 accumulator"
        ));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn load_phase23_decoding_cross_step_lookup_accumulator_rejects_tampered_manifest() {
        let mut manifest = sample_phase23_cross_step_lookup_accumulator_manifest();
        manifest.start_boundary_commitment = "tampered".to_string();
        let path = std::env::temp_dir().join(format!(
            "phase23-decoding-cross-step-lookup-accumulator-invalid-{}.json",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        fs::write(
            &path,
            serde_json::to_vec_pretty(&manifest).expect("serialize invalid manifest"),
        )
        .expect("write invalid manifest");
        let err = load_phase23_decoding_cross_step_lookup_accumulator(&path)
            .expect_err("tampered load should fail");
        assert!(err
            .to_string()
            .contains("start_boundary_commitment does not match the first member boundary"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn load_phase24_decoding_state_relation_accumulator_rejects_tampered_manifest() {
        let mut manifest = sample_phase24_decoding_state_relation_accumulator_manifest();
        manifest.start_state_commitment = "tampered".to_string();
        let path = std::env::temp_dir().join(format!(
            "phase24-decoding-state-relation-accumulator-invalid-{}.json",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        fs::write(
            &path,
            serde_json::to_vec_pretty(&manifest).expect("serialize invalid manifest"),
        )
        .expect("write invalid manifest");
        let err = load_phase24_decoding_state_relation_accumulator(&path)
            .expect_err("tampered load should fail");
        assert!(err
            .to_string()
            .contains("start_state_commitment does not match the first member boundary"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn load_phase25_intervalized_decoding_state_relation_rejects_tampered_manifest() {
        let mut manifest = sample_phase25_intervalized_decoding_state_relation_manifest();
        manifest.global_start_state_commitment = "tampered".to_string();
        let path = std::env::temp_dir().join(format!(
            "phase25-intervalized-decoding-state-relation-invalid-{}.json",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        fs::write(
            &path,
            serde_json::to_vec_pretty(&manifest).expect("serialize invalid manifest"),
        )
        .expect("write invalid manifest");
        let err = load_phase25_intervalized_decoding_state_relation(&path)
            .expect_err("tampered load should fail");
        let message = err.to_string();
        assert!(
            message.contains(
                "global_start_state_commitment does not match the derived rebased Phase 24 source"
            ),
            "unexpected error: {message}"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn load_phase26_folded_intervalized_decoding_state_relation_rejects_tampered_manifest() {
        let mut manifest = sample_phase26_folded_intervalized_decoding_state_relation_manifest();
        manifest.global_start_state_commitment = "tampered".to_string();
        let path = std::env::temp_dir().join(format!(
            "phase26-folded-intervalized-decoding-state-relation-invalid-{}.json",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        fs::write(
            &path,
            serde_json::to_vec_pretty(&manifest).expect("serialize invalid manifest"),
        )
        .expect("write invalid manifest");
        let err = load_phase26_folded_intervalized_decoding_state_relation(&path)
            .expect_err("tampered load should fail");
        assert!(err
            .to_string()
            .contains("global_start_state_commitment does not match the first member boundary"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn save_phase21_decoding_matrix_accumulator_rejects_manifest_exceeding_json_budget() {
        let mut manifest = sample_phase21_matrix_accumulator_manifest();
        manifest.matrices[0].rollups[0].rollups[0].segments[0]
            .chain
            .steps[0]
            .proof
            .proof = vec![0; MAX_PHASE21_MATRIX_ACCUMULATOR_JSON_BYTES];
        let path = std::env::temp_dir().join(format!(
            "phase21-decoding-matrix-accumulator-save-oversized-{}.json",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let err = save_phase21_decoding_matrix_accumulator(&manifest, &path)
            .expect_err("oversized phase21 manifest should be rejected on save");
        assert!(err.to_string().contains("exceeding the limit"));
        assert!(
            !path.exists(),
            "save should not write an unreadable manifest"
        );
    }

    #[test]
    fn save_phase22_decoding_lookup_accumulator_rejects_manifest_exceeding_json_budget() {
        let mut manifest = sample_phase22_lookup_accumulator_manifest();
        manifest.accumulator.matrices[0].rollups[0].rollups[0].segments[0]
            .chain
            .steps[0]
            .proof
            .proof = vec![0; MAX_PHASE22_LOOKUP_ACCUMULATOR_JSON_BYTES];
        let path = std::env::temp_dir().join(format!(
            "phase22-decoding-lookup-accumulator-save-oversized-{}.json",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let err = save_phase22_decoding_lookup_accumulator(&manifest, &path)
            .expect_err("oversized phase22 manifest should be rejected on save");
        assert!(err.to_string().contains("exceeding the limit"));
        assert!(
            !path.exists(),
            "save should not write an unreadable manifest"
        );
    }

    #[test]
    fn save_phase23_decoding_cross_step_lookup_accumulator_rejects_manifest_exceeding_json_budget()
    {
        let mut manifest = sample_phase23_cross_step_lookup_accumulator_manifest();
        manifest.members[0].accumulator.matrices[0].rollups[0].rollups[0].segments[0]
            .chain
            .steps[0]
            .proof
            .proof = vec![0; MAX_PHASE23_CROSS_STEP_LOOKUP_ACCUMULATOR_JSON_BYTES];
        let path = std::env::temp_dir().join(format!(
            "phase23-decoding-cross-step-lookup-accumulator-save-oversized-{}.json",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let err = save_phase23_decoding_cross_step_lookup_accumulator(&manifest, &path)
            .expect_err("oversized phase23 manifest should be rejected on save");
        assert!(err.to_string().contains("exceeding the limit"));
        assert!(
            !path.exists(),
            "save should not write an unreadable manifest"
        );
    }

    #[test]
    fn save_phase24_decoding_state_relation_accumulator_rejects_manifest_exceeding_json_budget() {
        let mut manifest = sample_phase24_decoding_state_relation_accumulator_manifest();
        manifest.members[0].members[0].accumulator.matrices[0].rollups[0].rollups[0].segments[0]
            .chain
            .steps[0]
            .proof
            .proof = vec![0; MAX_PHASE24_STATE_RELATION_ACCUMULATOR_JSON_BYTES];
        let path = std::env::temp_dir().join(format!(
            "phase24-decoding-state-relation-accumulator-save-oversized-{}.json",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let err = save_phase24_decoding_state_relation_accumulator(&manifest, &path)
            .expect_err("oversized phase24 manifest should be rejected on save");
        assert!(err.to_string().contains("exceeding the limit"));
        assert!(
            !path.exists(),
            "save should not write an unreadable manifest"
        );
    }

    #[test]
    fn save_phase25_intervalized_decoding_state_relation_rejects_manifest_exceeding_json_budget() {
        let mut manifest = sample_phase25_intervalized_decoding_state_relation_manifest();
        manifest.members[0].members[0].accumulator.matrices[0].rollups[0].rollups[0].segments[0]
            .chain
            .steps[0]
            .proof
            .proof = vec![0; MAX_PHASE25_INTERVALIZED_STATE_RELATION_JSON_BYTES];
        let path = std::env::temp_dir().join(format!(
            "phase25-intervalized-decoding-state-relation-save-oversized-{}.json",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let err = save_phase25_intervalized_decoding_state_relation(&manifest, &path)
            .expect_err("oversized phase25 intervalized manifest should be rejected on save");
        assert!(err.to_string().contains("exceeding the limit"));
        assert!(
            !path.exists(),
            "save should not write an unreadable manifest"
        );
    }

    #[test]
    fn save_phase26_folded_intervalized_decoding_state_relation_rejects_manifest_exceeding_json_budget(
    ) {
        let mut manifest = sample_phase26_folded_intervalized_decoding_state_relation_manifest();
        manifest.members[0].members[0].members[0]
            .accumulator
            .matrices[0]
            .rollups[0]
            .rollups[0]
            .segments[0]
            .chain
            .steps[0]
            .proof
            .proof = vec![0; MAX_PHASE26_FOLDED_INTERVALIZED_STATE_RELATION_JSON_BYTES];
        let path = std::env::temp_dir().join(format!(
            "phase26-folded-intervalized-decoding-state-relation-save-oversized-{}.json",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let err = save_phase26_folded_intervalized_decoding_state_relation(&manifest, &path)
            .expect_err("oversized phase26 folded manifest should be rejected on save");
        assert!(err.to_string().contains("exceeding the limit"));
        assert!(
            !path.exists(),
            "save should not write an unreadable manifest"
        );
    }

    #[test]
    fn save_phase15_decoding_segment_bundle_rejects_manifest_exceeding_json_budget() {
        let mut manifest = prove_phase15_decoding_demo().expect("phase15 demo");
        manifest.segments[0].chain.steps[0].proof.proof =
            vec![0; MAX_PHASE15_SEGMENT_BUNDLE_JSON_BYTES];
        let path = std::env::temp_dir().join(format!(
            "phase15-decoding-save-oversized-{}.json",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let err = save_phase15_decoding_segment_bundle(&manifest, &path)
            .expect_err("oversized phase15 manifest should be rejected on save");
        assert!(err.to_string().contains("exceeding the limit"));
        assert!(
            !path.exists(),
            "save should not write an unreadable manifest"
        );
    }

    fn assert_saved_json_budget<T>(
        label: &str,
        limit: usize,
        manifest: &T,
        save: impl Fn(&T, &std::path::Path) -> Result<()>,
    ) where
        T: serde::Serialize,
    {
        let thread_label = std::thread::current()
            .name()
            .unwrap_or("anon")
            .chars()
            .map(|ch| match ch {
                ':' | '/' | '\\' => '_',
                other => other,
            })
            .collect::<String>();
        let path = std::env::temp_dir().join(format!(
            "{}-{}-{}.json",
            label,
            std::process::id(),
            thread_label
        ));
        let _ = fs::remove_file(&path);
        save(manifest, &path).expect("manifest should fit within the configured json budget");
        let written = fs::metadata(&path).expect("metadata").len() as usize;
        assert!(
            written <= limit,
            "{label} demo wrote {written} bytes, exceeding the configured limit of {limit}"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn phase11_demo_manifest_fits_json_budget() {
        let manifest = prove_phase11_decoding_demo().expect("phase11 demo");
        assert_saved_json_budget(
            "phase11-demo",
            MAX_PHASE11_DECODING_CHAIN_JSON_BYTES,
            &manifest,
            save_phase11_decoding_chain,
        );
    }

    #[test]
    fn phase12_demo_manifest_fits_json_budget() {
        let manifest = prove_phase12_decoding_demo().expect("phase12 demo");
        assert_saved_json_budget(
            "phase12-demo",
            MAX_PHASE12_DECODING_CHAIN_JSON_BYTES,
            &manifest,
            save_phase12_decoding_chain,
        );
    }

    #[test]
    fn phase13_demo_manifest_fits_json_budget() {
        let manifest = prove_phase13_decoding_layout_matrix_demo().expect("phase13 demo");
        assert_saved_json_budget(
            "phase13-demo",
            MAX_PHASE13_LAYOUT_MATRIX_JSON_BYTES,
            &manifest,
            save_phase13_decoding_layout_matrix,
        );
    }

    #[test]
    fn phase14_demo_manifest_fits_json_budget() {
        let manifest = prove_phase14_decoding_demo().expect("phase14 demo");
        assert_saved_json_budget(
            "phase14-demo",
            MAX_PHASE14_DECODING_CHAIN_JSON_BYTES,
            &manifest,
            save_phase14_decoding_chain,
        );
    }

    #[test]
    fn phase15_demo_manifest_fits_json_budget() {
        let manifest = prove_phase15_decoding_demo().expect("phase15 demo");
        assert_saved_json_budget(
            "phase15-demo",
            MAX_PHASE15_SEGMENT_BUNDLE_JSON_BYTES,
            &manifest,
            save_phase15_decoding_segment_bundle,
        );
    }

    #[test]
    fn phase16_demo_manifest_fits_json_budget() {
        let manifest = prove_phase16_decoding_demo().expect("phase16 demo");
        assert_saved_json_budget(
            "phase16-demo",
            MAX_PHASE16_SEGMENT_ROLLUP_JSON_BYTES,
            &manifest,
            save_phase16_decoding_segment_rollup,
        );
    }

    #[test]
    fn phase17_demo_manifest_fits_json_budget() {
        let manifest = prove_phase17_decoding_rollup_matrix_demo().expect("phase17 demo");
        assert_saved_json_budget(
            "phase17-demo",
            MAX_PHASE17_ROLLUP_MATRIX_JSON_BYTES,
            &manifest,
            save_phase17_decoding_rollup_matrix,
        );
    }

    #[test]
    fn phase21_demo_manifest_fits_json_budget() {
        let manifest = prove_phase21_decoding_matrix_accumulator_demo()
            .expect("phase21 matrix accumulator demo");
        assert_saved_json_budget(
            "phase21-demo",
            MAX_PHASE21_MATRIX_ACCUMULATOR_JSON_BYTES,
            &manifest,
            save_phase21_decoding_matrix_accumulator,
        );
    }

    #[test]
    fn phase22_demo_manifest_fits_json_budget() {
        let manifest =
            prove_phase22_decoding_lookup_accumulator_demo().expect("phase22 lookup demo");
        assert_saved_json_budget(
            "phase22-demo",
            MAX_PHASE22_LOOKUP_ACCUMULATOR_JSON_BYTES,
            &manifest,
            save_phase22_decoding_lookup_accumulator,
        );
    }

    #[test]
    fn phase23_demo_manifest_fits_json_budget() {
        let manifest = prove_phase23_decoding_cross_step_lookup_accumulator_demo()
            .expect("phase23 cross-step lookup demo");
        assert_saved_json_budget(
            "phase23-demo",
            MAX_PHASE23_CROSS_STEP_LOOKUP_ACCUMULATOR_JSON_BYTES,
            &manifest,
            save_phase23_decoding_cross_step_lookup_accumulator,
        );
    }

    #[test]
    fn phase24_demo_manifest_fits_json_budget() {
        let manifest = prove_phase24_decoding_state_relation_accumulator_demo()
            .expect("phase24 state relation demo");
        assert_saved_json_budget(
            "phase24-demo",
            MAX_PHASE24_STATE_RELATION_ACCUMULATOR_JSON_BYTES,
            &manifest,
            save_phase24_decoding_state_relation_accumulator,
        );
    }

    #[test]
    fn phase25_demo_manifest_fits_json_budget() {
        let manifest = prove_phase25_intervalized_decoding_state_relation_demo()
            .expect("phase25 intervalized state relation demo");
        assert_saved_json_budget(
            "phase25-demo",
            MAX_PHASE25_INTERVALIZED_STATE_RELATION_JSON_BYTES,
            &manifest,
            save_phase25_intervalized_decoding_state_relation,
        );
    }

    #[test]
    fn phase26_demo_manifest_fits_json_budget() {
        let manifest = prove_phase26_folded_intervalized_decoding_state_relation_demo()
            .expect("phase26 folded intervalized state relation demo");
        assert_saved_json_budget(
            "phase26-demo",
            MAX_PHASE26_FOLDED_INTERVALIZED_STATE_RELATION_JSON_BYTES,
            &manifest,
            save_phase26_folded_intervalized_decoding_state_relation,
        );
    }

    #[test]
    fn phase11_verify_decoding_chain_rejects_wrong_backend_version() {
        let step = sample_step_proof(
            vec![
                0, 0, 0, 0, 0, 0, 2, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ],
            vec![
                0, 0, 0, 0, 2, 1, 2, 1, 1, 1, 1, 4, 1, 16, 64, 1, 1, 4, 128, 0, 1, 1, 1,
            ],
        );
        let mut manifest = phase11_prepare_decoding_chain(&[step]).expect("manifest");
        manifest.proof_backend_version = "stwo-phase10-gemma-block-v4".to_string();
        let err = verify_phase11_decoding_chain(&manifest).unwrap_err();
        assert!(err
            .to_string()
            .contains("unsupported decoding proof backend version"));
    }

    #[test]
    fn phase11_verify_decoding_chain_rejects_non_decoding_family_steps() {
        let step = sample_step_proof(
            vec![
                0, 0, 0, 0, 0, 0, 2, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ],
            vec![
                0, 0, 0, 0, 2, 1, 2, 1, 1, 1, 1, 4, 1, 16, 64, 1, 1, 4, 128, 0, 1, 1, 1,
            ],
        );
        let mut manifest = phase11_prepare_decoding_chain(&[step]).expect("manifest");
        manifest.steps[0].proof.claim.program =
            parse_program(include_str!("../../programs/addition.tvm")).expect("program");
        let err = verify_phase11_decoding_chain(&manifest).unwrap_err();
        assert!(err
            .to_string()
            .contains("is not a decoding_step_v1-family proof"));
    }

    #[test]
    fn phase11_validate_chain_steps_rejects_position_overflow() {
        let step = Phase11DecodingStep {
            from_state: Phase11DecodingState {
                state_version: STWO_DECODING_STATE_VERSION_PHASE11.to_string(),
                step_index: 0,
                position: i16::MAX,
                kv_cache_commitment: "kv".to_string(),
                output_commitment: "out".to_string(),
            },
            to_state: Phase11DecodingState {
                state_version: STWO_DECODING_STATE_VERSION_PHASE11.to_string(),
                step_index: 1,
                position: i16::MAX,
                kv_cache_commitment: "kv".to_string(),
                output_commitment: "out2".to_string(),
            },
            proof: sample_step_proof(
                vec![
                    0, 0, 0, 0, 0, 0, 2, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                ],
                vec![
                    0, 0, 0, 0, 2, 1, 2, 1, 1, 1, 1, 4, 1, 16, 64, 1, 1, 4, 128, 0, 1, 1, 1,
                ],
            ),
        };
        let err = validate_phase11_chain_steps(&[step]).unwrap_err();
        assert!(err.to_string().contains("cannot be incremented"));
    }

    #[test]
    fn phase12_decoding_layout_generates_inferable_family_program() {
        let layout = Phase12DecodingLayout::new(4, 4).expect("layout");
        let program = decoding_step_v2_template_program(&layout).expect("program");
        let inferred = infer_phase12_decoding_layout(&program).expect("layout inference");
        assert_eq!(inferred, layout);
        assert!(matches_decoding_step_v2_family(&program));
        assert!(matches_decoding_step_v2_family_with_layout(
            &program, &layout
        ));
    }

    #[test]
    fn phase12_template_consumes_shared_lookup_rows() {
        let layout = phase12_default_decoding_layout();
        let program = decoding_step_v2_template_program(&layout).expect("program");
        let lookup = layout.lookup_range().expect("lookup range");
        let output = layout.output_range().expect("output range");
        let instructions = program.instructions();
        let store_last_lookup =
            Instruction::Store((lookup.start + PHASE12_SHARED_LOOKUP_ROWS - 1) as u8);
        let lookup_store_index = instructions
            .iter()
            .rposition(|instruction| *instruction == store_last_lookup)
            .expect("last lookup store");
        assert_eq!(
            instructions.get(lookup_store_index + 1),
            Some(&Instruction::Load(output.start as u8))
        );
        assert_eq!(
            instructions.get(lookup_store_index + 2),
            Some(&Instruction::MulMemory((lookup.start + 1) as u8))
        );
        assert_eq!(
            instructions.get(lookup_store_index + 3),
            Some(&Instruction::Store(output.start as u8))
        );
        assert_eq!(
            instructions.get(lookup_store_index + 4),
            Some(&Instruction::Load(output.start as u8))
        );
        assert_eq!(
            instructions.get(lookup_store_index + 5),
            Some(&Instruction::AddMemory((lookup.start + 3) as u8))
        );
        assert_eq!(
            instructions.get(lookup_store_index + 6),
            Some(&Instruction::Store(output.start as u8))
        );
        assert_eq!(
            instructions.get(lookup_store_index + 7),
            Some(&Instruction::Load((output.start + 1) as u8))
        );
        assert_eq!(
            instructions.get(lookup_store_index + 8),
            Some(&Instruction::MulMemory((lookup.start + 5) as u8))
        );
        assert_eq!(
            instructions.get(lookup_store_index + 9),
            Some(&Instruction::Store((output.start + 1) as u8))
        );
        assert_eq!(
            instructions.get(lookup_store_index + 10),
            Some(&Instruction::Load((output.start + 1) as u8))
        );
        assert_eq!(
            instructions.get(lookup_store_index + 11),
            Some(&Instruction::AddMemory((lookup.start + 7) as u8))
        );
        assert_eq!(
            instructions.get(lookup_store_index + 12),
            Some(&Instruction::Store((output.start + 1) as u8))
        );
        assert_eq!(
            instructions.get(lookup_store_index + 13),
            Some(&Instruction::Load((lookup.start + 3) as u8))
        );
        assert_eq!(
            instructions.get(lookup_store_index + 14),
            Some(&Instruction::AddMemory((lookup.start + 7) as u8))
        );
        assert_eq!(
            instructions.get(lookup_store_index + 15),
            Some(&Instruction::AddMemory((lookup.start + 2) as u8))
        );
        assert_eq!(
            instructions.get(lookup_store_index + 16),
            Some(&Instruction::AddMemory((lookup.start + 4) as u8))
        );
        assert_eq!(
            instructions.get(lookup_store_index + 17),
            Some(&Instruction::Store((output.start + 2) as u8))
        );
    }

    #[test]
    fn phase12_template_adds_combined_output_into_primary_output() {
        let layout = phase12_default_decoding_layout();
        let output = layout.output_range().expect("output range");
        let program = decoding_step_v2_template_program(&layout).expect("program");
        let instructions = program.instructions();
        let combined_store_index = instructions
            .iter()
            .position(|instruction| *instruction == Instruction::Store((output.start + 2) as u8))
            .expect("combined-output store");
        assert_eq!(
            instructions.get(combined_store_index + 4),
            Some(&Instruction::Load(output.start as u8))
        );
        assert_eq!(
            instructions.get(combined_store_index + 5),
            Some(&Instruction::AddMemory((output.start + 2) as u8))
        );
        assert_eq!(
            instructions.get(combined_store_index + 6),
            Some(&Instruction::Store(output.start as u8))
        );
    }

    #[test]
    fn phase12_template_adds_combined_output_into_secondary_output() {
        let layout = phase12_default_decoding_layout();
        let output = layout.output_range().expect("output range");
        let program = decoding_step_v2_template_program(&layout).expect("program");
        let instructions = program.instructions();
        let combined_store_index = instructions
            .iter()
            .position(|instruction| *instruction == Instruction::Store((output.start + 2) as u8))
            .expect("combined-output store");
        assert_eq!(
            instructions.get(combined_store_index + 1),
            Some(&Instruction::Load((output.start + 1) as u8))
        );
        assert_eq!(
            instructions.get(combined_store_index + 2),
            Some(&Instruction::AddMemory((output.start + 2) as u8))
        );
        assert_eq!(
            instructions.get(combined_store_index + 3),
            Some(&Instruction::Store((output.start + 1) as u8))
        );
    }

    #[test]
    fn phase12_template_writes_primary_output_into_fourth_cache_lane_when_available() {
        let layout = phase12_default_decoding_layout();
        let latest_cached = layout.latest_cached_pair_range().expect("latest cached");
        let output = layout.output_range().expect("output range");
        let program = decoding_step_v2_template_program(&layout).expect("program");
        let instructions = program.instructions();
        let expected = [
            Instruction::Load(output.start as u8),
            Instruction::Store((latest_cached.start + 3) as u8),
        ];
        assert!(instructions
            .windows(expected.len())
            .any(|window| window == expected.as_slice()));
    }

    #[test]
    fn phase12_template_writes_combined_output_into_first_cache_lane_when_available() {
        let layout = phase12_default_decoding_layout();
        let latest_cached = layout.latest_cached_pair_range().expect("latest cached");
        let output = layout.output_range().expect("output range");
        let program = decoding_step_v2_template_program(&layout).expect("program");
        let instructions = program.instructions();
        let expected = [
            Instruction::Load((output.start + 2) as u8),
            Instruction::Store(latest_cached.start as u8),
        ];
        assert!(instructions
            .windows(expected.len())
            .any(|window| window == expected.as_slice()));
    }

    #[test]
    fn phase12_template_writes_combined_output_into_second_cache_lane_when_available() {
        let layout = phase12_default_decoding_layout();
        let latest_cached = layout.latest_cached_pair_range().expect("latest cached");
        let output = layout.output_range().expect("output range");
        let program = decoding_step_v2_template_program(&layout).expect("program");
        let instructions = program.instructions();
        let expected = [
            Instruction::Load((output.start + 2) as u8),
            Instruction::Store((latest_cached.start + 1) as u8),
        ];
        assert!(instructions
            .windows(expected.len())
            .any(|window| window == expected.as_slice()));
    }

    #[test]
    fn phase12_template_rejects_programs_beyond_u8_pc_horizon() {
        let layout = Phase12DecodingLayout::new(25, 4).expect("layout");
        let err = decoding_step_v2_template_program(&layout).expect_err("program must be rejected");
        match err {
            VmError::InvalidConfig(message) => {
                assert!(message.contains("instruction count"));
                assert!(message.contains("u8 pc horizon"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn phase12_runtime_uses_shared_lookup_rows_across_layouts() {
        for layout in phase13_default_decoding_layout_matrix().expect("layout matrix") {
            for memory in phase12_demo_initial_memories(&layout).expect("memories") {
                let program = decoding_step_v2_program_with_initial_memory(&layout, memory.clone())
                    .expect("program");
                let step_limit = decoding_program_step_limit(&program).expect("step limit");
                let mut runtime =
                    NativeInterpreter::new(program, Attention2DMode::AverageHard, step_limit);
                let result = runtime.run().expect("run program");
                assert!(result.halted);
                assert_eq!(
                    result.final_state.memory,
                    phase12_expected_final_memory(&layout, &memory)
                );
            }
        }
    }

    #[test]
    fn phase12_semantic_oracle_matches_manifest_states_across_layouts() {
        for layout in phase13_default_decoding_layout_matrix().expect("layout matrix") {
            let kv_cache_range = layout.kv_cache_range().expect("kv cache range");
            let latest_cached_range = layout
                .latest_cached_pair_range()
                .expect("latest cached range");
            let layout_commitment = commit_phase12_layout(&layout);
            let proofs = phase12_demo_initial_memories(&layout)
                .expect("memories")
                .into_iter()
                .map(|memory| sample_phase12_step_proof(&layout, memory))
                .collect::<Vec<_>>();
            let manifest = phase12_prepare_decoding_chain(&layout, &proofs).expect("manifest");

            let mut expected_history_length = layout.rolling_kv_pairs;
            let mut expected_history_commitment = commit_phase12_history_seed(
                &layout_commitment,
                &proofs[0].claim.program.initial_memory()[kv_cache_range.clone()],
                layout.pair_width,
            );

            for (step_index, (step, proof)) in manifest.steps.iter().zip(proofs.iter()).enumerate()
            {
                let initial_memory = proof.claim.program.initial_memory();
                let expected_final_memory = phase12_expected_final_memory(&layout, initial_memory);
                assert_eq!(proof.claim.final_state.memory, expected_final_memory);

                let expected_from = build_phase12_state(
                    step_index,
                    derive_phase12_state_view(initial_memory, &layout).expect("from view"),
                    expected_history_commitment.clone(),
                    expected_history_length,
                );
                assert_eq!(step.from_state, expected_from);

                let next_history_length = expected_history_length + 1;
                let next_history_commitment = advance_phase12_history_commitment(
                    &layout_commitment,
                    &expected_history_commitment,
                    &expected_final_memory[latest_cached_range.clone()],
                    next_history_length,
                );
                let expected_to = build_phase12_state(
                    step_index + 1,
                    derive_phase12_final_state_view_from_proof(proof, &layout).expect("to view"),
                    next_history_commitment.clone(),
                    next_history_length,
                );
                assert_eq!(step.to_state, expected_to);

                expected_history_commitment = next_history_commitment;
                expected_history_length = next_history_length;
            }

            verify_phase12_decoding_chain(&manifest).expect("verify oracle-backed manifest");
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        #[test]
        fn phase12_runtime_matches_oracle_for_bounded_layout_memory(
            (layout, memory) in phase12_bounded_memory_strategy(),
        ) {
            let program = decoding_step_v2_program_with_initial_memory(&layout, memory.clone()).expect("program");
            let step_limit = decoding_program_step_limit(&program).expect("step limit");
            let mut runtime = NativeInterpreter::new(
                program,
                Attention2DMode::AverageHard,
                step_limit,
            );
            let result = runtime.run().expect("run program");
            prop_assert!(result.halted);
            prop_assert_eq!(result.final_state.memory, phase12_expected_final_memory(&layout, &memory));
        }
    }

    #[test]
    fn phase12_random_bounded_memories_accept_real_stwo_proof_and_match_oracle() {
        const RANDOM_REAL_PROOF_CASES_PER_LAYOUT: usize = 1;

        let config = TransformerVmConfig {
            num_layers: 1,
            attention_mode: Attention2DMode::AverageHard,
            ..TransformerVmConfig::default()
        };
        let mut rng = StdRng::seed_from_u64(0x5EED_1202);
        for layout in phase13_default_decoding_layout_matrix().expect("layout matrix") {
            // Keep the real proving loop bounded; the broader randomized coverage lives in the
            // property test above, while this path ensures each layout still hits the real backend.
            for case_index in 0..RANDOM_REAL_PROOF_CASES_PER_LAYOUT {
                let initial_memory = phase12_random_bounded_memory(&layout, &mut rng);
                let expected_final_memory = phase12_expected_final_memory(&layout, &initial_memory);
                let program =
                    decoding_step_v2_program_with_initial_memory(&layout, initial_memory.clone())
                        .expect("program");
                let mut runtime = NativeInterpreter::new(
                    program.clone(),
                    Attention2DMode::AverageHard,
                    decoding_program_step_limit(&program).expect("step limit"),
                );
                let result = runtime.run().expect("run program");
                assert!(result.halted);
                assert_eq!(result.final_state.memory, expected_final_memory);

                let model = ProgramCompiler
                    .compile_program(program, config.clone())
                    .expect("compile");
                let proof = prove_execution_stark_with_backend_and_options(
                    &model,
                    128,
                    StarkProofBackend::Stwo,
                    production_v1_stark_options(),
                )
                .unwrap_or_else(|error| {
                    panic!(
                        "random bounded layout {:?} case {case_index} failed real stwo proof: {error}; initial_memory={initial_memory:?}",
                        layout
                    )
                });
                assert_eq!(proof.claim.final_state.memory, expected_final_memory);
                assert_eq!(
                    phase12_shared_lookup_rows_from_proof_payload(
                        &proof,
                        &commit_phase12_layout(&layout),
                    )
                    .expect("lookup rows from proof"),
                    Some(
                        expected_final_memory[layout.lookup_range().expect("lookup range")]
                            .to_vec()
                    )
                );
            }
        }
    }

    #[test]
    fn phase12_real_stwo_prove_accepts_default_layout_demo_memories() {
        let layout = phase12_default_decoding_layout();
        let config = TransformerVmConfig {
            num_layers: 1,
            attention_mode: Attention2DMode::AverageHard,
            ..TransformerVmConfig::default()
        };
        for (step_index, initial_memory) in phase12_demo_initial_memories(&layout)
            .expect("memories")
            .into_iter()
            .enumerate()
        {
            let debug_memory = initial_memory.clone();
            let program = decoding_step_v2_program_with_initial_memory(&layout, initial_memory)
                .expect("program");
            let model = ProgramCompiler
                .compile_program(program, config.clone())
                .expect("compile");
            prove_execution_stark_with_backend_and_options(
                &model,
                128,
                StarkProofBackend::Stwo,
                production_v1_stark_options(),
            )
            .unwrap_or_else(|error| {
                panic!(
                    "default layout step {step_index} failed real stwo proof: {error}; initial_memory={debug_memory:?}"
                )
            });
        }
    }

    #[test]
    fn phase13_real_stwo_prove_accepts_layout_matrix_demo_memories() {
        let config = TransformerVmConfig {
            num_layers: 1,
            attention_mode: Attention2DMode::AverageHard,
            ..TransformerVmConfig::default()
        };
        for layout in phase13_default_decoding_layout_matrix().expect("layout matrix") {
            for (step_index, initial_memory) in phase12_demo_initial_memories(&layout)
                .expect("memories")
                .into_iter()
                .enumerate()
            {
                let debug_layout = layout.clone();
                let debug_memory = initial_memory.clone();
                let program = decoding_step_v2_program_with_initial_memory(&layout, initial_memory)
                    .expect("program");
                let model = ProgramCompiler
                    .compile_program(program, config.clone())
                    .expect("compile");
                prove_execution_stark_with_backend_and_options(
                    &model,
                    128,
                    StarkProofBackend::Stwo,
                    production_v1_stark_options(),
                )
                .unwrap_or_else(|error| {
                    panic!(
                        "layout {:?} step {step_index} failed real stwo proof: {error}; initial_memory={debug_memory:?}",
                        debug_layout
                    )
                });
            }
        }
    }

    #[test]
    fn phase12_decoding_layout_accepts_full_u8_address_space() {
        let layout = Phase12DecodingLayout::new(241, 1).expect("layout");
        assert_eq!(layout.memory_size().expect("memory size"), 256);
    }

    #[test]
    fn phase12_decoding_layout_rejects_overflowing_address_space() {
        let error = Phase12DecodingLayout::new(242, 1).unwrap_err();
        assert!(error
            .to_string()
            .contains("exceeds the encoded address limit 256"));
    }

    #[test]
    fn phase12_prepare_decoding_chain_accepts_linked_steps() {
        let layout = phase12_default_decoding_layout();
        let memories = phase12_demo_initial_memories(&layout).expect("memories");
        let proofs = memories
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();

        let manifest = phase12_prepare_decoding_chain(&layout, &proofs).expect("manifest");
        assert_eq!(manifest.total_steps, 3);
        assert_eq!(manifest.layout, layout);
        assert_eq!(
            manifest.steps[0].to_state.persistent_state_commitment,
            manifest.steps[1].from_state.persistent_state_commitment
        );
        assert_eq!(
            manifest.steps[0].to_state.kv_cache_commitment,
            manifest.steps[1].from_state.kv_cache_commitment
        );
        assert_eq!(
            manifest.steps[0].to_state.kv_history_commitment,
            manifest.steps[1].from_state.kv_history_commitment
        );
        assert_eq!(
            manifest.steps[0].to_state.public_state_commitment,
            manifest.steps[1].from_state.public_state_commitment
        );
        assert_eq!(manifest.steps[0].from_state.kv_history_length, 4);
        assert_eq!(manifest.steps[2].to_state.kv_history_length, 7);
        assert_ne!(
            manifest.steps[0].from_state.incoming_token_commitment,
            manifest.steps[1].from_state.incoming_token_commitment
        );
        assert!(!manifest.shared_lookup_artifacts.is_empty());
        for step in &manifest.steps {
            let artifact = manifest
                .shared_lookup_artifacts
                .iter()
                .find(|artifact| {
                    artifact.artifact_commitment == step.shared_lookup_artifact_commitment
                })
                .expect("artifact for step");
            assert_eq!(
                artifact.lookup_rows_commitment,
                step.to_state.lookup_rows_commitment
            );
        }
    }

    #[test]
    fn phase12_shared_lookup_artifact_registry_deduplicates_identical_proofs() {
        let layout = phase12_default_decoding_layout();
        let layout_commitment = commit_phase12_layout(&layout);
        let memory = phase12_demo_initial_memories(&layout)
            .expect("memories")
            .into_iter()
            .next()
            .expect("first memory");
        let proof = sample_phase12_step_proof(&layout, memory);

        let (artifacts, refs) = build_phase12_shared_lookup_artifact_registry(
            &[proof.clone(), proof],
            &layout_commitment,
        )
        .expect("artifact registry");

        assert_eq!(artifacts.len(), 1);
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0], refs[1]);
    }

    #[test]
    fn phase12_history_commitment_tracks_executed_latest_cached_pair() {
        let layout = phase12_default_decoding_layout();
        let latest_cached_range = layout
            .latest_cached_pair_range()
            .expect("latest cached range");
        let memories = phase12_demo_initial_memories(&layout).expect("memories");
        let proofs = memories
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();

        let manifest = phase12_prepare_decoding_chain(&layout, &proofs).expect("manifest");
        let layout_commitment = commit_phase12_layout(&layout);
        let seeded_history_commitment = commit_phase12_history_seed(
            &layout_commitment,
            &manifest.steps[0].proof.claim.program.initial_memory()
                [layout.kv_cache_range().expect("kv cache range")],
            layout.pair_width,
        );
        let expected_commitment = advance_phase12_history_commitment(
            &layout_commitment,
            &seeded_history_commitment,
            &manifest.steps[0].proof.claim.final_state.memory[latest_cached_range],
            layout.rolling_kv_pairs + 1,
        );

        assert_eq!(
            manifest.steps[0].to_state.kv_history_commitment,
            expected_commitment
        );
    }

    #[test]
    fn phase12_verify_decoding_chain_rejects_broken_persistent_link() {
        let layout = phase12_default_decoding_layout();
        let memories = phase12_demo_initial_memories(&layout).expect("memories");
        let proofs = memories
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let mut manifest = phase12_prepare_decoding_chain(&layout, &proofs).expect("manifest");
        manifest.steps[1].from_state.persistent_state_commitment = "broken".to_string();
        let err = verify_phase12_decoding_chain(&manifest).unwrap_err();
        assert!(err
            .to_string()
            .contains("recorded from_state does not match the proof's initial state"));
    }

    #[test]
    fn phase12_verify_decoding_chain_rejects_broken_history_link() {
        let layout = phase12_default_decoding_layout();
        let memories = phase12_demo_initial_memories(&layout).expect("memories");
        let proofs = memories
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let mut manifest = phase12_prepare_decoding_chain(&layout, &proofs).expect("manifest");
        manifest.steps[1].from_state.kv_history_commitment = "broken".to_string();
        let err = verify_phase12_decoding_chain(&manifest).unwrap_err();
        assert!(err
            .to_string()
            .contains("recorded from_state does not match the proof's initial state"));
    }

    #[test]
    fn phase12_verify_decoding_chain_rejects_tampered_embedded_lookup_rows() {
        let layout = phase12_default_decoding_layout();
        let memories = phase12_demo_initial_memories(&layout).expect("memories");
        let proofs = memories
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let mut manifest = phase12_prepare_decoding_chain(&layout, &proofs).expect("manifest");
        let mut payload: serde_json::Value =
            serde_json::from_slice(&manifest.steps[1].proof.proof).expect("payload");
        payload["embedded_shared_activation_lookup"]["claimed_rows"][1]["expected_output"] =
            serde_json::json!(0);
        manifest.steps[1].proof.proof = serde_json::to_vec(&payload).expect("payload bytes");
        let err = verify_phase12_decoding_chain(&manifest).unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("embedded shared activation rows do not match")
                || message.contains("shared lookup artifact"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn phase12_verify_decoding_chain_rejects_missing_shared_lookup_artifact() {
        let layout = phase12_default_decoding_layout();
        let memories = phase12_demo_initial_memories(&layout).expect("memories");
        let proofs = memories
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let mut manifest = phase12_prepare_decoding_chain(&layout, &proofs).expect("manifest");
        manifest.shared_lookup_artifacts.clear();
        let err = verify_phase12_decoding_chain(&manifest).unwrap_err();
        assert!(err
            .to_string()
            .contains("must contain at least one shared lookup artifact"));
    }

    #[test]
    fn phase12_verify_decoding_chain_rejects_tampered_shared_lookup_artifact() {
        let layout = phase12_default_decoding_layout();
        let memories = phase12_demo_initial_memories(&layout).expect("memories");
        let proofs = memories
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let mut manifest = phase12_prepare_decoding_chain(&layout, &proofs).expect("manifest");
        manifest.shared_lookup_artifacts[0].flattened_lookup_rows[0] = 0;
        let err = verify_phase12_decoding_chain(&manifest).unwrap_err();
        assert!(err
            .to_string()
            .contains("lookup_rows_commitment does not match"));
    }

    #[test]
    fn phase12_verify_decoding_chain_rejects_oversized_proof_payload() {
        let layout = phase12_default_decoding_layout();
        let memories = phase12_demo_initial_memories(&layout).expect("memories");
        let proofs = memories
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let mut manifest = phase12_prepare_decoding_chain(&layout, &proofs).expect("manifest");
        manifest.steps[0].proof.proof = vec![0; MAX_DECODING_PROOF_PAYLOAD_BYTES + 1];
        let err = verify_phase12_decoding_chain(&manifest).unwrap_err();
        assert!(err.to_string().contains("proof payload is"));
    }

    #[test]
    fn phase12_verify_decoding_chain_rejects_oversized_registry_nested_proof() {
        let layout = phase12_default_decoding_layout();
        let memories = phase12_demo_initial_memories(&layout).expect("memories");
        let proofs = memories
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let mut manifest = phase12_prepare_decoding_chain(&layout, &proofs).expect("manifest");
        manifest.shared_lookup_artifacts[0]
            .activation_proof_envelope
            .proof_envelope
            .proof
            .resize(MAX_SHARED_LOOKUP_ENVELOPE_PROOF_BYTES + 1, 0);
        let err = verify_phase12_decoding_chain(&manifest).unwrap_err();
        assert!(err.to_string().contains("activation proof is"));
    }

    #[test]
    fn phase12_verify_decoding_chain_rejects_too_many_steps() {
        let layout = phase12_default_decoding_layout();
        let memories = phase12_demo_initial_memories(&layout).expect("memories");
        let proofs = memories
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let mut manifest = phase12_prepare_decoding_chain(&layout, &proofs).expect("manifest");
        let template_step = manifest.steps[0].clone();
        manifest.steps = vec![template_step; MAX_DECODING_CHAIN_STEPS + 1];
        manifest.total_steps = manifest.steps.len();
        let err = verify_phase12_decoding_chain(&manifest).unwrap_err();
        assert!(err.to_string().contains("exceeding the limit"));
    }

    #[test]
    fn phase12_prepare_decoding_chain_rejects_too_many_steps() {
        let layout = phase12_default_decoding_layout();
        let memory = phase12_demo_initial_memories(&layout)
            .expect("memories")
            .into_iter()
            .next()
            .expect("seed memory");
        let template = sample_phase12_step_proof(&layout, memory);
        let proofs = vec![template; MAX_DECODING_CHAIN_STEPS + 1];
        let err = phase12_prepare_decoding_chain(&layout, &proofs).unwrap_err();
        assert!(err.to_string().contains("exceeding the limit"));
    }

    #[test]
    fn phase12_verify_decoding_chain_rejects_unreferenced_shared_lookup_artifact() {
        let layout = phase12_default_decoding_layout();
        let memories = phase12_demo_initial_memories(&layout).expect("memories");
        let proofs = memories
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let mut manifest = phase12_prepare_decoding_chain(&layout, &proofs).expect("manifest");
        let extra_artifact = manifest.shared_lookup_artifacts[0].clone();
        manifest.shared_lookup_artifacts.push(extra_artifact);
        let err = verify_phase12_decoding_chain(&manifest).unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("contains 4 shared lookup artifacts for only 3 steps")
                || message.contains("is not referenced by any decoding step")
                || message.contains("appears more than once"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn phase12_verify_decoding_chain_rejects_too_many_shared_lookup_artifacts() {
        let layout = phase12_default_decoding_layout();
        let memories = phase12_demo_initial_memories(&layout).expect("memories");
        let proofs = memories
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let mut manifest = phase12_prepare_decoding_chain(&layout, &proofs).expect("manifest");
        let template_step = manifest.steps[0].clone();
        manifest.steps = vec![template_step; MAX_DECODING_SHARED_LOOKUP_ARTIFACTS];
        manifest.total_steps = manifest.steps.len();
        let template = manifest.shared_lookup_artifacts[0].clone();
        while manifest.shared_lookup_artifacts.len() <= MAX_DECODING_SHARED_LOOKUP_ARTIFACTS {
            let mut extra = template.clone();
            extra
                .artifact_commitment
                .push_str(&format!("-{}", manifest.shared_lookup_artifacts.len()));
            manifest.shared_lookup_artifacts.push(extra);
        }
        let err = verify_phase12_decoding_chain(&manifest).unwrap_err();
        assert!(err
            .to_string()
            .contains("shared lookup artifacts, exceeding the limit"));
    }

    #[test]
    fn phase12_verify_decoding_chain_rejects_wrong_shared_lookup_artifact_reference() {
        let layout = phase12_default_decoding_layout();
        let memories = phase12_demo_initial_memories(&layout).expect("memories");
        let proofs = memories
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let mut manifest = phase12_prepare_decoding_chain(&layout, &proofs).expect("manifest");
        let wrong_artifact = sample_phase12_valid_but_wrong_shared_lookup_artifact(&layout);
        let wrong_commitment = wrong_artifact.artifact_commitment.clone();
        manifest.shared_lookup_artifacts.push(wrong_artifact);
        manifest.steps[0].shared_lookup_artifact_commitment = wrong_commitment;
        let err = verify_phase12_decoding_chain(&manifest).unwrap_err();
        assert!(err.to_string().contains("does not match the proof payload"));
    }

    #[test]
    fn phase12_verify_decoding_chain_rejects_missing_embedded_shared_lookup_payload() {
        let layout = phase12_default_decoding_layout();
        let memories = phase12_demo_initial_memories(&layout).expect("memories");
        let proofs = memories
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let mut manifest = phase12_prepare_decoding_chain(&layout, &proofs).expect("manifest");
        let mut payload: serde_json::Value =
            serde_json::from_slice(&manifest.steps[0].proof.proof).expect("payload");
        payload
            .as_object_mut()
            .expect("payload object")
            .remove("embedded_shared_activation_lookup");
        manifest.steps[0].proof.proof = serde_json::to_vec(&payload).expect("payload bytes");
        let err = verify_phase12_decoding_chain(&manifest).unwrap_err();
        assert!(
            err.to_string()
                .contains("missing its Phase 12 shared lookup artifact payload")
                || err.to_string().contains("does not match the proof payload")
                || err
                    .to_string()
                    .contains("missing embedded shared activation rows"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn phase12_verify_decoding_chain_rejects_duplicate_shared_lookup_artifact_commitment() {
        let layout = phase12_default_decoding_layout();
        let memories = phase12_demo_initial_memories(&layout).expect("memories");
        let proofs = memories
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let mut manifest = phase12_prepare_decoding_chain(&layout, &proofs).expect("manifest");
        let duplicate = manifest.shared_lookup_artifacts[0].clone();
        manifest.shared_lookup_artifacts.push(duplicate);
        let err = verify_phase12_decoding_chain(&manifest).unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("appears more than once")
                || message.contains("is not referenced by any decoding step"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn phase12_verify_decoding_chain_rejects_layout_mismatch() {
        let layout = phase12_default_decoding_layout();
        let memories = phase12_demo_initial_memories(&layout).expect("memories");
        let proofs = memories
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let mut manifest = phase12_prepare_decoding_chain(&layout, &proofs).expect("manifest");
        manifest.layout = Phase12DecodingLayout::new(3, 4).expect("alternate layout");
        let err = verify_phase12_decoding_chain(&manifest).unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("is not a decoding_step_v2-family proof for the manifest layout")
                || message.contains("shared lookup artifact layout commitment")
        );
    }

    #[test]
    fn phase12_verify_decoding_chain_rejects_unsupported_backend_version() {
        let layout = phase12_default_decoding_layout();
        let memories = phase12_demo_initial_memories(&layout).expect("memories");
        let proofs = memories
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let mut manifest = phase12_prepare_decoding_chain(&layout, &proofs).expect("manifest");
        manifest.proof_backend_version = STWO_BACKEND_VERSION_PHASE11.to_string();
        let err = verify_phase12_decoding_chain(&manifest).unwrap_err();
        assert!(err
            .to_string()
            .contains("unsupported decoding proof backend version"));
    }

    #[test]
    fn phase12_verify_decoding_chain_rejects_tampered_public_state_commitment() {
        let layout = phase12_default_decoding_layout();
        let memories = phase12_demo_initial_memories(&layout).expect("memories");
        let proofs = memories
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let mut manifest = phase12_prepare_decoding_chain(&layout, &proofs).expect("manifest");
        manifest.steps[1].from_state.public_state_commitment = "broken".to_string();
        let err = verify_phase12_decoding_chain(&manifest).unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("from_state public_state_commitment does not match")
                || message.contains("recorded from_state does not match the proof's initial state"),
            "unexpected error: {message}"
        );
    }

    fn sample_phase30_decoding_step_proof_envelope_manifest(
    ) -> Phase30DecodingStepProofEnvelopeManifest {
        sample_phase30_chain_and_manifest().1
    }

    fn sample_phase30_chain_and_manifest() -> (
        Phase12DecodingChainManifest,
        Phase30DecodingStepProofEnvelopeManifest,
    ) {
        let layout = phase12_default_decoding_layout();
        let memories = phase12_demo_initial_memories(&layout).expect("memories");
        let proofs = memories
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let chain = phase12_prepare_decoding_chain(&layout, &proofs).expect("chain");
        let manifest =
            phase30_prepare_decoding_step_proof_envelope_manifest(&chain).expect("envelopes");
        (chain, manifest)
    }

    #[test]
    fn phase30_step_envelope_manifest_binds_phase12_chain_boundaries() {
        let layout = phase12_default_decoding_layout();
        let memories = phase12_demo_initial_memories(&layout).expect("memories");
        let proofs = memories
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let chain = phase12_prepare_decoding_chain(&layout, &proofs).expect("chain");
        let manifest = sample_phase30_decoding_step_proof_envelope_manifest();

        assert_eq!(
            manifest.manifest_version,
            STWO_DECODING_STEP_ENVELOPE_MANIFEST_VERSION_PHASE30
        );
        assert_eq!(manifest.total_steps, chain.steps.len());
        assert_eq!(
            manifest.chain_start_boundary_commitment,
            chain.steps[0].from_state.public_state_commitment
        );
        assert_eq!(
            manifest.chain_end_boundary_commitment,
            chain
                .steps
                .last()
                .expect("last step")
                .to_state
                .public_state_commitment
        );
        for (index, envelope) in manifest.envelopes.iter().enumerate() {
            let step = &chain.steps[index];
            let artifact = chain
                .shared_lookup_artifacts
                .iter()
                .find(|candidate| {
                    candidate.artifact_commitment == step.shared_lookup_artifact_commitment
                })
                .expect("artifact");
            assert_eq!(envelope.step_index, index);
            assert_eq!(
                envelope.input_boundary_commitment,
                step.from_state.public_state_commitment
            );
            assert_eq!(
                envelope.output_boundary_commitment,
                step.to_state.public_state_commitment
            );
            assert_eq!(
                envelope.source_chain_commitment,
                manifest.source_chain_commitment
            );
            assert_eq!(
                envelope.static_lookup_registry_commitment,
                artifact.static_table_registry_commitment
            );
            assert!(!envelope.proof_commitment.is_empty());
            assert!(!envelope.envelope_commitment.is_empty());
        }

        verify_phase30_decoding_step_proof_envelope_manifest(&manifest).expect("verify");
        verify_phase30_decoding_step_proof_envelope_manifest_against_chain(&manifest, &chain)
            .expect("verify against chain");
    }

    #[test]
    fn phase30_save_and_load_round_trip() {
        let manifest = sample_phase30_decoding_step_proof_envelope_manifest();
        let path = std::env::temp_dir().join(format!(
            "phase30-decoding-step-proof-envelope-manifest-roundtrip-{}-save.json",
            std::process::id(),
        ));
        save_phase30_decoding_step_proof_envelope_manifest(&manifest, &path).expect("save");
        let loaded = load_phase30_decoding_step_proof_envelope_manifest(&path).expect("load");
        assert_eq!(loaded, manifest);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn phase30_load_accepts_gzip_round_trip() {
        let manifest = sample_phase30_decoding_step_proof_envelope_manifest();
        let path = std::env::temp_dir().join(format!(
            "phase30-decoding-step-proof-envelope-manifest-roundtrip-{}-gzip.json",
            std::process::id(),
        ));
        let gzip_path = path.with_extension("json.gz");
        save_phase30_decoding_step_proof_envelope_manifest(&manifest, &path).expect("save");
        write_test_gzip_copy(&path, &gzip_path);
        let loaded = load_phase30_decoding_step_proof_envelope_manifest(&gzip_path).expect("load");
        assert_eq!(loaded, manifest);
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(gzip_path);
    }

    #[test]
    fn phase30_step_envelope_manifest_deserialization_verifies_manifest() {
        let manifest = sample_phase30_decoding_step_proof_envelope_manifest();
        let parsed = serde_json::from_value::<Phase30DecodingStepProofEnvelopeManifest>(
            serde_json::to_value(&manifest).expect("serialize manifest"),
        )
        .expect("deserialize manifest");
        assert_eq!(parsed, manifest);

        let mut tampered = serde_json::to_value(&manifest).expect("serialize manifest");
        tampered["total_steps"] = serde_json::json!(manifest.total_steps + 1);
        let err = serde_json::from_value::<Phase30DecodingStepProofEnvelopeManifest>(tampered)
            .expect_err("tampered deserialized manifest must be rejected");
        assert!(err.to_string().contains("total_steps"));
    }

    #[test]
    fn phase30_parse_manifest_reports_validation_error_as_invalid_config() {
        let manifest = sample_phase30_decoding_step_proof_envelope_manifest();
        let mut tampered = serde_json::to_value(&manifest).expect("serialize manifest");
        tampered["total_steps"] = serde_json::json!(manifest.total_steps + 1);
        let json = serde_json::to_string(&tampered).expect("tampered json");

        let err = parse_phase30_decoding_step_proof_envelope_manifest_json(&json)
            .expect_err("validation failure must surface as invalid config");
        assert!(
            matches!(err, VmError::InvalidConfig(_)),
            "expected InvalidConfig, got {err:?}"
        );
        assert!(err.to_string().contains("total_steps"));
    }

    #[test]
    fn phase30_parse_manifest_rejects_unknown_top_level_fields() {
        let manifest = sample_phase30_decoding_step_proof_envelope_manifest();
        let mut value = serde_json::to_value(&manifest).expect("serialize manifest");
        value["unexpected_phase30_field"] = serde_json::json!(true);
        let json = serde_json::to_string(&value).expect("json with unknown field");

        let err = parse_phase30_decoding_step_proof_envelope_manifest_json(&json)
            .expect_err("unknown top-level field must be rejected");
        assert!(
            matches!(err, VmError::InvalidConfig(_)),
            "expected InvalidConfig, got {err:?}"
        );
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn phase30_parse_manifest_rejects_unknown_nested_envelope_fields() {
        let manifest = sample_phase30_decoding_step_proof_envelope_manifest();
        let mut value = serde_json::to_value(&manifest).expect("serialize manifest");
        value["envelopes"][0]["unexpected_phase30_envelope_field"] = serde_json::json!(true);
        let json = serde_json::to_string(&value).expect("json with unknown nested field");

        let err = parse_phase30_decoding_step_proof_envelope_manifest_json(&json)
            .expect_err("unknown nested field must be rejected");
        assert!(
            matches!(err, VmError::InvalidConfig(_)),
            "expected InvalidConfig, got {err:?}"
        );
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn phase30_parse_manifest_rejects_unknown_layout_fields() {
        let manifest = sample_phase30_decoding_step_proof_envelope_manifest();
        let mut value = serde_json::to_value(&manifest).expect("serialize manifest");
        value["layout"]["unexpected_layout_field"] = serde_json::json!(true);
        let json = serde_json::to_string(&value).expect("json with unknown layout field");

        let err = parse_phase30_decoding_step_proof_envelope_manifest_json(&json)
            .expect_err("unknown layout field must be rejected");
        assert!(
            matches!(err, VmError::InvalidConfig(_)),
            "expected InvalidConfig, got {err:?}"
        );
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn phase30_parse_manifest_reports_malformed_json_as_invalid_config() {
        let err = parse_phase30_decoding_step_proof_envelope_manifest_json("{")
            .expect_err("malformed json must be rejected");
        assert!(
            matches!(err, VmError::InvalidConfig(_)),
            "expected InvalidConfig, got {err:?}"
        );
    }

    #[test]
    fn load_phase30_decoding_step_proof_envelope_manifest_reports_malformed_json_as_invalid_config()
    {
        use std::io::Write;

        let mut temp = tempfile::NamedTempFile::new().expect("create temp file");
        temp.write_all(b"{").expect("write malformed JSON");

        let err = load_phase30_decoding_step_proof_envelope_manifest(temp.path())
            .expect_err("malformed phase30 manifest should fail");
        assert!(
            matches!(err, VmError::InvalidConfig(_)),
            "expected InvalidConfig, got {err:?}"
        );
    }

    #[test]
    fn load_phase30_decoding_step_proof_envelope_manifest_rejects_oversized_manifest_file() {
        let path = std::env::temp_dir().join(format!(
            "phase30-decoding-step-proof-envelope-manifest-oversized-{}.json",
            std::process::id()
        ));
        fs::write(
            &path,
            vec![b'x'; MAX_PHASE30_DECODING_STEP_ENVELOPE_MANIFEST_JSON_BYTES + 1],
        )
        .expect("write");
        let err = load_phase30_decoding_step_proof_envelope_manifest(&path)
            .expect_err("oversized manifest should fail");
        assert!(err.to_string().contains("exceeding the limit"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn save_phase30_decoding_step_proof_envelope_manifest_rejects_manifest_exceeding_json_budget() {
        let mut manifest = sample_phase30_decoding_step_proof_envelope_manifest();
        manifest.envelopes[0].proof_commitment =
            "a".repeat(MAX_PHASE30_DECODING_STEP_ENVELOPE_MANIFEST_JSON_BYTES);
        let path = std::env::temp_dir().join(format!(
            "phase30-decoding-step-proof-envelope-manifest-too-large-{}.json",
            std::process::id()
        ));
        let err = save_phase30_decoding_step_proof_envelope_manifest(&manifest, &path)
            .expect_err("oversized phase30 manifest should fail");
        assert!(err.to_string().contains("limit"), "unexpected error: {err}");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn phase30_step_json_commitments_match_len_prefixed_digest_oracle() {
        let layout = phase12_default_decoding_layout();
        let memories = phase12_demo_initial_memories(&layout).expect("memories");
        let proofs = memories
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let chain = phase12_prepare_decoding_chain(&layout, &proofs).expect("chain");

        assert_eq!(
            commit_phase12_decoding_chain_for_step_envelopes(&chain).expect("chain commitment"),
            oracle_phase30_len_prefixed_json_digest_commit(
                STWO_DECODING_STEP_ENVELOPE_MANIFEST_VERSION_PHASE30,
                b"source-phase12-chain",
                &chain
            )
        );
        assert_eq!(
            commit_phase30_step_proof(&chain.steps[0].proof).expect("proof commitment"),
            oracle_phase30_len_prefixed_json_digest_commit(
                STWO_DECODING_STEP_ENVELOPE_VERSION_PHASE30,
                b"step-proof",
                &chain.steps[0].proof
            )
        );
    }

    #[test]
    fn phase30_step_json_digest_hashing_streams_large_payload() {
        let payload = Phase30LargeStreamingPayload {
            entries: 1024,
            row_width: 256,
        };
        let mut hasher = Blake2bVar::new(32).expect("blake2b-256");
        hasher.update(STWO_DECODING_STEP_ENVELOPE_VERSION_PHASE30.as_bytes());
        hasher.update(b"large-json-dos-regression");
        phase30_update_hasher_with_json(&mut hasher, &payload).expect("hash large payload");
        let mut out = [0u8; 32];
        hasher
            .finalize_variable(&mut out)
            .expect("blake2b finalize");

        assert_eq!(
            oracle_lower_hex(&out),
            oracle_phase30_len_prefixed_json_digest_commit(
                STWO_DECODING_STEP_ENVELOPE_VERSION_PHASE30,
                b"large-json-dos-regression",
                &payload
            )
        );
    }

    #[test]
    fn phase30_step_envelope_manifest_rejects_empty_or_unsupported_versions() {
        let layout = phase12_default_decoding_layout();
        let memories = phase12_demo_initial_memories(&layout).expect("memories");
        let proofs = memories
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let chain = phase12_prepare_decoding_chain(&layout, &proofs).expect("chain");
        let mut manifest =
            phase30_prepare_decoding_step_proof_envelope_manifest(&chain).expect("envelopes");

        manifest.proof_backend_version.clear();
        let err = verify_phase30_decoding_step_proof_envelope_manifest(&manifest)
            .expect_err("empty backend version should fail");
        assert!(
            err.to_string().contains("backend version"),
            "unexpected error: {err}"
        );

        manifest.proof_backend_version = "unsupported-stwo-backend".to_string();
        let err = verify_phase30_decoding_step_proof_envelope_manifest(&manifest)
            .expect_err("unsupported backend version should fail");
        assert!(
            err.to_string().contains("backend version"),
            "unexpected error: {err}"
        );

        manifest.proof_backend_version =
            crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12.to_string();
        manifest.statement_version.clear();
        let err = verify_phase30_decoding_step_proof_envelope_manifest(&manifest)
            .expect_err("empty statement version should fail");
        assert!(
            err.to_string().contains("statement version"),
            "unexpected error: {err}"
        );

        manifest.statement_version = "statement-v2".to_string();
        let err = verify_phase30_decoding_step_proof_envelope_manifest(&manifest)
            .expect_err("unsupported statement version should fail");
        assert!(
            err.to_string().contains("statement version"),
            "unexpected error: {err}"
        );

        manifest.statement_version = crate::proof::CLAIM_STATEMENT_VERSION_V1.to_string();
        manifest.source_chain_version.clear();
        let err = verify_phase30_decoding_step_proof_envelope_manifest(&manifest)
            .expect_err("empty source chain version should fail");
        assert!(
            err.to_string().contains("source chain version"),
            "unexpected error: {err}"
        );

        manifest.source_chain_version = "unsupported-phase12-chain".to_string();
        let err = verify_phase30_decoding_step_proof_envelope_manifest(&manifest)
            .expect_err("unsupported source chain version should fail");
        assert!(
            err.to_string().contains("source chain version"),
            "unexpected error: {err}"
        );

        manifest.source_chain_version = STWO_DECODING_CHAIN_VERSION_PHASE12.to_string();
        manifest.source_chain_semantic_scope.clear();
        let err = verify_phase30_decoding_step_proof_envelope_manifest(&manifest)
            .expect_err("empty source chain scope should fail");
        assert!(
            err.to_string().contains("source chain scope"),
            "unexpected error: {err}"
        );

        manifest.source_chain_semantic_scope = "unsupported-phase12-scope".to_string();
        let err = verify_phase30_decoding_step_proof_envelope_manifest(&manifest)
            .expect_err("unsupported source chain scope should fail");
        assert!(
            err.to_string().contains("source chain scope"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn phase30_step_envelope_manifest_rejects_excessive_envelope_count() {
        let layout = phase12_default_decoding_layout();
        let memories = phase12_demo_initial_memories(&layout).expect("memories");
        let proofs = memories
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let chain = phase12_prepare_decoding_chain(&layout, &proofs).expect("chain");
        let mut manifest =
            phase30_prepare_decoding_step_proof_envelope_manifest(&chain).expect("envelopes");

        let template = manifest.envelopes[0].clone();
        manifest.envelopes = vec![template; MAX_DECODING_CHAIN_STEPS + 1];
        manifest.total_steps = manifest.envelopes.len();

        let err = verify_phase30_decoding_step_proof_envelope_manifest(&manifest)
            .expect_err("excessive envelope count should fail before list hashing");
        assert!(
            err.to_string().contains("exceeding the limit"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn phase30_step_envelope_manifest_rejects_source_chain_commitment_drift() {
        let layout = phase12_default_decoding_layout();
        let memories = phase12_demo_initial_memories(&layout).expect("memories");
        let proofs = memories
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let chain = phase12_prepare_decoding_chain(&layout, &proofs).expect("chain");
        let mut manifest =
            phase30_prepare_decoding_step_proof_envelope_manifest(&chain).expect("envelopes");
        manifest.envelopes[0].source_chain_commitment = "tampered-source-chain".to_string();
        manifest.envelopes[0].envelope_commitment =
            commit_phase30_step_envelope(&manifest.envelopes[0]);
        manifest.step_envelopes_commitment = commit_phase30_step_envelope_list(&manifest.envelopes);

        let err = verify_phase30_decoding_step_proof_envelope_manifest(&manifest)
            .expect_err("source-chain drift should fail");
        assert!(
            err.to_string().contains("source_chain_commitment"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn phase30_step_envelope_list_commitment_binds_ordering() {
        let (_, manifest) = sample_phase30_chain_and_manifest();
        assert!(
            manifest.envelopes.len() >= 2,
            "fixture must provide at least two envelopes"
        );
        let mut swapped = manifest.envelopes.clone();
        swapped.swap(0, 1);

        assert_ne!(
            commit_phase30_step_envelope_list(&manifest.envelopes),
            commit_phase30_step_envelope_list(&swapped),
            "manifest list commitment must bind envelope order"
        );
    }

    #[test]
    fn phase30_step_envelope_commitment_length_prefixes_variable_fields() {
        let layout = phase12_default_decoding_layout();
        let memories = phase12_demo_initial_memories(&layout).expect("memories");
        let proofs = memories
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let chain = phase12_prepare_decoding_chain(&layout, &proofs).expect("chain");
        let manifest =
            phase30_prepare_decoding_step_proof_envelope_manifest(&chain).expect("envelopes");
        let mut left = manifest.envelopes[0].clone();
        let mut right = left.clone();

        left.input_boundary_commitment = "ab".to_string();
        left.output_boundary_commitment = "c".to_string();
        right.input_boundary_commitment = "a".to_string();
        right.output_boundary_commitment = "bc".to_string();

        assert_ne!(
            commit_phase30_step_envelope(&left),
            commit_phase30_step_envelope(&right),
            "length framing must distinguish adjacent variable-field splits"
        );
    }

    #[test]
    fn phase30_step_envelope_manifest_rejects_tampered_start_boundary() {
        let (_, mut manifest) = sample_phase30_chain_and_manifest();
        manifest.chain_start_boundary_commitment = "tampered-start-boundary".to_string();

        let err = verify_phase30_decoding_step_proof_envelope_manifest(&manifest)
            .expect_err("start boundary drift should fail");
        assert!(
            err.to_string()
                .contains("start boundary does not match the first envelope"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn phase30_step_envelope_manifest_rejects_tampered_end_boundary() {
        let (_, mut manifest) = sample_phase30_chain_and_manifest();
        manifest.chain_end_boundary_commitment = "tampered-end-boundary".to_string();

        let err = verify_phase30_decoding_step_proof_envelope_manifest(&manifest)
            .expect_err("end boundary drift should fail");
        assert!(
            err.to_string()
                .contains("end boundary does not match the final envelope"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn phase30_step_envelope_manifest_rejects_step_envelope_list_commitment_drift() {
        let (_, mut manifest) = sample_phase30_chain_and_manifest();
        manifest.step_envelopes_commitment = "tampered-step-envelope-list".to_string();

        let err = verify_phase30_decoding_step_proof_envelope_manifest(&manifest)
            .expect_err("list commitment drift should fail");
        assert!(
            err.to_string()
                .contains("step_envelopes_commitment does not match its envelopes"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn phase30_step_envelope_manifest_rejects_step_index_drift() {
        let (_, mut manifest) = sample_phase30_chain_and_manifest();
        assert!(
            manifest.envelopes.len() >= 3,
            "fixture must provide a non-boundary envelope"
        );
        let idx = manifest.envelopes.len() / 2;
        manifest.envelopes[idx].step_index += 1;
        manifest.envelopes[idx].envelope_commitment =
            commit_phase30_step_envelope(&manifest.envelopes[idx]);
        manifest.step_envelopes_commitment = commit_phase30_step_envelope_list(&manifest.envelopes);

        let err = verify_phase30_decoding_step_proof_envelope_manifest(&manifest)
            .expect_err("step index drift should fail");
        assert!(
            err.to_string().contains("records step_index"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn phase30_step_envelope_manifest_rejects_tampered_chain_link() {
        let layout = phase12_default_decoding_layout();
        let memories = phase12_demo_initial_memories(&layout).expect("memories");
        let proofs = memories
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let chain = phase12_prepare_decoding_chain(&layout, &proofs).expect("chain");
        let mut manifest =
            phase30_prepare_decoding_step_proof_envelope_manifest(&chain).expect("envelopes");
        manifest.envelopes[0].output_boundary_commitment = "tampered".to_string();
        manifest.envelopes[0].envelope_commitment =
            commit_phase30_step_envelope(&manifest.envelopes[0]);
        manifest.step_envelopes_commitment = commit_phase30_step_envelope_list(&manifest.envelopes);

        let err = verify_phase30_decoding_step_proof_envelope_manifest(&manifest)
            .expect_err("tampered envelope link should fail");
        assert!(
            err.to_string()
                .contains("does not preserve the carried output/input boundary"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn phase30_step_envelope_manifest_against_chain_rejects_proof_commitment_drift() {
        let layout = phase12_default_decoding_layout();
        let memories = phase12_demo_initial_memories(&layout).expect("memories");
        let proofs = memories
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let chain = phase12_prepare_decoding_chain(&layout, &proofs).expect("chain");
        let mut manifest =
            phase30_prepare_decoding_step_proof_envelope_manifest(&chain).expect("envelopes");
        manifest.envelopes[0].proof_commitment = "tampered".to_string();
        manifest.envelopes[0].envelope_commitment =
            commit_phase30_step_envelope(&manifest.envelopes[0]);
        manifest.step_envelopes_commitment = commit_phase30_step_envelope_list(&manifest.envelopes);

        verify_phase30_decoding_step_proof_envelope_manifest(&manifest)
            .expect("standalone envelope remains internally well-formed");
        let err =
            verify_phase30_decoding_step_proof_envelope_manifest_against_chain(&manifest, &chain)
                .expect_err("chain binding should reject proof commitment drift");
        assert!(
            err.to_string()
                .contains("does not match the derived Phase 12 chain"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn phase12_standalone_state_derivation_rejects_non_seed_steps() {
        let layout = phase12_default_decoding_layout();
        let memory = phase12_demo_initial_memories(&layout)
            .expect("memories")
            .into_iter()
            .next()
            .expect("first memory");
        let program =
            decoding_step_v2_program_with_initial_memory(&layout, memory.clone()).expect("program");
        let err = derive_phase12_from_program_initial_state(&program, 1).unwrap_err();
        assert!(err.to_string().contains("only supports the seed step"));

        let err = derive_phase12_from_final_memory(&memory, 1, &layout).unwrap_err();
        assert!(err.to_string().contains("only supports the seed step"));
    }

    #[test]
    fn phase12_demo_initial_memories_support_multiple_layouts() {
        for layout in phase13_default_decoding_layout_matrix().expect("layout matrix") {
            let memories = phase12_demo_initial_memories(&layout).expect("memories");
            assert_eq!(memories.len(), 3);
            for memory in memories {
                assert_eq!(memory.len(), layout.memory_size().expect("memory size"));
            }
        }
    }

    #[test]
    fn phase12_demo_initial_memories_follow_lookup_backed_cache_progression() {
        for layout in phase13_default_decoding_layout_matrix().expect("layout matrix") {
            let kv_cache_range = layout.kv_cache_range().expect("kv cache range");
            let memories = phase12_demo_initial_memories(&layout).expect("memories");
            for pair in memories.windows(2) {
                let current = pair[0].clone();
                let next = &pair[1];
                let program = decoding_step_v2_program_with_initial_memory(&layout, current)
                    .expect("program");
                let step_limit = decoding_program_step_limit(&program).expect("step limit");
                let mut runtime =
                    NativeInterpreter::new(program, Attention2DMode::AverageHard, step_limit);
                let result = runtime.run().expect("run program");
                assert!(result.halted);
                assert_eq!(
                    &result.final_state.memory[kv_cache_range.clone()],
                    &next[kv_cache_range.clone()]
                );
            }
        }
    }

    #[test]
    fn phase13_verify_decoding_layout_matrix_accepts_linked_chains() {
        let layouts = phase13_default_decoding_layout_matrix().expect("layouts");
        let chains = layouts
            .iter()
            .map(|layout| {
                let proofs = phase12_demo_initial_memories(layout)
                    .expect("memories")
                    .into_iter()
                    .map(|memory| sample_phase12_step_proof(layout, memory))
                    .collect::<Vec<_>>();
                phase12_prepare_decoding_chain(layout, &proofs).expect("chain")
            })
            .collect::<Vec<_>>();
        let manifest = Phase13DecodingLayoutMatrixManifest {
            proof_backend: StarkProofBackend::Stwo,
            matrix_version: STWO_DECODING_LAYOUT_MATRIX_VERSION_PHASE13.to_string(),
            semantic_scope: STWO_DECODING_LAYOUT_MATRIX_SCOPE_PHASE13.to_string(),
            proof_backend_version: crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12.to_string(),
            statement_version: crate::proof::CLAIM_STATEMENT_VERSION_V1.to_string(),
            total_layouts: chains.len(),
            total_steps: chains.iter().map(|chain| chain.total_steps).sum(),
            chains,
        };
        verify_phase13_decoding_layout_matrix(&manifest).expect("matrix verification");
    }

    #[test]
    fn phase13_verify_decoding_layout_matrix_rejects_mismatched_totals() {
        let layout = phase12_default_decoding_layout();
        let proofs = phase12_demo_initial_memories(&layout)
            .expect("memories")
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let chain = phase12_prepare_decoding_chain(&layout, &proofs).expect("chain");
        let manifest = Phase13DecodingLayoutMatrixManifest {
            proof_backend: StarkProofBackend::Stwo,
            matrix_version: STWO_DECODING_LAYOUT_MATRIX_VERSION_PHASE13.to_string(),
            semantic_scope: STWO_DECODING_LAYOUT_MATRIX_SCOPE_PHASE13.to_string(),
            proof_backend_version: crate::stwo_backend::STWO_BACKEND_VERSION_PHASE12.to_string(),
            statement_version: crate::proof::CLAIM_STATEMENT_VERSION_V1.to_string(),
            total_layouts: 2,
            total_steps: chain.total_steps,
            chains: vec![chain],
        };
        let err = verify_phase13_decoding_layout_matrix(&manifest).unwrap_err();
        assert!(err
            .to_string()
            .contains("total_layouts=2 does not match chains.len()=1"));
    }

    #[test]
    fn phase14_prepare_decoding_chain_accepts_linked_steps() {
        let layout = phase12_default_decoding_layout();
        let proofs = phase12_demo_initial_memories(&layout)
            .expect("memories")
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let phase12 = phase12_prepare_decoding_chain(&layout, &proofs).expect("chain");
        let manifest = phase14_prepare_decoding_chain(&phase12).expect("phase14 manifest");
        assert_eq!(manifest.total_steps, 3);
        assert_eq!(manifest.history_chunk_pairs, PHASE14_HISTORY_CHUNK_PAIRS);
        assert_eq!(manifest.steps[0].from_state.kv_history_sealed_chunks, 2);
        assert_eq!(manifest.steps[0].from_state.kv_history_open_chunk_pairs, 0);
        assert_eq!(
            manifest.steps[0].from_state.kv_history_frontier_pairs,
            layout.rolling_kv_pairs
        );
        assert_eq!(
            manifest.steps[0].from_state.kv_history_frontier_commitment,
            manifest.steps[0].from_state.kv_cache_commitment
        );
        assert_eq!(manifest.steps[0].from_state.lookup_transcript_entries, 1);
        assert_eq!(manifest.steps[0].from_state.lookup_frontier_entries, 1);
        assert_eq!(manifest.steps[2].to_state.kv_history_length, 7);
        assert_eq!(manifest.steps[2].to_state.kv_history_sealed_chunks, 3);
        assert_eq!(manifest.steps[2].to_state.kv_history_open_chunk_pairs, 1);
        assert_eq!(
            manifest.steps[2].to_state.kv_history_frontier_pairs,
            layout.rolling_kv_pairs
        );
        assert_eq!(
            manifest.steps[2].to_state.kv_history_frontier_commitment,
            manifest.steps[2].to_state.kv_cache_commitment
        );
        assert_eq!(manifest.steps[2].to_state.lookup_transcript_entries, 4);
        assert_eq!(
            manifest.steps[2].to_state.lookup_frontier_entries,
            PHASE14_HISTORY_CHUNK_PAIRS
        );
        assert_eq!(
            manifest.steps[0].to_state.public_state_commitment,
            manifest.steps[1].from_state.public_state_commitment
        );
        verify_phase14_decoding_chain(&manifest).expect("phase14 verification");
    }

    #[test]
    fn phase14_prepare_decoding_chain_preserves_statement_version() {
        let layout = phase12_default_decoding_layout();
        let proofs = phase12_demo_initial_memories(&layout)
            .expect("memories")
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let phase12 = phase12_prepare_decoding_chain(&layout, &proofs).expect("chain");
        let manifest = phase14_prepare_decoding_chain(&phase12).expect("phase14 manifest");
        assert_eq!(manifest.statement_version, phase12.statement_version);
    }

    #[test]
    fn phase14_prepare_decoding_chain_rejects_unsupported_statement_version() {
        let layout = phase12_default_decoding_layout();
        let proofs = phase12_demo_initial_memories(&layout)
            .expect("memories")
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let mut phase12 = phase12_prepare_decoding_chain(&layout, &proofs).expect("chain");
        phase12.statement_version = "claim-v2".to_string();
        for step in &mut phase12.steps {
            step.proof.claim.statement_version = "claim-v2".to_string();
        }

        let err = phase14_prepare_decoding_chain(&phase12).unwrap_err();
        assert!(err
            .to_string()
            .contains("unsupported chunked decoding statement version `claim-v2`"));
    }

    #[test]
    fn phase14_verify_decoding_chain_rejects_statement_version_drift() {
        let layout = phase12_default_decoding_layout();
        let proofs = phase12_demo_initial_memories(&layout)
            .expect("memories")
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let phase12 = phase12_prepare_decoding_chain(&layout, &proofs).expect("chain");
        let mut manifest = phase14_prepare_decoding_chain(&phase12).expect("phase14 manifest");
        manifest.steps[0].proof.claim.statement_version = "claim-v2".to_string();
        let err = verify_phase14_decoding_chain(&manifest).unwrap_err();
        assert!(err
            .to_string()
            .contains("statement version `claim-v2` does not match manifest"));
    }

    #[test]
    fn phase14_verify_decoding_chain_rejects_broken_open_chunk_link() {
        let layout = phase12_default_decoding_layout();
        let proofs = phase12_demo_initial_memories(&layout)
            .expect("memories")
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let phase12 = phase12_prepare_decoding_chain(&layout, &proofs).expect("chain");
        let mut manifest = phase14_prepare_decoding_chain(&phase12).expect("phase14 manifest");
        manifest.steps[1]
            .from_state
            .kv_history_open_chunk_commitment = "broken".to_string();
        let err = verify_phase14_decoding_chain(&manifest).unwrap_err();
        assert!(err
            .to_string()
            .contains("recorded from_state does not match the proof's initial state"));
    }

    #[test]
    fn phase14_verify_decoding_chain_rejects_wrong_chunk_size() {
        let layout = phase12_default_decoding_layout();
        let proofs = phase12_demo_initial_memories(&layout)
            .expect("memories")
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let phase12 = phase12_prepare_decoding_chain(&layout, &proofs).expect("chain");
        let mut manifest = phase14_prepare_decoding_chain(&phase12).expect("phase14 manifest");
        manifest.history_chunk_pairs = 4;
        let err = verify_phase14_decoding_chain(&manifest).unwrap_err();
        assert!(err
            .to_string()
            .contains("unsupported chunked decoding history_chunk_pairs=4"));
    }

    #[test]
    fn phase14_verify_decoding_chain_rejects_tampered_public_state_commitment() {
        let layout = phase12_default_decoding_layout();
        let proofs = phase12_demo_initial_memories(&layout)
            .expect("memories")
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let phase12 = phase12_prepare_decoding_chain(&layout, &proofs).expect("chain");
        let mut manifest = phase14_prepare_decoding_chain(&phase12).expect("phase14 manifest");
        manifest.steps[1].from_state.public_state_commitment = "broken".to_string();
        let err = verify_phase14_decoding_chain(&manifest).unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("from_state public_state_commitment does not match")
                || message.contains("recorded from_state does not match the proof's initial state"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn phase14_verify_decoding_chain_rejects_too_many_steps() {
        let layout = phase12_default_decoding_layout();
        let proofs = phase12_demo_initial_memories(&layout)
            .expect("memories")
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let phase12 = phase12_prepare_decoding_chain(&layout, &proofs).expect("chain");
        let mut manifest = phase14_prepare_decoding_chain(&phase12).expect("phase14 manifest");
        let template_step = manifest.steps[0].clone();
        manifest.steps = vec![template_step; MAX_DECODING_CHAIN_STEPS + 1];
        manifest.total_steps = manifest.steps.len();
        let err = verify_phase14_decoding_chain(&manifest).unwrap_err();
        assert!(err.to_string().contains("exceeding the limit"));
    }

    #[test]
    fn phase14_verify_decoding_chain_rejects_too_many_shared_lookup_artifacts() {
        let layout = phase12_default_decoding_layout();
        let proofs = phase12_demo_initial_memories(&layout)
            .expect("memories")
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let phase12 = phase12_prepare_decoding_chain(&layout, &proofs).expect("chain");
        let mut manifest = phase14_prepare_decoding_chain(&phase12).expect("phase14 manifest");
        let template_step = manifest.steps[0].clone();
        manifest.steps = vec![template_step; MAX_DECODING_SHARED_LOOKUP_ARTIFACTS];
        manifest.total_steps = manifest.steps.len();
        let template = manifest.shared_lookup_artifacts[0].clone();
        while manifest.shared_lookup_artifacts.len() <= MAX_DECODING_SHARED_LOOKUP_ARTIFACTS {
            let mut extra = template.clone();
            extra
                .artifact_commitment
                .push_str(&format!("-{}", manifest.shared_lookup_artifacts.len()));
            manifest.shared_lookup_artifacts.push(extra);
        }
        let err = verify_phase14_decoding_chain(&manifest).unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("shared lookup artifacts, exceeding the limit")
                || message.contains("shared lookup artifact")
                || message.contains("appears more than once"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn phase14_verify_decoding_chain_rejects_broken_frontier_cache_link() {
        let layout = phase12_default_decoding_layout();
        let proofs = phase12_demo_initial_memories(&layout)
            .expect("memories")
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let phase12 = phase12_prepare_decoding_chain(&layout, &proofs).expect("chain");
        let mut manifest = phase14_prepare_decoding_chain(&phase12).expect("phase14 manifest");
        manifest.steps[1].from_state.kv_history_frontier_commitment = "broken".to_string();
        let err = verify_phase14_decoding_chain(&manifest).unwrap_err();
        assert!(err
            .to_string()
            .contains("recorded from_state does not match the proof's initial state"));
    }

    #[test]
    fn phase14_verify_decoding_chain_rejects_broken_lookup_transcript_link() {
        let layout = phase12_default_decoding_layout();
        let proofs = phase12_demo_initial_memories(&layout)
            .expect("memories")
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let phase12 = phase12_prepare_decoding_chain(&layout, &proofs).expect("chain");
        let mut manifest = phase14_prepare_decoding_chain(&phase12).expect("phase14 manifest");
        manifest.steps[1].from_state.lookup_transcript_commitment = "broken".to_string();
        let err = verify_phase14_decoding_chain(&manifest).unwrap_err();
        assert!(err
            .to_string()
            .contains("recorded from_state does not match the proof's initial state"));
    }

    #[test]
    fn phase14_verify_decoding_chain_rejects_broken_lookup_frontier_link() {
        let layout = phase12_default_decoding_layout();
        let proofs = phase12_demo_initial_memories(&layout)
            .expect("memories")
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let phase12 = phase12_prepare_decoding_chain(&layout, &proofs).expect("chain");
        let mut manifest = phase14_prepare_decoding_chain(&phase12).expect("phase14 manifest");
        manifest.steps[1].from_state.lookup_frontier_commitment = "broken".to_string();
        let err = verify_phase14_decoding_chain(&manifest).unwrap_err();
        assert!(err
            .to_string()
            .contains("recorded from_state does not match the proof's initial state"));
    }

    #[test]
    fn phase15_prepare_segment_bundle_accepts_chunked_history_chain() {
        let layout = phase12_default_decoding_layout();
        let proofs = phase12_demo_initial_memories(&layout)
            .expect("memories")
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let phase12 = phase12_prepare_decoding_chain(&layout, &proofs).expect("chain");
        let phase14 = phase14_prepare_decoding_chain(&phase12).expect("phase14 manifest");
        let manifest =
            phase15_prepare_segment_bundle(&phase14, phase15_default_segment_step_limit())
                .expect("phase15 manifest");
        assert_eq!(manifest.total_segments, 2);
        assert_eq!(manifest.total_steps, 3);
        assert_eq!(manifest.max_segment_steps, 2);
        assert_eq!(manifest.segments[0].global_start_step_index, 0);
        assert_eq!(manifest.segments[1].global_start_step_index, 2);
        assert_eq!(manifest.segments[0].chain.total_steps, 2);
        assert_eq!(manifest.segments[1].chain.total_steps, 1);
        verify_phase15_decoding_segment_bundle(&manifest).expect("phase15 verification");
    }

    #[test]
    fn phase15_verify_segment_bundle_rejects_wrong_segment_start() {
        let layout = phase12_default_decoding_layout();
        let proofs = phase12_demo_initial_memories(&layout)
            .expect("memories")
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let phase12 = phase12_prepare_decoding_chain(&layout, &proofs).expect("chain");
        let phase14 = phase14_prepare_decoding_chain(&phase12).expect("phase14 manifest");
        let mut manifest =
            phase15_prepare_segment_bundle(&phase14, phase15_default_segment_step_limit())
                .expect("phase15 manifest");
        manifest.segments[1].global_start_step_index = 99;
        let err = verify_phase15_decoding_segment_bundle(&manifest).unwrap_err();
        assert!(err
            .to_string()
            .contains("starts at global step 99 instead of 2"));
    }

    #[test]
    fn phase15_verify_segment_bundle_rejects_tampered_global_boundary_state() {
        let layout = phase12_default_decoding_layout();
        let proofs = phase12_demo_initial_memories(&layout)
            .expect("memories")
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let phase12 = phase12_prepare_decoding_chain(&layout, &proofs).expect("chain");
        let phase14 = phase14_prepare_decoding_chain(&phase12).expect("phase14 manifest");
        let mut manifest =
            phase15_prepare_segment_bundle(&phase14, phase15_default_segment_step_limit())
                .expect("phase15 manifest");
        manifest.segments[1].global_from_state.kv_history_commitment = "tampered".to_string();
        let err = verify_phase15_decoding_segment_bundle(&manifest).unwrap_err();
        assert!(err
            .to_string()
            .contains("global_from_state does not match the carried-state replay"));
    }

    #[test]
    fn phase15_verify_segment_bundle_rejects_tampered_public_state_boundary_commitment() {
        let layout = phase12_default_decoding_layout();
        let proofs = phase12_demo_initial_memories(&layout)
            .expect("memories")
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let phase12 = phase12_prepare_decoding_chain(&layout, &proofs).expect("chain");
        let phase14 = phase14_prepare_decoding_chain(&phase12).expect("phase14 manifest");
        let mut manifest =
            phase15_prepare_segment_bundle(&phase14, phase15_default_segment_step_limit())
                .expect("phase15 manifest");
        manifest.segments[0].public_state_boundary_commitment = "tampered".to_string();
        let err = verify_phase15_decoding_segment_bundle(&manifest).unwrap_err();
        assert!(err.to_string().contains("public_state_boundary_commitment"));
    }

    #[test]
    fn phase16_prepare_segment_rollup_accepts_segment_bundle() {
        let layout = phase12_default_decoding_layout();
        let proofs = phase12_demo_initial_memories(&layout)
            .expect("memories")
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let phase12 = phase12_prepare_decoding_chain(&layout, &proofs).expect("chain");
        let phase14 = phase14_prepare_decoding_chain(&phase12).expect("phase14 manifest");
        let phase15 = phase15_prepare_segment_bundle(&phase14, 1).expect("phase15 manifest");
        let manifest =
            phase16_prepare_segment_rollup(&phase15, phase16_default_rollup_segment_limit())
                .expect("phase16 manifest");
        assert_eq!(manifest.total_rollups, 2);
        assert_eq!(manifest.total_segments, 3);
        assert_eq!(manifest.total_steps, 3);
        assert_eq!(manifest.rollups[0].global_start_step_index, 0);
        assert_eq!(manifest.rollups[1].global_start_step_index, 2);
        assert_eq!(manifest.rollups[0].total_segments, 2);
        assert_eq!(manifest.rollups[1].total_segments, 1);
        verify_phase16_decoding_segment_rollup(&manifest).expect("phase16 verification");
    }

    #[test]
    fn phase16_verify_segment_rollup_rejects_wrong_rollup_start() {
        let layout = phase12_default_decoding_layout();
        let proofs = phase12_demo_initial_memories(&layout)
            .expect("memories")
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let phase12 = phase12_prepare_decoding_chain(&layout, &proofs).expect("chain");
        let phase14 = phase14_prepare_decoding_chain(&phase12).expect("phase14 manifest");
        let phase15 = phase15_prepare_segment_bundle(&phase14, 1).expect("phase15 manifest");
        let mut manifest =
            phase16_prepare_segment_rollup(&phase15, phase16_default_rollup_segment_limit())
                .expect("phase16 manifest");
        manifest.rollups[1].global_start_step_index = 99;
        let err = verify_phase16_decoding_segment_rollup(&manifest).unwrap_err();
        assert!(err
            .to_string()
            .contains("starts at global step 99 instead of 2"));
    }

    #[test]
    fn phase16_verify_segment_rollup_rejects_tampered_rollup_boundary_state() {
        let layout = phase12_default_decoding_layout();
        let proofs = phase12_demo_initial_memories(&layout)
            .expect("memories")
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let phase12 = phase12_prepare_decoding_chain(&layout, &proofs).expect("chain");
        let phase14 = phase14_prepare_decoding_chain(&phase12).expect("phase14 manifest");
        let phase15 = phase15_prepare_segment_bundle(&phase14, 1).expect("phase15 manifest");
        let mut manifest =
            phase16_prepare_segment_rollup(&phase15, phase16_default_rollup_segment_limit())
                .expect("phase16 manifest");
        manifest.rollups[1].global_from_state.kv_history_commitment = "tampered".to_string();
        let err = verify_phase16_decoding_segment_rollup(&manifest).unwrap_err();
        assert!(err
            .to_string()
            .contains("global_from_state does not match the first segment boundary"));
    }

    #[test]
    fn phase16_verify_segment_rollup_rejects_tampered_public_state_boundary_commitment() {
        let layout = phase12_default_decoding_layout();
        let proofs = phase12_demo_initial_memories(&layout)
            .expect("memories")
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let phase12 = phase12_prepare_decoding_chain(&layout, &proofs).expect("chain");
        let phase14 = phase14_prepare_decoding_chain(&phase12).expect("phase14 manifest");
        let phase15 = phase15_prepare_segment_bundle(&phase14, 1).expect("phase15 manifest");
        let mut manifest =
            phase16_prepare_segment_rollup(&phase15, phase16_default_rollup_segment_limit())
                .expect("phase16 manifest");
        manifest.rollups[0].public_state_boundary_commitment = "tampered".to_string();
        let err = verify_phase16_decoding_segment_rollup(&manifest).unwrap_err();
        assert!(err.to_string().contains("public_state_boundary_commitment"));
    }

    #[test]
    fn phase17_rollup_matrix_accepts_multiple_layouts() {
        let manifest = sample_phase17_rollup_matrix_manifest();
        assert_eq!(manifest.total_layouts, 3);
        assert_eq!(manifest.rollups.len(), 3);
        assert!(manifest.total_rollups >= 3);
        assert!(manifest.total_segments >= 3);
        assert!(manifest.total_steps >= 3);
        verify_phase17_decoding_rollup_matrix(&manifest).expect("phase17 verification");
    }

    #[test]
    fn phase17_rollup_matrix_rejects_tampered_total_rollups() {
        let mut manifest = sample_phase17_rollup_matrix_manifest();
        manifest.total_rollups = 99;
        let err = verify_phase17_decoding_rollup_matrix(&manifest).unwrap_err();
        assert!(err
            .to_string()
            .contains("total_rollups=99 does not match derived total_rollups"));
    }

    #[test]
    fn phase17_rollup_matrix_rejects_tampered_public_state_boundary_commitment() {
        let mut manifest = sample_phase17_rollup_matrix_manifest();
        manifest.public_state_boundary_commitment = "tampered".to_string();
        let err = verify_phase17_decoding_rollup_matrix(&manifest).unwrap_err();
        assert!(err.to_string().contains("public_state_boundary_commitment"));
    }

    #[test]
    fn phase17_oracle_matches_production_public_state_boundary_commitment() {
        let manifest = sample_phase17_rollup_matrix_manifest();
        verify_phase17_decoding_rollup_matrix(&manifest).expect("production verifier");
        let oracle_commitment =
            oracle_commit_phase17_matrix_public_state_boundary(&manifest).expect("oracle");
        assert_eq!(manifest.public_state_boundary_commitment, oracle_commitment);
    }

    #[test]
    fn phase17_oracle_and_production_reject_same_public_state_boundary_tamper() {
        let mut manifest = sample_phase17_rollup_matrix_manifest();
        manifest.public_state_boundary_commitment = "tampered".to_string();
        assert!(verify_phase17_decoding_rollup_matrix(&manifest).is_err());
        let oracle_commitment =
            oracle_commit_phase17_matrix_public_state_boundary(&manifest).expect("oracle");
        assert_ne!(manifest.public_state_boundary_commitment, oracle_commitment);
    }

    #[test]
    fn phase17_oracle_matches_production_on_demo_matrix() {
        let manifest = sample_phase17_rollup_matrix_manifest();
        verify_phase17_decoding_rollup_matrix(&manifest).expect("production verifier");
        let oracle_commitment =
            oracle_commit_phase17_matrix_public_state_boundary(&manifest).expect("oracle");
        assert_eq!(manifest.public_state_boundary_commitment, oracle_commitment);
    }

    #[test]
    fn phase17_oracle_and_production_reject_same_layout_order_tamper() {
        let mut manifest = sample_phase17_rollup_matrix_manifest();
        assert!(
            manifest.rollups.len() >= 2,
            "sample_phase17_rollup_matrix_manifest must include at least two layouts"
        );
        manifest.rollups.swap(0, 1);
        assert!(verify_phase17_decoding_rollup_matrix(&manifest).is_err());
        let oracle_commitment =
            oracle_commit_phase17_matrix_public_state_boundary(&manifest).expect("oracle");
        assert_ne!(manifest.public_state_boundary_commitment, oracle_commitment);
    }

    #[test]
    fn phase17_oracle_and_production_reject_same_nested_rollup_boundary_tamper() {
        let mut manifest = sample_phase17_rollup_matrix_manifest();
        let first_layout = manifest
            .rollups
            .get_mut(0)
            .expect("sample_phase17_rollup_matrix_manifest must include at least one layout");
        let first_rollup = first_layout.rollups.get_mut(0).expect(
            "sample_phase17_rollup_matrix_manifest layouts must include at least one rollup",
        );
        first_rollup.public_state_boundary_commitment = "tampered".to_string();

        // First assert the matrix-level boundary check catches the nested tamper.
        assert!(verify_phase17_decoding_rollup_matrix(&manifest).is_err());
        let oracle_commitment_before =
            oracle_commit_phase17_matrix_public_state_boundary(&manifest).expect("oracle");
        assert_ne!(
            manifest.public_state_boundary_commitment,
            oracle_commitment_before
        );

        // Then recompute the matrix boundary and assert nested phase16 verification still fails.
        manifest.public_state_boundary_commitment = oracle_commitment_before;
        assert!(verify_phase17_decoding_rollup_matrix(&manifest).is_err());
        let oracle_commitment_after =
            oracle_commit_phase17_matrix_public_state_boundary(&manifest).expect("oracle");
        assert_eq!(
            manifest.public_state_boundary_commitment,
            oracle_commitment_after
        );
    }

    #[test]
    fn phase21_matrix_accumulator_accepts_shared_template_matrices() {
        let manifest = sample_phase21_matrix_accumulator_manifest();
        assert_eq!(manifest.total_matrices, 2);
        assert!(manifest.total_layouts >= 2);
        assert!(manifest.total_rollups >= 2);
        assert!(manifest.total_segments >= 2);
        assert!(manifest.total_steps >= 2);
        verify_phase21_decoding_matrix_accumulator(&manifest).expect("phase21 verification");
    }

    #[test]
    fn phase21_matrix_accumulator_rejects_tampered_template_commitment() {
        let mut manifest = sample_phase21_matrix_accumulator_manifest();
        manifest.template_commitment = "tampered".to_string();
        let err = verify_phase21_decoding_matrix_accumulator(&manifest).unwrap_err();
        assert!(err
            .to_string()
            .contains("template_commitment does not match the computed template commitment"));
    }

    #[test]
    fn phase21_matrix_accumulator_rejects_tampered_accumulator_commitment() {
        let mut manifest = sample_phase21_matrix_accumulator_manifest();
        manifest.accumulator_commitment = "tampered".to_string();
        let err = verify_phase21_decoding_matrix_accumulator(&manifest).unwrap_err();
        assert!(err
            .to_string()
            .contains("accumulator_commitment does not match the computed accumulator commitment"));
    }

    #[test]
    fn phase21_prepare_rejects_layout_template_mismatch() {
        let first = sample_phase17_rollup_matrix_manifest();
        let mut second = sample_phase17_rollup_matrix_manifest();
        second.rollups.pop().expect("at least one layout");
        second.total_layouts = second.rollups.len();
        second.total_rollups = second
            .rollups
            .iter()
            .map(|rollup| rollup.total_rollups)
            .sum();
        second.total_segments = second
            .rollups
            .iter()
            .map(|rollup| rollup.total_segments)
            .sum();
        second.total_steps = second.rollups.iter().map(|rollup| rollup.total_steps).sum();
        second.public_state_boundary_commitment =
            commit_phase17_matrix_public_state_boundary(&second).expect("phase17 boundary");
        verify_phase17_decoding_rollup_matrix(&second).expect("phase17 verification");

        let err = phase21_prepare_decoding_matrix_accumulator(&[first, second]).unwrap_err();
        assert!(err.to_string().contains("shared template commitment"));
    }

    #[test]
    fn phase21_oracle_matches_production_commitments() {
        let manifest = sample_phase21_matrix_accumulator_manifest();
        verify_phase21_decoding_matrix_accumulator(&manifest).expect("production verifier");
        let oracle_template =
            oracle_commit_phase21_matrix_template(&manifest.matrices[0]).expect("oracle template");
        let oracle_accumulator =
            oracle_commit_phase21_matrix_accumulator(&manifest).expect("oracle accumulator");
        assert_eq!(manifest.template_commitment, oracle_template);
        assert_eq!(manifest.accumulator_commitment, oracle_accumulator);
    }

    #[test]
    fn phase21_oracle_and_production_reject_same_accumulator_tamper() {
        let mut manifest = sample_phase21_matrix_accumulator_manifest();
        manifest.accumulator_commitment = "tampered".to_string();
        assert!(verify_phase21_decoding_matrix_accumulator(&manifest).is_err());
        let oracle_accumulator =
            oracle_commit_phase21_matrix_accumulator(&manifest).expect("oracle accumulator");
        assert_ne!(manifest.accumulator_commitment, oracle_accumulator);
    }

    #[test]
    fn phase22_lookup_accumulator_accepts_phase21_source_accumulator() {
        let manifest = sample_phase22_lookup_accumulator_manifest();
        assert_eq!(manifest.total_matrices, 2);
        assert!(manifest.total_layouts >= 2);
        assert!(manifest.total_rollups >= 2);
        assert!(manifest.total_segments >= 2);
        assert!(manifest.total_steps >= 2);
        assert_eq!(manifest.lookup_delta_entries, manifest.total_steps);
        verify_phase22_decoding_lookup_accumulator(&manifest).expect("phase22 verification");
    }

    #[test]
    fn phase22_lookup_accumulator_rejects_tampered_lookup_template_commitment() {
        let mut manifest = sample_phase22_lookup_accumulator_manifest();
        manifest.lookup_template_commitment = "tampered".to_string();
        let err = verify_phase22_decoding_lookup_accumulator(&manifest).unwrap_err();
        assert!(err.to_string().contains(
            "lookup_template_commitment does not match the computed lookup template commitment"
        ));
    }

    #[test]
    fn phase22_lookup_accumulator_rejects_tampered_lookup_accumulator_commitment() {
        let mut manifest = sample_phase22_lookup_accumulator_manifest();
        manifest.lookup_accumulator_commitment = "tampered".to_string();
        let err = verify_phase22_decoding_lookup_accumulator(&manifest).unwrap_err();
        assert!(err
            .to_string()
            .contains("lookup_accumulator_commitment does not match the computed lookup accumulator commitment"));
    }

    #[test]
    fn phase22_lookup_accumulator_rejects_tampered_lookup_delta_entries() {
        let mut manifest = sample_phase22_lookup_accumulator_manifest();
        manifest.lookup_delta_entries = manifest.lookup_delta_entries.saturating_add(1);
        let err = verify_phase22_decoding_lookup_accumulator(&manifest).unwrap_err();
        assert!(err.to_string().contains("lookup_delta_entries="));
        assert!(err
            .to_string()
            .contains("does not match derived lookup_delta_entries"));
    }

    #[test]
    fn phase22_lookup_accumulator_rejects_tampered_max_lookup_frontier_entries() {
        let mut manifest = sample_phase22_lookup_accumulator_manifest();
        manifest.max_lookup_frontier_entries =
            manifest.max_lookup_frontier_entries.saturating_add(1);
        let err = verify_phase22_decoding_lookup_accumulator(&manifest).unwrap_err();
        assert!(err.to_string().contains("max_lookup_frontier_entries="));
        assert!(err
            .to_string()
            .contains("does not match derived max_lookup_frontier_entries"));
    }

    #[test]
    fn phase22_lookup_accumulator_rejects_tampered_source_template_commitment() {
        let mut manifest = sample_phase22_lookup_accumulator_manifest();
        manifest.source_template_commitment = "tampered".to_string();
        let err = verify_phase22_decoding_lookup_accumulator(&manifest).unwrap_err();
        assert!(err
            .to_string()
            .contains("source_template_commitment does not match the nested Phase 21 accumulator"));
    }

    #[test]
    fn phase22_lookup_accumulator_rejects_tampered_source_accumulator_commitment() {
        let mut manifest = sample_phase22_lookup_accumulator_manifest();
        manifest.source_accumulator_commitment = "tampered".to_string();
        let err = verify_phase22_decoding_lookup_accumulator(&manifest).unwrap_err();
        assert!(err.to_string().contains(
            "source_accumulator_commitment does not match the nested Phase 21 accumulator"
        ));
    }

    #[test]
    fn phase22_oracle_matches_production_commitments() {
        let manifest = sample_phase22_lookup_accumulator_manifest();
        verify_phase22_decoding_lookup_accumulator(&manifest).expect("production verifier");
        let oracle_template =
            oracle_commit_phase22_lookup_template(&manifest.accumulator).expect("oracle template");
        let oracle_accumulator =
            oracle_commit_phase22_lookup_accumulator(&manifest).expect("oracle accumulator");
        assert_eq!(manifest.lookup_template_commitment, oracle_template);
        assert_eq!(manifest.lookup_accumulator_commitment, oracle_accumulator);
    }

    #[test]
    fn phase22_oracle_and_production_reject_same_lookup_accumulator_tamper() {
        let mut manifest = sample_phase22_lookup_accumulator_manifest();
        manifest.lookup_accumulator_commitment = "tampered".to_string();
        assert!(verify_phase22_decoding_lookup_accumulator(&manifest).is_err());
        let oracle_accumulator =
            oracle_commit_phase22_lookup_accumulator(&manifest).expect("oracle accumulator");
        assert_ne!(manifest.lookup_accumulator_commitment, oracle_accumulator);
    }

    #[test]
    fn phase23_cross_step_lookup_accumulator_accepts_contiguous_members() {
        let manifest = sample_phase23_cross_step_lookup_accumulator_manifest();
        assert_eq!(manifest.member_count, 2);
        assert!(manifest.total_matrices >= 1);
        assert!(manifest.total_layouts >= 1);
        assert!(manifest.total_rollups >= 1);
        assert!(manifest.total_segments >= 1);
        assert!(manifest.total_steps >= 2);
        assert_eq!(
            manifest.total_steps,
            manifest.members.last().expect("phase23 member").total_steps
        );
        verify_phase23_decoding_cross_step_lookup_accumulator(&manifest)
            .expect("phase23 verification");
    }

    #[test]
    fn phase23_cross_step_lookup_accumulator_accepts_prefix_inside_multi_step_segment() {
        let layout = phase12_default_decoding_layout();
        let phase12 = prove_phase12_decoding_demo_for_layout(&layout).expect("phase12 demo");
        let proofs = phase12
            .steps
            .iter()
            .map(|step| step.proof.clone())
            .collect::<Vec<_>>();
        assert!(
            proofs.len() >= 3,
            "phase23 regression needs at least 3 proofs"
        );

        let first_member =
            phase23_prepare_member_from_proof_window_with_segment_limit(&layout, &proofs[..1], 2)
                .expect("first phase23 member");
        let second_member =
            phase23_prepare_member_from_proof_window_with_segment_limit(&layout, &proofs[..3], 2)
                .expect("second phase23 member");

        assert_eq!(first_member.total_steps, 1);
        assert_eq!(second_member.total_steps, 3);
        assert_eq!(
            second_member.accumulator.matrices[0].rollups[0].rollups[0].segments[0].total_steps,
            2
        );

        let manifest =
            phase23_prepare_decoding_cross_step_lookup_accumulator(&[first_member, second_member])
                .expect("phase23 manifest");
        verify_phase23_decoding_cross_step_lookup_accumulator(&manifest)
            .expect("phase23 verification across interior segment boundary");
    }

    #[test]
    fn phase23_cross_step_lookup_accumulator_rejects_tampered_accumulator_commitment() {
        let mut manifest = sample_phase23_cross_step_lookup_accumulator_manifest();
        manifest.accumulator_commitment = "tampered".to_string();
        let err = verify_phase23_decoding_cross_step_lookup_accumulator(&manifest).unwrap_err();
        assert!(err
            .to_string()
            .contains("accumulator_commitment does not match the computed accumulator commitment"));
    }

    #[test]
    fn phase23_cross_step_lookup_accumulator_rejects_tampered_start_boundary_commitment() {
        let mut manifest = sample_phase23_cross_step_lookup_accumulator_manifest();
        manifest.start_boundary_commitment = "tampered".to_string();
        let err = verify_phase23_decoding_cross_step_lookup_accumulator(&manifest).unwrap_err();
        assert!(err
            .to_string()
            .contains("start_boundary_commitment does not match the first member boundary"));
    }

    #[test]
    fn phase23_cross_step_lookup_accumulator_rejects_tampered_end_boundary_commitment() {
        let mut manifest = sample_phase23_cross_step_lookup_accumulator_manifest();
        manifest.end_boundary_commitment = "tampered".to_string();
        let err = verify_phase23_decoding_cross_step_lookup_accumulator(&manifest).unwrap_err();
        assert!(err
            .to_string()
            .contains("end_boundary_commitment does not match the last member boundary"));
    }

    #[test]
    fn phase23_cross_step_lookup_accumulator_rejects_tampered_lookup_delta_entries() {
        let mut manifest = sample_phase23_cross_step_lookup_accumulator_manifest();
        manifest.lookup_delta_entries = manifest.lookup_delta_entries.saturating_add(1);
        let err = verify_phase23_decoding_cross_step_lookup_accumulator(&manifest).unwrap_err();
        assert!(err.to_string().contains("lookup_delta_entries="));
        assert!(err
            .to_string()
            .contains("does not match derived lookup_delta_entries"));
    }

    #[test]
    fn phase23_cross_step_lookup_accumulator_rejects_member_with_different_start_boundary() {
        let layout = phase12_default_decoding_layout();
        let phase12 = prove_phase12_decoding_demo_for_layout(&layout).expect("phase12 demo");
        let proofs = phase12
            .steps
            .iter()
            .map(|step| step.proof.clone())
            .collect::<Vec<_>>();
        assert!(
            proofs.len() >= 3,
            "phase23 regression needs at least 3 proofs"
        );

        let first_member =
            phase23_prepare_member_from_proof_window_with_segment_limit(&layout, &proofs[..1], 2)
                .expect("first phase23 member");
        let shifted_member =
            phase23_prepare_member_from_proof_window_with_segment_limit(&layout, &proofs[1..3], 2)
                .expect("shifted phase23 member");

        let err =
            phase23_prepare_decoding_cross_step_lookup_accumulator(&[first_member, shifted_member])
                .unwrap_err();
        assert!(err
            .to_string()
            .contains("does not share the starting decode-state boundary commitment of member 0"));
    }

    #[test]
    fn phase23_cross_step_lookup_accumulator_rejects_non_contiguous_member_boundary() {
        let mut manifest = sample_phase23_cross_step_lookup_accumulator_manifest();
        manifest.members[1].accumulator.matrices[0].rollups[0].rollups[0]
            .global_from_state
            .lookup_transcript_entries = manifest.members[1].accumulator.matrices[0].rollups[0]
            .rollups[0]
            .global_from_state
            .lookup_transcript_entries
            .saturating_add(1);
        manifest.members[1].accumulator.matrices[0].rollups[0].rollups[0]
            .global_from_state
            .public_state_commitment = commit_phase14_public_state(
            &manifest.members[1].accumulator.matrices[0].rollups[0].rollups[0].global_from_state,
        );
        let err = verify_phase23_decoding_cross_step_lookup_accumulator(&manifest).unwrap_err();
        assert!(
            err.to_string()
                .contains("member 1 failed Phase 22 verification")
                || err.to_string().contains("member boundary 0 -> 1 failed")
        );
    }

    #[test]
    fn phase23_cross_step_lookup_accumulator_rejects_tampered_lookup_template_commitment() {
        let mut manifest = sample_phase23_cross_step_lookup_accumulator_manifest();
        manifest.lookup_template_commitment = "tampered".to_string();
        let err = verify_phase23_decoding_cross_step_lookup_accumulator(&manifest).unwrap_err();
        assert!(err.to_string().contains(
            "lookup_template_commitment does not match the computed member lookup template commitment"
        ));
    }

    #[test]
    fn phase23_cross_step_lookup_accumulator_rejects_oversized_manifest_before_nested_checks() {
        let seed = sample_phase23_cross_step_lookup_accumulator_manifest();
        let mut manifest = seed.clone();
        manifest.members = vec![seed.members[0].clone(); MAX_PHASE23_ACCUMULATOR_MEMBERS + 1];
        manifest.member_count = manifest.members.len();
        manifest.members[0].accumulator.matrices.clear();

        let err = verify_phase23_decoding_cross_step_lookup_accumulator(&manifest).unwrap_err();
        assert!(err.to_string().contains("members.len()="));
        assert!(err.to_string().contains("exceeds the supported maximum"));
    }

    #[test]
    fn phase23_cross_step_lookup_accumulator_rejects_header_mismatch_before_nested_checks() {
        let mut manifest = sample_phase23_cross_step_lookup_accumulator_manifest();
        manifest.proof_backend = StarkProofBackend::Vanilla;
        manifest.members[0].accumulator.matrices.clear();

        let err = verify_phase23_decoding_cross_step_lookup_accumulator(&manifest).unwrap_err();
        assert!(err
            .to_string()
            .contains("decoding cross-step lookup accumulator backend `vanilla` is not `stwo`"));
    }

    #[test]
    fn phase23_oracle_matches_production_commitments() {
        let manifest = sample_phase23_cross_step_lookup_accumulator_manifest();
        verify_phase23_decoding_cross_step_lookup_accumulator(&manifest)
            .expect("production verifier");
        let oracle_accumulator =
            oracle_commit_phase23_lookup_accumulator(&manifest).expect("oracle accumulator");
        assert_eq!(manifest.accumulator_commitment, oracle_accumulator);
    }

    #[test]
    fn phase23_oracle_and_production_reject_same_accumulator_tamper() {
        let mut manifest = sample_phase23_cross_step_lookup_accumulator_manifest();
        manifest.accumulator_commitment = "tampered".to_string();
        assert!(verify_phase23_decoding_cross_step_lookup_accumulator(&manifest).is_err());
        let oracle_accumulator =
            oracle_commit_phase23_lookup_accumulator(&manifest).expect("oracle accumulator");
        assert_ne!(manifest.accumulator_commitment, oracle_accumulator);
    }

    #[test]
    fn phase24_state_relation_accumulator_accepts_contiguous_members() {
        let manifest = sample_phase24_decoding_state_relation_accumulator_manifest();
        assert_eq!(manifest.member_count, 2);
        assert_eq!(manifest.member_summaries.len(), 2);
        assert!(manifest.total_steps >= 2);
        assert_eq!(manifest.member_summaries[0].start_step, 0);
        assert_eq!(
            manifest.member_summaries[0].end_step,
            manifest.member_summaries[0].total_steps
        );
        assert_eq!(
            manifest.member_summaries[1].start_state_commitment,
            manifest.member_summaries[0].end_state_commitment
        );
        verify_phase24_decoding_state_relation_accumulator(&manifest)
            .expect("phase24 verification");
    }

    #[test]
    fn phase24_state_relation_accumulator_rejects_tampered_relation_accumulator_commitment() {
        let mut manifest = sample_phase24_decoding_state_relation_accumulator_manifest();
        manifest.relation_accumulator_commitment = "tampered".to_string();
        let err = verify_phase24_decoding_state_relation_accumulator(&manifest).unwrap_err();
        assert!(err.to_string().contains(
            "relation_accumulator_commitment does not match the computed accumulator commitment"
        ));
    }

    #[test]
    fn phase24_state_relation_accumulator_rejects_tampered_relation_template_commitment() {
        let mut manifest = sample_phase24_decoding_state_relation_accumulator_manifest();
        manifest.relation_template_commitment = "tampered".to_string();
        let err = verify_phase24_decoding_state_relation_accumulator(&manifest).unwrap_err();
        assert!(err.to_string().contains(
            "relation_template_commitment does not match the computed member relation template commitment"
        ));
    }

    #[test]
    fn phase24_state_relation_accumulator_rejects_tampered_start_state_commitment() {
        let mut manifest = sample_phase24_decoding_state_relation_accumulator_manifest();
        manifest.start_state_commitment = "tampered".to_string();
        let err = verify_phase24_decoding_state_relation_accumulator(&manifest).unwrap_err();
        assert!(err
            .to_string()
            .contains("start_state_commitment does not match the first member boundary"));
    }

    #[test]
    fn phase24_state_relation_accumulator_rejects_tampered_end_state_commitment() {
        let mut manifest = sample_phase24_decoding_state_relation_accumulator_manifest();
        manifest.end_state_commitment = "tampered".to_string();
        let err = verify_phase24_decoding_state_relation_accumulator(&manifest).unwrap_err();
        assert!(err
            .to_string()
            .contains("end_state_commitment does not match the last member boundary"));
    }

    #[test]
    fn phase24_state_relation_accumulator_rejects_tampered_lookup_delta_entries() {
        let mut manifest = sample_phase24_decoding_state_relation_accumulator_manifest();
        manifest.lookup_delta_entries = manifest.lookup_delta_entries.saturating_add(1);
        let err = verify_phase24_decoding_state_relation_accumulator(&manifest).unwrap_err();
        assert!(err.to_string().contains("lookup_delta_entries="));
        assert!(err
            .to_string()
            .contains("does not match derived lookup_delta_entries"));
    }

    #[test]
    fn phase24_state_relation_accumulator_rejects_non_contiguous_member_boundary() {
        let mut manifest = sample_phase24_decoding_state_relation_accumulator_manifest();
        manifest.members[1].members[0].accumulator.matrices[0].rollups[0].rollups[0]
            .global_to_state
            .lookup_transcript_entries =
            manifest.members[1].members[0].accumulator.matrices[0].rollups[0].rollups[0]
                .global_to_state
                .lookup_transcript_entries
                .saturating_add(1);
        manifest.members[1].members[0].accumulator.matrices[0].rollups[0].rollups[0]
            .global_to_state
            .public_state_commitment = commit_phase14_public_state(
            &manifest.members[1].members[0].accumulator.matrices[0].rollups[0].rollups[0]
                .global_to_state,
        );
        let err = verify_phase24_decoding_state_relation_accumulator(&manifest).unwrap_err();
        assert!(
            err.to_string()
                .contains("Phase 23 member 0 failed Phase 22 verification")
                || err.to_string().contains(
                    "member boundary 0 -> 1 does not preserve the full carried-state commitment"
                )
        );
    }

    #[test]
    fn phase24_state_relation_accumulator_rejects_tampered_member_summaries() {
        let mut manifest = sample_phase24_decoding_state_relation_accumulator_manifest();
        manifest.member_summaries[1].start_step = 99;
        let err = verify_phase24_decoding_state_relation_accumulator(&manifest).unwrap_err();
        assert!(err
            .to_string()
            .contains("member_summaries do not match the derived member summaries"));
    }

    #[test]
    fn phase24_state_relation_accumulator_rejects_oversized_manifest_before_nested_checks() {
        let seed = sample_phase24_decoding_state_relation_accumulator_manifest();
        let mut manifest = seed.clone();
        manifest.members = vec![seed.members[0].clone(); MAX_PHASE24_ACCUMULATOR_MEMBERS + 1];
        manifest.member_summaries = vec![seed.member_summaries[0].clone(); manifest.members.len()];
        manifest.member_count = manifest.members.len();
        manifest.members[0].members.clear();

        let err = verify_phase24_decoding_state_relation_accumulator(&manifest).unwrap_err();
        assert!(err.to_string().contains("members.len()="));
        assert!(err.to_string().contains("exceeds the supported maximum"));
    }

    #[test]
    fn phase24_state_relation_accumulator_rejects_excess_total_nested_phase23_members_before_deep_walk(
    ) {
        let seed = sample_phase24_decoding_state_relation_accumulator_manifest();
        let mut oversized_member = seed.members[0].clone();
        oversized_member.members =
            vec![seed.members[0].members[0].clone(); MAX_PHASE23_ACCUMULATOR_MEMBERS];
        oversized_member.member_count = oversized_member.members.len();

        let repeat_count =
            (MAX_PHASE24_TOTAL_NESTED_PHASE23_MEMBERS / MAX_PHASE23_ACCUMULATOR_MEMBERS) + 1;
        let mut manifest = seed.clone();
        manifest.members = vec![oversized_member; repeat_count];
        manifest.member_summaries = vec![seed.member_summaries[0].clone(); repeat_count];
        manifest.member_count = repeat_count;
        manifest.members[0].members[0].accumulator.matrices.clear();

        let err = verify_phase24_decoding_state_relation_accumulator(&manifest).unwrap_err();
        assert!(err.to_string().contains("total nested Phase 23 members"));
        assert!(err.to_string().contains("exceeds the supported maximum"));
    }

    #[test]
    fn phase24_state_relation_accumulator_rejects_oversized_nested_phase23_before_deep_walk() {
        let seed = sample_phase24_decoding_state_relation_accumulator_manifest();
        let mut manifest = seed.clone();
        manifest.members[0].members =
            vec![seed.members[0].members[0].clone(); MAX_PHASE23_ACCUMULATOR_MEMBERS + 1];
        manifest.members[0].member_count = manifest.members[0].members.len();
        manifest.members[0].members[0].accumulator.matrices.clear();

        let err = verify_phase24_decoding_state_relation_accumulator(&manifest).unwrap_err();
        assert!(err
            .to_string()
            .contains("Phase 24 member 0 failed shallow Phase 23 validation"));
        assert!(err.to_string().contains("members.len()="));
        assert!(err.to_string().contains("exceeds the supported maximum"));
    }

    #[test]
    fn phase24_state_relation_accumulator_rejects_empty_commitments_before_nested_checks() {
        let seed = sample_phase24_decoding_state_relation_accumulator_manifest();

        let mut empty_source = seed.clone();
        empty_source.source_template_commitment.clear();
        empty_source.members[0].members.clear();
        let err = verify_phase24_decoding_state_relation_accumulator(&empty_source).unwrap_err();
        assert!(err
            .to_string()
            .contains("source_template_commitment must not be empty"));

        let mut empty_state_boundary = seed.clone();
        empty_state_boundary.start_state_commitment.clear();
        empty_state_boundary.members[0].members.clear();
        let err =
            verify_phase24_decoding_state_relation_accumulator(&empty_state_boundary).unwrap_err();
        assert!(err
            .to_string()
            .contains("state-boundary commitments must not be empty"));

        let mut empty_relation_template = seed.clone();
        empty_relation_template.relation_template_commitment.clear();
        empty_relation_template.members[0].members.clear();
        let err = verify_phase24_decoding_state_relation_accumulator(&empty_relation_template)
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("relation_template_commitment must not be empty"));

        let mut empty_relation_accumulator = seed;
        empty_relation_accumulator
            .relation_accumulator_commitment
            .clear();
        empty_relation_accumulator.members[0].members.clear();
        let err = verify_phase24_decoding_state_relation_accumulator(&empty_relation_accumulator)
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("relation_accumulator_commitment must not be empty"));
    }

    #[test]
    fn phase24_state_relation_accumulator_rejects_header_mismatch_before_nested_checks() {
        let mut manifest = sample_phase24_decoding_state_relation_accumulator_manifest();
        manifest.statement_version = "statement-v2".to_string();
        manifest.members[0].members.clear();

        let err = verify_phase24_decoding_state_relation_accumulator(&manifest).unwrap_err();
        assert!(err.to_string().contains(
            "unsupported decoding state relation accumulator statement version `statement-v2`"
        ));
    }

    #[test]
    fn phase24_oracle_matches_production_commitments() {
        let manifest = sample_phase24_decoding_state_relation_accumulator_manifest();
        verify_phase24_decoding_state_relation_accumulator(&manifest).expect("production verifier");
        let oracle_template =
            oracle_commit_phase24_relation_template(&manifest).expect("oracle template");
        let oracle_accumulator = oracle_commit_phase24_state_relation_accumulator(&manifest)
            .expect("oracle accumulator");
        assert_eq!(manifest.relation_template_commitment, oracle_template);
        assert_eq!(manifest.relation_accumulator_commitment, oracle_accumulator);
    }

    #[test]
    fn phase24_oracle_and_production_reject_same_accumulator_tamper() {
        let mut manifest = sample_phase24_decoding_state_relation_accumulator_manifest();
        manifest.relation_accumulator_commitment = "tampered".to_string();
        assert!(verify_phase24_decoding_state_relation_accumulator(&manifest).is_err());
        let oracle_accumulator = oracle_commit_phase24_state_relation_accumulator(&manifest)
            .expect("oracle accumulator");
        assert_ne!(manifest.relation_accumulator_commitment, oracle_accumulator);
    }

    #[test]
    fn phase24_oracle_ignores_tampered_member_summary_mirror() {
        let mut manifest = sample_phase24_decoding_state_relation_accumulator_manifest();
        let expected_template = manifest.relation_template_commitment.clone();
        let expected_accumulator = manifest.relation_accumulator_commitment.clone();
        manifest.member_summaries[1].start_step = 99;
        manifest.member_summaries[1].lookup_accumulator_commitment = "mirror-tamper".to_string();
        let oracle_template =
            oracle_commit_phase24_relation_template(&manifest).expect("oracle template");
        let oracle_accumulator = oracle_commit_phase24_state_relation_accumulator(&manifest)
            .expect("oracle accumulator");
        assert_eq!(oracle_template, expected_template);
        assert_eq!(oracle_accumulator, expected_accumulator);
    }

    #[test]
    fn phase24_oracle_ignores_tampered_top_level_lookup_delta_mirror() {
        let mut manifest = sample_phase24_decoding_state_relation_accumulator_manifest();
        let original = manifest.relation_accumulator_commitment.clone();
        manifest.lookup_delta_entries = manifest.lookup_delta_entries.saturating_add(1);
        assert!(verify_phase24_decoding_state_relation_accumulator(&manifest).is_err());
        let oracle = oracle_commit_phase24_state_relation_accumulator(&manifest)
            .expect("oracle accumulator");
        assert_eq!(oracle, original);
    }

    #[test]
    fn phase25_intervalized_state_relation_accepts_canonical_source() {
        let manifest = sample_phase25_intervalized_decoding_state_relation_manifest();
        assert_eq!(manifest.member_count, 2);
        assert_eq!(manifest.member_summaries.len(), 2);
        assert!(manifest.total_steps >= 2);
        assert_eq!(manifest.member_summaries[0].start_step, 0);
        assert_eq!(
            manifest.member_summaries[1].start_state_commitment,
            manifest.member_summaries[0].end_state_commitment
        );
        verify_phase25_intervalized_decoding_state_relation(&manifest)
            .expect("phase25 intervalized verification");
    }

    #[test]
    fn phase25_intervalized_state_relation_rejects_tampered_interval_accumulator_commitment() {
        let mut manifest = sample_phase25_intervalized_decoding_state_relation_manifest();
        manifest.interval_accumulator_commitment = "tampered".to_string();
        let err = verify_phase25_intervalized_decoding_state_relation(&manifest).unwrap_err();
        assert!(err.to_string().contains(
            "interval_accumulator_commitment does not match the computed interval accumulator commitment"
        ));
    }

    #[test]
    fn phase25_intervalized_state_relation_rejects_tampered_interval_template_commitment() {
        let mut manifest = sample_phase25_intervalized_decoding_state_relation_manifest();
        manifest.interval_template_commitment = "tampered".to_string();
        let err = verify_phase25_intervalized_decoding_state_relation(&manifest).unwrap_err();
        assert!(err.to_string().contains(
            "interval_template_commitment does not match the computed interval template commitment"
        ));
    }

    #[test]
    fn phase25_intervalized_state_relation_rejects_tampered_source_relation_commitment() {
        let mut manifest = sample_phase25_intervalized_decoding_state_relation_manifest();
        manifest.source_relation_accumulator_commitment = "tampered".to_string();
        let err = verify_phase25_intervalized_decoding_state_relation(&manifest).unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains(
                "source_relation_accumulator_commitment does not match the derived rebased Phase 24 source"
            ),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn phase25_intervalized_state_relation_rejects_tampered_lookup_delta_entries() {
        let mut manifest = sample_phase25_intervalized_decoding_state_relation_manifest();
        manifest.lookup_delta_entries = manifest.lookup_delta_entries.saturating_add(1);
        let err = verify_phase25_intervalized_decoding_state_relation(&manifest).unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("lookup_delta_entries="),
            "unexpected error: {message}"
        );
        assert!(
            message.contains("exceed the final nested cumulative total"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn phase25_intervalized_state_relation_rejects_tampered_member_summaries() {
        let mut manifest = sample_phase25_intervalized_decoding_state_relation_manifest();
        manifest.member_summaries[1].start_step = 99;
        let err = verify_phase25_intervalized_decoding_state_relation(&manifest).unwrap_err();
        assert!(err
            .to_string()
            .contains("member_summaries do not match the derived interval summaries"));
    }

    #[test]
    fn phase25_intervalized_state_relation_rejects_oversized_manifest_before_nested_checks() {
        let seed = sample_phase25_intervalized_decoding_state_relation_manifest();
        let mut manifest = seed.clone();
        manifest.members = vec![seed.members[0].clone(); MAX_PHASE25_INTERVALIZED_MEMBERS + 1];
        manifest.member_summaries = vec![seed.member_summaries[0].clone(); manifest.members.len()];
        manifest.member_count = manifest.members.len();
        manifest.members[0].members.clear();

        let err = verify_phase25_intervalized_decoding_state_relation(&manifest).unwrap_err();
        assert!(err.to_string().contains("members.len()="));
        assert!(err.to_string().contains("exceeds the supported maximum"));
    }

    #[test]
    fn phase25_intervalized_state_relation_rejects_empty_commitments_before_nested_checks() {
        let seed = sample_phase25_intervalized_decoding_state_relation_manifest();

        let mut empty_source = seed.clone();
        empty_source.source_template_commitment.clear();
        empty_source.members[0].members.clear();
        let err = verify_phase25_intervalized_decoding_state_relation(&empty_source).unwrap_err();
        assert!(err
            .to_string()
            .contains("source_template_commitment must not be empty"));

        let mut empty_global_boundary = seed.clone();
        empty_global_boundary.global_start_state_commitment.clear();
        empty_global_boundary.members[0].members.clear();
        let err = verify_phase25_intervalized_decoding_state_relation(&empty_global_boundary)
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("global state-boundary commitments must not be empty"));

        let mut empty_interval_template = seed.clone();
        empty_interval_template.interval_template_commitment.clear();
        empty_interval_template.members[0].members.clear();
        let err = verify_phase25_intervalized_decoding_state_relation(&empty_interval_template)
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("interval_template_commitment must not be empty"));

        let mut empty_interval_accumulator = seed;
        empty_interval_accumulator
            .interval_accumulator_commitment
            .clear();
        empty_interval_accumulator.members[0].members.clear();
        let err = verify_phase25_intervalized_decoding_state_relation(&empty_interval_accumulator)
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("interval_accumulator_commitment must not be empty"));
    }

    #[test]
    fn phase25_intervalized_state_relation_rejects_header_mismatch_before_nested_checks() {
        let mut manifest = sample_phase25_intervalized_decoding_state_relation_manifest();
        manifest.statement_version = "statement-v2".to_string();
        manifest.members[0].members.clear();

        let err = verify_phase25_intervalized_decoding_state_relation(&manifest).unwrap_err();
        assert!(err.to_string().contains(
            "unsupported intervalized decoding state relation statement version `statement-v2`"
        ));
    }

    #[test]
    fn phase25_oracle_matches_production_commitments() {
        let manifest = sample_phase25_intervalized_decoding_state_relation_manifest();
        verify_phase25_intervalized_decoding_state_relation(&manifest)
            .expect("production verifier");
        let oracle_interval_template =
            oracle_commit_phase25_interval_template(&manifest).expect("oracle interval template");
        let oracle_interval_accumulator =
            oracle_commit_phase25_intervalized_state_relation(&manifest)
                .expect("oracle interval accumulator");
        assert_eq!(
            manifest.interval_template_commitment,
            oracle_interval_template
        );
        assert_eq!(
            manifest.interval_accumulator_commitment,
            oracle_interval_accumulator
        );
    }

    #[test]
    fn phase25_oracle_and_production_reject_same_accumulator_tamper() {
        let mut manifest = sample_phase25_intervalized_decoding_state_relation_manifest();
        manifest.interval_accumulator_commitment = "tampered".to_string();
        assert!(verify_phase25_intervalized_decoding_state_relation(&manifest).is_err());
        let oracle_accumulator = oracle_commit_phase25_intervalized_state_relation(&manifest)
            .expect("oracle interval accumulator");
        assert_ne!(manifest.interval_accumulator_commitment, oracle_accumulator);
    }

    #[test]
    fn phase26_folded_intervalized_state_relation_accepts_contiguous_members() {
        let manifest = sample_phase26_folded_intervalized_decoding_state_relation_manifest();
        assert_eq!(manifest.member_count, 2);
        assert_eq!(manifest.bounded_fold_arity, 2);
        assert_eq!(manifest.member_summaries.len(), 2);
        assert!(manifest.total_steps >= 2);
        assert_eq!(manifest.member_summaries[0].start_step, 0);
        assert_eq!(
            manifest.member_summaries[1].start_state_commitment,
            manifest.member_summaries[0].end_state_commitment
        );
        verify_phase26_folded_intervalized_decoding_state_relation(&manifest)
            .expect("phase26 folded intervalized verification");
    }

    #[test]
    fn phase26_folded_intervalized_state_relation_rejects_tampered_folded_interval_accumulator_commitment(
    ) {
        let mut manifest = sample_phase26_folded_intervalized_decoding_state_relation_manifest();
        manifest.folded_interval_accumulator_commitment = "tampered".to_string();
        let err =
            verify_phase26_folded_intervalized_decoding_state_relation(&manifest).unwrap_err();
        assert!(err.to_string().contains(
            "folded_interval_accumulator_commitment does not match the computed folded interval accumulator commitment"
        ));
    }

    #[test]
    fn phase26_folded_intervalized_state_relation_rejects_tampered_fold_template_commitment() {
        let mut manifest = sample_phase26_folded_intervalized_decoding_state_relation_manifest();
        manifest.fold_template_commitment = "tampered".to_string();
        let err =
            verify_phase26_folded_intervalized_decoding_state_relation(&manifest).unwrap_err();
        assert!(err.to_string().contains(
            "fold_template_commitment does not match the computed fold template commitment"
        ));
    }

    #[test]
    fn phase26_folded_intervalized_state_relation_rejects_tampered_lookup_delta_entries() {
        let mut manifest = sample_phase26_folded_intervalized_decoding_state_relation_manifest();
        manifest.lookup_delta_entries = manifest.lookup_delta_entries.saturating_add(1);
        let err =
            verify_phase26_folded_intervalized_decoding_state_relation(&manifest).unwrap_err();
        assert!(err.to_string().contains("lookup_delta_entries="));
        assert!(err
            .to_string()
            .contains("does not match derived lookup_delta_entries"));
    }

    #[test]
    fn phase26_folded_intervalized_state_relation_rejects_tampered_member_summaries() {
        let mut manifest = sample_phase26_folded_intervalized_decoding_state_relation_manifest();
        manifest.member_summaries[1].start_step = 99;
        let err =
            verify_phase26_folded_intervalized_decoding_state_relation(&manifest).unwrap_err();
        assert!(err
            .to_string()
            .contains("member_summaries do not match the derived fold summaries"));
    }

    #[test]
    fn phase26_folded_intervalized_state_relation_rejects_oversized_manifest_before_nested_checks()
    {
        let seed = sample_phase26_folded_intervalized_decoding_state_relation_manifest();
        let mut manifest = seed.clone();
        manifest.members =
            vec![seed.members[0].clone(); MAX_PHASE26_FOLDED_INTERVALIZED_MEMBERS + 1];
        manifest.member_summaries = vec![seed.member_summaries[0].clone(); manifest.members.len()];
        manifest.member_count = manifest.members.len();
        manifest.members[0].members.clear();

        let err =
            verify_phase26_folded_intervalized_decoding_state_relation(&manifest).unwrap_err();
        assert!(err.to_string().contains("members.len()="));
        assert!(err.to_string().contains("exceeds the supported maximum"));
    }

    #[test]
    fn phase26_folded_intervalized_state_relation_rejects_empty_commitments_before_nested_checks() {
        let seed = sample_phase26_folded_intervalized_decoding_state_relation_manifest();

        let mut empty_source = seed.clone();
        empty_source.source_template_commitment.clear();
        empty_source.members[0].members.clear();
        let err =
            verify_phase26_folded_intervalized_decoding_state_relation(&empty_source).unwrap_err();
        assert!(err
            .to_string()
            .contains("source_template_commitment must not be empty"));

        let mut empty_global_boundary = seed.clone();
        empty_global_boundary.global_start_state_commitment.clear();
        empty_global_boundary.members[0].members.clear();
        let err =
            verify_phase26_folded_intervalized_decoding_state_relation(&empty_global_boundary)
                .unwrap_err();
        assert!(err
            .to_string()
            .contains("global state-boundary commitments must not be empty"));

        let mut empty_fold_template = seed.clone();
        empty_fold_template.fold_template_commitment.clear();
        empty_fold_template.members[0].members.clear();
        let err = verify_phase26_folded_intervalized_decoding_state_relation(&empty_fold_template)
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("fold_template_commitment must not be empty"));

        let mut empty_folded_accumulator = seed;
        empty_folded_accumulator
            .folded_interval_accumulator_commitment
            .clear();
        empty_folded_accumulator.members[0].members.clear();
        let err =
            verify_phase26_folded_intervalized_decoding_state_relation(&empty_folded_accumulator)
                .unwrap_err();
        assert!(err
            .to_string()
            .contains("folded_interval_accumulator_commitment must not be empty"));
    }

    #[test]
    fn phase26_folded_intervalized_state_relation_rejects_header_mismatch_before_nested_checks() {
        let mut manifest = sample_phase26_folded_intervalized_decoding_state_relation_manifest();
        manifest.statement_version = "statement-v2".to_string();
        manifest.members[0].members.clear();

        let err =
            verify_phase26_folded_intervalized_decoding_state_relation(&manifest).unwrap_err();
        assert!(err.to_string().contains(
            "unsupported folded intervalized decoding state relation statement version `statement-v2`"
        ));
    }

    #[test]
    fn phase26_oracle_matches_production_commitments() {
        let manifest = sample_phase26_folded_intervalized_decoding_state_relation_manifest();
        verify_phase26_folded_intervalized_decoding_state_relation(&manifest)
            .expect("production verifier");
        let oracle_fold_template =
            oracle_commit_phase26_fold_template(&manifest).expect("oracle fold template");
        let oracle_folded_accumulator =
            oracle_commit_phase26_folded_intervalized_state_relation(&manifest)
                .expect("oracle folded interval accumulator");
        assert_eq!(manifest.fold_template_commitment, oracle_fold_template);
        assert_eq!(
            manifest.folded_interval_accumulator_commitment,
            oracle_folded_accumulator
        );
    }

    #[test]
    fn phase26_oracle_and_production_reject_same_accumulator_tamper() {
        let mut manifest = sample_phase26_folded_intervalized_decoding_state_relation_manifest();
        manifest.folded_interval_accumulator_commitment = "tampered".to_string();
        assert!(verify_phase26_folded_intervalized_decoding_state_relation(&manifest).is_err());
        let oracle_folded_accumulator =
            oracle_commit_phase26_folded_intervalized_state_relation(&manifest)
                .expect("oracle folded interval accumulator");
        assert_ne!(
            manifest.folded_interval_accumulator_commitment,
            oracle_folded_accumulator
        );
    }

    #[test]
    fn phase12_oracle_matches_production_on_demo_chain() {
        let layout = phase12_default_decoding_layout();
        let proofs = phase12_demo_initial_memories(&layout)
            .expect("memories")
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let manifest = phase12_prepare_decoding_chain(&layout, &proofs).expect("phase12 manifest");

        verify_phase12_decoding_chain(&manifest).expect("production verifier");
        oracle_verify_phase12_decoding_chain(&manifest).expect("oracle verifier");
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]
        #[test]
        fn phase12_oracle_matches_production_on_bounded_single_step_chain(
            (layout, memory) in phase12_bounded_memory_strategy()
        ) {
            let proof = sample_phase12_step_proof(&layout, memory);
            let manifest = phase12_prepare_decoding_chain(&layout, &[proof]).expect("phase12 manifest");
            prop_assert!(verify_phase12_decoding_chain(&manifest).is_ok());
            prop_assert!(oracle_verify_phase12_decoding_chain(&manifest).is_ok());
        }
    }

    #[test]
    fn phase12_oracle_and_production_reject_same_wrong_artifact_reference() {
        let layout = phase12_default_decoding_layout();
        let proofs = phase12_demo_initial_memories(&layout)
            .expect("memories")
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let mut manifest =
            phase12_prepare_decoding_chain(&layout, &proofs).expect("phase12 manifest");
        manifest.steps[0].shared_lookup_artifact_commitment = "missing-artifact".to_string();

        assert!(verify_phase12_decoding_chain(&manifest).is_err());
        assert!(oracle_verify_phase12_decoding_chain(&manifest).is_err());
    }

    #[test]
    fn phase12_oracle_and_production_reject_same_unreferenced_artifact() {
        let layout = phase12_default_decoding_layout();
        let proofs = phase12_demo_initial_memories(&layout)
            .expect("memories")
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let mut manifest =
            phase12_prepare_decoding_chain(&layout, &proofs).expect("phase12 manifest");
        manifest.shared_lookup_artifacts.push(
            sample_phase12_valid_but_wrong_shared_lookup_artifact(&layout),
        );

        assert!(verify_phase12_decoding_chain(&manifest).is_err());
        assert!(oracle_verify_phase12_decoding_chain(&manifest).is_err());
    }

    #[test]
    fn phase12_oracle_and_production_reject_same_semantic_scope_drift() {
        let layout = phase12_default_decoding_layout();
        let proofs = phase12_demo_initial_memories(&layout)
            .expect("memories")
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let mut manifest =
            phase12_prepare_decoding_chain(&layout, &proofs).expect("phase12 manifest");
        manifest.steps[1].proof.claim.semantic_scope = "tampered-semantic-scope".to_string();

        assert!(verify_phase12_decoding_chain(&manifest).is_err());
        assert!(oracle_verify_phase12_decoding_chain(&manifest).is_err());
    }

    #[test]
    fn phase12_oracle_and_production_reject_same_public_state_commitment_drift() {
        let layout = phase12_default_decoding_layout();
        let proofs = phase12_demo_initial_memories(&layout)
            .expect("memories")
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let mut manifest =
            phase12_prepare_decoding_chain(&layout, &proofs).expect("phase12 manifest");
        manifest.steps[1].from_state.public_state_commitment = "tampered".to_string();

        assert!(verify_phase12_decoding_chain(&manifest).is_err());
        assert!(oracle_verify_phase12_decoding_chain(&manifest).is_err());
    }

    #[test]
    fn phase12_oracle_and_production_reject_same_forged_semantic_scope_across_all_steps() {
        let layout = phase12_default_decoding_layout();
        let proofs = phase12_demo_initial_memories(&layout)
            .expect("memories")
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let mut manifest =
            phase12_prepare_decoding_chain(&layout, &proofs).expect("phase12 manifest");
        for step in &mut manifest.steps {
            step.proof.claim.semantic_scope = "forged-semantic-scope".to_string();
        }

        assert!(verify_phase12_decoding_chain(&manifest).is_err());
        assert!(oracle_verify_phase12_decoding_chain(&manifest).is_err());
    }

    #[test]
    fn phase14_oracle_matches_production_on_demo_chain() {
        let layout = phase12_default_decoding_layout();
        let proofs = phase12_demo_initial_memories(&layout)
            .expect("memories")
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let phase12 = phase12_prepare_decoding_chain(&layout, &proofs).expect("phase12 manifest");
        let manifest = phase14_prepare_decoding_chain(&phase12).expect("phase14 manifest");

        verify_phase14_decoding_chain(&manifest).expect("production verifier");
        oracle_verify_phase14_decoding_chain(&manifest).expect("oracle verifier");
    }

    #[test]
    fn phase14_oracle_and_production_reject_same_tampered_history_link() {
        let layout = phase12_default_decoding_layout();
        let proofs = phase12_demo_initial_memories(&layout)
            .expect("memories")
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let phase12 = phase12_prepare_decoding_chain(&layout, &proofs).expect("phase12 manifest");
        let mut manifest = phase14_prepare_decoding_chain(&phase12).expect("phase14 manifest");
        manifest.steps[1]
            .from_state
            .kv_history_open_chunk_commitment = "tampered".to_string();

        assert!(verify_phase14_decoding_chain(&manifest).is_err());
        assert!(oracle_verify_phase14_decoding_chain(&manifest).is_err());
    }

    #[test]
    fn phase14_oracle_and_production_reject_same_unreferenced_artifact() {
        let layout = phase12_default_decoding_layout();
        let proofs = phase12_demo_initial_memories(&layout)
            .expect("memories")
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let phase12 = phase12_prepare_decoding_chain(&layout, &proofs).expect("phase12 manifest");
        let mut manifest = phase14_prepare_decoding_chain(&phase12).expect("phase14 manifest");
        manifest
            .shared_lookup_artifacts
            .push(manifest.shared_lookup_artifacts[0].clone());

        assert!(verify_phase14_decoding_chain(&manifest).is_err());
        assert!(oracle_verify_phase14_decoding_chain(&manifest).is_err());
    }

    #[test]
    fn phase14_oracle_and_production_reject_same_semantic_scope_drift() {
        let layout = phase12_default_decoding_layout();
        let proofs = phase12_demo_initial_memories(&layout)
            .expect("memories")
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let phase12 = phase12_prepare_decoding_chain(&layout, &proofs).expect("phase12 manifest");
        let mut manifest = phase14_prepare_decoding_chain(&phase12).expect("phase14 manifest");
        manifest.steps[1].proof.claim.semantic_scope = "tampered-semantic-scope".to_string();

        assert!(verify_phase14_decoding_chain(&manifest).is_err());
        assert!(oracle_verify_phase14_decoding_chain(&manifest).is_err());
    }

    #[test]
    fn phase14_oracle_and_production_reject_same_public_state_commitment_drift() {
        let layout = phase12_default_decoding_layout();
        let proofs = phase12_demo_initial_memories(&layout)
            .expect("memories")
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let phase12 = phase12_prepare_decoding_chain(&layout, &proofs).expect("phase12 manifest");
        let mut manifest = phase14_prepare_decoding_chain(&phase12).expect("phase14 manifest");
        manifest.steps[1].from_state.public_state_commitment = "tampered".to_string();

        assert!(verify_phase14_decoding_chain(&manifest).is_err());
        assert!(oracle_verify_phase14_decoding_chain(&manifest).is_err());
    }

    #[test]
    fn phase14_oracle_and_production_reject_same_forged_semantic_scope_across_all_steps() {
        let layout = phase12_default_decoding_layout();
        let proofs = phase12_demo_initial_memories(&layout)
            .expect("memories")
            .into_iter()
            .map(|memory| sample_phase12_step_proof(&layout, memory))
            .collect::<Vec<_>>();
        let phase12 = phase12_prepare_decoding_chain(&layout, &proofs).expect("phase12 manifest");
        let mut manifest = phase14_prepare_decoding_chain(&phase12).expect("phase14 manifest");
        for step in &mut manifest.steps {
            step.proof.claim.semantic_scope = "forged-semantic-scope".to_string();
        }

        assert!(verify_phase14_decoding_chain(&manifest).is_err());
        assert!(oracle_verify_phase14_decoding_chain(&manifest).is_err());
    }

    #[test]
    fn phase27_save_and_load_round_trip() {
        let manifest =
            sample_phase27_chained_folded_intervalized_decoding_state_relation_manifest();
        let path = std::env::temp_dir().join(format!(
            "phase27-chained-folded-intervalized-decoding-state-relation-roundtrip-json-{}.json",
            std::process::id()
        ));
        save_phase27_chained_folded_intervalized_decoding_state_relation(&manifest, &path)
            .expect("save");
        let loaded =
            load_phase27_chained_folded_intervalized_decoding_state_relation(&path).expect("load");
        verify_phase27_chained_folded_intervalized_decoding_state_relation(&loaded)
            .expect("verify");
        assert_eq!(loaded, manifest);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn phase27_load_accepts_gzip_round_trip() {
        let manifest =
            sample_phase27_chained_folded_intervalized_decoding_state_relation_manifest();
        let path = std::env::temp_dir().join(format!(
            "phase27-chained-folded-intervalized-decoding-state-relation-roundtrip-gzip-{}.json",
            std::process::id()
        ));
        let gzip_path = path.with_extension("json.gz");
        save_phase27_chained_folded_intervalized_decoding_state_relation(&manifest, &path)
            .expect("save");
        write_test_gzip_copy(&path, &gzip_path);
        let loaded = load_phase27_chained_folded_intervalized_decoding_state_relation(&gzip_path)
            .expect("load");
        verify_phase27_chained_folded_intervalized_decoding_state_relation(&loaded)
            .expect("verify");
        assert_eq!(loaded, manifest);
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(gzip_path);
    }

    #[test]
    fn phase27_demo_manifest_fits_json_budget() {
        let manifest =
            sample_phase27_chained_folded_intervalized_decoding_state_relation_manifest();
        let bytes = serde_json::to_vec(&manifest).expect("serialize");
        eprintln!("phase27_json_bytes={}", bytes.len());
        assert!(
            bytes.len() <= MAX_PHASE27_CHAINED_FOLDED_INTERVALIZED_STATE_RELATION_JSON_BYTES,
            "Phase 27 demo manifest serialized to {} bytes, exceeding the {} byte budget",
            bytes.len(),
            MAX_PHASE27_CHAINED_FOLDED_INTERVALIZED_STATE_RELATION_JSON_BYTES
        );
    }

    #[test]
    fn phase27_chained_folded_intervalized_state_relation_accepts_contiguous_members() {
        let manifest =
            sample_phase27_chained_folded_intervalized_decoding_state_relation_manifest();
        assert_eq!(manifest.member_count, 2);
        assert_eq!(manifest.member_summaries.len(), 2);
        assert!(manifest.total_phase25_members >= 4);
        assert_eq!(manifest.member_summaries[0].start_step, 0);
        assert_eq!(
            manifest.member_summaries[1].start_state_commitment,
            manifest.member_summaries[0].end_state_commitment
        );
        verify_phase27_chained_folded_intervalized_decoding_state_relation(&manifest)
            .expect("phase27 verification");
    }

    #[test]
    fn phase27_chained_folded_intervalized_state_relation_rejects_tampered_accumulator_commitment()
    {
        let mut manifest =
            sample_phase27_chained_folded_intervalized_decoding_state_relation_manifest();
        manifest.chained_folded_interval_accumulator_commitment = "tampered".to_string();
        let err = verify_phase27_chained_folded_intervalized_decoding_state_relation(&manifest)
            .unwrap_err();
        assert!(err.to_string().contains(
            "chained_folded_interval_accumulator_commitment does not match the computed chained fold accumulator commitment"
        ));
    }

    #[test]
    fn phase27_chained_folded_intervalized_state_relation_rejects_tampered_chain_template_commitment(
    ) {
        let mut manifest =
            sample_phase27_chained_folded_intervalized_decoding_state_relation_manifest();
        manifest.chain_template_commitment = "tampered".to_string();
        let err = verify_phase27_chained_folded_intervalized_decoding_state_relation(&manifest)
            .unwrap_err();
        assert!(err.to_string().contains(
            "chain_template_commitment does not match the computed chain template commitment"
        ));
    }

    #[test]
    fn phase27_chained_folded_intervalized_state_relation_rejects_tampered_total_phase25_members() {
        let mut manifest =
            sample_phase27_chained_folded_intervalized_decoding_state_relation_manifest();
        manifest.total_phase25_members = manifest.total_phase25_members.saturating_add(1);
        let err = verify_phase27_chained_folded_intervalized_decoding_state_relation(&manifest)
            .unwrap_err();
        assert!(err.to_string().contains("total_phase25_members="));
        assert!(err
            .to_string()
            .contains("does not match derived total_phase25_members"));
    }

    #[test]
    fn phase27_chained_folded_intervalized_state_relation_rejects_tampered_max_nested_fold_arity() {
        let mut manifest =
            sample_phase27_chained_folded_intervalized_decoding_state_relation_manifest();
        manifest.max_nested_fold_arity = manifest.max_nested_fold_arity.saturating_add(1);
        let err = verify_phase27_chained_folded_intervalized_decoding_state_relation(&manifest)
            .unwrap_err();
        assert!(err.to_string().contains("max_nested_fold_arity="));
        assert!(err
            .to_string()
            .contains("does not match derived max_nested_fold_arity"));
    }

    #[test]
    fn phase27_chained_folded_intervalized_state_relation_rejects_tampered_member_summaries() {
        let mut manifest =
            sample_phase27_chained_folded_intervalized_decoding_state_relation_manifest();
        manifest.member_summaries[1].start_step = 99;
        let err = verify_phase27_chained_folded_intervalized_decoding_state_relation(&manifest)
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("member_summaries do not match the derived chain summaries"));
    }

    #[test]
    fn phase27_chained_folded_intervalized_state_relation_rejects_oversized_manifest_before_nested_checks(
    ) {
        let seed = sample_phase27_chained_folded_intervalized_decoding_state_relation_manifest();
        let mut manifest = seed.clone();
        manifest.members =
            vec![seed.members[0].clone(); MAX_PHASE27_CHAINED_FOLDED_INTERVALIZED_MEMBERS + 1];
        manifest.member_summaries = vec![seed.member_summaries[0].clone(); manifest.members.len()];
        manifest.member_count = manifest.members.len();
        manifest.members[0].members.clear();

        let err = verify_phase27_chained_folded_intervalized_decoding_state_relation(&manifest)
            .unwrap_err();
        assert!(err.to_string().contains("members.len()="));
        assert!(err.to_string().contains("exceeds the supported maximum"));
    }

    #[test]
    fn phase27_chained_folded_intervalized_state_relation_rejects_empty_commitments_before_nested_checks(
    ) {
        let seed = sample_phase27_chained_folded_intervalized_decoding_state_relation_manifest();

        let mut empty_source = seed.clone();
        empty_source.source_template_commitment.clear();
        empty_source.members[0].members.clear();
        let err = verify_phase27_chained_folded_intervalized_decoding_state_relation(&empty_source)
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("source_template_commitment must not be empty"));

        let mut empty_global_boundary = seed.clone();
        empty_global_boundary.global_start_state_commitment.clear();
        empty_global_boundary.members[0].members.clear();
        let err = verify_phase27_chained_folded_intervalized_decoding_state_relation(
            &empty_global_boundary,
        )
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("global_start_state_commitment must not be empty"));

        let mut empty_chain_template = seed.clone();
        empty_chain_template.chain_template_commitment.clear();
        empty_chain_template.members[0].members.clear();
        let err = verify_phase27_chained_folded_intervalized_decoding_state_relation(
            &empty_chain_template,
        )
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("chain_template_commitment must not be empty"));

        let mut empty_chained_accumulator = seed;
        empty_chained_accumulator
            .chained_folded_interval_accumulator_commitment
            .clear();
        empty_chained_accumulator.members[0].members.clear();
        let err = verify_phase27_chained_folded_intervalized_decoding_state_relation(
            &empty_chained_accumulator,
        )
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("chained_folded_interval_accumulator_commitment must not be empty"));
    }

    #[test]
    fn phase27_chained_folded_intervalized_state_relation_rejects_header_mismatch_before_nested_checks(
    ) {
        let mut manifest =
            sample_phase27_chained_folded_intervalized_decoding_state_relation_manifest();
        manifest.statement_version = "statement-v2".to_string();
        manifest.members[0].members.clear();

        let err = verify_phase27_chained_folded_intervalized_decoding_state_relation(&manifest)
            .unwrap_err();
        assert!(err.to_string().contains(
            "unsupported chained folded intervalized decoding state relation statement version `statement-v2`"
        ));
    }

    #[test]
    fn phase27_oracle_matches_production_commitments() {
        let manifest =
            sample_phase27_chained_folded_intervalized_decoding_state_relation_manifest();
        verify_phase27_chained_folded_intervalized_decoding_state_relation(&manifest)
            .expect("production verifier");
        let oracle_template =
            oracle_commit_phase27_chain_template(&manifest).expect("oracle chain template");
        let oracle_accumulator =
            oracle_commit_phase27_chained_folded_intervalized_state_relation(&manifest)
                .expect("oracle chained fold accumulator");
        assert_eq!(manifest.chain_template_commitment, oracle_template);
        assert_eq!(
            manifest.chained_folded_interval_accumulator_commitment,
            oracle_accumulator
        );
    }

    #[test]
    fn phase27_oracle_and_production_reject_same_accumulator_tamper() {
        let mut manifest =
            sample_phase27_chained_folded_intervalized_decoding_state_relation_manifest();
        manifest.chained_folded_interval_accumulator_commitment = "tampered".to_string();
        assert!(
            verify_phase27_chained_folded_intervalized_decoding_state_relation(&manifest).is_err()
        );
        let oracle_accumulator =
            oracle_commit_phase27_chained_folded_intervalized_state_relation(&manifest)
                .expect("oracle accumulator");
        assert_ne!(
            manifest.chained_folded_interval_accumulator_commitment,
            oracle_accumulator
        );
    }

    #[test]
    fn save_phase27_chained_folded_intervalized_decoding_state_relation_rejects_manifest_exceeding_json_budget(
    ) {
        let mut manifest =
            sample_phase27_chained_folded_intervalized_decoding_state_relation_manifest();
        manifest.chain_template_commitment =
            "x".repeat(MAX_PHASE27_CHAINED_FOLDED_INTERVALIZED_STATE_RELATION_JSON_BYTES);
        let path = std::env::temp_dir().join(format!(
            "phase27-chained-folded-intervalized-save-oversized-{}.json",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let err =
            save_phase27_chained_folded_intervalized_decoding_state_relation(&manifest, &path)
                .expect_err("oversized phase27 manifest should be rejected on save");
        assert!(err.to_string().contains("exceeding the limit"));
        assert!(
            !path.exists(),
            "save should not write an unreadable manifest"
        );
    }

    #[test]
    fn phase28_save_and_load_round_trip() {
        let (manifest, summaries) =
            sample_phase28_aggregated_chained_folded_intervalized_decoding_state_relation();
        let path = std::env::temp_dir().join(format!(
            "phase28-aggregated-chained-folded-intervalized-decoding-state-relation-roundtrip-json-{}.json",
            std::process::id()
        ));
        save_phase28_aggregated_chained_folded_intervalized_decoding_state_relation(
            &manifest, &path,
        )
        .expect("save");
        let loaded =
            load_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_unchecked(
                &path,
            )
            .expect("load");
        verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_summaries(
            &loaded,
            &summaries,
        )
        .expect("verify");
        assert_eq!(loaded, manifest);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn phase28_load_accepts_gzip_round_trip() {
        let (manifest, summaries) =
            sample_phase28_aggregated_chained_folded_intervalized_decoding_state_relation();
        let path = std::env::temp_dir().join(format!(
            "phase28-aggregated-chained-folded-intervalized-decoding-state-relation-roundtrip-gzip-{}.json",
            std::process::id()
        ));
        let gzip_path = path.with_extension("json.gz");
        save_phase28_aggregated_chained_folded_intervalized_decoding_state_relation(
            &manifest, &path,
        )
        .expect("save");
        write_test_gzip_copy(&path, &gzip_path);
        let loaded =
            load_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_unchecked(
                &gzip_path,
            )
            .expect("load");
        verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_summaries(
            &loaded,
            &summaries,
        )
        .expect("verify");
        assert_eq!(loaded, manifest);
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(gzip_path);
    }

    #[test]
    fn phase28_demo_manifest_fits_json_budget() {
        let (manifest, _) =
            sample_phase28_aggregated_chained_folded_intervalized_decoding_state_relation();
        let bytes = serde_json::to_vec(&manifest).expect("serialize");
        eprintln!("phase28_json_bytes={}", bytes.len());
        assert!(
            bytes.len()
                <= MAX_PHASE28_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_STATE_RELATION_JSON_BYTES,
            "Phase 28 demo manifest serialized to {} bytes, exceeding the {} byte budget",
            bytes.len(),
            MAX_PHASE28_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_STATE_RELATION_JSON_BYTES
        );
    }

    #[test]
    fn phase28_aggregated_chained_folded_intervalized_state_relation_accepts_contiguous_members() {
        let (manifest, summaries) =
            sample_phase28_aggregated_chained_folded_intervalized_decoding_state_relation();
        assert_eq!(manifest.member_count, 2);
        assert_eq!(manifest.member_summaries.len(), 2);
        assert!(manifest.total_phase26_members >= 4);
        assert!(manifest.total_phase25_members >= 8);
        assert_eq!(manifest.member_summaries[0].start_step, 0);
        assert_eq!(
            manifest.member_summaries[1].start_state_commitment,
            manifest.member_summaries[0].end_state_commitment
        );
        verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_summaries(
            &manifest,
            &summaries,
        )
        .expect("phase28 verification");
    }

    #[test]
    fn phase28_public_verifier_rejects_synthetic_member_shells_without_nested_phase27_evidence() {
        let (manifest, _) =
            sample_phase28_aggregated_chained_folded_intervalized_decoding_state_relation();
        let err = verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation(
            &manifest,
        )
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("must contain at least two members"));
    }

    #[test]
    fn phase28_member_proof_checks_reject_synthetic_member_shells_without_nested_phase27_evidence()
    {
        let (manifest, _) =
            sample_phase28_aggregated_chained_folded_intervalized_decoding_state_relation();
        let err =
            verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_members_with_proof_checks(
                &manifest,
            )
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("failed Phase 27 proof-bearing shell validation"));
        assert!(err
            .to_string()
            .contains("must contain at least two members"));
    }

    #[test]
    fn phase28_proof_checks_reject_synthetic_member_shells_without_nested_phase27_evidence() {
        let (manifest, _) =
            sample_phase28_aggregated_chained_folded_intervalized_decoding_state_relation();
        let err =
            verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_proof_checks(
                &manifest,
            )
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("must contain at least two members"));
    }

    #[test]
    #[ignore = "expensive live Phase 28 public verifier gate over 16 nested proofs"]
    fn phase28_public_verifier_accepts_live_nested_phase27_members() {
        let layout = Phase12DecodingLayout::new(2, 2).expect("layout");
        let manifest =
            phase28_prepare_demo_manifest_for_layout(&layout).expect("live phase28 manifest");
        assert_eq!(manifest.member_count, 2);
        assert!(manifest
            .members
            .iter()
            .all(|member| member.member_count == 2 && member.member_summaries.len() == 2));
        verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation(&manifest)
            .expect("public verifier accepts live nested Phase 27 members");
    }

    #[test]
    fn phase28_aggregated_chained_folded_intervalized_state_relation_rejects_tampered_accumulator_commitment(
    ) {
        let (mut manifest, summaries) =
            sample_phase28_aggregated_chained_folded_intervalized_decoding_state_relation();
        manifest.aggregated_chained_folded_interval_accumulator_commitment = "tampered".to_string();
        let err =
            verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_summaries(
                &manifest,
                &summaries,
            )
            .unwrap_err();
        assert!(err.to_string().contains(
            "aggregated_chained_folded_interval_accumulator_commitment does not match the computed aggregated accumulator commitment"
        ));
    }

    #[test]
    fn phase28_aggregated_chained_folded_intervalized_state_relation_rejects_tampered_aggregation_template_commitment(
    ) {
        let (mut manifest, summaries) =
            sample_phase28_aggregated_chained_folded_intervalized_decoding_state_relation();
        manifest.aggregation_template_commitment = "tampered".to_string();
        let err =
            verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_summaries(
                &manifest,
                &summaries,
            )
            .unwrap_err();
        assert!(err.to_string().contains(
            "aggregation_template_commitment does not match the computed aggregation template commitment"
        ));
    }

    #[test]
    fn phase28_aggregated_chained_folded_intervalized_state_relation_rejects_tampered_total_phase26_members(
    ) {
        let (mut manifest, summaries) =
            sample_phase28_aggregated_chained_folded_intervalized_decoding_state_relation();
        manifest.total_phase26_members = manifest.total_phase26_members.saturating_add(1);
        let err =
            verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_summaries(
                &manifest,
                &summaries,
            )
            .unwrap_err();
        assert!(err.to_string().contains("total_phase26_members="));
        assert!(err
            .to_string()
            .contains("does not match derived total_phase26_members"));
    }

    #[test]
    fn phase28_aggregated_chained_folded_intervalized_state_relation_rejects_tampered_total_phase25_members(
    ) {
        let (mut manifest, summaries) =
            sample_phase28_aggregated_chained_folded_intervalized_decoding_state_relation();
        manifest.total_phase25_members = manifest.total_phase25_members.saturating_add(1);
        let err =
            verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_summaries(
                &manifest,
                &summaries,
            )
            .unwrap_err();
        assert!(err.to_string().contains("total_phase25_members="));
        assert!(err
            .to_string()
            .contains("does not match derived total_phase25_members"));
    }

    #[test]
    fn phase28_aggregated_chained_folded_intervalized_state_relation_rejects_tampered_max_nested_chain_arity(
    ) {
        let (mut manifest, summaries) =
            sample_phase28_aggregated_chained_folded_intervalized_decoding_state_relation();
        manifest.max_nested_chain_arity = manifest.max_nested_chain_arity.saturating_add(1);
        let err =
            verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_summaries(
                &manifest,
                &summaries,
            )
            .unwrap_err();
        assert!(err.to_string().contains("max_nested_chain_arity="));
        assert!(err
            .to_string()
            .contains("does not match derived max_nested_chain_arity"));
    }

    #[test]
    fn phase28_aggregated_chained_folded_intervalized_state_relation_rejects_tampered_max_nested_fold_arity(
    ) {
        let (mut manifest, summaries) =
            sample_phase28_aggregated_chained_folded_intervalized_decoding_state_relation();
        manifest.max_nested_fold_arity = manifest.max_nested_fold_arity.saturating_add(1);
        let err =
            verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_summaries(
                &manifest,
                &summaries,
            )
            .unwrap_err();
        assert!(err.to_string().contains("max_nested_fold_arity="));
        assert!(err
            .to_string()
            .contains("does not match derived max_nested_fold_arity"));
    }

    #[test]
    fn phase28_aggregated_chained_folded_intervalized_state_relation_rejects_tampered_member_summaries(
    ) {
        let (mut manifest, summaries) =
            sample_phase28_aggregated_chained_folded_intervalized_decoding_state_relation();
        manifest.member_summaries[1].start_step = 999;
        let err =
            verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_summaries(
                &manifest,
                &summaries,
            )
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("member_summaries do not match the derived aggregation summaries"));
    }

    #[test]
    fn phase28_aggregation_sequence_rejects_member_with_insufficient_phase25_members() {
        let mut summaries = synthetic_phase28_member_summaries();
        summaries[0].total_phase25_members = 3;
        let err = verify_phase28_aggregation_sequence(&summaries).unwrap_err();
        assert!(err
            .to_string()
            .contains("must summarize at least four Phase 25 members"));
    }

    #[test]
    fn phase28_aggregated_chained_folded_intervalized_state_relation_rejects_oversized_manifest_before_nested_checks(
    ) {
        let (seed, summaries) =
            sample_phase28_aggregated_chained_folded_intervalized_decoding_state_relation();
        let mut manifest = seed.clone();
        manifest.members = vec![
            seed.members[0].clone();
            MAX_PHASE28_AGGREGATED_CHAINED_FOLDED_INTERVALIZED_MEMBERS + 1
        ];
        manifest.member_summaries = vec![seed.member_summaries[0].clone(); manifest.members.len()];
        manifest.member_count = manifest.members.len();
        let err =
            verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_summaries(
                &manifest,
                &summaries,
            )
            .unwrap_err();
        assert!(err.to_string().contains("members.len()="));
        assert!(err.to_string().contains("exceeds the supported maximum"));
    }

    #[test]
    fn phase28_aggregated_chained_folded_intervalized_state_relation_rejects_excess_total_phase26_members_before_nested_checks(
    ) {
        let (mut manifest, summaries) =
            sample_phase28_aggregated_chained_folded_intervalized_decoding_state_relation();
        manifest.total_phase26_members = MAX_PHASE28_TOTAL_NESTED_PHASE26_MEMBERS + 1;
        let err =
            verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_summaries(
                &manifest,
                &summaries,
            )
            .unwrap_err();
        assert!(err.to_string().contains("total_phase26_members="));
        assert!(err.to_string().contains("supported maximum"));
    }

    #[test]
    fn phase28_aggregated_chained_folded_intervalized_state_relation_rejects_empty_commitments_before_nested_checks(
    ) {
        let (seed, summaries) =
            sample_phase28_aggregated_chained_folded_intervalized_decoding_state_relation();

        let mut empty_source = seed.clone();
        empty_source.source_template_commitment.clear();
        let err =
            verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_summaries(
                &empty_source,
                &summaries,
            )
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("source_template_commitment must not be empty"));

        let mut empty_global_boundary = seed.clone();
        empty_global_boundary.global_start_state_commitment.clear();
        let err =
            verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_summaries(
                &empty_global_boundary,
                &summaries,
            )
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("global_start_state_commitment must not be empty"));

        let mut empty_aggregation_template = seed.clone();
        empty_aggregation_template
            .aggregation_template_commitment
            .clear();
        let err =
            verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_summaries(
                &empty_aggregation_template,
                &summaries,
            )
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("aggregation_template_commitment must not be empty"));

        let mut empty_aggregated_accumulator = seed;
        empty_aggregated_accumulator
            .aggregated_chained_folded_interval_accumulator_commitment
            .clear();
        let err =
            verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_summaries(
                &empty_aggregated_accumulator,
                &summaries,
            )
            .unwrap_err();
        assert!(err.to_string().contains(
            "aggregated_chained_folded_interval_accumulator_commitment must not be empty"
        ));
    }

    #[test]
    fn phase28_aggregated_chained_folded_intervalized_state_relation_rejects_header_mismatch_before_nested_checks(
    ) {
        let (mut manifest, summaries) =
            sample_phase28_aggregated_chained_folded_intervalized_decoding_state_relation();
        manifest.statement_version = "statement-v2".to_string();
        let err =
            verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_summaries(
                &manifest,
                &summaries,
            )
            .unwrap_err();
        assert!(err.to_string().contains(
            "unsupported aggregated chained folded intervalized decoding state relation statement version `statement-v2`"
        ));
    }

    #[test]
    fn phase28_aggregated_chained_folded_intervalized_state_relation_rejects_recursive_posture_label(
    ) {
        let (mut manifest, summaries) =
            sample_phase28_aggregated_chained_folded_intervalized_decoding_state_relation();
        manifest.recursion_posture = "recursive-compressed".to_string();
        let err =
            verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_summaries(
                &manifest,
                &summaries,
            )
            .unwrap_err();
        assert!(err.to_string().contains("recursion_posture"));
        assert!(err
            .to_string()
            .contains(STWO_PHASE28_RECURSION_POSTURE_PRE_RECURSIVE));
    }

    #[test]
    fn phase28_aggregated_chained_folded_intervalized_state_relation_rejects_long_recursive_posture_without_echoing_it(
    ) {
        let (mut manifest, summaries) =
            sample_phase28_aggregated_chained_folded_intervalized_decoding_state_relation();
        let untrusted_prefix = "untrusted-posture-prefix";
        manifest.recursion_posture = format!(
            "{}{}",
            untrusted_prefix,
            "x".repeat(MAX_PHASE28_RECURSION_POSTURE_BYTES)
        );
        let err =
            verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_summaries(
                &manifest,
                &summaries,
            )
            .unwrap_err();
        assert!(err.to_string().contains("recursion_posture_len="));
        assert!(!err.to_string().contains(untrusted_prefix));
        assert!(
            err.to_string().len() < 256,
            "error must not echo untrusted posture payload"
        );
    }

    #[test]
    fn phase28_aggregated_chained_folded_intervalized_state_relation_rejects_recursive_verification_claim(
    ) {
        let (mut manifest, summaries) =
            sample_phase28_aggregated_chained_folded_intervalized_decoding_state_relation();
        manifest.recursive_verification_claimed = true;
        let err =
            verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_summaries(
                &manifest,
                &summaries,
            )
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("must not claim recursive verification"));
    }

    #[test]
    fn phase28_aggregated_chained_folded_intervalized_state_relation_rejects_cryptographic_compression_claim(
    ) {
        let (mut manifest, summaries) =
            sample_phase28_aggregated_chained_folded_intervalized_decoding_state_relation();
        manifest.cryptographic_compression_claimed = true;
        let err =
            verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_summaries(
                &manifest,
                &summaries,
            )
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("must not claim cryptographic compression"));
    }

    #[test]
    fn phase28_deserialization_defaults_to_pre_recursive_posture() {
        let (manifest, summaries) =
            sample_phase28_aggregated_chained_folded_intervalized_decoding_state_relation();
        let mut value = serde_json::to_value(&manifest).expect("serialize manifest");
        let object = value
            .as_object_mut()
            .expect("manifest serializes to object");
        object.remove("recursion_posture");
        object.remove("recursive_verification_claimed");
        object.remove("cryptographic_compression_claimed");

        let decoded: Phase28AggregatedChainedFoldedIntervalizedDecodingStateRelationManifest =
            serde_json::from_value(value).expect("deserialize legacy phase28 manifest");
        assert_eq!(
            decoded.recursion_posture,
            STWO_PHASE28_RECURSION_POSTURE_PRE_RECURSIVE
        );
        assert!(!decoded.recursive_verification_claimed);
        assert!(!decoded.cryptographic_compression_claimed);
        verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_summaries(
            &decoded,
            &summaries,
        )
        .expect("legacy defaulted phase28 manifest stays verifiable");
    }

    #[test]
    fn phase28_deserialization_rejects_long_recursive_posture_without_echoing_it() {
        let (manifest, _) =
            sample_phase28_aggregated_chained_folded_intervalized_decoding_state_relation();
        let untrusted_prefix = "serde-untrusted-posture";
        let mut value = serde_json::to_value(&manifest).expect("serialize manifest");
        value
            .as_object_mut()
            .expect("manifest serializes to object")
            .insert(
                "recursion_posture".to_string(),
                serde_json::Value::String(format!(
                    "{}{}",
                    untrusted_prefix,
                    "x".repeat(MAX_PHASE28_RECURSION_POSTURE_BYTES)
                )),
            );

        let err = serde_json::from_value::<
            Phase28AggregatedChainedFoldedIntervalizedDecodingStateRelationManifest,
        >(value)
        .unwrap_err();
        assert!(err.to_string().contains("recursion_posture_len="));
        assert!(!err.to_string().contains(untrusted_prefix));
        assert!(
            err.to_string().len() < 256,
            "serde error must not echo untrusted posture payload"
        );
    }

    #[test]
    fn phase28_aggregated_chained_folded_intervalized_state_relation_accepts_max_nested_chain_arity_boundary(
    ) {
        let mut summaries = synthetic_phase28_member_summaries();
        summaries[0].bounded_chain_arity = MAX_PHASE27_CHAINED_FOLDED_INTERVALIZED_MEMBERS;
        let manifest = phase28_manifest_from_valid_summaries(&summaries);
        assert_eq!(
            manifest.max_nested_chain_arity,
            MAX_PHASE27_CHAINED_FOLDED_INTERVALIZED_MEMBERS
        );
        verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_summaries(
            &manifest,
            &summaries,
        )
        .expect("max nested Phase 27 chain arity is accepted at the supported boundary");
    }

    #[test]
    fn phase28_oracle_matches_production_commitments() {
        let (manifest, summaries) =
            sample_phase28_aggregated_chained_folded_intervalized_decoding_state_relation();
        verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_summaries(
            &manifest,
            &summaries,
        )
        .expect("production verifier");
        let oracle_template =
            oracle_commit_phase28_aggregation_template_from_summaries(&manifest, &summaries)
                .expect("oracle template");
        let oracle_accumulator =
            oracle_commit_phase28_aggregated_chained_folded_intervalized_state_relation_from_summaries(
                &manifest,
                &summaries,
            )
            .expect("oracle accumulator");
        assert_eq!(manifest.aggregation_template_commitment, oracle_template);
        assert_eq!(
            manifest.aggregated_chained_folded_interval_accumulator_commitment,
            oracle_accumulator
        );
    }

    #[test]
    fn phase28_oracle_and_production_reject_same_accumulator_tamper() {
        let (mut manifest, summaries) =
            sample_phase28_aggregated_chained_folded_intervalized_decoding_state_relation();
        manifest.aggregated_chained_folded_interval_accumulator_commitment = "tampered".to_string();
        assert!(
            verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_summaries(
                &manifest,
                &summaries,
            )
            .is_err()
        );
        let oracle_accumulator =
            oracle_commit_phase28_aggregated_chained_folded_intervalized_state_relation_from_summaries(
                &manifest,
                &summaries,
            )
            .expect("oracle accumulator");
        assert_ne!(
            manifest.aggregated_chained_folded_interval_accumulator_commitment,
            oracle_accumulator
        );
    }

    #[test]
    fn save_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_rejects_manifest_exceeding_json_budget(
    ) {
        let (mut manifest, _) =
            sample_phase28_aggregated_chained_folded_intervalized_decoding_state_relation();
        manifest.aggregation_template_commitment = "x".repeat(256);
        let path = std::env::temp_dir().join(format!(
            "phase28-aggregated-chained-folded-intervalized-save-oversized-{}.json",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let err =
            save_phase28_aggregated_chained_folded_intervalized_decoding_state_relation_with_json_limit(
                &manifest,
                &path,
                128,
            )
            .expect_err("oversized phase28 manifest should be rejected on save");
        assert!(err.to_string().contains("exceeding the limit"));
        assert!(
            !path.exists(),
            "save should not write an unreadable manifest"
        );
    }
}
