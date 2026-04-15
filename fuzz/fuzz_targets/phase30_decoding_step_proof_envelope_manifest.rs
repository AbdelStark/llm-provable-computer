#![no_main]

use libfuzzer_sys::fuzz_target;
use llm_provable_computer::{
    verify_phase30_decoding_step_proof_envelope_manifest,
    verify_phase30_decoding_step_proof_envelope_manifest_against_chain,
    Phase12DecodingChainManifest, Phase30DecodingStepProofEnvelopeManifest,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ManifestInput {
    manifest: Phase30DecodingStepProofEnvelopeManifest,
    chain: Option<Phase12DecodingChainManifest>,
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 8 * 1024 * 1024 {
        return;
    }
    let Ok(input) = serde_json::from_slice::<ManifestInput>(data) else {
        return;
    };
    let _ = verify_phase30_decoding_step_proof_envelope_manifest(&input.manifest);
    if let Some(chain) = input.chain.as_ref() {
        let _ = verify_phase30_decoding_step_proof_envelope_manifest_against_chain(
            &input.manifest,
            chain,
        );
    }
});
