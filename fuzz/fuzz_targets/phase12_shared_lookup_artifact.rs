#![no_main]

use libfuzzer_sys::fuzz_target;
use llm_provable_computer::stwo_backend::{
    verify_phase12_shared_lookup_artifact, Phase12SharedLookupArtifact,
};
use llm_provable_computer::Phase12DecodingLayout;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ArtifactInput {
    layout: Phase12DecodingLayout,
    expected_layout_commitment: String,
    artifact: Phase12SharedLookupArtifact,
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 8 * 1024 * 1024 {
        return;
    }
    let Ok(input) = serde_json::from_slice::<ArtifactInput>(data) else {
        return;
    };
    let _ = verify_phase12_shared_lookup_artifact(
        &input.artifact,
        &input.layout,
        &input.expected_layout_commitment,
    );
});
