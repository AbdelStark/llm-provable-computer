#![no_main]

use libfuzzer_sys::fuzz_target;
use llm_provable_computer::{verify_phase12_decoding_chain, Phase12DecodingChainManifest};

fuzz_target!(|data: &[u8]| {
    if data.len() > 8 * 1024 * 1024 {
        return;
    }
    let Ok(manifest) = serde_json::from_slice::<Phase12DecodingChainManifest>(data) else {
        return;
    };
    let _ = verify_phase12_decoding_chain(&manifest);
});
