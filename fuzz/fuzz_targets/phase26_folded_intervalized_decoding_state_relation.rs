#![no_main]

use libfuzzer_sys::fuzz_target;
use llm_provable_computer::{
    verify_phase26_folded_intervalized_decoding_state_relation,
    Phase26FoldedIntervalizedDecodingStateRelationManifest,
};

fuzz_target!(|data: &[u8]| {
    if data.len() > 16 * 1024 * 1024 {
        return;
    }
    let Ok(manifest) =
        serde_json::from_slice::<Phase26FoldedIntervalizedDecodingStateRelationManifest>(data)
    else {
        return;
    };
    let _ = verify_phase26_folded_intervalized_decoding_state_relation(&manifest);
});
