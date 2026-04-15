#![no_main]

use libfuzzer_sys::fuzz_target;
use llm_provable_computer::{
    verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation,
    Phase28AggregatedChainedFoldedIntervalizedDecodingStateRelationManifest,
};

fuzz_target!(|data: &[u8]| {
    let manifest = match serde_json::from_slice::<
        Phase28AggregatedChainedFoldedIntervalizedDecodingStateRelationManifest,
    >(data)
    {
        Ok(manifest) => manifest,
        Err(_) => return,
    };

    let _ = verify_phase28_aggregated_chained_folded_intervalized_decoding_state_relation(
        &manifest,
    );
});
