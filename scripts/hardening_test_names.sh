#!/usr/bin/env bash
# shellcheck disable=SC2034

hardening_base_test_filters=(
  "proof::tests::production_profile_v1_is_self_consistent"
  "proof::tests::commitment_hash_matches_blake2b_256_test_vector"
  "proof::tests::conjectured_security_bits_handles_large_query_counts"
  "proof::tests::canonical_json_hash_is_key_order_invariant"
  "vanillastark::proof_stream::tests::test_deserialize_rejects_huge_object_count"
  "vanillastark::proof_stream::tests::test_deserialize_rejects_huge_segment_length"
  "vanillastark::proof_stream::tests::test_deserialize_rejects_truncated_stream"
)

# Keep the `onnx-export` metadata parser gates on the smoke/UB path. They are
# intentionally excluded from the Miri loop, and from the ASAN suite on the
# current Apple toolchain, because feature-enabled tract/ONNX sanitizer builds
# are not reliable enough for the fast hardening cycle on this repo.
hardening_onnx_test_filters=(
  "onnx_export::tests::load_onnx_program_metadata_rejects_wrong_format_version"
  "onnx_export::tests::load_onnx_program_metadata_rejects_input_contract_drift"
  "onnx_export::tests::load_onnx_program_metadata_rejects_output_contract_drift"
  "onnx_export::tests::load_onnx_program_metadata_rejects_instruction_table_instruction_drift"
  "onnx_export::tests::load_onnx_program_metadata_rejects_model_path_escape"
  "onnx_export::tests::load_onnx_program_metadata_rejects_unknown_top_level_field"
  "onnx_export::tests::load_onnx_program_metadata_rejects_unknown_nested_config_field"
  "onnx_export::tests::load_onnx_program_metadata_rejects_unknown_nested_program_field"
  "onnx_export::tests::load_onnx_program_metadata_rejects_unknown_nested_memory_read_field"
  "onnx_export::tests::load_onnx_program_metadata_rejects_unknown_direct_memory_read_field"
  "onnx_export::tests::load_onnx_program_metadata_rejects_missing_direct_memory_read_address"
  "onnx_export::tests::load_onnx_program_metadata_maps_runtime_conversion_failures_to_serialization"
)

# Keep the other CLI-facing artifact loaders in the `tvm` binary smoke/UB path.
# These tests are intentionally run on the default `tvm` surface so the
# hardened HF provenance loader is exercised even when `onnx-export` is off.
hardening_tvm_bin_cargo_args=(
  --bin tvm
)

hardening_tvm_bin_test_filters=(
  "hf_provenance_manifest_tests::load_hf_provenance_manifest_rejects_unknown_top_level_field"
  "hf_provenance_manifest_tests::load_hf_provenance_manifest_rejects_unknown_nested_onnx_export_field"
  "hf_provenance_manifest_tests::load_hf_provenance_manifest_reports_malformed_json_as_serialization"
  "hf_provenance_manifest_tests::load_hf_provenance_manifest_rejects_oversized_file"
  "hf_provenance_manifest_tests::load_hf_provenance_manifest_rejects_non_regular_file"
  "hf_provenance_manifest_tests::prepare_hf_provenance_manifest_rejects_oversized_output"
  "hf_provenance_manifest_tests::verify_hf_provenance_manifest_rejects_non_regular_bound_file"
)

# Keep the `research-v3` equivalence artifact loader and witness checks on the
# smoke/UB path. These live in the `tvm` binary test harness rather than the
# library test harness because the strict loader is part of the CLI-facing
# verifier surface.
hardening_research_v3_test_filters=(
  "tests::research_v3_rule_witnesses_rejects_event_length_mismatch"
  "tests::load_research_v3_equivalence_artifact_rejects_unknown_top_level_field"
  "tests::load_research_v3_equivalence_artifact_rejects_unknown_nested_rule_witness_field"
  "tests::load_research_v3_equivalence_artifact_rejects_oversized_file"
  "tests::load_research_v3_equivalence_artifact_reports_malformed_json_as_serialization"
  "tests::load_research_v3_equivalence_artifact_rejects_non_regular_file"
  "tests::verify_research_v3_equivalence_artifact_rejects_unknown_engine_binding"
  "tests::verify_research_v3_equivalence_artifact_rejects_missing_pinned_engine"
  "tests::verify_research_v3_equivalence_artifact_rejects_extra_engine_events_beyond_checked_steps"
)

# Keep the heavier `stwo-backend` verifier gates on the sanitizer path. They are
# intentionally excluded from the Miri loop because feature-enabled Miri builds
# are too expensive for the fast hardening cycle on this repo.
hardening_stwo_test_filters=(
  "stwo_backend::decoding::tests::phase23_cross_step_lookup_accumulator_rejects_oversized_manifest_before_nested_checks"
  "stwo_backend::decoding::tests::phase23_cross_step_lookup_accumulator_rejects_header_mismatch_before_nested_checks"
  "stwo_backend::decoding::tests::phase24_state_relation_accumulator_rejects_oversized_manifest_before_nested_checks"
  "stwo_backend::decoding::tests::phase24_state_relation_accumulator_rejects_excess_total_nested_phase23_members_before_deep_walk"
  "stwo_backend::decoding::tests::phase24_state_relation_accumulator_rejects_oversized_nested_phase23_before_deep_walk"
  "stwo_backend::decoding::tests::phase24_state_relation_accumulator_rejects_empty_commitments_before_nested_checks"
  "stwo_backend::decoding::tests::phase24_state_relation_accumulator_rejects_header_mismatch_before_nested_checks"
  "stwo_backend::decoding::tests::phase25_intervalized_state_relation_rejects_oversized_manifest_before_nested_checks"
  "stwo_backend::decoding::tests::phase25_intervalized_state_relation_rejects_empty_commitments_before_nested_checks"
  "stwo_backend::decoding::tests::phase25_intervalized_state_relation_rejects_header_mismatch_before_nested_checks"
  "stwo_backend::decoding::tests::phase26_folded_intervalized_state_relation_rejects_oversized_manifest_before_nested_checks"
  "stwo_backend::decoding::tests::phase26_folded_intervalized_state_relation_rejects_empty_commitments_before_nested_checks"
  "stwo_backend::decoding::tests::phase26_folded_intervalized_state_relation_rejects_header_mismatch_before_nested_checks"
  "stwo_backend::decoding::tests::phase27_chained_folded_intervalized_state_relation_rejects_oversized_manifest_before_nested_checks"
  "stwo_backend::decoding::tests::phase27_chained_folded_intervalized_state_relation_rejects_empty_commitments_before_nested_checks"
  "stwo_backend::decoding::tests::phase27_chained_folded_intervalized_state_relation_rejects_header_mismatch_before_nested_checks"
  "stwo_backend::decoding::tests::phase28_aggregated_chained_folded_intervalized_state_relation_rejects_oversized_manifest_before_nested_checks"
  "stwo_backend::decoding::tests::phase28_aggregated_chained_folded_intervalized_state_relation_rejects_excess_total_phase26_members_before_nested_checks"
  "stwo_backend::decoding::tests::phase28_aggregated_chained_folded_intervalized_state_relation_rejects_empty_commitments_before_nested_checks"
  "stwo_backend::decoding::tests::phase28_aggregated_chained_folded_intervalized_state_relation_rejects_header_mismatch_before_nested_checks"
  "stwo_backend::decoding::tests::phase28_aggregated_chained_folded_intervalized_state_relation_accepts_max_nested_chain_arity_boundary"
  "stwo_backend::decoding::tests::phase28_aggregation_sequence_rejects_member_with_insufficient_phase25_members"
  "stwo_backend::decoding::tests::phase28_public_verifier_rejects_synthetic_member_shells_without_nested_phase27_evidence"
  "stwo_backend::decoding::tests::phase28_member_proof_checks_reject_synthetic_member_shells_without_nested_phase27_evidence"
  "stwo_backend::decoding::tests::phase28_proof_checks_reject_synthetic_member_shells_without_nested_phase27_evidence"
  "stwo_backend::decoding::tests::load_phase30_decoding_step_proof_envelope_manifest_reports_malformed_json_as_invalid_config"
  "stwo_backend::decoding::tests::load_phase30_decoding_step_proof_envelope_manifest_rejects_oversized_manifest_file"
  "stwo_backend::decoding::tests::phase30_step_envelope_list_commitment_binds_ordering"
  "stwo_backend::decoding::tests::phase30_step_envelope_manifest_rejects_tampered_start_boundary"
  "stwo_backend::decoding::tests::phase30_step_envelope_manifest_rejects_tampered_end_boundary"
  "stwo_backend::decoding::tests::phase30_step_envelope_manifest_rejects_step_envelope_list_commitment_drift"
  "stwo_backend::decoding::tests::phase30_step_envelope_manifest_rejects_step_index_drift"
  "stwo_backend::decoding::tests::phase30_step_envelope_manifest_rejects_tampered_chain_link"
  "stwo_backend::recursion::tests::phase29_recursive_compression_input_contract_accepts_committed_shape"
  "stwo_backend::recursion::tests::phase29_recursive_compression_input_contract_rejects_recursive_claim"
  "stwo_backend::recursion::tests::phase29_recursive_compression_input_contract_rejects_compression_claim"
  "stwo_backend::recursion::tests::phase29_recursive_compression_input_contract_rejects_empty_commitments"
  "stwo_backend::recursion::tests::phase29_recursive_compression_input_contract_rejects_tampered_commitment"
  "stwo_backend::recursion::tests::phase29_recursive_compression_input_contract_rejects_wrong_phase28_dialect"
  "stwo_backend::recursion::tests::phase29_recursive_compression_input_contract_rejects_wrong_statement_version"
  "stwo_backend::recursion::tests::phase29_recursive_compression_input_contract_deserialization_verifies_contract"
  "stwo_backend::recursion::tests::phase29_recursive_compression_input_contract_parse_reports_validation_error_as_invalid_config"
  "stwo_backend::recursion::tests::phase29_recursive_compression_input_contract_parse_rejects_unknown_fields"
  "stwo_backend::recursion::tests::phase29_parse_recursive_compression_input_contract_reports_malformed_json_as_invalid_config"
  "stwo_backend::recursion::tests::phase29_parse_recursive_compression_input_contract_rejects_oversized_json"
  "stwo_backend::recursion::tests::phase29_load_recursive_compression_input_contract_reports_malformed_json_as_invalid_config"
  "stwo_backend::recursion::tests::phase29_load_recursive_compression_input_contract_rejects_oversized_file"
  "stwo_backend::recursion::tests::phase29_load_recursive_compression_input_contract_rejects_oversized_gzip_file"
  "stwo_backend::recursion::tests::phase29_load_recursive_compression_input_contract_rejects_non_regular_file"
  "stwo_backend::recursion::tests::phase29_prepare_rejects_phase28_recursive_claim_before_contract_derivation"
  "stwo_backend::recursion::tests::phase29_prepare_rejects_phase28_synthetic_shell_without_nested_members"
)
