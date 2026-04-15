use ark_ff::{One, Zero};
use serde::{Deserialize, Serialize};
use stwo::core::air::Component;
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{
    relation, EvalAtRow, FrameworkComponent, FrameworkEval, RelationEntry, TraceLocationAllocator,
};

relation!(Phase5NormalizationLookupRelation, 2);
pub(crate) type Phase5NormalizationLookupElements = Phase5NormalizationLookupRelation;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Phase5NormalizationComponentMetadata {
    pub log_size: u32,
    pub max_constraint_log_degree_bound: u32,
    pub n_constraints: usize,
    pub preprocessed_columns: Vec<String>,
    pub preprocessed_column_indices: Vec<usize>,
    pub lookup_table_rows: Vec<Phase5NormalizationTableRow>,
    pub logup_relations_per_row: Vec<(String, usize)>,
    pub semantics: &'static str,
    pub statement_contract: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Phase5NormalizationTableRow {
    pub norm_sq: u16,
    pub inv_sqrt_q8: u16,
}

const PHASE5_NORM_TABLE_INPUT: &str = "phase5/norm/table_norm_sq";
const PHASE5_NORM_TABLE_OUTPUT: &str = "phase5/norm/table_inv_sqrt_q8";
const PHASE5_NORMALIZATION_SEMANTICS: &str =
    "bounded reciprocal-square-root normalization lookup pilot (Q8 fixed point)";

#[derive(Debug, Clone)]
pub(crate) struct Phase5NormalizationLookupEval {
    log_size: u32,
    lookup_elements: Phase5NormalizationLookupRelation,
    _claimed_sum: SecureField,
}

impl FrameworkEval for Phase5NormalizationLookupEval {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size.saturating_add(1)
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let norm_sq = eval.next_trace_mask();
        let inv_sqrt_q8 = eval.next_trace_mask();
        let table_norm_sq = eval.get_preprocessed_column(column_id(PHASE5_NORM_TABLE_INPUT));
        let table_inv_sqrt_q8 = eval.get_preprocessed_column(column_id(PHASE5_NORM_TABLE_OUTPUT));
        eval.add_to_relation(RelationEntry::new(
            &self.lookup_elements,
            E::EF::one(),
            &[norm_sq, inv_sqrt_q8],
        ));
        eval.add_to_relation(RelationEntry::new(
            &self.lookup_elements,
            -E::EF::one(),
            &[table_norm_sq, table_inv_sqrt_q8],
        ));
        eval.finalize_logup_in_pairs();
        eval
    }
}

pub fn phase5_normalization_lookup_component_metadata(
    log_size: u32,
) -> Phase5NormalizationComponentMetadata {
    let allocator = TraceLocationAllocator::new_with_preprocessed_columns(
        &phase5_normalization_preprocessed_columns(),
    );
    let component = phase5_normalization_component(
        log_size,
        Phase5NormalizationLookupRelation::dummy(),
        SecureField::zero(),
    );
    let mut logup_relations_per_row: Vec<_> = component
        .logup_counts()
        .iter()
        .map(|(name, count)| (name.clone(), *count >> log_size))
        .collect();
    logup_relations_per_row.sort_by(|lhs, rhs| lhs.0.cmp(&rhs.0));

    Phase5NormalizationComponentMetadata {
        log_size,
        max_constraint_log_degree_bound: component.max_constraint_log_degree_bound(),
        n_constraints: component.n_constraints(),
        preprocessed_columns: allocator
            .preprocessed_columns()
            .iter()
            .map(|column| column.id.clone())
            .collect(),
        preprocessed_column_indices: component.preprocessed_column_indices().to_vec(),
        lookup_table_rows: phase5_normalization_table_rows(),
        logup_relations_per_row,
        semantics: PHASE5_NORMALIZATION_SEMANTICS,
        statement_contract:
            "statement-v1 preserved; normalization lookup primitive remains internal",
    }
}

pub(crate) fn phase5_normalization_component(
    log_size: u32,
    lookup_elements: Phase5NormalizationLookupRelation,
    claimed_sum: SecureField,
) -> FrameworkComponent<Phase5NormalizationLookupEval> {
    FrameworkComponent::new(
        &mut TraceLocationAllocator::new_with_preprocessed_columns(
            &phase5_normalization_preprocessed_columns(),
        ),
        Phase5NormalizationLookupEval {
            log_size,
            lookup_elements,
            _claimed_sum: claimed_sum,
        },
        claimed_sum,
    )
}

pub fn phase5_normalization_preprocessed_columns() -> Vec<PreProcessedColumnId> {
    [PHASE5_NORM_TABLE_INPUT, PHASE5_NORM_TABLE_OUTPUT]
        .into_iter()
        .map(column_id)
        .collect()
}

pub fn phase5_normalization_table_rows() -> Vec<Phase5NormalizationTableRow> {
    vec![
        Phase5NormalizationTableRow {
            norm_sq: 1,
            inv_sqrt_q8: 256,
        },
        Phase5NormalizationTableRow {
            norm_sq: 2,
            inv_sqrt_q8: 181,
        },
        Phase5NormalizationTableRow {
            norm_sq: 4,
            inv_sqrt_q8: 128,
        },
        Phase5NormalizationTableRow {
            norm_sq: 8,
            inv_sqrt_q8: 91,
        },
        Phase5NormalizationTableRow {
            norm_sq: 16,
            inv_sqrt_q8: 64,
        },
    ]
}

fn column_id(id: &str) -> PreProcessedColumnId {
    PreProcessedColumnId { id: id.to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase5_normalization_component_exposes_logup_relation() {
        let metadata = phase5_normalization_lookup_component_metadata(4);
        // `finalize_logup_in_pairs` folds the two relation entries into one paired
        // logup constraint, so `n_constraints()` reports 1 rather than 2.
        assert_eq!(metadata.n_constraints, 1);
        assert_eq!(
            metadata.preprocessed_columns,
            vec![
                PHASE5_NORM_TABLE_INPUT.to_string(),
                PHASE5_NORM_TABLE_OUTPUT.to_string(),
            ]
        );
        assert_eq!(
            metadata.logup_relations_per_row,
            vec![("Phase5NormalizationLookupRelation".to_string(), 2)]
        );
        assert_eq!(
            metadata.lookup_table_rows,
            phase5_normalization_table_rows()
        );
        assert!(metadata.semantics.contains("reciprocal-square-root"));
        assert!(metadata.statement_contract.contains("statement-v1"));
    }
}
