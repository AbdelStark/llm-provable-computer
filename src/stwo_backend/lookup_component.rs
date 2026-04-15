use ark_ff::{One, Zero};
use serde::{Deserialize, Serialize};
use stwo::core::air::Component;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{
    relation, EvalAtRow, FrameworkComponent, FrameworkEval, RelationEntry, TraceLocationAllocator,
};

relation!(Phase3BinaryStepLookupRelation, 2);
pub(crate) type Phase3BinaryStepLookupElements = Phase3BinaryStepLookupRelation;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Phase3LookupComponentMetadata {
    pub log_size: u32,
    pub max_constraint_log_degree_bound: u32,
    pub n_constraints: usize,
    pub preprocessed_columns: Vec<String>,
    pub preprocessed_column_indices: Vec<usize>,
    pub lookup_table_rows: Vec<Phase3LookupTableRow>,
    pub logup_relations_per_row: Vec<(String, usize)>,
    pub activation_semantics: &'static str,
    pub statement_contract: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Phase3LookupTableRow {
    pub input: i16,
    pub output: u8,
}

const PHASE3_LOOKUP_TABLE_INPUT: &str = "phase3/lookup/table_input";
const PHASE3_LOOKUP_TABLE_OUTPUT: &str = "phase3/lookup/table_output";
const PHASE3_LOOKUP_SEMANTICS: &str = "bounded binary-step activation lookup pilot";

#[derive(Debug, Clone)]
pub(crate) struct Phase3BinaryStepLookupEval {
    log_size: u32,
    lookup_elements: Phase3BinaryStepLookupRelation,
}

impl FrameworkEval for Phase3BinaryStepLookupEval {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size.saturating_add(1)
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let activation_input = eval.next_trace_mask();
        let activation_output = eval.next_trace_mask();
        let table_input = eval.get_preprocessed_column(column_id(PHASE3_LOOKUP_TABLE_INPUT));
        let table_output = eval.get_preprocessed_column(column_id(PHASE3_LOOKUP_TABLE_OUTPUT));
        let one = E::F::from(BaseField::from(1u32));

        eval.add_constraint(activation_output.clone() * (activation_output.clone() - one));

        eval.add_to_relation(RelationEntry::new(
            &self.lookup_elements,
            E::EF::one(),
            &[activation_input, activation_output],
        ));
        eval.add_to_relation(RelationEntry::new(
            &self.lookup_elements,
            -E::EF::one(),
            &[table_input, table_output],
        ));
        eval.finalize_logup_in_pairs();
        eval
    }
}

pub fn phase3_binary_step_lookup_component_metadata(
    log_size: u32,
) -> Phase3LookupComponentMetadata {
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(
        &phase3_lookup_preprocessed_columns(),
    );
    let component = FrameworkComponent::new(
        &mut allocator,
        Phase3BinaryStepLookupEval {
            log_size,
            lookup_elements: Phase3BinaryStepLookupRelation::dummy(),
        },
        SecureField::zero(),
    );
    let mut logup_relations_per_row: Vec<_> = component
        .logup_counts()
        .iter()
        .map(|(name, count)| (name.clone(), *count >> log_size))
        .collect();
    logup_relations_per_row.sort_by(|lhs, rhs| lhs.0.cmp(&rhs.0));

    Phase3LookupComponentMetadata {
        log_size,
        max_constraint_log_degree_bound: component.max_constraint_log_degree_bound(),
        n_constraints: component.n_constraints(),
        preprocessed_columns: allocator
            .preprocessed_columns()
            .iter()
            .map(|column| column.id.clone())
            .collect(),
        preprocessed_column_indices: component.preprocessed_column_indices().to_vec(),
        lookup_table_rows: phase3_lookup_table_rows(),
        logup_relations_per_row,
        activation_semantics: PHASE3_LOOKUP_SEMANTICS,
        statement_contract: "statement-v1 preserved; lookup primitive remains internal",
    }
}

pub(crate) fn phase3_binary_step_lookup_component(
    log_size: u32,
    lookup_elements: Phase3BinaryStepLookupRelation,
    claimed_sum: SecureField,
) -> FrameworkComponent<Phase3BinaryStepLookupEval> {
    FrameworkComponent::new(
        &mut TraceLocationAllocator::new_with_preprocessed_columns(
            &phase3_lookup_preprocessed_columns(),
        ),
        Phase3BinaryStepLookupEval {
            log_size,
            lookup_elements,
        },
        claimed_sum,
    )
}

pub fn phase3_lookup_preprocessed_columns() -> Vec<PreProcessedColumnId> {
    [PHASE3_LOOKUP_TABLE_INPUT, PHASE3_LOOKUP_TABLE_OUTPUT]
        .into_iter()
        .map(column_id)
        .collect()
}

pub fn phase3_lookup_table_rows() -> Vec<Phase3LookupTableRow> {
    vec![
        Phase3LookupTableRow {
            input: -1,
            output: 0,
        },
        Phase3LookupTableRow {
            input: 0,
            output: 1,
        },
        Phase3LookupTableRow {
            input: 1,
            output: 1,
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
    fn phase3_lookup_component_exposes_logup_relation() {
        let metadata = phase3_binary_step_lookup_component_metadata(4);
        assert_eq!(metadata.n_constraints, 2);
        assert_eq!(
            metadata.preprocessed_columns,
            vec![
                PHASE3_LOOKUP_TABLE_INPUT.to_string(),
                PHASE3_LOOKUP_TABLE_OUTPUT.to_string(),
            ]
        );
        assert_eq!(
            metadata.logup_relations_per_row,
            vec![("Phase3BinaryStepLookupRelation".to_string(), 2)]
        );
        assert_eq!(metadata.lookup_table_rows, phase3_lookup_table_rows());
        assert!(metadata.statement_contract.contains("statement-v1"));
    }

    #[test]
    fn phase3_lookup_component_is_explicitly_bounded() {
        let metadata = phase3_binary_step_lookup_component_metadata(3);
        assert_eq!(metadata.activation_semantics, PHASE3_LOOKUP_SEMANTICS);
        assert_eq!(metadata.preprocessed_column_indices, vec![0, 1]);
        assert_eq!(metadata.lookup_table_rows, phase3_lookup_table_rows());
    }
}
