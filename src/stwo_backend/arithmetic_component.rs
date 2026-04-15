use ark_ff::Zero;
use stwo::core::air::Component;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::TreeSubspan;
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Phase3TreeSubspan {
    pub tree_index: usize,
    pub col_start: usize,
    pub col_end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Phase3ArithmeticComponentMetadata {
    pub log_size: u32,
    pub max_constraint_log_degree_bound: u32,
    pub n_constraints: usize,
    pub trace_locations: Vec<Phase3TreeSubspan>,
    pub trace_log_degree_bounds: Vec<Vec<u32>>,
    pub preprocessed_columns: Vec<String>,
    pub preprocessed_column_indices: Vec<usize>,
    pub statement_contract: &'static str,
    pub covered_instructions: &'static str,
}

const PHASE3_ARITHMETIC_COVERED_INSTRUCTIONS: &str = "LOADI, ADD-immediate, HALT";
const PHASE3_SELECTOR_LOADI: &str = "phase3/arith/selector_loadi";
const PHASE3_SELECTOR_ADDI: &str = "phase3/arith/selector_addi";
const PHASE3_SELECTOR_HALT: &str = "phase3/arith/selector_halt";
const PHASE3_IMMEDIATE: &str = "phase3/arith/immediate";
const PHASE3_PC_PLUS_ONE_WRAPPED: &str = "phase3/arith/pc_plus_one_wrapped";

#[derive(Debug, Clone, Copy)]
struct Phase3ArithmeticEval {
    log_size: u32,
}

impl FrameworkEval for Phase3ArithmeticEval {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size.saturating_add(1)
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let pc = eval.next_trace_mask();
        let acc = eval.next_trace_mask();
        let next_pc = eval.next_trace_mask();
        let next_acc = eval.next_trace_mask();
        let halted = eval.next_trace_mask();
        let next_halted = eval.next_trace_mask();

        let is_loadi = eval.get_preprocessed_column(column_id(PHASE3_SELECTOR_LOADI));
        let is_addi = eval.get_preprocessed_column(column_id(PHASE3_SELECTOR_ADDI));
        let is_halt = eval.get_preprocessed_column(column_id(PHASE3_SELECTOR_HALT));
        let immediate = eval.get_preprocessed_column(column_id(PHASE3_IMMEDIATE));
        let pc_plus_one_wrapped =
            eval.get_preprocessed_column(column_id(PHASE3_PC_PLUS_ONE_WRAPPED));

        let one = E::F::from(BaseField::from(1u32));

        for selector in [is_loadi.clone(), is_addi.clone(), is_halt.clone()] {
            eval.add_constraint(selector.clone() * (selector - one.clone()));
        }

        eval.add_constraint(is_loadi.clone() + is_addi.clone() + is_halt.clone() - one.clone());
        eval.add_constraint(halted.clone() * (halted.clone() - one.clone()));
        eval.add_constraint(next_halted.clone() * (next_halted.clone() - one.clone()));

        let expected_next_pc = is_halt.clone() * pc.clone()
            + (is_loadi.clone() + is_addi.clone()) * pc_plus_one_wrapped;
        let expected_next_acc = is_loadi.clone() * immediate.clone()
            + is_addi.clone() * (acc.clone() + immediate)
            + is_halt.clone() * acc;

        let expected_next_halted = halted.clone() + (one.clone() - halted.clone()) * is_halt;

        eval.add_constraint(next_pc - expected_next_pc);
        eval.add_constraint(next_acc - expected_next_acc);
        eval.add_constraint(next_halted - expected_next_halted);
        eval
    }
}

pub fn phase3_arithmetic_component_metadata(log_size: u32) -> Phase3ArithmeticComponentMetadata {
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(
        &phase3_arithmetic_preprocessed_columns(),
    );
    let component = FrameworkComponent::new(
        &mut allocator,
        Phase3ArithmeticEval { log_size },
        SecureField::zero(),
    );

    Phase3ArithmeticComponentMetadata {
        log_size,
        max_constraint_log_degree_bound: component.max_constraint_log_degree_bound(),
        n_constraints: component.n_constraints(),
        trace_locations: summarize_trace_locations(component.trace_locations()),
        trace_log_degree_bounds: component.trace_log_degree_bounds().0,
        preprocessed_columns: allocator
            .preprocessed_columns()
            .iter()
            .map(|column| column.id.clone())
            .collect(),
        preprocessed_column_indices: component.preprocessed_column_indices().to_vec(),
        statement_contract: "statement-v1 preserved; backend-specific internals only",
        covered_instructions: PHASE3_ARITHMETIC_COVERED_INSTRUCTIONS,
    }
}

pub fn phase3_arithmetic_preprocessed_columns() -> Vec<PreProcessedColumnId> {
    [
        PHASE3_SELECTOR_LOADI,
        PHASE3_SELECTOR_ADDI,
        PHASE3_SELECTOR_HALT,
        PHASE3_IMMEDIATE,
        PHASE3_PC_PLUS_ONE_WRAPPED,
    ]
    .into_iter()
    .map(column_id)
    .collect()
}

fn column_id(id: &str) -> PreProcessedColumnId {
    PreProcessedColumnId { id: id.to_string() }
}

fn summarize_trace_locations(spans: &[TreeSubspan]) -> Vec<Phase3TreeSubspan> {
    spans
        .iter()
        .map(|span| Phase3TreeSubspan {
            tree_index: span.tree_index,
            col_start: span.col_start,
            col_end: span.col_end,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase3_arithmetic_component_builds_real_framework_component() {
        let metadata = phase3_arithmetic_component_metadata(4);
        assert_eq!(metadata.log_size, 4);
        assert!(metadata.n_constraints >= 8);
        assert!(!metadata.trace_locations.is_empty());
        assert_eq!(
            metadata.preprocessed_columns,
            vec![
                PHASE3_SELECTOR_LOADI.to_string(),
                PHASE3_SELECTOR_ADDI.to_string(),
                PHASE3_SELECTOR_HALT.to_string(),
                PHASE3_IMMEDIATE.to_string(),
                PHASE3_PC_PLUS_ONE_WRAPPED.to_string(),
            ]
        );
        assert!(metadata.statement_contract.contains("statement-v1"));
        assert_eq!(
            metadata.covered_instructions,
            PHASE3_ARITHMETIC_COVERED_INSTRUCTIONS
        );
    }

    #[test]
    fn phase3_arithmetic_component_uses_preprocessed_and_original_trace_spans() {
        let metadata = phase3_arithmetic_component_metadata(3);
        assert_eq!(metadata.trace_locations.len(), 2);
        assert_eq!(metadata.trace_locations[0].tree_index, 0);
        assert_eq!(metadata.trace_locations[1].tree_index, 1);
        assert_eq!(metadata.trace_log_degree_bounds[0].len(), 5);
        assert_eq!(metadata.trace_log_degree_bounds[1].len(), 6);
    }
}
