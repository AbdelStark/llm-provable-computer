use crate::error::{Result, VmError};
use crate::instruction::{Instruction, Program};

const STWO_PHASE2_SUPPORTED_MNEMONICS: &str =
    "NOP, LOADI, LOAD, STORE, ADD, ADDM, SUBM, MULM, JMP, JZ, HALT";
const STWO_PHASE2_FIXTURE_MATRIX: &[&str] = &["addition", "multiply", "counter", "dot_product"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StwoBackendModuleLayout {
    pub adapter_module: &'static str,
    pub layout_module: &'static str,
    pub statement_contract: &'static str,
    pub trace_shape_policy: &'static str,
}

/// Returns the current module/layout plan for the Phase 2 S-two backend seam.
pub fn phase2_module_layout() -> StwoBackendModuleLayout {
    StwoBackendModuleLayout {
        adapter_module: "src/stwo_backend/adapter.rs",
        layout_module: "src/stwo_backend/layout.rs",
        statement_contract: "statement-v1 preserved; proof bytes remain opaque Vec<u8>",
        trace_shape_policy:
            "backend-specific internal trace shape allowed; public claim semantics unchanged",
    }
}

/// Returns the mnemonic summary for the current Phase 2 instruction subset.
pub fn phase2_supported_mnemonics() -> &'static str {
    STWO_PHASE2_SUPPORTED_MNEMONICS
}

/// Returns the fixture matrix used to anchor the current Phase 2 subset.
pub fn phase2_fixture_matrix() -> &'static [&'static str] {
    STWO_PHASE2_FIXTURE_MATRIX
}

pub fn validate_phase2_instruction_subset(program: &Program) -> Result<()> {
    for instruction in program.instructions() {
        if !supports_phase2_instruction(*instruction) {
            return Err(VmError::UnsupportedProof(format!(
                "instruction `{instruction}` is outside the current S-two Phase 2 arithmetic subset; supported mnemonics: {STWO_PHASE2_SUPPORTED_MNEMONICS}"
            )));
        }
    }

    Ok(())
}

fn supports_phase2_instruction(instruction: Instruction) -> bool {
    matches!(
        instruction,
        Instruction::Nop
            | Instruction::LoadImmediate(_)
            | Instruction::Load(_)
            | Instruction::Store(_)
            | Instruction::AddImmediate(_)
            | Instruction::AddMemory(_)
            | Instruction::SubMemory(_)
            | Instruction::MulMemory(_)
            | Instruction::Jump(_)
            | Instruction::JumpIfZero(_)
            | Instruction::Halt
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProgramCompiler, TransformerVmConfig};

    fn compile_program(path: &str) -> Program {
        let source = std::fs::read_to_string(path).expect("program source");
        ProgramCompiler
            .compile_source(&source, TransformerVmConfig::default())
            .expect("compile")
            .program()
            .clone()
    }

    #[test]
    fn phase2_module_layout_is_statement_v1_preserving() {
        let layout = phase2_module_layout();
        assert_eq!(layout.adapter_module, "src/stwo_backend/adapter.rs");
        assert_eq!(layout.layout_module, "src/stwo_backend/layout.rs");
        assert!(layout.statement_contract.contains("statement-v1"));
    }

    #[test]
    fn phase2_fixture_matrix_is_declared() {
        assert_eq!(
            phase2_fixture_matrix(),
            &["addition", "multiply", "counter", "dot_product"]
        );
    }

    #[test]
    fn phase2_subset_accepts_fixture_matrix() {
        for path in [
            "programs/addition.tvm",
            "programs/multiply.tvm",
            "programs/counter.tvm",
            "programs/dot_product.tvm",
        ] {
            let program = compile_program(path);
            validate_phase2_instruction_subset(&program)
                .unwrap_or_else(|error| panic!("{path} should be accepted: {error}"));
        }
    }

    #[test]
    fn phase2_subset_rejects_control_flow_outside_minimum_matrix() {
        let program = compile_program("programs/subroutine_addition.tvm");
        let err = validate_phase2_instruction_subset(&program)
            .expect_err("CALL/RET should be outside the phase2 subset");
        assert!(err
            .to_string()
            .contains("outside the current S-two Phase 2 arithmetic subset"));
    }
}
