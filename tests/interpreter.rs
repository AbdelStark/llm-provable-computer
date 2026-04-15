use llm_provable_computer::{
    parse_program, verify_model_against_native, Attention2DMode, NativeInterpreter,
    ProgramCompiler, TransformerVmConfig, VmError,
};

#[test]
fn native_interpreter_executes_subroutine_program() {
    let source = std::fs::read_to_string("programs/subroutine_addition.tvm").expect("fixture");
    let program = parse_program(&source).expect("parse");
    let mut interpreter = NativeInterpreter::new(program, Attention2DMode::AverageHard, 128);

    let result = interpreter.run().expect("run");

    assert!(result.halted);
    assert_eq!(result.steps, 5);
    assert_eq!(result.final_state.acc, 42);
    assert_eq!(result.final_state.sp, 8);
    assert_eq!(result.final_state.memory, vec![0, 0, 0, 0, 0, 0, 0, 2]);
}

#[test]
fn native_interpreter_reports_stack_underflow() {
    let program = parse_program(
        r#"
        .memory 4
        POP
        HALT
    "#,
    )
    .expect("parse");
    let mut interpreter = NativeInterpreter::new(program, Attention2DMode::AverageHard, 8);

    let error = interpreter.run().expect_err("POP should underflow");
    match error {
        VmError::StackUnderflow { sp, size } => {
            assert_eq!(sp, 4);
            assert_eq!(size, 4);
        }
        other => panic!("expected stack underflow, got {other:?}"),
    }
}

#[test]
fn native_interpreter_honors_soft_attention_mode() {
    let source = std::fs::read_to_string("programs/soft_attention_memory.tvm").expect("fixture");
    let program = parse_program(&source).expect("parse");
    let mut interpreter = NativeInterpreter::new(
        program,
        Attention2DMode::HardSoftmax { temperature: 10.0 },
        32,
    );

    let result = interpreter.run().expect("run");

    assert!(result.halted);
    assert_eq!(result.final_state.acc, 4);
}

#[test]
fn verifier_matches_transformer_for_shipped_programs() {
    let cases = [
        (
            "programs/addition.tvm",
            32,
            1,
            Attention2DMode::AverageHard,
            8,
        ),
        (
            "programs/counter.tvm",
            128,
            3,
            Attention2DMode::AverageHard,
            5,
        ),
        (
            "programs/fibonacci.tvm",
            512,
            4,
            Attention2DMode::AverageHard,
            21,
        ),
        (
            "programs/soft_attention_memory.tvm",
            32,
            2,
            Attention2DMode::HardSoftmax { temperature: 10.0 },
            4,
        ),
        (
            "programs/gemma_block_v1.tvm",
            128,
            3,
            Attention2DMode::AverageHard,
            16,
        ),
        (
            "programs/gemma_block_v2.tvm",
            128,
            3,
            Attention2DMode::AverageHard,
            16,
        ),
        (
            "programs/gemma_block_v3.tvm",
            128,
            3,
            Attention2DMode::AverageHard,
            16,
        ),
    ];

    for (path, max_steps, layers, attention_mode, expected_acc) in cases {
        let source = std::fs::read_to_string(path).expect("fixture");
        let model = ProgramCompiler
            .compile_source(
                &source,
                TransformerVmConfig {
                    num_layers: layers,
                    attention_mode: attention_mode.clone(),
                    ..TransformerVmConfig::default()
                },
            )
            .expect("compile");

        let comparison = verify_model_against_native(model, max_steps).expect("verify");
        assert_eq!(comparison.checked_steps, comparison.transformer.steps);
        assert_eq!(comparison.transformer.final_state.acc, expected_acc);
        assert_eq!(
            comparison.transformer.final_state, comparison.native.final_state,
            "mismatch for {path}"
        );
    }
}
