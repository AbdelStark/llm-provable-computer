//! End-to-end tests: parse → compile → execute → verify for complete programs.
//!
//! Every test runs the full pipeline through both the transformer model and
//! the native interpreter, then compares results.

use llm_provable_computer::{
    parse_program, verify_model_against_native, Attention2DMode, ExecutionRuntime, MachineState,
    NativeInterpreter, ProgramCompiler, TransformerVmConfig,
};

fn run_program(source: &str, max_steps: usize) -> MachineState {
    let model = ProgramCompiler
        .compile_source(source, TransformerVmConfig::default())
        .expect("compile");
    let mut runtime = ExecutionRuntime::new(model, max_steps);
    let result = runtime.run().expect("run");
    result.final_state
}

fn run_and_verify(source: &str, max_steps: usize, layers: usize) -> MachineState {
    let config = TransformerVmConfig {
        num_layers: layers,
        ..TransformerVmConfig::default()
    };
    let model = ProgramCompiler
        .compile_source(source, config)
        .expect("compile");
    let comparison = verify_model_against_native(model, max_steps).expect("verify");
    assert_eq!(
        comparison.transformer.final_state, comparison.native.final_state,
        "transformer and native diverged"
    );
    comparison.transformer.final_state
}

// --- Shipped programs ---

#[test]
fn e2e_addition_program() {
    let source = std::fs::read_to_string("programs/addition.tvm").expect("fixture");
    let state = run_and_verify(&source, 32, 1);
    assert!(state.halted);
    assert_eq!(state.acc, 8);
}

#[test]
fn e2e_counter_program() {
    let source = std::fs::read_to_string("programs/counter.tvm").expect("fixture");
    let state = run_and_verify(&source, 128, 2);
    assert!(state.halted);
    assert_eq!(state.acc, 5);
    assert_eq!(state.memory[0], 5);
}

#[test]
fn e2e_fibonacci_program() {
    let source = std::fs::read_to_string("programs/fibonacci.tvm").expect("fixture");
    let state = run_and_verify(&source, 512, 3);
    assert!(state.halted);
    assert_eq!(state.acc, 21, "Fibonacci(8) = 21");
}

#[test]
fn e2e_factorial_recursive_program() {
    let source = std::fs::read_to_string("programs/factorial_recursive.tvm").expect("fixture");
    let state = run_and_verify(&source, 128, 2);
    assert!(state.halted);
    assert_eq!(state.acc, 120, "5! = 120");
    assert_eq!(
        state.sp, 11,
        "stack pointer restored after recursion unwinds"
    );
}

#[test]
fn e2e_multiply_program() {
    let source = std::fs::read_to_string("programs/multiply.tvm").expect("fixture");
    let state = run_and_verify(&source, 256, 2);
    assert!(state.halted);
    assert_eq!(state.acc, 42, "6 * 7 = 42");
}

#[test]
fn e2e_dot_product_program() {
    let source = std::fs::read_to_string("programs/dot_product.tvm").expect("fixture");
    let state = run_and_verify(&source, 128, 2);
    assert!(state.halted);
    assert_eq!(state.acc, 70, "dot([1,2,3,4],[5,6,7,8]) = 70");
    assert_eq!(state.memory[9], 70, "result persisted in memory");
}

#[test]
fn e2e_matmul_2x2_program() {
    let source = std::fs::read_to_string("programs/matmul_2x2.tvm").expect("fixture");
    let state = run_and_verify(&source, 256, 2);
    assert!(state.halted);
    assert_eq!(state.acc, 134, "sum(C) = 134 for deterministic 2x2 matmul");
    assert_eq!(state.memory[8], 19);
    assert_eq!(state.memory[9], 22);
    assert_eq!(state.memory[10], 43);
    assert_eq!(state.memory[11], 50);
}

#[test]
fn e2e_single_neuron_program() {
    let source = std::fs::read_to_string("programs/single_neuron.tvm").expect("fixture");
    let state = run_and_verify(&source, 128, 2);
    assert!(state.halted);
    assert_eq!(state.acc, 1, "neuron activation should fire");
    assert_eq!(state.memory[7], 20, "pre-activation weighted sum");
}

#[test]
fn e2e_subroutine_addition() {
    let source = std::fs::read_to_string("programs/subroutine_addition.tvm").expect("fixture");
    let state = run_and_verify(&source, 32, 1);
    assert!(state.halted);
    assert_eq!(state.acc, 42);
    assert_eq!(state.sp, 8);
}

#[test]
fn e2e_stack_roundtrip() {
    let source = std::fs::read_to_string("programs/stack_roundtrip.tvm").expect("fixture");
    let state = run_and_verify(&source, 32, 1);
    assert!(state.halted);
    assert_eq!(state.acc, 42);
    assert_eq!(state.sp, 8);
}

#[test]
fn e2e_memory_roundtrip() {
    let source = std::fs::read_to_string("programs/memory_roundtrip.tvm").expect("fixture");
    let state = run_and_verify(&source, 32, 1);
    assert!(state.halted);
    assert_eq!(state.acc, 42);
}

// --- Soft attention programs ---

#[test]
fn e2e_soft_attention_average_hard() {
    let source = std::fs::read_to_string("programs/soft_attention_memory.tvm").expect("fixture");
    let model = ProgramCompiler
        .compile_source(
            &source,
            TransformerVmConfig {
                attention_mode: Attention2DMode::AverageHard,
                ..TransformerVmConfig::default()
            },
        )
        .expect("compile");
    let comparison = verify_model_against_native(model, 32).expect("verify");
    assert_eq!(comparison.transformer.final_state.acc, 10);
}

#[test]
fn e2e_soft_attention_softmax() {
    let source = std::fs::read_to_string("programs/soft_attention_memory.tvm").expect("fixture");
    let model = ProgramCompiler
        .compile_source(
            &source,
            TransformerVmConfig {
                attention_mode: Attention2DMode::Softmax,
                ..TransformerVmConfig::default()
            },
        )
        .expect("compile");
    let comparison = verify_model_against_native(model, 32).expect("verify");
    assert_eq!(comparison.transformer.final_state.acc, 9);
}

#[test]
fn e2e_soft_attention_hard_softmax() {
    let source = std::fs::read_to_string("programs/soft_attention_memory.tvm").expect("fixture");
    let model = ProgramCompiler
        .compile_source(
            &source,
            TransformerVmConfig {
                attention_mode: Attention2DMode::HardSoftmax { temperature: 10.0 },
                ..TransformerVmConfig::default()
            },
        )
        .expect("compile");
    let comparison = verify_model_against_native(model, 32).expect("verify");
    assert_eq!(comparison.transformer.final_state.acc, 4);
}

// --- Individual instruction E2E ---

#[test]
fn e2e_each_arithmetic_instruction() {
    let cases = [
        ("LOADI 100\nADD 50\nHALT\n", 150),
        ("LOADI 100\nSUB 30\nHALT\n", 70),
        ("LOADI 6\nMUL 7\nHALT\n", 42),
        ("LOADI -5\nADD 5\nHALT\n", 0),
        ("LOADI 0\nSUB 1\nHALT\n", -1),
    ];

    for (source, expected_acc) in cases {
        let state = run_and_verify(source, 16, 1);
        assert!(state.halted);
        assert_eq!(state.acc, expected_acc, "failed for: {source}");
    }
}

#[test]
fn e2e_each_bitwise_instruction() {
    let cases = [
        ("LOADI 15\nAND 9\nHALT\n", 9),  // 0b1111 & 0b1001 = 0b1001
        ("LOADI 5\nOR 10\nHALT\n", 15),  // 0b0101 | 0b1010 = 0b1111
        ("LOADI 15\nXOR 9\nHALT\n", 6),  // 0b1111 ^ 0b1001 = 0b0110
        ("LOADI 255\nAND 0\nHALT\n", 0), // anything & 0 = 0
        ("LOADI 0\nOR 42\nHALT\n", 42),  // 0 | x = x
        ("LOADI 42\nXOR 42\nHALT\n", 0), // x ^ x = 0
    ];

    for (source, expected_acc) in cases {
        let state = run_and_verify(source, 16, 1);
        assert!(state.halted);
        assert_eq!(state.acc, expected_acc, "failed for: {source}");
    }
}

#[test]
fn e2e_each_memory_instruction() {
    let source = r#"
        .memory 4
        .init 0 100
        LOADI 42
        STORE 1
        LOAD 0
        ADDM 1
        HALT
    "#;
    let state = run_and_verify(source, 16, 1);
    assert!(state.halted);
    assert_eq!(state.acc, 142, "100 + 42");
    assert_eq!(state.memory[1], 42);
}

#[test]
fn e2e_memory_arithmetic_instructions() {
    let source = r#"
        .memory 4
        .init 0 10
        .init 1 3
        .init 2 5
        LOAD 0
        SUBM 1
        MULM 2
        HALT
    "#;
    let state = run_and_verify(source, 16, 1);
    assert!(state.halted);
    assert_eq!(state.acc, 35, "(10 - 3) * 5 = 35");
}

#[test]
fn e2e_each_branch_instruction() {
    // JZ takes branch
    let state = run_program("LOADI 0\nJZ 3\nLOADI 99\nHALT\n", 16);
    assert_eq!(state.acc, 0);

    // JZ falls through
    let state = run_program("LOADI 1\nJZ 3\nLOADI 99\nHALT\n", 16);
    assert_eq!(state.acc, 99);

    // JNZ takes branch
    let state = run_program("LOADI 1\nJNZ 3\nLOADI 99\nHALT\n", 16);
    assert_eq!(state.acc, 1);

    // JNZ falls through
    let state = run_program("LOADI 0\nJNZ 3\nLOADI 99\nHALT\n", 16);
    assert_eq!(state.acc, 99);
}

#[test]
fn e2e_cmp_sets_flags_correctly() {
    // acc < value: carry=true, zero=false
    let source = "LOADI 5\nCMP 10\nHALT\n";
    let state = run_and_verify(source, 16, 1);
    assert!(state.carry_flag, "5 < 10 should set carry");
    assert!(!state.zero_flag);
    assert_eq!(state.acc, -5, "CMP stores difference");

    // acc == value: carry=false, zero=true
    let source = "LOADI 10\nCMP 10\nHALT\n";
    let state = run_and_verify(source, 16, 1);
    assert!(!state.carry_flag);
    assert!(state.zero_flag);

    // acc > value: carry=false, zero=false
    let source = "LOADI 10\nCMP 5\nHALT\n";
    let state = run_and_verify(source, 16, 1);
    assert!(!state.carry_flag, "10 > 5 should not set carry");
    assert!(!state.zero_flag);
}

#[test]
fn e2e_cmpm_with_memory_operand() {
    let source = r#"
        .memory 2
        .init 0 50
        LOADI 50
        CMPM 0
        HALT
    "#;
    let state = run_and_verify(source, 16, 1);
    assert!(state.zero_flag);
    assert!(!state.carry_flag);
    assert_eq!(state.acc, 0);
}

// --- Edge cases ---

#[test]
fn e2e_single_halt() {
    let state = run_and_verify("HALT\n", 16, 1);
    assert!(state.halted);
    assert_eq!(state.acc, 0);
    assert_eq!(state.pc, 0);
}

#[test]
fn e2e_nop_then_halt() {
    let state = run_and_verify("NOP\nNOP\nNOP\nHALT\n", 16, 1);
    assert!(state.halted);
    assert_eq!(state.acc, 0);
    assert_eq!(state.pc, 3);
}

#[test]
fn e2e_overflow_wraps_and_sets_carry() {
    let state = run_and_verify("LOADI 32767\nADD 1\nHALT\n", 16, 1);
    assert!(state.halted);
    assert_eq!(state.acc, i16::MIN);
    assert!(state.carry_flag);
}

#[test]
fn e2e_underflow_wraps_and_sets_carry() {
    let state = run_and_verify("LOADI -32768\nSUB 1\nHALT\n", 16, 1);
    assert!(state.halted);
    assert_eq!(state.acc, i16::MAX);
    assert!(state.carry_flag);
}

#[test]
fn e2e_max_steps_stops_infinite_loop() {
    let source = "loop: JMP loop\n";
    let model = ProgramCompiler
        .compile_source(source, TransformerVmConfig::default())
        .expect("compile");
    let mut runtime = ExecutionRuntime::new(model, 100);
    let result = runtime.run().expect("run");
    assert!(!result.halted);
    assert_eq!(result.steps, 100);
}

// --- Multi-layer tests ---

#[test]
fn e2e_multi_layer_fibonacci() {
    let source = std::fs::read_to_string("programs/fibonacci.tvm").expect("fixture");
    for layers in 1..=4 {
        let state = run_and_verify(&source, 512, layers);
        assert!(state.halted, "layers={layers}");
        assert_eq!(state.acc, 21, "Fibonacci(8) with {layers} layers");
    }
}

#[test]
fn e2e_multi_layer_multiply() {
    let source = std::fs::read_to_string("programs/multiply.tvm").expect("fixture");
    for layers in 1..=3 {
        let state = run_and_verify(&source, 256, layers);
        assert!(state.halted, "layers={layers}");
        assert_eq!(state.acc, 42, "6*7 with {layers} layers");
    }
}

// --- Complex programs ---

#[test]
fn e2e_sum_array() {
    // Sum memory[0..4] = 10 + 20 + 30 + 40 = 100
    let source = r#"
        .memory 8
        .init 0 10
        .init 1 20
        .init 2 30
        .init 3 40
        .init 4 0
        .init 5 4

        LOADI 0
        STORE 4
        LOADI 0
    loop:
        LOAD 4
        SUBM 5
        JZ done
        LOAD 4
        ADDM 4
        STORE 4
        ; This approach won't work for generic array sum due to computed addresses.
        ; Instead, just sum them inline.
        JMP done
    done:
        LOAD 0
        ADDM 1
        ADDM 2
        ADDM 3
        HALT
    "#;
    let state = run_and_verify(source, 64, 2);
    assert!(state.halted);
    assert_eq!(state.acc, 100);
}

#[test]
fn e2e_absolute_value() {
    // Compute abs(-42)
    let source = r#"
        LOADI -42
        CMP 0
        JZ done
        ; acc now holds -42 - 0 = -42
        ; If carry was set (acc < 0 as signed), negate by MUL -1
        MUL -1
    done:
        HALT
    "#;
    let state = run_and_verify(source, 16, 1);
    assert!(state.halted);
    assert_eq!(state.acc, 42);
}

#[test]
fn e2e_nested_subroutines() {
    let source = r#"
        .memory 8
        LOADI 0
        CALL add_ten
        CALL add_ten
        CALL add_ten
        HALT
    add_ten:
        ADD 10
        RET
    "#;
    let state = run_and_verify(source, 32, 2);
    assert!(state.halted);
    assert_eq!(state.acc, 30);
    assert_eq!(state.sp, 8, "stack pointer restored after all calls");
}

#[test]
fn e2e_bitwise_memory_ops() {
    let source = r#"
        .memory 4
        .init 0 255
        .init 1 15
        .init 2 170
        LOADI 170
        ANDM 1
        HALT
    "#;
    let state = run_and_verify(source, 16, 1);
    assert!(state.halted);
    assert_eq!(state.acc, 10, "0b10101010 & 0b00001111 = 0b00001010");
}

#[test]
fn e2e_xor_swap() {
    // XOR swap: a ^= b; b ^= a; a ^= b
    let source = r#"
        .memory 2
        .init 0 42
        .init 1 99
        LOAD 0
        XORM 1
        STORE 0
        LOAD 1
        XORM 0
        STORE 1
        LOAD 0
        XORM 1
        STORE 0
        HALT
    "#;
    let state = run_and_verify(source, 32, 2);
    assert!(state.halted);
    assert_eq!(state.memory[0], 99, "values should be swapped");
    assert_eq!(state.memory[1], 42, "values should be swapped");
}

// --- Determinism tests ---

#[test]
fn e2e_repeated_execution_is_deterministic() {
    let source = std::fs::read_to_string("programs/fibonacci.tvm").expect("fixture");

    let results: Vec<_> = (0..5)
        .map(|_| {
            let model = ProgramCompiler
                .compile_source(&source, TransformerVmConfig::default())
                .expect("compile");
            let mut runtime = ExecutionRuntime::new(model, 512);
            runtime.run().expect("run")
        })
        .collect();

    for result in &results[1..] {
        assert_eq!(result.final_state, results[0].final_state);
        assert_eq!(result.steps, results[0].steps);
    }
}

// --- Trace completeness ---

#[test]
fn e2e_trace_has_one_entry_per_step() {
    let source = "LOADI 1\nADD 2\nSUB 1\nHALT\n";
    let model = ProgramCompiler
        .compile_source(source, TransformerVmConfig::default())
        .expect("compile");
    let mut runtime = ExecutionRuntime::new(model, 16);
    let result = runtime.run().expect("run");

    assert_eq!(result.steps, 4);
    assert_eq!(runtime.events().len(), 4, "one event per step");
    assert_eq!(runtime.trace().len(), 5, "initial + one per step");

    // First trace entry is initial state
    assert_eq!(runtime.trace()[0].pc, 0);
    assert_eq!(runtime.trace()[0].acc, 0);
}

#[test]
fn e2e_native_trace_has_one_entry_per_step() {
    let source = "LOADI 1\nADD 2\nHALT\n";
    let program = parse_program(source).expect("parse");
    let mut interpreter = NativeInterpreter::new(program, Attention2DMode::AverageHard, 16);
    let result = interpreter.run().expect("run");

    assert_eq!(result.steps, 3);
    assert_eq!(interpreter.events().len(), 3);
    assert_eq!(interpreter.trace().len(), 4);
}

// --- Error propagation ---

#[test]
fn e2e_parse_error_propagates() {
    let result = ProgramCompiler.compile_source("INVALID_OP 42\n", TransformerVmConfig::default());
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("unknown instruction"));
}

#[test]
fn e2e_runtime_propagates_pc_out_of_bounds() {
    let source = "JMP 100\n";
    let model = ProgramCompiler
        .compile_source(source, TransformerVmConfig::default())
        .expect("compile");
    let mut runtime = ExecutionRuntime::new(model, 16);
    let err = runtime.run().expect_err("should fail on OOB jump");
    assert!(err.to_string().contains("out of bounds"));
}
