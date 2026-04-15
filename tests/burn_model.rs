#![cfg(feature = "burn-model")]

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use burn::backend::NdArray;
use llm_provable_computer::{
    load_burn_model, parse_program, save_burn_model, verify_engines, Attention2DMode,
    BurnExecutionRuntime, BurnTransformerVm, ExecutionRuntime, NativeInterpreter, ProgramCompiler,
    TransformerVmConfig,
};

type TestBackend = NdArray<f64>;

fn compile_native_model(
    source: &str,
    config: TransformerVmConfig,
) -> llm_provable_computer::TransformerVm {
    ProgramCompiler
        .compile_source(source, config)
        .expect("compile program")
}

fn compile_burn_model(
    source: &str,
    config: TransformerVmConfig,
) -> (
    llm_provable_computer::TransformerVm,
    BurnTransformerVm<TestBackend>,
) {
    let device = Default::default();
    let native = compile_native_model(source, config);
    let burn = BurnTransformerVm::<TestBackend>::from_compiled(&native, &device).expect("burn");
    (native, burn)
}

fn unique_temp_base(name: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!("llm-provable-computer-{name}-{suffix}"))
}

#[test]
fn burn_runtime_executes_addition_program() {
    let device = Default::default();
    let source = std::fs::read_to_string("programs/addition.tvm").expect("fixture");
    let (_, burn) = compile_burn_model(&source, TransformerVmConfig::default());
    let mut runtime = BurnExecutionRuntime::new(burn, device, 32);

    let result = runtime.run().expect("burn run");

    assert!(result.halted);
    assert_eq!(result.final_state.acc, 8);
}

#[test]
fn burn_verifies_against_native_engines_for_shipped_programs() {
    let cases = [
        (
            "programs/addition.tvm",
            32,
            TransformerVmConfig::default(),
            8,
        ),
        (
            "programs/counter.tvm",
            128,
            TransformerVmConfig::default(),
            5,
        ),
        (
            "programs/fibonacci.tvm",
            512,
            TransformerVmConfig::default(),
            21,
        ),
        (
            "programs/dot_product.tvm",
            128,
            TransformerVmConfig::default(),
            70,
        ),
        (
            "programs/matmul_2x2.tvm",
            256,
            TransformerVmConfig::default(),
            134,
        ),
        (
            "programs/single_neuron.tvm",
            128,
            TransformerVmConfig::default(),
            1,
        ),
        (
            "programs/multiply.tvm",
            256,
            TransformerVmConfig::default(),
            42,
        ),
        (
            "programs/subroutine_addition.tvm",
            64,
            TransformerVmConfig::default(),
            42,
        ),
        (
            "programs/soft_attention_memory.tvm",
            32,
            TransformerVmConfig {
                attention_mode: Attention2DMode::HardSoftmax { temperature: 10.0 },
                ..TransformerVmConfig::default()
            },
            4,
        ),
    ];

    for (path, max_steps, config, expected_acc) in cases {
        let device = Default::default();
        let source = std::fs::read_to_string(path).expect("fixture");
        let native_model = compile_native_model(&source, config.clone());
        let burn_model =
            BurnTransformerVm::<TestBackend>::from_compiled(&native_model, &device).expect("burn");
        let mut transformer = ExecutionRuntime::new(native_model.clone(), max_steps);
        let mut native = NativeInterpreter::new(
            native_model.program().clone(),
            native_model.config().attention_mode.clone(),
            max_steps,
        );
        let mut burn = BurnExecutionRuntime::new(burn_model, device, max_steps);

        let verification =
            verify_engines(&mut [&mut transformer, &mut native, &mut burn]).expect("verify");

        for engine in &verification.engines {
            assert_eq!(engine.result.final_state.acc, expected_acc, "path={path}");
            assert_eq!(
                engine.result.final_state, verification.engines[0].result.final_state,
                "state mismatch for {path} in {}",
                engine.name
            );
        }
    }
}

#[test]
fn burn_model_round_trips_via_save_and_load() {
    let device = Default::default();
    let source = std::fs::read_to_string("programs/fibonacci.tvm").expect("fixture");
    let native = compile_native_model(&source, TransformerVmConfig::default());
    let burn = BurnTransformerVm::<TestBackend>::from_compiled(&native, &device).expect("burn");
    let path = unique_temp_base("burn-roundtrip");

    save_burn_model(&burn, &path).expect("save burn model");
    let loaded = load_burn_model::<TestBackend>(&path).expect("load burn model");
    let mut runtime = BurnExecutionRuntime::new(loaded, device, 512);
    let result = runtime.run().expect("loaded burn run");

    assert!(result.halted);
    assert_eq!(result.final_state.acc, 21);

    let _ = std::fs::remove_file(path.with_extension("mpk"));
    let _ = std::fs::remove_file(path.with_extension("json"));
}

#[test]
fn burn_model_can_be_built_from_parsed_program() {
    let source = std::fs::read_to_string("programs/addition.tvm").expect("fixture");
    let program = parse_program(&source).expect("parse");
    let device = Default::default();
    let burn = BurnTransformerVm::<TestBackend>::from_program(
        TransformerVmConfig::default(),
        program,
        &device,
    )
    .expect("from_program");
    let mut runtime = BurnExecutionRuntime::new(burn, device, 32);

    let result = runtime.run().expect("run");
    assert_eq!(result.final_state.acc, 8);
}
