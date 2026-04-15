#![cfg(feature = "onnx-export")]

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "burn-model")]
use burn::backend::NdArray;
use llm_provable_computer::{
    export_program_onnx, load_onnx_program_metadata, verify_engines, Attention2DMode,
    ExecutionRuntime, NativeInterpreter, OnnxExecutionRuntime, ProgramCompiler,
    TransformerVmConfig,
};

#[cfg(feature = "burn-model")]
use llm_provable_computer::{BurnExecutionRuntime, BurnTransformerVm};

#[cfg(feature = "burn-model")]
type TestBackend = NdArray<f64>;

fn compile_model(
    source: &str,
    config: TransformerVmConfig,
) -> llm_provable_computer::TransformerVm {
    ProgramCompiler
        .compile_source(source, config)
        .expect("compile model")
}

fn unique_temp_dir(name: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("llm-provable-computer-{name}-{suffix}"));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn shipped_cases() -> Vec<(&'static str, TransformerVmConfig, usize)> {
    vec![
        ("programs/addition.tvm", TransformerVmConfig::default(), 64),
        ("programs/counter.tvm", TransformerVmConfig::default(), 256),
        (
            "programs/fibonacci.tvm",
            TransformerVmConfig::default(),
            512,
        ),
        (
            "programs/memory_roundtrip.tvm",
            TransformerVmConfig::default(),
            128,
        ),
        (
            "programs/dot_product.tvm",
            TransformerVmConfig::default(),
            128,
        ),
        (
            "programs/matmul_2x2.tvm",
            TransformerVmConfig::default(),
            256,
        ),
        (
            "programs/single_neuron.tvm",
            TransformerVmConfig::default(),
            128,
        ),
        ("programs/multiply.tvm", TransformerVmConfig::default(), 256),
        (
            "programs/stack_roundtrip.tvm",
            TransformerVmConfig::default(),
            128,
        ),
        (
            "programs/subroutine_addition.tvm",
            TransformerVmConfig::default(),
            128,
        ),
        (
            "programs/soft_attention_memory.tvm",
            TransformerVmConfig::default(),
            64,
        ),
        (
            "programs/soft_attention_memory.tvm",
            TransformerVmConfig {
                attention_mode: Attention2DMode::HardSoftmax { temperature: 10.0 },
                ..TransformerVmConfig::default()
            },
            64,
        ),
        (
            "programs/soft_attention_memory.tvm",
            TransformerVmConfig {
                attention_mode: Attention2DMode::Softmax,
                ..TransformerVmConfig::default()
            },
            64,
        ),
    ]
}

#[test]
fn exported_program_metadata_includes_execution_contract() {
    let source = std::fs::read_to_string("programs/fibonacci.tvm").expect("fixture");
    let model = compile_model(&source, TransformerVmConfig::default());
    let export_dir = unique_temp_dir("onnx-metadata");

    let metadata = export_program_onnx(&model, &export_dir).expect("export program");
    let reloaded = load_onnx_program_metadata(&export_dir).expect("reload metadata");

    assert_eq!(metadata, reloaded);
    assert_eq!(metadata.input_dim, 41);
    assert_eq!(metadata.output_dim, 9);
    assert_eq!(
        metadata.program.instructions().len(),
        metadata.instructions.len()
    );
    assert_eq!(metadata.input_layout.len(), metadata.input_dim);
    assert_eq!(metadata.output_layout.len(), metadata.output_dim);
    assert!(export_dir.join("metadata.json").exists());
    assert!(export_dir.join("instr_0.onnx").exists());
    assert_eq!(metadata.instructions[0].pc, 0);
    assert_eq!(metadata.instructions[0].model_file, "instr_0.onnx");

    let _ = std::fs::remove_dir_all(export_dir);
}

#[test]
fn onnx_runtime_matches_transformer_and_native_for_shipped_programs() {
    for (path, config, max_steps) in shipped_cases() {
        let source = std::fs::read_to_string(path).expect("fixture");
        let model = compile_model(&source, config.clone());
        let export_dir = unique_temp_dir("onnx-shipped");
        export_program_onnx(&model, &export_dir).expect("export program");

        let mut transformer = ExecutionRuntime::new(model.clone(), max_steps);
        let mut native = NativeInterpreter::new(
            model.program().clone(),
            model.config().attention_mode.clone(),
            max_steps,
        );
        let mut onnx =
            OnnxExecutionRuntime::from_export_dir(&export_dir, max_steps).expect("onnx runtime");

        let verification =
            verify_engines(&mut [&mut transformer, &mut native, &mut onnx]).expect("verify");

        assert_eq!(
            verification.engines[0].result.final_state, verification.engines[1].result.final_state,
            "transformer/native mismatch for {path}"
        );
        assert_eq!(
            verification.engines[0].result.final_state, verification.engines[2].result.final_state,
            "transformer/onnx mismatch for {path}"
        );

        let _ = std::fs::remove_dir_all(export_dir);
    }
}

#[test]
fn onnx_runtime_matches_long_counter_trace() {
    let source = r#"
        .memory 4
        .init 1 2000

        LOADI 0
        STORE 0
    loop:
        LOAD 0
        ADD 1
        STORE 0
        LOAD 0
        SUBM 1
        JZ done
        JMP loop
    done:
        LOAD 0
        HALT
    "#;
    let config = TransformerVmConfig {
        num_layers: 2,
        ..TransformerVmConfig::default()
    };
    let max_steps = 15_000;
    let model = compile_model(source, config);
    let export_dir = unique_temp_dir("onnx-long-trace");
    export_program_onnx(&model, &export_dir).expect("export program");

    let mut transformer = ExecutionRuntime::new(model.clone(), max_steps);
    let mut native = NativeInterpreter::new(
        model.program().clone(),
        model.config().attention_mode.clone(),
        max_steps,
    );
    let mut onnx =
        OnnxExecutionRuntime::from_export_dir(&export_dir, max_steps).expect("onnx runtime");

    let verification =
        verify_engines(&mut [&mut transformer, &mut native, &mut onnx]).expect("verify");

    assert!(verification.checked_steps > 10_000);
    assert_eq!(verification.engines[0].result.final_state.acc, 2000);
    assert_eq!(
        verification.engines[0].result.final_state,
        verification.engines[2].result.final_state
    );

    let _ = std::fs::remove_dir_all(export_dir);
}

#[cfg(feature = "burn-model")]
#[test]
fn onnx_runtime_matches_native_transformer_and_burn_for_shipped_programs() {
    for (path, config, max_steps) in [
        (
            "programs/addition.tvm",
            TransformerVmConfig::default(),
            64usize,
        ),
        (
            "programs/counter.tvm",
            TransformerVmConfig::default(),
            256usize,
        ),
        (
            "programs/fibonacci.tvm",
            TransformerVmConfig::default(),
            512usize,
        ),
        (
            "programs/memory_roundtrip.tvm",
            TransformerVmConfig::default(),
            128usize,
        ),
        (
            "programs/dot_product.tvm",
            TransformerVmConfig::default(),
            128usize,
        ),
        (
            "programs/matmul_2x2.tvm",
            TransformerVmConfig::default(),
            256usize,
        ),
        (
            "programs/single_neuron.tvm",
            TransformerVmConfig::default(),
            128usize,
        ),
        (
            "programs/multiply.tvm",
            TransformerVmConfig::default(),
            256usize,
        ),
        (
            "programs/stack_roundtrip.tvm",
            TransformerVmConfig::default(),
            128usize,
        ),
        (
            "programs/subroutine_addition.tvm",
            TransformerVmConfig::default(),
            128usize,
        ),
        (
            "programs/soft_attention_memory.tvm",
            TransformerVmConfig {
                attention_mode: Attention2DMode::HardSoftmax { temperature: 10.0 },
                ..TransformerVmConfig::default()
            },
            64usize,
        ),
    ] {
        let source = std::fs::read_to_string(path).expect("fixture");
        let model = compile_model(&source, config.clone());
        let export_dir = unique_temp_dir("onnx-four-way");
        export_program_onnx(&model, &export_dir).expect("export program");

        let device = Default::default();
        let burn_model =
            BurnTransformerVm::<TestBackend>::from_compiled(&model, &device).expect("burn model");

        let mut transformer = ExecutionRuntime::new(model.clone(), max_steps);
        let mut native = NativeInterpreter::new(
            model.program().clone(),
            model.config().attention_mode.clone(),
            max_steps,
        );
        let mut burn = BurnExecutionRuntime::new(burn_model, device, max_steps);
        let mut onnx =
            OnnxExecutionRuntime::from_export_dir(&export_dir, max_steps).expect("onnx runtime");

        let verification =
            verify_engines(&mut [&mut transformer, &mut native, &mut burn, &mut onnx])
                .expect("verify");

        for engine in &verification.engines[1..] {
            assert_eq!(
                verification.engines[0].result.final_state, engine.result.final_state,
                "state mismatch for {path} in {}",
                engine.name
            );
        }

        let _ = std::fs::remove_dir_all(export_dir);
    }
}
