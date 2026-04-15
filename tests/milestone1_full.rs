#![cfg(all(feature = "burn-model", feature = "onnx-export"))]

use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use std::time::{SystemTime, UNIX_EPOCH};

use assert_cmd::Command;
use burn::backend::NdArray;
use llm_provable_computer::{
    export_program_onnx, load_onnx_program_metadata, verify_engines, Attention2DMode,
    BurnExecutionRuntime, BurnTransformerVm, ExecutionRuntime, MachineState, NativeInterpreter,
    OnnxExecutionRuntime, ProgramCompiler, TransformerVm, TransformerVmConfig,
};
use predicates::prelude::*;
use serde::Deserialize;

type TestBackend = NdArray<f64>;

#[derive(Debug, Deserialize)]
struct PythonValidationReport {
    steps: usize,
    halted: bool,
    final_state: MachineState,
    trace: Vec<MachineState>,
}

#[derive(Debug, Clone)]
struct WorkflowCase {
    path: &'static str,
    program_name: &'static str,
    config: TransformerVmConfig,
    expected_acc: i16,
    max_steps: usize,
}

fn compile_model(source: &str, config: TransformerVmConfig) -> TransformerVm {
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

fn python_command() -> String {
    std::env::var("TVM_PYTHON").unwrap_or_else(|_| "python3".to_string())
}

fn python_validation_available() -> bool {
    StdCommand::new(python_command())
        .arg("-B")
        .arg("-c")
        .arg("import numpy, onnxruntime")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn run_python_validation(
    export_path: &Path,
    program_name: &str,
    expected_acc: i16,
    max_steps: usize,
) -> PythonValidationReport {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/validate_onnx.py");
    let output = StdCommand::new(python_command())
        .arg("-B")
        .arg(script)
        .arg(export_path)
        .arg("--json")
        .arg("--program-name")
        .arg(program_name)
        .arg("--expected-acc")
        .arg(expected_acc.to_string())
        .arg("--expected-halted")
        .arg("true")
        .arg("--max-steps")
        .arg(max_steps.to_string())
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("run python validator");

    if !output.status.success() {
        panic!(
            "python validator failed with status {:?}\nstdout:\n{}\nstderr:\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    serde_json::from_slice(&output.stdout).expect("parse python validator json")
}

fn shipped_workflow_cases() -> Vec<WorkflowCase> {
    vec![
        WorkflowCase {
            path: "programs/addition.tvm",
            program_name: "addition",
            config: TransformerVmConfig::default(),
            expected_acc: 8,
            max_steps: 64,
        },
        WorkflowCase {
            path: "programs/counter.tvm",
            program_name: "counter",
            config: TransformerVmConfig {
                num_layers: 2,
                ..TransformerVmConfig::default()
            },
            expected_acc: 5,
            max_steps: 256,
        },
        WorkflowCase {
            path: "programs/fibonacci.tvm",
            program_name: "fibonacci",
            config: TransformerVmConfig {
                num_layers: 3,
                ..TransformerVmConfig::default()
            },
            expected_acc: 21,
            max_steps: 512,
        },
        WorkflowCase {
            path: "programs/dot_product.tvm",
            program_name: "dot_product",
            config: TransformerVmConfig {
                num_layers: 2,
                ..TransformerVmConfig::default()
            },
            expected_acc: 70,
            max_steps: 128,
        },
        WorkflowCase {
            path: "programs/matmul_2x2.tvm",
            program_name: "matmul_2x2",
            config: TransformerVmConfig {
                num_layers: 2,
                ..TransformerVmConfig::default()
            },
            expected_acc: 134,
            max_steps: 256,
        },
        WorkflowCase {
            path: "programs/single_neuron.tvm",
            program_name: "single_neuron",
            config: TransformerVmConfig {
                num_layers: 2,
                ..TransformerVmConfig::default()
            },
            expected_acc: 1,
            max_steps: 128,
        },
        WorkflowCase {
            path: "programs/memory_roundtrip.tvm",
            program_name: "memory_roundtrip",
            config: TransformerVmConfig {
                num_layers: 2,
                ..TransformerVmConfig::default()
            },
            expected_acc: 42,
            max_steps: 128,
        },
        WorkflowCase {
            path: "programs/multiply.tvm",
            program_name: "multiply",
            config: TransformerVmConfig {
                num_layers: 2,
                ..TransformerVmConfig::default()
            },
            expected_acc: 42,
            max_steps: 256,
        },
        WorkflowCase {
            path: "programs/stack_roundtrip.tvm",
            program_name: "stack_roundtrip",
            config: TransformerVmConfig {
                num_layers: 2,
                ..TransformerVmConfig::default()
            },
            expected_acc: 42,
            max_steps: 128,
        },
        WorkflowCase {
            path: "programs/subroutine_addition.tvm",
            program_name: "subroutine_addition",
            config: TransformerVmConfig {
                num_layers: 2,
                ..TransformerVmConfig::default()
            },
            expected_acc: 42,
            max_steps: 128,
        },
        WorkflowCase {
            path: "programs/soft_attention_memory.tvm",
            program_name: "soft_attention_memory_average_hard",
            config: TransformerVmConfig {
                num_layers: 2,
                ..TransformerVmConfig::default()
            },
            expected_acc: 10,
            max_steps: 64,
        },
        WorkflowCase {
            path: "programs/soft_attention_memory.tvm",
            program_name: "soft_attention_memory_hard_softmax",
            config: TransformerVmConfig {
                num_layers: 2,
                attention_mode: Attention2DMode::HardSoftmax { temperature: 10.0 },
                ..TransformerVmConfig::default()
            },
            expected_acc: 4,
            max_steps: 64,
        },
        WorkflowCase {
            path: "programs/soft_attention_memory.tvm",
            program_name: "soft_attention_memory_softmax",
            config: TransformerVmConfig {
                num_layers: 2,
                attention_mode: Attention2DMode::Softmax,
                ..TransformerVmConfig::default()
            },
            expected_acc: 9,
            max_steps: 64,
        },
    ]
}

#[test]
fn milestone1_shipped_workflows_round_trip_across_all_artifacts_and_engines() {
    let python_available = python_validation_available();
    if !python_available {
        eprintln!(
            "skipping python replay assertions in milestone1_full: numpy and onnxruntime are not installed"
        );
    }

    for case in shipped_workflow_cases() {
        let source = std::fs::read_to_string(case.path).expect("fixture");
        let model = compile_model(&source, case.config.clone());
        let export_dir = unique_temp_dir("milestone1-full");
        let metadata = export_program_onnx(&model, &export_dir).expect("export program");
        let metadata_path = export_dir.join("metadata.json");
        let reloaded = load_onnx_program_metadata(&metadata_path).expect("reload metadata");

        assert_eq!(
            metadata, reloaded,
            "metadata round-trip mismatch for {case:?}"
        );
        assert_eq!(metadata.config, case.config, "config mismatch for {case:?}");
        assert_eq!(
            metadata.instructions.len(),
            model.program().len(),
            "instruction count mismatch for {case:?}"
        );
        assert_eq!(metadata.input_dim, 41, "unexpected input dim for {case:?}");
        assert_eq!(metadata.output_dim, 9, "unexpected output dim for {case:?}");

        for instruction in &metadata.instructions {
            assert!(
                export_dir.join(&instruction.model_file).exists(),
                "missing exported model {} for {case:?}",
                instruction.model_file
            );
            assert!(
                instruction.layer_idx < case.config.num_layers,
                "invalid layer index {} for {case:?}",
                instruction.layer_idx
            );
        }

        let device = Default::default();
        let burn_model =
            BurnTransformerVm::<TestBackend>::from_compiled(&model, &device).expect("burn model");

        let mut transformer = ExecutionRuntime::new(model.clone(), case.max_steps);
        let mut native = NativeInterpreter::new(
            model.program().clone(),
            model.config().attention_mode.clone(),
            case.max_steps,
        );
        let mut burn = BurnExecutionRuntime::new(burn_model, device, case.max_steps);
        let mut onnx =
            OnnxExecutionRuntime::from_export_dir(&metadata_path, case.max_steps).expect("onnx");

        let verification =
            verify_engines(&mut [&mut transformer, &mut native, &mut burn, &mut onnx])
                .expect("verify");

        assert_eq!(
            verification.checked_steps, verification.engines[0].result.steps,
            "checked steps mismatch for {case:?}"
        );

        for engine in &verification.engines {
            assert_eq!(
                engine.result.final_state.acc, case.expected_acc,
                "unexpected final acc for {case:?} in {}",
                engine.name
            );
            assert!(
                engine.result.halted,
                "expected halted execution for {case:?} in {}",
                engine.name
            );
        }

        assert_eq!(
            transformer.trace(),
            native.trace(),
            "transformer/native trace mismatch for {case:?}"
        );
        assert_eq!(
            transformer.trace(),
            burn.trace(),
            "transformer/burn trace mismatch for {case:?}"
        );
        assert_eq!(
            transformer.trace(),
            onnx.trace(),
            "transformer/onnx trace mismatch for {case:?}"
        );
        assert_eq!(
            transformer.events().len(),
            verification.engines[0].result.steps,
            "event count mismatch for {case:?}"
        );

        let transformer_instrs = transformer
            .events()
            .iter()
            .map(|event| event.instruction.to_string())
            .collect::<Vec<_>>();
        let native_instrs = native
            .events()
            .iter()
            .map(|event| event.instruction.to_string())
            .collect::<Vec<_>>();
        let burn_instrs = burn
            .events()
            .iter()
            .map(|event| event.instruction.to_string())
            .collect::<Vec<_>>();
        let onnx_instrs = onnx
            .events()
            .iter()
            .map(|event| event.instruction.to_string())
            .collect::<Vec<_>>();

        assert_eq!(
            transformer_instrs, native_instrs,
            "transformer/native instruction stream mismatch for {case:?}"
        );
        assert_eq!(
            transformer_instrs, burn_instrs,
            "transformer/burn instruction stream mismatch for {case:?}"
        );
        assert_eq!(
            transformer_instrs, onnx_instrs,
            "transformer/onnx instruction stream mismatch for {case:?}"
        );

        if python_available {
            let python_report = run_python_validation(
                &metadata_path,
                case.program_name,
                case.expected_acc,
                case.max_steps,
            );
            assert_eq!(
                python_report.steps, verification.engines[0].result.steps,
                "python steps mismatch for {case:?}"
            );
            assert!(python_report.halted, "python run should halt for {case:?}");
            assert_eq!(
                python_report.final_state, verification.engines[0].result.final_state,
                "python final state mismatch for {case:?}"
            );
            assert_eq!(
                python_report.trace,
                transformer.trace(),
                "python trace mismatch for {case:?}"
            );
        }

        let _ = std::fs::remove_dir_all(export_dir);
    }
}

#[test]
fn milestone1_all_engines_agree_when_execution_stops_at_max_steps() {
    let source = "loop: JMP loop\n";
    let model = compile_model(
        source,
        TransformerVmConfig {
            num_layers: 2,
            ..TransformerVmConfig::default()
        },
    );
    let export_dir = unique_temp_dir("milestone1-max-steps");
    export_program_onnx(&model, &export_dir).expect("export program");
    let metadata_path = export_dir.join("metadata.json");
    let device = Default::default();
    let burn_model =
        BurnTransformerVm::<TestBackend>::from_compiled(&model, &device).expect("burn model");

    let max_steps = 100usize;
    let mut transformer = ExecutionRuntime::new(model.clone(), max_steps);
    let mut native = NativeInterpreter::new(
        model.program().clone(),
        model.config().attention_mode.clone(),
        max_steps,
    );
    let mut burn = BurnExecutionRuntime::new(burn_model, device, max_steps);
    let mut onnx = OnnxExecutionRuntime::from_export_dir(&metadata_path, max_steps).expect("onnx");

    let verification =
        verify_engines(&mut [&mut transformer, &mut native, &mut burn, &mut onnx]).expect("verify");

    assert_eq!(verification.checked_steps, max_steps);
    for engine in &verification.engines {
        assert_eq!(
            engine.result.steps, max_steps,
            "step mismatch in {}",
            engine.name
        );
        assert!(
            !engine.result.halted,
            "infinite loop should stop on max steps, not HALT, in {}",
            engine.name
        );
    }

    assert_eq!(transformer.trace().len(), max_steps + 1);
    assert_eq!(transformer.trace(), native.trace());
    assert_eq!(transformer.trace(), burn.trace());
    assert_eq!(transformer.trace(), onnx.trace());

    let _ = std::fs::remove_dir_all(export_dir);
}

#[test]
fn milestone1_cli_workflow_exports_verifies_and_replays_fibonacci() {
    let export_dir = unique_temp_dir("milestone1-cli");

    Command::cargo_bin("tvm")
        .expect("binary")
        .arg("export-onnx")
        .arg("programs/fibonacci.tvm")
        .arg("-o")
        .arg(&export_dir)
        .arg("--layers")
        .arg("3")
        .assert()
        .success()
        .stdout(predicate::str::contains("instructions:"))
        .stdout(predicate::str::contains("layers: 3"))
        .stdout(predicate::str::contains("attention_mode: average-hard"))
        .stdout(predicate::str::contains("metadata:"));

    let metadata = load_onnx_program_metadata(&export_dir.join("metadata.json")).expect("metadata");
    assert_eq!(metadata.config.num_layers, 3);
    assert_eq!(metadata.config.attention_mode, Attention2DMode::AverageHard);
    assert_eq!(
        metadata.instructions.len(),
        metadata.program.instructions().len()
    );

    Command::cargo_bin("tvm")
        .expect("binary")
        .arg("run")
        .arg("programs/fibonacci.tvm")
        .arg("--layers")
        .arg("3")
        .arg("--verify-all")
        .arg("--trace")
        .assert()
        .success()
        .stdout(predicate::str::contains("engine: transformer"))
        .stdout(predicate::str::contains("verified_all: true"))
        .stdout(predicate::str::contains(
            "verified_all_engines: transformer,native,burn,onnx",
        ))
        .stdout(predicate::str::contains("trace[000] init"))
        .stdout(predicate::str::contains("trace[001]"))
        .stdout(predicate::str::contains("acc: 21"));

    if python_validation_available() {
        let report = run_python_validation(&export_dir.join("metadata.json"), "fibonacci", 21, 512);
        assert!(report.halted);
        assert_eq!(report.final_state.acc, 21);
    } else {
        eprintln!(
            "skipping python replay assertion in milestone1 cli workflow: numpy and onnxruntime are not installed"
        );
    }

    let _ = std::fs::remove_dir_all(export_dir);
}
