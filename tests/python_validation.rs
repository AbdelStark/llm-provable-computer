#![cfg(feature = "onnx-export")]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use llm_provable_computer::{
    export_program_onnx, MachineState, NativeInterpreter, ProgramCompiler, TransformerVm,
    TransformerVmConfig,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct PythonValidationReport {
    steps: usize,
    halted: bool,
    final_state: MachineState,
    trace: Vec<MachineState>,
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
    Command::new(python_command())
        .arg("-B")
        .arg("-c")
        .arg("import numpy, onnxruntime")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn run_python_validation(
    export_dir: &Path,
    program_name: &str,
    expected_acc: i16,
    max_steps: usize,
) -> PythonValidationReport {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/validate_onnx.py");
    let output = Command::new(python_command())
        .arg("-B")
        .arg(script)
        .arg(export_dir)
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

#[test]
fn python_validator_matches_native_trace_for_shipped_programs() {
    if !python_validation_available() {
        eprintln!("skipping python validation test: numpy and onnxruntime are not installed");
        return;
    }

    for (path, config, program_name, expected_acc, max_steps, use_metadata_path) in [
        (
            "programs/addition.tvm",
            TransformerVmConfig::default(),
            "addition",
            8i16,
            64usize,
            false,
        ),
        (
            "programs/counter.tvm",
            TransformerVmConfig {
                num_layers: 2,
                ..TransformerVmConfig::default()
            },
            "counter",
            5i16,
            256usize,
            false,
        ),
        (
            "programs/fibonacci.tvm",
            TransformerVmConfig {
                num_layers: 3,
                ..TransformerVmConfig::default()
            },
            "fibonacci",
            21i16,
            512usize,
            false,
        ),
        (
            "programs/dot_product.tvm",
            TransformerVmConfig {
                num_layers: 2,
                ..TransformerVmConfig::default()
            },
            "dot_product",
            70i16,
            128usize,
            false,
        ),
        (
            "programs/matmul_2x2.tvm",
            TransformerVmConfig {
                num_layers: 2,
                ..TransformerVmConfig::default()
            },
            "matmul_2x2",
            134i16,
            256usize,
            false,
        ),
        (
            "programs/single_neuron.tvm",
            TransformerVmConfig {
                num_layers: 2,
                ..TransformerVmConfig::default()
            },
            "single_neuron",
            1i16,
            128usize,
            false,
        ),
        (
            "programs/memory_roundtrip.tvm",
            TransformerVmConfig {
                num_layers: 2,
                ..TransformerVmConfig::default()
            },
            "memory_roundtrip",
            42i16,
            128usize,
            true,
        ),
        (
            "programs/multiply.tvm",
            TransformerVmConfig {
                num_layers: 2,
                ..TransformerVmConfig::default()
            },
            "multiply",
            42i16,
            256usize,
            false,
        ),
        (
            "programs/stack_roundtrip.tvm",
            TransformerVmConfig {
                num_layers: 2,
                ..TransformerVmConfig::default()
            },
            "stack_roundtrip",
            42i16,
            128usize,
            true,
        ),
        (
            "programs/subroutine_addition.tvm",
            TransformerVmConfig {
                num_layers: 2,
                ..TransformerVmConfig::default()
            },
            "subroutine_addition",
            42i16,
            128usize,
            false,
        ),
        (
            "programs/soft_attention_memory.tvm",
            TransformerVmConfig {
                num_layers: 2,
                ..TransformerVmConfig::default()
            },
            "soft_attention_memory_average_hard",
            10i16,
            64usize,
            true,
        ),
        (
            "programs/soft_attention_memory.tvm",
            TransformerVmConfig {
                num_layers: 2,
                attention_mode: llm_provable_computer::Attention2DMode::HardSoftmax {
                    temperature: 10.0,
                },
                ..TransformerVmConfig::default()
            },
            "soft_attention_memory_hard_softmax",
            4i16,
            64usize,
            false,
        ),
        (
            "programs/soft_attention_memory.tvm",
            TransformerVmConfig {
                num_layers: 2,
                attention_mode: llm_provable_computer::Attention2DMode::Softmax,
                ..TransformerVmConfig::default()
            },
            "soft_attention_memory_softmax",
            9i16,
            64usize,
            true,
        ),
    ] {
        let source = std::fs::read_to_string(path).expect("fixture");
        let model = compile_model(&source, config);
        let export_dir = unique_temp_dir("python-validation");
        export_program_onnx(&model, &export_dir).expect("export program");
        let validation_path = if use_metadata_path {
            export_dir.join("metadata.json")
        } else {
            export_dir.clone()
        };
        let mut native = NativeInterpreter::new(
            model.program().clone(),
            model.config().attention_mode.clone(),
            max_steps,
        );
        let native_result = native.run().expect("run native interpreter");
        let python_report =
            run_python_validation(&validation_path, program_name, expected_acc, max_steps);

        assert_eq!(
            python_report.steps, native_result.steps,
            "steps mismatch for {path}"
        );
        assert_eq!(
            python_report.halted, native_result.halted,
            "halted mismatch for {path}"
        );
        assert_eq!(
            python_report.final_state, native_result.final_state,
            "final state mismatch for {path}"
        );
        assert_eq!(
            python_report.trace,
            native.trace(),
            "trace mismatch for {path}"
        );

        let _ = std::fs::remove_dir_all(export_dir);
    }
}

#[test]
fn python_validator_reports_expectation_mismatch() {
    if !python_validation_available() {
        eprintln!("skipping python validation test: numpy and onnxruntime are not installed");
        return;
    }

    let source = std::fs::read_to_string("programs/addition.tvm").expect("fixture");
    let model = compile_model(&source, TransformerVmConfig::default());
    let export_dir = unique_temp_dir("python-validation-mismatch");
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/validate_onnx.py");
    export_program_onnx(&model, &export_dir).expect("export program");

    let output = Command::new(python_command())
        .arg("-B")
        .arg(script)
        .arg(export_dir.join("metadata.json"))
        .arg("--program-name")
        .arg("addition")
        .arg("--expected-acc")
        .arg("99")
        .arg("--expected-halted")
        .arg("true")
        .arg("--max-steps")
        .arg("64")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .output()
        .expect("run python validator");

    assert!(
        !output.status.success(),
        "validator should fail when expectations are wrong"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("expected ACC=99, got 8"),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let _ = std::fs::remove_dir_all(export_dir);
}
