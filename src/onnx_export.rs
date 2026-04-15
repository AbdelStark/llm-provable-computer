use std::fs;
use std::path::{Path, PathBuf};

use onnx_protobuf::{
    attribute_proto, tensor_proto, type_proto, AttributeProto, GraphProto, Message, ModelProto,
    NodeProto, OperatorSetIdProto, TensorProto, TensorShapeProto, TypeProto, ValueInfoProto,
};
use protobuf::{EnumOrUnknown, MessageField};
use serde::{Deserialize, Serialize};

use crate::config::TransformerVmConfig;
use crate::error::{Result, VmError};
use crate::instruction::{Instruction, Program};
use crate::model::{
    CompiledInstruction, FeedForwardWeights, MemoryRead, Scalar, TransformerVm, TransitionControls,
    INPUT_DIM, OUTPUT_DIM,
};

pub const ONNX_IR_VERSION: i64 = 9;
pub const ONNX_OPSET_VERSION: i64 = 19;
pub const ONNX_OUTPUT_DIM: usize = 9;

const FORMAT_VERSION: u32 = 1;
const METADATA_FILE_NAME: &str = "metadata.json";

const INPUT_NAME: &str = "input";
const OUTPUT_NAME: &str = "transition";

const IN_ACC: usize = 3;
const IN_ZERO: usize = 4;
const IN_CARRY: usize = 5;
const IN_HALTED: usize = 6;
const IN_OPERAND: usize = 8;

const OUT_RAW_ACC: usize = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OnnxInstructionRead {
    None,
    Direct { address: u8 },
    StackTop,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OnnxInputLayoutEntry {
    pub index: usize,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OnnxInstructionMetadata {
    pub pc: u8,
    pub layer_idx: usize,
    pub instruction: Instruction,
    pub model_file: String,
    pub memory_read: OnnxInstructionRead,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OnnxProgramMetadata {
    pub format_version: u32,
    pub ir_version: i64,
    pub opset_version: i64,
    pub input_dim: usize,
    pub output_dim: usize,
    pub input_encoding: String,
    pub output_encoding: String,
    pub input_layout: Vec<OnnxInputLayoutEntry>,
    pub output_layout: Vec<String>,
    pub config: TransformerVmConfig,
    pub program: Program,
    pub instructions: Vec<OnnxInstructionMetadata>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictOnnxInputLayoutEntry {
    index: usize,
    name: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictOnnxInstructionMetadata {
    pc: u8,
    layer_idx: usize,
    instruction: Instruction,
    model_file: String,
    memory_read: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictTransformerVmConfig {
    d_model: usize,
    num_heads: usize,
    num_layers: usize,
    vocab_size: usize,
    max_seq_len: usize,
    ff_dim: usize,
    attention_mode: crate::config::Attention2DMode,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictProgram {
    instructions: Vec<Instruction>,
    initial_memory: Vec<i16>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictOnnxProgramMetadata {
    format_version: u32,
    ir_version: i64,
    opset_version: i64,
    input_dim: usize,
    output_dim: usize,
    input_encoding: String,
    output_encoding: String,
    input_layout: Vec<StrictOnnxInputLayoutEntry>,
    output_layout: Vec<String>,
    config: StrictTransformerVmConfig,
    program: StrictProgram,
    instructions: Vec<StrictOnnxInstructionMetadata>,
}

impl From<StrictOnnxInputLayoutEntry> for OnnxInputLayoutEntry {
    fn from(value: StrictOnnxInputLayoutEntry) -> Self {
        Self {
            index: value.index,
            name: value.name,
        }
    }
}

impl TryFrom<StrictOnnxInstructionMetadata> for OnnxInstructionMetadata {
    type Error = VmError;

    fn try_from(value: StrictOnnxInstructionMetadata) -> Result<Self> {
        Ok(Self {
            pc: value.pc,
            layer_idx: value.layer_idx,
            instruction: value.instruction,
            model_file: value.model_file,
            memory_read: parse_strict_memory_read(value.memory_read)?,
        })
    }
}

impl From<StrictTransformerVmConfig> for TransformerVmConfig {
    fn from(value: StrictTransformerVmConfig) -> Self {
        Self {
            d_model: value.d_model,
            num_heads: value.num_heads,
            num_layers: value.num_layers,
            vocab_size: value.vocab_size,
            max_seq_len: value.max_seq_len,
            ff_dim: value.ff_dim,
            attention_mode: value.attention_mode,
        }
    }
}

impl StrictProgram {
    fn into_program(self) -> Result<Program> {
        Program::from_parts(self.instructions, self.initial_memory)
            .map_err(|err| VmError::Serialization(err.to_string()))
    }
}

impl StrictOnnxProgramMetadata {
    fn into_runtime_metadata(self) -> Result<OnnxProgramMetadata> {
        Ok(OnnxProgramMetadata {
            format_version: self.format_version,
            ir_version: self.ir_version,
            opset_version: self.opset_version,
            input_dim: self.input_dim,
            output_dim: self.output_dim,
            input_encoding: self.input_encoding,
            output_encoding: self.output_encoding,
            input_layout: self
                .input_layout
                .into_iter()
                .map(OnnxInputLayoutEntry::from)
                .collect(),
            output_layout: self.output_layout,
            config: self.config.into(),
            program: self.program.into_program()?,
            instructions: self
                .instructions
                .into_iter()
                .map(OnnxInstructionMetadata::try_from)
                .collect::<Result<Vec<_>>>()?,
        })
    }
}

fn parse_strict_memory_read(value: serde_json::Value) -> Result<OnnxInstructionRead> {
    let object = value
        .as_object()
        .ok_or_else(|| VmError::Serialization("memory_read must be a JSON object".to_string()))?;
    let kind = object
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| VmError::Serialization("memory_read.kind must be a string".to_string()))?;

    match kind {
        "none" => {
            if object.len() != 1 {
                return Err(VmError::Serialization(
                    "unknown field in memory_read none variant".to_string(),
                ));
            }
            Ok(OnnxInstructionRead::None)
        }
        "stack_top" => {
            if object.len() != 1 {
                return Err(VmError::Serialization(
                    "unknown field in memory_read stack_top variant".to_string(),
                ));
            }
            Ok(OnnxInstructionRead::StackTop)
        }
        "direct" => {
            if object.keys().any(|key| key != "kind" && key != "address") {
                return Err(VmError::Serialization(
                    "unknown field in memory_read direct variant".to_string(),
                ));
            }
            let address = object
                .get("address")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| {
                    VmError::Serialization(
                        "memory_read direct variant requires numeric address".to_string(),
                    )
                })?;
            let address = u8::try_from(address).map_err(|_| {
                VmError::Serialization(
                    "memory_read direct variant address exceeds u8 range".to_string(),
                )
            })?;
            Ok(OnnxInstructionRead::Direct { address })
        }
        _ => Err(VmError::Serialization(format!(
            "unknown memory_read kind `{kind}`"
        ))),
    }
}

pub fn export_program_onnx(
    model: &TransformerVm,
    output_dir: &Path,
) -> Result<OnnxProgramMetadata> {
    fs::create_dir_all(output_dir)?;

    let mut instructions = Vec::with_capacity(model.program().len());
    for pc in 0..model.program().len() {
        let pc_u8 = u8::try_from(pc).map_err(|_| {
            VmError::InvalidConfig(format!(
                "program length {} exceeds u8 pc space",
                model.program().len()
            ))
        })?;
        let dispatch = model.dispatch_info(pc_u8)?;
        let (compiled, layer_idx) = model.compiled_instruction(pc_u8)?;
        let model_file = instruction_model_file(pc);
        let model_path = output_dir.join(&model_file);
        let instruction_model = export_compiled_instruction_onnx(compiled)?;
        write_model(&instruction_model, &model_path)?;

        instructions.push(OnnxInstructionMetadata {
            pc: pc_u8,
            layer_idx,
            instruction: dispatch.instruction,
            model_file,
            memory_read: map_memory_read(compiled.memory_read),
        });
    }

    let metadata = OnnxProgramMetadata {
        format_version: FORMAT_VERSION,
        ir_version: ONNX_IR_VERSION,
        opset_version: ONNX_OPSET_VERSION,
        input_dim: INPUT_DIM,
        output_dim: ONNX_OUTPUT_DIM,
        input_encoding: "machine_input_v1".to_string(),
        output_encoding: "transition_with_flags_v1".to_string(),
        input_layout: input_layout(),
        output_layout: output_layout(),
        config: model.config().clone(),
        program: model.program().clone(),
        instructions,
    };

    let metadata_bytes = serde_json::to_vec_pretty(&metadata)
        .map_err(|err| VmError::Serialization(err.to_string()))?;
    fs::write(metadata_path(output_dir), metadata_bytes)?;

    Ok(metadata)
}

pub fn load_onnx_program_metadata(path: &Path) -> Result<OnnxProgramMetadata> {
    let metadata_path = if path.is_dir() {
        metadata_path(path)
    } else {
        path.to_path_buf()
    };
    let bytes = fs::read(metadata_path)?;
    let metadata: StrictOnnxProgramMetadata =
        serde_json::from_slice(&bytes).map_err(|err| VmError::Serialization(err.to_string()))?;
    let metadata = metadata.into_runtime_metadata()?;
    validate_onnx_program_metadata(&metadata)?;
    Ok(metadata)
}

fn validate_onnx_program_metadata(metadata: &OnnxProgramMetadata) -> Result<()> {
    if metadata.format_version != FORMAT_VERSION {
        return Err(VmError::InvalidConfig(format!(
            "ONNX metadata format_version {} does not match expected {}",
            metadata.format_version, FORMAT_VERSION
        )));
    }
    if metadata.ir_version != ONNX_IR_VERSION {
        return Err(VmError::InvalidConfig(format!(
            "ONNX metadata ir_version {} does not match expected {}",
            metadata.ir_version, ONNX_IR_VERSION
        )));
    }
    if metadata.opset_version != ONNX_OPSET_VERSION {
        return Err(VmError::InvalidConfig(format!(
            "ONNX metadata opset_version {} does not match expected {}",
            metadata.opset_version, ONNX_OPSET_VERSION
        )));
    }
    if metadata.input_dim != INPUT_DIM {
        return Err(VmError::InvalidConfig(format!(
            "ONNX metadata input_dim {} does not match expected {}",
            metadata.input_dim, INPUT_DIM
        )));
    }
    if metadata.output_dim != ONNX_OUTPUT_DIM {
        return Err(VmError::InvalidConfig(format!(
            "ONNX metadata output_dim {} does not match expected {}",
            metadata.output_dim, ONNX_OUTPUT_DIM
        )));
    }
    if metadata.input_encoding != "machine_input_v1" {
        return Err(VmError::InvalidConfig(format!(
            "ONNX metadata input_encoding {} does not match machine_input_v1",
            metadata.input_encoding
        )));
    }
    if metadata.output_encoding != "transition_with_flags_v1" {
        return Err(VmError::InvalidConfig(format!(
            "ONNX metadata output_encoding {} does not match transition_with_flags_v1",
            metadata.output_encoding
        )));
    }
    if metadata.input_layout != input_layout() {
        return Err(VmError::InvalidConfig(
            "ONNX metadata input_layout does not match the machine_input_v1 contract".to_string(),
        ));
    }
    if metadata.output_layout != output_layout() {
        return Err(VmError::InvalidConfig(
            "ONNX metadata output_layout does not match the transition_with_flags_v1 contract"
                .to_string(),
        ));
    }
    if metadata.instructions.len() != metadata.program.len() {
        return Err(VmError::InvalidConfig(format!(
            "ONNX metadata instruction table length {} does not match program length {}",
            metadata.instructions.len(),
            metadata.program.len()
        )));
    }

    for (index, instruction) in metadata.instructions.iter().enumerate() {
        let expected_pc = u8::try_from(index).map_err(|_| {
            VmError::InvalidConfig(format!(
                "ONNX metadata instruction table exceeds u8 pc space at index {}",
                index
            ))
        })?;
        if instruction.pc != expected_pc {
            return Err(VmError::InvalidConfig(format!(
                "ONNX metadata instruction table is misaligned at index {}: found pc {}",
                index, instruction.pc
            )));
        }

        let expected_instruction = metadata.program.instruction_at(expected_pc)?;
        if instruction.instruction != expected_instruction {
            return Err(VmError::InvalidConfig(format!(
                "ONNX metadata instruction table does not match embedded program at pc {}",
                expected_pc
            )));
        }

        let expected_model_file = instruction_model_file(index);
        if instruction.model_file != expected_model_file {
            return Err(VmError::InvalidConfig(format!(
                "ONNX metadata model_file {} does not match expected {} for pc {}",
                instruction.model_file, expected_model_file, expected_pc
            )));
        }
    }

    Ok(())
}

pub(crate) fn export_compiled_instruction_onnx(
    compiled: &CompiledInstruction,
) -> Result<ModelProto> {
    Ok(export_instruction_onnx(
        &compiled.ff_weights,
        &compiled.controls,
    ))
}

fn export_instruction_onnx(
    weights: &FeedForwardWeights,
    controls: &TransitionControls,
) -> ModelProto {
    let ff_dim = weights.gate.rows as i64;
    let mut graph = GraphProto::new();
    graph.name = "transformer_vm_instruction".to_string();
    graph.input.push(tensor_value_info(
        INPUT_NAME,
        &[1, INPUT_DIM as i64],
        tensor_proto::DataType::FLOAT,
    ));
    graph.output.push(tensor_value_info(
        OUTPUT_NAME,
        &[1, ONNX_OUTPUT_DIM as i64],
        tensor_proto::DataType::FLOAT,
    ));

    graph.initializer.push(float_tensor(
        "gate_weight",
        &[INPUT_DIM as i64, ff_dim],
        &transpose_matrix(&weights.gate),
    ));
    graph.initializer.push(float_tensor(
        "gate_bias",
        &[ff_dim],
        &to_f32(&weights.gate_bias),
    ));
    graph.initializer.push(float_tensor(
        "value_weight",
        &[INPUT_DIM as i64, ff_dim],
        &transpose_matrix(&weights.value),
    ));
    graph.initializer.push(float_tensor(
        "value_bias",
        &[ff_dim],
        &to_f32(&weights.value_bias),
    ));
    graph.initializer.push(float_tensor(
        "out_weight",
        &[ff_dim, OUTPUT_DIM as i64],
        &transpose_matrix(&weights.out),
    ));
    graph.initializer.push(float_tensor(
        "out_bias",
        &[OUTPUT_DIM as i64],
        &to_f32(&weights.out_bias),
    ));

    graph
        .initializer
        .push(int64_tensor("idx_acc", &[1], &[IN_ACC as i64]));
    graph
        .initializer
        .push(int64_tensor("idx_zero", &[1], &[IN_ZERO as i64]));
    graph
        .initializer
        .push(int64_tensor("idx_carry", &[1], &[IN_CARRY as i64]));
    graph
        .initializer
        .push(int64_tensor("idx_halted", &[1], &[IN_HALTED as i64]));
    graph
        .initializer
        .push(int64_tensor("idx_operand", &[1], &[IN_OPERAND as i64]));
    graph
        .initializer
        .push(int64_tensor("idx_raw_acc", &[1], &[OUT_RAW_ACC as i64]));

    graph
        .initializer
        .push(int64_tensor("const_modulus", &[1, 1], &[1i64 << 16]));
    graph
        .initializer
        .push(int64_tensor("const_zero_i64", &[1, 1], &[0]));
    graph
        .initializer
        .push(int64_tensor("const_min_i64", &[1, 1], &[i16::MIN as i64]));
    graph
        .initializer
        .push(int64_tensor("const_max_i64", &[1, 1], &[i16::MAX as i64]));
    graph
        .initializer
        .push(float_tensor("const_zero_f32", &[1, 1], &[0.0]));
    graph
        .initializer
        .push(float_tensor("const_threshold", &[1, 1], &[0.5]));

    push_control_initializers(&mut graph, controls);

    graph.node.push(node(
        "gate_matmul",
        "MatMul",
        &[INPUT_NAME, "gate_weight"],
        &["gate_linear"],
        &[],
    ));
    graph.node.push(node(
        "gate_add_bias",
        "Add",
        &["gate_linear", "gate_bias"],
        &["gate_out"],
        &[],
    ));
    graph.node.push(node(
        "value_matmul",
        "MatMul",
        &[INPUT_NAME, "value_weight"],
        &["value_linear"],
        &[],
    ));
    graph.node.push(node(
        "value_add_bias",
        "Add",
        &["value_linear", "value_bias"],
        &["value_out"],
        &[],
    ));
    graph.node.push(node(
        "hidden_mul",
        "Mul",
        &["gate_out", "value_out"],
        &["hidden"],
        &[],
    ));
    graph.node.push(node(
        "out_matmul",
        "MatMul",
        &["hidden", "out_weight"],
        &["transition_linear"],
        &[],
    ));
    graph.node.push(node(
        "out_add_bias",
        "Add",
        &["transition_linear", "out_bias"],
        &["transition_base"],
        &[],
    ));

    push_gather_input(&mut graph, "gather_acc", "idx_acc", "input_acc");
    push_gather_input(&mut graph, "gather_zero", "idx_zero", "input_zero");
    push_gather_input(&mut graph, "gather_carry", "idx_carry", "input_carry");
    push_gather_input(&mut graph, "gather_halted", "idx_halted", "input_halted");
    push_gather_input(&mut graph, "gather_operand", "idx_operand", "input_operand");
    push_gather_output(&mut graph, "gather_raw_acc", "idx_raw_acc", "raw_acc");

    graph.node.push(node(
        "round_raw_acc",
        "Round",
        &["raw_acc"],
        &["raw_acc_rounded"],
        &[],
    ));
    graph.node.push(node(
        "cast_raw_acc_i64",
        "Cast",
        &["raw_acc_rounded"],
        &["raw_acc_i64"],
        &[int_attribute("to", tensor_proto::DataType::INT64 as i64)],
    ));
    graph.node.push(node(
        "mod_wrapped_acc",
        "Mod",
        &["raw_acc_i64", "const_modulus"],
        &["wrapped_acc_mod"],
        &[],
    ));
    graph.node.push(node(
        "result_zero_equal",
        "Equal",
        &["wrapped_acc_mod", "const_zero_i64"],
        &["result_zero_bool"],
        &[],
    ));
    graph.node.push(node(
        "result_zero_cast",
        "Cast",
        &["result_zero_bool"],
        &["result_zero"],
        &[int_attribute("to", tensor_proto::DataType::FLOAT as i64)],
    ));

    graph.node.push(node(
        "overflow_low",
        "Less",
        &["raw_acc_i64", "const_min_i64"],
        &["overflow_low_bool"],
        &[],
    ));
    graph.node.push(node(
        "overflow_high",
        "Greater",
        &["raw_acc_i64", "const_max_i64"],
        &["overflow_high_bool"],
        &[],
    ));
    graph.node.push(node(
        "overflow_low_cast",
        "Cast",
        &["overflow_low_bool"],
        &["overflow_low_f32"],
        &[int_attribute("to", tensor_proto::DataType::FLOAT as i64)],
    ));
    graph.node.push(node(
        "overflow_high_cast",
        "Cast",
        &["overflow_high_bool"],
        &["overflow_high_f32"],
        &[int_attribute("to", tensor_proto::DataType::FLOAT as i64)],
    ));
    graph.node.push(node(
        "overflow_sum",
        "Add",
        &["overflow_low_f32", "overflow_high_f32"],
        &["overflow_flag"],
        &[],
    ));

    graph.node.push(node(
        "compare_rhs_scale",
        "Mul",
        &["input_operand", "carry_rhs_operand_weight"],
        &["compare_rhs_scaled_operand"],
        &[],
    ));
    graph.node.push(node(
        "compare_rhs_add",
        "Add",
        &["compare_rhs_scaled_operand", "carry_rhs_constant"],
        &["compare_rhs"],
        &[],
    ));
    graph.node.push(node(
        "compare_less",
        "Less",
        &["input_acc", "compare_rhs"],
        &["less_than_bool"],
        &[],
    ));
    graph.node.push(node(
        "compare_less_cast",
        "Cast",
        &["less_than_bool"],
        &["less_than_flag"],
        &[int_attribute("to", tensor_proto::DataType::FLOAT as i64)],
    ));

    push_blend_nodes(
        &mut graph,
        "zero",
        &[
            ("input_zero", "zero_prev_weight"),
            ("result_zero", "zero_result_weight"),
        ],
        "zero_constant",
        "zero_flag",
    );
    push_blend_nodes(
        &mut graph,
        "carry",
        &[
            ("input_carry", "carry_prev_weight"),
            ("overflow_flag", "carry_overflow_weight"),
            ("less_than_flag", "carry_less_than_weight"),
        ],
        "carry_constant",
        "carry_flag",
    );
    push_blend_nodes(
        &mut graph,
        "halted",
        &[("input_halted", "halted_prev_weight")],
        "halted_constant",
        "halted_flag",
    );

    graph.node.push(node(
        "concat_transition",
        "Concat",
        &["transition_base", "zero_flag", "carry_flag", "halted_flag"],
        &[OUTPUT_NAME],
        &[int_attribute("axis", 1)],
    ));

    let mut model = ModelProto::new();
    model.ir_version = ONNX_IR_VERSION;
    model.opset_import.push(OperatorSetIdProto {
        domain: String::new(),
        version: ONNX_OPSET_VERSION,
        ..OperatorSetIdProto::new()
    });
    model.producer_name = "llm-provable-computer".to_string();
    model.producer_version = env!("CARGO_PKG_VERSION").to_string();
    model.domain = "com.llm_provable_computer".to_string();
    model.model_version = FORMAT_VERSION as i64;
    model.doc_string =
        "Per-instruction llm-provable-computer feed-forward export with explicit flag outputs"
            .to_string();
    model.graph = MessageField::some(graph);
    model
}

fn push_control_initializers(graph: &mut GraphProto, controls: &TransitionControls) {
    graph.initializer.push(float_tensor(
        "zero_prev_weight",
        &[1, 1],
        &[controls.zero.prev_weight as f32],
    ));
    graph.initializer.push(float_tensor(
        "zero_result_weight",
        &[1, 1],
        &[controls.zero.result_weight as f32],
    ));
    graph.initializer.push(float_tensor(
        "zero_constant",
        &[1, 1],
        &[controls.zero.constant as f32],
    ));

    graph.initializer.push(float_tensor(
        "carry_prev_weight",
        &[1, 1],
        &[controls.carry.prev_weight as f32],
    ));
    graph.initializer.push(float_tensor(
        "carry_overflow_weight",
        &[1, 1],
        &[controls.carry.overflow_weight as f32],
    ));
    graph.initializer.push(float_tensor(
        "carry_less_than_weight",
        &[1, 1],
        &[controls.carry.less_than_weight as f32],
    ));
    graph.initializer.push(float_tensor(
        "carry_constant",
        &[1, 1],
        &[controls.carry.constant as f32],
    ));
    graph.initializer.push(float_tensor(
        "carry_rhs_constant",
        &[1, 1],
        &[controls.carry.rhs_constant as f32],
    ));
    graph.initializer.push(float_tensor(
        "carry_rhs_operand_weight",
        &[1, 1],
        &[controls.carry.rhs_operand_weight as f32],
    ));

    graph.initializer.push(float_tensor(
        "halted_prev_weight",
        &[1, 1],
        &[controls.halted.prev_weight as f32],
    ));
    graph.initializer.push(float_tensor(
        "halted_constant",
        &[1, 1],
        &[controls.halted.constant as f32],
    ));
}

fn push_blend_nodes(
    graph: &mut GraphProto,
    prefix: &str,
    weighted_inputs: &[(&str, &str)],
    constant_name: &str,
    output_name: &str,
) {
    let mut partials = Vec::with_capacity(weighted_inputs.len());
    for (idx, (input_name, weight_name)) in weighted_inputs.iter().enumerate() {
        let partial = format!("{prefix}_weighted_{idx}");
        graph.node.push(node(
            &partial,
            "Mul",
            &[input_name, weight_name],
            &[&partial],
            &[],
        ));
        partials.push(partial);
    }

    let mut accumulator = if let Some(first) = partials.first() {
        first.clone()
    } else {
        "const_zero_f32".to_string()
    };

    for (idx, partial) in partials.iter().skip(1).enumerate() {
        let sum_name = format!("{prefix}_sum_{idx}");
        graph.node.push(node(
            &sum_name,
            "Add",
            &[accumulator.as_str(), partial.as_str()],
            &[&sum_name],
            &[],
        ));
        accumulator = sum_name;
    }

    let blend_name = format!("{prefix}_blend");
    graph.node.push(node(
        &blend_name,
        "Add",
        &[accumulator.as_str(), constant_name],
        &[&blend_name],
        &[],
    ));

    let gt_name = format!("{prefix}_gt_threshold");
    graph.node.push(node(
        &gt_name,
        "Greater",
        &[blend_name.as_str(), "const_threshold"],
        &[&gt_name],
        &[],
    ));
    let eq_name = format!("{prefix}_eq_threshold");
    graph.node.push(node(
        &eq_name,
        "Equal",
        &[blend_name.as_str(), "const_threshold"],
        &[&eq_name],
        &[],
    ));
    let ge_name = format!("{prefix}_ge_threshold");
    graph.node.push(node(
        &ge_name,
        "Or",
        &[gt_name.as_str(), eq_name.as_str()],
        &[&ge_name],
        &[],
    ));
    graph.node.push(node(
        &format!("{prefix}_cast_output"),
        "Cast",
        &[ge_name.as_str()],
        &[output_name],
        &[int_attribute("to", tensor_proto::DataType::FLOAT as i64)],
    ));
}

fn push_gather_input(graph: &mut GraphProto, node_name: &str, index_name: &str, output_name: &str) {
    graph.node.push(node(
        node_name,
        "Gather",
        &[INPUT_NAME, index_name],
        &[output_name],
        &[int_attribute("axis", 1)],
    ));
}

fn push_gather_output(
    graph: &mut GraphProto,
    node_name: &str,
    index_name: &str,
    output_name: &str,
) {
    graph.node.push(node(
        node_name,
        "Gather",
        &["transition_base", index_name],
        &[output_name],
        &[int_attribute("axis", 1)],
    ));
}

fn node(
    name: &str,
    op_type: &str,
    inputs: &[&str],
    outputs: &[&str],
    attributes: &[AttributeProto],
) -> NodeProto {
    NodeProto {
        name: name.to_string(),
        op_type: op_type.to_string(),
        input: inputs.iter().map(|value| (*value).to_string()).collect(),
        output: outputs.iter().map(|value| (*value).to_string()).collect(),
        attribute: attributes.to_vec(),
        ..NodeProto::new()
    }
}

fn int_attribute(name: &str, value: i64) -> AttributeProto {
    AttributeProto {
        name: name.to_string(),
        type_: EnumOrUnknown::new(attribute_proto::AttributeType::INT),
        i: value,
        ..AttributeProto::new()
    }
}

fn tensor_value_info(
    name: &str,
    dims: &[i64],
    data_type: tensor_proto::DataType,
) -> ValueInfoProto {
    let mut shape = TensorShapeProto::new();
    shape.dim = dims
        .iter()
        .map(|dim| {
            let mut shape_dim = onnx_protobuf::tensor_shape_proto::Dimension::new();
            shape_dim.set_dim_value(*dim);
            shape_dim
        })
        .collect();

    let mut tensor_type = type_proto::Tensor::new();
    tensor_type.elem_type = data_type as i32;
    tensor_type.shape = MessageField::some(shape);

    let mut info_type = TypeProto::new();
    info_type.set_tensor_type(tensor_type);

    ValueInfoProto {
        name: name.to_string(),
        type_: MessageField::some(info_type),
        ..ValueInfoProto::new()
    }
}

fn float_tensor(name: &str, dims: &[i64], values: &[f32]) -> TensorProto {
    TensorProto {
        name: name.to_string(),
        dims: dims.to_vec(),
        data_type: tensor_proto::DataType::FLOAT as i32,
        float_data: values.to_vec(),
        ..TensorProto::new()
    }
}

fn int64_tensor(name: &str, dims: &[i64], values: &[i64]) -> TensorProto {
    TensorProto {
        name: name.to_string(),
        dims: dims.to_vec(),
        data_type: tensor_proto::DataType::INT64 as i32,
        int64_data: values.to_vec(),
        ..TensorProto::new()
    }
}

fn transpose_matrix(matrix: &crate::model::Matrix) -> Vec<f32> {
    let mut transposed = vec![0.0f32; matrix.rows * matrix.cols];
    for row in 0..matrix.rows {
        for col in 0..matrix.cols {
            transposed[col * matrix.rows + row] = matrix.data[row * matrix.cols + col] as f32;
        }
    }
    transposed
}

fn to_f32(values: &[Scalar]) -> Vec<f32> {
    values.iter().map(|value| *value as f32).collect()
}

fn map_memory_read(read: MemoryRead) -> OnnxInstructionRead {
    match read {
        MemoryRead::None => OnnxInstructionRead::None,
        MemoryRead::Direct(address) => OnnxInstructionRead::Direct { address },
        MemoryRead::StackTop => OnnxInstructionRead::StackTop,
    }
}

fn write_model(model: &ModelProto, path: &Path) -> Result<()> {
    let bytes = model
        .write_to_bytes()
        .map_err(|err| VmError::Onnx(err.to_string()))?;
    fs::write(path, bytes)?;
    Ok(())
}

fn instruction_model_file(pc: usize) -> String {
    format!("instr_{pc}.onnx")
}

fn metadata_path(output_dir: &Path) -> PathBuf {
    output_dir.join(METADATA_FILE_NAME)
}

fn input_layout() -> Vec<OnnxInputLayoutEntry> {
    let mut layout = vec![
        OnnxInputLayoutEntry {
            index: 0,
            name: "const".to_string(),
        },
        OnnxInputLayoutEntry {
            index: 1,
            name: "pc".to_string(),
        },
        OnnxInputLayoutEntry {
            index: 2,
            name: "pc_next".to_string(),
        },
        OnnxInputLayoutEntry {
            index: 3,
            name: "acc".to_string(),
        },
        OnnxInputLayoutEntry {
            index: 4,
            name: "zero_flag".to_string(),
        },
        OnnxInputLayoutEntry {
            index: 5,
            name: "carry_flag".to_string(),
        },
        OnnxInputLayoutEntry {
            index: 6,
            name: "halted".to_string(),
        },
        OnnxInputLayoutEntry {
            index: 7,
            name: "sp".to_string(),
        },
        OnnxInputLayoutEntry {
            index: 8,
            name: "operand".to_string(),
        },
    ];

    for bit in 0..16 {
        layout.push(OnnxInputLayoutEntry {
            index: 9 + bit,
            name: format!("acc_bit_{bit}"),
        });
    }
    for bit in 0..16 {
        layout.push(OnnxInputLayoutEntry {
            index: 25 + bit,
            name: format!("operand_bit_{bit}"),
        });
    }
    layout
}

fn output_layout() -> Vec<String> {
    [
        "next_pc",
        "raw_acc",
        "next_sp",
        "mem_write_enable",
        "mem_write_addr",
        "mem_write_value",
        "zero_flag",
        "carry_flag",
        "halted",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use tract_onnx::prelude::{
        tvec, Framework, InferenceModelExt, RunOptions, Tensor, TypedRunnableModel,
    };

    use super::*;
    use crate::compiler::ProgramCompiler;
    use crate::config::TransformerVmConfig;
    use crate::memory::AddressedMemory;
    use crate::model::{
        build_input_vector, transition_from_output, InstructionCompiler, MemoryRead,
    };
    use crate::state::MachineState;

    fn unique_temp_dir(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("llm-provable-computer-{name}-{suffix}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn instruction_cases() -> Vec<Instruction> {
        vec![
            Instruction::Nop,
            Instruction::LoadImmediate(-7),
            Instruction::Load(2),
            Instruction::Store(3),
            Instruction::Push,
            Instruction::Pop,
            Instruction::AddImmediate(5),
            Instruction::AddMemory(1),
            Instruction::SubImmediate(4),
            Instruction::SubMemory(2),
            Instruction::MulImmediate(-3),
            Instruction::MulMemory(1),
            Instruction::AndImmediate(0b1010),
            Instruction::AndMemory(2),
            Instruction::OrImmediate(0b0101),
            Instruction::OrMemory(3),
            Instruction::XorImmediate(0b1111),
            Instruction::XorMemory(0),
            Instruction::CmpImmediate(8),
            Instruction::CmpMemory(1),
            Instruction::Call(5),
            Instruction::Ret,
            Instruction::Jump(7),
            Instruction::JumpIfZero(4),
            Instruction::JumpIfNotZero(6),
            Instruction::Halt,
        ]
    }

    fn sample_exported_program_metadata(name: &str) -> (PathBuf, OnnxProgramMetadata) {
        let source = fs::read_to_string("programs/addition.tvm").expect("fixture");
        let model = ProgramCompiler
            .compile_source(&source, TransformerVmConfig::default())
            .expect("compile model");
        let export_dir = unique_temp_dir(name);
        let metadata = export_program_onnx(&model, &export_dir).expect("export program");
        (export_dir, metadata)
    }

    fn overwrite_metadata(export_dir: &Path, metadata: &OnnxProgramMetadata) {
        let bytes = serde_json::to_vec_pretty(metadata).expect("serialize metadata");
        fs::write(metadata_path(export_dir), bytes).expect("write metadata");
    }

    fn overwrite_metadata_json(export_dir: &Path, metadata: &serde_json::Value) {
        let bytes = serde_json::to_vec_pretty(metadata).expect("serialize metadata json");
        fs::write(metadata_path(export_dir), bytes).expect("write metadata");
    }

    fn load_plan(path: &Path) -> Arc<TypedRunnableModel> {
        tract_onnx::onnx()
            .model_for_path(path)
            .expect("load onnx")
            .into_optimized()
            .expect("optimize onnx")
            .into_runnable_with_options(&RunOptions::default())
            .expect("build runnable")
    }

    fn run_plan(plan: &Arc<TypedRunnableModel>, input: &[f32]) -> Vec<f32> {
        let input_tensor = Tensor::from_shape(&[1, input.len()], input).expect("input tensor");
        let outputs = plan.run(tvec!(input_tensor.into())).expect("run plan");
        outputs[0]
            .to_array_view::<f32>()
            .expect("output tensor")
            .iter()
            .copied()
            .collect()
    }

    #[test]
    fn exported_instruction_models_match_native_transition_semantics() {
        let config = TransformerVmConfig::default();
        let compiler = InstructionCompiler::new(&config).expect("compiler");
        let state = MachineState {
            pc: 3,
            acc: 19,
            sp: 4,
            zero_flag: false,
            carry_flag: true,
            halted: false,
            memory: vec![11, 22, 33, 44, 55, 66, 77, 88],
        };
        let mut memory = AddressedMemory::from_initial(&state.memory);
        memory.store(2, 99, 1).expect("store");
        memory.store(3, -17, 2).expect("store");

        let temp_dir = unique_temp_dir("onnx-instruction");
        let model_path = temp_dir.join("instruction.onnx");

        for instruction in instruction_cases() {
            let compiled = compiler
                .compile_instruction(instruction)
                .expect("compile instruction");
            let model = export_compiled_instruction_onnx(&compiled).expect("export instruction");
            write_model(&model, &model_path).expect("write onnx file");
            let plan = load_plan(&model_path);

            let operand = match compiled.memory_read {
                MemoryRead::None => 0,
                MemoryRead::Direct(address) => memory
                    .load_with_mode(address, &config.attention_mode)
                    .expect("memory read"),
                MemoryRead::StackTop => memory
                    .load_with_mode(state.sp, &config.attention_mode)
                    .expect("stack read"),
            };

            let input = build_input_vector(&state, operand);
            let onnx_output = run_plan(
                &plan,
                &input.iter().map(|value| *value as f32).collect::<Vec<_>>(),
            );
            let native_output = compiled.ff_weights.evaluate(&input);
            let native_transition =
                transition_from_output(&state, operand, &compiled.controls, &native_output);

            assert_eq!(
                onnx_output.len(),
                ONNX_OUTPUT_DIM,
                "instruction={instruction}"
            );
            assert_eq!(
                onnx_output[0].round() as i64,
                native_transition.pc,
                "pc mismatch for {instruction}"
            );
            assert_eq!(
                onnx_output[1].round() as i64 as i16,
                native_transition.acc,
                "acc mismatch for {instruction}"
            );
            assert_eq!(
                onnx_output[2].round() as i64,
                native_transition.sp,
                "sp mismatch for {instruction}"
            );
            assert_eq!(
                onnx_output[6] >= 0.5,
                native_transition.zero_flag,
                "zero mismatch for {instruction}"
            );
            assert_eq!(
                onnx_output[7] >= 0.5,
                native_transition.carry_flag,
                "carry mismatch for {instruction}"
            );
            assert_eq!(
                onnx_output[8] >= 0.5,
                native_transition.halted,
                "halt mismatch for {instruction}"
            );

            let onnx_memory_write = (onnx_output[3] >= 0.5).then(|| {
                (
                    onnx_output[4].round() as i64,
                    onnx_output[5].round() as i64 as i16,
                )
            });
            assert_eq!(
                onnx_memory_write, native_transition.memory_write,
                "memory write mismatch for {instruction}"
            );
        }

        let _ = fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn load_onnx_program_metadata_rejects_wrong_format_version() {
        let (export_dir, mut metadata) = sample_exported_program_metadata("onnx-metadata-format");
        metadata.format_version = metadata.format_version.saturating_add(1);
        overwrite_metadata(&export_dir, &metadata);

        let err = load_onnx_program_metadata(&export_dir)
            .expect_err("wrong metadata format version should fail");
        assert!(
            err.to_string().contains("format_version"),
            "unexpected error: {err}"
        );

        let _ = fs::remove_dir_all(export_dir);
    }

    #[test]
    fn load_onnx_program_metadata_rejects_input_contract_drift() {
        let (export_dir, mut metadata) =
            sample_exported_program_metadata("onnx-metadata-input-contract");
        metadata.input_layout[0].name = "tampered-input".to_string();
        overwrite_metadata(&export_dir, &metadata);

        let err =
            load_onnx_program_metadata(&export_dir).expect_err("input contract drift should fail");
        assert!(
            err.to_string().contains("input_layout"),
            "unexpected error: {err}"
        );

        let _ = fs::remove_dir_all(export_dir);
    }

    #[test]
    fn load_onnx_program_metadata_rejects_output_contract_drift() {
        let (export_dir, mut metadata) =
            sample_exported_program_metadata("onnx-metadata-output-contract");
        metadata.output_layout[0] = "tampered-output".to_string();
        overwrite_metadata(&export_dir, &metadata);

        let err =
            load_onnx_program_metadata(&export_dir).expect_err("output contract drift should fail");
        assert!(
            err.to_string().contains("output_layout"),
            "unexpected error: {err}"
        );

        let _ = fs::remove_dir_all(export_dir);
    }

    #[test]
    fn load_onnx_program_metadata_rejects_instruction_table_instruction_drift() {
        let (export_dir, mut metadata) =
            sample_exported_program_metadata("onnx-metadata-instruction-drift");
        let original = metadata.instructions[0].instruction;
        metadata.instructions[0].instruction = if original == Instruction::Halt {
            Instruction::Nop
        } else {
            Instruction::Halt
        };
        overwrite_metadata(&export_dir, &metadata);

        let err = load_onnx_program_metadata(&export_dir)
            .expect_err("instruction-table drift should fail");
        assert!(
            err.to_string()
                .contains("instruction table does not match embedded program"),
            "unexpected error: {err}"
        );

        let _ = fs::remove_dir_all(export_dir);
    }

    #[test]
    fn load_onnx_program_metadata_rejects_model_path_escape() {
        let (export_dir, mut metadata) =
            sample_exported_program_metadata("onnx-metadata-model-path");
        metadata.instructions[0].model_file = "../escape.onnx".to_string();
        overwrite_metadata(&export_dir, &metadata);

        let err =
            load_onnx_program_metadata(&export_dir).expect_err("path escape should fail to load");
        assert!(
            err.to_string().contains("model_file"),
            "unexpected error: {err}"
        );

        let _ = fs::remove_dir_all(export_dir);
    }

    #[test]
    fn load_onnx_program_metadata_rejects_unknown_top_level_field() {
        let (export_dir, metadata) = sample_exported_program_metadata("onnx-metadata-extra-top");
        let mut metadata_json = serde_json::to_value(metadata).expect("metadata to json");
        metadata_json
            .as_object_mut()
            .expect("metadata object")
            .insert(
                "unexpected_field".to_string(),
                serde_json::Value::Bool(true),
            );
        overwrite_metadata_json(&export_dir, &metadata_json);

        let err = load_onnx_program_metadata(&export_dir)
            .expect_err("unknown top-level metadata field should fail");
        assert!(
            err.to_string().contains("unknown field"),
            "unexpected error: {err}"
        );

        let _ = fs::remove_dir_all(export_dir);
    }

    #[test]
    fn load_onnx_program_metadata_rejects_unknown_nested_config_field() {
        let (export_dir, metadata) =
            sample_exported_program_metadata("onnx-metadata-extra-config-field");
        let mut metadata_json = serde_json::to_value(metadata).expect("metadata to json");
        metadata_json["config"]["unexpected_field"] = serde_json::json!(7);
        overwrite_metadata_json(&export_dir, &metadata_json);

        let err = load_onnx_program_metadata(&export_dir)
            .expect_err("unknown nested config field should fail");
        assert!(
            err.to_string().contains("unknown field"),
            "unexpected error: {err}"
        );

        let _ = fs::remove_dir_all(export_dir);
    }

    #[test]
    fn load_onnx_program_metadata_rejects_unknown_nested_program_field() {
        let (export_dir, metadata) =
            sample_exported_program_metadata("onnx-metadata-extra-program-field");
        let mut metadata_json = serde_json::to_value(metadata).expect("metadata to json");
        metadata_json["program"]["unexpected_field"] = serde_json::json!(7);
        overwrite_metadata_json(&export_dir, &metadata_json);

        let err = load_onnx_program_metadata(&export_dir)
            .expect_err("unknown nested program field should fail");
        assert!(
            err.to_string().contains("unknown field"),
            "unexpected error: {err}"
        );

        let _ = fs::remove_dir_all(export_dir);
    }

    #[test]
    fn load_onnx_program_metadata_rejects_unknown_nested_memory_read_field() {
        let (export_dir, metadata) =
            sample_exported_program_metadata("onnx-metadata-extra-memory-read-field");
        let mut metadata_json = serde_json::to_value(metadata).expect("metadata to json");
        metadata_json["instructions"][0]["memory_read"]["unexpected_field"] = serde_json::json!(7);
        overwrite_metadata_json(&export_dir, &metadata_json);

        let err = load_onnx_program_metadata(&export_dir)
            .expect_err("unknown nested memory_read field should fail");
        assert!(
            err.to_string().contains("unknown field"),
            "unexpected error: {err}"
        );

        let _ = fs::remove_dir_all(export_dir);
    }

    #[test]
    fn load_onnx_program_metadata_rejects_unknown_direct_memory_read_field() {
        let (export_dir, metadata) =
            sample_exported_program_metadata("onnx-metadata-direct-memory-read-extra-field");
        let mut metadata_json = serde_json::to_value(metadata).expect("metadata to json");
        metadata_json["instructions"][0]["memory_read"] = serde_json::json!({
            "kind": "direct",
            "address": 0,
            "unexpected_field": 7
        });
        overwrite_metadata_json(&export_dir, &metadata_json);

        let err = load_onnx_program_metadata(&export_dir)
            .expect_err("unknown direct memory_read field should fail");
        assert!(
            err.to_string()
                .contains("unknown field in memory_read direct variant"),
            "unexpected error: {err}"
        );

        let _ = fs::remove_dir_all(export_dir);
    }

    #[test]
    fn load_onnx_program_metadata_rejects_missing_direct_memory_read_address() {
        let (export_dir, metadata) =
            sample_exported_program_metadata("onnx-metadata-direct-memory-read-missing-address");
        let mut metadata_json = serde_json::to_value(metadata).expect("metadata to json");
        metadata_json["instructions"][0]["memory_read"] = serde_json::json!({
            "kind": "direct"
        });
        overwrite_metadata_json(&export_dir, &metadata_json);

        let err = load_onnx_program_metadata(&export_dir)
            .expect_err("missing direct memory_read address should fail");
        assert!(
            err.to_string()
                .contains("memory_read direct variant requires numeric address"),
            "unexpected error: {err}"
        );

        let _ = fs::remove_dir_all(export_dir);
    }

    #[test]
    fn load_onnx_program_metadata_maps_runtime_conversion_failures_to_serialization() {
        let (export_dir, metadata) =
            sample_exported_program_metadata("onnx-metadata-oversized-memory");
        let mut metadata_json = serde_json::to_value(metadata).expect("metadata to json");
        metadata_json["program"]["initial_memory"] =
            serde_json::Value::Array((0..256).map(|_| serde_json::json!(0)).collect());
        overwrite_metadata_json(&export_dir, &metadata_json);

        let err = load_onnx_program_metadata(&export_dir)
            .expect_err("oversized initial memory should fail");
        assert!(
            matches!(err, VmError::Serialization(_)),
            "unexpected error variant: {err:?}"
        );

        let _ = fs::remove_dir_all(export_dir);
    }
}
