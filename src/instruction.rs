use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::{Result, VmError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Instruction {
    Nop,
    LoadImmediate(i16),
    Load(u8),
    Store(u8),
    Push,
    Pop,
    AddImmediate(i16),
    AddMemory(u8),
    SubImmediate(i16),
    SubMemory(u8),
    MulImmediate(i16),
    MulMemory(u8),
    AndImmediate(i16),
    AndMemory(u8),
    OrImmediate(i16),
    OrMemory(u8),
    XorImmediate(i16),
    XorMemory(u8),
    CmpImmediate(i16),
    CmpMemory(u8),
    Call(u8),
    Ret,
    Jump(u8),
    JumpIfZero(u8),
    JumpIfNotZero(u8),
    Halt,
}

impl Instruction {
    pub fn mnemonic(&self) -> &'static str {
        match self {
            Instruction::Nop => "NOP",
            Instruction::LoadImmediate(_) => "LOADI",
            Instruction::Load(_) => "LOAD",
            Instruction::Store(_) => "STORE",
            Instruction::Push => "PUSH",
            Instruction::Pop => "POP",
            Instruction::AddImmediate(_) => "ADD",
            Instruction::AddMemory(_) => "ADDM",
            Instruction::SubImmediate(_) => "SUB",
            Instruction::SubMemory(_) => "SUBM",
            Instruction::MulImmediate(_) => "MUL",
            Instruction::MulMemory(_) => "MULM",
            Instruction::AndImmediate(_) => "AND",
            Instruction::AndMemory(_) => "ANDM",
            Instruction::OrImmediate(_) => "OR",
            Instruction::OrMemory(_) => "ORM",
            Instruction::XorImmediate(_) => "XOR",
            Instruction::XorMemory(_) => "XORM",
            Instruction::CmpImmediate(_) => "CMP",
            Instruction::CmpMemory(_) => "CMPM",
            Instruction::Call(_) => "CALL",
            Instruction::Ret => "RET",
            Instruction::Jump(_) => "JMP",
            Instruction::JumpIfZero(_) => "JZ",
            Instruction::JumpIfNotZero(_) => "JNZ",
            Instruction::Halt => "HALT",
        }
    }
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Instruction::Nop
            | Instruction::Push
            | Instruction::Pop
            | Instruction::Ret
            | Instruction::Halt => f.write_str(self.mnemonic()),
            Instruction::LoadImmediate(value)
            | Instruction::AddImmediate(value)
            | Instruction::SubImmediate(value)
            | Instruction::MulImmediate(value)
            | Instruction::AndImmediate(value)
            | Instruction::OrImmediate(value)
            | Instruction::XorImmediate(value)
            | Instruction::CmpImmediate(value) => write!(f, "{} {}", self.mnemonic(), value),
            Instruction::Load(address)
            | Instruction::Store(address)
            | Instruction::AddMemory(address)
            | Instruction::SubMemory(address)
            | Instruction::MulMemory(address)
            | Instruction::AndMemory(address)
            | Instruction::OrMemory(address)
            | Instruction::XorMemory(address)
            | Instruction::CmpMemory(address)
            | Instruction::Call(address)
            | Instruction::Jump(address)
            | Instruction::JumpIfZero(address)
            | Instruction::JumpIfNotZero(address) => {
                write!(f, "{} {}", self.mnemonic(), address)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Program {
    instructions: Vec<Instruction>,
    initial_memory: Vec<i16>,
}

impl Program {
    fn validate_memory_size(memory_size: usize) -> Result<()> {
        if memory_size > usize::from(u8::MAX) {
            return Err(VmError::InvalidConfig(format!(
                "memory size {} exceeds the encoded stack/address limit of {} cells",
                memory_size,
                u8::MAX
            )));
        }
        Ok(())
    }

    pub fn new(instructions: Vec<Instruction>, memory_size: usize) -> Self {
        Self {
            instructions,
            initial_memory: vec![0; memory_size],
        }
    }

    pub fn from_parts(instructions: Vec<Instruction>, initial_memory: Vec<i16>) -> Result<Self> {
        Self::validate_memory_size(initial_memory.len())?;
        Ok(Self {
            instructions,
            initial_memory,
        })
    }

    pub fn with_initial_memory(mut self, initial_memory: Vec<i16>) -> Result<Self> {
        Self::validate_memory_size(initial_memory.len())?;
        if initial_memory.len() != self.initial_memory.len() {
            return Err(VmError::InvalidConfig(format!(
                "initial memory length {} does not match configured memory size {}",
                initial_memory.len(),
                self.initial_memory.len()
            )));
        }
        self.initial_memory = initial_memory;
        Ok(self)
    }

    pub fn instruction_at(&self, pc: u8) -> Result<Instruction> {
        self.instructions
            .get(pc as usize)
            .copied()
            .ok_or(VmError::ProgramCounterOutOfBounds {
                pc: pc as usize,
                len: self.instructions.len(),
            })
    }

    pub fn instructions(&self) -> &[Instruction] {
        &self.instructions
    }

    pub fn len(&self) -> usize {
        self.instructions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }

    pub fn memory_size(&self) -> usize {
        self.initial_memory.len()
    }

    pub fn initial_memory(&self) -> &[i16] {
        &self.initial_memory
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn program_new_stores_instructions_and_memory() {
        let program = Program::new(vec![Instruction::Nop, Instruction::Halt], 4);
        assert_eq!(program.len(), 2);
        assert!(!program.is_empty());
        assert_eq!(program.memory_size(), 4);
        assert_eq!(program.initial_memory(), &[0, 0, 0, 0]);
    }

    #[test]
    fn program_empty() {
        let program = Program::new(vec![], 2);
        assert!(program.is_empty());
        assert_eq!(program.len(), 0);
    }

    #[test]
    fn instruction_at_returns_correct_instruction() {
        let program = Program::new(
            vec![
                Instruction::Nop,
                Instruction::AddImmediate(5),
                Instruction::Halt,
            ],
            4,
        );
        assert_eq!(program.instruction_at(0).unwrap(), Instruction::Nop);
        assert_eq!(
            program.instruction_at(1).unwrap(),
            Instruction::AddImmediate(5)
        );
        assert_eq!(program.instruction_at(2).unwrap(), Instruction::Halt);
    }

    #[test]
    fn instruction_at_out_of_bounds_returns_error() {
        let program = Program::new(vec![Instruction::Halt], 2);
        let err = program.instruction_at(1).unwrap_err();
        assert!(err.to_string().contains("out of bounds"));
    }

    #[test]
    fn with_initial_memory_sets_values() {
        let program = Program::new(vec![Instruction::Halt], 3)
            .with_initial_memory(vec![10, 20, 30])
            .unwrap();
        assert_eq!(program.initial_memory(), &[10, 20, 30]);
    }

    #[test]
    fn with_initial_memory_rejects_size_mismatch() {
        let err = Program::new(vec![Instruction::Halt], 3)
            .with_initial_memory(vec![1, 2])
            .unwrap_err();
        assert!(err.to_string().contains("does not match"));
    }

    #[test]
    fn with_initial_memory_rejects_exceeding_u8_max() {
        let err = Program::new(vec![Instruction::Halt], 256)
            .with_initial_memory(vec![0; 256])
            .unwrap_err();
        assert!(err.to_string().contains("encoded stack/address limit"));
    }

    #[test]
    fn from_parts_sets_values() {
        let program = Program::from_parts(vec![Instruction::Halt], vec![10, 20, 30]).unwrap();
        assert_eq!(program.initial_memory(), &[10, 20, 30]);
    }

    #[test]
    fn from_parts_rejects_exceeding_u8_max() {
        let err = Program::from_parts(vec![Instruction::Halt], vec![0; 256]).unwrap_err();
        assert!(err.to_string().contains("encoded stack/address limit"));
    }

    #[test]
    fn mnemonic_returns_correct_string_for_each_variant() {
        let cases: Vec<(Instruction, &str)> = vec![
            (Instruction::Nop, "NOP"),
            (Instruction::LoadImmediate(0), "LOADI"),
            (Instruction::Load(0), "LOAD"),
            (Instruction::Store(0), "STORE"),
            (Instruction::Push, "PUSH"),
            (Instruction::Pop, "POP"),
            (Instruction::AddImmediate(0), "ADD"),
            (Instruction::AddMemory(0), "ADDM"),
            (Instruction::SubImmediate(0), "SUB"),
            (Instruction::SubMemory(0), "SUBM"),
            (Instruction::MulImmediate(0), "MUL"),
            (Instruction::MulMemory(0), "MULM"),
            (Instruction::AndImmediate(0), "AND"),
            (Instruction::AndMemory(0), "ANDM"),
            (Instruction::OrImmediate(0), "OR"),
            (Instruction::OrMemory(0), "ORM"),
            (Instruction::XorImmediate(0), "XOR"),
            (Instruction::XorMemory(0), "XORM"),
            (Instruction::CmpImmediate(0), "CMP"),
            (Instruction::CmpMemory(0), "CMPM"),
            (Instruction::Call(0), "CALL"),
            (Instruction::Ret, "RET"),
            (Instruction::Jump(0), "JMP"),
            (Instruction::JumpIfZero(0), "JZ"),
            (Instruction::JumpIfNotZero(0), "JNZ"),
            (Instruction::Halt, "HALT"),
        ];
        for (instr, expected) in cases {
            assert_eq!(instr.mnemonic(), expected, "mnemonic wrong for {instr:?}");
        }
    }

    #[test]
    fn display_formats_nullary_instructions() {
        assert_eq!(format!("{}", Instruction::Nop), "NOP");
        assert_eq!(format!("{}", Instruction::Push), "PUSH");
        assert_eq!(format!("{}", Instruction::Pop), "POP");
        assert_eq!(format!("{}", Instruction::Ret), "RET");
        assert_eq!(format!("{}", Instruction::Halt), "HALT");
    }

    #[test]
    fn display_formats_immediate_instructions() {
        assert_eq!(format!("{}", Instruction::LoadImmediate(42)), "LOADI 42");
        assert_eq!(format!("{}", Instruction::AddImmediate(-5)), "ADD -5");
        assert_eq!(format!("{}", Instruction::SubImmediate(100)), "SUB 100");
        assert_eq!(format!("{}", Instruction::MulImmediate(3)), "MUL 3");
    }

    #[test]
    fn display_formats_address_instructions() {
        assert_eq!(format!("{}", Instruction::Load(7)), "LOAD 7");
        assert_eq!(format!("{}", Instruction::Store(3)), "STORE 3");
        assert_eq!(format!("{}", Instruction::Jump(10)), "JMP 10");
        assert_eq!(format!("{}", Instruction::JumpIfZero(5)), "JZ 5");
        assert_eq!(format!("{}", Instruction::Call(8)), "CALL 8");
    }
}
