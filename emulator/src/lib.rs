pub mod decision;
pub mod executor;
pub mod loader;

use bitcoin_script_riscv::ScriptValidation;
use bitvmx_cpu_definitions::challenge::EmulatorResultError;
use loader::program_definition::ProgramDefinitionError;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum EmulatorError {
    #[error("Invalid parameters")]
    InvalidParameters,

    #[error("Can't obtain execution trace")]
    CantObtainTrace,

    #[error("Can't load the program {0}")]
    CantLoadPorgram(String),

    #[error("Error with challenge log {0}")]
    ChallengeError(String),

    #[error("Error execution program {0}")]
    ExecutionError(#[from] ExecutionResult),

    #[error("Error with program definition {0}")]
    ProgramDefinition(#[from] ProgramDefinitionError),

    #[error("Error with emulator result {0}")]
    EmulatorResultError(#[from] EmulatorResultError),

    #[error("Invalid force configuration {0}")]
    InvalidForceConfiguration(String),
}

#[derive(Error, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ExecutionResult {
    #[error("Program halted return value: {0} at step: {1}")]
    Halt(u32, u64),

    #[error("Step limit reached: {0}")]
    LimitStepReached(u64),

    #[error("Section: {0} not found")]
    SectionNotFound(String),

    #[error("Registers section can not be accessed")]
    RegistersSectionFail,

    #[error("Not implemented {0} {1}")]
    InstructionNotImplemented(u32, String),

    #[error("Can't execute from non-code section")]
    ExecuteFromNonCodeSection,

    #[error("Can't write into read-only section")]
    WriteToReadOnlySection,

    #[error("Failed to verify the bitcoin script {0}")]
    BitcoinScriptVerification(#[from] ScriptValidation),

    #[error("Tried to jump to unaligned address: {0}")]
    UnalignedJump(u32),

    #[error("Tried to read unaligned address: {0}")]
    UnalignedRead(u32),

    #[error("Tried to write unaligned address: {0}")]
    UnalignedWrite(u32),

    #[error("Can't read from execute only section")]
    ReadFromExecuteOnlySection,
}

pub mod constants {
    pub const REGISTERS_BASE_ADDRESS: u32 = 0xF000_0000; //CHECK: this can be parameterized
    pub const STACK_BASE_ADDRESS: u32 = 0xE000_0000; //CHECK: this can be parameterized
    pub const STACK_SIZE: u32 = 0x80_0000; //QEMU Default stack size
    pub const MAX_SECTIONS: usize = 900; // Having too many sections can break some challenges due to max script size
}
