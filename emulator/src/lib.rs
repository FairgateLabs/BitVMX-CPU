pub mod executor;
pub mod loader;

use bitcoin_script_riscv::ScriptValidation;
use thiserror::Error;
#[derive(Error, Debug, PartialEq)]
pub enum ExecutionResult {
    #[error("Ok")]
    Ok,
    #[error("Program halted return value: {0} at step: {1}")]
    Halt(u32, u64),

    #[error("Step limit reached: {0}")]
    LimitStepReached(u64),

    #[error("Error")]
    Error,

    #[error("Section: {0} not found")]
    SectionNotFound(String),

    #[error("Registers section can not be accessed")]
    RegistersSectionFail,

    #[error("Not implemented {0} {1}")]
    InstructionNotImplemented(u32, String),

    #[error("Syscall not implemented {0}")]
    SyscallNotImplemented(u32),

    #[error("Can't load the program {0}")]
    CantLoadPorgram(String),

    #[error("Can't write into the code section")]
    WriteToCodeSection,

    #[error("Failed to verify the bitcoin script {0}")]
    BitcoinScriptVerification(#[from] ScriptValidation),
}

pub mod constants {
    pub const REGISTERS_BASE_ADDRESS: u32 = 0xF000_0000; //CHECK: this can be parameterized
    pub const STACK_BASE_ADDRESS: u32 = 0xE000_0000; //CHECK: this can be parameterized
    pub const STACK_SIZE: u32 = 0x80_0000; //QEMU Default stack size
    pub const LAST_STEP_INIT: u64 = 0xFFFF_FFFF_FFFF_FFFF;
}
