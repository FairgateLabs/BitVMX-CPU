pub mod executor;
pub mod loader;

use thiserror::Error;
#[derive(Error, Debug, PartialEq)]
pub enum ExecutionResult {
    #[error("Ok")]
    Ok,
    #[error("Program terminated successfully")]
    Halt(u32),

    #[error("Step limit reached")]
    LimitStepReached,

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
}

pub mod constants {
    pub const REGISTERS_BASE_ADDRESS: u32 = 0xF000_0000; //CHECK: this can be parameterized
    pub const STACK_BASE_ADDRESS: u32 = 0xE000_0000; //CHECK: this can be parameterized
    pub const STACK_SIZE: u32 = 0x80_0000; //QEMU Default stack size
    pub const LAST_STEP_INIT: u64 = 0xFFFF_FFFF_FFFF_FFFF;
}
