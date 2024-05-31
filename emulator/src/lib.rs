pub mod loader;
pub mod executor;

use thiserror::Error;
#[derive(Error, Debug)]
pub enum ExecutionResult {
    #[error("Ok")]
    Ok,
    #[error("Program terminated successfully")]
    Success,
    #[error("Error")]
    Error,

    #[error("Not implemented {0} {1}")]
    InstructionNotImplemented(u32, String),

    #[error("Syscall not implemented {0}")]
    SyscallNotImplemented(u32),
}
