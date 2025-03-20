pub mod riscv;

use thiserror::Error;
#[derive(Error, Debug, PartialEq)]
pub enum ScriptValidation {
    #[error("Not implemented {0}")]
    InstructionNotImplemented(String),

    #[error("Validation on Chain Fail {0}")]
    ValidationFail(String),
}
