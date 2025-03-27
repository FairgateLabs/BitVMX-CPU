pub mod riscv;

use serde::{Deserialize, Serialize};
use thiserror::Error;
#[derive(Error, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ScriptValidation {
    #[error("Not implemented {0}")]
    InstructionNotImplemented(String),

    #[error("Validation on Chain Fail {0}")]
    ValidationFail(String),
}
