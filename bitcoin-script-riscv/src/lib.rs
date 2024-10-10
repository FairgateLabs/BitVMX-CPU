pub mod riscv;

use thiserror::Error;
#[derive(Error, Debug)]
pub enum ScriptValidation {

    #[error("Not implemented {0}")]
    InstructionNotImplemented(String),
    
}