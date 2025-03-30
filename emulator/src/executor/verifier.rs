use crate::ExecutionResult;

use bitcoin_script_riscv::riscv::{instruction_mapping::InstructionMapping, instructions::*};
use bitvmx_cpu_definitions::trace::TraceRWStep;

pub fn verify_script(
    trace: &TraceRWStep,
    base_register_address: u32,
    instruction_mapping: &Option<InstructionMapping>,
) -> Result<(), ExecutionResult> {
    let program = ProgramSpec::new(base_register_address);
    let result = verify(instruction_mapping, program, trace)?;

    Ok(result)
}
