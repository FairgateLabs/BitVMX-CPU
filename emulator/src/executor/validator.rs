use crate::ExecutionResult;

use bitcoin_script_riscv::riscv::{instruction_mapping::InstructionMapping, instructions::*};
use bitvmx_cpu_definitions::trace::TraceRWStep;

pub fn validate(
    trace: &TraceRWStep,
    base_register_address: u32,
    instruction_mapping: &Option<InstructionMapping>,
) -> Result<(), ExecutionResult> {
    let program = ProgramSpec::new(base_register_address);
    let result = verify(
        instruction_mapping,
        program,
        //trace,
        trace.mem_witness.byte(),
        trace.read_1.address,
        trace.read_1.value,
        trace.read_2.address,
        trace.read_2.value,
        trace.read_pc.pc.get_address(),
        trace.read_pc.pc.get_micro(),
        trace.read_pc.opcode,
        trace.trace_step.write_1.address,
        trace.trace_step.write_1.value,
        trace.trace_step.get_pc().get_address(),
        trace.trace_step.get_pc().get_micro(),
        trace.witness,
    )?;

    Ok(result)
}
