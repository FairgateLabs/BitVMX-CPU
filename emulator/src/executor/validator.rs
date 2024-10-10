use super::trace::TraceRWStep;
use bitcoin_script_riscv::riscv::{instruction_mapping::InstructionMapping, instructions::*};

pub fn validate(trace: &TraceRWStep, base_register_address: u32, instruction_mapping: &Option<InstructionMapping> ) -> bool {

    let program = ProgramSpec::new(base_register_address);
    let result = verify(instruction_mapping, program, trace.read_1.address, trace.read_1.value, 
                    trace.read_2.address, trace.read_2.value, 
                    trace.read_pc.pc.get_address(), trace.read_pc.pc.get_micro(), 
                    trace.read_pc.opcode, 
                    trace.trace_step.write_1.address, trace.trace_step.write_1.value, 
                    trace.trace_step.get_pc().get_address(), trace.trace_step.get_pc().get_micro(), trace.witness );

    result.unwrap_or(false)
}