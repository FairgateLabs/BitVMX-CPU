use bitcoin_script_stack::stack::{StackTracker, StackVariable};
use bitvmx_cpu_definitions::trace::{TraceRWStep, TraceStep};

#[derive(Debug, Clone, Copy)]
pub struct STraceRead {
    pub mem_witness: StackVariable,
    pub read_1_add: StackVariable,
    pub read_1_value: StackVariable,
    pub read_2_add: StackVariable,
    pub read_2_value: StackVariable,
    pub program_counter: StackVariable,
    pub micro: StackVariable,
    pub opcode: StackVariable,
}

impl Default for STraceRead {
    fn default() -> Self {
        STraceRead {
            mem_witness: StackVariable::null(),
            read_1_add: StackVariable::null(),
            read_1_value: StackVariable::null(),
            read_2_add: StackVariable::null(),
            read_2_value: StackVariable::null(),
            program_counter: StackVariable::null(),
            micro: StackVariable::null(),
            opcode: StackVariable::null(),
        }
    }
}

impl STraceRead {
    pub fn define(stack: &mut StackTracker) -> STraceRead {
        let mem_witness = stack.define(2, "mem_witness");
        let read_1_add = stack.define(8, "read_1_add");
        let read_1_value = stack.define(8, "read_1_value");
        let read_2_add = stack.define(8, "read_2_add");
        let read_2_value = stack.define(8, "read_2_value");
        let program_counter = stack.define(8, "read_program_counter");
        let micro = stack.define(1, "read_micro");
        let opcode = stack.define(8, "read_opcode");
        STraceRead {
            mem_witness,
            read_1_add,
            read_1_value,
            read_2_add,
            read_2_value,
            program_counter,
            micro,
            opcode,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn load(
        stack: &mut StackTracker,
        mw: u8,
        r1: u32,
        v1: u32,
        r2: u32,
        v2: u32,
        pc: u32,
        micro: u8,
        opcode: u32,
    ) -> STraceRead {
        let mem_witness = stack.byte(mw);
        stack.rename(mem_witness, "mem_witness");
        let read_1_add = stack.number_u32(r1);
        stack.rename(read_1_add, "read_1_add");
        let read_1_value = stack.number_u32(v1);
        stack.rename(read_1_value, "read_1_value");
        let read_2_add = stack.number_u32(r2);
        stack.rename(read_2_add, "read_2_add");
        let read_2_value = stack.number_u32(v2);
        stack.rename(read_2_value, "read_2_value");
        let program_counter = stack.number_u32(pc);
        stack.rename(program_counter, "read_program_counter");
        let micro = stack.number(micro as u32);
        stack.rename(micro, "read_micro");
        let opcode = stack.number_u32(opcode);
        stack.rename(opcode, "read_opcode");
        STraceRead {
            mem_witness,
            read_1_add,
            read_1_value,
            read_2_add,
            read_2_value,
            program_counter,
            micro,
            opcode,
        }
    }

    pub fn from(stack: &mut StackTracker, trace: &TraceRWStep) -> STraceRead {
        Self::load(
            stack,
            trace.mem_witness.byte(),
            trace.read_1.address,
            trace.read_1.value,
            trace.read_2.address,
            trace.read_2.value,
            trace.read_pc.pc.get_address(),
            trace.read_pc.pc.get_micro(),
            trace.read_pc.opcode,
        )
    }
}

#[derive(Debug)]
pub struct STraceStep {
    pub write_1_add: StackVariable,
    pub write_1_value: StackVariable,
    pub program_counter: StackVariable,
    pub micro: StackVariable,
}

impl Default for STraceStep {
    fn default() -> Self {
        STraceStep {
            write_1_add: StackVariable::null(),
            write_1_value: StackVariable::null(),
            program_counter: StackVariable::null(),
            micro: StackVariable::null(),
        }
    }
}
impl STraceStep {
    pub fn new(
        write_1_add: StackVariable,
        write_1_value: StackVariable,
        program_counter: StackVariable,
        micro: StackVariable,
    ) -> STraceStep {
        STraceStep {
            write_1_add,
            write_1_value,
            program_counter,
            micro,
        }
    }

    pub fn to_altstack(&self, stack: &mut StackTracker) {
        stack.to_altstack_count(4);
    }

    pub fn from_altstack(&self, stack: &mut StackTracker) {
        for _ in 0..4 {
            stack.from_altstack();
        }
    }

    pub fn define(stack: &mut StackTracker) -> STraceStep {
        let write_1_add = stack.define(8, "write_1_add");
        let write_1_value = stack.define(8, "write_1_value");
        let program_counter = stack.define(8, "write_program_counter");
        let micro = stack.define(1, "write_micro");
        STraceStep {
            write_1_add,
            write_1_value,
            program_counter,
            micro,
        }
    }

    pub fn load(stack: &mut StackTracker, w1: u32, v1: u32, pc: u32, micro: u8) -> STraceStep {
        let write_1_add = stack.number_u32(w1);
        stack.rename(write_1_add, "write_1_add");
        let write_1_value = stack.number_u32(v1);
        stack.rename(write_1_value, "write_1_value");
        let program_counter = stack.number_u32(pc);
        stack.rename(program_counter, "write_program_counter");
        let micro = stack.number(micro as u32);
        stack.rename(micro, "write_micro");
        STraceStep {
            write_1_add,
            write_1_value,
            program_counter,
            micro,
        }
    }

    pub fn from(stack: &mut StackTracker, trace: &TraceStep) -> STraceStep {
        Self::load(
            stack,
            trace.write_1.address,
            trace.write_1.value,
            trace.write_pc.get_address(),
            trace.write_pc.get_micro(),
        )
    }
}
