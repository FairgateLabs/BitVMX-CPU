use bitcoin_script_stack::stack::{StackTracker, StackVariable};


#[derive(Debug, Clone, Copy)]
pub struct TraceRead {
    pub read_1_add: StackVariable,
    pub read_1_value: StackVariable,
    pub read_2_add: StackVariable,
    pub read_2_value: StackVariable,
    pub program_counter: StackVariable,
    pub micro: StackVariable,
    pub opcode: StackVariable,
}

impl Default for TraceRead {
    fn default() -> Self {
        TraceRead {
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

impl TraceRead {
    pub fn define(stack: &mut StackTracker) -> TraceRead {
        let read_1_add = stack.define(8, "read_1_add");
        let read_1_value = stack.define(8, "read_1_value");
        let read_2_add = stack.define(8, "read_2_add");
        let read_2_value = stack.define(8, "read_2_value");
        let program_counter = stack.define(8, "read_program_counter");
        let micro = stack.define(1, "read_micro");
        let opcode = stack.define(8, "read_opcode");
        TraceRead {
            read_1_add,
            read_1_value,
            read_2_add,
            read_2_value,
            program_counter,
            micro,
            opcode,
        }
    }
}

#[derive(Debug)]
pub struct TraceStep {
    pub write_1_add: StackVariable,
    pub write_1_value: StackVariable,
    pub program_counter: StackVariable,
    pub micro: StackVariable,
}

impl Default for TraceStep {
    fn default() -> Self {
        TraceStep {
            write_1_add: StackVariable::null(),
            write_1_value: StackVariable::null(),
            program_counter: StackVariable::null(),
            micro: StackVariable::null(),
        }
    }

}
impl TraceStep {
    pub fn new(write_1_add: StackVariable, write_1_value: StackVariable, program_counter: StackVariable, micro: StackVariable) -> TraceStep {
        TraceStep {
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
    
    pub fn define(stack: &mut StackTracker) -> TraceStep {
        let write_1_add = stack.define(8, "write_1_add");
        let write_1_value = stack.define(8, "write_1_value");
        let program_counter = stack.define(8, "write_program_counter");
        let micro = stack.define(1, "write_micro");
        TraceStep {
            write_1_add,
            write_1_value,
            program_counter,
            micro
        }
    }

}
