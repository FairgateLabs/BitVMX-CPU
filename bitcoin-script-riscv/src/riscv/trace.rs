use bitcoin_script_stack::stack::{StackTracker, StackVariable};


#[derive(Debug)]
pub struct TraceRead {
    pub read_1_add: StackVariable,
    pub read_1_value: StackVariable,
    pub read_2_add: StackVariable,
    pub read_2_value: StackVariable,
    pub program_counter: StackVariable,
    pub micro: StackVariable,
    pub opcode: StackVariable,
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


}
