use bitcoin_script_riscv::riscv::instructions::{load_trace_read_in_stack, load_trace_step_in_stack, verify_execution, ProgramSpec};
use bitcoin_script_stack::{interactive::interactive, stack::StackTracker};

fn execute_example() {
    let mut stack = StackTracker::new();
    let opcode = 0xfa010113;
    let program = ProgramSpec::new(0xA000_0000);
    let trace_step = load_trace_step_in_stack(&mut stack, 0xA000_0008, 0xDFFF_FFA0, 0x8000_00c4, 0);
    let trace_read = load_trace_read_in_stack(&mut stack, 0xA000_0008, 0xE000_0000, 0, 0, 0x8000_00c0, 0, opcode);
    verify_execution(&mut stack, trace_step, trace_read, None, opcode, 0, program).unwrap();
    stack.op_true();
    println!("addi length: {}", stack.get_script().len());
    interactive(&stack);
}

fn main() {
    execute_example();
}