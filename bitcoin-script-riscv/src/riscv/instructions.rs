use bitcoin_script_stack::stack::{StackTracker, StackVariable};

use riscv_decode::Instruction::*;

use super::decoder::decode_i_type;
use super::script_utils::*;
use super::trace::{TraceRead, TraceStep};



pub fn validate_register_address(stack: &mut StackTracker, read_address: StackVariable, register: StackVariable, base_register_address: u32  ) {

    for i in 0..4 {

        let mut x = stack.copy_var_sub_n(read_address, i * 2);
        stack.copy_var_sub_n(read_address, (i * 2) + 1);
        stack.join(&mut x);

        let mut base = if i < 3 {
            //verify the constant part of the address
            stack.byte(((base_register_address & (0xFF00_0000 >> i * 8) ) >> ((3-i)*8)) as u8)
        } else {
            //verify the address pointed by the register
            stack.copy_var(register)
        };

        stack.equals(&mut x, true, &mut base, true);
        
    }

}

pub fn pc_next(stack: &mut StackTracker, tables: &StackTables, pc: StackVariable) -> StackVariable {
    stack.set_breakpoint("pc_next");
    stack.move_var(pc);
    stack.explode(pc);
    stack.number(4);

    let mut last = StackVariable::null();
    for i in 0..8 {
        stack.op_add();
        if i < 7 {
            stack.op_dup();
        }

        last = stack.get_value_from_table(tables.modulo, None);

        if i < 7 {
            stack.to_altstack();
            stack.get_value_from_table(tables.quotient, None);
        }
    }

    for _ in 0..7 {
        stack.from_altstack();
    }

    stack.rename(last, "write_pc");
    stack.join_count(&mut last, 7)

}

pub fn add_with_bit_extension(stack: &mut StackTracker, tables: &StackTables, value: StackVariable, to_add: &mut StackVariable, bit_extension: StackVariable) -> StackVariable {
    stack.set_breakpoint("add_with_bit_extension");

    //move the value and split the nibbles
    stack.move_var(value);
    stack.explode(value);


    let add_size = to_add.size();
    let mut last = StackVariable::null();
    for i in 0..8 {
        if i > 0 {
            stack.op_add();
        }

        if i < add_size {
            stack.move_var_sub_n(to_add, add_size - i - 1);
        } else {
            if i < 7 { 
                stack.copy_var(bit_extension);
            } else {
                stack.move_var(bit_extension);
            }
        }

        
        stack.op_add();

        if i < 7 {
            stack.op_dup();
        }

        last = stack.get_value_from_table(tables.modulo, None);

        if i < 7 {
            stack.to_altstack();
            stack.get_value_from_table(tables.quotient, None);
        }

    }

    for _ in 0..7 {
        stack.from_altstack();
    }

    stack.rename(last, "add_bit_ext");
    stack.join_count(&mut last, 7)


}



pub fn op_addi(stack: &mut StackTracker, trace_read: &TraceRead, base_register_address: u32) -> TraceStep {

    let tables = StackTables::new(stack, true, true, 1,5);
    stack.set_breakpoint("addi");

    let (mut imm, rs1, rd, bit_extension) = decode_i_type(stack, &tables, trace_read.opcode);


    //these value are not used. can be droped or we can avoid to commit them
    move_and_drop(stack, trace_read.read_2_add);
    move_and_drop(stack, trace_read.read_2_value);
    move_and_drop(stack, trace_read.micro);

    // assert rs1 + base_register_address == read_1 address
    validate_register_address(stack, trace_read.read_1_add, rs1, base_register_address);

    move_and_drop(stack, rs1); //This should be consumed
    move_and_drop(stack, trace_read.read_1_add);

    let mut write_add = number_u32_partial(stack, base_register_address, 6);
    stack.move_var(rd);
    stack.join(&mut write_add);
    stack.rename(write_add, "write_add");

    let write_value = add_with_bit_extension(stack, &tables, trace_read.read_1_value, &mut imm, bit_extension);

    let write_pc = pc_next(stack, &tables, trace_read.program_counter);
    let micro = stack.byte(0);
    stack.rename(micro, "write_micro");

    // result: 
    //   write_add = base_register_address + rd 
    //   write_value = read_1_value + (bitextended) imm   
    //   program_counter = read_program_counter + 4
    let trace = TraceStep::new(write_add, write_value, write_pc, micro);
    trace.to_altstack(stack);
    tables.drop(stack);
    trace.from_altstack(stack);
    trace


}


pub struct ProgramSpec {
    base_register_address: u32,  // base address used for the registers
}
impl ProgramSpec {
    pub fn new(base_register_address: u32) -> ProgramSpec {
        //This requirement makes the easier to verify the addresses 
        assert_eq!(base_register_address & 0x0000_00FF, 0, "Base register address must be aligned to 256 bytes");
        ProgramSpec {
            base_register_address,
        }
    }
}

pub fn execute_step( stack: &mut StackTracker, trace_read: TraceRead, opcode: u32, program: ProgramSpec ) -> TraceStep {
    let instruction = riscv_decode::decode(opcode).unwrap();

    let ret = match instruction {
        Addi(x) => { 
            if x.rd() == 0 {
                //op_nop()
                panic!("NOP not implemented")
            }  else {
                op_addi(stack, &trace_read, program.base_register_address)
            }
        },
        _ => { panic!("Instruction not implemented") }
    };

    ret

}

pub fn load_trace_read_in_stack(stack: &mut StackTracker, r1: u32, v1: u32, r2: u32, v2: u32, pc: u32, micro: u8, opcode: u32) -> TraceRead {
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
    let micro = stack.byte(micro);
    stack.rename(micro, "read_micro");
    let opcode = stack.number_u32(opcode);
    stack.rename(opcode, "read_opcode");
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

pub fn load_trace_step_in_stack(stack: &mut StackTracker, w1: u32, v1: u32, pc: u32, micro: u8) -> TraceStep {
    let write_1_add = stack.number_u32(w1);
    stack.rename(write_1_add, "write_1_add");
    let write_1_value = stack.number_u32(v1);
    stack.rename(write_1_value, "write_1_value");
    let program_counter = stack.number_u32(pc);
    stack.rename(program_counter, "write_program_counter");
    let micro = stack.byte(micro);
    stack.rename(micro, "write_micro");
    TraceStep {
        write_1_add,
        write_1_value,
        program_counter,
        micro,
    }
}

pub fn verify_execution(stack: &mut StackTracker, mut trace_step: TraceStep, trace_read: TraceRead, opcode: u32, program: ProgramSpec) {
    let mut result_step = execute_step(stack, trace_read, opcode, program);

    stack.set_breakpoint("verify execution");

    stack.equals(&mut trace_step.micro, true, &mut result_step.micro, true);
    stack.equals(&mut trace_step.program_counter, true, &mut result_step.program_counter, true);
    stack.equals(&mut trace_step.write_1_value, true, &mut result_step.write_1_value, true);
    stack.equals(&mut trace_step.write_1_add, true, &mut result_step.write_1_add, true);

    stack.set_breakpoint("end verify execution");
}



#[cfg(test)]
mod tests {

    use crate::riscv::decoder::get_register_address;

    use super::*;


    #[test]
    fn test_get_register() {

        for r in 0..32 {  
            let mut stack = StackTracker::new();
            let tables = StackTables::new(&mut stack, false, false, 1, 4);

            let add = r * 4;
            let mut original = stack.number(add  >> 4);
            stack.number(add & 0x0f);
            stack.join(&mut original);

            let register_number : u8 = (r as u8) << 3;
            let register_encoded = stack.byte(register_number);
            let parts = stack.explode(register_encoded);


            let mut reconstructed = get_register_address(&mut stack, &tables, parts[0], parts[1]);
            stack.equals(&mut original, true, &mut reconstructed, true);

            tables.drop(&mut stack);

            stack.op_true();
            assert!(stack.run().success);
        }

    }


    #[test]
    fn test_validate_register() {
        let base = 0x1234_5600;
        for i in 0..32 {
            let mut stack = StackTracker::new();
            let add = i << 2;
            let register = stack.byte(add);
            let read_address = stack.number_u32(base + add as u32);
            validate_register_address(&mut stack,  read_address, register, base);
            stack.drop(read_address);
            stack.drop(register);
            stack.op_true();
            assert!(stack.run().success);
        }
    }



    #[test]
    fn test_addi() {
        let mut stack = StackTracker::new();
        let opcode = 0xfa010113;
        let program = ProgramSpec::new(0xA000_0000);
        let trace_step = load_trace_step_in_stack(&mut stack, 0xA000_0008, 0xDFFF_FFA0, 0x8000_00c4, 0);
        let trace_read = load_trace_read_in_stack(&mut stack, 0xA000_0008, 0xE000_0000, 0, 0, 0x8000_00c0, 0, opcode);
        verify_execution(&mut stack, trace_step, trace_read, opcode, program);
        stack.op_true();
        assert!(stack.run().success);
    }

}