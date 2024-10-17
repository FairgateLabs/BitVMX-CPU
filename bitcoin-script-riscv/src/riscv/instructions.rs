
use bitcoin_script_stack::stack::{StackTracker, StackVariable};

use riscv_decode::Instruction;
use riscv_decode::Instruction::*;

use crate::ScriptValidation;

use super::decoder::*;
use super::instruction_mapping::get_key_from_instruction_and_micro;
use super::instruction_mapping::InstructionMapping;
use super::instructions_load::op_load;
use super::instructions_store::op_store;
use super::operations;
use super::operations::*;
use super::script_utils::*;
use super::trace::{TraceRead, TraceStep};

pub const R_TYPE_OPCODE: u8 = 0x33;


pub fn validate_register_address(stack: &mut StackTracker, read_address: StackVariable, register: StackVariable, base_register_address: u32  ) {

    for i in 0..4 {

        let mut x = stack.copy_var_sub_n(read_address, i * 2);
        stack.copy_var_sub_n(read_address, (i * 2) + 1);
        stack.join(&mut x);

        let mut base = if i < 3 {
            //verify the constant part of the address
            stack.byte(((base_register_address & 0xFF00_0000 >> (i * 8 )) >> ((3-i)*8)) as u8)
        } else {
            //verify the address pointed by the register
            stack.copy_var(register)
        };

        stack.equals(&mut x, true, &mut base, true);
        
    }

}

pub fn op_nop(stack: &mut StackTracker, trace_read: &mut TraceRead) -> TraceStep {
    //TODO: Need to assert opcode and zeros ?

    move_and_drop(stack, trace_read.opcode);
    move_and_drop(stack, trace_read.micro);
    stack.to_altstack();
    move_and_drop(stack, trace_read.read_2_value);
    move_and_drop(stack, trace_read.read_2_add);
    move_and_drop(stack, trace_read.read_1_value);
    move_and_drop(stack, trace_read.read_1_add);


    let write_add = stack.number_u32(0);
    let write_value = stack.number_u32(0);

    let tables = StackTables::new(stack, true, true, 0, 0, 0);
    stack.from_altstack();
    let pc = pc_next(stack, &tables, trace_read.program_counter);
    stack.to_altstack();
    tables.drop(stack);
    stack.from_altstack();

    let micro = stack.number(0);
    TraceStep::new(write_add, write_value, pc, micro)
}

pub fn op_conditional(instruction: &Instruction, stack: &mut StackTracker, trace_read: &mut TraceRead, base_register_address: u32) -> TraceStep {

    let (func3, unsigned, lower, inverse) = match instruction {
        Beq(_) => (0, false, false, false),
        Bne(_) => (1, false, false, true),
        Blt(_) => (4, false, true, false),
        Bge(_) => (5, false, true, true),
        Bltu(_) => (6, true, true, false),
        Bgeu(_) => (7, true, true, true),
        _ => panic!("Unreachable")
    };

    //println!("op_conditional: {:?} ", instruction);
    let tables = StackTables::new(stack, true, true, 7, 7, 0);
    stack.set_breakpoint(&format!("op_{:?}", instruction));

    let (imm, rs1, rs2) = decode_b_type(stack, &tables, trace_read.opcode, func3);

    //micro is not used
    move_and_drop(stack, trace_read.micro);

    // assert rs1 + base_register_address == read_1 address
    validate_register_address(stack, trace_read.read_1_add, rs1, base_register_address);
    // assert rs2 + base_register_address == read_2 address
    validate_register_address(stack, trace_read.read_2_add, rs2, base_register_address);
    stack.drop(rs2);
    stack.drop(rs1);
    move_and_drop(stack, trace_read.read_1_add);
    move_and_drop(stack, trace_read.read_2_add);

    //prepare the result
    let write_add = stack.number_u32(0);    //not used
    stack.rename(write_add, "write_add");
    let write_value = stack.number_u32(0);  //not used
    stack.rename(write_value, "write_value");


    stack.move_var(trace_read.read_1_value);
    stack.move_var(trace_read.read_2_value);


    stack.move_var(imm);
    stack.move_var(trace_read.program_counter);


    if lower {
        is_lower_than(stack, &mut trace_read.read_1_value, &mut trace_read.read_2_value, unsigned);
    } else {
        is_equal_to(stack, &trace_read.read_1_value, &trace_read.read_2_value);
        move_and_drop(stack, trace_read.read_1_value);
        move_and_drop(stack, trace_read.read_2_value);
    }
    if inverse {
        stack.op_not();
    }

    let (mut stack_if_true, mut stack_if_false) = stack.open_if();

    //if the condition is true, the program counter is updated
    let mut pc = trace_read.program_counter;
    add_with_bit_extension(&mut stack_if_true, &tables, imm, &mut pc, StackVariable::null() );

    //if false, jump to the next instruction
    pc_next(&mut stack_if_false, &tables, trace_read.program_counter);
    move_and_drop(&mut stack_if_false, imm);

    let ret = stack.end_if(stack_if_true, stack_if_false, 2, vec![(8, "write_pc".to_string())], 0);
    let write_pc = ret[0];




    let micro = stack.number(0);
    stack.rename(micro, "write_micro");

    let trace = TraceStep::new(write_add, write_value, write_pc, micro);
    trace.to_altstack(stack);
    tables.drop(stack);
    trace.from_altstack(stack);
    trace
    
}


pub fn store_if_not_zero(stack: &mut StackTracker, tables: &StackTables, rd: StackVariable, program_counter: StackVariable, base_register_address: u32) -> (StackVariable, StackVariable) {


    stack.move_var(program_counter);
    stack.move_var(rd);

    let copy_rd = stack.copy_var(rd);
    stack.explode(copy_rd);
    stack.op_add();

    stack.number(0);
    stack.op_equal();

    let (mut stack_if_true, mut stack_if_false) =  stack.open_if();

    // if dest is zero, write data and value are zero
    stack_if_true.drop(rd);
    stack_if_true.drop(program_counter);
    stack_if_true.number_u32(0);
    stack_if_true.number_u32(0);

    let mut write_add = number_u32_partial(&mut stack_if_false, base_register_address, 6);
    stack_if_false.move_var(rd);
    stack_if_false.join(&mut write_add);
    stack_if_false.rename(write_add, "write_add");

    let write_value = pc_next(&mut stack_if_false, tables, program_counter);
    stack_if_false.rename(write_value, "write_value");

    let ret = stack.end_if(stack_if_true, stack_if_false, 2, vec![(8, "write_address".to_string()), (8, "write_value".to_string())], 0);
    (ret[0], ret[1])
    

}

pub fn op_jal(instruction: &Instruction, stack: &mut StackTracker, trace_read: &mut TraceRead, base_register_address: u32) -> TraceStep {


    let tables = StackTables::new(stack, true, true, 5,5, 0);

    stack.set_breakpoint(&format!("op_{:?}", instruction));

    let (rd, mut imm) = decode_j_type(stack, &tables, trace_read.opcode);

    //these value are not used. can be droped or we can avoid to commit them
    move_and_drop(stack, trace_read.read_1_add);
    move_and_drop(stack, trace_read.read_1_value);
    move_and_drop(stack, trace_read.read_2_add);
    move_and_drop(stack, trace_read.read_2_value);
    move_and_drop(stack, trace_read.micro);
    
    let pc = stack.copy_var(trace_read.program_counter);
    
    let (write_add, write_value) = store_if_not_zero(stack, &tables, rd, trace_read.program_counter, base_register_address);

    let write_pc = add_with_bit_extension(stack, &tables, pc, &mut imm, StackVariable::null());
    stack.rename(write_pc, "write_pc");

    let micro = stack.number(0);
    stack.rename(micro, "write_micro");

    let trace = TraceStep::new(write_add, write_value, write_pc, micro);
    trace.to_altstack(stack);
    tables.drop(stack);
    trace.from_altstack(stack);
    trace


}


pub fn op_jalr(instruction: &Instruction, stack: &mut StackTracker, trace_read: &mut TraceRead, base_register_address: u32) -> TraceStep {

    let tables = StackTables::new(stack, true, true, 1,5, 0);

    stack.set_breakpoint(&format!("op_{:?}", instruction));

    let (mut imm, rs1, rd, bit_extension) = decode_i_type(stack, &tables, trace_read.opcode, 0, 0x67, None);

    //these value are not used. can be droped or we can avoid to commit them
    move_and_drop(stack, trace_read.read_2_add);
    move_and_drop(stack, trace_read.read_2_value);
    move_and_drop(stack, trace_read.micro);

    
    // assert rs1 + base_register_address == read_1 address
    validate_register_address(stack, trace_read.read_1_add, rs1, base_register_address);

    move_and_drop(stack, rs1); //This should be consumed
    move_and_drop(stack, trace_read.read_1_add);
    
    let (write_add, write_value) = store_if_not_zero(stack, &tables, rd, trace_read.program_counter, base_register_address);

    let write_pc = add_with_bit_extension(stack, &tables, trace_read.read_1_value, &mut imm, bit_extension);
    stack.rename(write_pc, "write_pc");

    let micro = stack.number(0);
    stack.rename(micro, "write_micro");

    let trace = TraceStep::new(write_add, write_value, write_pc, micro);
    trace.to_altstack(stack);
    tables.drop(stack);
    trace.from_altstack(stack);
    trace


}

pub fn op_arithmetic_imm(instruction: &Instruction, stack: &mut StackTracker, trace_read: &mut TraceRead, base_register_address: u32) -> TraceStep {

    let (mask, logic, func3, func7) = match instruction {
        Xori(_) =>  (LOGIC_MASK_XOR, Some(LogicOperation::Xor), 4, None),
        Andi(_) => (LOGIC_MASK_AND, Some(LogicOperation::And), 7, None),
        Ori(_)  => (LOGIC_MASK_OR, Some(LogicOperation::Or), 6, None),
        Slti(_) => (0, None, 2, None),
        Sltiu(_) => (0, None, 3, None),
        Addi(_) => (0, None, 0, None),
        Slli(_) => (0, None, 1, Some(0)),
        Srli(_) => (0, None, 5, Some(0)),
        Srai(_) => (0, None, 5, Some(0x20)),
        _ => panic!("Unreachable") 
    };

    let extra_shift = if func7.is_some() { 7 } else { 0 };
    let tables = StackTables::new(stack, true, true, 1 | extra_shift,5 | extra_shift, mask);

    stack.set_breakpoint(&format!("op_{:?}", instruction));

    let (mut imm, rs1, rd, bit_extension) = decode_i_type(stack, &tables, trace_read.opcode, func3, 0x13, func7);

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

    let write_value = match instruction {
        Slli(_) => shift_value_with_bits(stack, &mut trace_read.read_1_value, imm, false, false),
        Srli(_) => shift_value_with_bits(stack, &mut trace_read.read_1_value, imm, true, false),
        Srai(_) => shift_value_with_bits(stack, &mut trace_read.read_1_value, imm, true, true),
        Slti(_) => { move_and_drop(stack, bit_extension); operations::is_lower_than_slti(stack, &mut trace_read.read_1_value, imm, false, true) },
        Sltiu(_) => { move_and_drop(stack, bit_extension); operations::is_lower_than_slti(stack, &mut trace_read.read_1_value, imm, true, true) },
        Xori(_) | Andi(_) | Ori(_)  => logic_with_bit_extension(stack, &tables, &mut trace_read.read_1_value, &mut imm, bit_extension, logic.unwrap()),
        Addi(_) => add_with_bit_extension(stack, &tables, trace_read.read_1_value, &mut imm, bit_extension),
        _ => panic!("Unreachable") 
    };

    let write_pc = pc_next(stack, &tables, trace_read.program_counter);
    let micro = stack.number(0);
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

pub fn op_arithmetic(instruction: &Instruction, stack: &mut StackTracker, trace_read: &mut TraceRead, trace_step: &TraceStep, witness: Option<StackVariable>, base_register_address: u32) -> TraceStep {
    let (mask, logic, func3, func7, extra_shift_for_mask) = match instruction {
        Mul(_)  => (0x0, None, 0x0, 0x1, 0),
        Mulh(_)  => (0x0, None, 0x1, 0x1, 0),
        Mulhsu(_)  => (0x0, None, 0x2, 0x1, 0),
        Mulhu(_)  => (0x0, None, 0x3, 0x1, 0),
        Div(_)  => (0x0, None, 0x4, 0x1, 0),
        Divu(_)  => (0x0, None, 0x5, 0x1, 0),
        Rem(_)  => (0x0, None, 0x6, 0x1, 0),
        Remu(_)  => (0x0, None, 0x7, 0x1, 0),
        Add(_)  => (0x0, None, 0x0, 0x0, 0),
        Sub (_) => (0x0, None, 0x0, 0x20, 0),
        Xor(_)  => (LOGIC_MASK_XOR, Some(LogicOperation::Xor), 0x4, 0x0, 0),
        And(_)  => (LOGIC_MASK_AND, Some(LogicOperation::And), 0x7, 0x0, 0),
        Or(_)   => (LOGIC_MASK_OR, Some(LogicOperation::Or), 0x6, 0x0, 0),
        Slt(_)  => (0, None, 2, 0, 0),
        Sltu(_) => (0, None, 3, 0, 0),
        Sll(_)  => (0, None, 0x1, 0x00, 4),
        Srl(_)  => (0, None, 0x5, 0x00, 4),
        Sra(_)  => (0, None, 0x5, 0x20, 4),
        _ => panic!("Unreachable")
    };

    let tables = StackTables::new(stack, true, true, 3 | extra_shift_for_mask, 6, mask);

    stack.set_breakpoint(&format!("op_{:?}", instruction));

    let (rs1, rs2, rd) = decode_r_type(stack, &tables, trace_read.opcode, func3, R_TYPE_OPCODE, func7);

    //these value are not used. can be droped or we can avoid to commit them
    move_and_drop(stack, trace_read.micro);

    // assert rs1 + base_register_address == read_1 address
    validate_register_address(stack, trace_read.read_1_add, rs1, base_register_address);

    // assert rs2 + base_register_address == read_2 address
    validate_register_address(stack, trace_read.read_2_add, rs2, base_register_address);

    move_and_drop(stack, rs1); //This should be consumed
    move_and_drop(stack, trace_read.read_1_add);

    move_and_drop(stack, rs2); //This should be consumed
    move_and_drop(stack, trace_read.read_2_add);

    let mut write_addr = number_u32_partial(stack, base_register_address, 6);
    stack.move_var(rd);
    stack.join(&mut write_addr);
    stack.rename(write_addr, "write_addr");

    let mut masked_5lsb = StackVariable::null();
    if extra_shift_for_mask > 0 {
        stack.move_var(trace_read.read_2_value);
        stack.explode(trace_read.read_2_value);
        stack.to_altstack();
        stack.get_value_from_table(tables.lshift.shift_3, None);
        stack.get_value_from_table(tables.rshift.shift_3, None);
        stack.to_altstack();
        stack.op_2drop();
        stack.op_2drop();
        stack.op_2drop();
        masked_5lsb = stack.from_altstack_joined(2, "masked_5lsb");
    }


    let write_value_copy = match instruction {
        Div(_) | 
        Divu(_) | 
        Rem(_) | 
        Remu(_) => Some(stack.copy_var(trace_step.write_1_value)), 
        _ => None
    };


    let write_value = match instruction {
        Mul(_) => multiply(stack, trace_read.read_1_value, trace_read.read_2_value, false, true),
        Mulh(_)  => mulh(stack, &tables, trace_read.read_1_value, trace_read.read_2_value, false),
        Mulhsu(_)  => mulh(stack, &tables, trace_read.read_1_value, trace_read.read_2_value, true),
        Mulhu(_) => multiply(stack, trace_read.read_1_value, trace_read.read_2_value, true, false),
        Div(_) => div(stack, &tables, trace_read.read_1_value, trace_read.read_2_value, write_value_copy.unwrap(), witness.unwrap()),
        Divu(_) => divu(stack, &tables, trace_read.read_1_value, trace_read.read_2_value, write_value_copy.unwrap(), witness.unwrap()),
        Remu(_) => remu(stack, &tables, trace_read.read_1_value, trace_read.read_2_value, write_value_copy.unwrap(), witness.unwrap()),
        Rem(_) => rem(stack, &tables, trace_read.read_1_value, trace_read.read_2_value, write_value_copy.unwrap(), witness.unwrap()),
        Add(_) => add_with_bit_extension(stack, &tables, trace_read.read_1_value, &mut trace_read.read_2_value, StackVariable::null()),
        Sub(_) => sub(stack, &tables, trace_read.read_1_value, &mut trace_read.read_2_value),
        Slt(_)  => is_lower_than_slti(stack, &mut trace_read.read_1_value, trace_read.read_2_value, false, false),
        Sltu(_) => is_lower_than_slti(stack, &mut trace_read.read_1_value, trace_read.read_2_value, true, false),
        Xor(_) |
        And(_) |
        Or(_)  => logic_with_bit_extension(stack, &tables, &mut trace_read.read_1_value, &mut trace_read.read_2_value, StackVariable::null(), logic.unwrap()),
        Sll(_) => shift_value_with_bits(stack, &mut trace_read.read_1_value, masked_5lsb, false, false),
        Srl(_) => shift_value_with_bits(stack, &mut trace_read.read_1_value, masked_5lsb, true, false),
        Sra(_) => shift_value_with_bits(stack, &mut trace_read.read_1_value, masked_5lsb, true, true),
        _ => panic!("Unreachable")
    };


    let write_pc = pc_next(stack, &tables, trace_read.program_counter);
    let micro = stack.number(0);
    stack.rename(micro, "write_micro");

    // result: 
    //   write_addr = base_register_address + rd * 4 
    //   write_value = read_1_value + read_2_value
    //   program_counter = read_program_counter + 4
    let trace = TraceStep::new(write_addr, write_value, write_pc, micro);
    trace.to_altstack(stack);
    tables.drop(stack);
    trace.from_altstack(stack);

    trace
}

pub fn op_upper(instruction: &Instruction, stack: &mut StackTracker, trace_read: &mut TraceRead, base_register_address: u32) -> TraceStep {
    let tables = StackTables::new(stack, true, true, 1, 4, 0);

    stack.set_breakpoint(&format!("op_{:?}", instruction));

    let expected_opcode = match instruction {
        Lui(_) => 0x37,
        Auipc(_) => 0x17,
        _ => panic!("Unreachable")
    };

    let (mut imm,rd) = decode_u_type(stack, &tables, trace_read.opcode, expected_opcode);
    // These value are not used
    move_and_drop(stack, trace_read.read_2_add);
    move_and_drop(stack, trace_read.read_2_value);
    move_and_drop(stack, trace_read.micro);
    move_and_drop(stack, trace_read.read_1_add);
    move_and_drop(stack, trace_read.read_1_value);


    let mut write_addr = number_u32_partial(stack, base_register_address, 6);
    stack.move_var(rd);
    stack.join(&mut write_addr);
    stack.rename(write_addr, "write_addr");

    let write_value = match instruction {
        Lui(_) => imm,
        Auipc(_) => {
            let pc= stack.copy_var(trace_read.program_counter);
            add_with_bit_extension(stack, &tables, pc, &mut imm, StackVariable::null())
        }
        _ => panic!("Unreachable")
    };

    let write_pc = pc_next(stack, &tables, trace_read.program_counter);
    let micro = stack.number(0);    
    stack.rename(micro, "write_micro");

    let trace = TraceStep::new(write_addr, write_value, write_pc, micro);
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


pub fn execute_step( stack: &mut StackTracker, mut trace_read: TraceRead, trace_step: &TraceStep, witness: Option<StackVariable>, instruction: &Instruction, micro: u8, program: ProgramSpec ) -> Result<TraceStep, ScriptValidation> {
    
    match instruction {

        Fence(_)  |
        Ebreak    |
        Ecall     => Ok(op_nop(stack, &mut trace_read)),


        Beq(_) | Bne(_) | Blt(_) | Bge(_) | Bltu(_) |
        Bgeu(_) => Ok(op_conditional(instruction, stack, &mut trace_read, program.base_register_address)),

        Lh(_)  | Lhu(_) | Lw(_)  |
        Lbu(_) | Lb(_) => Ok(op_load(instruction, stack, &mut trace_read, micro, program.base_register_address)),

        Sb(_) | Sh(_) | Sw(_) => Ok(op_store(instruction, stack, &mut trace_read, micro, program.base_register_address)),

        Jalr(_) => Ok(op_jalr(instruction, stack, &mut trace_read, program.base_register_address)),
        Jal(_) => Ok(op_jal(instruction, stack, &mut trace_read, program.base_register_address)),


        Slli(x) |
        Srli(x) |
        Srai(x) => {
            if x.rd() == 0 {
                Ok(op_nop(stack, &mut trace_read))
            }  else {
                Ok(op_arithmetic_imm(instruction, stack, &mut trace_read, program.base_register_address))
            }
        },
        Xori(x)  |
        Andi(x)  |
        Ori(x)   |
        Slti(x)  |
        Sltiu(x) |
        Addi(x) => { 
            if x.rd() == 0 {
                Ok(op_nop(stack, &mut trace_read))
            }  else {
                Ok(op_arithmetic_imm(instruction, stack, &mut trace_read, program.base_register_address))
            }
        },
        Mul( x) |
        Mulh( x) |
        Mulhsu( x) |
        Mulhu( x) |
        Div( x) |
        Divu( x) |
        Rem( x) |
        Remu( x) |
        Xor(x) |
        And(x) |
        Or (x) |
        Slt(x)  |
        Sltu(x) |
        Sll(x)  |
        Srl(x)  |
        Sra(x)  |
        Add(x)  |
        Sub(x) => {
            if x.rd() == 0 {
                Ok(op_nop(stack, &mut trace_read))
           } else {
                Ok(op_arithmetic(instruction, stack, &mut trace_read, trace_step, witness, program.base_register_address))
            }
        },
        Lui(x) | 
        Auipc(x) => {
            if x.rd() == 0 {
                Ok(op_nop(stack, &mut trace_read))
            } else {
                Ok(op_upper(instruction, stack, &mut trace_read, program.base_register_address))
            }
        },
        _ => Err(ScriptValidation::InstructionNotImplemented(format!("{:?}",instruction)))
    }

}

#[allow(clippy::too_many_arguments)]
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
    let micro = stack.number(micro as u32);
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
    let micro = stack.number(micro as u32);
    stack.rename(micro, "write_micro");
    TraceStep {
        write_1_add,
        write_1_value,
        program_counter,
        micro,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn verify(instruction_mapping: &Option<InstructionMapping>, program: ProgramSpec,
              r1: u32, v1: u32, r2: u32, v2: u32, pc: u32, micro: u8, opcode: u32,
              w1: u32, wv1: u32, wpc: u32, wmicro: u8, witness: Option<u32>) -> Result<bool, ScriptValidation> {

    let mut stack = StackTracker::new();
    let trace_step = load_trace_step_in_stack(&mut stack, w1, wv1, wpc, wmicro);
    let mut consumes = 11;

    let witness = match witness {
        Some(w) => {
            let witness = stack.number_u32(w);
            stack.rename(witness, "witness");
            consumes += 1;
            Some(witness)
        }
        None => None,
    };

    let trace_read = load_trace_read_in_stack(&mut stack, r1, v1, r2, v2, pc, micro, opcode);

    if let Some(mapping) = instruction_mapping {
        let instruction = riscv_decode::decode(opcode).unwrap();
        let key = get_key_from_instruction_and_micro(&instruction, micro);
        let verification_script = mapping.get(&key).unwrap();
        stack.custom(verification_script.clone() , consumes, false, 0, "verify");
    } else {
        verify_execution(&mut stack, trace_step, trace_read, witness, opcode, micro, program)?;
    }
    
    stack.op_true();

    if !stack.run().success {
        panic!("Verification failed");  
    }
    Ok(true)
}

pub fn verify_execution(stack: &mut StackTracker, mut trace_step: TraceStep, trace_read: TraceRead, witness: Option<StackVariable>, opcode: u32, micro: u8, program: ProgramSpec) -> Result<(), ScriptValidation> {
    let instruction = riscv_decode::decode(opcode).unwrap();
    let mut result_step = execute_step(stack, trace_read, &trace_step, witness,&instruction, micro, program)?;
    compare_trace_step(stack, &mut trace_step, &mut result_step);

    Ok(())
}

pub fn compare_trace_step(stack: &mut StackTracker, trace_step_commit: &mut TraceStep, trace_step_result: &mut TraceStep ) {

    stack.set_breakpoint("verify execution");

    stack.equals(&mut trace_step_commit.micro, true, &mut trace_step_result.micro, true);
    stack.equals(&mut trace_step_commit.program_counter, true, &mut trace_step_result.program_counter, true);
    stack.equals(&mut trace_step_commit.write_1_value, true, &mut trace_step_result.write_1_value, true);
    stack.equals(&mut trace_step_commit.write_1_add, true, &mut trace_step_result.write_1_add, true);

    stack.set_breakpoint("end verify execution");
}



#[cfg(test)]
mod tests {

    use riscv_decode::types::{BType, RType, ShiftType};

    use crate::riscv::decoder::get_register_address;

    use super::*;

    const BASE_REGISTER_ADDRESS: u32 = 0xA000_0000;

    #[test]
    fn test_conditional() {

        let mut stack = StackTracker::new();
        let opcode = 0x06f5C0e3; //beq
        let btype = BType(opcode);
        let instruction = Blt(btype);

        //let program = ProgramSpec::new(0xA000_0000);
        //let trace_step = load_trace_step_in_stack(&mut stack, 0xA000_0008, 0xDFFF_FFA0, 0x8000_00c4, 0);
        let mut trace_read = load_trace_read_in_stack(&mut stack, 0xA000_002c, 0x0000_0001, 0xA000_003c, 0x000_0002, 0x8000_0000, 0, opcode);
        op_conditional(&instruction, &mut stack, &mut trace_read, BASE_REGISTER_ADDRESS);

    }

    #[test]
    fn test_get_register() {

        for r in 0..32 {  
            let mut stack = StackTracker::new();
            let tables = StackTables::new(&mut stack, false, false, 1, 4, 0);

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
        verify_execution(&mut stack, trace_step, trace_read, None, opcode, 0, program).unwrap();
        stack.op_true();
        assert!(stack.run().success);
    }

    #[test]
    fn test_add() {
        let opcode = 0x00A485B3; // ADD 11 9 10
        let rtype = RType(opcode);

        let write_address = BASE_REGISTER_ADDRESS + rtype.rd() * 4;

        let mut stack = StackTracker::new();

        // reg_addr = BASE_REGISTER_ADDRESS + reg_num * 4;
        let trace_step = load_trace_step_in_stack(&mut stack, write_address, 0x0000_0007, 0x8000_00c4, 0); // w, v, pc, micro
        let trace_read = load_trace_read_in_stack(&mut stack, 0xA000_0024, 0x0000_0004, 0xA000_0028, 0x0000_0003, // r1, v1, r2, v2
            0x8000_00c0, 0, opcode); // pc, micro, opcode

        let program = ProgramSpec::new(BASE_REGISTER_ADDRESS);
        verify_execution(&mut stack, trace_step, trace_read, None, opcode, 0, program).unwrap();

        stack.op_true();

        assert!(stack.run().success);
    }

    #[test]
    fn test_sub() {
        let opcode = 0x40a485b3; // SUB 11 9 10
        let rtype = RType(opcode);

        assert_eq!(9, rtype.rs1());
        assert_eq!(10, rtype.rs2());
        assert_eq!(11, rtype.rd());

        let decoded = riscv_decode::decode(opcode).unwrap();

        assert!(decoded.eq(&Sub(rtype)));

        let mut stack = StackTracker::new();

        let trace_read = load_trace_read_in_stack(
            &mut stack,
            reg_address(rtype.rs1()), 0x0000_1010,
            reg_address(rtype.rs2()), 0x0000_0103,
            0x8000_00c0, 0, opcode // pc, micro, opcode
        );
        let trace_step = load_trace_step_in_stack(
            &mut stack,
            reg_address(rtype.rd()), 0x0000_0F0D,
            0x8000_00c4, 0 // pc, micro
        );

        let program = ProgramSpec::new(BASE_REGISTER_ADDRESS);
        verify_execution(&mut stack, trace_step, trace_read, None, opcode, 0, program).unwrap();

        stack.op_true();

        assert!(stack.run().success);
    }

    #[test]
    fn test_slt() {
        let opcode = 0x00a4a5b3; // SLT 11 9 10
        let rtype = RType(opcode);

        assert_eq!(9, rtype.rs1());
        assert_eq!(10, rtype.rs2());
        assert_eq!(11, rtype.rd());

        let decoded = riscv_decode::decode(opcode).unwrap();

        assert!(decoded.eq(&Slt(rtype)));


        // test set to one
        let mut stack = StackTracker::new();

        // reg_addr = BASE_REGISTER_ADDRESS + reg_num * 4;
        let trace_step = load_trace_step_in_stack(&mut stack, 0xA000_002C, 0x1, 0x8000_00C4, 0); // w, v, pc, micro
        let trace_read = load_trace_read_in_stack(&mut stack, 0xA000_0024, 0x3, 0xA000_0028, 0x4, // r1, v1, r2, v2
            0x8000_00C0, 0, opcode); // pc, micro, opcode

        let program = ProgramSpec::new(BASE_REGISTER_ADDRESS);
        verify_execution(&mut stack, trace_step, trace_read, None, opcode, 0, program).unwrap();

        stack.op_true();

        assert!(stack.run().success);

        // test set to zero
        let mut stack = StackTracker::new();

        // reg_addr = BASE_REGISTER_ADDRESS + reg_num * 4;
        let trace_step = load_trace_step_in_stack(&mut stack, 0xA000_002C, 0x0, 0x8000_00C4, 0); // w, v, pc, micro
        let trace_read = load_trace_read_in_stack(&mut stack, 0xA000_0024, 0x5, 0xA000_0028, 0x4, // r1, v1, r2, v2
            0x8000_00C0, 0, opcode); // pc, micro, opcode

        let program = ProgramSpec::new(BASE_REGISTER_ADDRESS);
        verify_execution(&mut stack, trace_step, trace_read, None, opcode, 0, program).unwrap();

        stack.op_true();

        assert!(stack.run().success);
    }

    #[test]
    fn test_sltu() {
        let opcode = 0x00a4b5b3; // SLTU 11 9 10
        let rtype = RType(opcode);

        assert_eq!(9, rtype.rs1());
        assert_eq!(10, rtype.rs2());
        assert_eq!(11, rtype.rd());

        let decoded = riscv_decode::decode(opcode).unwrap();

        assert!(decoded.eq(&Sltu(rtype)));

        // test set to one
        let mut stack = StackTracker::new();

        // reg_addr = BASE_REGISTER_ADDRESS + reg_num * 4;
        let trace_step = load_trace_step_in_stack(&mut stack, 0xA000_002C, 0x1, 0x8000_00C4, 0); // w, v, pc, micro
        let trace_read = load_trace_read_in_stack(&mut stack, 0xA000_0024, 0x3, 0xA000_0028, 0x4, // r1, v1, r2, v2
            0x8000_00C0, 0, opcode); // pc, micro, opcode

        let program = ProgramSpec::new(BASE_REGISTER_ADDRESS);
        verify_execution(&mut stack, trace_step, trace_read, None, opcode, 0, program).unwrap();

        stack.op_true();

        assert!(stack.run().success);

        // test set to zero
        let mut stack = StackTracker::new();

        // reg_addr = BASE_REGISTER_ADDRESS + reg_num * 4;
        let trace_step = load_trace_step_in_stack(&mut stack, 0xA000_002C, 0x0, 0x8000_00C4, 0); // w, v, pc, micro
        let trace_read = load_trace_read_in_stack(&mut stack, 0xA000_0024, 0x5, 0xA000_0028, 0x4, // r1, v1, r2, v2
            0x8000_00C0, 0, opcode); // pc, micro, opcode

        let program = ProgramSpec::new(BASE_REGISTER_ADDRESS);
        verify_execution(&mut stack, trace_step, trace_read, None, opcode, 0, program).unwrap();

        stack.op_true();

        assert!(stack.run().success);
    }

    #[test]
    fn test_xor() {
        let opcode = 0x00a4c5b3; // XOR 11 9 10
        let rtype = RType(opcode);

        assert_eq!(rtype.rs1(), 9);
        assert_eq!(rtype.rs2(), 10);
        assert_eq!(rtype.rd(), 11);

        // rs1 = BASE_REGISTER_ADDRESS + rtype.rs1() * 4;
        // rs2 = BASE_REGISTER_ADDRESS + rtype.rs2() * 4;
        // rd = BASE_REGISTER_ADDRESS + rtype.rd() * 4;

        let write_address = BASE_REGISTER_ADDRESS + rtype.rd() * 4;

        let mut stack = StackTracker::new();

        let read_value_1: u32 = 0b0001_0010_0011_0100_0101_0110_0111_1000;
        let read_value_2: u32 = 0b1001_1010_1011_1100_1101_1110_1111_0000;
        let write_value: u32 =  0b1000_1000_1000_1000_1000_1000_1000_1000;

        assert_eq!(read_value_1, 0x12345678);
        assert_eq!(read_value_2, 0x9ABCDEF0);
        assert_eq!(write_value, 0x88888888);

        let trace_step = load_trace_step_in_stack(&mut stack, write_address, write_value, 0x8000_00c4, 0); // w, v, pc, micro
        let trace_read = load_trace_read_in_stack(&mut stack, 0xA000_0024, read_value_1, 0xA000_0028, read_value_2, // r1, v1, r2, v2
            0x8000_00c0, 0, opcode); // pc, micro, opcode

        let program = ProgramSpec::new(BASE_REGISTER_ADDRESS);
        verify_execution(&mut stack, trace_step, trace_read, None, opcode, 0, program).unwrap();

        stack.op_true();

        assert!(stack.run().success);
    }

    #[test]
    fn test_and() {
        let opcode = 0x00a4f5b3; // AND 11 9 10
        let rtype = RType(opcode);

        assert_eq!(rtype.rs1(), 9);
        assert_eq!(rtype.rs2(), 10);
        assert_eq!(rtype.rd(), 11);

        // rs1 = BASE_REGISTER_ADDRESS + rtype.rs1() * 4;
        // rs2 = BASE_REGISTER_ADDRESS + rtype.rs2() * 4;
        // rd = BASE_REGISTER_ADDRESS + rtype.rd() * 4;

        let write_address = BASE_REGISTER_ADDRESS + rtype.rd() * 4;

        let mut stack = StackTracker::new();

        let read_value_1: u32 = 0b0001_0010_0011_0100_0101_0110_0111_1000;
        let read_value_2: u32 = 0b1001_1010_1011_1100_1101_1110_1111_0000;
        let write_value: u32 =  0b0001_0010_0011_0100_0101_0110_0111_0000;

        assert_eq!(read_value_1, 0x12345678);
        assert_eq!(read_value_2, 0x9ABCDEF0);
        assert_eq!(write_value,  0x12345670);

        let trace_step = load_trace_step_in_stack(&mut stack, write_address, write_value, 0x8000_00c4, 0); // w, v, pc, micro
        let trace_read = load_trace_read_in_stack(&mut stack, 0xA000_0024, read_value_1, 0xA000_0028, read_value_2, // r1, v1, r2, v2
            0x8000_00c0, 0, opcode); // pc, micro, opcode

        let program = ProgramSpec::new(BASE_REGISTER_ADDRESS);
        verify_execution(&mut stack, trace_step, trace_read, None, opcode, 0, program).unwrap();

        stack.op_true();

        assert!(stack.run().success);
    }

    #[test]
    fn test_or() {
        let opcode = 0x00a4e5b3; // OR 11 9 10
        let rtype = RType(opcode);

        assert_eq!(rtype.rs1(), 9);
        assert_eq!(rtype.rs2(), 10);
        assert_eq!(rtype.rd(), 11);

        // rs1 = BASE_REGISTER_ADDRESS + rtype.rs1() * 4;
        // rs2 = BASE_REGISTER_ADDRESS + rtype.rs2() * 4;
        // rd = BASE_REGISTER_ADDRESS + rtype.rd() * 4;

        let write_address = BASE_REGISTER_ADDRESS + rtype.rd() * 4;

        let mut stack = StackTracker::new();

        let read_value_1: u32 = 0b0001_0010_0011_0100_0101_0110_0111_1000;
        let read_value_2: u32 = 0b1001_1010_1011_1100_1101_1110_1111_0000;
        let write_value: u32 =  0b1001_1010_1011_1100_1101_1110_1111_1000;

        assert_eq!(read_value_1, 0x12345678);
        assert_eq!(read_value_2, 0x9ABCDEF0);
        assert_eq!(write_value,  0x9ABCDEF8);

        let trace_step = load_trace_step_in_stack(&mut stack, write_address, write_value, 0x8000_00c4, 0); // w, v, pc, micro
        let trace_read = load_trace_read_in_stack(&mut stack, 0xA000_0024, read_value_1, 0xA000_0028, read_value_2, // r1, v1, r2, v2
            0x8000_00c0, 0, opcode); // pc, micro, opcode

        let program = ProgramSpec::new(BASE_REGISTER_ADDRESS);
        verify_execution(&mut stack, trace_step, trace_read, None, opcode, 0, program).unwrap();

        stack.op_true();

        assert!(stack.run().success);
    }

    #[test]
    fn test_slli() {
        let opcode = 0x00449593; // SLLI 11 9 4
        let shtype = ShiftType(opcode);

        assert_eq!(9, shtype.rs1());
        assert_eq!(4, shtype.shamt());
        assert_eq!(11, shtype.rd());

        let decoded = riscv_decode::decode(opcode).unwrap();

        assert!(decoded.eq(&Slli(shtype)));

        let mut stack = StackTracker::new();

        let read_1_value = 0b0000_0000_0000_0100;
        let write_value = 0b0000_0000_0100_0000; // left shifted by 4

        let trace_step = load_trace_step_in_stack(&mut stack, 0xA000_002C, write_value, 0x8000_00C4, 0); // w, v, pc, micro
        let trace_read = load_trace_read_in_stack(&mut stack, 0xA000_0024, read_1_value, 0, 0, // r1, v1, r2, v2
            0x8000_00C0, 0, opcode); // pc, micro, opcode

        let program = ProgramSpec::new(BASE_REGISTER_ADDRESS);
        verify_execution(&mut stack, trace_step, trace_read, None, opcode, 0, program).unwrap();

        stack.op_true();

        assert!(stack.run().success);
    }


    #[test]
    fn test_sll() {
        let opcode = 0x00a495b3;
        let rtype = RType(opcode);

        assert_eq!(9, rtype.rs1());
        assert_eq!(10, rtype.rs2());
        assert_eq!(11, rtype.rd());

        let decoded = riscv_decode::decode(opcode).unwrap();

        assert!(decoded.eq(&Sll(rtype)));

        let mut stack = StackTracker::new();

        let read_1_value = 0b0000_0000_0000_0100;
        let read_2_value = 0x1;
        let write_value =  0b0000_0000_0000_1000; // left shifted by 1

        // reg_addr = BASE_REGISTER_ADDRESS + reg_num * 4;
        let trace_step = load_trace_step_in_stack(&mut stack, 0xA000_002C, write_value, 0x8000_00C4, 0); // w, v, pc, micro
        let trace_read = load_trace_read_in_stack(&mut stack, 0xA000_0024, read_1_value, 0xA000_0028, read_2_value, // r1, v1, r2, v2
            0x8000_00C0, 0, opcode); // pc, micro, opcode

        let program = ProgramSpec::new(BASE_REGISTER_ADDRESS);
        verify_execution(&mut stack, trace_step, trace_read, None, opcode, 0, program).unwrap();

        stack.op_true();

        assert!(stack.run().success);
    }

    #[test]
    fn test_srl() {
        let opcode = 0x00a4d5b3;
        let rtype = RType(opcode);

        assert_eq!(9, rtype.rs1());
        assert_eq!(10, rtype.rs2());
        assert_eq!(11, rtype.rd());

        let decoded = riscv_decode::decode(opcode).unwrap();

        assert!(decoded.eq(&Srl(rtype)));

        let mut stack = StackTracker::new();

        let read_1_value = 0b0000_0000_0000_0100;
        let read_2_value = 0x1;
        let write_value =  0b0000_0000_0000_0010; // right shifted by 1

        // reg_addr = BASE_REGISTER_ADDRESS + reg_num * 4;
        let trace_step = load_trace_step_in_stack(&mut stack, 0xA000_002C, write_value, 0x8000_00C4, 0); // w, v, pc, micro
        let trace_read = load_trace_read_in_stack(&mut stack, 0xA000_0024, read_1_value, 0xA000_0028, read_2_value, // r1, v1, r2, v2
            0x8000_00C0, 0, opcode); // pc, micro, opcode

        let program = ProgramSpec::new(BASE_REGISTER_ADDRESS);
        verify_execution(&mut stack, trace_step, trace_read, None, opcode, 0, program).unwrap();

        stack.op_true();

        assert!(stack.run().success);
    }

    #[test]
    fn test_sra() {
        let opcode = 0x40a4d5b3; // SRA 11 9 10
        let rtype = RType(opcode);

        assert_eq!(9, rtype.rs1());
        assert_eq!(10, rtype.rs2());
        assert_eq!(11, rtype.rd());

        let decoded = riscv_decode::decode(opcode).unwrap();

        assert!(decoded.eq(&Sra(rtype)));

        let mut stack = StackTracker::new();

        let read_1_value = 0b10000000000000000000000000000000;
        let read_2_value = 0x1;
        let write_value =  0b11000000000000000000000000000000; // right-arithmetical shifted by 1

        // reg_addr = BASE_REGISTER_ADDRESS + reg_num * 4;
        let trace_step = load_trace_step_in_stack(&mut stack, 0xA000_002C, write_value, 0x8000_00C4, 0); // w, v, pc, micro
        let trace_read = load_trace_read_in_stack(&mut stack, 0xA000_0024, read_1_value, 0xA000_0028, read_2_value, // r1, v1, r2, v2
            0x8000_00C0, 0, opcode); // pc, micro, opcode

        let program = ProgramSpec::new(BASE_REGISTER_ADDRESS);
        verify_execution(&mut stack, trace_step, trace_read, None, opcode, 0, program).unwrap();

        stack.op_true();

        assert!(stack.run().success);
    }

    fn reg_address(addr_num: u32) -> u32 {
        BASE_REGISTER_ADDRESS + addr_num * 4
    }

}
