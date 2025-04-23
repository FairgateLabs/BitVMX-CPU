use bitcoin_script_stack::stack::{StackTracker, StackVariable};
use bitvmx_cpu_definitions::memory::{MemoryAccessType, MemoryWitness};
use riscv_decode::Instruction::{self, *};

use crate::riscv::{decoder::decode_i_type, operations::*, script_utils::*};

use super::{
    instructions::{validate_register_address, verify_memory_witness},
    memory_alignment::*,
    trace::{STraceRead, STraceStep},
};

pub fn op_load(
    instruction: &Instruction,
    stack: &mut StackTracker,
    trace_read: &STraceRead,
    micro: u8,
    base_register_address: u32,
) -> STraceStep {
    match micro {
        0 => op_load_micro_0(instruction, stack, trace_read, micro, base_register_address),
        1 => op_load_micro_1(instruction, stack, trace_read, micro, base_register_address),
        2 => op_load_micro_2(instruction, stack, trace_read, micro, base_register_address),
        3 => op_load_micro_3(instruction, stack, trace_read, micro, base_register_address),
        _ => panic!("Unreachable"),
    }
}

pub fn op_load_micro_0(
    instruction: &Instruction,
    stack: &mut StackTracker,
    trace_read: &STraceRead,
    micro: u8,
    base_register_address: u32,
) -> STraceStep {
    let (func3, aligned_if_less_than) = match instruction {
        Lb(_) => (0, 4),
        Lh(_) => (1, 3),
        Lw(_) => (2, 1),
        Lbu(_) => (4, 4),
        Lhu(_) => (5, 3),
        _ => panic!("Unreachable"),
    };

    let tables = StackTables::new(stack, true, true, 1, 5, 0);

    stack.set_breakpoint(&format!("op_{:?}", instruction));

    let (imm, rs1, rd, bit_extension) =
        decode_i_type(stack, &tables, trace_read.opcode, func3, 0x3, None);

    verify_memory_witness(
        stack,
        trace_read.mem_witness,
        MemoryWitness::new(
            MemoryAccessType::Register,
            MemoryAccessType::Memory,
            MemoryAccessType::Register,
        ),
    );

    stack.move_var(trace_read.micro);
    let expected_micro = stack.number(0);
    stack.equals(trace_read.micro, true, expected_micro, true);

    // assert rs1 + base_register_address == read_1 address
    validate_register_address(stack, trace_read.read_1_add, rs1, base_register_address);
    move_and_drop(stack, rs1); //This should be consumed
    move_and_drop(stack, trace_read.read_1_add);

    //assert read_2_add = read_1_value + imm
    let post_mem_to_read =
        add_with_bit_extension(stack, &tables, trace_read.read_1_value, imm, bit_extension);

    //get the aligned memory address and the alignment offset
    let (aligned, alignment) = align_memory(stack, post_mem_to_read);
    stack.rename(aligned, "aligned_addr");
    stack.rename(alignment, "alignment_offset");

    stack.op_dup();

    stack.number(aligned_if_less_than);
    stack.op_lessthan(); //decide to use aligned to 0 case or missaligned case

    let (mut if_true, mut if_false) = stack.open_if();

    op_load_micro_0_aligned(
        instruction,
        &mut if_true,
        &tables,
        rd,
        aligned,
        alignment,
        trace_read,
        micro,
        base_register_address,
    );
    op_load_micro_0_missaligned(
        instruction,
        &mut if_false,
        &tables,
        rd,
        aligned,
        alignment,
        trace_read,
        micro,
        base_register_address,
    );

    let ret = stack.end_if(
        if_true,
        if_false,
        11,
        vec![
            (8, "write_add".to_string()),
            (8, "write_value".to_string()),
            (8, "write_pc".to_string()),
            (1, "write_micro".to_string()),
        ],
        0,
    );

    STraceStep::new(ret[0], ret[1], ret[2], ret[3])
}

#[allow(clippy::too_many_arguments)]
pub fn op_load_micro_0_missaligned(
    instruction: &Instruction,
    stack: &mut StackTracker,
    tables: &StackTables,
    rd: StackVariable,
    aligned: StackVariable,
    alignment: StackVariable,
    trace_read: &STraceRead,
    _micro: u8,
    base_register_address: u32,
) -> STraceStep {
    let (nibs, max_extra, prepad, unsigned) = match instruction {
        Lb(_) => (2, 0, 6, false),
        Lh(_) => (4, 2, 4, false),
        Lw(_) => (8, 6, 0, true),
        Lbu(_) => (2, 0, 6, true),
        Lhu(_) => (4, 2, 4, true),
        _ => panic!("Unreachable"),
    };

    //save the alignment
    stack.to_altstack();
    //assert read_2_add with expected memory read

    stack.equals(trace_read.read_2_add, true, aligned, true);

    //generate the write address
    let write_addr = stack.number_u32(base_register_address + 0x80); //address of AUX1
    stack.rename(write_addr, "write_add");

    move_and_drop(stack, rd);

    //calculate the byte to be stored (with proper bit extension)
    stack.move_var(trace_read.read_2_value);
    stack.from_altstack(); //restore alignment
    let write_value = choose_nibbles(
        stack,
        trace_read.read_2_value,
        alignment,
        nibs,
        max_extra,
        prepad,
        unsigned,
        0,
    );
    stack.rename(write_value, "write_value");

    let write_pc = stack.move_var(trace_read.program_counter);
    stack.rename(write_pc, "write_pc");
    let micro = stack.number(1);
    stack.rename(micro, "write_micro");

    let trace = STraceStep::new(write_addr, write_value, write_pc, micro);
    trace.to_altstack(stack);
    tables.drop(stack);
    trace.from_altstack(stack);

    trace
}

#[allow(clippy::too_many_arguments)]
pub fn op_load_micro_0_aligned(
    instruction: &Instruction,
    stack: &mut StackTracker,
    tables: &StackTables,
    rd: StackVariable,
    aligned: StackVariable,
    alignment: StackVariable,
    trace_read: &STraceRead,
    _micro: u8,
    base_register_address: u32,
) -> STraceStep {
    let (nibs, max_extra, prepad, unsigned) = match instruction {
        Lb(_) => (2, 0, 6, false),
        Lh(_) => (4, 2, 4, false),
        Lw(_) => (8, 6, 0, true),
        Lbu(_) => (2, 0, 6, true),
        Lhu(_) => (4, 2, 4, true),
        _ => panic!("Unreachable"),
    };

    //save the alignment
    stack.to_altstack();
    //assert read_2_add with expected memory read

    stack.equals(trace_read.read_2_add, true, aligned, true);

    //generate the write address
    let write_addr = number_u32_partial(stack, base_register_address, 6);
    stack.move_var(rd);
    stack.join(write_addr);
    stack.rename(write_addr, "write_add");

    //calculate the byte to be stored (with proper bit extension)
    stack.move_var(trace_read.read_2_value);
    stack.from_altstack(); //restore alignment
    let write_value = choose_nibbles(
        stack,
        trace_read.read_2_value,
        alignment,
        nibs,
        max_extra,
        prepad,
        unsigned,
        0,
    );
    stack.rename(write_value, "write_value");

    let write_pc = pc_next(stack, tables, trace_read.program_counter);
    let micro = stack.number(0);
    stack.rename(micro, "write_micro");

    let trace = STraceStep::new(write_addr, write_value, write_pc, micro);
    trace.to_altstack(stack);
    tables.drop(stack);
    trace.from_altstack(stack);

    trace
}

pub fn op_load_micro_1(
    instruction: &Instruction,
    stack: &mut StackTracker,
    trace_read: &STraceRead,
    _micro: u8,
    base_register_address: u32,
) -> STraceStep {
    let (func3, nibs, max_extra, pre_pad, post, unsigned) = match instruction {
        Lh(_) => (1, 4, 0, 4, 8, false),
        Lhu(_) => (5, 4, 0, 4, 8, true),
        Lw(_) => (2, 8, 0, 0, 8, true),
        _ => panic!("Unreachable"),
    };

    let tables = StackTables::new(stack, true, true, 1, 5, 0);

    stack.set_breakpoint(&format!("op_{:?}", instruction));

    let (imm, rs1, rd, bit_extension) =
        decode_i_type(stack, &tables, trace_read.opcode, func3, 0x3, None);

    verify_memory_witness(
        stack,
        trace_read.mem_witness,
        MemoryWitness::new(
            MemoryAccessType::Register,
            MemoryAccessType::Memory,
            MemoryAccessType::Register,
        ),
    );

    stack.move_var(trace_read.micro);
    let expected_micro = stack.number(1);
    stack.equals(trace_read.micro, true, expected_micro, true);

    validate_register_address(stack, trace_read.read_1_add, rs1, base_register_address);
    move_and_drop(stack, rs1); //This should be consumed
    move_and_drop(stack, trace_read.read_1_add);

    //generate the write address
    let write_addr = stack.number_u32(base_register_address + 0x84); //address of AUX2
    stack.rename(write_addr, "write_add");
    move_and_drop(stack, rd);

    //assert read_2_add = read_1_value + imm
    let post_mem_to_read =
        add_with_bit_extension(stack, &tables, trace_read.read_1_value, imm, bit_extension);

    //get the aligned memory address and the alignment offset
    let (aligned, alignment) = align_memory(stack, post_mem_to_read);
    //save the alignment
    stack.to_altstack();
    //assert read_2_add with expected memory read
    let add_4 = stack.number(4);
    let bit_extension = stack.number(0);

    let algined_plus_4 = add_with_bit_extension(stack, &tables, aligned, add_4, bit_extension);

    stack.equals(trace_read.read_2_add, true, algined_plus_4, true);

    //calculate the byte to be stored (with proper bit extension)
    stack.move_var(trace_read.read_2_value);
    stack.from_altstack(); //restore alignment
    let write_value = choose_nibbles(
        stack,
        trace_read.read_2_value,
        alignment,
        nibs,
        max_extra,
        pre_pad,
        unsigned,
        post,
    );
    stack.rename(write_value, "write_value");

    let write_pc = stack.move_var(trace_read.program_counter);
    stack.rename(write_pc, "write_pc");
    let micro = stack.number(2);
    stack.rename(micro, "write_micro");

    let trace = STraceStep::new(write_addr, write_value, write_pc, micro);
    trace.to_altstack(stack);
    tables.drop(stack);
    trace.from_altstack(stack);

    trace
}

pub fn op_load_micro_2(
    instruction: &Instruction,
    stack: &mut StackTracker,
    trace_read: &STraceRead,
    _micro: u8,
    base_register_address: u32,
) -> STraceStep {
    let func3 = match instruction {
        Lh(_) => 1,
        Lhu(_) => 5,
        Lw(_) => 2,
        _ => panic!("Unreachable"),
    };

    let tables = StackTables::new(stack, true, true, 1, 5, LOGIC_MASK_OR);

    let (imm, rs1, rd, bit_extension) =
        decode_i_type(stack, &tables, trace_read.opcode, func3, 0x3, None);

    verify_memory_witness(stack, trace_read.mem_witness, MemoryWitness::registers());
    stack.move_var(trace_read.micro);
    let expected_micro = stack.number(2);
    stack.equals(trace_read.micro, true, expected_micro, true);

    move_and_drop(stack, rs1);
    move_and_drop(stack, rd);
    move_and_drop(stack, imm);
    move_and_drop(stack, bit_extension);

    let expected_read_1 = stack.number_u32(base_register_address + 0x80);
    stack.equals(trace_read.read_1_add, true, expected_read_1, true);

    let expected_read_2 = stack.number_u32(base_register_address + 0x84);
    stack.equals(trace_read.read_2_add, true, expected_read_2, true);

    //generate the write address
    let write_addr = stack.number_u32(base_register_address + 0x80); //address of AUX1
    stack.rename(write_addr, "write_add");

    let write_value = logic_with_bit_extension(
        stack,
        &tables,
        trace_read.read_1_value,
        trace_read.read_2_value,
        StackVariable::null(),
        LogicOperation::Or,
    );
    stack.rename(write_value, "write_value");

    let write_pc = stack.move_var(trace_read.program_counter);
    stack.rename(write_pc, "write_pc");
    let micro = stack.number(3);
    stack.rename(micro, "write_micro");

    let trace = STraceStep::new(write_addr, write_value, write_pc, micro);
    trace.to_altstack(stack);
    tables.drop(stack);
    trace.from_altstack(stack);

    trace
}

pub fn op_load_micro_3(
    instruction: &Instruction,
    stack: &mut StackTracker,
    trace_read: &STraceRead,
    _micro: u8,
    base_register_address: u32,
) -> STraceStep {
    let func3 = match instruction {
        Lh(_) => 1,
        Lhu(_) => 5,
        Lw(_) => 2,
        _ => panic!("Unreachable"),
    };

    let tables = StackTables::new(stack, true, true, 1, 5, 0);

    let (imm, rs1, rd, bit_extension) =
        decode_i_type(stack, &tables, trace_read.opcode, func3, 0x3, None);

    verify_memory_witness(stack, trace_read.mem_witness, MemoryWitness::rur());
    stack.to_altstack(); // save rd
    stack.drop(rs1);
    stack.drop(bit_extension);
    stack.drop(imm);
    stack.from_altstack();

    stack.move_var(trace_read.micro);
    let expected_micro = stack.number(3);
    stack.equals(trace_read.micro, true, expected_micro, true);

    let expected_read_1 = stack.number_u32(base_register_address + 0x80);
    stack.equals(trace_read.read_1_add, true, expected_read_1, true);

    let expected_read_2_addr = stack.number_u32(0);
    stack.equals(trace_read.read_2_add, true, expected_read_2_addr, true);
    let expected_read_2_value = stack.number_u32(0);
    stack.equals(trace_read.read_2_value, true, expected_read_2_value, true);

    let write_addr = number_u32_partial(stack, base_register_address, 6);
    stack.move_var(rd);
    stack.join(write_addr);
    stack.rename(write_addr, "write_add");

    let write_value = stack.move_var(trace_read.read_1_value);
    stack.rename(write_value, "write_value");

    let write_pc = pc_next(stack, &tables, trace_read.program_counter);
    stack.rename(write_pc, "write_pc");
    let micro = stack.number(0);
    stack.rename(micro, "write_micro");

    let trace = STraceStep::new(write_addr, write_value, write_pc, micro);
    trace.to_altstack(stack);
    tables.drop(stack);
    trace.from_altstack(stack);

    trace
}
