use bitcoin_script_stack::stack::{StackTracker, StackVariable};
use bitvmx_cpu_definitions::memory::{MemoryAccessType, MemoryWitness};
use riscv_decode::Instruction::{self, *};

use crate::riscv::{decoder::decode_s_type, operations::*, script_utils::*};

use super::{
    instructions::{validate_register_address, verify_memory_witness},
    memory_alignment::*,
    trace::{STraceRead, STraceStep},
};

pub fn op_store(
    instruction: &Instruction,
    stack: &mut StackTracker,
    trace_read: &STraceRead,
    micro: u8,
    base_register_address: u32,
) -> STraceStep {
    let micro = micro as u32;
    match micro {
        0 | 4 => op_store_micro_0(instruction, stack, trace_read, micro, base_register_address),
        1 | 5 => op_store_micro_1(instruction, stack, trace_read, micro, base_register_address),
        2 | 6 => op_store_micro_2(instruction, stack, trace_read, micro, base_register_address),
        3 | 7 => op_store_micro_3(instruction, stack, trace_read, micro, base_register_address),
        _ => panic!("Unreachable"),
    }
}

pub fn op_store_micro_0(
    instruction: &Instruction,
    stack: &mut StackTracker,
    trace_read: &STraceRead,
    micro: u32,
    base_register_address: u32,
) -> STraceStep {
    let (func3, mut if_alignment_less) = match instruction {
        Sb(_) => (0x0, 0),
        Sh(_) => (0x1, 0),
        Sw(_) => (0x2, 1),
        _ => panic!("Unreachable"),
    };

    let tables = StackTables::new(stack, true, true, 3, 7, 0);
    let (bit_extension, imm, rs1, rs2) = decode_s_type(stack, &tables, trace_read.opcode, func3);

    //assert micro 0
    stack.move_var(trace_read.micro);
    let expected_micro = stack.number(micro);
    stack.equals(trace_read.micro, true, expected_micro, true);

    // assert rs1 + base_register_address == read_1 address
    validate_register_address(stack, trace_read.read_1_add, rs1, base_register_address);
    move_and_drop(stack, rs1);
    move_and_drop(stack, trace_read.read_1_add);

    //move vars that will be used and consumed on the branches
    stack.move_var(trace_read.read_2_add);
    stack.move_var(trace_read.read_2_value);
    stack.move_var(trace_read.program_counter);
    stack.move_var(trace_read.mem_witness);

    //mem_to_write = read_1_value + imm
    let mem_to_write =
        add_with_bit_extension(stack, &tables, trace_read.read_1_value, imm, bit_extension);
    //get the aligned memory address and the alignment offset
    let (mut aligned, alignment) = align_memory(stack, mem_to_write);

    if micro == 4 {
        if_alignment_less = 0;
        let add_4 = stack.number(4);
        let bit_extension = stack.number(0);
        aligned = add_with_bit_extension(stack, &tables, aligned, add_4, bit_extension);
        stack.move_var(alignment);
    }

    stack.op_dup(); //save alignment

    stack.number(if_alignment_less);
    stack.op_lessthan(); //branch if alignment < if_alignment_less
    let (mut if_true, mut if_false) = stack.open_if();

    verify_memory_witness(
        &mut if_true,
        trace_read.mem_witness,
        MemoryWitness::new(
            MemoryAccessType::Register,
            MemoryAccessType::Register,
            MemoryAccessType::Memory,
        ),
    );

    verify_memory_witness(
        &mut if_false,
        trace_read.mem_witness,
        MemoryWitness::new(
            MemoryAccessType::Register,
            MemoryAccessType::Memory,
            MemoryAccessType::Register,
        ),
    );

    op_store_sw_aligned(
        &mut if_true,
        &tables,
        trace_read,
        aligned,
        rs2,
        base_register_address,
    );
    op_store_micro_0_missaligned(
        &mut if_false,
        instruction,
        trace_read,
        aligned,
        rs2,
        micro,
        base_register_address,
    );

    let ret = stack.end_if(
        if_true,
        if_false,
        7,
        vec![
            (8, "write_add".to_string()),
            (8, "write_value".to_string()),
            (8, "write_pc".to_string()),
            (1, "write_micro".to_string()),
        ],
        0,
    );

    let trace = STraceStep::new(ret[0], ret[1], ret[2], ret[3]);

    trace.to_altstack(stack);
    tables.drop(stack);
    trace.from_altstack(stack);

    trace
}

fn op_store_micro_0_missaligned(
    stack: &mut StackTracker,
    instruction: &Instruction,
    trace_read: &STraceRead,
    aligned: StackVariable,
    rs2: StackVariable,
    micro: u32,
    base_register_address: u32,
) {
    stack.to_altstack(); //save alignment

    //assert that the aligned adddress is equal to read_2_address
    stack.equals(trace_read.read_2_add, true, aligned, true);

    move_and_drop(stack, rs2); //not used

    //generate the write address
    let write_addr = stack.number_u32(base_register_address + 0x80); //address of AUX1
    stack.rename(write_addr, "write_add");

    stack.move_var(trace_read.read_2_value);

    let round = if micro == 0 { 1 } else { 2 };
    let mask_table = create_alignment_table(stack, instruction, round);
    stack.from_altstack();
    let mask = mask_table.peek(stack);
    mask_table.drop(stack);

    let result = mask_value(stack, trace_read.read_2_value, mask);
    stack.rename(result, "write_value");

    let write_pc = stack.move_var(trace_read.program_counter);
    stack.rename(write_pc, "write_pc");
    let micro = stack.number(micro + 1);
    stack.rename(micro, "write_micro");
}

fn op_store_sw_aligned(
    stack: &mut StackTracker,
    tables: &StackTables,
    trace_read: &STraceRead,
    aligned: StackVariable,
    rs2: StackVariable,
    base_register_address: u32,
) {
    stack.op_drop();
    stack.rename(aligned, "write_addr");
    //stack.rename(alignment, "alignment_offset");

    validate_register_address(stack, trace_read.read_2_add, rs2, base_register_address);
    move_and_drop(stack, rs2);
    move_and_drop(stack, trace_read.read_2_add);

    let write_value = stack.move_var(trace_read.read_2_value);
    stack.rename(write_value, "write_value");

    pc_next(stack, tables, trace_read.program_counter);
    let micro = stack.number(0);
    stack.rename(micro, "write_micro");
}

pub fn op_store_micro_1(
    instruction: &Instruction,
    stack: &mut StackTracker,
    trace_read: &STraceRead,
    micro: u32,
    base_register_address: u32,
) -> STraceStep {
    let func3 = match instruction {
        Sb(_) => 0x0,
        Sh(_) => 0x1,
        Sw(_) => 0x2,
        _ => panic!("Unreachable"),
    };

    let tables = StackTables::new(stack, true, true, 3, 7, 0);
    let (bit_extension, imm, rs1, rs2) = decode_s_type(stack, &tables, trace_read.opcode, func3);

    verify_memory_witness(stack, trace_read.mem_witness, MemoryWitness::registers());

    //assert micro
    stack.move_var(trace_read.micro);
    let expected_micro = stack.number(micro);
    stack.equals(trace_read.micro, true, expected_micro, true);

    // assert rs1 + base_register_address == read_1 address
    validate_register_address(stack, trace_read.read_1_add, rs1, base_register_address);
    move_and_drop(stack, rs1);
    move_and_drop(stack, trace_read.read_1_add);

    // assert rs2 + base_register_address == read_1 address
    validate_register_address(stack, trace_read.read_2_add, rs2, base_register_address);
    move_and_drop(stack, rs2);
    move_and_drop(stack, trace_read.read_2_add);

    //alignment = read_1_value + imm
    let mem_to_write =
        add_with_bit_extension(stack, &tables, trace_read.read_1_value, imm, bit_extension);
    //get the aligned memory address and the alignment offset
    let (aligned, _alignment) = align_memory(stack, mem_to_write);

    stack.to_altstack();
    stack.drop(aligned);

    //generate the write address
    let write_addr = stack.number_u32(base_register_address + 0x84); //address of AUX2
    stack.rename(write_addr, "write_add");

    //the value to mask
    stack.move_var(trace_read.read_2_value);

    //load the mask table
    let round = if micro == 1 { 1 } else { 2 };
    let mask_table = create_alignment_table_2(stack, instruction, round);
    stack.from_altstack();
    stack.op_dup();
    stack.to_altstack();
    //peek with the alignment value
    let mask = mask_table.peek(stack);
    mask_table.drop(stack);

    //mask the value
    let masked_value = mask_value(stack, trace_read.read_2_value, mask);

    //restore alignment
    let alignment = stack.from_altstack();

    //rotate the value
    let result = left_rotate(stack, masked_value, alignment);
    stack.rename(result, "write_value");

    let write_pc = stack.move_var(trace_read.program_counter);
    stack.rename(write_pc, "write_pc");
    let write_micro = stack.number(micro + 1);
    stack.rename(write_micro, "write_micro");

    let trace = STraceStep::new(write_addr, result, write_pc, write_micro);

    trace.to_altstack(stack);
    tables.drop(stack);
    trace.from_altstack(stack);

    trace
}

pub fn op_store_micro_2(
    instruction: &Instruction,
    stack: &mut StackTracker,
    trace_read: &STraceRead,
    micro: u32,
    base_register_address: u32,
) -> STraceStep {
    let func3 = match instruction {
        Sb(_) => 0x0,
        Sh(_) => 0x1,
        Sw(_) => 0x2,
        _ => panic!("Unreachable"),
    };

    let tables = StackTables::new(stack, true, true, 3, 7, 0);
    let (bit_extension, imm, rs1, rs2) = decode_s_type(stack, &tables, trace_read.opcode, func3);

    verify_memory_witness(stack, trace_read.mem_witness, MemoryWitness::registers());

    //assert micro
    stack.move_var(trace_read.micro);
    let expected_micro = stack.number(micro);
    stack.equals(trace_read.micro, true, expected_micro, true);

    let expected_read_1 = stack.number_u32(base_register_address + 0x80);
    stack.equals(trace_read.read_1_add, true, expected_read_1, true);

    let expected_read_2 = stack.number_u32(base_register_address + 0x84);
    stack.equals(trace_read.read_2_add, true, expected_read_2, true);

    move_and_drop(stack, rs1);
    move_and_drop(stack, rs2);
    move_and_drop(stack, imm);
    move_and_drop(stack, bit_extension);

    //generate the write address
    let write_addr = stack.number_u32(base_register_address + 0x80); //address of AUX1
    stack.rename(write_addr, "write_add");

    //as the read_1_value and read_2_value are masked, we are going to just add them instead of doing or
    for _ in 0..8 {
        stack.move_var_sub_n(trace_read.read_1_value, 0);
        stack.move_var_sub_n(trace_read.read_2_value, 0);
        stack.op_add();
    }

    let write_value = stack.join_in_stack(8, None, Some("write_value"));

    let write_pc = stack.move_var(trace_read.program_counter);
    stack.rename(write_pc, "write_pc");
    let write_micro = stack.number(micro + 1);
    stack.rename(write_micro, "write_micro");

    let trace = STraceStep::new(write_addr, write_value, write_pc, write_micro);

    trace.to_altstack(stack);
    tables.drop(stack);
    trace.from_altstack(stack);

    trace
}

pub fn op_store_micro_3(
    instruction: &Instruction,
    stack: &mut StackTracker,
    trace_read: &STraceRead,
    micro: u32,
    base_register_address: u32,
) -> STraceStep {
    let (func3, if_alignment) = match instruction {
        Sb(_) => (0x0, 4),
        Sh(_) => (0x1, 3),
        Sw(_) => (0x2, 0),
        _ => panic!("Unreachable"),
    };

    let tables = StackTables::new(stack, true, true, 3, 7, 0);
    let (bit_extension, imm, rs1, rs2) = decode_s_type(stack, &tables, trace_read.opcode, func3);

    verify_memory_witness(
        stack,
        trace_read.mem_witness,
        MemoryWitness::new(
            MemoryAccessType::Register,
            MemoryAccessType::Register,
            MemoryAccessType::Memory,
        ),
    );

    //assert micro
    stack.move_var(trace_read.micro);
    let expected_micro = stack.number(micro);
    stack.equals(trace_read.micro, true, expected_micro, true);

    // assert rs1 + base_register_address == read_1 address
    validate_register_address(stack, trace_read.read_1_add, rs1, base_register_address);
    move_and_drop(stack, rs1);
    move_and_drop(stack, trace_read.read_1_add);

    let expected_read_2 = stack.number_u32(base_register_address + 0x80);
    stack.equals(trace_read.read_2_add, true, expected_read_2, true);
    move_and_drop(stack, rs2);

    //write_address = aligned(read_1_value + imm)
    let mem_to_write =
        add_with_bit_extension(stack, &tables, trace_read.read_1_value, imm, bit_extension);
    //get the aligned memory address and the alignment offset
    let (mut aligned, _alignment) = align_memory(stack, mem_to_write);
    stack.to_altstack();

    if micro == 7 {
        let add_4 = stack.number(4);
        let bit_extension = stack.number(0);
        aligned = add_with_bit_extension(stack, &tables, aligned, add_4, bit_extension);
    }

    stack.rename(aligned, "write_addr");

    //the result value
    let write_value = stack.move_var(trace_read.read_2_value);
    stack.rename(write_value, "write_value");

    stack.move_var(trace_read.program_counter);

    stack.from_altstack();
    if micro == 7 {
        stack.op_drop();
        stack.number(0); //force false
    } else {
        stack.number(if_alignment);
        stack.op_greaterthanorequal();
    }

    let (mut stack_if_true, mut stack_if_false) = stack.open_if();
    //if true keep the program counter
    stack_if_true.number(4);

    //if false, jump to the next instruction
    pc_next(&mut stack_if_false, &tables, trace_read.program_counter);
    stack_if_false.number(0);

    let ret = stack.end_if(
        stack_if_true,
        stack_if_false,
        1,
        vec![(8, "write_pc".to_string()), (1, "write_micro".to_string())],
        0,
    );
    let write_pc = ret[0];
    let write_micro = ret[1];

    let trace = STraceStep::new(aligned, write_value, write_pc, write_micro);

    trace.to_altstack(stack);
    tables.drop(stack);
    trace.from_altstack(stack);

    trace
}
