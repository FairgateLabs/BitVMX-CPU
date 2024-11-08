use std::{cmp::Ordering, collections::HashSet};

use crate::{executor::trace::*, executor::alignment_masks::*, loader::program::*, ExecutionResult};
use bitcoin_script_riscv::riscv::instruction_mapping::create_verification_script_mapping;
use riscv_decode::{types::*, Instruction::{self, *}};
use sha2::{Digest, Sha256};
use super::{trace::TraceRWStep, validator::validate, utils::FailReads};

pub fn execute_program(program: &mut Program, input: Vec<u8>, input_section: &str, little_endian: bool, save_checkpoints: bool, limit_step: Option<u64>, print_trace: bool,
                       validate_on_chain: bool, use_instruction_mapping: bool, print_program_stdout: bool, debug: bool, no_hash: bool,
                       fail_hash: Option<u64>, fail_execute: Option<u64>, trace_list: Option<Vec<u64>>,
                       mem_dump: Option<u64>, fail_reads: Option<FailReads>,
                       fail_pc: Option<u64>) -> Result<(Vec<String>, ExecutionResult), ExecutionResult> {
    let trace_set: Option<HashSet<u64>> = trace_list.map(|vec| vec.into_iter().collect());

    //TOOD: This is a hack to copy the input into the bss section
    //copy into bss section the input
    if !input.is_empty() {
        let section = program.find_section_by_name(input_section).ok_or(ExecutionResult::SectionNotFound(input_section.to_string()))?;
        let input_as_u32 = vec_u8_to_vec_u32(&input, little_endian);
        for (i, byte) in input_as_u32.iter().enumerate() {
            section.data[i] = *byte;
        }
    }
    let instruction_mapping = match validate_on_chain && use_instruction_mapping {
        true => Some(create_verification_script_mapping(program.registers.get_base_address())),
        false => None,
    };
    
    let mut hasher = Sha256::new();

    let mut count = 0;

    if save_checkpoints {
        Program::serialize_to_file(&program, "checkpoint.0.json");
    }

    let ret = loop {
        let mut should_patch = (false, false);
        if let Some(fr) = &fail_reads {
            should_patch = fr.patch_mem(program); // patches memory only at the right step
        }

        if let Some(fail) = fail_pc {
            if fail == program.step {
                program.pc.next_address(); // makes pc fail by advancing twice
            }
        }

        let mut trace = execute_step(program, print_program_stdout, debug);

        if trace.is_err() {
            if debug {
                println!("Result: {:?}", trace);
                println!("Returned value from main(): 0x{:08x}", program.registers.get(REGISTER_A0 as u32));
            }

            if debug && !input.is_empty() {
                let bss = program.find_section_by_name(input_section).ok_or(ExecutionResult::SectionNotFound(input_section.to_string()))?;
                for (idx, value) in bss.data.iter().enumerate().take(10) {
                    print!("{:x}: ", (idx * 4) + bss.start as usize);
                    println!("{:08x} ", value.to_be());
                }
            }
        }

        if trace.is_ok() {
            if let Some(fr) = &fail_reads {
                fr.patch_trace_reads(trace.as_mut().unwrap(), should_patch); // patches trace reads only at the right step
            }

            if let Some(fail) = fail_execute {
                if fail == program.step {
                    let value = &mut trace.as_mut().unwrap().trace_step.write_1.value;
                    *value = value.wrapping_add(1);
                }
            }

            if !no_hash {
                let trace_bytes = trace.as_ref().unwrap().trace_step.to_bytes();
                program.hash = compute_step_hash(&mut hasher, &program.hash, &trace_bytes);
                if let Some(fail) = fail_hash {
                    if fail == program.step {
                        program.hash = compute_step_hash(&mut hasher,&program.hash, &trace_bytes);
                    }
                }
            }

            if let Some(step) = mem_dump {
                if program.step == step {
                    println!("\n========== Dumping memory at step: {} ==========", step);
                    program.dump_memory();
                }
            }
        }

        if print_trace && trace.is_ok() {
            //println!("Step: {}", program.step);
            if trace_set.is_none() || trace_set.as_ref().unwrap().contains(&program.step) {
                let trace_str = trace.as_ref().unwrap().trace_step.to_hex_string();
                println!("{};{};{}", trace.as_ref().unwrap().to_csv(), trace_str, program.hash.iter().map(|byte| format!("{:02x}", byte)).collect::<String>());
            }
        }

        if save_checkpoints && (program.step % CHECKPOINT_SIZE == 0 || trace.is_err() || program.halt ) {
            Program::serialize_to_file(&program, &format!("checkpoint.{}.json", program.step));
        }

        if trace.is_ok() && validate_on_chain {
            if validate(trace.as_ref().unwrap(), program.registers.get_base_address(), &instruction_mapping ) {
                count += 1;
            } else {
                break ExecutionResult::Error;
            }
        }

        if trace.is_err() {
            break trace.unwrap_err();
        }

        if program.halt {
            break ExecutionResult::Halt(program.registers.get(REGISTER_A0 as u32));
        }

        if let Some(limit_step) = limit_step {
            if  limit_step == program.step {
                break ExecutionResult::LimitStepReached;
            }
        }
    };


    if debug && validate_on_chain {
        println!("Instructions validated on chain:  {}", count);
    }

    if debug { 
        println!("Last hash: {}", program.hash.iter().map(|byte| format!("{:02x}", byte)).collect::<String>());
    }

    Ok((vec![], ret))

}

pub fn wrapping_add(value: u32, x: u32, mask: u8) -> u32 {
    let offset = ((x as i32) << mask) >> mask;
    let value = value as i32;
    value.wrapping_add(offset) as u32
}

pub fn wrapping_add_btype(value: u32, x: &BType) -> u32 {
    wrapping_add(value, x.imm(),19)
}

pub fn wrapping_add_itype(value: u32, x: &IType) -> u32 {
    wrapping_add(value, x.imm(), 20)
}

pub fn wrapping_add_jtype(value: u32, x: &JType) -> u32 {
    wrapping_add(value, x.imm(), 11)
}

pub fn wrapping_add_stype(value: u32, x: &SType) -> u32 {
    wrapping_add(value, x.imm(), 20)
}

pub fn execute_step(program: &mut Program, print_program_stdout: bool, debug: bool) -> Result<TraceRWStep, ExecutionResult> {
    let pc = program.pc.clone();

    let opcode = program.read_mem(pc.get_address());
    let instruction = riscv_decode::decode(opcode).unwrap();

    if debug && program.step % 100000000 < 10000 {
        println!("Step: {} PC: 0x{:08x}:{} Opcode: 0x{:08x} Instruction: {:?} ", program.step, pc.get_address(), pc.get_micro(), opcode, instruction );
    }

    let mut witness = None;
    
    let (read_1, read_2, write_1) = match instruction {
        Ebreak |
        Fence(_) => {
            program.pc.next_address();
            (TraceRead::default(), TraceRead::default(), TraceWrite::default())
        },
        Ecall => op_ecall(program, print_program_stdout, debug), 
        Jal(x) => op_jal(&x, program),
        Jalr(x) => op_jalr(&x, program),
        Mul(x) |
        Mulh(x) |
        Mulhsu(x) |
        Mulhu(x) |
        Div(x) |
        Divu(x) |
        Rem(x) |
        Remu(x) |
        Sub(x) |
        Xor(x) |
        And(x) |
        Or(x) |
        Add(x) => {
            let (ret, wit) = op_arithmetic(&instruction, &x, program);
            witness = wit;
            ret
        },
        Sll(x)|
        Srl(x)|
        Sra(x)|
        Slt(x)|
        Sltu(x) => op_shift_sl(&instruction, &x, program),
        Slli(x)|
        Srli(x)|
        Srai(x) => op_shift_imm(&instruction, &x, program),
        Slti(x)|
        Sltiu(x) => op_sl_imm(&instruction, &x, program),
        Sb(x) |
        Sh(x) |
        Sw(x) => op_store(&instruction, &x, program),
        Lbu(x) |
        Lb(x) |
        Lh(x) |
        Lhu(x) |
        Lw(x) => op_load(&instruction, &x, program),
        Auipc(x) |
        Lui(x) => op_upper(&instruction, &x, program),
        Beq(x) |
        Bne(x) |
        Blt(x) |
        Bge(x) |
        Bltu(x) |
        Bgeu(x) => op_conditional(&instruction, &x, program),
        Addi(x) | Andi(x) | Ori(x) | Xori(x) => op_arithmetic_imm(&instruction, &x, program),
        _ => {
            return Err(ExecutionResult::InstructionNotImplemented(opcode, format!("{:?}", instruction)));
        }
    };

    let trace = TraceRWStep::new(
        read_1,
        read_2,
        TraceReadPC::new(pc, opcode),
        TraceStep::new(write_1, TraceWritePC::new(&program.pc)),
        witness,
    );

    
    program.step += 1;
    Ok(trace)
}

pub fn op_ecall(program: &mut Program, print_program_stdout: bool, debug: bool ) -> (TraceRead, TraceRead, TraceWrite) {

    let syscall = program.registers.get(REGISTER_A7_ECALL_ARG as u32);
    let value_2 = program.registers.get(REGISTER_A0 as u32);
    let read_1 = TraceRead::new_from(&program.registers, REGISTER_A7_ECALL_ARG as u32);
    let read_2 = TraceRead::new_from(&program.registers, REGISTER_A0 as u32);

    match syscall {
        116 => {
            if print_program_stdout {
                let x = program.read_mem(0xA000_1000) >> 24;
                print!("{}", x as u8 as char  ); 
            }
            program.pc.next_address();
            (read_1, read_2, TraceWrite::default())
        },
        93 => {
            if debug {
                println!("Exit code: 0x{:08x}", value_2);
                for i in 0..32 {
                    println!("Register {}: 0x{:08x}", i, program.registers.get(i));
                }
                println!("Total steps: {} 0x{:016x}", program.step, program.step);
            }

            program.halt = true;
            program.registers.set(REGISTER_A0 as u32, value_2, program.step);
            (read_1, read_2, TraceWrite::new_from(&program.registers, REGISTER_A0 as u32))
            //Intenttionally PC is not modified and remains in this instruction
        },
        _ => {
            println!("Unimplemented syscall: {}", syscall);
            program.pc.next_address();
            (read_1, read_2, TraceWrite::default())
        }
    }


}

pub fn op_conditional(instruction: &Instruction, x: &BType, program: &mut Program) -> (TraceRead, TraceRead, TraceWrite) {

    let value_1 = program.registers.get(x.rs1());
    let value_2 = program.registers.get(x.rs2());
    let read_1 = TraceRead::new_from(&program.registers, x.rs1());
    let read_2 = TraceRead::new_from(&program.registers, x.rs2());

    let conditional_dest = wrapping_add_btype(program.pc.get_address(), x);

    let condition_is_true = match instruction {
        Beq(_) => value_1 == value_2,
        Bne(_) => value_1 != value_2,
        Blt(_) => (value_1 as i32) < (value_2 as i32),
        Bge(_) => (value_1 as i32) >= (value_2 as i32),
        Bltu(_) => value_1 < value_2,
        Bgeu(_) => value_1 >= value_2,
        _ => panic!("Unreachable"),
    };

    if condition_is_true {
        program.pc.jump(conditional_dest);
    } else {
        program.pc.next_address();
    }

    (read_1, read_2, TraceWrite::default())

}

pub fn op_jal(x: &JType, program: &mut Program) -> (TraceRead, TraceRead, TraceWrite) {

    let pc = program.pc.clone();
    let dest_register = x.rd();

    let write_1 = if dest_register == REGISTER_ZERO as u32 {
        //used by direct jumps without return address
        TraceWrite::default()
    } else {
        //state modification
        program.registers.set(dest_register, pc.get_address() + 4 , program.step );
        TraceWrite::new_from(&program.registers, dest_register)
    };

    program.pc.jump( wrapping_add_jtype(pc.get_address(), x));

    (TraceRead::default(), TraceRead::default(), write_1)
}

pub fn op_jalr(x: &IType, program: &mut Program) -> (TraceRead, TraceRead, TraceWrite) {
    let pc = program.pc.clone();
    let dest_register = x.rd();
    let src_value = program.registers.get(x.rs1());
    let read_1 = TraceRead::new_from(&program.registers, x.rs1());

    let write_1 = if dest_register == REGISTER_ZERO as u32 {
        //used by rets 
        TraceWrite::default()
    } else {
        //state modification
        program.registers.set(dest_register, pc.get_address() + 4 , program.step );
        TraceWrite::new_from(&program.registers, dest_register)
    };

    program.pc.jump(wrapping_add_itype(src_value, x));

    (read_1, TraceRead::default(), write_1)
}

pub fn op_arithmetic(instruction: &Instruction, x: &RType, program: &mut Program) -> ((TraceRead, TraceRead, TraceWrite), Option<u32>) {

    if  x.rd() == REGISTER_ZERO as u32 { 
        program.pc.next_address();
        return ((TraceRead::default(), TraceRead::default(), TraceWrite::default()), None);
    }

    let read_1 = TraceRead::new_from(&program.registers, x.rs1());
    let read_2 = TraceRead::new_from(&program.registers, x.rs2());
    let value_1 = program.registers.get(x.rs1());
    let value_2 = program.registers.get(x.rs2());

    let witness = match instruction {
        Rem(_) => {
            match value_2 {
                0 => Some(0xFFFF_FFFF), 
                0xFFFF_FFFF => Some(value_1), 
                _ => Some((value_1 as i32 / value_2 as i32) as u32)
            }
        },
        Div(_) => {
            match value_2 {
                0 => Some(value_1),
                0xFFFF_FFFF => Some(0),
                _ => Some((value_1 as i32 % value_2 as i32) as u32)
            }
        },
        Remu(_) => if value_2 == 0 { Some(0xFFFFFFFF) } else { Some(value_1 / value_2) },
        Divu(_) => if value_2 == 0 { Some(value_1) } else { Some(value_1 % value_2) },
        _ => None
    };


    let result = match instruction {
        Mul(_) => {
            let result: u64 = (value_1 as u64) * (value_2 as u64);
            result as u32  // Low 32 bits
        },
        Mulh(_) => {
            let result: i64 = (value_1 as i32 as i64) * (value_2 as i32 as i64);
            (result >> 32) as u32  // High 32 bits
        },
        Mulhsu(_) => {
            let result: i64 = (value_1 as i32 as i64) * (value_2 as u64 as i64);
            (result >> 32) as u32  // High 32 bits
        },
        Mulhu(_) => {
            let result: u64 = (value_1 as u64) * (value_2 as u64);
            (result >> 32) as u32  // High 32 bits
        },
        Div(_) => {
            match value_2 {
                0 => 0xFFFF_FFFF, 
                0xFFFF_FFFF => value_1, 
                _ => (value_1 as i32 / value_2 as i32) as u32
            }
        },
        Divu(_) => if value_2 == 0 { 0xFFFFFFFF } else { value_1 / value_2 },
        Rem(_) => {
            match value_2 {
                0 => value_1,
                0xFFFF_FFFF => 0,
                _ => (value_1 as i32 % value_2 as i32) as u32
            }
        },
        Remu(_) => if value_2 == 0 { value_1 } else { value_1 % value_2 },
        Sub(_) => value_1.wrapping_sub(value_2),
        Xor(_) => value_1 ^ value_2,
        And(_) => value_1 & value_2,
        Or(_) => value_1 | value_2,
        Add(_) => value_1.wrapping_add(value_2),
        _ => panic!("Unreachable"),
    };

    //println!("{} {} = {} witness: {:?}", value_1, value_2, result, witness);

    program.registers.set(x.rd(), result, program.step);
    program.pc.next_address();

    ((read_1, read_2, TraceWrite::new_from(&program.registers, x.rd())), witness)
}

pub fn op_arithmetic_imm(instruction: &Instruction, x: &IType, program: &mut Program) -> (TraceRead, TraceRead, TraceWrite) {
    let rd = x.rd();

    // special cases

    if  rd == REGISTER_ZERO as u32 { // nop is translated in: addi 0,0,0
        program.pc.next_address();
        return (TraceRead::default(), TraceRead::default(), TraceWrite::default());
    }

    // Note, XORI rd, rs1, -1 performs a bitwise logical inversion of register rs1 (assembler pseudoinstruction NOT rd, rs).
    let read_1 = TraceRead::new_from(&program.registers, x.rs1());

    let rs1 = program.registers.get(x.rs1());
    let imm_value_signed = ((x.imm() as i32) << 20) >> 20;

    // registers.get(x.rs1());
    let result = match instruction {
        // arithmetical operations
        Addi(_) =>  wrapping_add_itype(rs1, x),
        // logical operations
        Andi(_) => (imm_value_signed & rs1 as i32) as u32,
        Ori(_) => (imm_value_signed | rs1 as i32) as u32,
        Xori(_) => (imm_value_signed ^ rs1 as i32) as u32,

        _ => panic!("Unreachable"),
    };

    program.registers.set(rd, result, program.step);
    program.pc.next_address();

    let write = TraceWrite::new_from(&program.registers, rd);

    (read_1, TraceRead::default(), write)
}

pub fn op_shift_sl(instruction: &Instruction, x: &RType, program: &mut Program) -> (TraceRead, TraceRead, TraceWrite) {
    let read_1 = TraceRead::new_from(&program.registers, x.rs1());
    let read_2 = TraceRead::new_from(&program.registers, x.rs2());
    let value_1 = program.registers.get(x.rs1());
    let value_2 = program.registers.get(x.rs2());

    if x.rd() == REGISTER_ZERO as u32 {
        program.pc.next_address();
        return (TraceRead::default(), TraceRead::default(), TraceWrite::default());
    }

    let result = match instruction {        // Shift amount held in the lower 5 bits of register rs2
        Sll(_) => value_1 << (value_2 & 0x1F),
        Srl(_) => value_1 >> (value_2 & 0x1F),
        Sra(_) => ((value_1 as i32) >> (value_2 & 0x1F)) as u32,
        Slt(_) => if (value_1 as i32) < (value_2 as i32) { 1 } else { 0 },
        Sltu(_) => if value_1 < value_2 { 1 } else { 0 },
        _ => panic!("Unreachable"),
    };
    
    program.registers.set(x.rd(), result, program.step);
    program.pc.next_address();

    (read_1, read_2, TraceWrite::new_from(&program.registers, x.rd())) 
}



pub fn op_shift_imm(instruction: &Instruction, x: &ShiftType, program: &mut Program) -> (TraceRead, TraceRead, TraceWrite) {

    if x.rd() == REGISTER_ZERO as u32 {
        program.pc.next_address();
        return (TraceRead::default(), TraceRead::default(), TraceWrite::default());
    }

    let read_1 = TraceRead::new_from(&program.registers, x.rs1());
    let value = program.registers.get(x.rs1());

    let result = match instruction {
        Slli(_) => value << x.shamt(),
        Srli(_) => value >> x.shamt(),
        Srai(_) => ((value as i32) >> x.shamt()) as u32,
        _ => panic!("Unreachable"),
    };

    program.registers.set(x.rd(), result, program.step);
    program.pc.next_address();

    (read_1, TraceRead::default(), TraceWrite::new_from(&program.registers, x.rd()))
}

pub fn op_sl_imm(instruction: &Instruction, x: &IType, program: &mut Program) -> (TraceRead, TraceRead, TraceWrite) {

    if x.rd() == REGISTER_ZERO as u32 {
        program.pc.next_address();
        return (TraceRead::default(), TraceRead::default(), TraceWrite::default());
    }

    let read_1 = TraceRead::new_from(&program.registers, x.rs1());
    let value = program.registers.get(x.rs1());
    let imm = x.imm();
    let imm_extended = ((imm as i32) << 20) >> 20;

    let result = match instruction {
        Slti(_) => if (value as i32) < imm_extended { 1 } else { 0 },
        Sltiu(_) => if value < imm_extended as u32 { 1 } else { 0 },
        _ => panic!("Unreachable"),
    };

    program.registers.set(x.rd(), result, program.step);
    program.pc.next_address();

    (read_1, TraceRead::default(), TraceWrite::new_from(&program.registers, x.rd()))
    
}
pub fn get_dest_mem(registers: &Registers, x: &SType) -> (TraceRead, u32, u32) {
    let read_1 = TraceRead::new_from(registers, x.rs1());
    let dest_mem = wrapping_add_stype(registers.get(x.rs1()), x);
    let alignment = dest_mem % 4;
    (read_1, dest_mem-alignment, alignment)
}

pub fn get_type_and_read_from_instruction(instruction: &Instruction, alignment: u32) -> (bool, bool, bool, u32) {
    match instruction {
        Lb(_)  |
        Lbu(_) |
        Sb(_) => (false, false, true, 1),
        Lh(_) |
        Lhu(_) |
        Sh(_) => (false, true, false, if alignment == 3 {2} else {1}),
        Lw(_) => (true, false, false, if alignment == 0 {1} else {2}),
        Sw(_) => (true, false, false, if alignment == 0 {0} else {2}),
        _ => panic!("Unreachable {:?}", instruction),
    }
}

pub fn op_store(instruction: &Instruction, x: &SType, program: &mut Program) -> (TraceRead, TraceRead, TraceWrite) {
    let micro = program.pc.get_micro();

    match micro {
        0 |
        4 => {
            let (read_1, mut dest_mem, alignment) = get_dest_mem(&program.registers, x);
            let (word, _half, _byte, reads ) = get_type_and_read_from_instruction(instruction, alignment);

            //only aligned word do not require reads
            //byte always require one read
            //half requires one reads if the second byte fits in the same word

            if micro == 0 && word && reads == 0 {
                let read_2 = TraceRead::new_from(&program.registers, x.rs2());
                let value = program.registers.get(x.rs2());
                program.write_mem(dest_mem, value);
                program.pc.next_address();

                
                return (read_1, read_2, TraceWrite::new(dest_mem, value));
            } 

            let (mask_dst, _mask_src, _move_masked) = if micro == 0 { get_mask_round_1(instruction, alignment)} else { get_mask_round_2(instruction, alignment)};

            // micro instructions steps:
            // 0:  address = rs1 + imm
            //     value = mem[add]
            //     reg[aux_1] = value
            if micro == 4 {
                dest_mem += 4;
            }
            let value = program.read_mem(dest_mem);
            let read_2 = TraceRead::new(dest_mem, value, program.get_last_step(dest_mem));

            let masked = mask_dst & value;
            program.registers.set(AUX_REGISTER_1, masked, program.step);
            program.pc.next_micro();

            (read_1, read_2, TraceWrite::new_from(&program.registers, AUX_REGISTER_1))
        },
        5 |
        1 => {

            //micro step
            //1:  address = rs1 + imm
            //    value = rs2[x:y] shifted
            //    reg[aux_2] = value
            let (read_1, _dest_mem, alignment) = get_dest_mem(&program.registers, x);
            let (_mask_dst, mask_src, move_masked) = if micro == 1 { get_mask_round_1(instruction, alignment) } else { get_mask_round_2(instruction, alignment)};
            let read_2 = TraceRead::new_from(&program.registers, x.rs2());

            let value = program.registers.get(x.rs2());
            let masked = mask_src & value;
            let shifted = match move_masked.cmp(&0) {
                Ordering::Less => masked >> (-move_masked * 8),
                Ordering::Greater => masked << (move_masked * 8),
                Ordering::Equal => masked
            };

            program.registers.set(AUX_REGISTER_2, shifted, program.step);
            program.pc.next_micro();

            (read_1, read_2, TraceWrite::new_from(&program.registers, AUX_REGISTER_2))

        },
        6 | 
        2 => {
            //micro step
            //2:  reg[aux_2] = reg[aux_1] | reg[aux_2]
            let value_1 = program.registers.get(AUX_REGISTER_1);
            let value_2 = program.registers.get(AUX_REGISTER_2);
            let read_1 = TraceRead::new_from(&program.registers, AUX_REGISTER_1);
            let read_2 = TraceRead::new_from(&program.registers, AUX_REGISTER_2);
            program.registers.set(AUX_REGISTER_1, value_1 | value_2, program.step);
            program.pc.next_micro();
            let write_1 = TraceWrite::new_from(&program.registers, AUX_REGISTER_1);

            ( read_1, read_2, write_1 )
        },
        7 |
        3 => {
            //micro step
            //3:  address = rs1 + imm
            //    mem[address] = reg[aux_1]
            let (read_1, mut dest_mem, alignment) = get_dest_mem(&program.registers, x);
            let (_word, _half, _byte, reads ) = get_type_and_read_from_instruction(instruction, alignment);
            let value = program.registers.get(AUX_REGISTER_1);
            let read_2 = TraceRead::new_from(&program.registers, AUX_REGISTER_1);
            if micro == 7 {
                dest_mem += 4;
            }
            program.write_mem(dest_mem, value);
            let write_1 = TraceWrite::new(dest_mem, value);

            if reads == 1 || micro == 7 {
                //println!("Write: 0x{:08x} to 0x{:08x}", value, dest_mem);
                program.pc.next_address();
            } else {
                program.pc.next_micro();
            }

            (read_1, read_2, write_1)

        }
        _ => { 
            panic!("Unreachable");
        }
        
    }


}



pub fn get_src_mem(registers: &Registers, x: &IType) -> (TraceRead, u32, u32) {
    let read_1 = TraceRead::new_from(registers, x.rs1());
    let src_mem = wrapping_add_itype(registers.get(x.rs1()), x);
    let alignment = src_mem % 4;
    (read_1, src_mem-alignment, alignment)
}
pub fn op_load(instruction: &Instruction, x: &IType, program: &mut Program) -> (TraceRead, TraceRead, TraceWrite) {

    if x.rd() == REGISTER_ZERO as u32 {
        program.pc.next_address();
        return (TraceRead::default(), TraceRead::default(), TraceWrite::default());
    }

    let micro = program.pc.get_micro();

    let (read_1, mut src_mem, alignment) = get_src_mem(&program.registers, x);
    let (_word, _half, _byte, reads ) = get_type_and_read_from_instruction(instruction, alignment);
    
    match micro {
        1 |
        0 => {
            // micro 0:
            //  alligned =>
            //    rd = mem[rs1 + imm]
            //  missaligned =>
            //    aux_1 = mem[rs1 + imm] & mask 
            //  micro 1:
            //    aux_2 = mem[rs1 + imm + 4] & mask 

            if micro == 1 {
                src_mem += 4;
            }

            let value = program.read_mem(src_mem);
            let last_step = program.get_last_step(src_mem);
            let read_2 = TraceRead::new(src_mem, value, last_step);

            let (mask, shift) = if micro == 0 { get_mask_round_1_for_load(instruction, alignment) }  else { get_mask_round_2_for_load(instruction, alignment) };
            let masked = mask & value;
            let shifted = match shift.cmp(&0) {
                Ordering::Less => masked >> (-shift * 8),
                Ordering::Greater => masked << (shift * 8),
                Ordering::Equal => masked
            };

            let shifted = sign_extension(instruction, shifted);

            let write_1 = if reads == 1 {
                program.pc.next_address();
                program.registers.set(x.rd(), shifted, program.step);
                TraceWrite::new_from(&program.registers, x.rd())
            } else {
                program.pc.next_micro();
                let dest = if  micro == 0 { AUX_REGISTER_1 } else { AUX_REGISTER_2 };
                program.registers.set(dest, shifted, program.step);
                TraceWrite::new_from(&program.registers, dest)
            };

            (read_1, read_2, write_1)

        },
        2 => {
            // micro 2:
            // aux1 = aux1 | aux2

            let value_1 = program.registers.get(AUX_REGISTER_1);
            let value_2 = program.registers.get(AUX_REGISTER_2);
            let read_1 = TraceRead::new_from(&program.registers, AUX_REGISTER_1);
            let read_2 = TraceRead::new_from(&program.registers, AUX_REGISTER_2);
            program.registers.set(AUX_REGISTER_1, value_1 | value_2, program.step);
            program.pc.next_micro();
            let write_1 = TraceWrite::new_from(&program.registers, AUX_REGISTER_1);

            ( read_1, read_2, write_1 )
        },
        3 => {
            // micro 3:
            // rd = aux1
            let value = program.registers.get(AUX_REGISTER_1);
            let read_1 = TraceRead::new_from(&program.registers, AUX_REGISTER_1);

            program.registers.set(x.rd(), value, program.step);
            program.pc.next_address();
            let write_1 = TraceWrite::new_from(&program.registers, x.rd());

            ( read_1, TraceRead::default(), write_1 )
        },
        _ => { panic!("Unreachable");}

    }

}

pub fn op_upper(instruction: &Instruction, x: &UType, program: &mut Program) -> (TraceRead, TraceRead, TraceWrite) {

    let dest_register = x.rd();
    if dest_register == REGISTER_ZERO as u32 {
        program.pc.next_address();
        return (TraceRead::default(), TraceRead::default(), TraceWrite::default());
    }

    let value = match instruction {
        Auipc(_) => program.pc.get_address().wrapping_add( x.imm() ),
        Lui(_) => x.imm(),
        _ => panic!("Unreachable"),
    };

    //state modification
    program.registers.set(dest_register, value, program.step );
    program.pc.next_address();

    ( TraceRead::default(), TraceRead::default(), TraceWrite::new_from(&program.registers, dest_register))

}

