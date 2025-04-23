use emulator::executor::fetcher::*;
use riscv_decode::Instruction;
use rstest::rstest;
mod utils;
use utils::common::{create_itype_from, get_new_program, get_new_section, rnd_range};

#[test]
fn test_slti() {
    let rs1_idx = 2;
    let rs1_value = 0xFFFFFFFE;
    let rd = 1;
    let imm = 0x1;

    let mut program = get_new_program();

    program.registers.set(rs1_idx, rs1_value, 0);
    let x = create_itype_from(imm, rs1_idx as u8, rd);
    let instruction = Instruction::Slti(x);

    let _ = op_sl_imm(&instruction, &x, &mut program);
    assert_eq!(program.registers.get(rd as u32), 0x00000001);
}

#[test]
fn test_sltiu() {
    let rs1_idx = 2;
    let rs1_value = 0xFFFFFFFE;
    let rd = 1;
    let imm = 0x1;

    let mut program = get_new_program();

    program.registers.set(rs1_idx, rs1_value, 0);

    let x = create_itype_from(imm, rs1_idx as u8, rd);
    let instruction = Instruction::Sltiu(x);

    let _ = op_sl_imm(&instruction, &x, &mut program);

    assert_eq!(program.registers.get(rd as u32), 0x00000000);
}

#[rstest]
fn test_jalr() {
    let imm = 63;
    let rd = 31;
    let rs1 = 15;
    let rs1_value = 10;

    let mut program = get_new_program();
    program.registers.set(rs1, rs1_value, 0);

    let x = create_itype_from(imm, rs1 as u8, rd as u8);

    let _ = op_jalr(&x, &mut program);

    assert_eq!(program.pc.get_address(), imm + rs1_value);
    assert_eq!(program.registers.get(rd), 4);
}

//Immediate arithmetic operations
#[test]
fn test_addi() {
    let mut program = get_new_program();

    program.registers.set(3, 0x00000002, 0);

    let x = create_itype_from(2, 3, 1);
    let instruction = Instruction::Addi(x);

    let _ = op_arithmetic_imm(&instruction, &x, &mut program);

    assert_eq!(program.registers.get(1), 0x00000004);
}

#[test]
#[should_panic(expected = "Cannot set register zero. Value: 0 Step: 0")]
fn test_addi_zero() {
    let mut program = get_new_program();

    program.registers.set(0, 0x00000000, 0);

    let x = create_itype_from(2, 0, 0);
    let instruction = Instruction::Addi(x);

    let _ = op_arithmetic_imm(&instruction, &x, &mut program);

    assert_eq!(program.registers.get(0), 0x00000000);
}

#[test]
fn test_xori() {
    let mut program = get_new_program();

    program.registers.set(3, 0b101, 0);

    let x = create_itype_from(0b111, 3, 1);
    let instruction = Instruction::Xori(x);

    let _ = op_arithmetic_imm(&instruction, &x, &mut program);

    assert_eq!(program.registers.get(1), 0b00000010);
}

#[test]
fn test_andi() {
    let mut program = get_new_program();

    program.registers.set(3, 0b11101, 0);

    let x = create_itype_from(0b10111, 3, 1);
    let instruction = Instruction::Andi(x);

    let _ = op_arithmetic_imm(&instruction, &x, &mut program);

    assert_eq!(program.registers.get(1), 0b00010101);
}

#[test]
fn test_ori() {
    let mut program = get_new_program();

    program.registers.set(3, 0b11001, 0);

    let x = create_itype_from(0b10011, 3, 1);
    let instruction = Instruction::Ori(x);

    let _ = op_arithmetic_imm(&instruction, &x, &mut program);

    assert_eq!(program.registers.get(1), 0b00011011);
}

// Load IType
#[rstest]
#[case(rnd_range(), 0x14, rnd_range(), "lb", 0x123456FD, 0xFFFFFFFD)]
#[case(rnd_range(), 0x14, rnd_range(), "lb", 0x1234567D, 0x0000007D)]
#[case(rnd_range(), 0x15, rnd_range(), "lb", 0x1234FE78, 0xFFFFFFFE)]
#[case(rnd_range(), 0x16, rnd_range(), "lb", 0x12FD5678, 0xFFFFFFFD)]
#[case(rnd_range(), 0x17, rnd_range(), "lb", 0xFD345678, 0xFFFFFFFD)]
#[case(rnd_range(), 0x14, rnd_range(), "lbu", 0x123456FD, 0x000000FD)]
fn test_load_byte(
    #[case] rd: u32,
    #[case] imm_value: u32,
    #[case] idx_rs1: u32,
    #[case] instruction: &str,
    #[case] set_mem: u32,
    #[case] expected: u32,
) {
    let mut program = get_new_program();
    program.add_section(get_new_section());

    let start_address = program.find_section_by_name("test_data").unwrap().start;

    program
        .write_mem(start_address + imm_value, set_mem)
        .unwrap();
    program.registers.set(idx_rs1, start_address, 0);

    let x = create_itype_from(imm_value, idx_rs1 as u8, rd as u8);

    let instruction = match instruction {
        "lb" => Instruction::Lb(x),
        "lbu" => Instruction::Lbu(x),
        _ => panic!("Unreachable"),
    };

    let _ = op_load(&instruction, &x, &mut program);

    assert_eq!(program.registers.get(rd as u32), expected);
}

#[rstest]
#[case(
    rnd_range(),
    0x14,
    rnd_range(),
    "lh",
    0x1234EEEE,
    0x12345678,
    0xFFFFEEEE,
    1
)]
#[case(
    rnd_range(),
    0x14,
    rnd_range(),
    "lh",
    0x12347D7D,
    0x12345678,
    0x00007D7D,
    1
)]
#[case(
    rnd_range(),
    0x15,
    rnd_range(),
    "lh",
    0x12EEEE78,
    0x12345678,
    0xFFFFEEEE,
    1
)]
#[case(
    rnd_range(),
    0x16,
    rnd_range(),
    "lh",
    0xEEEE5678,
    0x12345678,
    0xFFFFEEEE,
    1
)]
#[case(
    rnd_range(),
    0x17,
    rnd_range(),
    "lh",
    0x0D345678,
    0x12345678,
    0x0000780D,
    4
)]
#[case(
    rnd_range(),
    0x14,
    rnd_range(),
    "lhu",
    0x1234FDFD,
    0x12345678,
    0x0000FDFD,
    1
)]
fn test_load_half_word(
    #[case] rd: u32,
    #[case] imm_value: u32,
    #[case] idx_rs1: u32,
    #[case] instruction: &str,
    #[case] set_mem_aux_1: u32,
    #[case] set_mem_aux_2: u32,
    #[case] expected: u32,
    #[case] micros: u32,
) {
    let mem_aux_2_byte_offset = 4;
    let mut program = get_new_program();
    program.add_section(get_new_section());

    let start_address = program.find_section_by_name("test_data").unwrap().start;

    program
        .write_mem(start_address + imm_value, set_mem_aux_1)
        .unwrap();
    program
        .write_mem(
            start_address + imm_value + mem_aux_2_byte_offset,
            set_mem_aux_2,
        )
        .unwrap();
    program.registers.set(idx_rs1, start_address, 0);

    let x = create_itype_from(imm_value, idx_rs1 as u8, rd as u8);

    let instruction = match instruction {
        "lh" => Instruction::Lh(x),
        "lhu" => Instruction::Lhu(x),
        _ => panic!("Unreachable"),
    };

    for _ in 0..micros {
        let _ = op_load(&instruction, &x, &mut program);
    }

    assert_eq!(program.registers.get(rd), expected);
}

#[rstest]
#[case(
    rnd_range(),
    0x14,
    rnd_range(),
    "lw",
    0x12345678,
    0x12345678,
    0x12345678,
    1
)] // 0
#[case(
    rnd_range(),
    0x14,
    rnd_range(),
    "lw",
    0x7D7D7D7D,
    0x12345678,
    0x7D7D7D7D,
    1
)] // 0
#[case(
    rnd_range(),
    0x15,
    rnd_range(),
    "lw",
    0xFFFFFFFF,
    0x12345678,
    0x78FFFFFF,
    4
)] // -1
#[case(
    rnd_range(),
    0x16,
    rnd_range(),
    "lw",
    0xFFFFFFFF,
    0x12345678,
    0x5678FFFF,
    4
)] // -2
#[case(
    rnd_range(),
    0x17,
    rnd_range(),
    "lw",
    0xFFFFFFFF,
    0x12345678,
    0x345678FF,
    4
)] // -3
fn test_load_word(
    #[case] rd: u32,
    #[case] imm_value: u32,
    #[case] idx_rs1: u32,
    #[case] instruction: &str,
    #[case] set_mem_aux_1: u32,
    #[case] set_mem_aux_2: u32,
    #[case] expected: u32,
    #[case] micros: u32,
) {
    let mem_aux_2_byte_offset = 4;
    let mut program = get_new_program();
    program.add_section(get_new_section());

    let start_address = program.find_section_by_name("test_data").unwrap().start;

    program
        .write_mem(start_address + imm_value, set_mem_aux_1)
        .unwrap();
    program
        .write_mem(
            start_address + imm_value + mem_aux_2_byte_offset,
            set_mem_aux_2,
        )
        .unwrap();
    program.registers.set(idx_rs1, start_address, 0);

    let x = create_itype_from(imm_value, idx_rs1 as u8, rd as u8);

    let instruction = match instruction {
        "lw" => Instruction::Lw(x),
        _ => panic!("Unreachable"),
    };

    for _ in 0..micros {
        let _ = op_load(&instruction, &x, &mut program);
    }

    assert_eq!(program.registers.get(rd), expected);
}
