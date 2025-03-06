use emulator::executor::fetcher::*;
use riscv_decode::Instruction;
use rstest::rstest;
mod utils;
use utils::common::{
    create_shift_type_from, create_stype_from, get_new_program, get_new_section, rnd_range,
};

#[test]
fn test_stype() {
    for rs1 in 0..32 {
        let stype = create_stype_from(0, rs1, 0);
        assert_eq!(rs1, stype.rs1() as u8);
    }

    for rs2 in 0..16 {
        let stype = create_stype_from(0, 0, rs2);
        assert_eq!(rs2, stype.rs2() as u8);
    }
}

// Shift immediate operations
#[rstest]
fn test_srai() {
    let idx_rs1 = 2;
    let rs1_value = 0xF2345678; //11110010001101000101011001111000
    let rd = 1;

    let mut program = get_new_program();

    program.registers.set(idx_rs1, rs1_value, 0);

    let x = create_shift_type_from(0x4, idx_rs1 as u8, rd);
    let instruction = Instruction::Srai(x);

    let _ = op_shift_imm(&instruction, &x, &mut program);
    assert_eq!(program.registers.get(rd as u32), 0xFF234567);
}

#[rstest]
fn test_slli() {
    let idx_rs1 = 2;
    let rs1_value = 0xF2345678; //11110010001101000101011001111000
    let rd = 1;

    let mut program = get_new_program();

    program.registers.set(idx_rs1, rs1_value, 0);

    let x = create_shift_type_from(0x4, idx_rs1 as u8, rd);
    let instruction = Instruction::Slli(x);

    let _ = op_shift_imm(&instruction, &x, &mut program);
    assert_eq!(program.registers.get(rd as u32), 591751040);
}

#[rstest]
fn test_srli() {
    let idx_rs1 = 2;
    let rs1_value = 0xF2345678; //11110010001101000101011001111000
    let rd = 1;

    let mut program = get_new_program();

    program.registers.set(idx_rs1, rs1_value, 0);

    let x = create_shift_type_from(0x4, idx_rs1 as u8, rd);
    let instruction = Instruction::Srli(x);

    let _ = op_shift_imm(&instruction, &x, &mut program);
    assert_eq!(program.registers.get(rd as u32), 253969767);
}

#[rstest]
#[case(0x8, rnd_range(), 0x14, "sw", 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 1)] // 0
#[case(0x8, rnd_range(), 0x15, "sw", 0xFFFFFFFF, 0xFFFFFF00, 0x000000FF, 8)] // -1
#[case(0x8, rnd_range(), 0x16, "sw", 0xFFFFFFFF, 0xFFFF0000, 0x0000FFFF, 8)] // -2
#[case(0x8, rnd_range(), 0x17, "sw", 0xFFFFFFFF, 0xFF000000, 0x00FFFFFF, 8)] // -3
fn test_store_word(
    #[case] idx_rs1: u32,
    #[case] mut idx_rs2: u32,
    #[case] imm_value: u32,
    #[case] instruction: &str,
    #[case] rs2_value: u32,
    #[case] expected_reg_aux_1: u32,
    #[case] expected_reg_aux_2: u32,
    #[case] micros: u32,
) {
    let mem_aux_2_byte_offset = 4;
    if idx_rs2 == idx_rs1 {
        idx_rs2 += 1;
    }
    let mut program = get_new_program();
    program.add_section(get_new_section());

    let start_address = program.find_section_by_name("test_data").unwrap().start;
    program.registers.set(idx_rs1, start_address, 0);
    program.registers.set(idx_rs2, rs2_value, 0);

    let x = create_stype_from(imm_value, idx_rs1 as u8, idx_rs2 as u8);

    let instruction = match instruction {
        "sw" => Instruction::Sw(x),
        _ => panic!("Unreachable"),
    };

    for _ in 0..micros {
        let _ = op_store(&instruction, &x, &mut program);
    }

    assert_eq!(
        program.read_mem(start_address + imm_value).unwrap(),
        expected_reg_aux_1
    );
    assert_eq!(
        program
            .read_mem(start_address + imm_value + mem_aux_2_byte_offset)
            .unwrap(),
        expected_reg_aux_2
    );
}

#[rstest]
#[case(0x8, rnd_range(), 0x14, "sh", 0x12345678, 0x00005678, 0x00000000, 8)] // 0
#[case(0x8, rnd_range(), 0x15, "sh", 0x12345678, 0x00567800, 0x00000000, 8)] // -1
#[case(0x8, rnd_range(), 0x16, "sh", 0x12345678, 0x56780000, 0x00000000, 8)] // -2
#[case(0x8, rnd_range(), 0x17, "sh", 0x12345678, 0x78000000, 0x00000056, 8)] // -3
fn test_store_half_word(
    #[case] idx_rs1: u32,
    #[case] mut idx_rs2: u32,
    #[case] imm_value: u32,
    #[case] instruction: &str,
    #[case] rs2_value: u32,
    #[case] expected_reg_aux_1: u32,
    #[case] expected_reg_aux_2: u32,
    #[case] micros: u32,
) {
    let mem_aux_2_byte_offset = 4;
    if idx_rs2 == idx_rs1 {
        idx_rs2 += 1;
    }
    let mut program = get_new_program();
    program.add_section(get_new_section());

    let start_address = program.find_section_by_name("test_data").unwrap().start;

    program.registers.set(idx_rs1, start_address, 0);
    program.registers.set(idx_rs2, rs2_value, 0);

    let x = create_stype_from(imm_value, idx_rs1 as u8, idx_rs2 as u8);

    let instruction = match instruction {
        "sh" => Instruction::Sh(x),
        _ => panic!("Unreachable"),
    };

    for _ in 0..micros {
        let _ = op_store(&instruction, &x, &mut program);
    }

    assert_eq!(
        program.read_mem(start_address + imm_value).unwrap(),
        expected_reg_aux_1
    );
    assert_eq!(
        program
            .read_mem(start_address + imm_value + mem_aux_2_byte_offset)
            .unwrap(),
        expected_reg_aux_2
    );
}

#[rstest]
#[case(0x8, rnd_range(), 0x14, "sb", 0x12345678, 0x00000078, 8)] // 0
#[case(0x8, rnd_range(), 0x15, "sb", 0x12345678, 0x00007800, 8)] // -1
#[case(0x8, rnd_range(), 0x16, "sb", 0x12345678, 0x00780000, 8)] // -2
#[case(0x8, rnd_range(), 0x17, "sb", 0x12345678, 0x78000000, 8)] // -3
fn test_store_byte(
    #[case] idx_rs1: u32,
    #[case] mut idx_rs2: u32,
    #[case] imm_value: u32,
    #[case] instruction: &str,
    #[case] rs2_value: u32,
    #[case] expected: u32,
    #[case] micros: u32,
) {
    if idx_rs2 == idx_rs1 {
        idx_rs2 += 1;
    }

    let mut program = get_new_program();
    program.add_section(get_new_section());

    let start_address = program.find_section_by_name("test_data").unwrap().start;

    program.registers.set(idx_rs1, start_address, 0);
    program.registers.set(idx_rs2, rs2_value, 0);

    let x = create_stype_from(imm_value, idx_rs1 as u8, idx_rs2 as u8);

    let instruction = match instruction {
        "sb" => Instruction::Sb(x),
        _ => panic!("Unreachable"),
    };

    for _ in 0..micros {
        let _ = op_store(&instruction, &x, &mut program);
    }

    assert_eq!(
        program.read_mem(start_address + imm_value).unwrap(),
        expected
    );
}
