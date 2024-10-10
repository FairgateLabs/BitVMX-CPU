use emulator::executor::fetcher::*;
use riscv_decode::Instruction;
use rstest::rstest;
mod utils;
use utils::common::{create_rtype_from, get_new_program};

const LOGIC_TRUE: u32 = 0x00000001;
const LOGIC_FALSE: u32 = 0x0000000;

// Arithmetic operations
#[test]
fn test_add() {
    let mut program = get_new_program();

    program.registers.set(3, 0x00000001, 0);
    program.registers.set(2, 0x00000002, 0);

    let x = create_rtype_from(3, 2, 1);
    let instruction = Instruction::Add(x);

    let _ = op_arithmetic(&instruction, &x, &mut program);

    assert_eq!(program.registers.get(1), 0x00000003);
}

#[test]
fn test_sub() {
    let mut program = get_new_program();

    program.registers.set(3, 0x00000002, 0);
    program.registers.set(2, 0x00000003, 0);

    let x = create_rtype_from(3, 2, 1);
    let instruction = Instruction::Sub(x);

    let _ = op_arithmetic(&instruction, &x, &mut program);

    assert_eq!(program.registers.get(1), 0x00000001);
}

// Logic operations
#[rstest]
#[case(LOGIC_TRUE, LOGIC_FALSE, LOGIC_FALSE)]
#[case(LOGIC_FALSE, LOGIC_TRUE, LOGIC_FALSE)]
#[case(LOGIC_FALSE, LOGIC_FALSE, LOGIC_FALSE)]
#[case(LOGIC_TRUE, LOGIC_TRUE, LOGIC_TRUE)]
fn test_and(#[case] a: u32, #[case] b: u32, #[case] expected: u32) {
    let mut program = get_new_program();
    program.registers.set(3, a, 0);
    program.registers.set(2, b, 0);

    let x = create_rtype_from(3, 2, 1);
    let instruction = Instruction::And(x);

    let _ = op_arithmetic(&instruction, &x, &mut program);

    assert_eq!(program.registers.get(1), expected);
}

#[rstest]
#[case(LOGIC_TRUE, LOGIC_FALSE, LOGIC_TRUE)]
#[case(LOGIC_FALSE, LOGIC_TRUE, LOGIC_TRUE)]
#[case(LOGIC_TRUE, LOGIC_FALSE, LOGIC_TRUE)]
#[case(LOGIC_FALSE, LOGIC_FALSE, LOGIC_FALSE)]
fn test_or(#[case] a: u32, #[case] b: u32, #[case] expected: u32) {
    let mut program = get_new_program();

    program.registers.set(3, a, 0);
    program.registers.set(2, b, 0);

    let x = create_rtype_from(3, 2, 1);
    let instruction = Instruction::Or(x);

    let _ = op_arithmetic(&instruction, &x, &mut program);

    assert_eq!(program.registers.get(1), expected);
}

#[rstest]
#[case(LOGIC_TRUE, LOGIC_FALSE, LOGIC_TRUE)]
#[case(LOGIC_FALSE, LOGIC_TRUE, LOGIC_TRUE)]
#[case(LOGIC_TRUE, LOGIC_TRUE, LOGIC_FALSE)]
#[case(LOGIC_FALSE, LOGIC_FALSE, LOGIC_FALSE)]
fn test_xor(#[case] a: u32, #[case] b: u32, #[case] expected: u32) {
    let mut program = get_new_program();

    program.registers.set(3, a, 0);
    program.registers.set(2, b, 0);

    let x = create_rtype_from(3, 2, 1);
    let instruction = Instruction::Xor(x);

    let _ = op_arithmetic(&instruction, &x, &mut program);

    assert_eq!(program.registers.get(1), expected);
}

// Shift operations
#[rstest]
fn test_srl() {
    let idx_rs1 = 2;
    let idx_rs2 = 3;
    let rs1_value = 0x00000018;
    let rs2_value = 0x00000003;
    let rd = 1;

    let mut program = get_new_program();

    program.registers.set(idx_rs1, rs1_value, 0);
    program.registers.set(idx_rs2, rs2_value, 0);

    let x = create_rtype_from(idx_rs2 as u8, idx_rs1 as u8, rd as u8);

    let instruction = Instruction::Srl(x);

    let _ = op_shift_sl(&instruction, &x, &mut program);
    assert_eq!(program.registers.get(rd), 0x00000003);
}

#[rstest]
fn test_slt() {
    let idx_rs1 = 2;
    let idx_rs2 = 3;
    let rs1_value: i32 = -2;
    let rs2_value = 0x00000001;
    let rd = 1;

    let mut program = get_new_program();

    program.registers.set(idx_rs1, rs1_value as u32, 0); //Rs1 = -2
    program.registers.set(idx_rs2, rs2_value, 0);

    let x = create_rtype_from(idx_rs2 as u8, idx_rs1 as u8, rd as u8);
    let instruction = Instruction::Slt(x);

    let _ = op_shift_sl(&instruction, &x, &mut program);
    assert_eq!(program.registers.get(rd as u32), 0x00000001);
}

#[rstest]
fn test_sltu() {
    let idx_rs1 = 2;
    let idx_rs2 = 3;
    let rs1_value = 0x00000004;
    let rs2_value = 0x00000005;
    let rd = 1;

    let mut program = get_new_program();

    program.registers.set(idx_rs1, rs1_value, 0);
    program.registers.set(idx_rs2, rs2_value, 0);

    let x = create_rtype_from(idx_rs2 as u8, idx_rs1 as u8, rd as u8);
    let instruction = Instruction::Sltu(x);

    let _ = op_shift_sl(&instruction, &x, &mut program);
    assert_eq!(program.registers.get(rd as u32), 0x00000001);
}

#[rstest]
fn test_sll() {
    let idx_rs1 = 2;
    let idx_rs2 = 3;
    let rs1_value = 0xA;
    let rs2_value = 0x1;
    let rd = 1;

    let mut program = get_new_program();

    program.registers.set(idx_rs1, rs1_value, 0);
    program.registers.set(idx_rs2, rs2_value, 0);

    let x = create_rtype_from(idx_rs2 as u8, idx_rs1 as u8, rd as u8);
    let instruction = Instruction::Sll(x);

    let _ = op_shift_sl(&instruction, &x, &mut program);

    assert_eq!(program.registers.get(1), 0x14);
}

#[rstest]
fn test_sra() {
    let idx_rs1 = 2;
    let idx_rs2 = 3;
    let rs1_value = 0x5;
    let rs2_value = 0x2;
    let rd = 1;

    let mut program = get_new_program();

    program.registers.set(idx_rs1, rs1_value, 0);
    program.registers.set(idx_rs2, rs2_value, 0);

    let x = create_rtype_from(idx_rs2 as u8, idx_rs1 as u8, rd as u8);
    let instruction = Instruction::Sra(x);

    let _ = op_shift_sl(&instruction, &x, &mut program);

    assert_eq!(program.registers.get(1), 0x1);
}
