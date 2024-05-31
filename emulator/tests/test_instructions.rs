use emulator::{executor::fetcher::*, loader::program::{Program, ProgramCounter, Registers}};
use riscv_decode::{types::{RType, ShiftType, IType, JType}, Instruction};
use rstest::rstest;
mod common;

const LOGIC_TRUE: u32 = 0x00000001;
const LOGIC_FALSE: u32 = 0x0000000;

fn create_rtype_from(rs2: u8, rs1: u8, rd: u8) -> RType {
    RType((rs2 as u32) << 20 | (rs1 as u32) << 15 | (rd as u32) << 7)
}

fn create_shift_type_from(imm: u32, rs1: u8, rd: u8)-> ShiftType {
    ShiftType(imm << 20 | (rs1 as u32) << 15 | (rd as u32) << 7)    // shamt[4:0]
} 

fn create_itype_from(imm: u32, rs1: u8, rd: u8) -> IType {
    IType(imm << 20 | (rs1 as u32) << 15 | (rd as u32) << 7)
}

fn create_jtype_from(imm: u32, rd: u8) -> JType {
    JType(imm << 20 | (rd as u32) << 7)
}

// Arithmetic operations
#[test]
fn test_add() {

    let mut program = common::get_new_program();

    program.registers.set(3, 0x00000001, 0);
    program.registers.set(2, 0x00000002, 0);

    let x = create_rtype_from(3, 2, 1);
    let instruction = Instruction::Add( x );

    let _ = op_arithmetic(&instruction, &x, &mut program);

    assert_eq!(program.registers.get(1), 0x00000003);
}

#[test]
fn test_slti() {

    let mut program = Program {
        sections: vec![],
        registers: Registers::new(0, 0),
        pc: ProgramCounter::new(0, 0),
        step: 0,
    };

    program.registers.set(2, 0xFFFFFFFE     , 0);    //Rs1 =-2
    let x = create_itype_from(0x1, 2, 1);
    let instruction = Instruction::Slti(x);

    let _ = op_sl_imm(&instruction, &x, &mut program);
    assert_eq!(program.registers.get(1), 0x00000001); 

}

#[test]
fn test_sub() {

    let mut program = common::get_new_program();
    
    program.registers.set(3, 0x00000002, 0);
    program.registers.set(2, 0x00000003, 0);

    let x = create_rtype_from(3, 2, 1);
    let instruction = Instruction::Sub( x );

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

    let mut program = common::get_new_program();
    program.registers.set(3, a, 0);
    program.registers.set(2, b, 0);

    let x = create_rtype_from(3, 2, 1);
    let instruction = Instruction::And( x );

    let _ = op_arithmetic(&instruction, &x, &mut program);
    
    assert_eq!(program.registers.get(1), expected);
}

#[rstest]
#[case(LOGIC_TRUE, LOGIC_FALSE, LOGIC_TRUE)]
#[case(LOGIC_FALSE, LOGIC_TRUE, LOGIC_TRUE)]
#[case(LOGIC_TRUE, LOGIC_FALSE, LOGIC_TRUE)]
#[case(LOGIC_FALSE, LOGIC_FALSE, LOGIC_FALSE)]
fn test_or(#[case] a: u32, #[case] b: u32, #[case] expected: u32) {

    let mut program = common::get_new_program();

    program.registers.set(3, a, 0);
    program.registers.set(2, b, 0);

    let x = create_rtype_from(3, 2, 1);
    let instruction = Instruction::Or( x );

    let _ = op_arithmetic(&instruction, &x, &mut program);
    
    assert_eq!(program.registers.get(1), expected);
}

#[rstest]
#[case(LOGIC_TRUE, LOGIC_FALSE, LOGIC_TRUE)]
#[case(LOGIC_FALSE, LOGIC_TRUE, LOGIC_TRUE)]
#[case(LOGIC_TRUE, LOGIC_TRUE, LOGIC_FALSE)]
#[case(LOGIC_FALSE, LOGIC_FALSE, LOGIC_FALSE)]
fn test_xor(#[case] a: u32, #[case] b: u32, #[case] expected: u32) {

    let mut program = common::get_new_program();

    program.registers.set(3, a, 0);
    program.registers.set(2, b, 0);

    let x = create_rtype_from(3, 2, 1);
    let instruction = Instruction::Xor( x );

    let _ = op_arithmetic(&instruction, &x, &mut program);
    
    assert_eq!(program.registers.get(1), expected);
}

// Shift operations
#[rstest]
fn test_shift() {

    let mut program = Program {
        sections: vec![],
        registers: Registers::new(0, 0),
        pc: ProgramCounter::new(0, 0),
        step: 0,
    };

    program.registers.set(3, 0x00000003, 0);
    program.registers.set(2, 0x00000018, 0);

    let x = create_rtype_from(3, 2, 1);
    let instruction = Instruction::Srl( x );

    let _ = op_shift_sl(&instruction, &x, &mut program);
    assert_eq!(program.registers.get(1), 0x00000003);

}

#[rstest]
fn test_slt() {

    let mut program = Program {
        sections: vec![],
        registers: Registers::new(0, 0),
        pc: ProgramCounter::new(0, 0),
        step: 0,
    };

    program.registers.set(3, 0x00000001  , 0);    //Rs2 = 1
    program.registers.set(2, 0xFFFFFFFE   , 0);    //Rs1 = -2

    let x: RType = create_rtype_from(3, 2, 1);
    let instruction = Instruction::Slt(x);

    let _ = op_shift_sl(&instruction, &x, &mut program);
    assert_eq!(program.registers.get(1), 0x00000001);
}

#[rstest]
fn test_shifti() {

    let mut program = Program {
        sections: vec![],
        registers: Registers::new(0, 0),
        pc: ProgramCounter::new(0, 0),
        step: 0,
    };

    program.registers.set(2, 0xF2345678    , 0);    //Rs1
    let x = create_shift_type_from(0x4, 2, 1);
    let instruction = Instruction::Srai(x);

    let _ = op_shift_imm(&instruction, &x, &mut program);
    assert_eq!(program.registers.get(1), 0xFF234567 );

}


// Jump operations
#[rstest]
fn test_jal() {
    let imm = 1022;
    let rd = 8;

    let mut program = common::get_new_program();

    let x = create_jtype_from(imm, rd as u8);

    let _ = op_jal(&x, &mut program);

    assert_eq!(program.pc.get_address(), imm);
    assert_eq!(program.registers.get(rd), 4);
}

#[rstest]
fn test_jalr() {
    let imm = 63;
    let rd = 31;
    let rs1 = 15;
    let rs1_value = 10;

    let mut program = common::get_new_program();
    program.registers.set(rs1, rs1_value, 0);

    let x = create_itype_from(imm, rs1 as u8, rd as u8);

    let _ = op_jalr(&x, &mut program);

    assert_eq!(program.pc.get_address(), imm + rs1_value);
    assert_eq!(program.registers.get(rd), 4);
}
#[test]
fn test_addi() {

    let mut program = common::get_new_program();

    program.registers.set(3, 0x00000002, 0);

    let x = create_itype_from(2, 3, 1);
    let instruction = Instruction::Addi( x );

    let _ = op_arithmetic_imm(&instruction, &x, &mut program);

    assert_eq!(program.registers.get(1), 0x00000004);
}

#[test]
#[should_panic(expected = "Cannot set register zero. Value: 0 Step: 0"
)]
fn test_addi_zero() {
    let mut program = common::get_new_program();

    program.registers.set(0, 0x00000000, 0);

    let x = create_itype_from(2, 0, 0);
    let instruction = Instruction::Addi( x );

    let _ = op_arithmetic_imm(&instruction, &x, &mut program);

    assert_eq!(program.registers.get(0), 0x00000000);
}

#[test]
fn test_xori() {

    let mut program = common::get_new_program();

    program.registers.set(3, 0b101, 0);

    let x = create_itype_from(0b111, 3, 1);
    let instruction = Instruction::Xori( x );

    let _ = op_arithmetic_imm(&instruction, &x, &mut program);

    assert_eq!(program.registers.get(1), 0b00000010);
}

#[test]
fn test_andi() {
    let mut program = common::get_new_program();

    program.registers.set(3, 0b11101, 0);

    let x = create_itype_from(0b10111, 3, 1);
    let instruction = Instruction::Andi( x );

    let _ = op_arithmetic_imm(&instruction, &x, &mut program);

    assert_eq!(program.registers.get(1), 0b00010101);
}

#[test]
fn test_ori() {
    let mut program = common::get_new_program();

    program.registers.set(3, 0b11001, 0);

    let x = create_itype_from(0b10011, 3, 1);
    let instruction = Instruction::Ori( x );

    let _ = op_arithmetic_imm(&instruction, &x, &mut program);

    assert_eq!(program.registers.get(1), 0b00011011);
}
