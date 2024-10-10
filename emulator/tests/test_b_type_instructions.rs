use emulator::executor::fetcher::*;
use riscv_decode::Instruction;
use rstest::rstest;
mod utils;
use utils::common::{create_btype_from, get_new_program};

#[test]
fn test_btype() {
    for rs1 in 0..32 {
        let btype = create_btype_from(0, rs1, 0);
        assert_eq!(rs1, btype.rs1() as u8);
    }

    for rs2 in 0..16 {
        let btype = create_btype_from(0, 0, rs2);
        assert_eq!(rs2, btype.rs2() as u8);
    }

    for imm in 0..0x2000 {
        if imm % 2 == 1 {
            continue;
        }
        let mut signed_imm = imm as i32;
        signed_imm -= 0x1000;

        let btype = create_btype_from(signed_imm as u32, 0, 0);

        let x = btype.imm();
        let bitextended = ((x as i32) << 19) >> 19;

        assert_eq!(signed_imm, bitextended);
    }
}

// Conditional operations
#[rstest]
#[case(0x7, 0x8, 0xA, 0xA, -2, "Beq", 0x3)] // Beq == case
#[case(0x7, 0x8, 0xA, 0x8, -2, "Beq", 0x9)] // Beq != case
#[case(0x7, 0x8, 0xFFE, 0xFFA, -7, "Bne", 0xFFFFFFFD)] // odd imm ignores 1st bit (-1)
#[case(0x7, 0x8, 0xFFA, 0xFFE, -2, "Blt", 0x3)]
#[case(0x7, 0x8, 0xFFE, 0xFFA, -2, "Bge", 0x3)] // bge > case
#[case(0x7, 0x8, 0xFFA, 0xFFA, -2, "Bge", 0x3)] // bge == case
#[case(0x7, 0x8, 70, 70, 0x20, "Bgeu", 0x25)] // bgeu == caseu
#[case(0x7, 0x8, 70, 30, 0x20, "Bgeu", 0x25)] // bgeu > case
#[case(0x7, 0x8, 2000, 4000, 2, "Bltu", 0x7)]
fn test_bgeu_eq_values(
    #[case] idx_rs1: u32,
    #[case] idx_rs2: u32,
    #[case] rs1_value: u32,
    #[case] rs2_value: u32,
    #[case] imm_value: i32,
    #[case] instruction: &str,
    #[case] expected: u32,
) {
    let mut program = get_new_program();
    program.registers.set(idx_rs1, rs1_value, 0);
    program.registers.set(idx_rs2, rs2_value, 0);
    program.pc.jump(0x5);

    let x = create_btype_from(imm_value as u32, idx_rs1 as u8, idx_rs2 as u8);
    let instruction = match instruction {
        "Beq" => Instruction::Beq(x),
        "Bne" => Instruction::Bne(x),
        "Blt" => Instruction::Blt(x),
        "Bge" => Instruction::Bge(x),
        "Bltu" => Instruction::Bltu(x),
        "Bgeu" => Instruction::Bgeu(x),
        _ => panic!("Unreachable"),
    };
    let _ = op_conditional(&instruction, &x, &mut program);

    assert_eq!(program.pc.get_address(), expected);
}
