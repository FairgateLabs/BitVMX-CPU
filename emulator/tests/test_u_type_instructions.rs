use emulator::executor::fetcher::*;
use rand::Rng;
use riscv_decode::Instruction;
use rstest::rstest;
mod utils;
use utils::common::{create_utype_from, get_new_program};

#[test]
fn test_utype() {
    for rd in 0..32 {
        let utype = create_utype_from(0, rd);
        assert_eq!(rd, utype.rd() as u8);
    }

    for imm in 0..0x80000 {
        let value: u32 = imm << 12;
        let utype = create_utype_from(value as u32, 0);
        assert_eq!(value, utype.imm());
    }
}

// Upper UType
#[rstest]
#[case(0x3, rand::thread_rng().gen_range(0..0x80000) << 12, 0, "Lui", imm_value)]
#[case(0x3, rand::thread_rng().gen_range(0..0x80000) << 12, 0x1000, "Auipc", imm_value + pc)]
fn test_upper_instructions(
    #[case] rd: u32,
    #[case] imm_value: u32,
    #[case] pc: u32,
    #[case] instruction: &str,
    #[case] expected: u32,
) {
    let mut program = get_new_program();
    program.pc.jump(pc);

    let x = create_utype_from(imm_value, rd as u8);

    let instruction = match instruction {
        "Auipc" => Instruction::Auipc(x),
        "Lui" => Instruction::Lui(x),
        _ => panic!("Unreachable"),
    };

    let _ = op_upper(&instruction, &x, &mut program);
    assert_eq!(program.registers.get(rd as u32), expected);
}
