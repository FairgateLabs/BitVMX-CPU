use emulator::executor::fetcher::*;
use rstest::rstest;
mod utils;
use utils::common::{create_jtype_from, get_new_program};

// Jump operations
#[rstest]
fn test_jal() {
    let imm = 1022;
    let rd = 8;

    let mut program = get_new_program();

    let x = create_jtype_from(imm, rd as u8);

    let _ = op_jal(&x, &mut program);

    assert_eq!(program.pc.get_address(), imm);
    assert_eq!(program.registers.get(rd), 4);
}
