use emulator::loader::program::{Program, ProgramCounter, Registers};

pub fn get_new_program() -> Program {
    Program {
        sections: vec![],
        registers: Registers::new(0, 0),
        pc: ProgramCounter::new(0, 0),
        step: 0,
    }
}