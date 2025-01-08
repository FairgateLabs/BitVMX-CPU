use riscv_decode::Instruction::{self, *};

pub fn get_mask_round_1(instruction: &Instruction, alignment: u32) -> (u32, u32, i8) {
    match instruction {
        Sb(_) => match alignment {
            0 => (0xFFFF_FF00, 0x0000_00FF, 0),
            1 => (0xFFFF_00FF, 0x0000_00FF, 1),
            2 => (0xFF00_FFFF, 0x0000_00FF, 2),
            3 => (0x00FF_FFFF, 0x0000_00FF, 3),
            _ => panic!("Unreachable"),
        },
        Sh(_) => match alignment {
            0 => (0xFFFF_0000, 0x0000_FFFF, 0),
            1 => (0xFF00_00FF, 0x0000_FFFF, 1),
            2 => (0x0000_FFFF, 0x0000_FFFF, 2),
            3 => (0x00FF_FFFF, 0x0000_00FF, 3),
            _ => panic!("Unreachable"),
        },
        Sw(_) => match alignment {
            3 => (0x00FF_FFFF, 0x0000_00FF, 3),
            2 => (0x0000_FFFF, 0x0000_FFFF, 2),
            1 => (0x0000_00FF, 0x00FF_FFFF, 1),
            _ => panic!("Unreachable"),
        },
        _ => panic!("Unreachable"),
    }
}

pub fn get_mask_round_2(instruction: &Instruction, alignment: u32) -> (u32, u32, i8) {
    match instruction {
        Sh(_) => match alignment {
            3 => (0xFFFF_FF00, 0x0000_FF00, -1),
            _ => panic!("Unreachable"),
        },
        Sw(_) => match alignment {
            3 => (0xFF00_0000, 0xFFFF_FF00, -1),
            2 => (0xFFFF_0000, 0xFFFF_0000, -2),
            1 => (0xFFFF_FF00, 0xFF00_0000, -3),
            _ => panic!("Unreachable"),
        },
        _ => panic!("Unreachable"),
    }
}

pub fn sign_extension(instruction: &Instruction, value: u32) -> u32 {
    match instruction {
        Lb(_) => {
            if (value & 0x0000_0080) != 0 {
                return 0xFFFFFF00 | value;
            }
            value
        }
        Lh(_) => {
            if (value & 0x0000_8000) != 0 {
                return 0xFFFF_0000 | value;
            }
            value
        }
        _ => value,
    }
}

pub fn get_mask_round_1_for_load(instruction: &Instruction, alignment: u32) -> (u32, i8) {
    match instruction {
        Lb(_) | Lbu(_) => match alignment {
            0 => (0x0000_00FF, 0),
            1 => (0x0000_FF00, -1),
            2 => (0x00FF_0000, -2),
            3 => (0xFF00_0000, -3),
            _ => panic!("Unreachable"),
        },
        Lhu(_) | Lh(_) => match alignment {
            0 => (0x0000_FFFF, 0),
            1 => (0x00FF_FF00, -1),
            2 => (0xFFFF_0000, -2),
            3 => (0xFF00_0000, -3),
            _ => panic!("Unreachable"),
        },
        Lw(_) => match alignment {
            3 => (0xFF00_0000, -3),
            2 => (0xFFFF_0000, -2),
            1 => (0xFF_FFFF00, -1),
            0 => (0xFFFF_FFFF, 0),
            _ => panic!("Unreachable"),
        },
        _ => panic!("Unreachable"),
    }
}

pub fn get_mask_round_2_for_load(instruction: &Instruction, alignment: u32) -> (u32, i8) {
    match instruction {
        Lhu(_) | Lh(_) => match alignment {
            3 => (0x0000_00FF, 1),
            _ => panic!("Unreachable"),
        },
        Lw(_) => match alignment {
            3 => (0x00FF_FFFF, 1),
            2 => (0x0000_FFFF, 2),
            1 => (0x0000_00FF, 3),
            _ => panic!("Unreachable"),
        },
        _ => panic!("Unreachable"),
    }
}
