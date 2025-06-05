#![allow(dead_code)]
use bitvmx_cpu_definitions::{memory::SectionDefinition, trace::ProgramCounter};
use emulator::loader::program::{Program, Registers, Section};
use rand::Rng;
use riscv_decode::types::{BType, IType, JType, RType, SType, ShiftType, UType};
use std::ops::RangeInclusive;

const PROGRAM_REG_RANGE: RangeInclusive<u32> = 0x1..=0x1F;

pub fn create_btype_from(imm: u32, rs1: u8, rs2: u8) -> BType {
    let rs1 = (rs1 as u32) << 15;
    let rs2 = (rs2 as u32) << 20;

    let bit31 = (imm & 0x1000) << 19;
    let bit30_25 = (imm & 0x7e0) << 20;
    let bit11_8 = (imm & 0x1e) << 7;
    let bit7 = (imm & 0x800) >> 4;
    let ret = bit31 | bit30_25 | bit11_8 | bit7 | rs1 | rs2;
    BType(ret)
}

pub fn create_itype_from(imm: u32, rs1: u8, rd: u8) -> IType {
    IType(imm << 20 | (rs1 as u32) << 15 | (rd as u32) << 7)
}

pub fn create_jtype_from(imm: u32, rd: u8) -> JType {
    JType(imm << 20 | (rd as u32) << 7)
}

pub fn create_rtype_from(rs2: u8, rs1: u8, rd: u8) -> RType {
    RType((rs2 as u32) << 20 | (rs1 as u32) << 15 | (rd as u32) << 7)
}

pub fn create_shift_type_from(imm: u32, rs1: u8, rd: u8) -> ShiftType {
    ShiftType(imm << 20 | (rs1 as u32) << 15 | (rd as u32) << 7) // shamt[4:0]
}

pub fn create_stype_from(imm: u32, rs1: u8, rs2: u8) -> SType {
    let rs1 = (rs1 as u32) << 15;
    let rs2 = (rs2 as u32) << 20;
    let imm_part = ((imm & 0x1f) << 7) | ((imm & 0x7e0) << 20);
    SType(imm_part | rs1 | rs2)
}

pub fn create_utype_from(imm: u32, rd: u8) -> UType {
    UType((imm & 0xFFFF_F000) | ((rd as u32) << 7))
}

pub fn get_new_program() -> Program {
    Program {
        sections: vec![],
        registers: Registers::new(0, 0),
        pc: ProgramCounter::new(0, 0),
        step: 0,
        hash: [0; 20],
        halt: false,
        read_write_sections: SectionDefinition::default(),
        read_only_sections: SectionDefinition::default(),
        register_sections: SectionDefinition::default(),
        code_sections: SectionDefinition::default(),
    }
}

pub fn get_new_section() -> Section {
    Section {
        name: "test_data".to_string(),
        data: vec![0; 30],
        last_step: vec![0xffff_ffff; 30],
        start: 0x4000_0000,
        size: 20 * 4,
        is_code: false,
        is_write: true,
        initialized: true,
        registers: false,
    }
}

pub fn rnd_range() -> u32 {
    let mut rng = rand::thread_rng();
    rng.gen_range(PROGRAM_REG_RANGE)
}
