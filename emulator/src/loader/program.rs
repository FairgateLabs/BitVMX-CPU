use std::cmp::Ordering;

use bitcoin_script_riscv::riscv::instruction_mapping::{
    get_key_from_instruction_and_micro, get_required_microinstruction,
};
use bitvmx_cpu_definitions::{
    constants::LAST_STEP_INIT,
    trace::{generate_initial_step_hash, ProgramCounter, TraceRead, TraceWrite},
};
use elf::{abi::SHF_EXECINSTR, abi::SHF_WRITE, endian::LittleEndian, ElfBytes};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use tracing::{error, info};

use crate::{constants::*, EmulatorError, ExecutionResult};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Section {
    pub name: String,
    pub data: Vec<u32>,
    pub last_step: Vec<u64>,
    pub start: u32,
    pub size: u32,
    pub is_code: bool,
    pub is_write: bool,
    pub initialized: bool,
    pub registers: bool, // special section for registers
}

impl Section {
    pub fn new(
        name: &str,
        start: u32,
        size: u32,
        is_code: bool,
        is_write: bool,
        registers: bool,
    ) -> Section {
        Section {
            name: name.to_string(),
            data: vec![0; size as usize / 4],
            last_step: vec![LAST_STEP_INIT; size as usize / 4],
            start,
            size,
            is_code,
            is_write,
            initialized: false,
            registers,
        }
    }

    pub fn new_with_data(
        name: &str,
        data: Vec<u32>,
        start: u32,
        size: u32,
        is_code: bool,
        is_write: bool,
        initialized: bool,
    ) -> Section {
        Section {
            name: name.to_string(),
            data,
            last_step: vec![LAST_STEP_INIT; size as usize / 4],
            start,
            size,
            is_code,
            is_write,
            initialized,
            registers: false,
        }
    }
}

pub const CHECKPOINT_SIZE: u64 = 50_000_000;
pub const LIMIT_STEP: u64 = 10_000_000_000; //ten billion arbitrary limit
const RISCV32_REGISTERS: usize = 32;
const AUX_REGISTERS: usize = 2;
pub const AUX_REGISTER_1: u32 = 32;
pub const AUX_REGISTER_2: u32 = 33;
pub const REGISTER_STACK_POINTER: usize = 2;
pub const REGISTER_ZERO: usize = 0;
pub const REGISTER_A0: usize = 10;
pub const REGISTER_A7_ECALL_ARG: usize = 17;

#[derive(Debug, Serialize, Deserialize)]
pub struct Registers {
    #[serde(with = "BigArray")]
    value: [u32; RISCV32_REGISTERS + AUX_REGISTERS],
    #[serde(with = "BigArray")]
    last_step: [u64; RISCV32_REGISTERS + AUX_REGISTERS],
    base_address: u32,
}

impl Registers {
    pub fn new(base_address: u32, sp_base_address: u32) -> Registers {
        let mut registers = Registers {
            value: [0; RISCV32_REGISTERS + AUX_REGISTERS],
            last_step: [LAST_STEP_INIT; RISCV32_REGISTERS + AUX_REGISTERS],
            base_address,
        };
        registers.value[REGISTER_STACK_POINTER] = sp_base_address; // Stack pointer
        registers
    }

    pub fn get_base_address(&self) -> u32 {
        self.base_address
    }

    pub fn get_last_register_address(&self) -> u32 {
        self.base_address + (RISCV32_REGISTERS as u32 * 4 + AUX_REGISTERS as u32 * 4)
    }

    pub fn get(&self, idx: u32) -> u32 {
        self.value[idx as usize]
    }

    pub fn get_last_step(&self, idx: u32) -> u64 {
        self.last_step[idx as usize]
    }

    pub fn set(&mut self, idx: u32, value: u32, step: u64) {
        if idx == REGISTER_ZERO as u32 {
            panic!("Cannot set register zero. Value: {} Step: {}", value, step);
        }
        self.value[idx as usize] = value;
        self.last_step[idx as usize] = step;
    }

    pub fn get_register_address(&self, idx: u32) -> u32 {
        self.base_address + (idx * 4)
    }

    pub fn get_original_idx(&self, address: u32) -> u32 {
        (address - self.base_address) / 4
    }

    pub fn to_trace_read(&self, idx: u32) -> TraceRead {
        TraceRead {
            address: self.get_register_address(idx),
            value: self.get(idx),
            last_step: self.get_last_step(idx),
        }
    }

    pub fn to_trace_write(&self, idx: u32) -> TraceWrite {
        TraceWrite {
            address: self.get_register_address(idx),
            value: self.get(idx),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Program {
    pub sections: Vec<Section>,
    pub registers: Registers,
    pub pc: ProgramCounter,
    pub step: u64,
    pub hash: [u8; 20],
    pub halt: bool,
}

impl Program {
    pub fn serialize_to_file(&self, fpath: &str) {
        let fname = format!("{}/checkpoint.{}.json", fpath, self.step);
        let serialized = serde_json::to_string(self).unwrap();
        std::fs::write(fname, serialized).expect("Unable to write file");
    }

    pub fn deserialize_from_file(fpath: &str, step: u64) -> Result<Program, EmulatorError> {
        let fname = format!("{}/checkpoint.{}.json", fpath, step);
        let serialized = std::fs::read(&fname).map_err(|_| {
            EmulatorError::CantLoadPorgram(format!("Error loading file: {}", fname))
        })?;
        let serialized_str = std::str::from_utf8(&serialized).map_err(|_| {
            EmulatorError::CantLoadPorgram(format!("Error parsing file: {}", fname))
        })?;
        serde_json::from_str(serialized_str).map_err(|_| {
            EmulatorError::CantLoadPorgram(format!("Error deserializing file: {}", fname))
        })
    }

    pub fn new(entry_point: u32, registers_base_address: u32, sp_base_address: u32) -> Program {
        Program {
            sections: Vec::new(),
            registers: Registers::new(registers_base_address, sp_base_address),
            pc: ProgramCounter::new(entry_point, 0),
            step: 0,
            hash: generate_initial_step_hash()
                .try_into()
                .expect("Invalid hash size"),
            halt: false,
        }
    }

    pub fn sanity_check(&self) -> Result<(), EmulatorError> {
        //check overlapping sections
        for i in 0..self.sections.len() {
            for j in i + 1..self.sections.len() {
                let section1 = &self.sections[i];
                let section2 = &self.sections[j];
                if section1.start < section2.start + section2.size
                    && section1.start + section1.size > section2.start
                {
                    return Err(EmulatorError::CantLoadPorgram(format!(
                        "Overlapping sections: {} and {}",
                        section1.name, section2.name
                    )));
                }
            }
        }
        Ok(())
    }

    pub fn add_section(&mut self, section: Section) {
        let pos = self
            .sections
            .binary_search_by(|s| s.start.cmp(&section.start))
            .unwrap_or_else(|e| e);
        self.sections.insert(pos, section);
    }

    fn find_section_idx(&self, address: u32) -> Result<usize, ExecutionResult> {
        // Binary search to find the appropriate section
        Ok(self
            .sections
            .binary_search_by(|section| {
                if address < section.start {
                    Ordering::Greater
                } else if address >= section.start + section.size {
                    Ordering::Less
                } else {
                    Ordering::Equal
                }
            })
            .map_err(|_| {
                ExecutionResult::SectionNotFound(format!(
                    "Address 0x{:08x} not found in any section",
                    address
                ))
            })?)
    }

    // Find the section that contains the given address
    pub fn find_section(&self, address: u32) -> Result<&Section, ExecutionResult> {
        let section_idx = self.find_section_idx(address)?;
        let section = self.sections.get(section_idx).ok_or_else(|| {
            ExecutionResult::SectionNotFound(format!(
                "Address 0x{:08x} not found in any section",
                address
            ))
        })?;
        if section.registers {
            return Err(ExecutionResult::RegistersSectionFail);
        }
        Ok(section)
    }

    // Find the section that contains the given address
    pub fn find_section_mut(&mut self, address: u32) -> Result<&mut Section, ExecutionResult> {
        let section_idx = self.find_section_idx(address)?;
        let section = self.sections.get_mut(section_idx).ok_or_else(|| {
            ExecutionResult::SectionNotFound(format!(
                "Address 0x{:08x} not found in any section",
                address
            ))
        })?;
        if section.registers {
            return Err(ExecutionResult::RegistersSectionFail);
        }
        Ok(section)
    }

    pub fn find_section_by_name(&mut self, name: &str) -> Option<&mut Section> {
        self.sections
            .iter_mut()
            .find(|section| section.name == name)
    }

    pub fn read_mem(&self, address: u32) -> Result<u32, ExecutionResult> {
        if cfg!(target_endian = "big") {
            panic!("Big endian machine not supported");
        }
        let section = self.find_section(address)?;
        Ok(u32::from_be(
            section.data[(address - section.start) as usize / 4],
        ))
    }

    pub fn get_last_step(&self, address: u32) -> u64 {
        let section = self.find_section(address).unwrap();
        section.last_step[(address - section.start) as usize / 4]
    }

    pub fn write_mem(&mut self, address: u32, value: u32) -> Result<(), ExecutionResult> {
        let step = self.step;
        let section = self.find_section_mut(address)?;
        if !section.is_write {
            return Err(ExecutionResult::WriteToReadOnlySection);
        }
        section.data[(address - section.start) as usize / 4] = value.to_be();
        section.last_step[(address - section.start) as usize / 4] = step;
        Ok(())
    }

    pub fn dump_memory(&self) {
        info!(
            "\n------- Section: REGISTERS Start: 0x{:08x} Size: 0x{:08x} -------\n",
            REGISTERS_BASE_ADDRESS,
            (RISCV32_REGISTERS + AUX_REGISTERS) * std::mem::size_of::<u32>()
        );

        for (i, reg) in self.registers.value.iter().enumerate() {
            let reg_addr = self.registers.get_register_address(i as u32);
            info!(
                "{}Reg({}): 0x{:08x} Value: 0x{:08x}",
                if i == AUX_REGISTER_1 as usize || i == AUX_REGISTER_2 as usize {
                    "AUX"
                } else {
                    ""
                },
                i,
                reg_addr,
                reg
            );
        }

        for section in &self.sections {
            if section.data.iter().any(|&word| word != 0) {
                info!(
                    "\n------- Section: {} Start: 0x{:08x} Size: 0x{:08x} -------\n",
                    section.name, section.start, section.size
                );
                for (i, word) in section.data.iter().enumerate() {
                    let address = section.start + (i as u32 * 4);
                    if *word != 0 {
                        info!("Address: 0x{:08x} Value: 0x{:08x}", address, word);
                    }
                }
            } else {
                info!("\n------- Skipping empty section: {} -------", section.name);
            }
        }
        info!("\n================================================\n");
    }

    pub fn valid_address(
        &self,
        address: u32,
        section_filter: impl Fn(&&Section) -> bool,
    ) -> (bool, Vec<(u32, u32)>) {
        let sections_ranges: Vec<(u32, u32)> = self
            .sections
            .iter()
            .filter(section_filter)
            .map(|section| (section.start, section.start + section.size))
            .collect();

        let is_valid = sections_ranges
            .iter()
            .any(|&(start, end)| start <= address && address <= end - 3)
            && address % 4 == 0;
        (is_valid, sections_ranges)
    }
}

pub fn vec_u8_to_vec_u32(input: &[u8], little: bool) -> Vec<u32> {
    let mut padded_input = input.to_vec();
    let remainder = padded_input.len() % 4;

    if remainder != 0 {
        let padding = 4 - remainder;
        padded_input.extend(vec![0; padding]);
    }

    padded_input
        .chunks_exact(4)
        .map(|chunk| {
            // Convert each chunk to a little-endian u32
            if little {
                u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])
            } else {
                u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])
            }
        })
        .collect()
}

pub fn load_elf(fname: &str, show_sections: bool) -> Result<Program, EmulatorError> {
    let path = std::path::PathBuf::from(fname);
    let file_data = std::fs::read(path)
        .map_err(|_| EmulatorError::CantLoadPorgram(format!("Error loading file: {}", fname)))?;
    let slice = file_data.as_slice();
    let file = ElfBytes::<LittleEndian>::minimal_parse(slice)
        .map_err(|_| EmulatorError::CantLoadPorgram(format!("Error parsing elf: {}", fname)))?;

    let entry_point = u32::try_from(file.ehdr.e_entry).map_err(|_| {
        EmulatorError::CantLoadPorgram(format!("Invalid entrypoint for elf: {}", fname))
    })?;
    let string_table = file
        .section_headers_with_strtab()
        .map_err(|_| EmulatorError::CantLoadPorgram(format!("Can't read headers for: {}", fname)))?
        .1
        .ok_or_else(|| {
            EmulatorError::CantLoadPorgram(format!("Can't read string table for: {}", fname))
        })?;

    let mut program = Program::new(
        entry_point,
        REGISTERS_BASE_ADDRESS,
        STACK_BASE_ADDRESS + STACK_SIZE,
    );

    let sections = file.section_headers().ok_or_else(|| {
        EmulatorError::CantLoadPorgram(format!("Can't read headers for: {}", fname))
    })?;

    program.add_section(Section::new(
        "registers",
        program.registers.get_base_address(),
        ((RISCV32_REGISTERS + AUX_REGISTERS) * 4) as u32,
        false,
        true,
        true,
    ));
    if show_sections {
        info!("Loading section: {} Start: 0x{:08x} Size: 0x{:08x} Initialized: {} Flags: {:0b} Type: {:0b} ", "registers", REGISTERS_BASE_ADDRESS, ((RISCV32_REGISTERS + AUX_REGISTERS) * 4) as u32, false, 0, 0);
    }

    sections.iter().for_each(|phdr| {

        if phdr.sh_flags as u32 & elf::abi::SHF_ALLOC != elf::abi::SHF_ALLOC {
            return;
        }

        let name = string_table.get_raw(phdr.sh_name as usize).map(|name| {
            std::str::from_utf8(name).unwrap_or("").to_string()
        }).unwrap_or("".to_string());
        let start = u32::try_from(phdr.sh_addr);
        let size = u32::try_from(phdr.sh_size);
        if start.is_err() || size.is_err() {
            error!("Invalid start or size for section: {} Start: 0x{:08x} Size: 0x{:08x}", name, start.unwrap_or(0), size.unwrap_or(0));
            return;
        }
        let start = start.unwrap();
        let size = size.unwrap();


        let initialized = phdr.sh_type == elf::abi::SHT_PROGBITS;
        if size == 0 {
            if show_sections {
                info!("Empty section: {} Start: 0x{:08x} Size: 0x{:08x} Initialized: {}", name, start, size, initialized);
            }
            return;
        }

        let data = if initialized {
            vec_u8_to_vec_u32(&slice[phdr.sh_offset as usize..(phdr.sh_offset + size as u64) as usize], false)
        } else {
            assert!(size % 4 == 0, "Number of bytes must be a multiple of 4");
            let num_u32 = size / 4;
            vec![0; num_u32 as usize]
        };

        if show_sections {
            info!("Loading section: {} Start: 0x{:08x} Size: 0x{:08x} Initialized: {} Flags: {:0b} Type: {:0b} ", name, start, size, initialized, phdr.sh_flags, phdr.sh_type);
        }

        let is_code = phdr.sh_flags as u32 & SHF_EXECINSTR == SHF_EXECINSTR;
        let is_write = phdr.sh_flags as u32 & SHF_WRITE == SHF_WRITE;

        program.add_section(Section::new_with_data(&name, data, start, size, is_code, is_write, initialized));
    });

    program.sanity_check()?;

    Ok(program)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Code {
    pub address: u32,
    pub micro: u8,
    pub opcode: u32,
    pub key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RomCommitment {
    pub entrypoint: u32,
    pub code: Vec<Code>,
    pub constants: Vec<(u32, u32)>,        //address, data
    pub zero_initialized: Vec<(u32, u32)>, //start, size
}

pub fn generate_rom_commitment(program: &Program) -> Result<RomCommitment, EmulatorError> {
    let mut rom_commitment = RomCommitment {
        entrypoint: program.pc.get_address(),
        code: Vec::new(),
        constants: Vec::new(),
        zero_initialized: Vec::new(),
    };

    for section in &program.sections {
        if section.is_code {
            for i in 0..section.size / 4 {
                let position = section.start + i * 4;
                let data = program.read_mem(position)?;

                let instruction = riscv_decode::decode(data).expect(&format!(
                    "code section with undecodeable instruction: 0x{:08x} at position: 0x{:08x}",
                    data, position
                ));
                let micros = get_required_microinstruction(&instruction);
                for micro in 0..micros {
                    let key = get_key_from_instruction_and_micro(&instruction, micro);
                    info!(
                        "PC: 0x{:08x} Micro: {} Opcode: 0x{:08x} Key: {}",
                        position, micro, data, key
                    );
                    rom_commitment.code.push(Code {
                        address: position,
                        micro: micro,
                        opcode: data,
                        key: key,
                    });
                }
            }
        }
    }
    for section in &program.sections {
        if !section.is_code && section.initialized {
            for i in 0..section.size / 4 {
                let position = section.start + i * 4;
                let data = program.read_mem(position)?;
                info!("Address: 0x{:08x} value: 0x{:08x}", position, data);
                rom_commitment.constants.push((position, data));
            }
        }
    }
    for section in &program.sections {
        if !section.is_code && !section.initialized {
            info!(
                "Zero initialized range: start: 0x{:08x} size: 0x{:08x}",
                section.start, section.size
            );
            rom_commitment
                .zero_initialized
                .push((section.start, section.size));
        }
    }

    info!("Entrypoint: 0x{:08x}", program.pc.get_address());

    Ok(rom_commitment)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_overlap_sections() {
        let mut program = Program::new(0, 0, 0);
        program.add_section(Section::new("test_1", 0, 10, false, true, false));
        program.add_section(Section::new("test_2", 9, 5, false, true, false));
        assert!(program.sanity_check().is_err());
    }

    #[test]
    fn test_invalid_use_of_registers_section() {
        let mut program = Program::new(0, 0, 0);
        program.add_section(Section::new("registers", 0, 10, false, true, true));
        assert_eq!(
            program.find_section(0),
            Err(ExecutionResult::RegistersSectionFail)
        );
        assert_eq!(
            program.find_section_mut(0),
            Err(ExecutionResult::RegistersSectionFail)
        );
    }

    #[test]
    fn test_write_to_read_only_section() {
        let mut program = Program::new(0, 0, 0);
        program.add_section(Section::new("code", 0, 10, true, false, false));
        assert_eq!(
            program.write_mem(0, 123),
            Err(ExecutionResult::WriteToReadOnlySection)
        );
    }
}
