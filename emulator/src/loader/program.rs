use std::cmp::Ordering;

use bitcoin_script_riscv::riscv::instruction_mapping::{
    get_key_from_instruction_and_micro, get_required_microinstruction,
};
use bitvmx_cpu_definitions::{
    constants::LAST_STEP_INIT,
    memory::{MemoryAccessType, SectionDefinition},
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

    pub fn range(&self) -> (u32, u32) {
        (self.start, self.start + self.size - 1)
    }

    pub fn contains(&self, address: u32) -> bool {
        let (start, end) = self.range();
        return address >= start && address <= end - 3;
    }

    pub fn is_merge_compatible(&self, other: &Self) -> bool {
        return self.is_code == other.is_code
            && self.is_write == other.is_write
            && self.initialized == other.initialized
            && self.registers == other.registers
            && self.start + self.size == other.start;
    }

    pub fn merge_in_place(&mut self, other: Self) {
        assert!(
            self.is_merge_compatible(&other),
            "Incompatible merge {:?} with {:?}",
            self,
            other
        );

        self.data.extend(other.data);
        self.last_step.extend(other.last_step);
        self.size += other.size;

        self.name = format!(
            "merge_{}_{}",
            self.name.replace("merge_", ""),
            other.name.replace("merge_", "")
        );
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
    pub read_write_sections: SectionDefinition,
    pub read_only_sections: SectionDefinition,
    pub register_sections: SectionDefinition,
    pub code_sections: SectionDefinition,
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
            read_write_sections: SectionDefinition::default(),
            read_only_sections: SectionDefinition::default(),
            register_sections: SectionDefinition::default(),
            code_sections: SectionDefinition::default(),
        }
    }

    pub fn merge_sections(&mut self) {
        let sections = std::mem::take(&mut self.sections);
        let mut merged: Vec<Section> = Vec::with_capacity(sections.len());

        for section in sections {
            if let Some(last) = merged.last_mut() {
                if last.is_merge_compatible(&section) {
                    last.merge_in_place(section);
                    continue;
                }
            }
            merged.push(section);
        }

        self.sections = merged;
    }

    pub fn generate_sections_definitions(&mut self) {
        for section in &self.sections {
            let section_range = section.range();

            if section.registers {
                self.register_sections.ranges.push(section_range);
            } else if section.is_write {
                self.read_write_sections.ranges.push(section_range);
            } else if section.is_code {
                self.code_sections.ranges.push(section_range);
                self.read_only_sections.ranges.push(section_range);
            } else {
                self.read_only_sections.ranges.push(section_range);
            }
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
        if !section.is_write || section.is_code {
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

    pub fn address_in_sections(&self, address: u32, sections: &SectionDefinition) -> bool {
        sections
            .ranges
            .iter()
            .any(|&(start, end)| start <= address && address <= end - 3)
            && address % 4 == 0
    }

    pub fn is_valid_mem(
        &self,
        witness: MemoryAccessType,
        address: u32,
        valid_if_read_only: bool,
    ) -> bool {
        match witness {
            MemoryAccessType::Unused => true,
            MemoryAccessType::Register => {
                self.address_in_sections(address, &self.register_sections)
            }
            MemoryAccessType::Memory if valid_if_read_only => {
                self.address_in_sections(address, &self.read_only_sections)
                    || self.address_in_sections(address, &self.read_write_sections)
            }
            MemoryAccessType::Memory if !valid_if_read_only => {
                self.address_in_sections(address, &self.read_write_sections)
            }
            _ => unreachable!("unreachable"),
        }
    }

    pub fn get_chunk_info(&self, address: u32, chunk_size: u32) -> (u32, u32, usize) {
        let mut chunk_index = 0;

        for section in &self.sections {
            if !section.is_code {
                continue;
            }

            if section.contains(address) {
                let section_start = section.start;
                let offset = address - section_start;
                let instr_index = offset / 4;

                chunk_index += instr_index / chunk_size;

                let chunk_start_instr = instr_index - (instr_index % chunk_size);
                let chunk_base_addr = section_start + chunk_start_instr * 4;
                let chunk_start_index = chunk_start_instr as usize;

                return (chunk_index, chunk_base_addr, chunk_start_index);
            }

            let section_instrs = section.size / 4;
            // only counts full chunks
            let mut section_chunks = section_instrs / chunk_size;

            // if section_instrs isn't a multiple of chunk_size that means that there is a non-full chunk we have to count
            if section_instrs % chunk_size != 0 {
                section_chunks += 1;
            }

            chunk_index += section_chunks;
        }

        unreachable!("Non-executable address: 0x{:08X}", address);
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
        assert!(!(is_code && is_write), "We don't allow writable code sections");

        program.add_section(Section::new_with_data(&name, data, start, size, is_code, is_write, initialized));
    });

    program.merge_sections();
    program.generate_sections_definitions();
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

    #[test]
    fn test_merge_sections() {
        let mut program = Program::new(0, 0, 0);
        program.add_section(Section::new("code_1", 0, 10, true, false, false));
        program.add_section(Section::new("code_2", 10, 10, true, false, false));
        program.add_section(Section::new("code_3", 30, 10, true, false, false));

        program.add_section(Section::new("read_only", 40, 10, false, false, false));
        program.add_section(Section::new("read_write", 50, 10, false, true, false));

        program.merge_sections();

        // continuous code sections did merge
        let merged_code = &program.sections[0];
        assert_eq!(merged_code.start, 0);
        assert_eq!(merged_code.size, 20);
        assert!(merged_code.is_code);
        assert!(!merged_code.is_write);
        assert!(!merged_code.registers);

        // non continuous code section did not merge
        let unmerged_code = &program.sections[1];
        assert_eq!(unmerged_code.start, 30);
        assert_eq!(unmerged_code.size, 10);
        assert!(unmerged_code.is_code);
        assert!(!unmerged_code.is_write);
        assert!(!unmerged_code.registers);

        // continuous but incompatible sections did not merge
        let read_only = &program.sections[2];
        assert_eq!(read_only.start, 40);
        assert_eq!(read_only.size, 10);
        assert!(!read_only.is_code);
        assert!(!read_only.is_write);
        assert!(!read_only.registers);

        let read_write = &program.sections[3];
        assert_eq!(read_write.start, 50);
        assert_eq!(read_write.size, 10);
        assert!(!read_write.is_code);
        assert!(read_write.is_write);
        assert!(!read_write.registers);

        // there are no new sections
        assert_eq!(program.sections.len(), 4);
    }

    #[test]
    fn test_chunk_info() {
        let mut program = Program::new(0, 0, 0);

        // first section has 3 chunks, two full chunks of 500 instructions and half a chunk of 250 instructions
        program.add_section(Section::new(
            "code_1",
            1000,
            500 * 4 * 2 + 250 * 4,
            true,
            false,
            false,
        ));
        program.add_section(Section::new("code_2", 10000, 500 * 4, true, false, false));

        // start of first chunk
        let (chunk_index, chunk_base_addr, chunk_start_index) = program.get_chunk_info(1000, 500);
        assert_eq!(chunk_index, 0);
        assert_eq!(chunk_base_addr, 1000);
        assert_eq!(chunk_start_index, 0);

        // middle of first chunk
        let (chunk_index, chunk_base_addr, chunk_start_index) =
            program.get_chunk_info(1000 + 250 * 4, 500);
        assert_eq!(chunk_index, 0);
        assert_eq!(chunk_base_addr, 1000);
        assert_eq!(chunk_start_index, 0);

        // start of second chunk
        let (chunk_index, chunk_base_addr, chunk_start_index) =
            program.get_chunk_info(1000 + 500 * 4, 500);
        assert_eq!(chunk_index, 1);
        assert_eq!(chunk_base_addr, 1000 + 500 * 4);
        assert_eq!(chunk_start_index, 500);

        // middle of second chunk
        let (chunk_index, chunk_base_addr, chunk_start_index) =
            program.get_chunk_info(1000 + 500 * 4 + 250 * 4, 500);
        assert_eq!(chunk_index, 1);
        assert_eq!(chunk_base_addr, 1000 + 500 * 4);
        assert_eq!(chunk_start_index, 500);

        // start of first chunk of the second section
        let (chunk_index, chunk_base_addr, chunk_start_index) = program.get_chunk_info(10000, 500);
        assert_eq!(chunk_index, 3);
        assert_eq!(chunk_base_addr, 10000);
        assert_eq!(chunk_start_index, 0);

        // middle of first chunk of the second section
        let (chunk_index, chunk_base_addr, chunk_start_index) =
            program.get_chunk_info(10000 + 250 * 4, 500);
        assert_eq!(chunk_index, 3);
        assert_eq!(chunk_base_addr, 10000);
        assert_eq!(chunk_start_index, 0);
    }
}
