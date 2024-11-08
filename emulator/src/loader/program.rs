use std::cmp::Ordering;

use bitcoin_script_riscv::riscv::instruction_mapping::{get_key_from_instruction_and_micro, get_required_microinstruction};
use elf::{abi::SHF_EXECINSTR, endian::LittleEndian, ElfBytes};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::{executor::trace::generate_initial_step_hash, REGISTERS_BASE_ADDRESS};

#[derive(Debug, Serialize, Deserialize)]
pub struct Section {
    pub name: String,
    pub data: Vec<u32>,
    pub last_step: Vec<u64>,
    pub start: u32,
    pub size: u32,
    pub is_code: bool,
    pub initialized: bool,
}

pub const CHECKPOINT_SIZE : u64 = 50_000_000;
//pub const CHECKPOINT_SIZE : u64 = 50;
pub const LIMIT_STEP : u64 = 10_000_000_000; //ten billion arbitrary limit
const RISCV32_REGISTERS : usize = 32;
const AUX_REGISTERS : usize = 2;
pub const AUX_REGISTER_1 : u32 = 32;
pub const AUX_REGISTER_2 : u32 = 33;
pub const REGISTER_STACK_POINTER : usize = 2;
pub const REGISTER_ZERO : usize = 0;
pub const REGISTER_A0 : usize = 10;
pub const REGISTER_A7_ECALL_ARG : usize = 17;

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
            last_step: [0xffffffff; RISCV32_REGISTERS + AUX_REGISTERS],
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
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ProgramCounter {
    address: u32,
    micro: u8,
}

impl ProgramCounter {
    pub fn new(address: u32, micro: u8) -> ProgramCounter {
        ProgramCounter {
            address,
            micro,
        }
    }

    pub fn get_address(&self) -> u32 {
        self.address
    }

    pub fn get_micro(&self) -> u8 {
        self.micro
    }

    pub fn jump(&mut self, address: u32) {
        self.address = address;
    }

    pub fn next_address(&mut self) {
        self.address += 4;
        self.micro = 0;
    }

    pub fn next_micro(&mut self) {
        self.micro += 1;
    }

}

#[derive(Debug, Serialize, Deserialize)]
pub struct Program {
    pub sections: Vec<Section>,
    pub registers: Registers,
    pub pc: ProgramCounter,
    pub step: u64,
    pub hash: [u8; 32],
    pub halt: bool,
}

impl Program {
    pub fn serialize_to_file(&self, fname: &str) {
        let serialized = serde_json::to_string(self).unwrap();
        std::fs::write(fname, serialized).expect("Unable to write file");
    }

    pub fn deserialize_from_file(fname: &str) -> Program {
        let serialized = std::fs::read(fname).expect("Unable to read file");
        let serialized_str = std::str::from_utf8(&serialized).expect("Unable to convert to UTF-8");
        serde_json::from_str(serialized_str).expect("Unable to deserialize")
    }

    pub fn new(entry_point: u32, registers_base_address: u32, sp_base_address: u32) -> Program {
        Program {
            sections: Vec::new(),
            registers: Registers::new(registers_base_address, sp_base_address),
            pc: ProgramCounter::new(entry_point, 0),
            step: 0,
            hash: generate_initial_step_hash().try_into().expect("Invalid hash size"),
            halt: false,
        }
    }
    
    pub fn add_section(&mut self, section: Section) {
        let pos = self.sections.binary_search_by(|s| s.start.cmp(&section.start))
            .unwrap_or_else(|e| e);
        self.sections.insert(pos, section);
    }

    fn find_section_idx(&self, address: u32) -> Option<usize> {
        // Binary search to find the appropriate section
        self.sections.binary_search_by(|section| {
            if address < section.start {
                Ordering::Greater
            } else if address >= section.start + section.size {
                Ordering::Less
            } else {
                Ordering::Equal
            }
        }).ok()
    }

    // Find the section that contains the given address
    pub fn find_section(&self, address: u32) -> Option<&Section> {
        self.sections.get(self.find_section_idx(address)?)
    }

    // Find the section that contains the given address
    pub fn find_section_mut(&mut self, address: u32) -> Option<&mut Section> {
        let idx = self.find_section_idx(address)?;
        self.sections.get_mut(idx)
    }

    pub fn find_section_by_name(&mut self, name: &str) -> Option<&mut Section> {
        self.sections.iter_mut().find(|section| section.name == name)
    }

    //TODO: handle errors
    pub fn read_mem(&self, address: u32) -> u32 {
        if cfg!(target_endian = "big") {
            panic!("Big endian machine not supported");
        }
        let section = self.find_section(address).expect(&format!("Address 0x{:08x} not found in any section", address));
        u32::from_be( section.data[(address - section.start) as usize / 4])
    }

    pub fn get_last_step(&self, address: u32) -> u64 {
        let section = self.find_section(address).unwrap();
        section.last_step[(address - section.start) as usize / 4]
    }

    pub fn write_mem(&mut self, address: u32, value: u32) {
        let step = self.step;
        let section = self.find_section_mut(address).expect(&format!("Address 0x{:08x} not found in any section", address));
        section.data[(address - section.start) as usize / 4] = value.to_be(); 
        section.last_step[(address - section.start) as usize / 4] = step
    }

    pub fn dump_memory(&self) {
        println!("\n------- Section: REGISTERS Start: 0x{:08x} Size: 0x{:08x} -------\n",
            REGISTERS_BASE_ADDRESS, (RISCV32_REGISTERS + AUX_REGISTERS) * std::mem::size_of::<u32>());

        for (i, reg) in self.registers.value.iter().enumerate() {
            let reg_addr = self.registers.get_register_address(i as u32);
            println!("{}Reg({}): 0x{:08x} Value: 0x{:08x}",
                if i == AUX_REGISTER_1 as usize || i == AUX_REGISTER_2 as usize { "AUX" } else { "" },
                i, reg_addr, reg);
        }

        for section in &self.sections {
            if section.data.iter().any(|&word| word != 0) {
                println!("\n------- Section: {} Start: 0x{:08x} Size: 0x{:08x} -------\n", section.name, section.start, section.size);
                for (i, word) in section.data.iter().enumerate() {
                    let address = section.start + (i as u32 * 4);
                    if *word != 0 {
                        println!("Address: 0x{:08x} Value: 0x{:08x}", address, word);
                    }
                }
            } else {
                println!("\n------- Skipping empty section: {} -------", section.name);
            }
        }
        println!("\n================================================\n");
    }
}

pub fn vec_u8_to_vec_u32(input: &[u8], little:bool) -> Vec<u32> {
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


pub fn load_elf(fname: &str, show_sections: bool) -> Program  {
    //TODO: handle errors on unwrap

    const STACK_BASE_ADDRESS: u32 = 0xE000_0000;        //CHECK: this can be parameterized
    const STACK_SIZE: u32 = 0x80_0000;                  //QEMU Default stack size

    let path = std::path::PathBuf::from(fname);
    let file_data = std::fs::read(path).expect("Could not read file.");
    let slice = file_data.as_slice();
    let file = ElfBytes::<LittleEndian>::minimal_parse(slice).expect("Open test1");
    
    let entry_point = u32::try_from(file.ehdr.e_entry).unwrap();
    let string_table =file.section_headers_with_strtab().unwrap().1.unwrap();

    let mut program = Program::new(entry_point, REGISTERS_BASE_ADDRESS, STACK_BASE_ADDRESS+STACK_SIZE);

    file.section_headers().unwrap().iter().for_each(|phdr| {

        if phdr.sh_flags as u32 & elf::abi::SHF_ALLOC != elf::abi::SHF_ALLOC {
            return;
        }

        let name = string_table.get_raw(phdr.sh_name as usize).map(|name| {
            std::str::from_utf8(name).unwrap().to_string()
        }).unwrap_or("".to_string());
        let start = u32::try_from(phdr.sh_addr).unwrap();
        let size = u32::try_from(phdr.sh_size).unwrap();
        let initialized = phdr.sh_type == elf::abi::SHT_PROGBITS;
        //println!("{:?}",phdr);
        if size == 0 {
            if show_sections {
                println!("Empty section: {} Start: 0x{:08x} Size: 0x{:08x} Initialized: {}", name, start, size, initialized);
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
            println!("Loading section: {} Start: 0x{:08x} Size: 0x{:08x} Initialized: {} Flags: {:0b} Type: {:0b} ", name, start, size, initialized, phdr.sh_flags, phdr.sh_type);
        }

        program.add_section(Section {
            name,
            data,
            last_step: vec![0xffff_ffff; size as usize / 4],
            start,
            size,
            is_code: phdr.sh_flags as u32 & SHF_EXECINSTR == SHF_EXECINSTR,
            initialized: initialized,
        })
        
    });

    program


}


pub fn generate_rom_commitment(program: &Program) {
    for section in &program.sections {
        if section.is_code {
            for i in 0..section.size / 4 {
                let position = section.start + i * 4;
                let data = program.read_mem(position);

                let instruction = riscv_decode::decode(data).expect(&format!("code section with undecodeable instruction: 0x{:08x} at position: 0x{:08x}", data, position));
                let micros = get_required_microinstruction(&instruction);
                for micro in 0..micros {
                    let key = get_key_from_instruction_and_micro(&instruction, micro);
                    println!("PC: 0x{:08x} Micro: {} Opcode: 0x{:08x} Key: {}", position, micro, data, key);
                }
            }
        }
    }
    for section in &program.sections {
        if !section.is_code && section.initialized {
            for i in 0..section.size / 4 {
                let position = section.start + i * 4;
                let data = program.read_mem(position);
                println!("Address: 0x{:08x} value: 0x{:08x}", position, data);
            }
        }
    }
    for section in &program.sections {
        if !section.is_code && !section.initialized {
            println!("Zero initialized range: start: 0x{:08x} size: 0x{:08x}", section.start, section.size);
        }
    }
    println!("Entrypoint: 0x{:08x}", program.pc.get_address());
}
