use std::str::FromStr;

use bitvmx_cpu_definitions::trace::{TraceRWStep, TraceRead};
use num_traits;

use crate::loader::program::Program;

#[derive(Clone, Debug, Default)]
pub struct FailRead {
    pub address_original: u32,
    pub value: u32,
    pub modified_address: u32,
    pub modified_last_step: u64,
    pub step: u64,
    pub init: bool, // used to prevent failing on step == 0 (FailRead::default)
}

impl FailRead {
    #[allow(clippy::ptr_arg)]
    pub fn new(args: &Vec<String>) -> Self {
        fn parse_value<T>(value: &str) -> T
        where
            T: num_traits::Num + std::str::FromStr,
            T: std::fmt::Debug,
            <T as std::str::FromStr>::Err: std::fmt::Debug,
        {
            if value.starts_with("0x") {
                T::from_str_radix(&value[2..], 16)
                    .unwrap_or_else(|_| panic!("Invalid hexadecimal value"))
            } else {
                value.parse::<T>().expect("Invalid decimal value")
            }
        }

        Self {
            step: parse_value::<u64>(&args[0]) - 1,
            address_original: parse_value::<u32>(&args[1]),
            value: parse_value::<u32>(&args[2]),
            modified_address: parse_value::<u32>(&args[3]),
            modified_last_step: parse_value::<u64>(&args[4]),
            init: true,
        }

        /*Self {
            step: args[0].parse::<u64>().expect("Invalid modified_last_step") - 1,
            address_original: args[1]
                .parse::<u32>()
                .expect("Invalid address_original value"),
            value: args[2].parse::<u32>().expect("Invalid value"),
            modified_address: args[3]
                .parse::<u32>()
                .expect("Invalid modified_address value"),
            modified_last_step: args[4].parse::<u64>().expect("Invalid modified_last_step"),
            init: true,
        }*/
    }

    pub fn patch_trace_read(&self, trace: &mut TraceRead) {
        trace.address = self.modified_address;
        trace.last_step = self.modified_last_step;
    }

    //use this method to determine if the address is a register or a memory address until both are consolidated
    pub fn is_register_address(&self, program: &Program) -> bool {
        self.address_original >= program.registers.get_base_address()
            && self.address_original <= program.registers.get_last_register_address()
    }

    pub fn patch_mem(&self, program: &mut Program) {
        // wether the addr belongs to a section or to a register
        // todo this will be changed when we consolidate sections and registers
        if self.is_register_address(program) {
            let idx = program.registers.get_original_idx(self.address_original);
            program.registers.set(idx, self.value, program.step);
        }

        if program.find_section(self.address_original).is_ok() {
            program
                .write_mem(self.address_original, self.value)
                .unwrap();
            return;
        }
    }
}

#[derive(Clone, Debug)]
pub struct FailReads {
    read_1: FailRead,
    read_2: FailRead,
}

impl FailReads {
    pub fn new(
        fail_read_1_args: Option<&Vec<String>>,
        fail_read_2_args: Option<&Vec<String>>,
    ) -> Self {
        Self {
            read_1: fail_read_1_args.map_or(FailRead::default(), FailRead::new),
            read_2: fail_read_2_args.map_or(FailRead::default(), FailRead::new),
        }
    }

    pub fn patch_mem(&self, program: &mut Program) -> (bool, bool) {
        let (mut patch_1, mut patch_2) = (false, false);

        if self.read_1.init && self.read_1.step == program.step {
            self.read_1.patch_mem(program);
            patch_1 = true;
        }
        if self.read_2.init && self.read_2.step == program.step {
            self.read_2.patch_mem(program);
            patch_2 = true;
        }

        (patch_1, patch_2)
    }

    pub fn patch_trace_reads(&self, trace: &mut TraceRWStep, should_patch: (bool, bool)) {
        if self.read_1.init && should_patch.0 {
            self.read_1.patch_trace_read(&mut trace.read_1);
        }

        if self.read_2.init && should_patch.1 {
            self.read_2.patch_trace_read(&mut trace.read_2);
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct FailConfiguration {
    pub fail_hash: Option<u64>,
    pub fail_execute: Option<u64>,
    pub fail_reads: Option<FailReads>,
    pub fail_pc: Option<u64>,
}

impl FailConfiguration {
    pub fn new_fail_hash(fail_hash: u64) -> Self {
        Self {
            fail_hash: Some(fail_hash),
            ..Default::default()
        }
    }
    pub fn new_fail_execute(fail_execute: u64) -> Self {
        Self {
            fail_execute: Some(fail_execute),
            ..Default::default()
        }
    }
    pub fn new_fail_reads(fail_reads: FailReads) -> Self {
        Self {
            fail_reads: Some(fail_reads),
            ..Default::default()
        }
    }
    pub fn new_fail_pc(fail_pc: u64) -> Self {
        Self {
            fail_pc: Some(fail_pc),
            ..Default::default()
        }
    }
}

impl FromStr for FailConfiguration {
    type Err = String;

    fn from_str(_s: &str) -> Result<Self, Self::Err> {
        // TODO: implement
        Ok(FailConfiguration {
            fail_hash: None,
            fail_execute: None,
            fail_reads: None,
            fail_pc: None,
        })
    }
}

#[cfg(test)]
mod utils_tests {
    use super::*;
    use crate::loader::program::{Program, Section};

    #[test]
    fn test_fail_read_1_register_patch() {
        let mut program = Program::new(0x1000, 0xF000_0000, 0xE000_0000);
        let fail_read_1_args = vec![
            "10".to_string(),
            "4026531900".to_string(),
            "5".to_string(),
            "4026531900".to_string(),
            "15".to_string(),
        ];
        let fail_reads = FailReads::new(Some(&fail_read_1_args), None);
        program.step = 9;
        fail_reads.patch_mem(&mut program);
        let idx = program.registers.get_original_idx(4026531900);

        assert_eq!(program.registers.get(idx), 5);
    }

    #[test]
    fn test_fail_read_2_register_patch() {
        let mut program = Program::new(0x1000, 0xF000_0000, 0xE000_0000);
        let fail_read_2_args = vec![
            "10".to_string(),
            "4026531904".to_string(),
            "6".to_string(),
            "4026531904".to_string(),
            "20".to_string(),
        ];
        let fail_reads = FailReads::new(None, Some(&fail_read_2_args));
        program.step = 9;
        fail_reads.patch_mem(&mut program);
        let idx = program.registers.get_original_idx(4026531904);

        assert_eq!(program.registers.get(idx), 6);
    }

    #[test]
    fn test_fail_read_1_memory_patch() {
        let mut program = Program::new(0x1000, 0xF000_0000, 0xE000_0000);
        program.add_section(Section {
            name: "test_section".to_string(),
            data: vec![0; 4],
            last_step: vec![0; 4],
            start: 0x1000,
            size: 16,
            is_code: false,
            initialized: true,
            registers: false,
        });
        let fail_read_1_args = vec![
            "10".to_string(),
            "4096".to_string(),
            "10".to_string(),
            "4096".to_string(),
            "15".to_string(),
        ];
        let fail_reads = FailReads::new(Some(&fail_read_1_args), None);
        program.step = 9;
        fail_reads.patch_mem(&mut program);

        assert_eq!(program.read_mem(4096).unwrap(), 10);
    }

    #[test]
    fn test_fail_read_2_memory_patch() {
        let mut program = Program::new(0x1000, 0xF000_0000, 0xE000_0000);
        program.add_section(Section {
            name: "test_section".to_string(),
            data: vec![0; 4],
            last_step: vec![0; 4],
            start: 0x1000,
            size: 16,
            is_code: false,
            initialized: true,
            registers: false,
        });
        let fail_read_2_args = vec![
            "10".to_string(),
            "4100".to_string(),
            "11".to_string(),
            "4100".to_string(),
            "20".to_string(),
        ];
        let fail_reads = FailReads::new(None, Some(&fail_read_2_args));
        program.step = 9;
        fail_reads.patch_mem(&mut program);

        assert_eq!(program.read_mem(4100).unwrap(), 11);
    }

    #[test]
    fn test_fail_read_default_has_no_effect() {
        let mut program = Program::new(0x1000, 0xF000_0000, 0xE000_0000);
        program.add_section(Section {
            name: "test_section".to_string(),
            data: vec![0; 4],
            last_step: vec![0; 4],
            start: 0x1000,
            size: 16,
            is_code: false,
            initialized: true,
            registers: false,
        });
        let fail_reads = FailReads::new(None, None);
        program.step = 10;
        fail_reads.patch_mem(&mut program);

        assert_eq!(program.read_mem(4100).unwrap(), 0);
    }
}
