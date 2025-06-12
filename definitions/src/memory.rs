use serde::{Deserialize, Serialize};

pub mod memory_access_type {
    pub const REGISTER: u8 = 0;
    pub const MEMORY: u8 = 1;
    pub const UNUSED: u8 = 2;
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SectionDefinition {
    pub ranges: Vec<(u32, u32)>,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum MemoryAccessType {
    Register,
    Memory,
    Unused,
}

impl Into<u8> for MemoryAccessType {
    fn into(self) -> u8 {
        match self {
            MemoryAccessType::Register => memory_access_type::REGISTER,
            MemoryAccessType::Memory => memory_access_type::MEMORY,
            MemoryAccessType::Unused => memory_access_type::UNUSED,
        }
    }
}

impl From<u8> for MemoryAccessType {
    fn from(value: u8) -> Self {
        match value {
            memory_access_type::REGISTER => MemoryAccessType::Register,
            memory_access_type::MEMORY => MemoryAccessType::Memory,
            memory_access_type::UNUSED => MemoryAccessType::Unused,
            _ => panic!("Invalid value for MemoryAccessType"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemoryWitness {
    data: u8,
}

impl Default for MemoryWitness {
    fn default() -> Self {
        MemoryWitness::new(
            MemoryAccessType::Unused,
            MemoryAccessType::Unused,
            MemoryAccessType::Unused,
        )
    }
}

impl MemoryWitness {
    pub fn byte(&self) -> u8 {
        self.data
    }

    pub fn registers() -> Self {
        Self::new(
            MemoryAccessType::Register,
            MemoryAccessType::Register,
            MemoryAccessType::Register,
        )
    }

    pub fn no_write() -> Self {
        Self::new(
            MemoryAccessType::Register,
            MemoryAccessType::Register,
            MemoryAccessType::Unused,
        )
    }

    pub fn rur() -> Self {
        Self::new(
            MemoryAccessType::Register,
            MemoryAccessType::Unused,
            MemoryAccessType::Register,
        )
    }

    pub fn new(
        read_1: MemoryAccessType,
        read_2: MemoryAccessType,
        write: MemoryAccessType,
    ) -> Self {
        Self {
            data: ((read_1 as u8) << 4) | ((read_2 as u8) << 2) | (write as u8),
        }
    }

    pub fn from_byte(data: u8) -> Self {
        Self { data }
    }

    pub fn read_1(&self) -> MemoryAccessType {
        (self.data >> 4).into()
    }

    pub fn read_2(&self) -> MemoryAccessType {
        ((self.data >> 2) & 0b11).into()
    }

    pub fn write(&self) -> MemoryAccessType {
        (self.data & 0b11).into()
    }
}

//create tests for the functions
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mem_witness() {
        let read_1 = MemoryAccessType::Memory;
        let read_2 = MemoryAccessType::Register;
        let write = MemoryAccessType::Unused;

        let witness = MemoryWitness::new(read_1, read_2, write);

        assert_eq!(witness.read_1(), read_1);
        assert_eq!(witness.read_2(), read_2);
        assert_eq!(witness.write(), write);
    }
}
