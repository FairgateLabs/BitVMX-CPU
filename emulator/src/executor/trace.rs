use crate::loader::program::{ProgramCounter, Registers};
use sha2::{digest::FixedOutputReset, Digest, Sha256};

//TODO: Define INITIAL_STATE for last_step

#[derive(Debug, Default)]
pub struct TraceRead {
    pub address: u32,
    pub value: u32,
    pub last_step: u64,
}

impl TraceRead {
    pub fn new(address: u32, value: u32, last_step: u64) -> TraceRead {
        TraceRead {
            address,
            value,
            last_step,
        }
    }

    pub fn new_from(registers: &Registers, idx: u32) -> TraceRead {
        TraceRead {
            address: registers.get_register_address(idx),
            value: registers.get(idx),
            last_step: registers.get_last_step(idx),
        }
    }
}

#[derive(Debug, Default)]
pub struct TraceReadPC {
    pub pc: ProgramCounter,
    pub opcode: u32,
}

impl TraceReadPC {
    pub fn new(pc: ProgramCounter, opcode: u32) -> TraceReadPC {
        TraceReadPC {
            pc,
            opcode,
        }
    }
}

#[derive(Debug, Default)]
pub struct TraceWrite {
    pub address: u32,
    pub value: u32,
}


impl TraceWrite {
    pub fn new(address: u32, value: u32) -> TraceWrite {
        TraceWrite {
            address,
            value,
        }
    }

    pub fn new_from(registers: &Registers, idx: u32) -> TraceWrite {
        TraceWrite {
            address: registers.get_register_address(idx),
            value: registers.get(idx),
        }
    }
}

#[derive(Debug, Default)]
pub struct TraceWritePC {
    pub pc: ProgramCounter,
}

impl TraceWritePC {
    pub fn new(pc: &ProgramCounter) -> TraceWritePC {
        TraceWritePC {
            pc: pc.clone()
        }
    }
}

#[derive(Debug, Default)]
#[allow(unused)]
pub struct TraceStep {
    pub(crate) write_1: TraceWrite,
    pub(crate) write_pc: TraceWritePC,
}

impl TraceStep {
    pub fn new(write_1: TraceWrite, write_pc: TraceWritePC) -> TraceStep {
        TraceStep {
            write_1,
            write_pc,
        }
    }

    pub fn get_write(&self) -> &TraceWrite {
        &self.write_1
    }
    pub fn get_pc(&self) -> &ProgramCounter {
        &self.write_pc.pc
    }

    pub fn to_hex_string(&self) -> String {
        format!("{:08x}{:08x}{:08x}{:02x}", self.write_1.address, self.write_1.value, self.write_pc.pc.get_address(), self.write_pc.pc.get_micro())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(&self.write_1.address.to_be_bytes());
        bytes.extend(&self.write_1.value.to_be_bytes());
        bytes.extend(&self.write_pc.pc.get_address().to_be_bytes());
        bytes.push(self.write_pc.pc.get_micro());
        bytes
    }

}

#[derive(Debug, Default)]
#[allow(unused)]
pub struct TraceRWStep {
    pub(crate) read_1: TraceRead,
    pub(crate) read_2: TraceRead,
    pub(crate) read_pc: TraceReadPC,
    pub(crate) trace_step: TraceStep,
    pub(crate) witness: Option<u32>
}


impl TraceRWStep {
    pub fn new(read_1: TraceRead, read_2: TraceRead, read_pc: TraceReadPC, trace_step: TraceStep, witness: Option<u32>) -> TraceRWStep {
        TraceRWStep {
            read_1,
            read_2,
            read_pc,
            trace_step,
            witness,
        }
    }

    pub fn get_trace_step(&self) -> &TraceStep {
        &self.trace_step
    }

    pub fn to_write_trace(&self) -> String {
        self.trace_step.to_hex_string()
    }

    pub fn to_csv(&self) -> String {
        //"read1_address;read1_value;read1_last_step;read2_address;read2_value;read2_last_step;read_pc_address;read_pc_micro;read_pc_opcode;write_address;write_value;write_pc;write_micro;write_trace;step_hash;step".to_string()
        format!("{};{};{};{};{};{};{};{};{};{};{};{};{}",
            self.read_1.address,
            self.read_1.value,
            self.read_1.last_step,

            self.read_2.address,
            self.read_2.value,
            self.read_2.last_step,

            self.read_pc.pc.get_address(),
            self.read_pc.pc.get_micro(),
            self.read_pc.opcode,

            self.trace_step.get_write().address,
            self.trace_step.get_write().value,

            self.trace_step.get_pc().get_address(),
            self.trace_step.get_pc().get_micro(),
        )
    }
}


pub fn compute_step_hash(hasher: &mut Sha256,   previous_hash: &[u8; 32], write_trace: &Vec<u8>) -> [u8; 32] {
    // Compute the SHA-256 hash
    //let mut hasher = Sha256::new();
    hasher.update(previous_hash);
    hasher.update(write_trace);
    hasher.finalize_fixed_reset().into()
}

pub fn generate_initial_step_hash() -> Vec<u8> {
    // Convert "ff" to bytes
    let initial_bytes = hex::decode("ff").expect("Invalid hex string");
    // Compute the SHA-256 hash
    let mut hasher = Sha256::new();
    hasher.update(initial_bytes);
    hasher.finalize().to_vec()
}

