use std::str::FromStr;

use crate::memory::MemoryWitness;
use blake3::Hasher;
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ProgramCounter {
    address: u32,
    micro: u8,
}

impl ProgramCounter {
    pub fn new(address: u32, micro: u8) -> ProgramCounter {
        ProgramCounter { address, micro }
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

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
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
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TraceReadPC {
    pub pc: ProgramCounter,
    pub opcode: u32,
}

impl TraceReadPC {
    pub fn new(pc: ProgramCounter, opcode: u32) -> TraceReadPC {
        TraceReadPC { pc, opcode }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TraceWrite {
    pub address: u32,
    pub value: u32,
}

impl TraceWrite {
    pub fn new(address: u32, value: u32) -> TraceWrite {
        TraceWrite { address, value }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[allow(unused)]
pub struct TraceStep {
    pub write_1: TraceWrite,
    pub write_pc: ProgramCounter,
}

impl TraceStep {
    pub fn new(write_1: TraceWrite, write_pc: ProgramCounter) -> TraceStep {
        TraceStep { write_1, write_pc }
    }

    pub fn new_step(
        write_address: u32,
        write_value: u32,
        program_counter: u32,
        micro: u8,
    ) -> TraceStep {
        TraceStep {
            write_1: TraceWrite::new(write_address, write_value),
            write_pc: ProgramCounter::new(program_counter as u32, micro),
        }
    }

    pub fn get_write(&self) -> &TraceWrite {
        &self.write_1
    }
    pub fn get_pc(&self) -> &ProgramCounter {
        &self.write_pc
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(&self.write_1.address.to_be_bytes());
        bytes.extend(&self.write_1.value.to_be_bytes());
        bytes.extend(&self.write_pc.get_address().to_be_bytes());
        bytes.push(self.write_pc.get_micro());
        bytes
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[allow(unused)]
pub struct TraceRWStep {
    pub step_number: u64,
    pub read_1: TraceRead,
    pub read_2: TraceRead,
    pub read_pc: TraceReadPC,
    pub trace_step: TraceStep,
    pub witness: Option<u32>,
    pub mem_witness: MemoryWitness,
}

impl TraceRWStep {
    pub fn new(
        step_number: u64,
        read_1: TraceRead,
        read_2: TraceRead,
        read_pc: TraceReadPC,
        trace_step: TraceStep,
        witness: Option<u32>,
        mem_witness: MemoryWitness,
    ) -> TraceRWStep {
        TraceRWStep {
            step_number,
            read_1,
            read_2,
            read_pc,
            trace_step,
            witness,
            mem_witness,
        }
    }

    pub fn from_step(step_number: u64) -> Self {
        TraceRWStep {
            step_number,
            ..Default::default()
        }
    }

    pub fn get_trace_step(&self) -> &TraceStep {
        &self.trace_step
    }

    pub fn to_csv(&self) -> String {
        //"read1_address;read1_value;read1_last_step;read2_address;read2_value;read2_last_step;read_pc_address;read_pc_micro;read_pc_opcode;write_address;write_value;write_pc;write_micro;write_trace;step_hash;step".to_string()
        format!(
            "{:016x};{:08x};{:08x};{:016x};{:08x};{:08x};{:016x};{:08x};{:02x};{:08x};{:08x};{:08x};{:08x};{:02x};{:08x};{:02x}",
            self.step_number,
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
            self.witness.unwrap_or(0),
            self.mem_witness.byte()
        )
    }
}

impl FromStr for TraceRWStep {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s).map_err(|e| format!("Failed to parse TraceRWStep: {}", e))
    }
}

pub fn compute_step_hash(
    hasher: &mut Hasher,
    previous_hash: &[u8; 20],
    write_trace: &Vec<u8>,
) -> [u8; 20] {
    // Compute the Blake3 hash
    hasher.reset();
    hasher.update(previous_hash);
    hasher.update(write_trace);
    let mut output = [0u8; 20];
    hasher.finalize_xof().fill(&mut output);
    output
}

pub fn generate_initial_step_hash() -> Vec<u8> {
    // Convert "ff" to bytes
    let initial_bytes = hex::decode("ff").expect("Invalid hex string");
    // Compute the Blake3 hash
    let mut hasher = blake3::Hasher::new();
    hasher.update(&initial_bytes);
    hasher.finalize().as_bytes()[..20].to_vec()
}

pub fn validate_step_hash(hash: &str, step: &TraceStep, next_hash: &str) -> bool {
    let hash = hex::decode(hash).expect("Invalid hex string");
    let next_hash = hex::decode(next_hash).expect("Invalid hex string");
    let trace_bytes = step.to_bytes();

    let mut hasher = blake3::Hasher::new();
    hasher.update(&hash);
    hasher.update(&trace_bytes);
    let computed_hash = hasher.finalize().as_bytes()[..20].to_vec();
    computed_hash == next_hash
}

pub fn hashvec_to_string(hash: Vec<u8>) -> String {
    hash.iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<String>()
}

pub fn hash_to_string(hash: &[u8; 20]) -> String {
    hash.iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<String>()
}
