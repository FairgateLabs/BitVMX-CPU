use crate::loader::program::{ProgramCounter, Registers};
use sha2::{Sha256, Digest};

//TODO: Define INITIAL_STATE for last_step


#[derive(Debug, Default)]
pub struct TraceRead {
    pub address: u32,
    pub value: u32,
    pub last_step: u32,
}

impl TraceRead {
    pub fn new(address: u32, value: u32, last_step: u32) -> TraceRead {
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
    write_1: TraceWrite,
    write_pc: TraceWritePC,
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
}

#[derive(Debug, Default)]
#[allow(unused)]
pub struct TraceRWStep {
    read_1: TraceRead,
    read_2: TraceRead,
    read_pc: TraceReadPC,
    trace_step: TraceStep,
}


impl TraceRWStep {
    pub fn new(read_1: TraceRead, read_2: TraceRead, read_pc: TraceReadPC, trace_step: TraceStep) -> TraceRWStep {
        TraceRWStep {
            read_1,
            read_2,
            read_pc,
            trace_step,
        }
    }

    pub fn get_trace_step(&self) -> &TraceStep {
        &self.trace_step
    }
}


pub fn hash_trace(hashlist: &mut Vec<String>, program_step: u32, trace_step: &TraceStep ) {

    let write = trace_step.get_write();
    let pc = trace_step.get_pc();

    //TODO: avoid string conversion, use bytes directly
    let new_str = format!("{}{}{}{}{}{}", hashlist.last().unwrap(), program_step, write.address, write.value, pc.get_address(), pc.get_micro());
    let mut hasher = Sha256::new();
    hasher.update(&new_str);
    let result = hasher.finalize();
    let res = hex::encode(result);

    hashlist.push(res);

}