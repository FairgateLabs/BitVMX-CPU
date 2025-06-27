pub mod challenge;
pub mod memory;
pub mod trace;

pub mod constants {
    pub const LAST_STEP_INIT: u64 = 0xFFFF_FFFF_FFFF_FFFF;
    pub const CODE_CHUNK_SIZE: u32 = 500;
}
