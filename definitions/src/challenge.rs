use crate::trace::{TraceReadPC, TraceStep};

#[derive(Debug, Clone)]
pub enum ChallengeType {
    TraceHash(String, TraceStep, String), // PROVER_PREV_HASH, PROVER_TRACE_STEP, PROVER_STEP_HASH
    TraceHashZero(TraceStep, String),     // PROVER_TRACE_STEP, PROVER_STEP_HASH
    EntryPoint(TraceReadPC, u64, u32), // (PROVER_READ_PC, PROVER_READ_MICRO), PROVER_TRACE_STEP, ENTRYPOINT (only used on test)
    No,
}
