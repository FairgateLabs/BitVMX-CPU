use crate::trace::TraceStep;

#[derive(Debug, Clone)]
pub enum ChallengeType {
    TraceHash(String, TraceStep, String), // PROVER_PREV_HASH, PROVER_TRACE_STEP, PROVER_STEP_HASH
    TraceHashZero(TraceStep, String),     // PROVER_TRACE_STEP, PROVER_STEP_HASH
    No,
}
