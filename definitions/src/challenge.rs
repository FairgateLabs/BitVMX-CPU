use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    memory::{MemoryWitness, SectionDefinition},
    trace::{ProgramCounter, TraceRWStep, TraceRead, TraceReadPC, TraceStep, TraceWrite},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChallengeType {
    TraceHash(String, TraceStep, String), // PROVER_PREV_HASH, PROVER_TRACE_STEP, PROVER_STEP_HASH
    TraceHashZero(TraceStep, String),     // PROVER_TRACE_STEP, PROVER_STEP_HASH
    EntryPoint(TraceReadPC, u64, u32), // (PROVER_READ_PC, PROVER_READ_MICRO), PROVER_TRACE_STEP, ENTRYPOINT (only used on test)
    ProgramCounter(String, TraceStep, String, TraceReadPC),
    Opcode(TraceReadPC, u32, u32, Option<Vec<u32>>), // (PROVER_PC, PROVER_OPCODE), CHUNK_INDEX, CHUNK_BASE_ADDRESS, OPCODES_CHUNK
    InputData(TraceRead, TraceRead, u32, u32),
    AddressesSections(
        TraceRead,
        TraceRead,
        TraceWrite,
        MemoryWitness,
        ProgramCounter,
        Option<SectionDefinition>, // read write sections
        Option<SectionDefinition>, // read only sections
        Option<SectionDefinition>, // register sections
        Option<SectionDefinition>, // code sections
    ),
    No,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum EmulatorResultType {
    ProverExecuteResult {
        last_step: u64,
        last_hash: String,
        halt: Option<(u32, u64)>, // (return value, step)
    },
    VerifierCheckExecutionResult {
        step: Option<u64>, // step to challenge
    },
    ProverGetHashesForRoundResult {
        // hashes for the round
        hashes: Vec<String>,
        round: u8,
    },
    VerifierChooseSegmentResult {
        v_decision: u32,
        round: u8,
    },
    ProverFinalTraceResult {
        final_trace: TraceRWStep,
    },
    VerifierChooseChallengeResult {
        challenge: ChallengeType,
    },
}

#[derive(Error, Debug)]
pub enum EmulatorResultError {
    #[error("Emulator Result Error: {0}")]
    GenericError(String),
}

impl EmulatorResultType {
    pub fn from_value(value: serde_json::Value) -> Result<Self, EmulatorResultError> {
        serde_json::from_value(value)
            .map_err(|e| EmulatorResultError::GenericError(format!("Failed to deserialize: {}", e)))
    }

    pub fn to_value(&self) -> Result<serde_json::Value, EmulatorResultError> {
        serde_json::to_value(self)
            .map_err(|e| EmulatorResultError::GenericError(format!("Failed to serialize: {}", e)))
    }

    pub fn as_prover_execute(
        &self,
    ) -> Result<(u64, String, Option<(u32, u64)>), EmulatorResultError> {
        match self {
            EmulatorResultType::ProverExecuteResult {
                last_step,
                last_hash,
                halt,
            } => Ok((*last_step, last_hash.clone(), halt.clone())),
            _ => Err(EmulatorResultError::GenericError(
                "Expected ProverExecuteResult".to_string(),
            )),
        }
    }

    pub fn as_verifier_check(&self) -> Result<Option<u64>, EmulatorResultError> {
        match self {
            EmulatorResultType::VerifierCheckExecutionResult { step } => Ok(step.clone()),
            _ => Err(EmulatorResultError::GenericError(
                "Expected VerifierCheckExecutionResult".to_string(),
            )),
        }
    }

    pub fn as_prover_hashes(&self) -> Result<(Vec<String>, u8), EmulatorResultError> {
        match self {
            EmulatorResultType::ProverGetHashesForRoundResult { hashes, round } => {
                Ok((hashes.clone(), round.clone()))
            }
            _ => Err(EmulatorResultError::GenericError(
                "Expected ProverGetHashesForRoundResult".to_string(),
            )),
        }
    }

    pub fn as_v_decision(&self) -> Result<(u32, u8), EmulatorResultError> {
        match self {
            EmulatorResultType::VerifierChooseSegmentResult { v_decision, round } => {
                Ok((*v_decision, round.clone()))
            }
            _ => Err(EmulatorResultError::GenericError(
                "Expected VerifierChooseSegmentResult".to_string(),
            )),
        }
    }

    pub fn as_final_trace(&self) -> Result<TraceRWStep, EmulatorResultError> {
        match self {
            EmulatorResultType::ProverFinalTraceResult { final_trace } => Ok(final_trace.clone()),
            _ => Err(EmulatorResultError::GenericError(
                "Expected ProverFinalTraceResult".to_string(),
            )),
        }
    }

    pub fn as_challenge(&self) -> Result<ChallengeType, EmulatorResultError> {
        match self {
            EmulatorResultType::VerifierChooseChallengeResult { challenge } => {
                Ok(challenge.clone())
            }
            _ => Err(EmulatorResultError::GenericError(
                "Expected VerifierChooseChallengeResult".to_string(),
            )),
        }
    }
}
