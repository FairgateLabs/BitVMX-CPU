use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    memory::{Chunk, MemoryWitness, SectionDefinition},
    trace::{ProgramCounter, TraceRWStep, TraceRead, TraceReadPC, TraceStep, TraceWrite},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChallengeType {
    TraceHash {
        prover_step_hash: String,
        prover_trace: TraceStep,
        prover_next_hash: String,
    },
    TraceHashZero {
        prover_trace: TraceStep,
        prover_next_hash: String,
    },
    EntryPoint {
        prover_read_pc: TraceReadPC,
        prover_trace_step: u64,
        real_entry_point: Option<u32>,
    },
    ProgramCounter {
        pre_hash: String,
        trace: TraceStep,
        prover_step_hash: String,
        prover_pc_read: TraceReadPC,
    },
    Opcode {
        prover_pc_read: TraceReadPC,
        chunk_index: u32,
        chunk: Option<Chunk>,
    },
    InputData {
        prover_read_1: TraceRead,
        prover_read_2: TraceRead,
        address: u32,
        input_for_address: u32,
    },
    InitializedData {
        prover_read_1: TraceRead,
        prover_read_2: TraceRead,
        read_selector: u32,
        chunk_index: u32,
        chunk: Option<Chunk>,
    },
    UninitializedData {
        prover_read_1: TraceRead,
        prover_read_2: TraceRead,
        read_selector: u32,
        sections: Option<SectionDefinition>,
    },
    RomData {
        prover_read_1: TraceRead,
        prover_read_2: TraceRead,
        address: u32,
        input_for_address: u32,
    },
    AddressesSections {
        prover_read_1: TraceRead,
        prover_read_2: TraceRead,
        prover_write: TraceWrite,
        prover_witness: MemoryWitness,
        prover_pc: ProgramCounter,
        read_write_sections: Option<SectionDefinition>,
        read_only_sections: Option<SectionDefinition>,
        register_sections: Option<SectionDefinition>,
        code_sections: Option<SectionDefinition>,
    },
    FutureRead {
        step: u64,
        prover_read_step_1: u64,
        prover_read_step_2: u64,
        read_selector: u32,
    },
    ReadValueNArySearch {
        bits: u32,
    },
    ReadValue {
        prover_read_1: TraceRead,
        prover_read_2: TraceRead,
        read_selector: u32,
        prover_hash: String,
        trace: TraceStep,
        prover_next_hash: String,
        write_step: u64,
        conflict_step: u64,
    },
    CorrectHash {
        prover_step_hash: String,
        verifier_hash: String,
        trace: TraceStep,
        prover_next_hash: String,
    },
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
