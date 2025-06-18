use bitvmx_cpu_definitions::trace::TraceRWStep;
use serde::{Deserialize, Serialize};

use crate::{EmulatorError, ExecutionResult};

#[derive(Debug, Serialize, Deserialize)]
pub struct ExecutionLog {
    pub result: ExecutionResult,
    pub last_step: u64,
    pub last_hash: String,
}

impl ExecutionLog {
    pub fn new(result: ExecutionResult, last_step: u64, last_hash: String) -> Self {
        Self {
            result,
            last_step,
            last_hash,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProverChallengeLog {
    pub execution: ExecutionLog,
    pub input: Vec<u8>,
    pub base_step: u64,
    pub verifier_decisions: Vec<u32>,
    pub hash_rounds: Vec<Vec<String>>,
    pub final_trace: TraceRWStep,
}

impl ProverChallengeLog {
    pub fn new(execution: ExecutionLog, input: Vec<u8>) -> Self {
        Self {
            execution,
            input,
            base_step: 0,
            verifier_decisions: Vec::new(),
            hash_rounds: Vec::new(),
            final_trace: TraceRWStep::default(),
        }
    }

    pub fn save(&self, path: &str) -> Result<(), EmulatorError> {
        serialize_challenge_log(path, self)
    }

    pub fn load(path: &str) -> Result<Self, EmulatorError> {
        deserialize_challenge_log(path)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifierChallengeLog {
    pub prover_claim_execution: ExecutionLog,
    pub execution: ExecutionLog,
    pub input: Vec<u8>,
    pub base_step: u64,
    pub step_to_challenge: u64,
    pub verifier_decisions: Vec<u32>,
    pub prover_hash_rounds: Vec<Vec<String>>,
    pub verifier_hash_rounds: Vec<Vec<String>>,
    pub final_trace: TraceRWStep,
}

impl VerifierChallengeLog {
    pub fn new(
        prover_execution: ExecutionLog,
        execution: ExecutionLog,
        input: Vec<u8>,
        step_to_challenge: u64,
    ) -> Self {
        Self {
            prover_claim_execution: prover_execution,
            execution,
            input,
            base_step: 0,
            step_to_challenge,
            verifier_decisions: Vec::new(),
            prover_hash_rounds: Vec::new(),
            verifier_hash_rounds: Vec::new(),
            final_trace: TraceRWStep::default(),
        }
    }

    pub fn save(&self, path: &str) -> Result<(), EmulatorError> {
        serialize_challenge_log(path, self)
    }

    pub fn load(path: &str) -> Result<Self, EmulatorError> {
        deserialize_challenge_log(path)
    }
}

pub fn serialize_challenge_log<T: Serialize>(path: &str, data: &T) -> Result<(), EmulatorError> {
    let fname = format!("{}/challenge_log.json", path);
    let serialized = serde_json::to_string_pretty(data)
        .map_err(|e| EmulatorError::ChallengeError(e.to_string()))?;
    std::fs::write(fname, serialized).map_err(|e| EmulatorError::ChallengeError(e.to_string()))?;
    Ok(())
}

pub fn deserialize_challenge_log<T: for<'a> Deserialize<'a>>(
    path: &str,
) -> Result<T, EmulatorError> {
    let fname = format!("{}/challenge_log.json", path);
    let serialized = std::fs::read(&fname).map_err(|e| {
        EmulatorError::ChallengeError(format!("Error loading file: {} {}", e.to_string(), fname))
    })?;
    let serialized_str = std::str::from_utf8(&serialized).map_err(|e| {
        EmulatorError::ChallengeError(format!("Error parsing file: {}", e.to_string()))
    })?;
    Ok(serde_json::from_str(serialized_str).map_err(|e| {
        EmulatorError::ChallengeError(format!("Error deserializing file: {}", e.to_string()))
    })?)
}
