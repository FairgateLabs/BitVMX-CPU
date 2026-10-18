use bitvmx_cpu_definitions::trace::TraceRWStep;
use serde::{Deserialize, Serialize};

use crate::{decision::nary_search::NArySearchType, EmulatorError, ExecutionResult};

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ProverNAryLog {
    pub base_step: u64,
    pub verifier_decisions: Vec<u32>,
    pub hash_rounds: Vec<Vec<String>>,
    pub final_trace: TraceRWStep,
    /// Running upper bound on the disputed step. Only used by the full-duplex
    /// search, where the prover selects as well as dissects.
    #[serde(default)]
    pub step_to_challenge: u64,
    /// Dissections published by the counterparty. Only used by the full-duplex
    /// search.
    #[serde(default)]
    pub counterparty_hash_rounds: Vec<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProverChallengeLog {
    pub execution: ExecutionLog,
    pub input: Vec<u8>,
    pub conflict_step_log: ProverNAryLog,
    pub read_challenge_log: ProverNAryLog,
}

impl ProverChallengeLog {
    pub fn new(execution: ExecutionLog, input: Vec<u8>) -> Self {
        // Under the full-duplex search the prover selects as well as dissects,
        // so it needs the same running bound on the disputed step that the
        // verifier keeps: one before the earliest step the parties could still
        // disagree on. The prover's own claim is its only knowledge of that,
        // and the bound is only ever tightened by later selections.
        let step_to_challenge = execution.last_step.saturating_sub(1);
        Self {
            execution,
            input,
            conflict_step_log: ProverNAryLog {
                step_to_challenge,
                ..Default::default()
            },
            read_challenge_log: ProverNAryLog::default(),
        }
    }

    pub fn save(&self, path: &str) -> Result<(), EmulatorError> {
        serialize_challenge_log(path, self)
    }

    pub fn load(path: &str) -> Result<Self, EmulatorError> {
        deserialize_challenge_log(path)
    }

    pub fn get_nary_log(&mut self, nary_search: NArySearchType) -> &mut ProverNAryLog {
        match nary_search {
            NArySearchType::ConflictStep => &mut self.conflict_step_log,
            NArySearchType::ReadValueChallenge => &mut self.read_challenge_log,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct VerifierNAryLog {
    pub base_step: u64,
    pub step_to_challenge: u64,
    pub verifier_decisions: Vec<u32>,
    pub prover_hash_rounds: Vec<Vec<String>>,
    pub verifier_hash_rounds: Vec<Vec<String>>,
    pub final_trace: TraceRWStep,
}

impl VerifierNAryLog {
    pub fn new(step_to_challenge: u64) -> Self {
        Self {
            step_to_challenge,
            ..Default::default()
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifierChallengeLog {
    pub prover_claim_execution: ExecutionLog,
    pub execution: ExecutionLog,
    pub input: Vec<u8>,
    pub conflict_step_log: VerifierNAryLog,
    pub read_challenge_log: VerifierNAryLog,
    pub read_selector: u32,
    pub read_step: u64,
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
            conflict_step_log: VerifierNAryLog::new(step_to_challenge),
            read_challenge_log: VerifierNAryLog::default(),
            read_selector: 0,
            read_step: 0,
        }
    }

    pub fn save(&self, path: &str) -> Result<(), EmulatorError> {
        serialize_challenge_log(path, self)
    }

    pub fn load(path: &str) -> Result<Self, EmulatorError> {
        deserialize_challenge_log(path)
    }

    pub fn get_nary_log(&mut self, nary_search: NArySearchType) -> &mut VerifierNAryLog {
        match nary_search {
            NArySearchType::ConflictStep => &mut self.conflict_step_log,
            NArySearchType::ReadValueChallenge => &mut self.read_challenge_log,
        }
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
        EmulatorError::ChallengeError(format!("Error loading file: {} {}", e, fname))
    })?;
    let serialized_str = std::str::from_utf8(&serialized)
        .map_err(|e| EmulatorError::ChallengeError(format!("Error parsing file: {}", e)))?;
    serde_json::from_str(serialized_str)
        .map_err(|e| EmulatorError::ChallengeError(format!("Error deserializing file: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ExecutionResult;

    /// The full-duplex search clamps each selection by this bound, so a prover
    /// log that started it at zero would pin every selection to step zero.
    #[test]
    fn prover_log_starts_with_a_usable_selection_bound() {
        let log = ProverChallengeLog::new(
            ExecutionLog::new(ExecutionResult::Halt(0, 100), 100, "ab".to_string()),
            vec![],
        );
        assert_eq!(log.conflict_step_log.step_to_challenge, 99);
    }

    #[test]
    fn prover_log_bound_does_not_underflow_on_an_empty_execution() {
        let log = ProverChallengeLog::new(
            ExecutionLog::new(ExecutionResult::Halt(0, 0), 0, "ab".to_string()),
            vec![],
        );
        assert_eq!(log.conflict_step_log.step_to_challenge, 0);
    }
}
