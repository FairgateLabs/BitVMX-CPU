use bitvmx_cpu_definitions::{
    challenge::{ChallengeType, EquivocationKind},
    constants::{CHUNK_SIZE, LAST_STEP_INIT},
    memory::Chunk,
    trace::{generate_initial_step_hash, hashvec_to_string, validate_step_hash, TraceRWStep},
};

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use strum_macros::{Display, EnumIter, EnumString};
use tracing::{error, info, warn};

use crate::{
    decision::{
        execution_log::VerifierChallengeLog,
        nary_search::{choose_segment, ExecutionHashes, NArySearchType},
    },
    executor::utils::FailConfiguration,
    loader::program_definition::ProgramDefinition,
    EmulatorError, ExecutionResult,
};

use super::execution_log::{ExecutionLog, ProverChallengeLog};

pub fn prover_execute(
    program_definition_file: &str,
    input: Vec<u8>,
    checkpoint_path: &str,
    force: bool,
    fail_config: Option<FailConfiguration>,
    save_non_checkpoint_steps: bool,
) -> Result<(ExecutionResult, u64, String), EmulatorError> {
    let program_def = ProgramDefinition::from_config(program_definition_file)?;
    let (result, last_step, last_hash) = program_def.get_execution_result(
        input.clone(),
        checkpoint_path,
        fail_config,
        save_non_checkpoint_steps,
    )?;
    if result != ExecutionResult::Halt(0, last_step) {
        error!(
            "The execution of the program {} failed with error: {:?}. The claim should not be commited on-chain.",
            program_definition_file, result
        );
        // TODO: Enable this in production to avoid commiting a failed claim
        if !force {
            return Err(result)?;
        }
        error!("Execution with force. The claim will be commited on-chain.");
    }

    ProverChallengeLog::new(
        ExecutionLog::new(result.clone(), last_step, last_hash.clone()),
        input,
    )
    .save(checkpoint_path)?;

    Ok((result, last_step, last_hash))
}

pub fn prover_get_hashes_for_round(
    program_definition_file: &str,
    checkpoint_path: &str,
    round: u8,
    verifier_decision: u32,
    fail_config: Option<FailConfiguration>,
    nary_type: NArySearchType,
) -> Result<Vec<String>, EmulatorError> {
    let mut challenge_log = ProverChallengeLog::load(checkpoint_path)?;
    let input = challenge_log.input.clone();
    let nary_log = challenge_log.get_nary_log(nary_type);
    let program_def = ProgramDefinition::from_config(program_definition_file)?;

    let new_base = match round {
        1 => nary_log.base_step,
        _ => program_def.nary_def().step_from_base_and_bits(
            round - 1,
            nary_log.base_step,
            verifier_decision,
        ),
    };

    nary_log.base_step = new_base;
    let hashes = program_def.get_round_hashes(
        checkpoint_path,
        input,
        round,
        nary_log.base_step,
        fail_config,
    )?;
    nary_log.hash_rounds.push(hashes.clone());
    // at the first round the verifier hasn't decided anything yet
    if round > 1 {
        nary_log.verifier_decisions.push(verifier_decision)
    };
    // the hashes of the first round would be reused in the next nary-search
    if round == 1 && nary_type == NArySearchType::ConflictStep {
        challenge_log
            .read_challenge_log
            .hash_rounds
            .push(hashes.clone());
    }
    challenge_log.save(checkpoint_path)?;
    Ok(hashes)
}

pub fn verifier_check_execution(
    program_definition_file: &str,
    input: Vec<u8>,
    checkpoint_path: &str,
    claim_last_step: u64,
    claim_last_hash: &str,
    force_condition: ForceCondition,
    fail_config: Option<FailConfiguration>,
    save_non_checkpoint_steps: bool,
) -> Result<Option<u64>, EmulatorError> {
    let program_def = ProgramDefinition::from_config(program_definition_file)?;
    let (result, last_step, last_hash) = program_def.get_execution_result(
        input.clone(),
        checkpoint_path,
        fail_config,
        save_non_checkpoint_steps,
    )?;

    let input_is_valid = result == ExecutionResult::Halt(0, last_step);
    let same_step_and_hash = last_step == claim_last_step && last_hash == claim_last_hash;

    let should_challenge = force_condition == ForceCondition::Always
        || !input_is_valid
        || (force_condition == ForceCondition::ValidInputWrongStepOrHash && !same_step_and_hash)
        || (force_condition == ForceCondition::ValidInputStepAndHash && same_step_and_hash);

    if !should_challenge {
        if same_step_and_hash {
            info!("The program executed successfully with the prover input");
            info!("Do not challenge.");
        } else {
            warn!("The prover provided a valid input, but the last step or hash differs");
            warn!("Do not challenge (as the challenge is not guaranteed to be successful)");
            warn!("Report this case to be evaluated by the security team");
        }
        return Ok(None);
    }

    warn!("There is a discrepancy between the prover and verifier execution");
    warn!("This execution will be challenged");

    assert!(claim_last_step > 0 && last_step > 0);

    // we use the minimum agreed step (that is one before the disagreement)
    let step_to_challenge = claim_last_step.min(last_step) - 1;

    let challenge_log = VerifierChallengeLog::new(
        ExecutionLog::new(
            ExecutionResult::Halt(0, claim_last_step),
            claim_last_step,
            claim_last_hash.to_string(),
        ),
        ExecutionLog::new(result, last_step, last_hash.to_string()),
        input,
        step_to_challenge,
    );
    challenge_log.save(checkpoint_path)?;

    Ok(Some(step_to_challenge))
}

pub fn verifier_choose_segment(
    program_definition_file: &str,
    checkpoint_path: &str,
    round: u8,
    prover_last_hashes: Vec<String>,
    fail_config: Option<FailConfiguration>,
    nary_type: NArySearchType,
) -> Result<u32, EmulatorError> {
    let mut challenge_log = VerifierChallengeLog::load(checkpoint_path)?;
    let input = challenge_log.input.clone();

    let conflict_step = match nary_type {
        NArySearchType::ConflictStep => None,
        _ => Some(challenge_log.conflict_step_log.step_to_challenge),
    };

    let nary_log = challenge_log.get_nary_log(nary_type);
    let program_def = ProgramDefinition::from_config(program_definition_file)?;

    let hashes = program_def.get_round_hashes(
        checkpoint_path,
        input,
        round,
        nary_log.base_step,
        fail_config,
    )?;

    let claim_hashes = ExecutionHashes::from_hexstr(&prover_last_hashes);
    let my_hashes = ExecutionHashes::from_hexstr(&hashes);

    let (bits, base, new_selected) = choose_segment(
        &program_def.nary_def(),
        nary_log.base_step,
        nary_log.step_to_challenge,
        round,
        &claim_hashes,
        &my_hashes,
        nary_type,
        conflict_step,
    );
    nary_log.base_step = base;
    nary_log.step_to_challenge = new_selected;
    nary_log.verifier_decisions.push(bits);
    nary_log.prover_hash_rounds.push(prover_last_hashes);
    nary_log.verifier_hash_rounds.push(hashes);
    challenge_log.save(checkpoint_path)?;

    info!("Verifier selects bits: {bits} base: {base} selection: {new_selected}");

    Ok(bits)
}

pub fn prover_final_trace(
    program_definition_file: &str,
    checkpoint_path: &str,
    final_bits: u32,
    fail_config: Option<FailConfiguration>,
) -> Result<(TraceRWStep, String, String, u64), EmulatorError> {
    let mut challenge_log = ProverChallengeLog::load(checkpoint_path)?;
    let input = challenge_log.input.clone();
    let nary_log = challenge_log.get_nary_log(NArySearchType::ConflictStep);

    let program_def = ProgramDefinition::from_config(program_definition_file)?;
    let nary_def = program_def.nary_def();

    let total_rounds = nary_def.total_rounds();
    let final_step = nary_def.step_from_base_and_bits(total_rounds, nary_log.base_step, final_bits);

    nary_log.base_step = final_step;
    nary_log.verifier_decisions.push(final_bits - 1);

    info!("The prover needs to provide the full trace for the selected step {final_step}");
    let final_trace =
        program_def.get_trace_step(checkpoint_path, input, final_step, fail_config.clone())?;
    nary_log.final_trace = final_trace.clone();
    challenge_log.save(checkpoint_path)?;

    let (step_hash, next_hash, conflict_step) = prover_get_hashes_and_step(
        program_definition_file,
        checkpoint_path,
        NArySearchType::ConflictStep,
        None,
        fail_config,
    )?;

    Ok((final_trace, step_hash, next_hash, conflict_step))
}

pub fn prover_get_hashes_and_step(
    program_definition_file: &str,
    checkpoint_path: &str,
    nary_type: NArySearchType,
    final_bits: Option<u32>,
    fail_config: Option<FailConfiguration>,
) -> Result<(String, String, u64), EmulatorError> {
    let mut challenge_log = ProverChallengeLog::load(checkpoint_path)?;
    let nary_log = challenge_log.get_nary_log(nary_type);

    let program_def = ProgramDefinition::from_config(program_definition_file)?;
    let nary_def = program_def.nary_def();

    let total_rounds = nary_def.total_rounds();

    let final_step = match nary_type {
        NArySearchType::ConflictStep => nary_log.base_step - 1,
        _ => {
            let final_bits = final_bits.unwrap();
            nary_log.verifier_decisions.push(final_bits);
            nary_def.step_from_base_and_bits(total_rounds, nary_log.base_step, final_bits)
        }
    };

    let (mut step_hash, mut next_hash) = get_hashes(
        &nary_def.step_mapping(&nary_log.verifier_decisions),
        &nary_log.hash_rounds,
        final_step,
    );

    if let Some(step) = fail_config.unwrap_or_default().fail_resign_hash {
        if step == final_step {
            step_hash = next_hash.clone();
        } else if step == final_step + 1 {
            next_hash = step_hash.clone();
        }
    }

    Ok((step_hash, next_hash, final_step))
}

pub fn get_hashes(
    mapping: &HashMap<u64, (u8, u8)>,
    hashes: &Vec<Vec<String>>,
    challenge_step: u64,
) -> (String, String) {
    let next_step = challenge_step + 1;

    if challenge_step == 0 {
        let next_access = mapping.get(&next_step).unwrap();
        let claim_next_hash = hashes[next_access.0 as usize - 1][next_access.1 as usize].clone();
        return (
            hashvec_to_string(generate_initial_step_hash()),
            claim_next_hash,
        );
    }

    let step_access = mapping.get(&challenge_step).unwrap();
    let next_access = mapping.get(&next_step).unwrap();

    let claim_hash = hashes[step_access.0 as usize - 1][step_access.1 as usize].clone();
    let claim_next_hash = hashes[next_access.0 as usize - 1][next_access.1 as usize].clone();
    (claim_hash, claim_next_hash)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, EnumString, Display, EnumIter)]
#[strum(serialize_all = "snake_case")]
pub enum ForceChallenge {
    EquivocationHash,
    EquivocationResign(EquivocationKind),
    CorrectHash,
    TraceHash,
    TraceHashZero,
    EntryPoint,
    ProgramCounter,
    Opcode,
    InputData,
    InitializedData,
    UninitializedData,
    AddressesSections,
    FutureRead,
    ReadValueNArySearch,
    ReadValue,
    No,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, EnumString, Display, EnumIter)]
#[strum(serialize_all = "snake_case")]
pub enum ForceCondition {
    ValidInputStepAndHash,
    ValidInputWrongStepOrHash,
    Always,
    No,
}

fn find_chunk_index(chunks: &[Chunk], address: u32) -> Option<usize> {
    chunks.iter().position(|Chunk { base_addr, data }| {
        let chunk_size = data.len();
        *base_addr <= address && address < *base_addr + chunk_size as u32 * 4
    })
}

pub fn verifier_choose_challenge(
    program_definition_file: &str,
    checkpoint_path: &str,
    trace: TraceRWStep,
    resigned_step_hash: &str,
    resigned_next_hash: &str,
    force: ForceChallenge,
    fail_config: Option<FailConfiguration>,
    return_script_parameters: bool,
) -> Result<ChallengeType, EmulatorError> {
    let program_def = ProgramDefinition::from_config(program_definition_file)?;
    let mut program = program_def.load_program()?;
    let nary_def = program_def.nary_def();

    let mut verifier_log = VerifierChallengeLog::load(checkpoint_path)?;
    let conflict_step_log = &mut verifier_log.conflict_step_log;
    conflict_step_log.final_trace = trace.clone();

    program.load_input(
        verifier_log.input.clone(),
        &program_def.input_section_name,
        false,
    )?;

    let mapping = &nary_def.step_mapping(&conflict_step_log.verifier_decisions);
    let step = conflict_step_log.step_to_challenge;

    let (prover_step_hash, prover_next_hash) =
        get_hashes(mapping, &conflict_step_log.prover_hash_rounds, step);

    let nary = return_script_parameters.then_some(nary_def.nary);
    let nary_last_round = return_script_parameters.then_some(nary_def.nary_last_round);
    let rounds = return_script_parameters.then_some(nary_def.total_rounds());

    if (prover_step_hash != resigned_step_hash && force == ForceChallenge::No)
        || force == ForceChallenge::EquivocationResign(EquivocationKind::StepHash)
    {
        let (round, index) = *mapping.get(&step).unwrap();

        return Ok(ChallengeType::EquivocationResign {
            prover_true_hash: prover_step_hash,
            prover_wrong_hash: resigned_step_hash.to_string(),
            prover_challenge_step_tk: step,
            kind: EquivocationKind::StepHash,
            expected_round: round,
            expected_index: index + 1,
            nary,
            nary_last_round,
            rounds,
        });
    }

    if (prover_next_hash != resigned_next_hash && force == ForceChallenge::No)
        || force == ForceChallenge::EquivocationResign(EquivocationKind::NextHash)
    {
        let (round, index) = *mapping.get(&(step + 1)).unwrap();
        return Ok(ChallengeType::EquivocationResign {
            prover_true_hash: prover_next_hash,
            prover_wrong_hash: resigned_next_hash.to_string(),
            prover_challenge_step_tk: step,
            kind: EquivocationKind::NextHash,
            expected_round: round,
            expected_index: index + 1,
            nary,
            nary_last_round,
            rounds,
        });
    }

    // check trace_hash
    if (!validate_step_hash(&prover_step_hash, &trace.trace_step, &prover_next_hash)
        && force == ForceChallenge::No)
        || force == ForceChallenge::TraceHash
        || force == ForceChallenge::TraceHashZero
    {
        if trace.step_number == 1 {
            info!("Verifier choose to challenge TRACE_HASH_ZERO");
            return Ok(ChallengeType::TraceHashZero {
                prover_trace: trace.trace_step,
                prover_next_hash,
                prover_conflict_step_tk: step,
            });
        }

        info!("Verifier choose to challenge TRACE_HASH");
        return Ok(ChallengeType::TraceHash {
            prover_step_hash,
            prover_trace: trace.trace_step,
            prover_next_hash,
        });
    }

    let mut steps = vec![step, step + 1];
    let mut my_trace_idx = 1;
    if step > 0 {
        steps.insert(0, step - 1);
        my_trace_idx += 1;
    }

    //obtain all the steps needed
    let my_execution = program_def
        .execute_helper(
            checkpoint_path,
            verifier_log.input.clone(),
            Some(steps),
            fail_config,
            false,
        )?
        .1;
    info!("execution: {:?}", my_execution);
    let my_trace = my_execution[my_trace_idx].0.clone();

    // TODO: limit exception

    let read_write_sections = program.read_write_sections.clone();
    let read_only_sections = program.read_only_sections.clone();
    let register_sections = program.register_sections.clone();
    let code_sections = program.code_sections.clone();

    let prover_read_1 = trace.read_1;
    let prover_read_2 = trace.read_2;

    let is_valid_read_1 =
        program.is_valid_mem(trace.mem_witness.read_1(), prover_read_1.address, true);
    let is_valid_read_2 =
        program.is_valid_mem(trace.mem_witness.read_2(), prover_read_2.address, true);

    let is_valid_write = program.is_valid_mem(
        trace.mem_witness.write(),
        trace.trace_step.write_1.address,
        false,
    );

    let is_valid_pc = program.address_in_sections(trace.read_pc.pc.get_address(), &code_sections);

    if (!(is_valid_read_1 && is_valid_read_2 && is_valid_write && is_valid_pc)
        && force == ForceChallenge::No)
        || force == ForceChallenge::AddressesSections
    {
        info!("Verifier choose to challenge invalid ADDRESS_SECTION");
        return Ok(ChallengeType::AddressesSections {
            prover_read_1,
            prover_read_2,
            prover_write: trace.trace_step.write_1,
            prover_witness: trace.mem_witness,
            prover_pc: trace.read_pc.pc,
            read_write_sections: return_script_parameters.then_some(read_write_sections),
            read_only_sections: return_script_parameters.then_some(read_only_sections),
            register_sections: return_script_parameters.then_some(register_sections),
            code_sections: return_script_parameters.then_some(code_sections),
        });
    }

    // check entrypoint
    if (trace.read_pc.pc.get_address() != my_trace.read_pc.pc.get_address()
        && force == ForceChallenge::No)
        || (trace.read_pc.pc.get_micro() != my_trace.read_pc.pc.get_micro()
            && force == ForceChallenge::No)
        || force == ForceChallenge::EntryPoint
        || force == ForceChallenge::ProgramCounter
    {
        if trace.step_number == 1 {
            info!("Verifier choose to challenge ENTRYPOINT");
            return Ok(ChallengeType::EntryPoint {
                prover_read_pc: trace.read_pc,
                prover_trace_step: trace.step_number,
                real_entry_point: return_script_parameters.then_some(program.pc.get_address()), //this parameter is only used for the test
            });
        } else {
            info!("Verifier choose to challenge PROGRAM_COUNTER");
            let pre_hash = my_execution[0].1.clone();
            let pre_step = my_execution[1].0.clone();

            return Ok(ChallengeType::ProgramCounter {
                pre_hash,
                trace: pre_step.trace_step,
                prover_step_hash,
                prover_pc_read: trace.read_pc,
            });
        }
    }

    if trace.read_pc.opcode != my_trace.read_pc.opcode && force == ForceChallenge::No
        || force == ForceChallenge::Opcode
    {
        info!("Verifier choose to challenge invalid OPCODE");
        let pc = trace.read_pc.pc.get_address();
        let code_chunks = program.get_code_chunks(CHUNK_SIZE);
        let chunk_index = find_chunk_index(&code_chunks, pc).unwrap() as u32;

        return Ok(ChallengeType::Opcode {
            prover_pc_read: trace.read_pc,
            chunk_index,
            chunk: return_script_parameters.then_some(code_chunks[chunk_index as usize].clone()),
        });
    }

    let prover_read_step_1 = prover_read_1.last_step;
    let prover_read_step_2 = prover_read_2.last_step;

    let is_read_1_future = prover_read_step_1 > step && prover_read_step_1 != LAST_STEP_INIT;
    let is_read_2_future = prover_read_step_2 > step && prover_read_step_2 != LAST_STEP_INIT;

    if ((is_read_1_future || is_read_2_future) && force == ForceChallenge::No)
        || force == ForceChallenge::FutureRead
    {
        let read_selector = if is_read_1_future { 1 } else { 2 };

        return Ok(ChallengeType::FutureRead {
            prover_conflict_step_tk: step,
            prover_read_step_1,
            prover_read_step_2,
            read_selector,
        });
    }

    // check const read value
    let is_read_1_conflict = prover_read_1.value != my_trace.read_1.value;
    let is_read_2_conflict = prover_read_2.value != my_trace.read_2.value;

    if ((is_read_1_conflict || is_read_2_conflict) && force == ForceChallenge::No)
        || force == ForceChallenge::InputData
        || force == ForceChallenge::InitializedData
        || force == ForceChallenge::UninitializedData
        || force == ForceChallenge::ReadValueNArySearch
    {
        let (conflict_read, my_conflict_read, read_selector) = if is_read_1_conflict {
            (prover_read_1.clone(), my_trace.read_1.clone(), 1)
        } else {
            (prover_read_2.clone(), my_trace.read_2.clone(), 2)
        };

        let conflict_address = conflict_read.address;
        let conflict_last_step = conflict_read.last_step;
        let my_conflict_last_step = my_conflict_read.last_step;

        let section_idx = program.find_section_idx(conflict_address)?;
        let section = program.sections.get(section_idx).unwrap();

        if (conflict_last_step == LAST_STEP_INIT
            && my_conflict_last_step == LAST_STEP_INIT
            && force == ForceChallenge::No)
            || force == ForceChallenge::InputData
            || force == ForceChallenge::InitializedData
            || force == ForceChallenge::UninitializedData
        {
            let input_size = program_def
                .inputs
                .iter()
                .fold(0, |acc, input| acc + input.size);

            if (section.name == program_def.input_section_name
                && conflict_address < section.start + input_size as u32
                && force == ForceChallenge::No)
                || force == ForceChallenge::InputData
            {
                info!("Verifier choose to challenge invalid INPUT DATA");
                let value = program.read_mem(conflict_address, false)?;

                return Ok(ChallengeType::InputData {
                    prover_read_1: prover_read_1,
                    prover_read_2: prover_read_2,
                    address: conflict_address,
                    input_for_address: value,
                });
            } else if (section.initialized && force == ForceChallenge::No)
                || force == ForceChallenge::InitializedData
            {
                info!("Verifier choose to challenge invalid INITIALIZED DATA");
                let initialized_chunks = program.get_initialized_chunks(CHUNK_SIZE);
                let chunk_index =
                    find_chunk_index(&initialized_chunks, conflict_address).unwrap() as u32;

                return Ok(ChallengeType::InitializedData {
                    prover_read_1,
                    prover_read_2,
                    read_selector,
                    chunk_index,
                    chunk: return_script_parameters
                        .then_some(initialized_chunks[chunk_index as usize].clone()),
                });
            } else if (!section.initialized && force == ForceChallenge::No)
                || force == ForceChallenge::UninitializedData
            {
                info!("Verifier choose to challenge invalid UNINITIALIZED DATA");
                let uninitilized_sections = program.get_uninitialized_ranges(&program_def);

                return Ok(ChallengeType::UninitializedData {
                    prover_read_1,
                    prover_read_2,
                    read_selector,
                    sections: return_script_parameters.then_some(uninitilized_sections),
                });
            }
        } else {
            let step_to_challenge = if conflict_last_step == LAST_STEP_INIT {
                my_conflict_last_step
            } else if my_conflict_last_step == LAST_STEP_INIT {
                conflict_last_step
            } else {
                conflict_last_step.max(my_conflict_last_step)
            };

            let bits = nary_def.step_bits_for_round(1, step_to_challenge - 1);

            let read_challenge_log = &mut verifier_log.read_challenge_log;
            read_challenge_log.step_to_challenge = step_to_challenge - 1;
            read_challenge_log.base_step = nary_def.step_from_base_and_bits(1, 0, bits);
            read_challenge_log.verifier_decisions.push(bits);

            read_challenge_log
                .prover_hash_rounds
                .push(conflict_step_log.prover_hash_rounds[0].clone());

            read_challenge_log
                .verifier_hash_rounds
                .push(conflict_step_log.verifier_hash_rounds[0].clone());

            verifier_log.read_step = step_to_challenge - 1;
            verifier_log.read_selector = read_selector;
            verifier_log.save(checkpoint_path)?;

            return Ok(ChallengeType::ReadValueNArySearch { bits });
        }
    }
    verifier_log.save(checkpoint_path)?;
    Ok(ChallengeType::No)
}

pub fn verifier_choose_challenge_for_read_challenge(
    program_definition_file: &str,
    checkpoint_path: &str,
    resigned_step_hash: &str,
    resigned_next_hash: &str,
    fail_config: Option<FailConfiguration>,
    force: ForceChallenge,
    return_script_parameters: bool,
) -> Result<ChallengeType, EmulatorError> {
    let program_def = ProgramDefinition::from_config(program_definition_file)?;
    let nary_def = program_def.nary_def();
    let verifier_log = VerifierChallengeLog::load(checkpoint_path)?;

    let read_challenge_log = verifier_log.read_challenge_log;
    let conflict_step_log = verifier_log.conflict_step_log;
    let conflict_step = conflict_step_log.step_to_challenge;
    let challenge_step = read_challenge_log.step_to_challenge;

    let mapping = &nary_def.step_mapping(&read_challenge_log.verifier_decisions);
    let (prover_step_hash, prover_next_hash) = get_hashes(
        mapping,
        &read_challenge_log.prover_hash_rounds,
        challenge_step,
    );

    let (my_step_hash, _) = get_hashes(
        mapping,
        &read_challenge_log.verifier_hash_rounds,
        challenge_step,
    );

    let nary = return_script_parameters.then_some(nary_def.nary);
    let nary_last_round = return_script_parameters.then_some(nary_def.nary_last_round);
    let rounds = return_script_parameters.then_some(nary_def.total_rounds());

    if (prover_step_hash != resigned_step_hash && force == ForceChallenge::No)
        || force == ForceChallenge::EquivocationResign(EquivocationKind::StepHash)
    {
        let (round, index) = *mapping.get(&challenge_step).unwrap();

        return Ok(ChallengeType::EquivocationResign {
            prover_true_hash: prover_step_hash,
            prover_wrong_hash: resigned_step_hash.to_string(),
            prover_challenge_step_tk: challenge_step,
            kind: EquivocationKind::StepHash,
            expected_round: round,
            expected_index: index + 1,
            nary,
            nary_last_round,
            rounds,
        });
    }

    if (prover_next_hash != resigned_next_hash && force == ForceChallenge::No)
        || force == ForceChallenge::EquivocationResign(EquivocationKind::NextHash)
    {
        let (round, index) = *mapping.get(&(challenge_step + 1)).unwrap();
        return Ok(ChallengeType::EquivocationResign {
            prover_true_hash: prover_next_hash,
            prover_wrong_hash: resigned_next_hash.to_string(),
            prover_challenge_step_tk: challenge_step,
            kind: EquivocationKind::NextHash,
            expected_round: round,
            expected_index: index + 1,
            nary,
            nary_last_round,
            rounds,
        });
    }

    if (prover_step_hash != my_step_hash
        && conflict_step == challenge_step
        && force == ForceChallenge::No)
        || force == ForceChallenge::EquivocationHash
    {
        let mapping = &nary_def.step_mapping(&conflict_step_log.verifier_decisions);
        let (prover_step_hash1, _) = get_hashes(
            mapping,
            &conflict_step_log.prover_hash_rounds,
            challenge_step,
        );

        return Ok(ChallengeType::EquivocationHash {
            prover_step_hash1,
            prover_step_hash2: prover_step_hash,
            prover_write_step_tk: challenge_step,
            prover_conflict_step_tk: conflict_step_log.step_to_challenge,
        });
    }

    let my_execution = program_def
        .execute_helper(
            checkpoint_path,
            verifier_log.input.clone(),
            Some(vec![challenge_step + 1]),
            fail_config,
            false,
        )?
        .1;
    info!("execution: {:?}", my_execution);
    let my_trace = my_execution[0].0.clone();

    if (prover_step_hash != my_step_hash && force == ForceChallenge::No)
        || force == ForceChallenge::CorrectHash
    {
        return Ok(ChallengeType::CorrectHash {
            prover_step_hash,
            verifier_hash: my_step_hash,
            trace: my_trace.trace_step,
            prover_next_hash,
        });
    }

    let read_step = verifier_log.read_step;
    if (read_step == challenge_step && force == ForceChallenge::No)
        || force == ForceChallenge::ReadValue
    {
        let conflict_step_trace = conflict_step_log.final_trace;
        let prover_read_1 = conflict_step_trace.read_1;
        let prover_read_2 = conflict_step_trace.read_2;
        let read_selector = verifier_log.read_selector;

        return Ok(ChallengeType::ReadValue {
            prover_read_1,
            prover_read_2,
            read_selector,
            prover_hash: prover_step_hash,
            trace: my_trace.trace_step,
            prover_next_hash,
            prover_write_step_tk: challenge_step,
            prover_conflict_step_tk: conflict_step_log.step_to_challenge,
        });
    }

    Ok(ChallengeType::No)
}
/*
  TEST CASES
  ----------

  - prover can't provide last step equal to MAX_LAST_STEP (should be enforced in the script)
  - prover provides a last step that is > than the verifier last step
  - prover provides a last step that is = to the verifier last step
  - prover provides a last step that is < to the verifier last step

  - acording to the verifier there is no halt(0) at min(prover_last_step, verifier_last_step)
  - if both agrees on both hashes, then the verifier lies about the halt and will not succeed the execute

  - if prover lies about the result and prover_last_step is executed:
    - it will not succeed if it's halt(!0)
    - it will succeed if it's halt(0) (or other opcode)
        - this happens if the discrepancy in the hash if < than verifier_last_step
        - or prover lies with the trace_hash

    - if  hash(hash_prev|trace_write) != hash =>  challenge: trace_hash (does not matter if values agrees with the verifier)
        - if step is 1, challenge: trace_hash_special_case (initial hash is hardcoded)

    - if trace_step == prover_final_step and it is not a halt(0) => challenge: halt

    - if step == 1 and PC != entrypoint => challenge: entrypoint

    - if step > 1 and PC != MY_PC => challenge: program_counter

    - if execution succeeds:

        - my result at that step is crash => challenge memory section access

        - the opcode/pc is right: trace_write is different
            - challenge: memory_read (TBD)

    // check reads:
    // -- common data should be added to a rom section
    // -- address is asserted by the execution challenge (FUZZ fail_read (1 and 2) addresses and check if it fails on execution )
    // -- if value is different:
    //    -- if address in input section or rom section
    //          -- if last_step == initial => challenge equivocation
    //          -- if last_step != initial => should be segfault
    //    -- if address in ram section
    //          -- if last_step == initial => challenge equivocation (default initialization zero)
    //          -- if last_step != initial => memory_challenge search
    //              -- if last_step > current_step => equivocation (if can't be avoided directly)
    //              -- else
    //                 -- as we agree on prev_hash
    //                      -- search max(last_step, my_last_step)
    //                      -- find if the trace_hash is broken given a trace_step and challenge the hash
    //                      -- if the hashes are ok check:
    //                          -- verifier can generate a valid hash AND
    //                             -- if last_step = my_last_step
    //                                -- prover_read_value != verifier_written_value  (it lied about the value)
    //                          -- if last_step < my_last_step
    //                                -- verifier shows that address is written in that step
    //                                -- prover_read_add == verifier_written_add ( so it lied about last step the add was written)
    //                          -- if last_step > my_last_step
    //                                -- verifier shows that address is not written in that step
    //                                -- prover_read_add != verifier_written_add ( so it lied about last step the add was written)

*/

#[cfg(test)]
mod tests {
    use bitcoin_script_riscv::riscv::challenges::execute_challenge;
    use bitvmx_cpu_definitions::{
        memory::{MemoryAccessType, MemoryWitness},
        trace::{ProgramCounter, TraceRead, TraceReadPC, TraceStep, TraceWrite},
    };
    use tracing::Level;

    use crate::{
        constants::REGISTERS_BASE_ADDRESS,
        decision::challenge::*,
        executor::{
            utils::{FailExecute, FailOpcode, FailReads, FailWrite},
            verifier::verify_script,
        },
        loader::program_definition::ProgramDefinition,
    };

    use std::sync::Once;

    static INIT: Once = Once::new();

    fn init_trace() {
        INIT.call_once(|| {
            init_trace_aux();
        });
    }

    fn init_trace_aux() {
        tracing_subscriber::fmt()
            .without_time()
            .with_target(false)
            .with_max_level(Level::INFO)
            .init();
    }

    fn test_challenge_aux(
        id: &str,
        pdf: &str,
        input: u8,
        execute_err: bool,
        fail_config_prover: Option<FailConfiguration>,
        fail_config_prover_read_challenge: Option<FailConfiguration>,
        fail_config_verifier: Option<FailConfiguration>,
        fail_config_verifier_read_challenge: Option<FailConfiguration>,
        challenge_ok: bool,
        force_condition: ForceCondition,
        force: ForceChallenge,
        force_read_challenge: ForceChallenge,
    ) {
        let pdf = &format!("../docker-riscv32/riscv32/build/{}", pdf);
        let input = vec![17, 17, 17, input];
        let program_def = ProgramDefinition::from_config(pdf).unwrap();
        let nary_def = program_def.nary_def();

        let chk_prover_path = &format!("../temp-runs/challenge/{}/prover/", id);
        let chk_verifier_path = &format!("../temp-runs/challenge/{}/verifier/", id);

        // PROVER EXECUTES
        let result_1 = prover_execute(
            pdf,
            input.clone(),
            chk_prover_path,
            true,
            fail_config_prover.clone(),
            false,
        )
        .unwrap();
        info!("{:?}", result_1);

        // VERIFIER DECIDES TO CHALLENGE
        let result = verifier_check_execution(
            pdf,
            input,
            chk_verifier_path,
            result_1.1,
            &result_1.2,
            force_condition,
            fail_config_verifier.clone(),
            false,
        )
        .unwrap();
        info!("{:?}", result);

        let mut v_decision = 0;

        //MULTIPLE ROUNDS N-ARY SEARCH
        for round in 1..nary_def.total_rounds() + 1 {
            let hashes = prover_get_hashes_for_round(
                pdf,
                chk_prover_path,
                round,
                v_decision,
                fail_config_prover.clone(),
                NArySearchType::ConflictStep,
            )
            .unwrap();
            info!("{:?}", &hashes);

            v_decision = verifier_choose_segment(
                pdf,
                chk_verifier_path,
                round,
                hashes,
                fail_config_verifier.clone(),
                NArySearchType::ConflictStep,
            )
            .unwrap();
            info!("{:?}", v_decision);
        }

        //TODO: Add translation keys

        //PROVER PROVIDES EXECUTE STEP (and reveals full_trace)
        //Use v_desision + 1 as v_decision defines the last agreed step
        let (final_trace, step_hash, next_hash, _) =
            prover_final_trace(pdf, chk_prover_path, v_decision + 1, fail_config_prover).unwrap();
        info!("Prover final trace: {:?}", final_trace.to_csv());

        let result = verify_script(&final_trace, REGISTERS_BASE_ADDRESS, &None);
        info!("Validation result: {:?}", result);

        if execute_err {
            assert!(result.is_err());
            //once execution fails there is no need to execute more steps
            return;
        } else {
            assert!(result.is_ok());
        }

        let challenge = verifier_choose_challenge(
            pdf,
            chk_verifier_path,
            final_trace,
            step_hash.as_str(),
            next_hash.as_str(),
            force,
            fail_config_verifier,
            true,
        )
        .unwrap();

        let challenge = match &challenge {
            ChallengeType::ReadValueNArySearch { bits } => {
                let mut v_decision = *bits;
                for round in 2..nary_def.total_rounds() + 1 {
                    let hashes = prover_get_hashes_for_round(
                        pdf,
                        chk_prover_path,
                        round,
                        v_decision,
                        fail_config_prover_read_challenge.clone(),
                        NArySearchType::ReadValueChallenge,
                    )
                    .unwrap();
                    info!("{:?}", &hashes);

                    v_decision = verifier_choose_segment(
                        pdf,
                        chk_verifier_path,
                        round,
                        hashes,
                        fail_config_verifier_read_challenge.clone(),
                        NArySearchType::ReadValueChallenge,
                    )
                    .unwrap();
                    info!("{:?}", v_decision);
                }

                let (resigned_step_hash, resigned_next_hash, _) = prover_get_hashes_and_step(
                    pdf,
                    &chk_prover_path,
                    NArySearchType::ReadValueChallenge,
                    Some(v_decision),
                    fail_config_prover_read_challenge,
                )
                .unwrap();

                verifier_choose_challenge_for_read_challenge(
                    pdf,
                    chk_verifier_path,
                    resigned_step_hash.as_str(),
                    resigned_next_hash.as_str(),
                    fail_config_verifier_read_challenge,
                    force_read_challenge,
                    true,
                )
                .unwrap()
            }
            _ => challenge,
        };

        let result = execute_challenge(&challenge);
        info!("Challenge: {:?} result: {}", challenge, result);
        assert_eq!(result, challenge_ok);
    }

    #[test]
    fn test_challenge_execution() {
        init_trace();
        //bad input: exepct execute step to fail
        test_challenge_aux(
            "1",
            "hello-world.yaml",
            0,
            true,
            None,
            None,
            None,
            None,
            false,
            ForceCondition::No,
            ForceChallenge::No,
            ForceChallenge::No,
        );
        //good input: expect execute step to succeed
        test_challenge_aux(
            "2",
            "hello-world.yaml",
            17,
            false,
            None,
            None,
            None,
            None,
            false,
            ForceCondition::ValidInputStepAndHash,
            ForceChallenge::No,
            ForceChallenge::No,
        );
    }

    #[test]
    fn test_challenge_trace_hash() {
        init_trace();
        //invalid hash: expect trace hash to fail
        let fail_hash = Some(FailConfiguration::new_fail_hash(100));
        test_challenge_aux(
            "3",
            "hello-world.yaml",
            17,
            false,
            fail_hash.clone(),
            None,
            None,
            None,
            true,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::No,
            ForceChallenge::No,
        );
        test_challenge_aux(
            "4",
            "hello-world.yaml",
            17,
            false,
            None,
            None,
            fail_hash,
            None,
            false,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::TraceHash,
            ForceChallenge::No,
        );
    }

    #[test]
    fn test_challenge_trace_hash_zero() {
        init_trace();
        // support for trace hash where the agreed step hash is zero
        let fail_hash = Some(FailConfiguration::new_fail_hash(1));
        test_challenge_aux(
            "5",
            "hello-world.yaml",
            17,
            false,
            fail_hash.clone(),
            None,
            None,
            None,
            true,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::No,
            ForceChallenge::No,
        );
        test_challenge_aux(
            "6",
            "hello-world.yaml",
            17,
            false,
            None,
            None,
            fail_hash,
            None,
            false,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::TraceHashZero,
            ForceChallenge::No,
        );
    }

    #[test]
    fn test_challenge_entrypoint() {
        init_trace();
        let fail_entrypoint = Some(FailConfiguration::new_fail_pc(0));
        test_challenge_aux(
            "7",
            "hello-world.yaml",
            17,
            false,
            fail_entrypoint.clone(),
            None,
            None,
            None,
            true,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::No,
            ForceChallenge::No,
        );
        test_challenge_aux(
            "8",
            "hello-world.yaml",
            17,
            false,
            None,
            None,
            fail_entrypoint,
            None,
            false,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::EntryPoint,
            ForceChallenge::No,
        );
    }

    #[test]
    fn test_challenge_program_counter() {
        init_trace();
        let fail_pc = Some(FailConfiguration::new_fail_pc(1));
        test_challenge_aux(
            "9",
            "hello-world.yaml",
            17,
            false,
            fail_pc.clone(),
            None,
            None,
            None,
            true,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::No,
            ForceChallenge::No,
        );
        test_challenge_aux(
            "10",
            "hello-world.yaml",
            17,
            false,
            None,
            None,
            fail_pc,
            None,
            false,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::ProgramCounter,
            ForceChallenge::No,
        );
    }

    #[test]
    fn test_challenge_input() {
        init_trace();
        let fail_args = vec![
            "1106",
            "0xaa000000",
            "0x11111100",
            "0xaa000000",
            "0xffffffffffffffff",
        ]
        .iter()
        .map(|x| x.to_string())
        .collect::<Vec<String>>();
        let fail_read_2 = Some(FailConfiguration::new_fail_reads(FailReads::new(
            None,
            Some(&fail_args),
        )));
        test_challenge_aux(
            "11",
            "hello-world.yaml",
            17,
            false,
            fail_read_2.clone(),
            None,
            None,
            None,
            true,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::No,
            ForceChallenge::No,
        );

        test_challenge_aux(
            "12",
            "hello-world.yaml",
            17,
            false,
            None,
            None,
            fail_read_2,
            None,
            false,
            ForceCondition::No,
            ForceChallenge::InputData,
            ForceChallenge::No,
        );
    }

    #[test]
    fn test_challenge_read_invalid() {
        init_trace();

        let fail_execute = FailExecute {
            step: 9,
            fake_trace: TraceRWStep::new(
                9,
                TraceRead::new(4026531900, 0, 8),
                // reads from nullptr (address 0)
                TraceRead::new(0, 0, 0xffffffffffffffff),
                TraceReadPC::new(ProgramCounter::new(2147483672, 0), 501635),
                TraceStep::new(
                    TraceWrite::new(4026531900, 0),
                    ProgramCounter::new(2147483676, 0),
                ),
                None,
                MemoryWitness::new(
                    MemoryAccessType::Register,
                    MemoryAccessType::Memory,
                    MemoryAccessType::Register,
                ),
            ),
        };

        let fail_execute = Some(FailConfiguration::new_fail_execute(fail_execute));

        test_challenge_aux(
            "13",
            "read_invalid.yaml",
            0,
            false,
            fail_execute,
            None,
            None,
            None,
            true,
            ForceCondition::No,
            ForceChallenge::No,
            ForceChallenge::No,
        );

        let fail_args = vec![
            "1106",
            "0xaa000000",
            "0x11111100",
            "0x00000000",
            "0xffffffffffffffff",
        ]
        .iter()
        .map(|x| x.to_string())
        .collect::<Vec<String>>();
        let fail_read_2 = Some(FailConfiguration::new_fail_reads(FailReads::new(
            None,
            Some(&fail_args),
        )));

        test_challenge_aux(
            "14",
            "hello-world.yaml",
            17,
            false,
            None,
            None,
            fail_read_2,
            None,
            false,
            ForceCondition::No,
            ForceChallenge::AddressesSections,
            ForceChallenge::No,
        );
    }

    #[test]
    fn test_challenge_read_reg() {
        init_trace();

        let fail_execute = FailExecute {
            step: 10,
            fake_trace: TraceRWStep::new(
                10,
                TraceRead::new(4026531900, 4026531840, 9),
                // reads from register address but should be from memory
                TraceRead::new(4026531840, 0, 0xffffffffffffffff),
                TraceReadPC::new(ProgramCounter::new(2147483676, 0), 501635),
                TraceStep::new(
                    TraceWrite::new(4026531900, 0),
                    ProgramCounter::new(2147483680, 0),
                ),
                None,
                MemoryWitness::new(
                    MemoryAccessType::Register,
                    MemoryAccessType::Memory,
                    MemoryAccessType::Register,
                ),
            ),
        };

        let fail_execute = Some(FailConfiguration::new_fail_execute(fail_execute));

        test_challenge_aux(
            "15",
            "read_reg.yaml",
            0,
            false,
            fail_execute,
            None,
            None,
            None,
            true,
            ForceCondition::No,
            ForceChallenge::No,
            ForceChallenge::No,
        );

        let fail_args = vec![
            "1106",
            "0xaa000000",
            "0x11111100",
            "0xf0000004",
            "0xffffffffffffffff",
        ]
        .iter()
        .map(|x| x.to_string())
        .collect::<Vec<String>>();
        let fail_read_2 = Some(FailConfiguration::new_fail_reads(FailReads::new(
            None,
            Some(&fail_args),
        )));

        test_challenge_aux(
            "16",
            "hello-world.yaml",
            17,
            false,
            None,
            None,
            fail_read_2,
            None,
            false,
            ForceCondition::No,
            ForceChallenge::AddressesSections,
            ForceChallenge::No,
        );
    }

    #[test]
    fn test_challenge_write_invalid() {
        init_trace();

        let fail_execute = FailExecute {
            step: 10,
            fake_trace: TraceRWStep::new(
                10,
                TraceRead::new(4026531900, 0, 8),
                TraceRead::new(4026531896, 1234, 9),
                TraceReadPC::new(ProgramCounter::new(2147483676, 0), 15179811),
                // writes to nullptr (address 0)
                TraceStep::new(TraceWrite::new(0, 1234), ProgramCounter::new(2147483680, 0)),
                None,
                MemoryWitness::new(
                    MemoryAccessType::Register,
                    MemoryAccessType::Register,
                    MemoryAccessType::Memory,
                ),
            ),
        };

        let fail_execute = Some(FailConfiguration::new_fail_execute(fail_execute));

        test_challenge_aux(
            "17",
            "write_invalid.yaml",
            0,
            false,
            fail_execute,
            None,
            None,
            None,
            true,
            ForceCondition::No,
            ForceChallenge::No,
            ForceChallenge::No,
        );

        let fail_args = vec!["1106", "0xaa000000", "0x11111100", "0x00000000"]
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>();
        let fail_write = Some(FailConfiguration::new_fail_write(FailWrite::new(
            &fail_args,
        )));

        test_challenge_aux(
            "18",
            "hello-world.yaml",
            17,
            false,
            None,
            None,
            fail_write,
            None,
            false,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::AddressesSections,
            ForceChallenge::No,
        );
    }

    #[test]
    fn test_challenge_write_reg() {
        init_trace();

        let fail_execute = FailExecute {
            step: 11,
            fake_trace: TraceRWStep::new(
                11,
                TraceRead::new(4026531900, 4026531840, 9),
                TraceRead::new(4026531896, 1234, 10),
                TraceReadPC::new(ProgramCounter::new(2147483680, 0), 15179811),
                TraceStep::new(
                    // writes to register address but should be to memory
                    TraceWrite::new(4026531840, 1234),
                    ProgramCounter::new(2147483684, 0),
                ),
                None,
                MemoryWitness::new(
                    MemoryAccessType::Register,
                    MemoryAccessType::Register,
                    MemoryAccessType::Memory,
                ),
            ),
        };

        let fail_execute = Some(FailConfiguration::new_fail_execute(fail_execute));

        test_challenge_aux(
            "19",
            "write_reg.yaml",
            0,
            false,
            fail_execute,
            None,
            None,
            None,
            true,
            ForceCondition::No,
            ForceChallenge::No,
            ForceChallenge::No,
        );
        let fail_args = vec!["1106", "0xaa000000", "0x11111100", "0xf0000004"]
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>();
        let fail_write = Some(FailConfiguration::new_fail_write(FailWrite::new(
            &fail_args,
        )));

        test_challenge_aux(
            "20",
            "hello-world.yaml",
            17,
            false,
            None,
            None,
            fail_write,
            None,
            false,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::AddressesSections,
            ForceChallenge::No,
        );
    }

    #[test]
    fn test_challenge_write_protected() {
        init_trace();

        let fail_execute = FailExecute {
            step: 11,
            fake_trace: TraceRWStep::new(
                11,
                TraceRead::new(4026531900, 2147483648, 9),
                TraceRead::new(4026531896, 1234, 10),
                TraceReadPC::new(ProgramCounter::new(2147483680, 0), 15179811),
                TraceStep::new(
                    // writes to read only address
                    TraceWrite::new(2147483648, 1234),
                    ProgramCounter::new(2147483684, 0),
                ),
                None,
                MemoryWitness::new(
                    MemoryAccessType::Register,
                    MemoryAccessType::Register,
                    MemoryAccessType::Memory,
                ),
            ),
        };

        let fail_execute = Some(FailConfiguration::new_fail_execute(fail_execute));

        test_challenge_aux(
            "21",
            "write_protected.yaml",
            17,
            false,
            fail_execute,
            None,
            None,
            None,
            true,
            ForceCondition::No,
            ForceChallenge::No,
            ForceChallenge::No,
        );

        let fail_args = vec!["1106", "0xaa000000", "0x11111100", "0x80000000"]
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>();
        let fail_write = Some(FailConfiguration::new_fail_write(FailWrite::new(
            &fail_args,
        )));

        test_challenge_aux(
            "22",
            "hello-world.yaml",
            17,
            false,
            None,
            None,
            fail_write,
            None,
            false,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::AddressesSections,
            ForceChallenge::No,
        );
    }

    #[test]
    fn test_challenge_pc_invalid() {
        init_trace();

        let fail_execute = FailExecute {
            step: 9,
            fake_trace: TraceRWStep::new(
                9,
                TraceRead::new(4026531844, 2147483700, 2),
                TraceRead::default(),
                // ProgramCounter points to nullptr (address 0)
                TraceReadPC::new(ProgramCounter::new(0, 0), 32871), // Jalr
                TraceStep::new(TraceWrite::default(), ProgramCounter::new(2147483700, 0)),
                None,
                MemoryWitness::new(
                    MemoryAccessType::Register,
                    MemoryAccessType::Unused,
                    MemoryAccessType::Unused,
                ),
            ),
        };

        let fail_execute = Some(FailConfiguration::new_fail_execute(fail_execute));

        test_challenge_aux(
            "23",
            "pc_invalid.yaml",
            0,
            false,
            fail_execute.clone(),
            None,
            None,
            None,
            true,
            ForceCondition::No,
            ForceChallenge::No,
            ForceChallenge::No,
        );

        test_challenge_aux(
            "24",
            "hello-world.yaml",
            17,
            false,
            None,
            None,
            fail_execute,
            None,
            false,
            ForceCondition::No,
            ForceChallenge::AddressesSections,
            ForceChallenge::No,
        );
    }

    #[test]
    fn test_challenge_pc_reg() {
        init_trace();

        let fail_execute = FailExecute {
            step: 9,
            fake_trace: TraceRWStep::new(
                9,
                TraceRead::new(4026531844, 2147483700, 2),
                TraceRead::default(),
                // ProgramCounter points to register address
                TraceReadPC::new(ProgramCounter::new(4026531840, 0), 32871),
                TraceStep::new(TraceWrite::default(), ProgramCounter::new(2147483700, 0)),
                None,
                MemoryWitness::new(
                    MemoryAccessType::Register,
                    MemoryAccessType::Unused,
                    MemoryAccessType::Unused,
                ),
            ),
        };

        let fail_execute = Some(FailConfiguration::new_fail_execute(fail_execute));

        test_challenge_aux(
            "25",
            "pc_reg.yaml",
            0,
            false,
            fail_execute.clone(),
            None,
            None,
            None,
            true,
            ForceCondition::No,
            ForceChallenge::No,
            ForceChallenge::No,
        );

        test_challenge_aux(
            "26",
            "hello-world.yaml",
            17,
            false,
            None,
            None,
            fail_execute,
            None,
            false,
            ForceCondition::No,
            ForceChallenge::AddressesSections,
            ForceChallenge::No,
        );
    }

    #[test]
    fn test_challenge_opcode() {
        init_trace();

        let fail_args = vec!["2", "0x100073"] // Ebreak (NOP)
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>();
        let fail_opcode = Some(FailConfiguration::new_fail_opcode(FailOpcode::new(
            &fail_args,
        )));

        test_challenge_aux(
            "27",
            "hello-world.yaml",
            17,
            false,
            fail_opcode.clone(),
            None,
            None,
            None,
            true,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::No,
            ForceChallenge::No,
        );

        test_challenge_aux(
            "28",
            "hello-world.yaml",
            17,
            false,
            None,
            None,
            fail_opcode,
            None,
            false,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::Opcode,
            ForceChallenge::No,
        );
    }

    #[test]
    fn test_challenge_initialized() {
        init_trace();
        let fail_execute = FailExecute {
            step: 32,
            fake_trace: TraceRWStep::new(
                32,
                TraceRead::new(4026531900, 2952790016, 31),
                TraceRead::new(2952790016, 0, LAST_STEP_INIT), // read a different value from ROM
                TraceReadPC::new(ProgramCounter::new(2147483708, 0), 509699),
                TraceStep::new(
                    TraceWrite::new(4026531896, 0),
                    ProgramCounter::new(2147483712, 0),
                ),
                None,
                MemoryWitness::new(
                    MemoryAccessType::Register,
                    MemoryAccessType::Memory,
                    MemoryAccessType::Register,
                ),
            ),
        };

        let fail_execute = Some(FailConfiguration::new_fail_execute(fail_execute));

        test_challenge_aux(
            "29",
            "hello-world.yaml",
            17,
            false,
            fail_execute.clone(),
            None,
            None,
            None,
            true,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::No,
            ForceChallenge::No,
        );

        test_challenge_aux(
            "30",
            "hello-world.yaml",
            17,
            false,
            None,
            None,
            fail_execute,
            None,
            false,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::InitializedData,
            ForceChallenge::No,
        );
    }

    #[test]
    fn test_challenge_uninitialized() {
        init_trace();

        let fail_args = vec![
            "9",
            "0xa0001004",
            "0x11111100",
            "0xa0001004",
            "0xffffffffffffffff",
        ]
        .iter()
        .map(|x| x.to_string())
        .collect::<Vec<String>>();
        let fail_read_2 = Some(FailConfiguration::new_fail_reads(FailReads::new(
            None,
            Some(&fail_args),
        )));

        test_challenge_aux(
            "31",
            "hello-world-uninitialized.yaml",
            0,
            false,
            fail_read_2.clone(),
            None,
            None,
            None,
            true,
            ForceCondition::No,
            ForceChallenge::No,
            ForceChallenge::No,
        );

        test_challenge_aux(
            "32",
            "hello-world-uninitialized.yaml",
            17,
            false,
            None,
            None,
            fail_read_2,
            None,
            false,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::UninitializedData,
            ForceChallenge::No,
        );
    }

    #[test]
    fn test_challenge_modified_value_lies_all_hashes_from_write_step() {
        init_trace();
        let fail_read_args = vec!["1106", "0xaa000000", "0x11111100", "0xaa000000", "600"]
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>();

        let fail_read_2 = Some(FailConfiguration::new_fail_reads(FailReads::new(
            None,
            Some(&fail_read_args),
        )));

        let fail_write_args = vec!["600", "0xaa000000", "0x11111100", "0xaa000000"]
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>();
        let fail_write = Some(FailConfiguration::new_fail_write(FailWrite::new(
            &fail_write_args,
        )));

        test_challenge_aux(
            "35",
            "hello-world.yaml",
            17,
            false,
            fail_read_2.clone(),
            fail_write.clone(),
            None,
            None,
            true,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::No,
            ForceChallenge::No,
        );

        test_challenge_aux(
            "36",
            "hello-world.yaml",
            17,
            false,
            None,
            None,
            fail_read_2,
            fail_write,
            false,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::ReadValueNArySearch,
            ForceChallenge::CorrectHash,
        );
    }
    #[test]
    fn test_challenge_modified_value_lies_hashes_until_step() {
        init_trace();
        let fail_read_args = vec!["1106", "0xaa000000", "0x11111100", "0xaa000000", "600"]
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>();

        let fail_read_2 = Some(FailConfiguration::new_fail_reads(FailReads::new(
            None,
            Some(&fail_read_args),
        )));

        let fail_hash_until = Some(FailConfiguration::new_fail_hash_until(700));

        test_challenge_aux(
            "37",
            "hello-world.yaml",
            17,
            false,
            fail_read_2.clone(),
            fail_hash_until.clone(),
            None,
            None,
            true,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::No,
            ForceChallenge::No,
        );

        test_challenge_aux(
            "38",
            "hello-world.yaml",
            17,
            false,
            None,
            None,
            fail_read_2,
            fail_hash_until,
            false,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::ReadValueNArySearch,
            ForceChallenge::CorrectHash,
        );
    }

    #[test]
    fn test_challenge_read_different_address() {
        init_trace();
        let fail_read_args = vec!["1106", "0xaa000000", "0x11111100", "0xaa000000", "600"]
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>();

        let fail_read_2 = Some(FailConfiguration::new_fail_reads(FailReads::new(
            None,
            Some(&fail_read_args),
        )));

        test_challenge_aux(
            "39",
            "hello-world.yaml",
            17,
            false,
            fail_read_2.clone(),
            None,
            None,
            None,
            true,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::No,
            ForceChallenge::No,
        );

        test_challenge_aux(
            "40",
            "hello-world.yaml",
            17,
            false,
            None,
            None,
            fail_read_2,
            None,
            false,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::ReadValueNArySearch,
            ForceChallenge::ReadValue,
        );
    }

    #[test]
    fn test_challenge_read_different_value() {
        init_trace();
        let fail_read_args = vec!["1106", "0xf000003c", "0xaa000004", "0xf000003c", "1105"]
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>();

        let fail_read_1 = Some(FailConfiguration::new_fail_reads(FailReads::new(
            Some(&fail_read_args),
            None,
        )));

        test_challenge_aux(
            "41",
            "hello-world.yaml",
            17,
            false,
            fail_read_1.clone(),
            None,
            None,
            None,
            true,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::No,
            ForceChallenge::No,
        );

        test_challenge_aux(
            "42",
            "hello-world.yaml",
            17,
            false,
            None,
            None,
            fail_read_1,
            None,
            false,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::ReadValueNArySearch,
            ForceChallenge::ReadValue,
        );
    }

    #[test]
    fn test_challenge_future_read() {
        init_trace();
        let fail_read_args = vec!["1106", "0xf000003c", "0xaa000004", "0xf000003c", "1107"]
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>();

        let fail_read_1 = Some(FailConfiguration::new_fail_reads(FailReads::new(
            Some(&fail_read_args),
            None,
        )));

        test_challenge_aux(
            "43",
            "hello-world.yaml",
            17,
            false,
            fail_read_1.clone(),
            None,
            None,
            None,
            true,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::No,
            ForceChallenge::No,
        );

        test_challenge_aux(
            "44",
            "hello-world.yaml",
            17,
            false,
            None,
            None,
            fail_read_1,
            None,
            false,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::FutureRead,
            ForceChallenge::No,
        );
    }

    #[test]
    fn test_challenge_read_same_step() {
        init_trace();
        let fail_read_args = vec!["1106", "0xf000003c", "0xaa000004", "0xf000003c", "1106"]
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>();

        let fail_read_1 = Some(FailConfiguration::new_fail_reads(FailReads::new(
            Some(&fail_read_args),
            None,
        )));

        test_challenge_aux(
            "45",
            "hello-world.yaml",
            17,
            false,
            fail_read_1.clone(),
            None,
            None,
            None,
            true,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::No,
            ForceChallenge::No,
        );

        test_challenge_aux(
            "46",
            "hello-world.yaml",
            17,
            false,
            None,
            None,
            fail_read_1,
            None,
            false,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::FutureRead,
            ForceChallenge::No,
        );
    }

    #[test]
    fn test_challenge_equivocation_resign_step_hash() {
        init_trace();
        let fail_read_args = vec!["1106", "0xf000003c", "0xaa000004", "0xf000003c", "1100"]
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>();

        let mut fail_config =
            FailConfiguration::new_fail_reads(FailReads::new(Some(&fail_read_args), None));
        fail_config.fail_resign_hash = Some(1105);
        let fail_config = Some(fail_config);

        test_challenge_aux(
            "47",
            "hello-world.yaml",
            17,
            false,
            fail_config.clone(),
            None,
            None,
            None,
            true,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::No,
            ForceChallenge::No,
        );

        test_challenge_aux(
            "48",
            "hello-world.yaml",
            17,
            false,
            None,
            None,
            fail_config,
            None,
            false,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::EquivocationResign(EquivocationKind::StepHash),
            ForceChallenge::No,
        );
    }

    #[test]
    fn test_challenge_equivocation_resign_next_hash() {
        init_trace();
        let fail_read_args = vec!["1106", "0xf000003c", "0xaa000004", "0xf000003c", "1100"]
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>();

        let mut fail_config =
            FailConfiguration::new_fail_reads(FailReads::new(Some(&fail_read_args), None));
        fail_config.fail_resign_hash = Some(1106);
        let fail_config = Some(fail_config);

        test_challenge_aux(
            "49",
            "hello-world.yaml",
            17,
            false,
            fail_config.clone(),
            None,
            None,
            None,
            true,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::No,
            ForceChallenge::No,
        );

        test_challenge_aux(
            "50",
            "hello-world.yaml",
            17,
            false,
            None,
            None,
            fail_config,
            None,
            false,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::EquivocationResign(EquivocationKind::NextHash),
            ForceChallenge::No,
        );
    }

    #[test]
    fn test_challenge_equivocation_hash() {
        init_trace();
        let fail_read_args = vec!["1106", "0xaa000000", "0x11111100", "0xaa000000", "1100"]
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>();

        let fail_read_2 = Some(FailConfiguration::new_fail_reads(FailReads::new(
            None,
            Some(&fail_read_args),
        )));

        let fail_write_args = vec!["1100", "0xaa000000", "0x11111100", "0xaa000000"]
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>();
        let fail_write = Some(FailConfiguration::new_fail_write(FailWrite::new(
            &fail_write_args,
        )));

        test_challenge_aux(
            "51",
            "hello-world.yaml",
            17,
            false,
            fail_read_2.clone(),
            fail_write.clone(),
            None,
            None,
            true,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::No,
            ForceChallenge::No,
        );

        test_challenge_aux(
            "52",
            "hello-world.yaml",
            17,
            false,
            None,
            None,
            fail_read_2,
            fail_write,
            false,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::ReadValueNArySearch,
            ForceChallenge::EquivocationHash,
        );
    }

    #[test]
    fn test_challenge_pc_read_from_non_code() {
        init_trace();

        let fail_mem_protection = FailConfiguration::new_fail_memory_protection();

        test_challenge_aux(
            "audit_01",
            "audit_01.yaml",
            0,
            false,
            Some(fail_mem_protection),
            None,
            None,
            None,
            true,
            ForceCondition::No,
            ForceChallenge::No,
            ForceChallenge::No,
        );
    }

    #[test]
    fn test_challenge_load_to_x0_aligned() {
        init_trace();

        let fail_execute = FailExecute {
            step: 9,
            fake_trace: TraceRWStep::new(
                9,
                TraceRead::new(4026531900, 2852134912, 8),
                TraceRead::new(2852134912, 0, LAST_STEP_INIT),
                TraceReadPC::new(ProgramCounter::new(2147483796, 0), 499715),
                TraceStep::new(TraceWrite::default(), ProgramCounter::new(2147483800, 0)),
                None,
                MemoryWitness::new(
                    MemoryAccessType::Register,
                    MemoryAccessType::Memory,
                    MemoryAccessType::Unused,
                ),
            ),
        };

        let fail_execute = Some(FailConfiguration::new_fail_execute(fail_execute));

        test_challenge_aux(
            "audit_02_aligned",
            "audit_02_aligned.yaml",
            0,
            false,
            fail_execute,
            None,
            None,
            None,
            true,
            ForceCondition::No,
            ForceChallenge::No,
            ForceChallenge::No,
        );
    }

    #[test]
    fn test_challenge_load_to_x0_unaligned() {
        init_trace();

        let fail_execute = FailExecute {
            step: 10,
            fake_trace: TraceRWStep::new(
                10,
                TraceRead::new(4026531900, 2852134912, 8),
                TraceRead::new(2852134912, 0, LAST_STEP_INIT),
                TraceReadPC::new(ProgramCounter::new(2147483796, 1), 4292321283),
                TraceStep::new(
                    TraceWrite::new(4026531972, 0),
                    ProgramCounter::new(2147483796, 2),
                ),
                None,
                MemoryWitness::new(
                    MemoryAccessType::Register,
                    MemoryAccessType::Memory,
                    MemoryAccessType::Register,
                ),
            ),
        };

        let fail_execute = Some(FailConfiguration::new_fail_execute(fail_execute));

        test_challenge_aux(
            "audit_02_unaligned",
            "audit_02_unaligned.yaml",
            0,
            false,
            fail_execute,
            None,
            None,
            None,
            true,
            ForceCondition::No,
            ForceChallenge::No,
            ForceChallenge::No,
        );
    }

    #[test]
    fn test_read_to_execute_only_section() {
        init_trace();

        let fail_config = Some(FailConfiguration::new_fail_execute_only_protection());

        test_challenge_aux(
            "audit_10",
            "audit_10.yaml",
            0,
            false,
            fail_config.clone(),
            None,
            None,
            None,
            true,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::No,
            ForceChallenge::No,
        );
    }

    #[test]
    fn test_challenge_non_aligned_jump() {
        init_trace();

        let fail_mem_protection = FailConfiguration::new_fail_memory_protection();

        test_challenge_aux(
            "audit_15",
            "audit_15.yaml",
            0,
            true,
            Some(fail_mem_protection),
            None,
            None,
            None,
            true,
            ForceCondition::No,
            ForceChallenge::No,
            ForceChallenge::No,
        );
    }

    #[test]
    fn test_pc_limit() {
        init_trace();

        // executes a NOP in the step that should jump to the infinite loop, causing the program to wrongfuly halt
        let fail_args = vec!["2", "0x100073"] // Ebreak (NOP)
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>();
        let fail_opcode = Some(FailConfiguration::new_fail_opcode(FailOpcode::new(
            &fail_args,
        )));

        test_challenge_aux(
            "pc_limit",
            "pc_limit.yaml",
            0,
            false,
            fail_opcode,
            None,
            None,
            None,
            true,
            ForceCondition::No,
            ForceChallenge::No,
            ForceChallenge::No,
        );
    }
}
