use bitvmx_cpu_definitions::{
    challenge::ChallengeType,
    constants::LAST_STEP_INIT,
    trace::{generate_initial_step_hash, hashvec_to_string, validate_step_hash, TraceRWStep},
};

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use strum_macros::{Display, EnumIter, EnumString};
use tracing::{error, info, warn};

use crate::{
    decision::{
        execution_log::VerifierChallengeLog,
        nary_search::{choose_segment, ExecutionHashes},
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
) -> Result<(ExecutionResult, u64, String), EmulatorError> {
    let program_def = ProgramDefinition::from_config(program_definition_file)?;
    let (result, last_step, last_hash) =
        program_def.get_execution_result(input.clone(), checkpoint_path, fail_config)?;
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
) -> Result<Vec<String>, EmulatorError> {
    let mut challenge_log = ProverChallengeLog::load(checkpoint_path)?;
    let base = challenge_log.base_step;

    let program_def = ProgramDefinition::from_config(program_definition_file)?;

    let new_base = match round {
        1 => base,
        _ => program_def
            .nary_def()
            .step_from_base_and_bits(round - 1, base, verifier_decision),
    };

    challenge_log.base_step = new_base;
    let hashes = program_def.get_round_hashes(
        checkpoint_path,
        round,
        challenge_log.base_step,
        fail_config,
    )?;
    challenge_log.hash_rounds.push(hashes.clone());
    challenge_log.verifier_decisions.push(verifier_decision);
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
) -> Result<Option<u64>, EmulatorError> {
    let program_def = ProgramDefinition::from_config(program_definition_file)?;
    let (result, last_step, last_hash) =
        program_def.get_execution_result(input.clone(), checkpoint_path, fail_config)?;

    let mut should_challenge = true;

    if result == ExecutionResult::Halt(0, last_step) {
        info!("The program executed successfully with the prover input");
        info!("Do not challenge.");

        if claim_last_step != last_step || claim_last_hash != last_hash {
            warn!("The prover provided a valid input, but the last step or hash differs");
            warn!("Do not challenge (as the challenge is not waranteed to be successful)");
            warn!("Report this case to be evaluated by the security team");
            should_challenge = force_condition == ForceCondition::ValidInputWrongStepOrHash
                || force_condition == ForceCondition::Allways;
        } else {
            should_challenge = force_condition == ForceCondition::ValidInputStepAndHash
                || force_condition == ForceCondition::Allways;
        }
    }

    // if !should_challenge {
    //     // TODO: Should be removed after here, not creating challenge_log.
    //     return Ok(None);
    // }

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

    if !should_challenge {
        // TODO: Remove
        return Ok(None);
    }

    Ok(Some(step_to_challenge))
}

pub fn verifier_choose_segment(
    program_definition_file: &str,
    checkpoint_path: &str,
    round: u8,
    prover_last_hashes: Vec<String>,
    fail_config: Option<FailConfiguration>,
) -> Result<u32, EmulatorError> {
    let mut challenge_log = VerifierChallengeLog::load(checkpoint_path)?;
    let base = challenge_log.base_step;

    let program_def = ProgramDefinition::from_config(program_definition_file)?;

    let hashes = program_def.get_round_hashes(checkpoint_path, round, base, fail_config)?;

    let claim_hashes = ExecutionHashes::from_hexstr(&prover_last_hashes);
    let my_hashes = ExecutionHashes::from_hexstr(&hashes);

    let (bits, base, new_selected) = choose_segment(
        &program_def.nary_def(),
        base,
        challenge_log.step_to_challenge,
        round,
        &claim_hashes,
        &my_hashes,
    );
    challenge_log.base_step = base;
    challenge_log.step_to_challenge = new_selected;
    challenge_log.verifier_decisions.push(bits);
    challenge_log.prover_hash_rounds.push(prover_last_hashes);
    challenge_log.verifier_hash_rounds.push(hashes);
    challenge_log.save(checkpoint_path)?;

    info!("Verifier selects bits: {bits} base: {base} selection: {new_selected}");

    Ok(bits)
}

pub fn prover_final_trace(
    program_definition_file: &str,
    checkpoint_path: &str,
    final_bits: u32,
    fail_config: Option<FailConfiguration>,
) -> Result<TraceRWStep, EmulatorError> {
    let mut challenge_log = ProverChallengeLog::load(checkpoint_path)?;
    let base = challenge_log.base_step;

    let program_def = ProgramDefinition::from_config(program_definition_file)?;
    let nary_def = program_def.nary_def();

    let total_rounds = nary_def.total_rounds();
    let final_step = nary_def.step_from_base_and_bits(total_rounds, base, final_bits);

    challenge_log.base_step = final_step;
    challenge_log.verifier_decisions.push(final_bits);

    info!("The prover needs to provide the full trace for the selected step {final_step}");
    challenge_log.final_trace =
        program_def.get_trace_step(checkpoint_path, final_step, fail_config)?;
    challenge_log.save(checkpoint_path)?;
    Ok(challenge_log.final_trace)
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
    TraceHash,
    TraceHashZero,
    EntryPoint,
    ProgramCounter,
    Opcode,
    InputData,
    AddressesSections,
    No,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, EnumString, Display, EnumIter)]
#[strum(serialize_all = "snake_case")]
pub enum ForceCondition {
    ValidInputStepAndHash,
    ValidInputWrongStepOrHash,
    Allways,
    No,
}

pub fn verifier_choose_challenge(
    program_definition_file: &str,
    checkpoint_path: &str,
    trace: TraceRWStep,
    force: ForceChallenge,
    fail_config: Option<FailConfiguration>,
    return_script_parameters: bool,
) -> Result<ChallengeType, EmulatorError> {
    let program_def = ProgramDefinition::from_config(program_definition_file)?;
    let program = program_def.load_program_from_checkpoint(checkpoint_path, 0)?;
    let nary_def = program_def.nary_def();
    let verifier_log = VerifierChallengeLog::load(checkpoint_path)?;

    let (step_hash, next_hash) = get_hashes(
        &nary_def.step_mapping(&verifier_log.verifier_decisions),
        &verifier_log.prover_hash_rounds,
        verifier_log.step_to_challenge,
    );

    // check trace_hash
    if (!validate_step_hash(&step_hash, &trace.trace_step, &next_hash)
        && force == ForceChallenge::No)
        || force == ForceChallenge::TraceHash
        || force == ForceChallenge::TraceHashZero
    {
        if trace.step_number == 1 {
            info!("Veifier choose to challenge TRACE_HASH_ZERO");
            return Ok(ChallengeType::TraceHashZero(trace.trace_step, next_hash));
        }

        info!("Veifier choose to challenge TRACE_HASH");
        return Ok(ChallengeType::TraceHash(
            step_hash,
            trace.trace_step,
            next_hash,
        ));
    }

    let step = verifier_log.step_to_challenge;
    let mut steps = vec![step, step + 1];
    let mut my_trace_idx = 1;
    if step > 0 {
        steps.insert(0, step - 1);
        my_trace_idx += 1;
    }

    //obtain all the steps needed
    let my_execution = program_def
        .execute_helper(checkpoint_path, vec![], Some(steps), fail_config)?
        .1;
    info!("execution: {:?}", my_execution);
    let my_trace = my_execution[my_trace_idx].0.clone();

    // TODO: limit exception

    let read_write_sections = program.read_write_sections.clone();
    let read_only_sections = program.read_only_sections.clone();
    let register_sections = program.register_sections.clone();
    let code_sections = program.code_sections.clone();

    let is_valid_read_1 =
        program.is_valid_mem(trace.mem_witness.read_1(), trace.read_1.address, true);
    let is_valid_read_2 =
        program.is_valid_mem(trace.mem_witness.read_2(), trace.read_2.address, true);

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
        return Ok(ChallengeType::AddressesSections(
            trace.read_1,
            trace.read_2,
            trace.trace_step.write_1,
            trace.mem_witness,
            trace.read_pc.pc,
            return_script_parameters.then_some(read_write_sections),
            return_script_parameters.then_some(read_only_sections),
            return_script_parameters.then_some(register_sections),
            return_script_parameters.then_some(code_sections),
        ));
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
            info!("Veifier choose to challenge ENTRYPOINT");
            return Ok(ChallengeType::EntryPoint(
                trace.read_pc,
                trace.step_number,
                program.pc.get_address(), //this parameter is only used for the test
            ));
        } else {
            info!("Veifier choose to challenge PROGRAM_COUNTER");
            let pre_pre_hash = my_execution[0].1.clone();
            let pre_step = my_execution[1].0.clone();
            return Ok(ChallengeType::ProgramCounter(
                pre_pre_hash,
                pre_step.trace_step,
                step_hash,
                trace.read_pc,
            ));
        }
    }

    if trace.read_pc.opcode != my_trace.read_pc.opcode && force == ForceChallenge::No
        || force == ForceChallenge::Opcode
    {
        let pc = trace.read_pc.pc.get_address();

        const CHUNK_SIZE: u32 = 500;

        let (chunk_index, chunk_base_addr, chunk_start) = program.get_chunk_info(pc, CHUNK_SIZE);

        let section = program.find_section(pc).unwrap();
        let chunk_end = (chunk_start + CHUNK_SIZE as usize).min(section.data.len());

        let opcodes_chunk: Vec<u32> = section.data[chunk_start..chunk_end]
            .iter()
            .map(|opcode| u32::from_be(*opcode))
            .collect();

        return Ok(ChallengeType::Opcode(
            trace.read_pc,
            chunk_index,
            chunk_base_addr,
            return_script_parameters.then_some(opcodes_chunk),
        ));
    }

    // check const read value
    let conflict_read_1 =
        trace.read_1.value != my_trace.read_1.value && trace.read_1.last_step == LAST_STEP_INIT;
    let conflict_read_2 =
        trace.read_2.value != my_trace.read_2.value && trace.read_2.last_step == LAST_STEP_INIT;
    if conflict_read_1 || conflict_read_2 {
        let conflict_address = if conflict_read_1 {
            trace.read_1.address
        } else {
            trace.read_2.address
        };
        let section = program.find_section(conflict_address)?;
        //TODO: Check if the address is in the input section rom ram or registers
        let value = program.read_mem(conflict_address)?;
        if (section.name == program_def.input_section_name && force == ForceChallenge::No)
            || force == ForceChallenge::InputData
        {
            info!("Verifier choose to challenge invalid INPUT DATA");
            return Ok(ChallengeType::InputData(
                trace.read_1.clone(),
                trace.read_2.clone(),
                conflict_address,
                value,
            ));
        }
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
        fail_config_verifier: Option<FailConfiguration>,
        challenge_ok: bool,
        force_condition: ForceCondition,
        force: ForceChallenge,
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
            )
            .unwrap();
            info!("{:?}", &hashes);

            v_decision = verifier_choose_segment(
                pdf,
                chk_verifier_path,
                round,
                hashes,
                fail_config_verifier.clone(),
            )
            .unwrap();
            info!("{:?}", v_decision);
        }

        //TODO: Add translation keys

        //PROVER PROVIDES EXECUTE STEP (and reveals full_trace)
        //Use v_desision + 1 as v_decision defines the last agreed step
        let final_trace =
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
            &chk_verifier_path,
            final_trace,
            force,
            fail_config_verifier,
            true,
        )
        .unwrap();
        let result = execute_challenge(&challenge);
        assert_eq!(result, challenge_ok);

        info!("Challenge: {:?} result: {}", challenge, result);
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
            false,
            ForceCondition::No,
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
            false,
            ForceCondition::ValidInputStepAndHash,
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
            true,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::No,
        );
        test_challenge_aux(
            "4",
            "hello-world.yaml",
            17,
            false,
            None,
            fail_hash,
            false,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::TraceHash,
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
            true,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::No,
        );
        test_challenge_aux(
            "6",
            "hello-world.yaml",
            17,
            false,
            None,
            fail_hash,
            false,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::TraceHashZero,
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
            true,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::No,
        );
        test_challenge_aux(
            "8",
            "hello-world.yaml",
            17,
            false,
            None,
            fail_entrypoint,
            false,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::EntryPoint,
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
            true,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::No,
        );
        test_challenge_aux(
            "10",
            "hello-world.yaml",
            17,
            false,
            None,
            fail_pc,
            false,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::ProgramCounter,
        );
    }

    #[test]
    fn test_challenge_input() {
        init_trace();
        let fail_args = vec![
            "1106",
            "0xaa000000",
            "0x11111111",
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
            0,
            false,
            fail_read_2,
            None,
            true,
            ForceCondition::No,
            ForceChallenge::No,
        );

        // if we use the same fail_read as before, the prover won't challenge
        // because there is no hash difference, the previous fail_read reads
        // the value 0x11111111 and that's what we are already reading
        // because we pass 17 as input instead of 0
        let fail_args = vec![
            "1106",
            "0xaa000000",
            "0x11111100", // different input value
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
            "12",
            "hello-world.yaml",
            17,
            false,
            None,
            fail_read_2,
            false,
            ForceCondition::ValidInputStepAndHash,
            ForceChallenge::InputData,
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
            true,
            ForceCondition::No,
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
            fail_read_2,
            false,
            ForceCondition::No,
            ForceChallenge::AddressesSections,
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
            true,
            ForceCondition::No,
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
            fail_read_2,
            false,
            ForceCondition::No,
            ForceChallenge::AddressesSections,
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
            true,
            ForceCondition::No,
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
            fail_write,
            false,
            ForceCondition::No,
            ForceChallenge::AddressesSections,
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
            true,
            ForceCondition::No,
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
            fail_write,
            false,
            ForceCondition::No,
            ForceChallenge::AddressesSections,
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
            true,
            ForceCondition::No,
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
            fail_write,
            false,
            ForceCondition::No,
            ForceChallenge::AddressesSections,
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
            true,
            ForceCondition::No,
            ForceChallenge::No,
        );

        test_challenge_aux(
            "24",
            "hello-world.yaml",
            17,
            false,
            None,
            fail_execute,
            false,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::AddressesSections,
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
            true,
            ForceCondition::No,
            ForceChallenge::No,
        );

        test_challenge_aux(
            "26",
            "hello-world.yaml",
            17,
            false,
            None,
            fail_execute,
            false,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::AddressesSections,
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
            true,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::No,
        );

        test_challenge_aux(
            "28",
            "hello-world.yaml",
            17,
            false,
            None,
            fail_opcode,
            false,
            ForceCondition::ValidInputWrongStepOrHash,
            ForceChallenge::Opcode,
        );
    }
}
