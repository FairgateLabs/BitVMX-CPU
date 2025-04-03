use std::collections::HashMap;

use bitvmx_cpu_definitions::{
    challenge::ChallengeType,
    trace::{generate_initial_step_hash, hashvec_to_string, validate_step_hash, TraceRWStep},
};
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
    force: bool,
    fail_config: Option<FailConfiguration>,
) -> Result<Option<u64>, EmulatorError> {
    let program_def = ProgramDefinition::from_config(program_definition_file)?;
    let (result, last_step, last_hash) =
        program_def.get_execution_result(input.clone(), checkpoint_path, fail_config)?;

    if result == ExecutionResult::Halt(0, last_step) {
        info!("The program executed successfully with the prover input");
        info!("Do not challenge.");
        if !force {
            return Ok(None);
        }
    }

    if claim_last_step != last_step || claim_last_hash != last_hash {
        warn!("The prover provided a valid input, but the last step or hash differs");
        warn!("Do not challenge (as the challenge is not waranteed to be successful)");
        warn!("Report this case to be evaluated by the security team");
        if !force {
            return Ok(None);
        }
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

#[derive(Debug, Clone, PartialEq)]
pub enum ForceChallenge {
    TraceHash,
    TraceHashZero,
    EntryPoint,
    ProgramCounter,
    No,
}

pub fn verifier_choose_challenge(
    program_definition_file: &str,
    checkpoint_path: &str,
    trace: TraceRWStep,
    force: ForceChallenge,
    fail_config: Option<FailConfiguration>,
) -> Result<ChallengeType, EmulatorError> {
    let program_def = ProgramDefinition::from_config(program_definition_file)?;
    let nary_def = program_def.nary_def();
    let verifier_log = VerifierChallengeLog::load(checkpoint_path)?;

    let (step_hash, next_hash) = get_hashes(
        &nary_def.step_mapping(&verifier_log.verifier_decisions),
        &verifier_log.prover_hash_rounds,
        verifier_log.step_to_challenge,
    );

    // check trace_hash
    if !validate_step_hash(&step_hash, &trace.trace_step, &next_hash)
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

    // check entrypoint
    if trace.read_pc.pc.get_address() != my_trace.read_pc.pc.get_address()
        || trace.read_pc.pc.get_micro() != my_trace.read_pc.pc.get_micro()
        || force == ForceChallenge::EntryPoint
        || force == ForceChallenge::ProgramCounter
    {
        if trace.step_number == 1 {
            info!("Veifier choose to challenge ENTRYPOINT");
            return Ok(ChallengeType::EntryPoint(
                trace.read_pc,
                trace.step_number,
                program_def.load_program().unwrap().pc.get_address(), //this parameter is only used for the test
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
    // -- address is asserted by the execution challenge
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
    use tracing::Level;

    use crate::{
        constants::REGISTERS_BASE_ADDRESS, decision::challenge::*,
        executor::verifier::verify_script, loader::program_definition::ProgramDefinition,
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
        input: u8,
        execute_err: bool,
        fail_config_prover: Option<FailConfiguration>,
        fail_config_verifier: Option<FailConfiguration>,
        challenge_ok: bool,
        force: ForceChallenge,
    ) {
        let pdf = "../docker-riscv32/riscv32/build/hello-world.yaml";
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
            true,
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
        info!("{:?}", final_trace.to_csv());

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
        test_challenge_aux("1", 0, true, None, None, false, ForceChallenge::No);
        //good input: expect execute step to succeed
        test_challenge_aux("2", 17, false, None, None, false, ForceChallenge::No);
    }

    #[test]
    fn test_challenge_trace_hash() {
        init_trace();
        //invalid hash: expect trace hash to fail
        let fail_hash = Some(FailConfiguration::new_fail_hash(100));
        test_challenge_aux(
            "3",
            17,
            false,
            fail_hash.clone(),
            None,
            true,
            ForceChallenge::No,
        );
        test_challenge_aux(
            "4",
            17,
            false,
            None,
            fail_hash,
            false,
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
            17,
            false,
            fail_hash.clone(),
            None,
            true,
            ForceChallenge::No,
        );
        test_challenge_aux(
            "6",
            17,
            false,
            None,
            fail_hash,
            false,
            ForceChallenge::TraceHashZero,
        );
    }

    #[test]
    fn test_challenge_entrypoint() {
        init_trace();
        let fail_entrypoint = Some(FailConfiguration::new_fail_pc(0));
        test_challenge_aux(
            "5",
            17,
            false,
            fail_entrypoint.clone(),
            None,
            true,
            ForceChallenge::No,
        );
        test_challenge_aux(
            "6",
            17,
            false,
            None,
            fail_entrypoint,
            false,
            ForceChallenge::EntryPoint,
        );
    }

    #[test]
    fn test_challenge_program_counter() {
        init_trace();
        let fail_entrypoint = Some(FailConfiguration::new_fail_pc(1));
        test_challenge_aux(
            "7",
            17,
            false,
            fail_entrypoint.clone(),
            None,
            true,
            ForceChallenge::No,
        );
        test_challenge_aux(
            "8",
            17,
            false,
            None,
            fail_entrypoint,
            false,
            ForceChallenge::ProgramCounter,
        );
    }
}
