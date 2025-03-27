use tracing::{error, info, warn};

use crate::{
    decision::{
        execution_log::VerifierChallengeLog,
        nary_search::{choose_segment, ExecutionHashes},
    },
    executor::trace::TraceRWStep,
    loader::program_definition::ProgramDefinition,
    EmulatorError, ExecutionResult,
};

use super::execution_log::{ExecutionLog, ProverChallengeLog};

pub fn prover_execute(
    program_definition_file: &str,
    input: Vec<u8>,
    checkpoint_path: &str,
    force: bool,
) -> Result<(ExecutionResult, u64, String), EmulatorError> {
    let program_def = ProgramDefinition::from_config(program_definition_file)?;
    let (result, last_step, last_hash) =
        program_def.get_execution_result(input.clone(), checkpoint_path)?;
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
    let hashes = program_def.get_round_hashes(checkpoint_path, round, challenge_log.base_step)?;
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
) -> Result<Option<u64>, EmulatorError> {
    let program_def = ProgramDefinition::from_config(program_definition_file)?;
    let (result, last_step, last_hash) =
        program_def.get_execution_result(input.clone(), checkpoint_path)?;

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

    let step_to_challenge = claim_last_step.min(last_step);

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
) -> Result<u32, EmulatorError> {
    let mut challenge_log = VerifierChallengeLog::load(checkpoint_path)?;
    let base = challenge_log.base_step;

    let program_def = ProgramDefinition::from_config(program_definition_file)?;

    let hashes = program_def.get_round_hashes(checkpoint_path, round, base)?;

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
) -> Result<TraceRWStep, EmulatorError> {
    let mut challenge_log = ProverChallengeLog::load(checkpoint_path)?;
    let base = challenge_log.base_step;

    let program_def = ProgramDefinition::from_config(program_definition_file)?;
    let nary_def = program_def.nary_def();

    let total_rounds = nary_def.total_rounds();
    let final_step = nary_def.step_from_base_and_bits(total_rounds - 1, base, final_bits);

    challenge_log.base_step = final_step;
    challenge_log.verifier_decisions.push(final_bits);

    info!("The prover needs to provide the full trace for the selected step {final_step}");
    challenge_log.final_trace = program_def.get_trace_step(checkpoint_path, final_step)?;
    challenge_log.save(checkpoint_path)?;
    Ok(challenge_log.final_trace)
}

#[cfg(test)]
mod tests {
    use tracing::Level;

    use crate::{
        constants::REGISTERS_BASE_ADDRESS, decision::challenge::*, executor::validator::validate,
        loader::program_definition::ProgramDefinition,
    };

    fn init_trace() {
        tracing_subscriber::fmt()
            .without_time()
            .with_target(false)
            .with_max_level(Level::INFO)
            .init();
    }

    fn test_challenge_aux(input: u8, expect_err: bool) {
        let pdf = "../docker-riscv32/riscv32/build/hello-world.yaml";
        let input = vec![17, 17, 17, input];
        let program_def = ProgramDefinition::from_config(pdf).unwrap();
        let nary_def = program_def.nary_def();

        let extra = if expect_err { "fail" } else { "ok" };

        let chk_prover_path = &format!("../temp-runs/challenge/{}/prover/", extra);
        let chk_verifier_path = &format!("../temp-runs/challenge/{}/verifier/", extra);

        // PROVER EXECUTES
        let result_1 = prover_execute(pdf, input.clone(), chk_prover_path, true).unwrap();
        info!("{:?}", result_1);

        // VERIFIER DECIDES TO CHALLENGE
        let result =
            verifier_check_execution(pdf, input, chk_verifier_path, result_1.1, &result_1.2, true)
                .unwrap();
        info!("{:?}", result);

        let mut v_decision = 0;

        //MULTIPLE ROUNDS N-ARY SEARCH
        for round in 1..nary_def.total_rounds() + 1 {
            let hashes =
                prover_get_hashes_for_round(pdf, chk_prover_path, round, v_decision).unwrap();
            info!("{:?}", &hashes);

            v_decision = verifier_choose_segment(pdf, chk_verifier_path, round, hashes).unwrap();
            info!("{:?}", v_decision);
        }

        //PROVER PROVIDES FINAL TRACE
        let final_trace = prover_final_trace(pdf, chk_prover_path, v_decision).unwrap();
        info!("{:?}", final_trace.to_csv());

        let result = validate(&final_trace, REGISTERS_BASE_ADDRESS, &None);
        info!("Validation result: {:?}", result);

        if expect_err {
            assert!(result.is_err());
        } else {
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_challenge() {
        init_trace();
        test_challenge_aux(0, true);
        test_challenge_aux(17, false);
    }
}
