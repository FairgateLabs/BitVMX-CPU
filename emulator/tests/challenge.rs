use emulator::{
    constants::REGISTERS_BASE_ADDRESS,
    decision::{choose_segment, need_to_challenge, ExecutionHashes, ProgramResult},
    executor::{
        fetcher::{execute_program, FailConfiguration},
        trace::TraceRWStep,
        validator::validate,
    },
    loader::program_definition::ProgramDefinition,
    ExecutionResult,
};
use tracing::{info, Level};

pub fn get_execution_result(
    program_definition_file: &str,
    input_data: Vec<u8>,
    checkpoint_path: &str,
) -> Result<(ExecutionResult, u64, String), ExecutionResult> {
    let program_def = ProgramDefinition::from_config(program_definition_file).map_err(|_| {
        ExecutionResult::CantLoadPorgram("Error loading program definition".to_string())
    })?;

    let mut program = program_def.load_program()?;

    let result = execute_program(
        &mut program,
        input_data,
        &program_def.input_section_name,
        false,
        &Some(checkpoint_path.to_string()),
        Some(program_def.max_steps),
        false,
        false,
        false,
        false,
        false,
        false,
        None,
        None,
        FailConfiguration::default(),
    );

    if result.1.len() == 0 {
        return Err(ExecutionResult::Error);
    }

    let last_trace = result.1.last().unwrap();
    let last_step = last_trace.0.step_number;
    let last_hash = last_trace.1.clone();

    Ok((result.0, last_step, last_hash))
}

//TODO: Check that the base is not higher that the reported finish step
//it might be necessary to enforce this in bitcoin script
pub fn get_round_hashes(
    program_definition_file: &str,
    checkpoint_path: &str,
    round: u8,
    base: u64,
) -> Result<Vec<String>, ExecutionResult> {
    let program_def = ProgramDefinition::from_config(program_definition_file).map_err(|_| {
        ExecutionResult::CantLoadPorgram("Error loading program definition".to_string())
    })?;

    let mut program = program_def.load_program_from_checkpoint(checkpoint_path, base)?;
    let mut steps = program_def.nary_def().required_steps(round, base);
    info!("Steps: {:?}", steps);
    steps.insert(0, base); //asks base step as it should be always obtainable
    let steps_len = steps.len();

    let (_result, trace) = execute_program(
        &mut program,
        vec![], //running from checkpoint, no input data
        "",
        false,
        &None, //no checkpoint path, avoid overwrite
        Some(program_def.max_steps),
        true,
        false,
        false,
        false,
        false,
        false,
        Some(steps),
        None,
        FailConfiguration::default(),
    );

    // at least the base step should be present
    if trace.len() == 0 {
        return Err(ExecutionResult::Error);
    }

    // if there are actual steps skip the first one
    let skip = if trace.len() > 1 { 1 } else { 0 };

    let mut ret: Vec<String> = trace.iter().skip(skip).map(|t| t.1.clone()).collect();
    for _ in 0..steps_len - trace.len() {
        ret.push(trace.last().unwrap().1.clone());
    }

    Ok(ret)
}

pub fn get_trace_step(
    program_definition_file: &str,
    checkpoint_path: &str,
    step: u64,
) -> Result<TraceRWStep, ExecutionResult> {
    let program_def = ProgramDefinition::from_config(program_definition_file).map_err(|_| {
        ExecutionResult::CantLoadPorgram("Error loading program definition".to_string())
    })?;

    let mut program = program_def.load_program_from_checkpoint(checkpoint_path, step)?;
    let steps = vec![step];

    let (_result, trace) = execute_program(
        &mut program,
        vec![], //running from checkpoint, no input data
        "",
        false,
        &None, //no checkpoint path, avoid overwrite
        Some(program_def.max_steps),
        true,
        false,
        false,
        false,
        false,
        false,
        Some(steps),
        None,
        FailConfiguration::default(),
    );

    // at least the base step should be present
    if trace.len() == 0 {
        return Err(ExecutionResult::Error);
    }

    Ok(trace[0].0.clone())
}

fn test_nary_search_trace_aux(input: u8, expect_err: bool, checkpoint_path: &str) {
    let program_definition_file = "../docker-riscv32/riscv32/build/hello-world.yaml";
    let program_def = ProgramDefinition::from_config(program_definition_file).unwrap();

    let defs = program_def.nary_def();

    let (_bad_result, last_step, _last_hash) = get_execution_result(
        program_definition_file,
        vec![17, 17, 17, input],
        checkpoint_path,
    )
    .unwrap();

    let challenge_selected_step = need_to_challenge(
        &ProgramResult::new(true, 1500),
        &ProgramResult::new(false, last_step),
    )
    .unwrap();

    info!("Verifier decides to challenge");
    info!("Selected step to challenge: {}", challenge_selected_step);

    let mut selected = challenge_selected_step;
    let mut base = 0;

    for round in 1..defs.total_rounds() + 1 {
        info!("Prover gets the steps required by the n-ary search round: {round}");
        let reply_hashes =
            get_round_hashes(program_definition_file, checkpoint_path, round, base).unwrap(); //get_hashes(&bad_trace, &steps);
        info!("Hashes: {:?}", reply_hashes);

        let claim_hashes = ExecutionHashes::from_hexstr(&reply_hashes);
        let my_hashes = ExecutionHashes::from_hexstr(&reply_hashes);

        let (bits, new_base, new_selected) =
            choose_segment(&defs, base, selected, round, &claim_hashes, &my_hashes);
        base = new_base;
        selected = new_selected;

        info!("Verifier selects bits: {bits} base: {base} selection: {selected}");
    }

    info!("The prover needs to provide the full trace for the selected step {selected}");
    let trace = get_trace_step(program_definition_file, checkpoint_path, selected).unwrap();

    info!("{:?}", trace.to_csv());

    let result = validate(&trace, REGISTERS_BASE_ADDRESS, &None);
    info!("Validation result: {:?}", result);

    if expect_err {
        assert!(result.is_err());
    } else {
        assert!(result.is_ok());
    }
}

#[test]
fn test_nary_search_trace() {
    tracing_subscriber::fmt()
        .without_time()
        .with_target(false)
        .with_max_level(Level::INFO)
        .init();
    test_nary_search_trace_aux(17, false, "../temp-runs/ok/");
    test_nary_search_trace_aux(0, true, "../temp-runs/fail/");
}
