use emulator::{
    constants::REGISTERS_BASE_ADDRESS,
    decision::{choose_segment, need_to_challenge, ExecutionHashes, ProgramResult},
    executor::{
        fetcher::{execute_program, FailConfiguration, FullTrace},
        validator::validate,
    },
    loader::{program::Program, program_definition::ProgramDefinition},
    ExecutionResult,
};
use tracing::{info, Level};

fn verify_program(
    mut program: Program,
    input_section_name: &str,
    validate_on_chain: bool,
    input_data: Vec<u8>,
) -> Result<(ExecutionResult, FullTrace), ExecutionResult> {
    Ok(execute_program(
        &mut program,
        input_data,
        input_section_name,
        false,
        &Some("../temp-runs/".to_string()),
        None,
        true,
        validate_on_chain,
        false,
        false,
        false,
        false,
        None,
        None,
        FailConfiguration::default(),
    ))
}

fn get_hashes(trace: &FullTrace, steps: &Vec<u64>) -> Vec<String> {
    steps
        .iter()
        .map(|step| {
            if *step >= trace.len() as u64 {
                trace.last().unwrap().1.clone()
            } else {
                trace[*step as usize].1.clone()
            }
        })
        .collect::<Vec<String>>()
}

fn test_nary_search_trace_aux(input: u8, expect_err: bool) {
    let program_def =
        ProgramDefinition::from_config("../docker-riscv32/riscv32/build/hello-world.yaml").unwrap();

    let defs = program_def.nary_def();

    //bad result
    let (_bad_result, bad_trace) = verify_program(
        program_def.load_program().unwrap(),
        &program_def.input_section_name,
        false,
        vec![17, 17, 17, input],
    )
    .unwrap();
    let last_step = bad_trace.last().unwrap().0.step_number;

    let fake_end_hash = vec![1; 20]
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<String>();

    info!("Prover end_hash: {}", fake_end_hash);
    info!("Prover end_step: {}", 1500);

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
        let steps = defs.required_steps(round, base);
        let reply_hashes = get_hashes(&bad_trace, &steps);
        info!("Steps: {:?}", steps);
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
    let trace = &bad_trace[(selected - 1) as usize].0;
    info!("{:?}", trace.to_csv());

    let result = validate(trace, REGISTERS_BASE_ADDRESS, &None);
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
    test_nary_search_trace_aux(17, false);
    test_nary_search_trace_aux(0, true);
}
