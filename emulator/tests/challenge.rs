use emulator::{
    constants::REGISTERS_BASE_ADDRESS,
    decision::nary_search::{choose_segment, ExecutionHashes},
    executor::verifier::verify_script,
    loader::program_definition::ProgramDefinition,
};
use tracing::{info, Level};

fn init_trace() {
    tracing_subscriber::fmt()
        .without_time()
        .with_target(false)
        .with_max_level(Level::INFO)
        .init();
}

fn test_nary_search_trace_aux(input: u8, expect_err: bool, checkpoint_path: &str) {
    let program_definition_file = "../docker-riscv32/riscv32/build/hello-world.yaml";
    let program_def = ProgramDefinition::from_config(program_definition_file).unwrap();

    let defs = program_def.nary_def();

    let (_bad_result, last_step, _last_hash) = program_def
        .get_execution_result(vec![17, 17, 17, input], checkpoint_path, None)
        .unwrap();

    let challenge_selected_step = last_step.min(1500);
    info!("Verifier decides to challenge");
    info!("Selected step to challenge: {}", challenge_selected_step);

    let mut selected = challenge_selected_step;
    let mut base = 0;

    for round in 1..defs.total_rounds() + 1 {
        info!("Prover gets the steps required by the n-ary search round: {round}");
        let reply_hashes = program_def
            .get_round_hashes(checkpoint_path, round, base, None)
            .unwrap(); //get_hashes(&bad_trace, &steps);
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
    let trace = program_def
        .get_trace_step(checkpoint_path, selected, None)
        .unwrap();

    info!("{:?}", trace.to_csv());

    let result = verify_script(&trace, REGISTERS_BASE_ADDRESS, &None);
    info!("Validation result: {:?}", result);

    if expect_err {
        assert!(result.is_err());
    } else {
        assert!(result.is_ok());
    }
}

#[test]
fn test_nary_search_trace() {
    init_trace();
    test_nary_search_trace_aux(17, false, "../temp-runs/ok/");
    test_nary_search_trace_aux(0, true, "../temp-runs/fail/");
}
