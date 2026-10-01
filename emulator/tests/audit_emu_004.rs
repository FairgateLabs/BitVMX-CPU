//! EMU-004: verifier `assert!`/`unwrap` on prover-controlled claims.
//!
//! See docs/emulator-audit/tickets/EMU-004-verifier-panics-on-prover-claims.md
//!
//! Tests that assert the *expected* (correct) behaviour and currently fail
//! because of the bug are marked `#[ignore = "EMU-004: fails until fixed"]`.
//! Tests without `#[ignore]` pass today (boundary checks / documentation of
//! current behaviour).

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;

use bitvmx_cpu_definitions::{memory::MemoryWitness, trace::TraceRWStep};
use emulator::{
    decision::{
        challenge::{
            prover_execute, prover_final_trace, prover_get_hashes_for_round,
            verifier_check_execution, verifier_choose_challenge, verifier_choose_segment,
            ForceChallenge, ForceCondition,
        },
        nary_search::NArySearchType,
    },
    loader::program_definition::ProgramDefinition,
    ExecutionResult,
};

const HELLO_YAML: &str = "../docker-riscv32/riscv32/build/hello-world.yaml";
const HELLO_ELF: &str = "../docker-riscv32/riscv32/build/hello-world.elf";

/// Fresh, unique temp dir (forward slashes: ProgramDefinition splits paths on '/').
fn temp_dir(name: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir: PathBuf = std::env::temp_dir().join(format!(
        "audit_emu_004_{}_{}_{}",
        name,
        std::process::id(),
        nanos
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir.to_string_lossy().replace('\\', "/")
}

/// Copies hello-world.elf into `dir` with a yaml using the given `max_steps`.
fn write_program(dir: &str, max_steps: u64) -> String {
    std::fs::copy(HELLO_ELF, format!("{dir}/prog.elf")).unwrap();
    let yaml = format!(
        "elf: prog.elf\nnary_search: 8\nmax_steps: {max_steps}\ninput_section_name: .input\ninputs:\n  - size: 4\n    owner: prover\n"
    );
    let yaml_path = format!("{dir}/prog.yaml");
    std::fs::write(&yaml_path, yaml).unwrap();
    yaml_path
}

fn panic_msg(e: &Box<dyn std::any::Any + Send>) -> String {
    e.downcast_ref::<String>()
        .cloned()
        .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_else(|| "<non-string panic>".to_string())
}

/// Runs `verifier_check_execution` on hello-world with the given claim and
/// returns `Err(panic message)` if it panicked.
fn check_execution_with_claim(
    name: &str,
    input: Vec<u8>,
    claim_last_step: u64,
    force_condition: ForceCondition,
) -> Result<Result<Option<u64>, String>, String> {
    let dir = temp_dir(name);
    let res = catch_unwind(AssertUnwindSafe(|| {
        verifier_check_execution(
            HELLO_YAML,
            input,
            &dir,
            &dir,
            claim_last_step,
            "0000000000000000000000000000000000000000",
            force_condition,
            None,
            false,
        )
        .map_err(|e| e.to_string())
    }));
    res.map_err(|e| panic_msg(&e))
}

/// Expected: a prover claim of `last_step = 0` (valid input, wrong step) must not
/// crash the verifier. It should return an error (the claim is invalid; the
/// on-chain COMMITMENT script already rejects it) or a challenge decision.
#[test]
#[ignore = "EMU-004: fails until fixed"]
fn claim_last_step_zero_valid_input_does_not_panic() {
    let r = check_execution_with_claim(
        "claim0_valid",
        vec![17, 17, 17, 17],
        0,
        ForceCondition::ValidInputWrongStepOrHash,
    );
    println!("verifier_check_execution(claim_last_step = 0, valid input) -> {r:?}");
    assert!(r.is_ok(), "verifier panicked: {:?}", r.unwrap_err());
}

/// Same, with an input on which the program does not halt with 0 (the verifier
/// always challenges in this case, `ForceCondition::No`).
#[test]
#[ignore = "EMU-004: fails until fixed"]
fn claim_last_step_zero_invalid_input_does_not_panic() {
    let r = check_execution_with_claim("claim0_invalid", vec![17, 17, 17, 0], 0, ForceCondition::No);
    println!("verifier_check_execution(claim_last_step = 0, invalid input) -> {r:?}");
    assert!(r.is_ok(), "verifier panicked: {:?}", r.unwrap_err());
}

/// Boundary: claim 1 is accepted and leads to challenging step 0. Passes today.
#[test]
fn claim_last_step_one_is_challenged_at_step_zero() {
    let r = check_execution_with_claim(
        "claim1",
        vec![17, 17, 17, 17],
        1,
        ForceCondition::ValidInputWrongStepOrHash,
    );
    println!("verifier_check_execution(claim_last_step = 1) -> {r:?}");
    assert_eq!(r, Ok(Ok(Some(0))));
}

/// Related finding: when `max_steps` in the program definition is an exact power
/// of two (2^k), `NArySearchDefinition::max_steps == max_steps`, and a claim of
/// `last_step == max_steps` (allowed by the on-chain `last_step <= max_steps`
/// check) drives the n-ary search to step `2^k - 1`. The "next" step `2^k` is
/// never part of the n-ary step mapping, so `get_hashes` panics on
/// `mapping.get(&next_step).unwrap()` in `verifier_choose_challenge` (and in the
/// prover's `prover_final_trace`).
///
/// Here both parties run hello-world with `max_steps: 64` (it does not halt by
/// then), the prover commits `LimitStepReached(64)` with force, the verifier
/// challenges (input "invalid" because it did not halt) and the search agrees on
/// every hash.
#[test]
#[ignore = "EMU-004: fails until fixed"]
fn pow2_max_steps_claim_at_limit_verifier_does_not_panic() {
    let dir = temp_dir("pow2");
    let pdf = &write_program(&dir, 64);
    let prover_dir = format!("{dir}/prover");
    let verifier_dir = format!("{dir}/verifier");
    std::fs::create_dir_all(&prover_dir).unwrap();
    std::fs::create_dir_all(&verifier_dir).unwrap();
    let input = vec![17, 17, 17, 17];

    let (result, last_step, last_hash) =
        prover_execute(pdf, input.clone(), &prover_dir, &prover_dir, true, None, false).unwrap();
    println!("prover: {result:?} last_step={last_step}");
    assert_eq!(result, ExecutionResult::LimitStepReached(64));
    assert_eq!(last_step, 64);

    let step = verifier_check_execution(
        pdf,
        input.clone(),
        &verifier_dir,
        &verifier_dir,
        last_step,
        &last_hash,
        ForceCondition::ValidInputWrongStepOrHash,
        None,
        false,
    )
    .unwrap();
    println!("verifier step_to_challenge = {step:?}");
    assert_eq!(step, Some(63));

    let program_def = ProgramDefinition::from_config(pdf).unwrap();
    let nary_def = program_def.nary_def();
    println!(
        "nary max_steps={} rounds={}",
        nary_def.max_steps,
        nary_def.total_rounds()
    );
    let mut decision = 0;
    for round in 1..nary_def.total_rounds() + 1 {
        let hashes = prover_get_hashes_for_round(
            pdf,
            &prover_dir,
            &prover_dir,
            round,
            decision,
            None,
            NArySearchType::ConflictStep,
        )
        .unwrap();
        decision = verifier_choose_segment(
            pdf,
            &verifier_dir,
            &verifier_dir,
            round,
            hashes,
            None,
            NArySearchType::ConflictStep,
        )
        .unwrap();
        println!("round {round}: verifier decision {decision}");
    }

    // Prover side (honest software) also panics here:
    let prover_res = catch_unwind(AssertUnwindSafe(|| {
        prover_final_trace(pdf, &prover_dir, &prover_dir, decision + 1, None)
    }));
    match &prover_res {
        Ok(r) => println!("prover_final_trace -> {r:?}"),
        Err(e) => println!("prover_final_trace PANICKED: {}", panic_msg(e)),
    }

    // A dishonest prover runs its own software and can publish any trace for
    // step 64 (there is no committed hash for it). The verifier must not panic.
    // (`get_trace_step(64)` itself is rejected by `load_program_from_checkpoint`
    // because 64 >= nary max_steps, so start the query at step 63.)
    let (_, full_trace) = program_def
        .execute_helper(&prover_dir, &prover_dir, input, Some(vec![63, 64]), None, false)
        .unwrap();
    let trace: TraceRWStep = full_trace
        .iter()
        .find(|t| t.0.step_number == 64)
        .expect("trace for step 64")
        .0
        .clone();
    let verifier_res = catch_unwind(AssertUnwindSafe(|| {
        verifier_choose_challenge(
            pdf,
            &verifier_dir,
            &verifier_dir,
            trace,
            "0000000000000000000000000000000000000000",
            &last_hash,
            ForceChallenge::No,
            None,
            true,
        )
        .map_err(|e| e.to_string())
    }));
    match &verifier_res {
        Ok(r) => println!("verifier_choose_challenge -> {r:?}"),
        Err(e) => println!("verifier_choose_challenge PANICKED: {}", panic_msg(e)),
    }
    assert!(verifier_res.is_ok(), "verifier panicked");
}

/// Documentation of current behaviour (passes today): an out-of-range memory
/// witness byte panics when decoded. In the protocol the prover's
/// `prover_mem_witness` is validated by the per-instruction EXECUTE leaf scripts
/// before the verifier sees it, so this is not reachable on-chain.
#[test]
#[should_panic(expected = "Invalid value for MemoryAccessType")]
fn invalid_mem_witness_byte_panics_on_decode() {
    let _ = MemoryWitness::from_byte(0xFF).read_1();
}
