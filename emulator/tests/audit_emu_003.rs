//! EMU-003: the verifier underflows/panics when the prover claims a read `last_step` of 0.
//!
//! See docs/emulator-audit/tickets/EMU-003-read-last-step-zero-underflow.md
//!
//! Scenario (mirrors `test_challenge_uninitialized` / id "31" in `decision/challenge.rs`):
//! the prover lies about `read_2` of step 9 of `hello-world-uninitialized` (an uninitialized,
//! never written word at 0xa0001004 that really holds 0). Instead of claiming
//! `last_step = LAST_STEP_INIT` (which the verifier beats with `UninitializedData`) it claims
//! `last_step = 0`. Step 0 is the initial state, nothing is ever written at step 0, so this
//! is always a lie for a used read.

use std::panic::{catch_unwind, AssertUnwindSafe};

use bitcoin_script_riscv::riscv::challenges::execute_challenge;
use bitvmx_cpu_definitions::{
    challenge::ChallengeType, constants::LAST_STEP_INIT, trace::TraceRWStep,
    trace::TraceRead,
};
use emulator::{
    constants::REGISTERS_BASE_ADDRESS,
    decision::{
        challenge::{
            prover_execute, prover_final_trace, prover_get_hashes_and_step,
            prover_get_hashes_for_round, verifier_check_execution, verifier_choose_challenge,
            verifier_choose_challenge_for_read_challenge, verifier_choose_segment,
            ForceChallenge, ForceCondition,
        },
        nary_search::NArySearchType,
    },
    executor::{
        utils::{FailConfiguration, FailReads},
        verifier::verify_script,
    },
    loader::program_definition::ProgramDefinition,
};

const PDF: &str = "../docker-riscv32/riscv32/build/hello-world-uninitialized.yaml";
const LIE_ADDRESS: u32 = 0xa000_1004;
const LIE_VALUE: u32 = 0x1111_1100;

struct Setup {
    prover_path: String,
    verifier_path: String,
    fail_prover: Option<FailConfiguration>,
    final_trace: TraceRWStep,
    step_hash: String,
    next_hash: String,
}

fn temp_dir(id: &str, who: &str) -> String {
    let dir = std::env::temp_dir()
        .join("bitvmx-audit-emu-003")
        .join(format!("{}-{}", id, std::process::id()))
        .join(who);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    format!("{}/", dir.to_string_lossy().replace('\\', "/"))
}

fn fail_read_2(last_step: u64) -> Option<FailConfiguration> {
    let fail_args = vec![
        "9".to_string(),
        format!("0x{:08x}", LIE_ADDRESS),
        format!("0x{:08x}", LIE_VALUE),
        format!("0x{:08x}", LIE_ADDRESS),
        format!("{}", last_step),
    ];
    Some(FailConfiguration::new_fail_reads(FailReads::new(
        None,
        Some(&fail_args),
    )))
}

/// Runs the protocol (prover execute, verifier check, conflict n-ary search, prover final
/// trace) up to right before `verifier_choose_challenge`.
fn run_until_choose_challenge(id: &str, prover_read_last_step: u64) -> Setup {
    let input = vec![17, 17, 17, 0];
    let program_def = ProgramDefinition::from_config(PDF).unwrap();
    let nary_def = program_def.nary_def();
    let prover_path = temp_dir(id, "prover");
    let verifier_path = temp_dir(id, "verifier");
    let fail_prover = fail_read_2(prover_read_last_step);

    let (_res, claim_step, claim_hash) = prover_execute(
        PDF,
        input.clone(),
        &prover_path,
        &prover_path,
        true,
        fail_prover.clone(),
        false,
    )
    .unwrap();

    verifier_check_execution(
        PDF,
        input,
        &verifier_path,
        &verifier_path,
        claim_step,
        &claim_hash,
        ForceCondition::No,
        None,
        false,
    )
    .unwrap();

    let mut v_decision = 0;
    for round in 1..nary_def.total_rounds() + 1 {
        let hashes = prover_get_hashes_for_round(
            PDF,
            &prover_path,
            &prover_path,
            round,
            v_decision,
            fail_prover.clone(),
            NArySearchType::ConflictStep,
        )
        .unwrap();
        v_decision = verifier_choose_segment(
            PDF,
            &verifier_path,
            &verifier_path,
            round,
            hashes,
            None,
            NArySearchType::ConflictStep,
        )
        .unwrap();
    }

    let (final_trace, step_hash, next_hash, _) = prover_final_trace(
        PDF,
        &prover_path,
        &prover_path,
        v_decision + 1,
        fail_prover.clone(),
    )
    .unwrap()
    .as_final_trace_with_hashes_and_step()
    .unwrap();

    println!(
        "EMU-003 [{id}] last-round decision bits {} prover read_2 = {:?}",
        v_decision, final_trace.read_2
    );
    // The lying trace is internally consistent: the on-chain execution check passes.
    assert!(verify_script(&final_trace, REGISTERS_BASE_ADDRESS, &None).is_ok());
    assert_eq!(final_trace.read_2.address, LIE_ADDRESS);
    assert_eq!(final_trace.read_2.value, LIE_VALUE);
    assert_eq!(final_trace.read_2.last_step, prover_read_last_step);

    Setup {
        prover_path,
        verifier_path,
        fail_prover,
        final_trace,
        step_hash,
        next_hash,
    }
}

/// Continues the protocol after `verifier_choose_challenge` (second n-ary search if needed)
/// and returns the final challenge the verifier would post.
fn finish_challenge(s: &Setup, challenge: ChallengeType) -> ChallengeType {
    let nary_def = ProgramDefinition::from_config(PDF).unwrap().nary_def();
    match &challenge {
        ChallengeType::ReadValueNArySearch { bits } => {
            let mut v_decision = *bits;
            for round in 2..nary_def.total_rounds() + 1 {
                let hashes = prover_get_hashes_for_round(
                    PDF,
                    &s.prover_path,
                    &s.prover_path,
                    round,
                    v_decision,
                    s.fail_prover.clone(),
                    NArySearchType::ReadValueChallenge,
                )
                .unwrap();
                v_decision = verifier_choose_segment(
                    PDF,
                    &s.verifier_path,
                    &s.verifier_path,
                    round,
                    hashes,
                    None,
                    NArySearchType::ReadValueChallenge,
                )
                .unwrap();
            }
            let (h1, h2, _) = prover_get_hashes_and_step(
                PDF,
                &s.prover_path,
                NArySearchType::ReadValueChallenge,
                Some(v_decision),
                s.fail_prover.clone(),
            )
            .unwrap()
            .as_hashes_with_step()
            .unwrap();
            verifier_choose_challenge_for_read_challenge(
                PDF,
                &s.verifier_path,
                &s.verifier_path,
                &h1,
                &h2,
                None,
                ForceChallenge::No,
                true,
            )
            .unwrap()
        }
        _ => challenge,
    }
}

fn choose(s: &Setup) -> ChallengeType {
    verifier_choose_challenge(
        PDF,
        &s.verifier_path,
        &s.verifier_path,
        s.final_trace.clone(),
        &s.step_hash,
        &s.next_hash,
        ForceChallenge::No,
        None,
        true,
    )
    .unwrap()
}

/// Control: the same lie with `last_step = LAST_STEP_INIT` is caught by `UninitializedData`.
#[test]
fn emu_003_control_last_step_init_is_challenged() {
    let s = run_until_choose_challenge("control", LAST_STEP_INIT);
    let challenge = finish_challenge(&s, choose(&s));
    let ok = execute_challenge(&challenge);
    println!("EMU-003 control challenge: {:?} -> {}", challenge, ok);
    assert!(matches!(challenge, ChallengeType::UninitializedData { .. }));
    assert!(ok);
}

/// Expected behaviour: when the prover claims `last_step = 0` for a used read the verifier
/// must not panic and must post a challenge that the on-chain script accepts.
#[test]
#[ignore = "EMU-003: fails until fixed"]
fn emu_003_verifier_wins_against_read_last_step_zero() {
    let s = run_until_choose_challenge("expected", 0);
    let result = catch_unwind(AssertUnwindSafe(|| finish_challenge(&s, choose(&s))));
    let challenge = match result {
        Ok(c) => c,
        Err(e) => {
            let msg = e
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default();
            panic!("EMU-003: verifier panicked while choosing the challenge: {msg}");
        }
    };
    let ok = execute_challenge(&challenge);
    println!("EMU-003 challenge: {:?} -> {}", challenge, ok);
    assert!(ok, "the verifier's challenge must be accepted on-chain");
}

/// Demonstration (passes while the bug exists, debug builds only): the verifier panics with an
/// arithmetic underflow in `verifier_choose_challenge` (`step_to_challenge - 1` with
/// `step_to_challenge == 0`).
#[test]
#[cfg_attr(not(debug_assertions), ignore = "overflow checks are only on in debug builds")]
#[should_panic(expected = "attempt to subtract with overflow")]
fn emu_003_demo_verifier_underflows_on_read_last_step_zero() {
    let s = run_until_choose_challenge("demo-panic", 0);
    let _ = choose(&s);
}

/// Demonstration (passes while the gap exists): no existing on-chain challenge script accepts
/// a proof that a used read with `last_step = 0` is a lie. `FutureRead` requires
/// `conflict_step < read_step` and the static-data challenges require
/// `read_step == LAST_STEP_INIT`.
#[test]
fn emu_003_demo_no_script_rejects_last_step_zero() {
    let program_def = ProgramDefinition::from_config(PDF).unwrap();
    let program = program_def.load_program().unwrap();
    let ranges = program.get_uninitialized_ranges(&program_def);
    let conflict_step = 8;
    let read_1 = TraceRead::new(REGISTERS_BASE_ADDRESS + 4 * 15, LIE_ADDRESS, 5);

    let make_uninit = |last_step: u64| ChallengeType::UninitializedData {
        prover_read_1: read_1.clone(),
        prover_read_2: TraceRead::new(LIE_ADDRESS, LIE_VALUE, last_step),
        read_selector: 2,
        sections: Some(ranges.clone()),
    };
    let make_future = |last_step: u64| ChallengeType::FutureRead {
        prover_conflict_step_tk: conflict_step,
        prover_read_step_1: read_1.last_step,
        prover_read_step_2: last_step,
        read_selector: 2,
    };

    // controls: these lies are provable
    assert!(execute_challenge(&make_uninit(LAST_STEP_INIT)));
    assert!(execute_challenge(&make_future(conflict_step + 1)));

    // last_step == 0: no script proves the lie
    let uninit = execute_challenge(&make_uninit(0));
    let future = execute_challenge(&make_future(0));
    println!("EMU-003 last_step=0: UninitializedData -> {uninit}, FutureRead -> {future}");
    assert!(!uninit);
    assert!(!future);
}
