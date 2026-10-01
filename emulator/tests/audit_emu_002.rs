//! EMU-002: the register section (incl. the non-zero initial SP) is reported as an
//! "uninitialized (zero)" range by `Program::get_uninitialized_ranges`, which is the
//! range set baked into the on-chain `uninitialized_challenge` script.
//!
//! * `emu002_honest_program_reads_initial_sp` (runs normally): precondition, shows that
//!   hello-world reads SP (x2) with `last_step == LAST_STEP_INIT` and value 0xE080_0000.
//! * The other tests assert the CORRECT behaviour and are `#[ignore]`d because they fail
//!   until EMU-002 is fixed. Run them with `--include-ignored`.

use bitcoin_script_riscv::riscv::challenges::execute_challenge;
use bitvmx_cpu_definitions::{
    challenge::ChallengeType, constants::LAST_STEP_INIT, memory::SectionDefinition,
    trace::TraceRWStep,
};
use emulator::{
    constants::{REGISTERS_BASE_ADDRESS, STACK_BASE_ADDRESS, STACK_SIZE},
    decision::{
        challenge::{
            prover_execute, prover_final_trace, prover_get_hashes_for_round,
            verifier_check_execution, verifier_choose_challenge, verifier_choose_segment,
            ForceChallenge, ForceCondition,
        },
        nary_search::NArySearchType,
    },
    executor::utils::{FailConfiguration, FailReads},
    loader::program_definition::ProgramDefinition,
};

const PDF: &str = "../docker-riscv32/riscv32/build/hello-world.yaml";
const SP_ADDRESS: u32 = REGISTERS_BASE_ADDRESS + 2 * 4; // x2
const INITIAL_SP: u32 = STACK_BASE_ADDRESS + STACK_SIZE; // 0xE080_0000

fn input() -> Vec<u8> {
    vec![17, 17, 17, 17]
}

fn temp_dir(name: &str) -> String {
    let dir = std::env::temp_dir()
        .join("bitvmx-audit-emu-002")
        .join(format!("{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // the emulator concatenates "{path}/checkpoint..." so use forward slashes + trailing sep
    format!("{}/", dir.to_string_lossy().replace('\\', "/"))
}

fn in_ranges(address: u32, sections: &SectionDefinition) -> bool {
    sections
        .ranges
        .iter()
        .any(|&(start, end)| start <= address && address <= end)
}

/// Returns the first honest trace step that reads SP with LAST_STEP_INIT, plus the read selector.
fn first_initial_sp_read() -> (TraceRWStep, u32) {
    let program_def = ProgramDefinition::from_config(PDF).unwrap();
    let dir = temp_dir("trace");
    let steps: Vec<u64> = (1..=64).collect();
    let (_res, trace) = program_def
        .execute_helper(&dir, &dir, input(), Some(steps), None, false)
        .unwrap();
    for (t, _hash) in trace {
        if t.read_1.address == SP_ADDRESS && t.read_1.last_step == LAST_STEP_INIT {
            return (t, 1);
        }
        if t.read_2.address == SP_ADDRESS && t.read_2.last_step == LAST_STEP_INIT {
            return (t, 2);
        }
    }
    panic!("no initial SP read found in the first 64 steps");
}

#[test]
fn emu002_honest_program_reads_initial_sp() {
    let (t, selector) = first_initial_sp_read();
    println!(
        "first initial-SP read: step {} selector {} read_1={:?} read_2={:?} pc=0x{:08x} opcode=0x{:08x}",
        t.step_number,
        selector,
        t.read_1,
        t.read_2,
        t.read_pc.pc.get_address(),
        t.read_pc.opcode
    );
    let read = if selector == 1 { &t.read_1 } else { &t.read_2 };
    assert_eq!(read.value, INITIAL_SP);
    assert_eq!(read.last_step, LAST_STEP_INIT);
}

/// Expected: the SP word must not be part of the "zero-initialized" ranges used by the
/// on-chain uninitialized_challenge, because its initial value is not zero.
#[test]
#[ignore = "EMU-002: fails until fixed"]
fn emu002_uninitialized_ranges_exclude_sp() {
    let program_def = ProgramDefinition::from_config(PDF).unwrap();
    let program = program_def.load_program().unwrap();
    let ranges = program.get_uninitialized_ranges(&program_def);
    println!("uninitialized ranges: {:x?}", ranges.ranges);
    println!("register sections:    {:x?}", program.register_sections.ranges);
    assert!(
        !in_ranges(SP_ADDRESS, &ranges),
        "SP (0x{:08x}, initial value 0x{:08x}) is reported as zero-initialized memory",
        SP_ADDRESS,
        INITIAL_SP
    );
}

/// Expected: a malicious verifier must NOT be able to win the uninitialized challenge
/// against a correct (honest) trace. Builds the exact script the client builds
/// (`uninitialized_challenge` with `get_uninitialized_ranges`) and runs it.
#[test]
#[ignore = "EMU-002: fails until fixed"]
fn emu002_malicious_verifier_cannot_win_against_honest_sp_read() {
    let program_def = ProgramDefinition::from_config(PDF).unwrap();
    let program = program_def.load_program().unwrap();
    let ranges = program.get_uninitialized_ranges(&program_def);

    let (t, read_selector) = first_initial_sp_read();
    let challenge = ChallengeType::UninitializedData {
        prover_read_1: t.read_1.clone(),
        prover_read_2: t.read_2.clone(),
        read_selector,
        sections: Some(ranges),
    };
    let verifier_wins = execute_challenge(&challenge);
    println!(
        "honest step {} challenged with UninitializedData (selector {}): verifier_wins = {}",
        t.step_number, read_selector, verifier_wins
    );
    assert!(
        !verifier_wins,
        "on-chain uninitialized_challenge accepts a correct SP read -> honest prover loses"
    );
}

/// Expected: if the prover lies about the initial SP (claims 0 with LAST_STEP_INIT), the
/// honest verifier must pick a challenge that the on-chain script accepts.
/// Runs the full emulator protocol (prover_execute .. verifier_choose_challenge).
#[test]
#[ignore = "EMU-002: fails until fixed"]
fn emu002_honest_verifier_wins_when_prover_lies_about_initial_sp() {
    let (t, selector) = first_initial_sp_read();
    let k = t.step_number;

    let fail_args: Vec<String> = vec![
        k.to_string(),
        format!("0x{:08x}", SP_ADDRESS),
        "0".to_string(),
        format!("0x{:08x}", SP_ADDRESS),
        LAST_STEP_INIT.to_string(),
    ];
    let fail_reads = if selector == 1 {
        FailReads::new(Some(&fail_args), None)
    } else {
        FailReads::new(None, Some(&fail_args))
    };
    let fail_prover = Some(FailConfiguration::new_fail_reads(fail_reads));

    let program_def = ProgramDefinition::from_config(PDF).unwrap();
    let nary_def = program_def.nary_def();
    let prover_dir = temp_dir("prover");
    let verifier_dir = temp_dir("verifier");

    let (_res, claim_last_step, claim_last_hash) = prover_execute(
        PDF,
        input(),
        &prover_dir,
        &prover_dir,
        true,
        fail_prover.clone(),
        false,
    )
    .unwrap();

    let to_challenge = verifier_check_execution(
        PDF,
        input(),
        &verifier_dir,
        &verifier_dir,
        claim_last_step,
        &claim_last_hash,
        ForceCondition::ValidInputWrongStepOrHash,
        None,
        false,
    )
    .unwrap();
    assert!(to_challenge.is_some(), "verifier should challenge");

    let mut v_decision = 0;
    for round in 1..nary_def.total_rounds() + 1 {
        let hashes = prover_get_hashes_for_round(
            PDF,
            &prover_dir,
            &prover_dir,
            round,
            v_decision,
            fail_prover.clone(),
            NArySearchType::ConflictStep,
        )
        .unwrap();
        v_decision = verifier_choose_segment(
            PDF,
            &verifier_dir,
            &verifier_dir,
            round,
            hashes,
            None,
            NArySearchType::ConflictStep,
        )
        .unwrap();
    }

    let (final_trace, step_hash, next_hash, _) = prover_final_trace(
        PDF,
        &prover_dir,
        &prover_dir,
        v_decision + 1,
        fail_prover,
    )
    .unwrap()
    .as_final_trace_with_hashes_and_step()
    .unwrap();
    println!(
        "disputed step {} read_1={:?} read_2={:?}",
        final_trace.step_number, final_trace.read_1, final_trace.read_2
    );
    assert_eq!(final_trace.step_number, k, "n-ary search should land on the lie");

    let challenge = verifier_choose_challenge(
        PDF,
        &verifier_dir,
        &verifier_dir,
        final_trace,
        &step_hash,
        &next_hash,
        ForceChallenge::No,
        None,
        true,
    )
    .unwrap();
    let verifier_wins = execute_challenge(&challenge);
    println!("verifier chose {:?} -> verifier_wins = {}", challenge, verifier_wins);
    assert!(
        verifier_wins,
        "honest verifier picked a challenge the script rejects -> lying prover wins"
    );
}
