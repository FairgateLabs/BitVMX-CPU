//! EMU-012: register initial values as initialized data (alternative fix for EMU-002).
//!
//! The registers have loader-defined initial values (all 0 except SP = 0xE080_0000) but
//! the register section is published as "uninitialized (must be zero)" memory. The fix
//! under test makes the registers initialized data instead:
//!   * `get_uninitialized_ranges` excludes the register section;
//!   * `get_initialized_chunks` adds chunk(s) with the loader's initial register values;
//!   * `verifier_choose_challenge` routes a never-written register read to InitializedData.
//!
//! All tests assert the EXPECTED behaviour and are `#[ignore]`d because they fail on the
//! current tree (no register chunk exists). Run them with `--include-ignored`.

use bitcoin_script_riscv::riscv::challenges::execute_challenge;
use bitvmx_cpu_definitions::{
    challenge::ChallengeType,
    constants::{CHUNK_SIZE, LAST_STEP_INIT},
    memory::{Chunk, SectionDefinition},
    trace::{TraceRWStep, TraceRead},
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
    loader::{program::load_elf, program_definition::ProgramDefinition},
};

const PDF: &str = "../docker-riscv32/riscv32/build/hello-world.yaml";
const ELFS: [&str; 2] = [
    "../docker-riscv32/riscv32/build/hello-world.elf",
    "../docker-riscv32/verifier/build/zkverifier-new-mul.elf",
];
const NUM_REGISTERS: u32 = 34; // 32 GP + 2 aux
const SP_ADDRESS: u32 = REGISTERS_BASE_ADDRESS + 2 * 4; // x2
const INITIAL_SP: u32 = STACK_BASE_ADDRESS + STACK_SIZE; // 0xE080_0000

fn input() -> Vec<u8> {
    vec![17, 17, 17, 17]
}

fn temp_dir(name: &str) -> String {
    let dir = std::env::temp_dir()
        .join("bitvmx-audit-emu-012")
        .join(format!("{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    format!("{}/", dir.to_string_lossy().replace('\\', "/"))
}

fn in_ranges(address: u32, sections: &SectionDefinition) -> bool {
    sections
        .ranges
        .iter()
        .any(|&(start, end)| start <= address && address <= end)
}

/// Same selection as `find_chunk_index` in `decision/challenge.rs`.
fn find_chunk(chunks: &[Chunk], address: u32) -> Option<usize> {
    chunks.iter().position(|c| {
        c.base_addr <= address && address < c.base_addr + c.data.len() as u32 * 4
    })
}

fn expected_initial_register(idx: u32) -> u32 {
    if idx == 2 {
        INITIAL_SP
    } else {
        0
    }
}

/// First honest step that reads SP with LAST_STEP_INIT, plus the read selector.
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

/// Builds the InitializedData challenge exactly as the emulator / client would: chunk chosen
/// from `get_initialized_chunks` by address.
fn initialized_challenge_for(read_1: TraceRead, read_2: TraceRead, read_selector: u32) -> ChallengeType {
    let program_def = ProgramDefinition::from_config(PDF).unwrap();
    let program = program_def.load_program().unwrap();
    let chunks = program.get_initialized_chunks(CHUNK_SIZE);
    let address = if read_selector == 1 { read_1.address } else { read_2.address };
    let idx = find_chunk(&chunks, address)
        .unwrap_or_else(|| panic!("no initialized chunk covers register address 0x{address:08x}"));
    ChallengeType::InitializedData {
        prover_read_1: read_1,
        prover_read_2: read_2,
        read_selector,
        chunk_index: idx as u32,
        chunk: Some(chunks[idx].clone()),
    }
}

#[test]
#[ignore = "EMU-012: fails until fixed"]
fn emu012_registers_not_in_uninitialized_ranges() {
    let program_def = ProgramDefinition::from_config(PDF).unwrap();
    let program = program_def.load_program().unwrap();
    let ranges = program.get_uninitialized_ranges(&program_def);
    println!("uninitialized ranges: {:x?}", ranges.ranges);
    let inside: Vec<u32> = (0..NUM_REGISTERS)
        .map(|i| REGISTERS_BASE_ADDRESS + 4 * i)
        .filter(|a| in_ranges(*a, &ranges))
        .collect();
    assert!(inside.is_empty(), "register addresses published as zero-initialized: {inside:x?}");
}

#[test]
#[ignore = "EMU-012: fails until fixed"]
fn emu012_initialized_chunks_hold_initial_registers() {
    for elf in ELFS {
        let program = load_elf(elf, false).unwrap();
        let chunks = program.get_initialized_chunks(CHUNK_SIZE);
        for i in 0..NUM_REGISTERS {
            let address = REGISTERS_BASE_ADDRESS + 4 * i;
            let idx = find_chunk(&chunks, address)
                .unwrap_or_else(|| panic!("{elf}: no initialized chunk covers register x{i} (0x{address:08x})"));
            let chunk = &chunks[idx];
            let value = chunk.data[((address - chunk.base_addr) / 4) as usize];
            assert_eq!(
                value,
                expected_initial_register(i),
                "{elf}: register {i} committed as 0x{value:08x}"
            );
        }
        println!("{elf}: all {NUM_REGISTERS} registers committed with their initial values");
    }
}

/// A malicious verifier must not win either static-data challenge against the honest SP read.
#[test]
#[ignore = "EMU-012: fails until fixed"]
fn emu012_honest_sp_read_not_challengeable() {
    let program_def = ProgramDefinition::from_config(PDF).unwrap();
    let program = program_def.load_program().unwrap();
    let (t, selector) = first_initial_sp_read();

    let uninit = ChallengeType::UninitializedData {
        prover_read_1: t.read_1.clone(),
        prover_read_2: t.read_2.clone(),
        read_selector: selector,
        sections: Some(program.get_uninitialized_ranges(&program_def)),
    };
    let uninit_wins = execute_challenge(&uninit);

    let init = initialized_challenge_for(t.read_1.clone(), t.read_2.clone(), selector);
    let init_wins = execute_challenge(&init);

    println!(
        "honest step {}: UninitializedData -> {uninit_wins}, InitializedData -> {init_wins}",
        t.step_number
    );
    assert!(!uninit_wins, "UninitializedData succeeds against the honest SP read");
    assert!(!init_wins, "InitializedData succeeds against the honest SP read");
}

/// Wrong initial values of any register must be provable with InitializedData.
#[test]
#[ignore = "EMU-012: fails until fixed"]
fn emu012_wrong_initial_register_is_challengeable() {
    for (idx, lie) in [(2u32, 0u32), (2, INITIAL_SP + 4), (5, 7), (33, 1)] {
        let read = TraceRead::new(REGISTERS_BASE_ADDRESS + 4 * idx, lie, LAST_STEP_INIT);
        let challenge = initialized_challenge_for(read, TraceRead::default(), 1);
        let wins = execute_challenge(&challenge);
        println!("register x{idx} claimed 0x{lie:08x} -> verifier_wins = {wins}");
        assert!(wins, "lie about register x{idx} initial value not provable");
    }
}

/// End to end: the prover lies "SP = 0" at its first read; the honest verifier must pick
/// InitializedData and the script must accept it.
#[test]
#[ignore = "EMU-012: fails until fixed"]
fn emu012_honest_verifier_wins_when_prover_lies_about_initial_sp() {
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

    let (_res, claim_last_step, claim_last_hash) =
        prover_execute(PDF, input(), &prover_dir, &prover_dir, true, fail_prover.clone(), false)
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

    let (final_trace, step_hash, next_hash, _) =
        prover_final_trace(PDF, &prover_dir, &prover_dir, v_decision + 1, fail_prover)
            .unwrap()
            .as_final_trace_with_hashes_and_step()
            .unwrap();
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
        matches!(challenge, ChallengeType::InitializedData { .. }),
        "expected InitializedData for a never-written register read"
    );
    assert!(verifier_wins, "honest verifier picked a challenge the script rejects");
}
