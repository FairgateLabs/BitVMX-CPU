//! EMU-007: `Program::load_input` panics (index out of bounds) when the input
//! does not fit in the input section.
//!
//! Test kinds:
//! * `demo_*`     : demonstrate the current (buggy) behavior; they PASS today.
//! * `expected_*` : assert the correct behavior; they FAIL today and are
//!                  `#[ignore]`d until the fix lands.
//! * `doc_*`      : document related, currently-correct semantics (pass).
//!
//! Run: cargo test -p emulator --test audit_emu_007 -- --nocapture --include-ignored

use std::panic::{catch_unwind, AssertUnwindSafe};

use bitvmx_cpu_definitions::constants::LAST_STEP_INIT;
use emulator::{
    decision::challenge::{verifier_check_execution, ForceCondition},
    loader::{
        program::{load_elf, Program},
        program_definition::ProgramDefinition,
    },
};

const ELF: &str = "../docker-riscv32/riscv32/build/hello-world.elf";
const YAML: &str = "../docker-riscv32/riscv32/build/hello-world.yaml";
const INPUT_SECTION: &str = ".input";

fn load() -> Program {
    load_elf(ELF, false).expect("load hello-world.elf")
}

/// (start, size in bytes) of the input section of hello-world.elf
fn input_section_info(program: &Program) -> (u32, u32) {
    let s = program
        .find_section_by_name(INPUT_SECTION)
        .expect("hello-world.elf has an .input section");
    (s.start, s.size)
}

fn temp_dir(name: &str) -> String {
    let dir = std::env::temp_dir()
        .join("bitvmx-audit-emu-007")
        .join(format!("{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir.to_string_lossy().replace('\\', "/")
}

// ---------------------------------------------------------------------------
// Demonstrations of the bug (pass today)
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "index out of bounds")]
fn demo_load_input_oversized_panics() {
    let mut program = load();
    let (_, size) = input_section_info(&program);
    println!("hello-world .input size = {} bytes", size);
    let input = vec![0x11u8; size as usize + 4];
    let _ = program.load_input(input, INPUT_SECTION, false);
}

/// Not even a whole extra word is needed: one extra byte is padded to a word.
#[test]
#[should_panic(expected = "index out of bounds")]
fn demo_load_input_one_extra_byte_panics() {
    let mut program = load();
    let (_, size) = input_section_info(&program);
    let input = vec![0x11u8; size as usize + 1];
    let _ = program.load_input(input, INPUT_SECTION, false);
}

/// Same panic through the protocol entry point used by the verifier.
#[test]
#[should_panic(expected = "index out of bounds")]
fn demo_verifier_check_execution_oversized_panics() {
    let (_, size) = input_section_info(&load());
    let dir = temp_dir("demo-verifier");
    let input = vec![0x11u8; size as usize + 4];
    let _ = verifier_check_execution(
        YAML,
        input,
        &dir,
        &dir,
        10,
        "00",
        ForceCondition::ValidInputWrongStepOrHash,
        None,
        false,
    );
}

// ---------------------------------------------------------------------------
// Expected behavior (fail today, ignored)
// ---------------------------------------------------------------------------

#[test]
#[ignore = "EMU-007: fails until fixed"]
fn expected_load_input_oversized_returns_error() {
    let mut program = load();
    let (_, size) = input_section_info(&program);
    for extra in [1usize, 3, 4, 1024] {
        let mut program_clone = load();
        let input = vec![0x11u8; size as usize + extra];
        let res = catch_unwind(AssertUnwindSafe(|| {
            program_clone.load_input(input, INPUT_SECTION, false)
        }));
        match res {
            Err(_) => panic!("load_input panicked for input of size+{} bytes", extra),
            Ok(r) => assert!(
                r.is_err(),
                "load_input accepted an input of size+{} bytes",
                extra
            ),
        }
        // input section must be left untouched on error
        let s = program_clone.find_section_by_name(INPUT_SECTION).unwrap();
        assert!(s.data.iter().all(|w| *w == 0), "partial write on error");
    }
    // sanity: exact fit still OK
    assert!(program
        .load_input(vec![0x11u8; size as usize], INPUT_SECTION, false)
        .is_ok());
}

#[test]
#[ignore = "EMU-007: fails until fixed"]
fn expected_verifier_check_execution_oversized_returns_error() {
    let (_, size) = input_section_info(&load());
    let dir = temp_dir("expected-verifier");
    let input = vec![0x11u8; size as usize + 4];
    let res = catch_unwind(|| {
        verifier_check_execution(
            YAML,
            input,
            &dir,
            &dir,
            10,
            "00",
            ForceCondition::ValidInputWrongStepOrHash,
            None,
            false,
        )
    });
    let res = res.expect("verifier_check_execution must not panic on an oversized input");
    println!("verifier_check_execution result: {:?}", res);
    assert!(res.is_err(), "an input that does not fit must be rejected");
}

// ---------------------------------------------------------------------------
// Related semantics (pass today)
// ---------------------------------------------------------------------------

/// Exact fit works, input words keep last_step == LAST_STEP_INIT and bytes land
/// in RISC-V little-endian memory order (byte i at address start + i), the same
/// convention used for ELF-initialized data.
#[test]
fn doc_exact_fit_last_step_and_byte_order() {
    let mut program = load();
    let (start, size) = input_section_info(&program);
    let mut input: Vec<u8> = (0..size).map(|i| (i % 251) as u8 + 1).collect();
    input[0..4].copy_from_slice(&[0x01, 0x02, 0x03, 0x04]);
    program
        .load_input(input, INPUT_SECTION, false)
        .expect("exact fit must load");
    assert_eq!(program.read_mem(start, false).unwrap(), 0x0403_0201);
    let last = start + size - 4;
    assert_eq!(program.get_last_step(start), LAST_STEP_INIT);
    assert_eq!(program.get_last_step(last), LAST_STEP_INIT);

    // Same thing hello-world expects: 0x11111111 read as an int.
    let pd = ProgramDefinition::from_config(YAML).unwrap();
    let dir = temp_dir("doc-exec");
    let (result, _, _) = pd
        .get_execution_result(vec![0x11; 4], &dir, &dir, None, false)
        .unwrap();
    println!("hello-world with 0x11111111: {:?}", result);
    assert!(matches!(result, emulator::ExecutionResult::Halt(0, _)));
}

/// The input length is not checked against the declared `inputs` sizes:
/// hello-world.yaml declares 4 bytes, an 8-byte input is accepted and its
/// second word lands in the range that `get_uninitialized_ranges` publishes as
/// "must be zero" (see EMU-006).
#[test]
fn doc_input_longer_than_declared_is_accepted() {
    let pd = ProgramDefinition::from_config(YAML).unwrap();
    let declared: u64 = pd.inputs.iter().map(|i| i.size).sum();
    let mut program = load();
    let (start, size) = input_section_info(&program);
    assert!(size as u64 >= declared + 4, "need room for an extra word");
    let input = vec![0xAAu8; declared as usize + 4];
    program
        .load_input(input, INPUT_SECTION, false)
        .expect("currently accepted");
    let extra_addr = start + declared as u32;
    assert_eq!(program.read_mem(extra_addr, false).unwrap(), 0xAAAA_AAAA);
    let uninit = program.get_uninitialized_ranges(&pd);
    assert!(uninit
        .ranges
        .iter()
        .any(|(s, e)| *s <= extra_addr && extra_addr <= *e));
    println!(
        "declared input = {} bytes, word at 0x{:08x} = 0xAAAAAAAA is inside an uninitialized range {:?}",
        declared, extra_addr, uninit.ranges
    );
}
