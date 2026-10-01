//! EMU-006: `Program::get_uninitialized_ranges` edge cases around the input section.
//!
//! Tests:
//! * `emu006_input_exactly_fills_section_real_elf` (BUG test, ignored until fixed):
//!   hello-world.elf has a 0x2000-byte `.input` section. A program definition whose
//!   inputs total exactly 0x2000 bytes executes fine, but `get_uninitialized_ranges`
//!   (called by the client while building the "uninitialized" challenge leaf) panics.
//! * `emu006_demo_exact_fill_panics` (DEMONSTRATION, `#[should_panic]`): same panic on a
//!   synthetic program. Starts failing once the bug is fixed (delete it then).
//! * `emu006_tail_ranges_and_script_regression` (regression guard, passes before and
//!   after the fix): the tail range for input_size < section size is correct and the
//!   on-chain `uninitialized_challenge` script accepts/rejects at the right boundaries.
//! * `emu006_progbits_input_tail_not_uninitialized` (BUG test, ignored until fixed): if the
//!   input section is PROGBITS (initialized), its tail is still reported as uninitialized,
//!   so a dishonest verifier can win an UninitializedData challenge against an honest read
//!   of non-zero ELF data.
//! * `emu006_progbits_input_words_not_initialized_chunks` (BUG test, ignored, related
//!   follow-up): with a PROGBITS input section, the input words are also part of the
//!   `InitializedData` chunks (with ELF contents instead of the actual input), so a
//!   dishonest verifier can win an InitializedData challenge against an honest input read.
//! * `emu006_demo_missing_input_section_panics` (DEMONSTRATION, `#[should_panic]`): a wrong
//!   `input_section_name` panics instead of returning an error.

use std::path::PathBuf;

use bitcoin_script_riscv::riscv::challenges::execute_challenge;
use bitvmx_cpu_definitions::{
    challenge::ChallengeType,
    constants::{CHUNK_SIZE, LAST_STEP_INIT},
    memory::SectionDefinition,
    trace::TraceRead,
};
use emulator::{
    constants::{REGISTERS_BASE_ADDRESS, STACK_BASE_ADDRESS, STACK_SIZE},
    loader::{
        program::{Program, Section},
        program_definition::{InputDefinition, ProgramDefinition},
    },
    ExecutionResult,
};

const HELLO_ELF: &str = "../docker-riscv32/riscv32/build/hello-world.elf";

const INPUT_START: u32 = 0xAA00_0000;
const INPUT_SIZE: u32 = 0x40; // 16 words
const BSS_START: u32 = 0xA000_0000;
const BSS_SIZE: u32 = 0x100;

fn tmp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir()
        .join("bitvmx-audit-emu-006")
        .join(format!("{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn fwd(p: &PathBuf) -> String {
    // ProgramDefinition::load_program splits the config path on '/'
    p.to_string_lossy().replace('\\', "/")
}

fn def_with_inputs(sizes: &[u64]) -> ProgramDefinition {
    ProgramDefinition {
        config_path: String::new(),
        elf: String::new(),
        nary_search: 8,
        max_steps: 2000,
        input_section_name: ".input".to_string(),
        inputs: sizes
            .iter()
            .map(|s| InputDefinition {
                size: *s,
                owner: "prover".to_string(),
            })
            .collect(),
    }
}

/// Synthetic program: a NOBITS `.bss` and an `.input` section (NOBITS or PROGBITS with
/// the given little-endian word values).
fn synthetic_program(input_initialized: bool, input_words: Option<Vec<u32>>) -> Program {
    let mut program = Program::new(0x8000_0000, REGISTERS_BASE_ADDRESS, STACK_BASE_ADDRESS + STACK_SIZE);
    program.add_section(Section::new_with_data(
        ".bss",
        vec![0; (BSS_SIZE / 4) as usize],
        BSS_START,
        BSS_SIZE,
        false,
        true,
        false,
    ));
    let data = input_words
        .unwrap_or_else(|| vec![0; (INPUT_SIZE / 4) as usize])
        .into_iter()
        // memory words are stored big-endian encoded (see Program::read_mem)
        .map(|v| v.to_be())
        .collect::<Vec<_>>();
    assert_eq!(data.len() as u32, INPUT_SIZE / 4);
    program.add_section(Section::new_with_data(
        ".input",
        data,
        INPUT_START,
        INPUT_SIZE,
        false,
        true,
        input_initialized,
    ));
    program
}

fn uninit_script_accepts(sections: &SectionDefinition, addr: u32, value: u32) -> bool {
    // a single read (selector 1) at LAST_STEP_INIT with the given value
    let read = TraceRead::new(addr, value, LAST_STEP_INIT);
    let other = TraceRead::new(BSS_START, 0, LAST_STEP_INIT);
    execute_challenge(&ChallengeType::UninitializedData {
        prover_read_1: read,
        prover_read_2: other,
        read_selector: 1,
        sections: Some(sections.clone()),
    })
}

fn any_range_contains(sections: &SectionDefinition, addr: u32) -> bool {
    sections
        .ranges
        .iter()
        .any(|&(start, end)| start <= addr && addr <= end)
}

#[test]
#[ignore = "EMU-006: fails until fixed"]
fn emu006_input_exactly_fills_section_real_elf() {
    let dir = tmp_dir("exact-fill");
    std::fs::copy(HELLO_ELF, dir.join("hello-world.elf")).unwrap();
    let yaml = dir.join("audit_emu_006.yaml");
    // two inputs of 0x1000 bytes = 0x2000 = size of .input in hello-world.elf
    std::fs::write(
        &yaml,
        "elf: hello-world.elf\nnary_search: 8\nmax_steps: 2000\ninput_section_name: .input\n\
         inputs:\n  - size: 4096\n    owner: prover\n  - size: 4096\n    owner: verifier\n",
    )
    .unwrap();
    let def = ProgramDefinition::from_config(&fwd(&yaml)).unwrap();

    let program = def.load_program().unwrap();
    let input_section = program.find_section_by_name(".input").unwrap();
    let total: u64 = def.inputs.iter().map(|i| i.size).sum();
    assert_eq!(input_section.size as u64, total, "fixture: inputs fill .input exactly");
    let (in_start, in_end) = input_section.range();

    // The configuration is legitimate: the emulator runs it without problem.
    let checkpoints = dir.join("checkpoints");
    let (result, last_step, _) = def
        .get_execution_result(vec![0x11; total as usize], &fwd(&checkpoints), &fwd(&checkpoints), None, false)
        .unwrap();
    println!("execution result: {:?} last_step={}", result, last_step);
    assert!(matches!(result, ExecutionResult::Halt(_, _)));

    // Expected: no panic, and no part of the input section is reported as uninitialized.
    let ranges = program.get_uninitialized_ranges(&def);
    println!("uninitialized ranges: {:x?}", ranges.ranges);
    assert!(!any_range_contains(&ranges, in_start));
    assert!(!any_range_contains(&ranges, in_end - 3));
}

#[test]
#[should_panic(expected = "exceeds input section size")]
fn emu006_demo_exact_fill_panics() {
    // DEMONSTRATION of the current (buggy) behaviour: delete once EMU-006 is fixed.
    let program = synthetic_program(false, None);
    let def = def_with_inputs(&[INPUT_SIZE as u64]);
    let _ = program.get_uninitialized_ranges(&def);
}

#[test]
fn emu006_tail_ranges_and_script_regression() {
    let program = synthetic_program(false, None);
    let end = INPUT_START + INPUT_SIZE - 1;

    // no inputs: whole input section is uninitialized
    let r = program.get_uninitialized_ranges(&def_with_inputs(&[]));
    assert!(r.ranges.contains(&(BSS_START, BSS_START + BSS_SIZE - 1)));
    assert!(r.ranges.contains(&(INPUT_START, end)));

    // one word of input
    let r = program.get_uninitialized_ranges(&def_with_inputs(&[4]));
    assert!(r.ranges.contains(&(INPUT_START + 4, end)));
    assert!(!any_range_contains(&r, INPUT_START));

    // input leaves exactly one word free: tail range is (end-3, end)
    let r = program.get_uninitialized_ranges(&def_with_inputs(&[(INPUT_SIZE - 4) as u64]));
    println!("ranges with one free word: {:x?}", r.ranges);
    assert!(r.ranges.contains(&(end - 3, end)));
    // script: a non-zero init read of the free word is a valid challenge...
    assert!(uninit_script_accepts(&r, end - 3, 0x1234));
    // ...a zero read is not...
    assert!(!uninit_script_accepts(&r, end - 3, 0));
    // ...and the last input word cannot be challenged as uninitialized
    assert!(!uninit_script_accepts(&r, end - 7, 0x1234));

    // multiple inputs are summed
    let r = program.get_uninitialized_ranges(&def_with_inputs(&[8, 8]));
    assert!(r.ranges.contains(&(INPUT_START + 16, end)));
    assert!(!uninit_script_accepts(&r, INPUT_START + 12, 0x1234));
    assert!(uninit_script_accepts(&r, INPUT_START + 16, 0x1234));
}

#[test]
#[ignore = "EMU-006: fails until fixed"]
fn emu006_progbits_input_tail_not_uninitialized() {
    // PROGBITS input section (e.g. a C buffer declared with __attribute__((section(".input")))
    // and an initializer) whose tail holds non-zero ELF data.
    let mut words = vec![0u32; (INPUT_SIZE / 4) as usize];
    let tail_addr = INPUT_START + INPUT_SIZE - 4;
    *words.last_mut().unwrap() = 0xCAFE_BABE;
    let program = synthetic_program(true, Some(words));
    let def = def_with_inputs(&[8]);

    // The honest prover reads the ELF value from the (never written) tail word.
    assert_eq!(program.read_mem(tail_addr, false).unwrap(), 0xCAFE_BABE);

    let ranges = program.get_uninitialized_ranges(&def);
    println!("uninitialized ranges: {:x?}", ranges.ranges);
    let dishonest_win = uninit_script_accepts(&ranges, tail_addr, 0xCAFE_BABE);
    println!("UninitializedData challenge against honest tail read accepted: {}", dishonest_win);

    // Expected: the tail of an initialized input section is not "uninitialized".
    assert!(!any_range_contains(&ranges, tail_addr));
    assert!(!dishonest_win);
}

#[test]
#[ignore = "EMU-006 (related follow-up): fails until fixed"]
fn emu006_progbits_input_words_not_initialized_chunks() {
    // PROGBITS input section with all-zero ELF content (what GCC emits for a buffer
    // declared with __attribute__((section(".input")))); the actual input overwrites it.
    // The client builds the InitializedData leaves at setup from the freshly loaded ELF
    // (no input loaded), see rust-bitvmx-client challenge.rs ("initialized" leaves).
    let setup_program = synthetic_program(true, None);
    let mut program = synthetic_program(true, None);
    let def = def_with_inputs(&[8]);
    program
        .load_input(vec![0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0], ".input", false)
        .unwrap();
    // honest prover reads the input word at INPUT_START (never written => LAST_STEP_INIT)
    let value = program.read_mem(INPUT_START, false).unwrap();
    assert_eq!(value, 0x1234_5678);

    let chunks = setup_program.get_initialized_chunks(CHUNK_SIZE);
    let chunk_index = chunks
        .iter()
        .position(|c| c.range().0 <= INPUT_START && INPUT_START <= c.range().1);
    println!("input word is in initialized chunk: {:?}", chunk_index);

    let dishonest_win = chunk_index.is_some_and(|idx| {
        execute_challenge(&ChallengeType::InitializedData {
            prover_read_1: TraceRead::new(INPUT_START, value, LAST_STEP_INIT),
            prover_read_2: TraceRead::new(BSS_START, 0, LAST_STEP_INIT),
            read_selector: 1,
            chunk_index: idx as u32,
            chunk: Some(chunks[idx].clone()),
        })
    });
    println!("InitializedData challenge against honest input read accepted: {}", dishonest_win);
    let _ = def;
    assert!(!dishonest_win);
}

#[test]
#[should_panic(expected = "Input section not found")]
fn emu006_demo_missing_input_section_panics() {
    // DEMONSTRATION of the current behaviour: a wrong section name panics.
    let program = synthetic_program(false, None);
    let mut def = def_with_inputs(&[4]);
    def.input_section_name = ".inputs".to_string();
    let _ = program.get_uninitialized_ranges(&def);
}
