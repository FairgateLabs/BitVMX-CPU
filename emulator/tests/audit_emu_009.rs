//! EMU-009: minor issues (rom commitment, register range off-by-one,
//! fault-injection underflows, unaligned entrypoint, decode unwrap, div/rem witness).
//!
//! Test kinds:
//! * `expected_*`  : assert the correct behavior. `#[ignore]`d while they fail because of the bug.
//! * `demo_*`      : demonstrate the current (buggy) behavior directly (pass today).
//! * `check_*`     : cross-checks that pass (item refuted / behavior confirmed correct).

use bitcoin_script_riscv::riscv::instruction_mapping::create_verification_script_mapping;
use bitvmx_cpu_definitions::trace::{TraceRWStep, TraceWrite};
use emulator::{
    constants::{REGISTERS_BASE_ADDRESS, STACK_BASE_ADDRESS, STACK_SIZE},
    executor::{
        fetcher::{execute_program, execute_step},
        utils::{FailConfiguration, FailExecute, FailOpcode, FailReads, FailWrite},
        verifier::verify_script,
    },
    loader::program::{generate_rom_commitment, load_elf, Program, Section},
    EmulatorError, ExecutionResult,
};

const HELLO: &str = "../docker-riscv32/riscv32/build/hello-world.elf";

fn temp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join("bitvmx_audit_emu_009").join(name);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(program: &mut Program, trace_list: Option<Vec<u64>>, limit: u64, fail: FailConfiguration) -> (ExecutionResult, Vec<(TraceRWStep, String)>) {
    execute_program(
        program, vec![], ".input", false, &None, Some(limit), true, false, false, false, false,
        false, trace_list, None, fail, false,
    )
}

// ---------------------------------------------------------------------------------------------
// Item 1: generate_rom_commitment
// ---------------------------------------------------------------------------------------------

#[test]
fn demo_item1_rom_commitment_errors_on_code_sections() {
    let program = load_elf(HELLO, false).unwrap();
    let res = generate_rom_commitment(&program);
    println!("generate_rom_commitment(hello-world) = {:?}", res.as_ref().map(|r| r.code.len()));
    assert!(matches!(
        res,
        Err(EmulatorError::ExecutionError(ExecutionResult::ReadFromExecuteOnlySection))
    ));
}

#[test]
#[ignore = "EMU-009: fails until fixed"]
fn expected_item1_rom_commitment_succeeds_for_hello_world() {
    let program = load_elf(HELLO, false).unwrap();
    let rom = generate_rom_commitment(&program).expect("rom commitment must succeed");
    assert!(!rom.code.is_empty());
    assert_eq!(rom.entrypoint, program.pc.get_address());
    // every committed opcode must equal what the executor fetches
    for c in &rom.code {
        assert_eq!(program.read_instruction(c.address).unwrap(), c.opcode);
    }
}

/// Related: the registers pseudo-section (non-code, non-initialized, SP != 0) is reported
/// as a zero-initialized range in the ROM commitment (same root cause as EMU-002).
#[test]
#[ignore = "EMU-009: fails until fixed"]
fn expected_item1_rom_commitment_zero_ranges_exclude_registers() {
    let mut program = Program::new(0x1000, REGISTERS_BASE_ADDRESS, STACK_BASE_ADDRESS + STACK_SIZE);
    program.add_section(Section::new("registers", REGISTERS_BASE_ADDRESS, 34 * 4, false, true, true));
    program.add_section(Section::new("bss", 0x2000, 16, false, true, false));
    let rom = generate_rom_commitment(&program).unwrap();
    println!("zero_initialized = {:x?}", rom.zero_initialized);
    assert!(
        !rom.zero_initialized.iter().any(|(s, _)| *s == REGISTERS_BASE_ADDRESS),
        "registers section reported as zero-initialized"
    );
}

// ---------------------------------------------------------------------------------------------
// Item 2: get_last_register_address off by one
// ---------------------------------------------------------------------------------------------

#[test]
#[ignore = "EMU-009: fails until fixed"]
fn expected_item2_last_register_address_is_aux2() {
    let program = Program::new(0x1000, REGISTERS_BASE_ADDRESS, 0);
    let last = program.registers.get_last_register_address();
    println!("get_last_register_address = 0x{:08x}", last);
    assert_eq!(last, REGISTERS_BASE_ADDRESS + 33 * 4);
}

fn fail_read_args(step: &str, addr: u32) -> Vec<String> {
    vec![step.into(), format!("0x{:x}", addr), "7".into(), format!("0x{:x}", addr), "0".into()]
}

#[test]
#[should_panic(expected = "index out of bounds")]
fn demo_item2_fail_read_one_past_last_register_panics() {
    let mut program = Program::new(0x1000, REGISTERS_BASE_ADDRESS, 0);
    let args = fail_read_args("1", REGISTERS_BASE_ADDRESS + 34 * 4); // 0xF000_0088
    let fr = FailReads::new(Some(&args), None);
    fr.patch_mem(&mut program); // step 0 == arg-1 -> patches -> registers.set(34, ..)
}

#[test]
#[should_panic(expected = "index out of bounds")]
fn demo_item2_fail_write_one_past_last_register_panics() {
    let mut program = Program::new(0x1000, REGISTERS_BASE_ADDRESS, 0);
    let args: Vec<String> = vec!["0".into(), "0xf0000088".into(), "7".into(), "0xf0000088".into()];
    let fw = FailWrite::new(&args);
    fw.patch_mem(&mut program);
}

#[test]
fn check_item2_aux2_register_is_patchable() {
    let mut program = Program::new(0x1000, REGISTERS_BASE_ADDRESS, 0);
    let args = fail_read_args("1", REGISTERS_BASE_ADDRESS + 33 * 4);
    FailReads::new(Some(&args), None).patch_mem(&mut program);
    assert_eq!(program.registers.get(33), 7);
}

// ---------------------------------------------------------------------------------------------
// Item 3: fault-injection underflows / off-by-one
// ---------------------------------------------------------------------------------------------

fn fake_trace_json() -> String {
    let mut t = TraceRWStep::default();
    t.step_number = 424242;
    t.trace_step.write_1 = TraceWrite::new(REGISTERS_BASE_ADDRESS + 4, 0xDEAD_BEEF);
    serde_json::to_string(&t).unwrap()
}

#[test]
#[should_panic(expected = "subtract with overflow")]
fn demo_item3_fail_read_new_step_zero_underflows() {
    let args = fail_read_args("0", REGISTERS_BASE_ADDRESS + 4);
    let _ = FailReads::new(Some(&args), None);
}

#[test]
#[should_panic(expected = "subtract with overflow")]
fn demo_item3_fail_execute_new_step_zero_underflows() {
    let _ = FailExecute::new(&["0".to_string(), fake_trace_json()]);
}

#[test]
#[should_panic(expected = "subtract with overflow")]
fn demo_item3_fetcher_fail_execute_step_zero_underflows() {
    let mut program = load_elf(HELLO, false).unwrap();
    let fe = FailExecute { step: 0, fake_trace: serde_json::from_str(&fake_trace_json()).unwrap() };
    let _ = run(&mut program, Some(vec![1]), 5, FailConfiguration::new_fail_execute(fe));
}

fn step_with_fake_trace(fe: FailExecute) -> Vec<u64> {
    let mut program = load_elf(HELLO, false).unwrap();
    let (_, traces) = run(&mut program, None, 10, FailConfiguration::new_fail_execute(fe));
    // the fake trace keeps its own step_number; locate its position (index i => step i+1,
    // index 0 is the initial default trace for step 0)
    traces
        .iter()
        .enumerate()
        .filter(|(_, (t, _))| t.trace_step.write_1.value == 0xDEAD_BEEF)
        .map(|(i, _)| i as u64)
        .collect()
}

#[test]
fn check_item3_fail_execute_struct_replaces_given_step() {
    let fe = FailExecute { step: 5, fake_trace: serde_json::from_str(&fake_trace_json()).unwrap() };
    let steps = step_with_fake_trace(fe);
    println!("FailExecute {{ step: 5 }} replaced step(s) {:?}", steps);
    assert_eq!(steps, vec![5]);
}

/// The CLI constructor subtracts 1 and the fetcher subtracts 1 again, so `--fail-execute 5`
/// replaces step 4 while `FailExecute { step: 5 }` (used by all tests) replaces step 5.
#[test]
#[ignore = "EMU-009: fails until fixed"]
fn expected_item3_fail_execute_cli_replaces_given_step() {
    let fe = FailExecute::new(&["5".to_string(), fake_trace_json()]);
    println!("FailExecute::new([\"5\", ..]).step = {}", fe.step);
    let steps = step_with_fake_trace(fe);
    println!("FailExecute::new(\"5\") replaced step(s) {:?}", steps);
    assert_eq!(steps, vec![5]);
}

// ---------------------------------------------------------------------------------------------
// Item 4: unaligned entry point
// ---------------------------------------------------------------------------------------------

fn hello_with_entry_offset(offset: u32) -> (String, u32) {
    let mut bytes = std::fs::read(HELLO).unwrap();
    assert_eq!(&bytes[0..4], b"\x7fELF");
    assert_eq!(bytes[4], 1, "ELF32 expected");
    let entry = u32::from_le_bytes(bytes[24..28].try_into().unwrap());
    let new_entry = entry + offset;
    bytes[24..28].copy_from_slice(&new_entry.to_le_bytes());
    let path = temp_dir("item4").join(format!("hello-entry-plus-{}.elf", offset));
    std::fs::write(&path, bytes).unwrap();
    (path.to_string_lossy().to_string(), entry)
}

#[test]
fn demo_item4_unaligned_entrypoint_is_loaded_and_misexecuted() {
    let (path, entry) = hello_with_entry_offset(2);
    let mut program = load_elf(&path, false).expect("loader accepts an unaligned e_entry");
    assert_eq!(program.pc.get_address(), entry + 2);
    let aligned_opcode = program.read_instruction(entry).unwrap();
    // read_instruction silently floors the unaligned address to the word below it
    let fetched = program.read_instruction(entry + 2).unwrap();
    assert_eq!(fetched, aligned_opcode);
    // pc is not a valid code address for the on-chain AddressesSections check
    assert!(!program.address_in_sections(entry + 2, &program.code_sections));

    let (res, traces) = run(&mut program, None, 10, FailConfiguration::default());
    let t1 = &traces[1].0;
    println!(
        "entry=0x{:08x} fetched=0x{:08x} (word at 0x{:08x}) result={:?} step1 trace={:?}",
        entry + 2, fetched, entry, res, t1
    );
    assert!(matches!(res, ExecutionResult::UnalignedJump(_)), "{:?}", res);
}

#[test]
#[ignore = "EMU-009: fails until fixed"]
fn expected_item4_load_elf_rejects_unaligned_entrypoint() {
    let (path, _) = hello_with_entry_offset(2);
    assert!(load_elf(&path, false).is_err());
}

#[test]
#[ignore = "EMU-009: fails until fixed"]
fn expected_item4_read_instruction_rejects_unaligned_pc() {
    let program = load_elf(HELLO, false).unwrap();
    let pc = program.pc.get_address();
    assert!(program.read_instruction(pc + 2).is_err());
}

// ---------------------------------------------------------------------------------------------
// Item 5: execute_step decode unwrap
// ---------------------------------------------------------------------------------------------

/// First candidate word that riscv_decode cannot decode.
fn bad_opcode() -> u32 {
    let c = [0xFFFF_FFFFu32, 0x0000_007F, 0x0000_0001, 0x0000_0000, 0x0000_0002];
    let bad = *c.iter().find(|&&w| riscv_decode::decode(w).is_err()).expect("no undecodable candidate");
    println!("undecodable word: 0x{:08x} -> {:?}", bad, riscv_decode::decode(bad));
    bad
}

fn program_with_pc_in_data() -> Program {
    let bad = bad_opcode();
    let mut program = Program::new(0x2000, REGISTERS_BASE_ADDRESS, 0);
    program.add_section(Section::new_with_data("data", vec![bad.to_be()], 0x2000, 4, false, true, true));
    program
}

#[test]
fn check_item5_non_code_pc_returns_error_normally() {
    let mut program = program_with_pc_in_data();
    let r = execute_step(&mut program, false, false, FailConfiguration::default());
    assert_eq!(r.unwrap_err(), ExecutionResult::ExecuteFromNonCodeSection);
}

#[test]
#[should_panic(expected = "Reserved")]
fn demo_item5_fail_memory_protection_panics_on_undecodable_word() {
    let mut program = program_with_pc_in_data();
    let _ = execute_step(&mut program, false, false, FailConfiguration::new_fail_memory_protection());
}

#[test]
#[should_panic(expected = "Reserved")]
fn demo_item5_fail_opcode_panics_on_undecodable_opcode() {
    let mut program = load_elf(HELLO, false).unwrap();
    let fo = FailOpcode { step: 1, opcode: bad_opcode() };
    let _ = execute_step(&mut program, false, false, FailConfiguration::new_fail_opcode(fo));
}

// ---------------------------------------------------------------------------------------------
// Item 6: div/rem witness vs. bitcoin-script-riscv scripts
// ---------------------------------------------------------------------------------------------

const RS1: u32 = 5;
const RS2: u32 = 6;
const RD: u32 = 7;

fn encode_m(funct3: u32) -> u32 {
    (1 << 25) | (RS2 << 20) | (RS1 << 15) | (funct3 << 12) | (RD << 7) | 0x33
}

#[derive(Clone, Copy, Debug)]
enum Op { Div, Divu, Rem, Remu }

impl Op {
    fn funct3(self) -> u32 { match self { Op::Div => 4, Op::Divu => 5, Op::Rem => 6, Op::Remu => 7 } }
    /// RISC-V spec semantics (independent oracle).
    fn expected(self, a: u32, b: u32) -> u32 {
        let (sa, sb) = (a as i32, b as i32);
        match self {
            Op::Div => if b == 0 { u32::MAX } else { sa.wrapping_div(sb) as u32 },
            Op::Rem => if b == 0 { a } else { sa.wrapping_rem(sb) as u32 },
            Op::Divu => if b == 0 { u32::MAX } else { a / b },
            Op::Remu => if b == 0 { a } else { a % b },
        }
    }
}

fn emulate(op: Op, a: u32, b: u32) -> TraceRWStep {
    let mut program = Program::new(0x1000, REGISTERS_BASE_ADDRESS, 0);
    program.add_section(Section::new_with_data("code", vec![encode_m(op.funct3()).to_be(), 0], 0x1000, 8, true, false, true));
    program.registers.set(RS1, a, 0);
    program.registers.set(RS2, b, 0);
    execute_step(&mut program, false, false, FailConfiguration::default()).unwrap()
}

fn cases() -> Vec<(u32, u32)> {
    let s = |x: i32| x as u32;
    let mut v = vec![
        (s(100), 0), (s(-100), 0), (0, 0), (s(i32::MIN), 0), (u32::MAX, 0), (s(i32::MAX), 0),
        (s(i32::MIN), s(-1)), (s(i32::MIN), 1), (s(i32::MIN), s(i32::MIN)), (s(i32::MIN), s(i32::MAX)),
        (s(i32::MAX), s(-1)), (s(-1), s(-1)), (s(-1), 1), (1, s(-1)), (0, s(-1)), (0, 1),
        (s(100), s(-6)), (s(-100), s(6)), (s(-100), s(-6)), (s(100), s(6)), (s(7), s(7)), (s(-7), s(7)),
        (u32::MAX, 1), (u32::MAX, u32::MAX), (0x8000_0000, 0xFFFF_FFFF), (1, u32::MAX), (s(5), s(-10)),
        // inputs listed in script_utils::test_div_rem_signed_fails_for_certain_inputs
        (s(-187100008), s(234592619)), (s(-1234054314), s(1784177589)), (s(-1371573435), s(1470078231)),
        (s(-1171857267), s(2089119674)), (s(-1340669410), s(1481685986)), (s(-1460440325), s(2066183210)),
        (s(931887209), s(-1960352008)), (s(857158955), s(-1419303977)), (s(34309962), s(-1398707796)),
    ];
    // deterministic pseudo-random cases (LCG)
    let mut x: u64 = 0x0123_4567_89ab_cdef;
    for _ in 0..24 {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let a = (x >> 32) as u32;
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let b = (x >> 32) as u32 >> ((x as u32) % 31);
        v.push((a, b));
    }
    v
}

fn check_div_rem(use_mapping: bool) {
    let mapping = use_mapping.then(|| create_verification_script_mapping(REGISTERS_BASE_ADDRESS));
    let mut failures = vec![];
    let mut total = 0;
    for (a, b) in cases() {
        for op in [Op::Div, Op::Divu, Op::Rem, Op::Remu] {
            total += 1;
            let t = emulate(op, a, b);
            let value = t.trace_step.write_1.value;
            if value != op.expected(a, b) {
                failures.push(format!("{:?}({},{}) emulator=0x{:08x} spec=0x{:08x}", op, a as i32, b as i32, value, op.expected(a, b)));
            }
            if let Err(e) = verify_script(&t, REGISTERS_BASE_ADDRESS, &mapping) {
                failures.push(format!("{:?}(0x{:08x},0x{:08x}) witness={:?} script rejected honest trace: {:?}", op, a, b, t.witness, e));
            }
        }
    }
    println!("checked {} div/rem traces (mapping={}), {} failures", total, use_mapping, failures.len());
    for f in &failures { println!("  {}", f); }
    assert!(failures.is_empty());
}

#[test]
fn check_item6_div_rem_witness_accepted_by_script() {
    check_div_rem(false);
}

#[test]
fn check_item6_div_rem_witness_accepted_by_instruction_mapping() {
    check_div_rem(true);
}

/// Sanity check that the witness is actually constrained: swapping it (quotient <-> remainder)
/// must make the script reject the trace in the regular (non special) case.
#[test]
fn check_item6_swapped_witness_is_rejected() {
    for (op, a, b) in [(Op::Div, 100u32, 6u32), (Op::Rem, 100, 6), (Op::Divu, 100, 7), (Op::Remu, 100, 7), (Op::Div, (-100i32) as u32, 6)] {
        let mut t = emulate(op, a, b);
        let w = t.witness.unwrap();
        t.witness = Some(t.trace_step.write_1.value);
        assert_ne!(Some(w), t.witness);
        let r = verify_script(&t, REGISTERS_BASE_ADDRESS, &None);
        println!("{:?}({},{}) swapped witness -> {:?}", op, a as i32, b as i32, r.is_err());
        assert!(r.is_err(), "{:?} with swapped witness accepted", op);
    }
}
