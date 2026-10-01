//! EMU-001: single-step trace query returns `TraceRWStep::default()` when the
//! requested step is a non-zero multiple of `CHECKPOINT_SIZE`.
//!
//! See docs/emulator-audit/tickets/EMU-001-checkpoint-step-default-trace.md
//!
//! All tests here assert the *expected* (correct) behaviour. The ones that fail
//! because of the bug are marked `#[ignore = "EMU-001: fails until fixed"]`.

use std::path::PathBuf;

use bitvmx_cpu_definitions::trace::{validate_step_hash, TraceRWStep};
use elf::{endian::LittleEndian, ElfBytes};
use emulator::{
    executor::{fetcher::execute_program, utils::FailConfiguration},
    loader::{
        program::{load_elf, CHECKPOINT_SIZE},
        program_definition::ProgramDefinition,
    },
};

const HELLO_ELF: &str = "../docker-riscv32/riscv32/build/hello-world.elf";

/// Fresh, unique temp dir (forward slashes: ProgramDefinition splits paths on '/').
fn temp_dir(name: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir: PathBuf = std::env::temp_dir().join(format!(
        "audit_emu_001_{}_{}_{}",
        name,
        std::process::id(),
        nanos
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir.to_string_lossy().replace('\\', "/")
}

/// Writes `<dir>/prog.elf` and `<dir>/prog.yaml` and returns the yaml path.
fn write_program(dir: &str, elf_bytes: &[u8], max_steps: u64) -> String {
    std::fs::write(format!("{dir}/prog.elf"), elf_bytes).unwrap();
    let yaml = format!(
        "elf: prog.elf\nnary_search: 8\nmax_steps: {max_steps}\ninput_section_name: .input\ninputs:\n  - size: 4\n    owner: prover\n"
    );
    let yaml_path = format!("{dir}/prog.yaml");
    std::fs::write(&yaml_path, yaml).unwrap();
    yaml_path
}

/// hello-world.elf with the two instructions at the entrypoint replaced by an
/// infinite loop: `addi t0, t0, 1 ; jal x0, -4`. Never halts, so it can be run
/// past CHECKPOINT_SIZE steps (stopped by `max_steps`).
fn infinite_loop_elf() -> Vec<u8> {
    let mut bytes = std::fs::read(HELLO_ELF).unwrap();
    let file = ElfBytes::<LittleEndian>::minimal_parse(&bytes).unwrap();
    let entry = file.ehdr.e_entry;
    let shdrs = file.section_headers().unwrap();
    let text = shdrs
        .iter()
        .find(|s| entry >= s.sh_addr && entry + 8 <= s.sh_addr + s.sh_size)
        .expect("section containing entrypoint");
    let off = (text.sh_offset + (entry - text.sh_addr)) as usize;
    bytes[off..off + 4].copy_from_slice(&0x0012_8293u32.to_le_bytes()); // addi t0,t0,1
    bytes[off + 4..off + 8].copy_from_slice(&0xffdf_f06fu32.to_le_bytes()); // jal x0,-4
    bytes
}

fn is_default_trace(t: &TraceRWStep) -> bool {
    serde_json::to_string(t).unwrap() == serde_json::to_string(&TraceRWStep::default()).unwrap()
}

/// Fast check with a hand-made checkpoint: the state after a few real steps of
/// hello-world is relabelled as step CHECKPOINT_SIZE and stored as
/// `checkpoint.50000000.json`. `get_trace_step(CHECKPOINT_SIZE)` must never return
/// an empty/default trace (it should either return the real trace of that step,
/// or fail). With the bug it returns `Ok(TraceRWStep::default())`.
#[test]
#[ignore = "EMU-001: fails until fixed"]
fn emu_001_get_trace_step_on_fake_checkpoint_boundary_is_not_default() {
    let dir = temp_dir("fake");
    let yaml = write_program(&dir, &std::fs::read(HELLO_ELF).unwrap(), 4 * CHECKPOINT_SIZE);
    let def = ProgramDefinition::from_config(&yaml).unwrap();

    let mut program = def.load_program().unwrap();
    let (_res, _trace) = execute_program(
        &mut program,
        vec![],
        &def.input_section_name,
        false,
        &None,
        Some(5),
        false,
        false,
        false,
        false,
        false,
        false,
        None,
        None,
        FailConfiguration::default(),
        false,
    );
    program.step = CHECKPOINT_SIZE;
    program.serialize_to_file(&dir);

    let res = def.get_trace_step(&dir, &dir, vec![], CHECKPOINT_SIZE, None);
    println!("get_trace_step({CHECKPOINT_SIZE}) = {:?}", res.as_ref().map(|t| t.to_csv()));
    if let Ok(t) = &res {
        assert!(
            !is_default_trace(t),
            "get_trace_step({CHECKPOINT_SIZE}) returned TraceRWStep::default()"
        );
        assert_eq!(t.step_number, CHECKPOINT_SIZE);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Real end-to-end check (runs ~50M emulator steps, slow in debug builds).
///
/// A reference run from step 0 produces the real traces/hashes of steps
/// C-1, C, C+1 (C = CHECKPOINT_SIZE) and writes the real `checkpoint.C.json`,
/// exactly as `get_execution_result` would. Then the protocol helpers are queried.
#[test]
#[ignore = "EMU-001: fails until fixed (also slow: ~50M steps)"]
fn emu_001_get_trace_step_at_checkpoint_size_matches_real_trace() {
    let c = CHECKPOINT_SIZE;
    let dir = temp_dir("real");
    let yaml = write_program(&dir, &infinite_loop_elf(), c + 10);
    let def = ProgramDefinition::from_config(&yaml).unwrap();

    // Reference run from step 0, writing the real checkpoint at step C.
    let mut program = def.load_program().unwrap();
    let t0 = std::time::Instant::now();
    let (res, reference) = execute_program(
        &mut program,
        vec![],
        &def.input_section_name,
        false,
        &Some(dir.clone()),
        Some(c + 1),
        true,
        false,
        false,
        false,
        false,
        false,
        Some(vec![c - 1, c, c + 1]),
        None,
        FailConfiguration::default(),
        false,
    );
    println!("reference run: {:?} in {:?}", res, t0.elapsed());
    assert_eq!(reference.len(), 3);
    let (ref_prev, ref_cur, ref_next) = (&reference[0], &reference[1], &reference[2]);
    assert_eq!(ref_cur.0.step_number, c);
    assert!(std::path::Path::new(&format!("{dir}/checkpoint.{c}.json")).exists());
    // Sanity: the real trace of step C links h_{C-1} -> h_C.
    assert!(validate_step_hash(&ref_prev.1, &ref_cur.0.trace_step, &ref_cur.1));
    // ... and a default trace does not (this is what the verifier would TraceHash-challenge).
    assert!(!validate_step_hash(&ref_prev.1, &TraceRWStep::default().trace_step, &ref_cur.1));

    // (a) Round hashes / multi-step query starting at C: hashes must match.
    let (_r, q) = def
        .execute_helper(&dir, &dir, vec![], Some(vec![c, c + 1]), None, false)
        .unwrap();
    println!("execute_helper([C, C+1]) = {:?}", q.iter().map(|t| (t.0.step_number, &t.1)).collect::<Vec<_>>());
    assert_eq!(q.len(), 2);
    assert_eq!(q[0].1, ref_cur.1, "hash of step C");
    assert_eq!(q[1].1, ref_next.1, "hash of step C+1");
    assert_eq!(
        serde_json::to_string(&q[1].0).unwrap(),
        serde_json::to_string(&ref_next.0).unwrap(),
        "trace of step C+1"
    );

    // (b) The single-step query used by prover_final_trace and by
    // verifier_choose_challenge_for_read_challenge.
    let (_r, single) = def
        .execute_helper(&dir, &dir, vec![], Some(vec![c]), None, false)
        .unwrap();
    println!("execute_helper([C])[0] = {} ; {}", single[0].0.to_csv(), single[0].1);
    println!("reference trace C      = {} ; {}", ref_cur.0.to_csv(), ref_cur.1);
    assert_eq!(single[0].1, ref_cur.1, "hash of step C");

    let trace = def.get_trace_step(&dir, &dir, vec![], c, None).unwrap();
    assert!(!is_default_trace(&trace), "get_trace_step(C) returned TraceRWStep::default()");
    assert_eq!(
        serde_json::to_string(&trace).unwrap(),
        serde_json::to_string(&ref_cur.0).unwrap(),
        "get_trace_step(C) must equal the real trace of step C"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Non-boundary control: the same query for a step that is NOT a checkpoint
/// multiple returns the real trace (passes today).
#[test]
fn emu_001_control_get_trace_step_non_boundary_is_real() {
    let dir = temp_dir("control");
    let yaml = write_program(&dir, &std::fs::read(HELLO_ELF).unwrap(), 4 * CHECKPOINT_SIZE);
    let def = ProgramDefinition::from_config(&yaml).unwrap();
    let trace = def.get_trace_step(&dir, &dir, vec![], 7, None).unwrap();
    assert!(!is_default_trace(&trace));
    assert_eq!(trace.step_number, 7);

    let mut program = load_elf(&format!("{dir}/prog.elf"), false).unwrap();
    let (_r, reference) = execute_program(
        &mut program,
        vec![],
        &def.input_section_name,
        false,
        &None,
        None,
        true,
        false,
        false,
        false,
        false,
        false,
        Some(vec![7]),
        None,
        FailConfiguration::default(),
        false,
    );
    assert_eq!(
        serde_json::to_string(&trace).unwrap(),
        serde_json::to_string(&reference[0].0).unwrap()
    );
    let _ = std::fs::remove_dir_all(&dir);
}
