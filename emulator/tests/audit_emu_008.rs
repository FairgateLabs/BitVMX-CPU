//! EMU-008: step queries (`trace_list` mode) keep executing and hashing until
//! halt / error / `max_steps`, even after the last requested step was recorded.
//!
//! Tests:
//! * `emu008_trace_list_query_stops_after_last_requested_step` (BUG test, ignored
//!   until fixed): a query for step 10 of a long-running program must not run
//!   the program up to `max_steps`.
//! * `emu008_trace_list_semantics_hello_world` (regression guard, passes before
//!   and after the fix): traces/hashes/padding obtained in trace-list mode equal
//!   those of a full run, including queries past the halt step.
//! * `emu008_measure_step_query_cost` (measurement, ignored, run with --release):
//!   timing of an early step query vs. the program length.

use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

use emulator::{
    executor::{fetcher::execute_program, utils::FailConfiguration},
    loader::{program::load_elf, program_definition::ProgramDefinition},
    ExecutionResult,
};

const ZK_ELF: &str = "../docker-riscv32/verifier/build/zkverifier-new-mul.elf";
const HELLO_YAML: &str = "../docker-riscv32/riscv32/build/hello-world.yaml";

fn tmp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir()
        .join("bitvmx-audit-emu-008")
        .join(format!("{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn fwd(p: &PathBuf) -> String {
    // ProgramDefinition::load_program splits the config path on '/'
    p.to_string_lossy().replace('\\', "/")
}

/// Writes a program definition for the zk verifier ELF (no inputs needed) with the given max_steps.
fn zk_program_definition(name: &str, max_steps: u64) -> (ProgramDefinition, String) {
    let dir = tmp_dir(name);
    std::fs::copy(ZK_ELF, dir.join("zk.elf")).unwrap();
    let yaml = dir.join("zk.yaml");
    std::fs::write(
        &yaml,
        format!(
            "elf: zk.elf\nnary_search: 8\nmax_steps: {max_steps}\ninput_section_name: .input\ninputs: []\n"
        ),
    )
    .unwrap();
    let def = ProgramDefinition::from_config(&fwd(&yaml)).unwrap();
    (def, fwd(&dir))
}

fn result_step(r: &ExecutionResult) -> Option<u64> {
    match r {
        ExecutionResult::Halt(_, s) | ExecutionResult::LimitStepReached(s) => Some(*s),
        _ => None,
    }
}

/// Full run without hashes or traces, used to know where the program ends.
fn run_steps(limit: u64) -> (ExecutionResult, u64, Duration) {
    let mut program = load_elf(ZK_ELF, false).unwrap();
    let t = Instant::now();
    let (res, _) = execute_program(
        &mut program,
        vec![],
        ".input",
        false,
        &None,
        Some(limit),
        false,
        false,
        false,
        false,
        false,
        false, // hash like the protocol does
        None,
        None,
        FailConfiguration::default(),
        false,
    );
    (res, program.step, t.elapsed())
}

/// BUG test: a step query (trace_list = [10]) must stop once step 10 has been recorded.
/// Fails today: execute_program continues to `max_steps` (or halt).
#[test]
#[ignore = "EMU-008: fails until fixed"]
fn emu008_trace_list_query_stops_after_last_requested_step() {
    let max_steps = 2_000_000;
    let (def, dir) = zk_program_definition("stops", max_steps);

    // 1. With execute_program directly: the program must not advance past the last requested step.
    let mut program = def.load_program().unwrap();
    let t = Instant::now();
    let (res, trace) = execute_program(
        &mut program,
        vec![],
        ".input",
        false,
        &None,
        Some(max_steps),
        true,
        false,
        false,
        false,
        false,
        false,
        Some(vec![10]),
        None,
        FailConfiguration::default(),
        false,
    );
    let elapsed = t.elapsed();
    println!(
        "execute_program(trace_list=[10], limit={max_steps}): result={res:?}, program.step={}, traces={}, elapsed={elapsed:?}",
        program.step,
        trace.len()
    );
    assert_eq!(trace.len(), 1);
    assert_eq!(trace[0].0.step_number, 10);

    // 2. Through the protocol helper used by get_trace_step / verifier_choose_challenge.
    let t = Instant::now();
    let (res2, trace2) = def
        .execute_helper(&dir, &dir, vec![], Some(vec![10]), None, false)
        .unwrap();
    println!(
        "execute_helper(steps=[10]): result={res2:?}, elapsed={:?}",
        t.elapsed()
    );
    assert_eq!(trace2.len(), 1);
    assert_eq!(trace2[0].0.step_number, 10);

    assert!(
        program.step <= 10,
        "trace-list query for step 10 executed the program up to step {}",
        program.step
    );
    assert!(
        result_step(&res2).is_some_and(|s| s <= 10),
        "execute_helper for step 10 reported {res2:?}"
    );
}

/// Regression guard for the fix: everything the callers consume from trace-list mode
/// (traces, hashes, get_round_hashes padding after halt, get_trace_step) must stay identical.
/// Passes before and after the proposed fix.
#[test]
fn emu008_trace_list_semantics_hello_world() {
    let def = ProgramDefinition::from_config(HELLO_YAML).unwrap();
    let dir = fwd(&tmp_dir("hello"));
    let input = vec![17, 17, 17, 17];

    let (result, last_step, last_hash) = def
        .get_execution_result(input.clone(), &dir, &dir, None, false)
        .unwrap();
    assert_eq!(result, ExecutionResult::Halt(0, last_step));

    // full trace of every step for comparison
    let mut program = def.load_program().unwrap();
    let (_, full) = execute_program(
        &mut program,
        input.clone(),
        &def.input_section_name,
        false,
        &None,
        Some(def.max_steps),
        true,
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
    assert_eq!(full.len() as u64, last_step + 1);
    assert_eq!(full.last().unwrap().1, last_hash);

    // individual step queries, early, middle and the halt step
    for step in [1, 2, last_step / 2, last_step - 1, last_step] {
        let t = def
            .get_trace_step(&dir, &dir, input.clone(), step, None)
            .unwrap();
        assert_eq!(t.to_csv(), full[step as usize].0.to_csv(), "step {step}");
    }

    // a multi-step query returns exactly the requested steps and hashes, in order
    let steps = vec![3, 7, 100, last_step - 5];
    let (_, part) = def
        .execute_helper(&dir, &dir, input.clone(), Some(steps.clone()), None, false)
        .unwrap();
    assert_eq!(part.len(), steps.len());
    for (i, s) in steps.iter().enumerate() {
        assert_eq!(part[i].0.to_csv(), full[*s as usize].0.to_csv());
        assert_eq!(part[i].1, full[*s as usize].1);
    }

    // round hashes for every round from base 0 (round 1 asks steps past halt => padding)
    let nary = def.nary_def();
    let mut base = 0;
    for round in 1..=nary.total_rounds() {
        let hashes = def
            .get_round_hashes(&dir, &dir, input.clone(), round, base, None, Some(last_step))
            .unwrap();
        let required = nary.required_steps(round, base);
        assert_eq!(hashes.len(), required.len());
        let mut last_seen = full[base as usize].1.clone();
        for (h, s) in hashes.iter().zip(required.iter()) {
            if *s <= last_step {
                last_seen = full[*s as usize].1.clone();
                assert_eq!(h, &last_seen, "round {round} step {s}");
            } else {
                // padding with the last obtained hash (EMU-005 semantics, unchanged by the fix)
                assert_eq!(h, &last_seen, "round {round} padded step {s}");
            }
        }
        // move the base forward to the segment that still contains steps <= last_step
        base = required
            .iter()
            .copied()
            .filter(|s| *s < last_step)
            .max()
            .unwrap_or(base);
    }
}

/// Measurement: cost of an early step query vs. the program length. Run with --release.
#[test]
#[ignore = "EMU-008: measurement, run with --release --include-ignored"]
fn emu008_measure_step_query_cost() {
    let max_steps: u64 = std::env::var("EMU008_STEPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30_000_000);

    let (res, steps, full) = run_steps(max_steps);
    println!(
        "full hashed run up to {max_steps}: {res:?}, steps={steps}, elapsed={full:?}, {:.2} Msteps/s",
        steps as f64 / full.as_secs_f64() / 1e6
    );

    let (def, dir) = zk_program_definition("measure", max_steps);
    for step in [10u64, max_steps / 10] {
        let t = Instant::now();
        let tr = def.get_trace_step(&dir, &dir, vec![], step, None).unwrap();
        let e = t.elapsed();
        assert_eq!(tr.step_number, step);
        println!(
            "get_trace_step({step}) with max_steps={max_steps}: elapsed={e:?} (ideal: ~{:?})",
            full.mul_f64(step as f64 / steps as f64)
        );
    }
}
