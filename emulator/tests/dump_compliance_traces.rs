//! Dump every instruction the RISC-V compliance suite retires.
//!
//! The emulator and the Bitcoin Script verifier are both validated against
//! these 47 ELFs -- `compliance.rs` runs them with `verify_on_chain`, so
//! every instruction's trace goes through `verify_script`.  The garbled
//! step circuit is not: it has a few hundred hand-emitted vectors over
//! twenty opcodes, which is how a division defect survived in it while
//! Script was exercising the same case continuously.
//!
//! This writes the traces out so the circuit can be checked against them.
//! It is `#[ignore]`d because it exists to feed
//! `compact/circuits/compliance_check.py` rather than to assert anything
//! itself:
//!
//! ```sh
//! cargo test -p emulator --test dump_compliance_traces -- --ignored --nocapture
//! python3 compact/circuits/compliance_check.py <fair-riscv-mpc> <circuits> /tmp/compliance-traces.tsv
//! ```
use emulator::executor::fetcher::execute_program;
use emulator::executor::utils::FailConfiguration;
use emulator::loader::program::load_elf;
use std::io::Write;

const OUT: &str = "/tmp/compliance-traces.tsv";

#[test]
#[ignore = "writes a trace corpus for the circuit differential check"]
fn dump_compliance_traces() {
    let dir = "../docker-riscv32/compliance/build";
    let mut out = std::fs::File::create(OUT).expect("create the trace file");
    writeln!(
        out,
        "elf\tstep\tpc\tmicro\topcode\tr1_addr\trs1\tr2_addr\trs2\t\
         write_addr\twrite_val\twrite_pc\twrite_micro\twitness\tmem_witness"
    )
    .unwrap();

    let mut files: Vec<_> = std::fs::read_dir(dir)
        .expect("the compliance build directory")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension().is_some_and(|x| x == "elf")
                && !p.to_string_lossy().contains("fence_i")
        })
        .collect();
    files.sort();

    let (mut steps, mut programs) = (0usize, 0usize);
    for path in &files {
        let name = path.file_stem().unwrap().to_string_lossy().to_string();
        let mut program = match load_elf(&path.to_string_lossy(), false) {
            Ok(p) => p,
            Err(e) => panic!("{name}: {e:?}"),
        };
        let (_result, traces) = execute_program(
            &mut program,
            Vec::new(),
            ".bss",
            false,
            &None,
            Some(5_000),
            true, // print_trace: record every step
            false,
            false,
            false,
            false,
            true,
            None,
            None,
            FailConfiguration::default(),
            false,
        );
        for (t, _hash) in &traces {
            writeln!(
                out,
                "{}\t{}\t{:08x}\t{}\t{:08x}\t{:08x}\t{:08x}\t{:08x}\t{:08x}\t\
                 {:08x}\t{:08x}\t{:08x}\t{}\t{:08x}\t{:02x}",
                name,
                t.step_number,
                t.read_pc.pc.get_address(),
                t.read_pc.pc.get_micro(),
                t.read_pc.opcode,
                t.read_1.address,
                t.read_1.value,
                t.read_2.address,
                t.read_2.value,
                t.trace_step.get_write().address,
                t.trace_step.get_write().value,
                t.trace_step.get_pc().get_address(),
                t.trace_step.get_pc().get_micro(),
                t.witness.unwrap_or(0),
                t.mem_witness.byte(),
            )
            .unwrap();
            steps += 1;
        }
        programs += 1;
    }
    println!("{steps} instructions from {programs} compliance programs -> {OUT}");
    assert!(programs >= 40, "expected the compliance suite, got {programs}");
    assert!(steps > 10_000, "expected a real corpus, got {steps}");
}
