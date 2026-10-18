//! Synthetic programs for tests.
//!
//! The reference programs are compiled by a RISC-V toolchain that runs under
//! docker, so in an environment without it every checkpoint-backed path is
//! untestable: loading a program, executing it, dissecting its trace. This
//! module writes a minimal RISC-V ELF and a matching program definition into a
//! temporary directory instead, which exercises the real loader, executor and
//! checkpointing rather than standing in for them.

use std::fs;
use std::path::PathBuf;

/// Base address of the code section. Must be above the 0x1000 floor the loader
/// enforces, and clear of the register and stack regions.
pub const TEXT_BASE: u32 = 0x1000_0000;
/// Base address of the input section.
pub const INPUT_BASE: u32 = 0x2000_0000;

const REGISTER_A0: u32 = 10;
const REGISTER_A7: u32 = 17;
const SYSCALL_EXIT: i32 = 93;

/// `addi rd, rs1, imm`
pub fn addi(rd: u32, rs1: u32, imm: i32) -> u32 {
    ((imm as u32 & 0xfff) << 20) | (rs1 << 15) | (rd << 7) | 0x13
}

/// `ecall`
pub fn ecall() -> u32 {
    0x0000_0073
}

/// The three instructions that halt the machine with exit code zero.
pub fn exit_sequence() -> Vec<u32> {
    vec![
        addi(REGISTER_A7, 0, SYSCALL_EXIT),
        addi(REGISTER_A0, 0, 0),
        ecall(),
    ]
}

/// A program of `instructions` arithmetic steps followed by a clean exit.
/// Each instruction advances the trace by one step, so the trace length is
/// predictable without having to model the executor.
pub fn counting_program(instructions: usize) -> Vec<u32> {
    let mut code: Vec<u32> = (0..instructions)
        .map(|i| addi(5, 5, (i % 2048) as i32))
        .collect();
    code.extend(exit_sequence());
    code
}

fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

#[allow(clippy::too_many_arguments)]
fn section_header(
    out: &mut Vec<u8>,
    name: u32,
    kind: u32,
    flags: u32,
    addr: u32,
    offset: u32,
    size: u32,
    align: u32,
) {
    put_u32(out, name);
    put_u32(out, kind);
    put_u32(out, flags);
    put_u32(out, addr);
    put_u32(out, offset);
    put_u32(out, size);
    put_u32(out, 0); // sh_link
    put_u32(out, 0); // sh_info
    put_u32(out, align);
    put_u32(out, 0); // sh_entsize
}

/// Builds a 32-bit little-endian RISC-V executable with a code section, a
/// writable input section and a section-name string table.
pub fn build_elf(text: &[u32], input_size: u32) -> Vec<u8> {
    const EHSIZE: u32 = 52;
    const SHENTSIZE: u32 = 40;
    const SHNUM: u32 = 4;

    // "\0.text\0.input\0.shstrtab\0"
    let mut shstrtab = vec![0u8];
    let name_text = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".text\0");
    let name_input = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".input\0");
    let name_shstrtab = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".shstrtab\0");

    let text_bytes: Vec<u8> = text.iter().flat_map(|w| w.to_le_bytes()).collect();

    let data_start = EHSIZE + SHENTSIZE * SHNUM;
    let text_off = data_start;
    let input_off = text_off + text_bytes.len() as u32;
    let shstrtab_off = input_off + input_size;

    let mut out = Vec::new();

    // ELF header
    out.extend_from_slice(&[0x7f, b'E', b'L', b'F']);
    out.push(1); // EI_CLASS: 32-bit
    out.push(1); // EI_DATA: little endian
    out.push(1); // EI_VERSION
    out.extend_from_slice(&[0u8; 9]); // OSABI, ABIVERSION, padding
    put_u16(&mut out, 2); // e_type: ET_EXEC
    put_u16(&mut out, 243); // e_machine: EM_RISCV
    put_u32(&mut out, 1); // e_version
    put_u32(&mut out, TEXT_BASE); // e_entry
    put_u32(&mut out, 0); // e_phoff
    put_u32(&mut out, EHSIZE); // e_shoff
    put_u32(&mut out, 0); // e_flags
    put_u16(&mut out, EHSIZE as u16);
    put_u16(&mut out, 0); // e_phentsize
    put_u16(&mut out, 0); // e_phnum
    put_u16(&mut out, SHENTSIZE as u16);
    put_u16(&mut out, SHNUM as u16);
    put_u16(&mut out, 3); // e_shstrndx

    // Section headers
    section_header(&mut out, 0, 0, 0, 0, 0, 0, 0); // SHT_NULL
    section_header(
        &mut out,
        name_text,
        1,     // SHT_PROGBITS
        2 | 4, // SHF_ALLOC | SHF_EXECINSTR
        TEXT_BASE,
        text_off,
        text_bytes.len() as u32,
        4,
    );
    section_header(
        &mut out,
        name_input,
        1,     // SHT_PROGBITS
        2 | 1, // SHF_ALLOC | SHF_WRITE
        INPUT_BASE,
        input_off,
        input_size,
        4,
    );
    section_header(
        &mut out,
        name_shstrtab,
        3, // SHT_STRTAB
        0,
        0,
        shstrtab_off,
        shstrtab.len() as u32,
        1,
    );

    debug_assert_eq!(out.len() as u32, data_start);
    out.extend_from_slice(&text_bytes);
    out.extend(std::iter::repeat_n(0u8, input_size as usize));
    out.extend_from_slice(&shstrtab);
    out
}

/// A program definition and its ELF, written to a temporary directory that is
/// removed when this value is dropped.
pub struct SyntheticProgram {
    dir: PathBuf,
}

impl SyntheticProgram {
    /// Writes a program of `instructions` arithmetic steps plus a clean exit.
    pub fn new(instructions: usize, nary: u8, max_steps: u64) -> std::io::Result<Self> {
        let unique = format!(
            "bitvmx-synthetic-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let dir = std::env::temp_dir().join(unique);
        fs::create_dir_all(&dir)?;

        fs::write(
            dir.join("program.elf"),
            build_elf(&counting_program(instructions), 4),
        )?;
        fs::write(
            dir.join("program.yaml"),
            format!(
                "elf: program.elf\n\
                 nary_search: {}\n\
                 max_steps: {}\n\
                 input_section_name: .input\n\
                 inputs:\n\
                 \x20 - size: 4\n\
                 \x20   owner: prover\n",
                nary, max_steps
            ),
        )?;
        Ok(Self { dir })
    }

    /// Path of the program definition, for `ProgramDefinition::from_config`.
    pub fn definition(&self) -> String {
        self.dir.join("program.yaml").to_string_lossy().into_owned()
    }

    /// A fresh checkpoint directory for one party.
    pub fn checkpoint(&self, who: &str) -> std::io::Result<String> {
        let path = self.dir.join(who);
        fs::create_dir_all(&path)?;
        Ok(path.to_string_lossy().into_owned())
    }
}

impl Drop for SyntheticProgram {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::challenge::prover_execute;
    use crate::loader::program_definition::ProgramDefinition;

    #[test]
    fn a_synthetic_program_loads() {
        let prog = SyntheticProgram::new(20, 8, 128).unwrap();
        let def = ProgramDefinition::from_config(&prog.definition()).unwrap();
        let program = def.load_program().unwrap();
        assert_eq!(program.pc.get_address(), TEXT_BASE);
    }

    #[test]
    fn a_synthetic_program_executes_to_a_halt() {
        let prog = SyntheticProgram::new(20, 8, 128).unwrap();
        let input = prog.checkpoint("prover").unwrap();
        let (result, last_step, last_hash) = prover_execute(
            &prog.definition(),
            vec![0, 0, 0, 0],
            &input,
            &input,
            true,
            None,
            true,
        )
        .unwrap();
        // 20 arithmetic instructions plus the three-instruction exit.
        assert_eq!(last_step, 23, "result {:?}", result);
        assert_eq!(last_hash.len(), 40);
    }
}

#[cfg(test)]
mod search_tests {
    use super::*;
    use crate::decision::challenge::ForceCondition;
    use crate::decision::challenge::{
        prover_execute, prover_full_duplex_stage, verifier_check_execution,
        verifier_full_duplex_stage,
    };
    use crate::decision::challenge::{prover_get_hashes_for_round, verifier_choose_segment};
    use crate::decision::execution_log::{ProverChallengeLog, VerifierChallengeLog};
    use crate::decision::nary_search::NArySearchType;
    use crate::decision::nary_search::{Party, SearchMode};
    use crate::executor::utils::FailConfiguration;
    use crate::loader::program_definition::ProgramDefinition;

    /// Drives a complete full-duplex search over a real trace and returns the
    /// last step the parties agree on. The disputed step is one beyond it.
    fn run_search(instructions: usize, nary: u8, max_steps: u64, diverge_at: u64) -> u64 {
        let defs = ProgramDefinition::from_config(
            &SyntheticProgram::new(instructions, nary, max_steps)
                .unwrap()
                .definition(),
        )
        .unwrap();
        let digits = run_search_digits(instructions, nary, max_steps, diverge_at);
        defs.nary_def().step_from_decision_bits(&digits)
    }

    fn run_search_digits(
        instructions: usize,
        nary: u8,
        max_steps: u64,
        diverge_at: u64,
    ) -> Vec<u32> {
        let prog = SyntheticProgram::new(instructions, nary, max_steps).unwrap();
        let definition = prog.definition();
        let prover_cp = prog.checkpoint("prover").unwrap();
        let verifier_cp = prog.checkpoint("verifier").unwrap();
        let input = vec![0u8; 4];

        // The prover's trace hash is corrupted from `diverge_at`, so the two
        // views first differ at exactly that step.
        let (_, claim_last_step, claim_last_hash) = prover_execute(
            &definition,
            input.clone(),
            &prover_cp,
            &prover_cp,
            true,
            Some(FailConfiguration::new_fail_hash(diverge_at)),
            true,
        )
        .unwrap();

        let disputed = verifier_check_execution(
            &definition,
            input,
            &verifier_cp,
            &verifier_cp,
            claim_last_step,
            &claim_last_hash,
            ForceCondition::ValidInputWrongStepOrHash,
            None,
            true,
        )
        .unwrap();
        assert!(disputed.is_some(), "the verifier should find a dispute");

        let defs = ProgramDefinition::from_config(&definition).unwrap();
        let rounds = defs.nary_def().total_rounds();
        let mode = SearchMode::FullDuplex;

        // Stages alternate; the trailing selection has no dissection of its
        // own and rides on the adjudication message.
        // The prover dissects from its corrupted trace throughout, exactly as
        // it committed its claim.
        let prover_fail = Some(FailConfiguration::new_fail_hash(diverge_at));

        // The digit a stage must catch up on is the one published at the stage
        // immediately before it.
        let mut hashes: Vec<String> = Vec::new();
        let mut last_decision: Option<u32> = None;

        for stage in 1..rounds + 2 {
            let actor = mode.dissector(rounds, stage);
            let (cp, step) = match actor {
                Party::Prover => (
                    &prover_cp,
                    prover_full_duplex_stage(
                        &definition,
                        &prover_cp,
                        &prover_cp,
                        stage,
                        &hashes,
                        last_decision,
                        prover_fail.clone(),
                    )
                    .unwrap(),
                ),
                Party::Verifier => (
                    &verifier_cp,
                    verifier_full_duplex_stage(
                        &definition,
                        &verifier_cp,
                        &verifier_cp,
                        stage,
                        &hashes,
                        last_decision,
                        None,
                    )
                    .unwrap(),
                ),
            };
            let _ = cp;
            last_decision = step.0;
            hashes = step.1;
        }

        // The disputed step is what the digit sequence spells out, which is
        // the quantity the on-chain script reconstructs. The trailing
        // selection always falls to the prover, so its log holds every digit.
        let digits = ProverChallengeLog::load(&prover_cp)
            .unwrap()
            .conflict_step_log
            .verifier_decisions;
        assert_eq!(
            digits.len(),
            rounds as usize,
            "the search should commit one digit per level"
        );
        digits
    }

    /// Drives the classical asymmetric search over the same trace: the prover
    /// dissects, the verifier selects, two messages per level.
    fn run_asymmetric(instructions: usize, nary: u8, max_steps: u64, diverge_at: u64) -> Vec<u32> {
        let prog = SyntheticProgram::new(instructions, nary, max_steps).unwrap();
        let definition = prog.definition();
        let prover_cp = prog.checkpoint("prover").unwrap();
        let verifier_cp = prog.checkpoint("verifier").unwrap();
        let input = vec![0u8; 4];
        let fail = Some(FailConfiguration::new_fail_hash(diverge_at));

        let (_, claim_last_step, claim_last_hash) = prover_execute(
            &definition,
            input.clone(),
            &prover_cp,
            &prover_cp,
            true,
            fail.clone(),
            true,
        )
        .unwrap();

        verifier_check_execution(
            &definition,
            input,
            &verifier_cp,
            &verifier_cp,
            claim_last_step,
            &claim_last_hash,
            ForceCondition::ValidInputWrongStepOrHash,
            None,
            true,
        )
        .unwrap()
        .expect("the verifier should find a dispute");

        let defs = ProgramDefinition::from_config(&definition).unwrap();
        let rounds = defs.nary_def().total_rounds();
        let mut decision = 0u32;

        for round in 1..rounds + 1 {
            let hashes = prover_get_hashes_for_round(
                &definition,
                &prover_cp,
                &prover_cp,
                round,
                decision,
                fail.clone(),
                NArySearchType::ConflictStep,
            )
            .unwrap();
            decision = verifier_choose_segment(
                &definition,
                &verifier_cp,
                &verifier_cp,
                round,
                hashes,
                None,
                NArySearchType::ConflictStep,
            )
            .unwrap();
        }

        VerifierChallengeLog::load(&verifier_cp)
            .unwrap()
            .conflict_step_log
            .verifier_decisions
    }

    /// The two searches descend through the same intervals on a real trace,
    /// because agreement at a position does not depend on which party
    /// evaluates it. The full-duplex search just spends half the messages.
    #[test]
    fn full_duplex_and_asymmetric_searches_agree_on_a_real_trace() {
        for (nary, max_steps) in [(8u8, 64u64), (4, 64), (2, 64)] {
            for diverge_at in [3u64, 17, 42] {
                let full = run_search_digits(60, nary, max_steps, diverge_at);
                let asym = run_asymmetric(60, nary, max_steps, diverge_at);
                assert!(
                    !full.is_empty(),
                    "nary {}: the search should commit digits",
                    nary
                );
                assert_eq!(
                    full, asym,
                    "nary {} divergence {}: the searches should commit the same digits",
                    nary, diverge_at
                );
            }
        }
    }

    #[test]
    fn a_full_duplex_search_locates_the_divergence() {
        for diverge_at in [5u64, 13, 21, 37, 50] {
            let agreed = run_search(60, 8, 64, diverge_at);
            assert_eq!(
                agreed,
                diverge_at - 1,
                "divergence at {} should leave {} as the last agreed step",
                diverge_at,
                diverge_at - 1
            );
        }
    }
}
