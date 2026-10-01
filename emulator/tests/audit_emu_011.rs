//! EMU-011: `Program::get_chunks` computes `base_addr` in the wrong unit.
//!
//! `section.data.chunks(chunk_size)` splits by u32 *words*, but the chunk base is
//! `section.start + index * chunk_size`, i.e. it advances by `chunk_size` *bytes*
//! while every chunk spans `chunk_size * 4` bytes. Only the first chunk of each section
//! is labeled correctly; later chunks overlap and contain data from another address.
//!
//! Tests:
//! * `emu011_chunks_match_memory` (BUG test, ignored until fixed): every word of every
//!   code/initialized chunk must equal the program memory at `base_addr + 4*i`, and the
//!   chunks must tile each section without overlap.
//! * `emu011_malicious_verifier_wins_opcode_challenge_against_honest_pc` (BUG test,
//!   ignored until fixed): with the honest opcode for a PC outside the first chunk, the
//!   on-chain `opcode_challenge` built from the chunk the emulator selects must reject.
//! * `emu011_demo_*` (DEMONSTRATIONS, pass while the bug exists).

use bitcoin_script_riscv::riscv::challenges::execute_challenge;
use bitvmx_cpu_definitions::{
    challenge::ChallengeType,
    constants::CHUNK_SIZE,
    memory::Chunk,
    trace::{ProgramCounter, TraceReadPC},
};
use emulator::loader::program::{load_elf, Program};

const ELFS: [&str; 2] = [
    "../docker-riscv32/riscv32/build/hello-world.elf",
    "../docker-riscv32/verifier/build/zkverifier-new-mul.elf",
];

/// Raw word at `address` as the emulator sees it (code, data or initial register value),
/// bypassing access checks.
fn word_at(program: &Program, address: u32) -> u32 {
    let base = program.registers.get_base_address();
    if address >= base && address < program.registers.get_last_register_address() {
        // register chunks (see EMU-012) hold the loader's initial register values
        return program.registers.get((address - base) / 4);
    }
    let section = program.find_section(address).unwrap();
    u32::from_be(section.data[((address - section.start) / 4) as usize])
}

/// Same selection as `find_chunk_index` in `decision/challenge.rs` (first chunk covering the address).
fn find_chunk(chunks: &[Chunk], address: u32) -> Option<usize> {
    chunks.iter().position(|c| {
        c.base_addr <= address && address < c.base_addr + c.data.len() as u32 * 4
    })
}

/// Returns (#chunks, #mislabeled words, first mismatch description).
fn check_chunks(program: &Program, chunks: &[Chunk]) -> (usize, usize, Option<String>) {
    let mut bad = 0;
    let mut first = None;
    for (ci, chunk) in chunks.iter().enumerate() {
        for (i, value) in chunk.data.iter().enumerate() {
            let addr = chunk.base_addr + 4 * i as u32;
            let real = word_at(program, addr);
            if real != *value {
                bad += 1;
                first.get_or_insert(format!(
                    "chunk {ci} base 0x{:08x}: data[{i}] = 0x{value:08x} but memory[0x{addr:08x}] = 0x{real:08x}",
                    chunk.base_addr
                ));
            }
        }
    }
    (chunks.len(), bad, first)
}

fn overlapping_pairs(chunks: &[Chunk]) -> usize {
    chunks
        .windows(2)
        .filter(|w| w[0].range().1 >= w[1].base_addr)
        .count()
}

#[test]
#[ignore = "EMU-011: fails until fixed"]
fn emu011_chunks_match_memory() {
    let mut failures = vec![];
    for elf in ELFS {
        let program = load_elf(elf, false).unwrap();
        for (kind, chunks) in [
            ("code", program.get_code_chunks(CHUNK_SIZE)),
            ("initialized", program.get_initialized_chunks(CHUNK_SIZE)),
        ] {
            let (n, bad, first) = check_chunks(&program, &chunks);
            let overlaps = overlapping_pairs(&chunks);
            println!("{elf} {kind}: {n} chunks, {bad} mislabeled words, {overlaps} overlapping chunk pairs");
            if let Some(f) = first {
                println!("    first mismatch: {f}");
            }
            if bad > 0 || overlaps > 0 {
                failures.push(format!("{elf} {kind}"));
            }
        }
    }
    assert!(failures.is_empty(), "mislabeled chunks in: {failures:?}");
}

/// Finds an honest (pc, opcode) whose chunk, as chosen by the emulator, gives a wrong value
/// and runs the real on-chain opcode challenge with it.
fn malicious_opcode_challenge_result() -> Option<(u32, u32, bool)> {
    for elf in ELFS {
        let program = load_elf(elf, false).unwrap();
        let chunks = program.get_code_chunks(CHUNK_SIZE);
        for section in program.sections.iter().filter(|s| s.is_code) {
            for i in 0..section.size / 4 {
                let pc = section.start + 4 * i;
                let opcode = word_at(&program, pc);
                let idx = find_chunk(&chunks, pc).unwrap();
                let chunk = &chunks[idx];
                let committed = chunk.data[((pc - chunk.base_addr) / 4) as usize];
                if committed != opcode {
                    let challenge = ChallengeType::Opcode {
                        prover_pc_read: TraceReadPC::new(ProgramCounter::new(pc, 0), opcode),
                        chunk_index: idx as u32,
                        chunk: Some(chunk.clone()),
                    };
                    let verifier_wins = execute_challenge(&challenge);
                    println!(
                        "{elf}: honest pc 0x{pc:08x} opcode 0x{opcode:08x}, chunk {idx} (base 0x{:08x}) commits 0x{committed:08x}: verifier_wins = {verifier_wins}",
                        chunk.base_addr
                    );
                    return Some((pc, opcode, verifier_wins));
                }
            }
        }
    }
    None
}

#[test]
#[ignore = "EMU-011: fails until fixed"]
fn emu011_malicious_verifier_wins_opcode_challenge_against_honest_pc() {
    if let Some((pc, opcode, verifier_wins)) = malicious_opcode_challenge_result() {
        assert!(
            !verifier_wins,
            "opcode challenge succeeded against honest pc 0x{pc:08x} opcode 0x{opcode:08x}"
        );
    }
}

#[test]
fn emu011_demo_chunk_bases_advance_by_words_not_bytes() {
    let program = load_elf(ELFS[1], false).unwrap();
    let chunks = program.get_code_chunks(CHUNK_SIZE);
    assert!(chunks.len() > 1, "need a code section larger than one chunk");
    // Same section: base advances by CHUNK_SIZE bytes but each chunk spans CHUNK_SIZE*4 bytes.
    assert_eq!(chunks[1].base_addr - chunks[0].base_addr, CHUNK_SIZE);
    assert_eq!(chunks[0].data.len() as u32 * 4, CHUNK_SIZE * 4);
}

#[test]
fn emu011_demo_malicious_verifier_wins_against_honest_pc() {
    let (_, _, verifier_wins) =
        malicious_opcode_challenge_result().expect("expected a mislabeled code word");
    assert!(verifier_wins);
}
