//! Audit of `bitcoin-script-riscv` (on-chain RISC-V scripts) against the emulator.
//! See `BitVMX-CPU/docs/script-audit/` for the tickets (SCR-0NN).
//!
//! The EXECUTE leaves are run by the PROVER to prove its own trace step (client
//! `execution.rs`: the key comes from `get_key_from_opcode`, the prover posts the leaf).
//! The protocol is only sound if, for a given opcode and given reads, **exactly one**
//! `trace_step` (write address, write value, next pc, next micro) is accepted by **any**
//! leaf. Otherwise a lying prover makes its hash chain diverge on a step it can prove, the
//! n-ary search lands there, and the verifier has nothing left to challenge.
//!
//! Test kinds (same convention as the EMU audit):
//! * `scrNNN_demo_*`: shows the bug, passes today. Delete or flip it when the fix lands.
//! * `#[ignore = "SCR-0NN: fails until fixed"]`: asserts the correct behaviour, fails today.
//! * `fuzz_*` / `check_*`: regression checks that pass today and must keep passing.
//!
//! Run: `cargo test --release -p emulator --test audit_scr -- --nocapture --include-ignored`

use std::collections::HashMap;
use std::sync::OnceLock;

use bitcoin_script_riscv::riscv::{
    challenges::execute_challenge,
    instruction_mapping::{create_verification_script_mapping, get_key_from_opcode, InstructionMapping},
};
use bitvmx_cpu_definitions::{
    challenge::ChallengeType,
    constants::LAST_STEP_INIT,
    memory::{Chunk, MemoryAccessType, MemoryWitness, SectionDefinition},
    trace::{
        compute_step_hash, generate_initial_step_hash, hash_to_string, ProgramCounter, TraceRWStep,
        TraceRead, TraceStep, TraceWrite,
    },
};
use emulator::{
    constants::REGISTERS_BASE_ADDRESS,
    executor::{fetcher::execute_step, utils::FailConfiguration, verifier::verify_script},
    loader::program::{Program, Section},
};

const CODE: u32 = 0x1000;
const DATA: u32 = 0x4000_0000;
const DATA_SIZE: u32 = 0x200;
const AUX_1: u32 = REGISTERS_BASE_ADDRESS + 32 * 4;
const AUX_2: u32 = REGISTERS_BASE_ADDRESS + 33 * 4;

fn reg(r: u32) -> u32 {
    REGISTERS_BASE_ADDRESS + r * 4
}

// ---------------------------------------------------------------------------------------------
// Encoders
// ---------------------------------------------------------------------------------------------

fn enc_r(f7: u32, rs2: u32, rs1: u32, f3: u32, rd: u32) -> u32 {
    (f7 << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | 0x33
}
fn enc_i(imm: i32, rs1: u32, f3: u32, rd: u32, op: u32) -> u32 {
    (((imm as u32) & 0xfff) << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | op
}
fn enc_shift(f7: u32, shamt: u32, rs1: u32, f3: u32, rd: u32) -> u32 {
    (f7 << 25) | ((shamt & 0x1f) << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | 0x13
}
fn enc_s(imm: i32, rs2: u32, rs1: u32, f3: u32) -> u32 {
    let imm = imm as u32;
    (((imm >> 5) & 0x7f) << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12) | ((imm & 0x1f) << 7) | 0x23
}
fn enc_b(imm: i32, rs2: u32, rs1: u32, f3: u32) -> u32 {
    let imm = imm as u32;
    (((imm >> 12) & 1) << 31)
        | (((imm >> 5) & 0x3f) << 25)
        | (rs2 << 20)
        | (rs1 << 15)
        | (f3 << 12)
        | (((imm >> 1) & 0xf) << 8)
        | (((imm >> 11) & 1) << 7)
        | 0x63
}
fn enc_u(imm: u32, rd: u32, op: u32) -> u32 {
    (imm & 0xffff_f000) | (rd << 7) | op
}
fn enc_j(imm: i32, rd: u32) -> u32 {
    let imm = imm as u32;
    (((imm >> 20) & 1) << 31)
        | (((imm >> 1) & 0x3ff) << 21)
        | (((imm >> 11) & 1) << 20)
        | (((imm >> 12) & 0xff) << 12)
        | (rd << 7)
        | 0x6f
}

const ECALL: u32 = 0x0000_0073;
const NOP: u32 = 0x0000_0013; // addi x0, x0, 0

// ---------------------------------------------------------------------------------------------
// Emulator / script helpers
// ---------------------------------------------------------------------------------------------

fn mapping() -> &'static Option<InstructionMapping> {
    static M: OnceLock<Option<InstructionMapping>> = OnceLock::new();
    M.get_or_init(|| Some(create_verification_script_mapping(REGISTERS_BASE_ADDRESS)))
}

fn machine(opcode: u32, regs: &[(u32, u32)], data: &[u32]) -> Program {
    let mut p = Program::new(CODE, REGISTERS_BASE_ADDRESS, 0);
    p.add_section(Section::new_with_data("code", vec![opcode.to_be(), 0], CODE, 8, true, false, true));
    let mut d: Vec<u32> = data.iter().map(|x| x.to_be()).collect();
    d.resize((DATA_SIZE / 4) as usize, 0);
    p.add_section(Section::new_with_data("data", d, DATA, DATA_SIZE, false, true, true));
    for (r, v) in regs {
        if *r != 0 {
            p.registers.set(*r, *v, 0);
        }
    }
    p
}

/// Executes one RISC-V instruction (all its micro-instructions) and returns the honest traces.
fn run_instruction(opcode: u32, regs: &[(u32, u32)], data: &[u32]) -> Vec<TraceRWStep> {
    let mut p = machine(opcode, regs, data);
    let mut traces = vec![];
    loop {
        let t = execute_step(&mut p, false, false, FailConfiguration::default())
            .unwrap_or_else(|e| panic!("emulator error {:?} for opcode 0x{:08x}", e, opcode));
        let done = t.trace_step.write_pc.get_micro() == 0;
        traces.push(t);
        if done || p.halt {
            break;
        }
        assert!(traces.len() <= 8, "too many micro steps");
    }
    traces
}

/// The leaf the honest prover uses (key from `get_key_from_opcode`), through the instruction mapping.
fn honest_leaf_accepts(t: &TraceRWStep) -> bool {
    verify_script(t, REGISTERS_BASE_ADDRESS, mapping()).is_ok()
}

/// The direct (non mapping) script for the same trace.
fn direct_script_accepts(t: &TraceRWStep) -> bool {
    verify_script(t, REGISTERS_BASE_ADDRESS, &None).is_ok()
}

/// Runs the leaf `key` (any leaf of the EXECUTE tx) against the trace, i.e. what a prover that
/// chooses that leaf gets. `verify` looks the script up by the opcode's own key, so we map that
/// key to the chosen leaf's script.
fn leaf_accepts(key: &str, t: &TraceRWStep) -> bool {
    let base = mapping().as_ref().unwrap();
    let own_key = get_key_from_opcode(t.read_pc.opcode, t.read_pc.pc.get_micro()).unwrap();
    let mut m: InstructionMapping = HashMap::new();
    m.insert(own_key, base[key].clone());
    verify_script(t, REGISTERS_BASE_ADDRESS, &Some(m)).is_ok()
}

fn step_hash(prev: &[u8; 20], step: &TraceStep) -> [u8; 20] {
    compute_step_hash(&mut blake3::Hasher::new(), prev, &step.to_bytes())
}

/// Trace of a nop-like step: no reads, no write, pc + 4.
fn nop_trace_for(t: &TraceRWStep) -> TraceRWStep {
    let pc = t.read_pc.pc.get_address();
    TraceRWStep::new(
        t.step_number,
        TraceRead::default(),
        TraceRead::default(),
        t.read_pc.clone(),
        TraceStep::new(TraceWrite::default(), ProgramCounter::new(pc + 4, 0)),
        None,
        MemoryWitness::default(),
    )
}

fn assert_two_different_steps_accepted(honest: &TraceRWStep, forged: &TraceRWStep, forged_leaf: &str) {
    let h0: [u8; 20] = generate_initial_step_hash().try_into().unwrap();
    assert!(honest_leaf_accepts(honest), "honest trace must be accepted");
    assert!(leaf_accepts(forged_leaf, forged), "forged trace accepted by `{}`", forged_leaf);
    let (a, b) = (step_hash(&h0, &honest.trace_step), step_hash(&h0, &forged.trace_step));
    assert_ne!(a, b, "the two accepted steps must hash differently");
    println!(
        "opcode 0x{:08x}: honest step {:?} and forged step {:?} (leaf `{}`) are both accepted, hashes {} / {}",
        honest.read_pc.opcode,
        honest.trace_step,
        forged.trace_step,
        forged_leaf,
        hash_to_string(&a),
        hash_to_string(&b)
    );
}

// ---------------------------------------------------------------------------------------------
// Differential fuzzing: emulator honest traces vs. on-chain leaves (completeness + basic soundness)
// ---------------------------------------------------------------------------------------------

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u32 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (self.0 >> 32) as u32
    }
    fn below(&mut self, n: u32) -> u32 {
        self.next() % n
    }
    fn value(&mut self) -> u32 {
        const EDGE: [u32; 12] = [
            0, 1, 2, 0xffff_ffff, 0x8000_0000, 0x7fff_ffff, 0x8000_0001, 0xffff_fffe, 0xffff, 0x1_0000, 31, 32,
        ];
        match self.below(3) {
            0 => EDGE[self.below(EDGE.len() as u32) as usize],
            1 => self.next() >> self.below(32),
            _ => self.next(),
        }
    }
    fn reg(&mut self) -> u32 {
        // mostly non-zero, sometimes x0
        if self.below(8) == 0 { 0 } else { 1 + self.below(31) }
    }
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // names are only used in failure messages
enum Kind {
    R(&'static str, u32, u32),
    IArith(&'static str, u32),
    Shift(&'static str, u32, u32),
    Upper(&'static str, u32),
    Branch(&'static str, u32),
    Jal,
    Jalr,
    Load(&'static str, u32),
    Store(&'static str, u32),
}

const KINDS: [Kind; 37] = [
    Kind::R("add", 0x00, 0), Kind::R("sub", 0x20, 0), Kind::R("sll", 0x00, 1), Kind::R("slt", 0x00, 2),
    Kind::R("sltu", 0x00, 3), Kind::R("xor", 0x00, 4), Kind::R("srl", 0x00, 5), Kind::R("sra", 0x20, 5),
    Kind::R("or", 0x00, 6), Kind::R("and", 0x00, 7), Kind::R("mul", 0x01, 0), Kind::R("mulh", 0x01, 1),
    Kind::R("mulhsu", 0x01, 2), Kind::R("mulhu", 0x01, 3), Kind::R("div", 0x01, 4), Kind::R("divu", 0x01, 5),
    Kind::R("rem", 0x01, 6), Kind::R("remu", 0x01, 7),
    Kind::IArith("addi", 0), Kind::IArith("slti", 2), Kind::IArith("sltiu", 3), Kind::IArith("xori", 4),
    Kind::IArith("ori", 6), Kind::IArith("andi", 7),
    Kind::Shift("slli", 0x00, 1), Kind::Shift("srli", 0x00, 5), Kind::Shift("srai", 0x20, 5),
    Kind::Upper("lui", 0x37), Kind::Upper("auipc", 0x17),
    Kind::Branch("beq/bne/blt/bge/bltu/bgeu", 0), Kind::Jal, Kind::Jalr,
    Kind::Load("lb/lh/lw/lbu/lhu", 0), Kind::Store("sb", 0), Kind::Store("sh", 1), Kind::Store("sw", 2),
    Kind::Load("lw", 2),
];

fn random_case(rng: &mut Lcg, kind: Kind) -> (u32, Vec<(u32, u32)>, Vec<u32>) {
    let mut regs: Vec<(u32, u32)> = (1..32).map(|r| (r, rng.value())).collect();
    let data: Vec<u32> = (0..DATA_SIZE / 4).map(|_| rng.next()).collect();
    let (rd, rs1, rs2) = (rng.reg(), rng.reg(), rng.reg());
    let opcode = match kind {
        Kind::R(_, f7, f3) => enc_r(f7, rs2, rs1, f3, rd),
        Kind::IArith(_, f3) => enc_i(rng.next() as i32 >> 20, rs1, f3, rd, 0x13),
        Kind::Shift(_, f7, f3) => enc_shift(f7, rng.below(32), rs1, f3, rd),
        Kind::Upper(_, op) => enc_u(rng.next(), rd, op),
        Kind::Branch(..) => {
            let f3 = [0, 1, 4, 5, 6, 7][rng.below(6) as usize];
            let imm = ((rng.next() as i32) >> 20) & !3; // multiple of 4, 13-bit signed
            if rng.below(3) == 0 {
                // make equal values likely
                let v = rng.value();
                regs[(rs1.max(1) - 1) as usize].1 = v;
                regs[(rs2.max(1) - 1) as usize].1 = v;
            }
            enc_b(imm, rs2, rs1, f3)
        }
        Kind::Jal => enc_j(((rng.next() as i32) >> 11) & !3, rd),
        Kind::Jalr => {
            let rs1 = 1 + rng.below(31);
            regs[(rs1 - 1) as usize].1 = rng.next() & !3;
            enc_i(((rng.next() as i32) >> 20) & !3, rs1, 0, rd, 0x67)
        }
        Kind::Load(_, f3) => {
            let rs1 = 1 + rng.below(31);
            regs[(rs1 - 1) as usize].1 = DATA + 0x80 + rng.below(0x40);
            let f3 = if f3 == 0 { [0, 1, 2, 4, 5][rng.below(5) as usize] } else { f3 };
            enc_i(rng.below(0x80) as i32 - 0x40, rs1, f3, rd, 0x03)
        }
        Kind::Store(_, f3) => {
            let rs1 = 1 + rng.below(31);
            regs[(rs1 - 1) as usize].1 = DATA + 0x80 + rng.below(0x40);
            let rs2 = if rs2 == rs1 { 0 } else { rs2 };
            enc_s(rng.below(0x80) as i32 - 0x40, rs2, rs1, f3)
        }
    };
    (opcode, regs, data)
}

fn mutations(t: &TraceRWStep) -> Vec<(&'static str, TraceRWStep)> {
    let mut v = vec![];
    let mut m = t.clone();
    m.trace_step.write_1.value ^= 1;
    v.push(("write_value^1", m));
    let mut m = t.clone();
    m.trace_step.write_1.address ^= 4;
    v.push(("write_address^4", m));
    let mut m = t.clone();
    let pc = m.trace_step.write_pc.get_address();
    m.trace_step.write_pc = ProgramCounter::new(pc ^ 4, m.trace_step.write_pc.get_micro());
    v.push(("write_pc^4", m));
    let mut m = t.clone();
    m.trace_step.write_pc = ProgramCounter::new(pc, m.trace_step.write_pc.get_micro() ^ 1);
    v.push(("write_micro^1", m));
    v
}

fn fuzz(iterations_per_kind: u32, seed: u64, check_direct: bool) {
    let mut rng = Lcg(seed);
    let mut failures = vec![];
    let mut traces_checked = 0;
    for kind in KINDS {
        for _ in 0..iterations_per_kind {
            let (opcode, regs, data) = random_case(&mut rng, kind);
            for t in run_instruction(opcode, &regs, &data) {
                traces_checked += 1;
                if !honest_leaf_accepts(&t) {
                    failures.push(format!("{:?} 0x{:08x} micro {}: honest trace REJECTED by mapping leaf: {:?}", kind, opcode, t.read_pc.pc.get_micro(), t));
                }
                if check_direct && !direct_script_accepts(&t) {
                    failures.push(format!("{:?} 0x{:08x}: honest trace REJECTED by direct script", kind, opcode));
                }
                for (name, m) in mutations(&t) {
                    if honest_leaf_accepts(&m) {
                        failures.push(format!("{:?} 0x{:08x} micro {}: mutation {} ACCEPTED", kind, opcode, t.read_pc.pc.get_micro(), name));
                    }
                }
            }
        }
    }
    println!("fuzz: {} traces checked, {} failures", traces_checked, failures.len());
    for f in &failures {
        println!("  {}", f);
    }
    assert!(failures.is_empty());
}

/// Every honest emulator trace must be accepted by the leaf the client picks, and simple
/// mutations of the hashed `trace_step` must be rejected.
#[test]
fn fuzz_honest_traces_accepted_and_mutations_rejected() {
    // AUDIT_SCR_FUZZ=<iterations per instruction kind> for a longer run
    let iterations = std::env::var("AUDIT_SCR_FUZZ").ok().and_then(|v| v.parse().ok()).unwrap_or(12);
    fuzz(iterations, 0x5eed_0001, false);
}

#[test]
fn fuzz_direct_scripts_match_mapping() {
    fuzz(2, 0x5eed_0002, true);
}

#[test]
fn check_ecall_fence_ebreak_honest_traces_accepted() {
    for (opcode, regs) in [
        (ECALL, vec![(17, 93), (10, 0)]),
        (ECALL, vec![(17, 116), (10, 7)]),
        (ECALL, vec![(17, 64), (10, 7)]),
        (0x0ff0_000f, vec![]),  // fence
        (0x0010_0073, vec![]),  // ebreak
        (NOP, vec![]),
    ] {
        let t = &run_instruction(opcode, &regs, &[])[0];
        assert!(honest_leaf_accepts(t), "0x{:08x} {:?}", opcode, regs);
    }
}

// ---------------------------------------------------------------------------------------------
// SCR-001: the `nop` leaf (and the `ecall` leaf's non-halt branch) never checks the opcode
// ---------------------------------------------------------------------------------------------

fn scr001_cases() -> Vec<(&'static str, u32, Vec<(u32, u32)>)> {
    vec![
        ("add x1, x2, x3", enc_r(0, 3, 2, 0, 1), vec![(2, 5), (3, 7)]),
        ("beq x0, x0, +64 (taken)", enc_b(64, 0, 0, 0), vec![]),
        ("bne a0, x0, +64 (taken: e.g. 'if (!ok) goto fail')", enc_b(64, 0, 10, 1), vec![(10, 1)]),
        ("jal x0, +16", enc_j(16, 0), vec![]),
        ("sw x5, 0(x6)", enc_s(0, 5, 6, 2), vec![(5, 0xdead_beef), (6, DATA)]),
        ("lui a0, 0x12345", enc_u(0x1234_5000, 10, 0x37), vec![]),
    ]
}

#[test]
fn scr001_demo_nop_leaf_accepts_any_instruction_as_nop() {
    for (name, opcode, regs) in scr001_cases() {
        let honest = &run_instruction(opcode, &regs, &[0; 4])[0];
        let forged = nop_trace_for(honest);
        println!("{}", name);
        assert_two_different_steps_accepted(honest, &forged, "nop");
    }
}

#[test]
fn scr001_demo_ecall_leaf_accepts_any_instruction_as_nop() {
    for (name, opcode, regs) in scr001_cases() {
        let honest = &run_instruction(opcode, &regs, &[0; 4])[0];
        let forged = nop_trace_for(honest);
        println!("{}", name);
        assert_two_different_steps_accepted(honest, &forged, "ecall");
    }
}

/// The verifier's `opcode` leaf (ROM code chunk) and `rom` leaf (`.rodata` data) cannot catch the
/// SCR-001 forgery: the forged trace carries the REAL opcode of the ROM (only the leaf the prover
/// picked ignores it), and it has no reads. Control: if the prover instead fakes the opcode (e.g.
/// claims `nop` where the ROM has `add`), the `nop` leaf accepts it too, but then the `opcode`
/// challenge wins, which is the mechanism that protects against a wrong opcode.
#[test]
fn scr001_demo_opcode_and_rom_challenges_cannot_catch_it() {
    let rodata_word = 0x1234_5678;
    let rom = |opcode: u32| Chunk { base_addr: CODE, data: vec![opcode, 0] };
    for (name, opcode, regs) in scr001_cases() {
        let honest = &run_instruction(opcode, &regs, &[rodata_word]).remove(0);
        let forged = nop_trace_for(honest);
        assert!(leaf_accepts("nop", &forged));

        let opcode_challenge = ChallengeType::Opcode {
            prover_pc_read: forged.read_pc.clone(),
            chunk_index: 0,
            chunk: Some(rom(opcode)),
        };
        let rom_challenge = ChallengeType::RomData {
            prover_read_1: forged.read_1.clone(),
            prover_read_2: forged.read_2.clone(),
            address: DATA,
            input_for_address: rodata_word,
        };
        let (op_wins, rom_wins) = (execute_challenge(&opcode_challenge), execute_challenge(&rom_challenge));
        println!("{}: forged nop step (real opcode 0x{:08x}): opcode challenge wins = {}, rom challenge wins = {}", name, opcode, op_wins, rom_wins);
        assert!(!op_wins && !rom_wins);
    }

    // control: a faked opcode is accepted by the nop leaf but caught by the opcode challenge
    let add = enc_r(0, 3, 2, 0, 1);
    let honest = run_instruction(add, &[(2, 5), (3, 7)], &[]).remove(0);
    let mut faked = nop_trace_for(&honest);
    faked.read_pc.opcode = NOP;
    assert!(leaf_accepts("nop", &faked));
    let caught = execute_challenge(&ChallengeType::Opcode {
        prover_pc_read: faked.read_pc.clone(),
        chunk_index: 0,
        chunk: Some(rom(add)),
    });
    println!("control: prover claims opcode 0x{:08x} where the ROM has 0x{:08x}: opcode challenge wins = {}", NOP, add, caught);
    assert!(caught);
}

#[test]
#[ignore = "SCR-001: fails until fixed"]
fn scr001_nop_and_ecall_leaves_reject_other_opcodes() {
    for (name, opcode, regs) in scr001_cases() {
        let honest = &run_instruction(opcode, &regs, &[0; 4])[0];
        let forged = nop_trace_for(honest);
        assert!(!leaf_accepts("nop", &forged), "{}: nop leaf accepted", name);
        assert!(!leaf_accepts("ecall", &forged), "{}: ecall leaf accepted", name);
    }
}

// ---------------------------------------------------------------------------------------------
// SCR-002: instruction leaves accept rd = x0 (write to x0) next to the honest nop
// ---------------------------------------------------------------------------------------------

/// (name, honest trace, forged trace that writes x0, leaf that accepts the forged trace)
fn scr002_cases() -> Vec<(&'static str, TraceRWStep, TraceRWStep, &'static str)> {
    let mut v = vec![];

    // `nop` (= addi x0, x0, 0): honest step is "no write, pc+4". The `addi` leaf also accepts
    // "write x0 := 0, pc+4". `nop` is in practically every compiled program.
    let honest = run_instruction(NOP, &[], &[]).remove(0);
    let mut forged = honest.clone();
    forged.read_1 = TraceRead::new(reg(0), 0, LAST_STEP_INIT);
    forged.trace_step.write_1 = TraceWrite::new(reg(0), 0);
    forged.mem_witness = MemoryWitness::rur();
    v.push(("nop (addi x0, x0, 0)", honest, forged, "addi"));

    // lui x0, 0x12345 -> `lui` leaf writes x0
    let honest = run_instruction(enc_u(0x1234_5000, 0, 0x37), &[], &[]).remove(0);
    let mut forged = honest.clone();
    forged.trace_step.write_1 = TraceWrite::new(reg(0), 0x1234_5000);
    forged.mem_witness = MemoryWitness::new(MemoryAccessType::Unused, MemoryAccessType::Unused, MemoryAccessType::Register);
    v.push(("lui x0, 0x12345", honest, forged, "lui"));

    // add x0, x1, x2 -> `add` leaf
    let honest = run_instruction(enc_r(0, 2, 1, 0, 0), &[(1, 3), (2, 4)], &[]).remove(0);
    let mut forged = honest.clone();
    forged.read_1 = TraceRead::new(reg(1), 3, 0);
    forged.read_2 = TraceRead::new(reg(2), 4, 0);
    forged.trace_step.write_1 = TraceWrite::new(reg(0), 7);
    forged.mem_witness = MemoryWitness::registers();
    v.push(("add x0, x1, x2", honest, forged, "add"));

    // misaligned lw x0, 1(x5): micro 2 is a nop for the emulator, the `lw_2` leaf continues to micro 3
    let traces = run_instruction(enc_i(1, 5, 2, 0, 0x03), &[(5, DATA)], &[0x1122_3344, 0x5566_7788]);
    assert_eq!(traces.len(), 3);
    let honest = traces[2].clone();
    let mut forged = honest.clone();
    forged.read_1 = TraceRead::new(AUX_1, traces[0].trace_step.write_1.value, traces[0].step_number);
    forged.read_2 = TraceRead::new(AUX_2, traces[1].trace_step.write_1.value, traces[1].step_number);
    forged.trace_step.write_1 = TraceWrite::new(AUX_1, forged.read_1.value | forged.read_2.value);
    forged.trace_step.write_pc = ProgramCounter::new(CODE, 3);
    forged.mem_witness = MemoryWitness::registers();
    v.push(("lw x0, 1(x5), micro 2", honest, forged, "lw_2"));
    v
}

#[test]
fn scr002_demo_instruction_leaves_accept_write_to_x0() {
    for (name, honest, forged, leaf) in scr002_cases() {
        println!("{}", name);
        assert_two_different_steps_accepted(&honest, &forged, leaf);
    }
}

#[test]
#[ignore = "SCR-002: fails until fixed"]
fn scr002_instruction_leaves_reject_rd0_write() {
    for (name, honest, forged, leaf) in scr002_cases() {
        assert!(honest_leaf_accepts(&honest), "{}: honest trace rejected", name);
        assert!(!leaf_accepts(leaf, &forged), "{}: `{}` leaf accepts a write to x0", name, leaf);
    }
}

// ---------------------------------------------------------------------------------------------
// SCR-003: ecall chooses halt vs. nop from an unconstrained read; a real halt can be skipped
// ---------------------------------------------------------------------------------------------

#[test]
fn scr003_demo_halt_can_be_proven_as_nop() {
    for a0 in [0u32, 1] {
        let honest = &run_instruction(ECALL, &[(17, 93), (10, a0)], &[])[0];
        let forged = nop_trace_for(honest); // read_1_value = 0 != 93 -> nop branch
        println!(
            "exit({}): honest halt accepted by `ecall` leaf: {}, forged 'continue to pc+4' accepted: {}",
            a0,
            honest_leaf_accepts(honest),
            leaf_accepts("ecall", &forged)
        );
        assert!(leaf_accepts("ecall", &forged));
        assert_eq!(honest_leaf_accepts(honest), a0 == 0, "a failing halt can't be proven (by design)");
    }
}

/// The read challenges refute a read whose VALUE is wrong for its ADDRESS. They can't refute a
/// read that is true but taken from the wrong address. The `ecall` leaf's non-halt branch (like
/// `nop`) never binds read_1 to a7, so the prover fills the read slots with true reads of x0
/// (`value 0, last_step INIT`) and skips the halt. No read leaf can win against those reads.
#[test]
fn scr003_demo_skip_halt_with_true_reads_is_unchallengeable() {
    let honest = &run_instruction(ECALL, &[(17, 93), (10, 0)], &[])[0];
    let mut forged = nop_trace_for(honest);
    forged.read_1 = TraceRead::new(reg(0), 0, LAST_STEP_INIT); // a true read of x0, not of a7
    forged.read_2 = TraceRead::new(reg(0), 0, LAST_STEP_INIT);
    assert!(leaf_accepts("ecall", &forged), "the forged skip must be provable");

    // candidate write steps for read_value: a step without write and steps that write a0 / a7
    let no_write = run_instruction(enc_b(8, 0, 0, 1), &[], &[]).remove(0).trace_step;
    let writes_a0 = run_instruction(enc_i(0, 0, 0, 10, 0x13), &[], &[]).remove(0).trace_step;
    let writes_a7 = run_instruction(enc_i(93, 0, 0, 17, 0x13), &[], &[]).remove(0).trace_step;
    let h = [0x42u8; 20];
    let registers = (REGISTERS_BASE_ADDRESS, REGISTERS_BASE_ADDRESS + 34 * 4 - 1);
    let mut wins = vec![];
    for selector in [1u32, 2] {
        for (name, step) in [("no-write", &no_write), ("writes a0", &writes_a0), ("writes a7", &writes_a7)] {
            let c = ChallengeType::ReadValue {
                prover_read_1: forged.read_1.clone(),
                prover_read_2: forged.read_2.clone(),
                read_selector: selector,
                prover_hash: hash_to_string(&h),
                trace: step.clone(),
                prover_next_hash: hash_to_string(&step_hash(&h, step)),
                prover_write_step_tk: 2,
                prover_conflict_step_tk: 9,
            };
            wins.push((format!("read_value(read_{}, {})", selector, name), execute_challenge(&c)));
        }
        let regs_chunk = Chunk { base_addr: REGISTERS_BASE_ADDRESS, data: vec![0; 34] }; // EMU-012 style
        wins.push((format!("initialized(read_{}, registers chunk)", selector), execute_challenge(&ChallengeType::InitializedData {
            prover_read_1: forged.read_1.clone(),
            prover_read_2: forged.read_2.clone(),
            read_selector: selector,
            chunk_index: 0,
            chunk: Some(regs_chunk),
        })));
        wins.push((format!("uninitialized(read_{}, registers range)", selector), execute_challenge(&ChallengeType::UninitializedData {
            prover_read_1: forged.read_1.clone(),
            prover_read_2: forged.read_2.clone(),
            read_selector: selector,
            sections: Some(SectionDefinition { ranges: vec![registers] }),
        })));
        wins.push((format!("future_read(read_{})", selector), execute_challenge(&ChallengeType::FutureRead {
            prover_conflict_step_tk: 9,
            prover_read_step_1: forged.read_1.last_step,
            prover_read_step_2: forged.read_2.last_step,
            read_selector: selector,
        })));
    }
    for (name, w) in &wins {
        println!("skip-halt with true x0 reads: {} -> verifier wins = {}", name, w);
    }
    assert!(wins.iter().all(|(_, w)| !w));
}

#[test]
#[ignore = "SCR-003: fails until fixed"]
fn scr003_ecall_leaf_rejects_skipping_a_halt() {
    let honest = &run_instruction(ECALL, &[(17, 93), (10, 0)], &[])[0];
    assert!(!leaf_accepts("ecall", &nop_trace_for(honest)));
}

// ---------------------------------------------------------------------------------------------
// SCR-005: divu / remu accept a wrong result when the divisor is > 2^31 + dividend / 2
// ---------------------------------------------------------------------------------------------

const RS1: u32 = 5;
const RS2: u32 = 6;
const RD: u32 = 7;

fn divu_forgery(a: u32, d: u32, rem: bool) -> (TraceRWStep, TraceRWStep) {
    let opcode = enc_r(0x01, RS2, RS1, if rem { 7 } else { 5 }, RD);
    let honest = run_instruction(opcode, &[(RS1, a), (RS2, d)], &[]).remove(0);
    // a < d, so the honest quotient is 0 and the honest remainder is a.
    // Forged: quotient 1, remainder a + 2^32 - d (the subtraction a - d*q wraps around).
    let (q, r) = (1u32, a.wrapping_sub(d));
    let mut forged = honest.clone();
    forged.trace_step.write_1.value = if rem { r } else { q };
    forged.witness = Some(if rem { q } else { r });
    (honest, forged)
}

#[test]
fn scr005_demo_divu_remu_accept_wrong_result() {
    for (a, d) in [(4u32, 0xffff_ffffu32), (0x7fff_ffff, 0xc000_0000), (0, 0x8000_0001), (0x1234, 0x9000_0000)] {
        for rem in [false, true] {
            let (honest, forged) = divu_forgery(a, d, rem);
            let op = if rem { "remu" } else { "divu" };
            println!(
                "{}(0x{:08x}, 0x{:08x}): honest = 0x{:08x}, forged = 0x{:08x} (witness 0x{:08x})",
                op, a, d, honest.trace_step.write_1.value, forged.trace_step.write_1.value, forged.witness.unwrap()
            );
            assert_two_different_steps_accepted(&honest, &forged, op);
            assert!(direct_script_accepts(&forged));
        }
    }
}

/// The condition is exactly `d > 2^31 + a/2` (with `a < d`): below that the forgery is rejected.
#[test]
fn scr005_check_boundary() {
    let a = 0x7fff_ffffu32;
    let boundary = 0x8000_0000u32 + a / 2; // forged remainder a - d (mod 2^32) must be < d
    for d in [boundary - 1, boundary, boundary + 1, boundary + 2] {
        let (_, forged) = divu_forgery(a, d, false);
        let r = a.wrapping_sub(d);
        println!("d = 0x{:08x}: forged remainder 0x{:08x} < d: {}, accepted: {}", d, r, r < d, leaf_accepts("divu", &forged));
        assert_eq!(leaf_accepts("divu", &forged), r < d);
    }
}

#[test]
#[ignore = "SCR-005: fails until fixed"]
fn scr005_divu_remu_reject_wrapped_forgery() {
    for rem in [false, true] {
        let (_, forged) = divu_forgery(4, 0xffff_ffff, rem);
        assert!(!direct_script_accepts(&forged));
    }
}

/// The signed variants are not affected: |divisor| <= 2^31.
#[test]
fn check_signed_div_rem_reject_same_forgery() {
    for (a, d) in [(4u32, 0xffff_ffffu32), (0x7fff_ffff, 0xc000_0000), (0x1234, 0x9000_0000)] {
        for (f3, rem) in [(4u32, false), (6, true)] {
            let opcode = enc_r(0x01, RS2, RS1, f3, RD);
            let honest = run_instruction(opcode, &[(RS1, a), (RS2, d)], &[]).remove(0);
            let mut forged = honest.clone();
            let (q, r) = (1u32, a.wrapping_sub(d));
            forged.trace_step.write_1.value = if rem { r } else { q };
            forged.witness = Some(if rem { q } else { r });
            if forged.trace_step.write_1.value != honest.trace_step.write_1.value {
                assert!(!direct_script_accepts(&forged), "signed f3={} a={:#x} d={:#x}", f3, a, d);
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// SCR-004 (CPU side): the step hash covers the whole micro byte; the client strips its high
// nibble before the EXECUTE leaf (see the client test `audit_scr_004_write_micro_nibble.rs`).
// ---------------------------------------------------------------------------------------------

#[test]
fn scr004_demo_micro_high_nibble_changes_hash_and_trace_hash_leaf_cannot_win() {
    let honest = &run_instruction(NOP, &[], &[])[0];
    let h0: [u8; 20] = generate_initial_step_hash().try_into().unwrap();
    let mut forged_step = honest.trace_step.clone();
    forged_step.write_pc = ProgramCounter::new(forged_step.write_pc.get_address(), 0x10);
    let honest_hash = step_hash(&h0, &honest.trace_step);
    let forged_hash = step_hash(&h0, &forged_step);
    assert_ne!(honest_hash, forged_hash);
    // the verifier cannot win the trace hash challenges against a consistent forged hash
    let trace_hash = ChallengeType::TraceHash {
        prover_step_hash: hash_to_string(&h0),
        prover_trace: forged_step.clone(),
        prover_next_hash: hash_to_string(&forged_hash),
    };
    let trace_hash_zero = ChallengeType::TraceHashZero {
        prover_trace: forged_step.clone(),
        prover_next_hash: hash_to_string(&forged_hash),
        prover_conflict_step_tk: 0,
    };
    assert!(!execute_challenge(&trace_hash));
    assert!(!execute_challenge(&trace_hash_zero));
    println!("micro 0x00 -> {}, micro 0x10 -> {}; trace_hash(_zero) leaves can't win", hash_to_string(&honest_hash), hash_to_string(&forged_hash));
}

// ---------------------------------------------------------------------------------------------
// SCR-006: read_value leaf ignores the memory witness: unused reads (address 0, last_step 0)
// "conflict" with any step that does not write (write address 0)
// ---------------------------------------------------------------------------------------------

fn scr006_challenge() -> (ChallengeType, TraceRWStep) {
    // step 3: an honest branch (no write: write address 0)
    let branch = run_instruction(enc_b(8, 0, 0, 1), &[], &[]).remove(0); // bne x0, x0 (not taken)
    assert_eq!(branch.trace_step.write_1.address, 0);
    assert_eq!(branch.mem_witness.write(), MemoryAccessType::Unused);
    // conflict step: an honest addi, read_2 is unused (default: address 0, value 0, last_step 0)
    let addi = run_instruction(enc_i(5, 2, 0, 1, 0x13), &[(2, 10)], &[]).remove(0);
    assert_eq!(addi.mem_witness.read_2(), MemoryAccessType::Unused);
    assert_eq!((addi.read_2.address, addi.read_2.value, addi.read_2.last_step), (0, 0, 0));

    let prover_hash = [0x42u8; 20]; // honest prover hash h_2 (any value)
    let next = step_hash(&prover_hash, &branch.trace_step); // honest h_3
    (
        ChallengeType::ReadValue {
            prover_read_1: addi.read_1.clone(),
            prover_read_2: addi.read_2.clone(),
            read_selector: 2,
            prover_hash: hash_to_string(&prover_hash),
            trace: branch.trace_step.clone(),
            prover_next_hash: hash_to_string(&next),
            prover_write_step_tk: 2, // -> write step 3
            prover_conflict_step_tk: 9,
        },
        addi,
    )
}

#[test]
fn scr006_demo_verifier_wins_read_value_on_unused_read() {
    let (challenge, _) = scr006_challenge();
    let verifier_wins = execute_challenge(&challenge);
    println!("read_value challenge against the UNUSED read_2 of an honest trace: verifier wins = {}", verifier_wins);
    assert!(verifier_wins);
}

#[test]
#[ignore = "SCR-006: fails until fixed"]
fn scr006_read_value_rejects_unused_read() {
    let (challenge, _) = scr006_challenge();
    assert!(!execute_challenge(&challenge));
}
