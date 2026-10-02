# Script audit: `bitcoin-script-riscv` and its use by the emulator and the client

This audit covers the on-chain RISC-V scripts in `BitVMX-CPU/bitcoin-script-riscv`: the instruction leaves, the instruction-to-leaf mapping and the challenge leaves. It also covers the code on both sides that has to agree with them:
* the emulator (`emulator/src/executor/fetcher.rs`), which produces the traces;
* the client (`rust-bitvmx-client/src/program/protocols/dispute/*`), which builds and runs the leaves.

It follows the [emulator audit](../emulator-audit/README.md); read that first for the protocol (steps, hashes, n-ary search). Tickets are in [`tickets/`](tickets/).

## 1. Crate map

| File | Responsibility |
|---|---|
| `src/riscv/instruction_mapping.rs` | `get_key_from_instruction_and_micro` (opcode + micro → leaf key), `generate_sample_instructions` (one sample opcode per key), `create_verification_script_mapping` (key → `(script, requires_witness)`). |
| `src/riscv/instructions.rs` | `execute_step` (dispatch), `op_nop`, `op_ecall`, `op_conditional`, `op_jal(r)`, `op_arithmetic(_imm)`, `op_upper`, `compare_trace_step`, `verify` / `verify_execution` (used by the emulator's `verify_on_chain` mode). |
| `src/riscv/instructions_load.rs`, `instructions_store.rs`, `memory_alignment.rs` | Loads (micro 0..3) and stores (micro 0..7), including the misaligned split. |
| `src/riscv/decoder.rs` | Opcode decoding in script (I/B/R/S/J/U types). It checks the major opcode, funct3 and funct7, and returns `rs1`/`rs2`/`rd` as byte offsets (`reg * 4`). |
| `src/riscv/operations.rs`, `script_utils.rs` | Nibble arithmetic: add/sub/logic/shift/mul/mulh/div/rem, lookup tables, comparisons, `verify_challenge_step`, n-ary helpers. |
| `src/riscv/trace.rs` | `STraceRead` / `STraceStep`: the stack layout every instruction leaf consumes. |
| `src/riscv/challenges.rs` | The verifier's challenge leaves (`trace_hash`, `program_counter`, `halt`, `opcode`, `addresses_sections`, `input`/`rom`/`initialized`/`uninitialized`, `future_read`, `read_value`, `correct_hash`, `equivocation_*`) and `execute_challenge` (the emulator's off-chain model of them). |
| client `dispute/mod.rs` `execute_script`, `get_reverse_and_strip_scripts`, `build_trace_vars` | Builds one EXECUTE leaf per mapping key (sorted by key): Winternitz check + reverse + strip + instruction script. |
| client `dispute/execution.rs:216-231` | The **prover** picks the EXECUTE leaf with `get_key_from_opcode(trace.read_pc.opcode, micro)` and posts it. |
| client `dispute/challenge.rs` | Builds the verifier's challenge leaves (`CHALLENGES`, `READ_CHALLENGES`). |

## 2. How an instruction is proven on chain

1. After the n-ary search, the prover reveals the trace of the disputed step `s+1`. The revealed values are the Winternitz-signed variables in `TRACE_VARS`.
2. The prover runs the EXECUTE leaf for its own instruction. A leaf **succeeds iff** the `trace_step` it computes from the reads equals the committed one (`compare_trace_step`), and every opcode, address and witness check passes. If the leaf succeeds, the verifier can only win with a challenge leaf (trace hash, pc, opcode, read values, ...).
3. Stack layout seen by an instruction script, after the client's reverse and strip scripts (`trace.rs`):

```
write_1_add(8) write_1_value(8) write_pc(8) write_micro(1) [witness(8)]
mem_witness(2) read_1_add(8) read_1_value(8) read_2_add(8) read_2_value(8) read_pc(8) read_micro(1) opcode(8)
```

   Each value is a sequence of nibbles, most significant first. `write_micro` and `read_micro` are one byte each when signed, but the strip script cuts them to one nibble.
4. The step hash covers only `trace_step`: `write_add(4) | write_value(4) | write_pc(4) | write_micro(1)` (`TraceStep::to_bytes`, `trace_hash_challenge`). Reads are not hashed.

### Mapping keys

| Instruction | Key | Script | Note |
|---|---|---|---|
| `beq`..`bgeu` | `beq`..`bgeu` | `op_conditional` | |
| `jal`, `jalr` | `jal`, `jalr` | `op_jal(r)` | `rd == 0` handled in the leaf (`store_if_not_zero`) |
| `lb`, `lbu` | `lb_0`, `lbu_0` | `op_load_micro_0` | `rd == 0` handled in the leaf |
| `lh`, `lhu`, `lw` | `<name>_0..3` (micro > 1 with `rd == 0` → `nop`) | `op_load_micro_0..3` | micro 1..3 only for misaligned |
| `sb` | `sb_0..3` | `op_store_micro_0..3` | |
| `sh`, `sw` | `<name>_0..7` | `op_store_micro_0..3` (micro 4..7 = second word) | |
| OP-IMM, OP (incl. M), `lui`, `auipc` | name, or `nop` if `rd == 0` | `op_arithmetic_imm`, `op_arithmetic`, `op_upper` | |
| `fence`, `ebreak` | `nop` | `op_nop` | |
| `ecall` | `ecall` | `op_ecall` | halt branch iff `read_1_value == 93` |
| anything else | `get_key_*` **panics** | | |

## 3. Invariants the scripts must satisfy

* **Completeness:** every honest emulator trace is accepted by the leaf the client picks for it.
* **Uniqueness (soundness):** for a given opcode, `read_pc` micro and reads, **at most one** `trace_step` is accepted by **any** of the EXECUTE leaves. The prover chooses the leaf, so the opcode check of every leaf counts.
  * Every bit of the hashed `trace_step` must be fixed by the leaf.
  * Without uniqueness, a lying prover diverges on a step it can prove. The verifier's n-ary search lands on the first divergence, the prover proves that step, and nothing later is ever examined. **One non-unique step breaks every dispute.**
* **Challenge leaves:** they must not succeed against an honest trace (honest prover loses), and they must succeed against every lie the emulator's verifier detects (dishonest prover wins). This is the same as the emulator audit.

## 4. What was checked and found correct

* **Differential fuzzing** (`fuzz_honest_traces_accepted_and_mutations_rejected` in `emulator/tests/audit_scr.rs`):
  * Setup: random opcodes of every supported instruction (37 instruction kinds; `rd`/`rs1`/`rs2` including x0; edge-case and random register values; random alignments for loads and stores; all micro-steps).
  * Result: **78,040 honest traces** with 4 mutations each (`write_value ^ 1`, `write_address ^ 4`, `write_pc ^ 4`, `write_micro ^ 1`), and 0 mismatches. Every honest trace is accepted by its mapping leaf; every mutation is rejected.
  * Mapping scripts and the direct `verify_execution` agree.
  * So the arithmetic, the decoders, the alignment tables, the sign extension, mul/mulh and the signed div/rem with the witness all match the emulator for honest inputs.
* **Decoders:** the nibble layouts of I/B/S/J/U/R immediates and register fields were checked by hand against the RISC-V spec.
* **Signed div/rem:** the witness is unique. The magnitudes are bounded by 2^31, and the sign rules force the sign of any non-zero quotient and remainder.
* **Misaligned loads and stores:**
  * the masks (`create_alignment_table(_2)`) match `alignment_masks.rs`;
  * the micro sequence is enforced by the micro asserts and by the `program_counter` challenge;
  * the store micro 2 nibble-`ADD` is correct because the two aux values are disjoint by construction (see SCR-007).
* **Memory witness byte:** it is compared as a full byte in every leaf. The layout (`read_1 << 4 | read_2 << 2 | write`) matches `addresses_sections_challenge`.

## 5. Tickets

| Ticket | Summary | Who wins | Verdict | Severity |
|---|---|---|---|---|
| [SCR-001](tickets/SCR-001-nop-leaf-no-opcode-check.md) | The `nop` leaf, and the `ecall` leaf's non-halt branch, never check the opcode: **any** instruction can be proven as "no write, pc+4". | Lying prover | Confirmed; fix validated | Critical |
| [SCR-002](tickets/SCR-002-rd-zero-write-x0.md) | ALU, `lui`/`auipc` and `lw_2`/`lw_3` leaves accept `rd = x0`. A `nop` (`addi x0,x0,0`) can be proven both as a nop and as "write x0". | Lying prover | Confirmed; fix validated | Critical |
| [SCR-003](tickets/SCR-003-ecall-halt-skippable.md) | `ecall` picks halt or nop from `read_1_value`, which the nop branch never binds to a7 (the prover can report a true read of another register). A real halt (e.g. `exit(1)`) can be proven as "continue at pc+4". | Lying prover | Confirmed; fix validated (script + emulator) | Critical |
| [SCR-004](tickets/SCR-004-write-micro-high-nibble.md) | The client strip script drops the high nibble of `prover_write_micro` without checking it. That nibble is hashed, so a prover can fork its hash chain on any step. | Lying prover | Confirmed on the real leaf with real WOTS signatures; fix validated | Critical |
| [SCR-005](tickets/SCR-005-divu-remu-wraparound.md) | `divu`/`remu`: `div_check` subtracts mod 2^32. When `divisor > 2^31 + dividend/2`, the result `q=1`, `r=dividend-divisor` is accepted. | Lying prover | Confirmed; fix validated | High |
| [SCR-006](tickets/SCR-006-read-value-ignores-witness.md) | `read_value` (and the other read leaves) ignore `mem_witness`. An unused read (`0, 0, last_step 0`) "conflicts" with any step that does not write (write address 0). | Malicious verifier | Confirmed; fix proposed (not validated) | Critical |
| [SCR-007](tickets/SCR-007-minor-issues.md) | Minor: panics in `get_key_*`, RV64 shift encodings, unchecked micro/selection nibbles, halt rules, the store `ADD`, the TODOs. | | Mixed | Low / Info |

Severity rule (same as the EMU audit): if a party can win a dispute it should lose, on input it controls, the ticket is Critical. SCR-005 is High only because it needs the program to run a `divu`/`remu` with a divisor above 2^31 + dividend/2. Such divisors are common in 64-bit division routines (normalized divisors).

## 6. Tests

* CPU: `emulator/tests/audit_scr.rs`
  * `fuzz_*`, `check_*`: regressions; they pass now and must keep passing.
  * `scrNNN_demo_*`: show the bug; they pass now. Delete them when the fix lands.
  * `#[ignore = "SCR-0NN: fails until fixed"]`: the expected behaviour.

  ```
  cargo test --release -p emulator --test audit_scr -- --nocapture --include-ignored
  AUDIT_SCR_FUZZ=1500 cargo test --release -p emulator --test audit_scr -- --nocapture fuzz_honest   # long fuzz (~80 s)
  ```

* Client: `rust-bitvmx-client/tests/audit_scr_004_write_micro_nibble.rs`. It rebuilds the real EXECUTE leaf and runs it with real Winternitz signatures.

  ```
  cargo test --release --test audit_scr_004_write_micro_nibble -- --nocapture --include-ignored
  ```

## 7. Rollout notes

* Validated patches: [`patches/SCR-001-002-003.diff`](patches/SCR-001-002-003.diff) and [`patches/SCR-005.diff`](patches/SCR-005.diff) apply with `git apply` from `BitVMX-CPU/`. The SCR-004 fix is a client change; the diff is in its ticket.

* Every fix except SCR-006's CPU-only alternative changes the dispute taproot leaves. Ship them in the same coordinated version bump as EMU-011/012/013/014 and EMU-003. Existing dispute setups become incompatible.
* SCR-003 also changes the emulator trace of non-halt `ecall` steps: `read_1` becomes the a7 register read. Reads are not hashed, so hashes, checkpoints and n-ary searches don't change. Prover and verifier must still run the same emulator version.
* The SCR-001/002/003 fix keeps the mapping keys unchanged, so the client's leaf indexing does not move. SCR-006's preferred fix adds `prover_mem_witness` to the read-challenge leaves (client `challenge.rs`).
* After all fixes, re-run the fuzzer with a large `AUDIT_SCR_FUZZ`, plus the full `emulator` and `bitcoin-script-riscv` suites.
