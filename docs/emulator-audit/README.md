# Emulator audit: how the emulator works in challenges

This document is a reference for anyone (human or agent) investigating bugs in
`BitVMX-CPU/emulator` that can affect the BitVMX dispute ("challenge") protocol.
Tickets for suspicious findings are in [`tickets/`](tickets/).

## 1. Crate map

| File | Responsibility |
|---|---|
| `emulator/src/loader/program.rs` | ELF loading, `Section`/`Registers`/`Program` memory model, sanity checks, checkpoints (serde JSON), ROM commitment, section definitions used by on-chain challenges (`read_write_sections`, `read_only_sections`, `register_sections`, `code_sections`), `get_uninitialized_ranges`. |
| `emulator/src/loader/program_definition.rs` | `ProgramDefinition` (config yaml: elf, `nary_search`, `max_steps`, `input_section_name`, `inputs`). Helpers used by the protocol: `execute_helper`, `get_execution_result`, `get_round_hashes`, `get_trace_step`, `load_program_from_checkpoint`. |
| `emulator/src/executor/fetcher.rs` | `execute_program` (the main loop: input loading, hashing, trace collection, checkpoints, fail injection) and `execute_step` (decode + execute one RISC-V (micro)instruction and produce a `TraceRWStep`). |
| `emulator/src/executor/alignment_masks.rs` | Masks/shifts for misaligned loads/stores split into microinstructions. |
| `emulator/src/executor/utils.rs` | `FailConfiguration` and friends: fault injection used by tests to simulate a dishonest prover/verifier. |
| `emulator/src/decision/nary_search.rs` | `NArySearchDefinition` (rounds, bits per round, required steps per round) and `choose_segment` (verifier decision per round). |
| `emulator/src/decision/challenge.rs` | The protocol-level entry points called by `rust-bitvmx-client` via the job dispatcher: `prover_execute`, `verifier_check_execution`, `prover_get_hashes_for_round`, `verifier_choose_segment`, `prover_final_trace`, `prover_get_hashes_and_step`, `verifier_choose_challenge`, `verifier_choose_challenge_for_read_challenge`. |
| `emulator/src/decision/execution_log.rs` | `ProverChallengeLog` / `VerifierChallengeLog` persisted as `challenge_log.json` between protocol steps. |
| `bitcoin-script-riscv/src/riscv/challenges.rs` | The on-chain scripts for each challenge type (what the emulator's decisions must agree with). |
| `rust-bitvmx-client/src/program/protocols/dispute/*` | Calls the emulator and builds the on-chain scripts (e.g. `challenge.rs:603` uses `get_uninitialized_ranges`). |

## 2. Execution model

* RISC-V 32 IM. Instructions are fetched only from code sections (`read_instruction`), data reads from code sections are rejected (`ReadFromExecuteOnlySection`), writes only to writable, non-code sections.
* Memory words are stored **big-endian encoded** in `Section::data` (`value.to_be()` on write, `u32::from_be` on read).
* Registers are a fake memory section `"registers"` at `REGISTERS_BASE_ADDRESS = 0xF000_0000`, 32 GP registers + 2 aux registers (`AUX_REGISTER_1 = 32`, `AUX_REGISTER_2 = 33`) = 136 bytes. All registers start at value 0 with `last_step = LAST_STEP_INIT (u64::MAX)` **except SP (x2), which starts at `STACK_BASE_ADDRESS + STACK_SIZE = 0xE080_0000`**.
* Each memory word / register keeps the `last_step` at which it was written. Never written ⇒ `LAST_STEP_INIT`.
* Misaligned loads/stores are split in **microinstructions** (`ProgramCounter { address, micro }`): loads use micros 0..3, `sb` 0..3, `sh`/`sw` 0..7. Aux registers carry intermediate values. The script side (`instruction_mapping.rs`) must match exactly.
* `ecall` with `a7 = 93` halts (PC is *not* advanced); `a7 = 116` is a putchar no-op; any other syscall is a no-op with an error log.

## 3. Steps, traces and hashes

* `program.step` starts at 0 (initial state, no trace). Executing an instruction increments the step first, so the first executed instruction is step 1.
* `TraceRWStep` for step `n` contains: `read_1`, `read_2` (address, value, last_step), `read_pc` (pc + opcode), `trace_step` (write_1 + next pc), witness (div/rem helper), `mem_witness` (which of read_1/read_2/write are register/memory/unused).
* Hash chain: `h0 = blake3(0xff)[..20]`, `h_n = blake3(h_{n-1} || trace_step_n.to_bytes())[..20]`. Only `trace_step` (write + next pc) is hashed, not the reads.
* `execute_program(..., trace_list: Option<Vec<u64>>, ...)` only records traces whose step is in `trace_list`. Note the special initial push: **before the loop**, if the program's current step is in `trace_list`, a `TraceRWStep::default()` is pushed together with the current hash (intended for step 0 / "base step" hash).
* Halts and errors are always pushed if their step is in `trace_list` (or there is no list).

## 4. Checkpoints

* During the first full run (`get_execution_result`, no `trace_list`) a checkpoint `checkpoint.<step>.json` is written to the output path every `CHECKPOINT_SIZE = 50_000_000` steps (state **after** executing that step), plus optionally at the final step (`save_non_checkpoint_steps`).
* Later queries (`execute_helper` with `steps`) load the checkpoint `floor(steps[0] / CHECKPOINT_SIZE) * CHECKPOINT_SIZE` (or reload the ELF if 0) and run forward. Input is only loaded when `step == 0`.
* There is no early exit once the last requested step is collected: the loop runs until halt/error/`max_steps`.

## 5. N-ary search

`NArySearchDefinition::new(max_steps, nary)`: `max_bits = ceil(log2(max_steps))`, `full_rounds = floor(max_bits / log2(nary))`, an optional last round with `nary_last_round = 2^(bits_left)` choices. Rounds are 1-based.

* Each round the prover publishes `nary-1` hashes at `required_steps(round, base)` (`get_round_hashes`). Prover caps `base` to its claimed `last_step`; missing hashes (program halted before them) are padded with the last obtained hash.
* The verifier (`choose_segment`) compares hashes:
  * `ConflictStep`: picks the **first** mismatching hash; the agreed step is `min(selected_step, mismatch_step - 1)`.
  * `ReadValueChallenge`: picks the **last** mismatch, bounded above by the conflict step.
* After the last round the selected step `s` is the last agreed step; the disputed trace is step `s+1`.
  The client passes `final_bits = decision + 1` to `prover_final_trace`.

## 6. Protocol flow (emulator side)

1. **Prover** `prover_execute`: run full program, commit `(last_step, last_hash)`.
2. **Verifier** `verifier_check_execution`: run with same input, decide to challenge; `step_to_challenge = min(claim_last_step, my_last_step) - 1`.
3. Rounds: prover `prover_get_hashes_for_round` ↔ verifier `verifier_choose_segment`.
4. **Prover** `prover_final_trace`: provides `TraceRWStep` of step `s+1` plus `h_s`, `h_{s+1}` (or `ChallengeStep` if the verifier selected a step beyond the prover's last step).
5. **Verifier** `verifier_choose_challenge` checks, in order: equivocation of resigned hashes, trace hash, halt, address sections, entrypoint/program counter, opcode, future read, read value conflict. Read value conflicts are decided by:
   * both `last_step == LAST_STEP_INIT` ⇒ static data challenge: `InputData`, `InitializedData`, or `UninitializedData` (value must be 0 in an uninitialized range).
   * otherwise ⇒ second n-ary search (`ReadValueNArySearch`) towards the step where the value was last written, finished by `verifier_choose_challenge_for_read_challenge` (`EquivocationHash`, `CorrectHash`, `ReadValue`).

Every one of these decisions must be **provable by an on-chain script** (`bitcoin-script-riscv/src/riscv/challenges.rs`). A bug class to keep in mind:

* **Honest party loses**: the emulator gives the honest prover a wrong trace/hash, or an on-chain script accepts a challenge against a correct trace.
* **Dishonest party wins**: the verifier panics / errors / picks a challenge that the script will reject, on input controlled by the other party (prover claims, prover traces, prover hashes). A panic in the verifier usually means it times out and the lying prover wins.
* **Liveness**: operations too slow for protocol timeouts.

## 7. Testing hints

* Integration tests live in `emulator/tests/` (`challenge.rs`, `exceptions.rs`, instruction tests with helpers in `tests/utils/common.rs`). Programs: `docker-riscv32/riscv32/build/*.elf`, program definitions (`*.yaml`) next to them.
* Fault injection (`FailConfiguration`) lets a test act as a dishonest party.
* Run a single integration test file with `cargo test -p emulator --test <file_name>` from `BitVMX-CPU/`.

## 8. Tickets

| Ticket | Summary | Verdict | Severity |
|---|---|---|---|
| [EMU-001](tickets/EMU-001-checkpoint-step-default-trace.md) | Trace query for a step that is a multiple of `CHECKPOINT_SIZE` returns `TraceRWStep::default()` | Confirmed | High |
| [EMU-002](tickets/EMU-002-registers-in-uninitialized-ranges.md) | Register section (non-zero initial SP) counted as uninitialized/zero memory | Confirmed | Critical |
| [EMU-003](tickets/EMU-003-read-last-step-zero-underflow.md) | Prover read `last_step = 0` → verifier underflow; no on-chain script can prove the lie | Confirmed | High |
| [EMU-004](tickets/EMU-004-verifier-panics-on-prover-claims.md) | `claim_last_step == 0` assert (blocked on-chain); new: power-of-two `max_steps` panics in `get_hashes` | Partially confirmed | Low / Medium |
| [EMU-005](tickets/EMU-005-round-hash-padding-after-halt.md) | Round hashes past halt padded with last requested hash (benign) | Partially confirmed | Low |
| [EMU-006](tickets/EMU-006-uninitialized-ranges-input-edge.md) | `get_uninitialized_ranges` panics when inputs exactly fill input section; initialized input section issues | Confirmed | Medium |
| [EMU-007](tickets/EMU-007-load-input-oob.md) | `load_input` out-of-bounds panic for oversized input (not reachable via client) | Partially confirmed | Low |
| [EMU-008](tickets/EMU-008-no-early-exit-trace-list.md) | Step queries always execute to halt/max_steps (timeouts) | Confirmed | Medium |
| [EMU-009](tickets/EMU-009-minor-issues.md) | Minor: ROM commitment, register range off-by-one, fail-injection underflows, unaligned entrypoint; div/rem witness OK | 5 confirmed, 1 refuted | Low |
| [EMU-010](tickets/EMU-010-read-value-search-mismatch-after-conflict.md) | Read-value search pulled to conflict step by mismatches after it → cheating prover wins (split from EMU-005) | Confirmed | High |
| [EMU-011](tickets/EMU-011-get-chunks-base-addr-unit.md) | `get_chunks` labels chunk `base_addr` in words instead of bytes → opcode/initialized chunks mislabeled, malicious verifier wins against honest prover | Confirmed | Critical |
| [EMU-012](tickets/EMU-012-registers-as-initialized-data.md) | Preferred fix for EMU-002: commit initial register values as initialized data (all 34 registers, no new challenge type, no client code change) | Fix validated | Critical |
| [EMU-013](tickets/EMU-013-input-leaf-byte-order.md) | Client `input` leaves compare input words in the wrong byte order: a malicious verifier wins against an honest prover on any non-palindromic input word (found in the client review) | Confirmed, fix validated | Critical |
| [EMU-014](tickets/EMU-014-client-rom-leaf-count.md) | Client `rom` leaves are dead code and their counter can shift every later challenge leaf by one (latent) | Confirmed (code reading) | Medium |

The client-side checks that do (or don't) mitigate each ticket are analysed in [client-mitigations.md](client-mitigations.md).

Findings in the on-chain scripts (`bitcoin-script-riscv`, the instruction leaves and their mapping) are in the separate [script audit](../script-audit/README.md) (SCR-001..007).
