# EMU-007: `load_input` panics (index out of bounds) when the input is larger than the input section

* **Status:** Partially confirmed (the panic is real, but `rust-bitvmx-client` can't reach it with prover-controlled data)
* **Severity:** Low (robustness / defense in depth). Initial guess was Medium. The prover can't choose the input length in the client flow, see Findings.
* **Area:** `emulator/src/loader/program.rs:203-226`

## Suspicion

```rust
for (i, byte) in input_as_u32.iter().enumerate() {
    section.data[i] = *byte;   // no bounds check
}
```

If `input.len()` is larger than the input section size, this panics instead of returning an `ExecutionResult` error. In `verifier_check_execution` and `verifier_choose_challenge` (`challenge.rs:453`) the input comes from the prover. Check in `rust-bitvmx-client` whether the input length is fixed or validated against `ProgramDefinition.inputs` before reaching the emulator. If not, a prover could crash the verifier.

Related things to check while here:
* The input is not checked against the declared `inputs` sizes (`ProgramDefinition.inputs`), so input bytes past the declared size end up in the "uninitialized" range (see EMU-006). That range is then challengeable as non-zero.
* `load_input` does not touch `last_step` (stays `LAST_STEP_INIT`). This is consistent with `InputData` challenges, but confirm.
* Endianness: `vec_u8_to_vec_u32(input, little)` stores the numeric value directly while sections store words BE-encoded. Confirm that `InputData` (`challenge.rs:719`, `read_mem`) and the on-chain input commitment use the same byte order.

## What to do

Write a test calling `Program::load_input` / `execute_program` with an oversized input (e.g. `hello-world.elf`) and show the panic. Propose a fix that returns an error (and decide what the verifier should do: an input that doesn't fit is an invalid input, so challenge it or reject it).

## Findings

### Verdict

**Partially confirmed.**
* The emulator bug is real. `Program::load_input` panics with `index out of bounds` for any input longer than the input section. One extra byte is enough, because it is padded to a full word. The panic propagates through `execute_program`, `ProgramDefinition::get_execution_result`, `prover_execute` and `verifier_check_execution`. Nothing returns an `ExecutionResult`.
* In the current `rust-bitvmx-client` flow, a prover **can't** reach it. The program input length is fixed at setup to exactly `sum(ProgramDefinition.inputs[*].size)` bytes. A program definition whose declared inputs exceed the input section already fails (panics) at protocol setup, before any execution (see "Reachability").
* Severity is lowered to **Low**. It remains a robustness issue for the CLI, the job dispatcher and any other library caller, and the fix is trivial.

### Root cause

`emulator/src/loader/program.rs:212-217`:

```rust
let input_as_u32 = vec_u8_to_vec_u32(&input, little_endian);   // pads to a multiple of 4
for (i, byte) in input_as_u32.iter().enumerate() {
    section.data[i] = *byte;                                   // no bounds check -> panic
}
```

* `section.data` has `size / 4` words (`Section::new_with_data` / `load_elf`, `program.rs:789-804`). For `hello-world.elf`, `.input` is 8192 bytes = 2048 words. The observed panic is `index out of bounds: the len is 2048 but the index is 2048` at `program.rs:216:33`.
* The loop writes word by word, so an error after a partial write would also leave the section half-written. A fix must check before it writes.
* `execute_program` (`emulator/src/executor/fetcher.rs:42-45`) already handles an `Err` from `load_input`, so the only change needed is to return an error instead of indexing out of bounds.

### Reachability: where the input comes from in `rust-bitvmx-client`

1. **Setup.** `generate_input_owner_list` (`rust-bitvmx-client/src/program/protocols/dispute/input_handler.rs:27-63`) turns each `ProgramDefinition.inputs[i]` into `size / 4` words and rejects sizes that are 0 or not a multiple of 4. `generate_keys` (`dispute/mod.rs:315-322`) creates one Winternitz key **of 4 bytes** (`next_winternitz(4, ...)`) per word. The `prover_prev` inputs come from 4-byte keys of the previous protocol: the cardinal `slot.rs:159-168` keys and the union `dispute_core.rs:368-385` keys (`COSIGN_SLOT_SIZE = 4`).
2. **Execution.**
   * `unify_witnesses` (`input_handler.rs:230-264`) concatenates `message_bytes()` of exactly `input_txs_sizes[idx]` witnesses.
   * `unify_inputs` (`input_handler.rs:266-334`) concatenates the per-tx inputs (or `input_txs_sizes[idx]` previous-protocol witnesses for `prover_prev`).
   * Witnesses are decoded with the key's declared size (`protocol_handler.rs:595-609`, `decode_witness(sizes, ...)`), and the on-chain Winternitz check script enforces that size.
   * The result is passed to `ProverExecute` / `VerifierCheckExecution` in `dispute/tx_news.rs:283-340`.
   * So `input.len() == 4 * total_words == sum(inputs.size)` always holds, and the prover can't make it longer.
3. **Oversized definitions fail at setup.** If `sum(inputs.size)` exceeds the input section size, `challenge_scripts` (`dispute/challenge.rs:603`) calls `Program::get_uninitialized_ranges` while building the protocol. That function `assert!`s (`program.rs:680-686`), so setup fails for both parties before any input exists (the panic-vs-error aspect of that is EMU-006).
4. `verifier_choose_challenge` (`challenge.rs:453`) and the round/trace helpers reload `verifier_log.input` / `challenge_log.input`. That is the same vector the verifier already ran in `verifier_check_execution`, so they can't panic if the first run didn't.
5. The job dispatcher (`rust-bitvmx-job-dispatcher/jobtypes/src/emulator_messages.rs:49-90`) runs the emulator CLI as a subprocess with the input hex-encoded. A panic there kills only that job process. The client then never gets a result for the job, which in a real dispute means a timeout.

**Scenario if the length were ever not fixed:** for example, a future input owner type, a variable-length input, a decoding change, or a direct integration that passes prover-published bytes without validating them. The prover would publish an input longer than the input section. `verifier_check_execution` would then panic instead of returning, and the verifier would miss its protocol deadlines, so a lying prover wins. That is the "dishonest party wins" class from README §6. Today this needs a client-side bug, not just a malicious prover.

### Related points from the ticket

* **Input not checked against the declared `inputs`.** Confirmed: neither the emulator nor `ProgramDefinition::execute_helper` compares `input.len()` with `sum(inputs.size)`. A longer input (still within the section) is accepted. Its extra words land in the range that `get_uninitialized_ranges` publishes as must-be-zero. Test `doc_input_longer_than_declared_is_accepted` writes `0xAAAAAAAA` at `0xaa000004`, inside the uninitialized range `(0xaa000004, 0xaa001fff)`. The client always passes exactly the declared length, so this is not exploitable today. It is a consistency gap (follow-up below).
* **`last_step` after `load_input`.** Confirmed `LAST_STEP_INIT`. `load_input` only writes `section.data`, and `last_step` keeps its `LAST_STEP_INIT` initialization from `new_with_data`. This matches the `InputData` path in `verifier_choose_challenge` (`challenge.rs:701-726`, both last steps `== LAST_STEP_INIT`) and the `input_challenge` script (`bitcoin-script-riscv/src/riscv/challenges.rs:31-68`, which checks `prover_last_step == LAST_STEP_INIT`). Test: `doc_exact_fit_last_step_and_byte_order`.
* **Endianness.**
  * Inside the emulator it is consistent. With `little_endian = false` (the value every protocol path uses: `program_definition.rs:109` and `challenge.rs:456`), `vec_u8_to_vec_u32` does `from_be_bytes`, `read_mem` does `u32::from_be`, so `read_mem(start) == u32::from_le_bytes(input[0..4])`. Byte `i` of the input sits at address `start + i` in RISC-V little-endian memory, which is the same convention as ELF `PROGBITS` data (`program.rs:790`). `hello-world` with input `11 11 11 11` halts with 0.
  * `InputData` uses `read_mem` (`challenge.rs:719`), so the `input_for_address` it reports matches the trace read values.
  * Not verified here: whether the client's on-chain input commitment matches the read value's byte order for non-palindromic words. The prover input word is committed as raw message bytes. Read values are committed via `set_input_u32(value.to_be_bytes())`. For the `Const` path the client builds the expected value with `u32::from_be_bytes(bytes)` (`dispute/challenge.rs:447-450`), while the emulator reads `u32::from_le_bytes(bytes)`. These two look inconsistent for non-palindromic words. All existing examples use palindromic inputs (`0x11111111`), so this needs an end-to-end client test (follow-up).

### Tests

File: `emulator/tests/audit_emu_007.rs`

| Test | Kind | Current result |
|---|---|---|
| `demo_load_input_oversized_panics` | `#[should_panic(expected = "index out of bounds")]`, input = section + 4 bytes | passes (bug present) |
| `demo_load_input_one_extra_byte_panics` | `#[should_panic]`, input = section + 1 byte | passes (bug present) |
| `demo_verifier_check_execution_oversized_panics` | `#[should_panic]` via the protocol entry point | passes (bug present) |
| `expected_load_input_oversized_returns_error` | correct behavior: no panic, `Err`, section untouched, exact fit OK | `#[ignore = "EMU-007: fails until fixed"]`, fails today |
| `expected_verifier_check_execution_oversized_returns_error` | correct behavior: `verifier_check_execution` returns `Err`, no panic | `#[ignore = "EMU-007: fails until fixed"]`, fails today |
| `doc_exact_fit_last_step_and_byte_order` | documents `LAST_STEP_INIT` and byte order | passes |
| `doc_input_longer_than_declared_is_accepted` | documents the missing check against declared `inputs` | passes |

Command (from `BitVMX-CPU/`):

```
cargo test -p emulator --test audit_emu_007 -- --nocapture --include-ignored
```

Relevant output on the unfixed tree:

```
hello-world .input size = 8192 bytes
thread 'demo_load_input_oversized_panics' panicked at emulator\src\loader\program.rs:216:33:
index out of bounds: the len is 2048 but the index is 2048
test demo_load_input_oversized_panics - should panic ... ok
test demo_load_input_one_extra_byte_panics - should panic ... ok
test demo_verifier_check_execution_oversized_panics - should panic ... ok
thread 'expected_load_input_oversized_returns_error' panicked at emulator\tests\audit_emu_007.rs:108:23:
load_input panicked for input of size+1 bytes
test expected_load_input_oversized_returns_error ... FAILED
thread 'expected_verifier_check_execution_oversized_returns_error' panicked at emulator\tests\audit_emu_007.rs:144:19:
verifier_check_execution must not panic on an oversized input: Any { .. }
test expected_verifier_check_execution_oversized_returns_error ... FAILED
declared input = 4 bytes, word at 0xaa000004 = 0xAAAAAAAA is inside an uninitialized range [..., (2852126724, 2852134911)]
test result: FAILED. 5 passed; 2 failed
```

Without `--include-ignored` the suite is green: 5 passed, 2 ignored.

### Proposed fix

```diff
--- a/emulator/src/lib.rs
+++ b/emulator/src/lib.rs
@@ -72,6 +72,9 @@
 
     #[error("Can't read from execute only section")]
     ReadFromExecuteOnlySection,
+
+    #[error("Input of {0} bytes does not fit in the input section ({1} bytes)")]
+    InputTooLarge(u64, u32),
 }
 
 pub mod constants {
--- a/emulator/src/loader/program.rs
+++ b/emulator/src/loader/program.rs
@@ -212,9 +212,13 @@
         if !input.is_empty() && self.step == 0 {
             if let Some(section) = self.find_section_by_name_mut(input_section_name) {
                 let input_as_u32 = vec_u8_to_vec_u32(&input, little_endian);
-                for (i, byte) in input_as_u32.iter().enumerate() {
-                    section.data[i] = *byte;
+                if input_as_u32.len() > section.data.len() {
+                    return Err(ExecutionResult::InputTooLarge(
+                        input.len() as u64,
+                        section.size,
+                    ));
                 }
+                section.data[..input_as_u32.len()].copy_from_slice(&input_as_u32);
             } else {
                 return Err(ExecutionResult::SectionNotFound(
                     input_section_name.to_string(),
```

**Validation.** The diff was applied to a scratch copy of the workspace (separate `CARGO_TARGET_DIR`), not the shared tree. Results:
* Both `expected_*` tests pass.
* The three `demo_*` `should_panic` tests now fail ("did not panic"), as intended. They should be removed or inverted when the fix lands.
* `cargo test -p emulator --lib --test challenge --test exceptions` passes (70 + 1 + 1).

**Risks and side effects:**
* `ExecutionResult` gains a variant. It derives `Serialize`/`Deserialize`. No exhaustive `match` exists in this repo, the client or the job dispatcher (grep), but any consumer deserializing an `ExecutionResult` produced by a newer emulator needs the new version.
* With the fix, `verifier_check_execution` / `prover_execute` return `Err(EmulatorError::CantObtainTrace)`, not the specific `InputTooLarge`. `execute_program` returns an empty trace on a `load_input` error, and `get_execution_result` (`program_definition.rs:142-144`) maps an empty trace to `CantObtainTrace`. Optional improvement: in `get_execution_result`, return `Err(result.into())` when the trace is empty and `result` is not a `Halt`.
* **What the verifier should do with an input that doesn't fit:** reject it (return an error). It can't be challenged on-chain. No challenge script expresses "input too long", and in the client the input is a fixed set of 4-byte Winternitz words, so such an input can't be committed in the first place. If a future protocol allows variable-length inputs, the length must be bounded at commitment time (script side), not only in the emulator.

### Follow-ups

1. Optionally validate `input.len() <= sum(inputs.size)`, or `==`, in `ProgramDefinition::execute_helper` and the CLI. Today extra bytes silently land in the must-be-zero range (test `doc_input_longer_than_declared_is_accepted`). Check the existing CLI/tests that pass inputs of other lengths before making this strict.
2. Validate `sum(inputs.size) <= input section size` once, when the program definition is loaded, and return an error there. Today this case surfaces as the `get_uninitialized_ranges` assert at client setup (EMU-006).
3. Add an end-to-end client test of the `InputData` challenge (and the `Const` input / `rom_challenge` path) with a **non-palindromic** input word, to confirm the byte order between the Winternitz-committed input words, `set_input_u32(value.to_be_bytes())` read values, and the emulator's `read_mem` (see Endianness above).
4. `merge_sections` (`program.rs:263-278`) renames merged sections to `merge_<a>_<b>`. If `.input` were ever merged with an adjacent compatible section, `find_section_by_name(".input")` would fail (`SectionNotFound`) and the input-section logic in `get_uninitialized_ranges` and the client would break. This doesn't happen for current ELFs, but it's worth an assertion or exclusion.

## Client-side check (rust-bitvmx-client `dispute/*`)

**Endianness question resolved: it is a real bug, tracked as [EMU-013](EMU-013-input-leaf-byte-order.md) (Critical).**
* Prover input words are signed as raw bytes, and Const words compiled as `from_be_bytes`.
* The read values are signed as `to_be_bytes(from_le_bytes(bytes))`.
* So any non-palindromic input word makes the `input` leaf succeed against an honest prover. This was confirmed by running the real leaves with real WOTS signatures.

See [client-mitigations.md](../client-mitigations.md).
