# SCR-006: The `read_value` leaf ignores the memory witness: an unused read "conflicts" with any step that doesn't write

* **Status:** Confirmed (executed with `execute_challenge`, the emulator's model of the leaf, on honest emulator traces). Fix proposed, **not validated**.
* **Severity:** Critical. A malicious verifier wins against an honest prover in practically every program.
  * It only needs one disputed step with an unused read, such as `addi`, `jal`, `lui`, a branch or a store micro.
  * And one earlier step without a write (any branch, `j`, `ret` or `nop`).
* **Area:**
  * `bitcoin-script-riscv/src/riscv/challenges.rs:513-586` (`read_value_challenge`).
  * Client `dispute/challenge.rs:129-145` (`READ_VALUE_CHALLENGE`): the leaf gets no `prover_mem_witness`.
  * Emulator: unused reads are `TraceRead::default()` = `(address 0, value 0, last_step 0)`. Steps without a write have `TraceWrite::default()` = `(address 0, value 0)`.

## Bug

The verifier wins `read_value` if, for the selected read `(read_addr, read_value, read_step)` and the write of step `write_step` (proven by the prover's hashes):

```
(read_step == write_step && (write_addr != read_addr || write_value != read_value))
|| ((read_step == INIT || read_step < write_step) && write_addr == read_addr)
```

The intended case: the prover says it read address `A` as last written at `read_step`, but a later step `write_step` (before the conflict step) wrote `A` again.

The leaf never checks whether the selected read is a real read. For an **unused** read, the honest prover's committed values are `(0, 0, 0)`, while every step that doesn't write commits `write_addr = 0`. So for any no-write step `k` with `1 <= k <= conflict_step`:
* `read_step = 0 < k = write_step`;
* `write_addr = 0 == read_addr`;
* so the verifier wins.

The other read leaves have the same blind spot: `initialized`, `uninitialized`, `input`, `rom` and `future_read` are not gated on the witness either. Today they can't be triggered with address 0 (no section, chunk or input covers address 0, and `last_step = 0` is never a future read). They would become exploitable if a program ever had a section at address 0.

## Attack (malicious verifier, honest prover)

1. The verifier disputes the prover's (correct) claim. In the conflict n-ary search it steers to a step `s+1` with an unused read. Almost every program has one: `addi` (read_2 unused), `lui`/`auipc`/`jal` (both unused), etc.
2. The prover reveals its honest trace. Its EXECUTE leaf succeeds.
3. The verifier posts `read_value_nary_search`, then steers the second n-ary search to any earlier step `k` that doesn't write (a branch, `j`, `ret`, `nop`). The prover has to give `h_{k-1}`, `h_k`.
4. The verifier posts `read_value` with:
   * `verifier_read_selector` set to the unused read;
   * `verifier_write_* =` the honest `trace_step` of `k`, i.e. `(0, 0, pc, 0)`. Its hash matches the prover's.
5. The leaf succeeds, and the verifier wins.

## Test

File: `emulator/tests/audit_scr.rs`. The conflict step is an honest `addi x1, x2, 5`, whose read_2 is unused. The write step is an honest `bne x0, x0` (not taken, no write). Both traces come from the emulator.

| Test | Kind | Result now |
|---|---|---|
| `scr006_demo_verifier_wins_read_value_on_unused_read` | `execute_challenge(ReadValue { read_selector: 2, .. })` on honest data | returns `true` (verifier wins; shows the bug) |
| `scr006_read_value_rejects_unused_read` | expected behaviour | **fails**, `#[ignore = "SCR-006: fails until fixed"]` |

## Proposed fix (preferred; not validated)

Gate every read-based leaf on the prover's memory witness. The witness is Winternitz-signed in the trace, and every EXECUTE leaf checks it as a full byte, so it is reliable.

1. Client `challenge.rs`: add `("prover_mem_witness", 1)` to `READ_VALUE_CHALLENGE`. For defence in depth, also add it to `INITIALIZED_CHALLENGE`, `UNINITIALIZED_CHALLENGE`, `FUTURE_READ_CHALLENGE`, `INPUT_CHALLENGE` and `ROM_CHALLENGE`.
2. `challenges.rs`: after `get_selected_vars` (or, for `input`/`rom`, per read), assert that the selected read's access type is not `Unused`:
   * read_1: `mem_witness` nibble 0, low 2 bits (`load_lower_half_nibble_table`);
   * read_2: nibble 1, high 2 bits (`load_upper_half_nibble_table`), the same layout as `addresses_sections_challenge`.

```rust
// mem_witness = read_1 << 4 | read_2 << 2 | write   (MemoryAccessType::Unused = 2)
fn assert_selected_read_is_used(stack: &mut StackTracker, mem_witness: StackVariable, read_selector: StackVariable) {
    let lower = load_lower_half_nibble_table(stack);
    let upper = load_upper_half_nibble_table(stack);
    stack.copy_var_sub_n(mem_witness, 0);
    stack.get_value_from_table(lower, None);          // read_1 type
    stack.copy_var_sub_n(mem_witness, 1);
    stack.get_value_from_table(upper, None);          // read_2 type
    stack.copy_var(read_selector);
    stack.number(1);
    stack.op_equal();
    stack.custom(script!{ OP_IF OP_DROP OP_ELSE OP_NIP OP_ENDIF }.compile(), 3, true, 0, "selected_type");
    stack.number(MemoryAccessType::Unused as u32);
    stack.op_equal();
    stack.op_not();
    stack.op_verify();
    stack.drop(upper); stack.drop(lower);  // (adjust to the actual stack order)
}
```

3. `execute_challenge` / `ChallengeType::ReadValue` (emulator model): push `prover_trace.mem_witness` too. Make the emulator's `verifier_choose_challenge` never select an unused read; it doesn't today, but assert it.

A CPU-only alternative that changes no leaf variables: make an honest unused read impossible to match.

* Example: emit unused reads as `(0xFFFF_FFFC, 0, LAST_STEP_INIT)`. That address is never written, because no section contains it.
* Reads are not hashed, but this needs care:
  * `op_load_micro_3` asserts `read_2 == (0, 0)`;
  * `addresses_sections_challenge` checks the alignment of unused reads too;
  * the "unused values are don't-care" weakness stays.

We recommend the witness gate.

## Risks / notes

* The preferred fix changes the read-challenge leaves (one more Winternitz variable). Roll it out with the other leaf changes.
* Keep the invariant in mind for future leaves: **a challenge leaf over a trace field must check that the field is meaningful for that step.** For reads, use the memory witness. For writes, the write witness. `addresses_sections` already gates its section checks on the witness, but not the alignment check (harmless today; see SCR-007).
