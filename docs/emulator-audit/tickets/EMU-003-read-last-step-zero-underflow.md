# EMU-003: The verifier underflows or panics when the prover claims a read `last_step` of 0

* **Status:** Confirmed
* **Severity:** High (confirmed). A dishonest prover can make the verifier unable to win a read-value dispute. The verifier panics (debug) or runs a nonsense search (release), and no existing on-chain script can prove the lie.
* **Area:** `emulator/src/decision/challenge.rs:757-780` (`verifier_choose_challenge`, read-value conflict branch)

## Suspicion

When the prover's read value conflicts with the verifier's, and the two `last_step` values are not both `LAST_STEP_INIT`:

```rust
let step_to_challenge = if conflict_last_step == LAST_STEP_INIT { my_conflict_last_step }
    else if my_conflict_last_step == LAST_STEP_INIT { conflict_last_step }
    else { conflict_last_step.max(my_conflict_last_step) };
let mut bits = nary_def.step_bits_for_round(1, step_to_challenge - 1);
...
read_challenge_log.step_to_challenge = step_to_challenge - 1;
verifier_log.read_step = step_to_challenge - 1;
```

A dishonest prover controls `conflict_last_step`. If it claims `last_step = 0` for a read and the verifier's own last step is `LAST_STEP_INIT`, then `step_to_challenge = 0` and `0 - 1` underflows:
* debug build: panic, so the verifier never posts a challenge;
* release build: wraps to `u64::MAX`, so the read-value n-ary search targets a nonsense step.

Step 0 is the initial state and nothing is ever written at step 0, so `last_step = 0` is always a lie. The future-read check (`prover_read_step > step`) doesn't catch it.
Also review what happens when the prover claims a `last_step` that is `<= step` but is larger than `max_steps` or not reachable, and whether `step_bits_for_round` / later rounds behave.

## What to do

1. Write a test (integration test using a `FailConfiguration` with `fail_reads`, see `executor/utils.rs` `FailRead`, and the existing tests in `emulator/tests/` or the unit tests at the bottom of `challenge.rs`) where the prover's final trace has a read with a wrong value and `last_step = 0`. Call `verifier_choose_challenge` and observe the panic or wrap.
2. Determine which challenge the verifier *should* issue. Is there an on-chain script that can prove "last_step 0 is invalid"? Check `future_read_challenge`, `read_value_*` and the n-ary scripts in `bitcoin-script-riscv/src/riscv/challenges.rs`. Can the read-value search with target step 0 work (`get_hashes` has a special case for step 0)?
3. Propose a fix.

## Findings

### Verdict

**Confirmed, and the problem goes further than the ticket suggests.** On top of the `0 - 1` underflow in the emulator, **no on-chain challenge script can prove that `last_step = 0` is a lie** for an address that was never written. So fixing only the arithmetic is not enough: a script change is needed too.

### Root cause

* `emulator/src/decision/challenge.rs:659-676`: the only plausibility check on the prover's read steps is the future-read check `last_step > step && last_step != LAST_STEP_INIT`. It accepts `last_step = 0`.
* `challenge.rs:679-680`: a value conflict is detected. `challenge.rs:701` takes the static-data branch only when *both* last steps are `LAST_STEP_INIT`. With prover `0` and verifier `LAST_STEP_INIT`, it falls through to `challenge.rs:757-763` and gets `step_to_challenge = 0`.
* `challenge.rs:765` (`step_bits_for_round(1, step_to_challenge - 1)`), `:768` and `:780` compute `0 - 1`.
  * Debug or `overflow-checks` builds panic with `attempt to subtract with overflow`. The workspace has no `[profile]` override, so the default `dev` profile panics.
  * Release builds wrap to `u64::MAX`. Round-1 bits become `nary-1`, so the search starts at the top of the step space, far beyond the conflict step. Later rounds are clamped by `choose_segment` to the conflict step, but the decision bits stay in the top segment. In `verifier_choose_challenge_for_read_challenge`, `get_hashes(mapping, .., challenge_step)` (`challenge.rs:387`) then looks up a step that is not in the mapping and panics on `unwrap()` (this was reasoned through, not executed in a release build). In any case the verifier cannot produce a valid `ReadValue` challenge.
* On-chain gap (`bitcoin-script-riscv/src/riscv/challenges.rs`):
  * `input_challenge`, `rom_challenge`, `initialized_challenge` and `uninitialized_challenge` all require `read_step == LAST_STEP_INIT` (`:45`, `:84`, `:468`, `:504`).
  * `future_read_challenge` (`:617-638`) requires `conflict_step < read_step`.
  * `read_value_challenge` (`:513-586`) needs a trace at `write_step >= 1`, and either `read_step == write_step`, or `read_step < write_step` with `write_addr == read_addr`. If the address was never written up to the conflict step, there is no write the verifier could show.
  * Result: when the verifier's own `last_step` is `LAST_STEP_INIT`, a lie with `last_step = 0` cannot be proven.
* Why `last_step = 0` is always a lie for a *used* read: `program.step` is 0 only before the first instruction. `load_input` does not touch `last_step` (it stays `LAST_STEP_INIT`). Registers and sections are initialised to `LAST_STEP_INIT` (`loader/program.rs:45,67,133`), and every write is made at step >= 1.
* Caveat: **unused** reads (`MemoryAccessType::Unused`) are `TraceRead::default()`, i.e. `{address 0, value 0, last_step 0}` (e.g. `executor/fetcher.rs:288,470,660,1128`). So `last_step == 0` is legitimate in honest traces for unused slots. Any rule like "last_step 0 is invalid" must take the memory witness into account, or a dishonest verifier could challenge an honest prover.

Other cases the ticket asked about (analysed by reading the code, not tested):
* `1 <= last_step <= step` but never actually a write to that address: target = `max(prover, verifier)`. `ReadValue` then wins with `read_step == write_step && write_addr != read_addr`, or with `read_step < write_step && write_addr == read_addr`. `last_step = 1` gives `challenge_step = 0`, which `get_hashes` handles.
* `last_step > max_steps` is always `> step`, so `FutureRead` catches it.
* Prover `last_step = 0` while the verifier's `last_step = w >= 1`: target `w`, `ReadValue` with `read_step(0) < write_step(w)`. The verifier wins.
* Related, hardening only: `is_read_X_conflict` (`challenge.rs:679-680`) also compares *unused* read slots. If an unused `read_1` with a tampered value were picked, the verifier's own `last_step` would be 0 and the same underflow would follow. In practice no instruction has an unused `read_1` with a used `read_2`, and a tampered unused slot alone cannot cause a hash divergence, because the EXECUTE script enforces the memory witness (`bitcoin-script-riscv/src/riscv/instructions.rs:48`). So this is defensive only.

### Attack scenario

The prover runs the program honestly except for one used read at step `k`. It returns a wrong value `V` for an address that has never been written (uninitialised, initialised, or input data) and commits `last_step = 0` instead of `LAST_STEP_INIT`. Its trace is internally consistent with `V`: the EXECUTE script accepts it, and its hash chain is built on it. The conflict n-ary search ends at `k`. In `verifier_choose_challenge` none of the earlier checks fire (equivocation, trace hash, halt, sections, PC, opcode, future read). The value conflict then leads to `0 - 1`. The verifier job panics, or in release produces a search it cannot finish. Either way it posts no winnable challenge, the prover's timeout path wins, and **the prover gets a false result accepted** (for example, it reads a chosen value from a zeroed buffer).

### Tests

File: `emulator/tests/audit_emu_003.rs`. It mirrors `test_challenge_uninitialized`: program `hello-world-uninitialized.yaml`, a `FailRead` on step 9 `read_2` @ `0xa0001004`, value `0x11111100`. Checkpoints go under `%TEMP%/bitvmx-audit-emu-003/`.

| Test | Kind | Current result |
|---|---|---|
| `emu_003_control_last_step_init_is_challenged` | control: the same lie with `LAST_STEP_INIT` produces `UninitializedData`, which the script accepts | pass |
| `emu_003_verifier_wins_against_read_last_step_zero` | **expected behaviour**: the verifier must not panic and its final challenge must pass `execute_challenge` | **fails**, `#[ignore = "EMU-003: fails until fixed"]` |
| `emu_003_demo_verifier_underflows_on_read_last_step_zero` | demonstration, `#[should_panic(expected = "attempt to subtract with overflow")]` (debug builds only) | pass (shows the bug) |
| `emu_003_demo_no_script_rejects_last_step_zero` | demonstration: `UninitializedData` and `FutureRead` with `last_step = 0` both return `false` from `execute_challenge` (controls with `INIT` / `step+1` return `true`) | pass (shows the on-chain gap) |

Command (from `BitVMX-CPU/`):

```
cargo test -p emulator --test audit_emu_003 -- --nocapture --include-ignored
```

Relevant output:

```
EMU-003 last_step=0: UninitializedData -> false, FutureRead -> false
EMU-003 [expected] ... prover read_2 = TraceRead { address: 2684358660, value: 286331136, last_step: 0 }
thread 'emu_003_verifier_wins_against_read_last_step_zero' panicked at emulator\src\decision\challenge.rs:765:60:
attempt to subtract with overflow
test emu_003_verifier_wins_against_read_last_step_zero ... FAILED
test emu_003_demo_verifier_underflows_on_read_last_step_zero - should panic ... ok
test emu_003_control_last_step_init_is_challenged ... ok
```

Without `--include-ignored`: `3 passed; 0 failed; 1 ignored`.

### Proposed fix

Extend the existing `FutureRead` challenge into an "impossible read step" challenge. A **used** read (the memory witness for that slot is not `Unused`) with `last_step == 0` is provably a lie. The memory witness is committed by the prover (`prover_mem_witness`, already used by `addresses_sections`) and enforced by the EXECUTE script (`verify_memory_witness`), so it can be trusted on-chain.

1. `definitions`: add `prover_mem_witness: u8` to `ChallengeType::FutureRead`.
2. `bitcoin-script-riscv`: `future_read_challenge` takes an extra `prover_mem_witness` (2 nibbles). It accepts if `(selected_step != INIT && conflict_step < selected_step) || (read_1 used && read_step_1 == 0) || (read_2 used && read_step_2 == 0)`.
3. `emulator`:
   * Treat `last_step == 0` on a used read as a future/impossible read.
   * Only compare values of used reads.
   * Keep an explicit error instead of `0 - 1` as a final guard.
4. `rust-bitvmx-client` (not part of the diff below):
   * Append `("prover_mem_witness", 1)` to `FUTURE_READ_CHALLENGE` (`src/program/protocols/dispute/challenge.rs:119`), after `verifier_read_selector`, so the order matches the script.
   * Add `prover_mem_witness: _` to the `ChallengeType::FutureRead` pattern (`challenge.rs:914`).

```diff
diff --git a/bitcoin-script-riscv/src/riscv/challenges.rs b/bitcoin-script-riscv/src/riscv/challenges.rs
index c9239a5..69a2626 100644
--- a/bitcoin-script-riscv/src/riscv/challenges.rs
+++ b/bitcoin-script-riscv/src/riscv/challenges.rs
@@ -622,18 +622,65 @@ pub fn future_read_challenge(stack: &mut StackTracker) {
     let read_step_2 = stack.define(16, "prover_read_step_2");
 
     let read_selector = stack.define(1, "read_selector");
+    let memory_witness = stack.define(2, "prover_mem_witness");
+
+    // Impossible read step: step 0 is the initial state (it has no trace) so nothing is ever
+    // written at step 0. A *used* read (witness != Unused) claiming last_step == 0 is always a lie.
+    // Unused reads are TraceRead::default() (last_step == 0) in honest traces, so they are excluded.
+    let upper_half_nibble_table = load_upper_half_nibble_table(stack);
+    let lower_half_nibble_table = load_lower_half_nibble_table(stack);
+
+    witness_equals(
+        stack,
+        &lower_half_nibble_table,
+        0,
+        &memory_witness,
+        MemoryAccessType::Unused,
+    );
+    stack.op_not();
+    let read_step_1_copy = stack.copy_var(read_step_1);
+    let zero = stack.number_u64(0);
+    stack.equality(read_step_1_copy, true, zero, true, true, false);
+    stack.op_booland();
+
+    witness_equals(
+        stack,
+        &upper_half_nibble_table,
+        1,
+        &memory_witness,
+        MemoryAccessType::Unused,
+    );
+    stack.op_not();
+    let read_step_2_copy = stack.copy_var(read_step_2);
+    let zero = stack.number_u64(0);
+    stack.equality(read_step_2_copy, true, zero, true, true, false);
+    stack.op_booland();
+
+    stack.op_boolor();
+    stack.to_altstack();
+
+    stack.drop(lower_half_nibble_table);
+    stack.drop(upper_half_nibble_table);
+    stack.drop(memory_witness);
 
     let [read_step] = get_selected_vars(stack, [read_step_1], [read_step_2], read_selector);
 
     // read_step != LAST_STEP_INIT
     let init = stack.number_u64(LAST_STEP_INIT);
-    stack.equality(read_step, false, init, true, false, true);
+    stack.equality(read_step, false, init, true, false, false);
+    stack.to_altstack();
 
     // The first step corresponds to the step selected by the decision bits, and the second step
     // is the step of the given trace, that trace corresponds to the next step selected so
     // if both steps are the same that means that the trace did a read to a value writen in the previous step.
     // so step == read_step is valid and we shouldn't be able to challenge it, only if step < read_step ≡ trace_step <= read_step
     is_lower_than(stack, step, read_step, true);
+    stack.from_altstack();
+    stack.op_booland();
+
+    // future read || impossible (zero) read step
+    stack.from_altstack();
+    stack.op_boolor();
     stack.op_verify();
 }
 
@@ -932,11 +979,13 @@ pub fn execute_challenge(challege_type: &ChallengeType) -> bool {
             prover_read_step_1,
             prover_read_step_2,
             read_selector,
+            prover_mem_witness,
         } => {
             stack.number_u64(*prover_conflict_step_tk);
             stack.number_u64(*prover_read_step_1);
             stack.number_u64(*prover_read_step_2);
             stack.number(*read_selector);
+            stack.byte(*prover_mem_witness);
 
             future_read_challenge(&mut stack);
         }
@@ -2155,12 +2204,23 @@ mod tests {
     }
 
     fn test_future_read_aux(step: u64, read_step: u64) -> bool {
+        test_future_read_witness_aux(step, read_step, read_step, 1, MemoryWitness::registers())
+    }
+
+    fn test_future_read_witness_aux(
+        step: u64,
+        read_step_1: u64,
+        read_step_2: u64,
+        read_selector: u32,
+        witness: MemoryWitness,
+    ) -> bool {
         let stack = &mut StackTracker::new();
 
         stack.number_u64(step);
-        stack.number_u64(read_step); // read_1_step
-        stack.number_u64(read_step); // read_2_step
-        stack.number(1); // read_selector
+        stack.number_u64(read_step_1); // read_1_step
+        stack.number_u64(read_step_2); // read_2_step
+        stack.number(read_selector); // read_selector
+        stack.byte(witness.byte()); // memory witness
 
         future_read_challenge(stack);
 
@@ -2182,6 +2242,21 @@ mod tests {
 
         // challenge is valid if read after current step
         assert!(test_future_read_aux(step, step + 1));
+
+        // EMU-003: a used read can never have last_step == 0
+        assert!(test_future_read_aux(step, 0));
+        let rur = MemoryWitness::rur();
+        assert!(test_future_read_witness_aux(step, 0, 0, 1, rur.clone()));
+        assert!(test_future_read_witness_aux(step, 0, 0, 2, rur.clone()));
+        assert!(test_future_read_witness_aux(step, 0, LAST_STEP_INIT, 2, MemoryWitness::registers()));
+        assert!(test_future_read_witness_aux(step, 50, 0, 1, MemoryWitness::registers()));
+        // ...but unused reads are TraceRead::default() (last_step == 0) in honest traces
+        assert!(!test_future_read_witness_aux(step, 50, 0, 2, rur.clone()));
+        assert!(!test_future_read_witness_aux(step, 50, 0, 1, rur.clone()));
+        assert!(!test_future_read_witness_aux(step, 0, 0, 1, MemoryWitness::default()));
+        assert!(!test_future_read_witness_aux(step, 50, 99, 2, MemoryWitness::registers()));
+        // future read still detected regardless of the witness of the other read
+        assert!(test_future_read_witness_aux(step, 0, step + 1, 2, MemoryWitness::default()));
     }
 
     fn test_read_value_aux(
diff --git a/definitions/src/challenge.rs b/definitions/src/challenge.rs
index bf94a03..3303be8 100644
--- a/definitions/src/challenge.rs
+++ b/definitions/src/challenge.rs
@@ -83,6 +83,7 @@ pub enum ChallengeType {
         prover_read_step_1: u64,
         prover_read_step_2: u64,
         read_selector: u32,
+        prover_mem_witness: u8,
     },
     ReadValueNArySearch {
         bits: u32,
diff --git a/emulator/src/decision/challenge.rs b/emulator/src/decision/challenge.rs
index 7572a9f..2eca8c9 100644
--- a/emulator/src/decision/challenge.rs
+++ b/emulator/src/decision/challenge.rs
@@ -1,7 +1,7 @@
 use bitvmx_cpu_definitions::{
     challenge::{ChallengeType, EquivocationKind, ProverFinalTraceType, ProverHashesAndStepType},
     constants::{CHUNK_SIZE, LAST_STEP_INIT},
-    memory::Chunk,
+    memory::{Chunk, MemoryAccessType},
     trace::{generate_initial_step_hash, hashvec_to_string, validate_step_hash, TraceRWStep},
 };
 
@@ -659,8 +659,16 @@ pub fn verifier_choose_challenge(
     let prover_read_step_1 = prover_read_1.last_step;
     let prover_read_step_2 = prover_read_2.last_step;
 
-    let is_read_1_future = prover_read_step_1 > step && prover_read_step_1 != LAST_STEP_INIT;
-    let is_read_2_future = prover_read_step_2 > step && prover_read_step_2 != LAST_STEP_INIT;
+    let is_read_1_used = trace.mem_witness.read_1() != MemoryAccessType::Unused;
+    let is_read_2_used = trace.mem_witness.read_2() != MemoryAccessType::Unused;
+
+    // A read can only return a value written at a step in [1, step] (or LAST_STEP_INIT).
+    // Step 0 is the initial state: nothing is ever written there, so a used read claiming
+    // last_step == 0 is a lie (unused reads are TraceRead::default() and carry last_step == 0).
+    let is_read_1_future = (prover_read_step_1 > step && prover_read_step_1 != LAST_STEP_INIT)
+        || (prover_read_step_1 == 0 && is_read_1_used);
+    let is_read_2_future = (prover_read_step_2 > step && prover_read_step_2 != LAST_STEP_INIT)
+        || (prover_read_step_2 == 0 && is_read_2_used);
 
     if ((is_read_1_future || is_read_2_future) && force == ForceChallenge::No)
         || force == ForceChallenge::FutureRead
@@ -672,12 +680,13 @@ pub fn verifier_choose_challenge(
             prover_read_step_1,
             prover_read_step_2,
             read_selector,
+            prover_mem_witness: trace.mem_witness.byte(),
         });
     }
 
-    // check const read value
-    let is_read_1_conflict = prover_read_1.value != my_trace.read_1.value;
-    let is_read_2_conflict = prover_read_2.value != my_trace.read_2.value;
+    // check const read value (only reads that are actually used by the instruction)
+    let is_read_1_conflict = is_read_1_used && prover_read_1.value != my_trace.read_1.value;
+    let is_read_2_conflict = is_read_2_used && prover_read_2.value != my_trace.read_2.value;
 
     if ((is_read_1_conflict || is_read_2_conflict) && force == ForceChallenge::No)
         || force == ForceChallenge::InputData
@@ -762,6 +771,14 @@ pub fn verifier_choose_challenge(
                 conflict_last_step.max(my_conflict_last_step)
             };
 
+            // unreachable after the impossible-read check above, but never underflow on
+            // prover-controlled data
+            if step_to_challenge == 0 {
+                return Err(EmulatorError::ChallengeError(
+                    "read value challenge with last_step 0".to_string(),
+                ));
+            }
+
             let mut bits = nary_def.step_bits_for_round(1, step_to_challenge - 1);
 
             let read_challenge_log = &mut verifier_log.read_challenge_log;
```

**Validation:** I applied this diff to a scratch copy (`CARGO_TARGET_DIR` separate from the shared tree, nothing changed in the shared tree) and ran:
* `cargo test -p emulator --test audit_emu_003 -- --include-ignored`: `emu_003_verifier_wins_against_read_last_step_zero` passes, and the verifier now posts `FutureRead { prover_conflict_step_tk: 8, prover_read_step_1: 8, prover_read_step_2: 0, read_selector: 2, prover_mem_witness: 4 } -> true`. The control test passes. The two "demo" tests fail, as expected once the bug is fixed; they should then be removed or inverted. The `FutureRead` literal in the demo test also needs the new field.
* `cargo test -p bitcoin-script-riscv --lib challenges`: 51 passed, including the extended `test_future_read`. Its new cases check that unused slots with `last_step 0` are **not** challengeable.
* `cargo test -p emulator --lib test_challenge`: 33 passed, including `test_challenge_future_read`, `test_challenge_uninitialized` and `test_challenge_read_*`.

**Risks and side effects:**
* The `future_read` leaf script changes, and so do its WOTS variable list (one extra prover variable) and the `ChallengeType` serialisation. Every party must upgrade, and existing setups or presigned DAGs built with the old leaf are incompatible.
* The script gets slightly bigger: it adds two 16-element nibble tables.
* Using `prover_mem_witness` in this leaf relies on the EXECUTE script binding the witness to the instruction. That is the same assumption `addresses_sections` already makes.
* Restricting value-conflict detection to used reads changes nothing for honest traces. The witness used is the *prover's* committed witness, which matches the verifier's whenever the opcode matches (that is checked earlier).

An alternative that is not recommended: map `last_step == 0` to the static-data challenges. That fails on-chain, because those scripts require `LAST_STEP_INIT`.

### Follow-ups

* After the fix lands: un-ignore `emu_003_verifier_wins_against_read_last_step_zero` and delete or invert the two demo tests.
* Update `rust-bitvmx-client` as described in step 4 above, and add an end-to-end dispute test with `fail_reads` and `last_step = 0`.
* Related verifier panics on prover-controlled data, which belong to EMU-004: `get_hashes` / `mapping.get(..).unwrap()` (`challenge.rs:379-388, 844, 862`) should return errors instead of panicking.
* Unrelated observation (EMU-002): in the control test's `UninitializedData` ranges, the register section `0xF0000000-0xF0000087` is listed as uninitialised.

