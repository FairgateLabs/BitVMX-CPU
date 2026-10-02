# SCR-004: The EXECUTE leaf drops the high nibble of `prover_write_micro`, but that nibble is hashed

* **Status:** Confirmed on the real EXECUTE leaf with real Winternitz signatures. Fix proposed and validated in the test, not applied.
* **Severity:** Critical. A lying prover can fork its hash chain on **any** step and prove that step, by changing only the micro's high nibble (e.g. `0x00` → `0x10`). It wins every dispute.
* **Area:**
  * `rust-bitvmx-client/src/program/protocols/dispute/mod.rs:1164-1181` (`get_reverse_and_strip_scripts`, "TODO: This is a workaround to remove one nibble from the micro instructions").
  * `bitcoin-script-riscv/src/riscv/trace.rs`: `STraceStep::define` has `micro` as **1** nibble.
  * `definitions/src/trace.rs:112-119` (`TraceStep::to_bytes`): the micro is hashed as a full **byte**. So does `challenges.rs:218-241` (`trace_hash_challenge`), where `write_micro` is 2 nibbles.

## Bug

The prover signs `prover_write_micro` as one byte (two WOTS nibbles). The EXECUTE leaf's strip script removes the most significant nibble without looking at it:

```rust
let stripped = stack.move_var_sub_n(stackvars["prover_write_micro"], 0);
stack.drop(stripped);
let stripped = stack.move_var_sub_n(stackvars["prover_read_pc_micro"], 0);
stack.drop(stripped);
```

The instruction script then compares only the low nibble with the micro it computed. But the step hash `h_{n} = blake3(h_{n-1} || write_add || write_value || write_pc || write_micro)` uses the whole byte, on chain (`trace_hash(_zero)_challenge`) and in the emulator. So `0x00` and `0x10` (or anything up to `0xf0`) are two different hashed steps, and the same leaf accepts both.

`prover_read_pc_micro` has the same strip, but its high nibble *is* covered elsewhere: the `program_counter` and `entry_point` challenges compare the full byte with the previous write.

## Attack

1. The prover executes honestly, except on step 1 (or any step), where it commits `write_micro = 0x10` instead of `0x00`.
2. From that step on, its hash chain differs from the verifier's, and the prover can claim any final state.
3. The n-ary search lands on that step. The prover reveals the trace and posts the honest instruction leaf, which succeeds: only the low nibble is checked.
4. Every challenge fails for the verifier:
   * `trace_hash` / `trace_hash_zero`: the hash is consistent with `0x10`;
   * `program_counter`: that challenge applies to the *next* step's read, which is never examined;
   * no read is wrong.

## Test

* CPU: `emulator/tests/audit_scr.rs::scr004_demo_micro_high_nibble_changes_hash_and_trace_hash_leaf_cannot_win`. It shows that the hash changes and that `execute_challenge(TraceHash | TraceHashZero)` can't win against the forged step.
* Client: `rust-bitvmx-client/tests/audit_scr_004_write_micro_nibble.rs`.
  * It rebuilds the EXECUTE leaf exactly as `execute_script` does: TRACE_VARS without `prover_witness`, `verify_winternitz_signatures_aux`, `get_reverse_script`, the strip script of `get_reverse_and_strip_scripts`, the `nop` script from the mapping, and a 4-round n-ary definition.
  * It runs the leaf with real Winternitz signatures. The `<agg> OP_CHECKSIGVERIFY` prefix is stripped, as in the EMU-013 test.

| Test | Kind | Result now |
|---|---|---|
| `scr004_control_low_nibble_is_checked` | `0x00` accepted, `0x01` rejected | passes |
| `scr004_demo_high_nibble_is_not_checked` | `0x10` and `0xf0` accepted | passes (shows the bug) |
| `scr004_execute_leaf_rejects_non_zero_high_nibble` | expected behaviour | **fails**, `#[ignore = "SCR-004: fails until fixed"]` |
| `scr004_proposed_fix_rejects_non_zero_high_nibble` | the leaf with the fix below: `0x00` accepted; `0x01`, `0x10` and `0xf0` rejected | passes |

```
cargo test --release --test audit_scr_004_write_micro_nibble -- --nocapture --include-ignored
```

```
write_micro 0x00 -> accepted = true; 0x01 -> accepted = false
write_micro 0x10 -> accepted = true
write_micro 0xf0 -> accepted = true
fixed leaf: write_micro 0x00 -> accepted = true
fixed leaf: write_micro 0x01 -> accepted = false
fixed leaf: write_micro 0x10 -> accepted = false
fixed leaf: write_micro 0xf0 -> accepted = false
```

## Proposed fix (client only, validated in the test above)

Assert that the high nibble is zero instead of dropping it, for both micro bytes (for `read_pc_micro`, defence in depth):

```diff
--- a/src/program/protocols/dispute/mod.rs
+++ b/src/program/protocols/dispute/mod.rs
@@ fn get_reverse_and_strip_scripts(
-                let stripped = stack.move_var_sub_n(stackvars["prover_write_micro"], 0);
-                stack.drop(stripped);
-                let stripped = stack.move_var_sub_n(stackvars["prover_read_pc_micro"], 0);
-                stack.drop(stripped);
+                // the micro is signed as a byte but the instruction scripts use one nibble:
+                // the high nibble is hashed, so it must be zero
+                for micro in ["prover_write_micro", "prover_read_pc_micro"] {
+                    let high = stack.move_var_sub_n(stackvars[micro], 0);
+                    let zero = stack.number(0);
+                    stack.equals(high, true, zero, true);
+                }
```

An alternative that touches the CPU instead: make `STraceStep::micro` and `STraceRead::micro` two nibbles, and compare the full byte in `compare_trace_step`. That changes every instruction script.

## Risks / notes

* This changes the EXECUTE leaves. Roll it out together with the other leaf changes (see the README's rollout notes).
* The same pattern ("signed as N nibbles, used as fewer") must be checked for every variable the strip script touches:
  * `verifier_selection_bits_i`: its high nibble is dropped, but the verifier signs it and it is only used to recompute the conflict step. Not exploitable by the prover; see SCR-007.
  * `prover_step_number`, the `last_step`s and the hashes: dropped whole, and not used by the instruction scripts.
