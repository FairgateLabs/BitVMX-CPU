# EMU-013: The on-chain `input` challenge leaves compare input words in the wrong byte order

* **Status:** Confirmed (executed against the real leaf scripts). Fix proposed and validated in the test, not applied.
* **Severity:** Critical.
  * An honest prover loses whenever the program reads a non-palindromic input word. Real inputs (hashes, txids, proofs) are almost never palindromic.
  * A lying prover can't be refuted when its lie is the byte-swapped input word.
* **Found while:** reviewing `rust-bitvmx-client/src/program/protocols/dispute/*` for checks that mitigate the emulator findings. This resolves the open question in [EMU-007](EMU-007-load-input-oob.md) ("Endianness").
* **Area:**
  * `rust-bitvmx-client/src/program/protocols/dispute/challenge.rs:333-463`: the `"input"` leaves (prover, verifier and prover_prev words go through `input_challenge`, Const words through `rom_challenge`).
  * `bitcoin-script-riscv/src/riscv/challenges.rs:31-68` (`input_challenge`).
  * `emulator/src/loader/program.rs:203-226` (`load_input`) and `:698` (`vec_u8_to_vec_u32`).

## Bug

The same 4 input bytes `b = [b0, b1, b2, b3]` reach the input leaf in two different byte orders:

| Where | What is compared | Value for `b = 01 02 03 04` |
|---|---|---|
| Emulator: `load_input(.., little_endian = false)` then `read_mem` (every protocol path, `program_definition.rs:109`, `challenge.rs:456`) | the honest read value is `u32::from_le_bytes(b)` (RISC-V memory is little-endian: byte `i` of the input sits at `start + i`) | `0x04030201` |
| Client: the read value is Winternitz-signed as `value.to_be_bytes()` (`set_input_u32`, `execution.rs:196-201`) | nibbles of `04 03 02 01` | |
| Client: a prover, verifier or prover_prev input word is signed as the **raw input bytes** (`split_input`, `input_handler.rs:196-206`) | nibbles of `01 02 03 04` | |
| Client: a Const input word is compiled into the leaf as `u32::from_be_bytes(b)` (`challenge.rs:447-450`) | `0x01020304` | |

`input_challenge` / `rom_challenge` compare the read value nibble by nibble with the committed input. For an honest read, they compare `04 03 02 01` with `01 02 03 04`, see a difference, and **the verifier wins**.

The emulator never sees this. Its own model of the challenge (`execute_challenge`, `challenges.rs:837-853`) pushes `input_for_address = read_mem(..)` as a number, which is already the little-endian value. So every emulator and script test passes. The client tests use the palindromic input `11111111`, where the two byte orders agree.

## Attack

**Malicious verifier, honest prover:**
1. The verifier steers the conflict n-ary search to the first step that loads a non-palindromic input word. The prover has to publish that trace, with the read at `last_step = LAST_STEP_INIT`.
2. The verifier posts the `input` leaf for that address (`ForceChallenge::InputData` or a hand-built challenge).
3. The leaf script succeeds, the verifier wins and takes the funds.

This works for any DRP whose program reads its input.

**Lying prover, honest verifier:** the prover commits `read = from_be_bytes(b)` (the byte-swapped word) instead of the real value. The honest verifier's emulator detects the conflict and picks `InputData`, but the leaf script rejects it, so the lie stands.

## Test

File: `rust-bitvmx-client/tests/audit_emu_013_input_byte_order.rs` (in the client, because the bug is in how the client assembles and signs the leaf).

How the test works:
* It rebuilds the leaf exactly as `challenge.rs` does: the same `verify_winternitz_signatures_aux` call, the same reverse script, and `input_challenge` / `rom_challenge`.
* It strips only the 34-byte `<agg> OP_CHECKSIGVERIFY` prefix and runs the rest with real Winternitz signatures. The witness layout matches `get_winternitz_signature_for_script` / `push_winternitz_signature`.
* The honest read value comes from the emulator (`load_input` + `read_mem` on `verifiers/add-test.elf`).

| Test | Kind | Result now |
|---|---|---|
| `emu013_control_palindromic_input_works` | control: input `11111111`, honest read → verifier loses, lie `0x11111100` → verifier wins (both leaf kinds) | passes |
| `emu013_demo_honest_prover_loses_on_non_palindromic_input` | demonstration: input `01 02 03 04` | passes (shows the bug) |
| `emu013_input_leaves_match_emulator_byte_order` | expected behaviour, real leaves | **fails**, `#[ignore = "EMU-013: fails until fixed"]` |
| `emu013_proposed_fix_matches_emulator_byte_order` | the leaves with the fix below, 4 input patterns: honest → verifier loses; byte-swapped lie and 1-bit lie → verifier wins | passes |

Command (from `rust-bitvmx-client/`; uses the workspace path overrides, so it builds against the local BitVMX-CPU):

```
cargo test --release --test audit_emu_013_input_byte_order -- --nocapture --include-ignored
```

```
input bytes [01, 02, 03, 04]: the emulator reads 0x04030201
prover: honest read 0x04030201 -> verifier_wins = true; byte-swapped lie 0x01020304 -> verifier_wins = false
const: honest read 0x04030201 -> verifier_wins = true; byte-swapped lie 0x01020304 -> verifier_wins = false
prover: palindromic input, honest read -> verifier_wins = false, lie -> true
fixed prover [01, 02, 03, 04]: honest 0x04030201 -> false, swapped -> true, off-by-one-bit -> true
fixed const [de, ad, be, ef]: honest 0xefbeadde -> false, swapped -> true, off-by-one-bit -> true
...
test result: 3 passed; 1 failed (the ignored expected-behaviour test)
```

## Proposed fix (client only, validated in the test above)

What can and can't change:
* The signed input bytes must stay raw: they are also the program input (`unify_inputs`), and for `prover_prev` they come from another protocol.
* The emulator's byte order is the correct RISC-V semantics. Changing it would change every program's result.

So the leaf converts the committed word to the little-endian read order before comparing it:
* prover, verifier and prover_prev input leaves run a 4-byte swap of `prover_program_input_j` between the reverse script and `input_challenge`;
* Const leaves use `from_le_bytes`.

```diff
--- a/src/program/protocols/dispute/challenge.rs
+++ b/src/program/protocols/dispute/challenge.rs
@@ "input" => {
+                        let swap_input_script = swap_input_word_script();
@@ ProgramInputType::Verifier(words, offset) | ProgramInputType::Prover(words, offset) => {
                                         let address = base_addr + j * 4;
-                                        let mut scripts = vec![reverse_script.clone()];
+                                        let mut scripts =
+                                            vec![reverse_script.clone(), swap_input_script.clone()];
                                         stack = StackTracker::new();
                                         input_challenge(&mut stack, address);
@@ ProgramInputType::ProverPrev(words, offset) => {
                                         let address = base_addr + (j + offset) * 4;
-                                        let mut scripts = vec![reverse_script.clone()];
+                                        let mut scripts =
+                                            vec![reverse_script.clone(), swap_input_script.clone()];
@@ ProgramInputType::Const(words, offset) => {
-                                        let value =
-                                            u32::from_be_bytes(value.as_slice().try_into()?);
+                                        // memory words are read little-endian (emulator `load_input` + `read_mem`)
+                                        let value =
+                                            u32::from_le_bytes(value.as_slice().try_into()?);
@@
+/// The input words are signed as raw input bytes, but the program reads memory words
+/// little-endian, so the signed word is byte-swapped before `input_challenge` compares it with the
+/// read values. Runs after the reverse script and keeps the layout `input_challenge` expects.
+fn swap_input_word_script() -> ScriptBuf {
+    let mut stack = StackTracker::new();
+    let input = stack.define(INPUT_CHALLENGE[0].1 as u32 * 2, "prover_input");
+    let rest: Vec<_> = INPUT_CHALLENGE
+        .iter()
+        .skip(1)
+        .map(|(name, size)| stack.define(*size as u32 * 2, name))
+        .collect();
+    let input = stack.move_var(input);
+    let nibbles = stack.explode(input);
+    for i in [6, 7, 4, 5, 2, 3, 0, 1] {
+        stack.move_var(nibbles[i]);
+    }
+    stack.join_count(nibbles[6], 7);
+    for var in rest {
+        stack.move_var(var);
+    }
+    stack.get_script()
+}
```

No emulator change is needed: `InputData.input_for_address` is already the little-endian value, so the emulator's own model of the challenge stays correct.

**Alternative:** do the swap inside `bitcoin-script-riscv::input_challenge`. That also requires `execute_challenge` to push `input_for_address.swap_bytes()` (the "TODO: this should make input_wots[address]" at `challenges.rs:843`) and updating the script's input tests and fuzzers. It is more churn, for the same on-chain result.

## Risks / rollout

* The input leaf scripts change, so the dispute taproot changes. Existing setups are incompatible, and both parties must upgrade together. Can ship together with EMU-011 and EMU-012.
* Add a client end-to-end test with a **non-palindromic** input. One honest-prover case where the verifier forces `InputData` is enough, and so is the current forced-`Input` test run with e.g. `01020304`.
* Other protocols (cardinal, union) that pass DRP inputs need no change: the fix is inside the DRP leaves.
