# EMU-012: Commit the registers' initial values as initialized data (preferred fix for EMU-002)

* **Status:** Fix proposed and validated in a scratch copy (not applied)
* **Severity:** Critical. Same bug as [EMU-002](EMU-002-registers-in-uninitialized-ranges.md); this ticket tracks a better fix.
* **Source:** external bug report on `dev` @ 299009c6 (v0.8.6), which also independently reported [EMU-011](EMU-011-get-chunks-base-addr-unit.md). The report's patches weren't available, so the fix below was re-implemented and tested here.
* **Depends on:** the EMU-011 fix (`get_chunks` base address in bytes). The register section is 136 bytes, so it fits in a single chunk and would be correct without it. Apply both together anyway, since both change the initialized leaves.
* **Area:** `emulator/src/loader/program.rs` (`get_initialized_chunks`, `get_uninitialized_ranges`), `emulator/src/decision/challenge.rs` (`verifier_choose_challenge`, ~line 727)

## Problem (recap of EMU-002)

The loader gives the registers defined initial values: all 0, except SP (x2) = `0xE080_0000`, all with `last_step = LAST_STEP_INIT`. But the register section has `initialized == false`, so `get_uninitialized_ranges` publishes it as must-be-zero memory. Consequences:

* A malicious verifier wins `UninitializedData` against the honest first read of SP (hello-world, step 3).
* A prover that lies "SP = 0" beats the honest verifier.
* Just removing the register section from the ranges would leave every lie about a register's initial value impossible to challenge.

## Fix: registers become initialized data

1. `get_initialized_chunks` appends chunk(s) holding the loader's initial register values, taken from `self.registers` (the register section's `data` is not where those values live). It asserts `step == 0`, so it is only called on a freshly loaded program. Both callers (the emulator's `verifier_choose_challenge` and the client's `dispute/challenge.rs:492`) already use a freshly loaded program.
2. `get_uninitialized_ranges` skips `section.registers`.
3. `verifier_choose_challenge` sends a never-written register read to `InitializedData` (`section.initialized || section.registers`).

No new challenge type and no script change: the existing `initialized_challenge` already requires `LAST_STEP_INIT` and checks the value against the chunk.

### Why this is better than EMU-002's proposal

| | EMU-002 proposal (`InitialRegister` challenge) | EMU-012 (registers as initialized data) |
|---|---|---|
| Registers covered | SP only | all 34 (x0..x31 + 2 aux) |
| New `ChallengeType` / script | yes | no |
| Client code change | new `initial_register` leaf + name mapping (only sketched, not compiled) | none: the client builds initialized leaves from `get_initialized_chunks` and uses `chunk_index` as the leaf offset (`dispute/challenge.rs:492`, `:853-859`); it only needs the BitVMX-CPU tag bump |
| Taproot changes | yes | yes (one extra initialized leaf; uninitialized leaf loses the register range) |

### Diff (includes the EMU-011 line)

```diff
--- a/emulator/src/loader/program.rs
+++ b/emulator/src/loader/program.rs
@@ pub fn get_chunks(&self, chunk_size: u32, filter: impl Fn(&&Section) -> bool) -> Vec<Chunk> {
                     .map(|(index, chunk)| {
-                        let offset = section.start + index as u32 * chunk_size;
+                        // chunk_size is in words, addresses are in bytes
+                        let offset = section.start + index as u32 * chunk_size * 4;
                         let data = chunk.iter().map(|opcode| u32::from_be(*opcode)).collect();
@@
-    pub fn get_initialized_chunks(&self, chunk_size: u32) -> Vec<Chunk> {
-        self.get_chunks(chunk_size, |section| {
-            section.initialized && !section.is_code
-        })
-    }
+    // The registers have loader-defined initial values (e.g. SP), so they are committed as
+    // initialized data. Their values live in `self.registers`, not in the section data.
+    pub fn get_initialized_chunks(&self, chunk_size: u32) -> Vec<Chunk> {
+        assert_eq!(
+            self.step, 0,
+            "initialized chunks must be computed from a freshly loaded program"
+        );
+
+        let mut chunks = self.get_chunks(chunk_size, |section| {
+            section.initialized && !section.is_code
+        });
+
+        let base_address = self.registers.get_base_address();
+        chunks.extend(
+            self.registers
+                .value
+                .chunks(chunk_size as usize)
+                .enumerate()
+                .map(|(index, values)| Chunk {
+                    base_addr: base_address + index as u32 * chunk_size * 4,
+                    data: values.to_vec(),
+                }),
+        );
+
+        chunks
+    }
@@ pub fn get_uninitialized_ranges(
             .filter(|section| {
-                // we do inputs separately
-                !section.initialized && section.name != program_definition.input_section_name
+                // we do inputs separately, registers are initialized data
+                !section.initialized
+                    && !section.registers
+                    && section.name != program_definition.input_section_name
             })
--- a/emulator/src/decision/challenge.rs
+++ b/emulator/src/decision/challenge.rs
@@ pub fn verifier_choose_challenge(
-            } else if (section.initialized && force == ForceChallenge::No)
+            } else if ((section.initialized || section.registers) && force == ForceChallenge::No)
                 || force == ForceChallenge::InitializedData
```

The register chunk is appended **after** the section chunks, so the indexes of the existing initialized chunks don't change.

## Tests

File: `emulator/tests/audit_emu_012.rs`. All five tests assert the expected behaviour and are marked `#[ignore = "EMU-012: fails until fixed"]`.

| Test | Checks |
|---|---|
| `emu012_registers_not_in_uninitialized_ranges` | no register address is published as zero-initialized |
| `emu012_initialized_chunks_hold_initial_registers` | all 34 registers are covered by an initialized chunk with their initial value (hello-world + zkverifier) |
| `emu012_honest_sp_read_not_challengeable` | the honest SP read at step 3 can't be won with `UninitializedData` or `InitializedData` |
| `emu012_wrong_initial_register_is_challengeable` | wrong initial values for x2 (0 and SP+4), x5 and aux x33 are provable with `InitializedData` |
| `emu012_honest_verifier_wins_when_prover_lies_about_initial_sp` | end to end: the prover lies "SP = 0", and the verifier picks `InitializedData`, which the script accepts |

Command (from `BitVMX-CPU/`): `cargo test -p emulator --test audit_emu_012 -- --nocapture --include-ignored`

Results:

* **Current code:** 0 passed, 5 failed. The verifier picks `UninitializedData` for the "SP = 0" lie and the script rejects it (`verifier_wins = false`). No initialized chunk covers the registers.
* **With the fix (scratch copy, separate target dir):**
  * `audit_emu_012`: 5/5 pass.
  * `audit_emu_002` with `--include-ignored`: 4/4 pass, so EMU-002 is fixed too.
  * `audit_emu_011`: `chunks_match_memory` and the opcode test pass. The 2 `demo_*` tests fail as intended; delete them when the fix lands.
  * emulator lib: 70/70.
  * `bitcoin-script-riscv` challenges: 51/51.
  * The other audit test files stay green.
  * See the "Regression run" section below for the remaining emulator test files.

## Risks / rollout

* The taproot changes: one extra initialized leaf, and the uninitialized leaf no longer includes the register range. Existing dispute setups are incompatible, and both parties must upgrade together. The client needs a BitVMX-CPU tag bump (currently `v0.8.6`).
* The `get_initialized_chunks` assert (`step == 0`) panics if it's ever called on a program restored from a checkpoint. No such caller exists today.
* It edits the same function as the EMU-006 fix (`get_uninitialized_ranges`), so merge the two diffs.
* Follow-up (EMU-009 item 1): `generate_rom_commitment` still lists the register section under `zero_initialized`. Skip `section.registers` there too.

## Regression run

The remaining emulator test binaries, run with the EMU-011 and EMU-012 fixes (scratch copy), all pass:
`challenge` 1/1, `compliance` 1/1, `exceptions` 1/1, `audit` 1/1, `test_b/i/j/r/s/u_type_instructions` 10/32/1/20/16/7.
Together with the results above (lib 70/70, script challenges 51/51, audit tests), **no regressions**. The only failing tests are the two `emu011_demo_*` tests, which fail by design once the bug is fixed.
