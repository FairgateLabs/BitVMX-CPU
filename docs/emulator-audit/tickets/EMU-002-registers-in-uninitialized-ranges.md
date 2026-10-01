# EMU-002: The register section, including the non-zero initial SP, is reported as an "uninitialized (zero)" range

* **Status:** Confirmed
* **Severity (initial guess):** High. A malicious verifier may win an `UninitializedData` challenge against an honest prover, and an honest verifier may pick a challenge it cannot win.
* **Severity (after investigation):** Critical. Both directions are confirmed end to end. Every C program reads the initial SP in its first prologue (hello-world does it at step 3), so a malicious verifier can win against any honest prover. In the other direction, a prover that claims `SP = 0` at that read beats the stock emulator verifier, whatever final result it claims.
* **Area:** `emulator/src/loader/program.rs:653-695` (`get_uninitialized_ranges`), `program.rs:130-138` (`Registers::new` sets SP = `0xE080_0000`), `program.rs:749-756` (registers section created with `initialized = false`), `challenge.rs:698-755`, `rust-bitvmx-client/src/program/protocols/dispute/challenge.rs:603`, `bitcoin-script-riscv/src/riscv/challenges.rs:477` (`uninitialized_challenge`)

## Suspicion

`get_uninitialized_ranges` returns every section with `!section.initialized` except the input section.
The fake `"registers"` section is created with `Section::new(..., registers = true)`, which sets `initialized: false`, so its range `0xF000_0000..0xF000_0087` is included.

The on-chain `uninitialized_challenge` succeeds (verifier wins) when the read address is in those ranges, `last_step == LAST_STEP_INIT` and `value != 0`.
All registers start at 0 with `LAST_STEP_INIT`, **except SP (x2)**, which starts at `STACK_BASE_ADDRESS + STACK_SIZE` with `last_step = LAST_STEP_INIT`.

Consequences:
* **Honest prover loses:** the first instruction that reads SP before writing it (e.g. `addi sp, sp, -16` in a typical prologue) produces a correct trace with `read_1 = {0xF000_0008, 0xE080_0000, LAST_STEP_INIT}`. A malicious verifier steers the n-ary search to that step and posts `UninitializedData`. The script would accept it.
* **Honest verifier can't win:** if a prover lies about SP's initial value, e.g. claims `0`, the emulator selects `UninitializedData` (registers section is `!initialized`, `challenge.rs:743`). The script would then fail because the value is 0.

Also check how the register section is reflected in `register_sections` and the other challenges (e.g. is the initial SP value committed anywhere on-chain?).

## What to do

1. Write a test that loads e.g. `hello-world.elf` and asserts `get_uninitialized_ranges` does not contain the register range (expected to fail now).
2. Ideally build the actual `uninitialized_challenge` script with those ranges and run it (see `test_uninitialized_aux` in `bitcoin-script-riscv/src/riscv/challenges.rs`) with a correct SP read (`0xE080_0000`, `LAST_STEP_INIT`). Show the script succeeds, i.e. the verifier wins against a correct trace.
3. Check whether the existing programs actually read SP before writing it. Look at the start code in `docker-riscv32`.
4. Propose a fix. For example, exclude `section.registers` from uninitialized ranges, and decide how a register read with `LAST_STEP_INIT` should be challenged (SP needs its own rule or must be committed as an initialized constant). Look at both the emulator and the client side.

## Findings

### Verdict

**Confirmed (both directions).** The register section, including the SP word, is part of the "zero-initialized" ranges that the on-chain `uninitialized` leaf is built from. SP's initial value is `0xE080_0000`, not 0.

### Root cause

* `emulator/src/loader/program.rs:749-756`: `load_elf` adds the fake `"registers"` section with `Section::new(..., registers = true)`. `Section::new` always sets `initialized: false` (`program.rs:50`).
* `emulator/src/loader/program.rs:653-664` (`get_uninitialized_ranges`): returns the range of every `!initialized` section except the input section, so the result includes `(0xF000_0000, 0xF000_0087)`. Output for `hello-world.elf`: `[(a0000000, a0001003), (e0000000, e07fffff), (f0000000, f0000087), (aa000004, aa001fff)]`.
* `emulator/src/loader/program.rs:129-137` (`Registers::new`): SP (x2) starts at `STACK_BASE_ADDRESS + STACK_SIZE = 0xE080_0000` with `last_step = LAST_STEP_INIT`. Every other register and both aux registers start at 0. SP is the only word in the range that breaks the "zero" assumption.
* `bitcoin-script-riscv/src/riscv/challenges.rs:477-511` (`uninitialized_challenge`): the verifier wins if `addr in ranges && last_step == LAST_STEP_INIT && value != 0` (lines 501-508).
* `rust-bitvmx-client/src/program/protocols/dispute/challenge.rs:595-605`: the client builds the on-chain `uninitialized` leaf from `program.get_uninitialized_ranges(...)`, so the wrong range is part of the real taproot leaf.
* `emulator/src/decision/challenge.rs:698-755` (`verifier_choose_challenge`): if both reads have `LAST_STEP_INIT`, the section is `registers` (`!initialized`), so the verifier always picks `UninitializedData` (line 743). There is no rule for "a register whose initial value is a non-zero constant". The initial SP value is not committed anywhere on-chain: there is no leaf for it, and it is not in `register_sections` (which only describes valid addresses, `program.rs:279-286`) or in the ROM/initialized chunks.

Precondition check (item 3): `docker-riscv32/src/entrypoint.s` does not set `sp`. `_start` runs `li a0,0; call main`, and `main`'s prologue `addi sp,sp,-48` (pc `0x8000007c`, opcode `0xfd010113`) reads SP at **step 3** with `read_1 = {0xF000_0008, 0xE080_0000, LAST_STEP_INIT}`. Any program built this way reads the initial SP.

### Failure scenarios in the challenge protocol

1. **An honest prover loses (malicious verifier).** The verifier opens a dispute and steers the n-ary search to step 3. It controls the decision bits, so it can select any step. The prover must reveal the correct trace of step 3. The verifier then posts `UninitializedData` with `read_selector = 1`. The script finds the address in the ranges, `last_step == INIT` and `value = 0xE080_0000 != 0`, so the verifier wins. This works against every honest prover running a program that reads the initial SP.
2. **A dishonest prover wins against the stock verifier.** The prover claims any false result. Its trace diverges first at the initial SP read, where it claims `SP = 0` with `LAST_STEP_INIT` and then continues consistently with its own hashes. `choose_segment` picks the first mismatch, so the verifier lands on step 3. Both reads are INIT, so the emulator picks `UninitializedData`. The script rejects it because the value is 0, and the lying prover wins. (A lie `V != 0` is still caught by the current, wrong ranges, but only by accident. Once the register range is fixed without adding a dedicated SP rule, *any* SP lie becomes unpunishable. The two parts of the fix below must ship together.)

### Test

File: `emulator/tests/audit_emu_002.rs`. Three tests assert the correct behaviour and are `#[ignore = "EMU-002: fails until fixed"]`. One precondition test runs normally.

* `emu002_honest_program_reads_initial_sp` (not ignored, passes): the first initial-SP read is at step 3 with value `0xE080_0000` and `LAST_STEP_INIT`.
* `emu002_uninitialized_ranges_exclude_sp` (ignored): asserts that `0xF000_0008` is not in `get_uninitialized_ranges`.
* `emu002_malicious_verifier_cannot_win_against_honest_sp_read` (ignored): builds `ChallengeType::UninitializedData` from the honest step-3 trace and the real ranges, runs `execute_challenge` (the same `uninitialized_challenge` script the client builds), and asserts the verifier does not win.
* `emu002_honest_verifier_wins_when_prover_lies_about_initial_sp` (ignored): runs the full emulator protocol (`prover_execute` .. `verifier_choose_challenge`). The prover injects `FailReads` (SP read at step 3 reported as `0` / `LAST_STEP_INIT`). The test asserts that the challenge the verifier picks is accepted by the script.

Command (from `BitVMX-CPU/`):

```
cargo test -p emulator --test audit_emu_002 -- --nocapture --include-ignored
```

Output on the current tree (excerpt):

```
uninitialized ranges: [(a0000000, a0001003), (e0000000, e07fffff), (f0000000, f0000087), (aa000004, aa001fff)]
SP (0xf0000008, initial value 0xe0800000) is reported as zero-initialized memory
test emu002_uninitialized_ranges_exclude_sp ... FAILED
first initial-SP read: step 3 selector 1 read_1=TraceRead { address: 4026531848, value: 3766484992, last_step: 18446744073709551615 } ...
test emu002_honest_program_reads_initial_sp ... ok
honest step 3 challenged with UninitializedData (selector 1): verifier_wins = true
test emu002_malicious_verifier_cannot_win_against_honest_sp_read ... FAILED
disputed step 3 read_1=TraceRead { address: 4026531848, value: 0, last_step: 18446744073709551615 } ...
verifier chose UninitializedData { ... read_selector: 1, sections: Some(...) } -> verifier_wins = false
test emu002_honest_verifier_wins_when_prover_lies_about_initial_sp ... FAILED
test result: FAILED. 1 passed; 3 failed
```

Without `--include-ignored`, the suite is green (1 passed, 3 ignored).

> **Preferred fix: apply [EMU-012](EMU-012-registers-as-initialized-data.md) instead of the fix below.**
> EMU-012 commits the registers' initial values as initialized data (an extra `InitializedData` chunk) and excludes the register section from the uninitialized ranges. It covers all 34 registers rather than only SP, needs no new `ChallengeType` or script, and needs no client code change (only a BitVMX-CPU tag bump). Validated in a scratch copy: with it, all 4 EMU-002 tests here pass (including the 3 ignored ones). The `InitialRegister` approach below is kept for reference.

### Proposed fix

There are two parts, and they must land together:

1. `get_uninitialized_ranges` splits the register section around the SP word. x0, x1, x3..x31 and the aux registers really start at 0 and stay challengeable through `uninitialized`.
2. Add a dedicated challenge for the initial SP: `ChallengeType::InitialRegister { prover_read_1, prover_read_2, address, initial_value }`. On-chain it reuses the existing `rom_challenge(address, value)` script, which checks `step == INIT && addr == const && value != const` for read 1 or read 2. `verifier_choose_challenge` picks it when the conflicting INIT read is the SP register.

Validated in a scratch copy of `BitVMX-CPU` (not the shared tree) with a separate `CARGO_TARGET_DIR`: `audit_emu_002` 4/4 pass with `--include-ignored`, and the verifier now picks `InitialRegister`, which the script accepts. `cargo test -p emulator --lib` 70/70 pass. `cargo test -p bitcoin-script-riscv --lib challenges::tests::test_` 30/30 pass.

```diff
diff --git a/bitcoin-script-riscv/src/riscv/challenges.rs b/bitcoin-script-riscv/src/riscv/challenges.rs
index c9239a5..3e13b10 100644
--- a/bitcoin-script-riscv/src/riscv/challenges.rs
+++ b/bitcoin-script-riscv/src/riscv/challenges.rs
@@ -902,6 +902,20 @@ pub fn execute_challenge(challege_type: &ChallengeType) -> bool {
             stack.number_u64(prover_read_2.last_step);
             rom_challenge(&mut stack, *address, *input_for_address);
         }
+        ChallengeType::InitialRegister {
+            prover_read_1,
+            prover_read_2,
+            address,
+            initial_value,
+        } => {
+            stack.number_u32(prover_read_1.address);
+            stack.number_u32(prover_read_1.value);
+            stack.number_u64(prover_read_1.last_step);
+            stack.number_u32(prover_read_2.address);
+            stack.number_u32(prover_read_2.value);
+            stack.number_u64(prover_read_2.last_step);
+            rom_challenge(&mut stack, *address, *initial_value);
+        }
         ChallengeType::AddressesSections {
             prover_read_1,
             prover_read_2,
diff --git a/definitions/src/challenge.rs b/definitions/src/challenge.rs
index bf94a03..f014b03 100644
--- a/definitions/src/challenge.rs
+++ b/definitions/src/challenge.rs
@@ -67,6 +67,14 @@ pub enum ChallengeType {
         address: u32,
         input_for_address: u32,
     },
+    // A register whose initial value is a non-zero constant (the stack pointer)
+    // was read with LAST_STEP_INIT and a value different from that constant.
+    InitialRegister {
+        prover_read_1: TraceRead,
+        prover_read_2: TraceRead,
+        address: u32,
+        initial_value: u32,
+    },
     AddressesSections {
         prover_read_1: TraceRead,
         prover_read_2: TraceRead,
diff --git a/emulator/src/decision/challenge.rs b/emulator/src/decision/challenge.rs
index 7572a9f..56d8de5 100644
--- a/emulator/src/decision/challenge.rs
+++ b/emulator/src/decision/challenge.rs
@@ -15,8 +15,9 @@ use crate::{
         execution_log::VerifierChallengeLog,
         nary_search::{choose_segment, ExecutionHashes, NArySearchType},
     },
+    constants::{STACK_BASE_ADDRESS, STACK_SIZE},
     executor::utils::{FailConfiguration, FailSelectionBits},
-    loader::program_definition::ProgramDefinition,
+    loader::{program::REGISTER_STACK_POINTER, program_definition::ProgramDefinition},
     EmulatorError, ExecutionResult,
 };
 
@@ -724,6 +725,20 @@ pub fn verifier_choose_challenge(
                     address: conflict_address,
                     input_for_address: value,
                 });
+            } else if section.registers
+                && conflict_address
+                    == program
+                        .registers
+                        .get_register_address(REGISTER_STACK_POINTER as u32)
+                && force == ForceChallenge::No
+            {
+                info!("Verifier choose to challenge invalid INITIAL STACK POINTER");
+                return Ok(ChallengeType::InitialRegister {
+                    prover_read_1,
+                    prover_read_2,
+                    address: conflict_address,
+                    initial_value: STACK_BASE_ADDRESS + STACK_SIZE,
+                });
             } else if (section.initialized && force == ForceChallenge::No)
                 || force == ForceChallenge::InitializedData
             {
diff --git a/emulator/src/loader/program.rs b/emulator/src/loader/program.rs
index 8172b90..95fca5b 100644
--- a/emulator/src/loader/program.rs
+++ b/emulator/src/loader/program.rs
@@ -654,6 +654,9 @@ impl Program {
         &self,
         program_definition: &ProgramDefinition,
     ) -> SectionDefinition {
+        let sp_address = self
+            .registers
+            .get_register_address(REGISTER_STACK_POINTER as u32);
         let mut uninitialized: Vec<(u32, u32)> = self
             .sections
             .iter()
@@ -661,7 +664,23 @@ impl Program {
                 // we do inputs separately
                 !section.initialized && section.name != program_definition.input_section_name
             })
-            .map(|section| section.range())
+            .flat_map(|section| {
+                let (start, end) = section.range();
+                if section.registers && start <= sp_address && sp_address + 3 <= end {
+                    // the stack pointer starts with a non-zero constant, it is challenged
+                    // with ChallengeType::InitialRegister instead
+                    let mut ranges = vec![];
+                    if start < sp_address {
+                        ranges.push((start, sp_address - 1));
+                    }
+                    if sp_address + 3 < end {
+                        ranges.push((sp_address + 4, end));
+                    }
+                    ranges
+                } else {
+                    vec![(start, end)]
+                }
+            })
             .collect();
 
         let input_section = self
```

Client side (`rust-bitvmx-client/src/program/protocols/dispute/challenge.rs`). This is a sketch and was not compiled:

```diff
-pub const CHALLENGES: [(&str, &'static [(&str, usize)]); 14] = [
+pub const CHALLENGES: [(&str, &'static [(&str, usize)]); 15] = [
     ...
     ("equivocation_resign", &EQUIVOCATION_RESIGN_CHALLENGE),
+    ("initial_register", &ROM_CHALLENGE), // appended last to keep existing leaf indices
 ];
@@ inner `match *challenge_name` of the default single-leaf arm (next to "uninitialized")
+                            "initial_register" => {
+                                let sp_idx = REGISTER_STACK_POINTER as u32;
+                                rom_challenge(
+                                    &mut stack,
+                                    program.registers.get_register_address(sp_idx),
+                                    program.registers.get(sp_idx), // freshly loaded program: initial SP
+                                );
+                            }
@@ ChallengeType -> leaf name mapping (next to UninitializedData)
+        ChallengeType::InitialRegister { .. } => {
+            name = "initial_register";
+            info!("Verifier chose {name} challenge");
+        }
```

Risks and side effects:
* Adding a leaf changes the taproot tree. Disputes that are already set up are incompatible, and both parties must upgrade together. Appending the leaf at the end of `CHALLENGES` keeps the existing leaf indices stable.
* The new `ChallengeType` variant is a serde/API change for any consumer of `bitvmx_cpu_definitions`. The client's exhaustive `match` must get the new arm, or it will not compile, which is useful here.
* The change adds one range to the `uninitialized` script (5 instead of 4), which makes the script slightly larger.
* `ForceChallenge` has no `InitialRegister` variant in the diff. Add one if the forced test paths need it.
* Alternative design: start SP at 0 like every other register and have `_start` in `entrypoint.s` run `li sp, STACK_TOP`. The register range then really is all zero, and no new challenge is needed. This changes execution (hashes and step counts) of every program, requires rebuilding all ELFs, and breaks any program that relies on the emulator providing SP.

### Follow-ups

* `generate_rom_commitment` (`program.rs:877-887`, CLI only) also lists the whole register section as `zero_initialized`. Apply the same exclusion, or list SP as a constant.
* EMU-006 also modifies `get_uninitialized_ranges` (input edge case). Coordinate the two diffs.
* Verifier strategy: `choose_segment` always goes to the first mismatch. That is correct here, but any future "unprovable at the first mismatch" case also lets a lying prover win. Consider a systematic test that every `ChallengeType` the emulator picks in the `FailConfiguration` scenarios is accepted by `execute_challenge`.
