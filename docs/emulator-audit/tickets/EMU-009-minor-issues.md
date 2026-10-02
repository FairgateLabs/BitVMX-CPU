# EMU-009: Minor issues collected during review (rom commitment, register range off-by-one, fault-injection underflows, entrypoint alignment)

* **Status:** Investigated. Items 1-5 confirmed, all low; none of them affects an honest party in the challenge protocol. Item 6 refuted: the witness swap is correct. Fixes are proposed below and not applied.
* **Severity (initial guess):** Low each. Verify them and split out any that turn out to matter.
* **Area:** various

## Items

1. **`generate_rom_commitment` always fails for programs with code** (`program.rs:838-842`). It calls `program.read_mem(position, false)` on code sections. `read_mem` returns `ReadFromExecuteOnlySection` for `is_code` sections unless the flag is true, so the CLI `generate-rom-commitment` returns an error. Confirm (run `cargo run -p emulator -- generate-rom-commitment --elf docker-riscv32/riscv32/build/hello-world.elf`), check whether anything in the workspace depends on it, and propose a fix (`read_instruction` or a raw section read).
2. **`Registers::get_last_register_address` off by one** (`program.rs:144-146`). It returns `base + 34*4` (one past the last register), and `is_register_address` (`utils.rs:11-13`) uses `<=`. So `0xF000_0088` counts as a register address in fault injection, and `get_original_idx` returns 34, which panics on `set`. Only fault injection uses it, but check for other uses.
3. **Fault-injection underflows**: `fetcher.rs:87` `fe.step - 1` when `fail_execute.step == 0`, and `FailRead::new`/`FailExecute::new` `parse - 1` for step 0. Test-only, low.
4. **Unaligned entry point / PC not validated at load**: `read_instruction` (`program.rs:496-507`) does not check alignment. An ELF with an unaligned `e_entry` executes the instruction at `floor(pc/4)*4` while the trace reports the unaligned PC. Only `new_pc` is checked after the step (`fetcher.rs:326-329`). Check whether `load_elf` / `sanity_check` should reject it, and how the `EntryPoint` / `Opcode` challenges behave.
5. **`execute_step` decode `unwrap()`** (`fetcher.rs:269`): safe for code sections thanks to `check_sections_with_invalid_opcode`, but panics with `fail_memory_protection` (reads from any section). Test-only? Confirm.
6. **Div/Rem witness** (`fetcher.rs:538-558`): the witness for `Rem` is the quotient and for `Div` the remainder, swapped on purpose. Confirm it matches what the `div`/`rem` scripts in `bitcoin-script-riscv` expect, including the special cases (division by zero, `i32::MIN / -1`), by running `verify_script` over all special cases.

## What to do

For each item: confirm or reject with a small test, note the result, and propose a fix where it's real.

## Findings

All tests are in `BitVMX-CPU/emulator/tests/audit_emu_009.rs`, including the div/rem script cross-check. That check lives
in the emulator crate because `bitcoin-script-riscv` can't depend on `emulator` without a Cargo.toml change, while `emulator`
already depends on `bitcoin-script-riscv`. The tests come in three kinds:

* `expected_*` assert the correct behavior and are marked `#[ignore = "EMU-009: fails until fixed"]`.
* `demo_*` demonstrate the current behavior (with `#[should_panic]` or by asserting the buggy result) and pass today.
* `check_*` are cross-checks that pass.

```
cd BitVMX-CPU
cargo test -p emulator --test audit_emu_009 -- --nocapture                    # 15 passed, 6 ignored
cargo test -p emulator --test audit_emu_009 -- --nocapture --include-ignored  # the 6 expected_* tests fail (see below)
```

| # | Item | Verdict | Severity |
|---|---|---|---|
| 1 | `generate_rom_commitment` fails for code | **Confirmed**. Related: registers are listed as zero-initialized | Low (CLI only, no consumer) |
| 2 | `get_last_register_address` off by one | **Confirmed** | Low (fault injection only) |
| 3 | Fault-injection underflows | **Confirmed**. Related: `--fail-execute N` replaces step N-1 | Low (test/CLI only) |
| 4 | Unaligned entry point not rejected | **Confirmed** | Low (setup time; the program is agreed upon) |
| 5 | `execute_step` decode `unwrap()` | **Confirmed, test-only**. Also reachable through `fail_opcode` | Low (test-only) |
| 6 | Div/Rem witness swap | **Refuted**: consistent with the scripts, including all special cases | None |

### Item 1: `generate_rom_commitment` always fails for programs with code: CONFIRMED

* **Root cause:** `emulator/src/loader/program.rs:842` calls `program.read_mem(position, false)` on `is_code` sections.
  `read_mem` (`program.rs:522-524`) returns `ReadFromExecuteOnlySection` for code unless the flag is `true`.
* **CLI:** `cargo run -q -p emulator -- generate-rom-commitment --elf docker-riscv32/riscv32/build/hello-world.elf`
  prints `Error: ExecutionError(ReadFromExecuteOnlySection)`.
* **Who depends on it:** only the CLI (`emulator/src/main.rs:453-456`) and the docs (`README.md:31,62-63`). Nothing in
  `rust-bitvmx-client` or the rest of the workspace uses `generate_rom_commitment` or `RomCommitment`. The client gets
  the on-chain code/ROM data from `get_code_chunks`, `get_initialized_chunks` and the section definitions, so the protocol
  is unaffected.
* **Related (new):** the `zero_initialized` loop (`program.rs:877-887`) selects `!is_code && !initialized`. That includes
  the `registers` pseudo-section, which is created with `Section::new` (so `initialized = false`) even though SP starts
  non-zero. It is the same root cause as EMU-002, but here it only affects the unused CLI output.
* **Tests:**
  * `demo_item1_rom_commitment_errors_on_code_sections` (demo, passes): `generate_rom_commitment(hello-world) = Err(ExecutionError(ReadFromExecuteOnlySection))`.
  * `expected_item1_rom_commitment_succeeds_for_hello_world` (ignored): `rom commitment must succeed: ExecutionError(ReadFromExecuteOnlySection)`.
  * `expected_item1_rom_commitment_zero_ranges_exclude_registers` (ignored): `zero_initialized = [(2000, 10), (f0000000, 88)]` -> `registers section reported as zero-initialized`.
* **Proposed fix:**

```diff
--- a/emulator/src/loader/program.rs
+++ b/emulator/src/loader/program.rs
@@ pub fn generate_rom_commitment(program: &Program) -> Result<RomCommitment, EmulatorError> {
         if section.is_code {
             for i in 0..section.size / 4 {
                 let position = section.start + i * 4;
-                let data = program.read_mem(position, false)?;
+                let data = program.read_instruction(position)?;
@@
     for section in &program.sections {
-        if !section.is_code && !section.initialized {
+        if !section.is_code && !section.initialized && !section.registers {
```

### Item 2: `Registers::get_last_register_address` off by one: CONFIRMED

* **Root cause:** `emulator/src/loader/program.rs:144-146` returns `base + 34*4 = 0xF000_0088`. That is one past the last
  register: AUX_2 is at `0xF000_0084`. Because `is_register_address` (`emulator/src/executor/utils.rs:10-13`) uses `<=`,
  `0xF000_0088` counts as a register address. `get_original_idx` (`program.rs:168`) then returns 34, and `Registers::set`
  (`program.rs:160`) panics with an index out of bounds.
* **Other uses:** none. The only callers are `is_register_address` (used by `FailRead::patch_mem` and `FailWrite::patch_mem`)
  and the unit test `utils.rs:549 test_is_register_address_boundaries`, which asserts `is_register_address(last)`.
  The register range that matters for the protocol is `register_sections`, built from `Section::range()` = `(base, base+135)`
  and checked by `address_in_sections` with `address <= end - 3` (`program.rs:592-597`). That range is correct.
* **Impact:** fault injection only. A test that injects a fault at `0xF000_0088` panics instead of patching nothing.
  Honest execution and challenges are unaffected.
* **Tests:**
  * `expected_item2_last_register_address_is_aux2` (ignored): `get_last_register_address = 0xf0000088`, `left: 4026531976 right: 4026531972`.
  * `demo_item2_fail_read_one_past_last_register_panics` and `demo_item2_fail_write_one_past_last_register_panics` (`#[should_panic]`, pass):
    `panicked at emulator\src\loader\program.rs:160:9: index out of bounds: the len is 34 but the index is 34`.
  * `check_item2_aux2_register_is_patchable` (passes): `0xF000_0084` (AUX_2) is patched correctly.
* **Proposed fix:** the existing boundary unit test keeps passing, because `last+1 = 0xF000_0085` falls outside the new range.

```diff
--- a/emulator/src/loader/program.rs
+++ b/emulator/src/loader/program.rs
@@ impl Registers {
     pub fn get_last_register_address(&self) -> u32 {
-        self.base_address + (RISCV32_REGISTERS as u32 * 4 + AUX_REGISTERS as u32 * 4)
+        // address of the last (AUX_2) register, inclusive
+        self.base_address + ((RISCV32_REGISTERS + AUX_REGISTERS - 1) as u32 * 4)
     }
```

### Item 3: Fault-injection underflows: CONFIRMED, plus an off-by-one in `FailExecute::new`

* **Root cause:**
  * `emulator/src/executor/utils.rs:55` (`FailRead::new`) and `utils.rs:196` (`FailExecute::new`) compute `parse_value::<u64>(&args[0]) - 1`, which underflows for `"0"`.
  * `emulator/src/executor/fetcher.rs:87` checks `fe.step - 1 == program.step`, which underflows for `FailExecute { step: 0, .. }`.
* **Related (new): `--fail-execute N` replaces step N-1.** The CLI constructor and the fetcher both subtract 1.
  * `FailExecute { step: N }` replaces step N. Every test in `challenge.rs` and in `rust-bitvmx-client/tests/common/dispute.rs` uses this form.
  * `FailExecute::new(["N", ..])` (used for `--fail-execute` in `main.rs:531`) stores N-1, so it replaces step N-1.
  * The `-1` in `FailRead::new` is correct, because `FailReads::patch_mem` compares against `program.step` *before* the step executes.
  * The description of `--fail-execute [step]` in `README.md:84` is out of date. The option takes `step trace_json` and does not "add 1".
* **Impact:** test/CLI fault injection only. Debug builds panic. Release builds wrap to `u64::MAX`, so the fault silently
  never fires. No protocol impact.
* **Tests:**
  * `demo_item3_fail_read_new_step_zero_underflows` and `demo_item3_fail_execute_new_step_zero_underflows` (`#[should_panic]`):
    `panicked at emulator\src\executor\utils.rs:55:19` and `utils.rs:196:19`, `attempt to subtract with overflow`.
  * `demo_item3_fetcher_fail_execute_step_zero_underflows` (`#[should_panic]`): `panicked at emulator\src\executor\fetcher.rs:87:25: attempt to subtract with overflow`.
  * `check_item3_fail_execute_struct_replaces_given_step` (passes): `FailExecute { step: 5 } replaced step(s) [5]`.
  * `expected_item3_fail_execute_cli_replaces_given_step` (ignored): `FailExecute::new(["5", ..]).step = 4`, `replaced step(s) [4]`, `left: [4] right: [5]`.
* **Proposed fix:**

```diff
--- a/emulator/src/executor/fetcher.rs
+++ b/emulator/src/executor/fetcher.rs
@@ pub fn execute_program(
         let mut trace = match &fail_config.fail_execute {
-            Some(fe) if fe.step - 1 == program.step => {
+            Some(fe) if fe.step == program.step + 1 => {
--- a/emulator/src/executor/utils.rs
+++ b/emulator/src/executor/utils.rs
@@ impl FailRead {
         Self {
-            step: parse_value::<u64>(&args[0]) - 1,
+            step: parse_value::<u64>(&args[0])
+                .checked_sub(1)
+                .expect("fail-read step must be >= 1"),
@@ impl FailExecute {
         Self {
-            step: parse_value::<u64>(&args[0]) - 1,
+            // same meaning as the struct field: the step whose trace is replaced
+            step: parse_value::<u64>(&args[0]),
             fake_trace: TraceRWStep::from_str(&args[1]).unwrap(),
```

### Item 4: Unaligned entry point / PC not validated at load: CONFIRMED (low)

* **Root cause:**
  * `load_elf` (`emulator/src/loader/program.rs:728-730`) accepts any `e_entry`.
  * `sanity_check` (`program.rs:417-426`) has no entry-point check at all, not even "entry is inside a code section".
  * `read_instruction` (`program.rs:496-507`) indexes with `(address - start) / 4`, so it silently returns the word at `floor(pc/4)*4`.
  * Only `new_pc` is checked after the step (`emulator/src/executor/fetcher.rs:327-329`).
* **Observed behavior:** I patched hello-world to `e_entry + 2` (`0x800000fe`).
  * The ELF loads, and `read_instruction(0x800000fe)` returns `0x00000513`, which is the word at `0x800000fc`.
  * Step 1 ends with `UnalignedJump(0x80000102)`, because `pc + 4` is still unaligned. The pushed step-1 trace is `TraceRWStep::from_step(1)` (all zero).
  * So the program can never run correctly. It could only get past step 1 if its first instruction were a `jal`, `jalr` or branch to an aligned target.
* **Challenge behavior:** the emulator and the scripts agree.
  * `AddressesSections`: if a trace with the unaligned PC reached `verifier_choose_challenge`, `address_in_sections`
    requires `address % 4 == 0`, so `is_valid_pc` would be false and the verifier would raise `AddressesSections`, which is
    checked before `EntryPoint` and `Opcode`. The on-chain `is_invalid_pc` (`bitcoin-script-riscv/src/riscv/challenges.rs:362-374`)
    also flags unaligned PCs.
  * `EntryPoint` compares the full address (`challenges.rs:112-128`).
  * `Opcode` uses `>> 2` (`script_utils.rs:1513-1516`), the same floor as the emulator.
* **Impact:** setup time only. Both parties agree on the ELF, so a program with an unaligned entry point is simply broken.
  Rejecting it at load is defensive hardening.
* **Tests:**
  * `demo_item4_unaligned_entrypoint_is_loaded_and_misexecuted` (demo, passes):
    `entry=0x800000fe fetched=0x00000513 (word at 0x800000fc) result=UnalignedJump(2147483906) step1 trace=TraceRWStep { step_number: 1, ... all zero ... }`.
    The patched ELF is written under `std::env::temp_dir()/bitvmx_audit_emu_009/item4/`.
  * `expected_item4_load_elf_rejects_unaligned_entrypoint` (ignored): `assertion failed: load_elf(&path, false).is_err()`.
  * `expected_item4_read_instruction_rejects_unaligned_pc` (ignored): `assertion failed: program.read_instruction(pc + 2).is_err()`.
* **Proposed fix:**

```diff
--- a/emulator/src/loader/program.rs
+++ b/emulator/src/loader/program.rs
@@ pub fn read_instruction(&self, address: u32) -> Result<u32, ExecutionResult> {
         if cfg!(target_endian = "big") {
             panic!("Big endian machine not supported");
         }
+        if !address.is_multiple_of(4) {
+            return Err(ExecutionResult::UnalignedJump(address));
+        }
         let section = self.find_section(address)?;
@@ pub fn load_elf(fname: &str, show_sections: bool) -> Result<Program, EmulatorError> {
     program.sanity_check(Some(STACK_BASE_ADDRESS))?;
+    let entry = program.pc.get_address();
+    if !entry.is_multiple_of(4)
+        || !program.find_section(entry).map(|s| s.is_code).unwrap_or(false)
+    {
+        return Err(EmulatorError::CantLoadPorgram(format!(
+            "Invalid entrypoint 0x{:08x}: must be 4-byte aligned and inside a code section",
+            entry
+        )));
+    }
     program.merge_sections();
```

### Item 5: `execute_step` decode `unwrap()`: CONFIRMED, test-only

* **Root cause:** `emulator/src/executor/fetcher.rs:269` calls `riscv_decode::decode(opcode).unwrap()`.
  * In normal execution the opcode comes from `read_instruction`, which reads code sections only.
  * `check_sections_with_invalid_opcode` (`program.rs:379-401`, run by `load_elf`) guarantees that every code word decodes.
  * Checkpoints are not sanity-checked on load, but they are self-generated and not attacker-controlled.
* **Paths that reach the `unwrap`:** two fault-injection paths can hand it an undecodable word:
  * `fail_memory_protection`, which reads the opcode with `read_mem(pc, true)` from any section.
  * `fail_opcode`, which injects an arbitrary opcode.

  Without fault injection, a PC in a data section returns `ExecuteFromNonCodeSection`, which is correct.
* **Impact:** none on the protocol, since both paths are `FailConfiguration`. Note that in `riscv_decode` 0.2.3,
  `0x00000000` *does* decode, while `0xFFFFFFFF` returns `Err(Reserved)`.
* **Tests:**
  * `check_item5_non_code_pc_returns_error_normally` (passes): `Err(ExecuteFromNonCodeSection)`.
  * `demo_item5_fail_memory_protection_panics_on_undecodable_word` and `demo_item5_fail_opcode_panics_on_undecodable_opcode`
    (`#[should_panic(expected = "Reserved")]`): `panicked at emulator\src\executor\fetcher.rs:269:52: called Result::unwrap() on an Err value: Reserved`.
* **Proposed fix (optional):** makes fault injection return an error instead of panicking.

```diff
--- a/emulator/src/executor/fetcher.rs
+++ b/emulator/src/executor/fetcher.rs
@@ pub fn execute_step(
-    let instruction = riscv_decode::decode(opcode).unwrap();
+    let instruction = riscv_decode::decode(opcode).map_err(|e| {
+        ExecutionResult::InstructionNotImplemented(opcode, format!("undecodable: {:?}", e))
+    })?;
```

### Item 6: Div/Rem witness: REFUTED (correct as implemented)

* **Emulator** (`emulator/src/executor/fetcher.rs:538-558`): the `Div`/`Divu` witness is the remainder, and the `Rem`/`Remu`
  witness is the quotient. Special cases:

  | Instruction | Case | Witness |
  |---|---|---|
  | `Div` | `x / 0` | `x` |
  | `Div` | `MIN / -1` | `0` |
  | `Rem` | `x / 0` | `-1` |
  | `Rem` | `MIN / -1` | `MIN` |

* **Script** (`bitcoin-script-riscv/src/riscv/instructions.rs:580-645`): it passes `(write_value, witness)` to `div`/`divu`
  as `(quotient, remainder)` and to `rem`/`remu` as `(remainder, quotient)`. `remu` and `rem` take those parameters in
  swapped order (`script_utils.rs:1336-1368, 1445-1485`), so the swap is intentional and consistent with the emulator.
* **Special cases on the script side:** in the division-by-zero branch (`div_by_zero_case`, `script_utils.rs:1229-1253`)
  and the `MIN/-1` branch (`overflow_case`, `script_utils.rs:1255-1283`), the script drops both quotient and remainder
  and only checks the result:

  | Script | Result for division by zero |
  |---|---|
  | `div` | `-1` (and `MIN` for `MIN/-1`) |
  | `rem` | the dividend (and `0` for `MIN/-1`) |
  | `divu` | `u32::MAX` |
  | `remu` | the dividend |

  So the witness is unconstrained in these branches. That is harmless: the witness isn't hashed and only helps prove the write value.
* **Tests (all pass):**
  * `check_item6_div_rem_witness_accepted_by_script` and `check_item6_div_rem_witness_accepted_by_instruction_mapping`
    cover 60 operand pairs for each of Div, Divu, Rem and Remu. For each case they:
    1. run the real `execute_step`,
    2. compare the result with an independent RISC-V spec oracle,
    3. run `verify_script`, both with the dynamically built script and with the precomputed
       `create_verification_script_mapping` scripts used on-chain.

    The operand pairs are:
    * division by zero with several dividends, `MIN/-1`, `MIN/1`, `MIN/MIN`, `MIN/MAX`, `MAX/-1`, `-1/-1`, mixed signs and `u32::MAX` cases,
    * the 9 inputs listed in `script_utils.rs` `test_div_rem_signed_fails_for_certain_inputs`. Despite its name, that test asserts nothing; these inputs pass.
    * 24 deterministic pseudo-random pairs.

    Output: `checked 240 div/rem traces (mapping=false), 0 failures` and `checked 240 div/rem traces (mapping=true), 0 failures`.
  * `check_item6_swapped_witness_is_rejected`: with quotient and remainder swapped in the witness, the script rejects the
    trace in the regular Div/Rem/Divu/Remu cases. So the witness really is constrained outside the special cases.
* **No fix needed.**

## Client-side check (rust-bitvmx-client `dispute/*`)

The client doesn't call `generate_rom_commitment`, `is_register_address` or `get_last_register_address`, so items 1–2 don't affect the DRP. The client has its own (also broken, dead) `rom` leaves: [EMU-014](EMU-014-client-rom-leaf-count.md).

See [client-mitigations.md](../client-mitigations.md).
