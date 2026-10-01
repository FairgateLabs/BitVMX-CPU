# EMU-006: `get_uninitialized_ranges` panics when the inputs exactly fill the input section, and has other edge cases

* **Status:** Confirmed
* **Severity (initial guess):** Medium. The client calls it while building the dispute scripts, so a panic here can break the setup or the challenge.
* **Severity (after investigation):** Medium for the exact-fill panic (deterministic setup-time crash / liveness, no fund loss). The related PROGBITS-input issue (see Findings) has High impact (honest prover loses) but needs a non-standard ELF whose input section is PROGBITS.
* **Area:** `emulator/src/loader/program.rs:653-695`, `rust-bitvmx-client/src/program/protocols/dispute/challenge.rs:603`

## Suspicion

```rust
let (start, end) = input_section.range();          // end = start + size - 1 (inclusive)
let uninit_start = start + input_size as u32;
assert!(uninit_start <= end, "Input size ({}) exceeds input section size ...");
if uninit_start < end { uninitialized.push((uninit_start, end)); }
```

* If `input_size == section.size` (input exactly fills the section, which is a legitimate config), `uninit_start = end + 1` and the assert **panics** even though nothing is wrong.
* `uninit_start == end` (1 byte left) is silently skipped, which is fine but inconsistent.
* `input_size` that is not a multiple of 4 gives a range starting at an unaligned address. Check how `address_in_sections` in the script handles it (`start <= addr <= end - 3`), and whether the partially-used word is then challengeable as both input and uninitialized.
* If the input section is `initialized` (PROGBITS), it is excluded from the filter by name anyway. Is the tail still reported as uninitialized while it actually holds ELF data? Compare with `InputData` / `InitializedData` selection in `challenge.rs:708-755`.
* `.expect("Input section not found")` panics if the input section name is wrong.

## What to do

1. Add tests with a synthetic `Program` + `ProgramDefinition` (or a yaml in `docker-riscv32/riscv32/build/` pointing at an existing ELF with `inputs` sized to the section) reproducing the panic.
2. Propose a fix (use `<= end` / `>` comparisons correctly, return `Result`, align ranges).

## Findings

### Verdict

**Confirmed.** The main suspicion (panic when the inputs exactly fill the input section) reproduces on the
real `hello-world.elf`. The ticket's other points were refined as follows:

| Point | Result |
|---|---|
| `input_size == section.size` panics | **Confirmed** (`program.rs:678-686`). |
| `uninit_start == end` silently skipped | Harmless: fewer than 4 bytes are left (no word-aligned address), and the last word is classified as input. |
| `input_size % 4 != 0` gives an unaligned range start | Harmless: the script's `address_in_range` is an inclusive `start <= addr <= end` check (`bitcoin-script-riscv/src/riscv/script_utils.rs:1566-1583`) and memory reads in traces are word aligned. The partially used word is `< start + input_size`, so the verifier classifies it as `InputData` (`emulator/src/decision/challenge.rs:713-714`) and it is *not* in the uninitialized range. No double classification. The client also rejects non-multiple-of-4 sizes (`rust-bitvmx-client/src/program/protocols/dispute/input_handler.rs:33`). |
| PROGBITS input section | **Confirmed, and worse than suspected.** The tail is reported as uninitialized even if it holds non-zero ELF data, so a dishonest verifier can win an `UninitializedData` challenge against an honest prover. Related: the input words of a PROGBITS input section are also part of the `InitializedData` chunks (with the ELF contents, not the input), so a dishonest verifier can also win an `InitializedData` challenge against an honest input read. That part is outside `get_uninitialized_ranges` and is listed as a follow-up. |
| `.expect("Input section not found")` | Confirmed panic (`program.rs:667-669`). See also the `merge_sections` follow-up: a correct name can still be "not found". |

### Root cause

`emulator/src/loader/program.rs:653-695` (`Program::get_uninitialized_ranges`):

* `Section::range()` returns an *inclusive* end, `start + size - 1` (`program.rs:77-79`).
* `uninit_start = start + input_size as u32` (`program.rs:678`) is one past the last input byte. When the inputs
  fill the section, `uninit_start == end + 1` and `assert!(uninit_start <= end)` (`program.rs:680-686`) panics,
  even though the configuration is valid: `load_input` accepts it (`program.rs:203-226`) and the program runs.
  The assert compares an exclusive position with an inclusive bound. The correct condition is
  `input_size <= section.size`.
* `input_size` is a `u64` sum truncated with `as u32`, and `start + input_size` can overflow. Neither is checked.
* The tail range is pushed regardless of `input_section.initialized` (`program.rs:688-690`), while the filter for
  the other sections does check `!section.initialized` (`program.rs:662`). A section is `initialized` when it is
  `SHT_PROGBITS` (`program.rs:781`).
* Related (not in this function): `get_initialized_chunks` (`program.rs:643-647`) includes every PROGBITS non-code
  section, including the input section, so the on-chain `InitializedData` leaves for that section commit to the
  ELF contents of the input words. The client builds those leaves from a freshly loaded ELF without input
  (`rust-bitvmx-client/src/program/protocols/dispute/challenge.rs:230`, `:491-492`).

### Failure / attack scenario in the challenge protocol

1. **Exact fill (liveness).** The client builds the "uninitialized" challenge leaf at DRP setup by calling
   `program.get_uninitialized_ranges(program_definitions)` (`rust-bitvmx-client/src/program/protocols/dispute/challenge.rs:595-605`).
   If a program definition's `inputs` sum to exactly the input-section size (for example two 0x1000-byte inputs on
   the 0x2000-byte `.input` of `hello-world.elf`), every participant's client panics while building the scripts.
   The dispute protocol can then never be set up for that legitimate program. Depending on how the client thread
   handles panics, this may also take down the operator process, which would be a DoS for other programs.
   The emulator-side verifier (`emulator/src/decision/challenge.rs:743-747`) would panic in the same way if it were reached.
   Workaround today: make the input section at least one word bigger than the inputs.
2. **PROGBITS input section (honest party loses).** This applies when the guest's input section is PROGBITS instead
   of the `@nobits` section in `docker-riscv32/src/entrypoint.s:31` (for example, a C buffer placed with
   `__attribute__((section(".input")))` and an initializer). If the program reads a never-written tail word that
   holds non-zero ELF data, a dishonest verifier steers the n-ary search to that step and picks `UninitializedData`.
   The script only checks `addr in ranges && last_step == INIT && value != 0` (`bitcoin-script-riscv/src/riscv/challenges.rs:477-511`),
   so it accepts the challenge against the honest prover. In the same way, for an honest read of an input word, a
   dishonest verifier can pick `InitializedData` with the chunk containing that word. The script accepts because
   the committed chunk holds the ELF value, not the input.

### Tests

File: `BitVMX-CPU/emulator/tests/audit_emu_006.rs`

| Test | Kind | Current result |
|---|---|---|
| `emu006_input_exactly_fills_section_real_elf` | Expected behaviour, `#[ignore = "EMU-006: fails until fixed"]` | Fails (panic) |
| `emu006_demo_exact_fill_panics` | Demonstration, `#[should_panic]` (delete after the fix) | Passes |
| `emu006_tail_ranges_and_script_regression` | Regression guard (tail ranges + script boundary checks) | Passes, also with the fix |
| `emu006_progbits_input_tail_not_uninitialized` | Expected behaviour, ignored | Fails (dishonest challenge accepted) |
| `emu006_progbits_input_words_not_initialized_chunks` | Expected behaviour for the related follow-up, ignored | Fails (dishonest challenge accepted) |
| `emu006_demo_missing_input_section_panics` | Demonstration, `#[should_panic]` | Passes |

Command (from `BitVMX-CPU/`):

```
cargo test -p emulator --test audit_emu_006 -- --nocapture --include-ignored
```

Relevant output (unfixed tree):

```
execution result: Halt(0, 1500) last_step=1500
thread 'emu006_input_exactly_fills_section_real_elf' panicked at emulator\src\loader\program.rs:680:9:
Input size (8192) exceeds input section size (2852126720..2852134911)
UninitializedData challenge against honest tail read accepted: true
thread 'emu006_progbits_input_tail_not_uninitialized' panicked at emulator\tests\audit_emu_006.rs:229:5:
assertion failed: !any_range_contains(&ranges, tail_addr)
InitializedData challenge against honest input read accepted: true
thread 'emu006_progbits_input_words_not_initialized_chunks' panicked at emulator\tests\audit_emu_006.rs:267:5:
assertion failed: !dishonest_win
test result: FAILED. 3 passed; 3 failed; ...
```

Without `--include-ignored`: `test result: ok. 3 passed; 0 failed; 3 ignored`.

### Proposed fix

```diff
--- a/emulator/src/loader/program.rs
+++ b/emulator/src/loader/program.rs
@@ -669,24 +669,28 @@
             .expect("Input section not found");
 
         // input section is usually bigger than the actual input of the program, so the remaining space should be uninitialized
-        let input_size = program_definition
+        let input_size: u64 = program_definition
             .inputs
             .iter()
-            .fold(0, |acc, input| acc + input.size);
-
-        let (start, end) = input_section.range();
-        let uninit_start = start + input_size as u32;
+            .map(|input| input.size)
+            .sum();
 
         assert!(
-            uninit_start <= end,
-            "Input size ({}) exceeds input section size ({}..{})",
+            input_size <= input_section.size as u64,
+            "Input size ({}) exceeds input section size ({})",
             input_size,
-            start,
-            end
+            input_section.size
         );
 
-        if uninit_start < end {
-            uninitialized.push((uninit_start, end));
+        // An initialized (PROGBITS) input section keeps its ELF contents after the input,
+        // so its tail is not zero and must not be challengeable as uninitialized.
+        if !input_section.initialized {
+            // load_input pads the last input word with zeros; start the range at the next word
+            let used = (input_size + 3) & !3;
+            if used < input_section.size as u64 {
+                let (start, end) = input_section.range();
+                uninitialized.push((start + used as u32, end));
+            }
         }
 
         SectionDefinition {
```

Validation: I applied the diff to a scratch copy of the three crates and built it with a separate `CARGO_TARGET_DIR`:

* `emu006_input_exactly_fills_section_real_elf`, `emu006_progbits_input_tail_not_uninitialized` and
  `emu006_tail_ranges_and_script_regression` pass.
* `emu006_demo_exact_fill_panics` fails as expected. It documents the old behaviour and should be deleted together
  with the fix.
* `emu006_progbits_input_words_not_initialized_chunks` still fails. It belongs to the follow-up and is not covered
  by this diff.
* `cargo test -p emulator --lib --test challenge` in the scratch copy: 70 + 1 passed.

Risks / side effects:

* The set of uninitialized ranges changes in three cases only:
  (a) exact fill: no tail range, instead of a panic;
  (b) unaligned input sizes: the range starts at the next word instead of mid-word, and the set of challengeable
  aligned addresses is the same;
  (c) PROGBITS input sections: no tail range.
  The client (leaf script) and the emulator verifier call the same function, so they stay consistent. Because the
  on-chain script changes for (b) and (c), both parties must run the same version.
* Oversized inputs and a missing section still panic (assert / `expect`). A better option is to return
  `Result<SectionDefinition, EmulatorError>`, which needs a client change at `challenge.rs:603` and in
  `emulator/src/decision/challenge.rs:747`. Another option is to validate once in `ProgramDefinition::load_program`
  (input section exists, is NOBITS and writable, `sum(inputs) <= size`), so every caller gets an `Err` instead of
  a panic.

### Follow-ups

* **PROGBITS input section in `InitializedData` chunks** (`program.rs:643-647`): exclude the input section (or at
  least its first `input_size` bytes) from `get_initialized_chunks`, or reject PROGBITS input sections at load time.
  Rejecting at load time is the simplest option and also makes the tail fix above moot. Also, the emulator verifier
  computes chunks after `load_input` (`emulator/src/decision/challenge.rs:446-457`, `:731`), while the client builds
  the leaves without input. For PROGBITS input sections, the two sides' chunks therefore also disagree with each other.
* **`merge_sections` renames the input section** (`program.rs:89-106`, `:263-278`, called at `:808`): if the input
  section is contiguous with a compatible section (for example a NOBITS writable `.bss` ending exactly at the input
  start), the two are merged into `merge_<a>_<b>`. `find_section_by_name(".input")` then returns `None`,
  `load_input` fails with `SectionNotFound`, and `get_uninitialized_ranges` panics. This can't happen with
  `docker-riscv32/linker/link.ld` (fixed, non-adjacent addresses), but a custom linker script could trigger it.
  Consider never merging the input section.
* The register section is included in the uninitialized ranges (visible in the scratch-run output as
  `(f0000000, f0000087)`). This is tracked in EMU-002.
