# EMU-014: The client's `rom` challenge leaves are dead code, and their leaf counter can shift every later challenge leaf

* **Status:** Confirmed by code reading and section measurements. No executable test: the counter lives inside `challenge_scripts`, which needs a full `ProgramContext`.
* **Severity:** Medium (latent).
  * No program in the repo triggers it today.
  * Once triggered, the honest verifier can't post the `initialized`, `uninitialized`, `future_read`, `read_value_nary_search` or `equivocation_resign` challenges, so a lying prover wins those cases.
* **Found while:** reviewing `rust-bitvmx-client/src/program/protocols/dispute/*` for checks that mitigate the emulator findings.
* **Area:**
  * `rust-bitvmx-client/src/program/protocols/dispute/challenge.rs:467-490` (`"rom"` leaves) and `:875-889` (`RomData` leaf offset);
  * the leaf-start bookkeeping at `:285-289`.

## Bug

```rust
"rom" => {
    if let Some(rodata) = program.find_section_by_name(".rodata") {
        let rodata_words = rodata.data.len() as u32;          // number of WORDS
        let base_addr = rodata.start;
        let step = 4;
        for i in (0..rodata_words).step_by(step) {            // pushes ceil(words / 4) leaves
            let address = base_addr + i;                      // i is used as a BYTE offset
            ...
            challenge_leaf_script.push(winternitz_check);
        }
        challenge_current_leaf += rodata_words / step as u32 + 1;   // counts floor(words / 4) + 1
    }
}
```

1. **The counter doesn't match the leaves pushed when `words % 4 == 0`.**
   * The loop pushes `ceil(w/4)` leaves but the counter adds `floor(w/4) + 1`. That is one too many whenever `w` is a multiple of 4.
   * `challenge_current_leaf` is only used to set `challenge_leaf_start_<name>` for the challenges that follow: `initialized`, `uninitialized`, `future_read`, `read_value_nary_search` and `equivocation_resign`. All of these then point **one leaf past** their real leaf.
   * `get_challenge_leaf` returns that index, and `get_tx_with_speedup_data(.., CHALLENGE, .., leaf)` spends `scripts[leaf]`. So the verifier signs and runs the **next** leaf's script:
     * `InitializedData` chunk `k` runs chunk `k+1`'s script; the last chunk runs the uninitialized leaf.
     * `UninitializedData` runs the `future_read` leaf, and `FutureRead` runs the `read_value_nary_search` leaf.
     * The `read_value_nary_search` start points at the first `equivocation_resign` leaf, so the second n-ary search can't start.
     * The last `equivocation_resign` index runs past the challenge leaves.
   * Every one of those challenge transactions fails, either as an invalid script or with `KeysNotFound`.
2. **Only the first quarter of `.rodata` gets a leaf**: the addresses are `base + 0, 4, 8, ...` while `i < words`. Same word/byte unit confusion as [EMU-011](EMU-011-get-chunks-base-addr-unit.md).
3. **The `RomData` leaf offset** in `get_challenge_leaf` is `address - base_addr` (bytes), but leaf `j` covers `base + 4j`.
4. **All of it is dead code**:
   * the emulator never produces `ChallengeType::RomData` (`grep RomData emulator/src` is empty);
   * `.rodata` reads are already covered by the `initialized` chunk leaves, because `get_initialized_chunks` takes every `initialized && !is_code` section, `.rodata` included.

## Reachability today

| Program (client `verifiers/` + CPU builds) | `.rodata` section | words | leaves pushed / counted | Effect |
|---|---|---|---|---|
| `add-test.elf` | `.rodata` | 5 | 2 / 2 | none |
| `hello-world.elf` | `.rodata` | 25 | 7 / 7 | none |
| `cardinal-verifier.elf`, `generic-verifier.elf`, `zkverifier-new-mul.elf` | renamed by `merge_sections` (`merge_.rodata_...`), so `find_section_by_name(".rodata")` is `None` | n/a | 0 / 0 | none (no rom leaves at all) |
| `test_input_count.elf` | none | n/a | 0 / 0 | none |

Any future program that keeps a section named exactly `.rodata` with a word count that is a multiple of 4 (about 1 in 4 layouts) triggers the shift. Nothing at setup time detects it.

## Proposed fix (not applied)

1. Remove the `"rom"` entry from `CHALLENGES` and its branch: the emulator never uses it, and `initialized` already covers `.rodata`. Remove the `RomData` arm of `get_challenge_leaf` too, or make it return an error.
2. Hardening that removes this class of bug: derive each leaf start from the leaves actually pushed, not from a separate counter:

```diff
-                context.globals.set_var(
-                    id,
-                    &format!("challenge_leaf_start_{}", challenge_name),
-                    VariableTypes::Number(challenge_current_leaf),
-                )?;
+                context.globals.set_var(
+                    id,
+                    &format!("challenge_leaf_start_{}", challenge_name),
+                    VariableTypes::Number(challenge_leaf_script.len() as u32),
+                )?;
```

(Do the same in the `ReadValueChallenge` loop, and drop `challenge_current_leaf`.)

If the `rom` leaves are kept instead, iterate over words (`address = base + 4 * i` for `i in 0..words`) and use `(address - base) / 4` as the offset.

Both options change the taproot (fewer leaves, or different leaves), so ship with the other leaf-changing fixes (EMU-011, EMU-012, EMU-013).
