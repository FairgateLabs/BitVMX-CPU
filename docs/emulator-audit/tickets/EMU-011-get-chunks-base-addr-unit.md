# EMU-011: `get_chunks` computes chunk `base_addr` in words instead of bytes, so the code and initialized-data chunks are mislabeled

* **Status:** Confirmed
* **Severity:** Critical. A malicious verifier wins the `Opcode` (and `InitializedData`) challenge against an honest prover. An honest verifier can't prove a real opcode or data lie. Affects any program whose code or initialized section is larger than one chunk (400 bytes), which is every realistic program.
* **Area:** `emulator/src/loader/program.rs:622-641` (`get_chunks`), used by `get_code_chunks` / `get_initialized_chunks`:
  * on-chain leaves: `rust-bitvmx-client/src/program/protocols/dispute/challenge.rs:293` (opcode) and `:492` (initialized);
  * emulator challenge selection: `emulator/src/decision/challenge.rs:649-656`, `:731-741`;
  * script: `bitcoin-script-riscv/src/riscv/script_utils.rs:1501` (`verify_wrong_chunk_value`).

## Bug

```rust
section.data.chunks(chunk_size as usize)            // splits by u32 WORDS (100 words = 400 bytes)
    .enumerate()
    .map(|(index, chunk)| {
        let offset = section.start + index as u32 * chunk_size;   // advances by 100 BYTES
```

`CHUNK_SIZE = 100` (`definitions/src/lib.rs:7`). Chunk `k` holds the words at `start + 400k ..`, but it is labeled `base_addr = start + 100k`. `Chunk::range()` is `base_addr .. base_addr + len*4 - 1`, so consecutive chunks overlap by 300 bytes.

The script `verify_wrong_chunk_value` checks `address ∈ chunk.range()` and then compares the value with `chunk.data[(address - base_addr) / 4]`. It wins for the verifier if they differ. Only chunk 0 of each section maps addresses correctly. For any other chunk, the "committed" value at an address is really the word from a different address.

`find_chunk_index` (`challenge.rs:426`) picks the first chunk whose (overlapping) range covers the address. That is usually a mislabeled one: for example, `pc 0x80000190` selects chunk 1.

## Impact

* **Honest prover loses:** a malicious verifier steers the n-ary search to any step whose PC falls past the first 400 bytes of code. It posts an `Opcode` challenge with the mislabeled chunk, and the script accepts it against the honest opcode. `InitializedData` works the same way for reads of initialized data past the first chunk.
* **Lying prover wins:** if a prover reports an opcode or initialized value equal to the mislabeled committed word, no `Opcode` / `InitializedData` leaf can refute it. Each address is covered by up to 4 overlapping chunks, and the correct value is never committed for it.
* Existing tests didn't catch this because `hello-world.elf` has a single code chunk. The script's own tests build `Chunk`s by hand with correct bases.

## Test

File: `emulator/tests/audit_emu_011.rs`

| Test | Kind | Result now |
|---|---|---|
| `emu011_chunks_match_memory` | expected behaviour: every chunk word equals memory at `base_addr + 4*i`, no overlaps (hello-world + zkverifier) | **fails**, `#[ignore = "EMU-011: fails until fixed"]` |
| `emu011_malicious_verifier_wins_opcode_challenge_against_honest_pc` | expected behaviour: the real `opcode_challenge` script must reject an honest (pc, opcode) | **fails**, ignored |
| `emu011_demo_chunk_bases_advance_by_words_not_bytes` | demonstration | passes |
| `emu011_demo_malicious_verifier_wins_against_honest_pc` | demonstration | passes |

Command (from `BitVMX-CPU/`): `cargo test -p emulator --test audit_emu_011 -- --nocapture --include-ignored`

```
hello-world.elf code: 1 chunks, 0 mislabeled words, 0 overlapping chunk pairs
hello-world.elf initialized: 2 chunks, 0 mislabeled words, 0 overlapping chunk pairs
zkverifier-new-mul.elf code: 1773 chunks, 177064 mislabeled words, 1772 overlapping chunk pairs
    first mismatch: chunk 1 base 0x80000064: data[0] = 0x0d0080e7 but memory[0x80000064] = 0xfe010113
zkverifier-new-mul.elf initialized: 46 chunks, 4177 mislabeled words, 43 overlapping chunk pairs
zkverifier-new-mul.elf: honest pc 0x80000190 opcode 0x0d0080e7, chunk 1 (base 0x80000064) commits 0x00003097: verifier_wins = true
```

(The hello-world initialized chunks are fine only because each initialized section fits in one chunk.)

## Proposed fix (not applied)

```diff
--- a/emulator/src/loader/program.rs
+++ b/emulator/src/loader/program.rs
@@ pub fn get_chunks(&self, chunk_size: u32, filter: impl Fn(&&Section) -> bool) -> Vec<Chunk> {
                     .map(|(index, chunk)| {
-                        let offset = section.start + index as u32 * chunk_size;
+                        // chunk_size is in words; addresses are in bytes
+                        let offset = section.start + index as u32 * chunk_size * 4;
```

After the fix, chunks tile each section exactly (chunk `k` = `[start + 400k, start + 400k + 399]`), so `find_chunk_index` returns a unique chunk. The number of chunks and leaves is unchanged.

The fix is not yet validated with the tests above: once it is applied, both ignored tests should pass and the two `demo_*` tests should fail (delete them then).

**Validated** (scratch copy, together with the EMU-012 fix):
* `emu011_chunks_match_memory` passes: 0 mislabeled words and 0 overlaps on both ELFs (zkverifier: 1773 code chunks, 47 initialized chunks).
* `emu011_malicious_verifier_wins_opcode_challenge_against_honest_pc` passes.
* The two `demo_*` tests fail as intended; delete them when the fix lands.
* emulator lib (70/70) and `bitcoin-script-riscv` challenge tests (51/51) pass.

The same bug was reported independently by an external report, which also gave an additional honest example: `0x8000064c` (opcode `0x81010113`) mapped to `0x9385a583`. The report counts about 950 code chunks for `zkverifier-new-mul.elf` where we count 1773, so check that both used the same ELF build. Its register fix is tracked as [EMU-012](EMU-012-registers-as-initialized-data.md) and depends on this fix.

### Risks / rollout
* The opcode and initialized leaf scripts change, so the dispute taproot changes. Existing setups are incompatible, and both parties must upgrade together.
* `chunk_index` sent on-chain stays the position in the same list, so the client's leaf-index arithmetic (`challenge_leaf_start_*` + index) still works.

## Follow-ups
* Add a property test in the emulator: every chunk word equals the memory word at its address.
* Consider making the unit explicit (`chunk_words`) to avoid this class of bug.
* Re-run the existing challenge tests with a multi-chunk program (e.g. `zkverifier-new-mul.elf`), not only `hello-world`.
