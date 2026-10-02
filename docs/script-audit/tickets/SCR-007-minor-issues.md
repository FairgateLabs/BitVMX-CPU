# SCR-007: Minor issues and hardening notes

* **Status:** Code reading. Items 1 and 2 were checked against `riscv-decode 0.2.3`. None of these is exploitable with the client's current inputs.
* **Severity:** Low / Info.

## 1. `get_key_from_instruction_and_micro` panics on decodable but unsupported instructions (Low)

* `instruction_mapping.rs:124`: `_ => panic!("Instruction not supported {:?}", instruction)`.
* `riscv_decode` decodes CSR instructions, `fence.i`, `uret`/`sret`/`mret`, `wfi` and others. `Program::check_sections_with_invalid_opcode` only rejects *undecodable* words, so these can be in a loaded code section. Then:
  * `generate_rom_commitment` (`program.rs:852`) panics. It also panics (`unwrap_or_else(panic!)`) on undecodable words, e.g. data in a code section.
  * At runtime the emulator returns `InstructionNotImplemented`.
  * The client calls `get_key_from_opcode` on the prover's own trace only, after the emulator has run the step, so it is not reachable there.
* **Fix:** return `Option`/`Result` from `get_key_from_instruction_and_micro`. Have the loader reject code words that decode to an unsupported instruction.

## 2. RV64 shift encodings are accepted by the decoder/emulator but rejected by the scripts (Low)

* `riscv_decode` decodes `slli`/`srli`/`srai` when `i >> 26` matches. So shamt bit 5 (bit 25), which is reserved in RV32, can be 1, and `ShiftType::shamt()` returns up to 63.
* The emulator executes `value << x.shamt()`. That panics in debug builds and uses `shamt & 31` in release builds.
* The script decoder (`decode_i_type` with `func7`) requires nibble 1 to be ≤ 1, so it rejects the opcode. An honest prover could not prove such a step.
* The ROM is agreed by both parties, so this only matters for hand-built or adversarially supplied programs.
* **Fix:** have the loader reject OP-IMM shifts with bit 25 set, or have the emulator return `InstructionNotImplemented` for `shamt >= 32`.

## 3. Halt is only provable with exit code 0 (Info, by design)

* The `ecall` leaf's halt branch asserts `read_2_value (a0) == 0`. `halt_challenge` also lets the verifier win when the claimed last step is not `(93, 0, ecall)`.
* An honest prover running a program that exits non-zero can't defend a "halted" claim. So the prover client must never commit a halt with a non-zero exit code. Document this as a protocol rule.

## 4. The read micro is not checked by the non-micro leaves (Info)

* `op_conditional`, `op_jal(r)`, `op_arithmetic(_imm)`, `op_upper`, the `op_ecall` halt branch and `op_nop` drop `trace_read.micro` without checking it.
* `op_load_micro_1` does not check that the access is really misaligned.
* Both are safe today: the micro of step `s+1` must equal the micro written by the agreed step `s` (the `program_counter` and `entry_point` challenges). Honest steps write micro ≠ 0 only inside a load/store sequence at the same pc.
* SCR-001's fix makes `op_nop` check the micro.
* For defence in depth, assert `micro == 0` in the single-step leaves.

## 5. Store micro 2 adds nibbles instead of OR-ing them (Info)

* `op_store_micro_2` (`instructions_store.rs:327-332`) computes `aux1 = aux1 + aux2` nibble by nibble. This is correct because the masks of micro 0 (`create_alignment_table`) and micro 1 (`create_alignment_table_2` + rotate) cover disjoint bytes, and the read leaves pin the aux values to the earlier micro-steps.
* If the aux values ever overlapped, a nibble sum above 15 would make the leaf fail; it would never produce a wrong result. Still, `logic_with_bit_extension(.., Or)` (as in `op_load_micro_2`) would be clearer.

## 6. `addresses_sections_challenge` checks alignment of unused accesses (Info)

* `is_invalid_read` / `is_invalid_write` apply `!is_aligned(address)` whatever the witness says.
* Honest unused reads and writes use address 0, which is aligned, so this is harmless. It does mean an unused access must always carry an aligned address. Keep this in mind for SCR-006's CPU-only alternative.

## 7. `verifier_selection_bits_i` high nibble dropped in the EXECUTE strip (Info)

* The strip script drops the high nibble of each selection byte before `verify_challenge_step`.
* The verifier signs these values, and they only bind `prover_conflict_step_tk` to the verifier's choices. A prover can't use this.
* The verifier's own n-ary transactions already validate the bytes (`get_validate_selection_bits_script`). Assert zero anyway, for consistency with SCR-004.

## 8. Code hygiene (Info)

* `decoder.rs:5`, "TODO: Security check. The rs1, rs2, rd should be in 0-31 range": always true, since each field is 5 bits and is turned into `reg * 4` ≤ 124. The aux registers (`0x80`, `0x84`) are only used through constants. Replace the TODO with a comment.
* `validate_register_address` (`instructions.rs:38`): `base_register_address & 0xFF00_0000 >> (i * 8)` relies on `>>` binding tighter than `&`. That gives the intended result (byte `i` of the base), but add parentheses.
* `verify` / `verify_execution` (`instructions.rs:896-964`) `unwrap` the decode and the mapping lookup, and `println!` every instruction. They are only used by the emulator's `verify_on_chain` debug mode, but they would panic on a bad opcode.
* `create_alignment_table(_2)` "TODO: Assert valid alignment in runtime": the alignment comes from `align_memory`, which reduces modulo 4, so it is always 0..3.
