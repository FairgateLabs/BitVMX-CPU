# SCR-003: `ecall` chooses halt or nop from a read that is not bound to a7, so a real halt can be skipped

* **Status:** Confirmed (executed against the real mapping scripts). Fix proposed and validated (script + emulator), not applied.
* **Severity:** Critical. Every program ends in an `ecall` halt. A lying prover can prove the halt step as "continue at pc + 4" and fork its hash chain there. This works whatever the exit code is (e.g. `exit(1)`).
* **Area:**
  * `bitcoin-script-riscv/src/riscv/instructions.rs:85-162` (`op_ecall`).
  * `emulator/src/executor/fetcher.rs:344-404` (`op_ecall`): for non-halt syscalls, the emulator records **no** reads (`TraceRead::default()`, `MemoryWitness::default()`).

## Bug

```rust
let constant = stack.number_u32(93);
is_equal_to(stack, &trace_read.read_1_value, &constant);   // branch on read_1_value
...
op_nop(&mut stack_if_false, trace_read);                     // non-halt: mem_witness must be "all unused"
```

* The halt branch checks the read addresses (`read_1_add == a7`, `read_2_add == a0`) and the opcode.
* The non-halt branch is `op_nop`. It requires `mem_witness = (Unused, Unused, Unused)`, and it checks neither `read_1_add` nor the opcode (SCR-001).
* So the prover can pick the branch it wants: setting `read_1_value = 0` (or any value other than 93) selects the nop branch.
* The read challenges don't close this gap. Any read can be challenged if its value is not what that **address** holds (a constant, an input, or the last agreed write). But they check value against the *claimed* address. Only the EXECUTE leaf can check that the address is the right one (a7), and the non-halt branch doesn't.
  * So the prover reports a read that is true but from another address. For example: `read_1 = read_2 = (x0, 0, LAST_STEP_INIT)`. x0 is never written, so value 0 at `LAST_STEP_INIT` is correct, and no read leaf can win against it.
  * `scr003_demo_skip_halt_with_true_reads_is_unchallengeable` runs every read leaf against that forged step: `read_value` (both reads, against steps with no write, steps writing a0 and steps writing a7), `initialized` (registers as initialized data, EMU-012 style), `uninitialized` (the register range) and `future_read`. The verifier wins none.
  * With the default unused reads `(0, 0, 0)` the verifier *could* win today, but only through the SCR-006 bug, which must be fixed anyway. So that is not a defence.

The honest emulator does the same for non-halt syscalls: no reads and the default witness. So the script has no way to tell "a7 = 116 (putchar)" from "a7 = 93 (halt)".

Fixing SCR-001 (the opcode check) does **not** fix this. The opcode really is `ecall`; what is missing is a constraint on a7.

## Attack

1. Program `P` ends with `ecall` and `a7 = 93`. Say `a0 = 1` (the check failed), or the prover just wants a different trace.
2. On the halt step, the prover commits `pc + 4, no write` instead of "halt" (same pc, `a0` written).
3. It continues to a fabricated successful halt.
4. The n-ary search lands on the real halt step, which is the first divergence. The prover posts the `ecall` leaf with `read_1_value = 0` and `mem_witness = default`, and the leaf succeeds.
5. No challenge applies:
   * `halt` only concerns the *claimed* last step;
   * `program_counter` and `trace_hash` are consistent;
   * there is no read to challenge.

## Test

File: `emulator/tests/audit_scr.rs`.

| Test | Kind | Result now |
|---|---|---|
| `scr003_demo_halt_can_be_proven_as_nop` | `exit(0)` and `exit(1)`: the forged "continue" step is accepted by the `ecall` leaf. The honest halt is accepted only when `a0 == 0`, by design (see SCR-007). | passes (shows the bug) |
| `scr003_demo_skip_halt_with_true_reads_is_unchallengeable` | the same skip with true x0 reads: no read leaf (`read_value`, `initialized`, `uninitialized`, `future_read`) lets the verifier win | passes (shows the bug) |
| `scr003_ecall_leaf_rejects_skipping_a_halt` | expected behaviour | **fails**, `#[ignore = "SCR-003: fails until fixed"]` |
| `check_ecall_fence_ebreak_honest_traces_accepted` | regression: halt, putchar (116), unknown syscall, `fence`, `ebreak`, `nop` | passes before and after the fix |

## Proposed fix (validated together with SCR-001 and SCR-002)

* **Emulator:** for non-halt syscalls, record the a7 read: `read_1 = registers.to_trace_read(A7)`, `mem_witness = (Register, Unused, Unused)`. Reads are not hashed, so hashes, checkpoints and n-ary searches don't change.
* **Script:** the non-halt branch becomes `op_ecall_continue`, which checks:
  * `mem_witness == (Register, Unused, Unused)`;
  * `opcode == 0x00000073`;
  * `read_1_add == base + 17 * 4` (a7).

  Now `read_1_value` is a real register read, and a lie about it is caught by the read leaves (`read_value`, `initialized`, ...). The branch condition `read_1_value != 93` therefore comes from a value the verifier can challenge.

### Combined diff (SCR-001 + SCR-002 + SCR-003)

```diff
--- a/bitcoin-script-riscv/src/riscv/instructions.rs
+++ b/bitcoin-script-riscv/src/riscv/instructions.rs
@@ pub fn verify_memory_witness(
+// Asserts that the opcode is one of the encodings the emulator executes as a nop:
+// rd == x0 for OP-IMM (0x13), OP (0x33), LUI (0x37), AUIPC (0x17) at micro 0,
+// rd == x0 for LOAD (0x03) at micro 2 (the misaligned load ends early), FENCE (0x0f), or EBREAK.
+pub fn verify_nop_opcode(stack: &mut StackTracker, trace_read: &STraceRead) {
+    ... (see SCR-001) ...
+}
+
+pub fn verify_rd_not_zero(stack: &mut StackTracker, rd: StackVariable) {
+    let copy = stack.copy_var(rd);
+    stack.explode(copy);
+    stack.op_add();
+    stack.number(0);
+    stack.op_greaterthan();
+    stack.op_verify();
+}
+
 pub fn op_nop(stack: &mut StackTracker, trace_read: &STraceRead) -> STraceStep {
+    verify_nop_opcode(stack, trace_read);
     verify_memory_witness(stack, trace_read.mem_witness, MemoryWitness::default());
@@ pub fn op_ecall(
-    //any opcode other than halt (93) is treated as a nop
-    op_nop(&mut stack_if_false, trace_read);
+    //any syscall other than halt (93) is treated as a nop, but a7 is still read (so its value can be challenged)
+    op_ecall_continue(&mut stack_if_false, trace_read, base_register_address);
@@
+fn op_ecall_continue(
+    stack: &mut StackTracker,
+    trace_read: &STraceRead,
+    base_register_address: u32,
+) -> STraceStep {
+    verify_memory_witness(
+        stack,
+        trace_read.mem_witness,
+        MemoryWitness::new(MemoryAccessType::Register, MemoryAccessType::Unused, MemoryAccessType::Unused),
+    );
+    let ecall = stack.number_u32(0x00000073);
+    stack.equals(trace_read.opcode, true, ecall, true);
+    move_and_drop(stack, trace_read.micro);
+    stack.to_altstack(); // pc
+    move_and_drop(stack, trace_read.read_2_value);
+    move_and_drop(stack, trace_read.read_2_add);
+    move_and_drop(stack, trace_read.read_1_value);
+    let add_ra7 = stack.number_u32(base_register_address + (REGISTER_A7_ECALL_ARG as u32) * 4);
+    stack.equals(trace_read.read_1_add, true, add_ra7, true);
+
+    let write_add = stack.number_u32(0);
+    let write_value = stack.number_u32(0);
+
+    let tables = StackTables::new(stack, true, true, 0, 0, 0);
+    stack.from_altstack();
+    let pc = pc_next(stack, &tables, trace_read.program_counter);
+    stack.to_altstack();
+    tables.drop(stack);
+    stack.from_altstack();
+
+    let micro = stack.number(0);
+    STraceStep::new(write_add, write_value, pc, micro)
+}
@@ pub fn op_arithmetic_imm(
         decode_i_type(stack, &tables, trace_read.opcode, func3, 0x13, func7);
+    // rd == x0 is executed as a nop and proven with the nop leaf
+    verify_rd_not_zero(stack, rd);
@@ pub fn op_arithmetic(
         func7,
     );
+    // rd == x0 is executed as a nop and proven with the nop leaf
+    verify_rd_not_zero(stack, rd);
@@ pub fn op_upper(
     let (imm, rd) = decode_u_type(stack, &tables, trace_read.opcode, expected_opcode);
+    // rd == x0 is executed as a nop and proven with the nop leaf
+    verify_rd_not_zero(stack, rd);
--- a/bitcoin-script-riscv/src/riscv/instructions_load.rs
+++ b/bitcoin-script-riscv/src/riscv/instructions_load.rs
-    instructions::{validate_register_address, verify_memory_witness},
+    instructions::{validate_register_address, verify_memory_witness, verify_rd_not_zero},
@@ pub fn op_load_micro_2(
     move_and_drop(stack, rs1);
+    // rd == x0 ends the misaligned load at micro 2 (nop leaf)
+    verify_rd_not_zero(stack, rd);
     move_and_drop(stack, rd);
@@ pub fn op_load_micro_3(
     verify_memory_witness(stack, trace_read.mem_witness, MemoryWitness::rur());
+    verify_rd_not_zero(stack, rd);
     stack.to_altstack(); // save rd
--- a/emulator/src/executor/fetcher.rs
+++ b/emulator/src/executor/fetcher.rs
@@ pub fn op_ecall(  (both the `116 =>` and the `_ =>` arms)
             program.pc.next_address();
+            // a7 is read so the script can prove this is not a halt
             (
-                TraceRead::default(),
+                read_1,
                 TraceRead::default(),
                 TraceWrite::default(),
-                MemoryWitness::default(),
+                MemoryWitness::new(
+                    MemoryAccessType::Register,
+                    MemoryAccessType::Unused,
+                    MemoryAccessType::Unused,
+                ),
             )
```

The complete, compiling patch used for validation is [`patches/SCR-001-002-003.diff`](../patches/SCR-001-002-003.diff) (`git apply` from `BitVMX-CPU/`). The validation results are listed in [SCR-001](SCR-001-nop-leaf-no-opcode-check.md#proposed-fix-validated-together-with-scr-002-and-scr-003).

## Risks / notes

* With this fix, the a7 read of a non-halt ecall becomes challengeable. That is the intent. The emulator's verifier already handles register reads with `last_step` like any other read.
* `ebreak` stays a nop: the emulator does the same. If `ebreak` should halt or fail, decide that in both places at once.
