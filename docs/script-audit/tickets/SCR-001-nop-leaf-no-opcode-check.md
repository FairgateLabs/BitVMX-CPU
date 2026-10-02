# SCR-001: The `nop` leaf (and the `ecall` leaf's non-halt branch) never checks the opcode

* **Status:** Confirmed (executed against the real mapping scripts). Fix proposed and validated, not applied.
* **Severity:** Critical. A lying prover can prove **any** instruction as "no write, pc + 4". It wins every dispute.
* **Area:**
  * `bitcoin-script-riscv/src/riscv/instructions.rs:57-80` (`op_nop`): it verifies `mem_witness == default`, then `move_and_drop(opcode)`.
  * `instructions.rs:97-100` (`op_ecall`): the non-halt branch calls the same `op_nop`.
  * `instruction_mapping.rs:44-50,120-122`: the `nop` key is shared by every `rd == x0` OP/OP-IMM/LUI/AUIPC instruction, by load micro 2 with `rd == x0`, and by `fence` and `ebreak`.
  * Client `dispute/mod.rs:1440-1470`: one EXECUTE leaf per key. The **prover** chooses the leaf (`execution.rs:216-231`).

## Bug

The EXECUTE leaf is how the prover proves the disputed step. The leaf for key `nop` (`op_nop`):

```rust
verify_memory_witness(stack, trace_read.mem_witness, MemoryWitness::default()); // all Unused
move_and_drop(stack, trace_read.opcode);        // <- opcode never checked
move_and_drop(stack, trace_read.micro);
... drop the reads ...
write = (0, 0), pc = read_pc + 4, micro = 0
```

Nothing ties the opcode to the "nop" class. The opcode itself is **not** forged: it is the real word the agreed ROM holds at `pc`, so the `opcode` challenge has nothing to catch. What the prover chooses is **which leaf** to spend. The EXECUTE tx has one leaf per mapping key, and nothing on chain maps an opcode to a leaf: each leaf must check, in its own script, that the opcode belongs to it.
* The other leaves do this in their decoders. For example, the `add` leaf checks major opcode `0x33`, funct3 and funct7.
* The `nop` leaf doesn't.

So the prover can spend the `nop` leaf for **any** instruction, with the real opcode in the trace. It just sets:
* `mem_witness = default` (all unused);
* write `(0, 0)`;
* `pc + 4`, micro 0.

The `ecall` leaf does the same in its non-halt branch. The halt branch is chosen only when `read_1_value == 93`, and that branch is the only one that binds `read_1` to a7. In the non-halt branch the prover can fill the read slots with any read that is *true* (e.g. x0 = 0), so no read challenge refutes it (see [SCR-003](SCR-003-ecall-halt-skippable.md)). So the `ecall` leaf is a second universal nop.

## Attack (lying prover, honest verifier)

1. The prover wants to commit a wrong final state, for example "halted with 0" for a program that fails.
2. The prover follows the honest execution up to a step it wants to skip. Examples:
   * the `bne a0, x0, fail` that guards a proof check;
   * a `sw` that would store a bad result;
   * `jal x0, fail`.
3. On that step the prover commits "no write, pc + 4", then continues on the path it likes. The step hash diverges from the verifier's on that step.
4. The n-ary search lands on that step: it is the first divergence. The prover reveals the step and posts the `nop` (or `ecall`) leaf, which succeeds.
5. Every challenge leaf fails for the verifier:
   * `trace_hash`: the hash is consistent;
   * `program_counter`, `opcode`: the pc and the opcode are real;
   * the read leaves: nothing is read.
6. The prover wins.

## Why the `opcode` and `rom` challenges don't stop this

The intended defence: "if the prover picks a leaf for an opcode that isn't in memory, it can run the leaf but loses later". That defence works for a **faked opcode** but not for this bug.

* **`opcode` leaf** (`challenges.rs:437`, one leaf per ROM code chunk; the emulator picks it in `decision/challenge.rs:647`):
  * The verifier wins iff the prover's `read_pc.opcode` differs from the ROM word at `read_pc`. This is the leaf that penalizes a faked opcode: if the prover claims `nop` where the ROM has `add`, the `nop` leaf accepts it, and then the `opcode` challenge wins (the test control below).
  * In SCR-001 the prover keeps the **real** opcode. The problem is that the leaf it picked never looks at the opcode, so there is no mismatch for the `opcode` challenge to find.
* **`rom` leaf** (`challenges.rs:73`; client `challenge.rs:467-490`, the `"rom"` entry, one leaf per `.rodata` word):
  * It concerns **data reads** (`read_1`/`read_2` with `last_step == INIT` at a `.rodata` address), not the instruction fetch. The opcode is `read_pc`, never `read_1`/`read_2`.
  * The forged nop step has no reads at all, so the `rom` leaf (like `initialized`, which already covers `.rodata`) has nothing to compare.
  * The `rom` leaves also have their own bugs: only the first quarter of `.rodata` gets a leaf, the leaf offset is in bytes instead of words, and the leaf counter can shift every later leaf. See [EMU-014](../../emulator-audit/tickets/EMU-014-client-rom-leaf-count.md). Re-enabling the `RomData` decision needs those fixed first.

The same reasoning applies to SCR-002, SCR-003, SCR-004 and SCR-005: in all of them the prover's opcode and reads are the real ones, and only the leaf's acceptance is too loose. ROM/data challenges can't help; only a stricter leaf can.

## Test

File: `emulator/tests/audit_scr.rs`.

`scr001_demo_opcode_and_rom_challenges_cannot_catch_it` runs `execute_challenge(Opcode)` (with the real code chunk) and `execute_challenge(RomData)` against each forged step: the verifier wins neither. Its control case: a prover that fakes the opcode (`nop` in place of `add`) is accepted by the `nop` leaf, but the `opcode` challenge wins.

| Test | Kind | Result now |
|---|---|---|
| `scr001_demo_nop_leaf_accepts_any_instruction_as_nop` | `add`, taken `beq`/`bne`, `jal x0`, `sw`, `lui`: the honest trace is accepted by its own leaf and the forged "nop" trace by the `nop` leaf. The two hashes differ. | passes (shows the bug) |
| `scr001_demo_ecall_leaf_accepts_any_instruction_as_nop` | the same forged traces through the `ecall` leaf | passes (shows the bug) |
| `scr001_nop_and_ecall_leaves_reject_other_opcodes` | expected behaviour | **fails**, `#[ignore = "SCR-001: fails until fixed"]` |

```
cargo test --release -p emulator --test audit_scr -- --nocapture --include-ignored scr001
```

## Proposed fix (validated together with SCR-002 and SCR-003)

1. **`op_nop` checks the opcode class** with a new `verify_nop_opcode`. It accepts exactly the encodings the emulator runs as a nop:
   * `rd == x0` with major opcode `0x13`, `0x33`, `0x37` or `0x17`, at micro 0;
   * `rd == x0` with major opcode `0x03` (load), at micro 2;
   * `0x0f` (fence), at micro 0;
   * exactly `0x00100073` (ebreak).

   It does **not** accept `ecall` (`0x00000073`): an ecall must go through the `ecall` leaf.
2. **The `ecall` leaf's non-halt branch checks `opcode == 0x73`** and reads a7 (see [SCR-003](SCR-003-ecall-halt-skippable.md)).

The full diff (the SCR-001, SCR-002 and SCR-003 parts) is in [SCR-003](SCR-003-ecall-halt-skippable.md#combined-diff-scr-001--scr-002--scr-003). The SCR-001 part:

```rust
pub fn verify_nop_opcode(stack: &mut StackTracker, trace_read: &STraceRead) {
    let ebreak = stack.number_u32(0x0010_0073);
    is_equal_to(stack, &trace_read.opcode, &ebreak);
    stack.to_altstack();
    stack.drop(ebreak);

    stack.copy_var_sub_n(trace_read.opcode, 5);
    stack.copy_var_sub_n(trace_read.opcode, 6);
    stack.copy_var_sub_n(trace_read.opcode, 7);
    stack.copy_var(trace_read.micro);
    stack.custom(
        script! {
            OP_TOALTSTACK                               // n5 n6 n7 | micro
            OP_SWAP                                     // n5 n7 n6
            OP_DUP 8 OP_LESSTHAN OP_TOALTSTACK          // n5 n7 n6 | micro (rd bit 0 == 0)
            OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD
            OP_ADD                                      // n5 major_opcode
            OP_SWAP 0 OP_EQUAL
            OP_FROMALTSTACK OP_BOOLAND                  // major rd_is_zero
            OP_SWAP OP_FROMALTSTACK OP_SWAP             // rd_is_zero micro major
            OP_DUP 0x13 OP_EQUAL
            OP_OVER 0x33 OP_EQUAL OP_BOOLOR
            OP_OVER 0x37 OP_EQUAL OP_BOOLOR
            OP_OVER 0x17 OP_EQUAL OP_BOOLOR
            OP_OVER 0x0f OP_EQUAL OP_BOOLOR             // rd_is_zero micro major nop_class
            2 OP_PICK 0 OP_EQUAL OP_BOOLAND             // rd_is_zero micro major (nop_class && micro == 0)
            OP_SWAP 0x03 OP_EQUAL                       // rd_is_zero micro a is_load
            OP_ROT 2 OP_EQUAL OP_BOOLAND                // rd_is_zero a (is_load && micro == 2)
            OP_BOOLOR OP_BOOLAND
        }
        .compile(),
        4, true, 0, "is_nop_opcode",
    );
    stack.from_altstack();
    stack.op_boolor();
    stack.op_verify();
}

pub fn op_nop(stack: &mut StackTracker, trace_read: &STraceRead) -> STraceStep {
    verify_nop_opcode(stack, trace_read);
    verify_memory_witness(stack, trace_read.mem_witness, MemoryWitness::default());
    ...
```

Validation (scratch patch, reverted afterwards):
* `scr001_*`, `scr002_*` and `scr003_*`: the expected-behaviour tests pass, and every demo now fails.
* Honest traces are still accepted:
  * `fuzz_honest_traces_accepted_and_mutations_rejected` with `AUDIT_SCR_FUZZ=200` (10,457 traces);
  * `check_ecall_fence_ebreak_honest_traces_accepted` (`nop`, `fence`, `ebreak`, halt, putchar and unknown syscalls).
* All `bitcoin-script-riscv` unit tests pass (137), as does the full `emulator` test suite.

## Risks / notes

* The `nop` leaf grows by about 60 opcodes.
* Alternative design: drop the shared `nop` key, and have each instruction leaf branch on `rd == 0` (as `jal`/`jalr`/`lb` already do with `store_if_not_zero`). That would need a mapping change, and the client's leaf indexes would move.
* Fixing SCR-001 alone is not enough. SCR-002 (`rd == 0` in the instruction leaves) and SCR-003 (the ecall halt choice) are independent ways to break uniqueness.
* `fence` is accepted with any funct3 / rs1 / rd. `fence.i` (funct3 = 1) is rejected by the emulator (`InstructionNotImplemented`). Since the ROM is agreed by both parties, this only matters for hand-built programs. To be strict, also require funct3 == 0.
