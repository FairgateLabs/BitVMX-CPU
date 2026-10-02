# SCR-002: Instruction leaves accept `rd = x0`, so a `nop` can also be proven as "write x0"

* **Status:** Confirmed (executed against the real mapping scripts). Fix proposed and validated, not applied.
* **Severity:** Critical. A lying prover can fork its hash chain on any `nop` (`addi x0, x0, 0`) and prove that step. `nop`s appear in practically every compiled program, as alignment padding and in compiler output.
* **Area:**
  * `bitcoin-script-riscv/src/riscv/instructions.rs`: `op_arithmetic_imm` (`:415`), `op_arithmetic` (`:501`) and `op_upper` (`:703`) compute `write_add = base + rd` without checking `rd != 0`.
  * `instructions_load.rs`: `op_load_micro_2` (`:365`) and `op_load_micro_3` (`:426`) do the same.
  * `instruction_mapping.rs`: the key for `rd == 0` is `nop`, but the leaf for the instruction name still exists, and the prover chooses the leaf.
  * The emulator (`fetcher.rs`: `op_arithmetic`, `op_arithmetic_imm`, `op_shift_*`, `op_sl_imm`, `op_upper`, `op_load` micro > 1) runs every `rd == 0` case as "no reads, no write, pc + 4".

## Bug

For `rd == x0` there are two leaves that each accept a different `trace_step` for the same opcode and reads:

| Opcode | Honest step (key `nop`) | Also accepted | Leaf |
|---|---|---|---|
| `addi x0, x0, 0` (`nop`) | write `(0, 0)`, pc + 4 | write `(x0 = 0xF000_0000, 0)`, pc + 4 | `addi` |
| `add x0, x1, x2` | write `(0, 0)`, pc + 4 | write `(x0, x1 + x2)`, pc + 4 | `add` |
| `lui x0, imm` | write `(0, 0)`, pc + 4 | write `(x0, imm)`, pc + 4 | `lui` |
| misaligned `lw x0, ..`, micro 2 | write `(0, 0)`, pc + 4, micro 0 | write `(aux1, aux1 \| aux2)`, same pc, micro 3 | `lw_2` (then `lw_3` writes x0) |

`op_jal`, `op_jalr` and the aligned branch of `op_load_micro_0` already handle `rd == 0` correctly, through `store_if_not_zero` and the `if_is_register_zero` branch.

## Attack

The attack is the same as in [SCR-001](SCR-001-nop-leaf-no-opcode-check.md), with "write x0" as the diverging step:
1. The prover follows the honest execution until the first `nop`.
2. There it commits `write (0xF000_0000, 0)` instead of `(0, 0)`, so its hash chain diverges.
3. It reaches its false final claim through steps that are never examined.
4. In the dispute it posts the `addi` leaf for the `nop` step, and that leaf succeeds.
5. The verifier has no challenge left:
   * the read of x0 is honest;
   * a register write is a valid address for `addresses_sections`.

A `nop` with value 0 written to x0 is enough: the step only has to *differ*, not do anything useful.

## Test

File: `emulator/tests/audit_scr.rs`.

| Test | Kind | Result now |
|---|---|---|
| `scr002_demo_instruction_leaves_accept_write_to_x0` | `nop` (through `addi`), `lui x0`, `add x0`, misaligned `lw x0` at micro 2 (through `lw_2`): honest and forged steps are both accepted, with different hashes | passes (shows the bug) |
| `scr002_instruction_leaves_reject_rd0_write` | expected behaviour for all four cases | **fails**, `#[ignore = "SCR-002: fails until fixed"]` |

## Proposed fix (validated together with SCR-001 and SCR-003)

Add `verify_rd_not_zero(stack, rd)` right after decoding in:
* `op_arithmetic_imm`, `op_arithmetic` and `op_upper`;
* `op_load_micro_2` and `op_load_micro_3`.

The honest `rd == 0` cases keep using the `nop` leaf, which SCR-001 restricts to exactly these encodings.

```rust
pub fn verify_rd_not_zero(stack: &mut StackTracker, rd: StackVariable) {
    let copy = stack.copy_var(rd);
    stack.explode(copy);
    stack.op_add();
    stack.number(0);
    stack.op_greaterthan();
    stack.op_verify();
}
```

The full diff is in [SCR-003](SCR-003-ecall-halt-skippable.md#combined-diff-scr-001--scr-002--scr-003). The validation is described in [SCR-001](SCR-001-nop-leaf-no-opcode-check.md).

## Risks / notes

* Load micro 0 and micro 1 with `rd == 0` must keep accepting: the misaligned case writes aux1/aux2, and the aligned case already has its own `rd == 0` branch. The fix leaves them unchanged. The fuzzer includes `rd == 0` for every kind.
* The generic invariant to test for any new instruction: for each opcode, collect the leaves whose opcode check passes, and make sure their accepted `trace_step` sets don't overlap.
