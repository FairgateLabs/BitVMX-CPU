# SCR-005: `divu` / `remu` accept a wrong result when the divisor is greater than 2^31 + dividend / 2

* **Status:** Confirmed (executed against the real mapping scripts and the direct scripts). Fix proposed and validated, not applied.
* **Severity:** High. A lying prover can prove a wrong `divu`/`remu` result and win the dispute.
  * It needs the program to execute `divu`/`remu` with `divisor > 2^31 + dividend / 2`.
  * That is common in 64-bit division routines (`__udivdi3`, `__umoddi3`, Knuth's algorithm D), which normalize the divisor so that its top bit is set.
* **Area:** `bitcoin-script-riscv/src/riscv/script_utils.rs:1117-1150` (`div_check`), used by `divu`/`remu` (`division_and_remainder`) and, after taking absolute values, by `div`/`rem`.

## Bug

`div_check(dividend, divisor, quotient, remainder)` asserts three things:
1. `remainder < divisor` (unsigned);
2. `divisor * quotient < 2^32` (the high 32 bits of the product are zero);
3. `remainder == dividend - divisor * quotient`, computed by `sub` **mod 2^32**.

Check 3 also holds when `dividend < divisor * quotient` and the subtraction wraps around. Take `q = 1` and `r = dividend - divisor + 2^32`:
* check 1 needs `dividend + 2^32 - divisor < divisor`, that is `divisor > 2^31 + dividend / 2` (this also forces `dividend < divisor`, so the honest result is `q = 0`, `r = dividend`);
* check 2 holds because `divisor < 2^32`;
* check 3 holds by construction.

So for every `(a, d)` with `d > 2^31 + a/2`, both `(q, r) = (0, a)` (honest) and `(1, a - d mod 2^32)` are accepted. The witness is prover-chosen, so this gives:
* `divu(a, d)`: the honest result `0`, or `1` with witness `a - d`;
* `remu(a, d)`: the honest result `a`, or `a - d mod 2^32` with witness `1`.

The signed `div`/`rem` are **not** affected: after `sign_check` the magnitudes are at most 2^31, so the condition can't hold (`check_signed_div_rem_reject_same_forgery`).

Examples:

| Op | a | d | Honest | Also accepted (witness) |
|---|---|---|---|---|
| divu | 4 | 0xffffffff | 0 | 1 (5) |
| remu | 4 | 0xffffffff | 4 | 5 (1) |
| divu | 0x7fffffff | 0xc0000000 | 0 | 1 (0xbfffffff) |
| remu | 0x1234 | 0x90000000 | 0x1234 | 0x70001234 (1) |

## Test

File: `emulator/tests/audit_scr.rs`.

| Test | Kind | Result now |
|---|---|---|
| `scr005_demo_divu_remu_accept_wrong_result` | 4 `(a, d)` pairs, `divu` and `remu`: the honest and the forged step are both accepted, with different hashes | passes (shows the bug) |
| `scr005_check_boundary` | for `a = 0x7fffffff`, the forgery is accepted exactly when `d > 2^31 + a/2` | passes (documents the exact condition) |
| `check_signed_div_rem_reject_same_forgery` | `div`/`rem` reject the same forgery | passes |
| `scr005_divu_remu_reject_wrapped_forgery` | expected behaviour | **fails**, `#[ignore = "SCR-005: fails until fixed"]` |

## Proposed fix (validated, [`patches/SCR-005.diff`](../patches/SCR-005.diff))

Assert `divisor * quotient <= dividend` before the subtraction:

```diff
--- a/bitcoin-script-riscv/src/riscv/script_utils.rs
+++ b/bitcoin-script-riscv/src/riscv/script_utils.rs
@@ -1140,6 +1140,12 @@ pub fn div_check(
 
     // asserts dividend = divisor * quotient + remainder
     let div_round = stack.from_altstack_joined(8, "dividen_round");
+    // asserts divisor * quotient <= dividend, so the subtraction below can't wrap around
+    let div_round_copy = stack.copy_var(div_round);
+    let dividend_copy = stack.copy_var(dividend);
+    is_lower_than(stack, dividend_copy, div_round_copy, true);
+    stack.op_not();
+    stack.op_verify();
     let diff = sub(stack, tables, dividend, div_round);
     stack.move_var(remainder);
     is_equal_to(stack, &remainder, &diff);
```

Validation (scratch patch, reverted afterwards):
* `scr005_divu_remu_reject_wrapped_forgery` passes, and the `scr005_demo_*` / `scr005_check_boundary` tests now fail as they should;
* the honest traces of the fuzzer pass;
* `audit_emu_009 check_item6_*` (the div/rem witness tests from the EMU audit) pass;
* all 137 `bitcoin-script-riscv` unit tests pass.

## Risks / notes

* This changes the `div`, `divu`, `rem` and `remu` leaves (`div_check` is shared). Roll it out with the other leaf changes.
* The EMU audit (EMU-009 item 6) concluded "div/rem witness OK". It tested honest witnesses and swapped witnesses, but not wrapped ones.
