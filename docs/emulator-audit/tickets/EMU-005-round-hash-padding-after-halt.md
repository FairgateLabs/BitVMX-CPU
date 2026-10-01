# EMU-005: Round-hash padding after halt uses the hash of the last *requested* step, not the final hash

* **Status:** Partially confirmed (padding itself is benign; it exposed a related, exploitable bug in the read-value n-ary search)
* **Severity (initial guess):** Low to medium
* **Severity (after investigation):** padding: Low (no protocol impact); related read-value search bug: High (a cheating prover can win a read-value dispute)
* **Area:** `emulator/src/loader/program_definition.rs:752-819` (`get_round_hashes`), `fetcher.rs:161-179`

## Suspicion

When the program halts at step `H` and some `required_steps` are `> H`, `execute_program` only records steps in `trace_list`. The halt step is recorded only if `H` itself is requested. `get_round_hashes` pads missing hashes with `trace.last().1`, which is the hash of the **last requested step ≤ H**, not `h_H` (the final, committed hash).

Example: base 0, steps `8,16,…,56`, halt at 20: hashes = `[h8, h16, h16, h16, h16, h16, h16]` while one might expect `h20` for steps > 20.

Initial analysis: the prover and verifier run the same code, so they agree when they agree on the execution. Also, a final step beyond the prover's `last_step` is handled with `ChallengeStep` (`prover_get_hashes_and_step`). So this may be harmless. Verify:
* Does any on-chain script (n-ary search scripts in `bitcoin-script-riscv`, e.g. the challenge-step or equivocation scripts, or `rust-bitvmx-client` dispute code) assume that hashes after the last step equal the committed `last_hash`?
* What happens when prover and verifier disagree on `H` (prover claims larger `last_step` than verifier's halt): verifier passes `last_step = None`, and the base is never above its own step to challenge. Confirm no `CantObtainTrace` path (empty trace when all requested steps are > halt).
* Could padding with an earlier hash make a mismatch "disappear" or move it, so the verifier selects a wrong segment?

## What to do

Write a test with `hello-world.yaml` that compares `get_round_hashes` for a round whose required steps go past the halt step against the expected semantics. Document the conclusion. If it's a bug, propose a fix (e.g. always include the halt hash and pad with it).

## Findings

### Verdict

* **Padding observation: confirmed, but benign on its own.** For steps `> H` (the halt step), `get_round_hashes` returns the hash of the last *requested* step `<= H` (or of the base), not `h_H`. With hello-world (`H = 1500`), round 1, base 0: steps `[256 … 1792]` give `[h256, …, h1280, h1280, h1280]` (padding `h1280 != h_H`); round 2, base 1280: steps `[1312 … 1504]` give `h1472` for step 1504. These values are never re-signed by an honest prover and never change a ConflictStep (1st search) decision of an honest verifier.
* **Related finding: confirmed bug (High).** In the 2nd n-ary search (`ReadValueChallenge`), `choose_segment` also counts mismatches at steps *after* the conflict step. Any such mismatch (padded positions included) clamps the choice to the conflict step and pulls the search away from the write step. A prover that keeps its lie in the 2nd search (or simply publishes junk after the conflict step) gets the honest verifier to `ChallengeType::No`, so the cheating prover wins. The padding value matters only because of this: the verifier's read-value decision changes if the padding changes (1458 of 8748 checked patterns differ).

### Root cause analysis

1. Padding (`emulator/src/loader/program_definition.rs:167-221`, `emulator/src/executor/fetcher.rs:161-179`). `execute_program` records only the steps in `trace_list`. A halt is recorded only if `H` itself is requested. `get_round_hashes` pads `required_hashes - obtained_hashes` entries with `trace.last().1` (line 220), which is the hash of the last requested step `<= H`.
2. Why the padding is harmless for the honest prover:
   * `prover_get_hashes_and_step` (`emulator/src/decision/challenge.rs:332-349`) returns `ChallengeStep` whenever the selected step `s >= last_step` (`final_step > last_step - 1`). On-chain, the matching prover leaf (`rust-bitvmx-client/src/program/protocols/dispute/mod.rs:1316-1322`) accepts `last_step <= selection`. So the prover re-signs `h_s`, `h_{s+1}` only when `s + 1 <= H`. Every round base on the path is then `<= s < H`, the cap `min(last_step, base)` never applies, and `s` and `s+1` come from rounds where they are `<= H`, so they are real hashes. The halt step `H` is always requested in the round that contains it, so `next_hash == last_hash` when `s + 1 == H` (consistent with `halt_challenge`, `bitcoin-script-riscv/src/riscv/challenges.rs:184-213`).
   * No on-chain script (halt, trace-hash, equivocation-resign, equivocation-hash, challenge-step) compares round hashes of steps `> last_step` with `prover_last_hash`. The equivocation scripts only use the hashes at the final step(s).
3. Why it is harmless for the honest verifier in the 1st search: `choose_segment` ConflictStep takes the *first* mismatch and `choice = min(selected_step, mismatch_step - 1)` with `selected_step <= min(L_p, H_v) - 1` (`challenge.rs:173`). Padded positions are `> H_v`, so they can never lower the choice.
4. `CantObtainTrace`: the verifier's base is always `<= step_to_challenge <= H_v - 1`, and an honest prover caps its base to `last_step == H`. So the base step is always executed and recorded, and the trace is never empty. Only a prover with a forged `last_step > H` (e.g. `fail_commitment_step`) can reach `CantObtainTrace`, which only hurts that dishonest prover. If the base is a multiple of `CHECKPOINT_SIZE`, see EMU-001.
5. **Read-value search bug** (`emulator/src/decision/nary_search.rs:206-237`). For `ReadValueChallenge` the loop sets `selection` to the *last* mismatching index over **all** hashes (line 215). Then `base = max(selected_step, mismatch_step)` and `choice = min(base, conflict)` (lines 233-234). Both parties agree up to the conflict step `c` and diverge after it, so any requested step `> c` normally mismatches. That mismatch sets `choice = c` instead of keeping the target `read_step = max(w_prover, w_verifier) - 1` (`challenge.rs:757-769`). The search then ends at `c`. In `verifier_choose_challenge_for_read_challenge` (`challenge.rs:841-941`), `h_c` is agreed (no `EquivocationHash`/`CorrectHash`) and `read_step != c`, so the result is `ChallengeType::No`. Padded positions (`> H_v > c`) belong to this "after conflict" range. That's why the read-value decision depends on the padding value.
   The existing in-crate read-value tests (`challenge.rs` tests 35-42) pass only because the faulty prover publishes *honest* hashes in the 2nd search (`fail_config_prover_read_challenge` is `None` or a different failure), so nothing after `c` mismatches.

### Attack / failure scenario

The prover lies about a read value at step `c+1` (e.g. hello-world, step 1106: `read_1` of register `0xf000003c` reported as `0xaa000004` with `last_step = 1105`). The 1st search ends with `c = 1105` and the verifier starts the read-value search (target `read_step = 1104`). In rounds 2..4 the prover publishes hashes from its own (diverged) chain, or any junk, for steps `> c`. In round 4 (base 1104, steps 1105/1106/1107) the mismatch at 1106 makes the verifier choose 1105 instead of 1104. The 2nd search ends at the conflict step, the verifier finds no challenge, and the prover's false claim stands. A prover can always do this, because the hashes after `c` are entirely under its control.

### Tests

File: `emulator/tests/audit_emu_005.rs`. Checkpoints go to `std::env::temp_dir()/bitvmx-audit-emu-005/...`.

| Test | Kind | Result on current code |
|---|---|---|
| `emu005_padding_characterization_hello_world` | characterization of the padding rule | passes |
| `emu005_verifier_conflict_step_decision_independent_of_padding` | expected behavior (8748 `choose_segment` comparisons: current padding vs `h_H` padding) | passes, all identical |
| `emu005_honest_prover_never_resigns_padded_hash` | expected behavior: honest prover through all rounds for `s` in `H-6..H+6`, `H+37`, `H+300`, `2047` | passes (`ChallengeStep` for every `s >= 1500`, exact hashes otherwise) |
| `emu005_related_read_value_prover_honest_in_second_search` | baseline (same as the in-crate test) | passes, `ReadValue` at step 1104 |
| `emu005_verifier_read_value_decision_independent_of_padding` | expected behavior, `#[ignore = "EMU-005: fails until fixed"]` | **fails** |
| `emu005_related_read_value_consistent_cheating_prover_loses` | expected behavior, `#[ignore = "EMU-005: fails until fixed"]` | **fails** |

Command (from `BitVMX-CPU/`):

```
cargo test -p emulator --test audit_emu_005 -- --nocapture --include-ignored
```

Relevant output on the current code:

```
hello-world halts at H = 1500, last_hash = c4d2f485c603416d8c80f32bf2d94282a531bedb
round 1 base 0 steps [256, 512, 768, 1024, 1280, 1536, 1792]: steps > H padded with h_1280 (!= h_H)
round 2 base 1280 steps [1312, 1344, 1376, 1408, 1440, 1472, 1504]: steps > H padded with h_1472 (!= h_H)
ConflictStep: 4374 prover patterns, 8748 comparisons, all identical
s = 1499: final trace step 1500 (published padding: true)
s = 1500: ChallengeStep (published padding: true)
ReadValue: 8748 comparisons, 1458 differ
first difference: round 2 base 1280 sel 1280 conflict 1499: current (0, 1280, 1280) vs pad-with-h_H (6, 1472, 1499); ...
[rv-baseline]   2nd search final step 1104 -> challenge: ReadValue {...} script success: true
[rv-consistent] 2nd search round 4: verifier bits 1
[rv-consistent] 2nd search final step 1105
[rv-consistent] challenge: No script success: false
test result: FAILED. 4 passed; 2 failed
```

The default run (`cargo test -p emulator --test audit_emu_005`) is green: 4 passed, 2 ignored.

### Proposed fix (not applied)

In the read-value search, ignore hashes of steps after the conflict step. That covers padded positions and the expected post-conflict divergence:

```diff
--- a/emulator/src/decision/nary_search.rs
+++ b/emulator/src/decision/nary_search.rs
@@ -209,6 +209,14 @@ pub fn choose_segment(
         0
     };
     for i in 0..prover_hashes.hashes.len() {
+        if nary_type == NArySearchType::ReadValueChallenge {
+            // Hashes after the (agreed) conflict step are expected to differ, or are
+            // padding past the halt step: they must not steer the read-value search.
+            let step = nary_defs.step_from_base_and_bits(round, base_step, (i + 1) as u32);
+            if step > conflict_step.unwrap() {
+                break;
+            }
+        }
         let prover_hash = &prover_hashes.hashes[i];
         let my_hash = &my_hashes.hashes[i];
         if prover_hash != my_hash {
```

Validation: the fix was applied in a scratch copy of the workspace (separate `CARGO_TARGET_DIR`). `audit_emu_005` with `--include-ignored` gave 6/6 passed. The consistent cheating prover now ends at step 1104 with `ReadValue` and the script succeeds. `cargo test -p emulator --lib` gave 70/70 passed, and `--test challenge` passed.

Risks / side effects: this is a verifier-only decision change. Nothing changes on-chain. The selection bits are still only range-checked, and the prover's 2nd-search `ChallengeStep` (selection2 > selection1) is still impossible for an honest verifier because `choice <= conflict` as before. A mismatch exactly at the conflict step is still considered (only `step > conflict` is skipped), so the `EquivocationHash` path is unchanged. The 1st search (ConflictStep) is untouched.

No change is needed for the padding rule itself. Padding with `h_H` (the ticket's suggestion) would be cosmetic. Without the fix above it would actually make the read-value search *worse* in the case where both parties pad with the same agreed hash (all requested steps `> H` and base `<= c`): today those positions match, while with `h_H` padding they would mismatch.

### Follow-ups

* Open a dedicated ticket for the read-value `choose_segment` bug (High). Add unit tests in `nary_search.rs` for `ReadValueChallenge` (there are none today), and in-crate challenge tests where the prover keeps its failure config in the 2nd search.
* Document the padding semantics in `get_round_hashes` ("hashes for steps beyond the executed range are filler and must never be used").
* Separate, not investigated in depth: a prover that claims `last_step > H_v` while the verifier's run halts validly is only challenged with `ForceCondition::ValidInputWrongStepOrHash`. In that case the 1st search ends at `H_v` and the halt challenge needs `last_step == conflict + 1`. Worth checking which challenge the verifier has when the prover keeps "executing" past a real halt.
