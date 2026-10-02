# EMU-008: Step queries run the program to completion (no early exit), which risks protocol timeouts

* **Status:** Confirmed
* **Severity:** Medium (liveness / performance). Confirmed: every step query re-executes (and hashes) until halt / error / `max_steps`. This is worst for the verifier when the prover's input makes the program not halt, because each verifier query then runs the full `max_steps`.
* **Area:** `emulator/src/executor/fetcher.rs:74-214`, `emulator/src/loader/program_definition.rs:85-249`

## Suspicion

When `trace_list` is given (all challenge-phase queries: `get_round_hashes`, `get_trace_step`, `verifier_choose_challenge`), `execute_program` keeps executing **and hashing** every step until halt, error, or `limit_step == max_steps`, even after the last requested step was recorded. Checkpoints only help with the *start* position.

With `max_steps` in the billions (e.g. zk verifier programs, `LIMIT_STEP = 10_000_000_000`), each protocol step can take far longer than necessary. Protocol actions have on-chain timeouts, so an honest party could miss a deadline. The read-value search queries early steps, which makes it worse.

Side effects to check: does anything depend on the loop running to the end (e.g. `get_round_hashes` padding with `trace.last()` relies on the halt being found, see EMU-005; `ExecutionResult` returned from `execute_helper`)?

## What to do

1. Measure: time `get_trace_step` for an early step vs. a full run on a longer program (e.g. `docker-riscv32/verifier/build/*.elf` if present, otherwise any test ELF). Write a test that checks the trace list mode stops after `max(trace_list)`, or at least a benchmark-like test.
2. Propose a fix: break once `program.step >= max(trace_list)`, while keeping the halt/padding semantics needed by `get_round_hashes`.

## Findings

### Verdict

**Confirmed.** In trace-list mode `execute_program` never stops after the highest requested step. A query for step 10 of a program that runs 2,000,000 steps executes and hashes all 2,000,000 steps and returns `LimitStepReached(2000000)`. With the fix below it stops at step 10 (2.7 s in debug today vs. 21 µs in release with the fix). The returned traces and hashes stay identical.

### Root cause

* `emulator/src/executor/fetcher.rs:38` turns `trace_list` into a `HashSet` that is only used to decide which steps to record (`:66`, `:161-162`). The loop exits only on a step error (`:203-205`), a halt (`:207-209`) or `limit_step == program.step` (`:159`, `:211-213`). Nothing compares `program.step` with the requested steps.
* `ProgramDefinition::execute_helper` (`emulator/src/loader/program_definition.rs:85-123`) always passes `limit_step = Some(self.max_steps)` (`:111`), including for step queries. It loads the checkpoint for `steps[0]` (`:97`, `:63-83`), so checkpoints only shorten the start of the run. The run always ends at the halt or at `max_steps`.
* Every trace-list caller pays for the full run:
  * `get_round_hashes` (`program_definition.rs:157-224`), called by `prover_get_hashes_for_round` (`decision/challenge.rs:101`) and `verifier_choose_segment` (`challenge.rs:210`) in every round of both n-ary searches.
  * `get_trace_step` (`program_definition.rs:226-249`), called by `prover_final_trace` (`challenge.rs:293`).
  * `execute_helper` called directly with steps `[s-1, s, s+1]` in `verifier_choose_challenge` (`challenge.rs:561-570`) and with `[challenge_step+1]` in `verifier_choose_challenge_for_read_challenge` (`challenge.rs:896-905`).
* Only the CLI `execute --list` (`main.rs:562`) lets the user set `--limit` by hand. The README ("Advanced commands") documents this workaround. The library/protocol path has no equivalent.

### What depends on the loop running to the end (checked)

* **Returned `ExecutionResult`:** every trace-list caller ignores it (`_result` at `program_definition.rs:179` and `:235`, `.1` at `challenge.rs:570` and `:905`). Only `get_execution_result` (`program_definition.rs:125-151`) uses the result, and it runs without a trace list, so the fix doesn't change it. The CLI prints the result (`main.rs:581`).
* **Halt trace and `get_round_hashes` padding (EMU-005):** a halt or error is only recorded if its step is in `trace_list` (`fetcher.rs:161-162`). Padding uses `trace.last()` (`program_definition.rs:219-221`) and only happens when the program halts *before* some requested step. In that case the loop already ends at the halt, before `max(trace_list)`. A halt after `max(trace_list)` was never recorded anyway, so the output is identical. A future EMU-005 fix that pads with the final hash still works, because padding only happens when halt < max(trace_list).
* **Initial push** (`fetcher.rs:66-72`, step 0 or the checkpoint step): it happens before the loop and is unaffected. If the start step is the only requested step, the fixed loop runs one extra step and then stops.
* **Fault injection:** `fail_hash`, `fail_execute`, `fail_reads`, `fail_write` and `fail_pc` only matter for steps up to the last recorded step. `fail_hash_until` is applied after execution in `get_round_hashes`. No change.
* **Checkpoint writing:** in trace mode `execute_helper` passes `checkpoint_path = None` (`program_definition.rs:98`), so no checkpoints are lost. Only the CLI combination `--list ... --checkpoints` would stop writing checkpoints after `max(list)`.
* **Order of steps:** `load_program_from_checkpoint` uses `steps[0]` instead of `min(steps)`. All callers pass ascending lists, so this is fine today but fragile (see follow-ups).

### Failure scenario in the challenge protocol (measured)

The measurements use `zkverifier-new-mul.elf`, which needs no input and doesn't halt within 100M steps. Emulator throughput with hashing is **3.25 to 4.2 Msteps/s in release** and about 1.1 Msteps/s in debug.

| Query | Today | With fix (release) |
|---|---|---|
| `get_trace_step(10)`, `max_steps` = 30M | 47.0 s (debug) | 15 ms (measured) |
| `get_trace_step(3M)`, `max_steps` = 30M | 68.4 s (debug) | 0.76 s (measured) |
| `get_trace_step(10)`, `max_steps` = 100M | 29.6 s (release) | ~15 ms (estimated, not measured) |
| `get_trace_step(10M)`, `max_steps` = 100M | 24.8 s (release) | ~2.5 s (estimated, not measured) |

The client's production program definitions (`rust-bitvmx-client/verifiers/cardinal-verifier.yaml` and `generic-verifier.yaml`) use `max_steps: 500000000` and `nary_search: 8`. That gives 2^29 = 536,870,912 steps and 10 rounds per n-ary search (9 full rounds plus a last round of 4).

* **Cost per job:** a dispute runs about 45 emulator jobs. That is about 10 rounds × 2 parties for the conflict search, the same again for the read-value search, plus the final trace and the two challenge decisions. Today each job re-executes from the nearest 50M checkpoint to the halt step. If the program doesn't halt, the job runs to `max_steps`, up to about 500M steps, which is **about 2 to 2.5 minutes per job**. That adds up to roughly an hour of emulator time per dispute that could be seconds.
* **With the fix:** a query in round r costs at most (base mod 50M) + 7·2^29/8^r steps. That is at most 50M + 58.7M (about 30 s) in round 2 and at most 57M (about 15 s) from round 3 on. Round 1 still needs about the whole range by design.
* **Adversarial case:** a dishonest prover can submit an input that makes the program loop and then claim a short halt. The verifier's `verifier_check_execution` has to run to `max_steps` once, which can't be avoided. Today, *every* later verifier job also runs the full `max_steps` again: `verifier_choose_segment`, `verifier_choose_challenge` and the read-value rounds. That is about 2.5 min per job at 500M steps. At `LIMIT_STEP` scale (10B steps, `program.rs:110`, currently only used by the CLI) it would be 40 to 50 min per job.
* **Deadlines:** the client has no timeout for emulator jobs. The deadline is the on-chain timelock: `TIMELOCK_BLOCKS = 15` (`rust-bitvmx-client/src/program/protocols/dispute/mod.rs:73`), about 150 min on mainnet and much less on test networks with fast blocks. At 500M steps a single job fits the mainnet window. Multi-billion-step programs, slower hosts or networks with short blocks don't fit, and the honest party loses by timeout.

### Test

File: `emulator/tests/audit_emu_008.rs`

* `emu008_trace_list_query_stops_after_last_requested_step` is the **bug test**, marked `#[ignore = "EMU-008: fails until fixed"]`. It asserts the expected behavior: after a `trace_list = [10]` query, `program.step <= 10`, and `execute_helper(Some(vec![10]))` reports a step of at most 10.
* `emu008_trace_list_semantics_hello_world` is a **regression guard** that passes before and after the fix. It checks that trace-list mode returns the same traces and hashes as a full run for single- and multi-step queries, for `get_trace_step` up to the halt step, and for `get_round_hashes` in all rounds, including padding past the halt.
* `emu008_measure_step_query_cost` is a **measurement** test and is ignored. The `EMU008_STEPS` environment variable sets the program length (default 30M).

Commands, run from `BitVMX-CPU/`:

```
cargo test -p emulator --test audit_emu_008 -- --nocapture --include-ignored
EMU008_STEPS=100000000 cargo test --release -p emulator --test audit_emu_008 emu008_measure -- --nocapture --include-ignored
```

Current code, debug build:

```
test emu008_trace_list_semantics_hello_world ... ok
execute_program(trace_list=[10], limit=2000000): result=LimitStepReached(2000000), program.step=2000000, traces=1, elapsed=2.7168762s
execute_helper(steps=[10]): result=LimitStepReached(2000000), elapsed=2.2943378s
thread 'emu008_trace_list_query_stops_after_last_requested_step' panicked at emulator\tests\audit_emu_008.rs:140:5:
trace-list query for step 10 executed the program up to step 2000000
full hashed run up to 30000000: LimitStepReached(30000000), steps=30000000, elapsed=27.1286721s, 1.11 Msteps/s
get_trace_step(10) with max_steps=30000000: elapsed=47.0124879s (ideal: ~9.043µs)
get_trace_step(3000000) with max_steps=30000000: elapsed=68.3710115s (ideal: ~2.71286721s)
```

Current code, release build, `EMU008_STEPS=100000000`:

```
full hashed run up to 100000000: LimitStepReached(100000000), steps=100000000, elapsed=30.7473316s, 3.25 Msteps/s
get_trace_step(10) with max_steps=100000000: elapsed=29.6413005s (ideal: ~3.075µs)
get_trace_step(10000000) with max_steps=100000000: elapsed=24.8401224s (ideal: ~3.07473316s)
```

With the fix applied in a scratch copy, release build:

```
execute_program(trace_list=[10], limit=2000000): result=LimitStepReached(10), program.step=10, traces=1, elapsed=21.6µs
execute_helper(steps=[10]): result=LimitStepReached(10), elapsed=12.2104ms
test emu008_trace_list_query_stops_after_last_requested_step ... ok
test emu008_trace_list_semantics_hello_world ... ok
full hashed run up to 30000000: LimitStepReached(30000000), steps=30000000, elapsed=7.1015758s, 4.22 Msteps/s
get_trace_step(10) with max_steps=30000000: elapsed=15.0653ms (ideal: ~2.367µs)
get_trace_step(3000000) with max_steps=30000000: elapsed=756.8995ms (ideal: ~710.15758ms)
```

With the fix, the scratch copy also passes the full emulator suite (release, `--no-fail-fast`). That covers 70 lib unit tests (including the protocol tests in `decision/challenge.rs`), `challenge.rs`, `exceptions.rs`, `compliance.rs`, the instruction tests and the other `audit_emu_00x` files. The only failures were 3 `should_panic` underflow demos in `audit_emu_009`, which depend on overflow checks. They fail in release builds only and pass in debug (15 passed), so they are unrelated to this fix.

### Proposed fix

Stop the loop once the highest requested step has been executed and recorded. Halt and error still take precedence because they are checked first.

```diff
--- a/emulator/src/executor/fetcher.rs
+++ b/emulator/src/executor/fetcher.rs
@@ -36,6 +36,11 @@
     save_non_checkpoint_steps: bool,
 ) -> (ExecutionResult, FullTrace) {
     let trace_set: Option<HashSet<u64>> = trace_list.map(|vec| vec.into_iter().collect());
+    // In trace-list mode (step queries) nothing is recorded after the highest requested step,
+    // so the execution can stop there instead of running until halt / error / limit_step.
+    let last_requested_step: Option<u64> = trace_set
+        .as_ref()
+        .and_then(|set| set.iter().max().copied());
 
     let mut traces = Vec::new();
 
@@ -211,6 +216,10 @@
         if limit_step_reached {
             break ExecutionResult::LimitStepReached(program.step);
         }
+
+        if last_requested_step.is_some_and(|last| program.step >= last) {
+            break ExecutionResult::LimitStepReached(program.step);
+        }
     };
 
     if debug && verify_on_chain {
```

Risks and side effects:

* For trace-list queries, the returned `ExecutionResult` becomes `LimitStepReached(max(trace_list))` instead of the final `Halt` or error. No library caller reads it, but the CLI `execute --list` prints it. A dedicated variant such as `TraceListCompleted(step)` would be a clearer signal. That changes a public enum, so exhaustive matches in `rust-bitvmx-client` and the job dispatcher would need checking.
* In the CLI, `--list` combined with `--checkpoints` stops writing checkpoints after `max(list)`. If that combination matters, add `checkpoint_path.is_none()` to the early-exit condition.
* `trace_list = Some(vec![])` has no maximum, so it keeps today's behavior and runs to the end.
* Hashes, traces and padding don't change. The regression guard test checks this on `hello-world` for all rounds.

### Follow-ups

* `load_program_from_checkpoint(…, steps[0])` (`program_definition.rs:97`) assumes `steps` is sorted ascending. Using `steps.iter().min()` would make both the start and the end of the run independent of the list order.
* Round 1 of each n-ary search still needs nearly the whole execution, so only later rounds and final queries benefit from the fix. If round-1 latency matters, cache the round-1 hashes during the single full run in `prover_execute` / `verifier_check_execution`.
* When the prover's input doesn't halt, the fix already avoids running every job to `max_steps`: each job stops at its last requested step. If needed, the verifier could also persist its own result and last step and cap queries at `my_last_step`.
* Consider giving each emulator job in the client a wall-clock or step budget, compared against the remaining timelock and raising an alert, so liveness problems surface before the deadline.

## Client-side check (rust-bitvmx-client `dispute/*`)

**Not mitigated.** Each round has its own `timelock_blocks` deadline (default 15). This is fine at mainnet block times, but tight with short test timelocks or very large `max_steps`.

See [client-mitigations.md](../client-mitigations.md).
