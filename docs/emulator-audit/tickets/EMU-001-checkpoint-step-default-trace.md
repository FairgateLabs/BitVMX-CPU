# EMU-001: Single-step trace query returns an empty trace when the step is a multiple of CHECKPOINT_SIZE

* **Status:** Confirmed
* **Severity:** High. An honest prover can be made to publish an invalid final trace and lose (TraceHash challenge). The read-challenge path can also make an honest verifier submit an invalid CorrectHash/ReadValue trace. Only reachable for programs that run more than `CHECKPOINT_SIZE` (50M) steps.
* **Area:** `emulator/src/loader/program_definition.rs` (`get_trace_step`, `execute_helper`, `load_program_from_checkpoint`), `emulator/src/executor/fetcher.rs:66-72`

## Suspicion

`execute_helper(.., steps = Some(vec![S]), ..)` loads checkpoint `floor(S / CHECKPOINT_SIZE) * CHECKPOINT_SIZE`.
If `S` is a non-zero multiple of `CHECKPOINT_SIZE` (50,000,000), the loaded program is already at `program.step == S`.
`execute_program` then hits the *initial push* before the loop:

```rust
if print_trace && (trace_set.is_none() || trace_set.as_ref().unwrap().contains(&program.step)) {
    traces.push((TraceRWStep::default(), hash_hex.clone()));
```

so `trace[0]` is `TraceRWStep::default()` (the hash is correct, but the trace is empty). The real trace of step `S` is never produced.

Affected callers:
* `ProgramDefinition::get_trace_step` → `prover_final_trace` (`challenge.rs:293`): the prover would publish a default/empty trace for step `S`, so the verifier can win with a `TraceHash` or similar challenge against an **honest** prover. A malicious verifier controls the n-ary search decisions and can steer the search to `s+1 = k * 50M` for any program longer than 50M steps.
* `verifier_choose_challenge_for_read_challenge` (`challenge.rs:896-907`) calls `execute_helper` with `vec![challenge_step + 1]` and uses `my_execution[0].0` as `my_trace` for `CorrectHash` / `ReadValue`.
* Check `verifier_choose_challenge` (`challenge.rs:553-572`) too. It requests `[step-1, step, step+1]`, so the first entry may be a default trace. Only its hash is used, but confirm this.

## What to do

1. Confirm by test. Running 50M real steps is slow. Instead, create a checkpoint by hand: load a small ELF (e.g. `hello-world`), execute a few steps, set `program.step` to `CHECKPOINT_SIZE` (or execute exactly to a step and rename) and `serialize_to_file`. Alternatively, test the logic in `execute_program` directly with a `Program` whose `step` equals the requested step. Compare `get_trace_step(S)` against the trace produced by a run from step 0 for the same step (use a smaller "virtual" checkpoint if possible).
2. Check whether `get_round_hashes` and the hash values are still correct (they should be).
3. Propose a fix, e.g. load the checkpoint for `S - 1` (use `(steps[0].saturating_sub(1) / CHECKPOINT_SIZE) * CHECKPOINT_SIZE`), or only do the initial push for the hash and never use it as a "trace".

## Findings

### Verdict

**Confirmed.** For a single-step query of `S = k * CHECKPOINT_SIZE` (k >= 1), `get_trace_step(S)` returns `TraceRWStep::default()`, with `step_number = 0` and all fields zeroed. The hash returned with it, `h_S`, is correct. Reproduced with a real 50M-step execution and a real checkpoint (see below).

### Root cause

* `emulator/src/loader/program_definition.rs:76`: `load_program_from_checkpoint` picks `checkpoint_step = (step / CHECKPOINT_SIZE) * CHECKPOINT_SIZE`. A checkpoint stores the state *after* its step was executed (`fetcher.rs:181-186` serializes after executing step `n` when `n % CHECKPOINT_SIZE == 0`). So when `step` is itself a checkpoint step, the loaded program already has `program.step == step`, and that step can no longer be re-executed.
* `emulator/src/executor/fetcher.rs:66-72`: before the loop, if `program.step` is in `trace_list`, `execute_program` pushes `(TraceRWStep::default(), hash(program.hash))`. This is meant for the base step (step 0, or the `base` hash in `get_round_hashes`), where only the hash matters. The loop then starts at `S+1`, so the real trace of `S` is never produced.
* `program_definition.rs:244-248`: `get_trace_step` returns `trace[0].0` without checking `step_number == step`.

### Affected callers (`emulator/src/decision/challenge.rs`)

| Caller | Steps requested | Effect when hit |
|---|---|---|
| `prover_final_trace` (`:293`) via `get_trace_step(final_step)` | `[s+1]` | **Broken.** The prover publishes the default trace for `s+1 = kC`. |
| `verifier_choose_challenge_for_read_challenge` (`:896-907`) | `[challenge_step+1]` | **Broken.** `my_trace` is default, so the `CorrectHash.trace` and `ReadValue.trace` sent on-chain are zeroed. |
| `verifier_choose_challenge` (`:553-572`) | `[step-1, step, step+1]` | OK. Only entry 0 can be default (when `step-1 = kC`), and only its hash (`pre_hash`, `:632`) is used. `pre_step` (`:633`) and `my_trace` (`:572`) are produced by the loop. |
| `get_round_hashes` (`program_definition.rs:157`) | `[base, ...required]` | OK. The base entry is skipped and only hashes are used. The test confirms the hashes for `C` and `C+1` are correct. |

### Failure / attack scenario

1. **Honest prover loses.** The program runs more than 50M steps, and the n-ary search ends with disputed step `s+1 = k*50M`. A malicious verifier controls every round's bit selection, so it can steer the search there freely. An honest verifier lands there whenever the real divergence is at that step. The honest prover's `prover_final_trace` publishes `TraceRWStep::default()` together with the correct `h_s` / `h_{s+1}`. The verifier's `validate_step_hash(h_s, default.trace_step, h_{s+1})` fails (`challenge.rs:505`), so it raises `TraceHash`, which the on-chain script accepts because the published trace really does not hash to `h_{s+1}`. The honest prover loses the dispute. If `s+1` is the halt step, the default trace (`read_1.value = 0`, opcode 0) would also trigger the `Halt` challenge.
2. **Honest verifier loses a read sub-challenge.** In the second n-ary search, if `challenge_step + 1 = k*50M`, the verifier sends a zeroed `trace_step` for `CorrectHash` / `ReadValue`. The scripts recompute `hash(h, trace_step)`, so the verifier's challenge fails and a dishonest prover survives. Reachability depends on the read search bounds, which are partly derived from prover-claimed `last_step` values. This is plausible but was not exercised end to end.

### Test

File: `emulator/tests/audit_emu_001.rs`. All three tests assert the **expected** behavior. The two that fail because of the bug are `#[ignore = "EMU-001: fails until fixed..."]`.

* `emu_001_get_trace_step_on_fake_checkpoint_boundary_is_not_default` (fast, ignored). Runs hello-world for 5 steps, relabels the state as step 50,000,000, writes `checkpoint.50000000.json`, and asserts that `get_trace_step(50M)` is either an error or a non-default trace for that step.
* `emu_001_get_trace_step_at_checkpoint_size_matches_real_trace` (slow, about 70 s in debug before the fix and about 340 s with it; ignored). Patches hello-world's entrypoint into an infinite loop (`addi t0,t0,1; jal x0,-4`) with `max_steps = C+10`. A reference `execute_program` run from step 0 writes the real `checkpoint.50000000.json` and records the real traces/hashes of `C-1, C, C+1`. The test then checks `execute_helper([C, C+1])` (hashes and trace `C+1`), `execute_helper([C])`, and `get_trace_step(C)` against the reference.
* `emu_001_control_get_trace_step_non_boundary_is_real` (not ignored, passes). A control showing that non-boundary steps work.

Command (from `BitVMX-CPU/`):

```
cargo test -p emulator --test audit_emu_001 -- --nocapture --include-ignored
```

Output on the current code:

```
get_trace_step(50000000) = Ok("0000000000000000;00000000;00000000;...;00000000;2a")
panicked at emulator\tests\audit_emu_001.rs:109:9: get_trace_step(50000000) returned TraceRWStep::default()

reference run: LimitStepReached(50000001) in 68.1786699s
execute_helper([C, C+1]) = [(0, "ca0a9903f4205c01d72e0b6fb5438ff1c922f0eb"), (50000001, "85da70fc5c1355ba3941f66e3c3141cc7a13f3fb")]
execute_helper([C])[0] = 0000000000000000;00000000;00000000;0000000000000000;00000000;00000000;0000000000000000;00000000;00;00000000;00000000;00000000;00000000;00;00000000;2a ; ca0a9903f4205c01d72e0b6fb5438ff1c922f0eb
reference trace C      = 0000000002faf080;00000000;00000000;0000000000000000;00000000;00000000;0000000000000000;80000100;00;ffdff06f;00000000;00000000;800000fc;00;00000000;2a ; ca0a9903f4205c01d72e0b6fb5438ff1c922f0eb
panicked at emulator\tests\audit_emu_001.rs:186:5: get_trace_step(C) returned TraceRWStep::default()
```

The hashes are correct (`ca0a99...` for `C` in both runs, `85da70...` for `C+1`). Only the trace of `C` is wrong, as the ticket predicted. The test also asserts that `validate_step_hash(h_{C-1}, default, h_C)` is false, which is exactly what the verifier's `TraceHash` check sees.

### Proposed fix

```diff
--- a/emulator/src/loader/program_definition.rs
+++ b/emulator/src/loader/program_definition.rs
@@ -73,7 +73,10 @@ impl ProgramDefinition {
             )));
         }
 
-        let checkpoint_step = (step / CHECKPOINT_SIZE) * CHECKPOINT_SIZE;
+        // A checkpoint stores the state *after* its step was executed, so the trace of
+        // that step cannot be produced from it. Load the last checkpoint strictly before
+        // `step` (step 0 is the initial state: only its hash is meaningful).
+        let checkpoint_step = (step.saturating_sub(1) / CHECKPOINT_SIZE) * CHECKPOINT_SIZE;
 
         if checkpoint_step == 0 {
             self.load_program()
@@ -241,7 +244,7 @@ impl ProgramDefinition {
             false,
         )?;
         // at least the base step should be present
-        if trace.is_empty() {
+        if trace.is_empty() || trace[0].0.step_number != step {
             return Err(EmulatorError::CantObtainTrace);
         }
```

Validated in a scratch copy of the workspace with a separate `CARGO_TARGET_DIR`. With the fix, all 3 `audit_emu_001` tests pass with `--include-ignored`: `get_trace_step(C)` equals the reference trace, and the fake-checkpoint case returns `Err(CantObtainTrace)` instead of a default trace. `cargo test -p emulator --lib --test challenge` also passes (70 + 1 tests).

Risks and side effects:
* Queries whose first step is exactly `k*C` now replay from checkpoint `(k-1)*C`, up to 50M extra steps. The worst case is unchanged (any query for `k*C - 1` already did this), but it adds to the latency concern in EMU-008.
* `get_round_hashes` with `base = k*C` now gets the base hash from the loop instead of the initial push. The value is identical (the test checks `h_C`).
* The extra `step_number` check in `get_trace_step` turns any future "wrong entry" bug into an explicit error instead of a silently wrong trace. `TraceRWStep::default()` has `step_number = 0`, so a step-0 query would still pass, but the protocol never asks for the trace of step 0 (`final_step >= 1`).
* An alternative is to keep the loader and make the initial push in `fetcher.rs:66` hash-only (callers that need real traces would then have to request from `S-1`). That approach is more invasive.

### Follow-ups

* `verifier_choose_challenge_for_read_challenge` (`challenge.rs:907`) also uses `my_execution[0]` without checking `step_number`. Consider the same defensive check there.
* `TraceRWStep::default()` for a non-zero step reports `step_number = 0`, which also shows up in the `execute_helper([C, C+1])` output above. Any consumer that keys on `step_number` (e.g. `fail_hash_until` in `get_round_hashes`, `program_definition.rs:203`) sees step 0 for that entry. This is harmless today because the entry is skipped.
* If a program halts exactly at `k*C`, the checkpoint at `k*C` has `halt = true`. With the current code, queries for `k*C` load that checkpoint and keep executing past the halt. The fix avoids this for `k*C` itself. Queries for `k*C + j` are past the halt and are outside the normal protocol range.

## Client-side check (rust-bitvmx-client `dispute/*`)

**Not mitigated.** The zeroed trace has `opcode = 0`, which doesn't decode to a known instruction, so `execution.rs:216-224` should return `InstructionNotFound` and the honest prover posts no EXECUTE tx (opcode 0 assumed to fail to decode, not run). It loses by timeout rather than by `TraceHash`, which is the same outcome.

See [client-mitigations.md](../client-mitigations.md).
