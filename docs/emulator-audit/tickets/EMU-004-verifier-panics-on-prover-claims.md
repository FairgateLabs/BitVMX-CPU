# EMU-004: `verifier_check_execution` panics on a prover-controlled `claim_last_step == 0`, and other panics on adversarial input

* **Status:** Partially confirmed
* **Severity (initial guess):** Medium to high, depending on whether the on-chain or client layer already rejects such claims.
* **Severity (after investigation):** Low for the `claim_last_step == 0` panic (the on-chain COMMITMENT script rejects the claim, so this is defense in depth). Medium for the related finding (verifier and prover panic when `max_steps` is a power of two and the prover claims `last_step == max_steps`). No program definition in the repo currently uses a power-of-two `max_steps`.
* **Area:** `emulator/src/decision/challenge.rs:170-173`, plus the other `unwrap()`/indexing on data that comes from the other party.

## Suspicion

```rust
assert!(claim_last_step > 0 && last_step > 0);
let step_to_challenge = claim_last_step.min(last_step) - 1;
```

`claim_last_step` is the prover's on-chain claim. A prover claiming `last_step = 0` makes the verifier panic instead of challenging. The prover may then win by timeout. This depends on whether the protocol or the client validates the claim first.

Also review other verifier code paths that index or unwrap based on prover-controlled data:
* `get_hashes` (`challenge.rs:371-393`): `mapping.get(..).unwrap()`.
* `verifier_choose_challenge`: `my_execution[my_trace_idx]` (`:572`), `find_chunk_index(..).unwrap()` (`:650`, `:733`), `program.find_section_idx(conflict_address)?` (`:698`) for a conflict address not in any section. Is this reachable after the `AddressesSections` check?
* `ExecutionHashes::from_hexstr` (`nary_search.rs:169`) `unwrap()` on prover hashes, and odd-length strings.
* `validate_step_hash` `expect("Invalid hex string")`.
* Prover-side code on verifier-controlled data: `prover_get_hashes_and_step` `conflict_step_log.base_step - 1` (`:324`), `prover_final_trace` `final_bits - 1` (`:278`; the client passes `decision + 1`).

## What to do

1. For each item, decide whether the input is attacker-controlled. Trace it back through `rust-bitvmx-client/src/program/protocols/dispute/` to see where the value comes from (on-chain winternitz-signed data, sizes, ranges).
2. Write tests for the reachable ones (e.g. call `verifier_check_execution` with `claim_last_step = 0` using `hello-world.yaml`).
3. Propose fixes. Return a proper `EmulatorError`, or (for claim 0) still challenge, e.g. treat it as a `Halt` challenge at step 0 if there is a script for it.

## Findings

### Verdict

**Partially confirmed.**

* The `assert!` at `challenge.rs:170` does panic on `claim_last_step == 0`, but the protocol can't reach it. The on-chain COMMITMENT script rejects a claim of 0 (and a claim `> max_steps`) before the verifier ever reads it. So this is only a robustness/defense-in-depth issue.
* **New, related, reachable finding.** If the program definition's `max_steps` is an exact power of two (`2^k`), a prover claim of `last_step == max_steps` passes the on-chain check (`last_step <= max_steps`). It then drives the conflict n-ary search to step `2^k - 1`. Step `2^k` is not in the n-ary step mapping, so `get_hashes` panics (`challenge.rs:388`, `mapping.get(&next_step).unwrap()`) in both `verifier_choose_challenge` and the honest prover's `prover_final_trace`.
* None of the other listed `unwrap`/index sites can be reached with prover-controlled data in the current client/on-chain flow (details below).

### Root cause analysis

**1. `claim_last_step == 0` (`emulator/src/decision/challenge.rs:170-173`).**
`verifier_check_execution` checks `assert!(claim_last_step > 0 && last_step > 0)` and then computes `claim_last_step.min(last_step) - 1`. Calling it directly with claim 0 panics whenever the verifier decides to challenge (confirmed by tests, see below).
Where the value comes from in the protocol:
* The verifier only reads `prover_last_step` after the prover's COMMITMENT tx is mined (`rust-bitvmx-client/src/program/protocols/dispute/tx_news.rs:306-339`; it reads the winternitz witness and passes it straight to `EmulatorJobType::VerifierCheckExecution`).
* That spend path (PRE_COMMITMENT -> COMMITMENT, `dispute/mod.rs:694-714`) contains `get_validate_last_step_script(max_steps)` (`dispute/mod.rs:1535-1550`). That script does `equality(zero, last_step, eq=false, verify=true)` (`last_step != 0`) and then `last_step == max_steps || last_step < max_steps`.
* So a COMMITMENT tx with `last_step == 0` or `> max_steps` is invalid, and the assert can't be reached through the protocol. The verifier's own `last_step` can't be 0 either: `get_execution_result` returns `CantObtainTrace` on an empty trace, and the first executed step is 1.

**2. Power-of-two `max_steps` (new).**
* `ProgramDefinition::nary_def()` (`emulator/src/loader/program_definition.rs:52-54`) builds `NArySearchDefinition::new(max_steps, nary)` with `max_bits = ceil(log2(max_steps))` (`nary_search.rs:43-61`). When `max_steps == 2^k`, the search space is `[0, 2^k)`, and `required_steps` never produces `2^k` (`nary_search.rs:90-103`). The highest step hashed in round 1 is `(nary-1)*interval`.
* The on-chain check allows `last_step == max_steps == 2^k`. If the verifier's own execution also reaches `2^k`, `step_to_challenge = 2^k - 1`. That happens when the program runs into `LimitStepReached(max_steps)`, or for any claim with an honest last step `>= 2^k`. When all hashes agree, the search ends at step `2^k - 1`, and `get_hashes(.., 2^k - 1)` needs the mapping entry for `2^k`, which doesn't exist. Result: `challenge.rs:388` panics in `verifier_choose_challenge` (`:462`) and in `prover_get_hashes_and_step` (`:340`, called from `prover_final_trace`).
* `load_program_from_checkpoint` (`program_definition.rs:69`) also rejects step `2^k` (`step >= ndefs.max_steps`), so `get_trace_step(2^k)` errors as well.
* For a non-power-of-two `max_steps`, any `step+1 <= max_steps < 2^k` is on the mapping path. The last non-zero n-ary digit of `step+1` lies in a round whose base equals `step`'s path. So `get_hashes` can't miss there.
* Also, the protocol has no committed hash slot for step `2^k`. Such a config can't be disputed correctly at all at that boundary.

**3. Other sites in the ticket (not reachable with prover data):**
* `get_hashes` `mapping.get(..).unwrap()` (`challenge.rs:379,387-388`): `step` is chosen by the verifier's own `choose_segment`. It is always on the mapping path, except for the power-of-two case above. The verifier's selection bits are range-checked on-chain (`validate_selection_bits_script`).
* `my_execution[my_trace_idx]` (`:572`): `step + 1 <= min(claim, own_last_step)`, so the verifier's own run always yields `step-1`, `step` and `step+1`.
* `find_chunk_index(..).unwrap()` (`:650`): only reached after the AddressesSections check has validated `pc` in a code section, and code chunks cover the whole section. `:733`: the address is in an `initialized` section found by `find_section_idx`, and `get_initialized_chunks` covers it.
* `program.find_section_idx(conflict_address)?` (`:698`): returns `Err` (it doesn't panic). It is reachable only if the conflicting read is outside all sections. `Register`/`Memory` reads are validated by `is_valid_mem` (`program.rs:600-620`). `Unused` reads always pass `is_valid_mem`, and their values are dropped by the instruction scripts (e.g. `op_jal`, `bitcoin-script-riscv/src/riscv/instructions.rs:322-327`), so a prover can put arbitrary values there.
  * This is not exploitable today. The emulator never produces `read_1 = Unused` with `read_2` used, so a decoy can only be on `read_2` while `read_1` is used. When only the decoy differs, the write is fully determined by the agreed reads/pc/opcode, so no divergence can exist at that step. When `read_1` also differs, `read_1` is selected first.
  * It is fragile, though: a read should only count as a "conflict" if its witness is not `Unused` (follow-up).
* `ExecutionHashes::from_hexstr` (`nary_search.rs:169`) and `validate_step_hash` `expect` (`definitions/src/trace.rs:222-223`): hashes reach the emulator as `hex::encode` of fixed-size winternitz messages (`tx_news.rs:43`), so they are always valid, even-length hex. Malformed input via the CLI would panic (`zz`) or be silently truncated (odd length).
* `prover_get_hashes_and_step` `conflict_step_log.base_step - 1` (`:324`): `base_step` is set in `prover_final_trace` to `base + final_bits` with `final_bits = decision + 1 >= 1` (client `tx_news.rs:775`), so it is `>= 1`. `prover_final_trace` `final_bits - 1` (`:278`): same argument. It underflows only if a direct caller passes 0.
* `MemoryWitness::from_byte(x).read_1()` panics for a 2-bit value of 3 or a high nibble `> 2` (`definitions/src/memory.rs:31-39`). The verifier decodes the prover's `prover_mem_witness` (`tx_news.rs:450`). It is not reachable, because the EXECUTE tx can only be spent through the per-instruction verification leaves (`dispute/mod.rs:1442-1466`), which call `verify_memory_witness`.

### Attack / failure scenario

* **Claim 0:** not possible. The COMMITMENT tx with `prover_last_step = 0` can't be mined. If the on-chain check were ever dropped or misconfigured, the verifier job would panic, the verifier would never send POST_COMMITMENT/challenge txs, and the lying prover would win by timeout.
* **Power-of-two `max_steps`:**
  * Suppose a program has `max_steps: 2^k` and doesn't halt within `2^k` steps for some input, or halts after `2^k`. A dishonest prover commits `last_step = 2^k` with an arbitrary last hash, claiming "halted at the limit". This is accepted on-chain.
  * The verifier correctly decides to challenge and plays the n-ary search to step `2^k - 1`, then panics in `verifier_choose_challenge`. It never posts the Halt challenge, which would be correct here because the step-`2^k` trace isn't a halt. The prover wins by timeout.
  * An honest prover facing a dishonest verifier in that config would panic too (`prover_final_trace`).

### Test

File: `emulator/tests/audit_emu_004.rs`

| Test | Kind | Result today |
|---|---|---|
| `claim_last_step_zero_valid_input_does_not_panic` | expected behaviour, `#[ignore = "EMU-004: fails until fixed"]` | fails (panic) |
| `claim_last_step_zero_invalid_input_does_not_panic` | expected behaviour, ignored | fails (panic) |
| `pow2_max_steps_claim_at_limit_verifier_does_not_panic` | expected behaviour, ignored (hello-world with `max_steps: 64` in a temp dir) | fails (panic) |
| `claim_last_step_one_is_challenged_at_step_zero` | boundary, passes | ok |
| `invalid_mem_witness_byte_panics_on_decode` | `#[should_panic]`, documents current (unreachable) behaviour | ok |

Command (from `BitVMX-CPU/`):

```
cargo test -p emulator --test audit_emu_004 -- --nocapture --include-ignored
```

Relevant output (unfixed tree):

```
thread 'claim_last_step_zero_valid_input_does_not_panic' panicked at emulator\src\decision\challenge.rs:170:5:
assertion failed: claim_last_step > 0 && last_step > 0
test claim_last_step_zero_valid_input_does_not_panic ... FAILED
test claim_last_step_zero_invalid_input_does_not_panic ... FAILED   (same assertion)
verifier_check_execution(claim_last_step = 1) -> Ok(Ok(Some(0)))
test claim_last_step_one_is_challenged_at_step_zero ... ok
prover: LimitStepReached(64) last_step=64
verifier step_to_challenge = Some(63)
nary max_steps=64 rounds=2
round 1: verifier decision 7
round 2: verifier decision 7
thread 'pow2_max_steps_claim_at_limit_verifier_does_not_panic' panicked at emulator\src\decision\challenge.rs:388:47:
called `Option::unwrap()` on a `None` value
prover_final_trace PANICKED: called `Option::unwrap()` on a `None` value
verifier_choose_challenge PANICKED: called `Option::unwrap()` on a `None` value
test pow2_max_steps_claim_at_limit_verifier_does_not_panic ... FAILED
test result: FAILED. 2 passed; 3 failed
```

Without `--include-ignored` the suite is green (2 passed, 3 ignored).

### Proposed fix

```diff
diff --git a/emulator/src/decision/challenge.rs b/emulator/src/decision/challenge.rs
index 7572a9f..91addab 100644
--- a/emulator/src/decision/challenge.rs
+++ b/emulator/src/decision/challenge.rs
@@ -136,6 +136,16 @@ pub fn verifier_check_execution(
     save_non_checkpoint_steps: bool,
 ) -> Result<Option<u64>, EmulatorError> {
     let program_def = ProgramDefinition::from_config(program_definition_file)?;
+
+    // `claim_last_step` comes from the prover. The on-chain COMMITMENT script enforces
+    // 0 < claim_last_step <= max_steps, but never panic on it here.
+    if claim_last_step == 0 || claim_last_step > program_def.max_steps {
+        return Err(EmulatorError::ChallengeError(format!(
+            "Invalid prover claim: last_step {} must be in 1..={}",
+            claim_last_step, program_def.max_steps
+        )));
+    }
+
     let (result, last_step, last_hash) = program_def.get_execution_result(
         input.clone(),
         input_checkpoint_path,
@@ -143,6 +153,9 @@ pub fn verifier_check_execution(
         fail_config,
         save_non_checkpoint_steps,
     )?;
+    if last_step == 0 {
+        return Err(EmulatorError::CantObtainTrace);
+    }
 
     let input_is_valid = result == ExecutionResult::Halt(0, last_step);
     let same_step_and_hash = last_step == claim_last_step && last_hash == claim_last_hash;
@@ -167,8 +180,6 @@ pub fn verifier_check_execution(
     warn!("There is a discrepancy between the prover and verifier execution");
     warn!("This execution will be challenged");
 
-    assert!(claim_last_step > 0 && last_step > 0);
-
     // we use the minimum agreed step (that is one before the disagreement)
     let step_to_challenge = claim_last_step.min(last_step) - 1;
 
diff --git a/emulator/src/loader/program_definition.rs b/emulator/src/loader/program_definition.rs
index 3c1329a..51bb7df 100644
--- a/emulator/src/loader/program_definition.rs
+++ b/emulator/src/loader/program_definition.rs
@@ -50,7 +50,10 @@ impl ProgramDefinition {
     }
 
     pub fn nary_def(&self) -> NArySearchDefinition {
-        NArySearchDefinition::new(self.max_steps, self.nary_search)
+        // The search space must contain every step up to and including `max_steps`
+        // (a claim of `last_step == max_steps` is valid on-chain). With
+        // `max_steps == 2^k`, `ceil(log2(max_steps))` would only cover steps < 2^k.
+        NArySearchDefinition::new(self.max_steps + 1, self.nary_search)
     }
 
     pub fn load_program(&self) -> Result<Program, EmulatorError> {
```

Validated in a scratch copy of the crate (separate `CARGO_TARGET_DIR`):
* `audit_emu_004 --include-ignored`: 5/5 pass. With the fix, the pow2 case uses `nary max_steps=128 rounds=3`, `prover_final_trace` returns the step-64 trace, and `verifier_choose_challenge` returns a normal challenge (`EquivocationResign` for the test's dummy resigned hash).
* `cargo test -p emulator --lib`: 70 passed.
* `--test challenge`: 1 passed.

Risks / side effects:
* The claim range check returns `Err` from the verifier job instead of panicking. This changes nothing on the protocol path, since such claims can't be committed on-chain. A test that calls `verifier_check_execution` with a claim `> max_steps` now gets an error.
* `nary_def()` with `max_steps + 1` changes the n-ary geometry **only** when `max_steps` is a power of two (`ceil(log2(n+1)) == ceil(log2(n))` otherwise). For those configs it adds one bit, so the last round or an extra round changes, which changes the generated on-chain scripts/tx graph. Client and emulator both derive it from `ProgramDefinition::nary_def()`, so they stay consistent. In-flight disputes on such configs would be incompatible. No yaml in the repo or the client uses a power of two. `NArySearchDefinition::new` itself (and its unit tests) is unchanged.
* Alternative (protocol-preserving) fix for item 2: reject power-of-two `max_steps` in `ProgramDefinition::from_config`, or make the on-chain validate script enforce `last_step < 2^ceil(log2(max_steps))`.

### Follow-ups

* In `verifier_choose_challenge`, only consider `is_read_N_conflict` when the prover's witness for that read isn't `Unused` (and/or matches the verifier's witness). This hardens the decoy-read path behind `find_section_idx(conflict_address)?` (`:698`).
* Make `ExecutionHashes::from_hexstr` and `validate_step_hash` return errors (use `hex::decode`) instead of `unwrap`/`expect`. Make `get_hashes` return `Result`.
* Guard `final_bits == 0` in `prover_final_trace` (`:278`) for direct CLI use.
* Consider `MemoryWitness::read_1/read_2/write` returning `Result` (or `TryFrom`) instead of panicking.

## Client-side check (rust-bitvmx-client `dispute/*`)

Confirmed again: `get_validate_last_step_script` (`mod.rs:1535-1551`) enforces `last_step != 0 && last_step <= max_steps`. The `<=` is what makes `last_step == max_steps` (power-of-two panic) reachable. A client-only alternative to the CPU fix is to make that check strict (`<`).

See [client-mitigations.md](../client-mitigations.md).
