# EMU-010: The read-value n-ary search is pulled to the conflict step by hash mismatches after it, so a cheating prover wins

* **Status:** Confirmed (found while investigating EMU-005)
* **Severity:** High
* **Area:** `emulator/src/decision/nary_search.rs:211-234` (`choose_segment`, `ReadValueChallenge` mode)

## Summary

In the `ReadValueChallenge` search, `choose_segment` takes the **last** mismatching hash, including hashes at steps *after* the conflict step (padded ones too). Any such mismatch pulls the search to the conflict step instead of the step where the value was written.

A prover that keeps lying in the second search, or posts junk hashes after the conflict step, ends the search at the wrong step. `verifier_choose_challenge_for_read_challenge` then returns `ChallengeType::No`, so **the cheating prover wins**. The existing read-value tests pass only because their prover sends honest hashes in the second search.

## Evidence, test and fix

See the "Findings" section of [EMU-005](EMU-005-round-hash-padding-after-halt.md). In short:

* **Tests:** `emulator/tests/audit_emu_005.rs`
  * `emu005_related_read_value_consistent_cheating_prover_loses`: today the search ends at step 1105 with `No`.
  * `emu005_verifier_read_value_decision_independent_of_padding`: 1458 of 8748 padding variants change the verifier's choice.
* **Fix:** in `ReadValueChallenge` mode, ignore hashes whose step is after the conflict step. The diff is in EMU-005. In a scratch copy, the cheating prover loses with `ReadValue` at step 1104 and the script succeeds; the emulator lib (70/70) and `--test challenge` still pass. Nothing changes on-chain.

## Findings

_(already investigated under EMU-005; split out for tracking)_

## Client-side check (rust-bitvmx-client `dispute/*`)

**Not mitigated.** The read-search `challenge_step_script` (`mod.rs:1324-1354`) only lets the prover object when the verifier's 2nd-search selection is *after* the conflict step. A search pulled exactly to the conflict step is accepted on-chain, the verifier has no challenge to post, and the cheating prover wins.

See [client-mitigations.md](../client-mitigations.md).
