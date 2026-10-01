//! EMU-005: round hashes for steps past the halt step are padded with the hash of
//! the last *requested* step <= halt (or the base), not with the final hash `h_H`.
//!
//! Verdict: partially confirmed. The padding rule itself is harmless for the
//! honest prover and for the 1st (ConflictStep) search. But in the 2nd
//! (ReadValueChallenge) search the verifier's decision depends on hashes after the
//! conflict step (padded ones included), which lets a cheating prover steer the
//! search away from the write step and win (related finding, see ticket).
//!
//! * `emu005_padding_characterization_hello_world` (PASSES): documents the padding
//!   rule (requested steps <= H are exact; steps > H get the hash of the last
//!   requested step <= H, which is != `h_H` when H is not requested).
//! * `emu005_verifier_conflict_step_decision_independent_of_padding` (PASSES).
//! * `emu005_verifier_read_value_decision_independent_of_padding` (BUG test,
//!   ignored until fixed).
//! * `emu005_honest_prover_never_resigns_padded_hash` (PASSES): for final
//!   selections `s >= H` the honest prover answers `ChallengeStep`, for `s < H` it
//!   re-signs the exact `h_s`, `h_{s+1}`.
//! * `emu005_related_read_value_prover_honest_in_second_search` (PASSES, baseline).
//! * `emu005_related_read_value_consistent_cheating_prover_loses` (BUG test,
//!   ignored until fixed): a prover that keeps its lie in the 2nd search gets the
//!   verifier to `ChallengeType::No`.

use std::path::PathBuf;

use bitvmx_cpu_definitions::{
    challenge::ProverFinalTraceType,
    trace::{generate_initial_step_hash, hashvec_to_string},
};
use emulator::{
    decision::{
        challenge::{prover_execute, prover_final_trace, prover_get_hashes_for_round},
        nary_search::{choose_segment, ExecutionHashes, NArySearchDefinition, NArySearchType},
    },
    loader::program_definition::ProgramDefinition,
    ExecutionResult,
};

const HELLO_YAML: &str = "../docker-riscv32/riscv32/build/hello-world.yaml";

fn input() -> Vec<u8> {
    vec![17, 17, 17, 17]
}

fn tmp_dir(name: &str) -> String {
    let dir: PathBuf = std::env::temp_dir()
        .join("bitvmx-audit-emu-005")
        .join(format!("{}-{}", name, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir.to_string_lossy().replace('\\', "/")
}

/// Returns (H, last_hash, hashes[0..=H]) where hashes[k] = h_k.
fn full_hash_chain(def: &ProgramDefinition, dir: &str) -> (u64, String, Vec<String>) {
    let (result, last_step, last_hash) = def
        .get_execution_result(input(), dir, dir, None, false)
        .unwrap();
    assert_eq!(result, ExecutionResult::Halt(0, last_step));

    let steps: Vec<u64> = (0..=last_step).collect();
    let (_r, trace) = def
        .execute_helper(dir, dir, input(), Some(steps), None, false)
        .unwrap();
    assert_eq!(trace.len() as u64, last_step + 1);
    let hashes: Vec<String> = trace.into_iter().map(|t| t.1).collect();
    assert_eq!(hashes[0], hashvec_to_string(generate_initial_step_hash()));
    assert_eq!(hashes[last_step as usize], last_hash);
    (last_step, last_hash, hashes)
}

/// size of the segment that a round splits
fn block_size(nd: &NArySearchDefinition, round: u8) -> u64 {
    if round <= nd.full_rounds {
        nd.max_steps / (nd.nary as u64).pow(round as u32 - 1)
    } else {
        nd.nary_last_round as u64
    }
}

/// (round, base) pairs for which the round's required steps straddle H.
fn rounds_straddling_halt(nd: &NArySearchDefinition, h: u64) -> Vec<(u8, u64)> {
    let mut v = vec![];
    for round in 1..=nd.total_rounds() {
        let block = block_size(nd, round);
        let base = (h / block) * block;
        let steps = nd.required_steps(round, base);
        if base < h && steps.iter().any(|s| *s > h) {
            v.push((round, base));
        }
    }
    v
}

#[test]
fn emu005_padding_characterization_hello_world() {
    let dir = tmp_dir("characterization");
    let def = ProgramDefinition::from_config(HELLO_YAML).unwrap();
    let nd = def.nary_def();
    let (h, last_hash, chain) = full_hash_chain(&def, &dir);
    println!("hello-world halts at H = {h}, last_hash = {last_hash}");

    let cases = rounds_straddling_halt(&nd, h);
    assert!(!cases.is_empty());
    let mut padded_differs_from_final = 0;
    for (round, base) in cases {
        let steps = nd.required_steps(round, base);
        let got = def
            .get_round_hashes(&dir, &dir, input(), round, base, None, None)
            .unwrap();
        assert_eq!(got.len(), steps.len());

        // last requested step <= H (the base is always requested)
        let last_req = steps
            .iter()
            .copied()
            .filter(|s| *s <= h)
            .max()
            .unwrap_or(base);
        for (i, s) in steps.iter().enumerate() {
            if *s <= h {
                assert_eq!(got[i], chain[*s as usize], "round {round} step {s}");
            } else {
                // current padding rule
                assert_eq!(got[i], chain[last_req as usize], "round {round} step {s}");
                if got[i] != last_hash {
                    padded_differs_from_final += 1;
                }
            }
        }
        println!(
            "round {round} base {base} steps {:?}: steps > H padded with h_{last_req}{}",
            steps,
            if last_req == h { " (== h_H)" } else { " (!= h_H)" }
        );
    }
    // The ticket's observation: padding is not h_H in general.
    assert!(padded_differs_from_final > 0);
}

fn junk() -> String {
    "ab".repeat(20)
}

/// Enumerates, for every round whose segment straddles H, all prover hash vectors
/// built from {verifier's value, h_H, junk} per position and calls `f` with
/// (round, base, prover, mine (current padding), alt (padding with h_H)).
fn for_each_straddling_pattern(
    min_round: u8,
    mut f: impl FnMut(u8, u64, u64, &Vec<String>, &ExecutionHashes, &ExecutionHashes, &ExecutionHashes),
) -> u64 {
    let dir = tmp_dir("verifier");
    let def = ProgramDefinition::from_config(HELLO_YAML).unwrap();
    let nd = def.nary_def();
    let (h, last_hash, _chain) = full_hash_chain(&def, &dir);
    let mut cases = 0;
    for (round, base) in rounds_straddling_halt(&nd, h) {
        if round < min_round {
            continue;
        }
        let steps = nd.required_steps(round, base);
        // honest verifier: last_step = None
        let mine = def
            .get_round_hashes(&dir, &dir, input(), round, base, None, None)
            .unwrap();
        // alternative semantics proposed in the ticket: pad with h_H
        let alt: Vec<String> = steps
            .iter()
            .zip(mine.iter())
            .map(|(s, x)| if *s > h { last_hash.clone() } else { x.clone() })
            .collect();
        let m = ExecutionHashes::from_hexstr(&mine);
        let a = ExecutionHashes::from_hexstr(&alt);
        let n = steps.len();
        for c in 0..3u64.pow(n as u32) {
            let mut k = c;
            let prover: Vec<String> = (0..n)
                .map(|i| {
                    let choice = k % 3;
                    k /= 3;
                    match choice {
                        0 => mine[i].clone(),
                        1 => last_hash.clone(),
                        _ => junk(),
                    }
                })
                .collect();
            f(round, base, h, &prover, &ExecutionHashes::from_hexstr(&prover), &m, &a);
            cases += 1;
        }
    }
    cases
}

/// ConflictStep (1st n-ary search): the verifier's decision does not depend on
/// the padding value. PASSES.
#[test]
fn emu005_verifier_conflict_step_decision_independent_of_padding() {
    let nd = NArySearchDefinition::new(2000, 8);
    let mut checked = 0;
    let cases = for_each_straddling_pattern(1, |round, base, h, prover, p, m, a| {
        // verifier's selected step is always <= min(L_p, H) - 1 <= H - 1
        for sel in [base, h - 1] {
            let r1 = choose_segment(&nd, base, sel, round, p, m, NArySearchType::ConflictStep, None);
            let r2 = choose_segment(&nd, base, sel, round, p, a, NArySearchType::ConflictStep, None);
            assert_eq!(r1, r2, "ConflictStep round {round} base {base} sel {sel} prover {prover:?}");
            checked += 1;
        }
    });
    println!("ConflictStep: {cases} prover patterns, {checked} comparisons, all identical");
    assert!(checked > 0);
}

/// ReadValueChallenge (2nd n-ary search, rounds >= 2 since round 1 is reused):
/// hashes at steps > conflict step (in particular the padded ones, steps > H)
/// must not influence the verifier's decision. FAILS on current code because
/// `choose_segment` counts mismatches after the conflict step (see ticket,
/// "Related finding"); it passes with the proposed fix.
#[test]
#[ignore = "EMU-005: fails until fixed"]
fn emu005_verifier_read_value_decision_independent_of_padding() {
    let nd = NArySearchDefinition::new(2000, 8);
    let mut checked = 0;
    let mut differ = 0;
    let mut first: Option<String> = None;
    for_each_straddling_pattern(2, |round, base, h, prover, p, m, a| {
        for conflict in [base, h - 1] {
            for sel in [base, conflict] {
                let r1 = choose_segment(&nd, base, sel, round, p, m, NArySearchType::ReadValueChallenge, Some(conflict));
                let r2 = choose_segment(&nd, base, sel, round, p, a, NArySearchType::ReadValueChallenge, Some(conflict));
                checked += 1;
                if r1 != r2 {
                    differ += 1;
                    first.get_or_insert(format!(
                        "round {round} base {base} sel {sel} conflict {conflict}: current {r1:?} vs pad-with-h_H {r2:?}; prover {prover:?}"
                    ));
                }
            }
        }
    });
    println!("ReadValue: {checked} comparisons, {differ} differ");
    assert_eq!(differ, 0, "first difference: {}", first.unwrap_or_default());
}

#[test]
fn emu005_honest_prover_never_resigns_padded_hash() {
    let def = ProgramDefinition::from_config(HELLO_YAML).unwrap();
    let nd = def.nary_def();
    let (h, last_hash, chain) = full_hash_chain(&def, &tmp_dir("prover-chain"));
    let total = nd.total_rounds();

    let mut targets: Vec<u64> = (h.saturating_sub(6)..=h + 6).collect();
    targets.extend([h + 37, h + 300, nd.max_steps - 1]);
    targets.retain(|s| *s < nd.max_steps);

    for s in targets {
        let dir = tmp_dir(&format!("prover-s{s}"));
        let (res, ls, lh) = prover_execute(HELLO_YAML, input(), &dir, &dir, false, None, false).unwrap();
        assert_eq!((res, ls, lh.clone()), (ExecutionResult::Halt(0, h), h, last_hash.clone()));

        let mut decision = 0u32;
        let mut published_padding = false;
        let mut base = 0u64;
        for round in 1..=total {
            let hashes = prover_get_hashes_for_round(
                HELLO_YAML, &dir, &dir, round, decision, None, NArySearchType::ConflictStep,
            )
            .unwrap();
            if round > 1 {
                base = nd.step_from_base_and_bits(round - 1, base, decision);
            }
            let capped = base.min(h);
            for (i, st) in nd.required_steps(round, capped).iter().enumerate() {
                if *st <= h {
                    assert_eq!(hashes[i], chain[*st as usize]);
                } else {
                    published_padding = true;
                }
            }
            // verifier's (possibly dishonest) choice that leads to agreed step s
            decision = nd.step_bits_for_round(round, s);
        }
        let final_bits = decision + 1;
        let ft = prover_final_trace(HELLO_YAML, &dir, &dir, final_bits, None).unwrap();
        match ft {
            ProverFinalTraceType::ChallengeStep => {
                println!("s = {s:4}: ChallengeStep (published padding: {published_padding})");
                assert!(s >= h, "honest prover answered ChallengeStep for s = {s} < H = {h}");
            }
            ProverFinalTraceType::FinalTraceWithHashesAndStep { trace, step_hash, next_hash, step } => {
                println!("s = {s:4}: final trace step {} (published padding: {published_padding})", trace.step_number);
                assert!(s < h, "honest prover must not provide a trace for s = {s} >= H = {h}");
                assert_eq!(step, s);
                assert_eq!(trace.step_number, s + 1);
                assert_eq!(step_hash, chain[s as usize]);
                assert_eq!(next_hash, chain[s as usize + 1]);
                if s + 1 == h {
                    assert_eq!(next_hash, last_hash);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Related finding (see ticket): in the ReadValueChallenge search the verifier's
// `choose_segment` clamps any mismatch *after* the conflict step to the conflict
// step. A cheating prover whose chain diverges after the conflict step (i.e. a
// prover that keeps the same lie in both searches) therefore pulls the second
// search to the conflict step instead of the write step. The existing in-crate
// tests only pass because the prover publishes honest hashes in the second search
// (`fail_config_prover_read_challenge = None`).
// ---------------------------------------------------------------------------

use bitcoin_script_riscv::riscv::challenges::execute_challenge;
use bitvmx_cpu_definitions::challenge::ChallengeType;
use emulator::{
    decision::challenge::{
        prover_get_hashes_and_step, verifier_check_execution, verifier_choose_challenge,
        verifier_choose_challenge_for_read_challenge, verifier_choose_segment, ForceChallenge,
        ForceCondition,
    },
    executor::utils::{FailConfiguration, FailReads},
};

fn run_read_value_dispute(
    id: &str,
    prover_fail: Option<FailConfiguration>,
    prover_fail_read_challenge: Option<FailConfiguration>,
) -> (ChallengeType, bool) {
    let pdf = HELLO_YAML;
    let def = ProgramDefinition::from_config(pdf).unwrap();
    let nd = def.nary_def();
    let p = tmp_dir(&format!("{id}-prover"));
    let v = tmp_dir(&format!("{id}-verifier"));

    let (_r, ls, lh) = prover_execute(pdf, input(), &p, &p, true, prover_fail.clone(), false).unwrap();
    verifier_check_execution(
        pdf, input(), &v, &v, ls, &lh, ForceCondition::ValidInputWrongStepOrHash, None, false,
    )
    .unwrap()
    .expect("verifier must challenge");

    let mut d = 0;
    for round in 1..=nd.total_rounds() {
        let hashes = prover_get_hashes_for_round(
            pdf, &p, &p, round, d, prover_fail.clone(), NArySearchType::ConflictStep,
        )
        .unwrap();
        d = verifier_choose_segment(pdf, &v, &v, round, hashes, None, NArySearchType::ConflictStep)
            .unwrap();
    }
    let (trace, sh, nh, _) = prover_final_trace(pdf, &p, &p, d + 1, prover_fail)
        .unwrap()
        .as_final_trace_with_hashes_and_step()
        .unwrap();
    let challenge =
        verifier_choose_challenge(pdf, &v, &v, trace, &sh, &nh, ForceChallenge::No, None, true)
            .unwrap();
    let challenge = match challenge {
        ChallengeType::ReadValueNArySearch { bits } => {
            let mut d = bits;
            for round in 2..=nd.total_rounds() {
                let hashes = prover_get_hashes_for_round(
                    pdf, &p, &p, round, d, prover_fail_read_challenge.clone(),
                    NArySearchType::ReadValueChallenge,
                )
                .unwrap();
                d = verifier_choose_segment(
                    pdf, &v, &v, round, hashes, None, NArySearchType::ReadValueChallenge,
                )
                .unwrap();
                println!("[{id}] 2nd search round {round}: verifier bits {d}");
            }
            let (sh, nh, step) = prover_get_hashes_and_step(
                pdf, &p, NArySearchType::ReadValueChallenge, Some(d), prover_fail_read_challenge,
            )
            .unwrap()
            .as_hashes_with_step()
            .unwrap();
            println!("[{id}] 2nd search final step {step}");
            verifier_choose_challenge_for_read_challenge(
                pdf, &v, &v, &sh, &nh, None, ForceChallenge::No, true,
            )
            .unwrap()
        }
        c => c,
    };
    let ok = execute_challenge(&challenge);
    println!("[{id}] challenge: {challenge:?} script success: {ok}");
    (challenge, ok)
}

fn fail_read_1() -> Option<FailConfiguration> {
    // same lie as challenge.rs::test_challenge_read_different_value: at step 1106
    // read_1 (reg 0xf000003c) is reported/used with value 0xaa000004, last_step 1105
    let args: Vec<String> = ["1106", "0xf000003c", "0xaa000004", "0xf000003c", "1105"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    Some(FailConfiguration::new_fail_reads(FailReads::new(Some(&args), None)))
}

/// Baseline (same as the in-crate test): prover lies in the 1st search only and
/// publishes honest hashes in the 2nd search. Verifier wins with ReadValue.
#[test]
fn emu005_related_read_value_prover_honest_in_second_search() {
    let (c, ok) = run_read_value_dispute("rv-baseline", fail_read_1(), None);
    assert!(matches!(c, ChallengeType::ReadValue { .. }), "{c:?}");
    assert!(ok);
}

/// A consistent cheating prover (same lie in both searches) must still lose.
#[test]
#[ignore = "EMU-005: fails until fixed"]
fn emu005_related_read_value_consistent_cheating_prover_loses() {
    let (c, ok) = run_read_value_dispute("rv-consistent", fail_read_1(), fail_read_1());
    assert!(!matches!(c, ChallengeType::No), "verifier found no challenge: {c:?}");
    assert!(ok, "verifier challenge script fails: {c:?}");
}
