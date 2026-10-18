use std::{collections::HashMap, str::FromStr};

use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::cmp::{max, min};
use tracing::{error, info};

#[derive(Clone, Copy, PartialEq, ValueEnum, Serialize, Deserialize, Debug)]
pub enum NArySearchType {
    ConflictStep,
    ReadValueChallenge,
}
impl std::fmt::Display for NArySearchType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NArySearchType::ConflictStep => write!(f, "conflict-step"),
            NArySearchType::ReadValueChallenge => write!(f, "read-value-challenge"),
        }
    }
}

impl FromStr for NArySearchType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "conflict-step" => Ok(NArySearchType::ConflictStep),
            "read-value-challenge" => Ok(NArySearchType::ReadValueChallenge),
            _ => Err(format!("'{}' is not a valid NArySearchType", s)),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct NArySearchDefinition {
    pub max_steps: u64,
    pub nary: u8,
    pub full_rounds: u8,
    pub nary_last_round: u8,
}

impl NArySearchDefinition {
    pub fn new(aprox_max_steps: u64, nary: u8) -> NArySearchDefinition {
        assert!(nary > 1 && nary.count_ones() == 1);
        let max_bits = f64::ceil(f64::log2(aprox_max_steps as f64));
        let max_steps = 2f64.powi(max_bits as i32) as u64;
        let nary_bits = f64::log2(nary as f64);
        let full_rounds = f64::floor(max_bits / nary_bits);
        let bits_left = max_bits - full_rounds * nary_bits;
        let nary_last_round = if bits_left as u8 == 0 {
            0
        } else {
            f64::powf(2.0, bits_left) as u8
        };

        NArySearchDefinition {
            max_steps,
            nary,
            full_rounds: full_rounds as u8,
            nary_last_round,
        }
    }

    pub fn bits_nary(&self) -> u8 {
        f64::log2(self.nary as f64) as u8
    }

    pub fn bits_last_round(&self) -> u8 {
        f64::log2(self.nary_last_round as f64) as u8
    }

    pub fn total_rounds(&self) -> u8 {
        self.full_rounds + if self.nary_last_round > 0 { 1 } else { 0 }
    }

    pub fn bits_for_round(&self, round: u8) -> u8 {
        if round <= self.full_rounds {
            self.bits_nary()
        } else {
            self.bits_last_round()
        }
    }

    pub fn hashes_for_round(&self, round: u8) -> u8 {
        if round <= self.full_rounds {
            self.nary - 1
        } else {
            self.nary_last_round - 1
        }
    }

    pub fn required_steps(&self, round: u8, start: u64) -> Vec<u64> {
        let mut steps = Vec::new();

        if round <= self.full_rounds {
            for i in 1..self.nary {
                let interval = self.max_steps / (self.nary as u64).pow(round as u32);
                steps.push(start + i as u64 * interval);
            }
        } else {
            for i in 1..self.nary_last_round {
                steps.push(start + i as u64);
            }
        }
        steps
    }

    // on each round we need to be able to send the specific bits of the number
    // if we are on the full rounds, the number of bits required is the bits_nary()
    // if we are on the last round, the number of bits required is the bits_last_round()
    // the step number should be masked and shifted apropiately
    pub fn step_bits_for_round(&self, round: u8, step: u64) -> u32 {
        if round <= self.full_rounds {
            let shift = (self.full_rounds - round) * self.bits_nary() + self.bits_last_round();
            let mask = ((self.nary - 1) as u64) << shift;
            ((step & mask) >> shift) as u32
        } else {
            let mask = (self.nary_last_round - 1) as u64;
            (step & mask) as u32
        }
    }

    pub fn step_from_base_and_bits(&self, round: u8, base: u64, bits: u32) -> u64 {
        if round <= self.full_rounds {
            let shift = (self.full_rounds - round) * self.bits_nary() + self.bits_last_round();
            base + ((bits as u64) << shift)
        } else {
            base + (bits as u64)
        }
    }

    pub fn step_mapping(&self, bits: &[u32]) -> HashMap<u64, (u8, u8)> {
        assert_eq!(bits.len(), self.total_rounds() as usize);
        let mut base = 0;
        let mut mapping: HashMap<u64, (u8, u8)> = HashMap::new();

        for round in 1..self.total_rounds() + 1 {
            let required_steps = self.required_steps(round, base);
            for (n, step) in required_steps.iter().enumerate() {
                mapping.insert(*step, (round, n as u8));
            }

            base = self.step_from_base_and_bits(round, base, bits[round as usize - 1]);
        }

        info!("Mapping: {:?}", mapping);
        mapping
    }

    pub fn step_from_decision_bits(&self, decision_bits: &[u32]) -> u64 {
        decision_bits
            .iter()
            .enumerate()
            .fold(0, |res, (round, bits)| {
                (res << self.bits_for_round(round as u8 + 1)) + *bits as u64
            })
    }
}

#[derive(Debug, Clone)]
pub struct ExecutionHashes {
    pub hashes: Vec<Vec<u8>>,
}

impl ExecutionHashes {
    pub fn new(hashes: Vec<Vec<u8>>) -> ExecutionHashes {
        ExecutionHashes { hashes }
    }
    pub fn from_hexstr(hashes: &Vec<String>) -> ExecutionHashes {
        let mut v = Vec::new();
        for hash in hashes {
            let mut h = Vec::new();
            for i in 0..hash.len() / 2 {
                let byte = u8::from_str_radix(&hash[i * 2..i * 2 + 2], 16).unwrap();
                h.push(byte);
            }
            v.push(h);
        }
        ExecutionHashes::new(v)
    }
}

impl From<Vec<Vec<u8>>> for ExecutionHashes {
    fn from(hashes: Vec<Vec<u8>>) -> Self {
        ExecutionHashes::new(hashes)
    }
}

/// Selects the subinterval of a dissection in which the two views diverge.
///
/// We assume that the hash preceding the provided list is agreed by both
/// parties.
///
/// This decision is *symmetric*: it depends only on the positionwise comparison
/// of the two hash vectors, never on which party published which. Agreement at
/// a position is a symmetric relation, so either party may run this routine on
/// the other's dissection and both obtain the same answer. That is what allows
/// the full-duplex search (see [`full_duplex_stage`]) to let each message both
/// select and dissect, rather than spending one message on each.
///
/// `published_hashes` are the counterparty's committed values for this round's
/// positions, and `local_hashes` are our own values at the same positions.
#[allow(clippy::too_many_arguments)]
pub fn choose_segment(
    nary_defs: &NArySearchDefinition,
    base_step: u64,
    selected_step: u64,
    round: u8,
    published_hashes: &ExecutionHashes,
    local_hashes: &ExecutionHashes,
    nary_type: NArySearchType,
    conflict_step: Option<u64>,
) -> (u32, u64, u64) {
    if published_hashes.hashes.len() != local_hashes.hashes.len() {
        error!("Published and local hashes should have the same length");
    }

    // finds if there is any difference in the hashes
    // When every published interior hash matches ours, the divergence is the
    // one already recorded at the upper boundary of the interval, so we select
    // the topmost subinterval. This is the case where a party can select
    // without ever having seen the counterparty's value at that boundary.
    let mut selection = if nary_type == NArySearchType::ConflictStep {
        published_hashes.hashes.len() + 1
    } else {
        0
    };
    for i in 0..published_hashes.hashes.len() {
        let published_hash = &published_hashes.hashes[i];
        let my_hash = &local_hashes.hashes[i];
        if published_hash != my_hash {
            selection = i + 1;
            if nary_type == NArySearchType::ConflictStep {
                break;
            };
        }
    }

    // first mismatch step
    //println!("Selection: {}", selection);
    let mismatch_step = nary_defs.step_from_base_and_bits(round, base_step, selection as u32);
    //println!("Mismatch step: {}", mismatch_step);
    let (lower_limit_bits, choice) = match nary_type {
        NArySearchType::ConflictStep => {
            let choice = min(selected_step, mismatch_step - 1);
            (nary_defs.step_bits_for_round(round, choice), choice)
        }
        _ => {
            let conflict = conflict_step.unwrap();
            let base = max(selected_step, mismatch_step);
            let choice = min(base, conflict);
            (nary_defs.step_bits_for_round(round, choice), choice)
        }
    };

    //println!("Lower limit bits: {}", lower_limit_bits);
    let base_step = nary_defs.step_from_base_and_bits(round, base_step, lower_limit_bits);

    (lower_limit_bits, base_step, choice)
}

/// Which party dissects at a given stage of a full-duplex search.
///
/// In the asymmetric search one party always dissects and the other always
/// selects. In the full-duplex search the two alternate, and every message
/// carries both a selection and a dissection.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Party {
    Prover,
    Verifier,
}

impl Party {
    pub fn other(&self) -> Party {
        match self {
            Party::Prover => Party::Verifier,
            Party::Verifier => Party::Prover,
        }
    }

    /// Prefix used for this party's protocol variable names.
    pub fn prefix(&self) -> &'static str {
        match self {
            Party::Prover => "prover",
            Party::Verifier => "verifier",
        }
    }

    /// The party that dissects at `stage`, counting stages from 1, when `first`
    /// dissects at stage 1. Ownership of a stage is fixed by parity, and so is
    /// known at setup time when the one-time keys are generated.
    pub fn at_stage(first: Party, stage: u8) -> Party {
        if stage % 2 == 1 {
            first
        } else {
            first.other()
        }
    }
}

/// How the dissection search allocates work to the two parties.
///
/// This is a setup-time property, not a runtime one: it decides which party
/// owns which one-time keys, and the dispute transaction graph is built and
/// pre-signed before any dispute exists.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SearchMode {
    /// One party dissects and the other selects: two messages per narrowing
    /// level.
    #[default]
    Asymmetric,
    /// The parties alternate, and every message both selects over the
    /// counterparty's previous dissection and dissects the subinterval it just
    /// selected: one message per narrowing level.
    FullDuplex,
}

impl SearchMode {
    /// The party that dissects at `stage`, counting stages from 1.
    pub fn dissector(&self, total_rounds: u8, stage: u8) -> Party {
        match self {
            SearchMode::Asymmetric => Party::Prover,
            SearchMode::FullDuplex => Party::at_stage(self.first_dissector(total_rounds), stage),
        }
    }

    /// The party that commits the digit selecting over the dissection published
    /// at `round`.
    pub fn selector(&self, total_rounds: u8, round: u8) -> Party {
        match self {
            SearchMode::Asymmetric => Party::Verifier,
            SearchMode::FullDuplex => self.dissector(total_rounds, round).other(),
        }
    }

    /// Who dissects at stage 1.
    ///
    /// For the full-duplex search this is chosen from the parity of the round
    /// count so that the trailing selection -- the digit over the final
    /// dissection, which has no stage of its own to ride on -- always falls to
    /// the prover. It can then be carried by the prover's adjudication
    /// transaction rather than costing a further message.
    pub fn first_dissector(&self, total_rounds: u8) -> Party {
        match self {
            SearchMode::Asymmetric => Party::Prover,
            SearchMode::FullDuplex => {
                if total_rounds % 2 == 0 {
                    Party::Prover
                } else {
                    Party::Verifier
                }
            }
        }
    }

    /// On-chain messages the search consumes, including the adjudication
    /// message that carries the trailing selection.
    pub fn messages(&self, total_rounds: u8) -> u32 {
        let rounds = total_rounds as u32;
        match self {
            SearchMode::Asymmetric => 2 * rounds + 1,
            SearchMode::FullDuplex => rounds + 1,
        }
    }
}

/// The contents of one full-duplex stage message.
#[derive(Clone, Debug)]
pub struct StageMessage {
    pub stage: u8,
    pub sender: Party,
    /// Digit selecting a subinterval of the dissection published at the
    /// previous stage. `None` only at stage 1, which has no predecessor.
    pub selection: Option<u32>,
    /// The sender's dissection of the selected subinterval.
    pub hashes: ExecutionHashes,
}

/// The portion of a full-duplex search that both parties track identically.
///
/// Both parties derive the same state from the same transcript, so this is not
/// a per-role structure.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SearchState {
    /// Base of the currently active interval.
    pub base_step: u64,
    /// Running upper bound on the disputed step: the last step agreed so far.
    pub selected_step: u64,
    /// Selection digits committed so far, most significant first.
    pub digits: Vec<u32>,
}

impl SearchState {
    pub fn new(max_selectable_step: u64) -> Self {
        Self {
            base_step: 0,
            selected_step: max_selectable_step,
            digits: Vec::new(),
        }
    }
}

/// Computes our own dissection of the interval based at `base_step` for `round`.
pub fn dissect<F>(
    nary_defs: &NArySearchDefinition,
    round: u8,
    base_step: u64,
    hash_at: &F,
) -> ExecutionHashes
where
    F: Fn(u64) -> Vec<u8>,
{
    ExecutionHashes::new(
        nary_defs
            .required_steps(round, base_step)
            .into_iter()
            .map(hash_at)
            .collect(),
    )
}

/// Records a selection over the dissection published at `round`, advancing the
/// active interval. This is the half of a stage that resolves the previous one.
pub fn select_over<F>(
    nary_defs: &NArySearchDefinition,
    state: &mut SearchState,
    round: u8,
    published: &ExecutionHashes,
    hash_at: &F,
) -> u32
where
    F: Fn(u64) -> Vec<u8>,
{
    let local = dissect(nary_defs, round, state.base_step, hash_at);
    let (bits, base, selected) = choose_segment(
        nary_defs,
        state.base_step,
        state.selected_step,
        round,
        published,
        &local,
        NArySearchType::ConflictStep,
        None,
    );
    state.base_step = base;
    state.selected_step = selected;
    state.digits.push(bits);
    bits
}

/// Performs one full-duplex stage: select over the counterparty's previous
/// dissection, then dissect the subinterval just selected.
///
/// `incoming` is the dissection published at stage `stage - 1`, and is `None`
/// exactly at stage 1.
pub fn full_duplex_stage<F>(
    nary_defs: &NArySearchDefinition,
    state: &mut SearchState,
    stage: u8,
    sender: Party,
    incoming: Option<&ExecutionHashes>,
    hash_at: &F,
) -> StageMessage
where
    F: Fn(u64) -> Vec<u8>,
{
    let selection = incoming.map(|published| {
        debug_assert!(stage > 1, "stage 1 has no dissection to select over");
        select_over(nary_defs, state, stage - 1, published, hash_at)
    });

    let hashes = dissect(nary_defs, stage, state.base_step, hash_at);

    StageMessage {
        stage,
        sender,
        selection,
        hashes,
    }
}

/// The outcome of running a search to completion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchOutcome {
    /// The last step both parties agree on. The disputed step is this plus one.
    pub agreed_step: u64,
    /// The selection digits, most significant first. Their concatenation is the
    /// base-n representation of `agreed_step`.
    pub digits: Vec<u32>,
    /// On-chain messages consumed, including the final adjudication message
    /// that carries the trailing selection.
    pub messages: u32,
}

/// Runs a full-duplex search to completion over two views of a trace.
///
/// Stages alternate between the parties. Stage 1 carries a dissection only;
/// every later stage carries a selection over the previous dissection together
/// with a dissection of its own. The trailing selection has no dissection to
/// accompany it and rides on the final adjudication message.
pub fn run_full_duplex_search<FA, FB>(
    nary_defs: &NArySearchDefinition,
    max_selectable_step: u64,
    first: Party,
    prover_hash_at: &FA,
    verifier_hash_at: &FB,
) -> SearchOutcome
where
    FA: Fn(u64) -> Vec<u8>,
    FB: Fn(u64) -> Vec<u8>,
{
    let rounds = nary_defs.total_rounds();
    let mut state = SearchState::new(max_selectable_step);
    let mut incoming: Option<ExecutionHashes> = None;
    let mut messages = 0;

    for stage in 1..rounds + 1 {
        let sender = Party::at_stage(first, stage);
        let msg = match sender {
            Party::Prover => full_duplex_stage(
                nary_defs,
                &mut state,
                stage,
                sender,
                incoming.as_ref(),
                prover_hash_at,
            ),
            Party::Verifier => full_duplex_stage(
                nary_defs,
                &mut state,
                stage,
                sender,
                incoming.as_ref(),
                verifier_hash_at,
            ),
        };
        messages += 1;
        incoming = Some(msg.hashes);
    }

    // The trailing selection over the final dissection, carried by the
    // adjudication message.
    let closer = Party::at_stage(first, rounds).other();
    let published = incoming.expect("at least one stage");
    match closer {
        Party::Prover => select_over(nary_defs, &mut state, rounds, &published, prover_hash_at),
        Party::Verifier => select_over(nary_defs, &mut state, rounds, &published, verifier_hash_at),
    };
    messages += 1;

    SearchOutcome {
        agreed_step: state.selected_step,
        digits: state.digits,
        messages,
    }
}

/// Runs the classical asymmetric search to completion, as a reference for
/// comparison: the prover dissects and the verifier selects, two messages per
/// level.
pub fn run_asymmetric_search<FA, FB>(
    nary_defs: &NArySearchDefinition,
    max_selectable_step: u64,
    prover_hash_at: &FA,
    verifier_hash_at: &FB,
) -> SearchOutcome
where
    FA: Fn(u64) -> Vec<u8>,
    FB: Fn(u64) -> Vec<u8>,
{
    let rounds = nary_defs.total_rounds();
    let mut state = SearchState::new(max_selectable_step);
    let mut messages = 0;

    for round in 1..rounds + 1 {
        let published = dissect(nary_defs, round, state.base_step, prover_hash_at);
        messages += 1; // the prover's dissection
        select_over(nary_defs, &mut state, round, &published, verifier_hash_at);
        messages += 1; // the verifier's selection
    }

    SearchOutcome {
        agreed_step: state.selected_step,
        digits: state.digits,
        messages: messages + 1, // the adjudication message
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nary_search_definitions() {
        let max_steps_aprox = 500_000_000;
        let nary_search = NArySearchDefinition::new(max_steps_aprox, 8);
        assert_eq!(nary_search.full_rounds, 9);
        assert_eq!(nary_search.nary_last_round, 4);
        assert_eq!(nary_search.bits_nary(), 3);
        assert_eq!(nary_search.bits_last_round(), 2);

        let nary_search = NArySearchDefinition::new(64, 8);
        assert_eq!(nary_search.full_rounds, 2);
        assert_eq!(nary_search.nary_last_round, 0);
        assert_eq!(nary_search.bits_nary(), 3);
        assert_eq!(nary_search.bits_last_round(), 0);

        let nary_search = NArySearchDefinition::new(128, 8);
        assert_eq!(nary_search.full_rounds, 2);
        assert_eq!(nary_search.nary_last_round, 2);
        assert_eq!(nary_search.bits_nary(), 3);
        assert_eq!(nary_search.bits_last_round(), 1);

        let nary_search = NArySearchDefinition::new(256, 8);
        assert_eq!(nary_search.full_rounds, 2);
        assert_eq!(nary_search.nary_last_round, 4);
    }

    #[test]
    fn test_required_steps() {
        let nary_search = NArySearchDefinition::new(64, 8);
        let steps = nary_search.required_steps(1, 0);
        assert_eq!(steps, vec![8, 16, 24, 32, 40, 48, 56]);

        let steps = nary_search.required_steps(2, 0);
        assert_eq!(steps, vec![1, 2, 3, 4, 5, 6, 7]);

        let steps = nary_search.required_steps(2, 56);
        assert_eq!(steps, vec![57, 58, 59, 60, 61, 62, 63]);

        let nary_search = NArySearchDefinition::new(128, 8);
        let steps = nary_search.required_steps(1, 0);
        assert_eq!(steps, vec![16, 32, 48, 64, 80, 96, 112]);

        let steps = nary_search.required_steps(2, 112);
        assert_eq!(steps, vec![114, 116, 118, 120, 122, 124, 126]);

        let steps = nary_search.required_steps(3, 124);
        assert_eq!(steps, vec![125]);

        let nary_search = NArySearchDefinition::new(200, 8);
        let steps = nary_search.required_steps(1, 0);
        assert_eq!(steps, vec![32, 64, 96, 128, 160, 192, 224]);

        let steps = nary_search.required_steps(2, 32);
        assert_eq!(steps, vec![36, 40, 44, 48, 52, 56, 60]);

        let steps = nary_search.required_steps(3, 40);
        assert_eq!(steps, vec![41, 42, 43]);
    }

    #[test]
    fn test_bits_for_round() {
        let nary_search = NArySearchDefinition::new(64, 8);
        assert_eq!(nary_search.step_bits_for_round(1, 0), 0);
        assert_eq!(nary_search.step_bits_for_round(1, 8), 1);
        assert_eq!(nary_search.step_bits_for_round(1, 9), 1);
        assert_eq!(nary_search.step_bits_for_round(1, 58), 7);

        assert_eq!(nary_search.step_bits_for_round(2, 0), 0);
        assert_eq!(nary_search.step_bits_for_round(2, 8), 0);
        assert_eq!(nary_search.step_bits_for_round(2, 9), 1);
        assert_eq!(nary_search.step_bits_for_round(2, 58), 2);

        let nary_search = NArySearchDefinition::new(128, 8);
        assert_eq!(nary_search.step_bits_for_round(1, 75), 4);
        assert_eq!(nary_search.step_bits_for_round(2, 75), 5);
        assert_eq!(nary_search.step_bits_for_round(3, 75), 1);
    }
    #[test]
    fn test_step_from_bits() {
        let nary_search = NArySearchDefinition::new(64, 8);
        assert_eq!(nary_search.step_from_base_and_bits(1, 0, 7), 56);
        assert_eq!(nary_search.step_from_base_and_bits(1, 0, 0), 0);

        assert_eq!(nary_search.step_from_base_and_bits(2, 0, 0), 0);
        assert_eq!(nary_search.step_from_base_and_bits(2, 1, 56), 57);

        let nary_search = NArySearchDefinition::new(128, 8);
        assert_eq!(nary_search.step_from_base_and_bits(1, 0, 5), 80);
        assert_eq!(nary_search.step_from_base_and_bits(2, 80, 5), 90);
        assert_eq!(nary_search.step_from_base_and_bits(3, 90, 0), 90);
        assert_eq!(nary_search.step_from_base_and_bits(3, 90, 1), 91);
    }

    // ---------------------------------------------------------------
    // Full-duplex search
    // ---------------------------------------------------------------

    /// A trace whose state hashes are distinct per step.
    fn trace_hash(step: u64) -> Vec<u8> {
        let mut h = vec![0u8; 20];
        h[..8].copy_from_slice(&step.to_le_bytes());
        h
    }

    /// A trace that matches `trace_hash` below `divergence` and differs from it
    /// at and above `divergence`.
    fn diverging_trace(divergence: u64) -> impl Fn(u64) -> Vec<u8> {
        move |step: u64| {
            let mut h = trace_hash(step);
            if step >= divergence {
                h[19] = 0xff;
            }
            h
        }
    }

    fn search_cases() -> Vec<(u64, u8)> {
        vec![
            (64, 2),
            (64, 8),
            (128, 8),
            (256, 4),
            (2000, 8),
            (500_000, 8),
        ]
    }

    #[test]
    fn full_duplex_locates_the_first_divergence() {
        for (max_steps, nary) in search_cases() {
            let defs = NArySearchDefinition::new(max_steps, nary);
            let top = defs.max_steps - 1;
            for divergence in [1, 2, 7, 13, 64, top - 1, top] {
                if divergence > top {
                    continue;
                }
                let prover = diverging_trace(divergence);
                let outcome =
                    run_full_duplex_search(&defs, top, Party::Prover, &prover, &trace_hash);
                assert_eq!(
                    outcome.agreed_step,
                    divergence - 1,
                    "max_steps {} nary {} divergence {}",
                    max_steps,
                    nary,
                    divergence
                );
            }
        }
    }

    /// The two searches descend through the same intervals, because agreement
    /// at a position is a symmetric relation and so does not depend on which
    /// party evaluates it.
    #[test]
    fn full_duplex_agrees_with_asymmetric_search() {
        for (max_steps, nary) in search_cases() {
            let defs = NArySearchDefinition::new(max_steps, nary);
            let top = defs.max_steps - 1;
            for divergence in [1, 3, 9, 50, 129, top] {
                if divergence > top {
                    continue;
                }
                let prover = diverging_trace(divergence);
                let full = run_full_duplex_search(&defs, top, Party::Prover, &prover, &trace_hash);
                let asym = run_asymmetric_search(&defs, top, &prover, &trace_hash);

                assert_eq!(full.agreed_step, asym.agreed_step);
                assert_eq!(full.digits, asym.digits);
            }
        }
    }

    /// One on-chain message per narrowing level instead of one per round trip.
    #[test]
    fn full_duplex_halves_the_message_count() {
        for (max_steps, nary) in search_cases() {
            let defs = NArySearchDefinition::new(max_steps, nary);
            let rounds = defs.total_rounds() as u32;
            let top = defs.max_steps - 1;
            let prover = diverging_trace(7);

            let full = run_full_duplex_search(&defs, top, Party::Prover, &prover, &trace_hash);
            let asym = run_asymmetric_search(&defs, top, &prover, &trace_hash);

            assert_eq!(full.messages, rounds + 1);
            assert_eq!(asym.messages, 2 * rounds + 1);
        }
    }

    /// Ownership independence: the located step and the committed digits do not
    /// depend on which party dissects first, and therefore not on which party
    /// owns which stage.
    #[test]
    fn full_duplex_outcome_is_independent_of_who_starts() {
        for (max_steps, nary) in search_cases() {
            let defs = NArySearchDefinition::new(max_steps, nary);
            let top = defs.max_steps - 1;
            for divergence in [1, 11, 97, top] {
                if divergence > top {
                    continue;
                }
                let prover = diverging_trace(divergence);
                let prover_first =
                    run_full_duplex_search(&defs, top, Party::Prover, &prover, &trace_hash);
                let verifier_first =
                    run_full_duplex_search(&defs, top, Party::Verifier, &prover, &trace_hash);
                assert_eq!(prover_first, verifier_first);
            }
        }
    }

    /// The concatenated selection digits are the base-n representation of the
    /// agreed step, which is what lets the final script recover the step number
    /// without carrying an interval forward between transactions.
    #[test]
    fn full_duplex_digits_reconstruct_the_agreed_step() {
        for (max_steps, nary) in search_cases() {
            let defs = NArySearchDefinition::new(max_steps, nary);
            let top = defs.max_steps - 1;
            for divergence in [1, 5, 33, 200, top] {
                if divergence > top {
                    continue;
                }
                let prover = diverging_trace(divergence);
                let outcome =
                    run_full_duplex_search(&defs, top, Party::Prover, &prover, &trace_hash);
                assert_eq!(
                    defs.step_from_decision_bits(&outcome.digits),
                    outcome.agreed_step
                );
            }
        }
    }

    /// When a party agrees with every published interior hash, the divergence
    /// is the one already recorded at the upper boundary, and it selects the
    /// topmost subinterval without ever seeing the counterparty's value there.
    ///
    /// This is the case where the two traces agree everywhere the search can
    /// look, and the dispute rests solely on the state following the last
    /// inspected step.
    #[test]
    fn full_duplex_inherits_disagreement_at_the_upper_boundary() {
        let defs = NArySearchDefinition::new(64, 8);
        let top = defs.max_steps - 1;

        // Diverging only beyond the last selectable step means every interior
        // hash of every dissection matches, so every selection takes the top
        // branch and the search converges on the upper boundary itself.
        let prover = diverging_trace(defs.max_steps);
        let outcome = run_full_duplex_search(&defs, top, Party::Prover, &prover, &trace_hash);

        assert_eq!(outcome.agreed_step, top);
        for (round, digit) in outcome.digits.iter().enumerate() {
            let max_digit = (1u32 << defs.bits_for_round(round as u8 + 1)) - 1;
            assert_eq!(*digit, max_digit, "round {}", round + 1);
        }

        // Diverging at the last selectable step instead: the first dissection
        // still sees no divergence and inherits the boundary, but the final
        // dissection does reach the diverging step and selects it directly.
        let prover = diverging_trace(top);
        let outcome = run_full_duplex_search(&defs, top, Party::Prover, &prover, &trace_hash);

        assert_eq!(outcome.agreed_step, top - 1);
        assert_eq!(
            outcome.digits,
            vec![(defs.nary - 1) as u32, (defs.nary - 2) as u32]
        );
    }

    /// The trailing selection must always fall to the prover, so that it can
    /// ride on the adjudication transaction instead of costing a message.
    #[test]
    fn full_duplex_trailing_selection_belongs_to_the_prover() {
        for rounds in 1..12u8 {
            assert_eq!(
                SearchMode::FullDuplex.selector(rounds, rounds),
                Party::Prover,
                "rounds {}",
                rounds
            );
        }
    }

    #[test]
    fn search_modes_allocate_stages_consistently() {
        for rounds in 1..12u8 {
            for stage in 1..rounds + 1 {
                // The asymmetric search never alternates.
                assert_eq!(
                    SearchMode::Asymmetric.dissector(rounds, stage),
                    Party::Prover
                );
                assert_eq!(
                    SearchMode::Asymmetric.selector(rounds, stage),
                    Party::Verifier
                );
                // The full-duplex search alternates, and the party selecting
                // over a dissection is never the one that published it.
                let d = SearchMode::FullDuplex.dissector(rounds, stage);
                assert_eq!(SearchMode::FullDuplex.selector(rounds, stage), d.other());
            }
            assert_eq!(
                SearchMode::Asymmetric.messages(rounds),
                2 * rounds as u32 + 1
            );
            assert_eq!(SearchMode::FullDuplex.messages(rounds), rounds as u32 + 1);
        }
    }

    #[test]
    fn search_mode_defaults_to_asymmetric() {
        assert_eq!(SearchMode::default(), SearchMode::Asymmetric);
    }

    #[test]
    fn stage_ownership_alternates_by_parity() {
        assert_eq!(Party::at_stage(Party::Prover, 1), Party::Prover);
        assert_eq!(Party::at_stage(Party::Prover, 2), Party::Verifier);
        assert_eq!(Party::at_stage(Party::Prover, 3), Party::Prover);
        assert_eq!(Party::at_stage(Party::Verifier, 1), Party::Verifier);
        assert_eq!(Party::at_stage(Party::Verifier, 2), Party::Prover);
    }

    fn test_vector(size: usize, diff_index: Option<usize>) -> Vec<Vec<u8>> {
        let mut v = Vec::new();
        for i in 0..size {
            let mut hash = Vec::new();
            match diff_index {
                Some(index) => {
                    if index == i {
                        hash.push((i + 1) as u8);
                    } else {
                        hash.push(i as u8);
                    }
                }
                None => hash.push(i as u8),
            }
            v.push(hash);
        }
        v
    }

    fn test_selection_aux(
        nary: u8,
        max: u64,
        base_step: u64,
        selected_step: u64,
        round: u8,
        diff_index: Option<usize>,
        exp_bits: u32,
        exp_step: u64,
        exp_choice: u64,
    ) {
        println!("Test: nary: {}, max: {}, base_step: {}, selected_step: {}, round: {}, diff_index: {:?}, exp_bits: {}, exp_step: {}", nary, max, base_step, selected_step, round, diff_index, exp_bits, exp_step);
        let nary_search = NArySearchDefinition::new(max, nary);
        let hashes = nary_search.hashes_for_round(round);
        let prover_hashes = test_vector(hashes as usize, None);
        let my_hashes = test_vector(hashes as usize, diff_index);
        println!("Prover hashes: {:?}", prover_hashes);
        println!("My hashes: {:?}", my_hashes);
        let (bits, base, selected) = choose_segment(
            &nary_search,
            base_step,
            selected_step,
            round,
            &prover_hashes.into(),
            &my_hashes.into(),
            NArySearchType::ConflictStep,
            None,
        );
        assert_eq!(bits, exp_bits);
        assert_eq!(base, exp_step);
        assert_eq!(selected, exp_choice);
    }

    #[test]
    fn test_selection() {
        // when there is no inferior limit selected and all the hashes matches it should selected the max-1|max transition
        test_selection_aux(8, 64, 0, 63, 1, None, 7, 56, 63);
        test_selection_aux(8, 64, 56, 63, 2, None, 7, 63, 63);

        test_selection_aux(8, 128, 0, 127, 1, None, 7, 112, 127);
        test_selection_aux(8, 128, 112, 127, 2, None, 7, 126, 127);
        test_selection_aux(8, 128, 126, 127, 3, None, 1, 127, 127);

        // when the diference is in the first step should choose 0
        test_selection_aux(8, 64, 0, 63, 1, Some(0), 0, 0, 7);
        test_selection_aux(8, 64, 0, 7, 2, Some(0), 0, 0, 0);

        // chose something in the middle
        test_selection_aux(8, 64, 0, 63, 1, Some(1), 1, 8, 15);
        test_selection_aux(8, 64, 8, 15, 2, Some(2), 2, 10, 10);

        // test limiting selected_step
        test_selection_aux(8, 128, 0, 10, 1, None, 0, 0, 10);
        test_selection_aux(8, 128, 0, 10, 2, None, 5, 10, 10);
        test_selection_aux(8, 128, 10, 10, 3, None, 0, 10, 10);
        test_selection_aux(8, 128, 10, 10, 3, Some(1), 0, 10, 10);

        // test limiting selected_step
        test_selection_aux(8, 128, 0, 9, 1, None, 0, 0, 9);
        test_selection_aux(8, 128, 0, 9, 2, None, 4, 8, 9);
        test_selection_aux(8, 128, 8, 9, 3, None, 1, 9, 9);
        // selected_step is in action until one hash is different before
        test_selection_aux(8, 128, 8, 9, 3, Some(0), 0, 8, 8);
        // selected_step is in action and finds the same mismatch hash
        test_selection_aux(8, 128, 8, 9, 3, Some(1), 1, 9, 9);

        test_selection_aux(8, 128, 0, 9, 1, Some(0), 0, 0, 9);
        test_selection_aux(8, 128, 0, 9, 2, Some(1), 1, 2, 3);
        test_selection_aux(8, 128, 2, 3, 3, Some(0), 0, 2, 2);
    }

    fn test_step_from_all_bits_aux(max_steps: u64, nary: u8, bits: &Vec<u32>, expected_step: u64) {
        let nary_search = NArySearchDefinition::new(max_steps, nary);
        assert_eq!(bits.len(), nary_search.total_rounds() as usize);
        assert_eq!(nary_search.step_from_decision_bits(bits), expected_step);
    }

    #[test]
    fn test_step_from_all_bits() {
        test_step_from_all_bits_aux(128, 8, &vec![0, 0, 0], 0);
        test_step_from_all_bits_aux(128, 8, &vec![0, 0, 1], 1);
        test_step_from_all_bits_aux(2000, 8, &vec![4, 2, 4, 0], 1104);
        test_step_from_all_bits_aux(2000, 8, &vec![4, 2, 4, 1], 1105);
        test_step_from_all_bits_aux(2000, 8, &vec![4, 2, 4, 2], 1106);
        test_step_from_all_bits_aux(2000, 8, &vec![4, 2, 4, 3], 1107);
    }
}
