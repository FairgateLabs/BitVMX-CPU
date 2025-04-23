use std::collections::HashMap;

use serde::Serialize;
use tracing::{error, info};

#[derive(Debug, Clone, Serialize)]
pub struct NArySearchDefinition {
    pub max_steps: u64,
    pub nary: u8,
    pub full_rounds: u8,
    pub nary_last_round: u8,
}

impl NArySearchDefinition {
    pub fn new(aprox_max_steps: u64, nary: u8) -> NArySearchDefinition {
        assert!(nary > 1);
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

    pub fn step_mapping(&self, bits: &Vec<u32>) -> HashMap<u64, (u8, u8)> {
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

impl Into<ExecutionHashes> for Vec<Vec<u8>> {
    fn into(self) -> ExecutionHashes {
        ExecutionHashes::new(self)
    }
}

// we assume that the previous hash to the list provided is agreed by both parties
pub fn choose_segment(
    nary_defs: &NArySearchDefinition,
    base_step: u64,
    selected_step: u64,
    round: u8,
    prover_hashes: &ExecutionHashes,
    my_hashes: &ExecutionHashes,
) -> (u32, u64, u64) {
    if prover_hashes.hashes.len() != my_hashes.hashes.len() {
        error!("Prover and my hashes should have the same length");
    }

    // finds if there is any difference in the hashes
    let mut selection = prover_hashes.hashes.len() + 1;
    for i in 0..prover_hashes.hashes.len() {
        let prover_hash = &prover_hashes.hashes[i];
        let my_hash = &my_hashes.hashes[i];
        if prover_hash != my_hash {
            selection = i + 1;
            break;
        }
    }

    // first mismatch step
    //println!("Selection: {}", selection);
    let mismatch_step = nary_defs.step_from_base_and_bits(round, base_step, selection as u32) - 1;
    //println!("Mismatch step: {}", mismatch_step);
    let lower_limit_bits = if selected_step < mismatch_step {
        nary_defs.step_bits_for_round(round, selected_step)
    } else {
        selection as u32 - 1
    };
    let choice = mismatch_step.min(selected_step);

    //println!("Lower limit bits: {}", lower_limit_bits);
    let base_step = nary_defs.step_from_base_and_bits(round, base_step, lower_limit_bits);

    (lower_limit_bits, base_step, choice)
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
}
