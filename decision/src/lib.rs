pub const MAX_STEPS: u64 = 2u64.pow(29); //500M steps

#[derive(Debug, Clone)]
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
}

#[derive(Debug, Clone)]
pub struct ProgramResult {
    pub end_success: bool,
    pub steps: u64,
}

impl ProgramResult {
    pub fn new(end_success: bool, steps: u64) -> ProgramResult {
        ProgramResult { end_success, steps }
    }
}

pub fn need_to_challenge(prover_claim: &ProgramResult, my_result: &ProgramResult) -> Option<u64> {
    if my_result.end_success {
        return None;
    }
    Some(prover_claim.steps.min(my_result.steps))
}

#[derive(Debug, Clone)]
pub struct ExecutionHashes {
    pub hashes: Vec<Vec<u8>>,
    pub steps: Vec<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_need_to_challenge() {
        // if my result is success does not matter the steps it took
        let prover_claim = ProgramResult::new(true, 100);
        let my_result = ProgramResult::new(true, 50);
        assert_eq!(need_to_challenge(&prover_claim, &my_result), None);

        // if the execution fails try challenge that step number
        let prover_claim = ProgramResult::new(true, 100);
        let my_result = ProgramResult::new(false, 50);
        assert_eq!(need_to_challenge(&prover_claim, &my_result), Some(50));

        // if my execution fails after the prover claim, it means the step by the prover
        // is not a halt_success
        let prover_claim = ProgramResult::new(true, 100);
        let my_result = ProgramResult::new(false, 110);
        assert_eq!(need_to_challenge(&prover_claim, &my_result), Some(100));

        // if both steps match, try to challenge the step
        let prover_claim = ProgramResult::new(true, 100);
        let my_result = ProgramResult::new(false, 100);
        assert_eq!(need_to_challenge(&prover_claim, &my_result), Some(100));
    }

    #[test]
    fn test_nary_search_definitions() {
        let max_steps_aprox = 500_000_000;
        let nary_search = NArySearchDefinition::new(max_steps_aprox, 8);
        assert_eq!(nary_search.full_rounds, 9);
        assert_eq!(nary_search.nary_last_round, 4);

        let nary_search = NArySearchDefinition::new(64, 8);
        assert_eq!(nary_search.full_rounds, 2);
        assert_eq!(nary_search.nary_last_round, 0);

        let nary_search = NArySearchDefinition::new(128, 8);
        assert_eq!(nary_search.full_rounds, 2);
        assert_eq!(nary_search.nary_last_round, 2);

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
}
