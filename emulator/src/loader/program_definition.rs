use bitvmx_cpu_definitions::memory_tree::MemoryModel;
use bitvmx_cpu_definitions::trace::{hash_to_string, TraceRWStep};
use config::Config;
use serde::Deserialize;
use std::cmp::min;

use thiserror::Error;
use tracing::info;

use crate::{
    decision::nary_search::{NArySearchDefinition, SearchMode},
    decision::publication::PublicationMedium,
    executor::{
        fetcher::{execute_program, FullTrace},
        utils::FailConfiguration,
    },
    EmulatorError, ExecutionResult,
};

use super::program::{load_elf, Program, CHECKPOINT_SIZE};

#[derive(Error, Debug)]
pub enum ProgramDefinitionError {
    #[error("Bad configuration: {0}")]
    BadConfig(String),
    #[error("while trying to build configuration")]
    ConfigFileError(#[from] config::ConfigError),
}

#[derive(Debug, Deserialize)]
pub struct InputDefinition {
    pub size: u64,
    pub owner: String,
}

#[derive(Debug, Deserialize)]
pub struct ProgramDefinition {
    #[serde(skip)]
    pub config_path: String,
    pub elf: String,
    pub nary_search: u8,
    /// Defaults to the asymmetric search, so existing program definitions keep
    /// their current behaviour.
    #[serde(default)]
    pub search_mode: SearchMode,
    /// How a stage's dissection reaches the chain.
    ///
    /// Independent of `search_mode`: the search decides who sends what and
    /// when, this decides how the hashes are carried. Defaults to
    /// committed, so existing program definitions keep their current
    /// behaviour here too.
    #[serde(default)]
    pub publication: PublicationMedium,
    /// How a dispute justifies that a read returned the value it claims.
    ///
    /// Defaults to `last_step`, BitVMX's original scheme, so existing
    /// program definitions keep their current behaviour. `merkle` selects
    /// the compact endgame's model, where the state hash chains a memory
    /// root and a read is opened against it.
    #[serde(default)]
    pub memory_model: MemoryModel,
    pub max_steps: u64,
    pub input_section_name: String,
    pub inputs: Vec<InputDefinition>,
}

impl ProgramDefinition {
    pub fn from_config(config: &str) -> Result<Self, ProgramDefinitionError> {
        let mut program: Self = parse_config(config)?;
        program.config_path = config.to_string();
        Ok(program)
    }

    pub fn nary_def(&self) -> NArySearchDefinition {
        NArySearchDefinition::new(self.max_steps, self.nary_search)
    }

    pub fn search_mode(&self) -> SearchMode {
        self.search_mode
    }

    pub fn publication(&self) -> PublicationMedium {
        self.publication
    }

    pub fn memory_model(&self) -> MemoryModel {
        self.memory_model
    }

    /// Bytes of dissection one stage carries, before any framing.
    ///
    /// Twenty-byte state hashes, `nary - 1` of them. Only meaningful
    /// where the dissection is published; a committed one is priced by
    /// its commitment scheme and not by its size.
    pub fn dissection_bytes(&self, round: u8) -> Option<usize> {
        self.publication
            .is_published()
            .then(|| self.nary_def().hashes_for_round(round) as usize * 20)
    }

    pub fn load_program(&self) -> Result<Program, EmulatorError> {
        //extract the path from config path and concat with elf
        let elf_path = self.config_path.split("/").collect::<Vec<&str>>();
        let elf_file = format!("{}/{}", elf_path[..elf_path.len() - 1].join("/"), self.elf);
        let mut program = load_elf(&elf_file, false)?;
        program.memory_model = self.memory_model;
        Ok(program)
    }

    pub fn load_program_from_checkpoint(
        &self,
        checkpoint_path: &str,
        step: u64,
    ) -> Result<Program, EmulatorError> {
        let ndefs = self.nary_def();
        if step >= ndefs.max_steps {
            return Err(EmulatorError::CantLoadPorgram(format!(
                "Step {} is greater than max steps {}",
                step, ndefs.max_steps
            )));
        }

        let checkpoint_step = (step / CHECKPOINT_SIZE) * CHECKPOINT_SIZE;

        if checkpoint_step == 0 {
            self.load_program()
        } else {
            Program::deserialize_from_file(checkpoint_path, checkpoint_step)
        }
    }

    pub fn execute_helper(
        &self,
        input_checkpoint_path: &str,
        output_checkpoint_path: &str,
        input_data: Vec<u8>,
        steps: Option<Vec<u64>>,
        fail_config: Option<FailConfiguration>,
        save_non_checkpoint_steps: bool,
    ) -> Result<(ExecutionResult, FullTrace), EmulatorError> {
        let checkpoint_path_str = output_checkpoint_path.to_string();
        let (mut program, checkpoint_path, output_trace) = match &steps {
            Some(steps) => (
                self.load_program_from_checkpoint(input_checkpoint_path, steps[0])?,
                None,
                true,
            ),

            None => (self.load_program()?, Some(checkpoint_path_str), false),
        };

        Ok(execute_program(
            &mut program,
            input_data,
            &self.input_section_name,
            false,
            &checkpoint_path,
            Some(self.max_steps),
            output_trace,
            false,
            false,
            false,
            false,
            false,
            steps,
            None,
            fail_config.unwrap_or_default(),
            save_non_checkpoint_steps,
        ))
    }

    pub fn get_execution_result(
        &self,
        input_data: Vec<u8>,
        input_checkpoint_path: &str,
        output_checkpoint_path: &str,
        fail_config: Option<FailConfiguration>,
        save_non_checkpoint_steps: bool,
    ) -> Result<(ExecutionResult, u64, String), EmulatorError> {
        let (result, trace) = self.execute_helper(
            input_checkpoint_path,
            output_checkpoint_path,
            input_data,
            None,
            fail_config,
            save_non_checkpoint_steps,
        )?;

        if trace.is_empty() {
            return Err(EmulatorError::CantObtainTrace);
        }

        let last_trace = trace.last().unwrap();
        let last_step = last_trace.0.step_number;
        let last_hash = last_trace.1.clone();

        Ok((result, last_step, last_hash))
    }

    // If the base is higher that the reported last step, we cap it to the last step
    // so the prover can still generate hashes.
    // After the nary search finishes, the prover can challenge this.
    #[allow(clippy::too_many_arguments)]
    pub fn get_round_hashes(
        &self,
        input_checkpoint_path: &str,
        output_checkpoint_path: &str,
        input: Vec<u8>,
        round: u8,
        base: u64,
        fail_config: Option<FailConfiguration>,
        last_step: Option<u64>,
    ) -> Result<Vec<String>, EmulatorError> {
        let base = match last_step {
            Some(last_step) => min(last_step, base),
            None => base,
        };
        let mut steps = self.nary_def().required_steps(round, base);
        info!(
            "Getting hashes for round: {} with steps: {:?}",
            round, steps
        );
        let required_hashes = steps.len();
        steps.insert(0, base); //asks base step as it should be always obtainable

        let (_result, trace) = self.execute_helper(
            input_checkpoint_path,
            output_checkpoint_path,
            input,
            Some(steps),
            fail_config.clone(),
            false,
        )?;
        // at least the base step should be present
        if trace.is_empty() {
            return Err(EmulatorError::CantObtainTrace);
        }

        // if there are actual steps skip the first one
        let skip = if trace.len() > 1 { 1 } else { 0 };

        let fail_config = &fail_config.unwrap_or_default();

        let mut ret: Vec<String> = trace
            .iter()
            .skip(skip)
            .map(|t| {
                let mut hash = t.1.clone();

                if let Some(step) = fail_config.fail_hash_until {
                    if t.0.step_number < step {
                        let mut decoded = hex::decode(hash).unwrap();
                        decoded[0] = decoded[0].wrapping_add(1);

                        let new_hash: [u8; 20] = decoded.try_into().unwrap();
                        hash = hash_to_string(&new_hash);
                    }
                }

                hash
            })
            .collect();
        let obtained_hashes = ret.len();

        assert!(obtained_hashes <= required_hashes);
        for _ in 0..required_hashes - obtained_hashes {
            ret.push(trace.last().unwrap().1.clone());
        }

        Ok(ret)
    }

    pub fn get_trace_step(
        &self,
        input_checkpoint_path: &str,
        output_checkpoint_path: &str,
        input: Vec<u8>,
        step: u64,
        fail_config: Option<FailConfiguration>,
    ) -> Result<TraceRWStep, EmulatorError> {
        let steps = vec![step];
        let (_result, trace) = self.execute_helper(
            input_checkpoint_path,
            output_checkpoint_path,
            input,
            Some(steps),
            fail_config,
            false,
        )?;
        // at least the base step should be present
        if trace.is_empty() {
            return Err(EmulatorError::CantObtainTrace);
        }

        Ok(trace[0].0.clone())
    }
}

fn parse_config<T: for<'a> Deserialize<'a>>(config: &str) -> Result<T, ProgramDefinitionError> {
    let config = Config::builder()
        .add_source(config::File::with_name(config))
        .build()
        .map_err(ProgramDefinitionError::ConfigFileError)?;

    config
        .try_deserialize::<T>()
        .map_err(ProgramDefinitionError::ConfigFileError)
}

#[cfg(test)]
mod publication_tests {
    use super::*;
    use std::io::Write;

    fn definition(extra: &str) -> ProgramDefinition {
        let dir = std::env::temp_dir().join(format!("pubdef-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("d-{}.yaml", extra.len()));
        let mut f = std::fs::File::create(&path).unwrap();
        write!(
            f,
            "elf: hello-world.elf\n\
             nary_search: 8\n\
             max_steps: 2000\n\
             input_section_name: .input\n\
             inputs:\n\
             \x20 - size: 4\n\
             \x20   owner: prover\n\
             {extra}"
        )
        .unwrap();
        ProgramDefinition::from_config(path.to_str().unwrap()).unwrap()
    }

    /// The property that makes this a backend choice rather than a new
    /// protocol: a definition that says nothing about publication means
    /// exactly what it meant before.
    #[test]
    fn an_existing_definition_is_unchanged() {
        let d = definition("");
        assert_eq!(d.publication(), PublicationMedium::Committed);
        assert_eq!(d.search_mode(), SearchMode::Asymmetric);
        assert_eq!(d.dissection_bytes(1), None);
    }

    #[test]
    fn the_two_choices_are_independent() {
        let d = definition("search_mode: full-duplex\npublication: op-return\n");
        assert_eq!(d.search_mode(), SearchMode::FullDuplex);
        assert_eq!(d.publication(), PublicationMedium::OpReturn);

        let d = definition("publication: annex\n");
        assert_eq!(d.search_mode(), SearchMode::Asymmetric, "still the default");
        assert_eq!(d.publication(), PublicationMedium::Annex);
    }

    #[test]
    fn a_published_dissection_is_twenty_bytes_a_hash() {
        let d = definition("publication: op-return\n");
        let n = d.nary_def();
        for round in 1..=n.total_rounds() {
            assert_eq!(
                d.dissection_bytes(round),
                Some(n.hashes_for_round(round) as usize * 20)
            );
        }
        // nary = 8, so seven hashes a full round.
        assert_eq!(d.dissection_bytes(1), Some(140));
    }

    /// At the branching factor the publication exists to buy.
    #[test]
    fn a_192_ary_stage_publishes_3820_bytes() {
        let dir = std::env::temp_dir().join(format!("pubdef192-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("d192.yaml");
        std::fs::write(
            &path,
            "elf: hello-world.elf\n\
             nary_search: 192\n\
             search_mode: full-duplex\n\
             publication: annex\n\
             max_steps: 1073741824\n\
             input_section_name: .input\n\
             inputs:\n\
             \x20 - size: 4\n\
             \x20   owner: prover\n",
        )
        .unwrap();
        let d = ProgramDefinition::from_config(path.to_str().unwrap()).unwrap();
        let n = d.nary_def();
        assert_eq!(n.total_rounds(), 4, "four narrowing levels");
        assert_eq!(n.hashes_for_round(1), 191);
        assert_eq!(d.dissection_bytes(1), Some(191 * 20));
        assert_eq!(d.dissection_bytes(1), Some(3820));
    }
}
