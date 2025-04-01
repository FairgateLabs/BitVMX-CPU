use bitvmx_cpu_definitions::trace::TraceRWStep;
use config::Config;
use serde::Deserialize;

use thiserror::Error;
use tracing::info;

use crate::{
    decision::nary_search::NArySearchDefinition,
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

    pub fn load_program(&self) -> Result<Program, EmulatorError> {
        //extract the path from config path and concat with elf
        let elf_path = self.config_path.split("/").collect::<Vec<&str>>();
        let elf_file = format!("{}/{}", elf_path[..elf_path.len() - 1].join("/"), self.elf);
        load_elf(&elf_file, false)
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

        let mut checkpoint_step = 0;
        loop {
            if step < checkpoint_step + CHECKPOINT_SIZE {
                break;
            }
            checkpoint_step += CHECKPOINT_SIZE;
        }

        Program::deserialize_from_file(checkpoint_path, checkpoint_step)
    }

    pub fn execute_helper(
        &self,
        checkpoint_path: &str,
        input_data: Vec<u8>,
        steps: Option<Vec<u64>>,
        fail_config: Option<FailConfiguration>,
    ) -> Result<(ExecutionResult, FullTrace), EmulatorError> {
        let checkpoint_path_str = checkpoint_path.to_string();
        let (mut program, checkpoint_path, output_trace) = match &steps {
            Some(steps) => (
                self.load_program_from_checkpoint(checkpoint_path, steps[0])?,
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
        ))
    }

    pub fn get_execution_result(
        &self,
        input_data: Vec<u8>,
        checkpoint_path: &str,
        fail_config: Option<FailConfiguration>,
    ) -> Result<(ExecutionResult, u64, String), EmulatorError> {
        let (result, trace) =
            self.execute_helper(checkpoint_path, input_data, None, fail_config)?;

        if trace.len() == 0 {
            return Err(EmulatorError::CantObtainTrace);
        }

        let last_trace = trace.last().unwrap();
        let last_step = last_trace.0.step_number;
        let last_hash = last_trace.1.clone();

        Ok((result, last_step, last_hash))
    }

    //TODO: Check that the base is not higher that the reported finish step
    //it might be necessary to enforce this in bitcoin script
    pub fn get_round_hashes(
        &self,
        checkpoint_path: &str,
        round: u8,
        base: u64,
        fail_config: Option<FailConfiguration>,
    ) -> Result<Vec<String>, EmulatorError> {
        let mut steps = self.nary_def().required_steps(round, base);
        info!(
            "Getting hashes for round: {} with steps: {:?}",
            round, steps
        );
        let required_hashes = steps.len();
        steps.insert(0, base); //asks base step as it should be always obtainable

        let (_result, trace) =
            self.execute_helper(checkpoint_path, vec![], Some(steps), fail_config)?;
        // at least the base step should be present
        if trace.len() == 0 {
            return Err(EmulatorError::CantObtainTrace);
        }

        // if there are actual steps skip the first one
        let skip = if trace.len() > 1 { 1 } else { 0 };

        let mut ret: Vec<String> = trace.iter().skip(skip).map(|t| t.1.clone()).collect();
        let obtained_hashes = ret.len();

        assert!(obtained_hashes <= required_hashes);
        for _ in 0..required_hashes - obtained_hashes {
            ret.push(trace.last().unwrap().1.clone());
        }

        Ok(ret)
    }

    pub fn get_trace_step(
        &self,
        checkpoint_path: &str,
        step: u64,
        fail_config: Option<FailConfiguration>,
    ) -> Result<TraceRWStep, EmulatorError> {
        let steps = vec![step];
        let (_result, trace) =
            self.execute_helper(checkpoint_path, vec![], Some(steps), fail_config)?;
        // at least the base step should be present
        if trace.len() == 0 {
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
