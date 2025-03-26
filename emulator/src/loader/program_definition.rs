use config::Config;
use serde::Deserialize;

use thiserror::Error;

use crate::{decision::NArySearchDefinition, ExecutionResult};

use super::program::{load_elf, Program};

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

    pub fn load_program(&self) -> Result<Program, ExecutionResult> {
        //extract the path from config path and concat with elf
        let elf_path = self.config_path.split("/").collect::<Vec<&str>>();
        let elf_file = format!("{}/{}", elf_path[..elf_path.len() - 1].join("/"), self.elf);
        load_elf(&elf_file, false)
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
