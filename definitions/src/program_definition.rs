/*
elf: hello-world.elf
nary_search: 8
max_steps: 2000
input_section_name: .input
inputs:
  - size: 4
    owner: prover
    */

use serde::Deserialize;

use thiserror::Error;

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
    pub elf: String,
    pub nary_search: u8,
    pub max_steps: u64,
    pub input_section_name: String,
    pub inputs: Vec<InputDefinition>,
}
/*
fn parse_config<T: for<'a> Deserialize<'a>>(config: &str) -> Result<T, ProgramDefinitionError> {
    let config = Config::builder()
        .add_source(config::File::with_name(config))
        .build()
        .map_err(ConfigError::ConfigFileError)?;

    config
        .try_deserialize::<T>()
        .map_err(ConfigError::ConfigFileError)
}
*/
