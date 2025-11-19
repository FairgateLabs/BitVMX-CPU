use bitcoin_script_riscv::riscv::instruction_mapping::create_verification_script_mapping;
use bitvmx_cpu_definitions::{challenge::EmulatorResultType, trace::TraceRWStep};
use clap::{Parser, Subcommand};
use emulator::{
    constants::REGISTERS_BASE_ADDRESS,
    decision::{
        challenge::{
            prover_execute, prover_final_trace, prover_get_hashes_and_step,
            prover_get_hashes_for_round, verifier_check_execution, verifier_choose_challenge,
            verifier_choose_challenge_for_read_challenge, verifier_choose_segment, ForceChallenge,
            ForceCondition,
        },
        nary_search::NArySearchType,
    },
    executor::{
        fetcher::execute_program,
        utils::{FailConfiguration, FailExecute, FailOpcode, FailReads, FailWrite},
    },
    loader::program::{generate_rom_commitment, load_elf, Program},
    EmulatorError, ExecutionResult,
};
use hex::FromHex;
use std::io::Write;
use tracing::{error, info, Level};

/// BitVMX-CPU Emulator and Verifier
#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    ProverExecute {
        /// Yaml file to load
        #[arg(short, long, value_name = "FILE")]
        pdf: String,

        /// Input
        #[arg(short, long, value_name = "INPUT (hex)")]
        input: String,

        /// Checkpoint path
        #[arg(short, long, value_name = "CHECKPOINT_PROVER_PATH")]
        checkpoint_prover_path: String,

        /// Force
        #[arg(short, long, default_value = "true")]
        force: bool,

        /// Fail Configuration
        #[arg(short, long, value_name = "FailConfigProver")]
        fail_config_prover: Option<FailConfiguration>,

        /// Command File to write the result
        #[arg(short, long, value_name = "COMMAND_PATH")]
        command_file: String,

        /// Should we save steps that are not checkpoints (like first, error and halt steps)
        #[arg(short, long, action = clap::ArgAction::Set, default_value_t = true)]
        save_non_checkpoint_steps: bool,
    },

    VerifierCheckExecution {
        /// Yaml file to load
        #[arg(short, long, value_name = "FILE")]
        pdf: String,

        /// Input
        #[arg(short, long, value_name = "INPUT (hex)")]
        input: String,

        /// Checkpoint path
        #[arg(short, long, value_name = "CHECKPOINT_VERIFIER_PATH")]
        checkpoint_verifier_path: String,

        /// Claim last step
        #[arg(short, long, value_name = "CLAIM_LAST_STEP")]
        claim_last_step: u64,

        /// Claim last hash
        #[arg(short, long, value_name = "CLAIM_LAST_HASH")]
        claim_last_hash: String,

        /// Force
        #[arg(short, long)]
        force: ForceCondition,

        /// Fail Configuration
        #[arg(short, long, value_name = "FailConfigVerifier")]
        fail_config_verifier: Option<FailConfiguration>,

        /// Command File to write the result
        #[arg(short, long, value_name = "COMMAND_PATH")]
        command_file: String,

        /// Should we save steps that are not checkpoints (like first, error and halt steps)
        #[arg(short, long, action = clap::ArgAction::Set, default_value_t = true)]
        save_non_checkpoint_steps: bool,
    },

    ProverGetHashesForRound {
        /// Yaml file to load
        #[arg(short, long, value_name = "FILE")]
        pdf: String,

        /// Checkpoint prover path
        #[arg(short, long, value_name = "CHECKPOINT_PROVER_PATH")]
        checkpoint_prover_path: String,

        /// Round number
        #[arg(short, long, value_name = "ROUND_NUMBER")]
        round_number: u8,

        /// Verifier decision
        #[arg(short, long, value_name = "VERIFIER_DECISION")]
        v_decision: u32,

        /// Fail Configuration
        #[arg(short, long, value_name = "FailConfigProver")]
        fail_config_prover: Option<FailConfiguration>,

        /// Command File to write the result
        #[arg(short, long, value_name = "COMMAND_PATH")]
        command_file: String,

        /// Nary Search type
        #[arg(short, long, value_name = "NARY_TYPE")]
        nary_type: NArySearchType,
    },

    VerifierChooseSegment {
        /// Yaml file to load
        #[arg(short, long, value_name = "FILE")]
        pdf: String,

        /// Checkpoint verifier path
        #[arg(short, long, value_name = "CHECKPOINT_VERIFIER_PATH")]
        checkpoint_verifier_path: String,

        /// Round number
        #[arg(short, long, value_name = "ROUND_NUMBER")]
        round_number: u8,

        /// Hashes
        #[arg(short, long, value_name = "HASHES")]
        hashes: Vec<String>,

        /// Fail Configuration
        #[arg(short, long, value_name = "FailConfigVerifier")]
        fail_config_verifier: Option<FailConfiguration>,

        /// Command File to write the result
        #[arg(short, long, value_name = "COMMAND_PATH")]
        command_file: String,

        /// Nary Search type
        #[arg(short, long, value_name = "NARY_TYPE")]
        nary_type: NArySearchType,
    },

    ProverFinalTrace {
        /// Yaml file to load
        #[arg(short, long, value_name = "FILE")]
        pdf: String,

        /// Checkpoint prover path
        #[arg(short, long, value_name = "CHECKPOINT_PROVER_PATH")]
        checkpoint_prover_path: String,

        /// Verifier decision
        #[arg(short, long, value_name = "VERIFIER_DECISION")]
        v_decision: u32,

        /// Fail Configuration
        #[arg(short, long, value_name = "FailConfigProver")]
        fail_config_prover: Option<FailConfiguration>,

        /// Command File to write the result
        #[arg(short, long, value_name = "COMMAND_PATH")]
        command_file: String,
    },

    ProverGetCosignedBitsAndHashes {
        #[arg(short, long, value_name = "FILE")]
        pdf: String,

        /// Checkpoint prover path
        #[arg(short, long, value_name = "CHECKPOINT_PROVER_PATH")]
        checkpoint_prover_path: String,

        /// Verifier decision
        #[arg(short, long, value_name = "VERIFIER_DECISION")]
        v_decision: u32,

        /// Command File to write the result
        #[arg(short, long, value_name = "COMMAND_PATH")]
        command_file: String,

        // Fail Configuration
        #[arg(short, long, value_name = "FailConfigProver")]
        fail_config_prover: Option<FailConfiguration>,
    },

    VerifierChooseChallenge {
        /// Yaml file to load
        #[arg(short, long, value_name = "FILE")]
        pdf: String,

        /// Checkpoint verifier path
        #[arg(short, long, value_name = "CHECKPOINT_VERIFIER_PATH")]
        checkpoint_verifier_path: String,

        /// Prover final trace
        #[arg(short, long, value_name = "PROVER_FINAL_TRACE")]
        prover_final_trace: TraceRWStep,

        /// Force
        #[arg(short, long, default_value = "no")]
        force: ForceChallenge,

        /// Fail Configuration
        #[arg(short, long, value_name = "FailConfigVerifier")]
        fail_config_verifier: Option<FailConfiguration>,

        /// Command File to write the result
        #[arg(short, long, value_name = "COMMAND_PATH")]
        command_file: String,

        #[arg(short, long, value_name = "RESIGNED_STEP_HASH")]
        resigned_step_hash: String,

        #[arg(short, long, value_name = "RESIGNED_NEXT_HASH")]
        resigned_next_hash: String,
    },

    VerifierChooseChallengeForReadChallenge {
        /// Yaml file to load
        #[arg(short, long, value_name = "FILE")]
        pdf: String,

        /// Checkpoint verifier path
        #[arg(short, long, value_name = "CHECKPOINT_VERIFIER_PATH")]
        checkpoint_verifier_path: String,

        /// Fail Configuration
        #[arg(short, long, value_name = "FailConfigVerifier")]
        fail_config_verifier: Option<FailConfiguration>,

        /// Force
        #[arg(short, long, default_value = "no")]
        force: ForceChallenge,

        /// Command File to write the result
        #[arg(short, long, value_name = "COMMAND_PATH")]
        command_file: String,

        #[arg(short, long, value_name = "RESIGNED_STEP_HASH")]
        resigned_step_hash: String,

        #[arg(short, long, value_name = "RESIGNED_NEXT_HASH")]
        resigned_next_hash: String,
    },

    ///Generate the instruction mapping
    InstructionMapping,

    ///Generate the ROM commitment
    GenerateRomCommitment {
        /// ELF file to load
        #[arg(short, long, value_name = "FILE")]
        elf: String,

        /// Show sections
        #[arg(long)]
        sections: bool,
    },

    ///Execute ELF file
    Execute {
        /// Outputs the trace
        /// ELF file to load
        #[arg(short, long, value_name = "FILE")]
        elf: Option<String>,

        /// Step number to continue execution
        #[arg(short, long, value_name = "Step")]
        step: Option<u64>,

        /// Maximum number of steps to execute
        #[arg(short, long, value_name = "LimitStep")]
        limit: Option<u64>,

        /// Input as hex
        #[arg(short, long, value_name = "HEX")]
        input: Option<String>,

        /// Section name where the input will be loaded
        #[arg(long, value_name = "SectionName")]
        input_section: Option<String>,

        /// Input as little endina
        #[arg(long, default_value = "false")]
        input_as_little: bool,

        /// Avoid hashing the trace
        #[arg(short, long, default_value = "false")]
        no_hash: bool,

        /// Outputs the trace
        #[arg(short, long)]
        trace: bool,

        /// Verify on chain execution
        #[arg(short, long)]
        verify: bool,

        /// Use instruction map
        #[arg(long, default_value = "false")]
        no_mapping: bool,

        /// Print program stdout
        #[arg(long)]
        stdout: bool,

        /// Debug
        #[arg(short, long)]
        debug: bool,

        /// Show sections
        #[arg(long)]
        sections: bool,

        /// Checkpoint path
        #[arg(short, long)]
        checkpoint_path: Option<String>,

        /// Fail producing hash for a specific step
        #[arg(long)]
        fail_hash: Option<u64>,

        /// Fail producing hash but only for steps until a specific one.
        /// fail_hash will propagate the error to the next steps due to the hash of a step depending on the previous hash.
        /// this one doesn't since we modify the hash after all the hashes have been calculated in get_round_hashes
        #[arg(long)]
        fail_hash_until: Option<u64>,

        /// Fail producing the write value for a specific step
        #[arg(long, value_names = &["step", "fake_trace"], num_args = 2)]
        fail_execute: Option<Vec<String>>,

        /// List of specific trace step to print
        #[arg(long, value_name = "TraceList")]
        list: Option<String>,

        /// Fail reading read_1 at a given step
        #[arg(long, value_names = &["step", "address_original", "value", "modified_address", "modified_last_step"], num_args = 5)]
        fail_read_1: Option<Vec<String>>,

        /// Fail reading read_2 at a given step
        #[arg(long, value_names = &["step", "address_original", "value", "modified_address", "modified_last_step"], num_args = 5)]
        fail_read_2: Option<Vec<String>>,

        /// Fail write at a given step
        #[arg(long, value_names = &["step", "address_original", "value", "modified_address"], num_args = 4)]
        fail_write: Option<Vec<String>>,

        /// Fail while reading the pc at the given step
        #[arg(long)]
        fail_pc: Option<u64>,

        /// Fail reading opcode at a given step
        #[arg(long, value_names = &["step", "opcode"], num_args = 2)]
        fail_opcode: Option<Vec<String>>,

        /// Fail resign hash at a given step
        #[arg(long)]
        fail_resign_hash: Option<u64>,

        /// Memory dump at given step
        #[arg(short, long)]
        dump_mem: Option<u64>,

        /// Should we save steps that are not checkpoints (like first, error and halt steps)
        #[arg(short, long, action = clap::ArgAction::Set, default_value_t = true)]
        save_non_checkpoint_steps: bool,
    },
}

fn main() -> Result<(), EmulatorError> {
    tracing_subscriber::fmt()
        .without_time()
        .with_target(false)
        .with_max_level(Level::DEBUG)
        .init();

    let cli = Cli::parse();
    match &cli.command {
        Some(Commands::InstructionMapping) => {
            let mapping = create_verification_script_mapping(REGISTERS_BASE_ADDRESS);
            for (key, (script, requires_witness)) in mapping {
                info!(
                    "Key: {}, Script: {:?}, Size: {}, Witness: {}",
                    key,
                    script.to_hex_string(),
                    script.len(),
                    requires_witness
                );
            }
        }
        Some(Commands::GenerateRomCommitment { elf, sections }) => {
            let program = load_elf(elf, *sections)?;
            generate_rom_commitment(&program)?;
        }
        Some(Commands::Execute {
            elf,
            step,
            limit,
            input,
            input_section,
            input_as_little,
            no_hash,
            trace,
            verify,
            no_mapping,
            stdout,
            debug,
            sections,
            checkpoint_path,
            fail_hash,
            fail_hash_until,
            fail_execute: fail_execute_args,
            list,
            fail_read_1: fail_read_1_args,
            fail_read_2: fail_read_2_args,
            fail_write: fail_write_args,
            fail_opcode: fail_opcode_args,
            fail_resign_hash,
            dump_mem,
            fail_pc,
            save_non_checkpoint_steps,
        }) => {
            if elf.is_none() && step.is_none() {
                error!("To execute an elf file or a checkpoint step is required");
                return Err(EmulatorError::InvalidParameters);
            }
            if elf.is_some() && step.is_some() {
                error!("To execute chose an elf file or a checkpoint not both");
                return Err(EmulatorError::InvalidParameters);
            }

            let (mut program, input) = match elf {
                Some(elf) => {
                    let input = input
                        .clone()
                        .map(|i| Vec::from_hex(i).unwrap())
                        .unwrap_or(Vec::new());
                    let program = load_elf(elf, *sections)?;
                    if *debug {
                        info!("Execute program {} with input: {:?}", elf, input);
                    }
                    (program, input)
                }
                None => {
                    let step = step.expect("Step is expected");
                    let path = checkpoint_path
                        .as_ref()
                        .expect("Checkpoint path is expected");
                    let program = Program::deserialize_from_file(path, step)?;
                    if *debug {
                        info!("Execute from checkpoint: {} up to: {:?}", step, limit);
                    }
                    (program, vec![])
                }
            };

            let numbers = match list {
                Some(list) => {
                    let numbers: Result<Vec<u64>, _> =
                        list.split(',').map(str::trim).map(str::parse).collect();
                    Some(numbers.unwrap())
                }
                None => None,
            };

            let fail_execute = fail_execute_args.as_ref().map(FailExecute::new);

            let fail_reads = if fail_read_1_args.is_some() || fail_read_2_args.is_some() {
                Some(FailReads::new(
                    fail_read_1_args.as_ref(),
                    fail_read_2_args.as_ref(),
                ))
            } else {
                None
            };

            let fail_write = fail_write_args.as_ref().map(FailWrite::new);
            let fail_opcode = fail_opcode_args.as_ref().map(FailOpcode::new);

            let debugvar = *debug;
            let fail_config = FailConfiguration {
                fail_hash: *fail_hash,
                fail_hash_until: *fail_hash_until,
                fail_execute,
                fail_reads,
                fail_write,
                fail_pc: *fail_pc,
                fail_opcode,
                fail_memory_protection: false,
                fail_execute_only_protection: false,
                fail_resign_hash: *fail_resign_hash,
            };
            let result = execute_program(
                &mut program,
                input,
                &input_section.clone().unwrap_or(".input".to_string()),
                *input_as_little,
                &checkpoint_path,
                *limit,
                *trace,
                *verify,
                !*no_mapping,
                *stdout,
                debugvar,
                *no_hash,
                numbers,
                *dump_mem,
                fail_config,
                *save_non_checkpoint_steps,
            )
            .0;
            info!("Execution result: {:?}", result);
        }
        Some(Commands::ProverExecute {
            pdf,
            input,
            checkpoint_prover_path,
            force,
            fail_config_prover,
            command_file,
            save_non_checkpoint_steps,
        }) => {
            let input_bytes = hex::decode(input).expect("Invalid hex string");
            let result = prover_execute(
                pdf,
                input_bytes.clone(),
                checkpoint_prover_path,
                *force,
                fail_config_prover.clone(),
                *save_non_checkpoint_steps,
            )?;
            info!("Prover execute: {:?}", result);

            let halt = match result.0 {
                ExecutionResult::Halt(result, step) => Some((result, step)),
                _ => None,
            };

            let result = EmulatorResultType::ProverExecuteResult {
                last_step: result.1,
                last_hash: result.2,
                halt: halt,
            }
            .to_value()?;

            let mut file = create_or_open_file(command_file);
            file.write_all(result.to_string().as_bytes())
                .expect("Failed to write JSON to file");
        }
        Some(Commands::VerifierCheckExecution {
            pdf,
            input,
            checkpoint_verifier_path,
            claim_last_step,
            claim_last_hash,
            force,
            fail_config_verifier,
            command_file,
            save_non_checkpoint_steps,
        }) => {
            let input_bytes = hex::decode(input).expect("Invalid hex string");
            let result = verifier_check_execution(
                pdf,
                input_bytes.clone(),
                checkpoint_verifier_path,
                *claim_last_step,
                claim_last_hash,
                force.clone(),
                fail_config_verifier.clone(),
                *save_non_checkpoint_steps,
            )?;
            info!("Verifier checks execution: {:?}", result);

            let result =
                EmulatorResultType::VerifierCheckExecutionResult { step: result }.to_value()?;
            let mut file = create_or_open_file(command_file);
            file.write_all(result.to_string().as_bytes())
                .expect("Failed to write JSON to file");
        }
        Some(Commands::ProverGetHashesForRound {
            pdf,
            checkpoint_prover_path,
            round_number,
            v_decision,
            fail_config_prover,
            command_file,
            nary_type,
        }) => {
            let result = prover_get_hashes_for_round(
                pdf,
                checkpoint_prover_path,
                *round_number,
                *v_decision,
                fail_config_prover.clone(),
                *nary_type,
            )?;
            info!("Prover get hashes for round: {:?}", result);

            let result = EmulatorResultType::ProverGetHashesForRoundResult {
                hashes: result.clone(),
                round: *round_number,
            }
            .to_value()?;
            let mut file = create_or_open_file(command_file);
            file.write_all(result.to_string().as_bytes())
                .expect("Failed to write JSON to file");
        }
        Some(Commands::VerifierChooseSegment {
            pdf,
            checkpoint_verifier_path,
            round_number,
            hashes,
            fail_config_verifier,
            command_file,
            nary_type,
        }) => {
            let result = verifier_choose_segment(
                pdf,
                checkpoint_verifier_path,
                *round_number,
                hashes.clone(),
                fail_config_verifier.clone(),
                *nary_type,
            )?;
            info!("Verifier choose segment: {:?}", result);

            let result = EmulatorResultType::VerifierChooseSegmentResult {
                v_decision: result.clone(),
                round: *round_number,
            }
            .to_value()?;
            let mut file = create_or_open_file(command_file);
            file.write_all(result.to_string().as_bytes())
                .expect("Failed to write JSON to file");
        }
        Some(Commands::ProverFinalTrace {
            pdf,
            checkpoint_prover_path,
            v_decision,
            fail_config_prover,
            command_file,
        }) => {
            let (final_trace, resigned_step_hash, resigned_next_hash, conflict_step) =
                prover_final_trace(
                    pdf,
                    checkpoint_prover_path,
                    *v_decision,
                    fail_config_prover.clone(),
                )?;
            info!("Prover final trace: {:?}", final_trace);
            info!("Prover resigned step hash: {:?}", resigned_step_hash);
            info!("Prover resigned next hash: {:?}", resigned_next_hash);
            info!("Prover conflict step: {:?}", conflict_step);

            let result = EmulatorResultType::ProverFinalTraceResult {
                final_trace,
                resigned_step_hash,
                resigned_next_hash,
                conflict_step,
            }
            .to_value()?;
            let mut file = create_or_open_file(command_file);
            file.write_all(result.to_string().as_bytes())
                .expect("Failed to write JSON to file");
        }
        Some(Commands::VerifierChooseChallenge {
            pdf,
            checkpoint_verifier_path,
            prover_final_trace,
            resigned_step_hash,
            resigned_next_hash,
            force,
            fail_config_verifier,
            command_file,
        }) => {
            let result = verifier_choose_challenge(
                pdf,
                checkpoint_verifier_path,
                prover_final_trace.clone(),
                resigned_step_hash,
                resigned_next_hash,
                force.clone(),
                fail_config_verifier.clone(),
                false,
            )?;
            info!("Verifier choose challenge: {:?}", result);

            let result = EmulatorResultType::VerifierChooseChallengeResult {
                challenge: result.clone(),
            }
            .to_value()?;
            let mut file = create_or_open_file(command_file);
            file.write_all(result.to_string().as_bytes())
                .expect("Failed to write JSON to file");
        }
        Some(Commands::VerifierChooseChallengeForReadChallenge {
            pdf,
            checkpoint_verifier_path,
            fail_config_verifier,
            resigned_step_hash,
            resigned_next_hash,
            force,
            command_file,
        }) => {
            let result = verifier_choose_challenge_for_read_challenge(
                pdf,
                checkpoint_verifier_path,
                resigned_step_hash,
                resigned_next_hash,
                fail_config_verifier.clone(),
                force.clone(),
                false,
            )?;
            info!("Verifier choose challenge: {:?}", result);

            let result = EmulatorResultType::VerifierChooseChallengeResult {
                challenge: result.clone(),
            }
            .to_value()?;
            let mut file = create_or_open_file(command_file);
            file.write_all(result.to_string().as_bytes())
                .expect("Failed to write JSON to file");
        }
        Some(Commands::ProverGetCosignedBitsAndHashes {
            pdf,
            checkpoint_prover_path,
            v_decision,
            command_file,
            fail_config_prover,
        }) => {
            let (resigned_step_hash, resigned_next_hash, write_step) = prover_get_hashes_and_step(
                pdf,
                &checkpoint_prover_path,
                NArySearchType::ReadValueChallenge,
                Some(*v_decision),
                fail_config_prover.clone(),
            )?;

            let result = EmulatorResultType::ProverGetCosignedBitsAndHashesResult {
                resigned_step_hash,
                resigned_next_hash,
                write_step,
            }
            .to_value()?;
            let mut file = create_or_open_file(command_file);
            file.write_all(result.to_string().as_bytes())
                .expect("Failed to write JSON to file");
        }
        None => {
            error!("No command specified");
        }
    };

    Ok(())
}

fn create_or_open_file(file_path: &str) -> std::fs::File {
    std::fs::OpenOptions::new()
        .create(true) // create if it doesn't exist
        .write(true) // enable write
        .truncate(true) // clear existing content
        .open(file_path)
        .expect("Failed to open or create file")
}
