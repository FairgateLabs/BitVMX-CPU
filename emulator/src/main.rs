use bitcoin_script_riscv::riscv::instruction_mapping::create_verification_script_mapping;
use emulator::{executor::{fetcher::{execute_program}, utils::FailReads}, loader::program::{generate_rom_commitment, load_elf, Program}, ExecutionResult, REGISTERS_BASE_ADDRESS};
use hex::FromHex;

use clap::{Parser, Subcommand};

/// BitVMX-CPU Emulator and Verifier
#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {

    ///Generate the instruction mapping
    InstructionMapping,

    ///Generate the ROM commitment
    GenerateRomCommitment{
        /// ELF file to load
        #[arg(short, long, value_name = "FILE")]
        elf: String,

        /// Show sections
        #[arg(long)]
        sections: bool,

    },


    ///Execute ELF file
    Execute{

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
        #[arg(short, long, default_value = "false")]
        no_mapping: bool,

        /// Print program stdout 
        #[arg(short, long)]
        stdout: bool,

        /// Debug
        #[arg(short, long)]
        debug: bool,

        /// Show sections
        #[arg(long)]
        sections: bool,

        /// Checkpoints
        #[arg(short, long)]
        checkpoints: bool,

        /// Fail producing hash for a specific step
        #[arg(long)]
        fail_hash: Option<u64>,

        /// Fail producing the write value for a specific step
        #[arg(long)]
        fail_execute: Option<u64>,

        /// List of specific trace step to print
        #[arg(long, value_name = "TraceList")]
        list: Option<String>,

        /// Fail reading read_1 at a given step
        #[arg(long, value_names = &["step", "address_original", "value", "modified_address", "modified_last_step"], num_args = 5)]
        fail_read_1: Option<Vec<String>>,

        /// Fail reading read_2 at a given step
        #[arg(long, value_names = &["step", "address_original", "value", "modified_address", "modified_last_step"], num_args = 5)]
        fail_read_2: Option<Vec<String>>,

        /// Memory dump at given step
        #[arg(short, long)]
        dump_mem: Option<u64>,

        /// Fail while reading the pc at the given step
        #[arg(long)]
        fail_pc: Option<u64>,

    },

}


fn main() -> Result<(), ExecutionResult> {

    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::InstructionMapping) => {
            let mapping = create_verification_script_mapping(REGISTERS_BASE_ADDRESS);
            for (key, script) in mapping {
                println!("Key: {}, Script: {:?}, Size: {}", key, script.to_hex_string(), script.len());
            }
        },
        Some(Commands::GenerateRomCommitment { elf, sections }) => {
            let program = load_elf(elf, *sections);
            generate_rom_commitment(&program);
        },
        Some(Commands::Execute { elf, step, limit, input, input_section,
            input_as_little, no_hash, trace, verify, no_mapping, stdout , debug, sections,
            checkpoints, fail_hash, fail_execute, list,
            fail_read_1: fail_read_1_args, fail_read_2: fail_read_2_args, dump_mem, fail_pc }) => {

            if elf.is_none() && step.is_none() {
                println!("To execute an elf file or a checkpoint step is required");
                return Err(ExecutionResult::Error);
            }
            if elf.is_some() && step.is_some() {
                println!("To execute chose an elf file or a checkpoint not both");
                return Err(ExecutionResult::Error);
            }

            let (mut program, input, checkpoints) = match elf {
                Some(elf) => {
                    let input = input.clone().map(|i| Vec::from_hex(i).unwrap()).unwrap_or(Vec::new());
                    let program = load_elf(elf, *sections);
                    if *debug {
                        println!("Execute program {} with input: {:?}", elf, input);
                    }
                    (program, input, *checkpoints)
                },
                None => {
                    let step = step.expect("Step is expected");
                    let program = Program::deserialize_from_file(&format!("checkpoint.{}.json", step));
                    if *debug {
                        println!("Execute from checkpoint: {} up to: {:?}", step, limit);
                    }
                    (program, vec![], false)
                }

            };

            let numbers = match list {
                Some(list) => {
                    let numbers: Result<Vec<u64>, _> = list
                        .split(',')
                        .map(str::trim)
                        .map(str::parse)
                        .collect();
                    Some(numbers.unwrap())
                },
                None => None
            };

            let fail_reads = if fail_read_1_args.is_some() || fail_read_2_args.is_some() {
                Some(FailReads::new(fail_read_1_args.as_ref(), fail_read_2_args.as_ref()))
            } else {
                None
            };

            execute_program(&mut program, input, &input_section.clone().unwrap_or(".input".to_string()),
                            *input_as_little, checkpoints, *limit, *trace,
                            *verify, !*no_mapping, *stdout, *debug,
                            *no_hash, *fail_hash, *fail_execute, numbers, *dump_mem, fail_reads,
                            *fail_pc)?;
        },
        None => {
            println!("No command specified");
        }
    };

    Ok(())
}

