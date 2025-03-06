use std::collections::HashMap;

use emulator::{executor::fetcher::execute_program, loader::program::load_elf, ExecutionResult};
use tracing::info;

fn verify_file(fname: &str, validate_on_chain: bool) -> Result<ExecutionResult, ExecutionResult> {
    let mut program = load_elf(&fname, false)?;
    info!("Execute program {}", fname);
    Ok(execute_program(
        &mut program,
        Vec::new(),
        ".bss",
        false,
        &None,
        Some(1000),
        false,
        validate_on_chain,
        false,
        false,
        true,
        true,
        None,
        None,
        None,
        None,
        None,
        None,
    ))
}

#[test]
fn exception_cases() {
    let mut test_cases = HashMap::new();
    test_cases.insert("read_reg.elf", ExecutionResult::RegistersSectionFail);
    test_cases.insert(
        "read_invalid.elf",
        ExecutionResult::SectionNotFound("Address 0x00000000 not found in any section".to_string()),
    );
    test_cases.insert("pc_limit.elf", ExecutionResult::LimitStepReached);
    test_cases.insert(
        "pc_invalid.elf",
        ExecutionResult::SectionNotFound("Address 0x00000000 not found in any section".to_string()),
    );
    test_cases.insert("pc_reg.elf", ExecutionResult::RegistersSectionFail);

    let path = "../docker-riscv32/riscv32/build/exceptions";
    let paths = std::fs::read_dir(path).unwrap();
    for path in paths {
        if let Ok(path) = path {
            let fname = path.file_name();
            let fname = fname.to_string_lossy();
            if fname.ends_with(".elf") {
                println!("Testing file: {}", fname);
                let path = path.path();
                let path = path.to_string_lossy();

                let result = verify_file(&format!("{}", path), true).unwrap();
                assert_eq!(
                    test_cases.get(fname.into_owned().as_str()).unwrap(),
                    &result
                );
            }
        }
    }
}
