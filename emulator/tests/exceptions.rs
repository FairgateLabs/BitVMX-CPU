use emulator::ExecutionResult;
use std::collections::HashMap;

mod utils;
use utils::common::verify_file;

#[test]
fn exception_cases() {
    let mut test_cases = HashMap::new();
    test_cases.insert("read_reg.elf", ExecutionResult::RegistersSectionFail);
    test_cases.insert(
        "read_invalid.elf",
        ExecutionResult::SectionNotFound("Address 0x00000000 not found in any section".to_string()),
    );
    test_cases.insert("pc_limit.elf", ExecutionResult::LimitStepReached(1000));
    test_cases.insert(
        "pc_invalid.elf",
        ExecutionResult::SectionNotFound("Address 0x00000000 not found in any section".to_string()),
    );
    test_cases.insert("pc_reg.elf", ExecutionResult::RegistersSectionFail);
    test_cases.insert("write_reg.elf", ExecutionResult::RegistersSectionFail);
    test_cases.insert(
        "write_invalid.elf",
        ExecutionResult::SectionNotFound("Address 0x00000000 not found in any section".to_string()),
    );
    test_cases.insert(
        "write_protected.elf",
        ExecutionResult::WriteToReadOnlySection,
    );

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

                let (result, _) = verify_file(&format!("{}", path), false).unwrap();
                assert_eq!(
                    test_cases.get(fname.into_owned().as_str()).unwrap(),
                    &result
                );
            }
        }
    }
}
