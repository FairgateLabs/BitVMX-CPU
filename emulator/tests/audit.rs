use emulator::ExecutionResult;
use tracing::info;

mod utils;
use utils::common::verify_file;

#[test]
fn audit_tests() {
    let path = "../docker-riscv32/riscv32/build/audit";
    let paths = std::fs::read_dir(path).unwrap();
    let mut count = 0;
    for path in paths {
        if let Ok(path) = path {
            let fname = path.file_name();
            let fname = fname.to_string_lossy();
            if fname.ends_with("verify.elf") && fname.contains("14") {
                let path = path.path();
                let path = path.to_string_lossy();

                let (result, _) = verify_file(&format!("{}", path), true).unwrap();
                match result {
                    ExecutionResult::Halt(0, _) => {
                        info!("File {} executed successfully", path);
                        count += 1;
                    }
                    _ => panic!("Error executing file {}", path),
                }
            }
        }
    }

    info!("Total files executed: {}", count);
    assert_eq!(count, 4);
}
