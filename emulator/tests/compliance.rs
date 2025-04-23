use emulator::{
    executor::{
        fetcher::{execute_program, FullTrace},
        utils::FailConfiguration,
    },
    loader::program::load_elf,
    EmulatorError, ExecutionResult,
};
use tracing::info;

fn verify_file(
    fname: &str,
    verify_on_chain: bool,
) -> Result<(ExecutionResult, FullTrace), EmulatorError> {
    let mut program = load_elf(&fname, false)?;

    info!("Execute program {}", fname);
    Ok(execute_program(
        &mut program,
        Vec::new(),
        ".bss",
        false,
        &None,
        None,
        false,
        verify_on_chain,
        false,
        false,
        false,
        true,
        None,
        None,
        FailConfiguration::default(),
    ))
}

#[test]
fn list_files() {
    let path = "../docker-riscv32/compliance/build";
    let paths = std::fs::read_dir(path).unwrap();
    let mut count = 0;
    for path in paths {
        if let Ok(path) = path {
            let fname = path.file_name();
            let fname = fname.to_string_lossy();
            if fname.ends_with(".elf") && !fname.contains("fence_i") {
                let path = path.path();
                let path = path.to_string_lossy();

                let (result, _) = verify_file(&format!("{}", path), true).unwrap();
                match result {
                    ExecutionResult::Halt(exit_code, _) => {
                        assert!(exit_code == 0, "Error executing file {}", path);
                        info!("File {} executed successfully", path);
                        count += 1;
                    }
                    _ => assert!(false, "Error executing file {}", path),
                }
            }
        }
    }

    info!("Total files executed: {}", count);
    assert_eq!(count, 47);
}
