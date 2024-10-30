use emulator::{executor::fetcher::execute_program, loader::program::load_elf, ExecutionResult};


fn verify_file(fname: &str, validate_on_chain: bool) -> Result<(Vec<String>, ExecutionResult), ExecutionResult> {
    let mut program = load_elf(&fname, false);
    println!("Execute program {}", fname);
    execute_program(&mut program, Vec::new(), ".bss", false, false, None, false, validate_on_chain,
                    false, false, true, true, None, None, None, None, None,
                    None)
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
            if fname.ends_with(".elf") {

                let path = path.path();
                let path = path.to_string_lossy();

                let (_, result) = verify_file(&format!("{}", path), true).unwrap();
                match result {
                    ExecutionResult::Halt(exit_code) => {
                        assert!(exit_code == 0, "Error executing file {}", path);
                        println!("File {} executed successfully", path);
                        count += 1;
                    }
                    _ => assert!(false, "Error executing file {}", path),
                }
               
            }
        }
    }

    println!("Total files executed: {}", count);
    assert_eq!(count, 47);

}
