use emulator::{executor::fetcher::execute_program, loader::program::load_elf, ExecutionResult};
use tracing::{info, Level};

fn verify_file(fname: &str, validate_on_chain: bool) -> Result<ExecutionResult, ExecutionResult> {
    let mut program = load_elf(&fname, false)?;

    info!("Execute program {}", fname);
    Ok(execute_program(
        &mut program,
        vec![17, 17, 17, 17],
        ".input",
        false,
        &None,
        None,
        false,
        validate_on_chain,
        false,
        false,
        false,
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
fn test_1() {
    tracing_subscriber::fmt()
        .without_time()
        .with_target(false)
        .with_max_level(Level::DEBUG)
        .init();

    let path = "../docker-riscv32/riscv32/build/hello-world.elf";
    let result = verify_file(&format!("{}", path), true).unwrap();
    println!("{:?}", result);
}
