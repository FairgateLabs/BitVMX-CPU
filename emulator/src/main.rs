use emulator::{executor::fetcher::execute_program, loader::program::load_elf, ExecutionResult};
use hex::FromHex;

fn main() -> Result<(), ExecutionResult> {

    //TODO: Separated options to: 
    // Generate loading trace
    // Generate execution trace/hash
    // Execute with input and validate result  

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        println!("Usage: {} <ELF file> <input as hex>", args[0]);
        return Ok(());
    }
    let fname = &args[1];
    let input = Vec::from_hex(&args[2]).unwrap(); //TODO: handle error
    let mut program = load_elf(&fname);
    println!("Execute program {} with input: {:?}", fname, input);

    //compare hashlist with expected hashlist changing inputs
    let _hashlist = execute_program(&mut program, input)?;

    Ok(())

}
