
# BitVMX-CPU

**WARNING**: This repository contains the work in progress implementation of the CPU for [BitVMX](https://bitvmx.org/), and has not received careful code review. This implementation is NOT production ready.

The BitVMX-CPU is a core component of the BitVMX Protocol, please refer to the [BitVMX](https://bitvmx.org/) website and white paper for a better understanding.

The architecture adopted for this first version is [RISCV-32i](https://riscv.org/), with additional support for the 'M' extension, which significantly reduces the number of opcodes needed to perform multiplication, division, and remainder operations.


## Structure

The repository contains three folders
1. **docker-riscv32**: Contains the recipe for an image that allows the compilation of C programs into the RISCV-32i architecture. Currently, the programs must be carefully crafted to be used inside BitVMX, using specific memory layouts, predefined input sections and the lack of support for now of the stdlib.  
There are two subfolders: `compliance` which have the code necessary to create the RISCV compliance verification files, and `verifier` which helps with the compilation of a zero knowledge proof verifier program.
2. **emulator**: The emulator is a library with a command line interface implemented in Rust which is used to execute the binary files compiled. Also this tool helps in the creation of the execution trace, the hash list of the execution necessary for the challenge protocol.
3. **bitocoin-script-riscv**: This library contains the code that allows to verify any of the RISCV instructions on Bitcoin Script, and therefore challenge the execution of the CPU on-chain.  

## Emulator 

The emulator has three main command that can be listed using the cli help
`cargo run --release -p emulator help`

The options are:
- execute: That is used to execute the compiled binaries to generate traces and check the result of the execution for a given input.

- instruction-mapping: This is a helper method used to produce all the bitcoin scripts that are necessary to challenge every RISCV opcode.

- generate-rom-commitment: This method is used to generate the data that needs to be agreed by the two parties and are dependent on the program. One part contains the program opcodes, and the other contains any other constand data that might be necessary to challenge on-chain and define the behavior of the program.


### Running an example:

As an example, there is a precompiled [hello-world.elf](docker-riscv32/riscv32/build/hello-world.elf) that can be used with the emulator, but any other program compiled using the instructions of the next section should work too. The `.c` file is in the same folder.

execute:  
```cargo run --release -p emulator execute --elf docker-riscv32/riscv32/build/hello-world.elf --stdout```  
The execute command takes an `--elf` file and will output through `--stdout` some message and a resulting error code (1) in this case as it expects certain input.

Arguments:  
```cargo run --release -p emulator execute --elf docker-riscv32/riscv32/build/hello-world.elf --stdout --input 11111111```  
As the program expects `0x11111111` as input it will return (0) and a success message.
(The input of the program needs to be provided as hex values and is treated as big-endian encoding except `--input-as-little` flag is set, which will treat the input as 32 bit words as little endian.)

Trace:  
```cargo run --release -p emulator execute --elf docker-riscv32/riscv32/build/hello-world.elf --trace --input 11111111```  
If `--trace` is used, the program will generate the trace of every step as `;` delimited value, and the hash for that step (concatenated with the previous hash). You can test that the last hash of the trace changes if you change the input.

Debug:  
```cargo run --release -p emulator execute --elf docker-riscv32/riscv32/build/hello-world.elf --debug --input 11111111```
`--debug` will show every step of the execution, dumping the opcode and the decoded instruction, at the end will also show the state of the registers, some metrics and the input data.


### Generate the script validation mapping
To generate the bitcoin script mapping for every RISCV opcode just run:  
`cargo run -p emulator -- instruction-mapping`
The result will be a little unreadable as it generates the hexdump of the bitcoin script code for every opcode (+ some extra for microinstructions needed for some of the opcodes)

### Generate program commitment
To generate the ROM commitments use the following command:   
`cargo run -p emulator -- generate-rom-commitment --elf docker-riscv32/riscv32/build/hello-world.elf`

## Advanced commands 

When running longer programs first run with `--debug` and `--checkpoints` this will generate a checkpoint file every 50M steps and will print the last hash and the total number of steps.

`cargo run --release --bin emulator -- execute --elf docker-riscv32/verifier/build/zkverifier-new-mul.elf --debug --checkpoints`

Then when the binary search requires some specific step execute from the closest (lower) checkpoint: i.e `--step 150000000`, put as limit the maximun step required i.e: `--limit 180000000` and use list to specify the requested value steps: `--list "160000000,165000000,170000000"` and `--trace` to print them.

`cargo run --release --bin emulator -- execute  --step 150000000 --limit 180000000 --list "160000000,165000000,170000000" --trace`

#### Memory dump 

To generate a memory dump at a given step `--dump-mem [step]`. This will dump the memory state at the given step, excluding all the empty addresses.

### Generating failing cases:

To emulate an error in the hash calculation and get a defective hash list, use `--fail-hash [step]`


To emulate an error in the execution, `--fail-execute [step]`. This will add 1 to the trace_write_value.

To emulate an error in the program counter `--fail-pc [step]`. This will advance the program counter twice at the given step.

To emulate an error in the read value 1 or 2 `--fail-read-1/2 [step addr_original value addr_modified last_step_modified]`. This writes the given value at the given address, producing a read failure for `addr_original`. You also have to specify `addr_modified` and `last_step_modified` which are workarounds (they don't produce any real change) to generate a trace with different read `address` and `last_step` . The only way to produce a real different trace is by providing a different `value`.

## Building a program
To build your own programs follow the instructions in the [docker folder](https://github.com/FairgateLabs/bitvmx-docker-riscv32/blob/main/README.md)
