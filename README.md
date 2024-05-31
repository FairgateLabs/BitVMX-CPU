# BitVMX-CPU

This repository contains the work in progress implementation of the CPU for [BitVMX](https://bitvmx.org/).

The architecture adopted for this first version is [RISCV-32i](https://riscv.org/).


The repository contains three main components.
1. **Docker Image**: This image allows the compilation of C programs into the RISCV-32i architecture. Currently, the programs must follow specific rules regarding memory access and do not support stdlib.
2. **RISCV Emulator**: Implemented in Rust, this emulator produces the hash list and execution trace of the program. 
3. **Bitcoin Script Generator**: A Rust project responsible for generating Bitcoin scripts that validate the execution of RISCV instructions on-chain 

## Building a program
Follow the instructions in the [docker folder](docker-riscv32/README.rd)

## Emulation 
Run the compiled sample C program on the emulator.

`cargo run -p emulator docker-riscv32/plainc.elf 01`

## Bitcoin Script Validation

Run the step by step validation of the `addi` instruction on bitcoin script.

`cargo run -p bitcoin-script-riscv`
