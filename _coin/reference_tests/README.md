# README 

The scripts assume you've set $CPU to point to the directory where the `BitVMX-CPU` is.
The `.c` reference tests need to conform to a standard where they take a single 
number as an input. That number is used to select a `TestCase`, which compares 
result in the CPU with the expected result for a certain test (`sha256`, `aes`, etc).

## Examples

### Compile a C file 

#### Compilation command:
```sh
./docker-build.sh sha256/sha256.c
```

The `.c` file must be inside the current directory, as it is mounted by `./docker-build` command.
The path is relative to the PWD.

ELF file will be at `$CPU/docker-riscv32/riscv32/build/coin_reference_tests`.

### Run a file in the QEMU reference

```sh
./docker-run-qemu.sh sha256.elf
```

Pass the name directly, `docker-run-qemu` knows where to look for it. 

### Run a set of tests

```sh
./test_elfs.sh --start-index 0 quicksort/quicksort_test.yaml sha256/sha256.yaml
```

You can pass as many YAML test files as you want. The script will automatically extract the ELF path from each YAML file and run comprehensive tests including:
1. **EMU execution** - Run the program in the emulator
2. **Verification** - Verify execution with Bitcoin script validation  
3. **Prove/Verify** - Run prove and verify checks to ensure both implementations match

It will start testing with an incremental index (default: 0). Use `--start-index` to change the starting index.
It writes errors to `error.log`
