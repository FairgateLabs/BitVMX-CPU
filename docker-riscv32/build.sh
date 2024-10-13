#!/bin/bash

# Check if the input file argument is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <input_filename>"
    exit 1
fi

# Extract the input file name without extension
input_file=$1
base_name=$(basename "$input_file" .c)

# Generate assembly from the input file
$CC -march=rv32i -mabi=ilp32 -S "$input_file" -o "${base_name}.s"

# Generate assembly for mulsi3.c
$CC -march=rv32i -mabi=ilp32 -S /src/mulsi3.c -o /src/mulsi3.s

# Link the necessary files into an ELF executable
$CC -march=rv32i -mabi=ilp32 -nostdlib -T link.ld /src/div.S /src/mulsi3.s entrypoint.s "$input_file" -o "${base_name}.elf"

# Run the ELF with QEMU
$QEMU -d in_asm -D "${base_name}.s" "${base_name}.elf"

