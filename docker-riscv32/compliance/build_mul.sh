$CC -static -march=rv32g -mabi=ilp32 -nostdlib -nostartfiles -Wl,--no-warn-rwx-segments -I./ -I./../../ -I/riscv-tests/isa/macros/scalar/ -T../linker/link.ld -o build/$1.elf /riscv-tests/isa/rv32um/$1.S
$QEMU -d in_asm -D build/$1.s build/$1.elf
$DUMP -d build/$1.elf > build/$1_dump.s
