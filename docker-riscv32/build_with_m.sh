$CC -S -march=rv32im -mabi=ilp32 plainc.c
$CC -nostdlib -march=rv32im -mabi=ilp32 -T link.ld entrypoint.s plainc.c -o plainc.elf
$QEMU -d in_asm -D traces.s plainc.elf