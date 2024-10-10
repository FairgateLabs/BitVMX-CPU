$CC -S -march=rv32im plainc.c
$CC -nostdlib -march=rv32im  -T link.ld entrypoint.s plainc.c -o plainc.elf
$QEMU -d in_asm -D traces.s plainc.elf