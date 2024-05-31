$CC -S plainc.c
$CC -nostdlib -T link.ld entrypoint.s plainc.s -o plainc.elf
$QEMU -d in_asm -D traces.s plainc.elf