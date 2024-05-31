.section .text._start;
.globl _start;
_start:

	li a0, 0	# set 0 as calling argument
	call main
	j _halt

_halt:


	li a7, 93
	ecall


# data section
.section .data
my_data:
    .word 0xDEADBEEF


# reserved space section for input 0x1000 + one word as stdout
.section .bss
.space 4100
