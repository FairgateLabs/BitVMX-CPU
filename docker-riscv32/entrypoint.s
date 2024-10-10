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


.section .stack, "aw", @nobits
.globl _stack_start
_stack_start:
.space 0x800000

# reserved space section for input 0x1000 + one word as stdout
.section .bss
.space 4100

.section .input, "aw", @nobits
.skip 0x2000

.section .registers, "aw", @nobits
.skip 0x200
