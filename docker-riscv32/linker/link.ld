ENTRY(_start)

SECTIONS
{

    .text 0x80000000: ALIGN(4) {
        *(.text)
        . = ALIGN(4);
    }

    .data 0x90000000 : ALIGN(4) {
        *(.data)
        . = ALIGN(4);
    }

    .bss 0xA0000000 :  ALIGN(4) {
        *(.bss)
        . = ALIGN(4);
    } 

    .stack 0xE0000000 :  ALIGN(4) {
        *(.stack)
        . = ALIGN(4);
    }

    .input 0xAA000000 :  ALIGN(4) {
        *(.input)
        . = ALIGN(4);
    }
    
    .registers 0xF0000000 : ALIGN(4) {
        *(.registers)
        . = ALIGN(4);
    }
    
    .rodata 0xB0000000 : ALIGN(4) {
        *(.rodata) 
        . = ALIGN(4);
    }
}
