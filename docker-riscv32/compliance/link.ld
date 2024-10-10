ENTRY(_start)

SECTIONS
{

    .text 0x80000000: {
        *(.text)
    }

    .data 0x90000000 : {
        *(.data)
    }

    .bss 0xA0000000 : {
        *(.bss)
    } 

}
