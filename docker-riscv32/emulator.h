#define INPUT_ADDRESS 0xA0000000
#define INPUT_SIZE 0x1000

#define STDOOUT_ADDRESS 0xA0001000

void print_literal( char* str, int len ) {
    char* addr = (char*)STDOOUT_ADDRESS;
    addr += 3; // just use the last byte

    for (int i = 0; i < len; i+=4) {
        for (int j = 3; j >= 0; j--) {
            if (i + 3-j < len) {
                *addr = str[i+j];
                __asm__ ( "li a7, 116" );
                __asm__ ( "ecall" );
            }
        }
    }
}