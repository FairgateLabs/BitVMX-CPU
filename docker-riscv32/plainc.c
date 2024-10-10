#include <stdint.h>
#include "emulator.h"

int main(int x) {
    x++;
	//testing section limits
    int* z = (int*)INPUT_ADDRESS;
    z += 0x1000 / 4;
    z--;
    *z = 10;

    int a = 10;
    int b = 20;
    int c = a + b;
    int d = a - b;
    int e = a ^ b;
    int f = a & b;
    int g = a | b;
    int multiplied = a * b;
    if (multiplied != 200) {
        return 0xeeee;
    }

    /* TODO: fix docker to get muldi3
    unsigned int aa = 0xffffffff;
    unsigned int bb = 0xffffffff;
    unsigned long long int mul_64 = (unsigned long long int)aa * (unsigned long long int)bb;
    if (mul_64 != 0xfffffffe00000001) {
        return 0xffff;
    }*/
    int div = a / b;
    int mod = a % b;

    int e1 = a ^ 0x123;
    int f1 = a & 0x123;
    int g1 = a | 0x123;

    //test sw missaligned
    int* z2 = (int*)(INPUT_ADDRESS + 5);
    *z2 = 0x01020304;

    //test sh middle
    short* y = (short*)(INPUT_ADDRESS + 0xd);
    *y = 0x1234;

    //test sh two words
    short* y2 = (short*)(INPUT_ADDRESS + 0x13); 
    *y2 = 0xAABB;

    //test bytes
    char* y3 = (char*)INPUT_ADDRESS + 0x18;
    *y3 = 0x11; y3++;
    *y3 = 0x22; y3++;
    *y3 = 0x33; y3++;
    *y3 = 0x44; y3++;
    

    char* y4 = (char*)INPUT_ADDRESS + 0x20;
    char a1 = *y4;

    //uint8_t* y5 = (uint8_t*)0xA0000020;
    //uint8_t a2 = *y4;


    //volatile uint8_t *addr = (uint8_t *)0xA0000020;
    //uint8_t value;
    //__asm__ volatile (
    //    "lb %0, 0(%1)"
    //    : "=r" (value)  /* output: 'value' will hold the loaded byte */
    //    : "r" (addr)    /* input: 'addr' is the address from which to load */
    //    :               /* No clobbered registers */
    //);

    //__asm__ ( "Ebreak" );

    print_literal("Hello world\n", 12);

    char bxxx = 0;
    char cxxx = 1;
    if (bxxx > cxxx) 
        return 0x12345678;
    
    return 0x87654321;
}
