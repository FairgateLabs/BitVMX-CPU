#include <stdint.h>
#include "emulator.h"

int main(int x) {

    int* z = (int*)INPUT_ADDRESS;

    if (*z != 0x00001234) {
        return 0x1;
    }

    z++;
    if (*z != 0xdeadbeef) {
        return 0x2;
    }


    return 0x0;

}
