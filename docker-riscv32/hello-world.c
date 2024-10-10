#include <stdint.h>
#include "emulator.h"

int main(int x) {

    int* z = (int*)INPUT_ADDRESS;

    print_literal("Hello world! if you run with the right input, it will return 0\n", 63);
    if (*z == 0x11111111) {
        print_literal("Your input is right!\n", 21);
        return 0;
    } else {
        print_literal("Try again\n", 10);
        return 1;
    }

}

