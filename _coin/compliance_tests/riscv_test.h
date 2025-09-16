#ifndef _ENV_CUSTOM_H
#define _ENV_CUSTOM_H

#include "riscv-tests/env/p/riscv_test.h"

#undef RVTEST_CODE_BEGIN
#define RVTEST_CODE_BEGIN                                               \
        .text;                                                          \
        .global _start;                                                 \
_start:                                                                 \
        init


#endif
