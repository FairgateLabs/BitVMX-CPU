# See LICENSE for license details.

#*****************************************************************************
# jalr.S
#-----------------------------------------------------------------------------
#
# Test jalr instruction.
#

#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV64U
RVTEST_CODE_BEGIN

  #------------------------------------------------------------
  # Test 1: JALR clears least-significant bit of target address
  #-------------------------------------------------------------

test_1:
  li  TESTNUM, 1

  la   t0, target_1          # Load target address
  ori  t1, t0, 1             # Set LSB (force misalignment bit)

  jalr x1, t1, 0             # Jump to t1 (LSB set), link in x1

  # Verify return address
  auipc t2, 0
  bne t2, x1, fail

  TEST_PASSFAIL

target_1:
  # Verify we landed here with LSB cleared
  auipc t3, 0
  bne  t3, t0, fail          # This confirms t0 had correct aligned target

  ret

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

  TEST_DATA

RVTEST_DATA_END
