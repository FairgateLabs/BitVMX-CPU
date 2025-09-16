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
  ori  t0, t0, 1             # Set LSB (force misalignment bit)
  la   t1, after_jalr_1      # Expected link address

  jalr t2, t0, 0             # Jump to t0 (LSB set), link in t2
  j    fail                  # Should never execute this if jalr works

target_1:
  # Verify we landed here with LSB cleared
  la   t3, target_1
  bne  t3, t0, fail          # This confirms t0 had correct aligned target

  # Verify return address
  bne  t2, t1, fail

after_jalr_1:

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

  TEST_DATA

RVTEST_DATA_END
