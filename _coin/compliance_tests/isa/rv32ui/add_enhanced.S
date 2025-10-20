
# See LICENSE for license details.

#*****************************************************************************
# add_enhanced.S
#-----------------------------------------------------------------------------
#
# Enhanced test for add instruction with comprehensive coverage.
#

#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV32U
RVTEST_CODE_BEGIN

  #-------------------------------------------------------------
  # Basic arithmetic tests
  #-------------------------------------------------------------

  TEST_RR_OP( 2,  add, 0x00000000, 0x00000000, 0x00000000 );
  TEST_RR_OP( 3,  add, 0x00000002, 0x00000001, 0x00000001 );
  TEST_RR_OP( 4,  add, 0x0000000a, 0x00000003, 0x00000007 );

  #-------------------------------------------------------------
  # Edge cases and corner conditions
  #-------------------------------------------------------------

  # Addition with zero
  TEST_RR_OP( 5,  add, 0x00000042, 0x00000042, 0x00000000 );
  TEST_RR_OP( 6,  add, 0x00000042, 0x00000000, 0x00000042 );
  TEST_RR_OP( 7,  add, 0x00000000, 0x00000000, 0x00000000 );

  # Addition with 1
  TEST_RR_OP( 8,  add, 0x00000043, 0x00000042, 0x00000001 );
  TEST_RR_OP( 9,  add, 0x00000043, 0x00000001, 0x00000042 );
  TEST_RR_OP( 10, add, 0x00000002, 0x00000001, 0x00000001 );

  # Addition with -1
  TEST_RR_OP( 11, add, 0x00000041, 0x00000042, 0xffffffff );
  TEST_RR_OP( 12, add, 0x00000041, 0xffffffff, 0x00000042 );
  TEST_RR_OP( 13, add, 0xfffffffe, 0xffffffff, 0xffffffff );

  #-------------------------------------------------------------
  # Overflow and wrapping tests
  #-------------------------------------------------------------

  # Positive overflow
  TEST_RR_OP( 14, add, 0x80000000, 0x7fffffff, 0x00000001 );
  TEST_RR_OP( 15, add, 0x80000001, 0x7fffffff, 0x00000002 );
  TEST_RR_OP( 16, add, 0x80000002, 0x7fffffff, 0x00000003 );

  # Negative overflow
  TEST_RR_OP( 17, add, 0x7fffffff, 0x80000000, 0xffffffff );
  TEST_RR_OP( 18, add, 0x7ffffffe, 0x80000000, 0xfffffffe );
  TEST_RR_OP( 19, add, 0x7ffffffd, 0x80000000, 0xfffffffd );

  #-------------------------------------------------------------
  # Large number tests
  #-------------------------------------------------------------

  # Maximum positive value
  TEST_RR_OP( 20, add, 0xfffffffe, 0x7fffffff, 0x7fffffff );
  TEST_RR_OP( 21, add, 0x7fffffff, 0x7fffffff, 0x00000000 );
  TEST_RR_OP( 22, add, 0x80000000, 0x7fffffff, 0x00000001 );

  # Maximum negative value
  TEST_RR_OP( 23, add, 0x00000000, 0x80000000, 0x80000000 );
  TEST_RR_OP( 24, add, 0x7fffffff, 0x80000000, 0xffffffff );
  TEST_RR_OP( 25, add, 0x7ffffffe, 0x80000000, 0xfffffffe );

  #-------------------------------------------------------------
  # Special value tests
  #-------------------------------------------------------------

  # All ones patterns
  TEST_RR_OP( 26, add, 0xfffffffe, 0xffffffff, 0xffffffff );
  TEST_RR_OP( 27, add, 0x00000000, 0xffffffff, 0x00000001 );
  TEST_RR_OP( 28, add, 0x00000001, 0xffffffff, 0x00000002 );

  # Alternating bit patterns
  TEST_RR_OP( 29, add, 0xaaaaaaaa, 0x55555555, 0x55555555 );
  TEST_RR_OP( 31, add, 0xffffffff, 0x55555555, 0xaaaaaaaa );

  #-------------------------------------------------------------
  # Power of 2 tests
  #-------------------------------------------------------------

  # Addition with powers of 2
  TEST_RR_OP( 32, add, 0x00000002, 0x00000001, 0x00000001 );
  TEST_RR_OP( 33, add, 0x00000004, 0x00000002, 0x00000002 );
  TEST_RR_OP( 34, add, 0x00000008, 0x00000004, 0x00000004 );
  TEST_RR_OP( 35, add, 0x00000010, 0x00000008, 0x00000008 );
  TEST_RR_OP( 36, add, 0x00000020, 0x00000010, 0x00000010 );
  TEST_RR_OP( 37, add, 0x00000040, 0x00000020, 0x00000020 );
  TEST_RR_OP( 38, add, 0x00000080, 0x00000040, 0x00000040 );
  TEST_RR_OP( 39, add, 0x00000100, 0x00000080, 0x00000080 );

  #-------------------------------------------------------------
  # Source/Destination tests
  #-------------------------------------------------------------

  TEST_RR_SRC1_EQ_DEST( 40, add, 24, 13, 11 );
  TEST_RR_SRC2_EQ_DEST( 41, add, 25, 14, 11 );
  TEST_RR_SRC12_EQ_DEST( 42, add, 26, 13 );

  #-------------------------------------------------------------
  # Zero operand tests
  #-------------------------------------------------------------

  TEST_RR_ZEROSRC1( 58, add, 15, 15 );
  TEST_RR_ZEROSRC2( 59, add, 32, 32 );
  TEST_RR_ZEROSRC12( 60, add, 0 );
  TEST_RR_ZERODEST( 61, add, 16, 30 );

  #-------------------------------------------------------------
  # Additional edge cases
  #-------------------------------------------------------------

  # Values around maximum and minimum
  TEST_RR_OP( 62, add, 0x7fffffff, 0x7ffffffe, 0x00000001 );
  TEST_RR_OP( 63, add, 0x80000000, 0x7fffffff, 0x00000001 );
  TEST_RR_OP( 64, add, 0x80000001, 0x7fffffff, 0x00000002 );
  TEST_RR_OP( 65, add, 0x7fffffff, 0x80000000, 0xffffffff );
  TEST_RR_OP( 66, add, 0x7ffffffe, 0x80000000, 0xfffffffe );
  TEST_RR_OP( 67, add, 0x7ffffffd, 0x80000000, 0xfffffffd );

  #-------------------------------------------------------------
  # Stress tests with large numbers
  #-------------------------------------------------------------

  # Large positive numbers
  TEST_RR_OP( 68, add, 0x0000fffe, 0x00007fff, 0x00007fff );
  TEST_RR_OP( 69, add, 0x00010000, 0x00007fff, 0x00008001 );
  TEST_RR_OP( 70, add, 0x00010001, 0x00007fff, 0x00008002 );

  # Large negative numbers
  TEST_RR_OP( 71, add, 0xffff0000, 0xffff8000, 0xffff8000 );
  TEST_RR_OP( 72, add, 0xfffeffff, 0xffff8000, 0xffff7fff );
  TEST_RR_OP( 73, add, 0xfffefffe, 0xffff8000, 0xffff7ffe );

  #-------------------------------------------------------------
  # Boundary value tests
  #-------------------------------------------------------------

  # Values around zero
  TEST_RR_OP( 74, add, 0x00000001, 0x00000000, 0x00000001 );
  TEST_RR_OP( 75, add, 0x00000001, 0x00000001, 0x00000000 );
  TEST_RR_OP( 76, add, 0xffffffff, 0x00000000, 0xffffffff );
  TEST_RR_OP( 77, add, 0xffffffff, 0xffffffff, 0x00000000 );

  # Values around 1 and -1
  TEST_RR_OP( 78, add, 0x00000002, 0x00000001, 0x00000001 );
  TEST_RR_OP( 79, add, 0x00000000, 0x00000001, 0xffffffff );
  TEST_RR_OP( 80, add, 0x00000000, 0xffffffff, 0x00000001 );
  TEST_RR_OP( 81, add, 0xfffffffe, 0xffffffff, 0xffffffff );

  #-------------------------------------------------------------
  # Carry propagation tests
  #-------------------------------------------------------------

  # Tests for carry propagation through multiple bits
  TEST_RR_OP( 82, add, 0x00000000, 0x00000001, 0xffffffff );
  TEST_RR_OP( 83, add, 0x00000000, 0x00000002, 0xfffffffe );
  TEST_RR_OP( 84, add, 0x00000000, 0x00000004, 0xfffffffc );
  TEST_RR_OP( 85, add, 0x00000000, 0x00000008, 0xfffffff8 );
  TEST_RR_OP( 86, add, 0x00000000, 0x00000010, 0xfffffff0 );
  TEST_RR_OP( 87, add, 0x00000000, 0x00000020, 0xffffffe0 );
  TEST_RR_OP( 88, add, 0x00000000, 0x00000040, 0xffffffc0 );
  TEST_RR_OP( 89, add, 0x00000000, 0x00000080, 0xffffff80 );

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

  TEST_DATA

RVTEST_DATA_END 