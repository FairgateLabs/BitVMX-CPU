# See LICENSE for license details.

#*****************************************************************************
# beq_enhanced.S
#-----------------------------------------------------------------------------
#
# Enhanced test for beq instruction with comprehensive coverage.
#

#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV32U
RVTEST_CODE_BEGIN

  #-------------------------------------------------------------
  # Basic branch tests
  #-------------------------------------------------------------

  # Each test checks both forward and backward branches

  TEST_BR2_OP_TAKEN( 2, beq,  0,  0 );
  TEST_BR2_OP_TAKEN( 3, beq,  1,  1 );
  TEST_BR2_OP_TAKEN( 4, beq, -1, -1 );

  TEST_BR2_OP_NOTTAKEN( 5, beq,  0,  1 );
  TEST_BR2_OP_NOTTAKEN( 6, beq,  1,  0 );
  TEST_BR2_OP_NOTTAKEN( 7, beq, -1,  1 );
  TEST_BR2_OP_NOTTAKEN( 8, beq,  1, -1 );

  #-------------------------------------------------------------
  # Edge cases and corner conditions
  #-------------------------------------------------------------

  # Zero comparisons
  TEST_BR2_OP_TAKEN( 9, beq,  0,  0 );
  TEST_BR2_OP_NOTTAKEN( 10, beq,  0,  1 );
  TEST_BR2_OP_NOTTAKEN( 11, beq,  0, -1 );
  TEST_BR2_OP_NOTTAKEN( 12, beq,  1,  0 );
  TEST_BR2_OP_NOTTAKEN( 13, beq, -1,  0 );

  # Maximum and minimum values
  TEST_BR2_OP_TAKEN( 14, beq, 0x7fffffff, 0x7fffffff );
  TEST_BR2_OP_TAKEN( 15, beq, 0x80000000, 0x80000000 );
  TEST_BR2_OP_NOTTAKEN( 16, beq, 0x7fffffff, 0x80000000 );
  TEST_BR2_OP_NOTTAKEN( 17, beq, 0x80000000, 0x7fffffff );

  # All ones patterns
  TEST_BR2_OP_TAKEN( 18, beq, 0xffffffff, 0xffffffff );
  TEST_BR2_OP_NOTTAKEN( 19, beq, 0xffffffff, 0x00000000 );
  TEST_BR2_OP_NOTTAKEN( 20, beq, 0x00000000, 0xffffffff );

  # Alternating bit patterns
  TEST_BR2_OP_TAKEN( 21, beq, 0x55555555, 0x55555555 );
  TEST_BR2_OP_TAKEN( 22, beq, 0xaaaaaaaa, 0xaaaaaaaa );
  TEST_BR2_OP_NOTTAKEN( 23, beq, 0x55555555, 0xaaaaaaaa );
  TEST_BR2_OP_NOTTAKEN( 24, beq, 0xaaaaaaaa, 0x55555555 );

  #-------------------------------------------------------------
  # Power of 2 tests
  #-------------------------------------------------------------

  # Powers of 2 comparisons
  TEST_BR2_OP_TAKEN( 25, beq, 0x00000001, 0x00000001 );
  TEST_BR2_OP_TAKEN( 26, beq, 0x00000002, 0x00000002 );
  TEST_BR2_OP_TAKEN( 27, beq, 0x00000004, 0x00000004 );
  TEST_BR2_OP_TAKEN( 28, beq, 0x00000008, 0x00000008 );
  TEST_BR2_OP_TAKEN( 29, beq, 0x00000010, 0x00000010 );
  TEST_BR2_OP_TAKEN( 30, beq, 0x00000020, 0x00000020 );
  TEST_BR2_OP_TAKEN( 31, beq, 0x00000040, 0x00000040 );
  TEST_BR2_OP_TAKEN( 32, beq, 0x00000080, 0x00000080 );

  # Different powers of 2
  TEST_BR2_OP_NOTTAKEN( 33, beq, 0x00000001, 0x00000002 );
  TEST_BR2_OP_NOTTAKEN( 34, beq, 0x00000002, 0x00000004 );
  TEST_BR2_OP_NOTTAKEN( 35, beq, 0x00000004, 0x00000008 );
  TEST_BR2_OP_NOTTAKEN( 36, beq, 0x00000008, 0x00000010 );

  #-------------------------------------------------------------
  # Large number tests
  #-------------------------------------------------------------

  # Large positive numbers
  TEST_BR2_OP_TAKEN( 37, beq, 0x0000ffff, 0x0000ffff );
  TEST_BR2_OP_TAKEN( 38, beq, 0x00010000, 0x00010000 );
  TEST_BR2_OP_TAKEN( 39, beq, 0x00020000, 0x00020000 );
  TEST_BR2_OP_NOTTAKEN( 40, beq, 0x0000ffff, 0x00010000 );
  TEST_BR2_OP_NOTTAKEN( 41, beq, 0x00010000, 0x00020000 );

  # Large negative numbers
  TEST_BR2_OP_TAKEN( 42, beq, 0xffff0000, 0xffff0000 );
  TEST_BR2_OP_TAKEN( 43, beq, 0xfffe0000, 0xfffe0000 );
  TEST_BR2_OP_TAKEN( 44, beq, 0xfffc0000, 0xfffc0000 );
  TEST_BR2_OP_NOTTAKEN( 45, beq, 0xffff0000, 0xfffe0000 );
  TEST_BR2_OP_NOTTAKEN( 46, beq, 0xfffe0000, 0xfffc0000 );

  #-------------------------------------------------------------
  # Bypassing tests
  #-------------------------------------------------------------

  TEST_BR2_SRC12_BYPASS( 47,  0, 0, beq, 0, -1 );
  TEST_BR2_SRC12_BYPASS( 48,  0, 1, beq, 0, -1 );
  TEST_BR2_SRC12_BYPASS( 49,  0, 2, beq, 0, -1 );
  TEST_BR2_SRC12_BYPASS( 50,  1, 0, beq, 0, -1 );
  TEST_BR2_SRC12_BYPASS( 51,  1, 1, beq, 0, -1 );
  TEST_BR2_SRC12_BYPASS( 52,  2, 0, beq, 0, -1 );

  TEST_BR2_SRC12_BYPASS( 53,  0, 0, beq, 0, -1 );
  TEST_BR2_SRC12_BYPASS( 54,  0, 1, beq, 0, -1 );
  TEST_BR2_SRC12_BYPASS( 55,  0, 2, beq, 0, -1 );
  TEST_BR2_SRC12_BYPASS( 56,  1, 0, beq, 0, -1 );
  TEST_BR2_SRC12_BYPASS( 57,  1, 1, beq, 0, -1 );
  TEST_BR2_SRC12_BYPASS( 58,  2, 0, beq, 0, -1 );

  #-------------------------------------------------------------
  # Test delay slot instructions not executed nor bypassed
  #-------------------------------------------------------------

  TEST_CASE( 59, x1, 3, \
    li  x1, 1; \
    beq x0, x0, 1f; \
    addi x1, x1, 1; \
    addi x1, x1, 1; \
    addi x1, x1, 1; \
    addi x1, x1, 1; \
1:  addi x1, x1, 1; \
    addi x1, x1, 1; \
  )

  #-------------------------------------------------------------
  # Additional edge cases
  #-------------------------------------------------------------

  # Values around zero
  TEST_BR2_OP_TAKEN( 60, beq, 0x00000000, 0x00000000 );
  TEST_BR2_OP_NOTTAKEN( 61, beq, 0x00000000, 0x00000001 );
  TEST_BR2_OP_NOTTAKEN( 62, beq, 0x00000000, 0xffffffff );
  TEST_BR2_OP_NOTTAKEN( 63, beq, 0x00000001, 0x00000000 );
  TEST_BR2_OP_NOTTAKEN( 64, beq, 0xffffffff, 0x00000000 );

  # Values around 1 and -1
  TEST_BR2_OP_TAKEN( 65, beq, 0x00000001, 0x00000001 );
  TEST_BR2_OP_TAKEN( 66, beq, 0xffffffff, 0xffffffff );
  TEST_BR2_OP_NOTTAKEN( 67, beq, 0x00000001, 0xffffffff );
  TEST_BR2_OP_NOTTAKEN( 68, beq, 0xffffffff, 0x00000001 );

  #-------------------------------------------------------------
  # Stress tests with various patterns
  #-------------------------------------------------------------

  # Byte patterns
  TEST_BR2_OP_TAKEN( 69, beq, 0x000000ff, 0x000000ff );
  TEST_BR2_OP_TAKEN( 70, beq, 0x0000ff00, 0x0000ff00 );
  TEST_BR2_OP_TAKEN( 71, beq, 0x00ff0000, 0x00ff0000 );
  TEST_BR2_OP_TAKEN( 72, beq, 0xff000000, 0xff000000 );
  TEST_BR2_OP_NOTTAKEN( 73, beq, 0x000000ff, 0x0000ff00 );
  TEST_BR2_OP_NOTTAKEN( 74, beq, 0x0000ff00, 0x00ff0000 );
  TEST_BR2_OP_NOTTAKEN( 75, beq, 0x00ff0000, 0xff000000 );

  # Halfword patterns
  TEST_BR2_OP_TAKEN( 76, beq, 0x0000ffff, 0x0000ffff );
  TEST_BR2_OP_TAKEN( 77, beq, 0xffff0000, 0xffff0000 );
  TEST_BR2_OP_NOTTAKEN( 78, beq, 0x0000ffff, 0xffff0000 );
  TEST_BR2_OP_NOTTAKEN( 79, beq, 0xffff0000, 0x0000ffff );

  #-------------------------------------------------------------
  # Boundary value tests
  #-------------------------------------------------------------

  # Values just below and above maximum/minimum
  TEST_BR2_OP_TAKEN( 80, beq, 0x7ffffffe, 0x7ffffffe );
  TEST_BR2_OP_TAKEN( 81, beq, 0x7fffffff, 0x7fffffff );
  TEST_BR2_OP_TAKEN( 82, beq, 0x80000000, 0x80000000 );
  TEST_BR2_OP_TAKEN( 83, beq, 0x80000001, 0x80000001 );
  TEST_BR2_OP_NOTTAKEN( 84, beq, 0x7ffffffe, 0x7fffffff );
  TEST_BR2_OP_NOTTAKEN( 85, beq, 0x7fffffff, 0x80000000 );
  TEST_BR2_OP_NOTTAKEN( 86, beq, 0x80000000, 0x80000001 );

  #-------------------------------------------------------------
  # Special pattern tests
  #-------------------------------------------------------------

  # Gray code patterns
  TEST_BR2_OP_TAKEN( 87, beq, 0x00000001, 0x00000001 );
  TEST_BR2_OP_TAKEN( 88, beq, 0x00000003, 0x00000003 );
  TEST_BR2_OP_TAKEN( 89, beq, 0x00000002, 0x00000002 );
  TEST_BR2_OP_TAKEN( 90, beq, 0x00000006, 0x00000006 );
  TEST_BR2_OP_NOTTAKEN( 91, beq, 0x00000001, 0x00000003 );
  TEST_BR2_OP_NOTTAKEN( 92, beq, 0x00000003, 0x00000002 );
  TEST_BR2_OP_NOTTAKEN( 93, beq, 0x00000002, 0x00000006 );

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

  TEST_DATA

RVTEST_DATA_END 