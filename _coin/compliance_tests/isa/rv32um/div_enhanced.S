# See LICENSE for license details.

#*****************************************************************************
# div_enhanced.S
#-----------------------------------------------------------------------------
#
# Enhanced test for div instruction with comprehensive coverage.
#

#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV32U
RVTEST_CODE_BEGIN

  #-------------------------------------------------------------
  # Basic arithmetic tests
  #-------------------------------------------------------------

  TEST_RR_OP( 2, div,  3,  20,   6 );
  TEST_RR_OP( 3, div, -3, -20,   6 );
  TEST_RR_OP( 4, div, -3,  20,  -6 );
  TEST_RR_OP( 5, div,  3, -20,  -6 );

  #-------------------------------------------------------------
  # Edge cases and corner conditions
  #-------------------------------------------------------------

  # Division by 1 and -1
  TEST_RR_OP( 6, div,  42,  42,   1 );
  TEST_RR_OP( 7, div, -42,  42,  -1 );
  TEST_RR_OP( 8, div, -42, -42,   1 );
  TEST_RR_OP( 9, div,  42, -42,  -1 );

  # Division by powers of 2
  TEST_RR_OP( 10, div,  21,  42,   2 );
  TEST_RR_OP( 11, div,  10,  42,   4 );
  TEST_RR_OP( 12, div,   5,  42,   8 );
  TEST_RR_OP( 13, div,   2,  42,  16 );
  TEST_RR_OP( 14, div,   1,  42,  32 );
  TEST_RR_OP( 15, div,   0,  42,  64 );

  # Division by negative powers of 2
  TEST_RR_OP( 16, div, -21,  42,  -2 );
  TEST_RR_OP( 17, div, -10,  42,  -4 );
  TEST_RR_OP( 18, div,  -5,  42,  -8 );
  TEST_RR_OP( 19, div,  -2,  42, -16 );
  TEST_RR_OP( 20, div,  -1,  42, -32 );
  TEST_RR_OP( 21, div,   0,  42, -64 );

  #-------------------------------------------------------------
  # Large number tests
  #-------------------------------------------------------------

  # Maximum positive value
  TEST_RR_OP( 22, div,  1, 0x7fffffff, 0x7fffffff );
  TEST_RR_OP( 23, div, -1, 0x7fffffff, -0x7fffffff );
  TEST_RR_OP( 24, div,  0, 0x7fffffff, 0x80000000 );
  TEST_RR_OP( 25, div, -1, 0x7fffffff, 0x80000001 );

  # Maximum negative value
  TEST_RR_OP( 26, div,  1, 0x80000000, 0x80000000 );
  TEST_RR_OP( 27, div, 1, 0x80000000, -0x80000000 );
  TEST_RR_OP( 28, div,  -1, 0x80000000, 0x7fffffff );
  TEST_RR_OP( 29, div,  1, 0x80000000, 0x80000001 );

  #-------------------------------------------------------------
  # Division by zero tests
  #-------------------------------------------------------------

  TEST_RR_OP( 30, div, -1, -1<<31, 0 );
  TEST_RR_OP( 31, div, -1,      1, 0 );
  TEST_RR_OP( 32, div, -1,      0, 0 );

  #-------------------------------------------------------------
  # Overflow and special cases
  #-------------------------------------------------------------

  # Division that should result in overflow
  TEST_RR_OP( 34, div, -1<<31, -1<<31,  1 );
  TEST_RR_OP( 35, div, -1<<31, -1<<31, -1 );

  # Large dividend, small divisor
  TEST_RR_OP( 36, div,  0x3fffffff, 0x7fffffff,  2 );
  TEST_RR_OP( 37, div, -0x3fffffff, 0x7fffffff, -2 );
  TEST_RR_OP( 38, div,  0x1fffffff, 0x7fffffff,  4 );
  TEST_RR_OP( 39, div, -0x1fffffff, 0x7fffffff, -4 );

  # Small dividend, large divisor
  TEST_RR_OP( 40, div,  0,  1, 0x7fffffff );
  TEST_RR_OP( 41, div,  0,  1, 0x80000000 );
  TEST_RR_OP( 42, div,  0, -1, 0x7fffffff );
  TEST_RR_OP( 43, div,  0, -1, 0x80000000 );

  #-------------------------------------------------------------
  # Rounding behavior tests
  #-------------------------------------------------------------

  # Tests for truncation toward zero
  TEST_RR_OP( 44, div,  3,  7,  2 );
  TEST_RR_OP( 45, div,  4,  8,  2 );
  TEST_RR_OP( 46, div,  4,  9,  2 );
  TEST_RR_OP( 47, div, -3, -7,  2 );
  TEST_RR_OP( 48, div, -4, -8,  2 );
  TEST_RR_OP( 49, div, -4, -9,  2 );

  #-------------------------------------------------------------
  # Source/Destination tests
  #-------------------------------------------------------------

  TEST_RR_SRC1_EQ_DEST( 50, div, 3, 15, 5 );
  TEST_RR_SRC2_EQ_DEST( 51, div, 3, 15, 5 );
  TEST_RR_SRC12_EQ_DEST( 52, div, 1, 5 );

  #-------------------------------------------------------------
  # Bypassing tests
  #-------------------------------------------------------------

  TEST_RR_DEST_BYPASS( 53, 0, div, 3, 15, 5 );
  TEST_RR_DEST_BYPASS( 54, 1, div, 4, 16, 4 );
  TEST_RR_DEST_BYPASS( 55, 2, div, 5, 15, 3 );

  TEST_RR_SRC12_BYPASS( 56, 0, 0, div, 3, 15, 5 );
  TEST_RR_SRC12_BYPASS( 57, 0, 1, div, 4, 16, 4 );
  TEST_RR_SRC12_BYPASS( 58, 0, 2, div, 5, 15, 3 );
  TEST_RR_SRC12_BYPASS( 59, 1, 0, div, 3, 15, 5 );
  TEST_RR_SRC12_BYPASS( 60, 1, 1, div, 4, 16, 4 );
  TEST_RR_SRC12_BYPASS( 61, 2, 0, div, 5, 15, 3 );

  TEST_RR_SRC21_BYPASS( 62, 0, 0, div, 3, 15, 5 );
  TEST_RR_SRC21_BYPASS( 63, 0, 1, div, 4, 16, 4 );
  TEST_RR_SRC21_BYPASS( 64, 0, 2, div, 5, 15, 3 );
  TEST_RR_SRC21_BYPASS( 65, 1, 0, div, 3, 15, 5 );
  TEST_RR_SRC21_BYPASS( 66, 1, 1, div, 4, 16, 4 );
  TEST_RR_SRC21_BYPASS( 67, 2, 0, div, 5, 15, 3 );

  #-------------------------------------------------------------
  # Zero operand tests
  #-------------------------------------------------------------

  TEST_RR_ZEROSRC1( 68, div, 0, 31 );
  TEST_RR_ZEROSRC2( 69, div, -1, 0 );
  TEST_RR_ZEROSRC12( 70, div, -1 );
  TEST_RR_ZERODEST( 71, div, 33, 34 );

  #-------------------------------------------------------------
  # Additional stress tests
  #-------------------------------------------------------------

  # Various combinations of large numbers
  TEST_RR_OP( 72, div,  0x00000001, 0x7fffffff, 0x7fffffff );
  TEST_RR_OP( 73, div,  0x00000000, 0x7fffffff, 0x80000000 );
  TEST_RR_OP( 74, div,  -1, 0x80000000, 0x7fffffff );
  TEST_RR_OP( 75, div,  0x00000001, 0x80000000, 0x80000000 );

  #-------------------------------------------------------------
  # Boundary value tests
  #-------------------------------------------------------------

  # Values around zero
  TEST_RR_OP( 76, div,  0,  0,  1 );
  TEST_RR_OP( 77, div,  0,  0, -1 );
  TEST_RR_OP( 78, div,  0,  0,  0x7fffffff );
  TEST_RR_OP( 79, div,  0,  0, 0x80000000 );

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

  TEST_DATA

RVTEST_DATA_END 