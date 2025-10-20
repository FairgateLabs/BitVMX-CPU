# See LICENSE for license details.

#*****************************************************************************
# rem_enhanced.S
#-----------------------------------------------------------------------------
#
# Enhanced test for rem instruction with comprehensive coverage.
#

#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV32U
RVTEST_CODE_BEGIN

  #-------------------------------------------------------------
  # Basic arithmetic tests
  #-------------------------------------------------------------

  TEST_RR_OP( 2, rem,  2,  20,   6 );
  TEST_RR_OP( 3, rem, -2, -20,   6 );
  TEST_RR_OP( 4, rem,  2,  20,  -6 );
  TEST_RR_OP( 5, rem, -2, -20,  -6 );

  #-------------------------------------------------------------
  # Edge cases and corner conditions
  #-------------------------------------------------------------

  # Remainder with 1 and -1
  TEST_RR_OP( 6, rem,  0,  42,   1 );
  TEST_RR_OP( 7, rem,  0,  42,  -1 );
  TEST_RR_OP( 8, rem,  0, -42,   1 );
  TEST_RR_OP( 9, rem,  0, -42,  -1 );

  # Remainder with powers of 2
  TEST_RR_OP( 10, rem,  0,  42,   2 );
  TEST_RR_OP( 11, rem,  2,  42,   4 );
  TEST_RR_OP( 12, rem,  2,  42,   8 );
  TEST_RR_OP( 13, rem, 10,  42,  16 );
  TEST_RR_OP( 14, rem, 10,  42,  32 );
  TEST_RR_OP( 15, rem, 42,  42,  64 );

  # Remainder with negative powers of 2
  TEST_RR_OP( 16, rem,  0,  42,  -2 );
  TEST_RR_OP( 17, rem,  2,  42,  -4 );
  TEST_RR_OP( 18, rem,  2,  42,  -8 );
  TEST_RR_OP( 19, rem, 10,  42, -16 );
  TEST_RR_OP( 20, rem, 10,  42, -32 );
  TEST_RR_OP( 21, rem, 42,  42, -64 );

  #-------------------------------------------------------------
  # Large number tests
  #-------------------------------------------------------------

  # Maximum positive value
  TEST_RR_OP( 22, rem,  0, 0x7fffffff, 0x7fffffff );
  TEST_RR_OP( 23, rem,  0, 0x7fffffff, -0x7fffffff );
  TEST_RR_OP( 24, rem, 0x7fffffff, 0x7fffffff, 0x80000000 );
  TEST_RR_OP( 25, rem,  0, 0x7fffffff, 0x80000001 );

  # Maximum negative value
  TEST_RR_OP( 26, rem,  0, 0x80000000, 0x80000000 );
  TEST_RR_OP( 27, rem,  0, 0x80000000, -0x80000000 );
  TEST_RR_OP( 28, rem, -1, 0x80000000, 0x7fffffff );
  TEST_RR_OP( 29, rem, -1, 0x80000000, 0x80000001 );

  #-------------------------------------------------------------
  # Division by zero tests
  #-------------------------------------------------------------

  TEST_RR_OP( 30, rem, -1<<31, -1<<31, 0 );
  TEST_RR_OP( 31, rem,      1,      1, 0 );
  TEST_RR_OP( 32, rem,      0,      0, 0 );
  TEST_RR_OP( 33, rem,    0,    100, -1 );

  #-------------------------------------------------------------
  # Overflow and special cases
  #-------------------------------------------------------------

  # Large dividend, small divisor
  TEST_RR_OP( 34, rem,  1, 0x7fffffff,  2 );
  TEST_RR_OP( 35, rem,  1, 0x7fffffff, -2 );
  TEST_RR_OP( 36, rem,  3, 0x7fffffff,  4 );
  TEST_RR_OP( 37, rem,  3, 0x7fffffff, -4 );

  # Small dividend, large divisor
  TEST_RR_OP( 38, rem,  1,  1, 0x7fffffff );
  TEST_RR_OP( 39, rem,  1,  1, 0x80000000 );
  TEST_RR_OP( 40, rem, -1, -1, 0x7fffffff );
  TEST_RR_OP( 41, rem, -1, -1, 0x80000000 );

  #-------------------------------------------------------------
  # Remainder behavior tests
  #-------------------------------------------------------------

  # Tests for remainder sign behavior
  TEST_RR_OP( 42, rem,  1,  7,  2 );
  TEST_RR_OP( 43, rem,  0,  8,  2 );
  TEST_RR_OP( 44, rem,  1,  9,  2 );
  TEST_RR_OP( 45, rem, -1, -7,  2 );
  TEST_RR_OP( 46, rem,  0, -8,  2 );
  TEST_RR_OP( 47, rem, -1, -9,  2 );

  #-------------------------------------------------------------
  # Source/Destination tests
  #-------------------------------------------------------------

  TEST_RR_SRC1_EQ_DEST( 48, rem, 0, 15, 5 );
  TEST_RR_SRC2_EQ_DEST( 49, rem, 0, 15, 5 );
  TEST_RR_SRC12_EQ_DEST( 50, rem, 0, 5 );

  #-------------------------------------------------------------
  # Bypassing tests
  #-------------------------------------------------------------

  TEST_RR_DEST_BYPASS( 51, 0, rem, 0, 15, 5 );
  TEST_RR_DEST_BYPASS( 52, 1, rem, 0, 16, 4 );
  TEST_RR_DEST_BYPASS( 53, 2, rem, 0, 15, 3 );

  TEST_RR_SRC12_BYPASS( 54, 0, 0, rem, 0, 15, 5 );
  TEST_RR_SRC12_BYPASS( 55, 0, 1, rem, 0, 16, 4 );
  TEST_RR_SRC12_BYPASS( 56, 0, 2, rem, 0, 15, 3 );
  TEST_RR_SRC12_BYPASS( 57, 1, 0, rem, 0, 15, 5 );
  TEST_RR_SRC12_BYPASS( 58, 1, 1, rem, 0, 16, 4 );
  TEST_RR_SRC12_BYPASS( 59, 2, 0, rem, 0, 15, 3 );

  TEST_RR_SRC21_BYPASS( 60, 0, 0, rem, 0, 15, 5 );
  TEST_RR_SRC21_BYPASS( 61, 0, 1, rem, 0, 16, 4 );
  TEST_RR_SRC21_BYPASS( 62, 0, 2, rem, 0, 15, 3 );
  TEST_RR_SRC21_BYPASS( 63, 1, 0, rem, 0, 15, 5 );
  TEST_RR_SRC21_BYPASS( 64, 1, 1, rem, 0, 16, 4 );
  TEST_RR_SRC21_BYPASS( 65, 2, 0, rem, 0, 15, 3 );

  #-------------------------------------------------------------
  # Zero operand tests
  #-------------------------------------------------------------

  TEST_RR_ZEROSRC1( 66, rem, 0, 31 );
  TEST_RR_ZEROSRC2( 67, rem, -1, -1 );
  TEST_RR_ZEROSRC12( 68, rem, 0 );
  TEST_RR_ZERODEST( 69, rem, 33, 34 );

  #-------------------------------------------------------------
  # Additional stress tests
  #-------------------------------------------------------------

  # Various combinations of large numbers
  TEST_RR_OP( 70, rem,  0, 0x7fffffff, 0x7fffffff );
  TEST_RR_OP( 71, rem, 0x7fffffff, 0x7fffffff, 0x80000000 );
  TEST_RR_OP( 72, rem, -1, 0x80000000, 0x7fffffff );
  TEST_RR_OP( 73, rem,  0, 0x80000000, 0x80000000 );

  #-------------------------------------------------------------
  # Boundary value tests
  #-------------------------------------------------------------

  # Values around zero
  TEST_RR_OP( 74, rem,  0,  0,  1 );
  TEST_RR_OP( 75, rem,  0,  0, -1 );
  TEST_RR_OP( 76, rem,  0,  0,  0x7fffffff );
  TEST_RR_OP( 77, rem,  0,  0, 0x80000000 );

  # Values around 1 and -1
  TEST_RR_OP( 78, rem,  0,  1,  1 );
  TEST_RR_OP( 79, rem,  0,  1, -1 );
  TEST_RR_OP( 80, rem,  0, -1,  1 );
  TEST_RR_OP( 81, rem,  0, -1, -1 );

  #-------------------------------------------------------------
  # Specific remainder patterns
  #-------------------------------------------------------------

  # Remainder patterns for common divisors
  TEST_RR_OP( 82, rem,  0,  10,  5 );
  TEST_RR_OP( 83, rem,  1,  11,  5 );
  TEST_RR_OP( 84, rem,  2,  12,  5 );
  TEST_RR_OP( 85, rem,  3,  13,  5 );
  TEST_RR_OP( 86, rem,  4,  14,  5 );
  TEST_RR_OP( 87, rem,  0,  15,  5 );

  # Negative remainder patterns
  TEST_RR_OP( 88, rem,  0, -10,  5 );
  TEST_RR_OP( 89, rem, -1, -11,  5 );
  TEST_RR_OP( 90, rem, -2, -12,  5 );
  TEST_RR_OP( 91, rem, -3, -13,  5 );
  TEST_RR_OP( 92, rem, -4, -14,  5 );
  TEST_RR_OP( 93, rem,  0, -15,  5 );

  #-------------------------------------------------------------
  # Edge cases for remainder calculation
  #-------------------------------------------------------------

  # Dividend equals divisor
  TEST_RR_OP( 94, rem,  0,  5,  5 );
  TEST_RR_OP( 95, rem,  0, -5,  5 );
  TEST_RR_OP( 96, rem,  0,  5, -5 );
  TEST_RR_OP( 97, rem,  0, -5, -5 );

  # Dividend smaller than divisor
  TEST_RR_OP( 98, rem,  3,  3,  5 );
  TEST_RR_OP( 99, rem, -3, -3,  5 );
  TEST_RR_OP( 100, rem,  3,  3, -5 );
  TEST_RR_OP( 101, rem, -3, -3, -5 );

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

  TEST_DATA

RVTEST_DATA_END 