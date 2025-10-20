# See LICENSE for license details.

#*****************************************************************************
# mul_enhanced.S
#-----------------------------------------------------------------------------
#
# Enhanced test for mul instruction with comprehensive coverage.
#

#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV32U
RVTEST_CODE_BEGIN

  #-------------------------------------------------------------
  # Basic arithmetic tests
  #-------------------------------------------------------------

  TEST_RR_OP( 2,  mul, 0x00000000, 0x00000000, 0x00000000 );
  TEST_RR_OP( 3,  mul, 0x00000001, 0x00000001, 0x00000001 );
  TEST_RR_OP( 4,  mul, 0x00000015, 0x00000003, 0x00000007 );
  TEST_RR_OP( 5,  mul, 0x00000000, 0x00000000, 0xffff8000 );
  TEST_RR_OP( 6,  mul, 0x00000000, 0x80000000, 0x00000000 );
  TEST_RR_OP( 7,  mul, 0x00000000, 0x80000000, 0xffff8000 );

  #-------------------------------------------------------------
  # Edge cases and corner conditions
  #-------------------------------------------------------------

  # Power of 2 multiplications
  TEST_RR_OP( 8,  mul, 0x00000002, 0x00000001, 0x00000002 );
  TEST_RR_OP( 9,  mul, 0x00000004, 0x00000001, 0x00000004 );
  TEST_RR_OP( 10, mul, 0x00000008, 0x00000001, 0x00000008 );
  TEST_RR_OP( 11, mul, 0x00000010, 0x00000001, 0x00000010 );
  TEST_RR_OP( 12, mul, 0x00000020, 0x00000001, 0x00000020 );
  TEST_RR_OP( 13, mul, 0x00000040, 0x00000001, 0x00000040 );
  TEST_RR_OP( 14, mul, 0x00000080, 0x00000001, 0x00000080 );
  TEST_RR_OP( 15, mul, 0x00000100, 0x00000001, 0x00000100 );

  # Large numbers
  TEST_RR_OP( 16, mul, 0x40000000, 0x00000002, 0x20000000 );
  TEST_RR_OP( 17, mul, 0x80000000, 0x00000002, 0x40000000 );
  TEST_RR_OP( 18, mul, 0x00000000, 0x00000002, 0x80000000 );

  # Negative numbers
  TEST_RR_OP( 19, mul, 0x00000001, 0xffffffff, 0xffffffff );
  TEST_RR_OP( 20, mul, 0xffffffff, 0xffffffff, 0x00000001 );
  TEST_RR_OP( 21, mul, 0xffffffff, 0x00000001, 0xffffffff );
  TEST_RR_OP( 22, mul, 0x00000001, 0x00000001, 0x00000001 );
  TEST_RR_OP( 23, mul, 0xfffffffe, 0x00000002, 0xffffffff );
  TEST_RR_OP( 24, mul, 0xfffffffe, 0xffffffff, 0x00000002 );

  #-------------------------------------------------------------
  # Overflow and wrapping tests
  #-------------------------------------------------------------

  # 32-bit overflow cases
  TEST_RR_OP( 25, mul, 0x00000000, 0x00010000, 0x00010000 );
  TEST_RR_OP( 26, mul, 0x00000000, 0x00020000, 0x00008000 );
  TEST_RR_OP( 27, mul, 0x00000000, 0x00040000, 0x00004000 );
  TEST_RR_OP( 28, mul, 0x00000000, 0x00080000, 0x00002000 );

  # Mixed positive/negative overflow
  TEST_RR_OP( 29, mul, 0x80000000, 0x00000002, 0xc0000000 );
  TEST_RR_OP( 30, mul, 0x80000000, 0xc0000000, 0x00000002 );

  #-------------------------------------------------------------
  # Special value tests
  #-------------------------------------------------------------

  # All ones patterns
  TEST_RR_OP( 31, mul, 0x00000001, 0xffffffff, 0xffffffff );
  TEST_RR_OP( 32, mul, 0xfffffffe, 0xffffffff, 0x00000002 );
  TEST_RR_OP( 33, mul, 0x00000000, 0xffffffff, 0x00000000 );

  # Alternating bit patterns
  TEST_RR_OP( 34, mul, 0x55555555, 0x55555555, 0x00000001 );
  TEST_RR_OP( 35, mul, 0xaaaaaaaa, 0xaaaaaaaa, 0x00000001 );

  #-------------------------------------------------------------
  # Source/Destination tests
  #-------------------------------------------------------------

  TEST_RR_SRC1_EQ_DEST( 37, mul, 143, 13, 11 );
  TEST_RR_SRC2_EQ_DEST( 38, mul, 154, 14, 11 );
  TEST_RR_SRC12_EQ_DEST( 39, mul, 169, 13 );

  #-------------------------------------------------------------
  # Bypassing tests
  #-------------------------------------------------------------

  TEST_RR_DEST_BYPASS( 40, 0, mul, 143, 13, 11 );
  TEST_RR_DEST_BYPASS( 41, 1, mul, 154, 14, 11 );
  TEST_RR_DEST_BYPASS( 42, 2, mul, 165, 15, 11 );

  TEST_RR_SRC12_BYPASS( 43, 0, 0, mul, 143, 13, 11 );
  TEST_RR_SRC12_BYPASS( 44, 0, 1, mul, 154, 14, 11 );
  TEST_RR_SRC12_BYPASS( 45, 0, 2, mul, 165, 15, 11 );
  TEST_RR_SRC12_BYPASS( 46, 1, 0, mul, 143, 13, 11 );
  TEST_RR_SRC12_BYPASS( 47, 1, 1, mul, 154, 14, 11 );
  TEST_RR_SRC12_BYPASS( 48, 2, 0, mul, 165, 15, 11 );

  TEST_RR_SRC21_BYPASS( 49, 0, 0, mul, 143, 13, 11 );
  TEST_RR_SRC21_BYPASS( 50, 0, 1, mul, 154, 14, 11 );
  TEST_RR_SRC21_BYPASS( 51, 0, 2, mul, 165, 15, 11 );
  TEST_RR_SRC21_BYPASS( 52, 1, 0, mul, 143, 13, 11 );
  TEST_RR_SRC21_BYPASS( 53, 1, 1, mul, 154, 14, 11 );
  TEST_RR_SRC21_BYPASS( 54, 2, 0, mul, 165, 15, 11 );

  #-------------------------------------------------------------
  # Zero operand tests
  #-------------------------------------------------------------

  TEST_RR_ZEROSRC1( 55, mul, 0, 31 );
  TEST_RR_ZEROSRC2( 56, mul, 0, 32 );
  TEST_RR_ZEROSRC12( 57, mul, 0 );
  TEST_RR_ZERODEST( 58, mul, 33, 34 );

  #-------------------------------------------------------------
  # Additional edge cases
  #-------------------------------------------------------------

  # Maximum and minimum values
  TEST_RR_OP( 59, mul, 0x00000000, 0x7fffffff, 0x00000000 );
  TEST_RR_OP( 60, mul, 0x7fffffff, 0x7fffffff, 0x00000001 );
  TEST_RR_OP( 61, mul, 0x00000001, 0x7fffffff, 0x7fffffff );
  TEST_RR_OP( 62, mul, 0x80000000, 0x80000000, 0x00000001 );
  TEST_RR_OP( 63, mul, 0x00000000, 0x80000000, 0x00000000 );

  #-------------------------------------------------------------
  # Stress tests with large numbers
  #-------------------------------------------------------------

  TEST_RR_OP( 64, mul, 0x00001200, 0x00007e00, 0xb6db6db7 );
  TEST_RR_OP( 65, mul, 0x00001240, 0x00007fc0, 0xb6db6db7 );
  TEST_RR_OP( 66, mul, 0x0000ff7f, 0xaaaaaaab, 0x0002fe7d );
  TEST_RR_OP( 67, mul, 0x0000ff7f, 0x0002fe7d, 0xaaaaaaab );
  TEST_RR_OP( 68, mul, 0x00000000, 0xff000000, 0xff000000 );

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

  TEST_DATA

RVTEST_DATA_END 