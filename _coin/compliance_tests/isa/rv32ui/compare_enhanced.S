# See LICENSE for license details.

#*****************************************************************************
# compare_enhanced.S
#-----------------------------------------------------------------------------
#
# Enhanced test for comparison instructions with comprehensive coverage.
# Tests: slt, slti, sltu, sltiu
#

#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV32U
RVTEST_CODE_BEGIN

  #-------------------------------------------------------------
  # Set Less Than (SLT) tests
  #-------------------------------------------------------------

  # Basic SLT tests
  TEST_RR_OP( 2,  slt, 0, 0x00000000, 0x00000000 );
  TEST_RR_OP( 3,  slt, 1, 0x00000000, 0x00000001 );
  TEST_RR_OP( 4,  slt, 0, 0x00000001, 0x00000000 );
  TEST_RR_OP( 5,  slt, 0, 0x00000001, 0x00000001 );

  # SLT with immediate (SLTI)
  TEST_IMM_OP( 6,  slti, 0, 0x00000000, 0x00000000 );
  TEST_IMM_OP( 7,  slti, 1, 0x00000000, 0x00000001 );
  TEST_IMM_OP( 8,  slti, 0, 0x00000001, 0x00000000 );
  TEST_IMM_OP( 9,  slti, 0, 0x00000001, 0x00000001 );

  #-------------------------------------------------------------
  # Set Less Than Unsigned (SLTU) tests
  #-------------------------------------------------------------

  # Basic SLTU tests
  TEST_RR_OP( 10, sltu, 0, 0x00000000, 0x00000000 );
  TEST_RR_OP( 11, sltu, 1, 0x00000000, 0x00000001 );
  TEST_RR_OP( 12, sltu, 0, 0x00000001, 0x00000000 );
  TEST_RR_OP( 13, sltu, 0, 0x00000001, 0x00000001 );

  # SLTU with immediate (SLTIU)
  TEST_IMM_OP( 14, sltiu, 0, 0x00000000, 0x00000000 );
  TEST_IMM_OP( 15, sltiu, 1, 0x00000000, 0x00000001 );
  TEST_IMM_OP( 16, sltiu, 0, 0x00000001, 0x00000000 );
  TEST_IMM_OP( 17, sltiu, 0, 0x00000001, 0x00000001 );

  #-------------------------------------------------------------
  # Edge cases and corner conditions
  #-------------------------------------------------------------

  # Zero comparisons
  TEST_RR_OP( 18, slt, 0, 0x00000000, 0x00000000 );
  TEST_RR_OP( 19, slt, 1, 0x00000000, 0x00000001 );
  TEST_RR_OP( 20, slt, 0, 0x00000001, 0x00000000 );
  TEST_RR_OP( 21, slt, 0, 0x00000000, 0xffffffff );

  TEST_RR_OP( 22, sltu, 0, 0x00000000, 0x00000000 );
  TEST_RR_OP( 23, sltu, 1, 0x00000000, 0x00000001 );
  TEST_RR_OP( 24, sltu, 0, 0x00000001, 0x00000000 );
  TEST_RR_OP( 25, sltu, 1, 0x00000000, 0xffffffff );

  #-------------------------------------------------------------
  # Maximum and minimum value tests
  #-------------------------------------------------------------

  # Maximum positive value
  TEST_RR_OP( 26, slt, 0, 0x7fffffff, 0x7fffffff );
  TEST_RR_OP( 27, slt, 0, 0x7fffffff, 0x80000000 );
  TEST_RR_OP( 28, slt, 1, 0x80000000, 0x7fffffff );
  TEST_RR_OP( 29, slt, 0, 0x80000000, 0x80000000 );

  TEST_RR_OP( 30, sltu, 0, 0x7fffffff, 0x7fffffff );
  TEST_RR_OP( 31, sltu, 1, 0x7fffffff, 0x80000000 );
  TEST_RR_OP( 32, sltu, 0, 0x80000000, 0x7fffffff );
  TEST_RR_OP( 33, sltu, 0, 0x80000000, 0x80000000 );

  #-------------------------------------------------------------
  # Negative number tests
  #-------------------------------------------------------------

  # Negative numbers (signed comparison)
  TEST_RR_OP( 34, slt, 1, 0x80000000, 0x00000000 );
  TEST_RR_OP( 35, slt, 1, 0x80000000, 0x00000001 );
  TEST_RR_OP( 36, slt, 1, 0x80000000, 0x7fffffff );
  TEST_RR_OP( 37, slt, 0, 0x00000000, 0x80000000 );

  # Negative numbers (unsigned comparison)
  TEST_RR_OP( 38, sltu, 0, 0x80000000, 0x00000000 );
  TEST_RR_OP( 39, sltu, 0, 0x80000000, 0x00000001 );
  TEST_RR_OP( 40, sltu, 0, 0x80000000, 0x7fffffff );
  TEST_RR_OP( 41, sltu, 1, 0x00000000, 0x80000000 );

  #-------------------------------------------------------------
  # All ones patterns
  #-------------------------------------------------------------

  # All ones (signed comparison)
  TEST_RR_OP( 42, slt, 0, 0xffffffff, 0xffffffff );
  TEST_RR_OP( 43, slt, 1, 0xffffffff, 0x00000000 );
  TEST_RR_OP( 44, slt, 1, 0xffffffff, 0x00000001 );
  TEST_RR_OP( 45, slt, 0, 0x00000000, 0xffffffff );

  # All ones (unsigned comparison)
  TEST_RR_OP( 46, sltu, 0, 0xffffffff, 0xffffffff );
  TEST_RR_OP( 47, sltu, 0, 0xffffffff, 0x00000000 );
  TEST_RR_OP( 48, sltu, 0, 0xffffffff, 0x00000001 );
  TEST_RR_OP( 49, sltu, 1, 0x00000000, 0xffffffff );

  #-------------------------------------------------------------
  # Power of 2 tests
  #-------------------------------------------------------------

  # Powers of 2 (signed comparison)
  TEST_RR_OP( 50, slt, 1, 0x00000001, 0x00000002 );
  TEST_RR_OP( 51, slt, 1, 0x00000002, 0x00000004 );
  TEST_RR_OP( 52, slt, 1, 0x00000004, 0x00000008 );
  TEST_RR_OP( 53, slt, 1, 0x00000008, 0x00000010 );

  # Powers of 2 (unsigned comparison)
  TEST_RR_OP( 54, sltu, 1, 0x00000001, 0x00000002 );
  TEST_RR_OP( 55, sltu, 1, 0x00000002, 0x00000004 );
  TEST_RR_OP( 56, sltu, 1, 0x00000004, 0x00000008 );
  TEST_RR_OP( 57, sltu, 1, 0x00000008, 0x00000010 );

  #-------------------------------------------------------------
  # Large number tests
  #-------------------------------------------------------------

  # Large positive numbers
  TEST_RR_OP( 58, slt, 1, 0x0000ffff, 0x00010000 );
  TEST_RR_OP( 59, slt, 1, 0x00010000, 0x00020000 );
  TEST_RR_OP( 60, slt, 1, 0x00020000, 0x00040000 );
  TEST_RR_OP( 61, slt, 0, 0x00040000, 0x00020000 );

  # Large negative numbers
  TEST_RR_OP( 62, slt, 0, 0xffff0000, 0xfffe0000 );
  TEST_RR_OP( 63, slt, 0, 0xfffe0000, 0xfffc0000 );
  TEST_RR_OP( 64, slt, 0, 0xfffc0000, 0xfff80000 );
  TEST_RR_OP( 65, slt, 1, 0xfff80000, 0xfffc0000 );

  #-------------------------------------------------------------
  # Immediate tests with various values
  #-------------------------------------------------------------

  # SLTI with various immediates
  TEST_IMM_OP( 66, slti, 0, 0x00000000, 0x00000000 );
  TEST_IMM_OP( 67, slti, 1, 0x00000000, 0x00000001 );
  TEST_IMM_OP( 68, slti, 1, 0x00000000, 0x00000002 );
  TEST_IMM_OP( 69, slti, 1, 0x00000000, 0x00000004 );

  TEST_IMM_OP( 70, slti, 0, 0x00000001, 0x00000000 );
  TEST_IMM_OP( 71, slti, 0, 0x00000001, 0x00000001 );
  TEST_IMM_OP( 72, slti, 1, 0x00000001, 0x00000002 );
  TEST_IMM_OP( 73, slti, 1, 0x00000001, 0x00000004 );

  # SLTIU with various immediates
  TEST_IMM_OP( 74, sltiu, 0, 0x00000000, 0x00000000 );
  TEST_IMM_OP( 75, sltiu, 1, 0x00000000, 0x00000001 );
  TEST_IMM_OP( 76, sltiu, 1, 0x00000000, 0x00000002 );
  TEST_IMM_OP( 77, sltiu, 1, 0x00000000, 0x00000004 );

  TEST_IMM_OP( 78, sltiu, 0, 0x00000001, 0x00000000 );
  TEST_IMM_OP( 79, sltiu, 0, 0x00000001, 0x00000001 );
  TEST_IMM_OP( 80, sltiu, 1, 0x00000001, 0x00000002 );
  TEST_IMM_OP( 81, sltiu, 1, 0x00000001, 0x00000004 );

  #-------------------------------------------------------------
  # Source/Destination tests
  #-------------------------------------------------------------

  TEST_RR_SRC1_EQ_DEST( 82, slt, 0, 5, 3 );
  TEST_RR_SRC1_EQ_DEST( 83, slt, 1, 3, 5 );
  TEST_RR_SRC1_EQ_DEST( 84, slt, 0, 5, 5 );

  TEST_RR_SRC2_EQ_DEST( 85, slt, 0, 5, 3 );
  TEST_RR_SRC2_EQ_DEST( 86, slt, 1, 3, 5 );
  TEST_RR_SRC2_EQ_DEST( 87, slt, 0, 5, 5 );

  #-------------------------------------------------------------
  # Bypassing tests
  #-------------------------------------------------------------

  TEST_RR_DEST_BYPASS( 88, 0, slt, 0, 5, 3 );
  TEST_RR_DEST_BYPASS( 89, 1, slt, 1, 3, 5 );
  TEST_RR_DEST_BYPASS( 90, 2, slt, 0, 5, 5 );

  TEST_RR_SRC12_BYPASS( 91, 0, 0, slt, 0, 5, 3 );
  TEST_RR_SRC12_BYPASS( 92, 0, 1, slt, 1, 3, 5 );
  TEST_RR_SRC12_BYPASS( 93, 0, 2, slt, 0, 5, 5 );
  TEST_RR_SRC12_BYPASS( 94, 1, 0, slt, 0, 5, 3 );
  TEST_RR_SRC12_BYPASS( 95, 1, 1, slt, 1, 3, 5 );
  TEST_RR_SRC12_BYPASS( 96, 2, 0, slt, 0, 5, 5 );

  TEST_RR_SRC21_BYPASS( 97, 0, 0, slt, 0, 5, 3 );
  TEST_RR_SRC21_BYPASS( 98, 0, 1, slt, 1, 3, 5 );
  TEST_RR_SRC21_BYPASS( 99, 0, 2, slt, 0, 5, 5 );
  TEST_RR_SRC21_BYPASS( 100, 1, 0, slt, 0, 5, 3 );
  TEST_RR_SRC21_BYPASS( 101, 1, 1, slt, 1, 3, 5 );
  TEST_RR_SRC21_BYPASS( 102, 2, 0, slt, 0, 5, 5 );

  #-------------------------------------------------------------
  # Immediate bypassing tests
  #-------------------------------------------------------------

  TEST_IMM_DEST_BYPASS( 103, 0, slti, 0, 5, 3 );
  TEST_IMM_DEST_BYPASS( 104, 1, slti, 1, 3, 5 );
  TEST_IMM_DEST_BYPASS( 105, 2, slti, 0, 5, 5 );

  TEST_IMM_SRC1_BYPASS( 106, 0, slti, 0, 5, 3 );
  TEST_IMM_SRC1_BYPASS( 107, 1, slti, 1, 3, 5 );
  TEST_IMM_SRC1_BYPASS( 108, 2, slti, 0, 5, 5 );

  #-------------------------------------------------------------
  # Zero operand tests
  #-------------------------------------------------------------

  TEST_RR_ZEROSRC1( 109, slt, 1, 31 );
  TEST_RR_ZEROSRC1( 110, sltu, 1, 31 );
  TEST_RR_ZEROSRC2( 111, slt, 0, 32 );
  TEST_RR_ZEROSRC2( 112, sltu, 0, 32 );
  TEST_RR_ZEROSRC12( 113, slt, 0 );
  TEST_RR_ZEROSRC12( 114, sltu, 0 );
  TEST_RR_ZERODEST( 115, slt, 16, 30 );
  TEST_RR_ZERODEST( 116, sltu, 16, 30 );

  #-------------------------------------------------------------
  # Additional edge cases
  #-------------------------------------------------------------

  # Values around zero
  TEST_RR_OP( 117, slt, 0, 0x00000000, 0x00000000 );
  TEST_RR_OP( 118, slt, 1, 0x00000000, 0x00000001 );
  TEST_RR_OP( 119, slt, 0, 0x00000001, 0x00000000 );
  TEST_RR_OP( 120, slt, 0, 0x00000000, 0xffffffff );

  # Values around 1 and -1
  TEST_RR_OP( 121, slt, 0, 0x00000001, 0x00000001 );
  TEST_RR_OP( 122, slt, 1, 0x00000001, 0x00000002 );
  TEST_RR_OP( 123, slt, 0, 0x00000002, 0x00000001 );
  TEST_RR_OP( 124, slt, 1, 0xffffffff, 0x00000000 );

  #-------------------------------------------------------------
  # Stress tests with large numbers
  #-------------------------------------------------------------

  # Large positive numbers
  TEST_RR_OP( 125, slt, 1, 0x00007fff, 0x00008000 );
  TEST_RR_OP( 126, slt, 1, 0x00008000, 0x00010000 );
  TEST_RR_OP( 127, slt, 1, 0x00010000, 0x00020000 );
  TEST_RR_OP( 128, slt, 0, 0x00020000, 0x00010000 );

  # Large negative numbers
  TEST_RR_OP( 129, slt, 0, 0xffff8000, 0xffff0000 );
  TEST_RR_OP( 130, slt, 0, 0xffff0000, 0xfffe0000 );
  TEST_RR_OP( 131, slt, 0, 0xfffe0000, 0xfffc0000 );
  TEST_RR_OP( 132, slt, 1, 0xfffc0000, 0xfffe0000 );

  #-------------------------------------------------------------
  # Boundary value tests
  #-------------------------------------------------------------

  # Values just below and above maximum/minimum
  TEST_RR_OP( 133, slt, 1, 0x7ffffffe, 0x7fffffff );
  TEST_RR_OP( 134, slt, 0, 0x7fffffff, 0x7ffffffe );
  TEST_RR_OP( 135, slt, 1, 0x80000000, 0x80000001 );
  TEST_RR_OP( 136, slt, 0, 0x80000001, 0x80000000 );

  #-------------------------------------------------------------
  # Special pattern tests
  #-------------------------------------------------------------

  # Alternating bit patterns
  TEST_RR_OP( 137, slt, 0, 0x55555555, 0xaaaaaaaa );
  TEST_RR_OP( 138, slt, 1, 0xaaaaaaaa, 0x55555555 );
  TEST_RR_OP( 139, slt, 0, 0x55555555, 0x55555555 );
  TEST_RR_OP( 140, slt, 0, 0xaaaaaaaa, 0xaaaaaaaa );

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

  TEST_DATA

RVTEST_DATA_END 