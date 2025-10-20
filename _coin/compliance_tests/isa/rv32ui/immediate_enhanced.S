# See LICENSE for license details.

#*****************************************************************************
# immediate_enhanced.S
#-----------------------------------------------------------------------------
#
# Enhanced tests for immediate instructions including lui, addi, and others.
# Comprehensive coverage with edge cases and boundary testing.
#

#include "riscv_test.h"
#include "test_macros.h"

RVTEST_RV32U
RVTEST_CODE_BEGIN

  #-------------------------------------------------------------
  # LUI (Load Upper Immediate) Tests
  #-------------------------------------------------------------

  # Basic LUI tests
  TEST_CASE( 2, x1, 0x00000000, lui x1, 0x00000 );
  TEST_CASE( 3, x1, 0x00001000, lui x1, 0x00001 );
  TEST_CASE( 4, x1, 0x00002000, lui x1, 0x00002 );
  TEST_CASE( 5, x1, 0x00003000, lui x1, 0x00003 );

  # Edge cases for LUI
  TEST_CASE( 6, x1, 0x00007000, lui x1, 0x00007 );
  TEST_CASE( 7, x1, 0x00008000, lui x1, 0x00008 );
  TEST_CASE( 8, x1, 0x0000f000, lui x1, 0x0000f );
  TEST_CASE( 9, x1, 0x00010000, lui x1, 0x00010 );

  # Large immediate values
  TEST_CASE( 10, x1, 0x7ffff000, lui x1, 0x7ffff );
  TEST_CASE( 11, x1, 0x80000000, lui x1, 0x80000 );
  TEST_CASE( 12, x1, 0xfffff000, lui x1, 0xfffff );

  # Sign extension tests for LUI
  TEST_CASE( 13, x1, 0xfffff800, lui x1, 0xfffff;sra x1,x1,1);
  TEST_CASE( 14, x1, 0x000007ff, lui x1, 0x7ffff;sra x1,x1,20);
  TEST_CASE( 15, x1, 0xfffff800, lui x1, 0x80000;sra x1,x1,20);

  # Zero register tests
  TEST_CASE( 16, x0, 0, lui x0, 0x80000 );
  TEST_CASE( 17, x0, 0, lui x0, 0xfffff );
  TEST_CASE( 18, x0, 0, lui x0, 0x00000 );

  #-------------------------------------------------------------
  # ADDI (Add Immediate) Tests
  #-------------------------------------------------------------

  # Basic ADDI tests
  TEST_IMM_OP( 19, addi, 0x00000000, 0x00000000, 0x000 );
  TEST_IMM_OP( 20, addi, 0x00000002, 0x00000001, 0x001 );
  TEST_IMM_OP( 21, addi, 0x0000000a, 0x00000003, 0x007 );
  TEST_IMM_OP( 22, addi, 0x0000000f, 0x00000008, 0x007 );

  # Negative immediate tests
  TEST_IMM_OP( 23, addi, 0xffffffff, 0x00000000, 0xfff );
  TEST_IMM_OP( 24, addi, 0x00000000, 0x00000001, 0xfff );
  TEST_IMM_OP( 25, addi, 0xfffffffe, 0xffffffff, 0xfff );
  TEST_IMM_OP( 26, addi, 0xfffff800, 0x00000000, 0x800 );

  # Large immediate tests
  TEST_IMM_OP( 27, addi, 0x000007ff, 0x00000000, 0x7ff );
  TEST_IMM_OP( 28, addi, 0x7fffffff, 0x7fffffff, 0x000 );
  TEST_IMM_OP( 29, addi, 0x800007fe, 0x7fffffff, 0x7ff );
  TEST_IMM_OP( 30, addi, 0x800007ff, 0x80000000, 0x7ff );

  # Overflow and boundary tests
  TEST_IMM_OP( 31, addi, 0x80000000, 0x7fffffff, 0x001 );
  TEST_IMM_OP( 32, addi, 0x7ffff7ff, 0x7fffffff, 0x800 );
  TEST_IMM_OP( 33, addi, 0x80000000, 0x80000000, 0x000 );

  # Zero source tests
  TEST_IMM_ZEROSRC1( 34, addi, 32, 32 );
  TEST_IMM_ZEROSRC1( 35, addi, -1, -1 );
  TEST_IMM_ZEROSRC1( 36, addi, 0x7ff, 0x7ff );
  TEST_IMM_ZEROSRC1( 37, addi, -2048, 0x800 ); # x[rd] = x[rs1] + sext(immediate)

  # Zero destination tests
  TEST_IMM_ZERODEST( 38, addi, 33, 50 );
  TEST_IMM_ZERODEST( 39, addi, -1, -1 );
  TEST_IMM_ZERODEST( 40, addi, 0x7ff, 0x7ff );

  #-------------------------------------------------------------
  # SLTI (Set Less Than Immediate) Tests
  #-------------------------------------------------------------

  # Basic SLTI tests
  TEST_IMM_OP( 41, slti, 0x00000000, 0x00000000, 0x000 );
  TEST_IMM_OP( 42, slti, 0x00000001, 0x00000000, 0x001 );
  TEST_IMM_OP( 43, slti, 0x00000000, 0x00000001, 0x000 );
  TEST_IMM_OP( 44, slti, 0x00000000, 0x00000001, 0x001 );

  # Negative value tests
  TEST_IMM_OP( 45, slti, 0x00000000, 0x00000000, 0xfff );
  TEST_IMM_OP( 46, slti, 0x00000000, 0xffffffff, 0xfff );
  TEST_IMM_OP( 47, slti, 0x00000001, 0x80000000, 0x000 );

  # Large value tests
  TEST_IMM_OP( 48, slti, 0x00000000, 0x7fffffff, 0x7ff );
  TEST_IMM_OP( 49, slti, 0x00000000, 0x7fffffff, 0x800 );
  TEST_IMM_OP( 50, slti, 0x00000001, 0x80000000, 0x7ff );

  #-------------------------------------------------------------
  # SLTIU (Set Less Than Immediate Unsigned) Tests
  #-------------------------------------------------------------

  # Basic SLTIU tests
  TEST_IMM_OP( 51, sltiu, 0x00000000, 0x00000000, 0x000 );
  TEST_IMM_OP( 52, sltiu, 0x00000001, 0x00000000, 0x001 );
  TEST_IMM_OP( 53, sltiu, 0x00000000, 0x00000001, 0x000 );

  # Unsigned comparison tests
  TEST_IMM_OP( 54, sltiu, 0x00000000, 0xffffffff, 0x000 );
  TEST_IMM_OP( 55, sltiu, 0x00000001, 0x00000000, 0x800 );
  TEST_IMM_OP( 56, sltiu, 0x00000001, 0x7fffffff, 0x800 );

  #-------------------------------------------------------------
  # XORI (XOR Immediate) Tests
  #-------------------------------------------------------------

  # Basic XORI tests
  TEST_IMM_OP( 57, xori, 0x00000000, 0x00000000, 0x000 );
  TEST_IMM_OP( 58, xori, 0x00000001, 0x00000000, 0x001 );
  TEST_IMM_OP( 59, xori, 0x00000001, 0x00000001, 0x000 );
  TEST_IMM_OP( 60, xori, 0x00000000, 0x00000001, 0x001 );

  # Pattern tests
  TEST_IMM_OP( 61, xori, 0xffffffff, 0x00000000, 0xfff );
  TEST_IMM_OP( 62, xori, 0xfffff800, 0x00000000, 0x800 );
  TEST_IMM_OP( 63, xori, 0x000007ff, 0x00000000, 0x7ff );

  #-------------------------------------------------------------
  # ORI (OR Immediate) Tests
  #-------------------------------------------------------------

  # Basic ORI tests
  TEST_IMM_OP( 64, ori, 0x00000000, 0x00000000, 0x000 );
  TEST_IMM_OP( 65, ori, 0x00000001, 0x00000000, 0x001 );
  TEST_IMM_OP( 66, ori, 0x00000001, 0x00000001, 0x000 );
  TEST_IMM_OP( 67, ori, 0x00000001, 0x00000001, 0x001 );

  # Pattern tests
  TEST_IMM_OP( 68, ori, 0xffffffff, 0x00000000, 0xfff );
  TEST_IMM_OP( 69, ori, 0xfffff800, 0x00000000, 0x800 );
  TEST_IMM_OP( 70, ori, 0x000007ff, 0x00000000, 0x7ff );

  #-------------------------------------------------------------
  # ANDI (AND Immediate) Tests
  #-------------------------------------------------------------

  # Basic ANDI tests
  TEST_IMM_OP( 71, andi, 0x00000000, 0x00000000, 0x000 );
  TEST_IMM_OP( 72, andi, 0x00000000, 0x00000000, 0x001 );
  TEST_IMM_OP( 73, andi, 0x00000001, 0x00000001, 0x001 );
  TEST_IMM_OP( 74, andi, 0x00000000, 0x00000001, 0x002 );

  # Pattern tests
  TEST_IMM_OP( 75, andi, 0x00000000, 0x00000000, 0xfff );
  TEST_IMM_OP( 76, andi, 0x00000800, 0x00000800, 0x800 );
  TEST_IMM_OP( 77, andi, 0x000007ff, 0x000007ff, 0x7ff );

  #-------------------------------------------------------------
  # SLLI (Shift Left Logical Immediate) Tests
  #-------------------------------------------------------------

  # Basic SLLI tests
  TEST_IMM_OP( 78, slli, 0x00000000, 0x00000000, 0x000 );
  TEST_IMM_OP( 79, slli, 0x00000002, 0x00000001, 0x001 );
  TEST_IMM_OP( 80, slli, 0x00000004, 0x00000001, 0x002 );
  TEST_IMM_OP( 81, slli, 0x00000008, 0x00000001, 0x003 );

  # Large shift tests
  TEST_IMM_OP( 82, slli, 0x80000000, 0x00000001, 0x01f );
  TEST_IMM_OP( 83, slli, 0x40000000, 0x00000001, 0x01e );
  TEST_IMM_OP( 84, slli, 0x20000000, 0x00000001, 0x01d );

  #-------------------------------------------------------------
  # SRLI (Shift Right Logical Immediate) Tests
  #-------------------------------------------------------------

  # Basic SRLI tests
  TEST_IMM_OP( 85, srli, 0x00000000, 0x00000000, 0x000 );
  TEST_IMM_OP( 86, srli, 0x00000000, 0x00000001, 0x001 );
  TEST_IMM_OP( 87, srli, 0x00000000, 0x00000002, 0x002 );
  TEST_IMM_OP( 88, srli, 0x00000001, 0x00000002, 0x001 );

  # Large shift tests
  TEST_IMM_OP( 89, srli, 0x00000000, 0x00000001, 0x01f );
  TEST_IMM_OP( 90, srli, 0x00000000, 0x00000001, 0x01e );
  TEST_IMM_OP( 91, srli, 0x00000000, 0x00000001, 0x01d );

  #-------------------------------------------------------------
  # SRAI (Shift Right Arithmetic Immediate) Tests
  #-------------------------------------------------------------

  # Basic SRAI tests
  TEST_IMM_OP( 92, srai, 0x00000000, 0x00000000, 0x000 );
  TEST_IMM_OP( 93, srai, 0x00000000, 0x00000001, 0x001 );
  TEST_IMM_OP( 94, srai, 0x00000001, 0x00000002, 0x001 );

  # Sign extension tests
  TEST_IMM_OP( 95, srai, 0xffffffff, 0xffffffff, 0x000 );
  TEST_IMM_OP( 96, srai, 0xffffffff, 0xffffffff, 0x001 );
  TEST_IMM_OP( 97, srai, 0x80000000, 0x80000000, 0x000 );

  #-------------------------------------------------------------
  # Source/Destination tests
  #-------------------------------------------------------------

  TEST_IMM_SRC1_EQ_DEST( 98, addi, 24, 13, 11 );
  TEST_IMM_SRC1_EQ_DEST( 99, xori, 0x0000000f, 0x00000003, 0x00c );
  TEST_IMM_SRC1_EQ_DEST( 100, ori, 0x0000000f, 0x00000003, 0x00c );
  TEST_IMM_SRC1_EQ_DEST( 101, andi, 0x00000003, 0x00000003, 0x00f );

  #-------------------------------------------------------------
  # Bypassing tests
  #-------------------------------------------------------------

  TEST_IMM_DEST_BYPASS( 102, 0, addi, 24, 13, 11 );
  TEST_IMM_DEST_BYPASS( 103, 1, addi, 23, 13, 10 );
  TEST_IMM_DEST_BYPASS( 104, 2, addi, 22, 13,  9 );

  TEST_IMM_SRC1_BYPASS( 105, 0, addi, 24, 13, 11 );
  TEST_IMM_SRC1_BYPASS( 106, 1, addi, 23, 13, 10 );
  TEST_IMM_SRC1_BYPASS( 107, 2, addi, 22, 13,  9 );

  TEST_PASSFAIL

RVTEST_CODE_END

  .data
RVTEST_DATA_BEGIN

  TEST_DATA

RVTEST_DATA_END
