use bitcoin_script_stack::stack::{StackTracker, StackVariable};

use super::script_utils::*;

//TODO: Security check. The rs1, rs2, rd should be in 0-31 range.
//Aux registers are only accessible on specific instructions

// input: it assumes the register is encoded in 5 bits from 3 to 7
// to convert into the number of the register, we need to shift 3 bits to the right
// but as we need to get the address and we need to multiply by 4, we just need to shift 1 right
// as the low part also might have garbage on the first 3 bit we will just use and if to ask for the 3 bit and the return it i
// | high    | low     |
// | 7 6 5 4 | 3 2 1 0 |
//
pub fn get_register_address(
    stack: &mut StackTracker,
    tables: &StackTables,
    high: StackVariable,
    low: StackVariable,
) -> StackVariable {
    stack.copy_var(high);
    let ret_high = stack.get_value_from_table(tables.rshift.shift_1, None);

    stack.move_var(high);
    stack.get_value_from_table(tables.lshift.shift_3, None);

    stack.move_var(low);
    if_greater(stack, 7, 4, 0);

    stack.op_add();

    stack.join(ret_high);
    ret_high
}

pub fn get_register_address_rs2(
    stack: &mut StackTracker,
    tables: &StackTables,
    high: StackVariable,
    low: StackVariable,
) -> StackVariable {
    stack.move_var(high);
    stack.get_value_from_table(tables.lshift.shift_3, None);
    stack.get_value_from_table(tables.rshift.shift_1, None);

    stack.move_var(low);
    stack.op_dup();
    stack.to_altstack();
    stack.get_value_from_table(tables.rshift.shift_2, None);
    let ret_high = stack.op_add();

    stack.from_altstack();
    stack.get_value_from_table(tables.lshift.shift_2, None);

    stack.join(ret_high);
    ret_high
}

pub fn mask_4bit(stack: &mut StackTracker) -> StackVariable {
    stack
        .custom(
            script! {
                OP_DUP
                0x8
                OP_GREATERTHANOREQUAL
                OP_IF
                    0x8
                    OP_SUB
                OP_ENDIF
            },
            1,
            true,
            0,
            "masked",
        )
        .unwrap()
}

// I-Type
// | 0           | 1           | 2           | 3           | 4           | 5           | 6           | 7
// | 31 30 29 28 | 27 26 25 24 | 23 22 21 20 | 19 18 17 16 | 15 14 13 12 | 11 10 9  8  | 7  6  5  4  | 3  2  1  0  |
// | 31 ------------- imm --------------- 20 | 19 --- rs1 -- 15| -func3--| 11 -- rd ---- 7| ------   opcode -------|
// For shift subtypes, it uses imm[5:11] == u32[25:31] as funct7
// | 31 --- funct7 ----- 25|24 -- imm  -- 20 | 19 --- rs1 -- 15| -func3--| 11 -- rd ---- 7| ------   opcode -------|

pub fn decode_i_type(
    stack: &mut StackTracker,
    tables: &StackTables,
    opcode: StackVariable,
    expected_func3: u8,
    expected_opcode: u8,
    exepected_func7: Option<u8>,
) -> (StackVariable, StackVariable, StackVariable, StackVariable) {
    stack.set_breakpoint("decode_i_type");
    stack.move_var(opcode);
    let op_nibbles = stack.explode(opcode);

    // stack: 0 1 2 3 4 5 6 7
    let expected = stack.byte(expected_opcode); // ..... 6 7   expected_6  expected_7
    stack.explode(expected);
    stack.op_rot(); //      6  expected_6  7 expected_7
    stack.op_equalverify(); //      6  expected_6  assert(7 == expected_7)

    stack.copy_var(op_nibbles[6]); //      6  expected_6 6_copy
    mask_4bit(stack); //      6  expected_6  6_masked
    stack.op_equalverify(); //      6  assert(expected_6 == 6_masked)

    //verify func3 is correct
    stack.copy_var(op_nibbles[4]);
    mask_4bit(stack);
    stack.number(expected_func3 as u32);
    stack.op_equalverify();

    // funct7 is defined the options are 0 or 20. So the only valid values for this nibble is 0 or 1 (part of imm)
    let (imm, bit) = if let Some(func7) = exepected_func7 {
        stack.copy_var(op_nibbles[1]);
        stack.custom(
            script! {
                1
                OP_GREATERTHAN
                OP_IF
                    OP_0
                OP_ELSE
                    OP_1
                OP_ENDIF
                OP_VERIFY
            },
            1,
            false,
            0,
            "empty",
        );

        //shift the func7 expected number to match the nibble and verify it
        stack.move_var(op_nibbles[0]);
        stack.number((func7 >> 3) as u32);
        stack.op_equalverify();

        (stack.join_count(op_nibbles[1], 1), StackVariable::null())
    } else {
        stack.copy_var(op_nibbles[0]);
        let bit = if_greater(stack, 7, 0xf, 0);
        (stack.join_count(op_nibbles[0], 2), bit)
    };
    stack.rename(imm, "immediate");

    let rs1 = get_register_address(stack, tables, op_nibbles[3], op_nibbles[4]);
    stack.rename(rs1, "rs1");
    let rd = get_register_address(stack, tables, op_nibbles[5], op_nibbles[6]);
    stack.rename(rd, "rd");

    (imm, rs1, rd, bit)
}

// B-Type
// | 0           | 1           | 2           | 3           | 4           | 5              | 6                | 7
// | 31 30 29 28 | 27 26 25 24 | 23 22 21 20 | 19 18 17 16 | 15 14 13 12 | 11  10  9   8  | 7       6  5  4  | 3  2  1  0  |
// | 12|30 --imm[10:5]- 25 |24 --  rs2 -- 20 | 19 -- rs1 -- 15 |14-f3-12 | 11-imm[4:1]-8  |imm[11]| 6 ----   opcode -------|
//                                                                                                  |1 1  0  | 0  0  1  1  |

//imm[12|10:5] rs2 rs1 funct3 imm[4:1|11] opcode

pub fn decode_b_type(
    stack: &mut StackTracker,
    tables: &StackTables,
    opcode: StackVariable,
    expected_func3: u8,
) -> (StackVariable, StackVariable, StackVariable) {
    stack.set_breakpoint("decode_b_type");
    stack.move_var(opcode);
    let op_nibbles = stack.explode(opcode);

    // stack: 0 1 2 3 4 5 6 7
    stack.number(3); //      6  7
    stack.op_equalverify(); //      6  assert(7 == 0x3)

    //extract the higher bit of nibble 6
    //and verify the opcode remaining is 0x6
    stack.op_dup();
    stack.custom(
        script! {
            7
            OP_GREATERTHAN
            OP_IF
                8
                OP_TOALTSTACK
                8
                OP_SUB
            ELSE
                0
                OP_TOALTSTACK
            ENDIF
        },
        1,
        false,
        1,
        "opcode-high",
    ); //   6(masked)   | (8 or 0 )
    stack.number(6);
    stack.op_equalverify();

    //verify func3 is correct
    stack.copy_var(op_nibbles[4]);
    mask_4bit(stack);
    stack.number(expected_func3 as u32);
    stack.op_equalverify();

    //imm use bit 12 from pos 31 as signed bit. It needs to fill 5 positions
    stack.copy_var(op_nibbles[0]);
    let bit = if_greater(stack, 7, 0xf, 0);
    stack.op_dup();
    stack.op_2dup();
    stack.op_dup();

    stack.move_var(op_nibbles[0]);
    mask_4bit(stack);
    stack.from_altstack(); //adds the bit 11
    stack.op_add();

    stack.copy_var(op_nibbles[1]);
    stack.get_value_from_table(tables.rshift.shift_1, None);
    stack.get_value_from_table(tables.lshift.shift_1, None);

    stack.move_var(op_nibbles[5]);
    stack.op_dup();
    stack.to_altstack();
    if_greater(stack, 7, 1, 0); // add the bit 4
    stack.op_add();

    stack.from_altstack();
    stack.get_value_from_table(tables.lshift.shift_1, None); //shift 1-4 bits to the left

    stack.join_count(bit, 7);
    stack.rename(bit, "imm");

    let rs1 = get_register_address(stack, tables, op_nibbles[3], op_nibbles[4]);
    stack.rename(rs1, "rs1");

    let rs2 = get_register_address_rs2(stack, tables, op_nibbles[1], op_nibbles[2]);
    stack.rename(rs2, "rs2");

    (bit, rs1, rs2)
}

// R-Type
// | 0           | 1             | 2           | 3           | 4               | 5         | 6       | 7       |
// | 31 30 29 28 | 27 26 25   24 | 23 22 21 20 | 19 18 17 16 | 15  14   13  12 | 11 10 9 8 | 7 6 5 4 | 3 2 1 0 |
// | 31      funct7      25 | 24   rs2      20 | 19   rs1      15| 14 func3 12 | 11    rd    7|6    opcode   0 |
pub fn decode_r_type(
    stack: &mut StackTracker,
    tables: &StackTables,
    opcode: StackVariable,
    expected_funct3: u8,
    expected_opcode: u8,
    expected_funct7: u8,
) -> (StackVariable, StackVariable, StackVariable) {
    stack.set_breakpoint("decoding rtype");
    stack.move_var(opcode);
    let op_nibbles = stack.explode(opcode);

    // stack: 0 1 2 3 4 5 6 7
    let expected = stack.byte(expected_opcode); //      6 7   expected_6  expected_7
    stack.explode(expected);
    stack.op_rot(); //      6  expected_6  7 expected_7
    stack.op_equalverify(); //      6  expected_6  assert(7 == expected_7)

    stack.copy_var(op_nibbles[6]); //      6  expected_6 6_copy
    mask_4bit(stack); //      6  expected_6  6_masked
    stack.op_equalverify(); //      6  assert(expected_6 == 6_masked)

    //verify func3 is correct

    stack.copy_var(op_nibbles[4]);
    mask_4bit(stack);
    stack.number(expected_funct3 as u32);
    stack.op_equalverify();

    // verify funct7
    // possible options are [ 0x00 (0000 0000) | 0x20 (0010 0000)  | 0x01 (0000 0001) ]
    stack.copy_var(op_nibbles[1]);
    stack.get_value_from_table(tables.rshift.shift_1, None);
    if expected_funct7 == 0x01 {
        stack.number(1);
    } else {
        stack.number(0);
    }
    stack.op_equalverify();

    stack.move_var(op_nibbles[0]);
    stack.number((expected_funct7 >> 3) as u32); // shift expected number to match the nibble and verify it
    stack.op_equalverify();

    // decode rs1

    let rs1 = get_register_address(stack, tables, op_nibbles[3], op_nibbles[4]);
    stack.rename(rs1, "rs1");

    // decode rs2

    let rs2 = get_register_address_rs2(stack, tables, op_nibbles[1], op_nibbles[2]);
    stack.rename(rs2, "rs2");

    // decode rd

    let rd = get_register_address(stack, tables, op_nibbles[5], op_nibbles[6]);
    stack.rename(rd, "rd");

    stack.set_breakpoint("decoded rtype");

    (rs1, rs2, rd)
}

// S-Type
// | 0           | 1             | 2           | 3           | 4                | 5         | 6       | 7       |
// | 31 30 29 28 | 27 26 25   24 | 23 22 21 20 | 19 18 17 16 | 15   14   13  12 | 11 10 9 8 | 7 6 5 4 | 3 2 1 0 |
// | 31 --imm[11:5]----- 25 | 24 --  rs2 -- 20 | 19 -- rs1 --- 15 | 14 - f3 -12 | 11-imm[4:0]-7|6 --- opcode ---|
pub fn decode_s_type(
    stack: &mut StackTracker,
    tables: &StackTables,
    opcode: StackVariable,
    expected_funct3: u8,
) -> (StackVariable, StackVariable, StackVariable, StackVariable) {
    stack.set_breakpoint("decoding stype");
    stack.move_var(opcode);
    let op_nibbles = stack.explode(opcode);

    // stack: 0 1 2 3 4 5 6 7
    let expected = stack.byte(0x23); //      6 7   expected_6  expected_7
    stack.explode(expected);
    stack.op_rot(); //      6  expected_6  7 expected_7
    stack.op_equalverify(); //      6  expected_6  assert(7 == expected_7)

    stack.copy_var(op_nibbles[6]); //      6  expected_6 6_copy
    mask_4bit(stack); //      6  expected_6  6_masked
    stack.op_equalverify(); //      6  assert(expected_6 == 6_masked)

    //verify func3 is correct
    stack.copy_var(op_nibbles[4]);
    mask_4bit(stack);
    stack.number(expected_funct3 as u32);
    stack.op_equalverify();

    stack.copy_var(op_nibbles[0]);
    let bit = if_greater(stack, 7, 0xf, 0);
    stack.rename(bit, "bit_extension");

    // generate the full immediate value
    let imm = stack.move_var(op_nibbles[0]); // imm[11:8]
    stack.copy_var(op_nibbles[1]); // imm[7:5]+1bit garbage
    stack.get_value_from_table(tables.rshift.shift_1, None);
    stack.get_value_from_table(tables.lshift.shift_1, None); //  remove the garbage
    stack.copy_var(op_nibbles[5]); //  imm[4:1]
    if_greater(stack, 7, 1, 0); //
    stack.op_add(); //  add the bit 4
    stack.move_var(op_nibbles[5]);
    stack.get_value_from_table(tables.lshift.shift_1, None);
    stack.move_var(op_nibbles[6]);
    if_greater(stack, 7, 1, 0);
    stack.op_add();
    stack.join_count(imm, 2);
    stack.rename(imm, "immediate");

    // decode rs1
    let rs1 = get_register_address(stack, tables, op_nibbles[3], op_nibbles[4]);
    stack.rename(rs1, "rs1");

    // decode rs2
    let rs2 = get_register_address_rs2(stack, tables, op_nibbles[1], op_nibbles[2]);
    stack.rename(rs2, "rs2");

    stack.set_breakpoint("decoded stype");

    (bit, imm, rs1, rs2)
}

// J-Type
// | 0               | 1           | 2                 | 3           | 4           | 5           | 6           | 7
// | 31     30 29 28 | 27 26 25 24 | 23 22 21     20   | 19 18 17 16 | 15 14 13 12 | 11 10 9  8  | 7  6  5  4  | 3  2  1  0  |
// |im[20]| 30 ----------imm[10:1] -----------|-im[11]-| 19---- imm[19:12] ---- 12 | 11 -- rd ---- 7| ------   opcode -------|
pub fn decode_j_type(
    stack: &mut StackTracker,
    tables: &StackTables,
    opcode: StackVariable,
) -> (StackVariable, StackVariable) {
    stack.set_breakpoint("decode_j_type");
    stack.move_var(opcode);
    let op_nibbles = stack.explode(opcode);

    // stack: 0 1 2 3 4 5 6 7
    let expected = stack.byte(0x6f); // ..... 6 7   expected_6  expected_7
    stack.explode(expected);
    stack.op_rot(); //      6  expected_6  7 expected_7
    stack.op_equalverify(); //      6  expected_6  assert(7 == expected_7)

    stack.copy_var(op_nibbles[6]); //      6  expected_6 6_copy
    mask_4bit(stack); //      6  expected_6  6_masked
    stack.op_equalverify(); //      6  assert(expected_6 == 6_masked)

    let rd = get_register_address(stack, tables, op_nibbles[5], op_nibbles[6]);
    stack.rename(rd, "rd");

    stack.copy_var(op_nibbles[0]);
    let bit = if_greater(stack, 7, 0xf, 0x0); //imm[20] as bit extension
    stack.op_dup();
    stack.op_dup(); //complete u32 with bit extension

    stack.move_var(op_nibbles[3]); //imm[19:16]
    stack.move_var(op_nibbles[4]); //imm[15:12]

    stack.copy_var(op_nibbles[2]);
    stack.get_value_from_table(tables.lshift.shift_3, None); // imm[11]

    stack.op_dup();
    stack.get_value_from_table(tables.rshift.shift_3, None);
    stack.to_altstack(); // save original bit to remove the bit 0

    stack.move_var(op_nibbles[0]); // x + imm[10:8]
    mask_4bit(stack); //  imm[10:8]
    stack.op_add(); // imm[11:8]

    stack.move_var(op_nibbles[1]); // imm[7:4]

    stack.move_var(op_nibbles[2]); // imm[3:1] + x
    stack.from_altstack();
    stack.op_sub(); // imm[3:0]

    let imm = stack.join_count(bit, 7);
    stack.rename(imm, "immediate");
    stack.move_var(rd);

    (rd, imm)
}

// U-Type
// | 0           | 1           | 2           | 3           | 4           | 5           | 6           | 7
// | 31 30 29 28 | 27 26 25 24 | 23 22 21 20 | 19 18 17 16 | 15 14 13 12 | 11 10 9  8  | 7  6  5  4  | 3  2  1  0  |
// | 31 ------------- imm ------------------------------------------- 12 | 11 -- rd ---- 7| ------   opcode -------|

pub fn decode_u_type(
    stack: &mut StackTracker,
    tables: &StackTables,
    opcode: StackVariable,
    expected_opcode: u8,
) -> (StackVariable, StackVariable) {
    stack.set_breakpoint("decode_u_type");
    stack.move_var(opcode);
    let op_nibbles = stack.explode(opcode);

    // stack: 0 1 2 3 4 5 6 7
    let expected = stack.byte(expected_opcode); // ..... 6 7   expected_6  expected_7
    stack.explode(expected);
    stack.op_rot(); //      6  expected_6  7 expected_7
    stack.op_equalverify(); //      6  expected_6  assert(7 == expected_7)

    stack.copy_var(op_nibbles[6]); //      6  expected_6 6_copy
    mask_4bit(stack); //      6  expected_6  6_masked
    stack.op_equalverify(); //      6  assert(expected_6 == 6_masked)

    let imm = stack.join_count(op_nibbles[0], 4);
    stack.rename(imm, "immediate");

    let rd = get_register_address(stack, tables, op_nibbles[5], op_nibbles[6]);
    stack.rename(rd, "rd");

    //The lower 12 bits of the Uimmediate, which are always zero.
    stack.move_var(imm);
    let imm_exp = stack.explode(imm);
    stack.number(0);
    stack.number(0);
    stack.number(0);
    let imm = stack.join_count(imm_exp[0], 7);
    stack.rename(imm, "immediate");
    stack.move_var(rd);

    (imm, rd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::riscv::{decoder::decode_r_type, script_utils::StackTables};
    use bitcoin_script_stack::stack::StackTracker;
    use riscv_decode::types::{BType, JType, RType, SType, UType};

    #[test]
    fn test_decode_s_type() {
        //let opcode = 0x00d62a23; //sw
        let opcode = 0xFE112A23;

        let stype = SType(opcode);
        println!("stype: {:?}", stype);
        println!("rs1: {:?}", stype.rs1());
        println!("rs2: {:?}", stype.rs2());
        println!("imm: {:?}", stype.imm());

        let mut stack = StackTracker::new();
        let tables = StackTables::new(&mut stack, true, true, 0x7, 0x7, 0);
        let opcode = stack.number_u32(opcode);

        let (bit, imm, rs1, rs2) = decode_s_type(&mut stack, &tables, opcode, 0x2);

        stack.move_var(bit);
        stack.drop(bit);

        let expected_rs2 = stack.byte(stype.rs2() as u8 * 4);
        stack.equals(rs2, true, expected_rs2, true);

        let expected_rs1 = stack.byte(stype.rs1() as u8 * 4);
        stack.equals(rs1, true, expected_rs1, true);

        let leadingzeros = number_u32_partial(&mut stack, 0, 5);
        stack.move_var(imm);
        stack.join(leadingzeros);

        let extended = ((stype.imm() as i32) << 19) >> 19;
        let expected_imm = stack.number_u32(extended as u32);
        stack.equals(leadingzeros, true, expected_imm, true);

        tables.drop(&mut stack);

        stack.op_true();

        assert!(stack.run().success);
    }

    #[test]
    fn test_decode_b_type() {
        let opcode = 0x06f580e3; //beq
        let btype = BType(opcode);

        let mut stack = StackTracker::new();
        let tables = StackTables::new(&mut stack, true, true, 0x7, 0x7, 0);
        let opcode = stack.number_u32(opcode);

        let (imm, rs1, rs2) = decode_b_type(&mut stack, &tables, opcode, 0x0);

        let expected_rs2 = stack.byte(btype.rs2() as u8 * 4);
        stack.equals(rs2, true, expected_rs2, true);

        let expected_rs1 = stack.byte(btype.rs1() as u8 * 4);
        stack.equals(rs1, true, expected_rs1, true);

        let extended = ((btype.imm() as i32) << 19) >> 19;
        let expected_imm = stack.number_u32(extended as u32);
        stack.equals(imm, true, expected_imm, true);

        tables.drop(&mut stack);

        stack.op_true();

        assert!(stack.run().success);
    }

    #[test]
    pub fn test_decode_r_type() {
        // define r-type opcode

        let opcode = 0x00A485B3; // ADD 11 9 10
        let rtype = RType(opcode);

        // init stack

        let mut stack = StackTracker::new();
        let tables = StackTables::new(&mut stack, false, false, 3, 6, 0);

        // push opcode

        let opcode_var = stack.number_u32(opcode);
        stack.rename(opcode_var, "opcode_var");

        // decode

        let (d_rs1, d_rs2, d_rd) = decode_r_type(&mut stack, &tables, opcode_var, 0x0, 0x33, 0x00);

        // asserts

        let expected_rs2 = stack.byte(rtype.rs2() as u8 * 4);
        stack.equals(d_rs2, true, expected_rs2, true);

        let expected_rs1 = stack.byte(rtype.rs1() as u8 * 4);
        stack.equals(d_rs1, true, expected_rs1, true);

        let expected_rd = stack.byte(rtype.rd() as u8 * 4);
        stack.equals(d_rd, true, expected_rd, true);

        // clean remaning elements

        tables.drop(&mut stack);

        stack.op_true();

        assert!(stack.run().success);
    }

    #[test]
    pub fn test_decode_u_type() {
        // define u-type opcode

        let opcode = 0x0000_2517; // AUIPC 2 10
        let utype = UType(opcode);

        // init stack

        let mut stack = StackTracker::new();
        let tables = StackTables::new(&mut stack, false, false, 1, 4, 0);

        // push opcode

        let opcode_var = stack.number_u32(opcode);
        stack.rename(opcode_var, "opcode_var");

        // decode

        let (imm, d_rd) = decode_u_type(&mut stack, &tables, opcode_var, 0x17);

        //asserts
        let expected_rd = stack.byte(utype.rd() as u8 * 4);
        stack.equals(d_rd, true, expected_rd, true);

        let expected_imm = stack.number_u32(utype.imm() as u32);
        stack.equals(imm, true, expected_imm, true);

        stack.set_breakpoint("before ende");

        // clean remaning elements
        tables.drop(&mut stack);
        stack.op_true();

        assert!(stack.run().success);
    }

    #[test]
    pub fn test_decode_j_type() {
        // define u-type opcode

        let opcode = 0x0100_026f; //jal
        let jtype = JType(opcode);

        // init stack

        let mut stack = StackTracker::new();
        let tables = StackTables::new(&mut stack, false, false, 5, 4, 0);

        // push opcode

        let opcode_var = stack.number_u32(opcode);
        stack.rename(opcode_var, "opcode_var");

        // decode
        let (rd, imm) = decode_j_type(&mut stack, &tables, opcode_var);

        //asserts
        let expected_rd = stack.byte(jtype.rd() as u8 * 4);
        stack.equals(rd, true, expected_rd, true);

        let extended = ((jtype.imm() as i32) << 11) >> 11;
        let expected_imm = stack.number_u32(extended as u32);
        stack.equals(imm, true, expected_imm, true);

        // clean remaning elements
        tables.drop(&mut stack);
        stack.op_true();

        assert!(stack.run().success);
    }
}
