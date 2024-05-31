use bitcoin_script_stack::stack::{StackTracker, StackVariable};

use super::script_utils::*;


// input: it assumes the register is encoded in 5 bits from 3 to 7
// to convert into the number of the register, we need to shift 3 bits to the right
// but as we need to get the address and we need to multiply by 4, we just need to shift 1 right
// as the low part also might have garbage on the first 3 bit we will just use and if to ask for the 3 bit and the return it i
// | high    | low     |  
// | 7 6 5 4 | 3 2 1 0 |
// 
pub fn get_register_address(stack: &mut StackTracker, tables: &StackTables, high: StackVariable, low: StackVariable) -> StackVariable {

    stack.copy_var(high);
    let mut ret_high = stack.get_value_from_table(tables.rshift.shift_1, None);

    stack.move_var(high);
    stack.get_value_from_table(tables.lshift.shift_3, None);

    stack.move_var(low);
    if_greater(stack, 7, 4, 0);

    stack.op_add();

    stack.join(&mut ret_high);
    ret_high
}



// I-Type
// | 0           | 1           | 2           | 3           | 4           | 5           | 6           | 7
// | 31 30 29 28 | 27 26 25 24 | 23 22 21 20 | 19 18 17 16 | 15 14 13 12 | 11 10 9  8  | 7  6  5  4  | 3  2  1  0  |
// | 31 ------------- imm --------------- 20 | 19 --- rs1 -- 15| --------| 11 -- rd ---- 7| -----------------------| 

pub fn decode_i_type(stack: &mut StackTracker, tables: &StackTables, opcode: StackVariable) -> (StackVariable, StackVariable, StackVariable, StackVariable) {
    stack.move_var(opcode);
    let mut op_nibbles = stack.explode(opcode);
    let imm = stack.join_count(&mut op_nibbles[0], 2);
    stack.rename(imm, "immediate");

    // 7 is not used
    stack.drop(op_nibbles[7]);

    let rs1 = get_register_address(stack, tables, op_nibbles[3], op_nibbles[4]);
    stack.rename(rs1, "rs1");
    let rd = get_register_address(stack, tables, op_nibbles[5], op_nibbles[6]);
    stack.rename(rd, "rd");

    stack.copy_var_sub_n(imm, 0);
    let bit = if_greater(stack, 7, 0xf, 0);

    (imm, rs1, rd, bit)
}
