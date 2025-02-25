use bitcoin_script_stack::stack::{StackTracker, StackVariable};

use super::script_utils::*;

pub fn sort_nibbles(stack: &mut StackTracker) {
    stack.op_2dup();
    stack.op_min();
    stack.to_altstack();
    stack.op_max();
    stack.from_altstack();
}

pub fn pc_next(stack: &mut StackTracker, tables: &StackTables, pc: StackVariable) -> StackVariable {
    stack.set_breakpoint("pc_next");
    stack.move_var(pc);
    stack.explode(pc);
    stack.number(4);

    let mut last = StackVariable::null();
    for i in 0..8 {
        stack.op_add();
        if i < 7 {
            stack.op_dup();
        }

        last = stack.get_value_from_table(tables.modulo, None);

        if i < 7 {
            stack.to_altstack();
            stack.get_value_from_table(tables.quotient, None);
        }
    }

    for _ in 0..7 {
        stack.from_altstack();
    }

    stack.rename(last, "write_pc");
    stack.join_count(last, 7)
}

pub fn add_with_bit_extension(
    stack: &mut StackTracker,
    tables: &StackTables,
    value: StackVariable,
    to_add: StackVariable,
    bit_extension: StackVariable,
) -> StackVariable {
    stack.set_breakpoint("add_with_bit_extension");

    //move the value and split the nibbles
    stack.move_var(value);
    stack.explode(value);

    let add_size = stack.get_size(to_add);
    let mut last = StackVariable::null();
    for i in 0..8 {
        if i > 0 {
            stack.op_add();
        }

        if i < add_size {
            stack.move_var_sub_n(to_add, add_size - i - 1);
        } else if i < 7 {
            stack.copy_var(bit_extension);
        } else {
            stack.move_var(bit_extension);
        }

        stack.op_add();

        if i < 7 {
            stack.op_dup();
        }

        last = stack.get_value_from_table(tables.modulo, None);

        if i < 7 {
            stack.to_altstack();
            stack.get_value_from_table(tables.quotient, None);
        }
    }

    for _ in 0..7 {
        stack.from_altstack();
    }

    stack.rename(last, "add_bit_ext");
    stack.join_count(last, 7)
}

pub fn sub(
    stack: &mut StackTracker,
    tables: &StackTables,
    value: StackVariable,
    to_sub: StackVariable,
) -> StackVariable {
    stack.set_breakpoint("sub");

    stack.move_var(value); // move the value and split nibbles
    stack.explode(value);

    let sub_size = stack.get_size(to_sub);
    let mut last = StackVariable::null();
    for i in 0..8 {
        stack.move_var_sub_n(to_sub, sub_size - i - 1);

        stack.op_sub(); // normal sub

        if i > 0 {
            stack.from_altstack(); // get borrow from alt_stack
            stack.op_sub(); // subtracts 0 or 1
        }

        stack.op_dup(); // save after normal sub to calculate borrow
        stack.op_dup(); // used for op_add
        stack.op_dup(); // used for ifless
        if_less(stack, 0, 16, 0); // check if subtraction goes into negative number
        stack.op_add(); // handle negative subtraction

        last = stack.get_value_from_table(tables.modulo, None); // wrap around 16
        if i < 7 {
            stack.to_altstack(); // save partial result into alt_stack
            if_less(stack, 0, 1, 0); // calculate borrow with the initial subtraction
            stack.to_altstack(); // send borrow to alt_stack
            stack.op_drop(); // drop normal sub
        }
    }

    stack.to_altstack(); // send last nibble to altstack
    stack.op_drop(); // drop remaining elements 1/2
    stack.op_drop(); // drop remaining elements 2/2

    for _ in 0..8 {
        stack.from_altstack(); // retrieve nibble from altstack
    }

    stack.join_count(last, 7) // join nibbles to get the final result
}

pub fn logic_with_bit_extension(
    stack: &mut StackTracker,
    tables: &StackTables,
    value: StackVariable,
    to_add: StackVariable,
    bit_extension: StackVariable,
    logic: LogicOperation,
) -> StackVariable {
    stack.set_breakpoint(&format!("logic_{:?}_with_bit_extension", logic));

    let add_size = stack.get_size(to_add);
    let extension_size = 8 - add_size;

    for i in 0..8 {
        stack.move_var_sub_n(value, 0);
        if i < extension_size {
            if i < extension_size - 1 {
                stack.copy_var(bit_extension);
            } else {
                stack.move_var(bit_extension);
            }
        } else {
            stack.move_var_sub_n(to_add, 0);
        }

        tables.logic_op(stack, &logic);
    }

    stack.join_in_stack(8, None, Some(&format!("logic_{:?}_bit_ext", logic)))
}

pub fn shift_value_with_bits(
    stack: &mut StackTracker,
    value: StackVariable,
    mut to_shift: StackVariable,
    right: bool,
    msb: bool,
) -> StackVariable {
    stack.set_breakpoint(&format!(
        "shift_{}{}",
        if right { "right" } else { "left" },
        if msb { "_msb" } else { "" }
    ));

    stack.move_var(to_shift);
    stack.explode(to_shift);
    to_shift = u4_to_u8(stack);

    stack.move_var(value);

    shift_number(stack, to_shift, value, right, msb)
}

pub fn bit_extend(stack: &mut StackTracker, value: StackVariable) -> StackVariable {
    stack.set_breakpoint("bit_extend");
    let size = stack.get_size(value);
    let needed = 8 - size;
    stack.copy_var_sub_n(value, 0);
    let mut first = StackVariable::null();
    for i in 0..needed {
        if i < needed - 1 {
            stack.op_dup();
        }
        let ret = if_greater(stack, 7, 0xF, 0);
        if i == 0 {
            first = ret;
        }
        if i < needed - 1 {
            stack.op_swap();
        }
    }
    stack.move_var(value);
    stack.join_count(first, needed);
    first
}

pub fn is_lower_than_slti(
    stack: &mut StackTracker,
    value: StackVariable,
    than: StackVariable,
    unsigned: bool,
    immediate: bool,
) -> StackVariable {
    stack.set_breakpoint(&format!(
        "is_lower_{}",
        if unsigned { "unsigned" } else { "signed" }
    ));

    stack.move_var(value);

    let than_extended = if immediate {
        Some(bit_extend(stack, than))
    } else {
        None
    };

    let result = is_lower_than(stack, value, than_extended.unwrap_or(than), unsigned);
    let first = stack.number(0);
    stack.op_dup();
    stack.op_2dup();
    stack.op_3dup();
    stack.move_var(result);
    stack.rename(first, "is_lower_than");
    stack.join_count(first, 7);
    first
}

pub fn shift_value_with_tables(
    stack: &mut StackTracker,
    tables: &StackTables,
    value: StackVariable,
    to_shift: StackVariable,
    right: bool,
    msb: bool,
) -> StackVariable {
    stack.set_breakpoint(&format!(
        "shift_{}{}",
        if right { "right" } else { "left" },
        if msb { "_msb" } else { "" }
    ));

    //shift the value to shift two nibbles to the right to divide by for and get
    //the ammount of nibbles that needs to be shifted
    let to_shift_copy = stack.copy_var(to_shift);
    stack.explode(to_shift_copy);
    let nibbles_to_shift = tables.shift_2nb(stack, true, 2);
    stack.rename(nibbles_to_shift, "nib_2_shift");

    //move the whole value the necessary amount of nibbles to the right
    if !right {
        // is left
        stack.move_var(value);
    }
    let zero = stack.number(0); //TODO: use msb
    stack.op_dup();
    stack.op_2dup();
    stack.op_2dup();
    stack.op_2dup();
    if right {
        stack.move_var(value);
    }

    let first = if right { zero } else { value };
    stack.join_count(first, 8);

    //forms the number to be shifted
    let mut to_shift_parts = Vec::new();
    if right {
        to_shift_parts.push(stack.number(0)); //TODO: use msb
    }
    for i in (0..8).rev() {
        stack.number(i);
        if i > 0 {
            stack.copy_var(nibbles_to_shift);
        } else {
            stack.move_var(nibbles_to_shift);
        }
        stack.op_add();
        to_shift_parts.push(stack.get_value_from_table(first, None));
    }
    if !right {
        to_shift_parts.push(stack.number(0));
    }
    let number = stack.join_count(to_shift_parts[0], 8);

    //drop completion values
    stack.move_var(first);
    stack.drop(first);

    //calculate shift value
    stack.move_var_sub_n(to_shift, 1);
    stack.number(3);
    tables.logic_op(stack, &LogicOperation::And);
    stack.to_altstack();

    stack.move_var_sub_n(to_shift, 0);
    stack.op_drop();

    for i in 0..8 {
        stack.move_var_sub_n(number, 0);
        if i < 7 {
            stack.copy_var_sub_n(number, 0);
        } else {
            stack.move_var_sub_n(number, 0);
        }
        stack.from_altstack();
        if i < 7 {
            stack.op_dup();
            stack.to_altstack();
        }
        tables.shift_2nb_dynamic(stack, right);
    }

    stack.join_in_stack(8, None, None)
}

#[cfg(test)]
mod tests {
    use crate::riscv::script_utils::*;

    use super::*;

    #[test]
    fn test_bit_extend() {
        let mut stack = StackTracker::new();
        let number = stack.byte(0x81);
        let extended = bit_extend(&mut stack, number);
        let expected = stack.number_u32(0xffff_ff81);
        stack.equals(extended, true, expected, true);

        let number = stack.byte(0x71);
        let extended = bit_extend(&mut stack, number);
        let expected = stack.number_u32(0x71);
        stack.equals(extended, true, expected, true);

        stack.op_true();
        assert!(stack.run().success);
    }

    #[test]
    fn test_shift() {
        let mut stack = StackTracker::new();
        let size = stack.get_script().len();
        let tables = StackTables::new(&mut stack, false, false, 0xf, 0xf, LOGIC_MASK_AND);
        let original = 0xF120_4567;
        let shift = 13;
        let expected = original >> shift;
        //let expected = ((original as u64) << shift) as u32;

        let value = stack.number_u32(original);

        let to_shift = stack.byte(shift);

        let result = shift_value_with_tables(&mut stack, &tables, value, to_shift, true, false);

        let expected = stack.number_u32(expected);

        stack.equals(result, true, expected, true);

        tables.drop(&mut stack);

        println!("Script size: {}", stack.get_script().len() - size);
        stack.op_true();

        assert!(stack.run().success);
    }

    #[test]
    fn test_logic_and() {
        let mut stack = StackTracker::new();
        let tables = StackTables::new(&mut stack, false, false, 0, 0, LOGIC_MASK_AND);
        let value = stack.number_u32(0x12FF_FFFF);

        let to_add = stack.byte(0x82);
        let bit_extension = stack.number(0);

        let result = logic_with_bit_extension(
            &mut stack,
            &tables,
            value,
            to_add,
            bit_extension,
            LogicOperation::And,
        );

        let expected = stack.number_u32(0x82);

        stack.equals(result, true, expected, true);

        tables.drop(&mut stack);

        stack.op_true();

        assert!(stack.run().success);
    }

    #[test]
    fn test_logic_or() {
        let mut stack = StackTracker::new();
        let tables = StackTables::new(&mut stack, false, false, 0, 0, LOGIC_MASK_OR);
        let value = stack.number_u32(0x12FF_FF0F);

        let to_add = stack.byte(0x82);
        let bit_extension = stack.number(0);

        let start = stack.get_script().len();
        let result = logic_with_bit_extension(
            &mut stack,
            &tables,
            value,
            to_add,
            bit_extension,
            LogicOperation::Or,
        );
        let end = stack.get_script().len();
        println!("Script size: {}", end - start);

        let expected = stack.number_u32(0x12FF_FF8F);

        stack.equals(result, true, expected, true);

        tables.drop(&mut stack);

        stack.op_true();

        assert!(stack.run().success);
    }

    #[test]
    fn test_logic_xor() {
        let mut stack = StackTracker::new();
        let tables = StackTables::new(&mut stack, false, false, 0, 0, LOGIC_MASK_XOR);
        let value = stack.number_u32(0x12FF_FF0F);

        let to_add = stack.byte(0x82);
        let bit_extension = stack.number(0);

        let start = stack.get_script().len();
        let result = logic_with_bit_extension(
            &mut stack,
            &tables,
            value,
            to_add,
            bit_extension,
            LogicOperation::Xor,
        );
        let end = stack.get_script().len();
        println!("Script size: {}", end - start);

        let expected = stack.number_u32(0x12FF_FF8D);

        stack.equals(result, true, expected, true);

        tables.drop(&mut stack);

        stack.op_true();

        assert!(stack.run().success);
    }

    #[test]
    fn test_sub() {
        let mut stack = StackTracker::new();
        let tables = StackTables::new(&mut stack, true, false, 3, 6, 0);

        let num1 = stack.number_u32(0x1010);
        let num2 = stack.number_u32(0x103);

        let res = sub(&mut stack, &tables, num1, num2);

        stack.to_altstack();
        tables.drop(&mut stack);
        stack.from_altstack();

        let expected = stack.number_u32(0xF0D);
        stack.equals(expected, true, res, true);

        stack.op_true();

        assert!(stack.run().success);
    }
}
