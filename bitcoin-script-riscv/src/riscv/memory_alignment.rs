use bitcoin_script_stack::stack::{StackTracker, StackVariable};
use riscv_decode::Instruction::{self, *};

use super::{
    operations::bit_extend,
    script_utils::{number_u32_partial, WordTable},
};

pub fn load_modulo_4_table(stack: &mut StackTracker) -> StackVariable {
    for i in (0..16).rev() {
        stack.number(i % 4);
    }
    stack.join_in_stack(16, None, Some("modulo_4_table"))
}

pub fn load_lower_half_nibble_table(stack: &mut StackTracker) -> StackVariable {
    for i in (0..16).rev() {
        stack.number(i & 0b11);
    }
    stack.join_in_stack(16, None, Some("lower_half_nibble_table"))
}

pub fn load_upper_half_nibble_table(stack: &mut StackTracker) -> StackVariable {
    for i in (0..16).rev() {
        stack.number(i >> 2);
    }
    stack.join_in_stack(16, None, Some("upper_half_nibble_table"))
}

pub fn is_aligned(
    stack: &mut StackTracker,
    mem_address: StackVariable,
    consume: bool,
    lower_half_nibble_table: &StackVariable,
) -> StackVariable {
    stack.copy_var_sub_n(mem_address, 7);
    stack.get_value_from_table(*lower_half_nibble_table, None);

    stack.number(0);
    let result = stack.op_equal();

    if consume {
        stack.move_var(mem_address);
        stack.drop(mem_address);
    }

    result
}

//get's the memory address to be read, and returns the aligned memory address and the alignment delta
pub fn align_memory(
    stack: &mut StackTracker,
    mem_address: StackVariable,
) -> (StackVariable, StackVariable) {
    let parts = stack.explode(mem_address);

    let table = load_modulo_4_table(stack);

    stack.move_var(parts[7]); // address table x
    stack.op_dup(); // address table x  x

    stack.get_value_from_table(table, None); // address table x (x%4)
    stack.op_dup(); // address  table x (x%4) (x%4)
    stack.to_altstack(); // address table x (x%4) | (x%4)

    stack.op_negate(); // address table x -(x%4)| (x%4)
    stack.op_add(); // address table (x-(x%4)) | (x%4)
    stack.to_altstack(); // address table | (x-(x%4)) (x%4)

    stack.drop(table);

    stack.from_altstack(); // address (x-(x%4)) | (x%4)
    let aligned = stack.join_count(parts[0], 7);
    stack.rename(aligned, "aligned");
    let alignment = stack.from_altstack();
    stack.rename(alignment, "alignment");
    (aligned, alignment)
}

#[allow(clippy::too_many_arguments)]
pub fn choose_nibbles(
    stack: &mut StackTracker,
    data: StackVariable,
    _alignment: StackVariable,
    nibs: u32,
    max_extra: u8,
    pre_pad: u8,
    unsigned: bool,
    post: u8,
) -> StackVariable {
    stack.to_altstack();
    stack.to_altstack();

    for _ in 0..max_extra {
        stack.number(0);
    }

    stack.from_altstack();
    stack.explode(data);

    for _ in 0..post {
        stack.number(0);
    }

    stack.from_altstack();
    stack.op_dup();
    stack.op_add();

    stack.op_dup();
    stack.to_altstack();

    for i in 0..nibs {
        stack.op_pick();
        stack.from_altstack();
        stack.op_swap();
        stack.to_altstack();

        if i < nibs - 1 {
            stack.op_1add();
            stack.op_dup();
            stack.to_altstack();
        } else {
            stack.op_drop();
        }
    }

    for _ in 0..(4 + ((max_extra + post) / 2)) {
        stack.op_2drop();
    }

    let result = stack.from_altstack_joined(nibs, "nibs");
    if pre_pad == 0 {
        return result;
    }

    if unsigned {
        let partial = number_u32_partial(stack, 0x0000_0000, pre_pad);
        stack.move_var(result);
        stack.join_count(partial, 1)
    } else {
        bit_extend(stack, result)
    }
}

pub fn create_alignment_table(
    stack: &mut StackTracker,
    instruction: &Instruction,
    round: u8,
) -> WordTable {
    //TODO: Assert valid alignment in runtime
    match round {
        1 => match instruction {
            Sb(_) => WordTable::new(
                stack,
                vec![0x1111_1100, 0x1111_0011, 0x1100_1111, 0x0011_1111],
            ),
            Sh(_) => WordTable::new(
                stack,
                vec![0x1111_0000, 0x1100_0011, 0x0000_1111, 0x0011_1111],
            ),
            Sw(_) => WordTable::new(
                stack,
                vec![0x0000_0000, 0x0000_0011, 0x0000_1111, 0x0011_1111],
            ),
            _ => panic!("Unreachable"),
        },
        2 => match instruction {
            Sh(_) => WordTable::new(
                stack,
                vec![0x0000_0000, 0x0000_0000, 0x0000_0000, 0x1111_1100],
            ),
            Sw(_) => WordTable::new(
                stack,
                vec![0x0000_0000, 0x1111_1100, 0x1111_0000, 0x1100_0000],
            ),
            _ => panic!("Unreachable"),
        },
        _ => panic!("Unreachable"),
    }
}

pub fn create_alignment_table_2(
    stack: &mut StackTracker,
    instruction: &Instruction,
    round: u8,
) -> WordTable {
    //TODO: Assert valid alignment in runtime
    match round {
        1 => match instruction {
            Sb(_) => WordTable::new(
                stack,
                vec![0x0000_0011, 0x0000_0011, 0x0000_0011, 0x0000_0011],
            ),
            Sh(_) => WordTable::new(
                stack,
                vec![0x0000_1111, 0x0000_1111, 0x0000_1111, 0x0000_0011],
            ),
            Sw(_) => WordTable::new(
                stack,
                vec![0x0000_0000, 0x0011_1111, 0x0000_1111, 0x0000_0011],
            ),
            _ => panic!("Unreachable"),
        },
        2 => match instruction {
            Sh(_) => WordTable::new(
                stack,
                vec![0x0000_0000, 0x0000_0000, 0x0000_0000, 0x0000_1100],
            ),
            Sw(_) => WordTable::new(
                stack,
                vec![0x0000_0000, 0x1100_0000, 0x1111_0000, 0x1111_1100],
            ),
            _ => panic!("Unreachable"),
        },
        _ => panic!("Unreachable"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modulo_4() {
        for i in 0..16 {
            let mut stack = StackTracker::new();
            let table = load_modulo_4_table(&mut stack);
            stack.number(i);
            stack.get_value_from_table(table, None);
            stack.number(i % 4);
            stack.op_equalverify();
            stack.drop(table);
            stack.op_true();
            assert!(stack.run().success);
        }
    }

    fn test_is_aligned_helper(address: u32) -> bool {
        let mut stack = StackTracker::new();
        let address = stack.number_u32(address);
        let table = load_lower_half_nibble_table(&mut stack);
        is_aligned(&mut stack, address, true, &table);
        stack.move_var(table);
        stack.drop(table);
        stack.run().success
    }

    #[test]
    fn test_is_aligned() {
        assert!(test_is_aligned_helper(0x0000_0000));
        assert!(!test_is_aligned_helper(0x0000_0001));
        assert!(!test_is_aligned_helper(0x0000_0002));
        assert!(!test_is_aligned_helper(0x0000_0003));
        assert!(test_is_aligned_helper(0x0000_0004));
    }

    #[test]
    fn test_align_memory() {
        let mut stack = StackTracker::new();
        let address = stack.number_u32(0x0000_0003);
        let (aligned, _) = align_memory(&mut stack, address);
        stack.number(3);
        stack.op_equalverify();
        let expected = stack.number_u32(0x0000_0000);
        stack.equals(aligned, true, expected, true);
        stack.op_true();
        assert!(stack.run().success);
    }

    fn test_choose_byte_helper(number: u32, alignment: u32, expected: u32, unsigned: bool) {
        let mut stack = StackTracker::new();
        let value = stack.number_u32(number);
        let alignment = stack.number(alignment);
        let result = choose_nibbles(&mut stack, value, alignment, 2, 0, 6, unsigned, 0);
        let expected = stack.number_u32(expected);
        stack.equals(result, true, expected, true);
        stack.op_true();
        assert!(stack.run().success);
    }

    #[test]
    fn test_choose_byte() {
        test_choose_byte_helper(0x1234_5678, 0, 0x0000_0078, true);
        test_choose_byte_helper(0x1234_56F8, 0, 0x0000_00F8, true);
        test_choose_byte_helper(0x1234_56F8, 0, 0xFFFF_FFF8, false);

        test_choose_byte_helper(0x1234_5678, 1, 0x0000_0056, true);
        test_choose_byte_helper(0x1234_F678, 1, 0x0000_00F6, true);
        test_choose_byte_helper(0x1234_F678, 1, 0xFFFF_FFF6, false);
    }

    fn test_choose_half_helper(number: u32, alignment: u32, expected: u32, unsigned: bool) {
        let mut stack = StackTracker::new();
        let value = stack.number_u32(number);
        let alignment = stack.number(alignment);
        let result = choose_nibbles(&mut stack, value, alignment, 4, 2, 4, unsigned, 0);
        let expected = stack.number_u32(expected);
        stack.equals(result, true, expected, true);
        stack.op_true();
        assert!(stack.run().success);
    }

    #[test]
    fn test_choose_half() {
        test_choose_half_helper(0x1234_5678, 0, 0x0000_5678, false);
        test_choose_half_helper(0x1234_5678, 1, 0x0000_3456, false);
        test_choose_half_helper(0x1284_5678, 1, 0x0000_8456, true);
        test_choose_half_helper(0x1284_5678, 1, 0xffff_8456, false);
        test_choose_half_helper(0x1234_5678, 2, 0x0000_1234, false);
        test_choose_half_helper(0x1234_5678, 3, 0x0000_0012, false);
    }

    fn test_choose_half_round_2_helper(number: u32, alignment: u32, expected: u32, unsigned: bool) {
        let mut stack = StackTracker::new();
        let value = stack.number_u32(number);
        let alignment = stack.number(alignment);
        let result = choose_nibbles(&mut stack, value, alignment, 4, 0, 4, unsigned, 8);
        let expected = stack.number_u32(expected);
        stack.equals(result, true, expected, true);
        stack.op_true();
        assert!(stack.run().success);
    }

    #[test]
    fn test_choose_half_round_2() {
        test_choose_half_round_2_helper(0x1234_5678, 3, 0x0000_7800, false);
        test_choose_half_round_2_helper(0x1234_5678, 3, 0x0000_7800, true);
        test_choose_half_round_2_helper(0x1234_5688, 3, 0xffff_8800, false);
        test_choose_half_round_2_helper(0x1234_5688, 3, 0x0000_8800, true);
    }

    fn test_choose_word_helper(
        number: u32,
        alignment: u32,
        expected: u32,
        max_extra: u8,
        post: u8,
    ) {
        let mut stack = StackTracker::new();
        let value = stack.number_u32(number);
        let alignment = stack.number(alignment);
        let result = choose_nibbles(&mut stack, value, alignment, 8, max_extra, 0, true, post);
        let expected = stack.number_u32(expected);
        stack.equals(result, true, expected, true);
        stack.op_true();
        assert!(stack.run().success);
    }

    #[test]
    fn test_choose_word() {
        test_choose_word_helper(0x1234_5678, 0, 0x1234_5678, 6, 0);
        test_choose_word_helper(0x1234_5678, 1, 0x0012_3456, 6, 0);
        test_choose_word_helper(0x1234_5678, 2, 0x0000_1234, 6, 0);
        test_choose_word_helper(0x1234_5678, 3, 0x0000_0012, 6, 0);

        test_choose_word_helper(0x1234_5678, 1, 0x7800_0000, 0, 8);
        test_choose_word_helper(0x1234_5678, 2, 0x5678_0000, 0, 8);
        test_choose_word_helper(0x1234_5678, 3, 0x3456_7800, 0, 8);
    }
}
