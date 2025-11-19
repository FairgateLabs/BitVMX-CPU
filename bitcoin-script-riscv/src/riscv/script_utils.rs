use bitcoin_script_stack::stack::{StackTracker, StackVariable};

pub use bitcoin_script::{define_pushable, script};
define_pushable!();
pub use bitcoin::ScriptBuf as Script;
use bitvmx_cpu_definitions::memory::{Chunk, MemoryAccessType, SectionDefinition};

use super::operations::{sort_nibbles, sub};

pub fn u4_to_u8(stack: &mut StackTracker) -> StackVariable {
    stack.op_swap();
    for _ in 0..4 {
        stack.op_dup();
        stack.op_add();
    }

    stack.op_add()
}

pub fn reverse_4_from_stack(stack: &mut StackTracker) {
    for _ in 0..4 {
        stack.from_altstack();
    }
    stack.op_swap();
    stack.op_2swap();
    stack.op_swap();
}

pub fn reverse(stack: &mut StackTracker, var: StackVariable) -> StackVariable {
    let size = stack.get_size(var);
    let var_name = stack.get_var_name(var);
    let mut ret = Vec::new();
    for i in (0..size).rev() {
        ret.push(stack.move_var_sub_n(var, i));
    }
    let size_join = ret.len() - 1;
    stack.rename(ret[0], &format!("reversed({})", var_name));
    stack.join_count(ret[0], size_join as u32)
}

//leaves the result in the stack in reverse order
pub fn nib_to_bin(stack: &mut StackTracker) {
    for i in [8, 4, 2, 1] {
        if i != 1 {
            stack.op_dup();
        }
        stack.custom(
            script! {
                { i }
                OP_GREATERTHANOREQUAL
                OP_IF
                    if i != 1 {
                        { i}
                        OP_SUB
                    }
                    1
                OP_ELSE
                    0
                OP_ENDIF
                OP_TOALTSTACK
            },
            1,
            false,
            1,
            &format!("bit({})", i),
        );
    }
}

pub fn static_right_shift_2(
    stack: &mut StackTracker,
    tables: &StackTables,
    number: StackVariable,
) -> StackVariable {
    let size = stack.get_size(number);
    for n in 0..size {
        stack.move_var_sub_n(number, 0);
        if n < size - 1 {
            stack.op_dup();
            stack.get_value_from_table(tables.lshift.shift_2, None);
            stack.to_altstack();
        }

        stack.get_value_from_table(tables.rshift.shift_2, None);

        if n > 0 {
            stack.op_add();
        }

        if n < size - 1 {
            stack.from_altstack();
        }
    }

    stack.join_in_stack(size, None, Some("right_shift_2"))
}

//expects the shift ammount and the number to be shifted on the stack
pub fn shift_number(
    stack: &mut StackTracker,
    mut to_shift: StackVariable,
    number: StackVariable,
    right: bool,
    msb: bool,
) -> StackVariable {
    let size = stack.get_size(number);
    let number = reverse(stack, number);
    stack.explode(number);
    for _ in 0..size {
        nib_to_bin(stack);
    }

    if !right {
        for _ in 0..size * 4 {
            stack.number(0);
        }
    }

    for _ in 0..size * 4 {
        stack.from_altstack();
        //reverse_4(&mut stack);
    }

    if right {
        if msb {
            stack.op_dup();
            stack.op_dup();
            for _ in 0..size * 2 - 1 {
                stack.op_2dup();
            }
        } else {
            for _ in 0..size * 4 {
                stack.number(0);
            }
        }
        stack.number(size * 4);
    }

    stack.move_var(to_shift);
    if right {
        to_shift = stack.op_sub();
    }

    for i in 0..size {
        stack.number(0);
        for n in 0..4 {
            if n > 0 {
                stack.op_dup();
                stack.op_add();
            }

            stack.op_over();
            stack.number(i * 4 + n + 2);
            stack.op_add();
            stack.op_pick();

            stack.op_add();
        }

        stack.to_altstack();
    }

    stack.drop(to_shift);
    for _ in 0..size * 4 {
        stack.op_2drop();
    }

    let shifted = stack.from_altstack_joined(size, "shift_left");
    reverse(stack, shifted)
}

pub fn if_greater(stack: &mut StackTracker, than: u8, then: u8, else_: u8) -> StackVariable {
    stack
        .custom(
            script! {
                { than }
                OP_GREATERTHAN
                OP_IF
                    { then }
                OP_ELSE
                    { else_}
                OP_ENDIF
            },
            1,
            true,
            0,
            &format!("(x>{})?{}:{}", than, then, else_),
        )
        .unwrap()
}

pub fn if_less(stack: &mut StackTracker, than: u8, then: u8, else_: u8) -> StackVariable {
    stack
        .custom(
            script! {
                { than }
                OP_LESSTHAN
                OP_IF
                    { then }
                OP_ELSE
                    { else_}
                OP_ENDIF
            },
            1,
            true,
            0,
            &format!("(x>{})?{}:{}", than, then, else_),
        )
        .unwrap()
}

pub fn sub_1_if_positive(stack: &mut StackTracker) -> StackVariable {
    stack
        .custom(
            script! {
                OP_FROMALTSTACK
                OP_DUP
                OP_DUP
                0
                OP_GREATERTHAN
                OP_IF
                    1
                    OP_SUB
                OP_ELSE
                    OP_DROP
                    0
                OP_ENDIF
                OP_TOALTSTACK
            },
            0,
            true,
            0,
            "sub_1_if_positive",
        )
        .unwrap()
}

pub fn choose(stack: &mut StackTracker) -> StackVariable {
    stack
        .custom(
            script! {
                0
                OP_GREATERTHAN
                OP_IF
                    1
                OP_ELSE
                    0
                OP_ENDIF
                OP_ROLL
                OP_SWAP
                OP_DROP
            },
            3,
            true,
            0,
            "choose",
        )
        .unwrap()
}

pub fn move_and_drop(stack: &mut StackTracker, var: StackVariable) {
    stack.move_var(var);
    stack.drop(var);
}

pub fn number_u32_partial(stack: &mut StackTracker, number: u32, nibbles: u8) -> StackVariable {
    assert!(nibbles < 8);
    let mut ret = Vec::new();
    for i in 0..nibbles {
        ret.push(stack.number((number >> ((7 - i) * 4)) & 0xF));
    }
    stack.rename(ret[0], &format!("number_0x{:08x}[0:{}]", number, nibbles));
    if nibbles > 1 {
        stack.join_count(ret[0], (nibbles - 1) as u32)
    } else {
        ret[0]
    }
}

pub fn quotient_table(stack: &mut StackTracker) -> StackVariable {
    let table = stack.number(1);
    stack.op_dup();
    stack.op_2dup();
    stack.op_3dup();
    stack.op_3dup();
    stack.op_3dup();
    stack.op_3dup();
    stack.number(0);
    stack.op_dup();
    stack.op_2dup();
    stack.op_3dup();
    stack.op_3dup();
    stack.op_3dup();
    stack.op_3dup();
    stack.rename(table, "quotient_table");
    stack.join_count(table, 31)
}

pub fn quotient_table_ex(stack: &mut StackTracker, max: u32) -> StackVariable {
    let mut modulo = Vec::new();
    for i in (0..max).rev() {
        modulo.push(stack.number(i / 16));
    }
    stack.rename(modulo[0], &format!("quotient_table_{}", max));
    stack.join_count(modulo[0], max - 1)
}

pub fn modulo_table(stack: &mut StackTracker, max: u32) -> StackVariable {
    let mut modulo = Vec::new();
    for i in (0..max).rev() {
        modulo.push(stack.number(i % 16));
    }
    stack.rename(modulo[0], &format!("modulo_table_{}", max));
    stack.join_count(modulo[0], max - 1)
}

pub fn rshift_table(stack: &mut StackTracker, n: u8) -> StackVariable {
    let mut parts = Vec::new();
    for i in (0..16).rev() {
        parts.push(stack.number(i >> n));
    }
    stack.rename(parts[0], &format!("shiftr_{}", n));
    stack.join_count(parts[0], 15)
}

pub fn shift_lookup(stack: &mut StackTracker) -> StackVariable {
    let mut parts = Vec::new();
    for i in 0..5 {
        //is not in reverse because the tables itself are in cresendo
        parts.push(stack.number(i * 16 + 5));
    }
    stack.rename(parts[0], "shift_lookup");
    stack.join_count(parts[0], 4)
}

pub fn lshift_table(stack: &mut StackTracker, n: u8) -> StackVariable {
    let mut parts = Vec::new();
    for i in (0..16).rev() {
        parts.push(stack.number((i << n) & 0xF));
    }
    stack.rename(parts[0], &format!("shiftl_{}", n));
    stack.join_count(parts[0], 15)
}

pub fn half_lookup(stack: &mut StackTracker) -> StackVariable {
    let mut parts = Vec::new();
    let mut prev = 0;
    parts.push(0);
    for i in 1..16 {
        prev = 16 + prev - i;
        parts.push(prev);
    }
    let parts = parts
        .iter()
        .rev()
        .map(|x| stack.number(*x))
        .collect::<Vec<_>>();
    stack.rename(parts[0], "half_lookup");
    stack.join_count(parts[0], 15)
}

#[derive(Debug)]
pub enum LogicOperation {
    And,
    Or,
    Xor,
    MulMod,
    MulQuotient,
}

pub fn logic_table(stack: &mut StackTracker, logic: LogicOperation) -> StackVariable {
    let mut parts = Vec::new();
    for n in (0..16).rev() {
        for i in (n..16).rev() {
            let number = match logic {
                LogicOperation::And => i & n,
                LogicOperation::Or => i | n,
                LogicOperation::Xor => i ^ n,
                LogicOperation::MulMod => (i * n) % 16,
                LogicOperation::MulQuotient => (i * n) / 16,
            };
            parts.push(stack.number(number));
        }
    }
    stack.rename(parts[0], &format!("logic_{:?}", logic));
    stack.join_count(parts[0], 135)
}

pub struct StackLogicTables {
    pub and: StackVariable,
    pub or: StackVariable,
    pub xor: StackVariable,
    pub mul_mod: StackVariable,
    pub mul_quotient: StackVariable,
    pub lookup: StackVariable,
}

pub const LOGIC_MASK_AND: u8 = 1;
pub const LOGIC_MASK_OR: u8 = 2;
pub const LOGIC_MASK_XOR: u8 = 4;
pub const LOGIC_MASK_MUL: u8 = 8;

impl StackLogicTables {
    pub fn new(stack: &mut StackTracker, mask: u8) -> StackLogicTables {
        StackLogicTables {
            and: if mask & LOGIC_MASK_AND == LOGIC_MASK_AND {
                logic_table(stack, LogicOperation::And)
            } else {
                StackVariable::null()
            },
            or: if mask & LOGIC_MASK_OR == LOGIC_MASK_OR {
                logic_table(stack, LogicOperation::Or)
            } else {
                StackVariable::null()
            },
            xor: if mask & LOGIC_MASK_XOR == LOGIC_MASK_XOR {
                logic_table(stack, LogicOperation::Xor)
            } else {
                StackVariable::null()
            },
            mul_mod: if mask & LOGIC_MASK_MUL == LOGIC_MASK_MUL {
                logic_table(stack, LogicOperation::MulMod)
            } else {
                StackVariable::null()
            },
            mul_quotient: if mask & LOGIC_MASK_MUL == LOGIC_MASK_MUL {
                logic_table(stack, LogicOperation::MulQuotient)
            } else {
                StackVariable::null()
            },
            lookup: if mask != 0 {
                half_lookup(stack)
            } else {
                StackVariable::null()
            },
        }
    }

    pub fn drop(&self, stack: &mut StackTracker) {
        drop_if(stack, &self.lookup);
        drop_if(stack, &self.mul_quotient);
        drop_if(stack, &self.mul_mod);
        drop_if(stack, &self.xor);
        drop_if(stack, &self.or);
        drop_if(stack, &self.and);
    }

    pub fn get_logic_table(&self, logic: &LogicOperation) -> StackVariable {
        match logic {
            LogicOperation::And => self.and,
            LogicOperation::Or => self.or,
            LogicOperation::Xor => self.xor,
            LogicOperation::MulMod => self.mul_mod,
            LogicOperation::MulQuotient => self.mul_quotient,
        }
    }
}

pub fn drop_if(stack: &mut StackTracker, var: &StackVariable) {
    if !var.is_null() {
        stack.drop(*var);
    }
}

pub struct StackShiftTables {
    pub shift_0: StackVariable, // used to store the value not shifted
    pub shift_1: StackVariable,
    pub shift_2: StackVariable,
    pub shift_3: StackVariable,
    pub shift_4: StackVariable,      // use to store all zeros
    pub shift_lookup: StackVariable, //use to choose the table when the value is dynamic (known in runtime)
}

impl StackShiftTables {
    pub fn new(stack: &mut StackTracker, mask: u8, left: bool) -> StackShiftTables {
        StackShiftTables {
            shift_0: if mask & 8 == 8 {
                lshift_table(stack, 0)
            } else {
                StackVariable::null()
            },
            shift_1: if mask & 1 == 1 {
                if left {
                    lshift_table(stack, 1)
                } else {
                    rshift_table(stack, 1)
                }
            } else {
                StackVariable::null()
            },
            shift_2: if mask & 2 == 2 {
                if left {
                    lshift_table(stack, 2)
                } else {
                    rshift_table(stack, 2)
                }
            } else {
                StackVariable::null()
            },
            shift_3: if mask & 4 == 4 {
                if left {
                    lshift_table(stack, 3)
                } else {
                    rshift_table(stack, 3)
                }
            } else {
                StackVariable::null()
            },
            shift_4: if mask & 8 == 8 {
                lshift_table(stack, 4)
            } else {
                StackVariable::null()
            },
            shift_lookup: if mask & 8 == 8 {
                shift_lookup(stack)
            } else {
                StackVariable::null()
            },
        }
    }

    pub fn drop(&self, stack: &mut StackTracker) {
        drop_if(stack, &self.shift_lookup);
        drop_if(stack, &self.shift_4);
        drop_if(stack, &self.shift_3);
        drop_if(stack, &self.shift_2);
        drop_if(stack, &self.shift_1);
        drop_if(stack, &self.shift_0);
    }

    pub fn get_shift_table(&self, n: u8) -> StackVariable {
        match n {
            1 => self.shift_1,
            2 => self.shift_2,
            3 => self.shift_3,
            _ => panic!("Invalid shift table"),
        }
    }
}

pub struct StackTables {
    pub modulo: StackVariable,
    pub quotient: StackVariable,
    pub rshift: StackShiftTables,
    pub lshift: StackShiftTables,
    pub logic: StackLogicTables,
}

impl StackTables {
    pub fn new(
        stack: &mut StackTracker,
        modulo: bool,
        quotient: bool,
        rshift: u8,
        lshift: u8,
        logic_mask: u8,
    ) -> StackTables {
        StackTables {
            modulo: if modulo {
                modulo_table(stack, 32)
            } else {
                StackVariable::null()
            },
            quotient: if quotient {
                quotient_table(stack)
            } else {
                StackVariable::null()
            },
            rshift: StackShiftTables::new(stack, rshift, false),
            lshift: StackShiftTables::new(stack, lshift, true),
            logic: StackLogicTables::new(stack, logic_mask),
        }
    }

    pub fn drop(&self, stack: &mut StackTracker) {
        self.logic.drop(stack);
        self.lshift.drop(stack);
        self.rshift.drop(stack);
        drop_if(stack, &self.quotient);
        drop_if(stack, &self.modulo);
    }

    pub fn shift_2nb(&self, stack: &mut StackTracker, right: bool, n: u8) -> StackVariable {
        let (shift, complement) = if right {
            (&self.rshift, &self.lshift)
        } else {
            (&self.lshift, &self.rshift)
        };
        stack.get_value_from_table(shift.get_shift_table(n), None);
        stack.op_swap();
        stack.get_value_from_table(complement.get_shift_table(4 - n), None);
        let result = stack.op_add();
        stack.rename(
            result,
            &format!("shift_{}{}", if right { "right" } else { "left" }, n),
        );
        result
    }

    pub fn logic_op(&self, stack: &mut StackTracker, logic: &LogicOperation) -> StackVariable {
        sort_nibbles(stack);
        stack.get_value_from_table(self.logic.lookup, None);
        stack.op_add();
        let logic_table = self.logic.get_logic_table(logic);
        let result = stack.get_value_from_table(logic_table, None);
        stack.rename(result, &format!("{:?}", logic));
        result
    }

    //it assumes the stack with Y X N
    pub fn shift_2nb_dynamic(&self, stack: &mut StackTracker, right: bool) -> StackVariable {
        let (shift, complement) = if right {
            (&self.rshift, &self.lshift)
        } else {
            (&self.lshift, &self.rshift)
        };

        // Y X N
        stack.op_dup(); // Y X N N
        stack.to_altstack(); // Y X N | N

        stack.get_value_from_table(shift.shift_lookup, None); // Y X offset_n  | N
        stack.op_add();
        stack.get_value_from_table(shift.shift_lookup, None); // Y (X >> n)    | N

        stack.op_swap(); //  (X >> n) Y   | N
        stack.number(4); //  (X >> n) Y 4 | N
        stack.from_altstack(); //  (X >> n) Y 4  N
        stack.op_sub(); //  (X >> n) Y (4-N)

        stack.get_value_from_table(complement.shift_lookup, None); // (X>>n) Y offset_(4-n)
        stack.op_add();
        stack.get_value_from_table(complement.shift_lookup, None); // (X>>n) (Y<<n)
        stack.op_add()
    }
}

pub fn is_equal_to(
    stack: &mut StackTracker,
    value: &StackVariable,
    than: &StackVariable,
) -> StackVariable {
    stack.number(0);
    stack.to_altstack();
    for i in 0..8 {
        stack.copy_var_sub_n(*value, i);
        stack.copy_var_sub_n(*than, i);
        stack.op_equal();
        stack.from_altstack();
        stack.op_add();
        if i < 7 {
            stack.to_altstack();
        }
    }
    stack.number(8);
    let ret = stack.op_equal();
    stack.rename(ret, "is_equal");
    ret
}

pub fn is_lower_than(
    stack: &mut StackTracker,
    value: StackVariable,
    than: StackVariable,
    unsigned: bool,
) -> StackVariable {
    assert_eq!(stack.get_size(value), stack.get_size(than));
    let size = stack.get_size(value);

    if !unsigned {
        stack.copy_var_sub_n(value, 0);
        if_greater(stack, 7, 1, 0); //1 if negative
        stack.copy_var_sub_n(than, 0);
        if_greater(stack, 7, 1, 0); //1 if negative
        stack.op_2dup();
        stack.op_equal();
        let n = 2_i32.pow(size + 1);
        stack
            .custom(
                script! {
                    OP_IF
                        OP_2DROP
                        0
                    OP_ELSE
                        OP_GREATERTHAN
                        OP_IF
                            { n }
                        OP_ELSE
                            { -n }
                        OP_ENDIF
                    OP_ENDIF
                },
                3,
                true,
                0,
                "sign",
            )
            .unwrap();
    }

    for i in 0..size {
        let n: i32 = 2_i32.pow(size - i);
        stack.move_var_sub_n(value, 0);
        stack.move_var_sub_n(than, 0);
        stack.op_2dup();
        stack.op_lessthan();
        stack
            .custom(
                script! {
                    OP_IF
                        OP_2DROP
                        { n }
                    OP_ELSE
                        OP_EQUAL
                        OP_IF
                            0
                        OP_ELSE
                            { -n }
                        OP_ENDIF
                    OP_ENDIF
                },
                3,
                true,
                0,
                "compare",
            )
            .unwrap();
    }
    for _ in 0..size - 1 {
        stack.op_add();
    }
    if !unsigned {
        stack.op_add(); //if signed check, add the sign
    }
    stack.number(0);
    let ret = stack.op_greaterthan();
    stack.rename(ret, "is_lower_than");
    ret
}

pub fn multiply_by_8(stack: &mut StackTracker) {
    for _ in 0..3 {
        stack.op_dup();
        stack.op_add();
    }
}

pub fn multiply_by_16(stack: &mut StackTracker) {
    for _ in 0..4 {
        stack.op_dup();
        stack.op_add();
    }
}

pub fn mask_value(
    stack: &mut StackTracker,
    value: StackVariable,
    mask: StackVariable,
) -> StackVariable {
    for _ in 0..8 {
        stack.move_var_sub_n(value, 0);
        stack.move_var_sub_n(mask, 0);
        stack.custom(
            script! {
                OP_IF
                OP_ELSE
                    OP_DROP
                    0
                OP_ENDIF
            },
            2,
            true,
            0,
            "masked",
        );
    }

    stack.join_in_stack(8, None, Some("masked"))
}
pub struct WordTable {
    table: StackVariable,
}

impl WordTable {
    pub fn new(stack: &mut StackTracker, elements: Vec<u32>) -> WordTable {
        for element in elements.iter().rev() {
            stack.number_u32(*element);
        }
        let size = elements.len() as u32;
        WordTable {
            table: stack.join_in_stack(size, None, Some("word_table")),
        }
    }

    pub fn drop(&self, stack: &mut StackTracker) {
        stack.move_var(self.table);
        stack.drop(self.table);
    }

    //assume index on top of the stack
    pub fn peek(&self, stack: &mut StackTracker) -> StackVariable {
        stack.number(1);
        stack.op_add();
        multiply_by_8(stack);

        for i in 0..8 {
            if i > 0 {
                stack.op_swap();
            }

            if i < 7 {
                stack.op_dup();
            } else {
                stack.op_1sub();
            }

            stack.op_pick();
        }

        stack.join_in_stack(8, None, None)
    }
}

pub fn left_rotate(
    stack: &mut StackTracker,
    value: StackVariable,
    rotate: StackVariable,
) -> StackVariable {
    let copied = stack.copy_var(value);
    stack.explode(copied);
    stack.move_var(value);
    stack.explode(value);

    stack.number(4);
    stack.move_var(rotate);
    stack.op_sub(); //4-n to get the proper result
    stack.op_dup();
    stack.op_add(); //duplicate offset (from bytes to nibbles)

    stack.custom(
        script! {
            OP_1ADD
            for _ in 0..8 {
                OP_DUP
                OP_ROLL
                OP_TOALTSTACK
            }
            OP_DROP

            for _ in 0..4 {
                OP_2DROP
            }
        },
        17,
        false,
        8,
        "",
    );

    stack.from_altstack_joined(8, "left_rotated")
}

fn multiply_nib(
    stack: &mut StackTracker,
    logic_table: &StackLogicTables,
    a: StackVariable,
    b: StackVariable,
    i: u8,
    n: u8,
    add_previous_mod: bool,
    take_mod_from_alt: bool,
    add_quot: bool,
) {
    stack.copy_var_sub_n(a, i as u32);
    stack.copy_var_sub_n(b, n as u32);

    sort_nibbles(stack);
    stack.get_value_from_table(logic_table.lookup, None);
    stack.op_add();
    stack.op_dup();

    stack.get_value_from_table(logic_table.mul_mod, None);

    if add_previous_mod {
        if take_mod_from_alt {
            stack.from_altstack();
        } else {
            stack.op_rot();
        }
        stack.op_add();
    }

    stack.to_altstack();

    stack.get_value_from_table(logic_table.mul_quotient, None);
    if add_quot {
        stack.op_add();
    }
}

pub fn multiply(
    stack: &mut StackTracker,
    a: StackVariable,
    b: StackVariable,
    ret_high: bool,
    ret_low: bool,
) -> StackVariable {
    let logic_table = StackLogicTables::new(stack, LOGIC_MASK_MUL);

    stack.move_var(b);
    stack.move_var(a);

    let n = 8; // Size of the matrix

    let mut total_count = 0;

    stack.set_breakpoint("start_multiplication");

    //diagonal calculation
    for k in (0..=(2 * n - 2)).rev() {
        let start_i = if k < n { k } else { n - 1 };
        let end_i = if k >= n { k - n + 1 } else { 0 };

        let elements_in_diag = (start_i - end_i) + 1;
        let mut count = 0;

        for i in (end_i..=start_i).rev() {
            let j = k - i;
            multiply_nib(
                stack,
                &logic_table,
                a,
                b,
                j,
                i,
                total_count > 0,
                total_count > 0 && count > 0,
                elements_in_diag > 1 && count > 0,
            );
            total_count += 1;
            count += 1;
        }
    }

    stack.to_altstack();

    stack.drop(a);
    stack.drop(b);

    logic_table.drop(stack);

    let modulo = modulo_table(stack, 197);
    let quotient = quotient_table_ex(stack, 197);

    for _ in 0..15 {
        stack.from_altstack();
    }

    for i in 0..15 {
        if i < 14 {
            stack.op_dup();
        }
        stack.get_value_from_table(modulo, None);
        stack.to_altstack();
        if i < 14 {
            stack.get_value_from_table(quotient, None);
            stack.op_add();
        }
    }

    stack.drop(quotient);
    stack.drop(modulo);

    if ret_low {
        for _ in 0..4 {
            stack.from_altstack();
            stack.from_altstack();
            stack.op_2drop();
        }
        stack.from_altstack_joined(8, "mul_result_low")
    } else if ret_high {
        let ret = stack.from_altstack_joined(8, "mul_result_high");
        for _ in 0..4 {
            stack.from_altstack();
            stack.from_altstack();
            stack.op_2drop();
        }
        ret
    } else {
        stack.from_altstack_joined(16, "mul_result")
    }
}

pub fn twos_complement(
    stack: &mut StackTracker,
    tables: &StackTables,
    value: StackVariable,
    size: u32,
) -> StackVariable {
    stack.explode(value);

    for i in 0..size {
        if i > 0 {
            stack.op_swap();
        }

        stack.op_negate();
        if i == 0 {
            stack.number(16); //add 1 to the negated value
        } else {
            stack.number(15); //value to negate
        }
        stack.op_add();

        if i > 0 {
            stack.op_add(); // add the carry
        }

        if i < (size - 1) {
            stack.op_dup();
        }
        stack.get_value_from_table(tables.modulo, None);
        if i < (size - 1) {
            stack.to_altstack();
            stack.get_value_from_table(tables.quotient, None);
        }
    }

    for _ in 0..(size - 1) {
        stack.from_altstack();
    }

    stack.join_in_stack(size, None, None)
}

pub fn twos_complement_conditional(
    stack: &mut StackTracker,
    tables: &StackTables,
    value: StackVariable,
    size: u32,
) -> StackVariable {
    let (mut stack_true, stack_false) = stack.open_if();
    twos_complement(&mut stack_true, tables, value, size);
    stack.end_if(
        stack_true,
        stack_false,
        1,
        vec![(size, "twos_complement".to_string())],
        0,
    )[0]
}

pub fn is_negative(stack: &mut StackTracker, value: StackVariable) -> StackVariable {
    stack.copy_var_sub_n(value, 0);
    let result = if_greater(stack, 7, 1, 0);
    stack.rename(
        result,
        &format!("is_neg({})", stack.get_var_name(value)).to_string(),
    );
    result
}

pub fn mulh(
    stack: &mut StackTracker,
    tables: &StackTables,
    a: StackVariable,
    mut b: StackVariable,
    mulhsu: bool,
) -> StackVariable {
    is_negative(stack, a); // is_neg(a)
    stack.op_dup(); //a1 a1

    if !mulhsu {
        is_negative(stack, b); //a1 a1 b1 if b negative
        stack.op_dup(); //a1 a1 b1 b1

        stack.op_rot(); //a1 b1 b1 a1
        stack.op_add(); //a1 b1 a1+b1
        stack
            .custom(script! { 1 OP_EQUAL }, 1, true, 0, "result_neg")
            .unwrap();
        stack.to_altstack(); //a1 b1 | a1+b1
    }

    stack.to_altstack(); //a1 | b1 a1+b1
    stack.to_altstack(); // | a1 b1 a1+b1

    stack.move_var(a);
    stack.from_altstack();
    let a = twos_complement_conditional(stack, tables, a, 8);

    if !mulhsu {
        stack.move_var(b);
        stack.from_altstack();
        b = twos_complement_conditional(stack, tables, b, 8);
    }

    let ret = multiply(stack, a, b, false, false);
    stack.from_altstack();
    let ret = twos_complement_conditional(stack, tables, ret, 16);

    stack.explode(ret);
    for _ in 0..4 {
        stack.op_2drop();
    }

    stack.join_in_stack(8, None, None)
}

pub fn div_check(
    stack: &mut StackTracker,
    tables: &StackTables,
    dividend: StackVariable,
    divisor: StackVariable,
    quotient: StackVariable,
    remainder: StackVariable,
) {
    //this part asserts that the remainder is lower than the divisor
    let remainder_check = stack.copy_var(remainder);
    let divisor_check = stack.copy_var(divisor);
    is_lower_than(stack, remainder_check, divisor_check, true);
    stack.op_verify();

    let result = multiply(stack, divisor, quotient, false, false);
    stack.explode(result);
    stack.to_altstack_count(8);

    //assert no multiply overflow
    for _ in 0..8 {
        stack.number(0);
        stack.op_equalverify();
    }

    // asserts dividend = divisor * quotient + remainder
    let div_round = stack.from_altstack_joined(8, "dividen_round");
    let diff = sub(stack, tables, dividend, div_round);
    stack.move_var(remainder);
    is_equal_to(stack, &remainder, &diff);
    stack.op_verify();

    stack.drop(remainder);
    stack.drop(diff);
}

pub fn sign_check(
    stack: &mut StackTracker,
    tables: &StackTables,
    dividend: StackVariable,
    divisor: StackVariable,
    quotient: StackVariable,
    remainder: StackVariable,
) -> (StackVariable, StackVariable, StackVariable, StackVariable) {
    //take the sign of every variable and convert to positive if negative
    //save the result with the sign unchanged to be used in the final result

    //checks that the dividend and remainder have the same sign (and save the sign)
    is_negative(stack, remainder); //rem_sign
    stack.op_dup(); //rem_sign rem_sign
    stack.to_altstack(); //rem_sign | rem_sign

    is_negative(stack, dividend); //rem_sign dividend_sign | rem_sign
    stack.op_dup(); //rem_sign dividend_sign dividend_sign | rem_sign
    stack.op_dup(); //rem_sign dividend_sign dividend_sign dividen_sign | rem_sign
    stack.to_altstack(); //rem_sign dividend_sign dividend_sign | dividend_sign  rem_sign
    stack.to_altstack(); //rem_sign dividend_sign | dividend_sign dividend_sign  rem_sign

    //but if the remainder is zero the sign comparison can be ignored
    let zero = stack.number_u32(0);
    is_equal_to(stack, &remainder, &zero);
    stack.to_altstack();
    stack.drop(zero);
    stack.from_altstack();

    let (mut stack_true, mut stack_false) = stack.open_if();
    stack_true.op_2drop();
    stack_false.op_equalverify();
    stack.end_if(stack_true, stack_false, 2, vec![], 0);

    //then assert that if the sign of divisor and dividen are the same then the quotient sign is positive and negative otherwise
    is_negative(stack, divisor); // divisor_sign | dividend_sign dividend_sign  rem_sign
    stack.op_dup(); // divisor_sign divisor_sign | dividend_sign dividend_sign  rem_sign
    stack.from_altstack(); // divisor_sign divisor_sign dividend_sign | dividend_sign rem_sign
    stack.op_equal(); // divisor_sign ( divisor and dividend same sign)  | dividend_sign rem_sign
    stack.op_not(); // divisor_sign ~( divisor and dividend same sign) | dividend_sign rem_sign

    is_negative(stack, quotient); // divisor_sign ~( divisor and dividend same sign) quotient_sign | dividend_sign rem_sign
    stack.op_dup(); // divisor_sign ~( divisor and dividend same sign) quotient_sign quotient_sign | dividend_sign rem_sign
    stack.to_altstack(); // divisor_sign ~( divisor and dividend same sign) quotient_sign | quotient_sign  dividend_sign rem_sign

    let zero = stack.number_u32(0);
    is_equal_to(stack, &quotient, &zero);
    stack.to_altstack();
    stack.drop(zero);
    stack.from_altstack();

    let (mut stack_true, mut stack_false) = stack.open_if();
    stack_true.op_2drop();
    stack_false.op_equalverify();
    stack.end_if(stack_true, stack_false, 2, vec![], 0);

    stack.to_altstack(); // | divisor_sign  quotient_sign  dividend_sign rem_sign

    //invert the numbers if necessary
    stack.move_var(divisor);
    stack.from_altstack();
    let divisor = twos_complement_conditional(stack, tables, divisor, 8);

    stack.move_var(quotient);
    stack.from_altstack();
    let quotient = twos_complement_conditional(stack, tables, quotient, 8);

    stack.move_var(dividend);
    stack.from_altstack();
    let dividend = twos_complement_conditional(stack, tables, dividend, 8);

    stack.move_var(remainder);
    stack.from_altstack();
    let remainder = twos_complement_conditional(stack, tables, remainder, 8);
    (divisor, quotient, dividend, remainder)
}

pub fn div_by_zero_case(
    stack: &mut StackTracker,
    dividend: StackVariable,
    divisor: StackVariable,
    quotient: StackVariable,
    remainder: StackVariable,
    result: Option<u32>,
) -> (StackTracker, StackTracker) {
    let zero = stack.number_u32(0);
    is_equal_to(stack, &zero, &divisor);
    stack.to_altstack();
    stack.drop(zero);
    stack.from_altstack();
    let (mut stack_true, stack_false) = stack.open_if();

    stack_true.drop(remainder);
    stack_true.drop(quotient);
    stack_true.drop(divisor);
    if result.is_some() {
        stack_true.drop(dividend);
        stack_true.number_u32(result.unwrap());
    }

    (stack_true, stack_false)
}

pub fn overflow_case(
    stack: &mut StackTracker,
    dividend: StackVariable,
    divisor: StackVariable,
    quotient: StackVariable,
    remainder: StackVariable,
    result: Option<u32>,
) -> (StackTracker, StackTracker) {
    let minus_one = stack.number_u32(-1 as i32 as u32);
    let min_i32 = stack.number_u32(std::i32::MIN as u32);
    is_equal_to(stack, &minus_one, &divisor);
    is_equal_to(stack, &min_i32, &dividend);
    stack.op_booland();
    stack.to_altstack();
    stack.drop(min_i32);
    stack.drop(minus_one);
    stack.from_altstack();
    let (mut stack_true, stack_false) = stack.open_if();

    stack_true.drop(remainder);
    stack_true.drop(quotient);
    stack_true.drop(divisor);
    if result.is_some() {
        stack_true.drop(dividend);
        stack_true.number_u32(result.unwrap());
    }

    (stack_true, stack_false)
}

pub fn division_and_remainder(
    stack: &mut StackTracker,
    tables: &StackTables,
    dividend: StackVariable,
    divisor: StackVariable,
    quotient: StackVariable,
    remainder: StackVariable,
    div_by_zero_result: Option<u32>,
    is_rem_check: bool,
) -> StackVariable {
    stack.move_var(dividend);
    stack.move_var(divisor);
    stack.move_var(quotient);
    stack.move_var(remainder);

    let (stack_true, mut stack_false) = div_by_zero_case(
        stack,
        dividend,
        divisor,
        quotient,
        remainder,
        div_by_zero_result,
    );

    if is_rem_check {
        stack_false.copy_var(remainder);
    } else {
        stack_false.copy_var(quotient);
    }

    div_check(
        &mut stack_false,
        tables,
        dividend,
        divisor,
        quotient,
        remainder,
    );

    let ret = stack.end_if(
        stack_true,
        stack_false,
        4,
        vec![(8, "write_result".to_string())],
        0,
    );

    ret[0]
}

pub fn divu(
    stack: &mut StackTracker,
    tables: &StackTables,
    dividend: StackVariable,
    divisor: StackVariable,
    quotient: StackVariable,
    remainder: StackVariable,
) -> StackVariable {
    division_and_remainder(
        stack,
        tables,
        dividend,
        divisor,
        quotient,
        remainder,
        Some(std::u32::MAX),
        false,
    )
}

pub fn remu(
    stack: &mut StackTracker,
    tables: &StackTables,
    dividend: StackVariable,
    divisor: StackVariable,
    remainder: StackVariable,
    quotient: StackVariable,
) -> StackVariable {
    division_and_remainder(
        stack, tables, dividend, divisor, quotient, remainder, None, true,
    )
}

pub fn division_and_remainder_signed(
    stack: &mut StackTracker,
    tables: &StackTables,
    dividend: StackVariable,
    divisor: StackVariable,
    quotient: StackVariable,
    remainder: StackVariable,
    div_by_zero_result: Option<u32>,
    overflow_result: Option<u32>,
    is_rem_check: bool,
) -> StackVariable {
    stack.move_var(dividend);
    stack.move_var(divisor);
    stack.move_var(quotient);
    stack.move_var(remainder);

    let (stack_true, mut stack_false) = div_by_zero_case(
        stack,
        dividend,
        divisor,
        quotient,
        remainder,
        div_by_zero_result,
    );

    let (stack_true_2, mut stack_no_edge) = overflow_case(
        &mut stack_false,
        dividend,
        divisor,
        quotient,
        remainder,
        overflow_result,
    );

    if is_rem_check {
        stack_no_edge.copy_var(remainder);
    } else {
        stack_no_edge.copy_var(quotient);
    }
    let (divisor, quotient, dividend, remainder) = sign_check(
        &mut stack_no_edge,
        tables,
        dividend,
        divisor,
        quotient,
        remainder,
    );
    div_check(
        &mut stack_no_edge,
        tables,
        dividend,
        divisor,
        quotient,
        remainder,
    );

    stack_false.end_if(
        stack_true_2,
        stack_no_edge,
        4,
        vec![(8, "write_result".to_string())],
        0,
    );

    let ret = stack.end_if(
        stack_true,
        stack_false,
        4,
        vec![(8, "write_result".to_string())],
        0,
    );

    ret[0]
}

pub fn div(
    stack: &mut StackTracker,
    tables: &StackTables,
    dividend: StackVariable,
    divisor: StackVariable,
    quotient: StackVariable,
    remainder: StackVariable,
) -> StackVariable {
    division_and_remainder_signed(
        stack,
        tables,
        dividend,
        divisor,
        quotient,
        remainder,
        Some(-1 as i32 as u32),
        Some(std::i32::MIN as u32),
        false,
    )
}

pub fn rem(
    stack: &mut StackTracker,
    tables: &StackTables,
    dividend: StackVariable,
    divisor: StackVariable,
    remainder: StackVariable,
    quotient: StackVariable,
) -> StackVariable {
    division_and_remainder_signed(
        stack,
        tables,
        dividend,
        divisor,
        quotient,
        remainder,
        None,
        Some(0),
        true,
    )
}

pub fn witness_equals(
    stack: &mut StackTracker,
    lower_half_nibble_table: &StackVariable,
    witness_nibble: u32,
    memory_witness: &StackVariable,
    expected_access_type: MemoryAccessType,
) {
    stack.copy_var_sub_n(*memory_witness, witness_nibble);
    stack.get_value_from_table(*lower_half_nibble_table, None);

    stack.number(expected_access_type as u32);
    stack.op_equal();
}

pub fn verify_wrong_chunk_value(
    stack: &mut StackTracker,
    tables: &StackTables,
    chunk: &Chunk,
    address: StackVariable,
    value: StackVariable,
) {
    address_in_range(stack, &chunk.range(), &address);
    stack.op_verify();

    let chunk_table = WordTable::new(stack, chunk.data.clone());

    let base_addr = stack.number_u32(chunk.base_addr);
    let offset = sub(stack, &tables, address, base_addr);

    let index = static_right_shift_2(stack, tables, offset);

    var_to_number(stack, index);
    let real_opcode = chunk_table.peek(stack);

    stack.equality(real_opcode, true, value, true, false, true);
    chunk_table.drop(stack);
}

pub fn get_selected_vars<const N: usize>(
    stack: &mut StackTracker,
    vars_1: [StackVariable; N],
    vars_2: [StackVariable; N],
    var_selector: StackVariable,
) -> [StackVariable; N] {
    assert_eq!(vars_1.len(), vars_2.len());
    let consumes = vars_1.len() as u32 * 2;

    let output: Vec<_> = vars_1
        .iter()
        .enumerate()
        .map(|(i, var)| (stack.get_size(*var), format!("var_{}", i)))
        .collect();

    // we need the variables to be on top of the stack, or we will break variables that are higher when merging the branches
    for (var_1, var_2) in vars_1.iter().zip(vars_2.iter()) {
        assert_eq!(stack.get_size(*var_1), stack.get_size(*var_2));
        stack.move_var(*var_1);
        stack.move_var(*var_2);
    }

    stack.move_var(var_selector);
    stack.number(1);
    stack.op_equal();
    let (mut chose_var_1, mut chose_var_2) = stack.open_if();

    for (var_1, var_2) in vars_1.into_iter().zip(vars_2.into_iter()) {
        chose_var_1.move_var(var_2);
        chose_var_1.drop(var_2);

        chose_var_2.move_var(var_1);
        chose_var_2.drop(var_1);
    }

    stack
        .end_if(chose_var_1, chose_var_2, consumes, output, 0)
        .try_into()
        .ok()
        .expect("Vec length does not match expected array size")
}

pub fn address_in_range(stack: &mut StackTracker, range: &(u32, u32), address: &StackVariable) {
    let start = stack.number_u32(range.0);
    let end = stack.number_u32(range.1);
    let address_copy = stack.copy_var(*address);

    // start <= address
    is_equal_to(stack, &start, &address_copy);
    is_lower_than(stack, start, address_copy, true);
    stack.op_boolor();

    // address <= end
    let address_copy = stack.copy_var(*address);
    is_equal_to(stack, &end, &address_copy);
    is_lower_than(stack, address_copy, end, true);
    stack.op_boolor();

    stack.op_booland();
}

pub fn address_in_sections(
    stack: &mut StackTracker,
    address: &StackVariable,
    sections: &SectionDefinition,
) {
    stack.number(0); // op_false

    for range in &sections.ranges {
        address_in_range(stack, range, address);
    }

    for _ in 0..sections.ranges.len() {
        stack.op_boolor();
    }
}

pub fn address_not_in_sections(
    stack: &mut StackTracker,
    address: &StackVariable,
    sections: &SectionDefinition,
) {
    address_in_sections(stack, address, sections);
    stack.op_not();
}

// var should be smaller than std::i32::MAX
pub fn var_to_number(stack: &mut StackTracker, var: StackVariable) -> StackVariable {
    let size = stack.get_size(var);
    let mut result = stack.move_var_sub_n(var, 0);

    for _ in 0..size - 1 {
        multiply_by_16(stack);
        stack.move_var_sub_n(var, 0);
        result = stack.op_add();
    }

    result
}

pub fn shift(stack: &mut StackTracker, tables: &StackShiftTables, amount: u8) {
    if amount == 0 {
        return;
    }

    let tables = [tables.shift_1, tables.shift_2, tables.shift_3];

    if amount > 3 {
        stack.op_drop();
        stack.number(0);
    } else {
        stack.get_value_from_table(tables[amount as usize - 1], None);
    }
}

const BITS_NIBBLE: u8 = 4;

pub fn split(stack: &mut StackTracker, tables: &StackTables, right_size: u8) {
    stack.op_dup();

    shift(stack, &tables.rshift, right_size);
    stack.op_swap();
    shift(stack, &tables.lshift, BITS_NIBBLE - right_size);
    shift(stack, &tables.rshift, BITS_NIBBLE - right_size);
}

pub fn var_to_decisions_in_stack(
    stack: &mut StackTracker,
    tables: &StackTables,
    var: StackVariable,
    nary_last_round: u8,
    nary: u8,
    rounds: u8,
) {
    let bits_nary_round = f64::log2(nary as f64) as u8;
    let mut start_position = 0;
    let mut remaining_bits = if nary_last_round == 0 {
        bits_nary_round
    } else {
        f64::log2(nary_last_round as f64) as u8
    };

    stack.move_var(var);
    stack.explode(var);
    stack.number(0);
    let nibbles_needed =
        (remaining_bits + bits_nary_round * (rounds - 1) + BITS_NIBBLE - 1) / BITS_NIBBLE;

    for _ in 0..nibbles_needed {
        if remaining_bits > BITS_NIBBLE {
            stack.op_swap();
            shift(stack, &tables.lshift, start_position);
            stack.op_add();
            start_position += BITS_NIBBLE;
            remaining_bits -= BITS_NIBBLE;
        } else if remaining_bits == BITS_NIBBLE {
            stack.op_swap();
            shift(stack, &tables.lshift, start_position);
            stack.op_add();
            start_position = 0;
            remaining_bits = bits_nary_round;
            stack.to_altstack();
            stack.number(0);
        } else {
            let times_needed =
                1 + (BITS_NIBBLE - remaining_bits + bits_nary_round - 1) / bits_nary_round;
            let mut current_bits = BITS_NIBBLE;
            for _ in 0..times_needed {
                stack.op_swap();
                split(stack, tables, remaining_bits);
                shift(stack, &tables.lshift, start_position);
                stack.op_rot();
                stack.op_add();

                if remaining_bits <= current_bits {
                    current_bits -= remaining_bits;
                    remaining_bits = bits_nary_round;
                    start_position = 0;
                    stack.to_altstack();
                    stack.number(0);
                } else {
                    remaining_bits -= current_bits;
                    start_position += current_bits;
                }
            }
            stack.op_swap();
            stack.number(0);
            stack.op_equalverify();
        }
    }

    stack.number(0);
    stack.op_equalverify();

    for _ in 0..(16 - nibbles_needed) {
        stack.number(0);
        stack.op_equalverify();
    }
}

pub fn next_decision_in_stack(
    stack: &mut StackTracker,
    decisions_bits: StackVariable,
    rounds: u8,
    max_last_round: u8,
    max_nary: u8,
) {
    stack.move_var(decisions_bits);
    stack.explode(decisions_bits);

    stack.op_dup();
    stack.number(max_last_round as u32);
    stack.op_equal();

    let (mut overflow, mut no_overflow) = stack.open_if();
    no_overflow.op_1add();
    no_overflow.to_altstack();
    no_overflow.number(0);
    no_overflow.to_altstack();

    overflow.op_drop();
    overflow.number(0);
    overflow.to_altstack();
    overflow.number(1);
    overflow.to_altstack();

    stack.end_if(overflow, no_overflow, 1, vec![], 2);

    for _ in 1..rounds - 1 {
        stack.from_altstack();
        stack.number(1);
        stack.op_equal();

        let (mut inc, mut no_inc) = stack.open_if();
        no_inc.to_altstack();
        no_inc.number(0);
        no_inc.to_altstack();

        inc.op_dup();
        inc.number(max_nary as u32);
        inc.op_equal();

        let (mut overflow, mut no_overflow) = inc.open_if();
        no_overflow.op_1add();
        no_overflow.to_altstack();
        no_overflow.number(0);
        no_overflow.to_altstack();

        overflow.op_drop();
        overflow.number(0);
        overflow.to_altstack();
        overflow.number(1);
        overflow.to_altstack();

        inc.end_if(overflow, no_overflow, 1, vec![], 2);
        stack.end_if(inc, no_inc, 1, vec![], 2);
    }

    stack.from_altstack();
    stack.op_add();
    stack.to_altstack();
}

#[cfg(test)]
mod tests {
    use bitvmx_cpu_definitions::memory::MemoryWitness;

    use crate::riscv::memory_alignment::{
        load_lower_half_nibble_table, load_upper_half_nibble_table,
    };

    use super::*;

    #[test]
    fn test_twos_complement_conditional() {
        let mut stack = StackTracker::new();

        let tables = StackTables::new(&mut stack, true, true, 0, 0, 0);
        let value = stack.number_u32(0xaaaa_aaab);
        stack.number(1);
        let result = twos_complement_conditional(&mut stack, &tables, value, 8);
        stack.to_altstack();
        tables.drop(&mut stack);
        stack.from_altstack();
        let expected = stack.number_u32(0x5555_5555);
        stack.equals(result, true, expected, true);

        let tables = StackTables::new(&mut stack, true, true, 0, 0, 0);
        let value = stack.number_u32(0xaaaa_aaab);
        stack.number(0);
        let result = twos_complement_conditional(&mut stack, &tables, value, 8);
        stack.to_altstack();
        tables.drop(&mut stack);
        stack.from_altstack();
        let expected = stack.number_u32(0xaaaa_aaab);
        stack.equals(result, true, expected, true);

        stack.op_true();
        assert!(stack.run().success);
    }

    fn twos_complement_conditional_aux(value: u32, condition: bool) -> bool {
        let mut stack = StackTracker::new();
        let tables = StackTables::new(&mut stack, true, true, 0, 0, 0);

        // Calculate the "ground truth" expected result using standard Rust.
        let expected_result = if condition {
            (!value).wrapping_add(1)
        } else {
            value
        };

        let value_var = stack.number_u32(value);
        // Push the boolean condition onto the stack.
        stack.number(if condition { 1 } else { 0 });

        // Generate the conditional twos_complement script for a 32-bit number.
        let result_var = twos_complement_conditional(&mut stack, &tables, value_var, 8);
        stack.to_altstack();
        tables.drop(&mut stack);
        stack.from_altstack();
        let expected_var = stack.number_u32(expected_result);
        stack.equals(result_var, true, expected_var, true);
        stack.op_true();
        stack.run().success
    }

    #[test]
    fn test_twos_complement() {
        let mut stack = StackTracker::new();
        let tables = StackTables::new(&mut stack, true, true, 0, 0, 0);

        let value = stack.number_u32(0xaaaa_aaab);
        let result = twos_complement(&mut stack, &tables, value, 8);
        stack.to_altstack();
        tables.drop(&mut stack);
        stack.from_altstack();

        let expected = stack.number_u32(0x5555_5555);
        stack.equals(result, true, expected, true);
        stack.op_true();
        assert!(stack.run().success);
    }
    fn twos_complement_aux(value: u32) -> bool {
        let mut stack = StackTracker::new();
        let tables = StackTables::new(&mut stack, true, true, 0, 0, 0);

        let expected_result = (!value).wrapping_add(1);
        let value_var = stack.number_u32(value);
        let result_var = twos_complement(&mut stack, &tables, value_var, 8);
        stack.to_altstack();
        tables.drop(&mut stack);
        stack.from_altstack();

        let expected_var = stack.number_u32(expected_result);
        stack.equals(result_var, true, expected_var, true);
        stack.op_true();
        stack.run().success
    }

    fn test_multiply_aux(a: u32, b: u32, high: u32, low: u32) {
        let mut stack = StackTracker::new();

        let a = stack.number_u32(a);
        let b = stack.number_u32(b);

        let mult = multiply(&mut stack, a, b, false, false);

        stack.explode(mult);
        let res_high = stack.join_in_stack(16, Some(8), Some("high"));
        let res_low = stack.join_in_stack(8, None, Some("low"));

        let exp_low = stack.number_u32(low);
        stack.equals(res_low, true, exp_low, true);

        let exp_high = stack.number_u32(high);
        stack.equals(res_high, true, exp_high, true);

        stack.op_true();
        assert!(stack.run().success)
    }
    fn multiply_aux(a: u32, b: u32, high: u32, low: u32) -> bool {
        let mut stack = StackTracker::new();

        let a = stack.number_u32(a);
        let b = stack.number_u32(b);

        let mult = multiply(&mut stack, a, b, false, false);

        stack.explode(mult);
        let res_high = stack.join_in_stack(16, Some(8), Some("high"));
        let res_low = stack.join_in_stack(8, None, Some("low"));

        let exp_low = stack.number_u32(low);
        stack.equals(res_low, true, exp_low, true);

        let exp_high = stack.number_u32(high);
        stack.equals(res_high, true, exp_high, true);

        stack.op_true();
        stack.run().success
    }

    #[test]
    fn test_multiply() {
        test_multiply_aux(0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFE, 0x0000_0001);
        test_multiply_aux(0x0, 0xFFFF_FFFF, 0, 0);
        test_multiply_aux(0xFFFF_FFFF, 0x1, 0x0, 0xFFFF_FFFF);
        test_multiply_aux(0x0000_0002, 0x0000_0004, 0x0000_0000, 0x0000_0008);
        test_multiply_aux(0x1B49_F21B, 0x1F51_E1ED, 0x0356_AECC, 0x20C9_DDFF);
        test_multiply_aux(0x1DBD_BDBF, 0x1DBD_BDBF, 0x0374_899E, 0xFEA9_9481);
    }

    fn test_mulh_aux(a: i32, b: i32, expected: i32) {
        let mut stack = StackTracker::new();
        let tables = StackTables::new(&mut stack, true, true, 0, 0, 0);

        let a = stack.number_u32(a as u32);
        let b = stack.number_u32(b as u32);

        let result = mulh(&mut stack, &tables, a, b, false);

        let expected = stack.number_u32(expected as u32);

        stack.equals(result, true, expected, true);
        tables.drop(&mut stack);

        stack.op_true();

        assert!(stack.run().success);
    }

    #[test]
    fn test_mulh() {
        test_mulh_aux(-0x7BDD_925D, -0x7F37_3DED, 0x3D8D_A62D);
        test_mulh_aux(0x2A37_E15A, -0xC16_20C2, -0x1FE_44C5);
    }

    fn test_division_aux(dividend: i32, divisor: i32, quotient: i32, remainder: i32, signed: bool) {
        let mut stack = StackTracker::new();
        let tables = StackTables::new(&mut stack, true, true, 0, 0, 0);

        let dividend = stack.number_u32(dividend as u32);
        let dividend_copy = stack.copy_var(dividend);

        let divisor = stack.number_u32(divisor as u32);
        let divisor_copy = stack.copy_var(divisor);

        let quotient = stack.number_u32(quotient as u32);
        let quotient_copy = stack.copy_var(quotient);

        let remainder = stack.number_u32(remainder as u32);
        let remainder_copy = stack.copy_var(remainder);

        let expected_div = stack.copy_var(quotient);
        let expected_rem = stack.copy_var(remainder);

        let result_div;
        let result_rem;

        if signed {
            result_div = div(&mut stack, &tables, dividend, divisor, quotient, remainder);
            result_rem = rem(
                &mut stack,
                &tables,
                dividend_copy,
                divisor_copy,
                remainder_copy,
                quotient_copy,
            );
        } else {
            result_div = divu(&mut stack, &tables, dividend, divisor, quotient, remainder);
            result_rem = remu(
                &mut stack,
                &tables,
                dividend_copy,
                divisor_copy,
                remainder_copy,
                quotient_copy,
            );
        }

        stack.equals(expected_div, true, result_div, true);
        stack.equals(expected_rem, true, result_rem, true);

        tables.drop(&mut stack);

        stack.op_true();
        assert!(stack.run().success);
    }

    #[test]
    pub fn test_division() {
        // signed division by 0
        test_division_aux(100, 0, -1, 100, true);
        // unsigned division by 0
        test_division_aux(100, 0, std::u32::MAX as i32, 100, false);
        // overflow
        test_division_aux(std::i32::MIN, -1, std::i32::MIN, 0, true);

        test_division_aux(100, -6, -16, 4, true);
        test_division_aux(-100, 6, -16, -4, true);
        test_division_aux(-100, -6, 16, -4, true);

        test_division_aux(100, 6, 16, 4, false);
        test_division_aux(100, -1, -100, 0, true);
    }

    fn test_left_rotate_helper(value: u32, rotate: u32, expected: u32) {
        let mut stack = StackTracker::new();
        let value = stack.number_u32(value);
        let rotate = stack.number(rotate);
        let result = left_rotate(&mut stack, value, rotate);
        let expected = stack.number_u32(expected);
        stack.equals(result, true, expected, true);
        stack.op_true();
        assert!(stack.run().success);
    }

    fn test_left_rotate_aux(value: u32, rotate: u32) -> bool {
        let mut stack = StackTracker::new();
        let expected_result = value.rotate_left(rotate * 8);
        let value_var = stack.number_u32(value);
        let rotate_var = stack.number(rotate);
        let result_var = left_rotate(&mut stack, value_var, rotate_var);
        let expected_var = stack.number_u32(expected_result);
        stack.equals(result_var, true, expected_var, true);
        stack.op_true();
        stack.run().success
    }

    #[test]
    fn test_left_rotate() {
        test_left_rotate_helper(0x0000_00FF, 3, 0xFF00_0000);
        test_left_rotate_helper(0x0000_FF00, 3, 0x0000_00FF);
        test_left_rotate_helper(0x0000_FF00, 1, 0x00FF_0000);
        test_left_rotate_helper(0x0000_FF00, 2, 0xFF00_0000);
    }

    fn test_word_table_helper(values: Vec<u32>, index: u32, expected: u32) {
        let mut stack = StackTracker::new();
        let word_table = WordTable::new(&mut stack, values);
        stack.number(index);
        let result = word_table.peek(&mut stack);
        let expected = stack.number_u32(expected);
        stack.equals(result, true, expected, true);
        word_table.drop(&mut stack);
        stack.op_true();
        assert!(stack.run().success);
    }

    fn test_word_table_aux(values: Vec<u32>, index: u32) -> bool {
        let mut stack = StackTracker::new();
        let word_table = WordTable::new(&mut stack, values.clone());

        // The "ground truth" is just the value at the index in the original vector.
        let expected_value = values[index as usize];

        stack.number(index);
        let result_var = word_table.peek(&mut stack);

        let expected_var = stack.number_u32(expected_value);
        stack.equals(result_var, true, expected_var, true);

        word_table.drop(&mut stack);
        stack.op_true();

        stack.run().success
    }

    #[test]
    fn test_word_table() {
        test_word_table_helper(vec![0x1234_5678, 0x8765_4321], 0, 0x1234_5678);
        test_word_table_helper(vec![0x1234_5678, 0x8765_4321], 1, 0x8765_4321);
    }

    fn test_mask_helper(number: u32, mask: u32, expected: u32) {
        let mut stack = StackTracker::new();
        let value = stack.number_u32(number);
        let mask = stack.number_u32(mask);
        let result = mask_value(&mut stack, value, mask);
        let expected = stack.number_u32(expected);
        stack.debug_info();
        stack.show_stack();
        stack.equals(result, true, expected, true);
        stack.op_true();
        assert!(stack.run().success);
    }

    fn test_mask_aux(number: u32, _mask: u32) -> bool {
        let mut stack = StackTracker::new();
        let value_var = stack.number_u32(number);
        let mask_var = stack.number_u32(_mask);
        let expected_result = mask(number, _mask);
        let result_var = mask_value(&mut stack, value_var, mask_var);
        let expected_var = stack.number_u32(expected_result);
        stack.equals(result_var, true, expected_var, true);
        stack.op_true();
        let r = stack.run().success;
        r
    }
    fn mask(number: u32, mask: u32) -> u32 {
        let mut result = 0u32;
        for i in 0..8 {
            let shift = i * 4;
            let mask_nibble = (mask >> shift) & 0xF;
            let number_nibble = (number >> shift) & 0xF;

            if mask_nibble != 0 {
                result |= number_nibble << shift;
            }
        }
        result
    }

    #[test]
    fn test_mask() {
        test_mask_helper(0x1234_5678, 0x0000_0011, 0x0000_0078);
        test_mask_helper(0x1234_5678, 0x0000_1100, 0x0000_5600);
        test_mask_helper(0x1234_5678, 0x0011_0000, 0x0034_0000);
        test_mask_helper(0x1234_5678, 0x1100_0000, 0x1200_0000);
        test_mask_helper(0x1234_5678, 0x1100_0011, 0x1200_0078);
        test_mask_helper(0x1234_5678, 0x1100_0011, 0x1200_0078);
    }

    fn test_shift_case(value: u32, shift: u32, right: bool, msb: bool, expected: u32) {
        let mut stack = StackTracker::new();
        let to_shift = stack.number(shift);
        let number = stack.number_u32(value);
        let shifted = shift_number(&mut stack, to_shift, number, right, msb);
        let expected = stack.number_u32(expected);
        stack.equals(shifted, true, expected, true);
        stack.op_true();
        assert!(stack.run().success);
    }
    fn shift_case(value: u32, shift: u32, right: bool, msb: bool, expected: u32) -> bool {
        let mut stack = StackTracker::new();
        let to_shift = stack.number(shift);
        let number = stack.number_u32(value);
        let shifted = shift_number(&mut stack, to_shift, number, right, msb);
        let expected = stack.number_u32(expected);
        stack.equals(shifted, true, expected, true);
        stack.op_true();
        stack.run().success
    }

    #[test]
    fn test_shift_number() {
        test_shift_case(0x7100_0013, 13, true, true, 0x0003_8800);
        test_shift_case(0x7100_0013, 13, true, false, 0x0003_8800);
        test_shift_case(0xF100_0013, 13, true, true, 0xFFFF_8800);
        test_shift_case(0xF100_0013, 13, true, false, 0x0007_8800);
        test_shift_case(0xF100_0013, 13, false, false, 0x0002_6000);
    }

    fn test_static_right_shift_2_case(value: u32, expected: u32) {
        let mut stack = StackTracker::new();
        let tables = &StackTables::new(&mut stack, false, false, 2, 2, 0);
        let number = stack.number_u32(value);
        let shifted = static_right_shift_2(&mut stack, tables, number);
        println!("Size:  {} ", stack.get_script().len());
        let expected = stack.number_u32(expected);
        stack.equals(shifted, true, expected, true);
        tables.drop(&mut stack);
        stack.op_true();
        assert!(stack.run().success);
    }

    #[test]
    fn test_static_right_shift_2() {
        test_static_right_shift_2_case(0b1101_1011, 0b0011_0110);
        test_static_right_shift_2_case(0xF100_0013, 0x3C40_0004);
        test_static_right_shift_2_case(3, 0);
    }

    #[test]
    fn test_nib_to_bin() {
        for i in 0..16 {
            let mut stack = StackTracker::new();
            stack.number(i);
            nib_to_bin(&mut stack);
            stack.from_altstack_joined(4, &format!("bin({})", i));
        }
    }

    fn test_lower_helper(value: u32, than: u32, expected: u32, unsigned: bool) {
        let mut stack = StackTracker::new();
        let value = stack.number_u32(value);
        let than = stack.number_u32(than);
        is_lower_than(&mut stack, value, than, unsigned);
        stack.number(expected);
        stack.op_equal();
        assert!(stack.run().success);
    }

    fn lower_helper_aux(value: u32, than: u32, unsigned: bool) -> bool {
        let mut stack = StackTracker::new();

        let expected_result = if unsigned {
            if value < than {
                1
            } else {
                0
            }
        } else {
            if (value as i32) < (than as i32) {
                1
            } else {
                0
            }
        };

        let value_var = stack.number_u32(value);
        let than_var = stack.number_u32(than);
        is_lower_than(&mut stack, value_var, than_var, unsigned);
        stack.number(expected_result);
        stack.op_equalverify();
        stack.op_true();
        stack.run().success
    }

    #[test]
    fn test_lower() {
        test_lower_helper(0x0000_0000, 0xffff_ffff, 1, true);
        test_lower_helper(0x0000_0000, 0xffff_ffff, 0, false);
        test_lower_helper(0xf000_0000, 0xffff_ffff, 1, false);
        test_lower_helper(0x0000_0000, 0xffff_f800, 0, false);
    }

    fn test_lower_helper_64bits(value: u64, than: u64, expected: u32, unsigned: bool) {
        let mut stack = StackTracker::new();
        let value = stack.number_u64(value);
        let than = stack.number_u64(than);
        is_lower_than(&mut stack, value, than, unsigned);
        stack.number(expected);
        stack.op_equal();
        assert!(stack.run().success);
    }

    #[test]
    fn test_lower_64bits() {
        test_lower_helper_64bits(0x0000_0000_0000_0000, 0xffff_ffff_ffff_ffff, 1, true);
        test_lower_helper_64bits(0x0000_0000_0000_0000, 0xffff_ffff_ffff_ffff, 0, false);
        test_lower_helper_64bits(0xf000_0000_0000_0000, 0xffff_ffff_ffff_ffff, 1, false);
        test_lower_helper_64bits(0x0000_0000_0000_0000, 0xffff_f800_0000_0000, 0, false);
    }

    #[test]
    fn test_shift_dynamic() {
        for y in 0..16 {
            for x in 0..16 {
                for shift in 0..4 {
                    for direction in [true, false] {
                        let mut stack = StackTracker::new();
                        let tables = StackTables::new(&mut stack, false, false, 0xf, 0xf, 0);
                        stack.number(y);
                        stack.number(x);
                        stack.number(shift);
                        tables.shift_2nb_dynamic(&mut stack, direction);
                        if direction {
                            stack.number(((y << 4 - shift) | (x >> shift)) & 0xf);
                        } else {
                            stack.number(((y >> 4 - shift) | (x << shift)) & 0xf);
                        }
                        stack.op_equal();
                        stack.to_altstack();
                        tables.drop(&mut stack);
                        stack.from_altstack();
                        assert!(stack.run().success);
                    }
                }
            }
        }
    }

    #[test]
    fn test_shift() {
        for y in 0..16 {
            for x in 0..16 {
                for shift in 1..4 {
                    let mut stack = StackTracker::new();
                    let tables = StackTables::new(&mut stack, false, false, 7, 7, 0);
                    stack.number(y);
                    stack.number(x);
                    tables.shift_2nb(&mut stack, true, shift);
                    stack.number(((y << 4 - shift) | (x >> shift)) & 0xf);
                    stack.op_equal();
                    stack.to_altstack();
                    tables.drop(&mut stack);
                    stack.from_altstack();
                    assert!(stack.run().success);
                }
            }
        }
    }

    #[test]
    fn test_loop_choose() {
        let mut stack = StackTracker::new();
        stack.number(5);
        stack.to_altstack();
        for _ in 0..8 {
            stack.number(0);
            stack.number(1);
            sub_1_if_positive(&mut stack);
            choose(&mut stack);
        }
    }

    fn test_choose_aux(a: u32, b: u32, condition: bool) -> bool {
        let mut stack = StackTracker::new();

        // Ground truth
        let expected_result = if condition { a } else { b };

        stack.number_u32(a);
        stack.number_u32(b);
        stack.number(if condition { 1 } else { 0 }); // The condition

        // Generate the choose script
        let result_var = choose(&mut stack);

        // Compare the script's result with our ground truth
        let expected_var = stack.number_u32(expected_result);
        stack.equals(result_var, true, expected_var, true);

        stack.op_true();
        stack.run().success
    }

    #[test]
    fn test_is_equal_to() {
        let mut stack = StackTracker::new();
        let a = stack.number_u32(0x1234_5678);
        let b = stack.number_u32(0x1234_5678);
        is_equal_to(&mut stack, &a, &b);
        stack.to_altstack();
        stack.drop(b);
        stack.drop(a);
        stack.from_altstack();
        assert!(stack.run().success);
    }

    fn test_is_equal_to_aux(a: u32, b: u32) -> bool {
        let mut stack = StackTracker::new();

        let expected_result = if a == b { 1 } else { 0 };

        let a_var = stack.number_u32(a);
        let b_var = stack.number_u32(b);

        // Generate the is_equal_to script (non-verifying)
        let result_var = is_equal_to(&mut stack, &a_var, &b_var);

        // Compare the script's result with our ground truth.
        let expected_var = stack.number(expected_result);
        stack.equals(result_var, true, expected_var, true);
        stack.drop(b_var);
        stack.drop(a_var);

        stack.op_true();
        stack.run().success
    }

    fn test_if_less_aux(value: u32, than: u8) -> bool {
        let mut stack = StackTracker::new();
        let expected_result = if value < than.into() { 1 } else { 0 };

        stack.number(value);
        let result_var = if_less(&mut stack, than, 1, 0);
        let expected_var = stack.number(expected_result);
        stack.equals(result_var, true, expected_var, true);
        stack.op_true();
        stack.run().success
    }

    #[test]
    fn test_if_less() {
        let mut stack = StackTracker::new();
        stack.number(4);
        let res = if_less(&mut stack, 5, 1, 0);
        let expected = stack.number(1);
        stack.equals(expected, true, res, true);
        stack.op_true();
        assert!(stack.run().success);

        stack = StackTracker::new();
        stack.number(5);
        let res = if_less(&mut stack, 5, 1, 0);
        let expected = stack.number(0);
        stack.equals(expected, true, res, true);
        stack.op_true();
        assert!(stack.run().success);
    }

    fn test_witness_equals_aux(
        memory_witness: &MemoryWitness,
        witness_nibble: u32,
        is_upper: bool,
        expected_access_type: MemoryAccessType,
    ) {
        let mut stack = StackTracker::new();
        let half_nibble_table = if is_upper {
            load_upper_half_nibble_table(&mut stack)
        } else {
            load_lower_half_nibble_table(&mut stack)
        };

        let memory_witness = stack.byte(memory_witness.byte());

        witness_equals(
            &mut stack,
            &half_nibble_table,
            witness_nibble,
            &memory_witness,
            expected_access_type,
        );

        stack.op_verify();
        stack.drop(memory_witness);
        stack.drop(half_nibble_table);
        stack.op_true();
        assert!(stack.run().success);
    }

    #[test]
    fn test_witness_equals() {
        let memory_witness = &MemoryWitness::new(
            MemoryAccessType::Memory,
            MemoryAccessType::Register,
            MemoryAccessType::Unused,
        );
        test_witness_equals_aux(memory_witness, 0, false, MemoryAccessType::Memory);
        test_witness_equals_aux(memory_witness, 1, true, MemoryAccessType::Register);
        test_witness_equals_aux(memory_witness, 1, false, MemoryAccessType::Unused);
        test_witness_equals_aux(
            &MemoryWitness::from_byte(172),
            0,
            false,
            MemoryAccessType::Unused,
        );
    }

    fn test_witness_equals_aux_no_panic(
        witness_byte: u8,
        witness_nibble_idx: u32, // 0 for lower, 1 for upper
        is_upper_table: bool,
    ) -> bool {
        // 1. Calculate the ground truth in pure Rust.
        let nibble = if witness_nibble_idx == 1 {
            witness_byte & 0xF
        } else {
            witness_byte >> 4
        };

        let expected_2bit_value = if is_upper_table {
            nibble >> 2 // Upper 2 bits of the nibble
        } else {
            nibble & 0x3 // Lower 2 bits of the nibble
        };

        // 3 is an invalid MemoryAccessType, just ignore the test
        if expected_2bit_value == 3 {
            return true;
        }

        // Convert the 2-bit number into the MemoryAccessType enum.
        let expected_access_type = MemoryAccessType::from(expected_2bit_value);

        // 2. Setup and run the on-chain script simulation.
        let mut stack = StackTracker::new();
        let half_nibble_table = if is_upper_table {
            load_upper_half_nibble_table(&mut stack)
        } else {
            load_lower_half_nibble_table(&mut stack)
        };

        let memory_witness_var = stack.byte(witness_byte);

        // Generate the script that decodes the witness nibble and compares it to the expected type.
        witness_equals(
            &mut stack,
            &half_nibble_table,
            witness_nibble_idx,
            &memory_witness_var,
            expected_access_type,
        );
        stack.op_verify(); // Assert that the op_equal call returned TRUE.
        stack.drop(memory_witness_var);
        stack.drop(half_nibble_table);
        stack.op_true();
        stack.run().success
    }
    fn test_address_in_range_aux(address: u32, range: &(u32, u32)) -> bool {
        let mut stack = StackTracker::new();

        let address = stack.number_u32(address);

        address_in_range(&mut stack, range, &address);

        stack.op_verify();
        stack.drop(address);
        stack.op_true();
        stack.run().success
    }

    #[test]
    fn test_address_in_range() {
        const START: u32 = 0x0000_00f0;
        const END: u32 = 0x0000_f003;

        let range = &(START, END);

        assert!(test_address_in_range_aux(START, range));
        assert!(test_address_in_range_aux((START + END) / 2, range));
        assert!(test_address_in_range_aux(END, range));

        assert!(!test_address_in_range_aux(START - 1, range));
        assert!(!test_address_in_range_aux(END + 1, range));
    }

    #[test]
    fn test_var_to_number() {
        let mut stack = StackTracker::new();

        let expected = stack.number(0x1234_5678);
        let n = stack.number_u32(0x1234_5678);
        let result = var_to_number(&mut stack, n);
        stack.equals(expected, true, result, true);
        stack.op_true();
        assert!(stack.run().success);
    }

    #[test]
    fn test_number_to_number() {
        let mut stack = StackTracker::new();

        let expected = stack.number(0x1234_5678);
        let n = stack.number(0x1234_5678);
        let result = var_to_number(&mut stack, n);
        stack.equals(expected, true, result, true);
        stack.op_true();
        assert!(stack.run().success);
    }

    fn test_get_selected_vars_aux(var_selector: u32) {
        let mut stack = StackTracker::new();

        let previous_var = stack.number_u32(0x3333_3333);

        let var_1 = stack.number_u32(0x1111_1111);
        let var_2 = stack.number_u32(0x2222_2222);
        let selector = stack.number(var_selector);

        let next_var = stack.number_u32(0x4444_4444);

        let [chosen_var] = get_selected_vars(&mut stack, [var_1], [var_2], selector);

        // we should get the selected variable
        let expected_var = if var_selector == 1 {
            0x1111_1111
        } else {
            0x2222_2222
        };
        let expected_var = stack.number_u32(expected_var);
        stack.equality(chosen_var, true, expected_var, true, true, true);

        // previous variable should remain unchanged
        let expected_var = stack.number_u32(0x3333_3333);
        stack.equality(previous_var, true, expected_var, true, true, true);

        // next variable should also remain unchanged
        let expected_var = stack.number_u32(0x4444_4444);
        stack.equality(next_var, true, expected_var, true, true, true);

        stack.op_true();
        assert!(stack.run().success);
    }

    #[test]
    fn test_get_selected_vars() {
        test_get_selected_vars_aux(1);
        test_get_selected_vars_aux(2);
    }

    fn test_verify_wrong_chunk_value_aux(address: u32, value: u32, chunk: &Chunk) -> bool {
        let mut stack = StackTracker::new();

        let address = stack.number_u32(address);
        let value = stack.number_u32(value);
        let tables = &StackTables::new(&mut stack, true, false, 2, 2, 0);

        verify_wrong_chunk_value(&mut stack, tables, chunk, address, value);
        tables.drop(&mut stack);
        stack.op_true();
        stack.run().success
    }

    #[test]
    fn test_verify_wrong_chunk_value() {
        let chunk = &Chunk {
            base_addr: 0x1000_0000,
            data: vec![0x1111_1111, 0x2222_2222],
        };

        assert!(test_verify_wrong_chunk_value_aux(
            0x1000_0000,
            0x1234_5678,
            chunk
        ));
        assert!(test_verify_wrong_chunk_value_aux(
            0x1000_0004,
            0x1234_5678,
            chunk
        ));
        assert!(!test_verify_wrong_chunk_value_aux(
            0x1000_0000,
            0x1111_1111,
            chunk
        ));
        assert!(!test_verify_wrong_chunk_value_aux(
            0x1000_0004,
            0x2222_2222,
            chunk
        ));
    }

    fn test_var_to_decisions_in_stack_aux(
        decisions: &[u32],
        step: u64,
        nary_last_round: u8,
        nary: u8,
    ) {
        let stack = &mut StackTracker::new();
        let tables = &StackTables::new(stack, false, false, 0b111, 0b111, 0);

        for decision in decisions.iter().rev() {
            stack.number(*decision);
        }
        let var = stack.number_u64(step);
        var_to_decisions_in_stack(
            stack,
            tables,
            var,
            nary_last_round,
            nary,
            decisions.len() as u8,
        );

        for _ in 0..decisions.len() {
            stack.from_altstack();
            stack.op_equalverify();
        }

        tables.drop(stack);
        stack.op_true();
        assert!(stack.run().success);
    }

    #[test]
    fn test_var_to_decisions_in_stack() {
        test_var_to_decisions_in_stack_aux(&[4, 2, 4, 0], 1104, 4, 8);
        test_var_to_decisions_in_stack_aux(&[4, 2, 4, 1], 1105, 4, 8);
        test_var_to_decisions_in_stack_aux(&[4, 2, 4, 2], 1106, 4, 8);
        test_var_to_decisions_in_stack_aux(&[4, 2, 4, 3], 1107, 4, 8);

        test_var_to_decisions_in_stack_aux(&[0, 3, 0, 3], 99, 4, 8);
        test_var_to_decisions_in_stack_aux(&[1, 3, 0, 3], 355, 4, 8);
    }

    fn test_next_decision_aux(decision: u64, rounds: u8, nary: u8, nary_last_round: u8) {
        let stack = &mut StackTracker::new();
        let tables = &StackTables::new(stack, false, false, 0b111, 0b111, 0);

        let max_nary = nary - 1;
        let max_last_round = if nary_last_round == 0 {
            max_nary
        } else {
            nary_last_round - 1
        };

        let decision_var = stack.number_u64(decision);
        let next_decision_var = stack.number_u64(decision + 1);

        var_to_decisions_in_stack(
            stack,
            tables,
            next_decision_var,
            nary_last_round,
            nary,
            rounds,
        );

        var_to_decisions_in_stack(stack, tables, decision_var, nary_last_round, nary, rounds);

        let decision = stack.from_altstack_joined(rounds as u32, "decision_bits");

        next_decision_in_stack(stack, decision, rounds, max_last_round, max_nary);
        let next_decision_bits = stack.from_altstack_joined(rounds as u32, "decision_bits");

        let expected_next_decision_bits =
            stack.from_altstack_joined(rounds as u32, "expected_decision_bits");

        stack.equals(next_decision_bits, true, expected_next_decision_bits, true);

        tables.drop(stack);
        stack.op_true();

        assert!(stack.run().success);
    }
    #[test]
    fn test_next_decision() {
        test_next_decision_aux(100, 4, 8, 4);
        test_next_decision_aux(302, 8, 8, 2);
        test_next_decision_aux(38, 8, 2, 2);
        test_next_decision_aux(892, 4, 8, 0);
    }

    mod fuzz_tests {
        use super::*;
        use rand::Rng;
        use rand_pcg::Pcg32;
        use std::panic;
        use std::panic::AssertUnwindSafe;
        const FUZZ_ITERATIONS: u32 = 1000; // Increase for more thorough fuzzing

        const WORD_TABLES: [[u32; 4]; 5] = [
            [0x1111_1100, 0x1111_0011, 0x1100_1111, 0x0011_1111],
            [0x1111_0000, 0x1100_0011, 0x0000_1111, 0x0011_1111],
            [0x0000_0000, 0x0000_0011, 0x0000_1111, 0x0011_1111],
            [0x0000_0000, 0x0000_0000, 0x0000_0000, 0x1111_1100],
            [0x0000_0000, 0x1111_1100, 0x1111_0000, 0x1100_0000],
        ];

        fn push_i32_as_nibbles(stack: &mut StackTracker, value: i32) -> StackVariable {
            // Cast the i32 to u32 to get its raw two's complement bit pattern.
            let bits = value as u32;
            for i in (0..8).rev() {
                let nibble = (bits >> (i * 4)) & 0xF;
                stack.number(nibble);
            }
            stack.join_in_stack(8, None, Some(&format!("i32_as_nibbles({:#x})", bits)))
        }

        fn fuzz_generic_and_catch_panics<T, G, F>(
            fuzzer_name: &str,
            mut input_generator: G,
            mut test_logic: F,
        ) where
            F: FnMut(T) -> bool + std::panic::UnwindSafe,
            G: FnMut(&mut Pcg32) -> T,
            T: std::fmt::Debug + Clone,
        {
            use rand::prelude::*;
            use rand_pcg::Pcg32;
            use std::env;

            let seed_str =
                env::var("FUZZ_SEED").unwrap_or_else(|_| rand::rng().random::<u64>().to_string());
            let seed = seed_str.parse::<u64>().expect("FUZZ_SEED must be a number");
            println!("--- Fuzzing {} with seed: {} ---", fuzzer_name, seed);
            let mut rng = Pcg32::seed_from_u64(seed);

            const ITERATIONS: u32 = FUZZ_ITERATIONS;
            let mut panics = Vec::with_capacity(ITERATIONS as usize);
            let mut failures = Vec::with_capacity(ITERATIONS as usize);
            let mut oks = Vec::with_capacity(ITERATIONS as usize);

            for _ in 0..ITERATIONS {
                let input = input_generator(&mut rng);
                let result = panic::catch_unwind(AssertUnwindSafe(|| test_logic(input.clone())));

                match result {
                    Ok(success) if !success => {
                        failures.push(input);
                    }
                    Ok(success) if success => {
                        oks.push(input);
                    }
                    Err(_) => {
                        panics.push(input);
                    }
                    Ok(_) => unreachable!(),
                }
            }

            if !panics.is_empty() || !failures.is_empty() {
                println!(
                    "\n--- Found {} OK Inputs for {} (seed: {}) ---",
                    oks.len(),
                    fuzzer_name,
                    seed
                );
                println!(
                    "\n--- Found {} Failing (No Panic) Inputs for {} (seed: {}) ---",
                    failures.len(),
                    fuzzer_name,
                    seed
                );
                for input in &failures {
                    println!("{:?}", input);
                }
                println!(
                    "\n--- Found {} Panicking Inputs for {} (seed: {}) ---",
                    panics.len(),
                    fuzzer_name,
                    seed
                );
                for input in &panics {
                    println!("{:?}", input);
                }
                panic!("Fuzzer {} found divergences", fuzzer_name);
            } else {
                println!(
                    "\n✅ Success! No divergences found for {} in {} iterations.",
                    fuzzer_name, ITERATIONS
                );
            }
        }

        #[test]
        #[ignore = "Useful to run all fuzz manually, but `cargo test` will run them all anyway."]
        fn fuzz_all() {
            fuzz_shift_number();
            fuzz_twos_complement();
            fuzz_twos_complement_conditional();
            fuzz_left_rotate();
            fuzz_word_table();
            fuzz_divu_remu(); // ! TODO: model RISC-V overflows
            fuzz_is_lower_than();
            fuzz_u4_to_u8();
            fuzz_is_negative();
            fuzz_address_not_in_sections();
            fuzz_is_equal_to();
            fuzz_mask();
            fuzz_if_less();
            fuzz_multiply();
            fuzz_mulh();
            fuzz_sub_1_if_positive();
            fuzz_var_to_number();
            fuzz_div_rem();

            // ! Choose method is not used so we ignore it.
            // fuzz_choose(); // <-- choose is not used,
        }

        #[test]
        fn fuzz_multiply() {
            fuzz_generic_and_catch_panics(
                "multiply",
                |rng| -> (u32, u32) { (rng.random(), rng.random()) },
                |input| -> bool {
                    let (a, b) = input;
                    let result = (a as u64) * (b as u64);
                    let low = result as u32;
                    let high = (result >> 32) as u32;
                    multiply_aux(a, b, high, low)
                },
            );
        }

        #[test]
        fn fuzz_shift_number() {
            fuzz_generic_and_catch_panics(
                "shift_number",
                |rng| -> (u32, u32, bool, bool) {
                    (
                        rng.random(),
                        rng.random_range(0..32), // shift amount (0-31)
                        rng.random(),            // right (true) or left (false)
                        rng.random(),            // msb (true for arithmetic, false for logical)
                    )
                },
                |input| -> bool {
                    let (value, shift, right, msb) = input;
                    let expected = if right {
                        if msb {
                            ((value as i32) >> shift) as u32
                        } else {
                            value >> shift
                        }
                    } else {
                        value << shift
                    };

                    shift_case(value, shift, right, msb, expected)
                },
            );
        }

        #[test]
        fn fuzz_twos_complement() {
            fuzz_generic_and_catch_panics(
                "twos_complement",
                |rng| -> u32 { rng.random() },
                |value| -> bool { twos_complement_aux(value) },
            );
        }
        #[test]
        fn fuzz_twos_complement_conditional() {
            fuzz_generic_and_catch_panics(
                "twos_complement_conditional",
                |rng| -> (u32, bool) { (rng.random(), rng.random()) },
                |input| -> bool {
                    let (value, condition) = input;
                    twos_complement_conditional_aux(value, condition)
                },
            );
        }

        #[test]
        fn fuzz_left_rotate() {
            fuzz_generic_and_catch_panics(
                "left_rotate",
                |rng| -> (u32, u32) {
                    (
                        rng.random(),
                        rng.random_range(0..4), //
                    )
                },
                |input| -> bool {
                    let (value, rotate) = input;
                    test_left_rotate_aux(value, rotate)
                },
            );
        }
        #[test]
        fn fuzz_word_table() {
            fuzz_generic_and_catch_panics(
                "word_table",
                |rng| -> (Vec<u32>, u32) {
                    let vec_size = rng.random_range(1..20); // Create a table of 1 to 19 words
                    let values: Vec<u32> = (0..vec_size).map(|_| rng.random()).collect();
                    let index = rng.random_range(0..vec_size as u32);
                    (values, index)
                },
                |input| -> bool {
                    let (values, index) = input;
                    test_word_table_aux(values, index)
                },
            );
        }

        #[test]
        fn fuzz_mask() {
            fuzz_generic_and_catch_panics(
                "mask_value",
                |rng| -> (u32, u8, u8) {
                    (rng.random(), rng.random_range(0..5), rng.random_range(0..4))
                },
                |input| -> bool {
                    let (number, word_mask, word_index) = input;
                    let mask = WORD_TABLES[word_mask as usize][word_index as usize];
                    test_mask_aux(number, mask)
                },
            );
        }

        #[test]
        fn fuzz_is_lower_than() {
            fuzz_generic_and_catch_panics(
                "is_lower_than",
                |rng| -> (u32, u32, bool) {
                    (
                        rng.random(),
                        rng.random(),
                        rng.random(), // for the unsigned flag
                    )
                },
                |input| -> bool {
                    let (value, than, unsigned) = input;
                    lower_helper_aux(value, than, unsigned)
                },
            );
        }

        #[test]
        fn fuzz_is_equal_to() {
            fuzz_generic_and_catch_panics(
                "is_equal_to",
                |rng| -> (u32, u32, bool) { (rng.random(), rng.random(), rng.random()) },
                |input| -> bool {
                    let (mut a, b, equals) = input;
                    // force the exercising of the equals conditions
                    // as well as the non-equality in half the scenarios
                    if equals {
                        a = b;
                    }
                    test_is_equal_to_aux(a, b)
                },
            );
        }

        #[test]
        fn fuzz_if_less() {
            fuzz_generic_and_catch_panics(
                "if_less",
                |rng| -> (u32, u8) { (rng.random(), rng.random()) },
                |input| -> bool {
                    let (value, than) = input;
                    // Patch for issue in if_less
                    // as it works only with number()
                    // See `fuzz_all` for full description
                    if value > 0x0fff_ffff {
                        return true;
                    }
                    test_if_less_aux(value, than)
                },
            );
        }

        #[test]
        #[ignore = "choose() not used in the project"]
        fn fuzz_choose() {
            fuzz_generic_and_catch_panics(
                "choose",
                |rng| -> (u32, u32, bool) { (rng.random(), rng.random(), rng.random()) },
                |input| -> bool {
                    let (a, b, condition) = input;
                    test_choose_aux(a, b, condition)
                },
            );
        }

        #[test]
        fn fuzz_witness_equals() {
            fuzz_generic_and_catch_panics(
                "witness_equals",
                |rng| -> (u8, u32, bool) {
                    (
                        rng.random(),           // A random MemoryWitness byte
                        rng.random_range(0..2), // Which nibble to check (0 or 1)
                        rng.random(),           // Which table to use (upper or lower half)
                    )
                },
                |input| -> bool {
                    let (witness_byte, nibble_idx, is_upper) = input;
                    test_witness_equals_aux_no_panic(witness_byte, nibble_idx, is_upper)
                },
            );
        }

        fn u4_to_u8_aux(a: u8, b: u8) -> bool {
            let mut stack = StackTracker::new();
            let expected_result = ((a as u32) << 4) | (b as u32);
            stack.number(a as u32);
            stack.number(b as u32);
            u4_to_u8(&mut stack);
            stack.number(expected_result);
            stack.op_equalverify();
            stack.op_true();
            stack.run().success
        }

        #[test]
        fn fuzz_u4_to_u8() {
            fuzz_generic_and_catch_panics(
                "u4_to_u8",
                |rng| -> (u8, u8) { (rng.random_range(0..16), rng.random_range(0..16)) },
                |input| -> bool {
                    let (a, b) = input;
                    u4_to_u8_aux(a, b)
                },
            );
        }

        fn sub_1_if_positive_aux(value: i32) -> bool {
            let mut stack = StackTracker::new();

            let expected_result = if value > 0 { value - 1 } else { 0 };

            stack.numberi(value);
            stack.to_altstack();
            sub_1_if_positive(&mut stack);

            let result_var = stack.from_altstack();
            let expected_var = stack.numberi(expected_result);
            stack.equals(result_var, true, expected_var, true);
            stack.drop_var();

            stack.op_true();
            stack.run().success
        }

        #[test]
        fn fuzz_sub_1_if_positive() {
            fuzz_generic_and_catch_panics(
                "sub_1_if_positive",
                |rng| -> i32 { rng.random_range(-7..8) },
                |input| -> bool { sub_1_if_positive_aux(input) },
            );
        }

        fn is_negative_aux(value: i32) -> bool {
            let mut stack = StackTracker::new();
            let expected_result = if value < 0 { 1 } else { 0 };

            let value = push_i32_as_nibbles(&mut stack, value);
            is_negative(&mut stack, value);
            stack.number(expected_result);
            stack.op_equalverify();

            stack.drop(value);
            stack.op_true();
            let s = stack.run().success;
            s
        }

        #[test]
        fn fuzz_is_negative() {
            fuzz_generic_and_catch_panics(
                "is_negative",
                |rng| -> i32 { rng.random() },
                |input| -> bool { is_negative_aux(input) },
            );
        }
        fn var_to_number_aux(number: u32) -> bool {
            let mut stack = StackTracker::new();

            let var = stack.number_u32(number);
            let result_var = var_to_number(&mut stack, var);

            // Use stack.number() to get a size-1 variable for the expected result.
            let expected_number = stack.number(number);

            // Now that both are size-1 scalars and we've limited the input range,
            // we can use a direct op_equalverify.
            stack.move_var(result_var);
            stack.move_var(expected_number);
            stack.op_equalverify();

            stack.op_true();
            stack.run().success
        }

        #[test]
        fn fuzz_var_to_number() {
            fuzz_generic_and_catch_panics(
                "var_to_number",
                |rng| -> u32 { rng.random_range(0..std::i32::MAX as u32) },
                |input| -> bool { var_to_number_aux(input) },
            );
        }

        fn mulh_aux(a: u32, b: u32, mulhsu: bool) -> bool {
            let mut stack = StackTracker::new();
            let tables = StackTables::new(&mut stack, true, true, 0, 0, 0);

            // mulh is _multiplication high_, we only care about the
            // the highest 32 bits so we shift >> 32 at the end
            let expected_result = if mulhsu {
                let a_i64 = a as i32 as i64;
                let b_u64 = b as u64;
                let result = a_i64.wrapping_mul(b_u64 as i64);
                (result >> 32) as u32
            } else {
                let a_i64 = a as i32 as i64;
                let b_i64 = b as i32 as i64;
                let result = a_i64.wrapping_mul(b_i64);
                (result >> 32) as u32
            };

            // ! mulh:   signed x signed
            // ! mulhsu: signed x unsigned
            let a_var = push_i32_as_nibbles(&mut stack, a as i32);
            let b_var = if mulhsu {
                stack.number_u32(b)
            } else {
                push_i32_as_nibbles(&mut stack, b as i32)
            };

            let result_var = mulh(&mut stack, &tables, a_var, b_var, mulhsu);

            stack.to_altstack();
            tables.drop(&mut stack);
            stack.from_altstack();

            let expected_var = push_i32_as_nibbles(&mut stack, expected_result as i32);
            stack.equals(result_var, true, expected_var, true);

            stack.op_true();
            let s = stack.run().success;
            s
        }

        #[test]
        fn fuzz_mulh() {
            fuzz_generic_and_catch_panics(
                "mulh",
                |rng| -> (u32, u32, bool) { (rng.random(), rng.random(), rng.random()) },
                |input| -> bool {
                    let (a, b, mulhsu) = input;
                    mulh_aux(a, b, mulhsu)
                },
            );
        }

        fn div_rem_unsigned_aux(dividend: u32, divisor: u32) -> bool {
            let mut stack = StackTracker::new();
            let tables = StackTables::new(&mut stack, true, true, 0, 0, 0);

            let expected_quotient = dividend / divisor;
            let expected_remainder = dividend % divisor;

            let dividend_var = stack.number_u32(dividend);
            let divisor_var = stack.number_u32(divisor);
            let quotient_var = stack.number_u32(expected_quotient);
            let remainder_var = stack.number_u32(expected_remainder);

            let result_divu = divu(
                &mut stack,
                &tables,
                dividend_var,
                divisor_var,
                quotient_var,
                remainder_var,
            );

            let dividend_var = stack.number_u32(dividend);
            let divisor_var = stack.number_u32(divisor);
            let quotient_var = stack.number_u32(expected_quotient);
            let remainder_var = stack.number_u32(expected_remainder);

            let result_remu = remu(
                &mut stack,
                &tables,
                dividend_var,
                divisor_var,
                remainder_var,
                quotient_var,
            );

            let expected_q_var = stack.number_u32(expected_quotient);
            stack.equals(result_divu, true, expected_q_var, true);

            let expected_r_var = stack.number_u32(expected_remainder);
            stack.equals(result_remu, true, expected_r_var, true);
            tables.drop(&mut stack);

            stack.op_true();
            stack.run().success
        }

        #[test]
        fn fuzz_divu_remu() {
            fuzz_generic_and_catch_panics(
                "divu_remu",
                |rng| -> (u32, u32) { (rng.random(), rng.random()) },
                |input| -> bool {
                    let (a, b) = input;
                    div_rem_unsigned_aux(a, b)
                },
            );
        }

        fn div_rem_signed_aux(dividend: i32, divisor: i32) -> bool {
            if divisor == 0 || (dividend == i32::MIN && divisor == -1) {
                return true;
            }

            let mut stack = StackTracker::new();
            let tables = StackTables::new(&mut stack, true, true, 0, 0, 0);

            let expected_quotient = dividend / divisor;
            let expected_remainder = dividend % divisor;

            let dividend_var = push_i32_as_nibbles(&mut stack, dividend);
            let divisor_var = push_i32_as_nibbles(&mut stack, divisor);
            let quotient_var = push_i32_as_nibbles(&mut stack, expected_quotient as i32);
            let remainder_var = push_i32_as_nibbles(&mut stack, expected_remainder as i32);

            let result_div = div(
                &mut stack,
                &tables,
                dividend_var,
                divisor_var,
                quotient_var,
                remainder_var,
            );

            // Re-push variables for the next operation
            let dividend_var = push_i32_as_nibbles(&mut stack, dividend);
            let divisor_var = push_i32_as_nibbles(&mut stack, divisor);
            let quotient_var = push_i32_as_nibbles(&mut stack, expected_quotient as i32);
            let remainder_var = push_i32_as_nibbles(&mut stack, expected_remainder as i32);

            let result_rem = rem(
                &mut stack,
                &tables,
                dividend_var,
                divisor_var,
                remainder_var,
                quotient_var,
            );

            // Verification using stack.equals is already correct
            let expected_q_var = push_i32_as_nibbles(&mut stack, expected_quotient);
            stack.equals(result_div, true, expected_q_var, true);

            let expected_r_var = push_i32_as_nibbles(&mut stack, expected_remainder);
            stack.equals(result_rem, true, expected_r_var, true);
            tables.drop(&mut stack);

            stack.op_true();
            let s = stack.run().success;
            println!("success: {}", s);
            println!("expected quotient: {}", expected_quotient);
            println!("expected remainder: {}", expected_remainder);
            s
        }

        #[test]
        fn fuzz_div_rem() {
            fuzz_generic_and_catch_panics(
                "div_rem",
                |rng| -> (i32, i32) { (rng.random(), rng.random()) },
                |input| -> bool {
                    let (a, b) = input;
                    div_rem_signed_aux(a, b)
                },
            );
        }

        fn address_not_in_sections_aux(address: u32, ranges: Vec<(u32, u32)>) -> bool {
            let mut stack = StackTracker::new();

            let mut expected_result = true;
            for range in &ranges {
                if address >= range.0 && address <= range.1 - 3 {
                    expected_result = false;
                    break;
                }
            }

            let sections = SectionDefinition { ranges };
            let address_var = stack.number_u32(address);
            address_not_in_sections(&mut stack, &address_var, &sections);

            stack.number(if expected_result { 1 } else { 0 });
            stack.op_equalverify();
            stack.drop(address_var);

            stack.op_true();
            stack.show_stack();
            let r = stack.run().success;
            r
        }

        #[test]
        fn fuzz_address_not_in_sections() {
            fuzz_generic_and_catch_panics(
                "address_not_in_sections",
                |rng| -> (u32, Vec<(u32, u32)>) {
                    let num_ranges = rng.random_range(1..5);
                    let mut ranges = Vec::new();
                    for _ in 0..num_ranges {
                        let start = rng.random_range(0..0xFFFFFFF0);
                        let end = rng.random_range(start + 4..start + 0xFF);
                        ranges.push((start, end));
                    }
                    (rng.random(), ranges)
                },
                |input| -> bool {
                    let (address, ranges) = input;
                    address_not_in_sections_aux(address, ranges)
                },
            );
        }

        #[test]
        fn test_mulh_is_wrong() {
            // mulh_aux(0x84226da3, 0x80c8c213, false);
            // mulh_aux(3624813874, 158200733, false);
            // mulh_aux(3424953106, 1503063288, false);
            // mulh_aux(212774383, 495884893, true);
            mulh_aux(0x6dadedf2, 0x41c64e6d, false);
            mulh_aux(0x6dadedf2, 0x41c64e6d, true);
        }

        #[test]
        fn test_multiplication_carry_bug() {
            // A collection of input pairs that are known to cause failures due to the
            // suspected carry propagation bug. The products all contain long sequences of 0xF.
            let failing_inputs = vec![
                (0x2a37e15a, 0xf3e9df3e), // product: 0x28efffff28b28d74
                (0xaf3ef39b, 0xc4dbe6ec), // product: 0x87ffff747a83d414
                (0xe7a3effb, 0x7b64f3b2), // product: 0x6fffffea41d34c16 (causes panic)
                (0x1b49f21b, 0x1f51e1ed), // causes panic
                (0x6dadedf2, 0x41c64e6d),
            ];

            // // A collection of inputs that should pass, as their products do not have
            // // the problematic long carry sequences.
            let passing_inputs = vec![
                (0x00000002, 0x00000004),
                (0x12345678, 0x87654321),
                (0x1, 0x1),
                (u32::MAX, 0x1),
                (0x10000, 0x200),
                (0x7FFFFFFF, 2),
                (0x1, u32::MAX),
                // all of below are OK, unexpectedly
                (0xffffffff, 0xffffffff), // product: 0xfffffffe00000001
                (0x80000001, 0xfffffffe), // product: 0x7ffffffe80000002
                (0xffffffff, 0xfffffffe), // product: 0xfffffffd00000002
                (0x84226da3, 0x80c8c213), // fails mulh but passes mult
                (0xd80e4532, 0x96df39d),
                (0xcc24a312, 0x5996ecf8),
            ];

            println!("--- Testing known failing inputs ---");
            for (a, b) in &failing_inputs {
                let result = (*a as u64) * (*b as u64);
                let low = result as u32;
                let high = (result >> 32) as u32;

                let result = std::panic::catch_unwind(|| multiply_aux(*a, *b, high, low));

                match result {
                    Err(_) => {
                        println!("Confirmed failure for a=0x{:08x}, b=0x{:08x}", a, b);
                    }
                    Ok(res) => {
                        if res {
                            println!("Unexpected success for a=0x{:08x}, b=0x{:08x}", a, b);
                        } else {
                            println!("Confirmed failure for a=0x{:08x}, b=0x{:08x}", a, b);
                        }
                    }
                }
            }

            println!("\n--- Testing known passing inputs ---");
            for (a, b) in &passing_inputs {
                let result = (*a as u64) * (*b as u64);
                let low = result as u32;
                let high = (result >> 32) as u32;

                let result = std::panic::catch_unwind(|| multiply_aux(*a, *b, high, low));

                match result {
                    Ok(res) => {
                        if res {
                            println!("Confirmed success for a=0x{:08x}, b=0x{:08x}", a, b);
                        } else {
                            println!("Unexpected failure for a=0x{:08x}, b=0x{:08x}", a, b);
                        }
                    }
                    Err(_) => {
                        println!("Unexpected panick for a=0x{:08x}, b=0x{:08x}", a, b);
                    }
                }
            }
        }

        #[test]
        #[ignore = "Failing only with numbers of more than a nibble. Caller responsibility."]
        /// `test_big_negative_number_less_than_small_panics`
        /// This is `#[ignored]` because the contract with the caller
        /// is that this function operates on nibbles, not on big numbers
        fn test_big_negative_number_less_than_small_panics() {
            let mut stack = StackTracker::new();
            let big_number = 0x7544CA31;
            let small = 10;
            let _ = stack.number_u32(big_number);
            // ! big_number < small_number, false, should return false
            let res = if_less(&mut stack, small, 1, 0);
            let expected = stack.number(0);
            stack.equals(expected, true, res, true);
            stack.op_true();
        }

        #[test]
        fn test_push_fail_when_numbers_are_too_big() {
            // There's no clear way in the Stack API to push
            // arbitrary-sized negative integers
            // Using `hexstr_as_nibbles` will result in it
            // interpreting each nibble as a u4 anyway
            // If you use `number()` to push a full-sized u32 integer
            // it will overflow
            let val = 0x7FFF_FFFF;
            assert!(sub_1_if_positive_aux(val))
        }

        #[test]
        fn test_number_negative() {
            is_negative_aux(-0x8);
            is_negative_aux(0x8);
            is_negative_aux(0x8000);
            is_negative_aux(-0x8000);
        }

        #[test]
        fn test_div_rem_signed_fails_for_certain_inputs() {
            div_rem_signed_aux(-187100008, 234592619);
            div_rem_signed_aux(-1234054314, 1784177589);
            div_rem_signed_aux(-1371573435, 1470078231);
            div_rem_signed_aux(-1171857267, 2089119674);
            div_rem_signed_aux(-1340669410, 1481685986);
            div_rem_signed_aux(-1460440325, 2066183210);
            div_rem_signed_aux(931887209, -1960352008);
            div_rem_signed_aux(857158955, -1419303977);
            div_rem_signed_aux(34309962, -1398707796);
        }
    }
}
