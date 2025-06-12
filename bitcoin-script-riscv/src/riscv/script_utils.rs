use bitcoin_script_stack::stack::{StackTracker, StackVariable};

pub use bitcoin_script::{define_pushable, script};
define_pushable!();
pub use bitcoin::ScriptBuf as Script;
use bitvmx_cpu_definitions::memory::{MemoryAccessType, SectionDefinition};

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
    if !unsigned {
        stack.copy_var_sub_n(value, 0);
        if_greater(stack, 7, 1, 0); //1 if negative
        stack.copy_var_sub_n(than, 0);
        if_greater(stack, 7, 1, 0); //1 if negative
        stack.op_2dup();
        stack.op_equal();
        stack
            .custom(
                script! {
                    OP_IF
                        OP_2DROP
                        0
                    OP_ELSE
                        OP_GREATERTHAN
                        OP_IF
                            512
                        OP_ELSE
                            { -512 }
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

    for i in 0..8 {
        let n: i32 = 2_i32.pow(8 - i);
        stack.move_var_sub_n(value, 0);
        stack.move_var_sub_n(than, 0);
        stack.op_2dup();
        stack.op_lessthan();
        stack
            .custom(
                script! {
                    OP_IF
                        OP_2DROP
                        { n}
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
    for _ in 0..7 {
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

    let modulo = modulo_table(stack, 128);
    let quotient = quotient_table_ex(stack, 128);

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

    //then assert sign of divisor and dividen are the same the quotient sign is positive and negative otherwise
    is_negative(stack, divisor); // divisor_sign | dividend_sign dividend_sign  rem_sign
    stack.op_dup(); // divisor_sign divisor_sign | dividend_sign dividend_sign  rem_sign
    stack.from_altstack(); // divisor_sign divisor_sign dividend_sign | dividend_sign rem_sign
    stack.op_equal(); // divisor_sign ( divisor and dividend same sign)  | dividend_sign rem_sign
    stack.op_not(); // divisor_sign ~( divisor and dividend same sign) | dividend_sign rem_sign

    is_negative(stack, quotient); // divisor_sign ~( divisor and dividend same sign) quotient_sign | dividend_sign rem_sign
    stack.op_dup(); // divisor_sign ~( divisor and dividend same sign) quotient_sign quotient_sign | dividend_sign rem_sign
    stack.to_altstack(); // divisor_sign ~( divisor and dividend same sign) quotient_sign | quotient_sign  dividend_sign rem_sign

    stack.op_equalverify(); // divisor_sign | quotient_sign  dividend_sign rem_sign

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

pub fn edge_case(
    stack: &mut StackTracker,
    dividend: StackVariable,
    divisor: StackVariable,
    quotient: StackVariable,
    remainder: StackVariable,
    compare: u32,
    result: Option<u32>,
) -> (StackTracker, StackTracker) {
    let value = stack.number_u32(compare);
    is_equal_to(stack, &value, &divisor);
    stack.to_altstack();
    stack.drop(value);
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
    compare: u32,
    result: Option<u32>,
    is_rem_check: bool,
) -> StackVariable {
    stack.move_var(dividend);
    stack.move_var(divisor);
    stack.move_var(quotient);
    stack.move_var(remainder);

    let (stack_true, mut stack_false) = edge_case(
        stack, dividend, divisor, quotient, remainder, compare, result,
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
        0,
        Some(0xFFFF_FFFF),
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
        stack, tables, dividend, divisor, quotient, remainder, 0, None, true,
    )
}

pub fn division_and_remainder_signed(
    stack: &mut StackTracker,
    tables: &StackTables,
    dividend: StackVariable,
    divisor: StackVariable,
    quotient: StackVariable,
    remainder: StackVariable,
    compare_1: u32,
    result_1: Option<u32>,
    compare_2: u32,
    result_2: Option<u32>,
    is_rem_check: bool,
) -> StackVariable {
    stack.move_var(dividend);
    stack.move_var(divisor);
    stack.move_var(quotient);
    stack.move_var(remainder);

    let (stack_true, mut stack_false) = edge_case(
        stack, dividend, divisor, quotient, remainder, compare_1, result_1,
    );

    let (stack_true_2, mut stack_no_edge) = edge_case(
        &mut stack_false,
        dividend,
        divisor,
        quotient,
        remainder,
        compare_2,
        result_2,
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
        0,
        Some(0xFFFF_FFFF),
        0xFFFF_FFFF,
        None,
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
        0,
        None,
        0xFFFF_FFFF,
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

pub fn address_not_in_sections(
    stack: &mut StackTracker,
    address: &StackVariable,
    sections: &SectionDefinition,
) {
    for range in &sections.ranges {
        assert!(range.0 + 3 <= range.1);
        let section_start = stack.number_u32(range.0);
        let address_copy: StackVariable = stack.copy_var(*address);

        is_lower_than(stack, address_copy, section_start, true);

        // when we do a read on an address, we also read the 3 addresses after
        let section_end = stack.number_u32(range.1 - 3);
        let address_copy = stack.copy_var(*address);

        is_lower_than(stack, section_end, address_copy, true);

        stack.op_boolor();
    }

    for _ in 0..sections.ranges.len() - 1 {
        stack.op_booland();
    }
}

pub fn nibbles_to_number(stack: &mut StackTracker, nibbles: Vec<StackVariable>) -> StackVariable {
    let mut result = stack.number(0);

    for nibble in nibbles.iter() {
        multiply_by_16(stack);
        stack.move_var(*nibble);
        result = stack.op_add();
    }

    result
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

    #[test]
    fn test_twos_complement() {
        let mut stack = StackTracker::new();
        let tables = StackTables::new(&mut stack, true, true, 0, 0, 0);

        let value = stack.number_u32(0xaaaa_aaab);
        let size = stack.get_script().len();
        let result = twos_complement(&mut stack, &tables, value, 8);
        println!("Consumed: {}", stack.get_script().len() - size);
        stack.to_altstack();
        tables.drop(&mut stack);
        stack.from_altstack();

        let expected = stack.number_u32(0x5555_5555);
        stack.equals(result, true, expected, true);
        stack.op_true();
        assert!(stack.run().success);
    }

    fn test_multiply_aux(a: u32, b: u32, high: u32, low: u32) {
        let mut stack = StackTracker::new();

        let a = stack.number_u32(a);
        let b = stack.number_u32(b);

        let start = stack.get_script().len();

        let mult = multiply(&mut stack, a, b, false, false);

        println!("Consumed: {}", stack.get_script().len() - start);

        stack.explode(mult);
        let res_high = stack.join_in_stack(16, Some(8), Some("high"));
        let res_low = stack.join_in_stack(8, None, Some("low"));

        let exp_low = stack.number_u32(low);
        stack.equals(res_low, true, exp_low, true);

        let exp_high = stack.number_u32(high);
        stack.equals(res_high, true, exp_high, true);

        stack.op_true();

        assert!(stack.run().success);
    }

    #[test]
    fn test_multiply() {
        test_multiply_aux(0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFE, 0x0000_0001);
        test_multiply_aux(0x0, 0xFFFF_FFFF, 0, 0);
        test_multiply_aux(0xFFFF_FFFF, 0x1, 0x0, 0xFFFF_FFFF);
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
        stack.equals(result, true, expected, true);
        stack.op_true();
        assert!(stack.run().success);
    }

    #[test]
    fn test_mask() {
        test_mask_helper(0x1234_5678, 0x0000_0011, 0x0000_0078);
        test_mask_helper(0x1234_5678, 0x0000_1100, 0x0000_5600);
        test_mask_helper(0x1234_5678, 0x0011_0000, 0x0034_0000);
        test_mask_helper(0x1234_5678, 0x1100_0000, 0x1200_0000);
        test_mask_helper(0x1234_5678, 0x1100_0011, 0x1200_0078);
    }

    fn test_shift_case(value: u32, shift: u32, right: bool, msb: bool, expected: u32) {
        let mut stack = StackTracker::new();
        let to_shift = stack.number(shift);
        let number = stack.number_u32(value);
        let shifted = shift_number(&mut stack, to_shift, number, right, msb);
        println!("Size:  {} ", stack.get_script().len());
        let expected = stack.number_u32(expected);
        stack.equals(shifted, true, expected, true);
        stack.op_true();
        assert!(stack.run().success);
    }

    #[test]
    fn test_shift_number() {
        test_shift_case(0x7100_0013, 13, true, true, 0x0003_8800);
        test_shift_case(0x7100_0013, 13, true, false, 0x0003_8800);
        test_shift_case(0xF100_0013, 13, true, true, 0xFFFF_8800);
        test_shift_case(0xF100_0013, 13, true, false, 0x0007_8800);
        test_shift_case(0xF100_0013, 13, false, false, 0x0002_6000);
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

    #[test]
    fn test_lower() {
        test_lower_helper(0x0000_0000, 0xffff_ffff, 1, true);
        test_lower_helper(0x0000_0000, 0xffff_ffff, 0, false);
        test_lower_helper(0xf000_0000, 0xffff_ffff, 1, false);
        test_lower_helper(0x0000_0000, 0xffff_f800, 0, false);
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
    }

    fn test_address_not_in_sections_aux(address: u32, sections: &SectionDefinition) -> bool {
        let mut stack = StackTracker::new();

        let address = stack.number_u32(address);

        address_not_in_sections(&mut stack, &address, sections);

        stack.op_verify();
        stack.drop(address);
        stack.op_true();
        stack.run().success
    }

    #[test]
    fn test_address_not_in_sections() {
        const START_1: u32 = 0x0000_00f0;
        const START_2: u32 = 0x000f_00f0;
        const END_1: u32 = 0x0000_f003;
        const END_2: u32 = 0x000f_f003;

        let sections = &SectionDefinition {
            ranges: vec![(START_1, END_1), (START_2, END_2)],
        };

        assert!(!test_address_not_in_sections_aux(START_1, sections));
        assert!(!test_address_not_in_sections_aux(0x0000_0f00, sections));
        assert!(!test_address_not_in_sections_aux(END_1 - 3, sections));
        assert!(!test_address_not_in_sections_aux(START_2, sections));
        assert!(!test_address_not_in_sections_aux(0x000f_0f00, sections));
        assert!(!test_address_not_in_sections_aux(END_2 - 3, sections));

        assert!(test_address_not_in_sections_aux(START_1 - 1, sections));
        assert!(test_address_not_in_sections_aux(END_1 - 2, sections));
        assert!(test_address_not_in_sections_aux(START_2 - 1, sections));
        assert!(test_address_not_in_sections_aux(END_2 - 2, sections));
    }

    #[test]
    fn test_nibbles_to_number() {
        let mut stack = StackTracker::new();

        let expected = stack.number(0x1234_5678);
        let n = stack.number_u32(0x1234_5678);
        let nibbles = stack.explode(n);
        let result = nibbles_to_number(&mut stack, nibbles);
        stack.equals(expected, true, result, true);
        stack.op_true();
        assert!(stack.run().success);
    }
}
