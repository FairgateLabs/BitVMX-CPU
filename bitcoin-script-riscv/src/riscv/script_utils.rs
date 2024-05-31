use bitcoin_script_stack::stack::{StackTracker, StackVariable};

pub use bitcoin_script::{define_pushable, script};
define_pushable!();
pub use bitcoin::ScriptBuf as Script;

pub fn if_greater(stack: &mut StackTracker, than: u8, then: u8, else_: u8) -> StackVariable {
    stack.custom(script!{
        { than } 
        OP_GREATERTHAN
        OP_IF
            { then }
        OP_ELSE
            { else_} 
        OP_ENDIF
    }, 1, true, 0, &format!("(x>{})?{}:{}",than, then, else_)).unwrap()
}

pub fn move_and_drop(stack: &mut StackTracker, var: StackVariable) {
    stack.move_var(var);
    stack.drop(var);
}

pub fn number_u32_partial(stack: &mut StackTracker, number: u32, nibbles: u8) -> StackVariable {
    assert!(nibbles < 8);
    let mut ret = Vec::new();
    for i in 0..nibbles {
        ret.push(stack.number((number >> ((7-i) * 4)) & 0xF ));
    }
    stack.rename(ret[0], &format!("number_0x{:08x}[0:{}]", number, nibbles));
    if nibbles > 1 {
        stack.join_count(&mut ret[0], (nibbles - 1) as u32)
    } else {
        ret[0]
    }
}

pub fn quotient_table(stack: &mut StackTracker) -> StackVariable {
    let mut table = stack.number(1);
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
    stack.join_count(&mut table, 31)
}  

pub fn modulo_table(stack: &mut StackTracker) -> StackVariable {
    let mut modulo = Vec::new();
    for i in (0..32).rev() {
        modulo.push(stack.number(i % 16));
    }
    stack.rename(modulo[0], "modulo_table");
    stack.join_count(&mut modulo[0], 31)
}  

pub fn rshift_table(stack: &mut StackTracker, n: u8) -> StackVariable {
    let mut parts = Vec::new();
    for i in (0..16).rev() {
        parts.push(stack.number(i >> n));
    }
    stack.rename(parts[0], &format!("shiftr_{}", n));
    stack.join_count(&mut parts[0], 15)
}

pub fn lshift_table(stack: &mut StackTracker, n: u8) -> StackVariable {
    let mut parts = Vec::new();
    for i in (0..16).rev() {
        parts.push(stack.number((i << n) & 0xF));
    }
    stack.rename(parts[0], &format!("shiftl_{}", n));
    stack.join_count(&mut parts[0], 15)
}

pub fn drop_if(stack: &mut StackTracker, var: &StackVariable) {
    if !var.is_null() { 
        stack.drop(*var);
    }
}

pub struct StackShiftTables {
    pub shift_1: StackVariable,
    pub shift_2: StackVariable,
    pub shift_3: StackVariable,
}

impl StackShiftTables {
    pub fn new(stack: &mut StackTracker, mask: u8, left: bool) -> StackShiftTables {
        StackShiftTables {
            shift_1: if mask & 1 == 1 { if left { lshift_table(stack, 1) } else { rshift_table(stack, 1)} } else { StackVariable::null() },
            shift_2: if mask & 2 == 2 { if left { lshift_table(stack, 2) } else { rshift_table(stack, 2)} } else { StackVariable::null() },
            shift_3: if mask & 4 == 4 { if left { lshift_table(stack, 3) } else { rshift_table(stack, 3)} } else { StackVariable::null() },
        }
    }

    pub fn drop(&self, stack: &mut StackTracker) {
        drop_if(stack, &self.shift_3); 
        drop_if(stack, &self.shift_2); 
        drop_if(stack, &self.shift_1); 
    }
}


pub struct StackTables {
    pub modulo: StackVariable,
    pub quotient: StackVariable,
    pub rshift: StackShiftTables,
    pub lshift: StackShiftTables,
}

impl StackTables {
    pub fn new(stack: &mut StackTracker, modulo: bool, quotient: bool, rshift: u8, lshift: u8) -> StackTables {
        StackTables {
            modulo: if modulo { modulo_table(stack)} else { StackVariable::null() },
            quotient: if quotient { quotient_table(stack) } else {StackVariable::null()},
            rshift: StackShiftTables::new(stack, rshift, false), 
            lshift:  StackShiftTables::new(stack, lshift, true),
        }
    }

    pub fn drop(&self, stack: &mut StackTracker) {
        self.lshift.drop(stack);
        self.rshift.drop(stack);
        drop_if(stack, &self.quotient); 
        drop_if(stack, &self.modulo); 
    }
}
