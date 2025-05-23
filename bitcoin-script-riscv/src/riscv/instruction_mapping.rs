use std::collections::HashMap;

use crate::riscv::instructions::*;
pub use bitcoin::ScriptBuf as Script;
use riscv_decode::{
    types::*,
    Instruction::{self, *},
};

use super::{
    instructions::ProgramSpec,
    trace::{STraceRead, STraceStep},
};
use bitcoin_script_stack::stack::StackTracker;

pub trait RdZero {
    fn is_rd_zero(&self) -> bool;
}

impl RdZero for UType {
    fn is_rd_zero(&self) -> bool {
        self.rd() == 0
    }
}

impl RdZero for IType {
    fn is_rd_zero(&self) -> bool {
        self.rd() == 0
    }
}

impl RdZero for RType {
    fn is_rd_zero(&self) -> bool {
        self.rd() == 0
    }
}

impl RdZero for ShiftType {
    fn is_rd_zero(&self) -> bool {
        self.rd() == 0
    }
}

fn name_or_nop<X: RdZero>(x: &X, name: &str) -> String {
    if x.is_rd_zero() {
        "nop".to_string()
    } else {
        name.to_string()
    }
}

pub fn requires_witness(instruction: &Instruction) -> bool {
    match instruction {
        Div(_) | Divu(_) | Rem(_) | Remu(_) => true,
        _ => false,
    }
}

pub fn get_key_from_instruction_and_micro(instruction: &Instruction, micro: u8) -> String {
    match instruction {
        Beq(_) => "beq".to_string(),
        Bne(_) => "bne".to_string(),
        Blt(_) => "blt".to_string(),
        Bge(_) => "bge".to_string(),
        Bltu(_) => "bltu".to_string(),
        Bgeu(_) => "bgeu".to_string(),

        Lh(_) => format!("lh_{}", micro),
        Lhu(_) => format!("lhu_{}", micro),
        Lw(_) => format!("lhw_{}", micro),
        Lb(_) => format!("lb_{}", micro),
        Lbu(_) => format!("lbu_{}", micro),

        Sb(_) => format!("sb_{}", micro),
        Sh(_) => format!("sh_{}", micro),
        Sw(_) => format!("sw_{}", micro),

        Jalr(_) => "jalr".to_string(),
        Jal(_) => "jal".to_string(),

        Slli(x) => name_or_nop(x, "slli"),
        Srli(x) => name_or_nop(x, "srli"),
        Srai(x) => name_or_nop(x, "srai"),

        Xori(x) => name_or_nop(x, "xori"),
        Andi(x) => name_or_nop(x, "andi"),
        Ori(x) => name_or_nop(x, "ori"),
        Slti(x) => name_or_nop(x, "slti"),
        Sltiu(x) => name_or_nop(x, "sltiu"),
        Addi(x) => name_or_nop(x, "addi"),

        Mul(x) => name_or_nop(x, "mul"),
        Mulh(x) => name_or_nop(x, "mulh"),
        Mulhsu(x) => name_or_nop(x, "mulhsu"),
        Mulhu(x) => name_or_nop(x, "mulhu"),
        Div(x) => name_or_nop(x, "div"),
        Divu(x) => name_or_nop(x, "divu"),
        Rem(x) => name_or_nop(x, "rem"),
        Remu(x) => name_or_nop(x, "remu"),

        Xor(x) => name_or_nop(x, "xor"),
        And(x) => name_or_nop(x, "and"),
        Or(x) => name_or_nop(x, "or"),
        Slt(x) => name_or_nop(x, "slt"),
        Sltu(x) => name_or_nop(x, "sltu"),
        Sll(x) => name_or_nop(x, "sll"),
        Srl(x) => name_or_nop(x, "srl"),
        Sra(x) => name_or_nop(x, "sra"),
        Add(x) => name_or_nop(x, "add"),
        Sub(x) => name_or_nop(x, "sub"),

        Lui(x) => name_or_nop(x, "lui"),
        Auipc(x) => name_or_nop(x, "auipc"),

        Fence(_) => "nop".to_string(),
        Ecall => "ecall".to_string(),
        Ebreak => "nop".to_string(),

        _ => panic!("Instruction not supported {:?}", instruction),
    }
}

pub fn get_key_from_opcode(opcode: u32, micro: u8) -> Option<String> {
    let instruction = riscv_decode::decode(opcode);
    match instruction {
        Ok(instruction) => Some(get_key_from_instruction_and_micro(&instruction, micro)),
        Err(_) => None,
    }
}

pub fn get_required_microinstruction(instruction: &Instruction) -> u8 {
    match instruction {
        Lh(_) => 4,
        Lhu(_) => 4,
        Lw(_) => 4,
        Sb(_) => 4,
        Sh(_) => 8,
        Sw(_) => 8,
        _ => 1,
    }
}

pub fn generate_sample_instructions() -> Vec<(Instruction, u8)> {
    let mut sample = vec![
        (Add(RType(179)), 0),
        (Addi(IType(1299)), 0),
        (And(RType(28851)), 0),
        (Andi(IType(251687059)), 0),
        (Auipc(UType(268435735)), 0),
        (Beq(BType(2659)), 0),
        (Bge(BType(55907)), 0),
        (Bgeu(BType(64099)), 0),
        (Blt(BType(1067619)), 0),
        (Bltu(BType(1075811)), 0),
        (Bne(BType(36704355)), 0),
        (Lui(UType(16711863)), 0),
        (Jal(JType(16777839)), 0),
        (Jalr(IType(198375)), 0),
        (Mul(RType(33554611)), 0),
        (Mulh(RType(33591603)), 0),
        (Mulhsu(RType(33562803)), 0),
        (Mulhu(RType(33566899)), 0),
        (Divu(RType(46520115)), 0),
        (Remu(RType(46528307)), 0),
        (Div(RType(46516019)), 0),
        (Rem(RType(46524211)), 0),
        (Or(RType(24755)), 0),
        (Ori(IType(251682963)), 0),
        (Sll(RType(4275)), 0),
        (Slli(ShiftType(32510099)), 0),
        (Slt(RType(8371)), 0),
        (Slti(IType(4293927059)), 0),
        (Sltiu(IType(4293931155)), 0),
        (Sltu(RType(12467)), 0),
        (Sra(RType(1073762483)), 0),
        (Srai(ShiftType(1077956755)), 0),
        (Srl(RType(20659)), 0),
        (Srli(ShiftType(4214931)), 0),
        (Sub(RType(1073742003)), 0),
        (Xor(RType(16563)), 0),
        (Xori(IType(251674771)), 0),
        (Fence(FenceType(267386895)), 0), //as nop representative
        (Ecall, 0),
        (Lb(IType(5310211)), 0), //lb is just one
        (Lbu(IType(67390979)), 0),
    ];

    for i in 0..8 {
        sample.push((Sh(SType(10851107)), i));
        sample.push((Sw(SType(1124899)), i));
    }

    for i in 0..4 {
        sample.push((Sb(SType(10846627)), i));

        sample.push((Lh(IType(10557187)), i));
        sample.push((Lhu(IType(66346499)), i));
        sample.push((Lw(IType(21047043)), i));
    }

    sample
}

pub fn generate_verification_script(
    instruction: &Instruction,
    micro: u8,
    base_register_address: u32,
    witness: bool,
) -> Script {
    let mut stack = StackTracker::new();
    let program = ProgramSpec::new(base_register_address);
    let trace_step = STraceStep::define(&mut stack);
    let witness = match witness {
        true => Some(stack.define(8, "witness")),
        false => None,
    };

    let trace_read = STraceRead::define(&mut stack);
    let mut result = execute_step(
        &mut stack,
        &trace_read,
        &trace_step,
        witness,
        &instruction,
        micro,
        program,
    )
    .unwrap();
    compare_trace_step(&mut stack, &trace_step, &mut result);
    stack.get_script()
}

pub type InstructionMapping = HashMap<String, (Script, bool)>;

pub fn create_verification_script_mapping(base_register_address: u32) -> InstructionMapping {
    let sample = generate_sample_instructions();
    let mut mapping = HashMap::new();
    for (instruction, micro) in sample {
        let key = get_key_from_instruction_and_micro(&instruction, micro);
        let requires_witness = requires_witness(&instruction);
        let script = generate_verification_script(
            &instruction,
            micro,
            base_register_address,
            requires_witness,
        );
        mapping.insert(key, (script, requires_witness));
    }
    mapping
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_get_key_from_instruction_and_micro() {
        let sample = generate_sample_instructions();
        let size = sample.len();
        for (instruction, micro) in sample {
            let key = get_key_from_instruction_and_micro(&instruction, micro);
            const REGISTERS_BASE_ADDRESS: u32 = 0xF000_0000;
            println!(
                "Instruction: {:?}, Micro: {}, Key: {},",
                instruction, micro, key
            );
            let script = generate_verification_script(
                &instruction,
                micro,
                REGISTERS_BASE_ADDRESS,
                requires_witness(&instruction),
            );
            println!(
                "Instruction: {:?}, Micro: {}, Key: {}, Size: {}",
                instruction,
                micro,
                key,
                script.len()
            );
        }
        println!("Total instructions: {}", size);
    }
}
