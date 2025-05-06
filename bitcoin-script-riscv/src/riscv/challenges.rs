use bitcoin_script_functions::hash::blake3;
use bitcoin_script_stack::stack::StackTracker;
use bitvmx_cpu_definitions::{
    challenge::ChallengeType,
    constants::LAST_STEP_INIT,
    trace::{generate_initial_step_hash, hashvec_to_string},
};

use crate::riscv::{
    memory_alignment::is_aligned,
    script_utils::is_lower_than,
};

// TODO: Value commited in WOTS_PROVER_LAST_STEP should not be greater than the MAX_STEP_CONSTANT_VALUE
// the script should block this.

// TOOD: As the graph is presigned completely by both parts. The transaction always need something secret that can only be signed by the responsible part.
// is important if the other changes it. Probably in several transaction this is not a problem as the destination tx is the same. But in the case where choosing one leaf can lead to another part of the DAG
// then it's mandatory

// TODO: Implement multi value challange, using base address - address to pick value

// One input value equivocation challenge
// [WOTS_INPUT_DATA[address]|WOTS_PROVER_READ_ADD_1|WOTS_PROVER_READ_VALUE_1|WOTS_PROVER_LAST_STEP_1|WOTS_PROVER_READ_ADD_2|WOTS_PROVER_READ_VALUE_2|WOTS_PROVER_LAST_STEP_2]
// If STEP_1 == INIT && ADD_1 == const_address && VALUE_1 != [WOTS_INPUT_DATA[address] || STEP_2 == INIT && ADD_2 == const_address && VALUE_2 != [WOTS_INPUT_DATA[address]  => verifier wins
pub fn input_challenge(stack: &mut StackTracker, address: u32) {
    assert_ne!(address, 0x0000_0000);
    stack.clear_definitions();

    let input = stack.define(8, "prover_input");

    let add_1 = stack.define(8, "prover_read_add_1");
    let read_1 = stack.define(8, "prover_read_value_1");
    let prover_step_1 = stack.define(16, "prover_last_step_1");

    let add_2 = stack.define(8, "prover_read_add_2");
    let read_2 = stack.define(8, "prover_read_value_2");
    let prover_step_2 = stack.define(16, "prover_last_step_2");

    //compares agaisnt read_2
    let init = stack.number_u64(LAST_STEP_INIT);
    stack.equality(prover_step_2, true, init, true, true, false);
    stack.equality(read_2, true, input, false, false, false);
    let const_address = stack.number_u32(address);
    stack.equality(add_2, true, const_address, true, true, false);
    stack.op_booland();
    stack.op_booland();

    //compares agaisnt read_1
    let init = stack.number_u64(LAST_STEP_INIT);
    stack.equality(prover_step_1, true, init, true, true, false);
    stack.equality(read_1, true, input, true, false, false);
    let const_address = stack.number_u32(address);
    stack.equality(add_1, true, const_address, true, true, false);

    stack.op_booland();
    stack.op_booland();

    //one of the two needs to be right
    stack.op_boolor();
    stack.op_verify();
}

// One rom value equivocation challenge
// [WOTS_PROVER_READ_ADD_1|WOTS_PROVER_READ_VALUE_1|WOTS_PROVER_LAST_STEP_1|WOTS_PROVER_READ_ADD_2|WOTS_PROVER_READ_VALUE_2|WOTS_PROVER_LAST_STEP_2]
// If STEP_1 == INIT && ADD_1 == const_address && VALUE_1 != const_value || STEP_2 == INIT && ADD_2 == const_address && VALUE_2 != const_value  => verifier wins
pub fn rom_challenge(stack: &mut StackTracker, address: u32, value: u32) {
    assert_ne!(address, 0x0000_0000);
    stack.clear_definitions();
    let add_1 = stack.define(8, "prover_read_add_1");
    let read_1 = stack.define(8, "prover_read_value_1");
    let prover_step_1 = stack.define(16, "prover_last_step_1");

    let add_2 = stack.define(8, "prover_read_add_2");
    let read_2 = stack.define(8, "prover_read_value_2");
    let prover_step_2 = stack.define(16, "prover_last_step_2");

    //compares agaisnt read_2
    let init = stack.number_u64(LAST_STEP_INIT);
    stack.equality(prover_step_2, true, init, true, true, false);
    let const_value = stack.number_u32(value);
    stack.equality(read_2, true, const_value, true, false, false);
    let const_address = stack.number_u32(address);
    stack.equality(add_2, true, const_address, true, true, false);
    stack.op_booland();
    stack.op_booland();

    //compares agaisnt read_1
    let init = stack.number_u64(LAST_STEP_INIT);
    stack.equality(prover_step_1, true, init, true, true, false);
    let const_value = stack.number_u32(value);
    stack.equality(read_1, true, const_value, true, false, false);
    let const_address = stack.number_u32(address);
    stack.equality(add_1, true, const_address, true, true, false);

    stack.op_booland();
    stack.op_booland();

    //one of the two needs to be right
    stack.op_boolor();
    stack.op_verify();
}

// If the prover executes step = 1 and entry_point != valid entry point
// the verifier can execute this equivocation and win the challenge
// [WOTS_PROVER_TRACE_PC:8 | WOTS_PROVER_TRACE_MICRO:2 | WOTS_PROVER_TRACE_STEP:16]
pub fn entry_point_challenge(stack: &mut StackTracker, entry_point: u32) {
    stack.clear_definitions();
    let provided_pc = stack.define(8, "provided_pc");
    let _provided_micro = stack.define(2, "provided_micro");
    let provided_step = stack.define(16, "provided_step");

    let step_high = stack.number_u64(1);
    stack.equals(provided_step, true, step_high, true);

    let real = stack.number_u32(entry_point);
    let _micro = stack.byte(0);
    stack.join(real);
    stack.join(provided_pc);

    stack.not_equal(provided_pc, true, real, true);
}

// If the prover reveals a [program counter|micro] that is not the same that was written in the previous step
// the verifier can challenge it.
// As both agrees on the previous step hash and the [PC|micro] is included in that hash, the verifier is able to win the challenge if he can execute this equivocation:
// NOTE: the verifiers provides an step back of the agreed step.
// hash_funcion ( UNSIGNED_VERIFIER_HASH_PREV_PREV_STEP:64 | UNSIGINED_VERIFIER_WRITE_ADD_PREV:8 | UNSIGINED_VERIFIER_WRITE_DATA_PREV:8 | UNSIGNED_VERIFIER_WRITE_PC_PREV:8 | UNSIGNED_VERIFIER_WRITE_MICRO_PREV:2 ) == WOTS_PROVER_HASH_PREV_STEP:64
// && WOTS_PROVER_TRACE_READ_PC:8 | WOTS_PROVER_TRACE_READ_MICRO:2 != UNSIGNED_VERIFIER_WRITE_PC_PREV | UNSIGNED_VERIFIER_WRITE_MICRO_PREV
pub fn program_counter_challenge(stack: &mut StackTracker) {
    stack.clear_definitions();

    // verifier values (unsigned)
    let prev_prev_hash = stack.define(40, "prev_prev_hash");
    let prev_write_add = stack.define(8, "prev_write_add");
    let prev_write_data = stack.define(8, "prev_write_data");
    let prev_write_pc = stack.define(8, "prev_write_pc");
    let prev_write_micro = stack.define(2, "prev_write_micro");

    // santize the stack
    stack.verify_range_var_u4(prev_prev_hash);
    stack.verify_range_var_u4(prev_write_add);
    stack.verify_range_var_u4(prev_write_data);
    stack.verify_range_var_u4(prev_write_pc);
    stack.verify_range_var_u4(prev_write_micro);

    // prover values decoded from WOTS
    let prover_pc = stack.define(8, "prover_read_pc");
    let _prover_micro = stack.define(2, "prover_read_micro");
    let prover_prev_hash = stack.define(40, "prover_prev_hash");

    //save the hash to compare
    stack.to_altstack();

    stack.join(prover_pc); //joins the prover_pc with the prover micro

    // copies the values provided to assure that are not equal with the prover values
    let copy_prev_write_pc = stack.copy_var(prev_write_pc);
    let _copy_prev_write_micro = stack.copy_var(prev_write_micro);
    stack.join(copy_prev_write_pc);

    // asserts the inequality of the real values with the ones provided by the prover
    stack.not_equal(prover_pc, true, copy_prev_write_pc, true);

    stack.explode(prev_prev_hash);
    stack.explode(prev_write_add);
    stack.explode(prev_write_data);
    stack.explode(prev_write_pc);
    stack.explode(prev_write_micro);

    let result = blake3::blake3(stack, (40 + 8 + 8 + 8 + 2) / 2, 5);
    stack.from_altstack();
    stack.equals(result, true, prover_prev_hash, true);
}

// When the prover commits the final step as halt but it's is not a halt-success instruction the verifier can challenge it.
// TODO CHECK: The opcode needs to be provided and compared with the static opcode given by the PC on the proper leaf when expanding the trace
// WOTS_PROVER_FINAL_STEP:16 == WOTS_PROVER_TRACE_STEP:16 && ( WOTS_PROVER_READ_VALUE_1:8 | WOTS_PROVER_READ_VALUE_2:8 | WOTS_PROVER_OPCODE:8 !=  93 | 0 | 115 )
pub fn halt_challenge(stack: &mut StackTracker) {
    stack.clear_definitions();
    let final_step = stack.define(16, "final_step");
    let trace_step = stack.define(16, "trace_step");
    let provided = stack.define(8, "read_value_1");
    stack.define(8, "read_value_2");
    stack.define(8, "opcode");

    stack.join_count(provided, 2);

    let expected = stack.number_u32(93);
    stack.number_u32(0);
    stack.number_u32(115);
    stack.join_count(expected, 2);

    stack.not_equal(provided, true, expected, true);

    stack.equals(final_step, true, trace_step, true);
}

// When the prover expands the trace it could happen that  HASH( hash_prev_step | trace_write ) != hash_step
// in that case the verifier can win the challenge executing:
//  hash_funcion ( WOTS_PROVER_HASH_STEP_PREV:64 | WOTS_PROVER_WRITE_ADD:8 | WOTS_PROVER_WRITE_DATA:8 | WOTS_PROVER_WRITE_PC:8 | WOTS_PROVER_WRITE_MICRO:2 ) != WOTS_PROVER_HASH:64
pub fn trace_hash_challenge(stack: &mut StackTracker) {
    stack.clear_definitions();

    let prev_hash = stack.define(40, "prev_hash");
    let write_add = stack.define(8, "write_add");
    let write_data = stack.define(8, "write_data");
    let write_pc = stack.define(8, "write_pc");
    let write_micro = stack.define(2, "write_micro");

    let hash = stack.define(40, "hash");

    //save the hash to compare
    stack.to_altstack();

    stack.explode(prev_hash);
    stack.explode(write_add);
    stack.explode(write_data);
    stack.explode(write_pc);
    stack.explode(write_micro);

    let result = blake3::blake3(stack, (40 + 8 + 8 + 8 + 2) / 2, 5);
    stack.from_altstack();
    stack.not_equal(result, true, hash, true);
}

pub fn trace_hash_zero_challenge(stack: &mut StackTracker) {
    stack.clear_definitions();

    let write_add = stack.define(8, "write_add");
    let write_data = stack.define(8, "write_data");
    let write_pc = stack.define(8, "write_pc");
    let write_micro = stack.define(2, "write_micro");

    let hash = stack.define(40, "hash");

    //save the hash to compare
    stack.to_altstack();

    //save the trace steps
    stack.to_altstack();
    stack.to_altstack();
    stack.to_altstack();
    stack.to_altstack();

    //hardcoded the initial hash
    let prev_hash = stack.hexstr_as_nibbles(&hashvec_to_string(generate_initial_step_hash()));

    //restore the trace step
    stack.from_altstack();
    stack.from_altstack();
    stack.from_altstack();
    stack.from_altstack();

    stack.explode(prev_hash);
    stack.explode(write_add);
    stack.explode(write_data);
    stack.explode(write_pc);
    stack.explode(write_micro);

    let result = blake3::blake3(stack, (40 + 8 + 8 + 8 + 2) / 2, 5);
    stack.from_altstack();
    stack.not_equal(result, true, hash, true);
}

pub fn address_in_sections_challenge(stack: &mut StackTracker, sections: Vec<(u32, u32)>) {
    assert!(sections.len() > 0);
    stack.clear_definitions();

    let address = stack.define(8, "address");

    is_aligned(stack, address, false);
    stack.op_not();

    for section in &sections {
        let section_start = stack.number_u32(section.0);
        let add = stack.copy_var(address);

        is_lower_than(stack, add, section_start, true);

        // when we do a read on an address, we also read the 3 addresses after
        let section_end = stack.number_u32(section.1 - 3);
        let add = stack.copy_var(address);

        is_lower_than(stack, section_end, add, true);

        stack.op_boolor();
    }

    for _ in 0..sections.len() - 1 {
        stack.op_booland();
    }

    stack.op_boolor();

    stack.op_verify();
    stack.drop(address);
}

//TODO: memory section challenge
//TODO: program crash challenge - this might be more about finding the right place to challenge that a challenge itself

pub fn execute_challenge(challege_type: &ChallengeType) -> bool {
    let mut stack = StackTracker::new();
    match challege_type {
        ChallengeType::TraceHash(pre_hash, trace_step, hash) => {
            stack.hexstr_as_nibbles(pre_hash);
            stack.number_u32(trace_step.get_write().address);
            stack.number_u32(trace_step.get_write().value);
            stack.number_u32(trace_step.get_pc().get_address());
            stack.byte(trace_step.get_pc().get_micro() as u8);
            stack.hexstr_as_nibbles(hash);
            trace_hash_challenge(&mut stack);
        }
        ChallengeType::TraceHashZero(trace_step, hash) => {
            stack.number_u32(trace_step.get_write().address);
            stack.number_u32(trace_step.get_write().value);
            stack.number_u32(trace_step.get_pc().get_address());
            stack.byte(trace_step.get_pc().get_micro() as u8);
            stack.hexstr_as_nibbles(hash);
            trace_hash_zero_challenge(&mut stack);
        }
        ChallengeType::EntryPoint(read_pc, step, real_entry_point) => {
            stack.number_u32(read_pc.pc.get_address());
            stack.byte(read_pc.pc.get_micro() as u8);
            stack.number_u64(*step);
            entry_point_challenge(&mut stack, *real_entry_point);
        }
        ChallengeType::ProgramCounter(pre_pre_hash, pre_step, prover_step_hash, prover_pc_read) => {
            stack.hexstr_as_nibbles(pre_pre_hash);
            stack.number_u32(pre_step.get_write().address);
            stack.number_u32(pre_step.get_write().value);
            stack.number_u32(pre_step.get_pc().get_address());
            stack.byte(pre_step.get_pc().get_micro() as u8);

            stack.number_u32(prover_pc_read.pc.get_address());
            stack.byte(prover_pc_read.pc.get_micro() as u8);

            stack.hexstr_as_nibbles(&prover_step_hash);

            program_counter_challenge(&mut stack);
        }
        ChallengeType::InputData(read_1, read_2, address, input_for_address) => {
            stack.number_u32(*input_for_address); //TODO: this should make input_wots[address]
            stack.number_u32(read_1.address);
            stack.number_u32(read_1.value);
            stack.number_u64(read_1.last_step);
            stack.number_u32(read_2.address);
            stack.number_u32(read_2.value);
            stack.number_u64(read_2.last_step);
            input_challenge(&mut stack, *address);
        }
        ChallengeType::AddressInSections(address, sections) => {
            stack.number_u32(*address);
            address_in_sections_challenge(&mut stack, sections.clone());
        }
        _ => {
            return false;
        }
    }
    stack.op_true();
    stack.run().success
}

#[cfg(test)]
mod tests {

    use bitvmx_cpu_definitions::trace::TraceRead;

    use super::*;

    fn test_entry_point_challenge_aux(
        wots_prover_pc: u32,
        wots_prover_micro: u8,
        wots_step: u64,
        entry_point_real: u32,
    ) -> bool {
        let mut stack = StackTracker::new();

        //define entrypoint in the stack
        stack.number_u32(wots_prover_pc);
        stack.byte(wots_prover_micro);

        //define step in the stack
        stack.number_u64(wots_step);

        entry_point_challenge(&mut stack, entry_point_real);
        stack.op_true();
        stack.run().success
    }

    #[test]
    fn test_entry_point_challenge() {
        assert!(test_entry_point_challenge_aux(0x1234, 0, 1, 0x2222));
        assert!(test_entry_point_challenge_aux(0x2222, 1, 1, 0x2222));
        assert!(!test_entry_point_challenge_aux(0x1234, 0, 1, 0x1234));
        assert!(!test_entry_point_challenge_aux(0x1234, 0, 2, 0x2222));
    }

    fn test_program_counter_challenge_aux(
        pre_pre_hash: &str,
        write_add: u32,
        write_value: u32,
        pc: u32,
        micro: u8,
        prover_pc: u32,
        prover_micro: u8,
        pre_hash: &str,
    ) -> bool {
        let mut stack = StackTracker::new();

        stack.hexstr_as_nibbles(pre_pre_hash);
        stack.number_u32(write_add);
        stack.number_u32(write_value);
        stack.number_u32(pc);
        stack.byte(micro);

        stack.number_u32(prover_pc);
        stack.byte(prover_micro);

        stack.hexstr_as_nibbles(pre_hash);

        program_counter_challenge(&mut stack);

        stack.op_true();
        stack.run().success
    }

    #[test]
    fn test_program_counter_challenge() {
        //verifier provides valid trace that matches the hash and prover provided invalid pc
        let pre_pre_hash = "e2f115006467b4b1b2b27612bbfd40ed3bc8299b";
        let pre_hash = "345721506e79c53d2549fc63d02ba8fc3b17efa4";
        assert!(test_program_counter_challenge_aux(
            pre_pre_hash,
            0xf0000028,
            0x00000001,
            0x8000010c,
            0x00,
            0x80000100,
            0x00,
            pre_hash
        ));

        //verifier provides valid trace that matches the hash but the prover provided valid pc
        assert!(!test_program_counter_challenge_aux(
            pre_pre_hash,
            0xf0000028,
            0x00000001,
            0x8000010c,
            0x00,
            0x8000010c,
            0x00,
            pre_hash
        ));

        //verifier provides invalid trace that does not match the hash
        assert!(!test_program_counter_challenge_aux(
            pre_pre_hash,
            0xf0000028,
            0x00000001,
            0x80000100,
            0x00,
            0x8000010c,
            0x00,
            pre_hash
        ));
    }

    fn test_halt_challenge_aux(
        final_step: u64,
        trace_step: u64,
        read_value_1: u32,
        read_value_2: u32,
        opcode: u32,
    ) -> bool {
        let mut stack = StackTracker::new();

        stack.number_u64(final_step);
        stack.number_u64(trace_step);
        stack.number_u32(read_value_1);
        stack.number_u32(read_value_2);
        stack.number_u32(opcode);

        halt_challenge(&mut stack);
        stack.op_true();
        stack.run().success
    }

    #[test]
    fn test_halt_challenge() {
        assert!(test_halt_challenge_aux(0x0, 0x0, 93, 1, 115));
        assert!(test_halt_challenge_aux(0x0, 0x0, 92, 0, 115));
        assert!(test_halt_challenge_aux(0x0, 0x0, 93, 0, 114));
        assert!(!test_halt_challenge_aux(0x0, 0x0, 93, 0, 115));
        assert!(!test_halt_challenge_aux(0x0, 0x1, 93, 0, 114));
    }

    fn test_trace_hash_zero_aux(
        write_add: u32,
        write_value: u32,
        pc: u32,
        micro: u8,
        hash: &str,
    ) -> bool {
        let mut stack = StackTracker::new();

        stack.number_u32(write_add);
        stack.number_u32(write_value);
        stack.number_u32(pc);
        stack.byte(micro);

        stack.hexstr_as_nibbles(hash);

        trace_hash_zero_challenge(&mut stack);

        stack.op_true();
        stack.run().success
    }

    #[test]
    fn test_trace_hash_zero() {
        let hash = "3ebf30cdfd74fa9635abb08f13bb0d09bb6ae403";

        //prover provided valid hash, verifier loses
        assert!(!test_trace_hash_zero_aux(
            0xf0000028, 0x00000000, 0x80000100, 0x00, hash
        ));

        //prover provided invalid hash, verifier wins
        assert!(test_trace_hash_zero_aux(
            0xf0000028, 0x00000000, 0x80000100, 0x01, hash
        ));
    }

    fn test_trace_hash_aux(
        pre_hash: &str,
        write_add: u32,
        write_value: u32,
        pc: u32,
        micro: u8,
        hash: &str,
    ) -> bool {
        let mut stack = StackTracker::new();

        stack.hexstr_as_nibbles(pre_hash);
        stack.number_u32(write_add);
        stack.number_u32(write_value);
        stack.number_u32(pc);
        stack.byte(micro);

        stack.hexstr_as_nibbles(hash);

        trace_hash_challenge(&mut stack);

        stack.op_true();
        stack.run().success
    }

    #[test]
    fn test_trace_hash() {
        let pre_hash = "e2f115006467b4b1b2b27612bbfd40ed3bc8299b";
        let hash = "345721506e79c53d2549fc63d02ba8fc3b17efa4";

        //prover provided valid hash, verifier loses
        assert!(!test_trace_hash_aux(
            pre_hash, 0xf0000028, 0x00000001, 0x8000010c, 0x00, hash
        ));

        //prover provided invalid hash, verifier wins
        assert!(test_trace_hash_aux(
            pre_hash, 0xf0000028, 0x00000001, 0x8000010c, 0x01, hash
        ));
    }

    #[test]
    fn test_padding_hash() {
        let pre_hash = "006942ae363a1a52823aa28eebe597d32b9d92e9";
        let hash = "3e87b9ecc502799716c371d74afeefb830191400";

        assert!(!test_trace_hash_aux(
            pre_hash, 0xf0000038, 0x0000001e, 0x80000060, 0x00, hash
        ));

        let pre_hash = "3e87b9ecc502799716c371d74afeefb830191400";
        let hash = "b26883b2c7c5582cecc3394a2071725470048264";

        assert!(!test_trace_hash_aux(
            pre_hash, 0xf000003c, 0x0000003f, 0x80000064, 0x00, hash
        ));
    }

    fn test_rom_aux(read_1: &TraceRead, read_2: &TraceRead, rom_add: u32, rom_value: u32) -> bool {
        let mut stack = StackTracker::new();

        stack.number_u32(read_1.address);
        stack.number_u32(read_1.value);
        stack.number_u64(read_1.last_step);
        stack.number_u32(read_2.address);
        stack.number_u32(read_2.value);
        stack.number_u64(read_2.last_step);

        rom_challenge(&mut stack, rom_add, rom_value);

        stack.op_true();
        stack.run().success
    }

    #[test]
    fn test_rom() {
        //can't challenge not init state
        let read_1 = TraceRead::new(0x0000_0002, 0x1234_5678, 1);
        let read_2 = TraceRead::new(0x0000_0002, 0x1234_5678, 2);
        assert!(!test_rom_aux(&read_1, &read_2, 0x0000_0002, 0x0000_0000));

        //can't challenge if value is right
        let read_1 = TraceRead::new(0x0000_0002, 0x1234_5678, LAST_STEP_INIT);
        let read_2 = TraceRead::new(0x0000_0002, 0x1234_5678, LAST_STEP_INIT);
        assert!(!test_rom_aux(&read_1, &read_2, 0x0000_0002, 0x1234_5678));

        //can't challenge if address is different
        let read_1 = TraceRead::new(0x0000_0002, 0x1234_5678, LAST_STEP_INIT);
        let read_2 = TraceRead::new(0x0000_0002, 0x1234_5678, LAST_STEP_INIT);
        assert!(!test_rom_aux(&read_1, &read_2, 0x0000_0003, 0x1234_0000));

        //challenge is valid if the address is the same but the value differs in both
        let read_1 = TraceRead::new(0x0000_0002, 0x1234_5678, LAST_STEP_INIT);
        let read_2 = TraceRead::new(0x0000_0002, 0x1234_5678, LAST_STEP_INIT);
        assert!(test_rom_aux(&read_1, &read_2, 0x0000_0002, 0x1234_0000));

        //challenge is valid if the address is the same but the value differs in read_1
        let read_1 = TraceRead::new(0x0000_0002, 0x1234_5678, LAST_STEP_INIT);
        let read_2 = TraceRead::new(0x0000_0005, 0x1234_0000, LAST_STEP_INIT);
        assert!(test_rom_aux(&read_1, &read_2, 0x0000_0002, 0x1234_0000));

        //challenge is valid if the address is the same but the value differs in read_2
        let read_1 = TraceRead::new(0x0000_0005, 0x1234_0000, LAST_STEP_INIT);
        let read_2 = TraceRead::new(0x0000_0002, 0x1234_5678, LAST_STEP_INIT);
        assert!(test_rom_aux(&read_1, &read_2, 0x0000_0002, 0x1234_0000));
    }

    fn test_input_aux(
        read_1: &TraceRead,
        read_2: &TraceRead,
        address: u32,
        input_for_address: u32,
    ) -> bool {
        let mut stack = StackTracker::new();

        stack.number_u32(input_for_address);
        stack.number_u32(read_1.address);
        stack.number_u32(read_1.value);
        stack.number_u64(read_1.last_step);
        stack.number_u32(read_2.address);
        stack.number_u32(read_2.value);
        stack.number_u64(read_2.last_step);

        input_challenge(&mut stack, address);

        stack.op_true();
        stack.run().success
    }

    #[test]
    fn test_input() {
        //can't challenge not init state
        let read_1 = TraceRead::new(0x0000_0002, 0x1234_5678, 1);
        let read_2 = TraceRead::new(0x0000_0002, 0x1234_5678, 2);
        assert!(!test_input_aux(&read_1, &read_2, 0x0000_0002, 0x0000_0000));

        //can't challenge if value is right
        let read_1 = TraceRead::new(0x0000_0002, 0x1234_5678, LAST_STEP_INIT);
        let read_2 = TraceRead::new(0x0000_0002, 0x1234_5678, LAST_STEP_INIT);
        assert!(!test_input_aux(&read_1, &read_2, 0x0000_0002, 0x1234_5678));

        //can't challenge if address is different
        let read_1 = TraceRead::new(0x0000_0002, 0x1234_5678, LAST_STEP_INIT);
        let read_2 = TraceRead::new(0x0000_0002, 0x1234_5678, LAST_STEP_INIT);
        assert!(!test_input_aux(&read_1, &read_2, 0x0000_0003, 0x1234_0000));

        //challenge is valid if the address is the same but the value differs in both
        let read_1 = TraceRead::new(0x0000_0002, 0x1234_5678, LAST_STEP_INIT);
        let read_2 = TraceRead::new(0x0000_0002, 0x1234_5678, LAST_STEP_INIT);
        assert!(test_input_aux(&read_1, &read_2, 0x0000_0002, 0x1234_0000));

        //challenge is valid if the address is the same but the value differs in read_1
        let read_1 = TraceRead::new(0x0000_0002, 0x1234_5678, LAST_STEP_INIT);
        let read_2 = TraceRead::new(0x0000_0005, 0x1234_0000, LAST_STEP_INIT);
        assert!(test_input_aux(&read_1, &read_2, 0x0000_0002, 0x1234_0000));

        //challenge is valid if the address is the same but the value differs in read_2
        let read_1 = TraceRead::new(0x0000_0005, 0x1234_0000, LAST_STEP_INIT);
        let read_2 = TraceRead::new(0x0000_0002, 0x1234_5678, LAST_STEP_INIT);
        assert!(test_input_aux(&read_1, &read_2, 0x0000_0002, 0x1234_0000));
    }

    fn test_address_in_sections_aux(address: u32, sections: Vec<(u32, u32)>) -> bool {
        let mut stack = StackTracker::new();

        stack.number_u32(address);
        address_in_sections_challenge(&mut stack, sections);

        stack.op_true();
        stack.run().success
    }

    #[test]
    fn test_address_in_sections() {
        let sections = vec![(0x0000_00f0, 0x0000_fff3), (0x000f_fff0, 0x0fff_fff3)];

        // can't challenge if address is aligned and equal to the start of the first section
        assert!(!test_address_in_sections_aux(0x0000_00f0, sections.clone()));

        // can't challenge if address is aligned and 3 less than the end of the first section
        assert!(!test_address_in_sections_aux(
            0x0000_fff3 - 3,
            sections.clone()
        ));

        // can't challenge if address is aligned and between start and end of first section
        assert!(!test_address_in_sections_aux(0x0000_0ff0, sections.clone()));

        // can't challenge if address is aligned and equal to the start of the second section
        assert!(!test_address_in_sections_aux(0x000f_fff0, sections.clone()));

        // can't challenge if address is aligned and 3 less than the end of the first section
        assert!(!test_address_in_sections_aux(
            0x0fff_fff3 - 3,
            sections.clone()
        ));

        // can't challenge if address is aligned and between start and end of first section
        assert!(!test_address_in_sections_aux(0x00ff_fff0, sections.clone()));

        // challenges are valid if address is aligned and outside every section
        assert!(test_address_in_sections_aux(0x0000_00f0-4, sections.clone())); // before section 1
        assert!(test_address_in_sections_aux(0x0000_fff4, sections.clone())); // after section 1
        assert!(test_address_in_sections_aux(0x000f_fff0-4, sections.clone())); // before section 2
        assert!(test_address_in_sections_aux(0x0fff_fff4, sections.clone())); // after section 2
        
        // challenges are valid if address it not aligned
        assert!(test_address_in_sections_aux(0x0000_00f1, sections.clone()));
        assert!(test_address_in_sections_aux(0x0000_00f2, sections.clone()));
        assert!(test_address_in_sections_aux(0x0000_00f3, sections.clone()));
        assert!(test_address_in_sections_aux(0x000f_fff1, sections.clone()));
        assert!(test_address_in_sections_aux(0x000f_fff2, sections.clone()));
        assert!(test_address_in_sections_aux(0x000f_fff3, sections.clone()));

    }
}
