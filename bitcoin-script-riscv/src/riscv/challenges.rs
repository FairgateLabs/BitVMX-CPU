use bitcoin_script_functions::hash::blake3;
use bitcoin_script_stack::stack::{StackTracker, StackVariable};
use bitvmx_cpu_definitions::{
    challenge::ChallengeType,
    constants::LAST_STEP_INIT,
    memory::{MemoryAccessType, SectionDefinition},
    trace::{generate_initial_step_hash, hashvec_to_string},
};

use crate::riscv::{
    memory_alignment::{is_aligned, load_lower_half_nibble_table, load_upper_half_nibble_table},
    operations::sub,
    script_utils::{
        address_not_in_sections, is_equal_to, is_lower_than, nibbles_to_number, shift_number,
        witness_equals, StackTables, WordTable,
    },
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

fn is_invalid_read(
    stack: &mut StackTracker,
    half_nibble_table: &StackVariable,
    lower_half_nibble_table: &StackVariable,
    read: StackVariable,
    memory_witness: &StackVariable,
    witness_nibble: u32,
    read_write_sections: &SectionDefinition,
    read_only_sections: &SectionDefinition,
    register_sections: &SectionDefinition,
) {
    witness_equals(
        stack,
        half_nibble_table,
        witness_nibble,
        memory_witness,
        MemoryAccessType::Memory,
    );
    address_not_in_sections(stack, &read, read_write_sections);
    address_not_in_sections(stack, &read, read_only_sections);
    stack.op_booland();
    stack.op_booland();

    witness_equals(
        stack,
        half_nibble_table,
        witness_nibble,
        memory_witness,
        MemoryAccessType::Register,
    );
    address_not_in_sections(stack, &read, register_sections);
    stack.op_booland();

    is_aligned(stack, read, true, lower_half_nibble_table);
    stack.op_not();

    stack.op_boolor();
    stack.op_boolor();
}

fn is_invalid_write(
    stack: &mut StackTracker,
    lower_half_nibble_table: &StackVariable,
    write: StackVariable,
    memory_witness: &StackVariable,
    read_write_sections: &SectionDefinition,
    register_sections: &SectionDefinition,
) {
    witness_equals(
        stack,
        lower_half_nibble_table,
        1,
        memory_witness,
        MemoryAccessType::Memory,
    );
    address_not_in_sections(stack, &write, read_write_sections);
    stack.op_booland();

    witness_equals(
        stack,
        lower_half_nibble_table,
        1,
        memory_witness,
        MemoryAccessType::Register,
    );
    address_not_in_sections(stack, &write, register_sections);
    stack.op_booland();

    is_aligned(stack, write, true, lower_half_nibble_table);
    stack.op_not();

    stack.op_boolor();
    stack.op_boolor();
}

fn is_invalid_pc(
    stack: &mut StackTracker,
    lower_half_nibble_table: &StackVariable,
    pc_address: StackVariable,
    code_sections: &SectionDefinition,
) {
    address_not_in_sections(stack, &pc_address, code_sections);

    is_aligned(stack, pc_address, true, lower_half_nibble_table);
    stack.op_not();

    stack.op_boolor();
}

pub fn addresses_sections_challenge(
    stack: &mut StackTracker,
    read_write_sections: &SectionDefinition,
    read_only_sections: &SectionDefinition,
    register_sections: &SectionDefinition,
    code_sections: &SectionDefinition,
) {
    stack.clear_definitions();

    let read_1_address = stack.define(8, "read_1_address");
    let read_2_address = stack.define(8, "read_2_address");
    let write_address = stack.define(8, "write_address");
    let memory_witness = stack.define(2, "memory_witness");
    let pc_address = stack.define(8, "pc_address");
    let upper_half_nibble_table = &load_upper_half_nibble_table(stack);
    let lower_half_nibble_table = &load_lower_half_nibble_table(stack);

    is_invalid_read(
        stack,
        lower_half_nibble_table,
        lower_half_nibble_table,
        read_1_address,
        &memory_witness,
        0,
        read_write_sections,
        read_only_sections,
        register_sections,
    );
    is_invalid_read(
        stack,
        upper_half_nibble_table,
        lower_half_nibble_table,
        read_2_address,
        &memory_witness,
        1,
        read_write_sections,
        read_only_sections,
        register_sections,
    );
    is_invalid_write(
        stack,
        lower_half_nibble_table,
        write_address,
        &memory_witness,
        read_write_sections,
        register_sections,
    );

    is_invalid_pc(stack, lower_half_nibble_table, pc_address, code_sections);

    stack.op_boolor();
    stack.op_boolor();
    stack.op_boolor();

    stack.op_verify();

    stack.drop(*lower_half_nibble_table);
    stack.drop(*upper_half_nibble_table);
    stack.drop(memory_witness);
}

pub fn opcode_challenge(stack: &mut StackTracker, chunk_base: u32, opcodes_chunk: &Vec<u32>) {
    stack.clear_definitions();

    let pc = stack.define(8, "prover_pc");
    let opcode = stack.define(8, "prover_opcode");
    let tables = StackTables::new(stack, true, false, 0, 0, 0);

    let start = stack.number_u32(chunk_base);
    let end = stack.number_u32(chunk_base + 4 * opcodes_chunk.len() as u32);

    let start_copy = stack.copy_var(start);
    let pc_copy = stack.copy_var(pc);
    is_equal_to(stack, &start_copy, &pc_copy);
    is_lower_than(stack, start_copy, pc_copy, true);
    stack.op_boolor();

    let pc_copy = stack.copy_var(pc);
    is_lower_than(stack, pc_copy, end, true);
    stack.op_booland();

    stack.op_verify();

    let opcodes_table = WordTable::new(stack, opcodes_chunk.clone());

    let to_shift = stack.number(2);
    let opcode_offset = sub(stack, &tables, pc, start);
    let opcode_index = shift_number(stack, to_shift, opcode_offset, true, false);

    let index_nibbles = stack.explode(opcode_index);
    nibbles_to_number(stack, index_nibbles);

    let real_opcode = opcodes_table.peek(stack);

    stack.equality(real_opcode, true, opcode, true, false, true);

    opcodes_table.drop(stack);
    tables.drop(stack);
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
            stack.byte(trace_step.get_pc().get_micro());
            stack.hexstr_as_nibbles(hash);
            trace_hash_challenge(&mut stack);
        }
        ChallengeType::TraceHashZero(trace_step, hash) => {
            stack.number_u32(trace_step.get_write().address);
            stack.number_u32(trace_step.get_write().value);
            stack.number_u32(trace_step.get_pc().get_address());
            stack.byte(trace_step.get_pc().get_micro());
            stack.hexstr_as_nibbles(hash);
            trace_hash_zero_challenge(&mut stack);
        }
        ChallengeType::EntryPoint(read_pc, step, real_entry_point) => {
            stack.number_u32(read_pc.pc.get_address());
            stack.byte(read_pc.pc.get_micro());
            stack.number_u64(*step);
            entry_point_challenge(&mut stack, *real_entry_point);
        }
        ChallengeType::ProgramCounter(pre_pre_hash, pre_step, prover_step_hash, prover_pc_read) => {
            stack.hexstr_as_nibbles(pre_pre_hash);
            stack.number_u32(pre_step.get_write().address);
            stack.number_u32(pre_step.get_write().value);
            stack.number_u32(pre_step.get_pc().get_address());
            stack.byte(pre_step.get_pc().get_micro());

            stack.number_u32(prover_pc_read.pc.get_address());
            stack.byte(prover_pc_read.pc.get_micro());

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
        ChallengeType::AddressesSections(
            read_1,
            read_2,
            write,
            memory_witness,
            pc,
            read_write_sections,
            read_only_sections,
            register_sections,
            code_sections,
        ) => {
            stack.number_u32(read_1.address);
            stack.number_u32(read_2.address);
            stack.number_u32(write.address);
            stack.byte(memory_witness.byte());
            stack.number_u32(pc.get_address());

            addresses_sections_challenge(
                &mut stack,
                read_write_sections.as_ref().unwrap(),
                read_only_sections.as_ref().unwrap(),
                register_sections.as_ref().unwrap(),
                code_sections.as_ref().unwrap(),
            );
        }
        ChallengeType::Opcode(pc_read, _, chunk_base, opcodes_chunk) => {
            stack.number_u32(pc_read.pc.get_address());
            stack.number_u32(pc_read.opcode);
            opcode_challenge(&mut stack, *chunk_base, opcodes_chunk.as_ref().unwrap());
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

    use bitvmx_cpu_definitions::{memory::MemoryWitness, trace::TraceRead};

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

    fn test_addresses_sections_aux(
        read_1: u32,
        read_2: u32,
        write: u32,
        memory_witness: MemoryWitness,
        pc: u32,
        read_write_sections: &SectionDefinition,
        read_only_sections: &SectionDefinition,
        registers: &SectionDefinition,
        code_sections: &SectionDefinition,
    ) -> bool {
        let mut stack = StackTracker::new();

        stack.number_u32(read_1);
        stack.number_u32(read_2);
        stack.number_u32(write);
        stack.byte(memory_witness.byte());
        stack.number_u32(pc);

        addresses_sections_challenge(
            &mut stack,
            read_write_sections,
            read_only_sections,
            registers,
            code_sections,
        );

        stack.op_true();
        stack.run().success
    }

    #[test]
    fn test_addresses_sections() {
        let read_write_sections = &SectionDefinition {
            ranges: vec![(0x0000_00f0, 0x0000_0103)],
        };
        let read_only_sections = &SectionDefinition {
            ranges: vec![(0x0000_0f00, 0x0000_1003)],
        };
        let registers = &SectionDefinition {
            ranges: vec![(0x0000_f000, 0x0001_0003)],
        };
        let code_sections = &SectionDefinition {
            ranges: vec![(0x000f_0000, 0x0010_0003)],
        };

        // can't challenge valid addresses (register section reads and write)
        let memory_witness = MemoryWitness::registers();
        assert!(!test_addresses_sections_aux(
            0x0000_f000,
            0x0000_f000,
            0x0000_f000,
            memory_witness,
            0x000f_0000,
            read_write_sections,
            read_only_sections,
            registers,
            code_sections
        ));

        // can't challenge valid addresses (read_write section reads and write)
        let memory_witness = MemoryWitness::new(
            MemoryAccessType::Memory,
            MemoryAccessType::Memory,
            MemoryAccessType::Memory,
        );
        assert!(!test_addresses_sections_aux(
            0x0000_00f0,
            0x0000_00f0,
            0x0000_00f0,
            memory_witness,
            0x000f_0000,
            read_write_sections,
            read_only_sections,
            registers,
            code_sections
        ));

        // can't challenge valid addresses (read_only section reads and read_write write)
        let memory_witness = MemoryWitness::new(
            MemoryAccessType::Memory,
            MemoryAccessType::Memory,
            MemoryAccessType::Memory,
        );
        assert!(!test_addresses_sections_aux(
            0x0000_0f00,
            0x0000_0f00,
            0x0000_00f0,
            memory_witness,
            0x000f_0000,
            read_write_sections,
            read_only_sections,
            registers,
            code_sections
        ));

        // can't challenge valid addresses (unused reads and write)
        let memory_witness = MemoryWitness::default();
        assert!(!test_addresses_sections_aux(
            0,
            0,
            0,
            memory_witness,
            0x000f_0000,
            read_write_sections,
            read_only_sections,
            registers,
            code_sections
        ));

        // can challenge invalid read_1 to unmaped address
        let memory_witness = MemoryWitness::new(
            MemoryAccessType::Memory,
            MemoryAccessType::Memory,
            MemoryAccessType::Memory,
        );
        assert!(test_addresses_sections_aux(
            0xDEAD_DEAD,
            0x0000_0f00,
            0x0000_00f0,
            memory_witness,
            0x000f_0000,
            read_write_sections,
            read_only_sections,
            registers,
            code_sections
        ));

        // can challenge unaligned read_1
        let memory_witness = MemoryWitness::new(
            MemoryAccessType::Memory,
            MemoryAccessType::Memory,
            MemoryAccessType::Memory,
        );
        assert!(test_addresses_sections_aux(
            0x0000_0f01,
            0x0000_0f00,
            0x0000_00f0,
            memory_witness,
            0x000f_0000,
            read_write_sections,
            read_only_sections,
            registers,
            code_sections
        ));

        // can challenge read_1 with wrong witness (register witness but address is not in registers)
        let memory_witness = MemoryWitness::new(
            MemoryAccessType::Register, // says it's a register read
            MemoryAccessType::Memory,
            MemoryAccessType::Memory,
        );
        assert!(test_addresses_sections_aux(
            0x0000_0f00, // not in registers
            0x0000_0f00,
            0x0000_00f0,
            memory_witness,
            0x000f_0000,
            read_write_sections,
            read_only_sections,
            registers,
            code_sections
        ));

        // can challenge invalid read_2 to unmaped address
        let memory_witness = MemoryWitness::new(
            MemoryAccessType::Memory,
            MemoryAccessType::Memory,
            MemoryAccessType::Memory,
        );
        assert!(test_addresses_sections_aux(
            0x0000_0f00,
            0xDEAD_DEAD,
            0x0000_00f0,
            memory_witness,
            0x000f_0000,
            read_write_sections,
            read_only_sections,
            registers,
            code_sections
        ));

        // can challenge unaligned read_2
        let memory_witness = MemoryWitness::new(
            MemoryAccessType::Memory,
            MemoryAccessType::Memory,
            MemoryAccessType::Memory,
        );
        assert!(test_addresses_sections_aux(
            0x0000_0f00,
            0x0000_0f02,
            0x0000_00f0,
            memory_witness,
            0x000f_0000,
            read_write_sections,
            read_only_sections,
            registers,
            code_sections
        ));

        // can challenge read_2 with wrong witness (register witness but address is not in registers)
        let memory_witness = MemoryWitness::new(
            MemoryAccessType::Memory,
            MemoryAccessType::Register, // says it's a register read
            MemoryAccessType::Memory,
        );
        assert!(test_addresses_sections_aux(
            0x0000_0f00,
            0x0000_0f00, // not in registers
            0x0000_00f0,
            memory_witness,
            0x000f_0000,
            read_write_sections,
            read_only_sections,
            registers,
            code_sections
        ));

        // can challenge invalid write to read_only address
        let memory_witness = MemoryWitness::new(
            MemoryAccessType::Memory,
            MemoryAccessType::Memory,
            MemoryAccessType::Memory,
        );
        assert!(test_addresses_sections_aux(
            0x0000_0f00,
            0x0000_00f0,
            0x0000_0f00,
            memory_witness,
            0x000f_0000,
            read_write_sections,
            read_only_sections,
            registers,
            code_sections
        ));

        // can challenge invalid write to unmaped address
        let memory_witness = MemoryWitness::new(
            MemoryAccessType::Memory,
            MemoryAccessType::Memory,
            MemoryAccessType::Memory,
        );
        assert!(test_addresses_sections_aux(
            0x0000_0f00,
            0x0000_00f0,
            0xDEAD_DEAD,
            memory_witness,
            0x000f_0000,
            read_write_sections,
            read_only_sections,
            registers,
            code_sections
        ));

        // can challenge unaligned write
        let memory_witness = MemoryWitness::new(
            MemoryAccessType::Memory,
            MemoryAccessType::Memory,
            MemoryAccessType::Memory,
        );
        assert!(test_addresses_sections_aux(
            0x0000_0f00,
            0x0000_0f00,
            0x0000_00f3,
            memory_witness,
            0x000f_0000,
            read_write_sections,
            read_only_sections,
            registers,
            code_sections
        ));

        // can challenge write with wrong witness (register witness but address not in registers)
        let memory_witness = MemoryWitness::new(
            MemoryAccessType::Memory,
            MemoryAccessType::Memory,
            MemoryAccessType::Register, // says it's a register write
        );
        assert!(test_addresses_sections_aux(
            0x0000_0f00,
            0x0000_0f00,
            0x0000_00f0, // not in registers
            memory_witness,
            0x000f_0000,
            read_write_sections,
            read_only_sections,
            registers,
            code_sections
        ));

        // can challenge invalid pc in register address
        let memory_witness = MemoryWitness::registers();
        assert!(test_addresses_sections_aux(
            0x0000_f000,
            0x0000_f000,
            0x0000_f000,
            memory_witness,
            0x0000_f000,
            read_write_sections,
            read_only_sections,
            registers,
            code_sections
        ));

        // can challenge invalid pc in unmaped address
        let memory_witness = MemoryWitness::registers();
        assert!(test_addresses_sections_aux(
            0x0000_f000,
            0x0000_f000,
            0x0000_f000,
            memory_witness,
            0xDEAD_C0DE,
            read_write_sections,
            read_only_sections,
            registers,
            code_sections
        ));

        // can challenge unaligned pc
        let memory_witness = MemoryWitness::registers();
        assert!(test_addresses_sections_aux(
            0x0000_f000,
            0x0000_f000,
            0x0000_f000,
            memory_witness,
            0x0000_f002,
            read_write_sections,
            read_only_sections,
            registers,
            code_sections
        ));

        // can challenge multiple errors
        let memory_witness = MemoryWitness::new(
            MemoryAccessType::Memory,
            MemoryAccessType::Memory,
            MemoryAccessType::Register,
        );
        assert!(test_addresses_sections_aux(
            0xDEAD_DEAD, // unmaped
            0x0000_f000, // register but witness says memory
            0x0000_00f0, // read only
            memory_witness,
            0x000f_0002, // unaligned
            read_write_sections,
            read_only_sections,
            registers,
            code_sections
        ));
    }

    fn test_opcode_aux(pc: u32, opcode: u32, chunk_base: u32, opcodes_chunk: &Vec<u32>) -> bool {
        let mut stack = StackTracker::new();

        stack.number_u32(pc);
        stack.number_u32(opcode);

        opcode_challenge(&mut stack, chunk_base, opcodes_chunk);

        stack.op_true();
        let r = stack.run();

        r.success
    }

    #[test]
    fn test_opcode() {
        let opcodes = &vec![1234, 5678];
        // can't challenge correct opcode
        assert!(!test_opcode_aux(0xab00_0000, 1234, 0xab00_0000, opcodes));
        assert!(!test_opcode_aux(0xab00_0004, 5678, 0xab00_0000, opcodes));

        // can't challenge address outside chunk
        assert!(!test_opcode_aux(0xab00_0008, 8888, 0xab00_0000, opcodes));

        // can challenge invalid opcodes
        assert!(test_opcode_aux(0xab00_0000, 8888, 0xab00_0000, opcodes));
        assert!(test_opcode_aux(0xab00_0004, 8888, 0xab00_0000, opcodes));
    }
}
