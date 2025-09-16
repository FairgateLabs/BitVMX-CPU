use bitcoin_script_functions::hash::blake3;
use bitcoin_script_stack::{interactive, stack::{StackTracker, StackVariable}};
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
            entry_point_challenge(&mut stack, real_entry_point.unwrap());
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
        ChallengeType::RomData(read_1, read_2, address, input_for_address) => {
            stack.number_u32(read_1.address);
            stack.number_u32(read_1.value);
            stack.number_u64(read_1.last_step);
            stack.number_u32(read_2.address);
            stack.number_u32(read_2.value);
            stack.number_u64(read_2.last_step);
            rom_challenge(&mut stack, *address, *input_for_address);
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
            opcode_challenge(
                &mut stack,
                chunk_base.unwrap(),
                opcodes_chunk.as_ref().unwrap(),
            );
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

    mod coin_tests {
        use super::*;
        use ::blake3::Hasher;
        use bitvmx_cpu_definitions::trace::{
            compute_step_hash, ProgramCounter, TraceStep, TraceWrite,
        };

        // we sometimes use this for debugging, just better
        // to have it available all the time
        #[allow(unused_imports)]
        use bitcoin_script_stack::interactive::interactive;

        #[derive(Debug, Clone)]
        struct OpcodeFuzzInput {
            pc: u32,
            opcode: u32,
            chunk_base: u32,
            opcodes_chunk: Vec<u32>,
            expected_to_succeed: bool,
        }

        #[derive(Debug, Clone)]
        struct AddressFuzzInput {
            read_1: u32,
            read_2: u32,
            write: u32,
            memory_witness: MemoryWitness,
            pc: u32,
            read_write_sections: SectionDefinition,
            read_only_sections: SectionDefinition,
            registers: SectionDefinition,
            code_sections: SectionDefinition,
            expected_to_succeed: bool,
        }

        #[derive(Debug, Clone)]
        struct InputFuzzInput {
            read_1: TraceRead,
            read_2: TraceRead,
            address: u32,
            input_for_address: u32,
            expected_to_succeed: bool,
        }

        #[derive(Debug, Clone)]
        struct RomFuzzInput {
            read_1: TraceRead,
            read_2: TraceRead,
            rom_address: u32,
            rom_value: u32,
            expected_to_succeed: bool,
        }

        fn entry_point_challenge_aux(
            wots_prover_pc: u32,
            wots_prover_micro: u8,
            wots_step: u64,
            entry_point_real: u32,
        ) -> bool {
            let mut stack = StackTracker::new();

            stack.number_u32(wots_prover_pc);
            stack.byte(wots_prover_micro);
            stack.number_u64(wots_step);

            entry_point_challenge(&mut stack, entry_point_real);
            stack.op_true();

            let expected_to_succeed = wots_step == 1 && wots_prover_pc != entry_point_real;
            stack.run().success == expected_to_succeed
        }

        fn halt_challenge_aux(
            final_step: u64,
            trace_step: u64,
            read_value_1: u32,
            read_value_2: u32,
            opcode: u32,
            expected_to_succeed: bool,
        ) -> bool {
            let mut stack = StackTracker::new();
            stack.number_u64(final_step);
            stack.number_u64(trace_step);
            stack.number_u32(read_value_1);
            stack.number_u32(read_value_2);
            stack.number_u32(opcode);

            halt_challenge(&mut stack);
            stack.op_true();

            stack.run().success == expected_to_succeed
        }
        fn trace_hash_challenge_aux(
            pre_hash: [u8; 20],
            write_add: u32,
            write_value: u32,
            pc: u32,
            micro: u8,
            hash: [u8; 20],
            expected_to_succeed: bool,
        ) -> bool {
            let mut stack = StackTracker::new();

            stack.hexstr_as_nibbles(&hex::encode(pre_hash));
            stack.number_u32(write_add);
            stack.number_u32(write_value);
            stack.number_u32(pc);
            stack.byte(micro);
            stack.hexstr_as_nibbles(&hex::encode(hash));

            trace_hash_challenge(&mut stack);
            stack.op_true();

            stack.run().success == expected_to_succeed
        }

        // Copy-paste of `trace::compute_state_hash`
        // Modified  to take `previous_hash: &[u8]` instead
        // of an array
        pub fn compute_step_hash_slice(
            hasher: &mut Hasher,
            previous_hash: &[u8],
            write_trace: &Vec<u8>,
        ) -> [u8; 20] {
            assert!(
                previous_hash.len() == 20,
                "Expected previous_hash to be 20 bytes long"
            );

            hasher.reset();
            hasher.update(previous_hash);
            hasher.update(write_trace);
            let mut output = [0u8; 20];
            hasher.finalize_xof().fill(&mut output);
            output
        }

        fn compute_state_hash_oracle(
            prev_prev_hash: &[u8; 20],
            write_add: u32,
            write_value: u32,
            pc: u32,
            micro: u8,
        ) -> [u8; 20] {
            use ::blake3;
            let mut hasher = blake3::Hasher::new();
            let step = TraceStep::new(
                TraceWrite::new(write_add, write_value),
                ProgramCounter::new(pc, micro),
            );
            let bytes = step.to_bytes();

            compute_step_hash(&mut hasher, prev_prev_hash, &bytes)
        }

        fn compute_state_hash_zero_oracle(
            write_add: u32,
            write_value: u32,
            pc: u32,
            micro: u8,
        ) -> [u8; 20] {
            use ::blake3;
            let mut hasher = blake3::Hasher::new();
            let initial_hash = generate_initial_step_hash();

            let step = TraceStep::new(
                TraceWrite::new(write_add, write_value),
                ProgramCounter::new(pc, micro),
            );
            let bytes = step.to_bytes();

            compute_step_hash_slice(&mut hasher, &initial_hash, &bytes)
        }

        fn program_counter_challenge_aux(
            pre_pre_hash: [u8; 20],
            write_add: u32,
            write_value: u32,
            pc: u32,
            micro: u8,
            prover_pc: u32,
            prover_micro: u8,
            prover_pre_hash: [u8; 20],
            expected_to_succeed: bool,
        ) -> bool {
            let mut stack = StackTracker::new();

            stack.hexstr_as_nibbles(&hex::encode(pre_pre_hash));
            stack.number_u32(write_add);
            stack.number_u32(write_value);
            stack.number_u32(pc);
            stack.byte(micro);
            stack.number_u32(prover_pc);
            stack.byte(prover_micro);

            stack.hexstr_as_nibbles(&hex::encode(prover_pre_hash));

            program_counter_challenge(&mut stack);
            stack.op_true();

            stack.run().success == expected_to_succeed
        }
        fn trace_hash_zero_challenge_aux(
            write_add: u32,
            write_value: u32,
            pc: u32,
            micro: u8,
            hash: [u8; 20],
            expected_to_succeed: bool,
        ) -> bool {
            let mut stack = StackTracker::new();
            stack.number_u32(write_add);
            stack.number_u32(write_value);
            stack.number_u32(pc);
            stack.byte(micro);
            stack.hexstr_as_nibbles(&hex::encode(hash));

            trace_hash_zero_challenge(&mut stack);
            stack.op_true();

            stack.run().success == expected_to_succeed
        }

        fn addresses_sections_challenge_aux(input: AddressFuzzInput) -> bool {
            let mut stack = StackTracker::new();

            stack.number_u32(input.read_1);
            stack.number_u32(input.read_2);
            stack.number_u32(input.write);
            stack.byte(input.memory_witness.byte());
            stack.number_u32(input.pc);

            addresses_sections_challenge(
                &mut stack,
                &input.read_write_sections,
                &input.read_only_sections,
                &input.registers,
                &input.code_sections,
            );
            stack.op_true();
            // interactive(&stack);
            stack.run().success == input.expected_to_succeed
        }

        fn input_challenge_aux(input: InputFuzzInput) -> bool {
            let mut stack = StackTracker::new();

            stack.number_u32(input.input_for_address);
            stack.number_u32(input.read_1.address);
            stack.number_u32(input.read_1.value);
            stack.number_u64(input.read_1.last_step);
            stack.number_u32(input.read_2.address);
            stack.number_u32(input.read_2.value);
            stack.number_u64(input.read_2.last_step);

            input_challenge(&mut stack, input.address);
            stack.op_true();

            stack.run().success == input.expected_to_succeed
        }

        fn opcode_challenge_aux(input: OpcodeFuzzInput) -> bool {
            let mut stack = StackTracker::new();

            stack.number_u32(input.pc);
            stack.number_u32(input.opcode);

            opcode_challenge(&mut stack, input.chunk_base, &input.opcodes_chunk);
            stack.op_true();

            stack.run().success == input.expected_to_succeed
        }

        fn rom_challenge_aux(input: RomFuzzInput) -> bool {
            let mut stack = StackTracker::new();

            stack.number_u32(input.read_1.address);
            stack.number_u32(input.read_1.value);
            stack.number_u64(input.read_1.last_step);
            stack.number_u32(input.read_2.address);
            stack.number_u32(input.read_2.value);
            stack.number_u64(input.read_2.last_step);

            rom_challenge(&mut stack, input.rom_address, input.rom_value);
            stack.op_true();

            stack.run().success == input.expected_to_succeed
        }

        mod fuzz_test {
            use super::*;
            use hex;
            use rand::Rng;
            use rand_pcg::Pcg32;
            use std::panic;
            use std::panic::AssertUnwindSafe;
            const FUZZ_ITERATIONS: u32 = 1000;

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

                let seed_str = env::var("FUZZ_SEED")
                    .unwrap_or_else(|_| rand::rng().random::<u64>().to_string());
                let seed = seed_str.parse::<u64>().expect("FUZZ_SEED must be a number");
                println!("--- Fuzzing {} with seed: {} ---", fuzzer_name, seed);
                let mut rng = Pcg32::seed_from_u64(seed);

                const ITERATIONS: u32 = FUZZ_ITERATIONS;
                let mut panics = Vec::with_capacity(ITERATIONS as usize);
                let mut failures = Vec::with_capacity(ITERATIONS as usize);
                let mut oks = Vec::with_capacity(ITERATIONS as usize);

                for _ in 0..ITERATIONS {
                    let input = input_generator(&mut rng);
                    let result =
                        panic::catch_unwind(AssertUnwindSafe(|| test_logic(input.clone())));

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
            fn fuzz_entry_point_challenge() {
                fuzz_generic_and_catch_panics(
                    "entry_point_challenge",
                    |rng| {
                        let wots_prover_pc: u32 = rng.random();
                        let wots_prover_micro: u8 = rng.random();
                        let wots_step: u64 = if rng.random_bool(0.5) {
                            1
                        } else {
                            rng.random_range(0..100)
                        };
                        let entry_point_real: u32 = rng.random();

                        (
                            wots_prover_pc,
                            wots_prover_micro,
                            wots_step,
                            entry_point_real,
                        )
                    },
                    |input| {
                        let (wots_prover_pc, wots_prover_micro, wots_step, entry_point_real) =
                            input;
                        entry_point_challenge_aux(
                            wots_prover_pc,
                            wots_prover_micro,
                            wots_step,
                            entry_point_real,
                        )
                    },
                );
            }

            #[test]
            fn fuzz_program_counter_challenge() {
                fuzz_generic_and_catch_panics(
                    "program_counter_challenge",
                    |rng| {
                        let should_succeed = rng.random_bool(0.5);
                        let verifier_pre_pre_hash: [u8; 20] = rng.random();
                        let verifier_write_add: u32 = rng.random();
                        let verifier_write_value: u32 = rng.random();
                        let verifier_pc: u32 = rng.random();
                        let verifier_micro: u8 = rng.random();
                        let correct_pre_hash = compute_state_hash_oracle(
                            &verifier_pre_pre_hash,
                            verifier_write_add,
                            verifier_write_value,
                            verifier_pc,
                            verifier_micro,
                        );

                        let prover_pc;
                        let prover_micro;
                        let prover_pre_hash;

                        if should_succeed {
                            // To succeed, the PC must be wrong, but the hash must be right.
                            // Generate a PC that is guaranteed to be different.
                            prover_pc = verifier_pc.wrapping_add(rng.random_range(1..u32::MAX));
                            prover_micro = rng.random(); // Can be same or different
                            prover_pre_hash = correct_pre_hash;
                        } else {
                            // To fail, either the PC is correct, or the hash is wrong.
                            if rng.random_bool(0.5) {
                                // Scenario: PC is correct, which fails the script's `not_equal` check.
                                prover_pc = verifier_pc;
                                prover_micro = verifier_micro;
                                prover_pre_hash = correct_pre_hash;
                            } else {
                                // Scenario: PC is incorrect, but the hash is also incorrect,
                                // which fails the script's final `equals` check.
                                prover_pc = verifier_pc.wrapping_add(rng.random_range(1..u32::MAX));
                                prover_micro = rng.random();
                                prover_pre_hash = rng.random(); // A random, incorrect hash
                            }
                        }

                        (
                            verifier_pre_pre_hash,
                            verifier_write_add,
                            verifier_write_value,
                            verifier_pc,
                            verifier_micro,
                            prover_pc,
                            prover_micro,
                            prover_pre_hash,
                            should_succeed,
                        )
                    },
                    |input| {
                        let (
                            pre_pre_hash,
                            write_add,
                            write_value,
                            pc,
                            micro,
                            prover_pc,
                            prover_micro,
                            pre_hash,
                            expected_to_succeed,
                        ) = input;
                        program_counter_challenge_aux(
                            pre_pre_hash,
                            write_add,
                            write_value,
                            pc,
                            micro,
                            prover_pc,
                            prover_micro,
                            pre_hash,
                            expected_to_succeed,
                        )
                    },
                );
            }

            #[test]
            fn fuzz_halt_challenge() {
                fuzz_generic_and_catch_panics(
                    "halt_challenge",
                    |rng| {
                        let should_succeed = rng.random_bool(0.5);

                        const SUCCESS_ECALL_VAL1: u32 = 93;
                        const SUCCESS_ECALL_VAL2: u32 = 0;
                        const SUCCESS_ECALL_OPCODE: u32 = 115;

                        let final_step: u64 = rng.random();
                        let trace_step: u64;
                        let mut read_value_1: u32;
                        let mut read_value_2: u32;
                        let mut opcode: u32;

                        if should_succeed {
                            // To succeed, steps must match AND the instruction must NOT be the success ecall.
                            trace_step = final_step;

                            loop {
                                read_value_1 = rng.random();
                                read_value_2 = rng.random();
                                opcode = rng.random();
                                if !(read_value_1 == SUCCESS_ECALL_VAL1
                                    && read_value_2 == SUCCESS_ECALL_VAL2
                                    && opcode == SUCCESS_ECALL_OPCODE)
                                {
                                    break;
                                }
                            }
                        } else {
                            // To fail, either the steps mismatch, OR the instruction is the success ecall.
                            if rng.random_bool(0.5) {
                                // Scenario: Steps mismatch. Instruction can be anything.
                                trace_step = final_step.wrapping_add(rng.random_range(1..u64::MAX));
                                read_value_1 = rng.random();
                                read_value_2 = rng.random();
                                opcode = rng.random();
                            } else {
                                // Scenario: Steps match, but it's the valid success ecall.
                                trace_step = final_step;
                                read_value_1 = SUCCESS_ECALL_VAL1;
                                read_value_2 = SUCCESS_ECALL_VAL2;
                                opcode = SUCCESS_ECALL_OPCODE;
                            }
                        }

                        (
                            final_step,
                            trace_step,
                            read_value_1,
                            read_value_2,
                            opcode,
                            should_succeed,
                        )
                    },
                    |input| {
                        let (
                            final_step,
                            trace_step,
                            read_value_1,
                            read_value_2,
                            opcode,
                            expected_to_succeed,
                        ) = input;
                        halt_challenge_aux(
                            final_step,
                            trace_step,
                            read_value_1,
                            read_value_2,
                            opcode,
                            expected_to_succeed,
                        )
                    },
                );
            }

            #[test]
            fn fuzz_trace_hash_challenge() {
                fuzz_generic_and_catch_panics(
                    "trace_hash_challenge",
                    |rng| {
                        let should_succeed = rng.random_bool(0.5);

                        let prev_hash: [u8; 20] = rng.random();
                        let write_add: u32 = rng.random();
                        let write_value: u32 = rng.random();
                        let pc: u32 = rng.random();
                        let micro: u8 = rng.random();

                        let correct_hash = compute_state_hash_oracle(
                            &prev_hash,
                            write_add,
                            write_value,
                            pc,
                            micro,
                        );

                        let mut prover_hash: [u8; 20];
                        if should_succeed {
                            // To succeed, the prover's hash must be INCORRECT.
                            // We generate a random hash that is guaranteed to be different.
                            loop {
                                prover_hash = rng.random();
                                if prover_hash != correct_hash {
                                    break;
                                }
                            }
                        } else {
                            prover_hash = correct_hash;
                        }

                        (
                            prev_hash,
                            write_add,
                            write_value,
                            pc,
                            micro,
                            prover_hash,
                            should_succeed,
                        )
                    },
                    |input| {
                        let (
                            prev_hash,
                            write_add,
                            write_value,
                            pc,
                            micro,
                            hash,
                            expected_to_succeed,
                        ) = input;
                        trace_hash_challenge_aux(
                            prev_hash,
                            write_add,
                            write_value,
                            pc,
                            micro,
                            hash,
                            expected_to_succeed,
                        )
                    },
                );
            }

            #[test]
            fn fuzz_trace_hash_zero_challenge() {
                fuzz_generic_and_catch_panics(
                    "trace_hash_zero_challenge",
                    |rng| {
                        let should_succeed = rng.random_bool(0.5);
                        let write_add: u32 = rng.random();
                        let write_value: u32 = rng.random();
                        let pc: u32 = rng.random();
                        let micro: u8 = rng.random();

                        let correct_hash =
                            compute_state_hash_zero_oracle(write_add, write_value, pc, micro);

                        let mut prover_hash: [u8; 20];
                        if should_succeed {
                            loop {
                                prover_hash = rng.random();
                                if prover_hash != correct_hash {
                                    break;
                                }
                            }
                        } else {
                            prover_hash = correct_hash;
                        }

                        (
                            write_add,
                            write_value,
                            pc,
                            micro,
                            prover_hash,
                            should_succeed,
                        )
                    },
                    |input| {
                        let (write_add, write_value, pc, micro, hash, expected_to_succeed) = input;
                        trace_hash_zero_challenge_aux(
                            write_add,
                            write_value,
                            pc,
                            micro,
                            hash,
                            expected_to_succeed,
                        )
                    },
                );
            }

            fn generate_valid_address_case() -> AddressFuzzInput {
                let read_write_sections = SectionDefinition {
                    ranges: vec![(0x1000, 0x1FFF)],
                };
                let read_only_sections = SectionDefinition {
                    ranges: vec![(0x2000, 0x2FFF)],
                };
                let registers = SectionDefinition {
                    ranges: vec![(0xF0000000, 0xF000007F)],
                };
                let code_sections = SectionDefinition {
                    ranges: vec![(0x80000000, 0x8000FFFF)],
                };

                AddressFuzzInput {
                    read_1: 0xF0000004, // Valid register read
                    read_2: 0x2008,     // Valid read-only read
                    write: 0x100C,      // Valid read-write write
                    pc: 0x80000200,     // Valid PC
                    memory_witness: MemoryWitness::new(
                        MemoryAccessType::Register,
                        MemoryAccessType::Memory,
                        MemoryAccessType::Memory,
                    ),
                    read_write_sections,
                    read_only_sections,
                    registers,
                    code_sections,
                    expected_to_succeed: false, // A valid case should NOT succeed the challenge
                }
            }

            #[test]
            fn fuzz_addresses_unmapped() {
                fuzz_generic_and_catch_panics(
                    "addresses_sections_challenge_unmapped",
                    |rng| {
                        let mut input = generate_valid_address_case();
                        if rng.random_bool(0.5) {
                            // 50% chance to test an invalid case
                            input.expected_to_succeed = true;
                            match rng.random_range(0..4) {
                                0 => input.read_1 = 0xDEADBEEF,
                                1 => input.read_2 = 0xDEADBEEF,
                                2 => input.write = 0xDEADBEEF,
                                _ => input.pc = 0xDEADBEEF,
                            }
                        }
                        input
                    },
                    |input| addresses_sections_challenge_aux(input),
                );
            }

            #[test]
            fn fuzz_addresses_unaligned() {
                fuzz_generic_and_catch_panics(
                    "addresses_sections_challenge_unaligned",
                    |rng| {
                        let mut input = generate_valid_address_case();
                        if rng.random_bool(0.5) {
                            input.expected_to_succeed = true;
                            // Pick one access to make unaligned (must be a multiple of 1, 2, or 3, but not 4)
                            match rng.random_range(0..4) {
                                0 => input.read_1 = 0x1000 + rng.random_range(1..4),
                                1 => input.read_2 = 0x2000 + rng.random_range(1..4),
                                2 => input.write = 0x1000 + rng.random_range(1..4),
                                _ => input.pc = 0x80000100 + rng.random_range(1..4),
                            }
                        }
                        input
                    },
                    |input| addresses_sections_challenge_aux(input),
                );
            }

            #[test]
            fn fuzz_addresses_witness_mismatch() {
                fuzz_generic_and_catch_panics(
                    "addresses_sections_challenge_witness_mismatch",
                    |rng| {
                        let mut input = generate_valid_address_case();
                        if rng.random_bool(0.5) {
                            input.expected_to_succeed = true;
                            match rng.random_range(0..3) {
                                0 => {
                                    // read_1 is a valid memory address, but witness claims it's a register
                                    input.read_1 = 0x1000;
                                    input.memory_witness = MemoryWitness::new(
                                        MemoryAccessType::Register,
                                        input.memory_witness.read_2(),
                                        input.memory_witness.write(),
                                    );
                                }
                                1 => {
                                    // read_2 is a valid memory address, but witness claims it's a register
                                    input.read_2 = 0x2000;
                                    input.memory_witness = MemoryWitness::new(
                                        input.memory_witness.read_1(),
                                        MemoryAccessType::Register,
                                        input.memory_witness.write(),
                                    );
                                }
                                _ => {
                                    // write is a valid memory address, but witness claims it's a register
                                    input.write = 0x1000;
                                    input.memory_witness = MemoryWitness::new(
                                        input.memory_witness.read_1(),
                                        input.memory_witness.read_2(),
                                        MemoryAccessType::Register,
                                    );
                                }
                            }
                        }
                        input
                    },
                    |input| addresses_sections_challenge_aux(input),
                );
            }

            #[test]
            fn fuzz_addresses_write_to_readonly() {
                fuzz_generic_and_catch_panics(
                    "addresses_sections_challenge_write_to_readonly",
                    |rng| {
                        let mut input = generate_valid_address_case();
                        if rng.random_bool(0.5) {
                            input.expected_to_succeed = true;
                            // Attempt to write to a valid, aligned address within the .rodata section
                            input.write = 0x2004;
                        }
                        input
                    },
                    |input| addresses_sections_challenge_aux(input),
                );
            }

            #[test]
            fn fuzz_input_challenge() {
                fuzz_generic_and_catch_panics(
                    "input_challenge",
                    |rng| {
                        let should_succeed = rng.random_bool(0.5);

                        let challenge_address: u32 = rng.random();
                        let input_value: u32 = rng.random();
                        let mut read_1: TraceRead;
                        let mut read_2: TraceRead;

                        if should_succeed {
                            // To succeed, at least one of the reads must be an uninitialized read
                            // at the correct address, but with the wrong value.
                            let wrong_value =
                                input_value.wrapping_add(rng.random_range(1..u32::MAX));

                            if rng.random_bool(0.5) {
                                // Scenario: read_1 is the winning challenge.
                                read_1 =
                                    TraceRead::new(challenge_address, wrong_value, LAST_STEP_INIT);
                                // read_2 can be anything that fails the challenge. Easiest is to change the address.
                                read_2 = TraceRead::new(
                                    challenge_address.wrapping_add(1),
                                    rng.random(),
                                    LAST_STEP_INIT,
                                );
                            } else {
                                // Scenario: read_2 is the winning challenge.
                                read_2 =
                                    TraceRead::new(challenge_address, wrong_value, LAST_STEP_INIT);
                                // read_1 can be anything that fails.
                                read_1 = TraceRead::new(
                                    challenge_address.wrapping_add(1),
                                    rng.random(),
                                    LAST_STEP_INIT,
                                );
                            }
                        } else {
                            // To fail, NEITHER read can meet the success conditions.
                            // We'll create two failing traces.

                            // Failing trace 1: The step is not initial.
                            read_1 = TraceRead::new(
                                challenge_address,
                                rng.random(),
                                rng.random_range(0..LAST_STEP_INIT),
                            );

                            // Failing trace 2: The address is wrong.
                            read_2 = TraceRead::new(
                                challenge_address.wrapping_add(1),
                                rng.random(),
                                LAST_STEP_INIT,
                            );

                            // Randomly swap them to test both positions
                            if rng.random_bool(0.5) {
                                std::mem::swap(&mut read_1, &mut read_2);
                            }
                        }

                        InputFuzzInput {
                            read_1,
                            read_2,
                            address: challenge_address,
                            input_for_address: input_value,
                            expected_to_succeed: should_succeed,
                        }
                    },
                    |input| input_challenge_aux(input),
                );
            }

            #[test]
            fn fuzz_opcode_challenge() {
                fuzz_generic_and_catch_panics(
                    "opcode_challenge",
                    |rng| {
                        let should_succeed = rng.random_bool(0.5);

                        let chunk_base: u32 = rng.random();
                        let opcodes_chunk: Vec<u32> =
                            (0..rng.random_range(1..50)).map(|_| rng.random()).collect();

                        let pc: u32;
                        let mut opcode: u32;

                        if should_succeed {
                            // To succeed, the PC must be within the chunk, but the opcode must be wrong.
                            let pc_index = rng.random_range(0..opcodes_chunk.len());
                            pc = chunk_base.wrapping_add((pc_index * 4) as u32);
                            let correct_opcode = opcodes_chunk[pc_index];

                            loop {
                                opcode = rng.random();
                                if opcode != correct_opcode {
                                    break;
                                }
                            }
                        } else {
                            // To fail, either the PC is out of bounds, OR the opcode is correct.
                            if rng.random_bool(0.5) {
                                // Scenario: PC is out of bounds.
                                // Generate a PC that is before the chunk start or after the chunk end.
                                if rng.random_bool(0.5) {
                                    pc = chunk_base.wrapping_sub(rng.random_range(1..100) * 4);
                                } else {
                                    pc = chunk_base
                                        .wrapping_add((opcodes_chunk.len() as u32) * 4)
                                        .wrapping_add(rng.random_range(0..100) * 4);
                                }
                                opcode = rng.random(); // Opcode can be anything
                            } else {
                                // Scenario: PC is in bounds, but the opcode is correct.
                                let pc_index = rng.random_range(0..opcodes_chunk.len());
                                pc = chunk_base.wrapping_add((pc_index * 4) as u32);
                                opcode = opcodes_chunk[pc_index];
                            }
                        }

                        OpcodeFuzzInput {
                            pc,
                            opcode,
                            chunk_base,
                            opcodes_chunk,
                            expected_to_succeed: should_succeed,
                        }
                    },
                    |input| opcode_challenge_aux(input),
                );
            }

            #[test]
            fn fuzz_rom_challenge() {
                fuzz_generic_and_catch_panics(
                    "rom_challenge",
                    |rng| {
                        let should_succeed = rng.random_bool(0.5);

                        let rom_address: u32 = rng.random();
                        let rom_value: u32 = rng.random();
                        let mut read_1: TraceRead;
                        let mut read_2: TraceRead;

                        if should_succeed {
                            // To succeed, at least one read must be an uninitialized read at the
                            // correct address, but with the wrong value.
                            let wrong_value = rom_value.wrapping_add(rng.random_range(1..u32::MAX));

                            if rng.random_bool(0.5) {
                                // Scenario: read_1 is the winning challenge.
                                read_1 = TraceRead::new(rom_address, wrong_value, LAST_STEP_INIT);
                                // read_2 can be anything that fails (e.g., wrong address).
                                read_2 = TraceRead::new(
                                    rom_address.wrapping_add(4),
                                    rng.random(),
                                    LAST_STEP_INIT,
                                );
                            } else {
                                // Scenario: read_2 is the winning challenge.
                                read_2 = TraceRead::new(rom_address, wrong_value, LAST_STEP_INIT);
                                read_1 = TraceRead::new(
                                    rom_address.wrapping_add(4),
                                    rng.random(),
                                    LAST_STEP_INIT,
                                );
                            }
                        } else {
                            // To fail, NEITHER read can meet the success conditions.
                            // Three failure modes: wrong step, wrong address, or correct value.

                            // Failure case 1: Step is not initial.
                            read_1 = TraceRead::new(
                                rom_address,
                                rng.random(),
                                rng.random_range(0..LAST_STEP_INIT),
                            );

                            // Failure case 2: Address is wrong.
                            read_2 = TraceRead::new(
                                rom_address.wrapping_add(4),
                                rng.random(),
                                LAST_STEP_INIT,
                            );

                            // Randomly swap to ensure both positions are tested for failure.
                            if rng.random_bool(0.5) {
                                std::mem::swap(&mut read_1, &mut read_2);
                            }
                        }

                        RomFuzzInput {
                            read_1,
                            read_2,
                            rom_address,
                            rom_value,
                            expected_to_succeed: should_succeed,
                        }
                    },
                    |input| rom_challenge_aux(input),
                );
            }
        }

        mod border_test {
            use super::*;

            /// Tests various edge cases for the entry_point_challenge.
            #[test]
            fn test_entry_point_border_cases() {
                #[derive(Debug)]
                struct TestCase {
                    description: &'static str,
                    prover_pc: u32,
                    step: u64,
                    entry_point: u32,
                }

                let test_cases = [
                    // --- Success Scenarios (Challenge should succeed: Prover is wrong) ---
                    TestCase {
                        description: "Standard case: Prover's PC is simply wrong.",
                        prover_pc: 0x80000004,
                        step: 1,
                        entry_point: 0x80000000,
                    },
                    TestCase {
                        description: "Border case: Prover's PC is 0, but the entry point is not.",
                        prover_pc: 0,
                        step: 1,
                        entry_point: 0x80000000,
                    },
                    TestCase {
                        description:
                            "Border case: Prover's PC is u32::MAX, but the entry point is not.",
                        prover_pc: u32::MAX,
                        step: 1,
                        entry_point: 0x80000000,
                    },
                    TestCase {
                        description: "Border case: Entry point is 0, but the prover's PC is not.",
                        prover_pc: 0x80000000,
                        step: 1,
                        entry_point: 0,
                    },
                    TestCase {
                        description:
                            "Border case: Entry point is u32::MAX, but the prover's PC is not.",
                        prover_pc: 0,
                        step: 1,
                        entry_point: u32::MAX,
                    },
                    // --- Failure Scenarios (Challenge should fail: Prover is correct or conditions not met) ---
                    TestCase {
                        description:
                            "Failure Case: Prover is correct (step is 1, PC matches entry point).",
                        prover_pc: 0x80000000,
                        step: 1,
                        entry_point: 0x80000000,
                    },
                    TestCase {
                        description: "Border case: Prover is correct at entry point 0.",
                        prover_pc: 0,
                        step: 1,
                        entry_point: 0,
                    },
                    TestCase {
                        description: "Border case: Prover is correct at entry point u32::MAX.",
                        prover_pc: u32::MAX,
                        step: 1,
                        entry_point: u32::MAX,
                    },
                    TestCase {
                        description: "Failure Case: The step number is 0, PC check is irrelevant.",
                        prover_pc: 0x80000004,
                        step: 0,
                        entry_point: 0x80000000,
                    },
                    TestCase {
                        description: "Failure Case: The step number is 2, PC check is irrelevant.",
                        prover_pc: 0x80000004,
                        step: 2,
                        entry_point: 0x80000000,
                    },
                    TestCase {
                        description:
                            "Failure Case: The step number is u64::MAX, PC check is irrelevant.",
                        prover_pc: 0x80000000,
                        step: u64::MAX,
                        entry_point: 0x80000000,
                    },
                ];

                for case in test_cases.iter() {
                    // entry point is always with micro = 0 so we can hardcode it
                    let result =
                        entry_point_challenge_aux(case.prover_pc, 0, case.step, case.entry_point);
                    // result will be false only if the test did not match expectations
                    assert_eq!(
                        result, true,
                        "Test failed: {}. Case: {:?}",
                        case.description, case
                    );
                }
            }

            #[test]
            fn test_input_border_cases() {
                #[derive(Debug)]
                struct TestCase {
                    description: &'static str,
                    read_1: TraceRead,
                    read_2: TraceRead,
                    address: u32,
                    input_for_address: u32,
                    expected_to_succeed: bool,
                }

                let test_cases = [
            // --- Success Scenarios (Challenge should succeed) ---
            TestCase {
                description: "read_1 is fraudulent, read_2 is irrelevant.",
                read_1: TraceRead::new(0x1000, 0xAAAA, LAST_STEP_INIT),
                read_2: TraceRead::new(0x2000, 0, 0),
                address: 0x1000,
                input_for_address: 0xBBBB,
                expected_to_succeed: true,
            },
            TestCase {
                description: "read_2 is fraudulent, read_1 is irrelevant.",
                read_1: TraceRead::new(0x2000, 0, 0),
                read_2: TraceRead::new(0x1000, 0xAAAA, LAST_STEP_INIT),
                address: 0x1000,
                input_for_address: 0xBBBB,
                expected_to_succeed: true,
            },
            TestCase {
                description: "Both reads are fraudulent for the same address.",
                read_1: TraceRead::new(0x1000, 0xAAAA, LAST_STEP_INIT),
                read_2: TraceRead::new(0x1000, 0xCCCC, LAST_STEP_INIT),
                address: 0x1000,
                input_for_address: 0xBBBB,
                expected_to_succeed: true,
            },
            // ! IGNORED due to VMX-CPU-006
            // TestCase {
            //     description: "Border case: Fraudulent read at address 0.",
            //     read_1: TraceRead::new(0, 0xAAAA, LAST_STEP_INIT),
            //     read_2: TraceRead::new(0x2000, 0, 0),
            //     address: 0,
            //     input_for_address: 0xBBBB,
            //     expected_to_succeed: true,
            // },
            // --- Failure Scenarios (Challenge should fail) ---
            TestCase {
                description: "Prover is honest. Both reads are uninitialized and have the correct value.",
                read_1: TraceRead::new(0x1000, 0xBBBB, LAST_STEP_INIT),
                read_2: TraceRead::new(0x1000, 0xBBBB, LAST_STEP_INIT),
                address: 0x1000,
                input_for_address: 0xBBBB,
                expected_to_succeed: false,
            },
            TestCase {
                description: "The address being challenged doesn't match either read.",
                read_1: TraceRead::new(0x1000, 0xAAAA, LAST_STEP_INIT),
                read_2: TraceRead::new(0x2000, 0xCCCC, LAST_STEP_INIT),
                address: 0x3000,
                input_for_address: 0xBBBB,
                expected_to_succeed: false,
            },
            TestCase {
                description: "The reads were not uninitialized (last_step != INIT).",
                read_1: TraceRead::new(0x1000, 0xAAAA, 1),
                read_2: TraceRead::new(0x1000, 0xAAAA, 2),
                address: 0x1000,
                input_for_address: 0xBBBB,
                expected_to_succeed: false,
            },
            // ! IGNORED due to issue VMX-CPU-006
            // TestCase {
            //     description: "Prover is honest at address 0 with value 0.",
            //     read_1: TraceRead::new(0, 0, LAST_STEP_INIT),
            //     read_2: TraceRead::new(0, 0, LAST_STEP_INIT),
            //     address: 0,
            //     input_for_address: 0,
            //     expected_to_succeed: false,
            // },
        ];

                for case in test_cases.iter() {
                    let result = input_challenge_aux(InputFuzzInput {
                        read_1: case.read_1.clone(),
                        read_2: case.read_2.clone(),
                        address: case.address,
                        input_for_address: case.input_for_address,
                        expected_to_succeed: case.expected_to_succeed,
                    });
                    assert!(
                        result,
                        "Test failed: {}. Case: {:?}",
                        case.description, case
                    );
                }
            }

            #[test]
            fn test_halt_border_cases() {
                const SUCCESS_ECALL_VAL1: u32 = 93;
                const SUCCESS_ECALL_VAL2: u32 = 0;
                const SUCCESS_ECALL_OPCODE: u32 = 115;

                #[derive(Debug)]
                struct TestCase {
                    description: &'static str,
                    prover_step: u64,
                    verifier_step: u64,
                    val1: u32,
                    val2: u32,
                    opcode: u32,
                    expected_to_succeed: bool,
                }

                let test_cases = [
                    // --- Success Scenarios (Challenge should succeed) ---
                    TestCase {
                        description:
                            "Standard success: steps match, instruction is not success ecall.",
                        prover_step: 100,
                        verifier_step: 100,
                        val1: 94,
                        val2: 0,
                        opcode: 115,
                        expected_to_succeed: true,
                    },
                    TestCase {
                        description: "Success: val2 is different.",
                        prover_step: 100,
                        verifier_step: 100,
                        val1: SUCCESS_ECALL_VAL1,
                        val2: 1,
                        opcode: SUCCESS_ECALL_OPCODE,
                        expected_to_succeed: true,
                    },
                    TestCase {
                        description: "Success: opcode is different.",
                        prover_step: 100,
                        verifier_step: 100,
                        val1: SUCCESS_ECALL_VAL1,
                        val2: SUCCESS_ECALL_VAL2,
                        opcode: 116,
                        expected_to_succeed: true,
                    },
                    TestCase {
                        description: "Border case: Step is 0.",
                        prover_step: 0,
                        verifier_step: 0,
                        val1: 94,
                        val2: 0,
                        opcode: 115,
                        expected_to_succeed: true,
                    },
                    TestCase {
                        description: "Border case: Step is MAX.",
                        prover_step: u64::MAX,
                        verifier_step: u64::MAX,
                        val1: 94,
                        val2: 0,
                        opcode: 115,
                        expected_to_succeed: true,
                    },
                    TestCase {
                        description: "Border case: All instruction values are MAX.",
                        prover_step: 100,
                        verifier_step: 100,
                        val1: u32::MAX,
                        val2: u32::MAX,
                        opcode: u32::MAX,
                        expected_to_succeed: true,
                    },
                    // --- Failure Scenarios (Challenge should fail) ---
                    TestCase {
                        description: "Failure: Steps match, but it IS the success ecall.",
                        prover_step: 100,
                        verifier_step: 100,
                        val1: SUCCESS_ECALL_VAL1,
                        val2: SUCCESS_ECALL_VAL2,
                        opcode: SUCCESS_ECALL_OPCODE,
                        expected_to_succeed: false,
                    },
                    TestCase {
                        description: "Failure: Steps do not match.",
                        prover_step: 100,
                        verifier_step: 101,
                        val1: 94,
                        val2: 0,
                        opcode: 115,
                        expected_to_succeed: false,
                    },
                    TestCase {
                        description: "Border case: Steps do not match (0 and 1).",
                        prover_step: 0,
                        verifier_step: 1,
                        val1: 94,
                        val2: 0,
                        opcode: 115,
                        expected_to_succeed: false,
                    },
                    TestCase {
                        description: "Border case: Steps do not match (MAX-1 and MAX).",
                        prover_step: u64::MAX - 1,
                        verifier_step: u64::MAX,
                        val1: 94,
                        val2: 0,
                        opcode: 115,
                        expected_to_succeed: false,
                    },
                ];

                for case in test_cases.iter() {
                    let result = halt_challenge_aux(
                        case.prover_step,
                        case.verifier_step,
                        case.val1,
                        case.val2,
                        case.opcode,
                        case.expected_to_succeed,
                    );
                    assert!(
                        result,
                        "Test failed: {}. Case: {:?}",
                        case.description, case
                    );
                }
            }

            #[test]
            fn test_trace_hash_border_cases() {
                #[derive(Debug, Clone)]
                struct TestCase {
                    description: &'static str,
                    prev_hash: [u8; 20],
                    write_add: u32,
                    write_val: u32,
                    pc: u32,
                    micro: u8,
                }

                let test_cases = [
                    TestCase {
                        description: "All-zero inputs",
                        prev_hash: [0; 20],
                        write_add: 0,
                        write_val: 0,
                        pc: 0,
                        micro: 0,
                    },
                    TestCase {
                        description: "Max value inputs",
                        prev_hash: [0xff; 20],
                        write_add: u32::MAX,
                        write_val: u32::MAX,
                        pc: u32::MAX,
                        micro: u8::MAX,
                    },
                    TestCase {
                        description: "Mixed value inputs",
                        prev_hash: [0xAB; 20],
                        write_add: 0x12345678,
                        write_val: 0x9ABCDEF0,
                        pc: 0x80000000,
                        micro: 128,
                    },
                ];

                for case in test_cases.iter() {
                    let correct_hash = compute_state_hash_oracle(
                        &case.prev_hash,
                        case.write_add,
                        case.write_val,
                        case.pc,
                        case.micro,
                    );
                    let incorrect_hash = correct_hash.map(|b| b.wrapping_add(1));

                    // Success Case: Prover provides an incorrect hash.
                    let success_result = trace_hash_challenge_aux(
                        case.prev_hash,
                        case.write_add,
                        case.write_val,
                        case.pc,
                        case.micro,
                        incorrect_hash,
                        true,
                    );
                    assert!(
                        success_result,
                        "Success test failed for case: {}",
                        case.description
                    );

                    // Failure Case: Prover provides the correct hash.
                    let failure_result = trace_hash_challenge_aux(
                        case.prev_hash,
                        case.write_add,
                        case.write_val,
                        case.pc,
                        case.micro,
                        correct_hash,
                        false,
                    );
                    assert!(
                        failure_result,
                        "Failure test failed for case: {}",
                        case.description
                    );
                }
            }

            #[test]
            fn test_trace_hash_zero_border_cases() {
                #[derive(Debug, Clone)]
                struct TestCase {
                    description: &'static str,
                    write_add: u32,
                    write_val: u32,
                    pc: u32,
                    micro: u8,
                }

                let test_cases = [
                    TestCase {
                        description: "All-zero inputs",
                        write_add: 0,
                        write_val: 0,
                        pc: 0,
                        micro: 0,
                    },
                    TestCase {
                        description: "Max value inputs",
                        write_add: u32::MAX,
                        write_val: u32::MAX,
                        pc: u32::MAX,
                        micro: u8::MAX,
                    },
                    TestCase {
                        description: "Mixed values with zero pc",
                        write_add: u32::MAX,
                        write_val: 0,
                        pc: 0,
                        micro: u8::MAX,
                    },
                ];

                for case in test_cases.iter() {
                    let correct_hash = compute_state_hash_zero_oracle(
                        case.write_add,
                        case.write_val,
                        case.pc,
                        case.micro,
                    );
                    let incorrect_hash = correct_hash.map(|b| b.wrapping_add(1));

                    // Success Case: Prover provides an incorrect hash for step 0.
                    let success_result = trace_hash_zero_challenge_aux(
                        case.write_add,
                        case.write_val,
                        case.pc,
                        case.micro,
                        incorrect_hash,
                        true,
                    );
                    assert!(
                        success_result,
                        "Success test failed for case: {}",
                        case.description
                    );

                    // Failure Case: Prover provides the correct hash for step 0.
                    let failure_result = trace_hash_zero_challenge_aux(
                        case.write_add,
                        case.write_val,
                        case.pc,
                        case.micro,
                        correct_hash,
                        false,
                    );
                    assert!(
                        failure_result,
                        "Failure test failed for case: {}",
                        case.description
                    );
                }
            }

            #[test]
            fn test_program_counter_border_cases() {
                #[derive(Debug)]
                struct TestCase {
                    description: &'static str,
                    pre_pre_hash: [u8; 20],
                    write_add: u32,
                    write_val: u32,
                    verifier_pc: u32,
                    verifier_micro: u8,
                    prover_pc: u32,
                    prover_micro: u8,
                    use_correct_hash: bool,
                    expected_to_succeed: bool,
                }

                let test_cases = [
                    TestCase {
                        description:
                            "Success: Prover's PC is wrong, but verifier's state hash is correct.",
                        pre_pre_hash: [0u8; 20],
                        write_add: 0,
                        write_val: u32::MAX,
                        verifier_pc: 0x80000000,
                        verifier_micro: u8::MAX,
                        prover_pc: 0x80000004, // Wrong PC
                        prover_micro: u8::MAX,
                        use_correct_hash: true,
                        expected_to_succeed: true,
                    },
                    TestCase {
                        description: "Failure: Prover is honest (PCs match).",
                        pre_pre_hash: [1u8; 20],
                        write_add: 1,
                        write_val: 1,
                        verifier_pc: 1,
                        verifier_micro: 1,
                        prover_pc: 1, // Correct PC
                        prover_micro: 1,
                        use_correct_hash: true,
                        expected_to_succeed: false,
                    },
                    TestCase {
                        description: "Failure: Verifier is inconsistent (hash is wrong).",
                        pre_pre_hash: [0xFFu8; 20],
                        write_add: u32::MAX,
                        write_val: u32::MAX,
                        verifier_pc: u32::MAX,
                        verifier_micro: u8::MAX,
                        prover_pc: u32::MAX - 4, // Wrong PC
                        prover_micro: u8::MAX,
                        use_correct_hash: false, // But verifier can't prove it
                        expected_to_succeed: false,
                    },
                    TestCase {
                        description: "Success: Prover's micro instruction is wrong.",
                        pre_pre_hash: [0xAA; 20],
                        write_add: 100,
                        write_val: 200,
                        verifier_pc: 300,
                        verifier_micro: 5,
                        prover_pc: 300,
                        prover_micro: 6, // Wrong micro
                        use_correct_hash: true,
                        expected_to_succeed: true,
                    },
                ];

                for case in test_cases.iter() {
                    let prover_prev_hash = if case.use_correct_hash {
                        compute_state_hash_oracle(
                            &case.pre_pre_hash,
                            case.write_add,
                            case.write_val,
                            case.verifier_pc,
                            case.verifier_micro,
                        )
                    } else {
                        [0xDE; 20] // A deliberately wrong hash
                    };

                    let result = program_counter_challenge_aux(
                        case.pre_pre_hash,
                        case.write_add,
                        case.write_val,
                        case.verifier_pc,
                        case.verifier_micro,
                        case.prover_pc,
                        case.prover_micro,
                        prover_prev_hash,
                        case.expected_to_succeed,
                    );
                    assert!(
                        result,
                        "Test failed: {}. Case: {:?}",
                        case.description, case
                    );
                }
            }

            #[test]
            fn test_rom_challenge_border_cases() {
                #[derive(Debug)]
                struct TestCase {
                    description: &'static str,
                    read_1: TraceRead,
                    read_2: TraceRead,
                    challenge_address: u32,
                    correct_value: u32,
                    expected_to_succeed: bool,
                }

                let read_ok_irrelevant = TraceRead::new(0x2000, 0, 0);

                let test_cases = [
                    // --- Success Scenarios (Challenge should succeed) ---
                    TestCase {
                        description: "read_1 is fraudulent, read_2 is irrelevant.",
                        read_1: TraceRead::new(0x1000, 0xAAAA, LAST_STEP_INIT),
                        read_2: read_ok_irrelevant.clone(),
                        challenge_address: 0x1000,
                        correct_value: 0xBBBB,
                        expected_to_succeed: true,
                    },
                    TestCase {
                        description: "read_2 is fraudulent, read_1 is irrelevant.",
                        read_1: read_ok_irrelevant.clone(),
                        read_2: TraceRead::new(0x1000, 0xAAAA, LAST_STEP_INIT),
                        challenge_address: 0x1000,
                        correct_value: 0xBBBB,
                        expected_to_succeed: true,
                    },
                    TestCase {
                        description: "Border case: Challenge address is 1, value is 0.",
                        read_1: TraceRead::new(1, 1, LAST_STEP_INIT),
                        read_2: read_ok_irrelevant.clone(),
                        challenge_address: 1,
                        correct_value: 0,
                        expected_to_succeed: true,
                    },
                    TestCase {
                        description: "Border case: Challenge address is u32::MAX.",
                        read_1: TraceRead::new(u32::MAX, 0, LAST_STEP_INIT),
                        read_2: read_ok_irrelevant.clone(),
                        challenge_address: u32::MAX,
                        correct_value: 1,
                        expected_to_succeed: true,
                    },
                    // --- Failure Scenarios (Challenge should fail) ---
                    TestCase {
                        description:
                            "Prover is honest. The read is uninitialized and has the correct value.",
                        read_1: TraceRead::new(0x1000, 0xBBBB, LAST_STEP_INIT),
                        read_2: read_ok_irrelevant.clone(),
                        challenge_address: 0x1000,
                        correct_value: 0xBBBB,
                        expected_to_succeed: false,
                    },
                    TestCase {
                        description:
                            "The address being challenged doesn't match the fraudulent read.",
                        read_1: TraceRead::new(0x1000, 0xAAAA, LAST_STEP_INIT),
                        read_2: read_ok_irrelevant.clone(),
                        challenge_address: 0x3000,
                        correct_value: 0xBBBB,
                        expected_to_succeed: false,
                    },
                    TestCase {
                        description: "The read was not uninitialized (last_step != INIT).",
                        read_1: TraceRead::new(0x1000, 0xAAAA, 1),
                        read_2: read_ok_irrelevant.clone(),
                        challenge_address: 0x1000,
                        correct_value: 0xBBBB,
                        expected_to_succeed: false,
                    },
                ];

                for case in test_cases.iter() {
                    let result = test_rom_aux(
                        &case.read_1,
                        &case.read_2,
                        case.challenge_address,
                        case.correct_value,
                    );
                    assert_eq!(
                        result, case.expected_to_succeed,
                        "Test failed: {}. Case: {:?}",
                        case.description, case
                    );
                }
            }
        }

        #[test]
        fn test_opcode_challenge_border_cases() {
            #[derive(Debug)]
            struct TestCase<'a> {
                description: &'static str,
                prover_pc: u32,
                prover_opcode: u32,
                chunk_base: u32,
                opcodes_chunk: &'a Vec<u32>,
                expected_to_succeed: bool,
            }

            let standard_chunk = vec![0x11, 0x22, 0x33, 0x44];
            let single_item_chunk = vec![0xAA];

            let test_cases = [
                // --- Success Scenarios (Challenge should succeed) ---
                TestCase {
                    description: "Success: PC is valid, but opcode is wrong.",
                    prover_pc: 0x1004,
                    prover_opcode: 0x99, // Correct is 0x22
                    chunk_base: 0x1000,
                    opcodes_chunk: &standard_chunk,
                    expected_to_succeed: true,
                },
                TestCase {
                    description: "Success: PC is at the start of the chunk, but opcode is wrong.",
                    prover_pc: 0x1000,
                    prover_opcode: 0x99, // Correct is 0x11
                    chunk_base: 0x1000,
                    opcodes_chunk: &standard_chunk,
                    expected_to_succeed: true,
                },
                TestCase {
                    description: "Success: PC is at the end of the chunk, but opcode is wrong.",
                    prover_pc: 0x100C,
                    prover_opcode: 0x99, // Correct is 0x44
                    chunk_base: 0x1000,
                    opcodes_chunk: &standard_chunk,
                    expected_to_succeed: true,
                },
                TestCase {
                    description: "Success: Single item chunk, wrong opcode.",
                    prover_pc: 0x2000,
                    prover_opcode: 0xBB, // Correct is 0xAA
                    chunk_base: 0x2000,
                    opcodes_chunk: &single_item_chunk,
                    expected_to_succeed: true,
                },
                // --- Failure Scenarios (Challenge should fail) ---
                TestCase {
                    description: "Failure: Prover is honest (PC and opcode are correct).",
                    prover_pc: 0x1008,
                    prover_opcode: 0x33,
                    chunk_base: 0x1000,
                    opcodes_chunk: &standard_chunk,
                    expected_to_succeed: false,
                },
                TestCase {
                    description: "Failure: Prover is honest at the start of the chunk.",
                    prover_pc: 0x1000,
                    prover_opcode: 0x11,
                    chunk_base: 0x1000,
                    opcodes_chunk: &standard_chunk,
                    expected_to_succeed: false,
                },
                TestCase {
                    description: "Failure: Prover is honest at the end of the chunk.",
                    prover_pc: 0x100C,
                    prover_opcode: 0x44,
                    chunk_base: 0x1000,
                    opcodes_chunk: &standard_chunk,
                    expected_to_succeed: false,
                },
                TestCase {
                    description: "Failure: PC is out of bounds (too low).",
                    prover_pc: 0x0FFC,
                    prover_opcode: 0x11,
                    chunk_base: 0x1000,
                    opcodes_chunk: &standard_chunk,
                    expected_to_succeed: false,
                },
                TestCase {
                    description: "Failure: PC is out of bounds (at the end boundary).",
                    prover_pc: 0x1010,
                    prover_opcode: 0x99,
                    chunk_base: 0x1000,
                    opcodes_chunk: &standard_chunk,
                    expected_to_succeed: false,
                },
                TestCase {
                    description: "Failure: PC is out of bounds (too high).",
                    prover_pc: 0x2000,
                    prover_opcode: 0x99,
                    chunk_base: 0x1000,
                    opcodes_chunk: &standard_chunk,
                    expected_to_succeed: false,
                },
                TestCase {
                    description: "Failure: PC is not word-aligned.",
                    prover_pc: 0x1001,
                    prover_opcode: 0x11,
                    chunk_base: 0x1000,
                    opcodes_chunk: &standard_chunk,
                    expected_to_succeed: false,
                },
                TestCase {
                    description: "Failure: Single item chunk, prover is honest.",
                    prover_pc: 0x2000,
                    prover_opcode: 0xAA,
                    chunk_base: 0x2000,
                    opcodes_chunk: &single_item_chunk,
                    expected_to_succeed: false,
                },
            ];

            for case in test_cases.iter() {
                let input = OpcodeFuzzInput {
                    pc: case.prover_pc,
                    opcode: case.prover_opcode,
                    chunk_base: case.chunk_base,
                    opcodes_chunk: case.opcodes_chunk.clone(),
                    expected_to_succeed: case.expected_to_succeed,
                };
                let result = opcode_challenge_aux(input);
                assert!(
                    result,
                    "Test failed: {}. Case: {:?}",
                    case.description, case
                );
            }
        }

        #[test]
        fn test_addresses_sections_challenge_border_cases() {
            #[derive(Debug)]
            struct TestCase<'a> {
                description: &'static str,
                read_1_address: u32,
                read_2_address: u32,
                write_address: u32,
                pc_address: u32,
                memory_witness: u8, // Corrected to u8
                read_write_sections: &'a SectionDefinition,
                read_only_sections: &'a SectionDefinition,
                register_sections: &'a SectionDefinition,
                code_sections: &'a SectionDefinition,
                expected_to_succeed: bool,
            }

            // --- Test Section Definitions ---
            // Standard sections for general tests
            let rw_std = &SectionDefinition {
                ranges: vec![(0x1000, 0x1FFF)],
            };
            let ro_std = &SectionDefinition {
                ranges: vec![(0x2000, 0x2FFF)],
            };
            let reg_std = &SectionDefinition {
                ranges: vec![(0xF000_0000, 0xF000_007F)],
            };
            let code_std = &SectionDefinition {
                ranges: vec![(0x8000_0000, 0x8000_FFFF)],
            };

            // Sections starting at address 0
            let rw_zero = &SectionDefinition {
                ranges: vec![(0x0000, 0x0FFF)],
            };
            // Sections ending at the maximum address
            let code_max = &SectionDefinition {
                ranges: vec![(0xFFFF_F000, 0xFFFF_FFFF)],
            };
            // --- Witness Definitions ---
            let valid_witness_std = MemoryWitness::new(
                MemoryAccessType::Register,
                MemoryAccessType::Memory,
                MemoryAccessType::Memory,
            )
            .byte();

            let test_cases = [
                TestCase {
                    description:
                        "Failure: All addresses and witnesses are valid in standard sections.",
                    read_1_address: 0xF000_0004, // In REG
                    read_2_address: 0x2008,      // In RO
                    write_address: 0x100C,       // In RW
                    pc_address: 0x8000_0200,     // In CODE
                    memory_witness: valid_witness_std,
                    read_write_sections: rw_std,
                    read_only_sections: ro_std,
                    register_sections: reg_std,
                    code_sections: code_std,
                    expected_to_succeed: false,
                },
                TestCase {
                    description:
                        "Success: PC address at 0x8000_0000 (potential negative) is valid.",
                    read_1_address: 0xF000_0004,
                    read_2_address: 0x2008,
                    write_address: 0x100C,
                    pc_address: 0x8000_0000, // Boundary of code section
                    memory_witness: valid_witness_std,
                    read_write_sections: rw_std,
                    read_only_sections: ro_std,
                    register_sections: reg_std,
                    code_sections: code_std,
                    expected_to_succeed: false, // This is a valid access
                },
                TestCase {
                    description:
                        "Success: Write address at 0, which is outside the defined RW section.",
                    read_1_address: 0xF000_0004,
                    read_2_address: 0x2008,
                    write_address: 0x0000, // Invalid write
                    pc_address: 0x8000_0200,
                    memory_witness: valid_witness_std,
                    read_write_sections: rw_std,
                    read_only_sections: ro_std,
                    register_sections: reg_std,
                    code_sections: code_std,
                    expected_to_succeed: true,
                },
                TestCase {
                    description: "Failure: Read from address 0, which is inside a valid section.",
                    read_1_address: 0x0000, // Valid read from rw_zero
                    read_2_address: 0x2008,
                    write_address: 0x0100,
                    pc_address: 0x8000_0200,
                    memory_witness: MemoryWitness::new(
                        MemoryAccessType::Memory,
                        MemoryAccessType::Memory,
                        MemoryAccessType::Memory,
                    )
                    .byte(),
                    read_write_sections: rw_zero,
                    read_only_sections: ro_std,
                    register_sections: reg_std,
                    code_sections: code_std,
                    expected_to_succeed: false,
                },
                TestCase {
                    description: "Success: PC at u32::MAX, inside a valid section ending at MAX, unaligned",
                    read_1_address: 0xF000_0004,
                    read_2_address: 0x2008,
                    write_address: 0x100C,
                    pc_address: 0xFFFF_FFFF, // Valid but unaligned PC at the very end of the address space
                    memory_witness: valid_witness_std,
                    read_write_sections: rw_std,
                    read_only_sections: ro_std,
                    register_sections: reg_std,
                    code_sections: code_max,
                    expected_to_succeed: true,
                },
                TestCase {
                    description: "Success: Unmapped read_1 address (underflow boundary).",
                    read_1_address: 0x0FFF, // Just before rw_std
                    read_2_address: 0x2008,
                    write_address: 0x100C,
                    pc_address: 0x8000_0200,
                    memory_witness: valid_witness_std,
                    read_write_sections: rw_std,
                    read_only_sections: ro_std,
                    register_sections: reg_std,
                    code_sections: code_std,
                    expected_to_succeed: true,
                },
                TestCase {
                    description: "Success: Unmapped write address (overflow boundary).",
                    read_1_address: 0xF000_0004,
                    read_2_address: 0x2008,
                    write_address: 0x2000, // Just at the end of rw_std
                    pc_address: 0x8000_0200,
                    memory_witness: valid_witness_std,
                    read_write_sections: rw_std,
                    read_only_sections: ro_std,
                    register_sections: reg_std,
                    code_sections: code_std,
                    expected_to_succeed: true,
                },
            ];

            for case in test_cases.iter() {
                // Convert the TestCase struct into the AddressFuzzInput struct required by the aux function.
                let input = AddressFuzzInput {
                    read_1: case.read_1_address,
                    read_2: case.read_2_address,
                    write: case.write_address,
                    pc: case.pc_address,
                    memory_witness: MemoryWitness::from_byte(case.memory_witness),
                    read_write_sections: case.read_write_sections.clone(),
                    read_only_sections: case.read_only_sections.clone(),
                    registers: case.register_sections.clone(),
                    code_sections: case.code_sections.clone(),
                    expected_to_succeed: case.expected_to_succeed,
                };

                let result = addresses_sections_challenge_aux(input);

                assert!(
                    result,
                    "Test failed: {}. Case: {:?}",
                    case.description, case
                );
            }
        }
    }
}
