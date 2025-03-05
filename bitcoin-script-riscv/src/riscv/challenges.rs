use bitcoin_script_functions::hash::blake3;
use bitcoin_script_stack::stack::StackTracker;

// TODO: Value commited in WOTS_PROVER_LAST_STEP should not be greater than the MAX_STEP_CONSTANT_VALUE
// the script should block this.

// TOOD: As the graph is presigned completely by both parts. The transaction always need something secret that can only be signed by the responsible part.
// is important if the other changes it. Probably in several transaction this is not a problem as the destination tx is the same. But in the case where choosing one leaf can lead to another part of the DAG
// then it's mandatory

// TODO: For unsinged data we still need to validate ranges for nibbles (0-15)

// If the prover executes step = 1 and entry_point != valid entry point
// the verifier can execute this equivocation and win the challenge
// [WOTS_PROVER_TRACE_PC:8 | WOTS_PROVER_TRACE_MICRO:2 | WOTS_PROVER_TRACE_STEP:16]
pub fn entry_point_challenge(stack: &mut StackTracker, entry_point: u32) {
    stack.clear_definitions();
    let provided_pc = stack.define(8, "provided_pc");
    let _provided_micro = stack.define(2, "provided_micro");
    let provided_step = stack.define(16, "provided_step");

    let step_high = stack.number_u32(0);
    stack.number_u32(1);
    stack.join(step_high);
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
// && WOTS_PROVER_TRACE_PC:8 | WOTS_PROVER_TRACE_MICRO:2 != UNSIGNED_VERIFIER_WRITE_PC_PREV | UNSIGNED_VERIFIER_WRITE_MICRO_PREV
pub fn program_counter_challenge(stack: &mut StackTracker) {
    stack.clear_definitions();

    let prev_prev_hash = stack.define(40, "prev_prev_hash");
    let prev_write_add = stack.define(8, "prev_write_add");
    let prev_write_data = stack.define(8, "prev_write_data");
    let prev_write_pc = stack.define(8, "prev_write_pc");
    let prev_write_micro = stack.define(2, "prev_write_micro");

    let prover_pc = stack.define(8, "prover_pc");
    let _prover_micro = stack.define(2, "prover_micro");
    let prev_hash = stack.define(40, "prev_hash");

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
    stack.equals(result, true, prev_hash, true);
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

//TODO: memory section challenge
//TODO: program crash challenge - this might be more about finding the right place to challenge that a challenge itself

#[cfg(test)]
mod tests {

    use super::*;

    fn test_entry_point_challenge_aux(
        wots_prover_pc: u32,
        wots_prover_micro: u32,
        wots_step_low: u32,
        entry_point_real: u32,
    ) -> bool {
        let mut stack = StackTracker::new();

        //define entrypoint in the stack
        stack.number_u32(wots_prover_pc);
        stack.byte(wots_prover_micro as u8);

        //define step in the stack
        stack.number_u32(0);
        stack.number_u32(wots_step_low);

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
}
