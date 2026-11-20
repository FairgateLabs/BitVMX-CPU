//! Adjudicating one node of a published memory multiproof.
//!
//! Under [`MemoryModel::Merkle`](bitvmx_cpu_definitions::memory_tree::MemoryModel)
//! a read is justified by a Merkle path rather than by a `last_step`
//! pointer, and the endgame has to decide whether that path is good.
//!
//! It does not check the whole path on chain.  A multiproof over the four
//! words one instruction touches carries 89 siblings at the deployed depth,
//! and recomputing all of it in Script would be absurd.  Instead the prover
//! publishes the proof *and the working it drives* -- every node the
//! verifier computes on the way to the root -- and only if a challenger
//! says one of those nodes is wrong is a single node adjudicated.  That is
//! the locally-refutable shape: the claim is published, and one check over
//! a few words of a canonical verification trace decides it.
//!
//! So the on-chain cost of the memory argument is one of these scripts,
//! paid only when a path is actually disputed.  Each is a naysayer: it
//! *succeeds* when the published working is wrong, exactly as
//! `trace_hash_challenge` succeeds when a claimed state hash is wrong.
//!
//! # Why the node hash is blake3
//!
//! Bitcoin has no `OP_CAT`, so a Merkle path cannot be checked with the
//! native `OP_SHA256`: there is no way to build a parent's preimage from
//! two children on the stack.  The hash has to be implemented in Script
//! over nibbles, as BitVMX already does for its state hash, and then the
//! binding constraint is not weight but the thousand-element stack limit.
//!
//! Measured in this crate's interpreter:
//!
//! | hash over 40 bytes | script | peak stack |
//! |--------------------|-------:|-----------:|
//! | SHA-256            | 213,758 B | **979** |
//! | blake3 -> 20 bytes |  69,872 B | **659** |
//!
//! SHA-256 peaks at 979 *before* anything else is on the stack.  A node
//! check also has to hold the claimed parent, forty nibbles, which puts it
//! at 1,019 and over the limit -- the script aborts with `StackSize` rather
//! than deciding anything.  blake3 leaves 341 elements spare, is a third of
//! the size, and emits twenty bytes natively instead of thirty-two that
//! must then be truncated.  It is also the hash BitVMX already computes in
//! Script, so the two share one set of lookup tables.
//!
//! [`SHA256_NODE_PEAK_STACK`] records the measurement that forces this.
//!
//! # Unreconciled: the Rust tree still hashes with SHA-256
//!
//! `bitvmx_cpu_definitions::memory_tree` builds the tree with SHA-256,
//! following the paper's Definition 8.1, and this module checks it with
//! blake3.  **They do not agree, and the endgame cannot work until one of
//! them moves.**  The measurement above says which way: SHA-256 cannot be
//! checked on chain at all, so the tree's hash is the thing that has to
//! change.  Nothing depends on the tree's hash except the tree itself --
//! the publication commitment keeps SHA-256, because Bitcoin's own
//! signature hash is SHA-256 and that is a different object.
//!
//! `the_rust_tree_and_this_script_do_not_yet_agree` pins the gap so that
//! it cannot be forgotten, and will start failing the moment it closes.

use bitcoin_script_functions::hash::blake3;
use bitcoin_script_stack::stack::StackTracker;

/// Nibbles in a tree node: twenty bytes.
pub const NODE_NIBBLES: u32 = 40;

/// Nibbles in a machine word: four bytes.
pub const WORD_NIBBLES: u32 = 8;

/// blake3 output words; five of them are the twenty bytes a node is.
const NODE_WORDS: u8 = 5;

/// Peak stack of the in-Script SHA-256 over a forty-byte preimage, with
/// nothing else held.  A node check must also hold the forty nibbles of the
/// claimed parent, so SHA-256 cannot be used for this at all.
pub const SHA256_NODE_PEAK_STACK: u32 = 979;

/// Bitcoin's limit on stack plus altstack during one script.
pub const STACK_LIMIT: u32 = 1000;

/// SHA-256 cannot be used for a node check at all: its peak is reached
/// before the claimed parent is accounted for, and the forty nibbles of
/// that parent put it over the limit.  A script in that state aborts with
/// `StackSize` instead of deciding anything.
const _: () = assert!(SHA256_NODE_PEAK_STACK + NODE_NIBBLES > STACK_LIMIT);

/// Refute a claimed internal node of a published multiproof's working.
///
/// Witness, bottom to top: the left child, the right child, and the node
/// claimed for their parent.  Succeeds when
/// `blake3(left || right)[0..20] != claimed`, which is what makes the
/// publisher of that working lose.
pub fn memory_node_challenge(stack: &mut StackTracker) {
    stack.clear_definitions();

    let left = stack.define(NODE_NIBBLES, "left");
    let right = stack.define(NODE_NIBBLES, "right");
    let claimed = stack.define(NODE_NIBBLES, "claimed_parent");

    stack.verify_range_var_u4(left);
    stack.verify_range_var_u4(right);
    stack.verify_range_var_u4(claimed);

    // Hold the claim aside; the hash consumes everything below it.
    stack.to_altstack();

    stack.explode(left);
    stack.explode(right);

    let computed = blake3::blake3(stack, 2 * NODE_NIBBLES / 2, NODE_WORDS);

    stack.from_altstack();
    stack.not_equal(computed, true, claimed, true);
}

/// Refute a claimed leaf of a published multiproof.
///
/// Witness, bottom to top: the four-byte word, and the node claimed for its
/// leaf.  Succeeds when `blake3(w)[0..20] != claimed`.
pub fn memory_leaf_challenge(stack: &mut StackTracker) {
    stack.clear_definitions();

    let word = stack.define(WORD_NIBBLES, "word");
    let claimed = stack.define(NODE_NIBBLES, "claimed_leaf");

    stack.verify_range_var_u4(word);
    stack.verify_range_var_u4(claimed);

    stack.to_altstack();

    stack.explode(word);

    let computed = blake3::blake3(stack, WORD_NIBBLES / 2, NODE_WORDS);

    stack.from_altstack();
    stack.not_equal(computed, true, claimed, true);
}

#[cfg(test)]
mod tests {
    use super::*;

    type Node = [u8; 20];

    /// What the script computes for an internal node.
    fn node(left: &Node, right: &Node) -> Node {
        let mut hasher = ::blake3::Hasher::new();
        hasher.update(left);
        hasher.update(right);
        let mut out = [0u8; 20];
        out.copy_from_slice(&hasher.finalize().as_bytes()[..20]);
        out
    }

    /// What the script computes for a leaf.
    fn leaf(word: u32) -> Node {
        let mut hasher = ::blake3::Hasher::new();
        hasher.update(&word.to_be_bytes());
        let mut out = [0u8; 20];
        out.copy_from_slice(&hasher.finalize().as_bytes()[..20]);
        out
    }

    /// Outcome of running a naysayer script.
    ///
    /// A refutation that lands leaves `Refuted`.  One that does not lands
    /// `Upheld`, by failing the `OP_VERIFY` inside `not_equal` -- that is
    /// the script *deciding*, and is what an honest node looks like.
    /// Anything else is the script falling over before it decided, which a
    /// test must never mistake for either answer: a script that blows the
    /// stack limit "fails" exactly like an honest node unless the reason is
    /// checked, and an earlier draft of this module did.
    #[derive(Debug, PartialEq, Eq)]
    enum Outcome {
        Refuted,
        Upheld,
        Broke(String),
    }

    fn outcome(res: bitcoin_script_stack::debugger::StepResult) -> Outcome {
        match (res.success, res.error, res.error_msg.as_str()) {
            (true, false, _) => Outcome::Refuted,
            (false, true, "Some(Verify)") => Outcome::Upheld,
            (_, _, msg) => Outcome::Broke(msg.to_string()),
        }
    }

    fn run_node(left: &Node, right: &Node, claimed: &Node) -> Outcome {
        let mut stack = StackTracker::new();
        stack.hexstr_as_nibbles(&hex::encode(left));
        stack.hexstr_as_nibbles(&hex::encode(right));
        stack.hexstr_as_nibbles(&hex::encode(claimed));
        memory_node_challenge(&mut stack);
        stack.op_true();
        outcome(stack.run())
    }

    fn run_leaf(word: u32, claimed: &Node) -> Outcome {
        let mut stack = StackTracker::new();
        stack.number_u32(word);
        stack.hexstr_as_nibbles(&hex::encode(claimed));
        memory_leaf_challenge(&mut stack);
        stack.op_true();
        outcome(stack.run())
    }

    #[test]
    fn an_honest_internal_node_cannot_be_refuted() {
        let (l, r) = (leaf(0xdead_beef), leaf(42));
        assert_eq!(
            run_node(&l, &r, &node(&l, &r)),
            Outcome::Upheld,
            "an honest node must be upheld by the script deciding, not by \
             the script breaking"
        );
    }

    #[test]
    fn a_wrong_internal_node_is_refuted() {
        let (l, r) = (leaf(0xdead_beef), leaf(42));
        let mut wrong = node(&l, &r);
        wrong[19] ^= 1;
        assert_eq!(
            run_node(&l, &r, &wrong),
            Outcome::Refuted,
            "one flipped bit"
        );

        // Order matters: a working that swaps the children is a different
        // node, and refutable.
        assert_eq!(
            run_node(&r, &l, &node(&l, &r)),
            Outcome::Refuted,
            "left and right are not interchangeable"
        );
    }

    #[test]
    fn an_honest_leaf_cannot_be_refuted() {
        for word in [0u32, 1, 42, 0xdead_beef, u32::MAX] {
            assert_eq!(run_leaf(word, &leaf(word)), Outcome::Upheld, "{word:#x}");
        }
    }

    #[test]
    fn a_wrong_leaf_is_refuted() {
        assert_eq!(run_leaf(42, &leaf(43)), Outcome::Refuted, "wrong word");
        assert_eq!(
            run_leaf(0, &node(&leaf(0), &leaf(0))),
            Outcome::Refuted,
            "an internal node passed off as a leaf"
        );
    }

    #[test]
    fn both_checks_fit_the_stack_limit() {
        let (l, r) = (leaf(1), leaf(2));
        let mut stack = StackTracker::new();
        stack.hexstr_as_nibbles(&hex::encode(l));
        stack.hexstr_as_nibbles(&hex::encode(r));
        stack.hexstr_as_nibbles(&hex::encode(node(&l, &r)));
        let before = stack.get_script().len();
        memory_node_challenge(&mut stack);
        let bytes = stack.get_script().len() - before;
        let peak = stack.get_max_stack_size();
        println!("memory_node_challenge: {bytes} script bytes, peak stack {peak}");

        assert!(peak < STACK_LIMIT, "peak {peak} must fit {STACK_LIMIT}");
        // That SHA-256 does not fit is asserted at compile time above.
        assert!(
            peak + NODE_NIBBLES < SHA256_NODE_PEAK_STACK,
            "and blake3 leaves real room: {peak} against {SHA256_NODE_PEAK_STACK}"
        );
    }

    #[test]
    fn the_rust_tree_and_this_script_do_not_yet_agree() {
        // Deliberately asserting a defect, so it is visible rather than
        // latent.  definitions::memory_tree hashes nodes with SHA-256 and
        // this module checks them with blake3; the endgame needs one hash.
        // When the tree moves to blake3 this test fails and should be
        // replaced by one that checks they agree.
        let (l, r) = (leaf(1), leaf(2));
        let sha_parent = bitvmx_cpu_definitions::memory_tree::parent(&l, &r);
        assert_ne!(
            sha_parent,
            node(&l, &r),
            "if these now match, the tree has moved to blake3 -- delete \
             this test and assert agreement instead"
        );
        assert_eq!(
            run_node(&l, &r, &sha_parent),
            Outcome::Refuted,
            "which is why an honest SHA-256 node is refuted by this script"
        );
    }

    #[test]
    fn a_whole_path_is_checked_one_node_at_a_time() {
        // Eighteen levels of an honest path: every node of the working
        // survives its own challenge, and each is one script.
        let mut current = leaf(0xcafe_babe);
        for level in 0..18u32 {
            let sibling = leaf(level);
            let parent = node(&current, &sibling);
            assert_eq!(
                run_node(&current, &sibling, &parent),
                Outcome::Upheld,
                "honest node at level {level}"
            );
            let mut wrong = parent;
            wrong[0] ^= 0x80;
            assert_eq!(
                run_node(&current, &sibling, &wrong),
                Outcome::Refuted,
                "and a wrong one at level {level}"
            );
            current = parent;
        }
    }
}

/// Sizing the scripts a dispute can put on chain.
///
/// These are measurements, not estimates: each script is built by the same
/// code the protocol builds it with, and its length read off.  What they
/// feed is the worst-case weight comparison between BitVMX as it stands and
/// the compact construction.
#[cfg(test)]
mod script_sizes {
    use crate::riscv::challenges::*;
    use crate::riscv::memory_proof::{memory_leaf_challenge, memory_node_challenge};
    use bitcoin_script_stack::stack::StackTracker;
    use bitvmx_cpu_definitions::memory_tree::MemoryModel;

    fn size(name: &str, f: impl Fn(&mut StackTracker)) -> (String, usize, u32) {
        let mut stack = StackTracker::new();
        f(&mut stack);
        (
            name.to_string(),
            stack.get_script().len(),
            stack.get_max_stack_size(),
        )
    }

    #[test]
    fn report_every_challenge_script_size() {
        let mut rows = vec![
            size("trace_hash (last_step, 33 B)", |s| {
                trace_hash_challenge(s, MemoryModel::LastStep)
            }),
            size("trace_hash (merkle, 53 B)", |s| {
                trace_hash_challenge(s, MemoryModel::Merkle)
            }),
            size("trace_hash_zero (last_step)", |s| {
                trace_hash_zero_challenge(s, MemoryModel::LastStep)
            }),
            size("trace_hash_zero (merkle)", |s| {
                trace_hash_zero_challenge(s, MemoryModel::Merkle)
            }),
            size("program_counter (last_step)", |s| {
                program_counter_challenge(s, MemoryModel::LastStep)
            }),
            size("program_counter (merkle)", |s| {
                program_counter_challenge(s, MemoryModel::Merkle)
            }),
            size("correct_hash (last_step)", |s| {
                correct_hash_challenge(s, MemoryModel::LastStep)
            }),
            size("correct_hash (merkle)", |s| {
                correct_hash_challenge(s, MemoryModel::Merkle)
            }),
            size("read_value (last_step only)", read_value_challenge),
            size("future_read (last_step only)", future_read_challenge),
            size("halt", halt_challenge),
            size("equivocation_hash", equivocation_hash_challenge),
            size("memory_node (merkle only)", memory_node_challenge),
            size("memory_leaf (merkle only)", memory_leaf_challenge),
        ];
        rows.sort_by_key(|r| std::cmp::Reverse(r.1));

        println!(
            "\n{:<32} {:>10} {:>12}",
            "challenge script", "bytes", "peak stack"
        );
        println!("{}", "-".repeat(56));
        for (name, bytes, peak) in &rows {
            println!("{name:<32} {bytes:>10} {peak:>12}");
        }
        let biggest = rows.iter().max_by_key(|r| r.1).unwrap();
        println!("\nlargest: {} at {} bytes", biggest.0, biggest.1);
        assert!(biggest.1 > 0);
    }
}
