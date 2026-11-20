//! Merkelized memory: the model the compact endgame adjudicates against.
//!
//! Memory is a sparse binary Merkle tree over four-byte machine words.  A
//! leaf is `SHA256(w)[0..20]` for the word's contents `w`, an internal node
//! is `SHA256(left || right)[0..20]`, and the hash of an all-zero subtree is
//! precomputed per level so that untouched memory costs nothing.
//!
//! What this replaces is the `last_step` scheme: there, a read carried the
//! number of the step that last wrote its address, and a challenger who
//! disputed the claim opened a second search to that step.  Here a read
//! carries a Merkle path instead, and the dispute is a hash check against a
//! root the machine state already commits to.  Six challenge branches --
//! `FutureRead`, `ReadValue`, `ReadSection`, `WriteSection`, `Uninitialized`
//! and `Initialized` -- are statements about that scheme and have no
//! counterpart here.
//!
//! # Depth is a parameter, and the deployed depth is 30
//!
//! The depth fixes how much memory the tree can address, and BitVMX spreads
//! its address space across the whole 32-bit range: the register file sits
//! at `0xF000_0000` and the stack at `0xE000_0000` with eight megabytes
//! under it (`emulator/src/lib.rs`).  A tree over a contiguous megabyte
//! cannot hold that map -- it cannot address the registers at all -- so
//! [`DEPLOYED_DEPTH`] is `30`, one leaf per word of the full address space.
//!
//! [`PAPER_DEPTH`] is the shallower tree the paper measures, over a
//! megabyte, and is kept because it is what the published figures are
//! quoted at.  The construction is identical at either; only the path
//! lengths differ, and [`MemoryTree::new`] takes the depth so that both are
//! reachable and comparable.
//!
//! # What one instruction touches
//!
//! At most four distinct words.  The machine rejects unaligned reads, writes
//! and jumps, so no access straddles a leaf; and RISC-V is load/store, so no
//! instruction both touches memory and names three registers:
//!
//! | instruction | touches                       | words   |
//! |-------------|-------------------------------|---------|
//! | R-type ALU  | fetch, and `rs1`, `rs2`, `rd` | `1 + 3` |
//! | load        | fetch, data, `rs1`, `rd`      | `1+1+2` |
//! | store       | fetch, data, `rs1`, `rs2`     | `1+1+2` |
//!
//! Four either way, which is what [`MAX_TOUCHED`] records.  Three of them
//! always lie in the register block, so they share all but a few levels --
//! which is why a multiproof over the worst reachable pattern carries far
//! fewer nodes than four independent paths would.

use std::collections::{BTreeSet, HashMap};
use std::sync::OnceLock;

use bitcoin_hashes::{sha256, Hash};
use serde::{Deserialize, Serialize};

/// How a dispute justifies that a read returned the value it claims.
///
/// These are alternatives, not layers: a trace carries one or the other.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryModel {
    /// A read names the step that last wrote its address, and disputing
    /// that claim opens a second search to that step.  This is BitVMX's
    /// original scheme and remains the default, so an existing program
    /// definition means exactly what it meant before.
    #[default]
    LastStep,
    /// A read is opened against a Merkle root that the machine state hash
    /// commits to.  The compact endgame's model: one hash check against a
    /// root, and no second search.
    Merkle,
}

impl MemoryModel {
    /// Whether the machine state hash chains the memory root.
    pub fn chains_root(&self) -> bool {
        matches!(self, MemoryModel::Merkle)
    }
}

/// Depth of the deployed tree: one leaf per word of the 32-bit address
/// space, which is the only depth that can hold BitVMX's memory map.
pub const DEPLOYED_DEPTH: u8 = 30;

/// Depth of the tree the paper measures: `2^18` words over `2^20` bytes.
pub const PAPER_DEPTH: u8 = 18;

/// The deepest tree this module builds tables for.
pub const MAX_DEPTH: u8 = 32;

/// Width of a node, in bytes. Twenty, matching the machine state hash.
pub const NODE_BYTES: usize = 20;

/// The most distinct words one instruction can touch.
pub const MAX_TOUCHED: usize = 4;

/// A truncated SHA-256 digest.
pub type Node = [u8; NODE_BYTES];

fn truncate(h: sha256::Hash) -> Node {
    let mut out = [0u8; NODE_BYTES];
    out.copy_from_slice(&h.to_byte_array()[..NODE_BYTES]);
    out
}

/// The leaf for a word's contents: `SHA256(w)[0..20]`, big-endian.
pub fn leaf(word: u32) -> Node {
    truncate(sha256::Hash::hash(&word.to_be_bytes()))
}

/// An internal node: `SHA256(left || right)[0..20]`.
pub fn parent(left: &Node, right: &Node) -> Node {
    let mut buf = [0u8; 2 * NODE_BYTES];
    buf[..NODE_BYTES].copy_from_slice(left);
    buf[NODE_BYTES..].copy_from_slice(right);
    truncate(sha256::Hash::hash(&buf))
}

/// The node of an all-zero subtree, by level: `0` is a leaf holding the zero
/// word, and level `d` is the root of empty memory in a tree of depth `d`.
pub fn empty_node(level: u8) -> Node {
    static TABLE: OnceLock<Vec<Node>> = OnceLock::new();
    let table = TABLE.get_or_init(|| {
        let mut v = vec![leaf(0)];
        for _ in 0..MAX_DEPTH {
            let last = *v.last().expect("seeded above");
            v.push(parent(&last, &last));
        }
        v
    });
    table[level as usize]
}

/// The root of memory in which every word is zero, in a tree of `depth`.
pub fn empty_root(depth: u8) -> Node {
    empty_node(depth)
}

/// The leaf index a byte address maps to. Addresses are word-aligned, and
/// the machine rejects any that is not.
pub fn leaf_index(address: u32) -> u32 {
    address / 4
}

/// A sparse Merkle tree over `2^depth` four-byte words.
///
/// Only words that differ from zero, and the nodes above them, are stored,
/// so empty memory is free and a write costs `depth` compressions.
#[derive(Clone, Debug)]
pub struct MemoryTree {
    depth: u8,
    /// Level `0` is the leaves, level `depth` the root; entries equal to
    /// [`empty_node`] of their level are kept out.
    nodes: HashMap<(u8, u32), Node>,
    words: HashMap<u32, u32>,
}

impl Default for MemoryTree {
    fn default() -> Self {
        Self::new(DEPLOYED_DEPTH)
    }
}

impl MemoryTree {
    /// Empty memory in a tree of the given depth.
    pub fn new(depth: u8) -> Self {
        assert!(
            depth > 0 && depth <= MAX_DEPTH,
            "depth {depth} outside 1..={MAX_DEPTH}"
        );
        Self {
            depth,
            nodes: HashMap::new(),
            words: HashMap::new(),
        }
    }

    /// Memory with the given words set, the rest zero.
    pub fn with_words<I: IntoIterator<Item = (u32, u32)>>(depth: u8, words: I) -> Self {
        let mut tree = Self::new(depth);
        for (index, word) in words {
            tree.write(index, word);
        }
        tree
    }

    /// The tree's depth.
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// How many words the tree addresses.
    pub fn word_count(&self) -> u64 {
        1u64 << self.depth
    }

    /// The node at `level` and `index`, which is the empty node of that
    /// level when nothing below it has been written.
    pub fn node(&self, level: u8, index: u32) -> Node {
        self.nodes
            .get(&(level, index))
            .copied()
            .unwrap_or_else(|| empty_node(level))
    }

    /// The root of memory as it stands.
    pub fn root(&self) -> Node {
        self.node(self.depth, 0)
    }

    /// The word at `index`, zero if never written.
    pub fn read(&self, index: u32) -> u32 {
        debug_assert!(
            (index as u64) < self.word_count(),
            "word index out of range"
        );
        self.words.get(&index).copied().unwrap_or(0)
    }

    /// Set the word at `index` and update the path above it.
    pub fn write(&mut self, index: u32, word: u32) {
        assert!(
            (index as u64) < self.word_count(),
            "word index {index} outside a depth-{} tree",
            self.depth
        );
        if word == 0 {
            self.words.remove(&index);
        } else {
            self.words.insert(index, word);
        }
        self.set(0, index, leaf(word));
        let mut i = index;
        for level in 0..self.depth {
            let (l, r) = (i & !1, i | 1);
            let node = parent(&self.node(level, l), &self.node(level, r));
            i >>= 1;
            self.set(level + 1, i, node);
        }
    }

    /// Set many words at once, rebuilding each affected level once instead
    /// of walking a full path per word.
    ///
    /// Loading an ELF writes every initialised word of every section, and
    /// those words are contiguous, so they share almost all of their
    /// ancestors.  Updating them one at a time costs `depth` compressions
    /// each; doing it by level costs one per distinct node actually
    /// affected, which for a contiguous run is close to the size of the run
    /// rather than `depth` times it.
    pub fn bulk_write<I: IntoIterator<Item = (u32, u32)>>(&mut self, items: I) {
        let mut touched: BTreeSet<u32> = BTreeSet::new();
        for (index, word) in items {
            assert!(
                (index as u64) < self.word_count(),
                "word index {index} outside a depth-{} tree",
                self.depth
            );
            if word == 0 {
                self.words.remove(&index);
            } else {
                self.words.insert(index, word);
            }
            self.set(0, index, leaf(word));
            touched.insert(index);
        }
        for level in 0..self.depth {
            let parents: BTreeSet<u32> = touched.iter().map(|&i| i >> 1).collect();
            for &j in parents.iter() {
                let node = parent(&self.node(level, 2 * j), &self.node(level, 2 * j + 1));
                self.set(level + 1, j, node);
            }
            touched = parents;
        }
    }

    fn set(&mut self, level: u8, index: u32, node: Node) {
        if node == empty_node(level) {
            self.nodes.remove(&(level, index));
        } else {
            self.nodes.insert((level, index), node);
        }
    }

    /// The sibling path authenticating one leaf, leaf-first.
    pub fn path(&self, index: u32) -> Vec<Node> {
        let mut out = Vec::with_capacity(self.depth as usize);
        let mut i = index;
        for level in 0..self.depth {
            out.push(self.node(level, i ^ 1));
            i >>= 1;
        }
        out
    }

    /// The nodes a multiproof over `leaves` must carry: every sibling on a
    /// path that is not itself derivable from the revealed leaves.
    ///
    /// Returned bottom-up, and within a level in ascending index order,
    /// which is the order [`MultiProof::compute_root`] consumes them in.
    pub fn authenticated_set(&self, leaves: &[u32]) -> Vec<(u8, u32)> {
        let mut needed = Vec::new();
        walk(leaves, self.depth, |level, index, derivable| {
            if !derivable {
                needed.push((level, index));
            }
        });
        needed
    }

    /// The nodes a verifier *computes* while checking a multiproof: every
    /// strict ancestor of a revealed leaf, the root included.
    ///
    /// These are the verification trace.  The authenticated set is the
    /// verifier's input and this is its working, and publishing only the
    /// former leaves a failed step of the latter with nothing committed to
    /// be refuted against.
    pub fn derived_set(&self, leaves: &[u32]) -> Vec<(u8, u32)> {
        let mut frontier: BTreeSet<(u8, u32)> = leaves.iter().map(|&i| (0u8, i)).collect();
        let mut derived = Vec::new();
        for level in 0..self.depth {
            let next: BTreeSet<(u8, u32)> =
                frontier.iter().map(|&(_, j)| (level + 1, j >> 1)).collect();
            derived.extend(next.iter().copied());
            frontier = next;
        }
        derived
    }

    /// A multiproof over the given leaves, with their current contents.
    pub fn multiproof(&self, leaves: &[u32]) -> MultiProof {
        let mut sorted: Vec<u32> = leaves.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        let siblings = self
            .authenticated_set(&sorted)
            .into_iter()
            .map(|(level, index)| self.node(level, index))
            .collect();
        MultiProof {
            depth: self.depth,
            leaves: sorted.iter().map(|&i| (i, self.read(i))).collect(),
            siblings,
        }
    }
}

/// Walk the tree bottom-up over the ancestors of `leaves`, reporting each
/// sibling encountered and whether it is derivable from what is already
/// known.  Siblings are visited bottom-up and, within a level, in ascending
/// index order.
fn walk<F: FnMut(u8, u32, bool)>(leaves: &[u32], depth: u8, mut visit: F) {
    let mut known: BTreeSet<(u8, u32)> = leaves.iter().map(|&i| (0u8, i)).collect();
    let mut frontier: BTreeSet<(u8, u32)> = known.clone();
    for level in 0..depth {
        for &(_, j) in frontier.iter() {
            visit(level, j ^ 1, known.contains(&(level, j ^ 1)));
        }
        let next: BTreeSet<(u8, u32)> =
            frontier.iter().map(|&(_, j)| (level + 1, j >> 1)).collect();
        known.extend(next.iter().copied());
        frontier = next;
    }
}

/// A multiproof: the revealed words, and the sibling nodes needed to carry
/// them to a root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultiProof {
    /// Depth of the tree the proof was taken from.
    pub depth: u8,
    /// Revealed leaves as `(index, word)`, ascending and deduplicated.
    pub leaves: Vec<(u32, u32)>,
    /// Siblings in the order [`MemoryTree::authenticated_set`] produces them.
    pub siblings: Vec<Node>,
}

impl MultiProof {
    /// Bytes on the wire: the siblings alone.
    pub fn proof_bytes(&self) -> usize {
        self.siblings.len() * NODE_BYTES
    }

    /// Recompute the root this proof implies, with `overrides` replacing the
    /// contents of the named leaves.  Passing an empty slice gives the
    /// pre-state root; passing the instruction's write gives the post-state
    /// root, because a write changes exactly one leaf and leaves every
    /// sibling on its path alone.
    pub fn compute_root(&self, overrides: &[(u32, u32)]) -> Option<Node> {
        let indices: Vec<u32> = self.leaves.iter().map(|&(i, _)| i).collect();
        let mut current: HashMap<(u8, u32), Node> = self
            .leaves
            .iter()
            .map(|&(i, w)| {
                let word = overrides
                    .iter()
                    .find(|&&(oi, _)| oi == i)
                    .map(|&(_, ow)| ow)
                    .unwrap_or(w);
                ((0u8, i), leaf(word))
            })
            .collect();

        let mut supplied = self.siblings.iter();
        let mut failed = false;
        let mut pending: Vec<(u8, u32, Node)> = Vec::new();
        walk(&indices, self.depth, |level, index, derivable| {
            if failed || derivable {
                return;
            }
            match supplied.next() {
                Some(node) => pending.push((level, index, *node)),
                None => failed = true,
            }
        });
        if failed || supplied.next().is_some() {
            return None;
        }
        for (level, index, node) in pending {
            current.entry((level, index)).or_insert(node);
        }

        let mut frontier: BTreeSet<(u8, u32)> = indices.iter().map(|&i| (0u8, i)).collect();
        for level in 0..self.depth {
            let next: BTreeSet<(u8, u32)> =
                frontier.iter().map(|&(_, j)| (level + 1, j >> 1)).collect();
            for &(_, j) in next.iter() {
                let left = *current.get(&(level, 2 * j))?;
                let right = *current.get(&(level, 2 * j + 1))?;
                current.insert((level + 1, j), parent(&left, &right));
            }
            frontier = next;
        }
        current.get(&(self.depth, 0)).copied()
    }
}

/// Check a single leaf against a root.
pub fn verify_path(root: &Node, index: u32, word: u32, path: &[Node]) -> bool {
    let mut current = leaf(word);
    let mut i = index;
    for sibling in path {
        current = if i & 1 == 1 {
            parent(sibling, &current)
        } else {
            parent(&current, sibling)
        };
        i >>= 1;
    }
    current == *root
}

/// Check a multiproof against a root.
pub fn verify_multiproof(root: &Node, proof: &MultiProof) -> bool {
    proof.compute_root(&[]).is_some_and(|r| r == *root)
}

/// Check one instruction's memory accesses: the reads against the pre-state
/// root, and the single write against the post-state root, from one proof.
///
/// The write's leaf must be among the proof's leaves; a write changes
/// exactly that leaf, so the same siblings carry both roots.
pub fn verify_step(
    pre_root: &Node,
    post_root: &Node,
    proof: &MultiProof,
    write: Option<(u32, u32)>,
) -> bool {
    if proof.compute_root(&[]) != Some(*pre_root) {
        return false;
    }
    match write {
        None => pre_root == post_root,
        Some((index, word)) => {
            proof.leaves.iter().any(|&(i, _)| i == index)
                && proof.compute_root(&[(index, word)]) == Some(*post_root)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pattern the paper's model maximises the multiproof over at
    /// [`PAPER_DEPTH`]: a fetch word, a data word, and two register words at
    /// opposite ends of the 32-leaf register block.
    const PAPER_WORST: [u32; 4] = [0, 31, 65_536, 196_607];

    /// BitVMX's memory map, from `emulator/src/lib.rs`.  These are the
    /// constants that decide the depth.
    const REGISTERS_BASE_ADDRESS: u32 = 0xF000_0000;
    const STACK_BASE_ADDRESS: u32 = 0xE000_0000;
    const STACK_SIZE: u32 = 0x80_0000;

    #[test]
    fn a_leaf_is_the_word_not_the_slot() {
        let expect = sha256::Hash::hash(&[0u8; 4]);
        assert_eq!(leaf(0), truncate(expect));
        assert_eq!(empty_node(0), leaf(0));
        assert_ne!(
            leaf(0),
            truncate(sha256::Hash::hash(&[0u8; 32])),
            "the empty leaf is a zero word, not a zero 32-byte slot"
        );
    }

    #[test]
    fn the_deployed_depth_is_what_bitvmx_s_memory_map_forces() {
        // The register file and the stack sit near the top of the address
        // space, so a tree over a contiguous megabyte cannot address them.
        let tree = MemoryTree::new(DEPLOYED_DEPTH);
        for address in [
            REGISTERS_BASE_ADDRESS,
            STACK_BASE_ADDRESS,
            STACK_BASE_ADDRESS + STACK_SIZE - 4,
            u32::MAX - 3,
        ] {
            assert!(
                (leaf_index(address) as u64) < tree.word_count(),
                "depth {DEPLOYED_DEPTH} must address {address:#x}"
            );
        }
        let paper = MemoryTree::new(PAPER_DEPTH);
        assert!(
            (leaf_index(REGISTERS_BASE_ADDRESS) as u64) >= paper.word_count(),
            "and depth {PAPER_DEPTH} cannot address the register file at all"
        );
        assert!(
            (STACK_SIZE / 4) as u64 > paper.word_count(),
            "the 8 MB stack alone is larger than the whole depth-{PAPER_DEPTH} tree"
        );
        assert_eq!(DEPLOYED_DEPTH, 30);
        assert_eq!(
            1u64 << DEPLOYED_DEPTH,
            (1u64 << 32) / 4,
            "one leaf per word"
        );
    }

    #[test]
    fn empty_memory_has_a_root_and_writing_zero_keeps_it() {
        for depth in [PAPER_DEPTH, DEPLOYED_DEPTH] {
            let mut tree = MemoryTree::new(depth);
            let empty = tree.root();
            assert_eq!(empty, empty_root(depth));
            tree.write(12_345, 0);
            assert_eq!(tree.root(), empty, "writing zero is not a change");
            tree.write(12_345, 7);
            assert_ne!(tree.root(), empty);
            tree.write(12_345, 0);
            assert_eq!(tree.root(), empty, "and undoing it restores the root");
        }
    }

    #[test]
    fn depth_fixes_how_much_memory_is_addressable() {
        assert_eq!(MemoryTree::new(PAPER_DEPTH).word_count(), 262_144);
        assert_eq!(MemoryTree::new(PAPER_DEPTH).word_count() * 4, 1 << 20);
        assert_eq!(MemoryTree::new(DEPLOYED_DEPTH).word_count() * 4, 1 << 32);
        assert_eq!(MemoryTree::default().depth(), DEPLOYED_DEPTH);
    }

    #[test]
    fn a_path_authenticates_its_leaf_and_nothing_else() {
        let mut tree = MemoryTree::with_words(
            DEPLOYED_DEPTH,
            [
                (3, 0xdead_beef),
                (100, 1),
                (leaf_index(REGISTERS_BASE_ADDRESS), 9),
            ],
        );
        tree.write(leaf_index(STACK_BASE_ADDRESS), 0x4142_4344);
        let root = tree.root();
        for &i in &[
            3u32,
            100,
            leaf_index(REGISTERS_BASE_ADDRESS),
            leaf_index(STACK_BASE_ADDRESS),
            12_345,
        ] {
            let path = tree.path(i);
            assert_eq!(path.len(), DEPLOYED_DEPTH as usize);
            assert!(verify_path(&root, i, tree.read(i), &path), "leaf {i}");
            assert!(
                !verify_path(&root, i, tree.read(i).wrapping_add(1), &path),
                "a different word must not verify at {i}"
            );
        }
    }

    #[test]
    fn at_the_paper_s_depth_the_worst_case_is_fifty_two_siblings() {
        // compact2/python/memory.py: word_worst_case() -> [0, 31, 65536,
        // 196607], word_worst_case_bytes() -> 1040, trace 2140.
        let tree = MemoryTree::new(PAPER_DEPTH);
        let needed = tree.authenticated_set(&PAPER_WORST);
        assert_eq!(needed.len(), 52, "siblings");
        assert_eq!(needed.len() * NODE_BYTES, 1_040, "bytes on the wire");

        let derived = tree.derived_set(&PAPER_WORST);
        assert_eq!(derived.len(), 55, "nodes the verifier computes");
        assert_eq!(derived.len() * NODE_BYTES, 1_100, "the working alone");
        assert_eq!((needed.len() + derived.len()) * NODE_BYTES, 2_140);
    }

    #[test]
    fn at_the_deployed_depth_a_real_instruction_costs_more_but_publishes_the_same() {
        // A store: instruction fetch, a stack word, and two registers.  The
        // three register words share all but a few levels, which is why four
        // leaves cost far less than four independent paths.
        let tree = MemoryTree::new(DEPLOYED_DEPTH);
        let reg = leaf_index(REGISTERS_BASE_ADDRESS);
        let shape = [1u32, 0x1FFF_FFFF, reg, reg + 33];
        let proof = tree.authenticated_set(&shape).len();
        let derived = tree.derived_set(&shape).len();
        assert_eq!(proof, 89, "siblings at depth 30");
        assert_eq!(proof * NODE_BYTES, 1_780);
        assert_eq!(derived, 92);
        assert_eq!((proof + derived) * NODE_BYTES, 3_620, "the published trace");

        // What is published is a FlatMerkle file: 20-byte nodes packed three
        // to a 64-byte element, rounded up to a power of two, at least four.
        let elements = |nodes: usize| -> usize {
            let n = usize::max(4, nodes.div_ceil(3));
            n.next_power_of_two()
        };
        assert_eq!(elements(52 + 55), 64, "the paper's tree");
        assert_eq!(elements(proof + derived), 64, "and the deployed one");
        assert_eq!(
            64 * (2 * 64 - 2) + 64,
            8_128,
            "so the endgame publishes 8,128 bytes either way"
        );
        assert!(
            proof + derived <= 64 * 3,
            "with {} nodes of margin",
            64 * 3 - (proof + derived)
        );
        assert_eq!(64 * 3 - (proof + derived), 11, "the margin, exactly");
    }

    #[test]
    fn four_leaves_is_the_most_one_instruction_touches() {
        assert_eq!(MAX_TOUCHED, 4);
        assert_eq!(PAPER_WORST.len(), MAX_TOUCHED);
    }

    #[test]
    fn a_multiproof_round_trips_at_both_depths() {
        for (depth, shape) in [
            (PAPER_DEPTH, PAPER_WORST),
            (
                DEPLOYED_DEPTH,
                [1u32, 0x1FFF_FFFF, 0x3C00_0000, 0x3C00_0021],
            ),
        ] {
            let mut tree = MemoryTree::new(depth);
            for (i, w) in shape.iter().zip([11u32, 22, 33, 44]) {
                tree.write(*i, w);
            }
            tree.write(999, 0xffff_ffff);
            let root = tree.root();
            let proof = tree.multiproof(&shape);
            assert_eq!(proof.depth, depth);
            assert_eq!(proof.leaves.len(), 4);
            assert!(verify_multiproof(&root, &proof), "depth {depth}");
        }
    }

    #[test]
    fn a_multiproof_beats_the_separate_paths_it_replaces() {
        let tree = MemoryTree::with_words(
            PAPER_DEPTH,
            PAPER_WORST.iter().copied().zip([1u32, 2, 3, 4]),
        );
        let root = tree.root();
        let proof = tree.multiproof(&PAPER_WORST);
        assert!(verify_multiproof(&root, &proof));
        let separate: usize = PAPER_WORST.iter().map(|&i| tree.path(i).len()).sum();
        assert_eq!(separate, 72, "four paths of eighteen");
        assert_eq!(proof.siblings.len(), 52, "against one multiproof");
    }

    #[test]
    fn a_tampered_multiproof_does_not_verify() {
        let tree = MemoryTree::with_words(
            PAPER_DEPTH,
            PAPER_WORST.iter().copied().zip([1u32, 2, 3, 4]),
        );
        let root = tree.root();

        let mut wrong_word = tree.multiproof(&PAPER_WORST);
        wrong_word.leaves[1].1 ^= 1;
        assert!(!verify_multiproof(&root, &wrong_word));

        let mut wrong_sibling = tree.multiproof(&PAPER_WORST);
        wrong_sibling.siblings[17][0] ^= 1;
        assert!(!verify_multiproof(&root, &wrong_sibling));

        let mut short = tree.multiproof(&PAPER_WORST);
        short.siblings.pop();
        assert!(!verify_multiproof(&root, &short), "too few siblings");
        assert_eq!(short.compute_root(&[]), None);

        let mut long = tree.multiproof(&PAPER_WORST);
        long.siblings.push([0u8; NODE_BYTES]);
        assert!(!verify_multiproof(&root, &long), "too many siblings");

        let mut wrong_depth = tree.multiproof(&PAPER_WORST);
        wrong_depth.depth = DEPLOYED_DEPTH;
        assert!(
            !verify_multiproof(&root, &wrong_depth),
            "a proof does not carry across depths"
        );
    }

    #[test]
    fn adjacent_leaves_need_no_siblings_between_them() {
        let tree = MemoryTree::with_words(PAPER_DEPTH, [(10, 1), (11, 2)]);
        assert_eq!(
            tree.authenticated_set(&[10]).len(),
            PAPER_DEPTH as usize,
            "one leaf needs a full path"
        );
        assert_eq!(
            tree.authenticated_set(&[10, 11]).len(),
            PAPER_DEPTH as usize - 1,
            "a sibling pair derives its parent and saves the bottom node"
        );
    }

    #[test]
    fn one_proof_carries_both_roots_of_a_write() {
        let mut tree = MemoryTree::with_words(
            DEPLOYED_DEPTH,
            [(1, 1), (0x1FFF_FFFF, 2), (0x3C00_0000, 3), (0x3C00_0021, 4)],
        );
        let shape = [1u32, 0x1FFF_FFFF, 0x3C00_0000, 0x3C00_0021];
        let pre_root = tree.root();
        let proof = tree.multiproof(&shape);

        let (written, new_word) = (0x3C00_0021u32, 0xcafe_babe);
        tree.write(written, new_word);
        let post_root = tree.root();
        assert_ne!(pre_root, post_root);

        assert_eq!(proof.compute_root(&[]), Some(pre_root));
        assert_eq!(proof.compute_root(&[(written, new_word)]), Some(post_root));
        assert!(verify_step(
            &pre_root,
            &post_root,
            &proof,
            Some((written, new_word))
        ));
        assert_eq!(
            proof.siblings.len(),
            89,
            "and it is one set of siblings, not two"
        );
    }

    #[test]
    fn verify_step_rejects_a_mismatched_write() {
        let mut tree = MemoryTree::with_words(
            PAPER_DEPTH,
            PAPER_WORST.iter().copied().zip([1u32, 2, 3, 4]),
        );
        let pre_root = tree.root();
        let proof = tree.multiproof(&PAPER_WORST);
        tree.write(31, 0xcafe_babe);
        let post_root = tree.root();

        assert!(!verify_step(&pre_root, &post_root, &proof, Some((31, 0))));
        assert!(
            !verify_step(&pre_root, &post_root, &proof, None),
            "claiming no write when the roots differ"
        );
        assert!(
            !verify_step(&pre_root, &post_root, &proof, Some((12_345, 1))),
            "the written leaf must be one the proof carries"
        );
        assert!(
            verify_step(&pre_root, &pre_root, &proof, None),
            "an instruction that writes nothing leaves the root alone"
        );
    }

    #[test]
    fn the_root_does_not_depend_on_the_order_of_writes() {
        let a = MemoryTree::with_words(DEPLOYED_DEPTH, [(5, 1), (1_000, 2), (70_000, 3)]);
        let b = MemoryTree::with_words(DEPLOYED_DEPTH, [(70_000, 3), (5, 1), (1_000, 2)]);
        assert_eq!(a.root(), b.root());

        let mut c = MemoryTree::new(DEPLOYED_DEPTH);
        c.write(5, 99);
        c.write(1_000, 2);
        c.write(5, 1);
        c.write(70_000, 3);
        assert_eq!(c.root(), a.root(), "and overwriting leaves no trace");
    }

    #[test]
    #[should_panic(expected = "outside a depth-18 tree")]
    fn a_write_past_the_end_of_the_tree_is_refused() {
        MemoryTree::new(PAPER_DEPTH).write(1 << PAPER_DEPTH, 1);
    }
}

/// Vectors computed by the paper's independent model, `compact2/python/
/// memory.py`, which builds the same tree from a different implementation in
/// a different language.  Agreement on concrete bytes is what makes the two
/// the same specification rather than two constructions of the same shape.
#[cfg(test)]
mod cross_check {
    use super::*;

    fn hex(node: &Node) -> String {
        node.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn the_zero_leaf_matches_the_model() {
        assert_eq!(hex(&leaf(0)), "df3f619804a92fdb4057192dc43dd748ea778adc");
    }

    #[test]
    fn the_empty_root_matches_the_model() {
        assert_eq!(
            hex(&empty_root(PAPER_DEPTH)),
            "bac77725f5cfaa5386da6723865ec4b4f0be00b5"
        );
    }

    #[test]
    fn a_populated_root_matches_the_model() {
        let tree = MemoryTree::with_words(
            PAPER_DEPTH,
            [(0, 11), (31, 22), (65_536, 33), (196_607, 44)],
        );
        assert_eq!(
            hex(&tree.root()),
            "6f3f7354099b983e93c611cbc5dcd9a594e2609d"
        );
    }

    #[test]
    fn a_post_write_root_matches_the_model() {
        let mut tree = MemoryTree::with_words(
            PAPER_DEPTH,
            [(0, 11), (31, 22), (65_536, 33), (196_607, 44)],
        );
        let proof = tree.multiproof(&[0, 31, 65_536, 196_607]);
        tree.write(31, 0xcafe_babe);
        assert_eq!(
            hex(&tree.root()),
            "4a8bd32caa72513360aaeae9994e4a540358a327"
        );
        assert_eq!(
            proof.compute_root(&[(31, 0xcafe_babe)]).map(|r| hex(&r)),
            Some("4a8bd32caa72513360aaeae9994e4a540358a327".to_string())
        );
    }
}

#[cfg(test)]
mod bulk_tests {
    use super::*;

    #[test]
    fn bulk_write_agrees_with_writing_one_at_a_time() {
        let items: Vec<(u32, u32)> = (0..500u32)
            .map(|i| (i, i.wrapping_mul(2_654_435_761)))
            .collect();
        let mut one_by_one = MemoryTree::new(DEPLOYED_DEPTH);
        for &(i, w) in &items {
            one_by_one.write(i, w);
        }
        let mut bulk = MemoryTree::new(DEPLOYED_DEPTH);
        bulk.bulk_write(items.iter().copied());
        assert_eq!(bulk.root(), one_by_one.root());
        for &(i, w) in &items {
            assert_eq!(bulk.read(i), w);
        }
    }

    #[test]
    fn bulk_write_handles_scattered_sections_and_zeros() {
        // Three runs far apart, as a loaded ELF leaves them: code low, data
        // in the middle, registers at the top of the address space.
        let mut items: Vec<(u32, u32)> = Vec::new();
        for base in [0x0000_0400u32, 0x0004_0000, 0x3C00_0000] {
            for k in 0..64u32 {
                items.push((base + k, if k % 7 == 0 { 0 } else { base ^ k }));
            }
        }
        let mut one_by_one = MemoryTree::new(DEPLOYED_DEPTH);
        for &(i, w) in &items {
            one_by_one.write(i, w);
        }
        let mut bulk = MemoryTree::new(DEPLOYED_DEPTH);
        bulk.bulk_write(items.iter().copied());
        assert_eq!(bulk.root(), one_by_one.root());

        // And a proof taken from the bulk-built tree verifies against it.
        let shape = [0x0000_0400u32, 0x0004_0000, 0x3C00_0000, 0x3C00_0001];
        let proof = bulk.multiproof(&shape);
        assert!(verify_multiproof(&bulk.root(), &proof));
    }

    #[test]
    fn bulk_write_is_incremental() {
        let mut tree = MemoryTree::new(DEPLOYED_DEPTH);
        tree.bulk_write([(1u32, 10u32), (2, 20)]);
        let after_first = tree.root();
        tree.bulk_write([(3u32, 30u32)]);
        let mut expected = MemoryTree::new(DEPLOYED_DEPTH);
        expected.bulk_write([(1u32, 10u32), (2, 20), (3, 30)]);
        assert_eq!(tree.root(), expected.root());
        assert_ne!(after_first, tree.root());
    }
}
