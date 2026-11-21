//! How a dissection reaches the chain.
//!
//! This is the second of the two setup-time choices a dispute makes about
//! its search, and it is independent of the first.  [`SearchMode`] decides
//! *who sends what and when*; the medium below decides *how the hashes a
//! stage sends are carried*, and the useful combination is full duplex
//! with a published dissection.
//!
//! [`SearchMode`]: super::nary_search::SearchMode
//!
//! The choice is what sets the branching factor.  A committed dissection
//! is read by Bitcoin Script, which means the verifier for a one-time
//! signature is written out in the witness, and a tapscript execution may
//! hold only a thousand stack elements -- eighty-eight per twenty-byte
//! digest under the deployed Winternitz parameters, so twelve hashes is
//! the ceiling whatever the fee. A *published* dissection is seen rather
//! than read: it costs no stack at all, because BIP341 strips the annex
//! before the stack the script runs on is formed, and an `OP_RETURN`
//! output is never executed either. That is what admits a branching
//! factor of 192 and four narrowing levels where the deployed protocol
//! has eight and ten.

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

/// Where a stage's dissection is carried.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PublicationMedium {
    /// One one-time commitment per hash, read by Bitcoin Script.
    ///
    /// The default, and what every existing program definition means.
    #[default]
    Committed,
    /// One FlatMerkle file per stage, in an `OP_RETURN` output.
    ///
    /// Four weight units a byte, and relayed by Bitcoin Core today.
    OpReturn,
    /// One FlatMerkle file per stage, in the Taproot annex of the stage
    /// that publishes it.
    ///
    /// One weight unit a byte. Consensus accepts it; Bitcoin Core's
    /// default policy does not relay it, so a publisher needs a peer that
    /// does.
    Annex,
}

impl PublicationMedium {
    /// Whether the dissection is published rather than committed.
    pub fn is_published(&self) -> bool {
        !matches!(self, PublicationMedium::Committed)
    }

    /// Weight units per byte of dissection.
    ///
    /// Witness data is one, non-witness four. `None` where the dissection
    /// is committed rather than published, since then the cost is the
    /// commitment scheme's and not the medium's.
    pub fn weight_per_byte(&self) -> Option<u32> {
        match self {
            PublicationMedium::Committed => None,
            PublicationMedium::Annex => Some(1),
            PublicationMedium::OpReturn => Some(4),
        }
    }

    /// Whether Bitcoin Core's default policy relays a transaction
    /// carrying this.
    ///
    /// A publisher whose dissection is not relayed can still reach a
    /// miner, so this is a liveness property and not a soundness one --
    /// but a protocol that depends on a minority relay policy has a
    /// deployment condition, and it should be visible here.
    pub fn relayed_by_default_policy(&self) -> bool {
        !matches!(self, PublicationMedium::Annex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_is_what_every_existing_definition_means() {
        assert_eq!(PublicationMedium::default(), PublicationMedium::Committed);
        assert!(!PublicationMedium::default().is_published());
        assert_eq!(PublicationMedium::default().weight_per_byte(), None);
    }

    #[test]
    fn publishing_costs_a_witness_byte_or_four_output_bytes() {
        assert_eq!(PublicationMedium::Annex.weight_per_byte(), Some(1));
        assert_eq!(PublicationMedium::OpReturn.weight_per_byte(), Some(4));
        assert!(PublicationMedium::Annex.is_published());
        assert!(PublicationMedium::OpReturn.is_published());
    }

    #[test]
    fn only_the_annex_asks_for_a_peer_that_relays_it() {
        assert!(!PublicationMedium::Annex.relayed_by_default_policy());
        assert!(PublicationMedium::OpReturn.relayed_by_default_policy());
        assert!(PublicationMedium::Committed.relayed_by_default_policy());
    }

    #[test]
    fn it_parses_from_a_program_definition_in_kebab_case() {
        // The spelling a YAML program definition uses.  `op-return`
        // rather than `op_return`, to match `full-duplex`.
        for (text, want) in [
            ("committed", PublicationMedium::Committed),
            ("op-return", PublicationMedium::OpReturn),
            ("annex", PublicationMedium::Annex),
        ] {
            let got: PublicationMedium = serde_json::from_str(&format!("\"{text}\""))
                .unwrap_or_else(|e| panic!("{text}: {e}"));
            assert_eq!(got, want);
        }
    }

    #[test]
    fn an_unknown_medium_is_rejected_rather_than_defaulted() {
        assert!(serde_json::from_str::<PublicationMedium>("\"envelope\"").is_err());
        assert!(serde_json::from_str::<PublicationMedium>("\"op_return\"").is_err());
    }
}
