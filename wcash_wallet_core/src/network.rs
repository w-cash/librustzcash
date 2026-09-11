//! Immutable Wcash wallet chain profiles.

use zcash_protocol::consensus::{BlockHeight, BranchId, NetworkType, NetworkUpgrade, Parameters};

/// Public ticker for valueless Wcash test funds.
pub const TEST_CURRENCY_TICKER: &str = "TWC";

const TESTNET_GENESIS_DISPLAY: &str =
    "0271b5b0a10b2838f43cccdec9ca2f72aa72a7c103830082bac8f82f47f0593a";
const REGTEST_GENESIS_DISPLAY: &str =
    "70bf0bab17eff361a6331bb825b3b7253c8c96ff96407f948161d2912658bb1c";
const COMPACT_SERVER_CHAIN_NAME: &str = "test";

const TESTNET_GENESIS_INTERNAL: [u8; 32] = [
    0x3a, 0x59, 0xf0, 0x47, 0x2f, 0xf8, 0xc8, 0xba, 0x82, 0x00, 0x83, 0x03, 0xc1, 0xa7, 0x72, 0xaa,
    0x72, 0x2f, 0xca, 0xc9, 0xde, 0xcc, 0x3c, 0xf4, 0x38, 0x28, 0x0b, 0xa1, 0xb0, 0xb5, 0x71, 0x02,
];
const REGTEST_GENESIS_INTERNAL: [u8; 32] = [
    0x1c, 0xbb, 0x58, 0x26, 0x91, 0xd2, 0x61, 0x81, 0x94, 0x7f, 0x40, 0x96, 0xff, 0x96, 0x8c, 0x3c,
    0x25, 0xb7, 0xb3, 0x25, 0xb8, 0x1b, 0x33, 0xa6, 0x61, 0xf3, 0xef, 0x17, 0xab, 0x0b, 0xbf, 0x70,
];

/// A frozen Wcash network identity supported by wallet code.
///
/// Mainnet is intentionally not a variant. This makes enabling an unfinished
/// production identity a compile-time API change rather than a configuration
/// toggle.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum WcashNetwork {
    /// Public Wcash Testnet v5.
    Testnet,
    /// Process-local Wcash Regtest v5.
    Regtest,
}

/// Value pools a Wcash wallet is permitted to create or receive.
///
/// The cumulative activation schedule required by Zcash transaction tooling
/// does not enable historical shielded pools for Wcash. Sapling and legacy
/// Orchard value components remain outside this closed capability set.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum WcashValuePool {
    /// Transparent value, including optional transparent coinbase payouts.
    Transparent,
    /// Private Ironwood value carried by the V6 Orchard receiver slot.
    Ironwood,
}

/// A Wcash genesis block identifier in internal serialization byte order.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct WcashGenesisHash([u8; 32]);

impl WcashGenesisHash {
    const fn from_internal_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns this identifier in internal serialization byte order.
    pub const fn as_internal_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl WcashNetwork {
    /// Every network whose complete wallet identity is currently frozen.
    pub const ALL: [Self; 2] = [Self::Testnet, Self::Regtest];

    /// Returns the exact network selector accepted by a Wcash node.
    pub const fn node_network_name(self) -> &'static str {
        match self {
            Self::Testnet => "WcashTestnet",
            Self::Regtest => "WcashRegtest",
        }
    }

    /// Returns the chain name currently reported by the compact-block RPC.
    ///
    /// This compatibility value is `test` for both enabled networks and is not
    /// an identity attestation. A wallet must additionally verify the genesis
    /// hash and transaction branch ID before accepting compact blocks.
    pub const fn compact_server_chain_name(self) -> &'static str {
        match self {
            Self::Testnet | Self::Regtest => COMPACT_SERVER_CHAIN_NAME,
        }
    }

    /// Returns the versioned namespace required for wallet and block-cache data.
    pub const fn storage_namespace(self) -> &'static str {
        match self {
            Self::Testnet => "wcashtestnet-v5",
            Self::Regtest => "wcashregtest-v5",
        }
    }

    /// Returns the ticker displayed for funds on this testing network.
    pub const fn currency_ticker(self) -> &'static str {
        TEST_CURRENCY_TICKER
    }

    /// Returns the frozen genesis block identifier in display byte order.
    pub const fn genesis_hash_display(self) -> &'static str {
        match self {
            Self::Testnet => TESTNET_GENESIS_DISPLAY,
            Self::Regtest => REGTEST_GENESIS_DISPLAY,
        }
    }

    /// Returns the frozen genesis block identifier in internal/serialized order.
    pub const fn genesis_hash(self) -> WcashGenesisHash {
        match self {
            Self::Testnet => WcashGenesisHash::from_internal_bytes(TESTNET_GENESIS_INTERNAL),
            Self::Regtest => WcashGenesisHash::from_internal_bytes(REGTEST_GENESIS_INTERNAL),
        }
    }

    /// Returns the transaction and signature domain active from height 1.
    pub const fn branch_id(self) -> BranchId {
        match self {
            Self::Testnet => BranchId::WcashTestnetV1,
            Self::Regtest => BranchId::WcashRegtestV1,
        }
    }

    /// Returns the height where the Ironwood transaction format activates.
    pub const fn ironwood_activation_height(self) -> BlockHeight {
        BlockHeight::from_u32(1)
    }

    /// Returns a stable discriminator used by the Wcash seed KDF.
    pub(crate) const fn seed_domain_byte(self) -> u8 {
        match self {
            Self::Testnet => 1,
            Self::Regtest => 2,
        }
    }

    /// Returns the corresponding receiver-container network.
    ///
    /// This compatibility value is private because it is not sufficient to
    /// identify a Wcash chain and must never be passed to a Zcash synchronizer.
    pub(crate) const fn receiver_network(self) -> NetworkType {
        match self {
            Self::Testnet => NetworkType::Test,
            Self::Regtest => NetworkType::Regtest,
        }
    }
}

/// Zcash-library compatibility parameters used only behind Wcash APIs.
///
/// Keeping this adapter private prevents generic Zcash address APIs from
/// accepting a public Wcash network value and silently selecting Zcash text
/// encodings.
#[derive(Clone, Copy, Debug)]
pub(crate) struct WcashConsensusParameters(WcashNetwork);

impl WcashConsensusParameters {
    /// Constructs compatibility parameters for an already selected Wcash
    /// network.
    pub(crate) const fn new(network: WcashNetwork) -> Self {
        Self(network)
    }
}

impl Parameters for WcashConsensusParameters {
    fn network_type(&self) -> NetworkType {
        self.0.receiver_network()
    }

    fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight> {
        match nu {
            NetworkUpgrade::Overwinter
            | NetworkUpgrade::Sapling
            | NetworkUpgrade::Blossom
            | NetworkUpgrade::Heartwood
            | NetworkUpgrade::Canopy
            | NetworkUpgrade::Nu5
            | NetworkUpgrade::Nu6
            | NetworkUpgrade::Nu6_1
            | NetworkUpgrade::Nu6_2
            | NetworkUpgrade::Nu6_3 => Some(self.0.ironwood_activation_height()),
            #[cfg(zcash_unstable = "nu7")]
            NetworkUpgrade::Nu7 => None,
            #[cfg(zcash_unstable = "nutachyon")]
            NetworkUpgrade::NuTachyon => None,
        }
    }

    fn branch_id_for_upgrade(&self, nu: NetworkUpgrade) -> BranchId {
        match nu {
            NetworkUpgrade::Nu6_3 => self.0.branch_id(),
            _ => nu.branch_id(),
        }
    }
}

#[cfg(test)]
mod tests {
    use static_assertions::assert_not_impl_any;

    use super::*;

    assert_not_impl_any!(WcashNetwork: Parameters);

    fn assert_genesis_byte_orders(network: WcashNetwork) {
        const GENESIS_HASH_LEN: usize = 32;

        let mut display_bytes: [u8; GENESIS_HASH_LEN] = hex::decode(network.genesis_hash_display())
            .expect("the frozen genesis ID is hexadecimal")
            .try_into()
            .expect("the frozen genesis ID is exactly 32 bytes");
        display_bytes.reverse();
        assert_eq!(network.genesis_hash().as_internal_bytes(), &display_bytes);
    }

    #[test]
    fn profiles_match_the_frozen_node_identity() {
        assert_eq!(WcashNetwork::ALL.len(), 2);
        assert_eq!(WcashNetwork::Testnet.node_network_name(), "WcashTestnet");
        assert_eq!(
            WcashNetwork::Testnet.compact_server_chain_name(),
            COMPACT_SERVER_CHAIN_NAME
        );
        assert_eq!(WcashNetwork::Testnet.storage_namespace(), "wcashtestnet-v5");
        assert_eq!(WcashNetwork::Testnet.currency_ticker(), "TWC");
        assert_eq!(
            WcashNetwork::Testnet.genesis_hash_display(),
            TESTNET_GENESIS_DISPLAY
        );
        assert_eq!(u32::from(WcashNetwork::Testnet.branch_id()), 0xb3cf_d27e);
        assert_genesis_byte_orders(WcashNetwork::Testnet);

        assert_eq!(WcashNetwork::Regtest.node_network_name(), "WcashRegtest");
        assert_eq!(
            WcashNetwork::Regtest.compact_server_chain_name(),
            COMPACT_SERVER_CHAIN_NAME
        );
        assert_eq!(WcashNetwork::Regtest.storage_namespace(), "wcashregtest-v5");
        assert_eq!(WcashNetwork::Regtest.currency_ticker(), "TWC");
        assert_eq!(
            WcashNetwork::Regtest.genesis_hash_display(),
            REGTEST_GENESIS_DISPLAY
        );
        assert_eq!(u32::from(WcashNetwork::Regtest.branch_id()), 0xc3a6_678a);
        assert_genesis_byte_orders(WcashNetwork::Regtest);
    }

    #[test]
    fn supported_profiles_are_disjoint() {
        assert_ne!(
            WcashNetwork::Testnet.node_network_name(),
            WcashNetwork::Regtest.node_network_name()
        );
        assert_ne!(
            WcashNetwork::Testnet.storage_namespace(),
            WcashNetwork::Regtest.storage_namespace()
        );
        assert_ne!(
            WcashNetwork::Testnet.genesis_hash(),
            WcashNetwork::Regtest.genesis_hash()
        );
        assert_ne!(
            WcashNetwork::Testnet.branch_id(),
            WcashNetwork::Regtest.branch_id()
        );
        assert_eq!(
            WcashNetwork::Testnet.compact_server_chain_name(),
            WcashNetwork::Regtest.compact_server_chain_name()
        );
    }

    #[test]
    fn height_one_selects_the_wcash_v6_domain() {
        for network in WcashNetwork::ALL {
            let parameters = WcashConsensusParameters::new(network);
            assert_eq!(
                BranchId::for_height(&parameters, BlockHeight::from_u32(0)),
                BranchId::Sprout
            );
            assert_eq!(
                BranchId::for_height(&parameters, network.ironwood_activation_height()),
                network.branch_id()
            );
            assert_eq!(
                parameters.activation_height(NetworkUpgrade::Sapling),
                Some(network.ironwood_activation_height())
            );
            assert_eq!(
                parameters.activation_height(NetworkUpgrade::Nu6_3),
                Some(network.ironwood_activation_height())
            );
        }
    }
}
