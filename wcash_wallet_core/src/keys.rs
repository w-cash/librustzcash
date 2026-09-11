//! Wcash-only wallet key derivation.

use std::fmt;

use orchard::keys::{FullViewingKey as IronwoodFullViewingKey, SpendingKey as IronwoodSpendingKey};
use secrecy::{ExposeSecret, SecretVec};
use thiserror::Error;
use zcash_protocol::consensus::NetworkConstants;
use zcash_transparent::keys::{AccountPrivKey, AccountPubKey};
use zip32::AccountId;

use crate::network::{WcashConsensusParameters, WcashNetwork};

#[cfg(feature = "ironwood-scanning")]
use {crate::scanning::WcashScanningKey, orchard::keys::Scope};

/// Version of the Wcash master-seed derivation domain.
///
/// Persistent wallet identities must store and compare this value before
/// deriving keys or opening chain-bound wallet state.
pub const WALLET_SEED_KDF_VERSION: u32 = 1;

const SEED_PERSONALIZATION: &[u8; 16] = b"WcashSeedV1_____";
const DERIVATION_LABEL: &[u8] = b"Wcash wallet seed derivation version 1";
const DERIVED_SEED_LEN: usize = 64;
const MIN_MASTER_SEED_LEN: usize = 32;
const MAX_MASTER_SEED_LEN: usize = 252;

/// An error returned by Wcash wallet key derivation.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum WalletKeyError {
    /// ZIP 32 requires between 32 and 252 bytes of seed entropy.
    #[error("wallet seed must contain between 32 and 252 bytes")]
    InvalidSeedLength,

    /// The transparent account key could not be derived.
    #[error("could not derive transparent account key: {0}")]
    TransparentDerivation(String),

    /// The Ironwood spending key could not be derived.
    #[error("could not derive Ironwood spending key: {0}")]
    IronwoodDerivation(String),
}

/// A network-bound Wcash spending capability.
///
/// Transparent and Ironwood component keys are derived only inside this crate.
/// The retained domain-separated seed is held in [`SecretVec`] and cleared
/// when dropped.
pub struct WcashSpendingKey {
    network: WcashNetwork,
    account: AccountId,
    derived_seed: SecretVec<u8>,
}

impl fmt::Debug for WcashSpendingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WcashSpendingKey")
            .field("network", &self.network)
            .field("account", &self.account)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl WcashSpendingKey {
    /// Returns the immutable network bound to this key.
    pub const fn network(&self) -> WcashNetwork {
        self.network
    }

    /// Returns the ZIP 32 account bound to this key.
    pub const fn account(&self) -> AccountId {
        self.account
    }

    /// Derives this account's network-bound full viewing capability.
    ///
    /// Returns a component-specific derivation error if a key cannot be
    /// reconstructed.
    pub fn to_full_viewing_key(&self) -> Result<WcashFullViewingKey, WalletKeyError> {
        let transparent = self.derive_transparent_key()?.to_account_pubkey();
        let ironwood = IronwoodFullViewingKey::from(&self.derive_ironwood_key()?);
        Ok(WcashFullViewingKey {
            network: self.network,
            account: self.account,
            transparent,
            ironwood,
        })
    }

    fn derive_transparent_key(&self) -> Result<AccountPrivKey, WalletKeyError> {
        let parameters = WcashConsensusParameters::new(self.network);
        AccountPrivKey::from_seed(&parameters, self.derived_seed.expose_secret(), self.account)
            .map_err(|error| WalletKeyError::TransparentDerivation(error.to_string()))
    }

    fn derive_ironwood_key(&self) -> Result<IronwoodSpendingKey, WalletKeyError> {
        let parameters = WcashConsensusParameters::new(self.network);
        IronwoodSpendingKey::from_zip32_seed(
            self.derived_seed.expose_secret(),
            parameters.coin_type(),
            self.account,
        )
        .map_err(|error| WalletKeyError::IronwoodDerivation(error.to_string()))
    }
}

/// A network-bound Wcash full viewing capability.
///
/// Its explicit transparent and Ironwood components remain private so they
/// cannot be encoded with a Zcash or different Wcash network by downstream
/// callers. No feature-dependent generic unified key is retained.
pub struct WcashFullViewingKey {
    network: WcashNetwork,
    account: AccountId,
    transparent: AccountPubKey,
    ironwood: IronwoodFullViewingKey,
}

impl fmt::Debug for WcashFullViewingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WcashFullViewingKey")
            .field("network", &self.network)
            .field("account", &self.account)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl WcashFullViewingKey {
    /// Returns the immutable network bound to this viewing key.
    pub const fn network(&self) -> WcashNetwork {
        self.network
    }

    /// Returns the ZIP 32 account bound to this viewing key.
    pub const fn account(&self) -> AccountId {
        self.account
    }

    /// Restricts this viewing capability to Ironwood scanning for `scope`.
    #[cfg(feature = "ironwood-scanning")]
    pub fn scanning_key(&self, scope: Scope) -> WcashScanningKey {
        WcashScanningKey::new(self, scope)
    }

    pub(crate) const fn transparent(&self) -> &AccountPubKey {
        &self.transparent
    }

    pub(crate) const fn ironwood(&self) -> &IronwoodFullViewingKey {
        &self.ironwood
    }
}

fn derive_wallet_seed(
    master_seed: &SecretVec<u8>,
    network: WcashNetwork,
) -> Result<SecretVec<u8>, WalletKeyError> {
    let master_seed = master_seed.expose_secret();
    if !(MIN_MASTER_SEED_LEN..=MAX_MASTER_SEED_LEN).contains(&master_seed.len()) {
        return Err(WalletKeyError::InvalidSeedLength);
    }

    let mut state = blake2b_simd::Params::new()
        .hash_length(DERIVED_SEED_LEN)
        .personal(SEED_PERSONALIZATION)
        .to_state();
    state.update(DERIVATION_LABEL);
    let seed_len = u16::try_from(master_seed.len())
        .expect("the validated Wcash seed length always fits in a u16");
    state.update(&seed_len.to_le_bytes());
    state.update(master_seed);
    state.update(&[network.seed_domain_byte()]);
    state.update(network.genesis_hash().as_internal_bytes());

    Ok(SecretVec::new(state.finalize().as_bytes().to_vec()))
}

/// Derives a network-bound Wcash spending capability from caller-owned entropy.
///
/// Returns an error when the seed length is invalid or a component key cannot
/// be derived for `account`.
pub fn derive_wallet_spending_key(
    master_seed: &SecretVec<u8>,
    network: WcashNetwork,
    account: AccountId,
) -> Result<WcashSpendingKey, WalletKeyError> {
    let key = WcashSpendingKey {
        network,
        account,
        derived_seed: derive_wallet_seed(master_seed, network)?,
    };

    // Validate each explicitly supported component at construction. Avoiding a
    // generic unified key here prevents workspace feature unification from
    // silently adding a legacy shielded component.
    key.derive_transparent_key()?;
    key.derive_ironwood_key()?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::encode_ironwood_receiver;

    const VALID_SEED_LEN: usize = 32;
    const TESTNET_KDF_VECTOR: &str = "92dc36b870456da70d67656db7730a849c4921e77d80cf525f8f82001d0c43b547cc6b5c96813175927bd0985bd21e5f3f2bc0e3bac790d046e9dc5062e6e158";
    const REGTEST_KDF_VECTOR: &str = "fcff1de4ea666421af9b960b15e04b50b25d90444b2cdec3fb2497781a5429d71aaf486fe4afbf3b6042d1410b207e696329e34189a62763f42c08ac406137b8";

    fn seed(byte: u8) -> SecretVec<u8> {
        SecretVec::new(vec![byte; VALID_SEED_LEN])
    }

    fn account(index: u32) -> AccountId {
        AccountId::try_from(index).expect("test account index is in the ZIP 32 range")
    }

    #[test]
    fn seed_domain_is_deterministic_and_network_bound() {
        const MASTER_SEED_BYTE: u8 = 7;

        let master = seed(MASTER_SEED_BYTE);
        let first = derive_wallet_seed(&master, WcashNetwork::Testnet).unwrap();
        let second = derive_wallet_seed(&master, WcashNetwork::Testnet).unwrap();
        let regtest = derive_wallet_seed(&master, WcashNetwork::Regtest).unwrap();

        assert_eq!(first.expose_secret(), second.expose_secret());
        assert_ne!(first.expose_secret(), regtest.expose_secret());
        assert_ne!(first.expose_secret(), master.expose_secret());
        assert_eq!(first.expose_secret().len(), DERIVED_SEED_LEN);
    }

    #[test]
    fn v5_seed_domains_match_the_node_vectors() {
        const EXPECTED_KDF_VERSION: u32 = 1;

        assert_eq!(WALLET_SEED_KDF_VERSION, EXPECTED_KDF_VERSION);
        let master = SecretVec::new((0u8..VALID_SEED_LEN as u8).collect());
        let testnet = derive_wallet_seed(&master, WcashNetwork::Testnet).unwrap();
        let regtest = derive_wallet_seed(&master, WcashNetwork::Regtest).unwrap();

        assert_eq!(hex::encode(testnet.expose_secret()), TESTNET_KDF_VECTOR);
        assert_eq!(hex::encode(regtest.expose_secret()), REGTEST_KDF_VECTOR);
    }

    #[test]
    fn seed_length_is_checked_before_the_kdf() {
        const TOO_SHORT_SEED_LEN: usize = MIN_MASTER_SEED_LEN - 1;
        const TOO_LONG_SEED_LEN: usize = MAX_MASTER_SEED_LEN + 1;

        assert!(matches!(
            derive_wallet_seed(
                &SecretVec::new(vec![0; TOO_SHORT_SEED_LEN]),
                WcashNetwork::Testnet
            ),
            Err(WalletKeyError::InvalidSeedLength)
        ));
        assert!(matches!(
            derive_wallet_seed(
                &SecretVec::new(vec![0; TOO_LONG_SEED_LEN]),
                WcashNetwork::Testnet
            ),
            Err(WalletKeyError::InvalidSeedLength)
        ));
    }

    #[test]
    fn spending_key_derivation_is_account_separated() {
        const MASTER_SEED_BYTE: u8 = 42;

        let master = seed(MASTER_SEED_BYTE);
        let first = derive_wallet_spending_key(&master, WcashNetwork::Testnet, account(0)).unwrap();
        let same = derive_wallet_spending_key(&master, WcashNetwork::Testnet, account(0)).unwrap();
        let other = derive_wallet_spending_key(&master, WcashNetwork::Testnet, account(1)).unwrap();

        let first_address =
            encode_ironwood_receiver(&first.to_full_viewing_key().unwrap()).unwrap();
        let same_address = encode_ironwood_receiver(&same.to_full_viewing_key().unwrap()).unwrap();
        let other_address =
            encode_ironwood_receiver(&other.to_full_viewing_key().unwrap()).unwrap();

        assert_eq!(first_address, same_address);
        assert_ne!(first_address, other_address);
    }

    #[test]
    fn key_wrappers_preserve_network_and_redact_debug_output() {
        const MASTER_SEED_BYTE: u8 = 91;

        let spending =
            derive_wallet_spending_key(&seed(MASTER_SEED_BYTE), WcashNetwork::Testnet, account(7))
                .unwrap();
        let viewing = spending.to_full_viewing_key().unwrap();

        assert_eq!(spending.network(), WcashNetwork::Testnet);
        assert_eq!(viewing.network(), WcashNetwork::Testnet);
        assert_eq!(spending.account(), account(7));
        assert_eq!(viewing.account(), account(7));

        for debug in [format!("{spending:?}"), format!("{viewing:?}")] {
            assert!(debug.contains("[REDACTED]"));
            assert!(!debug.contains(TESTNET_KDF_VECTOR));
        }
    }
}
