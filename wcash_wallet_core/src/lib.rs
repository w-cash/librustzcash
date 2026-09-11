//! Shared, fail-closed primitives for Wcash wallets.
//!
//! This crate contains no network client or persistent wallet database. It
//! defines the immutable public values that those layers must bind to before
//! scanning, deriving keys, parsing addresses, or signing transactions.

#![forbid(unsafe_code)]
#![deny(rustdoc::broken_intra_doc_links)]
#![warn(missing_docs)]

pub mod address;
pub mod keys;
pub mod network;

pub use address::{
    WalletAddressError, WcashAddress, WcashAddressKind, WcashAddressParseError, WcashRecipient,
    decode_recipient, encode_ironwood_receiver, encode_transparent_coinbase_receiver,
};
pub use keys::{
    WALLET_SEED_KDF_VERSION, WalletKeyError, WcashFullViewingKey, WcashSpendingKey,
    derive_wallet_spending_key,
};
pub use network::{WcashGenesisHash, WcashNetwork, WcashValuePool};
