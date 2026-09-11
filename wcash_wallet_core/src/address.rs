//! Wcash payment-address encoding and wallet-boundary conversion.
//!
//! Wcash reuses Zcash receiver payloads and the ZIP 316 container structure,
//! but uses a disjoint textual namespace. The Wcash HRP is part of both
//! F4Jumble padding and the Bech32m checksum, so replacing a Zcash address's
//! visible prefix cannot produce a valid Wcash address.

use std::{fmt, str::FromStr};

use bech32::{Bech32m, Hrp, primitives::decode::CheckedHrpstring};
use orchard::{Address as IronwoodAddress, keys::Scope};
use thiserror::Error;
use zcash_address::unified::{
    Address as UnifiedContainer, Bech32mZip316, Container, Encoding, Item, Receiver,
};
use zcash_encoding::CompactSize;
use zcash_transparent::{
    address::TransparentAddress,
    keys::{AccountPubKey, IncomingViewingKey},
};

use crate::{keys::WcashFullViewingKey, network::WcashNetwork};

/// Testnet Wcash Unified Address HRP.
pub const HRP_UNIFIED_TESTNET: &str = "wutest";
/// Regtest Wcash Unified Address HRP.
pub const HRP_UNIFIED_REGTEST: &str = "wuregtest";

// These namespaces remain reserved while the corresponding address types are
// unsupported. Recognizing them makes a malformed or premature Wcash address
// fail as Wcash data instead of being mistaken for another payment protocol.
const RESERVED_UNIFIED_MAINNET: &str = "wu";
const RESERVED_SAPLING_MAINNET: &str = "ws";
const RESERVED_SAPLING_TESTNET: &str = "wtestsapling";
const RESERVED_SAPLING_REGTEST: &str = "wregtestsapling";
const RESERVED_TEX_MAINNET: &str = "wtex";
const RESERVED_P2PKH_MAINNET_TEXT_PREFIX: &str = "W1";
const RESERVED_P2SH_MAINNET_TEXT_PREFIX: &str = "W3";

/// Testnet Wcash transparent-source-only address HRP.
pub const HRP_TEX_TESTNET: &str = "wtextest";
/// Regtest Wcash transparent-source-only address HRP.
pub const HRP_TEX_REGTEST: &str = "wtexregtest";

/// Testnet Wcash P2PKH Base58Check version bytes (`WT...`).
pub const B58_P2PKH_TESTNET: [u8; 2] = [0x10, 0x95];
/// Testnet Wcash P2SH Base58Check version bytes (`WU...`).
pub const B58_P2SH_TESTNET: [u8; 2] = [0x10, 0x98];
/// Regtest Wcash P2PKH Base58Check version bytes (`WR...`).
pub const B58_P2PKH_REGTEST: [u8; 2] = [0x10, 0x90];
/// Regtest Wcash P2SH Base58Check version bytes (`WS...`).
pub const B58_P2SH_REGTEST: [u8; 2] = [0x10, 0x93];

const ZIP316_PADDING_LEN: usize = 16;
const TRANSPARENT_RECEIVER_LEN: usize = 20;
const TRANSPARENT_ENCODED_PAYLOAD_LEN: usize = 22;
#[cfg(test)]
const BASE58_CHECKSUM_LEN: usize = 4;

/// The externally visible kind of a Wcash payment address.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum WcashAddressKind {
    /// A ZIP 316 container whose Orchard slot carries the Ironwood receiver.
    Unified,
    /// A transparent pay-to-public-key-hash address.
    P2pkh,
    /// A transparent pay-to-script-hash address.
    P2sh,
    /// A transparent-source-only P2PKH address.
    Tex,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum WcashAddressPayload {
    Unified(UnifiedContainer),
    P2pkh([u8; TRANSPARENT_RECEIVER_LEN]),
    P2sh([u8; TRANSPARENT_RECEIVER_LEN]),
    Tex([u8; TRANSPARENT_RECEIVER_LEN]),
}

/// A canonical Wcash payment address for an enabled Wcash network.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct WcashAddress {
    network: WcashNetwork,
    payload: WcashAddressPayload,
}

/// A validated Ironwood-capable recipient bound to one Wcash network.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WcashRecipient {
    network: WcashNetwork,
    ironwood: IronwoodAddress,
    transparent: Option<TransparentAddress>,
}

/// An error encountered while parsing or constructing a Wcash payment address.
#[derive(Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum WcashAddressParseError {
    /// The string does not use a Wcash address namespace.
    #[error("not a Wcash address")]
    NotWcash,

    /// The string uses a Wcash namespace but its encoded payload is malformed.
    #[error("invalid Wcash {0} encoding")]
    InvalidEncoding(&'static str),

    /// The Unified Address payload violates ZIP 316 container rules.
    #[error("invalid Wcash Unified Address: {0}")]
    InvalidUnified(String),

    /// The Unified Address does not contain the receiver used by Ironwood.
    #[error("Wcash Unified Addresses must contain an Ironwood receiver")]
    MissingIronwoodReceiver,

    /// The address contains a receiver for a pool Wcash does not activate.
    #[error("Wcash does not support {0} receivers")]
    UnsupportedReceiver(&'static str),
}

/// An error returned by a Wcash wallet address operation.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum WalletAddressError {
    /// A transparent receiver could not be derived from the viewing key.
    #[error("could not derive the default transparent coinbase address: {0}")]
    TransparentDerivation(String),

    /// The encoded value is not a canonical Wcash address.
    #[error("invalid Wcash address: {0}")]
    Parse(#[from] WcashAddressParseError),

    /// A recipient is not a Unified Address with an Ironwood receiver.
    #[error("recipient must be a Wcash Unified Address with an Ironwood receiver")]
    MissingIronwoodReceiver,

    /// The receiver payload is malformed.
    #[error("invalid Unified Address receiver payload: {0}")]
    InvalidUnified(String),
}

impl WcashAddress {
    /// Constructs an Ironwood-capable Unified Address.
    ///
    /// Returns an error when `data` lacks an Orchard receiver slot or contains
    /// a Sapling or unknown receiver.
    fn from_unified(
        network: WcashNetwork,
        data: UnifiedContainer,
    ) -> Result<Self, WcashAddressParseError> {
        validate_unified_receivers(&data)?;
        Ok(Self {
            network,
            payload: WcashAddressPayload::Unified(data),
        })
    }

    /// Constructs a transparent pay-to-public-key-hash address.
    fn from_transparent_p2pkh(network: WcashNetwork, data: [u8; TRANSPARENT_RECEIVER_LEN]) -> Self {
        Self {
            network,
            payload: WcashAddressPayload::P2pkh(data),
        }
    }

    /// Constructs a transparent pay-to-script-hash address.
    fn from_transparent_p2sh(network: WcashNetwork, data: [u8; TRANSPARENT_RECEIVER_LEN]) -> Self {
        Self {
            network,
            payload: WcashAddressPayload::P2sh(data),
        }
    }

    /// Constructs a transparent-source-only address.
    fn from_tex(network: WcashNetwork, data: [u8; TRANSPARENT_RECEIVER_LEN]) -> Self {
        Self {
            network,
            payload: WcashAddressPayload::Tex(data),
        }
    }

    /// Parses a Wcash address from its canonical string representation.
    pub fn try_from_encoded(encoded: &str) -> Result<Self, WcashAddressParseError> {
        encoded.parse()
    }

    /// Encodes this address in its canonical Wcash representation.
    pub fn encode(&self) -> String {
        self.to_string()
    }

    /// Returns this address's exact Wcash network profile.
    pub const fn network(&self) -> WcashNetwork {
        self.network
    }

    /// Returns this address's kind without exposing its networkless receiver
    /// payload.
    pub const fn kind(&self) -> WcashAddressKind {
        match &self.payload {
            WcashAddressPayload::Unified(_) => WcashAddressKind::Unified,
            WcashAddressPayload::P2pkh(_) => WcashAddressKind::P2pkh,
            WcashAddressPayload::P2sh(_) => WcashAddressKind::P2sh,
            WcashAddressPayload::Tex(_) => WcashAddressKind::Tex,
        }
    }
}

impl WcashRecipient {
    /// Returns the immutable Wcash network this recipient belongs to.
    pub const fn network(&self) -> WcashNetwork {
        self.network
    }

    /// Returns whether the recipient contains its required Ironwood receiver.
    pub fn has_ironwood_receiver(&self) -> bool {
        // Construction validates and stores this concrete component rather
        // than a feature-dependent generic unified address.
        let _ = &self.ironwood;
        true
    }

    /// Returns whether the recipient also contains a transparent receiver.
    pub fn has_transparent_receiver(&self) -> bool {
        self.transparent.is_some()
    }
}

impl fmt::Display for WcashAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let encoded = match &self.payload {
            WcashAddressPayload::Unified(address) => encode_unified(self.network, address),
            WcashAddressPayload::P2pkh(data) => encode_base58(p2pkh_prefix(self.network), data),
            WcashAddressPayload::P2sh(data) => encode_base58(p2sh_prefix(self.network), data),
            WcashAddressPayload::Tex(data) => encode_bech32::<Bech32m>(tex_hrp(self.network), data),
        };

        f.write_str(&encoded)
    }
}

impl FromStr for WcashAddress {
    type Err = WcashAddressParseError;

    fn from_str(encoded: &str) -> Result<Self, Self::Err> {
        if let Ok(parsed) = CheckedHrpstring::new::<Bech32mZip316>(encoded) {
            let parsed_hrp = parsed.hrp();
            let hrp = parsed_hrp.as_str();
            if let Some(network) = unified_network(hrp) {
                let data = parsed.byte_iter().collect::<Vec<_>>();
                let address = decode_unified(hrp, data)?;

                return Self::from_unified(network, address);
            }
        }

        if let Ok(parsed) = CheckedHrpstring::new::<Bech32m>(encoded) {
            let parsed_hrp = parsed.hrp();
            let hrp = parsed_hrp.as_str();
            if let Some(network) = tex_network(hrp) {
                let data: [u8; TRANSPARENT_RECEIVER_LEN] = parsed
                    .byte_iter()
                    .collect::<Vec<_>>()
                    .try_into()
                    .map_err(|_| WcashAddressParseError::InvalidEncoding("TEX"))?;

                return Ok(Self::from_tex(network, data));
            }
        }

        if let Ok(decoded) = bs58::decode(encoded).with_check(None).into_vec() {
            if decoded.len() == TRANSPARENT_ENCODED_PAYLOAD_LEN {
                let prefix = [decoded[0], decoded[1]];
                let data: [u8; TRANSPARENT_RECEIVER_LEN] = decoded[2..]
                    .try_into()
                    .map_err(|_| WcashAddressParseError::InvalidEncoding("transparent"))?;

                if let Some(network) = p2pkh_network(prefix) {
                    return Ok(Self::from_transparent_p2pkh(network, data));
                }
                if let Some(network) = p2sh_network(prefix) {
                    return Ok(Self::from_transparent_p2sh(network, data));
                }
            }
        }

        if looks_like_wcash_address(encoded) {
            Err(WcashAddressParseError::InvalidEncoding("address"))
        } else {
            Err(WcashAddressParseError::NotWcash)
        }
    }
}

/// Encodes the default Ironwood-only receiver of a wallet as a Wcash address.
///
/// Returns an error only if the internally constructed receiver container
/// violates its canonical encoding invariants.
pub fn encode_ironwood_receiver(
    viewing_key: &WcashFullViewingKey,
) -> Result<String, WalletAddressError> {
    let network = viewing_key.network();
    let receiver = viewing_key
        .ironwood()
        .address_at(0u32, Scope::External)
        .to_raw_address_bytes();
    let unified = UnifiedContainer::try_from_items(vec![Receiver::Orchard(receiver)])
        .map_err(|error| WalletAddressError::InvalidUnified(error.to_string()))?;
    let container = WcashAddress::from_unified(network, unified)?;

    Ok(container.encode())
}

/// Encodes the wallet's default external P2PKH receiver in the Wcash namespace.
///
/// Returns an error when the transparent account key cannot derive its default
/// external receiver.
pub fn encode_transparent_coinbase_receiver(
    viewing_key: &WcashFullViewingKey,
) -> Result<String, WalletAddressError> {
    let network = viewing_key.network();
    default_transparent_receiver(viewing_key.transparent())
        .map(|receiver| encode_wcash_transparent_receiver(receiver, network))
}

/// Decodes an Ironwood-capable Wcash recipient and its embedded network.
///
/// Returns an error for transparent-only recipients, Zcash text encodings,
/// malformed payloads, and unsupported receivers. Callers do not supply a
/// network: the Wcash encoding selects it and the returned capability retains
/// it.
pub fn decode_recipient(encoded: &str) -> Result<WcashRecipient, WalletAddressError> {
    let address = WcashAddress::try_from_encoded(encoded)?;
    let network = address.network();

    let WcashAddressPayload::Unified(container) = &address.payload else {
        return Err(WalletAddressError::MissingIronwoodReceiver);
    };
    let mut ironwood = None;
    let mut transparent = None;
    for receiver in container.items() {
        match receiver {
            Receiver::Orchard(bytes) => {
                ironwood = Option::from(IronwoodAddress::from_raw_address_bytes(&bytes));
                if ironwood.is_none() {
                    return Err(WalletAddressError::InvalidUnified(
                        "invalid Ironwood receiver".to_owned(),
                    ));
                }
            }
            Receiver::P2pkh(bytes) => {
                transparent = Some(TransparentAddress::PublicKeyHash(bytes));
            }
            Receiver::P2sh(bytes) => {
                transparent = Some(TransparentAddress::ScriptHash(bytes));
            }
            Receiver::Sapling(_) => {
                return Err(WalletAddressError::InvalidUnified(
                    "Sapling receivers are disabled".to_owned(),
                ));
            }
            Receiver::Unknown { .. } => {
                return Err(WalletAddressError::InvalidUnified(
                    "unknown receivers are disabled".to_owned(),
                ));
            }
        }
    }

    Ok(WcashRecipient {
        network,
        ironwood: ironwood.ok_or(WalletAddressError::MissingIronwoodReceiver)?,
        transparent,
    })
}

fn default_transparent_receiver(
    account_key: &AccountPubKey,
) -> Result<TransparentAddress, WalletAddressError> {
    let incoming = account_key
        .derive_external_ivk()
        .map_err(|error| WalletAddressError::TransparentDerivation(error.to_string()))?;
    Ok(incoming.default_address().0)
}

fn encode_wcash_transparent_receiver(
    receiver: TransparentAddress,
    network: WcashNetwork,
) -> String {
    match receiver {
        TransparentAddress::PublicKeyHash(bytes) => {
            WcashAddress::from_transparent_p2pkh(network, bytes).encode()
        }
        TransparentAddress::ScriptHash(bytes) => {
            WcashAddress::from_transparent_p2sh(network, bytes).encode()
        }
    }
}

fn encode_unified(network: WcashNetwork, address: &UnifiedContainer) -> String {
    encode_unified_with_hrp(unified_hrp(network), address)
}

fn encode_unified_with_hrp(hrp: &str, address: &UnifiedContainer) -> String {
    let mut raw = Vec::new();
    for receiver in address.items_as_parsed() {
        raw.extend(receiver.typed_encoding());
    }

    let mut padding = [0u8; ZIP316_PADDING_LEN];
    padding[..hrp.len()].copy_from_slice(hrp.as_bytes());
    raw.extend(padding);

    let jumbled = f4jumble::f4jumble(&raw)
        .expect("a valid Unified Address is within the F4Jumble length bounds");
    encode_bech32::<Bech32mZip316>(hrp, &jumbled)
}

fn decode_unified(
    hrp: &str,
    mut jumbled: Vec<u8>,
) -> Result<UnifiedContainer, WcashAddressParseError> {
    f4jumble::f4jumble_inv_mut(&mut jumbled)
        .map_err(|_| WcashAddressParseError::InvalidEncoding("Unified Address"))?;

    if jumbled.len() < ZIP316_PADDING_LEN {
        return Err(WcashAddressParseError::InvalidEncoding("Unified Address"));
    }

    let raw_len = jumbled.len() - ZIP316_PADDING_LEN;
    let (raw, padding) = jumbled.split_at(raw_len);
    let mut expected_padding = [0u8; ZIP316_PADDING_LEN];
    expected_padding[..hrp.len()].copy_from_slice(hrp.as_bytes());
    if padding != expected_padding {
        return Err(WcashAddressParseError::InvalidEncoding(
            "Unified Address padding",
        ));
    }

    let mut raw = raw;
    let mut receivers = Vec::new();
    let mut previous_typecode = None;
    while !raw.is_empty() {
        let typecode = CompactSize::read(&mut raw)
            .map_err(|_| WcashAddressParseError::InvalidEncoding("Unified Address typecode"))?;
        let typecode = u32::try_from(typecode)
            .map_err(|_| WcashAddressParseError::InvalidEncoding("Unified Address typecode"))?;
        if previous_typecode.is_some_and(|previous| typecode <= previous) {
            return Err(WcashAddressParseError::InvalidUnified(
                "receiver typecodes are duplicated or out of canonical order".to_owned(),
            ));
        }
        previous_typecode = Some(typecode);

        let length = CompactSize::read(&mut raw)
            .map_err(|_| WcashAddressParseError::InvalidEncoding("Unified Address length"))?;
        let length = usize::try_from(length)
            .map_err(|_| WcashAddressParseError::InvalidEncoding("Unified Address length"))?;
        if raw.len() < length {
            return Err(WcashAddressParseError::InvalidEncoding(
                "Unified Address receiver",
            ));
        }

        let (receiver, remaining) = raw.split_at(length);
        receivers.push(
            Receiver::try_from((typecode, receiver))
                .map_err(|error| WcashAddressParseError::InvalidUnified(error.to_string()))?,
        );
        raw = remaining;
    }

    UnifiedContainer::try_from_items(receivers)
        .map_err(|error| WcashAddressParseError::InvalidUnified(error.to_string()))
}

fn validate_unified_receivers(address: &UnifiedContainer) -> Result<(), WcashAddressParseError> {
    let mut has_ironwood_receiver = false;

    for receiver in address.items() {
        match receiver {
            Receiver::Orchard(_) => has_ironwood_receiver = true,
            Receiver::Sapling(_) => {
                return Err(WcashAddressParseError::UnsupportedReceiver("Sapling"));
            }
            Receiver::Unknown { .. } => {
                return Err(WcashAddressParseError::UnsupportedReceiver("unknown"));
            }
            Receiver::P2pkh(_) | Receiver::P2sh(_) => {}
        }
    }

    if has_ironwood_receiver {
        Ok(())
    } else {
        Err(WcashAddressParseError::MissingIronwoodReceiver)
    }
}

fn encode_bech32<Ck: bech32::Checksum>(hrp: &str, data: &[u8]) -> String {
    bech32::encode::<Ck>(
        Hrp::parse(hrp).expect("Wcash address HRPs are compile-time constants"),
        data,
    )
    .expect("Wcash address length is bounded by its payload type")
}

fn encode_base58(prefix: [u8; 2], data: &[u8; TRANSPARENT_RECEIVER_LEN]) -> String {
    let mut bytes = Vec::with_capacity(TRANSPARENT_ENCODED_PAYLOAD_LEN);
    bytes.extend(prefix);
    bytes.extend(data);
    bs58::encode(bytes).with_check().into_string()
}

const fn unified_hrp(network: WcashNetwork) -> &'static str {
    match network {
        WcashNetwork::Testnet => HRP_UNIFIED_TESTNET,
        WcashNetwork::Regtest => HRP_UNIFIED_REGTEST,
    }
}

fn unified_network(hrp: &str) -> Option<WcashNetwork> {
    match hrp {
        HRP_UNIFIED_TESTNET => Some(WcashNetwork::Testnet),
        HRP_UNIFIED_REGTEST => Some(WcashNetwork::Regtest),
        _ => None,
    }
}

const fn tex_hrp(network: WcashNetwork) -> &'static str {
    match network {
        WcashNetwork::Testnet => HRP_TEX_TESTNET,
        WcashNetwork::Regtest => HRP_TEX_REGTEST,
    }
}

fn tex_network(hrp: &str) -> Option<WcashNetwork> {
    match hrp {
        HRP_TEX_TESTNET => Some(WcashNetwork::Testnet),
        HRP_TEX_REGTEST => Some(WcashNetwork::Regtest),
        _ => None,
    }
}

const fn p2pkh_prefix(network: WcashNetwork) -> [u8; 2] {
    match network {
        WcashNetwork::Testnet => B58_P2PKH_TESTNET,
        WcashNetwork::Regtest => B58_P2PKH_REGTEST,
    }
}

fn p2pkh_network(prefix: [u8; 2]) -> Option<WcashNetwork> {
    match prefix {
        B58_P2PKH_TESTNET => Some(WcashNetwork::Testnet),
        B58_P2PKH_REGTEST => Some(WcashNetwork::Regtest),
        _ => None,
    }
}

const fn p2sh_prefix(network: WcashNetwork) -> [u8; 2] {
    match network {
        WcashNetwork::Testnet => B58_P2SH_TESTNET,
        WcashNetwork::Regtest => B58_P2SH_REGTEST,
    }
}

fn p2sh_network(prefix: [u8; 2]) -> Option<WcashNetwork> {
    match prefix {
        B58_P2SH_TESTNET => Some(WcashNetwork::Testnet),
        B58_P2SH_REGTEST => Some(WcashNetwork::Regtest),
        _ => None,
    }
}

fn looks_like_wcash_address(encoded: &str) -> bool {
    const BECH32_PREFIXES: [&str; 9] = [
        RESERVED_UNIFIED_MAINNET,
        HRP_UNIFIED_TESTNET,
        HRP_UNIFIED_REGTEST,
        RESERVED_SAPLING_MAINNET,
        RESERVED_SAPLING_TESTNET,
        RESERVED_SAPLING_REGTEST,
        RESERVED_TEX_MAINNET,
        HRP_TEX_TESTNET,
        HRP_TEX_REGTEST,
    ];
    const BASE58_PREFIXES: [&str; 6] = [
        RESERVED_P2PKH_MAINNET_TEXT_PREFIX,
        RESERVED_P2SH_MAINNET_TEXT_PREFIX,
        "WT",
        "WU",
        "WR",
        "WS",
    ];

    BECH32_PREFIXES
        .iter()
        .any(|hrp| encoded.starts_with(&format!("{hrp}1")))
        || BASE58_PREFIXES
            .iter()
            .any(|prefix| encoded.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use secrecy::SecretVec;
    use zcash_address::{ZcashAddress, unified::Receiver};
    use zcash_protocol::consensus::NetworkType;
    use zip32::AccountId;

    use super::*;
    use crate::keys::derive_wallet_spending_key;

    const ORCHARD_FIXTURE: &str = "uregtest1pszqlgxaf5w8mu2yd9uygg8cswp0ec4f7eejqnqc35tztw4tk0sxnt3pym2f3s2872cy2ruuc5n8y9cen5q6ngzlmzu8ztrjesv8zm9j";
    const TESTNET_UNIFIED_ZERO_VECTOR: &str = "wutest12ky95e9c6mu3qveefsekul4tk949ahkllsu8yglndurppu8j8qeleyd20r7z6jaacwhnwar5wlrmw0nynugqr2yldvc9cv9y9gfktz8k";
    const REGTEST_UNIFIED_ZERO_VECTOR: &str = "wuregtest1ctr282fk80mmwz0t69s4kywtstpyh0lr23u6ynpy54m7lufs0qyrautm3kjg7sxk5mu0lp0ck4hea672xhvrdzz2863afkz6ss423hgj";
    const TESTNET_WALLET_UNIFIED_VECTOR: &str = "wutest17mvne4ygv9v8rkjf6yxnrveceejh8nutee8svp8swkgj7s7ac9ga36u2av8hgpc28cc42u474ypjq2jsdt64utcxtztm2jr6guvaryhh";
    const REGTEST_WALLET_UNIFIED_VECTOR: &str = "wuregtest1xryxj7ddyajw4mv7jpelftnfhkwu3v5w03smp88kk6fkmfvlewpzrs26pxqs4wycul43485lg0h9ry8zzxkj9q8gvh7dmg0uh5e2t28k";
    const TESTNET_WALLET_TRANSPARENT_VECTOR: &str = "WTNjqDPXEGEgKHS1YPtfEgdrqk6egFRULDz";
    const REGTEST_WALLET_TRANSPARENT_VECTOR: &str = "WRHUq9CTLZFa52NmAyHH5usN21Q8jZVskN1";

    fn orchard_unified_address() -> UnifiedContainer {
        let (network, unified) = UnifiedContainer::decode(ORCHARD_FIXTURE).unwrap();
        assert_eq!(network, NetworkType::Regtest);
        unified
    }

    fn round_trip(address: WcashAddress, expected: &str) {
        assert_eq!(address.encode(), expected);
        assert_eq!(expected.parse::<WcashAddress>(), Ok(address));
    }

    fn fixture_viewing_key(network: WcashNetwork) -> WcashFullViewingKey {
        const MASTER_SEED_BYTE: u8 = 19;
        const MASTER_SEED_LEN: usize = 32;
        let account = AccountId::try_from(0).expect("zero is a valid ZIP 32 account");
        derive_wallet_spending_key(
            &SecretVec::new(vec![MASTER_SEED_BYTE; MASTER_SEED_LEN]),
            network,
            account,
        )
        .unwrap()
        .to_full_viewing_key()
        .unwrap()
    }

    #[test]
    fn address_constants_match_the_node_byte_for_byte() {
        assert_eq!(HRP_UNIFIED_TESTNET.as_bytes(), b"wutest");
        assert_eq!(HRP_UNIFIED_REGTEST.as_bytes(), b"wuregtest");
        assert_eq!(HRP_TEX_TESTNET.as_bytes(), b"wtextest");
        assert_eq!(HRP_TEX_REGTEST.as_bytes(), b"wtexregtest");
    }

    #[test]
    fn unified_golden_vectors_match_the_node() {
        let unified = orchard_unified_address();

        round_trip(
            WcashAddress::from_unified(WcashNetwork::Testnet, unified.clone())
                .expect("the Orchard-only fixture is supported"),
            TESTNET_UNIFIED_ZERO_VECTOR,
        );
        round_trip(
            WcashAddress::from_unified(WcashNetwork::Regtest, unified)
                .expect("the Orchard-only fixture is supported"),
            REGTEST_UNIFIED_ZERO_VECTOR,
        );
    }

    #[test]
    fn unified_codec_preserves_zip_316_construction() {
        let unified = orchard_unified_address();

        for (network, hrp) in [
            (NetworkType::Test, "utest"),
            (NetworkType::Regtest, "uregtest"),
        ] {
            let reference = unified.encode(&network);
            assert_eq!(encode_unified_with_hrp(hrp, &unified), reference);

            let parsed = CheckedHrpstring::new::<Bech32mZip316>(&reference).unwrap();
            assert_eq!(
                decode_unified(hrp, parsed.byte_iter().collect()).unwrap(),
                unified
            );
        }
    }

    #[test]
    fn transparent_golden_vectors_match_the_node() {
        const ZERO_RECEIVER: [u8; TRANSPARENT_RECEIVER_LEN] = [0; TRANSPARENT_RECEIVER_LEN];

        for (address, expected) in [
            (
                WcashAddress::from_transparent_p2pkh(WcashNetwork::Testnet, ZERO_RECEIVER),
                "WT6kWkxJzyp4LdwrjtvvuVFRbkMhH2SsBeq",
            ),
            (
                WcashAddress::from_transparent_p2sh(WcashNetwork::Testnet, ZERO_RECEIVER),
                "WUJmKiHCs7MSy6FGzyBvrwdExdsU75uiFgz",
            ),
            (
                WcashAddress::from_transparent_p2pkh(WcashNetwork::Regtest, ZERO_RECEIVER),
                "WR64VqQpZRujxYnAJmqGK4d4fbqQZRZHazG",
            ),
            (
                WcashAddress::from_transparent_p2sh(WcashNetwork::Regtest, ZERO_RECEIVER),
                "WSJ5JnjiRZT8b15aZr6GGWzt2VMBPapmhBQ",
            ),
        ] {
            round_trip(address, expected);
        }
    }

    #[test]
    fn base58_prefixes_cover_the_entire_receiver_range() {
        const PREFIXES: [([u8; 2], &str); 4] = [
            (B58_P2PKH_TESTNET, "WT"),
            (B58_P2SH_TESTNET, "WU"),
            (B58_P2PKH_REGTEST, "WR"),
            (B58_P2SH_REGTEST, "WS"),
        ];

        for (version, expected_text) in PREFIXES {
            for (payload, checksum) in [
                ([0; TRANSPARENT_RECEIVER_LEN], [0; BASE58_CHECKSUM_LEN]),
                (
                    [u8::MAX; TRANSPARENT_RECEIVER_LEN],
                    [u8::MAX; BASE58_CHECKSUM_LEN],
                ),
            ] {
                let mut bytes = Vec::with_capacity(
                    version.len() + TRANSPARENT_RECEIVER_LEN + BASE58_CHECKSUM_LEN,
                );
                bytes.extend(version);
                bytes.extend(payload);
                bytes.extend(checksum);
                let encoded = bs58::encode(bytes).into_string();
                assert!(
                    encoded.starts_with(expected_text),
                    "{version:02x?} escaped its {expected_text} namespace: {encoded}"
                );
            }
        }
    }

    #[test]
    fn tex_golden_vectors_match_the_node() {
        const ZERO_RECEIVER: [u8; TRANSPARENT_RECEIVER_LEN] = [0; TRANSPARENT_RECEIVER_LEN];

        round_trip(
            WcashAddress::from_tex(WcashNetwork::Testnet, ZERO_RECEIVER),
            "wtextest1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqf4k4nr",
        );
        round_trip(
            WcashAddress::from_tex(WcashNetwork::Regtest, ZERO_RECEIVER),
            "wtexregtest1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqx3mu38",
        );
    }

    #[test]
    fn sapling_and_unknown_receivers_remain_disabled_under_feature_unification() {
        const UNKNOWN_TYPECODE: u32 = 65_536;
        const SHIELDED_RECEIVER_LEN: usize = 43;

        let sapling =
            UnifiedContainer::try_from_items(vec![Receiver::Sapling([0; SHIELDED_RECEIVER_LEN])])
                .expect("a Sapling-only Unified Address is structurally valid");
        assert_eq!(
            WcashAddress::from_unified(WcashNetwork::Testnet, sapling),
            Err(WcashAddressParseError::UnsupportedReceiver("Sapling")),
        );

        let unknown = UnifiedContainer::try_from_items(vec![
            Receiver::Orchard([0; SHIELDED_RECEIVER_LEN]),
            Receiver::Unknown {
                typecode: UNKNOWN_TYPECODE,
                data: vec![0; SHIELDED_RECEIVER_LEN],
            },
        ])
        .expect("the mixed receiver fixture is structurally valid");
        assert_eq!(
            WcashAddress::from_unified(WcashNetwork::Testnet, unknown),
            Err(WcashAddressParseError::UnsupportedReceiver("unknown")),
        );

        let transparent = WcashAddress::from_transparent_p2pkh(
            WcashNetwork::Testnet,
            [0; TRANSPARENT_RECEIVER_LEN],
        )
        .encode();
        assert!(matches!(
            decode_recipient(&transparent),
            Err(WalletAddressError::MissingIronwoodReceiver)
        ));
    }

    #[test]
    fn zcash_and_wcash_namespaces_are_mutually_rejected() {
        const ZCASH_ADDRESSES: [&str; 8] = [
            "utest10c5kutapazdnf8ztl3pu43nkfsjx89fy3uuff8tsmxm6s86j37pe7uz94z5jhkl49pqe8yz75rlsaygexk6jpaxwx0esjr8wm5ut7d5s",
            "uregtest15xk7vj4grjkay6mnfl93dhsflc2yeunhxwdh38rul0rq3dfhzzxgm5szjuvtqdha4t4p2q02ks0jgzrhjkrav70z9xlvq0plpcjkd5z3",
            "ztestsapling1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqfhgwqu",
            "zregtestsapling1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqknpr3m",
            "tm9iMLAuYMzJ6jtFLcA7rzUmfreGuKvr7Ma",
            "t26YoyZ1iPgiMEWL4zGUm74eVWfhyDMXzY2",
            "textest1qyqszqgpqyqszqgpqyqszqgpqyqszqgpfcjgfy",
            "texregtest1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqz7rhv3",
        ];

        for encoded in ZCASH_ADDRESSES {
            assert_eq!(
                encoded.parse::<WcashAddress>(),
                Err(WcashAddressParseError::NotWcash),
                "accepted Zcash address {encoded}"
            );
            assert!(encoded.parse::<ZcashAddress>().is_ok());
        }

        let wcash_addresses = [
            WcashAddress::from_unified(WcashNetwork::Testnet, orchard_unified_address())
                .expect("the Orchard-only fixture is supported"),
            WcashAddress::from_transparent_p2pkh(
                WcashNetwork::Testnet,
                [0; TRANSPARENT_RECEIVER_LEN],
            ),
            WcashAddress::from_transparent_p2sh(
                WcashNetwork::Regtest,
                [0; TRANSPARENT_RECEIVER_LEN],
            ),
            WcashAddress::from_tex(WcashNetwork::Testnet, [0; TRANSPARENT_RECEIVER_LEN]),
        ];

        for address in wcash_addresses {
            let encoded = address.encode();
            assert!(encoded.parse::<ZcashAddress>().is_err(), "{encoded}");
            assert_eq!(
                format!(" {encoded}").parse::<WcashAddress>(),
                Err(WcashAddressParseError::NotWcash),
                "accepted leading whitespace around {encoded}"
            );
        }
    }

    #[test]
    fn reserved_and_malformed_wcash_namespaces_fail_closed() {
        const RESERVED_ADDRESSES: [&str; 6] = [
            "wu1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
            "ws1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
            "wtestsapling1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
            "wregtestsapling1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
            "wtex1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
            "W1notyetvalid",
        ];

        for encoded in RESERVED_ADDRESSES {
            assert!(matches!(
                encoded.parse::<WcashAddress>(),
                Err(WcashAddressParseError::InvalidEncoding(_))
            ));
        }
    }

    #[test]
    fn rejects_cross_network_and_corrupted_addresses() {
        const FIRST_MATCH_ONLY: usize = 1;

        let address = WcashAddress::from_unified(WcashNetwork::Regtest, orchard_unified_address())
            .expect("the Orchard-only fixture is supported");
        let decoded = decode_recipient(&address.encode()).unwrap();
        assert_eq!(decoded.network(), WcashNetwork::Regtest);

        let mut corrupted = address.encode().into_bytes();
        let last = corrupted.last_mut().unwrap();
        *last = if *last == b'q' { b'p' } else { b'q' };
        let corrupted = String::from_utf8(corrupted).unwrap();
        assert!(matches!(
            corrupted.parse::<WcashAddress>(),
            Err(WcashAddressParseError::InvalidEncoding(_))
        ));

        let replaced_hrp = address.encode().replacen(
            &format!("{HRP_UNIFIED_REGTEST}1"),
            &format!("{HRP_UNIFIED_TESTNET}1"),
            FIRST_MATCH_ONLY,
        );
        assert!(matches!(
            replaced_hrp.parse::<WcashAddress>(),
            Err(WcashAddressParseError::InvalidEncoding(_))
        ));
    }

    #[test]
    fn rejects_noncanonical_unified_receiver_order() {
        const SHIELDED_RECEIVER_LEN: usize = 43;

        let mut raw = Receiver::Sapling([0; SHIELDED_RECEIVER_LEN]).typed_encoding();
        raw.extend(Receiver::P2pkh([0; TRANSPARENT_RECEIVER_LEN]).typed_encoding());

        let mut padding = [0u8; ZIP316_PADDING_LEN];
        padding[..HRP_UNIFIED_REGTEST.len()].copy_from_slice(HRP_UNIFIED_REGTEST.as_bytes());
        raw.extend(padding);

        let jumbled = f4jumble::f4jumble(&raw).unwrap();
        let encoded = encode_bech32::<Bech32mZip316>(HRP_UNIFIED_REGTEST, &jumbled);
        assert!(matches!(
            encoded.parse::<WcashAddress>(),
            Err(WcashAddressParseError::InvalidUnified(message))
                if message.contains("canonical order")
        ));
    }

    #[test]
    fn wallet_boundaries_match_the_node_vectors() {
        let master_seed = SecretVec::new((0u8..32).collect());
        let account = AccountId::try_from(0).expect("zero is a valid ZIP 32 account");
        let testnet = derive_wallet_spending_key(&master_seed, WcashNetwork::Testnet, account)
            .unwrap()
            .to_full_viewing_key()
            .unwrap();
        let regtest = derive_wallet_spending_key(&master_seed, WcashNetwork::Regtest, account)
            .unwrap()
            .to_full_viewing_key()
            .unwrap();

        assert_eq!(
            encode_ironwood_receiver(&testnet).unwrap(),
            TESTNET_WALLET_UNIFIED_VECTOR
        );
        assert_eq!(
            encode_ironwood_receiver(&regtest).unwrap(),
            REGTEST_WALLET_UNIFIED_VECTOR
        );
        assert_eq!(
            encode_transparent_coinbase_receiver(&testnet).unwrap(),
            TESTNET_WALLET_TRANSPARENT_VECTOR
        );
        assert_eq!(
            encode_transparent_coinbase_receiver(&regtest).unwrap(),
            REGTEST_WALLET_TRANSPARENT_VECTOR
        );

        let decoded = decode_recipient(TESTNET_WALLET_UNIFIED_VECTOR)
            .expect("the frozen testnet vector is a valid Ironwood recipient");
        assert_eq!(decoded.network(), WcashNetwork::Testnet);
        assert!(decoded.has_ironwood_receiver());
        assert!(!decoded.has_transparent_receiver());
    }

    #[test]
    fn derived_addresses_are_ironwood_only() {
        let address =
            encode_ironwood_receiver(&fixture_viewing_key(WcashNetwork::Testnet)).unwrap();
        let parsed = WcashAddress::try_from_encoded(&address).unwrap();
        let WcashAddressPayload::Unified(container) = parsed.payload else {
            panic!("the derived Ironwood address must be unified");
        };
        assert!(matches!(
            container.items().as_slice(),
            [Receiver::Orchard(_)]
        ));

        let decoded = decode_recipient(&address).unwrap();
        assert!(decoded.has_ironwood_receiver());
        assert!(!decoded.has_transparent_receiver());
    }
}
