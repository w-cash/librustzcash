//! Opaque Wcash Ironwood scanning capabilities.

use std::fmt;

use orchard::{
    Address as IronwoodRecipient, Note as IronwoodNote,
    keys::{
        FullViewingKey as IronwoodFullViewingKey, IncomingViewingKey as IronwoodIncomingViewingKey,
        PreparedIncomingViewingKey, Scope,
    },
    note::Nullifier as IronwoodNullifier,
    note_encryption::{CompactAction, IronwoodDomain},
};
use thiserror::Error;
use zcash_note_encryption::batch;
use zip32::AccountId;

use crate::{keys::WcashFullViewingKey, network::WcashNetwork};

/// A Wcash-bound capability that privately holds the Ironwood keys needed to
/// scan one account scope.
pub struct WcashScanningKey {
    network: WcashNetwork,
    account: AccountId,
    scope: Scope,
    incoming: IronwoodIncomingViewingKey,
    full: IronwoodFullViewingKey,
}

impl Clone for WcashScanningKey {
    fn clone(&self) -> Self {
        Self {
            network: self.network,
            account: self.account,
            scope: self.scope,
            incoming: self.incoming.clone(),
            full: self.full.clone(),
        }
    }
}

impl WcashScanningKey {
    pub(crate) fn new(viewing_key: &WcashFullViewingKey, scope: Scope) -> Self {
        Self {
            network: viewing_key.network(),
            account: viewing_key.account(),
            scope,
            incoming: viewing_key.ironwood().to_ivk(scope),
            full: viewing_key.ironwood().clone(),
        }
    }

    /// Returns the immutable Wcash network bound to this capability.
    pub const fn network(&self) -> WcashNetwork {
        self.network
    }

    /// Returns the ZIP 32 account bound to this capability.
    pub const fn account(&self) -> AccountId {
        self.account
    }

    /// Returns the external or internal key scope used for trial decryption.
    pub const fn scope(&self) -> Scope {
        self.scope
    }
}

impl fmt::Debug for WcashScanningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WcashScanningKey")
            .field("network", &self.network)
            .field("account", &self.account)
            .field("scope", &self.scope)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

/// A version-3 Ironwood note and nullifier detected by one Wcash scanning key.
#[derive(Clone)]
pub struct WcashIronwoodDecryption {
    network: WcashNetwork,
    account: AccountId,
    scope: Scope,
    note: IronwoodNote,
    recipient: IronwoodRecipient,
    nullifier: IronwoodNullifier,
}

impl WcashIronwoodDecryption {
    /// Returns the Wcash network whose key decrypted this note.
    pub const fn network(&self) -> WcashNetwork {
        self.network
    }

    /// Returns the ZIP 32 account whose key decrypted this note.
    pub const fn account(&self) -> AccountId {
        self.account
    }

    /// Returns the key scope that decrypted this note.
    pub const fn scope(&self) -> Scope {
        self.scope
    }

    /// Returns the validated version-3 Ironwood note.
    pub const fn note(&self) -> &IronwoodNote {
        &self.note
    }

    /// Returns the recipient recovered from the Ironwood note plaintext.
    pub const fn recipient(&self) -> IronwoodRecipient {
        self.recipient
    }

    /// Returns the nullifier derived immediately after trial decryption.
    pub const fn nullifier(&self) -> IronwoodNullifier {
        self.nullifier
    }
}

impl fmt::Debug for WcashIronwoodDecryption {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WcashIronwoodDecryption")
            .field("network", &self.network)
            .field("account", &self.account)
            .field("scope", &self.scope)
            .field("note", &"[REDACTED]")
            .field("recipient", &"[REDACTED]")
            .field("nullifier", &"[REDACTED]")
            .finish()
    }
}

/// An invalid batch of Wcash Ironwood scanning keys.
#[derive(Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum WcashScanningError {
    /// A key is bound to a different Wcash network than the requested scan.
    #[error("scanning key {key_index} is for {actual:?}, but the batch requires {expected:?}")]
    NetworkMismatch {
        /// Position of the mismatched key in the input slice.
        key_index: usize,
        /// Wcash network required by the caller.
        expected: WcashNetwork,
        /// Wcash network bound to the key.
        actual: WcashNetwork,
    },

    /// Two keys claim the same account and scope in one batch.
    #[error(
        "scanning keys {first_index} and {duplicate_index} both claim account {account:?} scope {scope:?}"
    )]
    DuplicateKey {
        /// Position of the first key in the input slice.
        first_index: usize,
        /// Position of the duplicate key in the input slice.
        duplicate_index: usize,
        /// Duplicated ZIP 32 account.
        account: AccountId,
        /// Duplicated key scope.
        scope: Scope,
    },
}

/// Batch-decrypts compact version-3 Ironwood actions in input order and derives
/// each detected note's nullifier, rejecting key batches containing another
/// Wcash network or duplicate account scopes.
pub fn try_decrypt_compact_ironwood_batch(
    expected_network: WcashNetwork,
    keys: &[WcashScanningKey],
    actions: &[CompactAction],
) -> Result<Vec<Option<WcashIronwoodDecryption>>, WcashScanningError> {
    validate_keys(expected_network, keys)?;

    let prepared = keys
        .iter()
        .map(|key| PreparedIncomingViewingKey::new(&key.incoming))
        .collect::<Vec<_>>();
    let outputs = actions
        .iter()
        .cloned()
        .map(|action| (IronwoodDomain::for_compact_action(&action), action))
        .collect::<Vec<_>>();

    Ok(batch::try_compact_note_decryption(&prepared, &outputs)
        .into_iter()
        .map(|result| {
            result.map(|((note, recipient), key_index)| {
                let key = &keys[key_index];
                let nullifier = note.nullifier(&key.full);

                WcashIronwoodDecryption {
                    network: key.network,
                    account: key.account,
                    scope: key.scope,
                    note,
                    recipient,
                    nullifier,
                }
            })
        })
        .collect())
}

fn validate_keys(
    expected_network: WcashNetwork,
    keys: &[WcashScanningKey],
) -> Result<(), WcashScanningError> {
    for (key_index, key) in keys.iter().enumerate() {
        if key.network != expected_network {
            return Err(WcashScanningError::NetworkMismatch {
                key_index,
                expected: expected_network,
                actual: key.network,
            });
        }

        if let Some((first_index, _)) = keys[..key_index]
            .iter()
            .enumerate()
            .find(|(_, previous)| previous.account == key.account && previous.scope == key.scope)
        {
            return Err(WcashScanningError::DuplicateKey {
                first_index,
                duplicate_index: key_index,
                account: key.account,
                scope: key.scope,
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use orchard::{
        keys::FullViewingKey as IronwoodFullViewingKey,
        note::{ExtractedNoteCommitment, NoteVersion, RandomSeed, Rho},
        note_encryption::{IronwoodNoteEncryption, OrchardDomain, OrchardNoteEncryption},
        value::NoteValue,
    };
    use secrecy::SecretVec;
    use zcash_note_encryption::{
        COMPACT_NOTE_SIZE, Domain, EphemeralKeyBytes, NOTE_PLAINTEXT_SIZE,
    };

    use crate::keys::derive_wallet_spending_key;

    use super::*;

    /// Length of a Wcash wallet seed used by these deterministic fixtures.
    const MASTER_SEED_LEN: usize = 32;
    /// Byte width of encoded Pallas fields and ephemeral keys.
    const ENCODED_FIELD_SIZE: usize = 32;
    /// Index of the fixture discriminator in an encoded field.
    const FIXTURE_TAG_INDEX: usize = 0;
    /// Memo length implied by the note-encryption protocol constants.
    const MEMO_SIZE: usize = NOTE_PLAINTEXT_SIZE - COMPACT_NOTE_SIZE;
    /// Empty memo used because compact decryption does not return memo contents.
    const EMPTY_MEMO: [u8; MEMO_SIZE] = [u8::MIN; MEMO_SIZE];
    /// Invalid encoded ephemeral key used to exercise batch parsing failure.
    const INVALID_EPHEMERAL_KEY: [u8; ENCODED_FIELD_SIZE] = [u8::MAX; ENCODED_FIELD_SIZE];
    /// Empty compact ciphertext paired with the invalid ephemeral key.
    const EMPTY_COMPACT_CIPHERTEXT: [u8; COMPACT_NOTE_SIZE] = [u8::MIN; COMPACT_NOTE_SIZE];
    /// Primary deterministic wallet seed byte.
    const PRIMARY_SEED_BYTE: u8 = 0x2a;
    /// Distinct wallet seed byte used to detect metadata collisions.
    const ALTERNATE_SEED_BYTE: u8 = 0x3b;
    /// First ZIP 32 account fixture.
    const ACCOUNT_ZERO_INDEX: u32 = 0;
    /// Second ZIP 32 account fixture.
    const ACCOUNT_ONE_INDEX: u32 = 1;
    /// First unique rho discriminator.
    const FIRST_RHO_TAG: u8 = 1;
    /// Second unique rho discriminator.
    const SECOND_RHO_TAG: u8 = 2;
    /// Smallest non-zero note-value fixture.
    const MIN_NOTE_VALUE: u64 = 1;
    /// Distinct small note-value fixture.
    const SECOND_NOTE_VALUE: u64 = 10;
    /// Larger note-value fixture for batch ordering.
    const FIRST_NOTE_VALUE: u64 = 62_500_000;
    /// Number of actions in a single-action fixture.
    const SINGLE_ACTION_COUNT: usize = 1;
    /// Number of actions in the positive batch fixture.
    const POSITIVE_ACTION_COUNT: usize = 2;
    /// Index of the first key or action in a fixture.
    const FIRST_ITEM_INDEX: usize = 0;
    /// Index of the second key or action in a fixture.
    const SECOND_ITEM_INDEX: usize = 1;
    /// Marker required in privacy-sensitive debug output.
    const REDACTION_MARKER: &str = "[REDACTED]";
    /// Diversifier index used by all note fixtures.
    const DIVERSIFIER_INDEX: u32 = 7;

    fn viewing_key(
        network: WcashNetwork,
        seed_byte: u8,
        account_index: u32,
    ) -> WcashFullViewingKey {
        let account = AccountId::try_from(account_index).expect("the test account is in range");
        derive_wallet_spending_key(
            &SecretVec::new(vec![seed_byte; MASTER_SEED_LEN]),
            network,
            account,
        )
        .expect("the test seed derives")
        .to_full_viewing_key()
        .expect("the validated key reconstructs")
    }

    fn note_and_action(
        viewing_key: &IronwoodFullViewingKey,
        scope: Scope,
        version: NoteVersion,
        value: u64,
        rho_tag: u8,
    ) -> (IronwoodNote, IronwoodRecipient, CompactAction) {
        let recipient = viewing_key.address_at(DIVERSIFIER_INDEX, scope);
        let mut nf_old_bytes = [u8::MIN; ENCODED_FIELD_SIZE];
        nf_old_bytes[FIXTURE_TAG_INDEX] = rho_tag;
        let nf_old: IronwoodNullifier = Option::from(IronwoodNullifier::from_bytes(&nf_old_bytes))
            .expect("the small test nullifier is canonical");
        let rho = Rho::from_bytes(&nf_old.to_bytes()).expect("a nullifier is a valid rho");
        let random_seed = (u8::MIN..=u8::MAX)
            .find_map(|counter| {
                let mut bytes = [rho_tag; ENCODED_FIELD_SIZE];
                bytes[FIXTURE_TAG_INDEX] = counter;
                Option::from(RandomSeed::from_bytes(bytes, &rho))
            })
            .expect("the deterministic search finds a valid note seed");
        let note: IronwoodNote = Option::from(IronwoodNote::from_parts(
            recipient,
            NoteValue::from_raw(value),
            rho,
            random_seed,
            version,
        ))
        .expect("the test note is valid");
        let cmx = ExtractedNoteCommitment::from(note.commitment());

        let (ephemeral_key, ciphertext) = match version {
            NoteVersion::V2 => {
                let encryptor = OrchardNoteEncryption::new(None, note, EMPTY_MEMO);
                (
                    OrchardDomain::epk_bytes(encryptor.epk()),
                    encryptor.encrypt_note_plaintext(),
                )
            }
            NoteVersion::V3 => {
                let encryptor = IronwoodNoteEncryption::new(None, note, EMPTY_MEMO);
                (
                    IronwoodDomain::epk_bytes(encryptor.epk()),
                    encryptor.encrypt_note_plaintext(),
                )
            }
        };
        let action = CompactAction::from_parts(
            nf_old,
            cmx,
            ephemeral_key,
            ciphertext[..COMPACT_NOTE_SIZE]
                .try_into()
                .expect("compact ciphertext length is fixed"),
        );

        (note, recipient, action)
    }

    #[test]
    fn scanning_capability_retains_identity_and_redacts_key_material() {
        let viewing_key = viewing_key(WcashNetwork::Testnet, PRIMARY_SEED_BYTE, ACCOUNT_ZERO_INDEX);
        let scanning_key = viewing_key.scanning_key(Scope::External);
        let cloned_key = scanning_key.clone();

        assert_eq!(scanning_key.network(), WcashNetwork::Testnet);
        assert_eq!(scanning_key.account(), viewing_key.account());
        assert_eq!(scanning_key.scope(), Scope::External);
        assert_eq!(scanning_key.incoming, cloned_key.incoming);
        assert_eq!(scanning_key.full, cloned_key.full);

        let debug = format!("{scanning_key:?}");
        assert!(debug.contains(REDACTION_MARKER));
        assert!(!debug.contains(&hex::encode(scanning_key.incoming.to_bytes())));
    }

    #[test]
    fn scanning_capability_binds_scope_and_network() {
        let testnet = viewing_key(WcashNetwork::Testnet, PRIMARY_SEED_BYTE, ACCOUNT_ZERO_INDEX);
        let external = testnet.scanning_key(Scope::External);
        let internal = testnet.scanning_key(Scope::Internal);
        let regtest = viewing_key(WcashNetwork::Regtest, PRIMARY_SEED_BYTE, ACCOUNT_ZERO_INDEX)
            .scanning_key(Scope::External);

        assert_ne!(external.incoming, internal.incoming);
        assert_ne!(external.incoming, regtest.incoming);
        assert_eq!(external.full, internal.full);
        assert_ne!(external.full, regtest.full);
    }

    #[test]
    fn batch_decrypts_v3_notes_in_action_order_and_derives_nullifiers() {
        let account_zero =
            viewing_key(WcashNetwork::Testnet, PRIMARY_SEED_BYTE, ACCOUNT_ZERO_INDEX);
        let account_one = viewing_key(WcashNetwork::Testnet, PRIMARY_SEED_BYTE, ACCOUNT_ONE_INDEX);
        let keys = [
            account_zero.scanning_key(Scope::External),
            account_one.scanning_key(Scope::Internal),
        ];
        let (note_one, recipient_one, action_one) = note_and_action(
            account_one.ironwood(),
            Scope::Internal,
            NoteVersion::V3,
            FIRST_NOTE_VALUE,
            FIRST_RHO_TAG,
        );
        let (note_zero, recipient_zero, action_zero) = note_and_action(
            account_zero.ironwood(),
            Scope::External,
            NoteVersion::V3,
            SECOND_NOTE_VALUE,
            SECOND_RHO_TAG,
        );

        let results = try_decrypt_compact_ironwood_batch(
            WcashNetwork::Testnet,
            &keys,
            &[action_one, action_zero],
        )
        .expect("the key batch is valid");

        assert_eq!(results.len(), POSITIVE_ACTION_COUNT);
        let first = results[FIRST_ITEM_INDEX]
            .as_ref()
            .expect("account one decrypts");
        assert_eq!(first.network(), WcashNetwork::Testnet);
        assert_eq!(first.account(), account_one.account());
        assert_eq!(first.scope(), Scope::Internal);
        assert_eq!(first.note().version(), NoteVersion::V3);
        assert_eq!(first.note(), &note_one);
        assert_eq!(first.recipient(), recipient_one);
        assert_eq!(
            first.nullifier(),
            note_one.nullifier(account_one.ironwood())
        );

        let second = results[SECOND_ITEM_INDEX]
            .as_ref()
            .expect("account zero decrypts");
        assert_eq!(second.account(), account_zero.account());
        assert_eq!(second.scope(), Scope::External);
        assert_eq!(second.note(), &note_zero);
        assert_eq!(second.recipient(), recipient_zero);
        assert_eq!(
            second.nullifier(),
            note_zero.nullifier(account_zero.ironwood())
        );
        assert!(format!("{first:?}").contains(REDACTION_MARKER));
    }

    #[test]
    fn batch_rejects_legacy_v2_ciphertext() {
        let viewing_key = viewing_key(WcashNetwork::Testnet, PRIMARY_SEED_BYTE, ACCOUNT_ZERO_INDEX);
        let key = viewing_key.scanning_key(Scope::External);
        let (_, _, action) = note_and_action(
            viewing_key.ironwood(),
            Scope::External,
            NoteVersion::V2,
            MIN_NOTE_VALUE,
            FIRST_RHO_TAG,
        );

        let results = try_decrypt_compact_ironwood_batch(WcashNetwork::Testnet, &[key], &[action])
            .expect("the key batch is valid");

        assert!(results[FIRST_ITEM_INDEX].is_none());
    }

    #[test]
    fn batch_does_not_cross_account_or_scope() {
        let recipient_key =
            viewing_key(WcashNetwork::Testnet, PRIMARY_SEED_BYTE, ACCOUNT_ONE_INDEX);
        let wrong_account =
            viewing_key(WcashNetwork::Testnet, PRIMARY_SEED_BYTE, ACCOUNT_ZERO_INDEX)
                .scanning_key(Scope::External);
        let wrong_scope = recipient_key.scanning_key(Scope::Internal);
        let (_, _, action) = note_and_action(
            recipient_key.ironwood(),
            Scope::External,
            NoteVersion::V3,
            MIN_NOTE_VALUE,
            FIRST_RHO_TAG,
        );

        let results = try_decrypt_compact_ironwood_batch(
            WcashNetwork::Testnet,
            &[wrong_account, wrong_scope],
            &[action],
        )
        .expect("the key batch is valid");

        assert!(results[FIRST_ITEM_INDEX].is_none());
    }

    #[test]
    fn batch_rejects_mixed_network_keys_before_decryption() {
        let testnet = viewing_key(WcashNetwork::Testnet, PRIMARY_SEED_BYTE, ACCOUNT_ZERO_INDEX)
            .scanning_key(Scope::External);
        let regtest = viewing_key(WcashNetwork::Regtest, PRIMARY_SEED_BYTE, ACCOUNT_ONE_INDEX)
            .scanning_key(Scope::External);

        let error =
            try_decrypt_compact_ironwood_batch(WcashNetwork::Testnet, &[testnet, regtest], &[])
                .expect_err("a mixed-network key batch is rejected");

        assert_eq!(
            error,
            WcashScanningError::NetworkMismatch {
                key_index: SECOND_ITEM_INDEX,
                expected: WcashNetwork::Testnet,
                actual: WcashNetwork::Regtest,
            }
        );
    }

    #[test]
    fn batch_rejects_duplicate_account_scope_keys() {
        let first = viewing_key(WcashNetwork::Testnet, PRIMARY_SEED_BYTE, ACCOUNT_ZERO_INDEX)
            .scanning_key(Scope::External);
        let duplicate = viewing_key(
            WcashNetwork::Testnet,
            ALTERNATE_SEED_BYTE,
            ACCOUNT_ZERO_INDEX,
        )
        .scanning_key(Scope::External);

        let error =
            try_decrypt_compact_ironwood_batch(WcashNetwork::Testnet, &[first, duplicate], &[])
                .expect_err("duplicate account and scope metadata is rejected");

        assert_eq!(
            error,
            WcashScanningError::DuplicateKey {
                first_index: FIRST_ITEM_INDEX,
                duplicate_index: SECOND_ITEM_INDEX,
                account: AccountId::ZERO,
                scope: Scope::External,
            }
        );
    }

    #[test]
    fn malformed_ephemeral_key_and_empty_batches_fail_closed() {
        let viewing_key = viewing_key(WcashNetwork::Testnet, PRIMARY_SEED_BYTE, ACCOUNT_ZERO_INDEX);
        let key = viewing_key.scanning_key(Scope::External);
        let (_, _, valid_action) = note_and_action(
            viewing_key.ironwood(),
            Scope::External,
            NoteVersion::V3,
            MIN_NOTE_VALUE,
            FIRST_RHO_TAG,
        );
        let malformed = CompactAction::from_parts(
            valid_action.nullifier(),
            valid_action.cmx(),
            EphemeralKeyBytes(INVALID_EPHEMERAL_KEY),
            EMPTY_COMPACT_CIPHERTEXT,
        );

        let malformed_result =
            try_decrypt_compact_ironwood_batch(WcashNetwork::Testnet, &[key], &[malformed])
                .expect("the key batch is valid");
        assert_eq!(malformed_result.len(), SINGLE_ACTION_COUNT);
        assert!(malformed_result[FIRST_ITEM_INDEX].is_none());

        let no_actions = try_decrypt_compact_ironwood_batch(WcashNetwork::Testnet, &[], &[])
            .expect("an empty batch is valid");
        assert!(no_actions.is_empty());

        let no_keys =
            try_decrypt_compact_ironwood_batch(WcashNetwork::Testnet, &[], &[valid_action])
                .expect("a batch without keys is valid");
        assert_eq!(no_keys.len(), SINGLE_ACTION_COUNT);
        assert!(no_keys[FIRST_ITEM_INDEX].is_none());
    }
}
