use orchard::{
    Address as IronwoodAddress,
    keys::{FullViewingKey as IronwoodFullViewingKey, SpendingKey as IronwoodSpendingKey},
};
use secrecy::SecretVec;
use static_assertions::assert_not_impl_any;
use wcash_wallet_core::{
    WcashAddress, WcashFullViewingKey, WcashNetwork, WcashRecipient, WcashSpendingKey,
    decode_recipient, derive_wallet_spending_key, encode_ironwood_receiver,
};
use zcash_address::ZcashAddress;
use zcash_keys::{
    address::UnifiedAddress,
    keys::{UnifiedFullViewingKey, UnifiedSpendingKey},
};
use zcash_protocol::consensus::Parameters;
use zcash_transparent::{
    address::TransparentAddress,
    keys::{AccountPrivKey, AccountPubKey},
};
use zip32::AccountId;

// These assertions are compiled as a downstream consumer. They lock out the
// conversion traits that would let an application rebind a Wcash capability
// to generic Zcash network or address APIs.
assert_not_impl_any!(WcashNetwork: Parameters);
assert_not_impl_any!(WcashSpendingKey: Clone, Copy, AsRef<UnifiedSpendingKey>, Into<UnifiedSpendingKey>);
assert_not_impl_any!(WcashFullViewingKey: Clone, Copy, AsRef<UnifiedFullViewingKey>, Into<UnifiedFullViewingKey>);
assert_not_impl_any!(WcashAddress: AsRef<ZcashAddress>, Into<ZcashAddress>);
assert_not_impl_any!(WcashRecipient: AsRef<UnifiedAddress>, Into<UnifiedAddress>);
assert_not_impl_any!(WcashSpendingKey: AsRef<AccountPrivKey>, Into<AccountPrivKey>, AsRef<IronwoodSpendingKey>, Into<IronwoodSpendingKey>);
assert_not_impl_any!(WcashFullViewingKey: AsRef<AccountPubKey>, Into<AccountPubKey>, AsRef<IronwoodFullViewingKey>, Into<IronwoodFullViewingKey>);
assert_not_impl_any!(WcashRecipient: AsRef<TransparentAddress>, Into<TransparentAddress>, AsRef<IronwoodAddress>, Into<IronwoodAddress>);

#[test]
fn public_key_and_address_apis_retain_the_selected_network() {
    const MASTER_SEED_BYTE: u8 = 0x5a;
    const MASTER_SEED_LEN: usize = 32;

    let master_seed = SecretVec::new(vec![MASTER_SEED_BYTE; MASTER_SEED_LEN]);
    let account = AccountId::try_from(0).expect("zero is a valid ZIP 32 account");
    let testnet = derive_wallet_spending_key(&master_seed, WcashNetwork::Testnet, account)
        .expect("the test seed derives")
        .to_full_viewing_key()
        .expect("the validated key reconstructs");
    let regtest = derive_wallet_spending_key(&master_seed, WcashNetwork::Regtest, account)
        .expect("the test seed derives")
        .to_full_viewing_key()
        .expect("the validated key reconstructs");

    let testnet_address = encode_ironwood_receiver(&testnet).expect("the testnet receiver derives");
    let regtest_address = encode_ironwood_receiver(&regtest).expect("the regtest receiver derives");

    assert_ne!(testnet_address, regtest_address);
    assert_eq!(
        decode_recipient(&testnet_address)
            .expect("the testnet address decodes")
            .network(),
        WcashNetwork::Testnet
    );
    assert_eq!(
        decode_recipient(&regtest_address)
            .expect("the regtest address decodes")
            .network(),
        WcashNetwork::Regtest
    );
}
