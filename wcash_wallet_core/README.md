# Wcash wallet core

This crate is the shared source of truth for Wcash wallet chain identity,
address encoding, and seed-domain separation. It is intentionally independent
of Zebra, Android, and Apple UI code so every client can verify the same public
vectors.

The crate currently exposes only public Wcash Testnet v5 and local Regtest v5.
It does not expose Wcash Mainnet. Adding Mainnet requires a separately reviewed
release after its genesis and transaction signature domain are frozen.

Wcash uses Zcash NU6.3 / Ironwood transaction semantics, but it uses distinct
transaction branch IDs, address namespaces, and a genesis-bound wallet seed
derivation. Zcash addresses and ordinary Zcash wallet seeds are not Wcash
addresses or keys. Persistent clients bind wallet state to
`WALLET_SEED_KDF_VERSION` as well as the selected chain identity.

Public key capabilities are opaque and retain the Wcash network selected at
derivation. The crate does not expose the intermediate derived seed or generic
Zcash key types, and address derivation infers its network from the viewing
capability. This prevents callers from rebinding Wcash key material to a Zcash
or different Wcash textual namespace.

The optional `ironwood-scanning` feature derives a cloneable, scope-bound
`WcashScanningKey`. Its viewing capability remains opaque, so a
consumer cannot reinterpret it as a generic Orchard or Zcash viewing key.
`try_decrypt_compact_ironwood_batch` accepts only compact Ironwood actions,
uses the version-3 Ironwood note-encryption domain, and derives each detected
note's nullifier without exposing its full viewing key.

The compact-block compatibility RPC currently reports `test` for both Wcash
Testnet and Regtest. Wallets must therefore attest the exact genesis hash and
transaction branch ID in addition to checking the RPC chain name.
