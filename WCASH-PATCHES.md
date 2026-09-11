# Wcash downstream protocol extensions

This repository is an auditable downstream of
[`zcash/librustzcash`](https://github.com/zcash/librustzcash). Standard Zcash
network behavior remains unchanged.

Wcash Testnet v1 and local Regtest reuse NU6.3 / Ironwood transaction semantics
but use distinct transaction and signature domains:

- Testnet v1: `0xb3cfd27e`, derived from SHA-256 over
  `Wcash/NU6.3/Ironwood/v0`.
- Regtest v1: `0xc3a6678a`, derived from SHA-256 over
  `Wcash/regtest/NU6.3/Ironwood/v1`.

The `Parameters::branch_id_for_upgrade` hook selects those domains without
altering Zcash's standard network-upgrade mapping. Transaction construction,
version selection, parsing, hashing, and PCZT creation then carry the exact
selected branch ID.

These identifiers are frozen only for Wcash Testnet v1 and Regtest. Wcash
mainnet remains intentionally unsupported until its genesis, branch ID,
address/key domains, and activation parameters are independently reviewed and
frozen in the node implementation.
