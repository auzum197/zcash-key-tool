# A Network selects encodings, not a chain

The tool is offline. It never sees a chain, so a Network is nothing but a coin
type and a table of human-readable prefixes.

`zcash_protocol::consensus::Network` carries only mainnet and testnet. Regtest
lives outside it as `LocalNetwork`, which demands ten or more activation
heights. We define `derivator::Network { Main, Test, Regtest }` in
`src/network.rs` and implement `Parameters` ourselves — the trait is not
sealed. `network_type()` is the entire implementation. `activation_height()`
returns `None` for every upgrade, because there is no chain to activate
against, and `zcash_keys` 0.16 never reads it. The blanket
`impl<P: Parameters> NetworkConstants for P` supplies every `hrp_*`,
`coin_type`, and b58 prefix unchanged.

## Consequences

`activation_height() -> None` is the decision, not an unfinished stub.
Restoring real heights would mean the tool had stopped being offline.

Test and Regtest both use coin type 1. One Root Secret yields identical key
bytes on both, and only the encoding differs. The regtest vector tier asserts
exactly that.

Regtest transparent b58 prefixes are byte-identical to testnet's (`0x1d25`,
`0x1cba`, `0xef`), so a regtest t-address is a testnet t-address. The tool
prints it unremarked on both networks, and an equality assertion in the regtest
tier fails the day upstream gives regtest its own prefix.

Swapping back to `zcash_protocol::consensus::Network` in a cleanup pass
silently drops regtest. The upstream enum cannot express it.
