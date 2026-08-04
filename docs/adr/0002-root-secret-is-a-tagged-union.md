# A Root Secret is a tagged union, not a seed

A Wallet File stores its Root Secret as one of three variants: a Mnemonic with its optional Seed Passphrase, a raw seed, or an imported key. Collapsing all three into a seed would be smaller, and it would destroy information we cannot rebuild. A Mnemonic cannot be recovered from the seed it produced, so a seed-only file could never show a user their words again.

v0 accepts these imports: `uview…` and `uivk…` (ZIP-316), and Sapling `secret-extended-key-main`/`-test` (ZIP-32). We deliberately exclude the `UnifiedSpendingKey` byte blob from `zcash_keys`. It is era-tagged and internal to librustzcash rather than an interchange encoding, and persisting it inside our own format would import someone else's versioning problem.

## Consequences

Each variant carries a different Capability and Pool Coverage. A `uivk` import can produce addresses and nothing else. A Sapling extended spending key reaches exactly one pool. Every read verb reports what a Root Secret can and cannot do instead of silently omitting receivers.
