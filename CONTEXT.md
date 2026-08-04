# Offline Key Derivation

An offline tool for creating, importing, and inspecting Zcash key material. It never touches the network and never sees a chain.

## Language

### Secrets

**Root Secret**:
The single piece of key material a Wallet File is built around. It is one of a Mnemonic, a raw seed, or an imported key, and every other artifact the tool shows is derived from it.
_Avoid_: master key, root key

**Mnemonic**:
A BIP-39 word sequence that encodes entropy, from which a seed is computed.
_Avoid_: seed phrase, recovery phrase, words

**Seed Passphrase**:
The optional BIP-39 passphrase (the "25th word") that is mixed with a Mnemonic to produce a different seed. Wrong input yields a valid but different wallet, with no error.
_Avoid_: passphrase, password, 25th word

**File Passphrase**:
The secret that unlocks a Wallet File. It has no effect on any derived key.
_Avoid_: passphrase, password, PIN

### Artifacts

**Wallet File**:
One file holding exactly one Root Secret, encrypted at rest.
_Avoid_: keystore, vault, wallet

### Derivation

**Account**:
The hardened ZIP-32 level that separates independent balances under one Root Secret. Identified by an account index.
_Avoid_: wallet, sub-wallet, profile

**Diversifier Index**:
The value that picks one shielded address out of the many an Account can present. It is not a derivation child, and it does not change the underlying keys.
_Avoid_: index, address index, address number

**Scope**:
Whether an address is meant to be handed out (External) or to receive this Account's own change (Internal).
_Avoid_: chain, branch, change flag

**Receiver**:
One pool-specific address embedded in a Unified Address. A Unified Address carries one or more.
_Avoid_: pool address, sub-address

**Capability**:
What a Root Secret permits: spending, full viewing, or incoming viewing only. Imports can arrive with less than full capability, and the tool reports what is missing rather than pretending.
_Avoid_: permission, access level

**Pool Coverage**:
Which of Orchard, Sapling, and transparent a given Root Secret can produce keys for. A Sapling extended spending key covers exactly one pool, a seed covers all three.
_Avoid_: supported pools, key types

**Network**:
Which Zcash network a derivation and its encodings target: Main, Test, or
Regtest. It selects the coin type and the human-readable prefixes, and never
changes a Root Secret. Test and Regtest share coin type 1, so a Root Secret
yields the same key bytes on both and differs only in how they are written.
_Avoid_: chain, environment

**Unified Address**:
An address that carries Receivers for one or more pools, selected by an Account, a Diversifier Index, and a Scope.
_Avoid_: UA, address
