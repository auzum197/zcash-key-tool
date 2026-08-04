# The Wallet File header carries no metadata

The plaintext header holds only what is needed to derive the key-encrypting key and unwrap the data key: magic bytes, a format version, the Argon2id parameters, the salt, the nonce, and the wrapped data key. Network, Root Secret kind, seed fingerprint and any label live inside the encrypted body.

Anyone holding the file without the File Passphrase learns nothing beyond "this is one of our files". A ZIP-32 seed fingerprint in the clear would link every backup copy of a seed across every machine it was written to, which is exactly the correlation a wallet file should not hand out.

## Consequences

`display` must decrypt before it can say anything about a file, including what kind of Root Secret it holds. Inventorying a directory of Wallet Files means unlocking each one. We accept that: the alternative is a file that announces itself as a funded mainnet wallet to whoever picked it up.
