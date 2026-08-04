# Wallet Files use an envelope we define, not age

A Wallet File may hold a seed that controls real funds, so it is always encrypted. We define the container ourselves instead of delegating to `age`. The File Passphrase and a stored salt feed Argon2id to produce a key-encrypting key. That key wraps a fresh random data key, and the data key encrypts the body under XChaCha20-Poly1305. The entire header is bound as associated data.

Argon2id defaults to m=256 MiB, t=4, p=4, around a second on a laptop. The parameters live in the header, so files written under older or different settings keep opening. A `--kdf-cost fast|standard|paranoid` flag selects presets rather than raw numbers.

## Considered Options

`age` would have handed us an audited envelope and X25519 recipients for free. We rejected it because it fixes its own work factor, and because designing this format is part of what the project exists to do.

XChaCha20-Poly1305 over AES-256-GCM: the tool runs offline on whatever hardware is available, and ChaCha20 is constant-time in software without AES instructions. Its 192-bit nonce also leaves headroom if the format later encrypts more than one thing under one key.

## Consequences

Separating the key-encrypting key from the data key makes `rekey` rewrap 32 bytes instead of re-encrypting the body. We own the design risk of the envelope, which the property tests exist to cover.
