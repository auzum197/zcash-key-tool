# Secrets leave only through `reveal`

One verb prints secret material. `reveal` prints the Mnemonic and spending keys, and refuses to run when stdout is not a TTY unless `--allow-redirect` is passed. `display` prints Unified Addresses, viewing keys, seed fingerprints, Capability and Pool Coverage, and never a secret. `create` prints no Mnemonic at all, only the fingerprint, the default Unified Address, and an instruction to run `reveal` to record the words.

A flag on `display` would have been fewer commands to document. Flags get copied out of issue threads without their context, and the dangerous invocation would then differ from the safe one by one token. A verb appears in shell history as its own event.

We do not re-prompt for the File Passphrase before revealing. In a one-shot CLI it was supplied seconds earlier to open the file, so a second prompt guards nothing and teaches people to type passphrases at any prompt that appears.

## Consequences

Creating a wallet does not show you your words, which will surprise anyone expecting the usual CLI wallet flow. The words remain recoverable from the file at any time, so nothing is lost, and every disclosure is attributable to a `reveal` invocation.
