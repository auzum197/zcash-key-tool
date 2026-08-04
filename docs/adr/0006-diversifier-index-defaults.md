# Without an explicit index, derivation searches for a complete address

Roughly half of all Diversifier Indices yield no valid Sapling address. A tool that always used index 0 would therefore show a Unified Address missing its Sapling Receiver about half the time, with nothing to indicate anything was dropped.

So the behaviour splits on whether the caller named an index:

- No `--diversifier-index`: require every Receiver the Root Secret covers and walk upward until one index satisfies all of them. The index actually used is printed, and a note says the search happened.
- An explicit `--diversifier-index`: use exactly that index, allow whatever Receivers are valid there, and note the ones that are not.
- An explicit `--receivers` list: honour it exactly in both cases.

## Consequences

The default view is the complete address rather than the one a wallet would hand out at index 0, which is the right default for a tool whose job is inspection. Anyone reproducing a specific wallet's address passes the index and gets index-for-index behaviour.
