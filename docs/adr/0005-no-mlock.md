# Zeroize and disabled core dumps, but no mlock

Secret types are held in `Zeroizing` and `secrecy` wrappers so they are cleared on drop and cannot be printed or copied by accident. At startup we call `setrlimit(RLIMIT_CORE, 0)` to stop a panic or a segfault from writing a seed into a core file.

The crate contains exactly two `unsafe` expressions, both FFI rather than memory tricks: that `setrlimit` call, and `File::from_raw_fd` for `--file-passphrase-fd`, where the descriptor comes from the caller and the compiler cannot know it is valid. The second is wrapped in `ManuallyDrop` so we read from the caller's descriptor without closing it.

We do not call `mlock`. It would pin pages against swap, and it protects only the buffer we locked, never the copies that already exist: the `String` a Mnemonic arrives in, a `Vec` that reallocated while growing, a value the compiler moved. `RLIMIT_MEMLOCK` is commonly 64 KiB and lower inside containers, so the call fails often, and it fails hardest on the constrained machines most likely to be swapping. A guarantee that is absent precisely when it matters is worse than a documented absence.

## Consequences

Secrets can reach swap or a hibernation image. The documentation says so and recommends encrypted swap. Anyone proposing `mlock` should read this first.

The File Passphrase and the Mnemonic never arrive via argv or environment variables, only from a TTY prompt, `--file-passphrase-fd`, or `--file-passphrase-file`. `ps` output and `/proc/<pid>/environ` are readable by things we do not control.
