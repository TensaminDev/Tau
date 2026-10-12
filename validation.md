# Validation record

Executed on October 12, 2026, on Linux in Omikron's Nix development shell.

- Rust `1.99.0`, revision `b940084d7`, September 28, 2026.
- Cargo `1.99.0`, revision `5f94df478`, August 27, 2026.
- MTP source `https://git.methanium.net/methanium/mtp`.
- MTP revision `ad489265deacadd6de52ed2129d071803a0e7247`.
- Tau working tree had no published Git revision.

The private type-map flake input failed SSH host-key verification. Validation used
the existing local type-map checkout without changing the flake lockfile:

```sh
nix develop ../omikron \
  --override-input type-maps path:/home/alex/Development/tensamin/omikron/mtp-type-maps \
  --no-write-lock-file \
  --command bash -c 'cargo fmt --all -- --check && cargo check --all-targets && cargo test --all-targets && cargo clippy --all-targets -- -D warnings'
```

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | Passed |
| `cargo check --all-targets` | Passed |
| `cargo test --all-targets` | Passed, 14 tests |
| `cargo clippy --all-targets -- -D warnings` | Passed |

The compatibility test executed real guest and authenticated handshakes against
`MTPHost` and `MTPWebServer`. It also checked incompatible admission roles and
rejection of a cryptographic proof made with the wrong key. The separate type
compatibility test compiled both connection metadata adapters.

## Deferred dependency validation

Omikron's `cargo tree -i mtp` resolved a single MTP package shared by Tau and
Omikron at the revision above. Tau was consumed through its local path.

A Git-dependent consumer build is deferred by the user's request to keep the
integration local and commit neither repository. Tau has no commits or configured
remote. Before release, publish the validated source, select its pinned
revision in Omikron, refresh the consumer lockfile and Nix vendor hash, then run
the consumer checks without a local Cargo patch. This record does not claim a
standalone Git-dependent build passed.
