# Federation relay protocol

`tau-relay-protocol` is independent of the Tau host, Iota identity resolver and storage.
It uses the same pinned MTP revision as the native applications, with MTP's
`crypto` feature and a direct `mtp-type-map` registry dependency. Registry support
keeps fixed-map lookup available without host feature unification. Its optional `wasm` feature exports the same Rust implementation
to a browser.

## Native API

- `Principal { authority: String, user_id: u64 }`
- `RelayWire::from_json(bytes)` performs bounded JSON decoding and structural validation. `wire.validate()` applies the same structural policy to an existing struct. Neither authenticates signatures. Direct `serde_json` deserialization does not enforce these limits.
- `sign_protected(signer, recipient, destination, message_id, created_at, application, &keyring, recipients)` returns `Result<RelayWire, Error>`.
- `RelayWire::to_json()` returns signed JSON bytes. `into_frame(frame_id)` returns an MTP Relay frame whose only payload field is SecurePayload containing those bytes. `RelayWire::from_frame()` rejects legacy version fields, unsigned envelope metadata and mismatched type maps.
- `verify_outer(json, signer_keys, expected_recipient, expected_destination)` authenticates the exact decoded content bytes and returns `VerifiedRelay { wire, protected }`.
- `verify_and_open(json, signer_keys, keyring, expected_recipient, expected_destination)` additionally decrypts, verifies the inner dual signature and checks its signer, recipient, derived message ID and timestamp. It returns `OpenedRelay { wire, application }`.
- `canonical_bytes(&wire, decoded_content)` produces the signed bytes. It does not decode, normalize or reserialize content.
- `derived_message_id(message_id)` hashes `tensamin-relay-message\0` followed by the opaque ID's UTF-8 bytes and uses the first 16 digest bytes as a big-endian MTP MessageId. The outer signature domain is `tensamin-federated-relay\0`.

Callers must authenticate signer key history and the encryption recipients before
calling these functions. Supply the origin Iota, destination Iota, signing client
and recipient client encryption bundles to `sign_protected`. Including the signing
client lets its durable outbox reopen its own pending operations. The protocol cannot infer their roles from
keys alone. Identity resolution, recipient home checks, authorization and durable
replay deduplication belong to callers. Expected recipient and destination are
optional in Rust so the same verification supports Iota ingress and client delivery.

The application must have an explicit, supported type map. The signed
`type_map_version` declares that application's map, and opening decodes the
application with exactly that map. There is no latest-map fallback or legacy
wire negotiation. Unknown or noncanonical versions fail.

`PROTECTED_TYPE_MAP_VERSION` is the exported fixed string `"1.0"`. Relay protection
always builds and decodes the encrypted `ProtectedMessage` with this map, independently
of the application's declared map. The compiled map `1.0` must contain the application
communication type `ProtectedMessage` and MTP's reserved protected-envelope fields.
The deployment map currently assigns `ProtectedMessage` ID 32. SecurePayload
must be available in the application's map for `into_frame`.
A build without the protected map fails when signing or verifying protected content.
This contract does not infer a protected map from untrusted application version text.

`DEFAULT_APPLICATION_TYPE_MAP_VERSION` re-exports MTP's `PROTOCOL_VERSION` as a
`mtp::type_map::Version`. Default native producers can construct their explicit
`TypeMap` from it. The WASM getter `relay_application_type_map_version()` returns
its canonical string for SDK default producers and journal fingerprints. This
shares the SDK frame builder's selected map without a separate literal. Explicit
per-message application maps remain supported and signed independently.

The full serialized application CommunicationValue goes inside encrypted protected
content. This includes ChatId, SecretId, recipient lists and other application
metadata. Existing application ciphertext remains ciphertext. Relay protection uses
dual signatures and purposes 0x31 for signatures and 0x32 for encryption. Routers
can still see the signed routing principals, destination, opaque ID and timestamp.

## Resource limits

`RelayProtocolLimits` is the shared native and browser policy. All sizes measure
bytes, including UTF-8 text. Its defaults are:

| Field | Default |
| --- | --- |
| `max_wire_bytes` | 24 MiB of complete wire JSON |
| `max_protected_bytes` | 16 MiB of serialized protected CV bytes |
| `max_application_bytes` | 16 MiB of serialized application CV bytes |
| `max_authority_bytes` | 1024 per principal |
| `max_message_id_bytes` | 256 |
| `max_type_map_version_bytes` | 32 |
| `max_destination_bytes` | 72, with the existing canonical `iota:v1:` plus 64 lowercase hex digits requirement |
| `max_signer_keys` | 8 |
| `max_recipient_keys` | 64, also capped by MTP's `MAX_RECIPIENTS` |
| `max_depth` | 64 |
| `max_fields` | 65,536 MTP value nodes or JSON tokens, including object keys and containers |
| `max_allocated_bytes` | 64 MiB per MTP decoder operation |

The original APIs use `RelayProtocolLimits::default()`. Configurable variants take
`&RelayProtocolLimits` as their last argument:

- `sign_protected_with_limits`, `verify_outer_with_limits`, `verify_and_open_with_limits`
- `canonical_bytes_with_limits`
- `RelayWire::to_json_with_limits`, `RelayWire::into_frame_with_limits`
- `RelayWire::from_json_with_limits`, `RelayWire::validate_with_limits`
- `bridge::sign_protected_bytes_with_limits`, `bridge::verify_and_open_bytes_with_limits`
- `bridge::public_keys_with_limits`

The general `public_keys` parser uses the recipient-list bound. The verification
bridge applies the signer-history bound instead. Empty signer histories and empty
encryption recipient lists remain invalid. Every bridge and relay default uses the
same policy, including the signing and opening WASM exports. Browser chat helpers
also bound their principal JSON inputs with that policy.

The MTP defaults ground the 16 MiB codec byte bounds, depth 64, 65,536 values,
64 recipients and 64 MiB decoder allocation budget. Wire JSON allows 24 MiB to
hold base64 expansion of 16 MiB protected bytes plus signatures and identities.
This is a protocol ceiling. A transport with MTP's default 16 MiB message limit
must admit a smaller wire or increase its transport policy deliberately. The
signer-history ceiling preserves the existing eight-key relay contract. Identity
ceilings bound routing text independently of the application payload.

Raw JSON gets an allocation-free byte, depth and token-count preflight before
Serde deserialization. Principal fields are checked after this bounded parse and
before canonical-byte allocation or crypto. Key arrays additionally get raw string
and list-count checks before `Vec<String>` deserialization. Their JSON byte bound
allows six-byte JSON escapes for each base64 character and 1024 bytes of extra
whitespace. Base64 lengths are checked before decoding. Public bundles use the
pinned suite constants, 1216-byte KEM, 1952-byte ML-DSA and 32-byte Ed25519 keys,
plus three u16 length prefixes. Their field lengths are checked before MTP validation.
Outer signatures must contain exactly MTP's 3373-byte dual signature, split at its
64-byte Ed25519 signature length.

The raw keyring bound follows MTP's format, six u16-length fields, at most 393,222
bytes total. Layout and trailing bytes are checked before MTP allocates key fields.
This preserves MTP's role-specific partial keyrings. It is a format bound, not full
key-material validation or a change to keyring policy.

MTP receives explicit decode and encode limits for application frames, protected
frames and protected opening, including signed-byte reconstruction. Protected
opening retains one decryption keyring and the configured signer history bound.
The application byte bound is checked before decoding the opened application.
The protected builder also receives explicit encode limits. Protected framing,
signatures and encryption overhead share the protected-byte budget, so an application
at its own byte ceiling may not fit inside that budget.

These are per-operation bounds, not a process-wide allocation or crypto-work budget.
The pinned protected opener decrypts the admitted ciphertext and decodes the signed
envelope before the relay can inspect the application's byte-string length. Its
decode allocation budget does not include all temporary decryption buffers or
copies. JSON allocations are bounded by the admitted JSON size, not by the MTP
allocation budget. Serde's own recursion ceiling and MTP's fixed recipient ceiling
still apply when a custom policy raises those limits. WASM argument copying occurs
before the Rust boundary checks. In-memory Rust APIs cannot undo allocations made
by their callers. Relay-side limit failures return `Error::Limit { field, actual, max }`;
codec-internal limit failures retain the existing `Error::Mtp` representation.
With unusually small custom allocation budgets, signing can fit the application
and encrypted frame while opening rejects the larger decrypted signed-envelope
allocation. The pinned builder has no receive-allocation hook for that envelope.
Custom policies therefore need a sign/open compatibility check before deployment.

## Chat identity

`canonical_chat_id(&first, &second)` sorts principals by authority and numeric user ID,
serializes the pair as compact JSON and returns `principal:` followed by URL-safe
base64 without padding. `canonical_chat_participants` returns the individual compact
principal JSON strings in that same order. Use those strings for SetChatSecret's
recipient UserId fields. `chat_secret_id(chat_id)` returns `chat:{chat_id}:main`.
Compute these IDs before encrypting application content whose key derivation binds
to them.

## Browser API

Build from this directory with the deployment type map and an installed WASM target:

```sh
MTP_TYPE_MAPS=/absolute/path/to/type-maps.yaml wasm-pack build --target web --features wasm --out-dir pkg
```

Use a wasm-pack/wasm-bindgen CLI version matching Cargo.lock's wasm-bindgen version.
Generated artifacts belong in the consuming client's chosen asset directory.

Exports:

```text
relay_sign_protected(signer_json, recipient_json, destination, message_id,
  created_at, type_map_version, application_bytes, keyring_bytes,
  recipient_keys_json) -> Uint8Array of wire JSON
relay_verify_and_open(wire_json, signer_keys_json, keyring_bytes,
  expected_recipient_json, expected_destination) -> Uint8Array of application CV
relay_canonical_chat_id(first_json, second_json) -> string
relay_chat_participants(first_json, second_json) -> JSON array of principal strings
relay_chat_secret_id(chat_id) -> string
relay_protected_type_map_version() -> string, currently "1.0"
relay_application_type_map_version() -> string, MTP's default producer map
```

`created_at` is a JS BigInt because Rust uses u64. Key arrays are JSON arrays of
standard-base64 raw MTP PublicKeyBundle `try_as_bytes()` results. `keyring_bytes`
is the raw MTP keyring serialization. Private keys remain in the browser. Principal
JSON uses numeric `user_id`; callers must retain exact u64 JSON values rather than
rounding them through JS Number. All canonicalization, signing and verification
happen in Rust. `bridge` exposes the byte/string conversion implementation for native
verification of the browser boundary.

The protected-map getter generates a JS export and a TypeScript `(): string`
declaration through wasm-bindgen. It does not report the application's map. CV
bytes do not include that version; the encoder must supply its selected version
to `relay_sign_protected`. Generated bindings belong in the consuming package.

## Validation

The fixture map is isolated from deployment maps. Protected signing/opening tests
must compile map `1.0` with ProtectedMessage; a fixture containing only map `3.0`
cannot exercise the fixed protected-map contract. A multi-map fixture additionally
requires MTP's registry support, enabled directly by this crate.
Run with the Iota development shell:

```sh
nix develop ../../iota --command env MTP_TYPE_MAPS="$PWD/tests/type-maps.yaml" cargo test --locked --features wasm
nix develop ../../iota --command env MTP_TYPE_MAPS="$PWD/tests/type-maps.yaml" cargo clippy --locked --all-targets --features wasm -- -D warnings
```

If the private type-map flake input cannot be fetched, add
`--override-input type-maps path:/absolute/path/to/iota/mtp-type-maps` before
`--command`. If the pinned MTP repository is unavailable, use Cargo's `--config`
patch flags to map both `mtp` and `mtp-crypto` from the git source to the local MTP
checkout at the exact manifest revision. No MTP source changes are needed. The
standalone Cargo.lock retains the pinned MTP revision's locked dependencies,
including versions subsequently yanked from the registry. A local source override
is not evidence that the published dependency build succeeds.

Tests cover canonical vectors, chat identity ordering, encrypted metadata, all three
decryption recipients, wrong decryption keys, signed field tampering, invalid IDs
and maps, re-signed inner/outer mismatches and the shared browser byte boundary.
