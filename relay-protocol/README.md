# Relay V2 protocol

`tau-relay-protocol` is independent of the Tau host, Iota identity resolver and storage.
It uses the same pinned MTP revision as the native applications, with only MTP's
`crypto` feature. Its optional `wasm` feature exports the same Rust implementation
to a browser.

## Native API

- `Principal { authority: String, user_id: u64 }`
- `sign_protected(signer, recipient, destination, message_id, created_at, application, &keyring, recipients)` returns `Result<RelayWire, Error>`.
- `RelayWire::to_json()` returns signed JSON bytes. `into_frame(frame_id)` returns an MTP Relay frame with VersionNumber 2 and SecurePayload containing those bytes.
- `verify_outer(json, signer_keys, expected_recipient, expected_destination)` authenticates the exact decoded content bytes and returns `VerifiedRelay { wire, protected }`.
- `verify_and_open(json, signer_keys, keyring, expected_recipient, expected_destination)` additionally decrypts, verifies the inner dual signature and checks its signer, recipient, derived message ID and timestamp. It returns `OpenedRelay { wire, application }`.
- `canonical_bytes(&wire, decoded_content)` produces the signed bytes. It does not decode, normalize or reserialize content.
- `derived_message_id(message_id)` hashes `tensamin-relay-message:v2` followed by the opaque ID's UTF-8 bytes and uses the first 16 digest bytes as a big-endian MTP MessageId.

Callers must authenticate signer key history and the encryption recipients before
calling these functions. Supply the origin Iota, destination Iota, signing client
and recipient client encryption bundles to `sign_protected`. Including the signing
client lets its durable outbox reopen its own pending operations. The protocol cannot infer their roles from
keys alone. Identity resolution, recipient home checks, authorization and durable
replay deduplication belong to callers. Expected recipient and destination are
optional in Rust so the same verification supports Iota ingress and client delivery.

The application must have an explicit type map. That map must include the
application communication type `ProtectedMessage`, SecurePayload and VersionNumber.
No legacy wire negotiation occurs. Unknown or noncanonical type-map versions fail.

The full serialized application CommunicationValue goes inside encrypted protected
content. This includes ChatId, SecretId, recipient lists and other application
metadata. Existing application ciphertext remains ciphertext. Relay protection uses
dual signatures and purposes 0x31 for signatures and 0x32 for encryption. Routers
can still see the signed routing principals, destination, opaque ID and timestamp.

## Chat identity

`canonical_chat_id(&first, &second)` sorts principals by authority and numeric user ID,
serializes the pair as compact JSON and returns `principal:v2:` followed by URL-safe
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
```

`created_at` is a JS BigInt because Rust uses u64. Key arrays are JSON arrays of
standard-base64 raw MTP PublicKeyBundle `try_as_bytes()` results. `keyring_bytes`
is the raw MTP keyring serialization. Private keys remain in the browser. Principal
JSON uses numeric `user_id`; callers must retain exact u64 JSON values rather than
rounding them through JS Number. All canonicalization, signing and verification
happen in Rust. `bridge` exposes the byte/string conversion implementation for native
verification of the browser boundary.

## Validation

The fixture map is isolated from deployment maps and includes ProtectedMessage.
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
