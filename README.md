# Tau

Tau validates admission after an MTP handshake. It borrows accepted connection
metadata, matches the requested description to application-defined role rules,
and returns an owned context with a unique connection-instance ID.

The application owns its host, transport, connection limits, message handlers,
identity authority, authorization and cleanup. Tau has no listener or routing
registry. Its lifecycle state describes one connection. Reconnect replacement
and stale-disconnect protection require an application-owned registry.

Tau does not implement handshakes, key lookup, registration, task supervision,
connection permits, connection authorization, federation, Community permissions or routing.
Its separate `tau::calls` module owns call-domain authorization after the host
has resolved an authenticated actor.

## Call management

`tau::calls::CallManagement` is the shared execute, snapshot, and join-authorization
interface. `CallEngine` coordinates the host repository, media controller, event
publisher, ciphertext directory, and authoritative clock. SQL and provider SDKs
remain outside Tau.

`transition` is deterministic for the aggregate, verified actor, typed request,
and host time. The repository commits its aggregate, audit, revisioned events,
durable operation result, and effects in one transaction. It checks operation-ID
replays before current membership or revision, and rejects conflicting content.
Hosts must construct one engine per authoritative writer and route every call
mutation through it. Admission roles are independent of mutable call roles.

Microphone restrictions and server deafen are independent. Server deafen denies
all media reception and microphone publication, not audio-only reception. Clearing
a restriction restores permission; it never starts capture or remotely unmutes.
Provider capability errors and pending enforcement remain explicit.

Snapshots include a canonical roster, requester permissions and restrictions,
visible invitations, lifecycle, revision, and separate key-availability and
installation generations. Key-envelope reads use `authorize_envelope_read`,
which is stricter than snapshot visibility. Ciphertext availability does not prove
that a client installed the epoch.

`calls::conformance::call_management_conformance` accepts an async fixture factory.
It runs the same interface checks against the reference in-memory backend and
Omikron's SQLite backend. Future Iota hosting can supply its own factory without
duplicating policy. Iota-hosted authority execution is not implemented here.

## Admission

```rust,no_run
use tau::{AdmissionEngine, AuthenticationRequirement, ConnectionFacts, RoleRule, RoleRules};

#[derive(Clone)]
enum Role { Client, Guest }

let mut rules = RoleRules::new();
rules.register(RoleRule {
    description: "client".into(),
    authentication: AuthenticationRequirement::Authenticated,
    role: Role::Client,
})?;
rules.register(RoleRule {
    description: "guest".into(),
    authentication: AuthenticationRequirement::Guest,
    role: Role::Guest,
})?;
let engine = AdmissionEngine::new(rules);

// This example assumes the application's MTP key lookup already binds account
// IDs to the expected keys. Keep the full key if your principal needs it.
enum Principal {
    Account { id: u64, key: Vec<u8> },
}

fn admit<S, R, P>(
    connection: &mtp::host::MTPConnection<S, R, P>,
    engine: &AdmissionEngine<Role>,
) -> Result<tau::Session<Role, Principal>, tau::AdmissionError> {
    engine.admit(&ConnectionFacts::from_mtp(connection))?
        .into_session(|role, id, key| match role {
            Role::Client => Ok(Principal::Account {
                id,
                key: key.try_as_bytes().map_err(|_| tau::AdmissionError::RejectedActivation)?,
            }),
            Role::Guest => Err(tau::AdmissionError::RejectedActivation),
        })
}
# Ok::<(), tau::AdmissionError>(())
```

For an accepted native or WebTransport connection, call
`engine.admit(&ConnectionFacts::from_mtp(&connection))`. This borrows metadata
without cloning senders or receivers. The admission stores a copy of the
verified public-key bundle so its session can outlive the metadata borrow.
Call admission once per accepted connection. Tau deliberately accepts generic
facts and does not deduplicate transports. The owning adapter must combine
admission and connection construction, then retain the one authoritative context.
`ConnectionId`, MTP's `client_id` and application session IDs are independent.

Unknown descriptions, pending or failed authentication, missing authenticated
keys and guest connections carrying verified keys fail closed. Descriptions,
paths, claimed numeric IDs and remote addresses do not prove identity. Supply
facts only from a trusted accepted MTP connection. Manually constructed facts
are useful in policy tests but do not verify a handshake.

## Principal identity and authentication

`Admission::into_session` takes a synchronous trusted identity resolver. Tau
invokes it only for authenticated transport, with the resolved role, MTP ID
and verified key. The resolver must bind that key and role to the application's
principal type. It can reject the binding. Guest sessions never invoke it and
have no registered principal.

Transport verification means MTP checked possession of the expected key through
the application's configured lookup. Identity resolution associates that result
with an application principal. Tau repeats neither the lookup nor the signature
verification. A resolver must reject a key, ID or namespace inconsistent with
the role. An arbitrary unverified numeric ID must never produce an authenticated
principal. Tau cannot inspect the meaning of a generic application identity.

The verified key remains part of every resolver call. A centralized adapter can
rely on the key-to-principal relationship established by its lookup. A
decentralized adapter can instead resolve an identity derived from the full key.

`Session<Role, Identity>` has separate transport and application authentication
states. Identity has no `Copy`, numeric-conversion or equality requirement.
An adapter can use typed numeric account IDs, public-key-derived node IDs or
foreign principals without changing Tau.

After transport authentication and any application activation checks, call
`establish_transport_session()`. A guest upgrade instead consumes a
`VerifiedApplicationAuthentication<Identity>` through
`authenticate_application()`. `session.verify_application(request, verifier)`
passes the connection context and request to a trusted application-supplied
closure. The closure returns a future with an application identity or its own
verification error. Tau binds a successful result to that session's connection
ID without mutating authentication. The caller then commits the transition after
its attachment and activation checks succeed.

`VerifiedApplicationAuthentication::assert_verified` is also available for
existing verifier integrations. It is a trusted caller assertion, not a proof
created or verified by Tau. Construct it only after the application's verifier
validates the proof, identity, key, challenge and connection binding.
The application must enforce replay restrictions and authorize the caller to
assert that identity.
The result contains the target `ConnectionId` and cannot be applied to another
connection. Tau does not verify signatures or grant application permissions.

These transitions never alter MTP's `AuthState` or Tau's original transport
result. An application-authenticated foreign principal can therefore retain
guest transport authentication. Community membership checks belong to the
application.

The admission role is immutable. It records the handshake request validated by
the admission rules, not the handler now running. An upgraded registration guest
can have a client principal and client handler while retaining its guest
transport and registration role. Authorization must use the verified principal
and application policy rather than the original description alone.

## Lifecycle

Call `activate()` when application handling starts and `close()` after it ends.
Activation is allowed once, from `Admitted`. Closing is terminal and idempotent.
Active means the application accepted handling responsibility. It does not
promise successful application registry insertion, published peer routes, handler
availability, or a physically connected transport.
`reject()` records `SessionOutcome::Rejected` and closes the session without
changing its verified principal. Normal closure records `SessionOutcome::Closed`.
Repeated closure or rejection preserves the first terminal outcome.
Tau does not release permits
or close a transport. The application must await its actual handler lifetime,
including any registration upgrade, before releasing those resources.

Authentication describes the verified principal and origin. Lifecycle describes
handler execution. Outcome describes terminal closure or rejection. Admission
failure returns `AdmissionError` before a session exists. The same error type
also covers validated transitions because current consumers handle these failures
at the same connection boundary.

| Operation | Required state | Result |
|---|---|---|
| Activate guest handler | Admitted guest | Active guest, no new principal |
| Activate transport handler | Admitted transport principal | Active, authentication unchanged |
| Authenticate application | Open guest, result bound to this connection | Application-authenticated principal, lifecycle unchanged |
| Establish transport session | Open transport-authenticated principal | Application session established, lifecycle unchanged |
| Reject before activation | Admitted | Closed with rejected outcome, principal unchanged |
| Reject after activation | Active | Closed with rejected outcome, principal unchanged |
| Close normally | Admitted or active | Closed with normal outcome, principal unchanged |
| Close or reject again | Closed | No change |
| Activate again | Active or closed | Error |
| Repeat authentication or establishment | Already upgraded or incompatible origin | Error |
| Authenticate or establish after termination | Closed | Error |

Applications own handler selection and must keep an admitted guest in its guest
handler until application policy accepts a verified upgrade. A handler change
does not authenticate a principal. Transport-authenticated sessions can still
fail application activation and be rejected.
