# Reusable services and application ownership

Enable `xconn-core`'s optional `services` feature to use RPC bridging,
managed backends, stream routing, and endpoint discovery. The separate
`crypto` feature re-exports portable packet encryption. Ordinary WAMP clients and
routers do not need either feature.

| Responsibility | Owner |
| --- | --- |
| WAMP protocol, clients, routers, transport connections and TLS | XConn Core |
| RPC forwarding, cancellation and owned caller-session cleanup | XConn Core |
| Backend reconnection, retry/backoff and transport cleanup | XConn Core |
| Endpoint directory, validation, ownership and presence cleanup | XConn Core |
| Packet encryption and key-agreement primitives | XConn Core |
| Enrollment protocol and credential issuance/revocation | Application or service provider |
| Credential storage, machine identifiers, roles and permissions | Application |
| Shell, files, VPN, UI and operating-system integration | Application |

Core services impose no product-specific procedure prefix, identity format,
credential files, enrollment server, or local socket architecture.

## Managed backends

Use `Client::serve` to connect a backend and restore its registrations after a
connection loss. Setup receives an ordinary session and runs once per connection.
A setup error stops the runner. Dropping the runner future closes its session.

```rust
Client::default().serve(uri, realm, |session| async move {
    let registered = session.register("example.echo", |invocation| async move {
        RpcResult::new(invocation.args, invocation.kwargs)
    }).execute().await?;
    if let Some(error) = registered.error {
        return Err(Error::application(error));
    }
    Ok(())
}).await?;
```

Go provides the same lifecycle with context cancellation:

```go
err := client.Serve(ctx, uri, realm, func(ctx context.Context, session *xconn.Session) error {
    return session.Register("example.echo", echo).ExecuteContext(ctx).Err
})
```

Use Rust `quic::run_backend` or Go `RunQUICBackend` when a backend also accepts raw
streams. Its handler receives the session and QUIC connection. Returning an error
stops the runner; return success on normal stream EOF and honor cancellation.
The runner closes the connection and restores the handler after disconnection.

The runnable [`backend` example](../crates/xconn-core/examples/backend.rs) has
`hub`, `backend` and `call` modes. Restart its router to see RPC restoration.
Credentials, enrollment, and decisions to stop retrying belong to the application.
The lower-level `attachment::supervise` / Go `RunAttachment` remain available for
custom enrollment cycles with multiple sessions and detachment outcomes.

## Managed stream routing

Configure `Router::route_streams` / Go `Router.RouteStreams` before starting
QUIC or WebTransport listeners. Applications supply three policies:

- `Destination`: map an authenticated backend identity to an opaque routing key.
- `Route`: read the application's existing header and choose its destination.
- `Authorize`: check the authenticated source and target before opening a stream.

Listeners then own destination registration, replacement, forwarding and cleanup.
Applications do not need accept loops, a broker registry or forwarding workers.
The first successfully authenticated WAMP session identifies the connection.
Identity always comes from WAMP authentication, never the routing header.

```go
err := router.RouteStreams(ctx, xconn.StreamRouting{
    Destination: backendKey,
    Route: readRoutingHeader,
    Authorize: authorize,
})
```

Go's route callback receives a borrowed native stream and returns `StreamRoute`.
It may supply `Prefix` to replay its header and `Failure` to send its protocol's
error response when the destination cannot be opened. The callback must not
retain the stream or start concurrent I/O. Header reads have a ten-second deadline;
router closure also cancels them. Rust returns `incoming.route_to(key)` with
optional `with_prefix` / `with_failure`; Rust applications should bound their
header parser with `tokio::time::timeout`.

Policy callbacks and wire framing stay application-owned. There is no prescribed
machine realm, role, file operation or enrollment protocol. Existing WAMP clients
and routers that do not configure stream routing keep their current behavior.
These additions require the native SDK prepared on this branch.

## RPC bridges

`async_::services::bridge::Bridge` owns forwarding registrations. It can forward
to a shared target session or use an application-supplied factory that creates
an owned target session for each disclosed caller. It preserves payloads,
progressive inputs/results, and WAMP application errors, and propagates call
cancellation.

The application owns the source and shared target sessions. The bridge owns
sessions created by its factory and closes them when their callers leave.
Factory mode requires caller disclosure and `wamp.session.on_leave` meta events.
Explicit `close` waits for cleanup. Dropping the bridge schedules cleanup on its
original Tokio runtime, which must remain alive for that work to complete.

A forwarded progressive call remains correlated until its source invocation
finishes writing the final reply or is interrupted. Trailing input chunks cannot
reopen an already-completed backend invocation. Tests cover this race, independent
input/results options, and cancellation of the backend handler.

## Stream broker

`async_::services::stream_broker::StreamBroker` tracks authenticated destinations
under application-chosen keys. Construction requires a policy callback receiving
the authenticated source, destination key and destination identity. Policy is
checked before opening each stream. Identity comes from the transport's
successful WAMP authentication, never a client-provided routing header.

`register(key, identity, opener)` returns an owned `DestinationRegistration`.
Keep it alive until that destination disconnects; dropping it removes the entry.
An old connection's cleanup cannot remove a newer registration under the same
key. The application is responsible for admitting destinations and choosing
which key each may register. There is no remote registration RPC or built-in
realm/role convention.

The opener can capture a QUIC connection or another stream-capable transport:

```rust
let registration = broker.register(key, authenticated_identity, Arc::new(move || {
    let connection = connection.clone();
    Box::pin(async move {
        Ok(Box::new(connection.open_raw().await?) as BoxStream)
    })
}))?;
```

`relay(source, key, incoming)` opens and forwards a stream. `open(source, key)`
returns an authorized destination stream instead, allowing a compatibility
adapter to write its existing header before calling `forward(incoming, outgoing)`.
The broker parses no DeskConn operations, file paths, or text/binary framing.

Forwarding uses bounded buffers and transport backpressure. A request-side EOF
half-closes the destination writer and lets the remaining reply drain. Cancelling
the forwarding future releases both owned streams. Applications own forwarding
tasks and must stop/join them with their listener or attachment. They also supply
open deadlines; cancelling `open` drops the pending connector future.
Unregistering a destination prevents new lookups; it does not cancel opens already
in progress or existing streams. Close the underlying connection and its tasks
when that behavior is required.

Tests cover policy denial, connection replacement, cancellation, a large reply
after request EOF, and forwarding between real authenticated QUIC connections.

The Go API provides `NewStreamBroker`, `RegisterQUIC`, `Open`, `Relay`, and
`ForwardStreams`. Register identities from `QUICListener.AcceptConnection`; use
the source identity returned by `AcceptStream`, not fields from a routing header.
Keep and close each `StreamDestination` with its accepted connection.

A legacy header adapter can keep its existing parser and writer:

```go
outgoing, err := broker.Open(ctx, sourceIdentity, destinationKey)
if err != nil {
    return err
}
defer outgoing.Close()
if err := writeExistingHeader(outgoing, request); err != nil {
    return err
}
_, err = xconn.ForwardStreams(ctx, incoming, outgoing)
return err
```

`ForwardStreams` and `Relay` consume the native stream handles. Do not run
concurrent reads or writes on them. Cancellation releases both sides and payload
bytes stay inside Rust. Existing stream deadlines are replaced by the forwarding
context. These APIs currently accept the native streams exposed as `QUICStream`,
including WebTransport streams; arbitrary Go `io.ReadWriteCloser` adapters and
message-oriented WebRTC channels are not silently converted into byte streams.

## Endpoint discovery

`DiscoveryService::start(session, prefix, policy)` hosts an in-memory directory
over ordinary WAMP RPC. It requires an explicit authorization callback. Enable
caller disclosure and session meta events on the hosting realm; realm permissions
remain the application's responsibility.

An endpoint is a service, application, or device. A record contains:

- `id`: nonempty string.
- `addresses`: array of connection hints.
- `capabilities`: string array.
- `metadata`: dictionary visible to authorized readers; omit credentials.

| Procedure suffix | Positional arguments | First result argument |
| --- | --- | --- |
| `.advertise` | Endpoint record | Normalized endpoint record |
| `.get` | Endpoint ID | Endpoint record |
| `.list` | None | Endpoints sorted by ID |
| `.withdraw` | Endpoint ID | Removed endpoint record |

Every operation applies host policy, including filtering list results per caller.
Another authid cannot overwrite or withdraw an existing record. Advertisements
belong to the announcing session and disappear when it leaves. Refreshing a
record from a new session of the same identity transfers its session ownership.

`DiscoveryClient` provides the Rust client API. Discovery does not authenticate
an advertised address or connect automatically. The directory currently supports
queries, not pushed availability subscriptions or persistent storage.

Run the example host:

```sh
cargo run -p xconn-core --features services --example discovery
```

It prints a WebSocket URI and serves realm `example` with prefix `example.peers`.
Its example policy permits public discovery/advertising; production hosts supply
their own authorization policy.

## Packet encryption

The optional `crypto` feature exposes `xconn_core::crypto`. The independent
[`xconn-crypto`](../crates/xconn-crypto) crate provides X25519, HKDF-SHA256, and
ChaCha20-Poly1305 packets for native and browser WASM consumers.

Packets contain `12-byte random nonce || ciphertext || 16-byte tag`. Associated
data can authenticate application context without transmitting it. Key agreement
does not authenticate a peer: the application must establish trust in the public
key. Core does not impose an encrypted-stream handshake, replay policy, or key
persistence format.
