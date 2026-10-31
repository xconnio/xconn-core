# Go binding

The module is `github.com/xconnio/xconn-core/bindings/go` and its package name is
`xconn`. It uses cgo and the Rust client/router runtime.

## Install

Install Go, a C compiler and `pkg-config`, then run the native SDK installer once:

```sh
curl -fL https://raw.githubusercontent.com/xconnio/xconn-core/main/scripts/install-xconn-sdk.sh -o install-xconn-sdk.sh
sh install-xconn-sdk.sh
go get github.com/xconnio/xconn-core/bindings/go
go build ./...
```

The installer downloads and verifies the static SDK for Linux amd64/arm64 or
macOS arm64. No Rust toolchain or separate XConn shared library is needed.
It installs under `/usr/local`, or `/opt/homebrew` when Homebrew is installed
on Apple Silicon, and asks for sudo when needed. Prerequisite packages must
already be installed.

If your app already declares the Go dependency, run the installer and your normal
app build; no separate `go get` is needed.

See [native installation](../../docs/native-install.md) for prerequisites,
installation paths and manual setups.

For source development:

```sh
cargo build --locked -p xconn-ffi --release
python3 scripts/package-native.py --stage-only target/native
export PKG_CONFIG_PATH="$PWD/target/native/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
cd bindings/go
go test -race -count=1 -timeout=90s ./...
```

The public client API retains xconn-go's fluent request builders, authenticator
and serializer interfaces, callbacks, response accessors and error types. Import
paths use this module and its `auth`, `messages`, `serializers`, `transports`
subpackages; no standalone Wampproto Go module is required.

```go
router, err := xconn.NewRouter(nil)
if err != nil { return err }
defer router.Close()
if err := router.AddRealm("realm1", nil); err != nil { return err }
session, err := xconn.ConnectInMemory(router, "realm1")
if err != nil { return err }
defer session.Close()

registration := session.Register("example.echo", func(ctx context.Context, inv *xconn.Invocation) *xconn.Result {
    return xconn.NewResult(inv.Args()...)
}).Execute()
if registration.Err != nil { return registration.Err }
result := session.Call("example.echo").Arg("hello").ExecuteContext(ctx)
if result.Err != nil { return result.Err }
fmt.Println(result.ArgStringOr(0, ""))
```

Network clients use `Client{Authenticator: ..., SerializerSpec: xconn.CBORSerializerSpec}`
and `Connect(ctx, uri, realm)`. `NewServer(router, authenticator, nil)` exposes
TCP/Unix WebSocket and RawSocket listeners. Go realms retain the original trusted
role default; add anonymous permissions explicitly for anonymous network clients.

Request options, `Session.Details`, `ID`, `Connected`, `GoodBye`, leave listeners and
`Leave()` are supported. Additive `CallContext`, `RegisterContext`,
`SubscribeContext`, `PublishContext` and `LeaveContext` methods remain available.
Application failures use `*xconn.Error`, preserving their URI and payloads. Context cancellation returns standard context errors.

Original authenticator and serializer objects are accepted, including custom
implementations for the built-in codecs. Rust performs protocol processing,
crypto, framing and default serialization. Custom `BaseSession` adapters can
supply an existing transport; the session receive loop stays in Rust. Local
`ConnectInMemoryBase` preserves queue capacity and nonblocking `TryWrite`.

Callbacks run in Go goroutines and can make nested calls. One native completion
waiter multiplexes operations; default networking needs no waiting thread per
idle session. Close resources explicitly; `Close` is idempotent.

Compatibility tests include the original client and parser suites, custom auth/serializers/base sessions, Unix listeners, management and an
independent original-Go router. This is not complete operational API parity:
custom `NetDial`, network queue tuning, custom server codecs, and
diagnostics/log publishing remain unbound.
Native SDK artifacts support installation outside the workspace; the Go module
release uses a separate subdirectory-prefixed tag. Unsupported exposed tuning options return errors.
See [binding scope](../README.md).

## WebRTC

The [webrtc subpackage](webrtc/README.md) uses the same native library and Rust
runtime for WAMP sessions and raw channels. Run the local example with
`go -C bindings/go run ./examples/webrtc` from the workspace root after building
`xconn-ffi`. No Pion dependency is required.

Fluent request terminals are `Execute()` and, for calls with a context,
`ExecuteContext(ctx)`. The former `Do()` / `DoContext(ctx)` names have been removed.
See the [shared execution contract](../../docs/fluent-api.md).

Invocation, Event and Result share [strict typed payload accessors](../../docs/payload.md)
with explicit defaults and consistent numeric/binary conversion rules.

[Result construction and received values](../../docs/results.md) use one payload
type for handler replies, progressive results and completed calls.

## Initial QUIC transport API

The default native SDK now includes QUIC. `Router.ListenQUIC(ctx, "127.0.0.1:0")`
creates a listener with a generated localhost certificate.
`ListenQUICWithCertificate(ctx, address, tls.Certificate)` instead accepts an
application-supplied DER certificate chain and exportable private key. Pass its DER
`Certificate` to `DialQUIC(ctx, listener.Address, "localhost", certificate)`;
certificate and hostname verification remain enabled. Configure trust through a
trusted channel rather than downloading a certificate from an untrusted endpoint.

A `QUICConnection` opens WAMP sessions with `OpenSession(ctx, realm, client)` and
raw streams with `OpenStream(ctx)`. `QUICListener.AcceptStream(ctx)` returns the
stream and the identity authenticated by WAMP on that connection. Authenticate a
WAMP session before sending raw data. Raw classification uses the existing Rust
transport convention: the first byte must differ from the RawSocket magic byte
`0x7f`; the receiver accepts a raw stream after its first data arrives.

Streams implement `io.Reader` and `io.Writer`, context-aware reads/writes,
`CloseWrite()`/`CloseWriteContext(ctx)`, and `Close()`. Individual bridge reads and
writes are bounded to 1 MiB. Close resources explicitly. Closing the connection
closes its sessions and streams; closing a session or stream leaves siblings
open. Router closure also closes its QUIC listeners.

`ConnectQUIC(ctx, address, realm, config)` and `ConnectWebTransport(ctx, url,
realm, config)` retain the multiplexed-session convenience API. Their raw streams
implement `net.Conn`, including real endpoint addresses and read/write deadlines.
Updating a deadline preserves pending native I/O; clearing it permits new I/O.
Closing a session leaves its independently owned connection open.

Server `KeepAliveInterval` and `KeepAliveTimeout` configure native transport
PING probes; peers that do not answer are disconnected. Network queue tuning,
TLS client certificates and arbitrary TLS algorithm configuration remain
unsupported. QUIC and WebTransport WAMP interoperability is tested in both
directions against pinned original Go peers across all three codecs. QUIC raw
byte echo is also tested against the original Go server.

Cancellation of a write can leave a partial payload on the wire; applications
must close that stream rather than retry the payload blindly.

`AcceptConnection(ctx)` returns the connection and its first authenticated WAMP
identity. The accepted handle can open reverse streams toward the client, which
receives them with `QUICConnection.AcceptStream(ctx)`. `Wait(ctx)` observes
transport disconnection, allowing relay connection maps to remove stale entries.
Closing any connection handle closes the shared connection. Listener connection
notifications use a bounded queue; consumers should drain it continuously.

Rust listeners opt into these notifications with
`enable_connection_notifications()` before clients connect. The Go bridge enables
them automatically. Existing Rust listeners retain their previous behavior.
The notification identity is the first authenticated session; raw stream identity
continues to follow the existing transport's authentication watch. Authorization
for multi-realm/multi-identity connection reuse needs review before cloud rollout.

Raw WebRTC channels now preserve text/binary metadata through
`ReadDataPacketContext` and `OnMessage`, including legacy classification packets.
`SendText`, `BufferedAmount`, `SetBufferedAmountLowThreshold`,
`OnBufferedAmountLow`, and `OnError` support DeskConn's channel adapter.
Application low-buffer notifications are monitored by Rust only after a send
crosses the configured threshold; idle channels do not poll. Internal bounded-send
backpressure remains independent of the application's threshold. Channel failures
and receive-queue overflow are retained for error callbacks; ordinary closure
is not reported as a failure.

WAMP WebRTC providers deliver raw application channels only after a WAMP session
on the connection has authenticated. A failed initial join cannot expose a raw
channel. An authenticated channel may outlive its initial WAMP session. The
lower-level Rust `Connection` transport remains usable without WAMP.

`DialQUICWithOptions` supports DNS names with staggered IPv4/IPv6 connection
attempts and uses platform trust roots when no DER roots are supplied.
`DialQUICWithTLS` supports Go certificate pools, verification time, hostname
verification, explicit development verification settings, and certificate
verification callbacks. Custom Go trust callbacks run before a connection is
returned or WAMP application data is sent. Connection-state callbacks receive
certificate chains, verified chains, SNI, ALPN and TLS version; other Go TLS
connection-state fields are not synthesized. TLS client certificates are not
supported. Default dialing keeps TLS verification entirely in Rust.

### Native WebTransport

`DialWebTransport(ctx, "https://host:port/wamp", tlsConfig)` opens an HTTP/3
connection backed by Rust. `OpenSession` joins independent WAMP sessions;
`OpenStream` and `AcceptStream` carry application bytes alongside them.
`Server.ListenWebTransport(ctx, address, path, certificate)` serves authenticated
WAMP sessions and exposes incoming raw streams with their WAMP identity.

TLS trust uses Go certificate pools and verification callbacks before the
connection is returned or WAMP data is sent. Rust verifies handshake signatures.
The listener rejects CONNECT requests for other paths. Streams reuse the bounded
native QUIC stream adapter, including context cancellation and `CloseWrite`.
The native SDK's default features include WebTransport; custom SDK builds must
enable the `webtransport` feature.

## Static Linux linking

The native crate also produces `libxconn_ffi.a`. To stage a static SDK:

```sh
cargo build --locked --profile native -p xconn-ffi
python3 scripts/package-native.py --stage-only --static --profile native target/native
export PKG_CONFIG_PATH="$PWD/target/native/lib/pkgconfig"
CGO_ENABLED=1 go build -tags xconn_static,netgo,osusergo \
  -ldflags "-linkmode external -extldflags '-static -Wl,--gc-sections'" ./path/to/application
```

Run these commands from the XConn checkout and replace the application path.
The `xconn_static` tag selects `xconn-static.pc`, which explicitly links the Rust
archive instead of a neighboring shared library. The native profile enables thin LTO, one codegen unit, and size optimization
while retaining panic unwinding. The host needs a C toolchain and static libc.
TLS uses rustls/ring; no OpenSSL development libraries are required.
Relink Go applications after rebuilding the Rust archive: Go does not track
changes to external native archives in its build cache (use `go build -a`). Static packaging currently supports
Linux on the build host architecture. Certificates and any glibc runtime modules
remain system resources; this is not a hermetic cross-distribution build.

## Reusable services

`Client.Serve` restores a backend’s RPC setup after disconnection;
`RunQUICBackend` also owns its stream connection. Hubs configure
`Router.RouteStreams` once before listening, supplying their identity, routing
and authorization policies. The listeners handle registration and forwarding.

Advanced `Session.Bridge`, `RunAttachment`, and `Session.Discovery` delegate to
Rust services. Directory hosts use `Session.ServeDiscovery` with an explicit
authorization callback. Portable packet encryption lives in the `crypto` subpackage.
See [ownership and service contracts](../../docs/services.md). DeskConn orchestration
previously under `bindings/go/xconn` now lives in DeskConn’s `internal/connectivity`.

## Progressive RPC

Use `Stream()` or `StreamContext(ctx)` to receive owned progressive results.
Configure `StreamOptions{ProgressiveInput: true}` for input chunks, and
`Results: ResultsFinalOnly` to disable intermediate results independently.
`Send`, `Finish`, `Receive`, and `Close` manage one RPC. See
[streaming API and examples](../../docs/streaming.md).
