# XConn Core

Reusable connectivity technology implemented in Rust, with language bindings.

The workspace contains the sans-I/O WAMP engine and its Rust networking runtime.
Optional services provide managed backends, stream routing, RPC bridging and
endpoint discovery. Language bindings live under [`bindings`](bindings).

[From many implementations to XConn Core](CONSOLIDATION.md) describes the
project’s origins and the work behind this consolidation.

## Workspace

- [`docs/services.md`](docs/services.md): service contracts, resource ownership,
  and the boundary between reusable technology and application policy.

- [`crates/xconn-webrtc`](crates/xconn-webrtc): reusable WebRTC data channels,
  trickle ICE, timeouts, and optional WAMP signaling and sessions.

- [`crates/xconn-framing`](crates/xconn-framing): bounded data-channel message
  framing shared by native WebRTC and browser WASM.

- [`crates/xconn-crypto`](crates/xconn-crypto): portable packet encryption and
  key agreement for native and browser WASM consumers.

- [`crates/xconn-core`](crates/xconn-core): async and blocking clients, routers,
  transport connections, and the optional router executable.

- [`crates/wampproto`](crates/wampproto): protocol messages, codecs,
  authentication, client joining, router acceptance, broker, and dealer.

The protocol crate has no socket or async runtime dependency. Applications own
network I/O and drive its state machines with incoming protocol messages.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
```

CI runs these checks on Linux, macOS, and Windows, plus async-only, blocking,
and protocol-only builds. Go is not required for the normal Rust tests.
CI runs on pull requests and pushes to `main`. The path filters in
[`.github/filters.yaml`](.github/filters.yaml) select affected checks; shared
changes run the full suite. Go changes also run Python interoperability tests.
Linux binding jobs share the native SDK, test helpers, and independent Go
reference through same-run artifacts. Python still builds its own extension,
and browser tests build WASM. Lint runs independently of native compilation.

[Progressive RPC APIs](docs/streaming.md) and the
[WebTransport Retry limitation](docs/webtransport-retry.md) describe runtime behavior.

## License

MIT. Copyright XConnIO Ltd.

## Language bindings

- [Browser JS / TypeScript](bindings/js): WebSocket, WebTransport and WebRTC;
  `import { Client } from "@xconnio/core"`.
- [Dart](bindings/dart): Future-based clients with QUIC, WebTransport and WebRTC;
  `package:xconn_core/xconn_core.dart`.
- [Python](bindings/python): blocking and asyncio clients with QUIC, WebTransport
  and WebRTC; `from xconn_core import Client`.
- [Go](bindings/go): context-aware clients, routers, transports, and WebRTC.

Go imports `github.com/xconnio/xconn-core/bindings/go` using package name `xconn`.
Build the native SDK first; see [native installation](docs/native-install.md).
