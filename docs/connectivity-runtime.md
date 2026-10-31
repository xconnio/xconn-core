# Connectivity runtime integration

The public entry points are described in [services](services.md): managed backend
runners and router stream-routing policy. Ordinary WAMP APIs remain unchanged.
Bridges, brokers and the retry supervisor remain available for custom compositions.

DeskConn keeps enrollment, credentials, account snapshots/events, role policy and
its existing stream header. XConn owns transport implementation, authenticated
destination registration and byte forwarding. Hub keeps its account/database
adapter and uses DeskConn's relay policy without implementing forwarding workers.

Integration uses an external Go workspace and a locally built SDK. Published
application dependency pins have not yet changed. The release order is:

1. Review and merge the XConn changes and native SDK version `0.1.5`.
2. Tag `v0.1.5`; wait for all native SDK archives to publish.
3. Tag `bindings/go/v0.1.5` on the same source commit.
4. Update DeskConn's SDK/Go pins, verify without the workspace, and release it.
5. Update Hub's DeskConn pin, tidy its module and verify standalone CI/Docker.

Local Hub fixtures cover salted CRA, CryptoSign, routed RPCs, WebTransport-to-QUIC
streams, cross-realm denial and backend replacement. They do not exercise the
production Postgres inventory or deployed account service. No release is created
by this development branch.
