package xconn

import (
	"context"
	"fmt"
	"sync"
)

// StreamRelayPolicy decides whether an authenticated source may open a stream
// to the authenticated destination registered under key.
type StreamRelayPolicy func(source *SessionDetails, key string, target *SessionDetails) bool

// StreamBroker routes streams in Rust. Applications own destination admission,
// routing headers, and the lifetime of connections and forwarding tasks.
type StreamBroker struct {
	handle    uint64
	callbacks *foreignCallbacks
	once      sync.Once
}

type StreamDestination struct {
	handle uint64
	once   sync.Once
}

type StreamRelayStats struct {
	Sent     uint64
	Received uint64
}

func streamIdentity(details *SessionDetails) map[string]any {
	return map[string]any{
		"session_id": details.ID(), "realm": details.Realm(), "authid": details.AuthID(),
		"authrole": details.AuthRole(), "authmethod": details.AuthMethod(), "authextra": details.AuthExtra(),
	}
}

func streamDetails(value any) *SessionDetails {
	fields := nativeFields(value)
	return NewSessionDetails(nativeUint64(fields["session_id"]), stringField(fields, "realm"),
		stringField(fields, "authid"), stringField(fields, "authrole"), stringField(fields, "authmethod"),
		nativeFields(fields["authextra"]))
}

func NewStreamBroker(ctx context.Context, policy StreamRelayPolicy) (*StreamBroker, error) {
	if policy == nil {
		return nil, fmt.Errorf("stream relay policy is required")
	}
	callbacks, err := newForeignCallbacks(ctx, func(method string, value any) (any, error) {
		if method != "stream_authorize" {
			return nil, unexpectedCallback(method)
		}
		fields := nativeFields(value)
		return policy(streamDetails(fields["source"]), stringField(fields, "key"), streamDetails(fields["target"])), nil
	})
	if err != nil {
		return nil, err
	}
	value, err := invoke(ctx, "service_stream_new", map[string]any{"callback": callbacks.handle})
	if err != nil {
		callbacks.close()
		return nil, err
	}
	return &StreamBroker{handle: nativeUint64(nativeFields(value)["handle"]), callbacks: callbacks}, nil
}

// RegisterQUIC replaces a destination. Use identity from AcceptConnection and
// close the returned registration when that connection ends.
func (b *StreamBroker) RegisterQUIC(ctx context.Context, key string,
	identity *SessionDetails, connection *QUICConnection) (*StreamDestination, error) {
	if identity == nil || connection == nil {
		return nil, fmt.Errorf("authenticated identity and QUIC connection are required")
	}
	value, err := invoke(ctx, "service_stream_register_quic", map[string]any{
		"handle": b.handle, "key": key, "target": streamIdentity(identity), "connection": connection.handle,
	})
	if err != nil {
		return nil, err
	}
	return &StreamDestination{handle: nativeUint64(nativeFields(value)["handle"])}, nil
}

// Open authorizes and opens a destination stream. The caller may write an
// application header before handing both streams to ForwardStreams.
func (b *StreamBroker) Open(ctx context.Context, source *SessionDetails, key string) (*QUICStream, error) {
	if source == nil {
		return nil, fmt.Errorf("authenticated source identity is required")
	}
	value, err := invoke(ctx, "service_stream_open", map[string]any{
		"handle": b.handle, "source": streamIdentity(source), "key": key,
	})
	if err != nil {
		return nil, err
	}
	return &QUICStream{handle: nativeUint64(nativeFields(value)["handle"])}, nil
}

// Relay consumes stream, including on failure. Do not perform concurrent I/O on
// it. Cancellation closes the forwarded streams; payload bytes stay in Rust.
func (b *StreamBroker) Relay(ctx context.Context, source *SessionDetails, key string,
	stream *QUICStream) (StreamRelayStats, error) {
	if source == nil || stream == nil {
		return StreamRelayStats{}, fmt.Errorf("authenticated source and native stream are required")
	}
	defer stream.Close()
	value, err := invoke(ctx, "service_stream_relay", map[string]any{
		"handle": b.handle, "source": streamIdentity(source), "key": key, "stream": stream.handle,
	})
	return relayStats(value), err
}

// ForwardStreams consumes both native streams, including on failure. Existing
// deadlines do not transfer; ctx controls forwarding. No concurrent I/O is allowed.
// EOF half-closes the opposite writer and lets its remaining reply drain.
func ForwardStreams(ctx context.Context, incoming, outgoing *QUICStream) (StreamRelayStats, error) {
	if incoming == nil || outgoing == nil || incoming == outgoing {
		return StreamRelayStats{}, fmt.Errorf("two different native streams are required")
	}
	defer incoming.Close()
	defer outgoing.Close()
	value, err := invoke(ctx, "service_stream_forward", map[string]any{
		"incoming": incoming.handle, "outgoing": outgoing.handle,
	})
	return relayStats(value), err
}

func relayStats(value any) StreamRelayStats {
	if value == nil {
		return StreamRelayStats{}
	}
	fields := nativeFields(value)
	return StreamRelayStats{Sent: nativeUint64(fields["sent"]), Received: nativeUint64(fields["received"])}
}

func (d *StreamDestination) Close() error {
	d.once.Do(func() { closeHandle(d.handle) })
	return nil
}

func (b *StreamBroker) Close() error {
	b.once.Do(func() {
		closeHandle(b.handle)
		b.callbacks.close()
	})
	return nil
}
