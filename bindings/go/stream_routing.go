package xconn

import (
	"context"
	"fmt"
	"time"
)

// StreamRoute selects a backend and optionally replays an application's header.
type StreamRoute struct {
	Destination string
	Prefix      []byte
	// Failure is an optional protocol response if the destination cannot be opened.
	Failure []byte
}

// StreamRouting supplies application policy. Listeners own destination tracking,
// forwarding and cleanup. Configure it before starting QUIC/WebTransport listeners.
type StreamRouting struct {
	// Destination returns an opaque key for a backend, or "" for a client.
	Destination func(*SessionDetails) string
	// Route reads only the routing header. The stream is borrowed for this call;
	// do not retain it or start concurrent I/O. Its default deadline is 10 seconds.
	Route func(context.Context, *SessionDetails, *QUICStream) (StreamRoute, error)
	// Authorize runs for every source/destination pair before opening a stream.
	Authorize StreamRelayPolicy
}

func (r *Router) RouteStreams(ctx context.Context, routing StreamRouting) error {
	if routing.Destination == nil || routing.Route == nil || routing.Authorize == nil {
		return fmt.Errorf("stream destination, routing and authorization policies are required")
	}
	r.policyMu.Lock()
	defer r.policyMu.Unlock()
	if r.isClosed() || r.streamCallbacks != nil {
		return fmt.Errorf("router is closed or stream routing is already configured")
	}
	lifetime, cancel := context.WithCancel(context.WithoutCancel(ctx))
	callbacks, err := newForeignCallbacks(lifetime, func(method string, value any) (any, error) {
		fields := nativeFields(value)
		switch method {
		case "stream_destination":
			return routing.Destination(streamDetails(value)), nil
		case "stream_authorize":
			return routing.Authorize(streamDetails(fields["source"]), stringField(fields, "key"),
				streamDetails(fields["target"])), nil
		case "stream_route":
			headerContext, stop := context.WithTimeout(lifetime, 10*time.Second)
			defer stop()
			stream := &QUICStream{handle: nativeUint64(fields["handle"])}
			closeOnCancel := context.AfterFunc(headerContext, func() { _ = stream.Close() })
			defer closeOnCancel()
			route, routeErr := routing.Route(headerContext, streamDetails(fields["source"]), stream)
			if routeErr != nil {
				return nil, routeErr
			}
			return map[string]any{"key": route.Destination, "prefix": route.Prefix, "failure": route.Failure}, nil
		default:
			return nil, unexpectedCallback(method)
		}
	})
	if err != nil {
		cancel()
		return err
	}
	_, err = invoke(ctx, "service_stream_configure", map[string]any{"handle": r.handle, "callback": callbacks.handle})
	if err != nil {
		cancel()
		callbacks.close()
		return err
	}
	r.streamCallbacks = callbacks
	r.streamCancel = cancel
	return nil
}
