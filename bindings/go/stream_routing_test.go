package xconn_test

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	api "github.com/xconnio/xconn-core/bindings/go"
)

func TestRouterCloseCancelsAnIncompleteRoutingHeader(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	router, err := api.NewRouter(nil)
	require.NoError(t, err)
	t.Cleanup(router.Close)
	require.NoError(t, router.AddRealm("example", &api.RealmConfig{}))
	started, finished := make(chan struct{}), make(chan struct{})
	require.NoError(t, router.RouteStreams(ctx, api.StreamRouting{
		Destination: func(*api.SessionDetails) string { return "" },
		Authorize:   func(*api.SessionDetails, string, *api.SessionDetails) bool { return false },
		Route: func(_ context.Context, _ *api.SessionDetails, stream *api.QUICStream) (api.StreamRoute, error) {
			close(started)
			defer close(finished)
			// Even an existing parser using Read rather than ReadContext must stop.
			_, readErr := io.ReadFull(stream, make([]byte, 2))
			return api.StreamRoute{}, readErr
		},
	}))
	listener, err := router.ListenQUIC(ctx, "127.0.0.1:0")
	require.NoError(t, err)
	connection, err := api.DialQUIC(ctx, listener.Address, "localhost", listener.Certificate)
	require.NoError(t, err)
	t.Cleanup(func() { _ = connection.Close() })
	session, err := connection.OpenSession(ctx, "example", nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = session.Close() })
	stream, err := connection.OpenStream(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = stream.Close() })
	_, err = stream.WriteContext(ctx, []byte{1})
	require.NoError(t, err)
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("routing header callback did not start")
	}
	router.Close()
	select {
	case <-finished:
	case <-ctx.Done():
		t.Fatal("routing header callback survived router closure")
	}
}
