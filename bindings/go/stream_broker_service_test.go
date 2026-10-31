package xconn_test

import (
	"bytes"
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	api "github.com/xconnio/xconn-core/bindings/go"
)

func connectBrokerQUIC(t *testing.T, ctx context.Context, listener *api.QUICListener) (
	*api.QUICConnection, *api.Session, *api.QUICConnection, *api.SessionDetails) {
	t.Helper()
	connection, err := api.DialQUIC(ctx, listener.Address, "localhost", listener.Certificate)
	require.NoError(t, err)
	t.Cleanup(func() { _ = connection.Close() })
	session, err := connection.OpenSession(ctx, "example", nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = session.Close() })
	accepted, identity, err := listener.AcceptConnection(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = accepted.Close() })
	return connection, session, accepted, identity
}

func TestStreamBrokerCompatibilityHeaderAndNativeForwarding(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	router, err := api.NewRouter(nil)
	require.NoError(t, err)
	t.Cleanup(router.Close)
	require.NoError(t, router.AddRealm("example", &api.RealmConfig{}))
	listener, err := router.ListenQUIC(ctx, "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	backend, _, destination, destinationIdentity := connectBrokerQUIC(t, ctx, listener)
	client, clientSession, _, _ := connectBrokerQUIC(t, ctx, listener)
	var allowed atomic.Bool
	broker, err := api.NewStreamBroker(ctx, func(source *api.SessionDetails, key string, target *api.SessionDetails) bool {
		return allowed.Load() && source.ID() == clientSession.ID() &&
			key == "service" && target.ID() == destinationIdentity.ID()
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = broker.Close() })
	old, err := broker.RegisterQUIC(ctx, "service", destinationIdentity, destination)
	require.NoError(t, err)
	current, err := broker.RegisterQUIC(ctx, "service", destinationIdentity, destination)
	require.NoError(t, err)
	t.Cleanup(func() { _ = current.Close() })
	require.NoError(t, old.Close())
	_, err = broker.Open(ctx, clientSession.Details(), "service")
	require.Error(t, err)
	allowed.Store(true)
	request, err := client.OpenStream(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = request.Close() })
	_, err = request.WriteContext(ctx, []byte("headerpayload"))
	require.NoError(t, err)
	require.NoError(t, request.CloseWriteContext(ctx))
	incoming, source, err := listener.AcceptStream(ctx)
	require.NoError(t, err)
	header := make([]byte, 6)
	_, err = io.ReadFull(incoming, header)
	require.NoError(t, err)
	outgoing, err := broker.Open(ctx, source, "service")
	require.NoError(t, err)
	_, err = outgoing.WriteContext(ctx, header)
	require.NoError(t, err)
	forwarded := make(chan error, 1)
	go func() {
		stats, forwardErr := api.ForwardStreams(ctx, incoming, outgoing)
		if forwardErr == nil && (stats.Sent != 7 || stats.Received != 128*1024) {
			forwardErr = io.ErrUnexpectedEOF
		}
		forwarded <- forwardErr
	}()
	response, err := backend.AcceptStream(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = response.Close() })
	body, err := io.ReadAll(response)
	require.NoError(t, err)
	require.Equal(t, "headerpayload", string(body))
	reply := bytes.Repeat([]byte{42}, 128*1024)
	_, err = response.WriteContext(ctx, reply)
	require.NoError(t, err)
	require.NoError(t, response.CloseWriteContext(ctx))
	body, err = io.ReadAll(request)
	require.NoError(t, err)
	require.Equal(t, reply, body)
	require.NoError(t, <-forwarded)
	require.NoError(t, current.Close())
	_, err = broker.Open(ctx, source, "service")
	require.Error(t, err)
}

func TestStreamBrokerRelayCancellationReleasesNativeStreams(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	router, err := api.NewRouter(nil)
	require.NoError(t, err)
	t.Cleanup(router.Close)
	require.NoError(t, router.AddRealm("example", &api.RealmConfig{}))
	listener, err := router.ListenQUIC(ctx, "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	backend, _, destination, identity := connectBrokerQUIC(t, ctx, listener)
	client, _, _, _ := connectBrokerQUIC(t, ctx, listener)
	broker, err := api.NewStreamBroker(ctx, func(_ *api.SessionDetails, _ string, _ *api.SessionDetails) bool {
		return true
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = broker.Close() })
	registration, err := broker.RegisterQUIC(ctx, "service", identity, destination)
	require.NoError(t, err)
	t.Cleanup(func() { _ = registration.Close() })
	request, err := client.OpenStream(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = request.Close() })
	_, err = request.WriteContext(ctx, []byte("hello"))
	require.NoError(t, err)
	incoming, source, err := listener.AcceptStream(ctx)
	require.NoError(t, err)
	forwarding, stop := context.WithCancel(ctx)
	result := make(chan error, 1)
	go func() {
		_, relayErr := broker.Relay(forwarding, source, "service", incoming)
		result <- relayErr
	}()
	response, err := backend.AcceptStream(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = response.Close() })
	body := make([]byte, 5)
	_, err = io.ReadFull(response, body)
	require.NoError(t, err)
	require.Equal(t, "hello", string(body))
	stop()
	require.ErrorIs(t, <-result, context.Canceled)
	_, err = request.ReadContext(ctx, make([]byte, 1))
	require.Error(t, err)
	_, err = response.ReadContext(ctx, make([]byte, 1))
	require.Error(t, err)
}
