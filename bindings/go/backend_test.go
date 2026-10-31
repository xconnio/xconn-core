package xconn_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	api "github.com/xconnio/xconn-core/bindings/go"
)

func TestBackendRestoresRPCsAfterReconnectAndClosesOnCancel(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	router, err := api.NewRouter(nil)
	require.NoError(t, err)
	t.Cleanup(router.Close)
	require.NoError(t, router.AddRealm("example", &api.RealmConfig{Roles: []api.RealmRole{{
		Name: "anonymous", Permissions: []api.Permission{{
			URI: "example.", MatchPolicy: "prefix", AllowRegister: true, AllowCall: true,
		}},
	}}}))
	listener, err := router.Listen(ctx, "127.0.0.1:0", "rawsocket")
	require.NoError(t, err)
	ready := make(chan *api.Session, 3)
	lifetime, stop := context.WithCancel(ctx)
	finished := make(chan error, 1)
	go func() {
		finished <- (&api.Client{}).Serve(lifetime, "rs://"+listener.Address, "example",
			func(attempt context.Context, session *api.Session) error {
				registered := session.Register("example.echo", func(_ context.Context, inv *api.Invocation) *api.Result {
					return api.NewResult(inv.Args()...)
				}).ExecuteContext(attempt)
				if registered.Err != nil {
					return registered.Err
				}
				select {
				case ready <- session:
					return nil
				case <-attempt.Done():
					return attempt.Err()
				}
			})
	}()
	defer stop()
	connect := func() *api.Session {
		session, connectErr := api.ConnectAnonymous(ctx, "rs://"+listener.Address, "example")
		require.NoError(t, connectErr)
		t.Cleanup(func() { _ = session.Close() })
		return session
	}
	await := func() *api.Session {
		select {
		case session := <-ready:
			return session
		case err := <-finished:
			t.Fatalf("backend stopped before becoming ready: %v", err)
			return nil
		case <-ctx.Done():
			t.Fatal("backend did not become ready")
			return nil
		}
	}
	serving := await()
	caller := connect()
	require.Equal(t, "hello", caller.Call("example.echo").Arg("hello").ExecuteContext(ctx).ArgStringOr(0, ""))
	require.NoError(t, serving.Close())
	serving = await()
	require.Equal(t, "again", caller.Call("example.echo").Arg("again").ExecuteContext(ctx).ArgStringOr(0, ""))
	stop()
	require.ErrorIs(t, <-finished, context.Canceled)
	select {
	case <-serving.Done():
	case <-ctx.Done():
		t.Fatal("backend session survived cancellation")
	}
}

func TestBackendSetupErrorIsReturned(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	router, err := api.NewRouter(nil)
	require.NoError(t, err)
	t.Cleanup(router.Close)
	require.NoError(t, router.AddRealm("example", &api.RealmConfig{Roles: []api.RealmRole{{
		Name: "anonymous", Permissions: []api.Permission{{
			URI: "example.", MatchPolicy: "prefix", AllowRegister: true, AllowCall: true,
		}},
	}}}))
	listener, err := router.Listen(ctx, "127.0.0.1:0", "rawsocket")
	require.NoError(t, err)
	expected := errors.New("invalid backend setup")
	err = (&api.Client{}).Serve(ctx, "rs://"+listener.Address, "example", func(context.Context, *api.Session) error {
		return expected
	})
	require.ErrorIs(t, err, expected)
}

func TestQUICBackendOwnsItsConnectionAndAcceptsStreams(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	router, err := api.NewRouter(nil)
	require.NoError(t, err)
	t.Cleanup(router.Close)
	require.NoError(t, router.AddRealm("example", &api.RealmConfig{}))
	listener, err := router.ListenQUIC(ctx, "127.0.0.1:0")
	require.NoError(t, err)
	roots := x509.NewCertPool()
	certificate, err := x509.ParseCertificate(listener.Certificate)
	require.NoError(t, err)
	roots.AddCert(certificate)
	lifetime, stop := context.WithCancel(ctx)
	defer stop()
	ready := make(chan *api.QUICSession, 1)
	finished := make(chan error, 1)
	go func() {
		finished <- api.RunQUICBackend(lifetime, listener.Address, "example", &api.QUICDialerConfig{
			TLSConfig: &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS13},
		}, func(attempt context.Context, session *api.QUICSession) error {
			ready <- session
			stream, acceptErr := session.Connection().AcceptRawStream(attempt)
			if acceptErr != nil {
				return acceptErr
			}
			defer func() { _ = stream.Close() }()
			_, writeErr := stream.Write([]byte("reply"))
			return writeErr
		})
	}()
	accepted, _, err := listener.AcceptConnection(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = accepted.Close() })
	stream, err := accepted.OpenStream(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = stream.Close() })
	_, err = stream.WriteContext(ctx, []byte("request"))
	require.NoError(t, err)
	reply := make([]byte, 5)
	_, err = io.ReadFull(stream, reply)
	require.NoError(t, err)
	require.Equal(t, "reply", string(reply))
	session := <-ready
	stop()
	require.ErrorIs(t, <-finished, context.Canceled)
	require.False(t, session.Connected())
	_, err = session.Connection().OpenRawStream(ctx)
	require.Error(t, err, "cancellation must close the connection, not just WAMP")
}
