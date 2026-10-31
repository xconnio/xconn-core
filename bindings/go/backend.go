package xconn

import (
	"context"
	"fmt"
)

// Serve runs a backend using ordinary Session APIs. Setup runs after each
// connection, so registrations/subscriptions are restored after a disconnect.
// Setup errors stop the backend. Cancellation closes its session and waits for
// the handler to return; handlers must honor their context.
func (c *Client) Serve(ctx context.Context, uri, realm string,
	setup func(context.Context, *Session) error) error {
	if setup == nil {
		return fmt.Errorf("backend setup is required")
	}
	return runBackend(ctx, func(attempt context.Context) (*backendConnection, error) {
		session, err := c.Connect(attempt, uri, realm)
		if err != nil {
			return nil, err
		}
		return &backendConnection{
			session: session, close: session.Close,
			run: func(lifetime context.Context) error { return setup(lifetime, session) },
		}, nil
	})
}

// RunQUICBackend connects a backend and restores it after transport loss. The
// handler uses normal RPC and stream APIs. Return nil on normal stream EOF;
// returning an error stops the backend. Handler goroutines must honor ctx.
func RunQUICBackend(ctx context.Context, address, realm string, config *QUICDialerConfig,
	handler func(context.Context, *QUICSession) error) error {
	if handler == nil {
		return fmt.Errorf("backend handler is required")
	}
	return runBackend(ctx, func(attempt context.Context) (*backendConnection, error) {
		session, err := ConnectQUIC(attempt, address, realm, config)
		if err != nil {
			return nil, err
		}
		return &backendConnection{
			session: session.Session,
			close: func() error {
				_ = session.Close()
				return session.Connection().Close()
			},
			run: func(lifetime context.Context) error { return handler(lifetime, session) },
		}, nil
	})
}

type backendConnection struct {
	session *Session
	close   func() error
	run     func(context.Context) error
}

func runBackend(ctx context.Context, connect func(context.Context) (*backendConnection, error)) error {
	failure := make(chan error, 1)
	err := RunAttachment(ctx, AttachmentRetryPolicy{}, func(attempt context.Context) (AttachmentOutcome, error) {
		lifetime, cancel := context.WithCancel(attempt)
		defer cancel()
		backend, err := connect(lifetime)
		if err != nil {
			return AttachmentRetry, err
		}
		defer func() { _ = backend.close() }()
		stop := context.AfterFunc(lifetime, func() { _ = backend.close() })
		defer stop()
		completed := make(chan error, 1)
		go func() { completed <- backend.run(lifetime) }()
		select {
		case err = <-completed:
			if err != nil {
				failure <- err
				return AttachmentDetached, nil
			}
		case <-backend.session.Done():
			cancel()
			_ = backend.close()
			<-completed
			return AttachmentDisconnected, nil
		case <-lifetime.Done():
			_ = backend.close()
			<-completed
			return AttachmentRetry, lifetime.Err()
		}
		select {
		case <-backend.session.Done():
			return AttachmentDisconnected, nil
		case <-lifetime.Done():
			return AttachmentRetry, lifetime.Err()
		}
	}, nil)
	select {
	case setupError := <-failure:
		return setupError
	default:
		return err
	}
}
