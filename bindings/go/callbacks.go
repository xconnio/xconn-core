package xconn

import (
	"context"
	"fmt"
	"sync"
)

type foreignCallbacks struct {
	handle uint64
	done   chan struct{}
	once   sync.Once
	mu     sync.Mutex
	err    error
}

func newForeignCallbacks(ctx context.Context, handler func(string, any) (any, error)) (*foreignCallbacks, error) {
	value, err := invoke(ctx, "callbacks_new", nil)
	if err != nil {
		return nil, err
	}

	callbacks := &foreignCallbacks{handle: nativeUint64(nativeFields(value)["handle"]), done: make(chan struct{})}
	go func() {
		defer close(callbacks.done)

		for {
			value, err := invoke(
				context.WithoutCancel(ctx),
				"callbacks_next",
				map[string]any{"handle": callbacks.handle},
			)

			if err != nil || value == nil {
				return
			}

			event := nativeFields(value)
			respond := func() {
				result, err := handler(stringField(event, "method"), event["value"])
				reply := map[string]any{"handle": callbacks.handle, "id": event["id"], "value": result}
				if err != nil {
					callbacks.mu.Lock()
					callbacks.err = err
					callbacks.mu.Unlock()
					reply["error"] = err.Error()
				}

				if _, err = invoke(context.WithoutCancel(ctx), "callbacks_reply", reply); err != nil {
					return
				}
			}

			method := stringField(event, "method")
			switch method {
			case "peer_read", "peer_write", "peer_close", "authorize", "stream_route":
				go respond()
			default:
				respond()
			}

		}
	}()
	return callbacks, nil
}

func (c *foreignCallbacks) close() {
	c.once.Do(func() { closeHandle(c.handle) })
	<-c.done
}

func (c *foreignCallbacks) failure() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.err
}

func unexpectedCallback(method string) error {
	return fmt.Errorf("unexpected native callback %s", method)
}
