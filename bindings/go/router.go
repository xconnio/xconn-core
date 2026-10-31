package xconn

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/xconnio/xconn-core/bindings/go/messages"
)

type Router struct {
	streamCallbacks *foreignCallbacks
	streamCancel    context.CancelFunc
	// Serialize realm ownership changes; never wait for callback shutdown under this lock.
	policyMu  sync.Mutex
	policies  map[string]*realmPolicy
	handle    uint64
	realm     string
	mu        sync.Mutex
	listeners []*Listener
	closed    bool
}

// Aliases share a policy owner; its bridge lives until the final realm name is removed.
type realmPolicy struct{ callbacks *foreignCallbacks }

func (r *Router) isClosed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closed
}

func NewRouter(config *RouterConfig) (*Router, error) {
	value, err := invoke(
		context.Background(),
		"router_new",
		map[string]any{"management": config != nil && config.Management},
	)

	if err != nil {
		return nil, err
	}

	return &Router{
		handle:   nativeUint64(nativeFields(value)["handle"]),
		realm:    "",
		policies: make(map[string]*realmPolicy),
	}, nil
}

func (r *Router) Connect(ctx context.Context, serializer string) (*Session, error) {
	f := (&Client{Serializer: serializer}).fields()
	r.mu.Lock()
	f["handle"], f["realm"] = r.handle, r.realm
	r.mu.Unlock()
	value, err := invoke(ctx, "connect_local", f)
	if err != nil {
		return nil, err
	}

	return newSession(ctx, nativeFields(value)), nil
}

type Listener struct {
	closer  io.Closer
	addr    net.Addr
	onClose func()
	err     error
	handle  uint64
	Address string
	once    sync.Once
}

func (r *Router) Listen(ctx context.Context, address, transport string) (*Listener, error) {
	value, err := invoke(ctx, "listen", map[string]any{"handle": r.handle, "address": address, "transport": transport})
	if err != nil {
		return nil, err
	}

	fields := nativeFields(value)
	listener := &Listener{handle: nativeUint64(fields["handle"]), Address: fields["address"].(string)}
	r.mu.Lock()

	if r.closed {
		r.mu.Unlock()
		_ = listener.Close()
		return nil, fmt.Errorf("router closed")
	}

	r.listeners = append(r.listeners, listener)
	r.mu.Unlock()
	return listener, nil
}

func (l *Listener) Close() error {
	l.once.Do(func() {
		if l.closer != nil {
			l.err = l.closer.Close()
		} else {
			closeHandle(l.handle)
		}

		if l.onClose != nil {
			l.onClose()
		}
	})
	return l.err
}

func (r *Router) Close() {
	r.policyMu.Lock()
	r.mu.Lock()

	if r.closed {
		r.mu.Unlock()
		r.policyMu.Unlock()
		return
	}

	callbacks := make(map[*foreignCallbacks]struct{})
	if r.streamCallbacks != nil {
		callbacks[r.streamCallbacks] = struct{}{}
	}
	stopStreams := r.streamCancel
	r.streamCallbacks, r.streamCancel = nil, nil

	for _, policy := range r.policies {
		if policy.callbacks != nil {
			callbacks[policy.callbacks] = struct{}{}
		}
	}

	listeners := r.listeners
	r.listeners, r.policies = nil, nil
	r.closed = true
	r.mu.Unlock()
	r.policyMu.Unlock()

	if stopStreams != nil {
		stopStreams()
	}
	for _, listener := range listeners {
		_ = listener.Close()
	}

	closeHandle(r.handle)

	for callback := range callbacks {
		callback.close()
	}
}

const ManagementRealm = "io.xconn.mgmt"

type LogLevel uint32

const (
	LogLevelError LogLevel = 2
	LogLevelWarn  LogLevel = 3
	LogLevelInfo  LogLevel = 4
	LogLevelDebug LogLevel = 5
	LogLevelTrace LogLevel = 6
)

type RouterConfig struct {
	Management bool
	LogLevel   LogLevel
}

func DefaultRouterConfig() *RouterConfig { return &RouterConfig{LogLevel: LogLevelDebug} }

type RealmConfig struct {
	AutoDiscloseCaller    bool
	AutoDisclosePublisher bool
	Meta                  bool
	Authorizer            Authorizer
	Roles                 []RealmRole
}

func DefaultRealmConfig() *RealmConfig { return &RealmConfig{} }

type RealmRole struct {
	Name        string
	Permissions []Permission
}

type Permission struct {
	URI               string
	MatchPolicy       string
	AllowCall         bool
	AllowRegister     bool
	AllowPublish      bool
	AllowSubscribe    bool
	DiscloseCaller    bool
	DisclosePublisher bool
	Cache             bool
}

func (r *Router) AddRealm(name string, config *RealmConfig) error {
	r.policyMu.Lock()
	callbacks, err := r.addRealm(name, config)
	r.policyMu.Unlock()

	if err != nil && callbacks != nil {
		callbacks.close()
	}

	return err
}

func (r *Router) addRealm(name string, config *RealmConfig) (*foreignCallbacks, error) {
	if r.isClosed() {
		return nil, fmt.Errorf("router closed")
	}

	if r.HasRealm(name) {
		return nil, fmt.Errorf("realm '%s' already registered", name)
	}

	options := map[string]any{"legacy_go": true}
	var callbacks *foreignCallbacks

	if config != nil {
		options["meta"] = config.Meta
		options["disclose_caller"] = config.AutoDiscloseCaller
		options["disclose_publisher"] = config.AutoDisclosePublisher
		roles := make([]any, len(config.Roles))

		for index, role := range config.Roles {
			roles[index] = map[string]any{"name": role.Name, "permissions": permissionFields(role.Permissions)}
		}

		options["roles"] = roles

		if config.Authorizer != nil {
			var err error
			callbacks, err = authorizerCallbacks(config.Authorizer)

			if err != nil {
				return nil, err
			}

			options["callback"] = callbacks.handle
		}
	}

	_, err := invoke(
		context.Background(),
		"realm_add",
		map[string]any{"handle": r.handle, "realm": name, "config": options},
	)

	if err != nil {
		return callbacks, err
	}

	r.mu.Lock()

	if r.realm == "" {
		r.realm = name
	}

	r.policies[name] = &realmPolicy{callbacks: callbacks}

	r.mu.Unlock()
	return callbacks, nil
}

func (r *Router) HasRealm(name string) bool {
	value, err := invoke(context.Background(), "realm_has", map[string]any{"handle": r.handle, "realm": name})
	return err == nil && value == true
}

func (r *Router) RemoveRealm(name string) {
	r.policyMu.Lock()
	_, err := invoke(context.Background(), "realm_remove", map[string]any{"handle": r.handle, "realm": name})
	var released *foreignCallbacks

	if err == nil {
		policy := r.policies[name]
		delete(r.policies, name)
		if policy != nil {
			released = policy.callbacks

			for _, other := range r.policies {
				if other == policy {
					released = nil
					break
				}
			}
		}
	}

	r.policyMu.Unlock()

	if released != nil {
		released.close()
	}
}

func (r *Router) AddRealmAlias(realm, alias string) error {
	r.policyMu.Lock()
	defer r.policyMu.Unlock()
	if r.isClosed() {
		return fmt.Errorf("router closed")
	}

	_, err := invoke(
		context.Background(),
		"realm_alias",
		map[string]any{"handle": r.handle, "realm": realm, "alias": alias},
	)
	if err == nil {
		policy := r.policies[realm]

		if policy == nil {
			policy = &realmPolicy{}
			r.policies[realm] = policy
		}

		r.policies[alias] = policy
	}

	return err
}

type Authorizer interface {
	Authorize(BaseSession, messages.Message) (bool, error)
}

func permissionFields(permissions []Permission) []any {
	fields := make([]any, len(permissions))

	for index, permission := range permissions {
		fields[index] = map[string]any{
			"uri":       permission.URI,
			"match":     permission.MatchPolicy,
			"call":      permission.AllowCall,
			"register":  permission.AllowRegister,
			"publish":   permission.AllowPublish,
			"subscribe": permission.AllowSubscribe,
		}
	}

	return fields
}

func (p Permission) Allows(kind uint64) bool {
	switch kind {
	case messages.MessageTypeCall:
		return p.AllowCall
	case messages.MessageTypeRegister:
		return p.AllowRegister
	case messages.MessageTypePublish:
		return p.AllowPublish
	case messages.MessageTypeSubscribe:
		return p.AllowSubscribe
	default:
		return false
	}
}

func (p Permission) MatchURI(uri string) bool {
	result, err := invoke(
		context.Background(),
		"permission_match",
		map[string]any{"pattern": p.URI, "policy": p.MatchPolicy, "uri": uri},
	)
	return err == nil && result == true
}

func (r *Router) AddRealmRole(realm string, role RealmRole) error {
	_, err := invoke(
		context.Background(),
		"role_add",
		map[string]any{
			"handle":      r.handle,
			"realm":       realm,
			"name":        role.Name,
			"permissions": permissionFields(role.Permissions),
		},
	)
	return err
}

func (r *Router) HasRealmRole(realm, name string) (bool, error) {
	result, err := invoke(
		context.Background(),
		"role_has",
		map[string]any{"handle": r.handle, "realm": realm, "name": name},
	)
	return result == true, err
}

func (r *Router) RemoveRealmRole(realm, name string) error {
	_, err := invoke(
		context.Background(),
		"role_remove",
		map[string]any{"handle": r.handle, "realm": realm, "name": name},
	)
	return err
}

func (r *Router) EnableMetaAPI(realm string) error {
	_, err := invoke(context.Background(), "realm_meta", map[string]any{"handle": r.handle, "realm": realm})
	return err
}

func authorizerCallbacks(authorizer Authorizer) (*foreignCallbacks, error) {
	return newForeignCallbacks(context.Background(), func(method string, value any) (any, error) {
		if method != "authorize" {
			return nil, unexpectedCallback(method)
		}

		fields := nativeFields(value)
		wire, ok := fields["message"].([]any)
		if !ok {
			return nil, fmt.Errorf("native authorization message must be an array")
		}

		message, err := messages.NewForWire(wire)
		if err != nil {
			return nil, err
		}

		if err = message.Parse(wire); err != nil {
			return nil, err
		}

		details := NewSessionDetails(
			nativeUint64(fields["session_id"]),
			stringField(fields, "realm"),
			stringField(fields, "authid"),
			stringField(fields, "authrole"),
			stringField(fields, "authmethod"),
			nativeFields(fields["authextra"]),
		)
		return authorizer.Authorize(&nativeBase{details: details}, message)
	})
}

func (r *Router) SetRealmAuthorizer(realm string, authorizer Authorizer) error {
	if authorizer == nil {
		return fmt.Errorf("authorizer is required")
	}
	callbacks, err := authorizerCallbacks(authorizer)
	if err != nil {
		return err
	}
	r.policyMu.Lock()
	var previous *foreignCallbacks
	if r.isClosed() {
		err = fmt.Errorf("router closed")
	} else {
		_, err = invoke(
			context.Background(),
			"realm_authorizer",
			map[string]any{"handle": r.handle, "realm": realm, "callback": callbacks.handle},
		)
		if err == nil {
			policy := r.policies[realm]

			if policy == nil {
				policy = &realmPolicy{}
				r.policies[realm] = policy
			}

			previous, policy.callbacks = policy.callbacks, callbacks
		}
	}

	r.policyMu.Unlock()

	if err != nil {
		callbacks.close()
	} else if previous != nil {
		previous.close()
	}

	return err
}
