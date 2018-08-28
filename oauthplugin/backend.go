package oauthplugin

import (
	"context"
	"sync"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// TODO: implement invalidation

func Factory(ctx context.Context, config *logical.BackendConfig) (logical.Backend, error) {
	backend := &oauthBackend{
		Backend: &framework.Backend{
			BackendType: logical.TypeCredential,
			Help:        backendHelp,
			PathsSpecial: &logical.Paths{
				Unauthenticated: []string{"login", "auth-request"},
				SealWrapStorage: []string{"config"},
			},
		},
	}

	backend.Paths = []*framework.Path{
		pathConfig(backend),
		pathLogin(backend),
		pathAuthRequest(backend),
		pathRole(backend),
		pathRoleList(backend),
	}

	if err := backend.Setup(ctx, config); err != nil {
		return nil, err
	}

	return backend, nil
}

type oauthBackend struct {
	*framework.Backend

	lock             sync.RWMutex
	cachedIdProvider IdentityProvider
}

const (
	backendHelp = `
The OAuth backend plugin allows authentication with a variety of OAuth-flavored
identity providers.
`
)

type IdentityProvider interface {
	Issuer() string
	ClientID() string
	ClientSecret() string
	AuthURL(ctx context.Context) string
	ValidateCode(ctx context.Context, code string, redirectURL string) (map[string]interface{}, error)
}
