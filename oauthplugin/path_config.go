package oauthplugin

import (
	"context"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathConfig(backend *oauthBackend) *framework.Path {
	return &framework.Path{
		Pattern: `config`,
		Fields: map[string]*framework.FieldSchema{
			"issuer": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "OIDC issuer identifier.",
			},

			"client_id": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Required. The OAuth client identifier assigned to Vault.",
			},

			"client_secret": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Required. The OAuth client secret assigned to Vault.",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   backend.pathConfigRead,
			logical.UpdateOperation: backend.pathConfigWrite,
		},

		HelpSynopsis: "Configures the OAuth authentication backend.",
	}
}

func (backend *oauthBackend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	backend.lock.RLock()
	defer backend.lock.RUnlock()

	idProvider, err := backend.IdentityProvider(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if idProvider == nil {
		return nil, nil
	}

	response := &logical.Response{
		Data: map[string]interface{}{
			"issuer":        idProvider.Issuer(),
			"client_secret": idProvider.ClientSecret(),
			"client_id":     idProvider.ClientID(),
		},
	}
	return response, nil
}

func (backend *oauthBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	backend.lock.Lock()
	defer backend.lock.Unlock()

	config := &pluginConfig{}
	config.SetFromRequestData(data)

	if err := config.Validate(); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	idProvider, err := newOidcIdProvider(ctx, config)
	if err != nil {
		return nil, err
	}

	backend.cachedIdProvider = nil
	err = config.Save(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	backend.cachedIdProvider = idProvider
	return nil, nil
}

// Returns the IdentityProvider for the backend, which is the meat of
// interfacing with an OAuth provider. Because initially getting the provider
// might involve some slow network discovery, the provider is cached.
func (backend *oauthBackend) IdentityProvider(ctx context.Context, storage logical.Storage) (IdentityProvider, error) {
	if backend.cachedIdProvider != nil {
		return backend.cachedIdProvider, nil
	}

	config, err := LoadConfig(ctx, storage)
	if err != nil || config == nil {
		return nil, err
	}

	idProvider, err := newOidcIdProvider(ctx, config)
	if err != nil {
		return nil, err
	}

	backend.cachedIdProvider = idProvider
	return idProvider, nil
}

const (
	configPath string = "config"
)
