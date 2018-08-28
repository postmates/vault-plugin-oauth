package oauthplugin

import (
	"context"
	"errors"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathAuthRequest(backend *oauthBackend) *framework.Path {
	return &framework.Path{
		Pattern: "auth-request",
		Fields:  map[string]*framework.FieldSchema{},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: backend.readAuthRequest,
		},
	}
}

func (backend *oauthBackend) readAuthRequest(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	backend.lock.RLock()
	defer backend.lock.RUnlock()

	idProvider, err := backend.IdentityProvider(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if idProvider == nil {
		return nil, errors.New("plugin not configured")
	}

	response := &logical.Response{
		Data: map[string]interface{}{
			"url": idProvider.AuthURL(ctx),
		},
	}
	return response, nil
}
