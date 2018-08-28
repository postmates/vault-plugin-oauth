package oauthplugin

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathLogin(backend *oauthBackend) *framework.Path {
	return &framework.Path{
		Pattern: "login$",
		Fields: map[string]*framework.FieldSchema{
			"code": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "OAuth authorization code.",
			},
			"redirect_uri": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Optional. Redirect URI used in the authorization request.",
			},
			"role": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Required.",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: backend.pathLogin,
		},
	}
}

func (backend *oauthBackend) pathLogin(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	idProvider, err := backend.IdentityProvider(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	roleName := data.Get("role").(string)
	if roleName == "" {
		return logical.ErrorResponse("role is required"), nil
	}
	role, err := LoadRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("role " + roleName + " does not exist"), nil
	}

	if idProvider == nil {
		return nil, errors.New("plugin is not yet configured")
	}

	claims, err := idProvider.ValidateCode(ctx, data.Get("code").(string), data.Get("redirect_uri").(string))
	if err != nil {
		return nil, err
	}

	userName, ok := claims[role.UserClaim].(string)
	if !ok {
		return logical.ErrorResponse("User claim (" + role.UserClaim + ") is missing"), nil
	}

	if err = backend.verifyBoundClaims(claims, role.BoundClaims); err != nil {
		return logical.ErrorResponse("claims do not match bound_claims of role"), nil
	}

	metadata := map[string]string{}
	{
		givenName, ok := claims[role.GivenNameClaim].(string)
		if ok {
			metadata["given_name"] = givenName
		}
		email, ok := claims[role.EmailClaim].(string)
		if ok {
			metadata["email"] = email
		}
	}

	response := &logical.Response{
		Auth: &logical.Auth{
			Policies:    role.Policies,
			DisplayName: userName,
			NumUses:     role.NumUses,

			Alias: &logical.Alias{
				Name:     userName,
				Metadata: metadata,
			},

			LeaseOptions: logical.LeaseOptions{
				TTL:    role.TTL,
				MaxTTL: role.MaxTTL,
			},
		},
	}
	return response, nil
}

func (backend *oauthBackend) verifyBoundClaims(claims map[string]interface{}, boundClaims map[string]interface{}) error {
	for claim, expectedValue := range boundClaims {
		claimedValue := claims[claim]
		if claimedValue != expectedValue {
			backend.Logger().Warn(fmt.Sprintf("login failed: %#v bound to %#v, found %#v\n", claim, expectedValue, claimedValue))
			return errors.New("bah")
		}
	}

	return nil
}
