package oauthplugin

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathRoleList(backend *oauthBackend) *framework.Path {
	return &framework.Path{
		Pattern: "role/?",
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: backend.pathRoleList,
		},
	}
}

func pathRole(backend *oauthBackend) *framework.Path {
	return &framework.Path{
		Pattern: rolePrefix + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role.",
			},
			"policies": &framework.FieldSchema{
				Type:        framework.TypeCommaStringSlice,
				Description: "List of policies on the role.",
			},
			"num_uses": &framework.FieldSchema{
				Type:        framework.TypeInt,
				Description: `Number of times issued tokens can be used`,
			},
			"ttl": &framework.FieldSchema{
				Type: framework.TypeDurationSecond,
				Description: `Duration in seconds after which the issued token should expire. Defaults
to 0, in which case the value will fall back to the system/mount defaults.`,
			},
			"max_ttl": &framework.FieldSchema{
				Type: framework.TypeDurationSecond,
				Description: `Duration in seconds after which the issued token should not be allowed to
be renewed. Defaults to 0, in which case the value will fall back to the system/mount defaults.`,
			},
			"user_claim": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `Default: "sub". The claim to use for the Identity entity alias name. It should
be something guaranteed not to change, usually "sub". Identities can be
associated with more familiar data with email_claim and given_name_claim.`,
			},
			"email_claim": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `Default: "email". OK if this claim does not exist. Associated with the entity
alias metadata to made identification easier when "sub" is an opaque number.`,
			},
			"given_name_claim": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `Default: "given_name". OK if this claim does not exist. Associated with the
entity alias metadata to made identification easier when "sub" is an opaque
number.`,
			},
			"bound_claims": &framework.FieldSchema{
				Type: framework.TypeMap,
				Description: `Optional. Arbitrary claims which all must match to use this role.
The value of this option is an arbitrary map which must be specified as JSON.
Example:

vault write auth/oauth/role/default - <<EOF
{
	"bound_claims": {
		"hd": "example.com",
		"email_verified": true
	}
}
EOF
`,
			},
		},
		ExistenceCheck: backend.pathRoleExistenceCheck,
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: backend.pathRoleCreateUpdate,
			logical.UpdateOperation: backend.pathRoleCreateUpdate,
			logical.ReadOperation:   backend.pathRoleRead,
			logical.DeleteOperation: backend.pathRoleDelete,
		},
	}
}

func (backend *oauthBackend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	role, err := LoadRole(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return false, err
	}
	return role != nil, nil
}

func (backend *oauthBackend) pathRoleCreateUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	var (
		role *oauthRole
		err  error
	)

	switch req.Operation {
	case logical.CreateOperation:
		role = DefaultRole()
	case logical.UpdateOperation:
		role, err = LoadRole(ctx, req.Storage, roleName)
		if err != nil {
			return nil, err
		}
		if role == nil {
			return nil, errors.New("role entry not found during update operation")
		}
	default:
		return nil, fmt.Errorf("What kind of operation is %#v!?", logical.UpdateOperation)
	}

	role.SetFromRequestData(data)
	if err := role.Validate(); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	resp := &logical.Response{}
	if role.MaxTTL > backend.System().MaxLeaseTTL() {
		resp.AddWarning("max_ttl is greater than the system or backend mount's maximum TTL value; issued tokens' max TTL value will be truncated")
	}

	return nil, role.Save(ctx, req.Storage, roleName)
}

func (backend *oauthBackend) pathRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing name"), nil
	}

	role, err := LoadRole(ctx, req.Storage, roleName)
	if err != nil || role == nil {
		return nil, err
	}

	resp := &logical.Response{
		Data: role.ToStringMap(),
	}

	return resp, nil
}

func (backend *oauthBackend) pathRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)
	if roleName == "" {
		return logical.ErrorResponse("role name required"), nil
	}

	return nil, DeleteRole(ctx, req.Storage, roleName)
}

func (backend *oauthBackend) pathRoleList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roles, err := ListRoles(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(roles), nil
}
