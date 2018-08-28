package oauthplugin

import (
	"context"
	"errors"
	"time"

	"github.com/hashicorp/vault/helper/policyutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

const (
	rolePrefix string = "role/"
)

type oauthRole struct {
	// See logical.Auth for semantics
	Policies []string      `json:"policies"`
	NumUses  int           `json:"num_uses"`
	TTL      time.Duration `json:"ttl"`
	MaxTTL   time.Duration `json:"max_ttl"`

	// Role binding properties
	UserClaim      string                 `json:"user_claim"`
	EmailClaim     string                 `json:"email_claim"`
	GivenNameClaim string                 `json:"given_name_claim"`
	BoundClaims    map[string]interface{} `json:"bound_claims"`
}

func DefaultRole() *oauthRole {
	return &oauthRole{
		UserClaim:      "sub",
		EmailClaim:     "email",
		GivenNameClaim: "given_name",
	}
}

func LoadRole(ctx context.Context, s logical.Storage, name string) (*oauthRole, error) {
	raw, err := s.Get(ctx, rolePrefix+name)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}

	role := new(oauthRole)
	if err := raw.DecodeJSON(role); err != nil {
		return nil, err
	}

	return role, nil
}

func DeleteRole(ctx context.Context, storage logical.Storage, name string) error {
	return storage.Delete(ctx, rolePrefix+name)
}

func ListRoles(ctx context.Context, storage logical.Storage) ([]string, error) {
	return storage.List(ctx, rolePrefix)
}

func (role *oauthRole) Save(ctx context.Context, storage logical.Storage, name string) error {
	entry, err := logical.StorageEntryJSON(rolePrefix+name, role)
	if err != nil {
		return err
	}
	return storage.Put(ctx, entry)
}

func (role *oauthRole) Validate() error {
	if role.NumUses < 0 {
		return errors.New("num_uses cannot be negative")
	}

	if role.UserClaim == "" {
		return errors.New("a user claim must be defined on the role")
	}

	if role.MaxTTL > 0 && role.TTL > role.MaxTTL {
		return errors.New("ttl should not be greater than max_ttl")
	}

	return nil
}

func (role *oauthRole) SetFromRequestData(data *framework.FieldData) {
	if policiesRaw, ok := data.GetOk("policies"); ok {
		role.Policies = policyutil.ParsePolicies(policiesRaw)
	}

	if tokenNumUsesRaw, ok := data.GetOk("num_uses"); ok {
		role.NumUses = tokenNumUsesRaw.(int)
	}

	if tokenTTLRaw, ok := data.GetOk("ttl"); ok {
		role.TTL = time.Duration(tokenTTLRaw.(int)) * time.Second
	}

	if tokenMaxTTLRaw, ok := data.GetOk("max_ttl"); ok {
		role.MaxTTL = time.Duration(tokenMaxTTLRaw.(int)) * time.Second
	}

	if userClaim, ok := data.GetOk("user_claim"); ok {
		role.UserClaim = userClaim.(string)
	}

	if emailClaim, ok := data.GetOk("email_claim"); ok {
		role.EmailClaim = emailClaim.(string)
	}

	if displayNameClaim, ok := data.GetOk("given_name_claim"); ok {
		role.GivenNameClaim = displayNameClaim.(string)
	}

	if boundClaims, ok := data.GetOk("bound_claims"); ok {
		role.BoundClaims = boundClaims.(map[string]interface{})
	}
}

func (role *oauthRole) ToStringMap() map[string]interface{} {
	return map[string]interface{}{
		"policies":         role.Policies,
		"num_uses":         role.NumUses,
		"ttl":              int64(role.TTL.Seconds()),
		"max_ttl":          int64(role.MaxTTL.Seconds()),
		"user_claim":       role.UserClaim,
		"email_claim":      role.EmailClaim,
		"given_name_claim": role.GivenNameClaim,
		"bound_claims":     role.BoundClaims,
	}
}
