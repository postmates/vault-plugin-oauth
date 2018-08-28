package oauthplugin

import (
	"context"
	"errors"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

type pluginConfig struct {
	Issuer       string `json:"issuer"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Scopes       string `json:"scopes"`
}

func (config *pluginConfig) Save(ctx context.Context, storage logical.Storage) error {
	entry, err := logical.StorageEntryJSON(configPath, config)
	if err != nil {
		return err
	}
	return storage.Put(ctx, entry)
}

func (config *pluginConfig) SetFromRequestData(data *framework.FieldData) {
	config.Issuer = data.Get("issuer").(string)
	config.ClientSecret = data.Get("client_secret").(string)
	config.ClientID = data.Get("client_id").(string)
}

func (config *pluginConfig) Validate() error {
	if config.ClientID == "" || config.ClientSecret == "" || config.Issuer == "" {
		return errors.New("issuer, client_secret, and client_id are required")
	}

	return nil
}

func LoadConfig(ctx context.Context, storage logical.Storage) (*pluginConfig, error) {
	entry, err := storage.Get(ctx, configPath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	config := &pluginConfig{}
	if err := entry.DecodeJSON(config); err != nil {
		return nil, err
	}

	return config, nil
}
