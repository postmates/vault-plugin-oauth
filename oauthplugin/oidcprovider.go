package oauthplugin

import (
	"context"
	"errors"

	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

type oidcAuth struct {
	issuer       string
	oidcProvider *oidc.Provider
	oauthConfig  oauth2.Config
	oidcConfig   oidc.Config
	verifier     *oidc.IDTokenVerifier
}

func newOidcIdProvider(ctx context.Context, backendConf *pluginConfig) (*oidcAuth, error) {
	// The context passed to NewProvider must remain valid for as long as we
	// want to be able to use this provider. See
	// https://github.com/coreos/go-oidc/pull/176
	oidcProvider, err := oidc.NewProvider(context.Background(), backendConf.Issuer)
	if err != nil {
		return nil, err
	}

	provider := &oidcAuth{
		issuer:       backendConf.Issuer,
		oidcProvider: oidcProvider,
		oidcConfig: oidc.Config{
			ClientID: backendConf.ClientID,
		},
	}

	provider.oauthConfig = oauth2.Config{
		ClientID:     backendConf.ClientID,
		ClientSecret: backendConf.ClientSecret,
		RedirectURL:  "urn:ietf:wg:oauth:2.0:oob",
		Endpoint:     oidcProvider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "email"},
	}

	provider.verifier = oidcProvider.Verifier(&provider.oidcConfig)

	return provider, nil
}

func (idp *oidcAuth) ValidateCode(ctx context.Context, code string, redirectURL string) (map[string]interface{}, error) {
	// The OAuth2 spec requires that when exchanging the authorization code for
	// tokens, the redirect_uri is provided exactly as it was in the
	// authorization request that generated the authorization code.
	//
	// https://www.oauth.com/oauth2-servers/access-tokens/authorization-code-request/
	// https://tools.ietf.org/html/rfc6749#section-4.1.3
	//
	// vault-login-oauth uses a different redirect URI each time, firstly
	// because it listens on a random port, and secondly in accordance with
	// best practice for native apps:
	// https://tools.ietf.org/html/rfc8252#section-8.10
	//
	// The oauth2 package is designed for the more typical web app case where
	// the redirect URI is the same always, and saves the redirect URI in
	// Config rather than require it as a parameter to Exchange(). Thus we must
	// make a temporary copy of the Config.

	var oauthConfig oauth2.Config = idp.oauthConfig
	if redirectURL != "" {
		oauthConfig.RedirectURL = redirectURL
	}

	oauth2Token, err := oauthConfig.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("No id_token was returned. Maybe not requesting the right scopes?")
	}

	idToken, err := idp.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, err
	}

	claims := map[string]interface{}{}
	err = idToken.Claims(&claims)
	if err != nil {
		return nil, err
	}

	return claims, nil
}

func (idp *oidcAuth) AuthURL(ctx context.Context) string {
	// It's OK that we don't use a random state here. The redirect_uri we set
	// by default is urn:ietf:wg:oauth:2.0:oob, which displays the
	// authorization code for manual copying rather than sending it to a
	// server. Since there's no server running to which requests can be forged,
	// CSRF isn't a threat.
	//
	// It's possible the user is using vault-login-oauth, which does run a
	// server. In that case vault-login-oauth will modify the URL to include a
	// nonce in the state parameter to mitigate the risk of a forged request.

	return idp.oauthConfig.AuthCodeURL("")
}

func (idp *oidcAuth) Issuer() string {
	return idp.issuer
}

func (idp *oidcAuth) ClientID() string {
	return idp.oauthConfig.ClientID
}

func (idp *oidcAuth) ClientSecret() string {
	return idp.oauthConfig.ClientSecret
}
